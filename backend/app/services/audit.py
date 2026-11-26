"""Tamper-evident audit trail.

Each event stores ``hash = sha256(prev_hash || canonical_json(event))``. Events
are written inside the caller's transaction under a transaction-scoped
advisory lock so the chain is strictly ordered. ``verify_chain`` recomputes
the chain to detect modification or deletion.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.logging import redact_mapping
from app.db.base import utcnow
from app.models import AuditEvent

GENESIS = "0" * 64
_AUDIT_LOCK_KEY = 0x43574155  # "CWAU"


@dataclass
class AuditActor:
    user_id: uuid.UUID | None = None
    actor_type: str = "system"  # user | staff | system | anonymous
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    via_grant_id: uuid.UUID | None = None


SYSTEM_ACTOR = AuditActor(actor_type="system")


def _canonical(event: dict[str, Any]) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)


def _event_payload(e: AuditEvent) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "occurred_at": e.occurred_at.astimezone(UTC).isoformat(),
        "tenant_id": str(e.tenant_id) if e.tenant_id else None,
        "actor_user_id": str(e.actor_user_id) if e.actor_user_id else None,
        "actor_type": e.actor_type,
        "action": e.action,
        "category": e.category,
        "target_type": e.target_type,
        "target_id": e.target_id,
        "outcome": e.outcome,
        "details": e.details,
        "via_grant_id": str(e.via_grant_id) if e.via_grant_id else None,
    }


def compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + _canonical(payload)).encode()).hexdigest()


def record(
    db: Session,
    action: str,
    *,
    actor: AuditActor = SYSTEM_ACTOR,
    tenant_id: uuid.UUID | None = None,
    category: str | None = None,
    target_type: str | None = None,
    target_id: object | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})
    prev = db.execute(select(AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1)).scalar()
    event = AuditEvent(
        id=uuid.uuid4(),
        occurred_at=utcnow(),
        tenant_id=tenant_id,
        actor_user_id=actor.user_id,
        actor_type=actor.actor_type,
        action=action,
        category=category or action.split(".", 1)[0],
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        outcome=outcome,
        ip_address=actor.ip_address,
        user_agent=(actor.user_agent or "")[:400] or None,
        request_id=actor.request_id,
        details=json.loads(_canonical(redact_mapping(details or {}))),
        via_grant_id=actor.via_grant_id,
        prev_hash=prev or GENESIS,
        hash="",
    )
    event.hash = compute_hash(event.prev_hash, _event_payload(event))
    db.add(event)
    db.flush()
    return event


@dataclass
class ChainVerification:
    valid: bool
    events_checked: int
    first_invalid_seq: int | None = None
    reason: str | None = None


def verify_chain(db: Session, limit: int | None = None) -> ChainVerification:
    q = select(AuditEvent).order_by(AuditEvent.seq.asc())
    if limit:
        q = q.limit(limit)
    prev = GENESIS
    n = 0
    for event in db.execute(q).scalars():
        n += 1
        if event.prev_hash != prev:
            return ChainVerification(False, n, event.seq, "Chain link broken (event removed or reordered).")
        if compute_hash(prev, _event_payload(event)) != event.hash:
            return ChainVerification(False, n, event.seq, "Event content does not match its hash.")
        prev = event.hash
    return ChainVerification(True, n)


def as_utc_iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None
