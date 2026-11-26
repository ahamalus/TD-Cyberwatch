"""Off-server anchoring of the audit trail.

The audit trail is a hash chain: editing or deleting one event breaks every later hash. Someone with full
control of the server could still rewrite the *whole* chain and recompute it. Anchors close that gap: the
current head of the chain (its sequence number and hash) is regularly published somewhere that server access
does not reach:

* every nightly backup writes ``audit-anchor-<stamp>.txt`` next to the encrypted backup set, and the Windows
  host copies it off the VM (and keeps anchor files indefinitely);
* the daily anchor task emails the line to ``CW_AUDIT_ANCHOR_EMAILS`` (an external mailbox).

To check the trail, feed any collection of saved anchor lines to ``python -m app.cli verify-audit --anchors
FILE``: each anchored event must still exist with exactly the published hash, and the chain must be intact.
A rewritten history cannot match anchors published before the rewrite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import utcnow
from app.models import AuditEvent, PlatformSetting
from app.services import audit

ANCHOR = re.compile(r"CWANCHOR v1 seq=(\d+) hash=([0-9a-f]{64}) at=(\S+)")
SETTING_KEY = "audit_anchor"


class ChainBroken(Exception):
    pass


def make_anchor(db: Session) -> str:
    """Verify the whole chain, then record and return an anchor line for its current head."""
    res = audit.verify_chain(db)
    if not res.valid:
        raise ChainBroken(f"Audit chain is broken at event {res.first_invalid_seq}: {res.reason}")
    head = db.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)).scalar_one_or_none()
    now = utcnow()
    seq, digest = (head.seq, head.hash) if head else (0, audit.GENESIS)
    line = f"CWANCHOR v1 seq={seq} hash={digest} at={now.astimezone(UTC):%Y-%m-%dT%H:%M:%SZ}"
    value = {"seq": seq, "hash": digest, "at": now.isoformat(), "events": res.events_checked}
    row = db.get(PlatformSetting, SETTING_KEY)
    if row is None:
        db.add(PlatformSetting(key=SETTING_KEY, value=value, description="Latest published audit-trail anchor."))
    else:
        row.value, row.updated_at = value, now
    return line


def publish(db: Session) -> dict:
    """Daily task: anchor the chain and email the anchor off-server. A broken chain is reported loudly."""
    from app.services.notifications import queue_simple

    recipients = get_settings().audit_anchor_emails
    today = f"{utcnow():%Y-%m-%d}"
    try:
        line = make_anchor(db)
    except ChainBroken as exc:
        for to in recipients:
            queue_simple(db, tenant_id=None, channel="email", recipient=to, category="security",
                         subject="CyberWatch ALERT: audit trail verification failed",
                         body=f"{exc}\n\nNo new anchor was published. Investigate before trusting the audit trail.",
                         idempotency_key=f"audit_broken:{today}:{to}")
        return {"status": "chain_broken", "detail": str(exc)}
    for to in recipients:
        queue_simple(db, tenant_id=None, channel="email", recipient=to, category="security",
                     subject=f"CyberWatch audit anchor {today}",
                     body=("Keep this message. It lets you prove later that CyberWatch's audit trail was not "
                           "rewritten (python -m app.cli verify-audit --anchors FILE).\n\n" + line),
                     idempotency_key=f"audit_anchor:{today}:{to}")
    return {"status": "published", "anchor": line, "emailed": len(recipients)}


@dataclass
class AnchorCheck:
    line: str
    ok: bool
    reason: str


def verify_anchors(db: Session, text_blob: str) -> list[AnchorCheck]:
    """Check every anchor line found in ``text_blob`` (email bodies, files, anything) against the trail."""
    out: list[AnchorCheck] = []
    seen: set[tuple[int, str]] = set()
    for m in ANCHOR.finditer(text_blob):
        seq, digest = int(m.group(1)), m.group(2)
        if (seq, digest) in seen:
            continue
        seen.add((seq, digest))
        if seq == 0:
            out.append(AnchorCheck(m.group(0), digest == audit.GENESIS, "empty trail"))
            continue
        event = db.execute(select(AuditEvent).where(AuditEvent.seq == seq)).scalar_one_or_none()
        if event is None:
            out.append(AnchorCheck(m.group(0), False, f"event {seq} no longer exists (history truncated or rewritten)"))
        elif event.hash != digest:
            out.append(AnchorCheck(m.group(0), False, f"event {seq} has a different hash (history rewritten)"))
        else:
            out.append(AnchorCheck(m.group(0), True, "matches"))
    return out


def last_anchor_age_hours(db: Session) -> float | None:
    row = db.get(PlatformSetting, SETTING_KEY)
    if row is None or "at" not in (row.value or {}):
        return None
    return (utcnow() - datetime.fromisoformat(row.value["at"])).total_seconds() / 3600
