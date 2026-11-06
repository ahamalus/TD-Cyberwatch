"""Incident lifecycle, evidence and tamper-evident history."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.errors import AppError, NotFound, ValidationFailed
from app.db.base import utcnow
from app.models import (
    AvailabilityCheck,
    FileChange,
    Incident,
    IncidentEvent,
    IncidentEvidence,
    SuppressionRule,
)
from app.models.incidents import OPEN_STATUSES, SEVERITY_RANK
from app.monitoring.inventory import matches_any
from app.services import audit
from app.services.audit import AuditActor

GENESIS = "0" * 64

# Allowed manual status transitions.
TRANSITIONS: dict[str, set[str]] = {
    "new": {"acknowledged", "investigating", "resolved", "closed"},
    "acknowledged": {"investigating", "contained", "resolved", "closed"},
    "investigating": {"contained", "resolved", "closed", "acknowledged"},
    "contained": {"investigating", "resolved", "closed"},
    "resolved": {"closed", "investigating"},
    "closed": {"investigating"},
}


def jsonable(value: Any) -> Any:
    """Normalise to JSON-native types (datetimes/UUIDs become strings)."""
    return json.loads(json.dumps(value, default=str))


def canonical_sha256(content: Any) -> str:
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


@dataclass
class EvidenceSpec:
    kind: str
    source: str
    collection_method: str
    content: dict[str, Any]
    reference_id: uuid.UUID | None = None


@dataclass
class DetectionSpec:
    tenant_id: uuid.UUID
    website_id: uuid.UUID | None
    title: str
    summary: str
    category: str
    finding_class: str
    severity: str
    confidence: str
    detection_source: str
    rule_key: str
    dedupe_key: str
    recommended_action: str
    affected_resources: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[EvidenceSpec] = field(default_factory=list)
    hosting_account_id: uuid.UUID | None = None
    requires_human_verification: bool = True
    path_for_suppression: str | None = None
    is_demo: bool = False


def _event_hash(prev: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev + json.dumps(payload, sort_keys=True, default=str)).encode()).hexdigest()


def add_event(
    db: Session,
    incident: Incident,
    event_type: str,
    *,
    actor_user_id: uuid.UUID | None = None,
    actor_type: str = "system",
    body: str | None = None,
    from_status: str | None = None,
    to_status: str | None = None,
    data: dict[str, Any] | None = None,
    is_manual: bool = False,
) -> IncidentEvent:
    last = db.execute(
        select(IncidentEvent.seq, IncidentEvent.hash)
        .where(IncidentEvent.incident_id == incident.id)
        .order_by(IncidentEvent.seq.desc())
        .limit(1)
    ).first()
    seq = (last.seq + 1) if last else 1
    data = jsonable(data or {})
    prev = last.hash if last else GENESIS
    now = utcnow()
    payload = {
        "incident_id": str(incident.id),
        "seq": seq,
        "event_type": event_type,
        "actor_user_id": str(actor_user_id) if actor_user_id else None,
        "body": body,
        "from_status": from_status,
        "to_status": to_status,
        "data": data or {},
        "created_at": now.isoformat(),
    }
    ev = IncidentEvent(
        tenant_id=incident.tenant_id,
        incident_id=incident.id,
        seq=seq,
        actor_user_id=actor_user_id,
        actor_type=actor_type,
        event_type=event_type,
        from_status=from_status,
        to_status=to_status,
        body=body,
        data=data or {},
        is_manual=is_manual,
        created_at=now,
        prev_hash=prev,
        hash=_event_hash(prev, payload),
    )
    db.add(ev)
    db.flush()
    return ev


def verify_incident_history(db: Session, incident_id: uuid.UUID) -> bool:
    prev = GENESIS
    for ev in db.execute(
        select(IncidentEvent).where(IncidentEvent.incident_id == incident_id).order_by(IncidentEvent.seq)
    ).scalars():
        payload = {
            "incident_id": str(ev.incident_id),
            "seq": ev.seq,
            "event_type": ev.event_type,
            "actor_user_id": str(ev.actor_user_id) if ev.actor_user_id else None,
            "body": ev.body,
            "from_status": ev.from_status,
            "to_status": ev.to_status,
            "data": ev.data,
            "created_at": ev.created_at.astimezone(utcnow().tzinfo).isoformat(),
        }
        if ev.prev_hash != prev or _event_hash(prev, payload) != ev.hash:
            return False
        prev = ev.hash
    return True


def add_evidence(db: Session, incident: Incident, spec: EvidenceSpec) -> IncidentEvidence:
    content = jsonable(spec.content)
    ev = IncidentEvidence(
        tenant_id=incident.tenant_id,
        incident_id=incident.id,
        kind=spec.kind,
        reference_id=spec.reference_id,
        source=spec.source,
        collection_method=spec.collection_method,
        content=content,
        content_sha256=canonical_sha256(content),
    )
    db.add(ev)
    db.flush()
    return ev


def _is_suppressed(db: Session, spec: DetectionSpec) -> SuppressionRule | None:
    now = utcnow()
    rules = db.execute(
        select(SuppressionRule).where(
            SuppressionRule.tenant_id == spec.tenant_id,
            SuppressionRule.is_active.is_(True),
            SuppressionRule.rule_key.in_([spec.rule_key, "*"]),
        )
    ).scalars()
    for r in rules:
        if r.expires_at and r.expires_at <= now:
            continue
        if r.website_id and r.website_id != spec.website_id:
            continue
        if r.path_glob:
            if not spec.path_for_suppression or not matches_any(spec.path_for_suppression, [r.path_glob]):
                continue
        return r
    return None


def _next_reference(db: Session, tenant_id: uuid.UUID) -> str:
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"incref:{tenant_id}"})
    n = db.execute(select(func.count()).select_from(Incident).where(Incident.tenant_id == tenant_id)).scalar_one()
    return f"INC-{n + 1:05d}"


def raise_detection(db: Session, spec: DetectionSpec) -> tuple[Incident | None, bool]:
    """Open a new incident or record a repeat observation on the open one.

    Returns (incident, created). Returns (None, False) if suppressed.
    """
    rule = _is_suppressed(db, spec)
    if rule is not None:
        return None, False
    now = utcnow()
    existing = db.execute(
        select(Incident)
        .where(
            Incident.tenant_id == spec.tenant_id,
            Incident.dedupe_key == spec.dedupe_key,
            Incident.status.in_(OPEN_STATUSES),
        )
        .with_for_update()
    ).scalar_one_or_none()
    if existing is not None:
        existing.last_observed_at = now
        existing.occurrence_count += 1
        existing.affected_resources = _merge_resources(existing.affected_resources, spec.affected_resources)
        escalated = SEVERITY_RANK[spec.severity] > SEVERITY_RANK[existing.severity]
        data: dict[str, Any] = {"occurrence": existing.occurrence_count}
        if escalated:
            data["severity_from"], data["severity_to"] = existing.severity, spec.severity
            existing.severity = spec.severity
        add_event(db, existing, "observed", body=spec.summary, data=data)
        for ev in spec.evidence:
            add_evidence(db, existing, ev)
        if escalated:
            _notify(db, existing, "incident_escalated")
        return existing, False

    incident = Incident(
        tenant_id=spec.tenant_id,
        website_id=spec.website_id,
        hosting_account_id=spec.hosting_account_id,
        reference=_next_reference(db, spec.tenant_id),
        title=spec.title[:300],
        summary=spec.summary,
        category=spec.category,
        finding_class=spec.finding_class,
        severity=spec.severity,
        confidence=spec.confidence,
        detection_source=spec.detection_source,
        rule_key=spec.rule_key,
        dedupe_key=spec.dedupe_key,
        recommended_action=spec.recommended_action,
        requires_human_verification=spec.requires_human_verification,
        affected_resources=spec.affected_resources[:200],
        first_detected_at=now,
        last_observed_at=now,
        is_demo=spec.is_demo,
    )
    db.add(incident)
    db.flush()
    score, explanation = compute_risk(db, incident)
    incident.risk_score, incident.risk_explanation = score, explanation
    add_event(db, incident, "created", body=spec.summary, to_status="new",
              data={"rule_key": spec.rule_key, "detection_source": spec.detection_source})
    for ev in spec.evidence:
        add_evidence(db, incident, ev)
    audit.record(db, "incident.created", tenant_id=incident.tenant_id, target_type="incident",
                 target_id=incident.id, details={"severity": incident.severity, "rule": spec.rule_key})
    _notify(db, incident, "incident_opened")
    return incident, True


def _merge_resources(existing: list, new: list, cap: int = 200) -> list:
    seen = {json.dumps(r, sort_keys=True) for r in existing}
    out = list(existing)
    for r in new:
        k = json.dumps(r, sort_keys=True)
        if k not in seen and len(out) < cap:
            out.append(r)
            seen.add(k)
    return out


def _notify(db: Session, incident: Incident, reason: str) -> None:
    from app.services.notifications import route_incident

    route_incident(db, incident, reason)


# --------------------------------------------------------------------------
# Risk scoring (M07): documented, explainable, never presented as proof.
# --------------------------------------------------------------------------

SEVERITY_POINTS = {"critical": 60, "high": 45, "medium": 25, "low": 10, "informational": 0}


def compute_risk(db: Session, incident: Incident) -> tuple[int, list[dict[str, Any]]]:
    explanation: list[dict[str, Any]] = []
    score = SEVERITY_POINTS[incident.severity]
    explanation.append({"factor": "severity", "points": score, "detail": f"Base points for {incident.severity}"})
    if incident.finding_class == "confirmed_malware":
        score += 25
        explanation.append({"factor": "confirmed_detection", "points": 25,
                            "detail": "A signature engine confirmed the detection"})
    if incident.website_id:
        since = utcnow() - timedelta(hours=24)
        recent_changes = db.execute(
            select(func.count()).select_from(FileChange).where(
                FileChange.website_id == incident.website_id,
                FileChange.detected_at >= since,
                FileChange.severity.in_(["high", "critical"]),
            )
        ).scalar_one()
        if recent_changes and incident.category != "file_integrity":
            score += 10
            explanation.append({"factor": "correlated_file_changes", "points": 10,
                                "detail": f"{recent_changes} high-severity file change(s) in the last 24h"})
        outages = db.execute(
            select(func.count()).select_from(AvailabilityCheck).where(
                AvailabilityCheck.website_id == incident.website_id,
                AvailabilityCheck.checked_at >= since,
                AvailabilityCheck.outcome.in_(["down", "error"]),
            )
        ).scalar_one()
        if outages and incident.category not in ("availability", "tls"):
            score += 5
            explanation.append({"factor": "correlated_availability", "points": 5,
                                "detail": f"{outages} failed availability check(s) in the last 24h"})
    if incident.requires_human_verification:
        explanation.append({"factor": "heuristic", "points": 0,
                            "detail": "Heuristic finding: requires human verification; not proof of compromise"})
    return min(score, 100), explanation


# --------------------------------------------------------------------------
# Manual workflow
# --------------------------------------------------------------------------


def get_incident(db: Session, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> Incident:
    inc = db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if inc is None:
        raise NotFound("Incident not found.")
    return inc


def change_status(
    db: Session,
    incident: Incident,
    new_status: str,
    actor: AuditActor,
    *,
    note: str | None = None,
    false_positive: bool | None = None,
) -> Incident:
    if new_status == incident.status:
        return incident
    if new_status not in TRANSITIONS.get(incident.status, set()):
        raise ValidationFailed(f"Cannot move an incident from {incident.status} to {new_status}.",
                               code="invalid_transition")
    if new_status in ("resolved", "closed") and not (note or incident.resolution_notes):
        raise ValidationFailed("Resolution notes are required to resolve or close an incident.")
    old = incident.status
    if new_status == "investigating" and old in ("resolved", "closed"):
        # Re-opening: check another open incident does not already hold the dedupe key.
        clash = db.execute(
            select(Incident.id).where(
                Incident.tenant_id == incident.tenant_id,
                Incident.dedupe_key == incident.dedupe_key,
                Incident.status.in_(OPEN_STATUSES),
                Incident.id != incident.id,
            )
        ).first()
        if clash:
            raise AppError("A newer open incident already tracks this detection.", code="conflict", status_code=409)
        incident.resolved_at = None
        incident.closed_at = None
    incident.status = new_status
    if new_status == "resolved":
        incident.resolved_at = utcnow()
    if new_status == "closed":
        incident.closed_at = utcnow()
        incident.resolved_at = incident.resolved_at or utcnow()
    if note and new_status in ("resolved", "closed"):
        incident.resolution_notes = note
    if false_positive is not None:
        incident.is_false_positive = false_positive
    add_event(db, incident, "status_changed", actor_user_id=actor.user_id, actor_type=actor.actor_type,
              from_status=old, to_status=new_status, body=note,
              data={"false_positive": incident.is_false_positive}, is_manual=True)
    audit.record(db, "incident.status_changed", actor=actor, tenant_id=incident.tenant_id,
                 target_type="incident", target_id=incident.id, details={"from": old, "to": new_status})
    return incident


def add_note(db: Session, incident: Incident, actor: AuditActor, body: str) -> IncidentEvent:
    if not body.strip():
        raise ValidationFailed("Note cannot be empty.")
    ev = add_event(db, incident, "note", actor_user_id=actor.user_id, actor_type=actor.actor_type,
                   body=body.strip()[:10000], is_manual=True)
    audit.record(db, "incident.note_added", actor=actor, tenant_id=incident.tenant_id,
                 target_type="incident", target_id=incident.id)
    return ev


def assign(db: Session, incident: Incident, actor: AuditActor, assignee_id: uuid.UUID | None) -> None:
    incident.assigned_to = assignee_id
    add_event(db, incident, "assigned", actor_user_id=actor.user_id, actor_type=actor.actor_type,
              data={"assignee": str(assignee_id) if assignee_id else None}, is_manual=True)
    audit.record(db, "incident.assigned", actor=actor, tenant_id=incident.tenant_id, target_type="incident",
                 target_id=incident.id, details={"assignee": str(assignee_id) if assignee_id else None})
