"""Incident centre (C07) and suppression rules."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, or_, select
from sqlalchemy.orm import Session

from app.api.deps import TenantContext, require
from app.core.errors import NotFound, ValidationFailed
from app.core.permissions import P
from app.db.session import get_db
from app.models import (
    Incident,
    IncidentEvent,
    IncidentEvidence,
    Notification,
    SuppressionRule,
    TenantMembership,
    User,
    Website,
)
from app.models.incidents import INCIDENT_STATUSES, OPEN_STATUSES
from app.schemas.common import Message, PageParams, paginate
from app.services import audit
from app.services import incidents as svc

router = APIRouter(prefix="/tenants/{tenant_id}", tags=["incidents"])

SEVERITY_ORDER = case(
    {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}, value=Incident.severity
)


def incident_dict(i: Incident, names: dict, users: dict) -> dict:
    return {
        "id": str(i.id), "reference": i.reference, "title": i.title, "summary": i.summary, "category": i.category,
        "finding_class": i.finding_class, "severity": i.severity, "confidence": i.confidence, "status": i.status,
        "detection_source": i.detection_source, "rule_key": i.rule_key,
        "website_id": str(i.website_id) if i.website_id else None, "website_name": names.get(i.website_id),
        "hosting_account_id": str(i.hosting_account_id) if i.hosting_account_id else None,
        "first_detected_at": i.first_detected_at, "last_observed_at": i.last_observed_at,
        "occurrence_count": i.occurrence_count, "assigned_to": str(i.assigned_to) if i.assigned_to else None,
        "assigned_to_name": users.get(i.assigned_to), "requires_human_verification": i.requires_human_verification,
        "risk_score": i.risk_score, "is_false_positive": i.is_false_positive, "is_demo": i.is_demo,
        "resolved_at": i.resolved_at, "closed_at": i.closed_at,
    }


def _lookups(db: Session, tenant_id: uuid.UUID) -> tuple[dict, dict]:
    names = dict(db.execute(select(Website.id, Website.name).where(Website.tenant_id == tenant_id)).all())
    users = dict(db.execute(
        select(User.id, User.full_name).join(TenantMembership, TenantMembership.user_id == User.id)
        .where(TenantMembership.tenant_id == tenant_id)).all())
    return names, users


@router.get("/incidents")
def list_incidents(
    ctx: TenantContext = Depends(require(P.INCIDENTS_READ)),
    db: Session = Depends(get_db),
    params: PageParams = Depends(),
    status: list[str] | None = Query(None),
    open_only: bool = False,
    severity: list[str] | None = Query(None),
    category: str | None = Query(None, max_length=32),
    website_id: uuid.UUID | None = None,
    assigned_to_me: bool = False,
    q: str | None = Query(None, max_length=200),
    sort: str = Query("-last_observed_at", pattern="^-?(last_observed_at|first_detected_at|severity|reference)$"),
) -> dict:
    query = select(Incident).where(Incident.tenant_id == ctx.tenant_id)
    if open_only:
        query = query.where(Incident.status.in_(OPEN_STATUSES))
    if status:
        query = query.where(Incident.status.in_([s for s in status if s in INCIDENT_STATUSES]))
    if severity:
        query = query.where(Incident.severity.in_(severity))
    if category:
        query = query.where(Incident.category == category)
    if website_id:
        query = query.where(Incident.website_id == website_id)
    if assigned_to_me:
        query = query.where(Incident.assigned_to == ctx.user.id)
    if q:
        like = f"%{q}%"
        query = query.where(or_(Incident.title.ilike(like), Incident.reference.ilike(like)))
    key = sort.lstrip("-")
    col = SEVERITY_ORDER if key == "severity" else getattr(Incident, key)
    desc = sort.startswith("-")
    if key == "severity":
        desc = not desc  # severity order expression is ascending-critical
    query = query.order_by(col.desc() if desc else col.asc(), Incident.id)
    names, users = _lookups(db, ctx.tenant_id)
    return paginate(db, query, params, lambda i: incident_dict(i, names, users))


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: uuid.UUID, ctx: TenantContext = Depends(require(P.INCIDENTS_READ)),
                 db: Session = Depends(get_db)) -> dict:
    inc = svc.get_incident(db, ctx.tenant_id, incident_id)
    names, users = _lookups(db, ctx.tenant_id)
    events = db.execute(select(IncidentEvent).where(IncidentEvent.incident_id == inc.id).order_by(IncidentEvent.seq)).scalars().all()
    evidence = db.execute(select(IncidentEvidence).where(IncidentEvidence.incident_id == inc.id)
                          .order_by(IncidentEvidence.collected_at)).scalars().all()
    notifications = db.execute(select(Notification).where(Notification.incident_id == inc.id)
                               .order_by(Notification.created_at.desc()).limit(50)).scalars().all()
    actor_ids = {e.actor_user_id for e in events if e.actor_user_id}
    actor_names = dict(db.execute(select(User.id, User.full_name).where(User.id.in_(actor_ids))).all()) if actor_ids else {}
    d = incident_dict(inc, names, users)
    d.update({
        "recommended_action": inc.recommended_action,
        "affected_resources": inc.affected_resources,
        "risk_explanation": inc.risk_explanation,
        "resolution_notes": inc.resolution_notes,
        "history_verified": svc.verify_incident_history(db, inc.id),
        "events": [{"seq": e.seq, "event_type": e.event_type, "actor_type": e.actor_type,
                    "actor_name": actor_names.get(e.actor_user_id), "from_status": e.from_status,
                    "to_status": e.to_status, "body": e.body, "data": e.data, "is_manual": e.is_manual,
                    "created_at": e.created_at, "hash": e.hash} for e in events],
        "evidence": [{"id": str(v.id), "kind": v.kind, "source": v.source, "collection_method": v.collection_method,
                      "collected_at": v.collected_at, "content": v.content, "content_sha256": v.content_sha256,
                      "integrity_ok": svc.canonical_sha256(v.content) == v.content_sha256} for v in evidence],
        "notifications": [{"channel": n.channel, "recipient": _mask(n.recipient), "status": n.status,
                           "attempts": n.attempts, "sent_at": n.sent_at, "last_error": n.last_error,
                           "created_at": n.created_at} for n in notifications],
        "allowed_transitions": sorted(svc.TRANSITIONS.get(inc.status, set())),
    })
    return d


def _mask(addr: str) -> str:
    if "@" in addr:
        name, dom = addr.split("@", 1)
        return (name[:2] + "•••@" + dom) if len(name) > 2 else ("•••@" + dom)
    return addr[:4] + "•••" + addr[-2:] if len(addr) > 6 else "•••"


class StatusIn(BaseModel):
    status: str = Field(pattern="^(new|acknowledged|investigating|contained|resolved|closed)$")
    note: str | None = Field(default=None, max_length=10000)
    false_positive: bool | None = None


@router.post("/incidents/{incident_id}/status")
def set_status(incident_id: uuid.UUID, body: StatusIn, ctx: TenantContext = Depends(require(P.INCIDENTS_MANAGE)),
               db: Session = Depends(get_db)) -> dict:
    inc = svc.get_incident(db, ctx.tenant_id, incident_id)
    svc.change_status(db, inc, body.status, ctx.actor(), note=body.note, false_positive=body.false_positive)
    db.commit()
    return get_incident(incident_id, ctx, db)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=10000)


@router.post("/incidents/{incident_id}/notes")
def add_note(incident_id: uuid.UUID, body: NoteIn, ctx: TenantContext = Depends(require(P.INCIDENTS_MANAGE)),
             db: Session = Depends(get_db)) -> dict:
    inc = svc.get_incident(db, ctx.tenant_id, incident_id)
    svc.add_note(db, inc, ctx.actor(), body.body)
    db.commit()
    return get_incident(incident_id, ctx, db)


class AssignIn(BaseModel):
    user_id: uuid.UUID | None


@router.post("/incidents/{incident_id}/assign")
def assign(incident_id: uuid.UUID, body: AssignIn, ctx: TenantContext = Depends(require(P.INCIDENTS_MANAGE)),
           db: Session = Depends(get_db)) -> dict:
    inc = svc.get_incident(db, ctx.tenant_id, incident_id)
    if body.user_id is not None and not db.execute(select(TenantMembership.id).where(
            TenantMembership.tenant_id == ctx.tenant_id, TenantMembership.user_id == body.user_id,
            TenantMembership.status == "active")).first():
        raise ValidationFailed("Assignee must be an active member of this organisation.")
    svc.assign(db, inc, ctx.actor(), body.user_id)
    db.commit()
    return get_incident(incident_id, ctx, db)


# ---------------------------------------------------------------- suppressions


class SuppressionIn(BaseModel):
    rule_key: str = Field(min_length=1, max_length=80)
    website_id: uuid.UUID | None = None
    path_glob: str | None = Field(default=None, max_length=512)
    reason: str = Field(min_length=5, max_length=2000)
    expires_at: datetime | None = None
    from_incident_id: uuid.UUID | None = None


@router.get("/suppressions")
def list_suppressions(ctx: TenantContext = Depends(require(P.INCIDENTS_READ)), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(SuppressionRule).where(SuppressionRule.tenant_id == ctx.tenant_id)
                      .order_by(SuppressionRule.created_at.desc())).scalars()
    return [{"id": str(r.id), "rule_key": r.rule_key, "website_id": str(r.website_id) if r.website_id else None,
             "path_glob": r.path_glob, "reason": r.reason, "expires_at": r.expires_at, "is_active": r.is_active,
             "created_at": r.created_at} for r in rows]


@router.post("/suppressions", status_code=201)
def create_suppression(body: SuppressionIn, ctx: TenantContext = Depends(require(P.INCIDENTS_MANAGE)),
                       db: Session = Depends(get_db)) -> dict:
    if body.website_id and not db.execute(select(Website.id).where(Website.id == body.website_id,
                                                                   Website.tenant_id == ctx.tenant_id)).first():
        raise ValidationFailed("Website not found.")
    if body.rule_key == "*" and not body.path_glob:
        raise ValidationFailed("A wildcard rule requires a path pattern.")
    r = SuppressionRule(tenant_id=ctx.tenant_id, website_id=body.website_id, rule_key=body.rule_key,
                        path_glob=body.path_glob, reason=body.reason, created_by=ctx.user.id,
                        expires_at=body.expires_at)
    db.add(r)
    db.flush()
    if body.from_incident_id:
        inc = svc.get_incident(db, ctx.tenant_id, body.from_incident_id)
        svc.add_event(db, inc, "note", actor_user_id=ctx.user.id, actor_type=ctx.actor().actor_type,
                      body=f"Suppression rule created: {body.reason}", data={"suppression_id": str(r.id)}, is_manual=True)
    audit.record(db, "suppression.created", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="suppression",
                 target_id=r.id, details=body.model_dump(mode="json"))
    db.commit()
    return {"id": str(r.id)}


@router.delete("/suppressions/{rule_id}", response_model=Message)
def delete_suppression(rule_id: uuid.UUID, ctx: TenantContext = Depends(require(P.INCIDENTS_MANAGE)),
                       db: Session = Depends(get_db)) -> Message:
    r = db.execute(select(SuppressionRule).where(SuppressionRule.id == rule_id,
                                                 SuppressionRule.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if r is None:
        raise NotFound("Rule not found.")
    r.is_active = False
    audit.record(db, "suppression.disabled", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="suppression",
                 target_id=r.id)
    db.commit()
    return Message(message="Suppression rule disabled.")
