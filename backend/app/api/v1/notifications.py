"""Alert policies, recipients, notification history and test messages (C08)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import TenantContext, require
from app.core.errors import NotFound, ValidationFailed
from app.core.permissions import ALL_ROLES, P
from app.core.ratelimit import get_limiter
from app.db.base import utcnow
from app.db.session import get_db
from app.models import AlertPolicy, AlertRecipient, Notification, TenantMembership, Website, WebsiteGroup
from app.models.incidents import CATEGORIES
from app.schemas.common import Message, PageParams, paginate
from app.services import audit
from app.services.notifications import channel_status, queue_simple

router = APIRouter(prefix="/tenants/{tenant_id}", tags=["notifications"])


class RecipientIO(BaseModel):
    user_id: uuid.UUID | None = None
    role_key: str | None = None
    email: EmailStr | None = None
    whatsapp_number: str | None = Field(default=None, pattern=r"^\+[1-9]\d{7,14}$")
    whatsapp_consent: bool = False


class QuietHours(BaseModel):
    start: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    end: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    timezone: str = "Africa/Lagos"
    bypass_severity: str = Field(default="critical", pattern="^(critical|high|medium|low|informational)$")


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    min_severity: str = Field(default="medium", pattern="^(critical|high|medium|low|informational)$")
    categories: list[str] = Field(default_factory=list)
    website_ids: list[uuid.UUID] = Field(default_factory=list)
    group_ids: list[uuid.UUID] = Field(default_factory=list)
    channels: list[str] = Field(default_factory=lambda: ["email"], min_length=1)
    escalation_stage: int = Field(default=0, ge=0, le=5)
    escalation_delay_minutes: int = Field(default=0, ge=0, le=7 * 24 * 60)
    quiet_hours: QuietHours | None = None
    email_fallback: bool = True
    recipients: list[RecipientIO] = Field(default_factory=list, max_length=50)

    @field_validator("categories")
    @classmethod
    def _cats(cls, v: list[str]) -> list[str]:
        bad = [c for c in v if c not in CATEGORIES]
        if bad:
            raise ValueError(f"Unknown categories: {bad}")
        return v

    @field_validator("channels")
    @classmethod
    def _channels(cls, v: list[str]) -> list[str]:
        if any(c not in ("email", "whatsapp") for c in v):
            raise ValueError("Channels must be email and/or whatsapp.")
        return sorted(set(v))


def policy_dict(db: Session, p: AlertPolicy) -> dict:
    recips = db.execute(select(AlertRecipient).where(AlertRecipient.policy_id == p.id)).scalars()
    return {
        "id": str(p.id), "name": p.name, "enabled": p.enabled, "min_severity": p.min_severity,
        "categories": p.categories, "website_ids": [str(x) for x in p.website_ids],
        "group_ids": [str(x) for x in p.group_ids], "channels": p.channels, "escalation_stage": p.escalation_stage,
        "escalation_delay_minutes": p.escalation_delay_minutes, "quiet_hours": p.quiet_hours,
        "email_fallback": p.email_fallback,
        "recipients": [{"id": str(r.id), "user_id": str(r.user_id) if r.user_id else None, "role_key": r.role_key,
                        "email": r.email, "whatsapp_number": r.whatsapp_number,
                        "whatsapp_consent": r.whatsapp_opt_in_at is not None} for r in recips],
        "created_at": p.created_at,
    }


def _apply(db: Session, ctx: TenantContext, p: AlertPolicy, body: PolicyIn) -> None:
    for wid in body.website_ids:
        if not db.execute(select(Website.id).where(Website.id == wid, Website.tenant_id == ctx.tenant_id)).first():
            raise ValidationFailed("Website not found in this organisation.")
    for gid in body.group_ids:
        if not db.execute(select(WebsiteGroup.id).where(WebsiteGroup.id == gid, WebsiteGroup.tenant_id == ctx.tenant_id)).first():
            raise ValidationFailed("Group not found in this organisation.")
    for r in body.recipients:
        if not (r.user_id or r.role_key or r.email or r.whatsapp_number):
            raise ValidationFailed("Each recipient needs a user, role, email or WhatsApp number.")
        if r.role_key and (r.role_key not in ALL_ROLES or ALL_ROLES[r.role_key].scope != "tenant"):
            raise ValidationFailed("Unknown role.")
        if r.user_id and not db.execute(select(TenantMembership.id).where(
                TenantMembership.tenant_id == ctx.tenant_id, TenantMembership.user_id == r.user_id)).first():
            raise ValidationFailed("Recipient user is not a member of this organisation.")
        if r.whatsapp_number and not r.whatsapp_consent:
            raise ValidationFailed("WhatsApp recipients must have given consent to receive messages.")
    p.name, p.enabled, p.min_severity = body.name, body.enabled, body.min_severity
    p.categories, p.website_ids, p.group_ids = body.categories, body.website_ids, body.group_ids
    p.channels, p.escalation_stage, p.escalation_delay_minutes = body.channels, body.escalation_stage, body.escalation_delay_minutes
    p.quiet_hours = body.quiet_hours.model_dump() if body.quiet_hours else None
    p.email_fallback = body.email_fallback
    db.flush()
    for old in db.execute(select(AlertRecipient).where(AlertRecipient.policy_id == p.id)).scalars():
        db.delete(old)
    db.flush()
    now = utcnow()
    for r in body.recipients:
        db.add(AlertRecipient(tenant_id=ctx.tenant_id, policy_id=p.id, user_id=r.user_id, role_key=r.role_key,
                              email=r.email.lower() if r.email else None, whatsapp_number=r.whatsapp_number,
                              whatsapp_opt_in_at=now if r.whatsapp_number and r.whatsapp_consent else None))


@router.get("/alert-policies")
def list_policies(ctx: TenantContext = Depends(require(P.NOTIFICATIONS_READ)), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(AlertPolicy).where(AlertPolicy.tenant_id == ctx.tenant_id)
                      .order_by(AlertPolicy.escalation_stage, AlertPolicy.name)).scalars()
    return [policy_dict(db, p) for p in rows]


@router.post("/alert-policies", status_code=201)
def create_policy(body: PolicyIn, ctx: TenantContext = Depends(require(P.NOTIFICATIONS_MANAGE)),
                  db: Session = Depends(get_db)) -> dict:
    p = AlertPolicy(tenant_id=ctx.tenant_id, name=body.name)
    db.add(p)
    db.flush()
    _apply(db, ctx, p, body)
    audit.record(db, "alert_policy.created", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="alert_policy",
                 target_id=p.id, details={"name": p.name, "channels": p.channels, "min_severity": p.min_severity})
    db.commit()
    return policy_dict(db, p)


@router.put("/alert-policies/{policy_id}")
def update_policy(policy_id: uuid.UUID, body: PolicyIn, ctx: TenantContext = Depends(require(P.NOTIFICATIONS_MANAGE)),
                  db: Session = Depends(get_db)) -> dict:
    p = db.execute(select(AlertPolicy).where(AlertPolicy.id == policy_id, AlertPolicy.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if p is None:
        raise NotFound("Policy not found.")
    _apply(db, ctx, p, body)
    audit.record(db, "alert_policy.updated", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="alert_policy",
                 target_id=p.id)
    db.commit()
    return policy_dict(db, p)


@router.delete("/alert-policies/{policy_id}", response_model=Message)
def delete_policy(policy_id: uuid.UUID, ctx: TenantContext = Depends(require(P.NOTIFICATIONS_MANAGE)),
                  db: Session = Depends(get_db)) -> Message:
    p = db.execute(select(AlertPolicy).where(AlertPolicy.id == policy_id, AlertPolicy.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if p is None:
        raise NotFound("Policy not found.")
    db.delete(p)
    audit.record(db, "alert_policy.deleted", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="alert_policy",
                 target_id=policy_id)
    db.commit()
    return Message(message="Policy deleted.")


@router.get("/notifications")
def history(
    ctx: TenantContext = Depends(require(P.NOTIFICATIONS_READ)),
    db: Session = Depends(get_db),
    params: PageParams = Depends(),
    status: str | None = Query(None, max_length=16),
    channel: str | None = Query(None, pattern="^(email|whatsapp)$"),
) -> dict:
    q = select(Notification).where(Notification.tenant_id == ctx.tenant_id)
    if status:
        q = q.where(Notification.status == status)
    if channel:
        q = q.where(Notification.channel == channel)
    return paginate(db, q.order_by(Notification.created_at.desc()), params, lambda n: {
        "id": str(n.id), "channel": n.channel, "category": n.category, "recipient": n.recipient,
        "subject": n.subject, "status": n.status, "attempts": n.attempts, "max_attempts": n.max_attempts,
        "next_attempt_at": n.next_attempt_at, "last_error": n.last_error, "sent_at": n.sent_at,
        "incident_id": str(n.incident_id) if n.incident_id else None, "created_at": n.created_at,
        "is_fallback": n.fallback_for_id is not None or n.idempotency_key.startswith("fallback:"),
    })


@router.get("/notification-channels")
def channels(ctx: TenantContext = Depends(require(P.NOTIFICATIONS_READ))) -> dict:
    return channel_status()


class TestIn(BaseModel):
    channel: str = Field(pattern="^(email|whatsapp)$")
    recipient: str | None = Field(default=None, max_length=320)


@router.post("/notifications/test", status_code=202)
def send_test(body: TestIn, ctx: TenantContext = Depends(require(P.NOTIFICATIONS_MANAGE)),
              db: Session = Depends(get_db)) -> dict:
    get_limiter().hit(f"notify-test:{ctx.tenant_id}", 10, 3600)
    if body.channel == "email":
        recipient = (body.recipient or ctx.user.email).lower()
        allowed = {e for (e,) in db.execute(select(AlertRecipient.email).where(
            AlertRecipient.tenant_id == ctx.tenant_id, AlertRecipient.email.is_not(None))).all()} | {ctx.user.email}
        if recipient not in allowed:
            raise ValidationFailed("Test messages can only be sent to yourself or configured recipients.")
    else:
        recipient = body.recipient or ctx.user.phone or ""
        if not recipient:
            raise ValidationFailed("Add a WhatsApp number to your profile or provide a configured recipient.")
        allowed_wa = {n for (n,) in db.execute(select(AlertRecipient.whatsapp_number).where(
            AlertRecipient.tenant_id == ctx.tenant_id, AlertRecipient.whatsapp_opt_in_at.is_not(None))).all()}
        if recipient != ctx.user.phone and recipient not in allowed_wa:
            raise ValidationFailed("Test messages can only be sent to yourself or consenting recipients.")
    n = queue_simple(db, tenant_id=ctx.tenant_id, channel=body.channel, recipient=recipient, category="test",
                     subject="CyberWatch test notification",
                     body=f"This is a test notification from TrustData CyberWatch for {ctx.tenant.name}.",
                     template="test", idempotency_key=f"test:{ctx.tenant_id}:{uuid.uuid4()}")
    audit.record(db, "notification.test_sent", actor=ctx.actor(), tenant_id=ctx.tenant_id,
                 details={"channel": body.channel})
    db.commit()
    return {"notification_id": str(n.id) if n else None, "status": "queued",
            "channels": channel_status()}

