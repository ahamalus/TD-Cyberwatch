"""Platform administration (A01–A13) and monitoring operations (M01–M12).

Platform routes never expose customer monitoring content (file paths, hashes,
evidence) across tenants. Detailed customer data requires a managed-service
grant and is accessed through the ordinary tenant routes, where it is
audited with the grant ID.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app.api.deps import PlatformContext, require_platform
from app.api.v1.monitoring import job_dict
from app.api.v1.tenants import audit_rows_out, grant_out
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.permissions import ALL_ROLES, GRANTABLE_TENANT_PERMISSIONS, P
from app.db.base import utcnow
from app.models import (
    AuditEvent,
    ConnectorDefinition,
    HostingAccount,
    Incident,
    ManagedServiceGrant,
    Notification,
    Payment,
    Plan,
    PlatformRoleAssignment,
    PlatformSetting,
    RolePermission,
    ScanJob,
    Subscription,
    Tenant,
    TenantMembership,
    User,
    WebhookEvent,
    Website,
)
from app.models.incidents import OPEN_STATUSES, SEVERITIES
from app.monitoring import jobs
from app.schemas.common import Message, PageParams, paginate
from app.services import audit
from app.services.health import system_health

admin = APIRouter(prefix="/admin", tags=["platform-admin"])
ops = APIRouter(prefix="/ops", tags=["operations"])

PLATFORM_ROLE_KEYS = {k for k, r in ALL_ROLES.items() if r.scope == "platform"}


# ======================================================================
# Administration
# ======================================================================


@admin.get("/overview")
def overview(pc: PlatformContext = Depends(require_platform(P.PLATFORM_OVERVIEW))) -> dict:
    db = pc.db
    now = utcnow()
    since = now - timedelta(hours=24)
    tenants = dict(db.execute(select(Tenant.status, func.count()).where(Tenant.is_demo.is_(False))
                              .group_by(Tenant.status)).all())
    subs = dict(db.execute(select(Subscription.status, func.count()).where(Subscription.is_current.is_(True))
                           .group_by(Subscription.status)).all())
    month = func.date_trunc(text("'month'"), Payment.paid_at)
    revenue = db.execute(
        select(month, Payment.currency, func.sum(Payment.amount_minor), func.count())
        .where(Payment.status == "success", Payment.verified_at.is_not(None), Payment.paid_at >= now - timedelta(days=186))
        .group_by(month, Payment.currency)
        .order_by(month)
    ).all()
    return {
        "tenants": tenants,
        "demo_tenants": db.execute(select(func.count()).select_from(Tenant).where(Tenant.is_demo.is_(True))).scalar_one(),
        "users": db.execute(select(func.count()).select_from(User)).scalar_one(),
        "subscriptions": subs,
        "websites": db.execute(select(func.count()).select_from(Website)).scalar_one(),
        "hosting_accounts": dict(db.execute(select(HostingAccount.status, func.count()).group_by(HostingAccount.status)).all()),
        "jobs_24h": dict(db.execute(select(ScanJob.status, func.count()).where(ScanJob.queued_at >= since)
                                    .group_by(ScanJob.status)).all()),
        "open_incidents_by_severity": dict(db.execute(select(Incident.severity, func.count())
                                                      .where(Incident.status.in_(OPEN_STATUSES)).group_by(Incident.severity)).all()),
        "notifications_24h": dict(db.execute(select(Notification.status, func.count()).where(Notification.created_at >= since)
                                             .group_by(Notification.status)).all()),
        "revenue_verified": [{"month": m.date().isoformat() if m else None, "currency": c, "amount_minor": int(a or 0),
                              "payments": n} for m, c, a, n in revenue],
        "health": {k: v for k, v in system_health(db).items() if k in ("database", "redis", "alerts", "scheduler")},
    }


@admin.get("/tenants")
def list_tenants(pc: PlatformContext = Depends(require_platform(P.PLATFORM_TENANTS_READ)), params: PageParams = Depends(),
                 q: str | None = Query(None, max_length=200), status: str | None = Query(None, max_length=16)) -> dict:
    db = pc.db
    query = select(Tenant)
    if q:
        query = query.where(or_(Tenant.name.ilike(f"%{q}%"), Tenant.slug.ilike(f"%{q}%")))
    if status:
        query = query.where(Tenant.status == status)

    def row(t: Tenant) -> dict:
        sub = db.execute(select(Subscription, Plan).join(Plan, Plan.id == Subscription.plan_id).where(
            Subscription.tenant_id == t.id, Subscription.is_current.is_(True))).first()
        return {
            "id": str(t.id), "name": t.name, "slug": t.slug, "status": t.status, "is_demo": t.is_demo,
            "country": t.country, "created_at": t.created_at, "contact_email": t.contact_email,
            "plan": sub[1].name if sub else None, "subscription_status": sub[0].status if sub else None,
            "websites": db.execute(select(func.count()).select_from(Website).where(Website.tenant_id == t.id)).scalar_one(),
            "hosting_accounts": db.execute(select(func.count()).select_from(HostingAccount).where(HostingAccount.tenant_id == t.id)).scalar_one(),
            "members": db.execute(select(func.count()).select_from(TenantMembership).where(TenantMembership.tenant_id == t.id)).scalar_one(),
            "open_incidents": db.execute(select(func.count()).select_from(Incident).where(
                Incident.tenant_id == t.id, Incident.status.in_(OPEN_STATUSES))).scalar_one(),
        }

    return paginate(db, query.order_by(Tenant.name), params, row)


class TenantStatusIn(BaseModel):
    status: str = Field(pattern="^(active|suspended|deactivated)$")
    reason: str = Field(min_length=5, max_length=1000)
    confirm: bool


@admin.post("/tenants/{tenant_id}/status")
def set_tenant_status(tenant_id: uuid.UUID, body: TenantStatusIn,
                      pc: PlatformContext = Depends(require_platform(P.PLATFORM_TENANTS_MANAGE))) -> dict:
    if not body.confirm:
        raise ValidationFailed("Confirmation is required for this action.")
    t = pc.db.get(Tenant, tenant_id)
    if t is None:
        raise NotFound("Tenant not found.")
    old = t.status
    t.status, t.status_reason = body.status, body.reason
    audit.record(pc.db, "admin.tenant_status_changed", actor=pc.actor(), tenant_id=t.id, target_type="tenant",
                 target_id=t.id, details={"from": old, "to": body.status, "reason": body.reason})
    pc.db.commit()
    return {"id": str(t.id), "status": t.status, "note": "Customer data is retained; monitoring pauses while not active."}


# ---------------------------------------------------------------- staff & roles


@admin.get("/roles")
def roles(pc: PlatformContext = Depends(require_platform(P.PLATFORM_OVERVIEW))) -> list[dict]:
    perms: dict[str, list[str]] = {}
    for rk, code in pc.db.execute(select(RolePermission.role_key, RolePermission.permission_code)).all():
        perms.setdefault(rk, []).append(code)
    return [{"key": r.key, "name": r.name, "scope": r.scope, "description": r.description,
             "permissions": sorted(perms.get(r.key, []))} for r in ALL_ROLES.values()]


@admin.get("/staff")
def list_staff(pc: PlatformContext = Depends(require_platform(P.PLATFORM_USERS_MANAGE))) -> list[dict]:
    rows = pc.db.execute(select(User).where(User.is_platform_staff.is_(True)).order_by(User.full_name)).scalars()
    return [{"id": str(u.id), "email": u.email, "full_name": u.full_name, "is_active": u.is_active,
             "mfa_enabled": u.mfa_enabled, "roles": sorted(a.role_key for a in u.platform_roles),
             "last_login_at": u.last_login_at} for u in rows]


class StaffIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=200)
    roles: list[str] = Field(min_length=1)


@admin.post("/staff", status_code=201)
def create_staff(body: StaffIn, pc: PlatformContext = Depends(require_platform(P.PLATFORM_USERS_MANAGE))) -> dict:
    from app.core.config import get_settings
    from app.services.auth import create_email_token
    from app.services.notifications import queue_simple

    db = pc.db
    if set(body.roles) - PLATFORM_ROLE_KEYS:
        raise ValidationFailed("Unknown platform role.")
    email = body.email.lower()
    if db.execute(select(User.id).where(User.email == email)).first():
        raise Conflict("A user with this email already exists.")
    u = User(email=email, full_name=body.full_name, is_platform_staff=True)
    db.add(u)
    db.flush()
    for r in body.roles:
        db.add(PlatformRoleAssignment(user_id=u.id, role_key=r, granted_by=pc.principal.user.id))
    token = create_email_token(db, u, "password_reset")
    s = get_settings()
    queue_simple(db, tenant_id=None, channel="email", recipient=email, category="account",
                 subject=f"Your {s.product_name} staff account",
                 body=f"An administrator created a staff account for you. Set your password: "
                      f"{s.public_base_url}/reset-password?token={token}\n\nYou must enrol multi-factor authentication "
                      "before platform functions become available.",
                 idempotency_key=f"staff-invite:{u.id}")
    audit.record(db, "admin.staff_created", actor=pc.actor(), target_type="user", target_id=u.id,
                 details={"email": email, "roles": body.roles})
    db.commit()
    return {"id": str(u.id)}


class RolesIn(BaseModel):
    roles: list[str]


@admin.put("/staff/{user_id}/roles")
def set_staff_roles(user_id: uuid.UUID, body: RolesIn,
                    pc: PlatformContext = Depends(require_platform(P.PLATFORM_USERS_MANAGE))) -> dict:
    db = pc.db
    if set(body.roles) - PLATFORM_ROLE_KEYS:
        raise ValidationFailed("Unknown platform role.")
    if user_id == pc.principal.user.id:
        raise ValidationFailed("You cannot change your own platform roles.")
    u = db.get(User, user_id)
    if u is None or not u.is_platform_staff:
        raise NotFound("Staff member not found.")
    before = sorted(a.role_key for a in u.platform_roles)
    u.platform_roles.clear()
    db.flush()
    for r in body.roles:
        u.platform_roles.append(PlatformRoleAssignment(user_id=u.id, role_key=r, granted_by=pc.principal.user.id))
    audit.record(db, "admin.staff_roles_changed", actor=pc.actor(), target_type="user", target_id=u.id,
                 details={"before": before, "after": sorted(body.roles)})
    db.commit()
    return {"id": str(u.id), "roles": sorted(body.roles)}


# ---------------------------------------------------------------- connectors


@admin.get("/connectors")
def admin_connectors(pc: PlatformContext = Depends(require_platform(P.PLATFORM_OVERVIEW))) -> list[dict]:
    db = pc.db
    since = utcnow() - timedelta(days=7)
    stats = {(c, s): n for c, s, n in db.execute(
        select(HostingAccount.connector_type, ScanJob.status, func.count())
        .join(HostingAccount, HostingAccount.id == ScanJob.hosting_account_id)
        .where(ScanJob.queued_at >= since).group_by(HostingAccount.connector_type, ScanJob.status)).all()}
    out = []
    for c in db.execute(select(ConnectorDefinition).order_by(ConnectorDefinition.key)).scalars():
        accounts = dict(db.execute(select(HostingAccount.status, func.count()).where(
            HostingAccount.connector_type == c.key).group_by(HostingAccount.status)).all())
        ok = stats.get((c.key, "succeeded"), 0)
        failed = stats.get((c.key, "failed"), 0)
        out.append({"key": c.key, "name": c.name, "status": c.status, "adapter_version": c.adapter_version,
                    "description": c.description, "connect_timeout_seconds": c.connect_timeout_seconds,
                    "io_timeout_seconds": c.io_timeout_seconds, "max_retries": c.max_retries,
                    "min_poll_interval_minutes": c.min_poll_interval_minutes,
                    "max_concurrency_per_host": c.max_concurrency_per_host, "notes": c.capability_notes,
                    "accounts_by_status": accounts,
                    "job_error_rate_7d": round(failed / (ok + failed), 3) if (ok + failed) else None})
    return out


class ConnectorPatch(BaseModel):
    status: str | None = Field(default=None, pattern="^(implemented|disabled)$")
    connect_timeout_seconds: float | None = Field(default=None, ge=2, le=120)
    io_timeout_seconds: float | None = Field(default=None, ge=5, le=600)
    max_retries: int | None = Field(default=None, ge=0, le=10)
    min_poll_interval_minutes: int | None = Field(default=None, ge=1, le=10080)
    max_concurrency_per_host: int | None = Field(default=None, ge=1, le=20)


@admin.patch("/connectors/{key}")
def patch_connector(key: str, body: ConnectorPatch,
                    pc: PlatformContext = Depends(require_platform(P.PLATFORM_CONNECTORS_MANAGE))) -> dict:
    from app.connectors.registry import is_implemented

    c = pc.db.get(ConnectorDefinition, key)
    if c is None:
        raise NotFound("Connector not found.")
    changes = body.model_dump(exclude_none=True)
    if changes.get("status") == "implemented" and not is_implemented(key):
        raise ValidationFailed("This connector has no implementation and cannot be enabled.")
    for k, v in changes.items():
        setattr(c, k, v)
    audit.record(pc.db, "admin.connector_updated", actor=pc.actor(), target_type="connector", target_id=key,
                 details=changes)
    pc.db.commit()
    return {"key": c.key, **changes}


# ---------------------------------------------------------------- plans


class PlanIn(BaseModel):
    key: str = Field(pattern="^[a-z0-9_]{2,40}$")
    name: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=2000)
    currency: str = Field(default="NGN", pattern="^[A-Z]{3}$")
    price_monthly_minor: int | None = Field(default=None, ge=0)
    price_annual_minor: int | None = Field(default=None, ge=0)
    entitlements: dict
    is_public: bool = True
    is_active: bool = True
    sort_order: int = 0
    contact_sales: bool = False


REQUIRED_ENTITLEMENTS = {"max_websites", "max_hosting_accounts", "max_users", "min_file_scan_interval_minutes",
                         "min_availability_interval_minutes", "retention_days", "notifications_per_month"}


@admin.get("/plans")
def admin_plans(pc: PlatformContext = Depends(require_platform(P.PLATFORM_PLANS_MANAGE))) -> list[dict]:
    rows = pc.db.execute(select(Plan).order_by(Plan.sort_order)).scalars()
    return [{"id": str(p.id), "key": p.key, "name": p.name, "description": p.description, "currency": p.currency,
             "price_monthly_minor": p.price_monthly_minor, "price_annual_minor": p.price_annual_minor,
             "entitlements": p.entitlements, "is_public": p.is_public, "is_active": p.is_active,
             "sort_order": p.sort_order, "contact_sales": p.contact_sales,
             "subscribers": pc.db.execute(select(func.count()).select_from(Subscription).where(
                 Subscription.plan_id == p.id, Subscription.is_current.is_(True))).scalar_one()} for p in rows]


@admin.put("/plans/{key}")
def upsert_plan(key: str, body: PlanIn, pc: PlatformContext = Depends(require_platform(P.PLATFORM_PLANS_MANAGE))) -> dict:
    if body.key != key:
        raise ValidationFailed("Plan key mismatch.")
    missing = REQUIRED_ENTITLEMENTS - set(body.entitlements)
    if missing:
        raise ValidationFailed("Missing entitlement values.", details=sorted(missing))
    for k in REQUIRED_ENTITLEMENTS:
        if not isinstance(body.entitlements[k], int) or body.entitlements[k] < 0:
            raise ValidationFailed(f"Entitlement {k} must be a non-negative integer.")
    p = pc.db.execute(select(Plan).where(Plan.key == key)).scalar_one_or_none()
    before = None
    if p is None:
        p = Plan(**body.model_dump())
        pc.db.add(p)
    else:
        before = {"price_monthly_minor": p.price_monthly_minor, "price_annual_minor": p.price_annual_minor,
                  "entitlements": p.entitlements, "is_active": p.is_active}
        for k, v in body.model_dump().items():
            setattr(p, k, v)
    audit.record(pc.db, "admin.plan_saved", actor=pc.actor(), target_type="plan", target_id=key,
                 details={"before": before, "after": body.model_dump()})
    pc.db.commit()
    return {"key": key}


# ---------------------------------------------------------------- payments


@admin.get("/payments")
def admin_payments(pc: PlatformContext = Depends(require_platform(P.PLATFORM_PAYMENTS_READ)), params: PageParams = Depends(),
                   status: str | None = Query(None, max_length=16)) -> dict:
    db = pc.db
    q = select(Payment)
    if status:
        q = q.where(Payment.status == status)
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    return paginate(db, q.order_by(Payment.created_at.desc()), params, lambda p: {
        "id": str(p.id), "tenant": names.get(p.tenant_id), "tenant_id": str(p.tenant_id), "reference": p.reference,
        "amount_minor": p.amount_minor, "currency": p.currency, "status": p.status, "purpose": p.purpose,
        "verified_at": p.verified_at, "paid_at": p.paid_at, "channel": p.channel,
        "gateway_response": p.gateway_response, "created_at": p.created_at,
        "reconciled": p.status == "success" and p.verified_at is not None and p.verification.get("amount") == p.amount_minor,
    })


@admin.get("/webhooks")
def admin_webhooks(pc: PlatformContext = Depends(require_platform(P.PLATFORM_PAYMENTS_READ)),
                   params: PageParams = Depends()) -> dict:
    q = select(WebhookEvent).order_by(WebhookEvent.received_at.desc())
    return paginate(pc.db, q, params, lambda w: {
        "id": str(w.id), "provider": w.provider, "event_type": w.event_type, "status": w.status,
        "signature_valid": w.signature_valid, "received_at": w.received_at, "processed_at": w.processed_at,
        "error": w.error})


@admin.post("/payments/{payment_id}/reverify")
def reverify_payment(payment_id: uuid.UUID,
                     pc: PlatformContext = Depends(require_platform(P.PLATFORM_PAYMENTS_MANAGE))) -> dict:
    from app.services import billing

    p = pc.db.get(Payment, payment_id)
    if p is None:
        raise NotFound("Payment not found.")
    p = billing.verify_reference(pc.db, p.tenant_id, p.reference, pc.actor())
    pc.db.commit()
    return {"status": p.status, "verified_at": p.verified_at}


# ---------------------------------------------------------------- audit


@admin.get("/audit")
def admin_audit(pc: PlatformContext = Depends(require_platform(P.PLATFORM_AUDIT_READ)), params: PageParams = Depends(),
                action: str | None = Query(None, max_length=80), category: str | None = Query(None, max_length=24),
                tenant_id: uuid.UUID | None = None, actor_user_id: uuid.UUID | None = None,
                outcome: str | None = Query(None, max_length=12), since: datetime | None = None) -> dict:
    q = select(AuditEvent)
    if action:
        q = q.where(AuditEvent.action.ilike(f"{action}%"))
    if category:
        q = q.where(AuditEvent.category == category)
    if tenant_id:
        q = q.where(AuditEvent.tenant_id == tenant_id)
    if actor_user_id:
        q = q.where(AuditEvent.actor_user_id == actor_user_id)
    if outcome:
        q = q.where(AuditEvent.outcome == outcome)
    if since:
        q = q.where(AuditEvent.occurred_at >= since)
    page = paginate(pc.db, q.order_by(AuditEvent.seq.desc()), params)
    page["items"] = audit_rows_out(pc.db, page["items"])
    return page


@admin.get("/audit/verify")
def verify_audit(pc: PlatformContext = Depends(require_platform(P.PLATFORM_AUDIT_READ))) -> dict:
    res = audit.verify_chain(pc.db)
    return {"valid": res.valid, "events_checked": res.events_checked, "first_invalid_seq": res.first_invalid_seq,
            "reason": res.reason}


# ---------------------------------------------------------------- settings, health, messaging


SETTING_KEYS = {
    "retention_policy": "Default retention and cleanup policy.",
    "feature_flags": "Feature flags (JSON object of booleans).",
    "rate_limits": "Override rate limits.",
    "security": "Security settings (e.g. session lifetimes) — informational; env settings take precedence.",
    "job_scheduling": "Scheduler configuration.",
    "whatsapp_templates": "Approved WhatsApp template names per message type.",
    "backup_status": "Reported by the backup job.",
}


@admin.get("/settings")
def get_settings_api(pc: PlatformContext = Depends(require_platform(P.PLATFORM_CONFIG_MANAGE))) -> dict:
    from app.core.config import get_settings

    s = get_settings()
    rows = {r.key: {"value": r.value, "updated_at": r.updated_at} for r in pc.db.execute(select(PlatformSetting)).scalars()}
    return {
        "editable": {k: {"description": d, **rows.get(k, {"value": None})} for k, d in SETTING_KEYS.items()},
        "environment": {
            "environment": s.environment, "session_ttl_minutes": s.session_ttl_minutes,
            "session_idle_minutes": s.session_idle_minutes, "require_platform_mfa": s.require_platform_mfa,
            "tenant_max_concurrent_jobs": s.tenant_max_concurrent_jobs, "job_max_attempts": s.job_max_attempts,
            "scan_max_file_bytes": s.scan_max_file_bytes, "scan_max_total_bytes": s.scan_max_total_bytes,
            "scan_max_files": s.scan_max_files, "trial_days": s.trial_days, "grace_period_days": s.grace_period_days,
            "allowed_sftp_ports": s.allowed_sftp_ports, "allowed_cpanel_ports": s.allowed_cpanel_ports,
            "allowed_http_ports": s.allowed_http_ports,
            "outbound_private_overrides": bool(s.outbound_allow_cidrs),
        },
    }


class SettingIn(BaseModel):
    value: dict


@admin.put("/settings/{key}")
def put_setting(key: str, body: SettingIn, pc: PlatformContext = Depends(require_platform(P.PLATFORM_CONFIG_MANAGE))) -> dict:
    if key not in SETTING_KEYS or key == "backup_status":
        raise ValidationFailed("Unknown or read-only setting.")
    row = pc.db.get(PlatformSetting, key)
    before = row.value if row else None
    if row is None:
        row = PlatformSetting(key=key, value=body.value, description=SETTING_KEYS[key])
        pc.db.add(row)
    row.value, row.updated_by, row.updated_at = body.value, pc.principal.user.id, utcnow()
    audit.record(pc.db, "admin.setting_changed", actor=pc.actor(), target_type="setting", target_id=key,
                 details={"before": before, "after": body.value})
    pc.db.commit()
    return {"key": key, "value": row.value}


@admin.get("/health")
def admin_health(pc: PlatformContext = Depends(require_platform(P.PLATFORM_HEALTH_READ))) -> dict:
    return system_health(pc.db)


@admin.get("/messaging")
def messaging(pc: PlatformContext = Depends(require_platform(P.PLATFORM_MESSAGING_MANAGE)), params: PageParams = Depends(),
              status: str = Query("failed", pattern="^(failed|pending|unconfigured|suppressed|sent)$")) -> dict:
    from app.services.notifications import WHATSAPP_TEMPLATES, channel_status

    db = pc.db
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    page = paginate(db, select(Notification).where(Notification.status == status).order_by(Notification.created_at.desc()),
                    params, lambda n: {"id": str(n.id), "tenant": names.get(n.tenant_id), "channel": n.channel,
                                       "category": n.category, "status": n.status, "attempts": n.attempts,
                                       "last_error": n.last_error, "created_at": n.created_at,
                                       "next_attempt_at": n.next_attempt_at})
    page["channels"] = channel_status()
    page["whatsapp_templates"] = {k: {"name": v[0], "language": v[1], "params": v[2]} for k, v in WHATSAPP_TEMPLATES.items()}
    return page


@admin.post("/notifications/{notification_id}/retry", response_model=Message)
def retry_notification(notification_id: uuid.UUID,
                       pc: PlatformContext = Depends(require_platform(P.PLATFORM_MESSAGING_MANAGE))) -> Message:
    n = pc.db.get(Notification, notification_id)
    if n is None:
        raise NotFound("Notification not found.")
    if n.status not in ("failed", "unconfigured"):
        raise ValidationFailed("Only failed or unconfigured notifications can be retried.")
    n.status, n.next_attempt_at, n.max_attempts = "pending", utcnow(), n.attempts + 3
    audit.record(pc.db, "admin.notification_retried", actor=pc.actor(), tenant_id=n.tenant_id,
                 target_type="notification", target_id=n.id)
    pc.db.commit()
    return Message(message="Notification re-queued.")


@admin.get("/analytics")
def analytics(pc: PlatformContext = Depends(require_platform(P.PLATFORM_OVERVIEW)), days: int = Query(30, ge=1, le=180)) -> dict:
    db = pc.db
    since = utcnow() - timedelta(days=days)
    d = func.date_trunc(text("'day'"), ScanJob.queued_at)
    scans = db.execute(select(d, ScanJob.job_type, ScanJob.status, func.count(),
                              func.avg(func.extract("epoch", ScanJob.finished_at - ScanJob.started_at)))
                       .where(ScanJob.queued_at >= since).group_by(d, ScanJob.job_type, ScanJob.status).order_by(d)).all()
    di = func.date_trunc(text("'day'"), Incident.first_detected_at)
    incidents = db.execute(select(di, Incident.severity, func.count()).where(Incident.first_detected_at >= since)
                           .group_by(di, Incident.severity).order_by(di)).all()
    dn = func.date_trunc(text("'day'"), Notification.created_at)
    notifs = db.execute(select(dn, Notification.channel, Notification.status, func.count())
                        .where(Notification.created_at >= since).group_by(dn, Notification.channel, Notification.status)
                        .order_by(dn)).all()
    usage = []
    for t, plan in db.execute(select(Tenant, Plan).join(Subscription, Subscription.tenant_id == Tenant.id)
                              .join(Plan, Plan.id == Subscription.plan_id).where(Subscription.is_current.is_(True))).all():
        sites = db.execute(select(func.count()).select_from(Website).where(Website.tenant_id == t.id)).scalar_one()
        usage.append({"tenant": t.name, "plan": plan.name, "websites": sites,
                      "limit": plan.entitlements.get("max_websites"),
                      "over_limit": sites > int(plan.entitlements.get("max_websites", 0))})
    return {
        "scans": [{"day": a.date().isoformat(), "job_type": b, "status": c, "count": n, "avg_seconds": round(float(s or 0), 1)}
                  for a, b, c, n, s in scans],
        "incidents": [{"day": a.date().isoformat(), "severity": b, "count": n} for a, b, n in incidents],
        "notifications": [{"day": a.date().isoformat(), "channel": b, "status": c, "count": n} for a, b, c, n in notifs],
        "tenant_usage": usage,
    }


# ---------------------------------------------------------------- managed-service grants


class GrantRequestIn(BaseModel):
    tenant_id: uuid.UUID
    grantee_user_id: uuid.UUID | None = None
    permissions: list[str] = Field(min_length=1)
    reason: str = Field(min_length=10, max_length=2000)
    duration_hours: int = Field(default=72, ge=1, le=24 * 90)
    customer_approval_reference: str | None = Field(default=None, max_length=200)


@admin.get("/grants")
def admin_grants(pc: PlatformContext = Depends(require_platform()), status: str | None = Query(None, max_length=16)) -> list[dict]:
    q = select(ManagedServiceGrant).order_by(ManagedServiceGrant.created_at.desc()).limit(200)
    if P.GRANTS_ISSUE not in pc.principal.platform_permissions:
        q = q.where(ManagedServiceGrant.grantee_user_id == pc.principal.user.id)
    if status:
        q = q.where(ManagedServiceGrant.status == status)
    names = dict(pc.db.execute(select(Tenant.id, Tenant.name)).all())
    return [{**grant_out(pc.db, g).model_dump(mode="json"), "tenant_id": str(g.tenant_id),
             "tenant_name": names.get(g.tenant_id)} for g in pc.db.execute(q).scalars()]


@admin.post("/grants", status_code=201)
def request_grant(body: GrantRequestIn, pc: PlatformContext = Depends(require_platform())) -> dict:
    perms = pc.principal.platform_permissions
    if not ({P.GRANTS_REQUEST, P.GRANTS_ISSUE} & perms):
        raise ValidationFailed("You cannot request managed-service access.")
    grantee = body.grantee_user_id or pc.principal.user.id
    if grantee != pc.principal.user.id and P.GRANTS_ISSUE not in perms:
        raise ValidationFailed("You can only request access for yourself.")
    u = pc.db.get(User, grantee)
    if u is None or not u.is_platform_staff:
        raise ValidationFailed("Grantee must be a Trust Data staff member.")
    if pc.db.get(Tenant, body.tenant_id) is None:
        raise NotFound("Tenant not found.")
    bad = set(body.permissions) - GRANTABLE_TENANT_PERMISSIONS
    if bad:
        raise ValidationFailed("Some permissions cannot be granted to staff.", details=sorted(bad))
    now = utcnow()
    g = ManagedServiceGrant(tenant_id=body.tenant_id, grantee_user_id=grantee, permissions=sorted(set(body.permissions)),
                            reason=body.reason, requested_by=pc.principal.user.id,
                            expires_at=now + timedelta(hours=body.duration_hours), status="requested")
    # A platform administrator may activate a grant directly only by recording
    # the customer's out-of-band approval (e.g. a signed managed-service order).
    if body.customer_approval_reference and P.GRANTS_ISSUE in perms:
        if grantee == pc.principal.user.id:
            raise ValidationFailed("Administrators cannot issue a grant to themselves; ask another administrator.")
        g.status, g.approved_by, g.approved_at, g.starts_at = "active", pc.principal.user.id, now, now
        g.customer_approval_reference = body.customer_approval_reference
    pc.db.add(g)
    pc.db.flush()
    audit.record(pc.db, "grant.issued" if g.status == "active" else "grant.requested", actor=pc.actor(),
                 tenant_id=body.tenant_id, target_type="grant", target_id=g.id,
                 details={"grantee": str(grantee), "permissions": g.permissions, "reason": body.reason,
                          "customer_approval_reference": body.customer_approval_reference})
    pc.db.commit()
    return {"id": str(g.id), "status": g.status, "expires_at": g.expires_at}


# ======================================================================
# Monitoring operations
# ======================================================================


@ops.get("/overview")
def ops_overview(pc: PlatformContext = Depends(require_platform(P.OPS_JOBS_READ))) -> dict:
    db = pc.db
    now = utcnow()
    since = now - timedelta(hours=24)
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    counts = dict(db.execute(select(ScanJob.status, func.count()).where(
        or_(ScanJob.status.in_(["queued", "running"]), ScanJob.finished_at >= since)).group_by(ScanJob.status)).all())
    health = system_health(db)
    hi = []
    if P.OPS_INCIDENTS_READ in pc.principal.platform_permissions:
        hi = [{"id": str(i.id), "tenant": names.get(i.tenant_id), "reference": i.reference, "severity": i.severity,
               "category": i.category, "status": i.status, "first_detected_at": i.first_detected_at,
               "last_observed_at": i.last_observed_at, "is_demo": i.is_demo}
              for i in db.execute(select(Incident).where(Incident.status.in_(OPEN_STATUSES),
                                                         Incident.severity.in_(["critical", "high"]))
                                  .order_by(Incident.last_observed_at.desc()).limit(15)).scalars()]
    new_findings = dict(db.execute(select(Incident.severity, func.count()).where(Incident.first_detected_at >= since)
                                   .group_by(Incident.severity)).all())
    failing_accounts = db.execute(select(func.count()).select_from(HostingAccount).where(
        HostingAccount.status.in_(["auth_failed", "error", "disconnected", "expired"]))).scalar_one()
    return {
        "jobs": {"queued": counts.get("queued", 0), "running": counts.get("running", 0),
                 "failed_24h": counts.get("failed", 0), "succeeded_24h": counts.get("succeeded", 0),
                 "partial_24h": counts.get("partial", 0), "stale_running": health["stale_running_jobs"]},
        "new_findings_24h": {s: new_findings.get(s, 0) for s in SEVERITIES},
        "high_priority_incidents": hi,
        "notification_failures_24h": health["notifications_24h"].get("failed", 0),
        "failing_connections": failing_accounts,
        "workers": health["workers"],
        "queues": health["redis"].get("queues", {}),
        "scheduler": health["scheduler"],
        "alerts": health["alerts"],
    }


@ops.get("/jobs")
def ops_jobs(pc: PlatformContext = Depends(require_platform(P.OPS_JOBS_READ)), params: PageParams = Depends(),
             status: str | None = Query(None, max_length=16), job_type: str | None = Query(None, max_length=32),
             tenant_id: uuid.UUID | None = None) -> dict:
    db = pc.db
    q = select(ScanJob)
    if status:
        q = q.where(ScanJob.status == status)
    if job_type:
        q = q.where(ScanJob.job_type == job_type)
    if tenant_id:
        q = q.where(ScanJob.tenant_id == tenant_id)
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())

    def row(j: ScanJob) -> dict:
        d = job_dict(j)
        # Operators see job metadata but not customer inventory details.
        d["result_summary"] = {k: v for k, v in (j.result_summary or {}).items()
                               if k in ("files_seen", "files_hashed", "errors", "limits_hit", "changes", "ok",
                                        "outcome", "http_status", "deletions_unverified")}
        d["tenant"] = names.get(j.tenant_id)
        d["tenant_id"] = str(j.tenant_id)
        return d

    return paginate(db, q.order_by(ScanJob.queued_at.desc()), params, row)


def _ops_job(db: Session, job_id: uuid.UUID) -> ScanJob:
    j = db.execute(select(ScanJob).where(ScanJob.id == job_id).with_for_update()).scalar_one_or_none()
    if j is None:
        raise NotFound("Job not found.")
    return j


@ops.post("/jobs/{job_id}/retry")
def ops_retry(job_id: uuid.UUID, pc: PlatformContext = Depends(require_platform(P.OPS_JOBS_MANAGE))) -> dict:
    j = _ops_job(pc.db, job_id)
    new, created = jobs.retry_job(pc.db, j, pc.actor())
    pc.db.commit()
    if created:
        jobs.dispatch(new)
    return {"job_id": str(new.id), "created": created}


@ops.post("/jobs/{job_id}/cancel")
def ops_cancel(job_id: uuid.UUID, pc: PlatformContext = Depends(require_platform(P.OPS_JOBS_MANAGE))) -> dict:
    j = _ops_job(pc.db, job_id)
    if j.status not in ("queued", "running"):
        raise ValidationFailed("Only queued or running jobs can be cancelled.")
    jobs.request_cancel(pc.db, j, pc.actor())
    pc.db.commit()
    return {"job_id": str(j.id), "status": j.status, "cancel_requested": j.cancel_requested}


@ops.get("/incidents")
def ops_incidents(pc: PlatformContext = Depends(require_platform(P.OPS_INCIDENTS_READ)), params: PageParams = Depends(),
                  severity: list[str] | None = Query(None), category: str | None = Query(None, max_length=32),
                  tenant_id: uuid.UUID | None = None, open_only: bool = True) -> dict:
    db = pc.db
    q = select(Incident)
    if open_only:
        q = q.where(Incident.status.in_(OPEN_STATUSES))
    if severity:
        q = q.where(Incident.severity.in_(severity))
    if category:
        q = q.where(Incident.category == category)
    if tenant_id:
        q = q.where(Incident.tenant_id == tenant_id)
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    my_grants = {g for (g,) in db.execute(select(ManagedServiceGrant.tenant_id).where(
        ManagedServiceGrant.grantee_user_id == pc.principal.user.id, ManagedServiceGrant.status == "active",
        ManagedServiceGrant.expires_at > utcnow())).all()}
    return paginate(db, q.order_by(Incident.last_observed_at.desc()), params, lambda i: {
        "id": str(i.id), "tenant_id": str(i.tenant_id), "tenant": names.get(i.tenant_id), "reference": i.reference,
        "severity": i.severity, "category": i.category, "finding_class": i.finding_class, "status": i.status,
        "first_detected_at": i.first_detected_at, "last_observed_at": i.last_observed_at,
        "occurrence_count": i.occurrence_count, "is_demo": i.is_demo,
        # Titles can contain customer file paths: only shown with an active grant.
        "title": i.title if i.tenant_id in my_grants else None,
        "has_grant": i.tenant_id in my_grants,
    })


class OpsActionIn(BaseModel):
    action: str = Field(min_length=3, max_length=200)
    note: str = Field(min_length=3, max_length=5000)


@ops.post("/incidents/{incident_id}/actions")
def ops_incident_action(incident_id: uuid.UUID, body: OpsActionIn,
                        pc: PlatformContext = Depends(require_platform(P.OPS_INCIDENTS_MANAGE))) -> Message:
    from app.services.incidents import add_event

    inc = pc.db.get(Incident, incident_id)
    if inc is None:
        raise NotFound("Incident not found.")
    add_event(pc.db, inc, "note", actor_user_id=pc.principal.user.id, actor_type="staff",
              body=f"[Trust Data SOC] {body.action}: {body.note}", data={"soc_action": body.action}, is_manual=True)
    audit.record(pc.db, "ops.incident_action", actor=pc.actor(), tenant_id=inc.tenant_id, target_type="incident",
                 target_id=inc.id, details={"action": body.action})
    pc.db.commit()
    return Message(message="Response action recorded.")


@ops.get("/connections")
def ops_connections(pc: PlatformContext = Depends(require_platform(P.OPS_DIAGNOSTICS)), params: PageParams = Depends(),
                    failing_only: bool = True) -> dict:
    db = pc.db
    q = select(HostingAccount)
    if failing_only:
        q = q.where(HostingAccount.status.in_(["auth_failed", "error", "disconnected", "expired", "untested"]))
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    return paginate(db, q.order_by(HostingAccount.last_tested_at.desc().nulls_last()), params, lambda a: {
        "id": str(a.id), "tenant": names.get(a.tenant_id), "tenant_id": str(a.tenant_id), "name": a.name,
        "connector_type": a.connector_type, "hostname": a.hostname, "port": a.port, "status": a.status,
        "last_tested_at": a.last_tested_at, "last_success_at": a.last_success_at,
        "last_error_code": a.last_error_code, "last_error_message": a.last_error_message,
        "host_key_fingerprint": a.host_key_fingerprint})


@ops.get("/health")
def ops_health(pc: PlatformContext = Depends(require_platform(P.PLATFORM_HEALTH_READ))) -> dict:
    return system_health(pc.db)


@ops.get("/notifications")
def ops_notifications(pc: PlatformContext = Depends(require_platform(P.OPS_JOBS_READ)), params: PageParams = Depends(),
                      status: str = Query("failed", pattern="^(failed|pending|unconfigured)$")) -> dict:
    names = dict(pc.db.execute(select(Tenant.id, Tenant.name)).all())
    return paginate(pc.db, select(Notification).where(Notification.status == status)
                    .order_by(Notification.created_at.desc()), params, lambda n: {
        "id": str(n.id), "tenant": names.get(n.tenant_id), "channel": n.channel, "category": n.category,
        "status": n.status, "attempts": n.attempts, "last_error": n.last_error, "created_at": n.created_at})
