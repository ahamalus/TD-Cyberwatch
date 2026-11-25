"""Service desk: professional services (malware cleanup, fixing broken sites, migrations, maintenance tasks,
performance work) delivered by Trust Data staff and tracked as support tickets.

* **SLA:** response and resolution targets come from the plan's ``support_level`` (or explicit
  ``sla_response_hours`` / ``sla_resolution_hours`` entitlements), scaled by the request's priority.
* **Allowance:** ``service_tasks_per_month`` (or the support level's default) service requests a month are
  included; beyond that a request is marked ``quote`` (price to agree) and still handled.
* **Access:** staff with the service-desk permission read the ticket itself (the customer is writing to Trust
  Data), but website data, incidents and files still need a managed-service grant. When the customer authorises
  the work and an engineer is assigned, a time-limited grant scoped to the work is issued to that engineer, with
  the authorisation as the customer approval reference. The grant is revoked when the ticket closes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.permissions import ALL_ROLES, P
from app.db.base import utcnow
from app.models import ManagedServiceGrant, PlatformRoleAssignment, SupportTicket, TicketMessage, User
from app.services import audit
from app.services.audit import AuditActor

SERVICE_TYPES: dict[str, dict[str, Any]] = {
    "malware_cleanup": {
        "label": "Malware removal and hacked-site cleanup",
        "checklist": [
            "Confirm scope; snapshot the current state before any change",
            "Identify how the attacker got in (logs, vulnerable plugin, stolen password)",
            "Remove malicious files and restore genuine core/plugin files",
            "Check the database for injected content and unknown administrator accounts",
            "Change hosting, CMS, database and FTP passwords; reset WordPress security keys",
            "Update or remove vulnerable plugins and themes",
            "Harden: block PHP in uploads, disable the file editor",
            "Rescan and confirm the site is clean",
            "Write the cleanup report and recommendations",
        ],
    },
    "fix_site": {
        "label": "Fix a broken site (white screen, errors, forms, checkout)",
        "checklist": [
            "Reproduce the problem",
            "Check recent file changes, updates and error logs",
            "Fix or roll back the cause",
            "Test key pages: home, contact forms, checkout",
            "Summarise the cause and the fix",
        ],
    },
    "migration": {
        "label": "Website migration",
        "checklist": [
            "Agree source, destination and cut-over time",
            "Back up files and database at the source",
            "Copy files and database; update configuration and URLs",
            "Test on the new host before switching DNS",
            "Switch DNS; check TLS, email and forms",
            "Update CyberWatch hosting connection and take a new baseline",
        ],
    },
    "maintenance": {
        "label": "Maintenance task (updates, changes, configuration)",
        "checklist": [
            "Confirm the requested change",
            "Back up before changing anything",
            "Make and test the change",
            "Confirm with the customer",
        ],
    },
    "performance": {
        "label": "Speed and page optimisation",
        "checklist": [
            "Measure current speed (response time, page scores)",
            "Identify the slowest causes (hosting, plugins, images, caching)",
            "Apply and test improvements",
            "Measure again and report the difference",
        ],
    },
}
# remediation_request is the original name for a cleanup request and counts as one.
SERVICE_CATEGORIES = frozenset(SERVICE_TYPES) | {"remediation_request"}
ALL_CATEGORIES = ("general", "investigation", "billing", "technical", *SERVICE_CATEGORIES)

# support_level -> (response hours, resolution hours, included service requests a month; -1 = unlimited)
SUPPORT_LEVELS = {
    "standard": (24, 120, 0),
    "priority": (8, 72, 2),
    "dedicated": (4, 48, 5),
    "managed": (2, 24, -1),
}
PRIORITY_FACTOR = {"urgent": 0.25, "high": 0.5, "normal": 1.0, "low": 2.0}
OPEN_TICKET_STATUSES = ("open", "in_progress", "awaiting_customer")
GRANT_DAYS = 14
GRANT_PERMISSIONS = sorted({P.TENANT_READ, P.WEBSITES_READ, P.HOSTING_READ, P.MONITORING_READ, P.INVENTORY_READ,
                            P.INCIDENTS_READ, P.INCIDENTS_MANAGE, P.SCANS_RUN, P.REPORTS_READ, P.REPORTS_GENERATE,
                            P.SUPPORT_READ, P.SUPPORT_MANAGE})


def plan_terms(db: Session, tenant_id: uuid.UUID) -> dict[str, Any]:
    from app.services.entitlements import effective

    ent = effective(db, tenant_id)
    level = ent.get("support_level", "standard")
    resp, res, tasks = SUPPORT_LEVELS.get(level, SUPPORT_LEVELS["standard"])
    return {"support_level": level, "plan": ent.plan_name,
            "response_hours": float(ent.get("sla_response_hours", resp)),
            "resolution_hours": float(ent.get("sla_resolution_hours", res)),
            "tasks_per_month": int(ent.get("service_tasks_per_month", tasks))}


def month_usage(db: Session, tenant_id: uuid.UUID, now: datetime | None = None) -> int:
    now = now or utcnow()
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return db.execute(select(func.count()).select_from(SupportTicket).where(
        SupportTicket.tenant_id == tenant_id, SupportTicket.category.in_(SERVICE_CATEGORIES),
        SupportTicket.created_at >= start, SupportTicket.billing_status == "included",
        SupportTicket.status != "cancelled")).scalar_one()


def summary(db: Session, tenant_id: uuid.UUID) -> dict[str, Any]:
    terms = plan_terms(db, tenant_id)
    used = month_usage(db, tenant_id)
    allowance = terms["tasks_per_month"]
    return {**terms, "used_this_month": used,
            "remaining_this_month": None if allowance < 0 else max(0, allowance - used),
            "service_types": [{"key": k, "label": v["label"]} for k, v in SERVICE_TYPES.items()],
            "sla_by_priority": {p: {"response_hours": terms["response_hours"] * f,
                                    "resolution_hours": terms["resolution_hours"] * f}
                                for p, f in PRIORITY_FACTOR.items()}}


def on_create(db: Session, t: SupportTicket) -> None:
    """SLA targets, allowance and checklist for a new ticket (call before flush of the first message)."""
    now = utcnow()
    terms = plan_terms(db, t.tenant_id)
    f = PRIORITY_FACTOR.get(t.priority, 1.0)
    t.sla_response_due = now + timedelta(hours=terms["response_hours"] * f)
    t.sla_resolution_due = now + timedelta(hours=terms["resolution_hours"] * f)
    if t.category in SERVICE_CATEGORIES:
        allowance = terms["tasks_per_month"]
        t.billing_status = "included" if allowance < 0 or month_usage(db, t.tenant_id, now) < allowance else "quote"
        kind = "malware_cleanup" if t.category == "remediation_request" else t.category
        t.checklist = [{"key": f"c{i}", "label": label, "done": False, "done_at": None, "done_by": None}
                       for i, label in enumerate(SERVICE_TYPES[kind]["checklist"], start=1)]


def sla_state(t: SupportTicket, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()

    def one(due: datetime | None, met_at: datetime | None) -> str:
        if due is None:
            return "none"
        if met_at is not None:
            return "met" if met_at <= due else "missed"
        if t.status in ("resolved", "closed", "cancelled"):
            return "none"
        if now > due:
            return "overdue"
        return "due_soon" if due - now < timedelta(hours=2) else "on_track"

    return {"response": one(t.sla_response_due, t.first_response_at),
            "resolution": one(t.sla_resolution_due, t.resolved_at)}


def add_message(db: Session, t: SupportTicket, author_id: uuid.UUID, body: str, *, staff: bool,
                internal: bool = False, kind: str = "message") -> TicketMessage:
    m = TicketMessage(tenant_id=t.tenant_id, ticket_id=t.id, author_user_id=author_id, author_is_staff=staff,
                      body=body, internal=internal, kind=kind)
    db.add(m)
    now = utcnow()
    if staff and not internal and kind == "message" and t.first_response_at is None:
        t.first_response_at = now
    t.updated_at = now
    return m


def set_status(db: Session, t: SupportTicket, status: str, actor_id: uuid.UUID) -> None:
    old = t.status
    if old == status:
        return
    t.status = status
    now = utcnow()
    if status == "resolved" and t.resolved_at is None:
        t.resolved_at = now
    if status in ("open", "in_progress", "awaiting_customer"):
        t.resolved_at = None
    if status in ("closed", "cancelled"):
        revoke_grant(db, t, actor_id, f"ticket {status}")
    add_message(db, t, actor_id, f"Status changed from {old.replace('_', ' ')} to {status.replace('_', ' ')}.",
                staff=True, kind="status")


def ensure_grant(db: Session, t: SupportTicket, actor: AuditActor) -> ManagedServiceGrant | None:
    """Issue the engineer's access once the customer has authorised the work and someone is assigned."""
    if t.remediation_approved_at is None or t.assigned_to is None:
        return None
    if t.grant_id:
        g = db.get(ManagedServiceGrant, t.grant_id)
        if g and g.status == "active" and g.grantee_user_id == t.assigned_to and g.expires_at > utcnow():
            return g
        if g and g.status == "active":
            g.status, g.revoked_at = "revoked", utcnow()
    now = utcnow()
    g = ManagedServiceGrant(
        tenant_id=t.tenant_id, grantee_user_id=t.assigned_to, permissions=GRANT_PERMISSIONS,
        reason=f"Service request {t.reference}: {t.subject}"[:500], requested_by=t.assigned_to,
        approved_by=t.remediation_approved_by, approved_at=t.remediation_approved_at, starts_at=now,
        expires_at=now + timedelta(days=GRANT_DAYS), status="active",
        customer_approval_reference=f"{t.reference} authorisation {t.remediation_approved_at:%Y-%m-%d %H:%M} UTC")
    db.add(g)
    db.flush()
    t.grant_id = g.id
    audit.record(db, "grant.issued", actor=actor, tenant_id=t.tenant_id, target_type="grant", target_id=g.id,
                 details={"ticket": t.reference, "grantee": str(t.assigned_to), "permissions": GRANT_PERMISSIONS,
                          "basis": "customer authorisation of service request"})
    return g


def revoke_grant(db: Session, t: SupportTicket, actor_id: uuid.UUID | None, why: str) -> None:
    if not t.grant_id:
        return
    g = db.get(ManagedServiceGrant, t.grant_id)
    if g and g.status == "active":
        g.status, g.revoked_at, g.revoked_by = "revoked", utcnow(), actor_id
        audit.record(db, "grant.revoked", tenant_id=t.tenant_id, target_type="grant", target_id=g.id,
                     details={"ticket": t.reference, "reason": why})


def desk_staff_emails(db: Session) -> list[str]:
    roles = [k for k, r in ALL_ROLES.items() if r.scope == "platform" and P.OPS_SERVICE_DESK in r.permissions]
    emails = db.execute(select(User.email).join(PlatformRoleAssignment, PlatformRoleAssignment.user_id == User.id)
                        .where(User.is_active.is_(True), User.is_platform_staff.is_(True),
                               PlatformRoleAssignment.role_key.in_(roles))).scalars().all()
    return sorted(set(emails) | {e.strip().lower() for e in get_settings().support_emails if e.strip()})


def owner_emails(db: Session, tenant_id: uuid.UUID) -> list[str]:
    """Organisation owners: the people who can authorise work."""
    from app.models import TenantMembership

    return list(db.execute(select(User.email).join(TenantMembership, TenantMembership.user_id == User.id).where(
        TenantMembership.tenant_id == tenant_id, TenantMembership.role_key == "owner",
        TenantMembership.status == "active", User.is_active.is_(True))).scalars())


def notify(db: Session, t: SupportTicket, *, to_customer: bool, subject: str, body: str, key: str,
           include_owners: bool = False) -> None:
    from app.services.notifications import queue_simple

    s = get_settings()
    if to_customer:
        u = db.get(User, t.created_by)
        recipients = [u.email] if u and u.is_active else []
        if include_owners:
            recipients = sorted(set(recipients) | set(owner_emails(db, t.tenant_id)))
        link = f"{s.public_base_url.rstrip('/')}/app/{t.tenant_id}/support/{t.id}"
        tenant_id = t.tenant_id
    else:
        assignee = db.get(User, t.assigned_to) if t.assigned_to else None
        recipients = [assignee.email] if assignee and assignee.is_active else desk_staff_emails(db)
        link = f"{s.public_base_url.rstrip('/')}/ops/service-desk/{t.id}"
        tenant_id = None
    for r in recipients:
        queue_simple(db, tenant_id=tenant_id, channel="email", recipient=r, category="support",
                     subject=f"[{t.reference}] {subject}"[:250], body=f"{body}\n\n{link}",
                     idempotency_key=f"ticket:{t.id}:{key}:{r}")
