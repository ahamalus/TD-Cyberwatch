"""Billing (C09), reports (C10) and support (C11)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import TenantContext, require
from app.core.errors import NotFound, ValidationFailed
from app.core.permissions import P
from app.db.base import utcnow
from app.db.session import get_db
from app.models import Payment, Plan, Report, SupportTicket, TicketMessage, User, Website
from app.schemas.common import PageParams, paginate
from app.services import audit, billing, entitlements, reports, service_desk, storage

router = APIRouter(prefix="/tenants/{tenant_id}", tags=["billing", "reports", "support"])
public_router = APIRouter(tags=["billing"])


def plan_dict(p: Plan) -> dict:
    return {"key": p.key, "name": p.name, "description": p.description, "currency": p.currency,
            "price_monthly_minor": p.price_monthly_minor, "price_annual_minor": p.price_annual_minor,
            "contact_sales": p.contact_sales, "entitlements": p.entitlements}


@public_router.get("/plans")
def public_plans(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(Plan).where(Plan.is_active.is_(True), Plan.is_public.is_(True)).order_by(Plan.sort_order)).scalars()
    return [plan_dict(p) for p in rows]


@public_router.post("/webhooks/paystack", include_in_schema=False)
async def paystack_webhook(request: Request, db: Session = Depends(get_db)) -> JSONResponse:
    raw = await request.body()
    if len(raw) > 1024 * 1024:
        return JSONResponse({"status": "too large"}, status_code=413)
    code, status = billing.process_webhook(db, raw, request.headers.get("x-paystack-signature"))
    return JSONResponse({"status": status}, status_code=code)


@public_router.get("/webhooks/whatsapp", include_in_schema=False)
def whatsapp_webhook_verify(request: Request) -> Response:
    """Meta's subscription check: echo hub.challenge only for the configured verify token."""
    from app.services import whatsapp_webhook

    q = request.query_params
    challenge = whatsapp_webhook.verify_subscription(q.get("hub.mode"), q.get("hub.verify_token"), q.get("hub.challenge"))
    if challenge is None:
        return Response("forbidden", status_code=403, media_type="text/plain")
    return Response(challenge, media_type="text/plain")


@public_router.post("/webhooks/whatsapp", include_in_schema=False)
async def whatsapp_webhook_events(request: Request) -> JSONResponse:
    from app.db.session import platform_session
    from app.services import whatsapp_webhook

    raw = await request.body()
    if len(raw) > 1024 * 1024:
        return JSONResponse({"status": "too large"}, status_code=413)
    with platform_session() as db:
        code, stats = whatsapp_webhook.process(db, raw, request.headers.get("x-hub-signature-256"))
    return JSONResponse({"status": "ok" if code == 200 else "rejected", **stats}, status_code=code)


@router.get("/billing")
def billing_overview(ctx: TenantContext = Depends(require(P.BILLING_READ)), db: Session = Depends(get_db)) -> dict:
    sub = entitlements.current_subscription(db, ctx.tenant_id)
    plan = db.get(Plan, sub.plan_id) if sub else None
    ent = entitlements.effective(db, ctx.tenant_id)
    payments = db.execute(select(Payment).where(Payment.tenant_id == ctx.tenant_id)
                          .order_by(Payment.created_at.desc()).limit(50)).scalars().all()
    plan_names = dict(db.execute(select(Plan.id, Plan.name)).all())
    return {
        "payments_configured": billing.payments_configured(),
        "subscription": None if sub is None else {
            "id": str(sub.id), "plan_key": plan.key if plan else None, "plan_name": plan.name if plan else None,
            "status": sub.status, "interval": sub.interval, "current_period_start": sub.current_period_start,
            "current_period_end": sub.current_period_end, "trial_ends_at": sub.trial_ends_at,
            "grace_until": sub.grace_until, "cancel_at_period_end": sub.cancel_at_period_end,
            "payment_method": sub.auth_display,
        },
        "in_service": ent.in_service,
        "entitlements": ent.limits,
        "usage": entitlements.usage(db, ctx.tenant_id),
        "payments": [{"id": str(p.id), "reference": p.reference, "plan": plan_names.get(p.plan_id),
                      "interval": p.interval, "amount_minor": p.amount_minor, "currency": p.currency,
                      "status": p.status, "purpose": p.purpose, "paid_at": p.paid_at, "created_at": p.created_at,
                      "channel": p.channel} for p in payments],
    }


class CheckoutIn(BaseModel):
    plan_key: str = Field(max_length=40)
    interval: str = Field(pattern="^(monthly|annual)$")


@router.post("/billing/checkout")
def checkout(body: CheckoutIn, ctx: TenantContext = Depends(require(P.BILLING_MANAGE)), db: Session = Depends(get_db)) -> dict:
    result = billing.start_checkout(db, ctx.tenant, ctx.user, body.plan_key, body.interval, ctx.actor())
    db.commit()
    return result


class VerifyIn(BaseModel):
    reference: str = Field(min_length=4, max_length=100)


@router.post("/billing/verify")
def verify(body: VerifyIn, ctx: TenantContext = Depends(require(P.BILLING_READ)), db: Session = Depends(get_db)) -> dict:
    p = billing.verify_reference(db, ctx.tenant_id, body.reference, ctx.actor())
    db.commit()
    return {"reference": p.reference, "status": p.status, "verified_at": p.verified_at}


@router.post("/billing/cancel")
def cancel(ctx: TenantContext = Depends(require(P.BILLING_MANAGE)), db: Session = Depends(get_db)) -> dict:
    sub = billing.cancel_subscription(db, ctx.tenant_id, ctx.actor())
    db.commit()
    return {"status": sub.status, "cancel_at_period_end": sub.cancel_at_period_end,
            "current_period_end": sub.current_period_end}


@router.get("/billing/payments/{payment_id}/receipt")
def receipt(payment_id: uuid.UUID, ctx: TenantContext = Depends(require(P.BILLING_READ)), db: Session = Depends(get_db)) -> dict:
    p = db.execute(select(Payment).where(Payment.id == payment_id, Payment.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if p is None or p.status != "success":
        raise NotFound("Receipt not available for this payment.")
    plan = db.get(Plan, p.plan_id)
    return {"receipt_number": f"RCPT-{p.reference[-10:].upper()}", "organisation": ctx.tenant.name,
            "reference": p.reference, "plan": plan.name if plan else None, "interval": p.interval,
            "amount_minor": p.amount_minor, "currency": p.currency, "paid_at": p.paid_at, "channel": p.channel,
            "verified_at": p.verified_at, "issuer": "Trust Data Compliance Ltd"}


# ---------------------------------------------------------------- reports


class ReportIn(BaseModel):
    report_type: str
    format: str = Field(pattern="^(csv|pdf)$")
    website_id: uuid.UUID | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None


@router.get("/reports")
def list_reports(ctx: TenantContext = Depends(require(P.REPORTS_READ)), db: Session = Depends(get_db),
                 params: PageParams = Depends()) -> dict:
    q = select(Report).where(Report.tenant_id == ctx.tenant_id).order_by(Report.created_at.desc())
    return paginate(db, q, params, lambda r: {
        "id": str(r.id), "report_type": r.report_type, "title": r.title, "format": r.format, "status": r.status,
        "website_id": str(r.website_id) if r.website_id else None, "period_start": r.period_start,
        "period_end": r.period_end, "generated_at": r.generated_at, "content_sha256": r.content_sha256,
        "size_bytes": r.size_bytes, "error": r.error, "created_at": r.created_at})


@router.get("/report-types")
def report_types(ctx: TenantContext = Depends(require(P.REPORTS_READ))) -> dict:
    return reports.REPORT_TYPES


@router.post("/reports", status_code=201)
def create_report(body: ReportIn, ctx: TenantContext = Depends(require(P.REPORTS_GENERATE)),
                  db: Session = Depends(get_db)) -> dict:
    if body.report_type not in reports.REPORT_TYPES:
        raise ValidationFailed("Unknown report type.")
    if not entitlements.effective(db, ctx.tenant_id).get("reports", False):
        raise ValidationFailed("Report generation is not included in your plan.", code="plan_feature_unavailable")
    if body.website_id and not db.execute(select(Website.id).where(Website.id == body.website_id,
                                                                   Website.tenant_id == ctx.tenant_id)).first():
        raise ValidationFailed("Website not found.")
    end = body.period_end or utcnow()
    start = body.period_start or end - timedelta(days=30)
    if start >= end or end - start > timedelta(days=400):
        raise ValidationFailed("Report period must be positive and at most 400 days.")
    r = reports.generate(db, ctx.tenant, body.report_type, body.format, body.website_id, start, end, ctx.user.id)
    audit.record(db, "report.generated", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="report",
                 target_id=r.id, outcome="success" if r.status == "ready" else "failure",
                 details={"type": body.report_type, "format": body.format, "sha256": r.content_sha256})
    db.commit()
    return {"id": str(r.id), "status": r.status, "error": r.error, "content_sha256": r.content_sha256}


@router.get("/reports/{report_id}/download")
def download_report(report_id: uuid.UUID, ctx: TenantContext = Depends(require(P.REPORTS_READ)),
                    db: Session = Depends(get_db)) -> Response:
    r = db.execute(select(Report).where(Report.id == report_id, Report.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if r is None or r.status != "ready" or not r.object_key:
        raise NotFound("Report not available.")
    try:
        data = storage.get(ctx.tenant_id, r.object_key)
    except storage.StorageError as exc:
        raise NotFound("Report file is unavailable.") from exc
    audit.record(db, "report.downloaded", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="report", target_id=r.id)
    db.commit()
    media = "application/pdf" if r.format == "pdf" else "text/csv"
    fname = f"cyberwatch-{r.report_type}-{r.created_at:%Y%m%d}.{r.format}"
    return Response(content=data, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{fname}"', "X-Content-SHA256": r.content_sha256 or ""})


# ---------------------------------------------------------------- support and service desk

_CATEGORY_PATTERN = "^(" + "|".join(service_desk.ALL_CATEGORIES) + ")$"


class TicketIn(BaseModel):
    subject: str = Field(min_length=3, max_length=200)
    category: str = Field(pattern=_CATEGORY_PATTERN)
    priority: str = Field(default="normal", pattern="^(low|normal|high|urgent)$")
    body: str = Field(min_length=1, max_length=20000)
    website_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None
    incident_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)


class TicketMessageIn(BaseModel):
    body: str = Field(min_length=1, max_length=20000)


class RemediationApprovalIn(BaseModel):
    scope: str = Field(min_length=10, max_length=5000)
    confirm: bool


def ticket_dict(db: Session, t: SupportTicket, with_messages: bool = False, internal: bool = False) -> dict:
    """Ticket as the customer sees it (``internal`` adds staff-only notes, for the service desk)."""
    d = {"id": str(t.id), "reference": t.reference, "subject": t.subject, "category": t.category,
         "priority": t.priority, "status": t.status, "website_id": str(t.website_id) if t.website_id else None,
         "incident_id": str(t.incident_id) if t.incident_id else None,
         "incident_ids": [str(x) for x in (t.incident_ids or [])],
         "created_at": t.created_at, "updated_at": t.updated_at, "remediation_approved_at": t.remediation_approved_at,
         "remediation_scope": t.remediation_scope, "is_service_request": t.category in service_desk.SERVICE_CATEGORIES,
         "sla": {"response_due": t.sla_response_due, "resolution_due": t.sla_resolution_due,
                 "first_response_at": t.first_response_at, "resolved_at": t.resolved_at,
                 **service_desk.sla_state(t)},
         "checklist": [{"key": c["key"], "label": c["label"], "done": c["done"], "done_at": c.get("done_at")}
                       for c in (t.checklist or [])],
         "time_spent_minutes": t.time_spent_minutes, "report": t.report or {},
         "billing_status": t.billing_status, "price_minor": t.price_minor,
         "access_granted": bool(t.grant_id)}
    if t.assigned_to:
        u = db.get(User, t.assigned_to)
        d["assigned_team_member"] = u.full_name if u else None
    if with_messages:
        q = (select(TicketMessage, User).join(User, User.id == TicketMessage.author_user_id)
             .where(TicketMessage.ticket_id == t.id).order_by(TicketMessage.created_at))
        if not internal:
            q = q.where(TicketMessage.internal.is_(False))
        d["messages"] = [{"body": m.body, "author": u.full_name or u.email, "is_staff": m.author_is_staff,
                          "internal": m.internal, "kind": m.kind, "created_at": m.created_at}
                         for m, u in db.execute(q).all()]
    return d


@router.get("/service-desk")
def service_desk_summary(ctx: TenantContext = Depends(require(P.SUPPORT_READ)), db: Session = Depends(get_db)) -> dict:
    """What the plan includes: SLA targets, monthly service requests used and remaining, service types."""
    return service_desk.summary(db, ctx.tenant_id)


@router.get("/tickets")
def list_tickets(ctx: TenantContext = Depends(require(P.SUPPORT_READ)), db: Session = Depends(get_db),
                 params: PageParams = Depends(), status: str | None = Query(None, max_length=20)) -> dict:
    q = select(SupportTicket).where(SupportTicket.tenant_id == ctx.tenant_id)
    if status:
        q = q.where(SupportTicket.status == status)
    return paginate(db, q.order_by(SupportTicket.updated_at.desc()), params, lambda t: ticket_dict(db, t))


def _owned(db: Session, tenant_id: uuid.UUID, website_id: uuid.UUID | None, incident_ids: list[uuid.UUID]) -> None:
    from app.models import Incident

    if website_id and db.execute(select(Website.id).where(Website.id == website_id, Website.tenant_id == tenant_id)).first() is None:
        raise ValidationFailed("Unknown website.")
    if incident_ids:
        found = set(db.execute(select(Incident.id).where(Incident.id.in_(incident_ids), Incident.tenant_id == tenant_id)).scalars())
        if found != set(incident_ids):
            raise ValidationFailed("Unknown incident.")


@router.post("/tickets", status_code=201)
def create_ticket(body: TicketIn, ctx: TenantContext = Depends(require(P.SUPPORT_MANAGE)), db: Session = Depends(get_db)) -> dict:
    from sqlalchemy import text

    incident_ids = list(dict.fromkeys(body.incident_ids + ([body.incident_id] if body.incident_id else [])))
    _owned(db, ctx.tenant_id, body.website_id, incident_ids)
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"ticketref:{ctx.tenant_id}"})
    n = db.execute(select(func.count()).select_from(SupportTicket).where(SupportTicket.tenant_id == ctx.tenant_id)).scalar_one()
    t = SupportTicket(tenant_id=ctx.tenant_id, reference=f"SUP-{n + 1:05d}", subject=body.subject,
                      category=body.category, priority=body.priority, website_id=body.website_id,
                      incident_id=incident_ids[0] if incident_ids else None,
                      incident_ids=[str(i) for i in incident_ids], created_by=ctx.user.id, status="open")
    service_desk.on_create(db, t)
    db.add(t)
    db.flush()
    service_desk.add_message(db, t, ctx.user.id, body.body, staff=ctx.grant is not None)
    audit.record(db, "support.ticket_created", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="ticket",
                 target_id=t.id, details={"category": body.category, "priority": body.priority,
                                          "billing_status": t.billing_status, "incidents": len(incident_ids)})
    service_desk.notify(db, t, to_customer=False, key="created",
                        subject=f"New {body.priority} {body.category.replace('_', ' ')} request: {body.subject}",
                        body=f"{ctx.user.full_name or ctx.user.email} opened a request.\n\n{body.body[:2000]}")
    db.commit()
    return ticket_dict(db, t, with_messages=True)


def _ticket(db: Session, ctx: TenantContext, ticket_id: uuid.UUID) -> SupportTicket:
    t = db.execute(select(SupportTicket).where(SupportTicket.id == ticket_id,
                                               SupportTicket.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if t is None:
        raise NotFound("Ticket not found.")
    return t


@router.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: uuid.UUID, ctx: TenantContext = Depends(require(P.SUPPORT_READ)), db: Session = Depends(get_db)) -> dict:
    return ticket_dict(db, _ticket(db, ctx, ticket_id), with_messages=True)


@router.post("/tickets/{ticket_id}/messages")
def reply(ticket_id: uuid.UUID, body: TicketMessageIn, ctx: TenantContext = Depends(require(P.SUPPORT_MANAGE)),
          db: Session = Depends(get_db)) -> dict:
    t = _ticket(db, ctx, ticket_id)
    if t.status == "cancelled":
        raise ValidationFailed("This request was cancelled; open a new one.")
    staff = ctx.grant is not None
    service_desk.add_message(db, t, ctx.user.id, body.body, staff=staff)
    if not staff and t.status in ("resolved", "closed", "awaiting_customer"):
        service_desk.set_status(db, t, "open", ctx.user.id)
    audit.record(db, "support.ticket_replied", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="ticket", target_id=t.id)
    service_desk.notify(db, t, to_customer=staff, key=f"msg:{utcnow().timestamp():.0f}",
                        subject=f"New reply: {t.subject}", body=body.body[:2000])
    db.commit()
    return ticket_dict(db, t, with_messages=True)


@router.post("/tickets/{ticket_id}/close")
def close_ticket(ticket_id: uuid.UUID, ctx: TenantContext = Depends(require(P.SUPPORT_MANAGE)),
                 db: Session = Depends(get_db)) -> dict:
    """The customer confirms the work is done (or withdraws an open request). Ends any staff access it opened."""
    t = _ticket(db, ctx, ticket_id)
    if t.status in ("closed", "cancelled"):
        return ticket_dict(db, t, with_messages=True)
    new = "closed" if t.status == "resolved" or t.first_response_at else "cancelled"
    service_desk.set_status(db, t, new, ctx.user.id)
    audit.record(db, f"support.ticket_{new}", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="ticket", target_id=t.id)
    db.commit()
    return ticket_dict(db, t, with_messages=True)


@router.post("/tickets/{ticket_id}/remediation-approval")
def approve_remediation(ticket_id: uuid.UUID, body: RemediationApprovalIn,
                        ctx: TenantContext = Depends(require(P.MANAGED_SERVICE_APPROVE)),
                        db: Session = Depends(get_db)) -> dict:
    """The customer authorises Trust Data to work on the site within ``scope``. The assigned engineer then gets
    time-limited access (a managed-service grant), revoked when the request is closed."""
    if not body.confirm:
        raise ValidationFailed("Explicit confirmation is required.")
    if ctx.grant is not None:
        raise ValidationFailed("Remediation must be approved by the customer, not by service staff.")
    t = _ticket(db, ctx, ticket_id)
    if t.status in ("closed", "cancelled"):
        raise ValidationFailed("This request is closed.")
    t.remediation_approved_by, t.remediation_approved_at, t.remediation_scope = ctx.user.id, utcnow(), body.scope
    service_desk.add_message(db, t, ctx.user.id, f"Customer authorised the work within this scope:\n{body.scope}",
                             staff=False, kind="authorisation")
    audit.record(db, "support.remediation_approved", actor=ctx.actor(), tenant_id=ctx.tenant_id,
                 target_type="ticket", target_id=t.id, details={"scope": body.scope})
    service_desk.ensure_grant(db, t, ctx.actor())
    service_desk.notify(db, t, to_customer=False, key="authorised", subject=f"Work authorised: {t.subject}",
                        body=f"The customer authorised the work within this scope:\n{body.scope}")
    db.commit()
    return ticket_dict(db, t, with_messages=True)
