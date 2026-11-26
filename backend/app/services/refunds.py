"""Refunds and disputes (chargebacks) through Paystack.

Refunds are requested by Trust Data staff with PLATFORM_PAYMENTS_MANAGE. Paystack processes them
asynchronously; the local status is only ever taken from Paystack's own API (webhooks trigger a re-fetch,
their body is never trusted on its own). The paid amount is credited back only for refunds Paystack
reports as processed.

Disputes are raised by the customer's bank. CyberWatch records them from ``charge.dispute.*`` webhooks
(confirmed with Paystack when possible) and alerts payment staff by email, because a dispute must be
answered on the Paystack dashboard before its due date.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import NotFound, ValidationFailed
from app.core.logging import get_logger
from app.core.permissions import ALL_ROLES, P
from app.db.base import utcnow
from app.models import Payment, PaymentDispute, PaymentRefund, PlatformRoleAssignment, Subscription, User
from app.services import audit
from app.services.audit import AuditActor
from app.services.notifications import queue_simple

log = get_logger(__name__)

OPEN_REFUND = ("pending", "processing", "needs-attention")
FINAL_REFUND = ("processed", "failed")


def refundable_minor(db: Session, payment: Payment) -> int:
    """Amount still refundable: paid minus processed and in-flight refunds."""
    committed = db.execute(
        select(func.coalesce(func.sum(PaymentRefund.amount_minor), 0)).where(
            PaymentRefund.payment_id == payment.id, PaymentRefund.status.in_((*OPEN_REFUND, "processed")))
    ).scalar_one()
    return max(0, payment.amount_minor - int(committed))


def request_refund(db: Session, payment_id: uuid.UUID, amount_minor: int | None, reason: str,
                   end_subscription: bool, actor: AuditActor) -> PaymentRefund:
    from app.services.billing import PaystackError, get_client

    payment = db.execute(select(Payment).where(Payment.id == payment_id).with_for_update()).scalar_one_or_none()
    if payment is None:
        raise NotFound("Payment not found.")
    if payment.status not in ("success", "refunded") or payment.verified_at is None:
        raise ValidationFailed("Only verified, successful payments can be refunded.")
    available = refundable_minor(db, payment)
    amount = available if amount_minor is None else amount_minor
    if amount <= 0 or amount > available:
        raise ValidationFailed(f"Refund amount must be between 1 and {available} (minor units still refundable).")
    if len(reason.strip()) < 10:
        raise ValidationFailed("Give a reason of at least 10 characters; it is kept in the audit trail.")
    refund = PaymentRefund(tenant_id=payment.tenant_id, payment_id=payment.id, amount_minor=amount,
                           currency=payment.currency, reason=reason.strip(), requested_by=actor.user_id,
                           end_subscription=end_subscription)
    db.add(refund)
    db.flush()
    try:
        data = get_client().refund(reference=payment.reference, amount=amount,
                                   merchant_note=f"CyberWatch refund {refund.id}: {reason.strip()}"[:250])
    except PaystackError as exc:
        refund.status, refund.detail = "failed", f"Paystack refused the refund: {exc}"[:300]
        audit.record(db, "payment.refund_requested", actor=actor, tenant_id=payment.tenant_id, target_type="payment",
                     target_id=payment.id, outcome="failure",
                     details={"amount_minor": amount, "reason": reason, "error": str(exc)[:200]})
        return refund
    refund.provider_refund_id = str(data.get("id") or "") or None
    _apply_provider_status(db, refund, payment, str(data.get("status") or "pending"))
    audit.record(db, "payment.refund_requested", actor=actor, tenant_id=payment.tenant_id, target_type="payment",
                 target_id=payment.id, details={"amount_minor": amount, "currency": payment.currency, "reason": reason,
                                                "refund_id": str(refund.id), "end_subscription": end_subscription,
                                                "provider_status": refund.status})
    return refund


def _apply_provider_status(db: Session, refund: PaymentRefund, payment: Payment, status: str) -> None:
    status = status if status in (*OPEN_REFUND, *FINAL_REFUND) else "pending"
    if refund.status == "processed" or (refund.status == "failed" and status != "processed"):
        return  # final states do not move back
    refund.status = status
    if status != "processed":
        return
    refund.processed_at = utcnow()
    payment.refunded_minor = min(payment.amount_minor, payment.refunded_minor + refund.amount_minor)
    if payment.refunded_minor >= payment.amount_minor:
        payment.status = "refunded"
    if refund.end_subscription and payment.subscription_id:
        sub = db.get(Subscription, payment.subscription_id)
        if sub is not None and sub.status not in ("cancelled", "expired"):
            sub.status, sub.cancelled_at, sub.current_period_end = "cancelled", utcnow(), utcnow()
            audit.record(db, "subscription.ended_by_refund", tenant_id=sub.tenant_id, target_type="subscription",
                         target_id=sub.id, details={"refund_id": str(refund.id)})
    audit.record(db, "payment.refund_processed", tenant_id=payment.tenant_id, target_type="payment",
                 target_id=payment.id, details={"refund_id": str(refund.id), "amount_minor": refund.amount_minor,
                                                "refunded_total_minor": payment.refunded_minor})


def refresh_refund(db: Session, refund: PaymentRefund) -> PaymentRefund:
    """Take the refund's state from Paystack."""
    from app.services.billing import get_client

    if not refund.provider_refund_id:
        return refund
    data = get_client().get_refund(refund.provider_refund_id)
    payment = db.execute(select(Payment).where(Payment.id == refund.payment_id).with_for_update()).scalar_one()
    _apply_provider_status(db, refund, payment, str(data.get("status") or refund.status))
    return refund


def refresh_open_refunds(db: Session, older_than_minutes: int = 10) -> int:
    """Re-check refunds still open with Paystack (a webhook may have arrived before Paystack's API caught up,
    or been lost). Run by the hourly billing maintenance."""
    from datetime import timedelta

    from app.services.billing import PaystackError

    cutoff = utcnow() - timedelta(minutes=older_than_minutes)
    changed = 0
    for r in db.execute(select(PaymentRefund).where(PaymentRefund.status.in_(OPEN_REFUND),
                                                    PaymentRefund.provider_refund_id.is_not(None),
                                                    PaymentRefund.updated_at <= cutoff)).scalars().all():
        before = r.status
        try:
            refresh_refund(db, r)
        except PaystackError as exc:
            log.warning("refund_refresh_failed", refund=str(r.id), error=str(exc)[:200])
            continue
        changed += int(r.status != before)
    return changed


def handle_refund_event(db: Session, data: dict[str, Any]) -> str:
    """refund.pending / processing / processed / failed webhook: re-fetch from Paystack, then apply."""
    from app.services.billing import PaystackError

    reference = str(data.get("transaction_reference") or (data.get("transaction") or {}).get("reference") or "")
    provider_id = str(data.get("id") or data.get("refund_id") or "")
    refund = None
    if provider_id:
        refund = db.execute(select(PaymentRefund).where(PaymentRefund.provider_refund_id == provider_id)).scalar_one_or_none()
    if refund is None and reference:
        refund = db.execute(
            select(PaymentRefund).join(Payment, Payment.id == PaymentRefund.payment_id)
            .where(Payment.reference == reference, PaymentRefund.status.in_(OPEN_REFUND))
            .order_by(PaymentRefund.created_at.desc()).limit(1)
        ).scalar_one_or_none()
    if refund is None:
        return "unknown refund"
    try:
        refresh_refund(db, refund)
    except PaystackError as exc:
        return f"not confirmed with Paystack: {exc}"[:200]
    return f"refund {refund.status}"


# ---------------------------------------------------------------- disputes


def _staff_emails(db: Session) -> list[str]:
    roles = [k for k, r in ALL_ROLES.items() if r.scope == "platform" and P.PLATFORM_PAYMENTS_MANAGE in r.permissions]
    roles.append("platform_admin")
    rows = db.execute(select(User.email).join(PlatformRoleAssignment, PlatformRoleAssignment.user_id == User.id)
                      .where(PlatformRoleAssignment.role_key.in_(roles), User.is_active.is_(True))).scalars()
    return sorted(set(rows))


def handle_dispute_event(db: Session, event: str, data: dict[str, Any]) -> str:
    from app.services.billing import PaystackError, get_client

    dispute_id = str(data.get("id") or "")
    if not dispute_id:
        return "no dispute id"
    verified = False
    try:
        data = get_client().get_dispute(dispute_id) or data
        verified = True
    except PaystackError as exc:  # record anyway: disputes are time-critical; mark as unconfirmed
        log.warning("paystack_dispute_unconfirmed", dispute=dispute_id, error=str(exc)[:200])
    tx = data.get("transaction") or {}
    reference = str(tx.get("reference") or data.get("transaction_reference") or "") or None
    payment = db.execute(select(Payment).where(Payment.reference == reference)).scalar_one_or_none() if reference else None
    row = db.execute(select(PaymentDispute).where(PaymentDispute.provider_dispute_id == dispute_id)).scalar_one_or_none()
    created = row is None
    if row is None:
        row = PaymentDispute(provider_dispute_id=dispute_id, status="")
        db.add(row)
    row.payment_id = payment.id if payment else row.payment_id
    row.tenant_id = payment.tenant_id if payment else row.tenant_id
    row.transaction_reference = reference or row.transaction_reference
    row.status = str(data.get("status") or row.status or "open")[:40]
    row.resolution = (str(data.get("resolution"))[:40] if data.get("resolution") else row.resolution)
    row.category = (str(data.get("category"))[:40] if data.get("category") else row.category)
    amount = data.get("refund_amount") or tx.get("amount")
    row.amount_minor = int(amount) if isinstance(amount, (int, float, str)) and str(amount).isdigit() else row.amount_minor
    row.currency = str(data.get("currency") or tx.get("currency") or row.currency or "")[:3] or None
    row.due_at = _parse_time(data.get("dueAt") or data.get("due_at")) or row.due_at
    row.verified_with_provider = row.verified_with_provider or verified
    if row.resolution or row.status == "resolved":
        row.resolved_at = row.resolved_at or _parse_time(data.get("resolvedAt") or data.get("resolved_at")) or utcnow()
    db.flush()
    audit.record(db, f"payment.dispute_{'opened' if created else 'updated'}", tenant_id=row.tenant_id,
                 target_type="payment_dispute", target_id=row.id,
                 details={"event": event, "status": row.status, "resolution": row.resolution,
                          "reference": reference, "verified_with_provider": row.verified_with_provider})
    if event in ("charge.dispute.create", "charge.dispute.remind"):
        due = f" Respond by {row.due_at:%Y-%m-%d %H:%M} UTC." if row.due_at else ""
        for email in _staff_emails(db):
            queue_simple(
                db, tenant_id=None, channel="email", recipient=email, category="billing",
                subject=f"Payment dispute {'reminder' if event.endswith('remind') else 'opened'}: {reference or dispute_id}",
                body=(f"A customer's bank has disputed payment {reference or 'unknown'} "
                      f"({row.amount_minor or '?'} {row.currency or ''} minor units, category {row.category or 'unknown'})."
                      f"{due} Answer it on the Paystack dashboard (Disputes); CyberWatch only tracks it."
                      + ("" if row.verified_with_provider else " Note: this could not yet be confirmed with Paystack.")),
                idempotency_key=f"dispute:{dispute_id}:{event}:{email}",
            )
    return f"dispute {row.status}"


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
