"""Subscriptions and Paystack payments.

Lifecycle rules:

* Prices are validated server-side from the ``plans`` table; the client only
  names a plan and interval.
* A subscription is activated only after the transaction is verified with
  Paystack's verify endpoint (``GET /transaction/verify/:reference``) and the
  verified amount, currency and reference match our record. Returning to the
  callback URL alone never grants entitlements.
* Webhooks (``charge.success``) are authenticated with HMAC-SHA512 of the raw
  body using the secret key (header ``x-paystack-signature``), deduplicated by
  a stable key, and then *still* re-verified via the API before acting.
* Renewals are charged by this platform using the stored reusable
  authorization (``/transaction/charge_authorization``). Failed renewals are
  NOT assumed to be retried by Paystack: the platform retries daily during a
  configurable grace period and sends reminders, then restricts service.
* Card numbers and CVV values never touch this system (hosted checkout).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.crypto import CredentialVault, EncryptedBlob, get_vault
from app.core.errors import AppError, NotFound, ServiceUnavailable, ValidationFailed
from app.core.logging import get_logger
from app.core.security import new_token
from app.db.base import utcnow
from app.models import Payment, Plan, Subscription, Tenant, TenantMembership, User, WebhookEvent
from app.services import audit
from app.services.audit import AuditActor
from app.services.notifications import queue_simple

log = get_logger(__name__)

RENEWAL_REMINDER_DAYS = (7, 1)


class PaystackError(Exception):
    pass


@dataclass
class VerifiedTransaction:
    status: str
    reference: str
    amount: int
    currency: str
    paid_at: str | None
    channel: str | None
    gateway_response: str | None
    customer_code: str | None
    authorization: dict[str, Any] | None
    raw_metadata: dict[str, Any]


class PaystackClient:
    """Thin adapter; all provider-specific behaviour lives here."""

    def __init__(self, secret_key: str, base_url: str, transport: httpx.BaseTransport | None = None):
        self._key = secret_key
        self._base = base_url.rstrip("/")
        self._transport = transport

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict[str, Any]:
        try:
            with httpx.Client(transport=self._transport, timeout=30) as c:
                resp = c.request(method, f"{self._base}{path}", json=payload,
                                 headers={"Authorization": f"Bearer {self._key}"})
        except httpx.HTTPError as exc:
            raise PaystackError(f"Paystack unreachable ({type(exc).__name__}).") from exc
        try:
            body = resp.json()
        except ValueError as exc:
            raise PaystackError(f"Paystack returned HTTP {resp.status_code} without JSON.") from exc
        if resp.status_code >= 400 or not body.get("status"):
            raise PaystackError(str(body.get("message") or f"HTTP {resp.status_code}")[:300])
        return body.get("data") or {}

    def initialize(self, *, email: str, amount: int, currency: str, reference: str, callback_url: str,
                   metadata: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/transaction/initialize", {
            "email": email, "amount": amount, "currency": currency, "reference": reference,
            "callback_url": callback_url, "metadata": metadata,
        })

    def verify(self, reference: str) -> VerifiedTransaction:
        d = self._request("GET", f"/transaction/verify/{reference}")
        return _to_verified(d)

    def charge_authorization(self, *, authorization_code: str, email: str, amount: int, currency: str,
                             reference: str, metadata: dict[str, Any]) -> VerifiedTransaction:
        d = self._request("POST", "/transaction/charge_authorization", {
            "authorization_code": authorization_code, "email": email, "amount": amount,
            "currency": currency, "reference": reference, "metadata": metadata,
        })
        return _to_verified(d)


def _to_verified(d: dict[str, Any]) -> VerifiedTransaction:
    return VerifiedTransaction(
        status=str(d.get("status", "")),
        reference=str(d.get("reference", "")),
        amount=int(d.get("amount") or 0),
        currency=str(d.get("currency", "")),
        paid_at=d.get("paid_at") or d.get("paidAt"),
        channel=d.get("channel"),
        gateway_response=(d.get("gateway_response") or "")[:200] or None,
        customer_code=(d.get("customer") or {}).get("customer_code"),
        authorization=d.get("authorization"),
        raw_metadata=d.get("metadata") if isinstance(d.get("metadata"), dict) else {},
    )


_client_override: PaystackClient | None = None


def set_client(client: PaystackClient | None) -> None:
    global _client_override
    _client_override = client


def get_client() -> PaystackClient:
    if _client_override is not None:
        return _client_override
    s = get_settings()
    if not s.paystack_secret_key:
        raise ServiceUnavailable("Online payments are not configured. Please contact Trust Data sales.",
                                 code="payments_unconfigured")
    return PaystackClient(s.paystack_secret_key.get_secret_value(), s.paystack_base_url)


def payments_configured() -> bool:
    return _client_override is not None or bool(get_settings().paystack_secret_key)


def verify_webhook_signature(raw_body: bytes, signature: str | None) -> bool:
    s = get_settings()
    if not s.paystack_secret_key or not signature:
        return False
    expected = hmac.new(s.paystack_secret_key.get_secret_value().encode(), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature.strip())


def plan_price(plan: Plan, interval: str) -> int:
    if plan.contact_sales or not plan.is_active:
        raise ValidationFailed("This plan is not available for online purchase.")
    price = plan.price_monthly_minor if interval == "monthly" else plan.price_annual_minor
    if not price or price <= 0:
        raise ValidationFailed(f"The {plan.name} plan is not offered with {interval} billing.")
    return int(price)


def start_checkout(db: Session, tenant: Tenant, user: User, plan_key: str, interval: str, actor: AuditActor) -> dict[str, str]:
    if interval not in ("monthly", "annual"):
        raise ValidationFailed("Interval must be monthly or annual.")
    plan = db.execute(select(Plan).where(Plan.key == plan_key, Plan.is_active.is_(True))).scalar_one_or_none()
    if plan is None:
        raise NotFound("Plan not found.")
    amount = plan_price(plan, interval)
    client = get_client()
    reference = f"cw_{uuid.uuid4().hex[:24]}"
    payment = Payment(
        tenant_id=tenant.id, plan_id=plan.id, interval=interval, reference=reference, amount_minor=amount,
        currency=plan.currency, status="initialized", purpose="new", initiated_by=user.id,
    )
    db.add(payment)
    db.flush()
    try:
        data = client.initialize(
            email=user.email, amount=amount, currency=plan.currency, reference=reference,
            callback_url=f"{get_settings().public_base_url}/app/{tenant.id}/billing?reference={reference}",
            metadata={"tenant_id": str(tenant.id), "plan_key": plan.key, "interval": interval,
                      "payment_id": str(payment.id)},
        )
    except PaystackError as exc:
        payment.status = "failed"
        payment.gateway_response = str(exc)[:200]
        audit.record(db, "billing.checkout_failed", actor=actor, tenant_id=tenant.id, target_type="payment",
                     target_id=payment.id, outcome="failure", details={"error": str(exc)})
        db.commit()
        raise AppError("The payment provider could not start checkout. Please try again.", code="payment_provider_error",
                       status_code=502) from exc
    audit.record(db, "billing.checkout_started", actor=actor, tenant_id=tenant.id, target_type="payment",
                 target_id=payment.id, details={"plan": plan.key, "interval": interval, "amount": amount})
    return {"authorization_url": data.get("authorization_url", ""), "reference": reference}


def _period_end(start, interval: str):
    return start + (timedelta(days=365) if interval == "annual" else timedelta(days=30))


def apply_verified_payment(db: Session, payment: Payment, tx: VerifiedTransaction, actor: AuditActor) -> Payment:
    """Apply a verified Paystack transaction to our payment and subscription. Idempotent."""
    if tx.reference != payment.reference:
        raise ValidationFailed("Transaction reference mismatch.")
    payment.verification = {
        "status": tx.status, "amount": tx.amount, "currency": tx.currency, "paid_at": tx.paid_at,
        "channel": tx.channel, "gateway_response": tx.gateway_response,
    }
    payment.verified_at = utcnow()
    payment.channel = tx.channel
    payment.gateway_response = tx.gateway_response
    if payment.status == "success":
        return payment  # already applied
    if tx.status != "success":
        payment.status = "failed" if tx.status == "failed" else ("abandoned" if tx.status == "abandoned" else payment.status)
        audit.record(db, "billing.payment_not_successful", actor=actor, tenant_id=payment.tenant_id,
                     target_type="payment", target_id=payment.id, details={"status": tx.status})
        return payment
    if tx.amount != payment.amount_minor or tx.currency.upper() != payment.currency.upper():
        payment.status = "failed"
        payment.gateway_response = "Amount or currency mismatch; manual review required."
        audit.record(db, "billing.payment_mismatch", actor=actor, tenant_id=payment.tenant_id, target_type="payment",
                     target_id=payment.id, outcome="failure",
                     details={"expected": payment.amount_minor, "received": tx.amount, "currency": tx.currency})
        return payment

    payment.status = "success"
    payment.paid_at = utcnow()
    now = utcnow()
    sub = db.execute(
        select(Subscription).where(Subscription.tenant_id == payment.tenant_id, Subscription.is_current.is_(True))
        .with_for_update()
    ).scalar_one_or_none()
    renewing_same = sub is not None and sub.plan_id == payment.plan_id and sub.status in ("active", "past_due", "grace_period") and payment.purpose == "renewal"
    if renewing_same:
        start = max(sub.current_period_end or now, now) if sub.status == "active" else now
    else:
        if sub is not None:
            sub.is_current = False
            if sub.status not in ("cancelled", "expired"):
                sub.status = "cancelled"
                sub.cancelled_at = now
            db.flush()
        sub = Subscription(tenant_id=payment.tenant_id, plan_id=payment.plan_id, status="active",
                           interval=payment.interval, is_current=True)
        db.add(sub)
        start = now
    sub.status = "active"
    sub.interval = payment.interval
    sub.current_period_start = start
    sub.current_period_end = _period_end(start, payment.interval)
    sub.grace_until = None
    sub.cancel_at_period_end = False
    sub.provider_customer_code = tx.customer_code or sub.provider_customer_code
    auth = tx.authorization or {}
    if auth.get("reusable") and auth.get("authorization_code"):
        db.flush()
        blob = get_vault().encrypt(auth["authorization_code"].encode(),
                                   CredentialVault.associated_data(sub.tenant_id, sub.id, "paystack_auth"))
        sub.auth_key_id, sub.auth_nonce, sub.auth_ciphertext = blob.key_id, blob.nonce, blob.ciphertext
        sub.auth_display = f"{auth.get('card_type', 'card').strip()} ••••{auth.get('last4', '')} exp {auth.get('exp_month', '')}/{auth.get('exp_year', '')}"[:80]
    db.flush()
    payment.subscription_id = sub.id
    audit.record(db, "billing.subscription_activated", actor=actor, tenant_id=payment.tenant_id,
                 target_type="subscription", target_id=sub.id,
                 details={"payment": str(payment.id), "period_end": sub.current_period_end.isoformat()})
    return payment


def verify_reference(db: Session, tenant_id: uuid.UUID, reference: str, actor: AuditActor) -> Payment:
    payment = db.execute(
        select(Payment).where(Payment.reference == reference, Payment.tenant_id == tenant_id).with_for_update()
    ).scalar_one_or_none()
    if payment is None:
        raise NotFound("Payment not found.")
    if payment.status == "success":
        return payment
    try:
        tx = get_client().verify(reference)
    except PaystackError as exc:
        raise AppError("Could not verify the payment with the provider yet. Please retry shortly.",
                       code="payment_verification_pending", status_code=502) from exc
    return apply_verified_payment(db, payment, tx, actor)


def process_webhook(db: Session, raw_body: bytes, signature: str | None) -> tuple[int, str]:
    valid = verify_webhook_signature(raw_body, signature)
    if not valid:
        log.warning("paystack_webhook_bad_signature")
        return 401, "invalid signature"
    try:
        payload = json.loads(raw_body)
    except ValueError:
        return 400, "invalid json"
    event = str(payload.get("event", ""))
    data = payload.get("data") or {}
    reference = str(data.get("reference", ""))
    dedupe = f"paystack:{event}:{data.get('id', '')}:{reference}"
    row = WebhookEvent(provider="paystack", event_type=event[:64], dedupe_key=dedupe[:200], signature_valid=True,
                       payload=_sanitise_webhook(payload))
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        return 200, "duplicate"
    if event != "charge.success" or not reference:
        row.status = "ignored"
        row.processed_at = utcnow()
        db.commit()
        return 200, "ignored"
    payment = db.execute(select(Payment).where(Payment.reference == reference).with_for_update()).scalar_one_or_none()
    if payment is None:
        row.status, row.error = "ignored", "Unknown reference"
        row.processed_at = utcnow()
        db.commit()
        return 200, "unknown reference"
    row.tenant_id = payment.tenant_id
    try:
        tx = get_client().verify(reference)  # never trust the webhook body alone
        apply_verified_payment(db, payment, tx, AuditActor(actor_type="system"))
        row.status = "processed"
    except (PaystackError, AppError) as exc:
        row.status, row.error = "failed", str(exc)[:500]
    row.processed_at = utcnow()
    db.commit()
    return 200, row.status


def _sanitise_webhook(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload.get("data") or {})
    auth = data.pop("authorization", None)
    if isinstance(auth, dict):
        data["authorization"] = {k: auth.get(k) for k in ("last4", "card_type", "bank", "channel", "reusable")}
    cust = data.get("customer")
    if isinstance(cust, dict):
        data["customer"] = {"customer_code": cust.get("customer_code")}
    return {"event": payload.get("event"), "data": data}


def cancel_subscription(db: Session, tenant_id: uuid.UUID, actor: AuditActor) -> Subscription:
    sub = db.execute(
        select(Subscription).where(Subscription.tenant_id == tenant_id, Subscription.is_current.is_(True))
    ).scalar_one_or_none()
    if sub is None or sub.status in ("cancelled", "expired"):
        raise ValidationFailed("There is no active subscription to cancel.")
    sub.cancel_at_period_end = True
    audit.record(db, "billing.cancel_requested", actor=actor, tenant_id=tenant_id, target_type="subscription",
                 target_id=sub.id, details={"effective": sub.current_period_end.isoformat() if sub.current_period_end else None})
    return sub


def _owners(db: Session, tenant_id: uuid.UUID) -> list[User]:
    return list(db.execute(
        select(User).join(TenantMembership, TenantMembership.user_id == User.id).where(
            TenantMembership.tenant_id == tenant_id, TenantMembership.status == "active",
            TenantMembership.role_key.in_(["owner", "billing"]))
    ).scalars())


def _notify_billing(db: Session, tenant_id: uuid.UUID, key: str, subject: str, body: str) -> None:
    for u in _owners(db, tenant_id):
        queue_simple(db, tenant_id=tenant_id, channel="email", recipient=u.email, category="billing",
                     subject=subject, body=body, idempotency_key=f"billing:{key}:{u.id}")


def run_subscription_maintenance(db: Session) -> dict[str, int]:
    s = get_settings()
    now = utcnow()
    stats = {"trials_expired": 0, "renewed": 0, "renewal_failed": 0, "grace_started": 0, "expired": 0,
             "cancelled": 0, "reminders": 0}
    subs = db.execute(select(Subscription).where(Subscription.is_current.is_(True))).scalars().all()
    for sub in subs:
        plan = db.get(Plan, sub.plan_id)
        if sub.status == "trialing" and sub.trial_ends_at and sub.trial_ends_at <= now:
            sub.status = "expired"
            stats["trials_expired"] += 1
            _notify_billing(db, sub.tenant_id, f"trial_end:{sub.id}", "Your CyberWatch trial has ended",
                            "Your trial has ended. Choose a plan to continue monitoring. Your data is retained.")
            continue
        if sub.status == "active" and sub.current_period_end:
            for d in RENEWAL_REMINDER_DAYS:
                if timedelta(0) < sub.current_period_end - now <= timedelta(days=d):
                    _notify_billing(db, sub.tenant_id, f"reminder:{sub.id}:{sub.current_period_end:%Y%m%d}:{d}",
                                    f"Your CyberWatch subscription renews in {d} day(s)",
                                    "Your subscription will renew automatically. Update your payment method in Billing if needed."
                                    if not sub.cancel_at_period_end else "Your subscription will end at the close of this period.")
                    stats["reminders"] += 1
                    break
        due = sub.status in ("active", "past_due", "grace_period") and sub.current_period_end and sub.current_period_end <= now
        if not due:
            if sub.status == "grace_period" and sub.grace_until and sub.grace_until <= now:
                sub.status = "expired"
                stats["expired"] += 1
            continue
        if sub.cancel_at_period_end:
            sub.status, sub.cancelled_at = "cancelled", now
            stats["cancelled"] += 1
            continue
        if sub.grace_until and sub.grace_until <= now:
            sub.status = "expired"
            stats["expired"] += 1
            _notify_billing(db, sub.tenant_id, f"expired:{sub.id}:{sub.current_period_end:%Y%m%d}",
                            "Your CyberWatch subscription has expired",
                            "Monitoring has been restricted because payment was not received. Your data is retained; renew to resume.")
            continue
        # Attempt at most one renewal charge per day.
        last_attempt = db.execute(
            select(Payment.created_at).where(Payment.subscription_id == sub.id, Payment.purpose == "renewal")
            .order_by(Payment.created_at.desc()).limit(1)
        ).scalar()
        if last_attempt and last_attempt > now - timedelta(hours=23):
            continue
        if sub.grace_until is None:
            sub.grace_until = sub.current_period_end + timedelta(days=s.grace_period_days)
            sub.status = "grace_period"
            stats["grace_started"] += 1
        if not (sub.auth_ciphertext and plan and payments_configured()):
            _notify_billing(db, sub.tenant_id, f"renew_manual:{sub.id}:{now:%Y%m%d}",
                            "Action needed: renew your CyberWatch subscription",
                            f"Your subscription period has ended. Renew from Billing before {sub.grace_until:%Y-%m-%d} to avoid interruption.")
            continue
        try:
            amount = plan_price(plan, sub.interval)
        except ValidationFailed:
            continue
        owner = next(iter(_owners(db, sub.tenant_id)), None)
        if owner is None:
            continue
        reference = f"cw_r_{new_token(nbytes=12).replace('-', '').replace('_', '')[:20]}"
        payment = Payment(tenant_id=sub.tenant_id, subscription_id=sub.id, plan_id=plan.id, interval=sub.interval,
                          reference=reference, amount_minor=amount, currency=plan.currency, purpose="renewal")
        db.add(payment)
        db.flush()
        auth_code = get_vault().decrypt(
            EncryptedBlob(sub.auth_key_id or "", sub.auth_nonce or b"", sub.auth_ciphertext),
            CredentialVault.associated_data(sub.tenant_id, sub.id, "paystack_auth"),
        ).decode()
        try:
            tx = get_client().charge_authorization(authorization_code=auth_code, email=owner.email, amount=amount,
                                                   currency=plan.currency, reference=reference,
                                                   metadata={"tenant_id": str(sub.tenant_id), "renewal": True})
            # Re-verify before granting, as for any payment.
            tx = get_client().verify(reference) if tx.status == "success" else tx
            apply_verified_payment(db, payment, tx, AuditActor(actor_type="system"))
        except (PaystackError, ServiceUnavailable) as exc:
            payment.status, payment.gateway_response = "failed", str(exc)[:200]
        if payment.status == "success":
            stats["renewed"] += 1
        else:
            stats["renewal_failed"] += 1
            _notify_billing(db, sub.tenant_id, f"renew_failed:{payment.id}", "CyberWatch renewal payment failed",
                            f"We could not charge your saved payment method. We will retry daily until {sub.grace_until:%Y-%m-%d}. "
                            "You can also pay now from Billing.")
    db.flush()
    return stats
