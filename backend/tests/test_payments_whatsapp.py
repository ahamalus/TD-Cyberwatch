"""Phase 4: refunds and disputes through Paystack, and WhatsApp delivery receipts / opt-outs."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from pydantic import SecretStr
from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import platform_session
from app.models import (
    AlertRecipient,
    AuditEvent,
    Notification,
    Payment,
    PaymentDispute,
    PaymentRefund,
    Subscription,
    User,
    WebhookEvent,
)
from tests.test_security import _sign, _staff, paystack  # noqa: F401 - fixture

# ---------------------------------------------------------------- refunds


class RefundingPaystack:
    """Adds Paystack's refund and dispute endpoints to the fake client."""

    def __init__(self, fake):
        self.fake = fake
        self.refunds: dict[str, dict] = {}
        self.disputes: dict[str, dict] = {}
        self.refuse = False

    def __getattr__(self, name):
        return getattr(self.fake, name)

    def refund(self, *, reference, amount, merchant_note):
        from app.services.billing import PaystackError

        if self.refuse:
            raise PaystackError("Transaction has been fully reversed")
        rid = str(1000 + len(self.refunds))
        self.refunds[rid] = {"id": int(rid), "status": "pending", "amount": amount, "transaction": {"reference": reference}}
        return self.refunds[rid]

    def get_refund(self, refund_id):
        return self.refunds[refund_id]

    def get_dispute(self, dispute_id):
        from app.services.billing import PaystackError

        if dispute_id not in self.disputes:
            raise PaystackError("Dispute not found")
        return self.disputes[dispute_id]


@pytest.fixture
def gateway(paystack):  # noqa: F811
    from app.services import billing

    fake = RefundingPaystack(paystack)
    billing.set_client(fake)
    yield fake
    billing.set_client(paystack)


def _paid(alice, client) -> str:
    a, atid = alice
    ref = a.post(f"/api/v1/tenants/{atid}/billing/checkout", json={"plan_key": "starter", "interval": "monthly"}).json()["reference"]
    body = json.dumps({"event": "charge.success", "data": {"id": 1, "reference": ref}}).encode()
    assert client.post("/api/v1/webhooks/paystack", content=body, headers={"x-paystack-signature": _sign(body)}).status_code == 200
    with platform_session() as db:
        p = db.execute(select(Payment).where(Payment.reference == ref)).scalar_one()
        assert p.status == "success"
        return str(p.id)


def _hook(client, event, data):
    body = json.dumps({"event": event, "data": data}).encode()
    return client.post("/api/v1/webhooks/paystack", content=body, headers={"x-paystack-signature": _sign(body)})


def test_partial_then_full_refund_confirmed_by_paystack(alice, client, gateway):
    pid = _paid(alice, client)
    billing_admin = _staff("billing@trustdata.example", ["billing_admin"])
    platform_admin = _staff("padmin@trustdata.example", ["platform_admin"])
    # Only staff who manage payments can refund.
    assert platform_admin.post(f"/api/v1/admin/payments/{pid}/refund", json={"reason": "Duplicate charge, refund"}).status_code == 403

    r = billing_admin.post(f"/api/v1/admin/payments/{pid}/refund",
                           json={"amount_minor": 500000, "reason": "Goodwill credit for outage"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "pending"
    info = billing_admin.get(f"/api/v1/admin/payments/{pid}/refunds").json()
    assert info["refundable_minor"] == 1000000, "in-flight refunds are reserved"
    too_much = billing_admin.post(f"/api/v1/admin/payments/{pid}/refund",
                                  json={"amount_minor": 1000001, "reason": "More than what is left"})
    assert too_much.status_code == 422

    # A webhook body is never trusted: the state comes from Paystack's API.
    _hook(client, "refund.processed", {"transaction_reference": "whatever", "id": 1000, "status": "processed"})
    with platform_session() as db:
        assert db.get(Payment, pid).refunded_minor == 0, "Paystack still says pending"
    # Paystack does not resend an acknowledged webhook: the hourly maintenance re-checks open refunds.
    gateway.refunds["1000"]["status"] = "processed"
    from app.services.refunds import refresh_open_refunds

    with platform_session() as db:
        assert refresh_open_refunds(db, older_than_minutes=0) == 1
        db.commit()
    with platform_session() as db:
        p = db.get(Payment, pid)
        assert p.refunded_minor == 500000 and p.status == "success"

    # Refund the rest and end the subscription.
    r = billing_admin.post(f"/api/v1/admin/payments/{pid}/refund",
                           json={"reason": "Customer cancelled within 14 days", "end_subscription": True})
    rid = r.json()["id"]
    assert r.json()["amount_minor"] == 1000000, "defaults to the remaining amount"
    gateway.refunds["1001"]["status"] = "processed"
    assert billing_admin.post(f"/api/v1/admin/refunds/{rid}/refresh").json()["status"] == "processed"
    with platform_session() as db:
        p = db.get(Payment, pid)
        assert p.status == "refunded" and p.refunded_minor == p.amount_minor
        sub = db.get(Subscription, p.subscription_id)
        assert sub.status == "cancelled"
        actions = [a.action for a in db.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars()]
    assert actions.count("payment.refund_requested") == 2 and actions.count("payment.refund_processed") == 2
    assert "subscription.ended_by_refund" in actions
    assert billing_admin.post(f"/api/v1/admin/payments/{pid}/refund", json={"reason": "Nothing left to refund"}).status_code == 422


def test_refused_refund_is_recorded_not_applied(alice, client, gateway):
    pid = _paid(alice, client)
    gateway.refuse = True
    r = _staff("billing2@trustdata.example", ["billing_admin"]).post(
        f"/api/v1/admin/payments/{pid}/refund", json={"reason": "Customer asked for refund"})
    assert r.json()["status"] == "failed" and "fully reversed" in r.json()["detail"]
    with platform_session() as db:
        assert db.get(Payment, pid).refunded_minor == 0


# ---------------------------------------------------------------- disputes


def test_dispute_is_recorded_confirmed_and_alerts_payment_staff(alice, client, gateway):
    pid = _paid(alice, client)
    _staff("billing3@trustdata.example", ["billing_admin"])
    with platform_session() as db:
        ref = db.get(Payment, pid).reference
    gateway.disputes["555"] = {"id": 555, "status": "awaiting-merchant-feedback", "category": "chargeback",
                               "refund_amount": 1500000, "currency": "NGN", "dueAt": "2026-12-01T12:00:00.000Z",
                               "transaction": {"reference": ref, "amount": 1500000}}
    # The webhook body says something else; the stored record follows Paystack's API.
    assert _hook(client, "charge.dispute.create", {"id": 555, "status": "resolved"}).json()["status"] == "processed"
    staff = _staff("billing4@trustdata.example", ["billing_admin"])
    rows = staff.get("/api/v1/admin/disputes").json()["items"]
    assert len(rows) == 1 and rows[0]["status"] == "awaiting-merchant-feedback" and rows[0]["verified_with_provider"]
    assert rows[0]["reference"] == ref and rows[0]["due_at"].startswith("2026-12-01")
    payments = staff.get("/api/v1/admin/payments").json()["items"]
    assert payments[0]["open_dispute"] is True
    with platform_session() as db:
        mails = db.execute(select(Notification).where(Notification.category == "billing",
                                                      Notification.subject.like("Payment dispute%"))).scalars().all()
    assert {m.recipient for m in mails} >= {"billing3@trustdata.example"}

    gateway.disputes["555"].update(status="resolved", resolution="merchant-accepted")
    _hook(client, "charge.dispute.resolve", {"id": 555})
    assert staff.get("/api/v1/admin/disputes").json()["items"] == []
    with platform_session() as db:
        d = db.execute(select(PaymentDispute)).scalar_one()
        assert d.resolution == "merchant-accepted" and d.resolved_at is not None


def test_unconfirmable_dispute_is_still_recorded(client, gateway):
    _hook(client, "charge.dispute.create", {"id": 777, "status": "awaiting-merchant-feedback",
                                            "transaction": {"reference": "unknown-ref"}})
    with platform_session() as db:
        d = db.execute(select(PaymentDispute)).scalar_one()
        assert d.provider_dispute_id == "777" and d.verified_with_provider is False


# ---------------------------------------------------------------- WhatsApp


@pytest.fixture
def wa(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "whatsapp_app_secret", SecretStr("app-secret"))
    monkeypatch.setattr(s, "whatsapp_verify_token", SecretStr("verify-me-please"))


def _wa_post(client, payload):
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(b"app-secret", body, hashlib.sha256).hexdigest()
    return client.post("/api/v1/webhooks/whatsapp", content=body, headers={"x-hub-signature-256": sig})


def _statuses(*items):
    return {"entry": [{"changes": [{"value": {"statuses": list(items)}}]}]}


def test_whatsapp_subscription_check(client, wa):
    ok = client.get("/api/v1/webhooks/whatsapp",
                    params={"hub.mode": "subscribe", "hub.verify_token": "verify-me-please", "hub.challenge": "12345"})
    assert ok.status_code == 200 and ok.text == "12345"
    bad = client.get("/api/v1/webhooks/whatsapp",
                     params={"hub.mode": "subscribe", "hub.verify_token": "nope", "hub.challenge": "12345"})
    assert bad.status_code == 403


def test_unsigned_whatsapp_events_rejected(client, wa):
    body = json.dumps(_statuses({"id": "wamid.X", "status": "read"})).encode()
    assert client.post("/api/v1/webhooks/whatsapp", content=body).status_code == 401
    assert client.post("/api/v1/webhooks/whatsapp", content=body,
                       headers={"x-hub-signature-256": "sha256=" + "0" * 64}).status_code == 401


def _wa_notification(tid, wamid, policy_id=None, incident_id=None, recipient="+2348012345678"):
    with platform_session() as db:
        n = Notification(tenant_id=tid, channel="whatsapp", category="incident", recipient=recipient,
                         template="incident_alert", subject="High incident", body="Incident body",
                         status="sent", provider_message_id=wamid, idempotency_key=f"t:{wamid}",
                         policy_id=policy_id, incident_id=incident_id)
        db.add(n)
        db.commit()
        return n.id


def test_delivery_receipts_never_move_backwards(alice, client, wa):
    _, tid = alice
    nid = _wa_notification(tid, "wamid.A")
    r = _wa_post(client, _statuses({"id": "wamid.A", "status": "delivered", "timestamp": "1790000000"},
                                   {"id": "wamid.A", "status": "read", "timestamp": "1790000060"}))
    assert r.json()["statuses"] == 2
    _wa_post(client, _statuses({"id": "wamid.A", "status": "delivered", "timestamp": "1790000100"}))
    with platform_session() as db:
        n = db.get(Notification, nid)
        assert n.delivery_status == "read" and n.read_at is not None and n.status == "sent"
    # Replays are counted as duplicates, unknown messages ignored.
    again = _wa_post(client, _statuses({"id": "wamid.A", "status": "read"}, {"id": "wamid.ZZZ", "status": "read"}))
    assert again.json()["duplicates"] == 1 and again.json()["unknown"] == 1


def test_late_failure_falls_back_to_email(alice, client, wa):
    from app.models import AlertPolicy, Incident

    _, tid = alice
    with platform_session() as db:
        u = db.execute(select(User).where(User.email == "alice@alpha.example.com")).scalar_one()
        u.phone = "+2348012345678"
        db.commit()
    with platform_session() as db:
        policy = AlertPolicy(tenant_id=tid, name="WhatsApp first", channels=["whatsapp"], email_fallback=True)
        db.add(policy)
        db.commit()
        pid = policy.id
    with platform_session() as db:
        incident = Incident(tenant_id=tid, reference="INC-T1", title="t", summary="s", category="malware",
                            finding_class="heuristic_suspicion", severity="high", confidence="medium",
                            detection_source="yara", rule_key="r", dedupe_key="d", recommended_action="a")
        db.add(incident)
        db.commit()
        iid = incident.id
    nid = _wa_notification(tid, "wamid.F", policy_id=pid, incident_id=iid)
    r = _wa_post(client, _statuses({"id": "wamid.F", "status": "failed",
                                    "errors": [{"code": 131026, "title": "Message undeliverable"}]}))
    assert r.json()["failed"] == 1
    with platform_session() as db:
        n = db.get(Notification, nid)
        assert n.status == "failed" and "131026" in n.last_error
        fallback = db.execute(select(Notification).where(Notification.idempotency_key == f"fallback:{nid}:alice@alpha.example.com")).scalar_one()
        assert fallback.channel == "email"


def test_stop_reply_opts_the_number_out_everywhere(alice, bob, client, wa):
    _, atid = alice
    _, btid = bob
    from app.models import AlertPolicy

    with platform_session() as db:
        for tid in (atid, btid):
            policy = AlertPolicy(tenant_id=tid, name="WhatsApp", channels=["whatsapp"])
            db.add(policy)
            db.flush()
            db.add(AlertRecipient(tenant_id=tid, policy_id=policy.id, whatsapp_number="+234 801 234 5678",
                                  whatsapp_opt_in_at=policy.created_at))
        u = db.execute(select(User).where(User.email == "alice@alpha.example.com")).scalar_one()
        u.phone, u.preferences = "+2348012345678", {**(u.preferences or {}), "whatsapp_opt_in": True}
        db.commit()
    msg = {"entry": [{"changes": [{"value": {"messages": [
        {"id": "wamid.IN1", "from": "2348012345678", "type": "text", "text": {"body": " Stop "}}]}}]}]}
    assert _wa_post(client, msg).json()["opt_outs"] == 3
    assert _wa_post(client, msg).json()["opt_outs"] == 0, "replayed message"
    with platform_session() as db:
        assert all(r.whatsapp_opt_in_at is None for r in db.execute(select(AlertRecipient)).scalars())
        u = db.execute(select(User).where(User.email == "alice@alpha.example.com")).scalar_one()
        assert u.preferences["whatsapp_opt_in"] is False
        assert db.execute(select(AuditEvent).where(AuditEvent.action == "whatsapp.opt_out")).scalars().all()
        stored = json.dumps([w.payload for w in db.execute(select(WebhookEvent)).scalars()])
    assert "Stop" not in stored and "2348012345678" not in stored, "message text and numbers are not stored"
    # Any other message is ignored.
    other = {"entry": [{"changes": [{"value": {"messages": [{"id": "wamid.IN2", "from": "2348012345678",
                                                            "type": "text", "text": {"body": "thanks"}}]}}]}]}
    assert _wa_post(client, other).json()["opt_outs"] == 0


def test_customers_cannot_reach_refund_or_dispute_endpoints(alice, client, gateway):
    pid = _paid(alice, client)
    a, _ = alice
    assert a.post(f"/api/v1/admin/payments/{pid}/refund", json={"reason": "Refund me please now"}).status_code in (401, 403, 404)
    assert a.get("/api/v1/admin/disputes").status_code in (401, 403, 404)
    with platform_session() as db:
        assert db.execute(select(PaymentRefund)).scalars().all() == []
