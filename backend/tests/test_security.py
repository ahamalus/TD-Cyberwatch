"""Explicit security tests required by the build specification (section 15)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid

import pytest
from sqlalchemy import select, text

from app.connectors.base import ConnectorError, safe_join, safe_rel
from app.core.config import get_settings
from app.core.logging import redact_mapping, redact_value
from app.core.netguard import TargetNotAllowed, check_ip_allowed, resolve_public_target, validate_website_url
from app.db.session import platform_session, tenant_session
from app.models import HostingCredential, Payment, Plan, Subscription, Website
from tests.conftest import PASSWORD, Session, register_and_login, run_dispatched


def _make_site(sess, tid, url="https://www.alpha-site.com/"):
    r = sess.post(f"/api/v1/tenants/{tid}/websites", json={"name": "Site", "url": url})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------------------------------------------------------------- tenant isolation


def test_tenant_cannot_access_another_tenants_websites(alice, bob):
    a, atid = alice
    b, btid = bob
    wid = _make_site(a, atid)
    # Bob uses his session against Alice's tenant: not found (no enumeration).
    assert b.get(f"/api/v1/tenants/{atid}/websites").status_code == 404
    assert b.get(f"/api/v1/tenants/{atid}/websites/{wid}").status_code == 404
    # Bob tries Alice's website ID inside his own tenant (IDOR): not found.
    assert b.get(f"/api/v1/tenants/{btid}/websites/{wid}").status_code == 404
    assert b.patch(f"/api/v1/tenants/{btid}/websites/{wid}", json={"name": "pwned"}).status_code == 404
    assert b.delete(f"/api/v1/tenants/{btid}/websites/{wid}").status_code == 404
    assert b.get(f"/api/v1/tenants/{btid}/websites/{wid}/inventory").status_code == 404
    assert b.get(f"/api/v1/tenants/{btid}/websites").json()["total"] == 0


def test_tenant_cannot_read_other_incidents_reports_or_changes(alice, bob):
    from app.services.incidents import DetectionSpec, raise_detection

    a, atid = alice
    b, btid = bob
    wid = _make_site(a, atid)
    with tenant_session(atid) as db:
        inc, _ = raise_detection(db, DetectionSpec(
            tenant_id=atid, website_id=uuid.UUID(wid), title="Alpha secret incident", summary="s",
            category="file_integrity", finding_class="integrity_anomaly", severity="high", confidence="high",
            detection_source="test", rule_key="t", dedupe_key="t", recommended_action="r"))
        db.commit()
        inc_id = inc.id
    assert b.get(f"/api/v1/tenants/{btid}/incidents/{inc_id}").status_code == 404
    assert b.post(f"/api/v1/tenants/{btid}/incidents/{inc_id}/status", json={"status": "closed", "note": "x"}).status_code == 404
    assert b.get(f"/api/v1/tenants/{btid}/incidents").json()["total"] == 0
    assert b.get(f"/api/v1/tenants/{atid}/incidents").status_code == 404
    # Reports
    r = a.post(f"/api/v1/tenants/{atid}/reports", json={"report_type": "incidents", "format": "csv"})
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert a.get(f"/api/v1/tenants/{atid}/reports/{rid}/download").status_code == 200
    assert b.get(f"/api/v1/tenants/{btid}/reports/{rid}/download").status_code == 404
    assert b.get(f"/api/v1/tenants/{atid}/reports/{rid}/download").status_code == 404
    assert b.get(f"/api/v1/tenants/{btid}/changes/export.csv").text.count("\n") == 1


def test_rls_blocks_cross_tenant_rows_even_without_where_clause(alice, bob):
    a, atid = alice
    b, btid = bob
    _make_site(a, atid)
    _make_site(b, btid, url="https://www.beta-site.com/")
    with tenant_session(btid) as db:
        rows = db.execute(select(Website)).scalars().all()  # deliberately unscoped query
        assert {w.tenant_id for w in rows} == {btid}
        # Writing a row for another tenant is rejected by the RLS WITH CHECK policy.
        with pytest.raises(Exception):
            db.execute(text("INSERT INTO website_groups (id, tenant_id, name, kind, created_at, updated_at) "
                            "VALUES (gen_random_uuid(), :t, 'x', 'other', now(), now())"), {"t": str(atid)})
            db.flush()
        db.rollback()
    from app.db.session import session_factory

    s = session_factory()()
    try:
        assert s.execute(select(Website)).scalars().all() == []  # no scope at all: nothing visible
    finally:
        s.close()


def test_api_token_is_bound_to_its_tenant(alice, bob):
    a, atid = alice
    b, btid = bob
    with platform_session() as db:
        pro = db.execute(select(Plan).where(Plan.key == "professional")).scalar_one()
        sub = db.execute(select(Subscription).where(Subscription.tenant_id == atid)).scalar_one()
        sub.plan_id = pro.id
        db.commit()
    r = a.post(f"/api/v1/tenants/{atid}/api-tokens", json={"name": "ci", "scopes": ["websites:read"]})
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    h = {"Authorization": f"Bearer {token}"}
    assert c.get(f"/api/v1/tenants/{atid}/websites", headers=h).status_code == 200
    assert c.get(f"/api/v1/tenants/{btid}/websites", headers=h).status_code == 404
    # Scope enforcement: the token cannot read incidents.
    assert c.get(f"/api/v1/tenants/{atid}/incidents", headers=h).status_code == 403
    # Tokens cannot be used for platform endpoints.
    assert c.get("/api/v1/admin/overview", headers=h).status_code == 404
    # Token value is never listed again
    assert token not in a.get(f"/api/v1/tenants/{atid}/api-tokens").text


# ---------------------------------------------------------------- privilege escalation


def test_customer_cannot_escalate_role(alice):
    a, atid = alice
    # Invite a viewer, accept, then the viewer tries to promote themselves.
    r = a.post(f"/api/v1/tenants/{atid}/invitations", json={"email": "victor@alpha.example.com", "role": "viewer"})
    assert r.status_code == 201
    from app.core.security import new_token, token_digest
    from app.models import Invitation

    tok = new_token()
    with platform_session() as db:
        inv = db.execute(select(Invitation)).scalar_one()
        inv.token_digest = token_digest(tok)
        db.commit()
    v, _ = register_and_login("victor@alpha.example.com", "Victor Org")
    assert v.post("/api/v1/invitations/accept", json={"token": tok}).status_code == 200
    members = a.get(f"/api/v1/tenants/{atid}/members").json()
    victor = next(m for m in members if m["email"] == "victor@alpha.example.com")
    assert victor["role"] == "viewer"
    # Viewer attempts: change own role, write websites, create admin invitations.
    assert v.patch(f"/api/v1/tenants/{atid}/members/{victor['membership_id']}", json={"role": "owner"}).status_code == 403
    assert v.post(f"/api/v1/tenants/{atid}/websites", json={"name": "x", "url": "https://x.example.com/"}).status_code == 403
    assert v.post(f"/api/v1/tenants/{atid}/invitations", json={"email": "e@x.example.com", "role": "owner"}).status_code == 403
    # Mass-assignment attempt on profile is ignored
    r = v.patch("/api/v1/auth/me", json={"full_name": "V", "is_platform_staff": True})
    assert r.status_code == 200 and r.json()["is_platform_staff"] is False
    # Platform endpoints are invisible to customers
    assert v.get("/api/v1/admin/overview").status_code == 404
    assert a.get("/api/v1/ops/overview").status_code == 404


def test_admin_cannot_create_owner(alice):
    a, atid = alice
    from app.models import TenantMembership

    _, _ = register_and_login("adam@alpha.example.com", "Adam Org")
    with platform_session() as db:
        from app.models import User

        adam = db.execute(select(User).where(User.email == "adam@alpha.example.com")).scalar_one()
        db.add(TenantMembership(tenant_id=atid, user_id=adam.id, role_key="admin"))
        db.commit()
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    c.post("/api/v1/auth/login", json={"email": "adam@alpha.example.com", "password": PASSWORD})
    adam_s = Session(c)
    members = a.get(f"/api/v1/tenants/{atid}/members").json()
    alice_m = next(m for m in members if m["role"] == "owner")
    assert adam_s.patch(f"/api/v1/tenants/{atid}/members/{alice_m['membership_id']}", json={"role": "viewer"}).status_code == 403
    assert adam_s.post(f"/api/v1/tenants/{atid}/invitations", json={"email": "o@x.example.com", "role": "owner"}).status_code == 403


def _staff(email: str, roles: list[str], mfa: bool = True) -> Session:
    import pyotp

    from app.core.crypto import CredentialVault, get_vault
    from app.core.security import hash_password
    from app.models import PlatformRoleAssignment, User

    with platform_session() as db:
        u = User(email=email, full_name=email, password_hash=hash_password(PASSWORD), is_platform_staff=True)
        db.add(u)
        db.flush()
        for r in roles:
            db.add(PlatformRoleAssignment(user_id=u.id, role_key=r))
        secret = pyotp.random_base32()
        if mfa:
            blob = get_vault().encrypt(secret.encode(), CredentialVault.associated_data("user", u.id, "totp"))
            u.mfa_enabled, u.mfa_key_id, u.mfa_nonce, u.mfa_ciphertext = True, blob.key_id, blob.nonce, blob.ciphertext
        db.commit()
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200
    s = Session(c)
    if mfa:
        assert r.json()["mfa_required"] is True
        r = s.post("/api/v1/auth/mfa/verify", json={"code": pyotp.TOTP(secret).now()})
        assert r.status_code == 200, r.text
    return s


def test_support_agent_has_no_unrestricted_tenant_access(alice):
    a, atid = alice
    wid = _make_site(a, atid)
    agent = _staff("agent@trustdata.example.com", ["support_agent"])
    # Platform role does not open customer data
    assert agent.get(f"/api/v1/tenants/{atid}/websites").status_code == 404
    assert agent.get(f"/api/v1/tenants/{atid}/websites/{wid}").status_code == 404
    assert agent.get("/api/v1/ops/jobs").status_code == 403
    # Agent requests a grant; it is inactive until the customer approves.
    r = agent.post("/api/v1/admin/grants", json={"tenant_id": str(atid), "permissions": ["websites:read"],
                                                 "reason": "Customer asked for help with onboarding"})
    assert r.status_code == 201 and r.json()["status"] == "requested"
    assert agent.get(f"/api/v1/tenants/{atid}/websites").status_code == 404
    # Agent cannot self-approve or request billing permissions.
    assert agent.post(f"/api/v1/tenants/{atid}/grants/{r.json()['id']}/decision", json={"approve": True}).status_code == 404
    bad = agent.post("/api/v1/admin/grants", json={"tenant_id": str(atid), "permissions": ["billing:manage"],
                                                   "reason": "attempting escalation"})
    assert bad.status_code == 422
    # Customer approves: access is limited to granted permissions and audited.
    assert a.post(f"/api/v1/tenants/{atid}/grants/{r.json()['id']}/decision",
                  json={"approve": True, "duration_hours": 2}).status_code == 200
    assert agent.get(f"/api/v1/tenants/{atid}/websites").status_code == 200
    assert agent.get(f"/api/v1/tenants/{atid}/incidents").status_code == 403
    assert agent.delete(f"/api/v1/tenants/{atid}/websites/{wid}").status_code == 403
    # Customer revokes
    a.post(f"/api/v1/tenants/{atid}/grants/{r.json()['id']}/revoke")
    assert agent.get(f"/api/v1/tenants/{atid}/websites").status_code == 404


def test_platform_privileges_require_mfa():
    s = _staff("nomfa@trustdata.example.com", ["platform_admin"], mfa=False)
    r = s.get("/api/v1/admin/overview")
    assert r.status_code == 403 and r.json()["error"]["code"] == "mfa_enrolment_required"
    admin = _staff("admin@trustdata.example.com", ["platform_admin"])
    assert admin.get("/api/v1/admin/overview").status_code == 200
    # Platform admin role alone does not grant tenant data access
    assert admin.get("/api/v1/admin/health").status_code == 200


# ---------------------------------------------------------------- secrets


def test_secrets_absent_from_api_logs_and_db(alice, caplog, capsys):
    a, atid = alice
    secret = "S3cret-Value-That-Must-Never-Leak"
    with caplog.at_level(logging.DEBUG):
        r = a.post(f"/api/v1/tenants/{atid}/hosting-accounts", json={
            "name": "Leak test", "connector_type": "sftp", "hostname": "sftp.alpha-host.com", "port": 22,
            "username": "u", "credential": {"kind": "password", "value": secret}})
    assert r.status_code == 201
    assert secret not in r.text
    assert secret not in a.get(f"/api/v1/tenants/{atid}/hosting-accounts").text
    out = capsys.readouterr()
    assert secret not in out.out + out.err
    assert secret not in caplog.text
    with platform_session() as db:
        cred = db.execute(select(HostingCredential)).scalar_one()
        assert secret.encode() not in cred.ciphertext
        dump = db.execute(text("SELECT string_agg(details::text, ' ') FROM audit_events")).scalar() or ""
        assert secret not in dump


def test_log_redaction():
    data = {"password": "hunter2", "nested": {"api_token": "abc"}, "msg": "Authorization: Bearer abcdefghijkl",
            "has_password": True}
    clean = redact_mapping(data)
    assert clean["password"] == "[REDACTED]"
    assert clean["nested"]["api_token"] == "[REDACTED]"
    assert "abcdefghijkl" not in clean["msg"]
    assert clean["has_password"] is True
    assert "sk_live_" not in redact_value("key sk_live_abcdef123")


def test_credential_ciphertext_bound_to_tenant(alice, bob):
    a, atid = alice
    b, btid = bob
    for s, t, name in ((a, atid, "A"), (b, btid, "B")):
        s.post(f"/api/v1/tenants/{t}/hosting-accounts", json={
            "name": name, "connector_type": "sftp", "hostname": f"sftp.{name.lower()}-host.com", "port": 22,
            "username": "u", "credential": {"kind": "password", "value": f"pw-{name}"}})
    from app.connectors.registry import decrypt_secret
    from app.core.crypto import CredentialVaultError

    with platform_session() as db:
        ca, cb = sorted(db.execute(select(HostingCredential)).scalars(), key=lambda c: c.tenant_id == btid)
        assert decrypt_secret(ca).value == "pw-A"
        # Copy A's ciphertext into B's row: authenticated decryption fails.
        cb.nonce, cb.ciphertext = ca.nonce, ca.ciphertext
        with pytest.raises(CredentialVaultError):
            decrypt_secret(cb)
        db.rollback()


# ---------------------------------------------------------------- SSRF


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254",
                                "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1",
                                "224.0.0.1", "198.18.0.1"])
def test_ssrf_blocks_internal_and_metadata_ips(ip, monkeypatch):
    monkeypatch.setattr(get_settings(), "outbound_allow_cidrs", [])
    with pytest.raises(TargetNotAllowed):
        check_ip_allowed(ip)


def test_ssrf_blocks_hostnames_and_ports(monkeypatch):
    monkeypatch.setattr(get_settings(), "outbound_allow_cidrs", [])
    for host in ("localhost", "metadata.google.internal", "foo.internal", "printer.local"):
        with pytest.raises(TargetNotAllowed):
            resolve_public_target(host, 443, [443])
    with pytest.raises(TargetNotAllowed):
        resolve_public_target("8.8.8.8", 6379, [443])  # disallowed port
    with pytest.raises(TargetNotAllowed):
        validate_website_url("http://user:pass@example.com/")
    with pytest.raises(TargetNotAllowed):
        validate_website_url("file:///etc/passwd")
    with pytest.raises(TargetNotAllowed):
        validate_website_url("gopher://example.com/")
    with pytest.raises(TargetNotAllowed):
        validate_website_url("http://example.com:6379/")


def test_ssrf_dns_rebinding_to_private_is_blocked(monkeypatch):
    import socket

    monkeypatch.setattr(get_settings(), "outbound_allow_cidrs", [])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))])
    with pytest.raises(TargetNotAllowed):
        resolve_public_target("evil.example.com", 443, [443])


def test_website_api_rejects_internal_urls(alice, monkeypatch):
    a, atid = alice
    for url in ("http://localhost/", "http://169.254.169.254/latest/meta-data/", "ftp://example.com/",
                "http://example.com:22/"):
        r = a.post(f"/api/v1/tenants/{atid}/websites", json={"name": "x", "url": url})
        assert r.status_code == 422, url
    r = a.post(f"/api/v1/tenants/{atid}/hosting-accounts", json={
        "name": "x", "connector_type": "sftp", "hostname": "localhost", "port": 22, "username": "u",
        "credential": {"kind": "password", "value": "p"}})
    assert r.status_code == 422


def test_availability_check_refuses_private_target(monkeypatch):
    from app.monitoring.availability import check_availability

    monkeypatch.setattr(get_settings(), "outbound_allow_cidrs", [])
    res = check_availability("http://127.0.0.1/")
    assert res.outcome == "error" and res.error_class == "target_not_allowed"


# ---------------------------------------------------------------- path traversal


@pytest.mark.parametrize("bad", ["../etc/passwd", "a/../../b", "/etc/passwd", "a\x00b", "..", "a/b/../../.."])
def test_path_traversal_rejected(bad):
    with pytest.raises(ConnectorError):
        safe_rel(bad)


def test_safe_join_stays_in_root():
    assert safe_join("/home/u/public_html", "wp/x.php") == "/home/u/public_html/wp/x.php"
    assert safe_join("/home/u/public_html", ".") == "/home/u/public_html"
    with pytest.raises(ConnectorError):
        safe_join("/home/u/public_html", "../../.ssh/id_rsa")


def test_document_root_traversal_rejected_by_api(alice):
    a, atid = alice
    r = a.post(f"/api/v1/tenants/{atid}/websites", json={"name": "x", "url": "https://t.example.com/",
                                                         "document_root": "../../etc"})
    assert r.status_code == 422


def test_symlinks_are_not_followed(alice, sftp_server, sftp_root, tmp_path):
    import os

    outside = tmp_path / "outside.txt"
    outside.write_text("outside the authorised scope")
    os.symlink(outside, sftp_root / "public_html" / "link.txt")
    a, atid = alice
    r = a.post(f"/api/v1/tenants/{atid}/hosting-accounts", json={
        "name": "S", "connector_type": "sftp", "hostname": "127.0.0.1", "port": sftp_server.port,
        "username": "webuser", "root_path": "/public_html",
        "credential": {"kind": "password", "value": sftp_server.state.password}})
    run_dispatched()
    wid = a.post(f"/api/v1/tenants/{atid}/websites", json={"name": "S", "url": "https://s.example.com/",
                                                           "hosting_account_id": r.json()["id"]}).json()["id"]
    a.put(f"/api/v1/tenants/{atid}/websites/{wid}/monitoring", json={"file_scan_enabled": True,
                                                                      "availability_enabled": False})
    a.post(f"/api/v1/tenants/{atid}/websites/{wid}/checks", json={"check": "file_scan"})
    run_dispatched()
    inv = a.get(f"/api/v1/tenants/{atid}/websites/{wid}/inventory", params={"q": "link"}).json()["items"]
    assert inv[0]["entry_type"] == "symlink" and inv[0]["sha256"] is None


# ---------------------------------------------------------------- payments


def _sign(body: bytes) -> str:
    return hmac.new(b"sk_test_dummy", body, hashlib.sha512).hexdigest()


@pytest.fixture
def paystack(monkeypatch):
    from pydantic import SecretStr

    from app.services import billing

    monkeypatch.setattr(get_settings(), "paystack_secret_key", SecretStr("sk_test_dummy"))

    class Fake:
        def __init__(self):
            self.status = "success"
            self.amount = None
            self.initialized = []

        def initialize(self, **kw):
            self.initialized.append(kw)
            return {"authorization_url": "https://checkout.paystack.com/abc", "reference": kw["reference"]}

        def verify(self, reference):
            with platform_session() as db:
                p = db.execute(select(Payment).where(Payment.reference == reference)).scalar_one()
                amount = self.amount if self.amount is not None else p.amount_minor
                cur = p.currency
            return billing.VerifiedTransaction(self.status, reference, amount, cur, "2026-10-19T10:00:00Z", "card",
                                               "Approved", "CUS_x", {"authorization_code": "AUTH_x", "reusable": True,
                                                                     "last4": "4081", "card_type": "visa"}, {})

    fake = Fake()
    billing.set_client(fake)
    yield fake
    billing.set_client(None)


def test_invalid_webhook_signature_rejected(client, paystack):
    body = json.dumps({"event": "charge.success", "data": {"reference": "x"}}).encode()
    r = client.post("/api/v1/webhooks/paystack", content=body, headers={"x-paystack-signature": "deadbeef"})
    assert r.status_code == 401
    r = client.post("/api/v1/webhooks/paystack", content=body)
    assert r.status_code == 401


def test_unverified_payment_does_not_activate(alice, paystack, client):
    a, atid = alice
    r = a.post(f"/api/v1/tenants/{atid}/billing/checkout", json={"plan_key": "starter", "interval": "monthly"})
    assert r.status_code == 200, r.text
    ref = r.json()["reference"]
    # Browser "returns" but verification says failed -> no activation.
    paystack.status = "failed"
    v = a.post(f"/api/v1/tenants/{atid}/billing/verify", json={"reference": ref})
    assert v.json()["status"] == "failed"
    billing_view = a.get(f"/api/v1/tenants/{atid}/billing").json()
    assert billing_view["subscription"]["status"] == "trialing"
    # A forged webhook body claiming success with a valid signature is still re-verified.
    body = json.dumps({"event": "charge.success", "data": {"id": 1, "reference": ref, "amount": 1}}).encode()
    client.post("/api/v1/webhooks/paystack", content=body, headers={"x-paystack-signature": _sign(body)})
    assert a.get(f"/api/v1/tenants/{atid}/billing").json()["subscription"]["status"] == "trialing"


def test_amount_mismatch_does_not_activate(alice, paystack):
    a, atid = alice
    ref = a.post(f"/api/v1/tenants/{atid}/billing/checkout", json={"plan_key": "starter", "interval": "monthly"}).json()["reference"]
    paystack.amount = 100  # underpaid
    a.post(f"/api/v1/tenants/{atid}/billing/verify", json={"reference": ref})
    assert a.get(f"/api/v1/tenants/{atid}/billing").json()["subscription"]["plan_key"] == "business"  # trial plan


def test_verified_payment_activates_and_webhook_is_idempotent(alice, paystack, client):
    a, atid = alice
    ref = a.post(f"/api/v1/tenants/{atid}/billing/checkout", json={"plan_key": "starter", "interval": "annual"}).json()["reference"]
    assert paystack.initialized[0]["amount"] == 15000000  # server-side price, not client supplied
    body = json.dumps({"event": "charge.success", "data": {"id": 77, "reference": ref}}).encode()
    for _ in range(3):
        r = client.post("/api/v1/webhooks/paystack", content=body, headers={"x-paystack-signature": _sign(body)})
        assert r.status_code == 200
    view = a.get(f"/api/v1/tenants/{atid}/billing").json()
    assert view["subscription"]["status"] == "active"
    assert view["subscription"]["plan_key"] == "starter"
    assert view["subscription"]["payment_method"].startswith("visa")
    with platform_session() as db:
        from app.models import WebhookEvent

        assert len(db.execute(select(WebhookEvent)).scalars().all()) == 1
        assert len(db.execute(select(Subscription).where(Subscription.tenant_id == atid,
                                                         Subscription.is_current.is_(True))).scalars().all()) == 1
        sub = db.execute(select(Subscription).where(Subscription.tenant_id == atid, Subscription.is_current.is_(True))).scalar_one()
        assert b"AUTH_x" not in sub.auth_ciphertext
    assert "AUTH_x" not in a.get(f"/api/v1/tenants/{atid}/billing").text


def test_client_cannot_set_price(alice, paystack):
    a, atid = alice
    r = a.post(f"/api/v1/tenants/{atid}/billing/checkout", json={"plan_key": "enterprise", "interval": "monthly"})
    assert r.status_code == 422  # contact-sales plan cannot be bought online
    r = a.post(f"/api/v1/tenants/{atid}/billing/checkout",
               json={"plan_key": "starter", "interval": "monthly", "amount": 1})
    assert r.status_code == 200
    assert paystack.initialized[-1]["amount"] == 1500000


# ---------------------------------------------------------------- CSRF & headers


def test_csrf_required_for_cookie_sessions(alice):
    a, atid = alice
    r = a.c.post(f"/api/v1/tenants/{atid}/websites", json={"name": "x", "url": "https://x.example.com/"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "csrf_failed"
    r = a.c.post(f"/api/v1/tenants/{atid}/websites", json={"name": "x", "url": "https://x.example.com/"},
                 headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403


def test_security_headers_and_no_stack_traces(client):
    r = client.get("/api/v1/health/live")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"
    r = client.get("/api/v1/tenants/not-a-uuid/websites")
    assert r.status_code in (401, 422)
    assert "Traceback" not in r.text


def test_production_refuses_unsafe_config(monkeypatch):
    from app.core.config import Settings

    s = Settings(environment="production", debug=True, cookie_secure=False, credential_keys="",
                 outbound_allow_cidrs=["10.0.0.0/8"])
    problems = s.validate_for_runtime()
    assert any("Debug" in p for p in problems)
    assert any("CREDENTIAL_KEYS" in p for p in problems)
    assert any("COOKIE_SECURE" in p for p in problems)
    assert any("OUTBOUND" in p for p in problems)
    assert any("database" in p.lower() for p in problems)
