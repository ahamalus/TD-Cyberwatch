from __future__ import annotations

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import platform_session
from app.models import EmailToken, LoginEvent, User
from tests.conftest import PASSWORD, Session, register_and_login


def _client() -> TestClient:
    from app.main import app

    return TestClient(app)


def test_register_creates_owner_trial_and_verification(client):
    r = client.post("/api/v1/auth/register", json={"email": "Owner@Gamma.example.com", "password": PASSWORD,
                                                   "full_name": "Owner", "organisation_name": "Gamma Ltd"})
    assert r.status_code == 201
    r = client.post("/api/v1/auth/login", json={"email": "owner@gamma.example.com", "password": PASSWORD})
    me = r.json()["user"]
    assert me["memberships"][0]["role"] == "owner"
    assert me["email_verified"] is False
    s = Session(client)
    tenant = s.get(f"/api/v1/tenants/{me['memberships'][0]['tenant_id']}").json()
    assert tenant["plan"]["status"] == "trialing" and tenant["plan"]["in_service"] is True
    with platform_session() as db:
        assert db.execute(select(EmailToken).where(EmailToken.purpose == "verify_email")).scalar_one()


def test_weak_password_and_duplicate_rejected(client):
    r = client.post("/api/v1/auth/register", json={"email": "w@x.example.com", "password": "short",
                                                   "full_name": "W", "organisation_name": "W Org"})
    assert r.status_code == 422
    register_and_login("dup@x.example.com", "Dup")
    r = client.post("/api/v1/auth/register", json={"email": "dup@x.example.com", "password": PASSWORD,
                                                   "full_name": "D", "organisation_name": "Dup2"})
    assert r.status_code == 409


def test_login_failure_lockout_and_history(client):
    register_and_login("lock@x.example.com", "Lock")
    c = _client()
    for _ in range(8):
        r = c.post("/api/v1/auth/login", json={"email": "lock@x.example.com", "password": "wrong-password-xx"})
        assert r.status_code in (401, 429)
    from app.core.ratelimit import get_limiter

    get_limiter().reset()
    r = c.post("/api/v1/auth/login", json={"email": "lock@x.example.com", "password": PASSWORD})
    assert r.status_code == 401 and r.json()["error"]["code"] == "account_locked"
    with platform_session() as db:
        reasons = {e.reason for e in db.execute(select(LoginEvent)).scalars()}
    assert {"bad_credentials", "locked"} <= reasons or {"locked_now", "locked"} <= reasons


def test_login_rate_limited(client):
    for _ in range(12):
        r = client.post("/api/v1/auth/login", json={"email": "nobody@x.example.com", "password": "whatever-123"})
    assert r.status_code == 429


def test_unknown_and_wrong_password_same_message(client):
    register_and_login("same@x.example.com", "Same")
    a = _client().post("/api/v1/auth/login", json={"email": "same@x.example.com", "password": "nope-nope-nope"})
    b = _client().post("/api/v1/auth/login", json={"email": "ghost@x.example.com", "password": "nope-nope-nope"})
    assert a.json()["error"]["message"] == b.json()["error"]["message"]


def test_mfa_enrolment_and_login():
    s, _ = register_and_login("mfa@x.example.com", "MFA Org")
    enrol = s.post("/api/v1/auth/mfa/enroll").json()
    assert enrol["otpauth_uri"].startswith("otpauth://totp/")
    assert s.post("/api/v1/auth/mfa/enroll/confirm", json={"code": "000000"}).status_code == 422
    codes = s.post("/api/v1/auth/mfa/enroll/confirm", json={"code": pyotp.TOTP(enrol["secret"]).now()}).json()["recovery_codes"]
    assert len(codes) == 8
    with platform_session() as db:
        u = db.execute(select(User).where(User.email == "mfa@x.example.com")).scalar_one()
        assert enrol["secret"].encode() not in u.mfa_ciphertext
    # New login requires MFA; protected routes are blocked until verified.
    c = _client()
    r = c.post("/api/v1/auth/login", json={"email": "mfa@x.example.com", "password": PASSWORD})
    assert r.json()["mfa_required"] is True
    assert c.get("/api/v1/auth/me").status_code == 401
    s2 = Session(c)
    assert s2.post("/api/v1/auth/mfa/verify", json={"code": "123456"}).status_code == 401
    assert s2.post("/api/v1/auth/mfa/verify", json={"code": pyotp.TOTP(enrol["secret"]).now()}).status_code == 200
    assert c.get("/api/v1/auth/me").status_code == 200
    # Recovery code works once
    c3 = _client()
    c3.post("/api/v1/auth/login", json={"email": "mfa@x.example.com", "password": PASSWORD})
    s3 = Session(c3)
    assert s3.post("/api/v1/auth/mfa/verify", json={"code": codes[0]}).status_code == 200
    c4 = _client()
    c4.post("/api/v1/auth/login", json={"email": "mfa@x.example.com", "password": PASSWORD})
    assert Session(c4).post("/api/v1/auth/mfa/verify", json={"code": codes[0]}).status_code == 401


def test_logout_and_session_revocation():
    s, _ = register_and_login("sess@x.example.com", "Sess")
    other = _client()
    other.post("/api/v1/auth/login", json={"email": "sess@x.example.com", "password": PASSWORD})
    sessions = s.get("/api/v1/auth/sessions").json()
    assert len(sessions) == 2
    victim = next(x for x in sessions if not x["current"])
    assert s.delete(f"/api/v1/auth/sessions/{victim['id']}").status_code == 200
    assert other.get("/api/v1/auth/me").status_code == 401
    assert s.post("/api/v1/auth/logout").status_code == 200
    assert s.get("/api/v1/auth/me").status_code == 401


def test_password_reset_flow(client):
    register_and_login("reset@x.example.com", "Reset")
    r = client.post("/api/v1/auth/password/forgot", json={"email": "reset@x.example.com"})
    assert r.status_code == 202
    r2 = client.post("/api/v1/auth/password/forgot", json={"email": "nobody@x.example.com"})
    assert r2.json() == r.json()  # no account enumeration
    from app.core.security import new_token, token_digest

    tok = new_token()
    with platform_session() as db:
        row = db.execute(select(EmailToken).where(EmailToken.purpose == "password_reset")).scalar_one()
        row.token_digest = token_digest(tok)
        db.commit()
    new_pw = "Another-Strong-Passw0rd!"
    assert client.post("/api/v1/auth/password/reset", json={"token": tok, "password": new_pw}).status_code == 200
    assert client.post("/api/v1/auth/password/reset", json={"token": tok, "password": new_pw}).status_code == 400
    c = _client()
    assert c.post("/api/v1/auth/login", json={"email": "reset@x.example.com", "password": new_pw}).status_code == 200


def test_email_verification(client):
    register_and_login("verify@x.example.com", "Verify")
    from app.core.security import new_token, token_digest

    tok = new_token()
    with platform_session() as db:
        row = db.execute(select(EmailToken).where(EmailToken.purpose == "verify_email")).scalar_one()
        row.token_digest = token_digest(tok)
        db.commit()
    assert client.post("/api/v1/auth/verify-email", json={"token": tok}).status_code == 200
    with platform_session() as db:
        assert db.execute(select(User).where(User.email == "verify@x.example.com")).scalar_one().email_verified_at


def test_change_password_revokes_other_sessions():
    s, _ = register_and_login("chg@x.example.com", "Chg")
    other = _client()
    other.post("/api/v1/auth/login", json={"email": "chg@x.example.com", "password": PASSWORD})
    r = s.post("/api/v1/auth/password/change", json={"current_password": PASSWORD,
                                                     "new_password": "Brand-New-Passw0rd-123"})
    assert r.status_code == 200
    assert s.get("/api/v1/auth/me").status_code == 200
    assert other.get("/api/v1/auth/me").status_code == 401
