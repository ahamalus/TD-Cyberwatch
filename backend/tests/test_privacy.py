"""NDPA data-subject rights and storage limitation."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.errors import ValidationFailed
from app.db.base import utcnow
from app.db.session import platform_session
from app.models import AuditEvent, LoginEvent, TenantMembership, User, UserSession
from app.services import privacy
from app.services.audit import AuditActor
from tests.conftest import PASSWORD, register_and_login


def test_user_can_download_their_data(alice):
    a, _ = alice
    r = a.get("/api/v1/auth/me/export")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert r.headers["cache-control"] == "no-store"
    data = r.json()
    assert data["profile"]["email"] == "alice@alpha.example.com"
    assert data["organisations"][0]["role"] == "owner"
    assert data["sign_in_history"] and data["sessions"]
    assert "password_hash" not in r.text and "mfa_ciphertext" not in r.text and "token_digest" not in r.text
    with platform_session() as db:
        assert db.execute(select(AuditEvent).where(AuditEvent.action == "user.data_exported")).first()


def test_anonymisation_removes_personal_data_but_keeps_the_audit_chain():
    from fastapi.testclient import TestClient

    from app.main import app
    from app.services import audit

    register_and_login("erase.me@example.com", "Erase Org")
    with platform_session() as db:
        uid = privacy.anonymise_user(db, "Erase.Me@example.com", AuditActor(actor_type="system"), "NDPA erasure request #12")
        db.commit()
    with platform_session() as db:
        u = db.get(User, uid)
        assert u.email.endswith("@anonymised.invalid") and u.full_name == "Deleted user" and not u.is_active
        assert db.execute(select(LoginEvent).where(LoginEvent.email == "erase.me@example.com")).first() is None
        assert db.execute(select(UserSession).where(UserSession.user_id == uid)).first() is None
        assert {m.status for m in db.execute(select(TenantMembership).where(TenantMembership.user_id == uid)).scalars()} == {"disabled"}
        assert audit.verify_chain(db).valid, "the audit trail stays verifiable"
    login = TestClient(app).post("/api/v1/auth/login", json={"email": "erase.me@example.com", "password": PASSWORD})
    assert login.status_code == 401


def test_sole_owner_with_members_cannot_be_anonymised(alice):
    a, atid = alice
    from app.core.security import new_token, token_digest
    from app.models import Invitation

    a.post(f"/api/v1/tenants/{atid}/invitations", json={"email": "bea@alpha.example.com", "role": "viewer"})
    tok = new_token()
    with platform_session() as db:
        db.execute(select(Invitation)).scalar_one().token_digest = token_digest(tok)
        db.commit()
    b, _ = register_and_login("bea@alpha.example.com", "Bea Org")
    assert b.post("/api/v1/invitations/accept", json={"token": tok}).status_code == 200
    with platform_session() as db, pytest.raises(ValidationFailed, match="only owner"):
        privacy.anonymise_user(db, "alice@alpha.example.com", AuditActor(actor_type="system"), "request")


def test_old_sign_in_history_and_ended_sessions_are_pruned(alice):
    from app.services.retention import run_retention

    with platform_session() as db:
        uid = db.execute(select(User.id).where(User.email == "alice@alpha.example.com")).scalar_one()
        db.add(LoginEvent(user_id=uid, email="alice@alpha.example.com", success=True, reason="ok",
                          created_at=utcnow() - timedelta(days=400)))
        db.add(UserSession(user_id=uid, token_digest="x" * 64, csrf_digest="y" * 64,
                           expires_at=utcnow() - timedelta(days=45)))
        db.commit()
        stats = run_retention(db)
        db.commit()
    assert stats["login_events"] == 1 and stats["sessions"] == 1
    a, _ = alice
    assert a.get("/api/v1/auth/me").status_code == 200, "current session untouched"
