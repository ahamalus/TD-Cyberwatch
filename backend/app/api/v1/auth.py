from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    Principal,
    client_ip,
    current_principal,
    current_principal_mfa_pending,
    platform_permissions_for,
    role_permissions,
)
from app.core.config import get_settings
from app.core.errors import NotFound
from app.core.ratelimit import get_limiter
from app.db.base import utcnow
from app.db.session import get_db
from app.models import LoginEvent, Tenant, TenantMembership, User, UserSession
from app.schemas.common import Message
from app.services import audit
from app.services import auth as auth_svc
from app.services.audit import AuditActor
from app.services.notifications import queue_simple

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    full_name: str = Field(min_length=1, max_length=200)
    organisation_name: str = Field(min_length=2, max_length=200)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class TokenIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)


class ResetIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(min_length=1, max_length=256)


class EmailIn(BaseModel):
    email: EmailStr


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class PasswordIn(BaseModel):
    password: str = Field(max_length=256)


class ProfileIn(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    phone: str | None = Field(default=None, pattern=r"^\+[1-9]\d{7,14}$")
    theme: str | None = Field(default=None, pattern="^(light|dark|system)$")
    whatsapp_opt_in: bool | None = None


class MembershipOut(BaseModel):
    tenant_id: uuid.UUID
    tenant_name: str
    tenant_status: str
    is_demo: bool
    role: str
    permissions: list[str]


class MeOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    phone: str | None
    email_verified: bool
    mfa_enabled: bool
    is_platform_staff: bool
    platform_roles: list[str]
    platform_permissions: list[str]
    platform_mfa_required: bool
    preferences: dict
    memberships: list[MembershipOut]


class LoginOut(BaseModel):
    mfa_required: bool
    user: MeOut | None = None


def _set_session_cookies(response: Response, token: str, csrf: str) -> None:
    s = get_settings()
    common = {"secure": s.cookie_secure, "samesite": "lax", "domain": s.cookie_domain, "path": "/"}
    response.set_cookie(SESSION_COOKIE, token, httponly=True, max_age=s.session_ttl_minutes * 60, **common)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, max_age=s.session_ttl_minutes * 60, **common)


def _clear_cookies(response: Response) -> None:
    s = get_settings()
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, domain=s.cookie_domain, path="/")


def build_me(db: Session, user: User) -> MeOut:
    rows = db.execute(
        select(TenantMembership, Tenant)
        .join(Tenant, Tenant.id == TenantMembership.tenant_id)
        .where(TenantMembership.user_id == user.id, TenantMembership.status == "active",
               Tenant.status != "deactivated")
        .order_by(Tenant.name)
    ).all()
    memberships = [
        MembershipOut(
            tenant_id=t.id, tenant_name=t.name, tenant_status=t.status, is_demo=t.is_demo, role=m.role_key,
            permissions=sorted(role_permissions(db, m.role_key)),
        )
        for m, t in rows
    ]
    pperms = platform_permissions_for(db, user)
    return MeOut(
        id=user.id, email=user.email, full_name=user.full_name, phone=user.phone,
        email_verified=user.email_verified_at is not None, mfa_enabled=user.mfa_enabled,
        is_platform_staff=user.is_platform_staff,
        platform_roles=sorted(a.role_key for a in user.platform_roles),
        platform_permissions=sorted(pperms),
        platform_mfa_required=user.is_platform_staff and not user.mfa_enabled and get_settings().require_platform_mfa,
        preferences=user.preferences or {},
        memberships=memberships,
    )


def _actor(request: Request) -> AuditActor:
    return AuditActor(actor_type="anonymous", ip_address=client_ip(request),
                      user_agent=request.headers.get("user-agent"),
                      request_id=getattr(request.state, "request_id", None))


@router.post("/register", response_model=Message, status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)) -> Message:
    s = get_settings()
    get_limiter().hit(f"register:{client_ip(request)}", 5, 3600)
    user, tenant, token = auth_svc.register(
        db, email=body.email, password=body.password, full_name=body.full_name,
        organisation_name=body.organisation_name, actor=_actor(request),
    )
    queue_simple(
        db, tenant_id=tenant.id, channel="email", recipient=user.email, category="account",
        subject=f"Verify your {s.product_name} account",
        body=f"Welcome to {s.product_name}.\n\nVerify your email address: {s.public_base_url}/verify-email?token={token}\n\n"
             "This link expires in 48 hours.",
        idempotency_key=f"verify:{user.id}:{token[:8]}",
    )
    db.commit()
    return Message(message="Account created. Check your email to verify your address.")


@router.post("/login", response_model=LoginOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> LoginOut:
    s = get_settings()
    ip = client_ip(request)
    get_limiter().hit(f"login:{ip}", s.auth_rate_limit, s.auth_rate_window_seconds)
    get_limiter().hit(f"login:{body.email.lower()}", s.auth_rate_limit, s.auth_rate_window_seconds)
    issued = auth_svc.login(db, email=body.email, password=body.password, ip=ip, ua=request.headers.get("user-agent"))
    user = db.get(User, issued.session.user_id)
    db.commit()
    _set_session_cookies(response, issued.token, issued.csrf_token)
    if issued.session.mfa_pending:
        return LoginOut(mfa_required=True)
    return LoginOut(mfa_required=False, user=build_me(db, user))


@router.post("/mfa/verify", response_model=LoginOut)
def mfa_verify(body: CodeIn, request: Request, principal: Principal = Depends(current_principal_mfa_pending),
               db: Session = Depends(get_db)) -> LoginOut:
    get_limiter().hit(f"mfa:{principal.user.id}", 6, 300)
    assert principal.session is not None
    auth_svc.complete_mfa(db, principal.session, principal.user, body.code, principal.ip)
    db.commit()
    return LoginOut(mfa_required=False, user=build_me(db, principal.user))


@router.post("/logout", response_model=Message)
def logout(response: Response, principal: Principal = Depends(current_principal_mfa_pending),
           db: Session = Depends(get_db)) -> Message:
    if principal.session is not None:
        principal.session.revoked_at = utcnow()
        audit.record(db, "auth.logout", actor=principal.actor())
        db.commit()
    _clear_cookies(response)
    return Message(message="Signed out.")


@router.get("/me", response_model=MeOut)
def me(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> MeOut:
    return build_me(db, principal.user)


@router.patch("/me", response_model=MeOut)
def update_me(body: ProfileIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> MeOut:
    u = principal.user
    if body.full_name is not None:
        u.full_name = body.full_name.strip()
    if body.phone is not None:
        u.phone = body.phone
    prefs = dict(u.preferences or {})
    if body.theme is not None:
        prefs["theme"] = body.theme
    if body.whatsapp_opt_in is not None:
        prefs["whatsapp_opt_in"] = body.whatsapp_opt_in
        prefs["whatsapp_opt_in_at"] = utcnow().isoformat() if body.whatsapp_opt_in else None
    u.preferences = prefs
    audit.record(db, "user.profile_updated", actor=principal.actor(), target_type="user", target_id=u.id,
                 details={k: v for k, v in body.model_dump(exclude_none=True).items() if k != "phone"})
    db.commit()
    return build_me(db, u)


@router.post("/verify-email", response_model=Message)
def verify_email(body: TokenIn, request: Request, db: Session = Depends(get_db)) -> Message:
    get_limiter().hit(f"verify:{client_ip(request)}", 20, 3600)
    auth_svc.verify_email(db, body.token)
    db.commit()
    return Message(message="Email address verified.")


@router.post("/password/forgot", response_model=Message, status_code=202)
def forgot(body: EmailIn, request: Request, db: Session = Depends(get_db)) -> Message:
    s = get_settings()
    get_limiter().hit(f"forgot:{client_ip(request)}", 5, 3600)
    res = auth_svc.request_password_reset(db, body.email)
    if res:
        user, token = res
        queue_simple(
            db, tenant_id=None, channel="email", recipient=user.email, category="account",
            subject=f"Reset your {s.product_name} password",
            body=f"A password reset was requested for your account.\n\nReset it here (valid 30 minutes): "
                 f"{s.public_base_url}/reset-password?token={token}\n\nIf you did not request this, ignore this email.",
            idempotency_key=f"reset:{user.id}:{token[:8]}",
        )
    db.commit()
    # Same response whether or not the account exists.
    return Message(message="If an account exists for that address, a reset link has been sent.")


@router.post("/password/reset", response_model=Message)
def reset(body: ResetIn, request: Request, db: Session = Depends(get_db)) -> Message:
    get_limiter().hit(f"reset:{client_ip(request)}", 10, 3600)
    auth_svc.reset_password(db, body.token, body.password)
    db.commit()
    return Message(message="Password updated. Please sign in.")


@router.post("/password/change", response_model=Message)
def change_password(body: ChangePasswordIn, principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)) -> Message:
    get_limiter().hit(f"pwchange:{principal.user.id}", 5, 900)
    auth_svc.change_password(db, principal.user, body.current_password, body.new_password,
                             principal.session.id if principal.session else None)
    db.commit()
    return Message(message="Password changed. Other sessions were signed out.")


class MfaEnrolOut(BaseModel):
    secret: str
    otpauth_uri: str


@router.post("/mfa/enroll", response_model=MfaEnrolOut)
def mfa_enroll(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> MfaEnrolOut:
    secret, uri = auth_svc.begin_mfa_enrolment(db, principal.user)
    db.commit()
    return MfaEnrolOut(secret=secret, otpauth_uri=uri)


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


@router.post("/mfa/enroll/confirm", response_model=RecoveryCodesOut)
def mfa_confirm(body: CodeIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> RecoveryCodesOut:
    get_limiter().hit(f"mfa-confirm:{principal.user.id}", 10, 300)
    codes = auth_svc.confirm_mfa_enrolment(db, principal.user, body.code)
    db.commit()
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/mfa/disable", response_model=Message)
def mfa_disable(body: PasswordIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Message:
    auth_svc.disable_mfa(db, principal.user, body.password)
    db.commit()
    return Message(message="Multi-factor authentication disabled.")


class SessionOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    current: bool


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[SessionOut]:
    rows = db.execute(
        select(UserSession).where(UserSession.user_id == principal.user.id, UserSession.revoked_at.is_(None),
                                  UserSession.expires_at > utcnow()).order_by(UserSession.last_seen_at.desc())
    ).scalars()
    cur = principal.session.id if principal.session else None
    return [SessionOut(id=s.id, created_at=s.created_at, last_seen_at=s.last_seen_at, expires_at=s.expires_at,
                       ip_address=s.ip_address, user_agent=s.user_agent, current=s.id == cur) for s in rows]


@router.delete("/sessions/{session_id}", response_model=Message)
def revoke_session(session_id: uuid.UUID, principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)) -> Message:
    sess = db.get(UserSession, session_id)
    if sess is None or sess.user_id != principal.user.id:
        raise NotFound("Session not found.")
    sess.revoked_at = utcnow()
    audit.record(db, "auth.session_revoked", actor=principal.actor(), target_type="session", target_id=session_id)
    db.commit()
    return Message(message="Session revoked.")


class LoginEventOut(BaseModel):
    created_at: datetime
    success: bool
    reason: str
    ip_address: str | None
    user_agent: str | None


@router.get("/login-history", response_model=list[LoginEventOut])
def login_history(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[LoginEventOut]:
    rows = db.execute(
        select(LoginEvent).where(LoginEvent.user_id == principal.user.id).order_by(LoginEvent.created_at.desc()).limit(50)
    ).scalars()
    return [LoginEventOut(created_at=r.created_at, success=r.success, reason=r.reason, ip_address=r.ip_address,
                          user_agent=r.user_agent) for r in rows]
