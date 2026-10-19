"""Authentication: registration, login, sessions, MFA, password reset."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import get_settings
from app.core.crypto import CredentialVault, EncryptedBlob, get_vault
from app.core.errors import AppError, Conflict, Unauthenticated, ValidationFailed
from app.db.base import utcnow
from app.models import EmailToken, LoginEvent, Tenant, TenantMembership, User, UserSession
from app.services import audit
from app.services.audit import AuditActor

MAX_FAILED_LOGINS = 8
LOCKOUT_MINUTES = 15
EMAIL_TOKEN_TTL = {"verify_email": timedelta(days=2), "password_reset": timedelta(minutes=30)}


def normalise_email(email: str) -> str:
    return (email or "").strip().lower()


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:60] or "org"


@dataclass
class IssuedSession:
    session: UserSession
    token: str
    csrf_token: str


def _issue_session(db: Session, user: User, ip: str | None, ua: str | None, mfa_pending: bool) -> IssuedSession:
    settings = get_settings()
    token = security.new_token("cws_")
    csrf = security.new_token(nbytes=24)
    now = utcnow()
    sess = UserSession(
        user_id=user.id,
        token_digest=security.token_digest(token),
        csrf_digest=security.token_digest(csrf),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(minutes=settings.session_ttl_minutes),
        mfa_pending=mfa_pending,
        ip_address=ip,
        user_agent=(ua or "")[:400] or None,
    )
    db.add(sess)
    db.flush()
    return IssuedSession(sess, token, csrf)


def register(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str,
    organisation_name: str,
    actor: AuditActor,
) -> tuple[User, Tenant, str]:
    """Create a user, their organisation (as owner) and a trial. Returns the verify token."""
    from app.services import entitlements

    email = normalise_email(email)
    problems = security.password_problems(password, email)
    if problems:
        raise ValidationFailed("Password does not meet requirements.", details=problems)
    if db.execute(select(User.id).where(User.email == email)).first():
        # Do not reveal whether the address is registered beyond this endpoint's
        # inherent signal; the message is generic.
        raise Conflict("An account with this email address already exists.")
    user = User(email=email, full_name=full_name.strip(), password_hash=security.hash_password(password))
    user.password_changed_at = utcnow()
    db.add(user)
    db.flush()
    base_slug = slugify(organisation_name)
    slug = base_slug
    i = 1
    while db.execute(select(Tenant.id).where(Tenant.slug == slug)).first():
        i += 1
        slug = f"{base_slug}-{i}"
    tenant = Tenant(name=organisation_name.strip(), slug=slug, contact_email=email)
    db.add(tenant)
    db.flush()
    db.add(TenantMembership(tenant_id=tenant.id, user_id=user.id, role_key="owner"))
    entitlements.start_trial(db, tenant)
    token = create_email_token(db, user, "verify_email")
    actor = AuditActor(**{**actor.__dict__, "user_id": user.id, "actor_type": "user"})
    audit.record(db, "auth.register", actor=actor, tenant_id=tenant.id, target_type="user", target_id=user.id)
    audit.record(
        db, "tenant.created", actor=actor, tenant_id=tenant.id, target_type="tenant", target_id=tenant.id,
        details={"name": tenant.name},
    )
    return user, tenant, token


def create_email_token(db: Session, user: User, purpose: str) -> str:
    token = security.new_token()
    db.add(
        EmailToken(
            user_id=user.id,
            purpose=purpose,
            token_digest=security.token_digest(token),
            expires_at=utcnow() + EMAIL_TOKEN_TTL[purpose],
        )
    )
    db.flush()
    return token


def consume_email_token(db: Session, token: str, purpose: str) -> User:
    row = db.execute(
        select(EmailToken).where(EmailToken.token_digest == security.token_digest(token or ""))
        .with_for_update()
    ).scalar_one_or_none()
    if row is None or row.purpose != purpose or row.used_at is not None or row.expires_at < utcnow():
        raise AppError("This link is invalid or has expired.", code="invalid_token")
    row.used_at = utcnow()
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise AppError("This link is invalid or has expired.", code="invalid_token")
    return user


def verify_email(db: Session, token: str) -> User:
    user = consume_email_token(db, token, "verify_email")
    user.email_verified_at = user.email_verified_at or utcnow()
    audit.record(db, "auth.email_verified", actor=AuditActor(user_id=user.id, actor_type="user"),
                 target_type="user", target_id=user.id)
    return user


def _log_login(db: Session, email: str, user: User | None, success: bool, reason: str, ip: str | None, ua: str | None) -> None:
    db.add(LoginEvent(user_id=user.id if user else None, email=email, success=success, reason=reason,
                      ip_address=ip, user_agent=(ua or "")[:400] or None))


def login(db: Session, *, email: str, password: str, ip: str | None, ua: str | None) -> IssuedSession:
    email = normalise_email(email)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    now = utcnow()
    actor = AuditActor(user_id=user.id if user else None, actor_type="user" if user else "anonymous",
                       ip_address=ip, user_agent=ua)
    if user and user.locked_until and user.locked_until > now:
        security.verify_password(None, password)
        _log_login(db, email, user, False, "locked", ip, ua)
        audit.record(db, "auth.login", actor=actor, outcome="denied", details={"reason": "locked"})
        db.commit()
        raise Unauthenticated("Account temporarily locked after repeated failures. Try again later.",
                              code="account_locked")
    if user is None or not user.is_active or not security.verify_password(user.password_hash, password):
        reason = "bad_credentials" if user is None or user.is_active else "inactive"
        if user is not None and user.is_active:
            user.failed_login_count += 1
            if user.failed_login_count >= MAX_FAILED_LOGINS:
                user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                user.failed_login_count = 0
                reason = "locked_now"
        _log_login(db, email, user, False, reason, ip, ua)
        audit.record(db, "auth.login", actor=actor, outcome="denied", details={"reason": reason, "email": email})
        db.commit()
        raise Unauthenticated("Email or password is incorrect.", code="invalid_credentials")
    settings = get_settings()
    if settings.is_production_like and user.email_verified_at is None:
        _log_login(db, email, user, False, "email_unverified", ip, ua)
        db.commit()
        raise Unauthenticated("Please verify your email address before signing in.", code="email_unverified")
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    if user.password_hash and security.password_needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(password)
    issued = _issue_session(db, user, ip, ua, mfa_pending=user.mfa_enabled)
    _log_login(db, email, user, True, "mfa_pending" if user.mfa_enabled else "ok", ip, ua)
    audit.record(db, "auth.login", actor=actor, details={"mfa_pending": user.mfa_enabled})
    return issued


def _mfa_secret(user: User, vault: CredentialVault) -> str:
    if not (user.mfa_ciphertext and user.mfa_nonce and user.mfa_key_id):
        raise AppError("MFA is not configured.", code="mfa_not_configured")
    blob = EncryptedBlob(user.mfa_key_id, user.mfa_nonce, user.mfa_ciphertext)
    return vault.decrypt(blob, CredentialVault.associated_data("user", user.id, "totp")).decode()


def complete_mfa(db: Session, sess: UserSession, user: User, code: str, ip: str | None) -> None:
    ok = False
    try:
        ok = security.verify_totp(_mfa_secret(user, get_vault()), code)
    except AppError:
        ok = False
    if not ok:
        digest = security.token_digest((code or "").strip().lower())
        if digest in (user.mfa_recovery_digests or []):
            user.mfa_recovery_digests = [d for d in user.mfa_recovery_digests if d != digest]
            ok = True
            audit.record(db, "auth.mfa_recovery_code_used", actor=AuditActor(user_id=user.id, actor_type="user", ip_address=ip))
    if not ok:
        audit.record(db, "auth.mfa_verify", actor=AuditActor(user_id=user.id, actor_type="user", ip_address=ip), outcome="denied")
        db.commit()
        raise Unauthenticated("The verification code is not valid.", code="invalid_mfa_code")
    sess.mfa_pending = False
    audit.record(db, "auth.mfa_verify", actor=AuditActor(user_id=user.id, actor_type="user", ip_address=ip))


def begin_mfa_enrolment(db: Session, user: User) -> tuple[str, str]:
    if user.mfa_enabled:
        raise Conflict("MFA is already enabled.")
    secret = security.new_totp_secret()
    vault = get_vault()
    blob = vault.encrypt(secret.encode(), CredentialVault.associated_data("user", user.id, "totp"))
    user.mfa_key_id, user.mfa_nonce, user.mfa_ciphertext = blob.key_id, blob.nonce, blob.ciphertext
    settings = get_settings()
    return secret, security.totp_uri(secret, user.email, settings.product_name)


def confirm_mfa_enrolment(db: Session, user: User, code: str) -> list[str]:
    if not security.verify_totp(_mfa_secret(user, get_vault()), code):
        raise ValidationFailed("The verification code is not valid.", code="invalid_mfa_code")
    codes = security.new_recovery_codes()
    user.mfa_enabled = True
    user.mfa_recovery_digests = [security.token_digest(c) for c in codes]
    audit.record(db, "auth.mfa_enabled", actor=AuditActor(user_id=user.id, actor_type="user"),
                 target_type="user", target_id=user.id)
    return codes


def disable_mfa(db: Session, user: User, password: str) -> None:
    if not security.verify_password(user.password_hash, password):
        raise Unauthenticated("Password is incorrect.", code="invalid_credentials")
    if user.is_platform_staff and get_settings().require_platform_mfa:
        raise AppError("MFA is mandatory for platform staff.", code="mfa_required")
    user.mfa_enabled = False
    user.mfa_key_id = user.mfa_nonce = user.mfa_ciphertext = None
    user.mfa_recovery_digests = []
    audit.record(db, "auth.mfa_disabled", actor=AuditActor(user_id=user.id, actor_type="user"),
                 target_type="user", target_id=user.id)


def change_password(db: Session, user: User, current: str, new: str, keep_session_id: uuid.UUID | None) -> None:
    if not security.verify_password(user.password_hash, current):
        raise Unauthenticated("Current password is incorrect.", code="invalid_credentials")
    problems = security.password_problems(new, user.email)
    if problems:
        raise ValidationFailed("Password does not meet requirements.", details=problems)
    user.password_hash = security.hash_password(new)
    user.password_changed_at = utcnow()
    revoke_user_sessions(db, user.id, except_session_id=keep_session_id)
    audit.record(db, "auth.password_changed", actor=AuditActor(user_id=user.id, actor_type="user"),
                 target_type="user", target_id=user.id)


def request_password_reset(db: Session, email: str) -> tuple[User, str] | None:
    user = db.execute(select(User).where(User.email == normalise_email(email))).scalar_one_or_none()
    if user is None or not user.is_active:
        return None
    token = create_email_token(db, user, "password_reset")
    audit.record(db, "auth.password_reset_requested", actor=AuditActor(user_id=user.id, actor_type="user"))
    return user, token


def reset_password(db: Session, token: str, new_password: str) -> User:
    user = consume_email_token(db, token, "password_reset")
    problems = security.password_problems(new_password, user.email)
    if problems:
        raise ValidationFailed("Password does not meet requirements.", details=problems)
    user.password_hash = security.hash_password(new_password)
    user.password_changed_at = utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    revoke_user_sessions(db, user.id)
    audit.record(db, "auth.password_reset", actor=AuditActor(user_id=user.id, actor_type="user"),
                 target_type="user", target_id=user.id)
    return user


def revoke_user_sessions(db: Session, user_id: uuid.UUID, except_session_id: uuid.UUID | None = None) -> int:
    q = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_session_id:
        q = q.where(UserSession.id != except_session_id)
    return db.execute(q.values(revoked_at=utcnow())).rowcount or 0


def resolve_session(db: Session, token: str) -> tuple[UserSession, User] | None:
    if not token or not token.startswith("cws_"):
        return None
    sess = db.execute(
        select(UserSession).where(UserSession.token_digest == security.token_digest(token))
    ).scalar_one_or_none()
    now = utcnow()
    settings = get_settings()
    if sess is None or sess.revoked_at is not None or sess.expires_at <= now:
        return None
    if sess.last_seen_at + timedelta(minutes=settings.session_idle_minutes) <= now:
        sess.revoked_at = now
        db.commit()
        return None
    user = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        return None
    if (now - sess.last_seen_at).total_seconds() > 60:
        sess.last_seen_at = now
        db.commit()
    return sess, user
