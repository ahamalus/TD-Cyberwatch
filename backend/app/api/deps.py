"""Request authentication, tenant context and permission dependencies.

Every tenant-scoped route takes ``tenant_id`` from the path and resolves it
through :func:`tenant_context`, which:

1. verifies the caller is an active member of that tenant, **or** holds an
   active managed-service grant for it (Trust Data staff), and
2. applies the PostgreSQL RLS tenant scope to the DB session.

A caller with no relationship to the tenant receives 404, not 403, so tenant
IDs cannot be enumerated.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import Depends, Path, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, Forbidden, NotFound, Unauthenticated
from app.core.permissions import GRANTABLE_TENANT_PERMISSIONS
from app.core.security import constant_time_equals, token_digest
from app.db.base import utcnow
from app.db.session import get_db, set_platform_scope, set_tenant_scope
from app.models import (
    ApiToken,
    ManagedServiceGrant,
    RolePermission,
    Tenant,
    TenantMembership,
    User,
    UserSession,
)
from app.services.audit import AuditActor

SESSION_COOKIE = "cw_session"
CSRF_COOKIE = "cw_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class Principal:
    user: User
    session: UserSession | None
    api_token: ApiToken | None
    platform_permissions: frozenset[str]
    ip: str | None
    user_agent: str | None
    request_id: str | None

    @property
    def is_staff(self) -> bool:
        return self.user.is_platform_staff

    def actor(self, via_grant_id: uuid.UUID | None = None) -> AuditActor:
        return AuditActor(
            user_id=self.user.id,
            actor_type="staff" if self.user.is_platform_staff else "user",
            ip_address=self.ip,
            user_agent=self.user_agent,
            request_id=self.request_id,
            via_grant_id=via_grant_id,
        )


@dataclass
class TenantContext:
    tenant: Tenant
    principal: Principal
    permissions: frozenset[str]
    role_key: str | None
    grant: ManagedServiceGrant | None = None
    read_only: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.tenant.id

    @property
    def user(self) -> User:
        return self.principal.user

    def actor(self) -> AuditActor:
        return self.principal.actor(self.grant.id if self.grant else None)

    def has(self, perm: str) -> bool:
        return perm in self.permissions


def client_ip(request: Request) -> str | None:
    # The reverse proxy must set X-Forwarded-For; uvicorn's --proxy-headers with
    # --forwarded-allow-ips restricts which proxies are trusted.
    return request.client.host if request.client else None


def role_permissions(db: Session, role_key: str) -> frozenset[str]:
    return frozenset(
        db.execute(select(RolePermission.permission_code).where(RolePermission.role_key == role_key)).scalars()
    )


def platform_permissions_for(db: Session, user: User) -> frozenset[str]:
    if not user.is_platform_staff:
        return frozenset()
    if get_settings().require_platform_mfa and not user.mfa_enabled:
        # Platform privileges are withheld until MFA is enrolled.
        return frozenset()
    perms: set[str] = set()
    for assignment in user.platform_roles:
        perms |= role_permissions(db, assignment.role_key)
    return frozenset(perms)


def _authenticate(request: Request, db: Session, allow_mfa_pending: bool = False) -> Principal:
    ip = client_ip(request)
    ua = request.headers.get("user-agent")
    rid = getattr(request.state, "request_id", None)
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        raw = auth_header[7:].strip()
        if not raw.startswith("cwp_"):
            raise Unauthenticated("Invalid API token.")
        tok = db.execute(select(ApiToken).where(ApiToken.token_digest == token_digest(raw))).scalar_one_or_none()
        now = utcnow()
        if tok is None or tok.revoked_at is not None or tok.expires_at <= now:
            raise Unauthenticated("Invalid or expired API token.")
        user = db.get(User, tok.user_id)
        if user is None or not user.is_active:
            raise Unauthenticated("Invalid API token.")
        tok.last_used_at = now
        db.commit()
        return Principal(user, None, tok, frozenset(), ip, ua, rid)

    from app.services.auth import resolve_session

    raw = request.cookies.get(SESSION_COOKIE, "")
    resolved = resolve_session(db, raw)
    if resolved is None:
        raise Unauthenticated("Please sign in.")
    sess, user = resolved
    if sess.mfa_pending and not allow_mfa_pending:
        raise Unauthenticated("Multi-factor verification required.", code="mfa_required")
    if request.method not in SAFE_METHODS:
        header = request.headers.get(CSRF_HEADER, "")
        if not header or not constant_time_equals(token_digest(header), sess.csrf_digest):
            raise Forbidden("Missing or invalid CSRF token.", code="csrf_failed")
    return Principal(user, sess, None, platform_permissions_for(db, user), ip, ua, rid)


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    return _authenticate(request, db)


def current_principal_mfa_pending(request: Request, db: Session = Depends(get_db)) -> Principal:
    return _authenticate(request, db, allow_mfa_pending=True)


def active_grant(db: Session, tenant_id: uuid.UUID, user_id: uuid.UUID) -> ManagedServiceGrant | None:
    now = utcnow()
    return db.execute(
        select(ManagedServiceGrant)
        .where(
            ManagedServiceGrant.tenant_id == tenant_id,
            ManagedServiceGrant.grantee_user_id == user_id,
            ManagedServiceGrant.status == "active",
            ManagedServiceGrant.expires_at > now,
            ManagedServiceGrant.revoked_at.is_(None),
        )
        .order_by(ManagedServiceGrant.expires_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def tenant_context(
    request: Request,
    tenant_id: uuid.UUID = Path(...),
    principal: Principal = Depends(current_principal),
    db: Session = Depends(get_db),
) -> TenantContext:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise NotFound("Organisation not found.")
    ctx: TenantContext | None = None

    if principal.api_token is not None:
        if principal.api_token.tenant_id != tenant_id:
            raise NotFound("Organisation not found.")

    membership = db.execute(
        select(TenantMembership).where(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.user_id == principal.user.id,
            TenantMembership.status == "active",
        )
    ).scalar_one_or_none()
    if membership is not None:
        perms = role_permissions(db, membership.role_key)
        if principal.api_token is not None:
            perms = perms & frozenset(principal.api_token.scopes)
        ctx = TenantContext(tenant, principal, perms, membership.role_key)
    elif principal.is_staff and principal.api_token is None:
        grant = active_grant(db, tenant_id, principal.user.id)
        if grant is not None and principal.platform_permissions:
            perms = frozenset(grant.permissions) & GRANTABLE_TENANT_PERMISSIONS
            ctx = TenantContext(tenant, principal, perms, None, grant=grant)
    if ctx is None:
        raise NotFound("Organisation not found.")

    if tenant.status == "deactivated" and ctx.grant is None:
        raise Forbidden("This organisation has been deactivated.", code="tenant_deactivated")
    if tenant.status != "active":
        ctx.read_only = True

    set_tenant_scope(db, tenant_id)
    request.state.tenant_id = tenant_id
    return ctx


def require(*perms: str) -> Callable[[TenantContext], TenantContext]:
    """Dependency factory: require all listed tenant permissions."""

    def _dep(ctx: TenantContext = Depends(tenant_context)) -> TenantContext:
        missing = [p for p in perms if p not in ctx.permissions]
        if missing:
            raise Forbidden("You do not have permission to perform this action.", details={"missing": missing})
        if ctx.read_only and any(p.endswith((":manage", ":run", ":approve", ":generate")) for p in perms):
            raise AppError(
                "This organisation is suspended; changes are disabled.", code="tenant_suspended", status_code=423
            )
        return ctx

    return _dep


@dataclass
class PlatformContext:
    principal: Principal
    db: Session

    def actor(self) -> AuditActor:
        return self.principal.actor()


def require_platform(*perms: str) -> Callable[..., PlatformContext]:
    def _dep(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> PlatformContext:
        if not principal.is_staff or principal.api_token is not None:
            raise NotFound("Not found.")
        if not principal.platform_permissions:
            raise Forbidden(
                "Multi-factor authentication must be enabled to use platform functions.", code="mfa_enrolment_required"
            )
        missing = [p for p in perms if p not in principal.platform_permissions]
        if missing:
            raise Forbidden("You do not have permission to perform this action.", details={"missing": missing})
        set_platform_scope(db)
        return PlatformContext(principal, db)

    return _dep
