"""Organisation profile, team membership, invitations, groups, grants, API tokens."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, TenantContext, current_principal, require
from app.core.config import get_settings
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from app.core.permissions import ALL_ROLES, GRANTABLE_TENANT_PERMISSIONS, P
from app.core.security import new_token, token_digest
from app.db.base import utcnow
from app.db.session import get_db
from app.models import (
    ApiToken,
    AuditEvent,
    Invitation,
    ManagedServiceGrant,
    TenantMembership,
    User,
    WebsiteGroup,
)
from app.schemas.common import Message, PageParams, paginate
from app.services import audit, entitlements
from app.services.notifications import queue_simple

router = APIRouter(prefix="/tenants/{tenant_id}", tags=["organisation"])
public_router = APIRouter(tags=["organisation"])

TENANT_ROLE_KEYS = {k for k, r in ALL_ROLES.items() if r.scope == "tenant"}


class TenantOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    status: str
    country: str
    industry: str | None
    contact_email: str | None
    contact_phone: str | None
    timezone: str
    is_demo: bool
    created_at: datetime
    role: str | None
    permissions: list[str]
    via_managed_service_grant: bool
    read_only: bool
    entitlements: dict
    usage: dict
    plan: dict


class TenantPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    industry: str | None = Field(default=None, max_length=80)
    contact_email: EmailStr | None = None
    contact_phone: str | None = Field(default=None, pattern=r"^\+[1-9]\d{7,14}$")
    timezone: str | None = Field(default=None, max_length=64)


def tenant_out(db: Session, ctx: TenantContext) -> TenantOut:
    t = ctx.tenant
    ent = entitlements.effective(db, t.id)
    return TenantOut(
        id=t.id, name=t.name, slug=t.slug, status=t.status, country=t.country, industry=t.industry,
        contact_email=t.contact_email, contact_phone=t.contact_phone, timezone=t.timezone, is_demo=t.is_demo,
        created_at=t.created_at, role=ctx.role_key, permissions=sorted(ctx.permissions),
        via_managed_service_grant=ctx.grant is not None, read_only=ctx.read_only,
        entitlements=ent.limits, usage=entitlements.usage(db, t.id),
        plan={"key": ent.plan_key, "name": ent.plan_name, "status": ent.subscription_status,
              "in_service": ent.in_service},
    )


@router.get("", response_model=TenantOut)
def get_tenant(ctx: TenantContext = Depends(require(P.TENANT_READ)), db: Session = Depends(get_db)) -> TenantOut:
    return tenant_out(db, ctx)


@router.patch("", response_model=TenantOut)
def patch_tenant(body: TenantPatch, ctx: TenantContext = Depends(require(P.TENANT_MANAGE)),
                 db: Session = Depends(get_db)) -> TenantOut:
    changes = body.model_dump(exclude_none=True)
    if "timezone" in changes:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

        try:
            ZoneInfo(changes["timezone"])
        except ZoneInfoNotFoundError as exc:
            raise ValidationFailed("Unknown timezone.") from exc
    for k, v in changes.items():
        setattr(ctx.tenant, k, v)
    audit.record(db, "tenant.updated", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="tenant",
                 target_id=ctx.tenant_id, details={"fields": sorted(changes)})
    db.commit()
    return tenant_out(db, ctx)


# ---------------------------------------------------------------- members


class MemberOut(BaseModel):
    membership_id: uuid.UUID
    user_id: uuid.UUID
    email: str
    full_name: str
    role: str
    status: str
    department: str | None
    mfa_enabled: bool
    last_login_at: datetime | None
    joined_at: datetime


class MemberPatch(BaseModel):
    role: str | None = None
    status: str | None = Field(default=None, pattern="^(active|disabled)$")
    department: str | None = Field(default=None, max_length=120)


class InvitationIn(BaseModel):
    email: EmailStr
    role: str


class InvitationOut(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


@router.get("/members", response_model=list[MemberOut])
def list_members(ctx: TenantContext = Depends(require(P.MEMBERS_READ)), db: Session = Depends(get_db)) -> list[MemberOut]:
    rows = db.execute(
        select(TenantMembership, User).join(User, User.id == TenantMembership.user_id)
        .where(TenantMembership.tenant_id == ctx.tenant_id).order_by(User.full_name)
    ).all()
    return [MemberOut(membership_id=m.id, user_id=u.id, email=u.email, full_name=u.full_name, role=m.role_key,
                      status=m.status, department=m.department, mfa_enabled=u.mfa_enabled,
                      last_login_at=u.last_login_at, joined_at=m.created_at) for m, u in rows]


def _owner_count(db: Session, tenant_id: uuid.UUID) -> int:
    return len(db.execute(select(TenantMembership.id).where(
        TenantMembership.tenant_id == tenant_id, TenantMembership.role_key == "owner",
        TenantMembership.status == "active")).all())


@router.patch("/members/{membership_id}", response_model=Message)
def patch_member(membership_id: uuid.UUID, body: MemberPatch, ctx: TenantContext = Depends(require(P.MEMBERS_MANAGE)),
                 db: Session = Depends(get_db)) -> Message:
    m = db.execute(select(TenantMembership).where(TenantMembership.id == membership_id,
                                                  TenantMembership.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if m is None:
        raise NotFound("Member not found.")
    if body.role is not None:
        if body.role not in TENANT_ROLE_KEYS:
            raise ValidationFailed("Unknown role.")
        # Only owners may grant or remove the owner role (prevents escalation by admins).
        if (body.role == "owner" or m.role_key == "owner") and ctx.role_key != "owner":
            raise Forbidden("Only an organisation owner can change owner roles.")
        if m.role_key == "owner" and body.role != "owner" and _owner_count(db, ctx.tenant_id) <= 1:
            raise ValidationFailed("An organisation must keep at least one owner.")
    if body.status == "disabled" and m.role_key == "owner" and _owner_count(db, ctx.tenant_id) <= 1:
        raise ValidationFailed("The last owner cannot be disabled.")
    if m.user_id == ctx.user.id and body.role is not None and body.role != m.role_key:
        raise ValidationFailed("You cannot change your own role.")
    before = {"role": m.role_key, "status": m.status}
    if body.role is not None:
        m.role_key = body.role
    if body.status is not None:
        m.status = body.status
    if body.department is not None:
        m.department = body.department
    audit.record(db, "member.updated", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="membership",
                 target_id=m.id, details={"before": before, "after": {"role": m.role_key, "status": m.status}})
    db.commit()
    return Message(message="Member updated.")


@router.delete("/members/{membership_id}", response_model=Message)
def remove_member(membership_id: uuid.UUID, ctx: TenantContext = Depends(require(P.MEMBERS_MANAGE)),
                  db: Session = Depends(get_db)) -> Message:
    m = db.execute(select(TenantMembership).where(TenantMembership.id == membership_id,
                                                  TenantMembership.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if m is None:
        raise NotFound("Member not found.")
    if m.role_key == "owner" and (ctx.role_key != "owner" or _owner_count(db, ctx.tenant_id) <= 1):
        raise ValidationFailed("This owner cannot be removed.")
    db.delete(m)
    audit.record(db, "member.removed", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="membership",
                 target_id=membership_id, details={"user_id": str(m.user_id)})
    db.commit()
    return Message(message="Member removed.")


@router.get("/invitations", response_model=list[InvitationOut])
def list_invitations(ctx: TenantContext = Depends(require(P.MEMBERS_READ)), db: Session = Depends(get_db)) -> list[InvitationOut]:
    rows = db.execute(select(Invitation).where(Invitation.tenant_id == ctx.tenant_id)
                      .order_by(Invitation.created_at.desc()).limit(100)).scalars()
    return [InvitationOut(id=i.id, email=i.email, role=i.role_key, expires_at=i.expires_at, accepted_at=i.accepted_at,
                          revoked_at=i.revoked_at, created_at=i.created_at) for i in rows]


@router.post("/invitations", response_model=InvitationOut, status_code=201)
def invite(body: InvitationIn, ctx: TenantContext = Depends(require(P.MEMBERS_MANAGE)),
           db: Session = Depends(get_db)) -> InvitationOut:
    if body.role not in TENANT_ROLE_KEYS:
        raise ValidationFailed("Unknown role.")
    if body.role == "owner" and ctx.role_key != "owner":
        raise Forbidden("Only an owner can invite another owner.")
    entitlements.require_capacity(db, ctx.tenant_id, "users")
    email = body.email.lower()
    existing_user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing_user and db.execute(select(TenantMembership.id).where(
            TenantMembership.tenant_id == ctx.tenant_id, TenantMembership.user_id == existing_user.id)).first():
        raise Conflict("This person is already a member.")
    token = new_token()
    inv = Invitation(tenant_id=ctx.tenant_id, email=email, role_key=body.role, token_digest=token_digest(token),
                     invited_by=ctx.user.id, expires_at=utcnow() + timedelta(days=7))
    db.add(inv)
    db.flush()
    s = get_settings()
    queue_simple(db, tenant_id=ctx.tenant_id, channel="email", recipient=email, category="account",
                 subject=f"You have been invited to {ctx.tenant.name} on {s.product_name}",
                 body=f"{ctx.user.full_name or ctx.user.email} invited you to join {ctx.tenant.name} as "
                      f"{ALL_ROLES[body.role].name}.\n\nAccept the invitation: {s.public_base_url}/invite?token={token}\n\n"
                      "This invitation expires in 7 days.",
                 idempotency_key=f"invite:{inv.id}")
    audit.record(db, "member.invited", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="invitation",
                 target_id=inv.id, details={"email": email, "role": body.role})
    db.commit()
    return InvitationOut(id=inv.id, email=inv.email, role=inv.role_key, expires_at=inv.expires_at,
                         accepted_at=None, revoked_at=None, created_at=inv.created_at)


@router.delete("/invitations/{invitation_id}", response_model=Message)
def revoke_invitation(invitation_id: uuid.UUID, ctx: TenantContext = Depends(require(P.MEMBERS_MANAGE)),
                      db: Session = Depends(get_db)) -> Message:
    inv = db.execute(select(Invitation).where(Invitation.id == invitation_id,
                                              Invitation.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if inv is None:
        raise NotFound("Invitation not found.")
    inv.revoked_at = utcnow()
    audit.record(db, "member.invitation_revoked", actor=ctx.actor(), tenant_id=ctx.tenant_id,
                 target_type="invitation", target_id=inv.id)
    db.commit()
    return Message(message="Invitation revoked.")


class AcceptIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)


@public_router.post("/invitations/accept", response_model=Message)
def accept_invitation(body: AcceptIn, principal: Principal = Depends(current_principal),
                      db: Session = Depends(get_db)) -> Message:
    inv = db.execute(select(Invitation).where(Invitation.token_digest == token_digest(body.token))
                     .with_for_update()).scalar_one_or_none()
    now = utcnow()
    if inv is None or inv.accepted_at or inv.revoked_at or inv.expires_at <= now:
        raise ValidationFailed("This invitation is invalid or has expired.")
    if inv.email != principal.user.email:
        raise Forbidden("This invitation was sent to a different email address.")
    if db.execute(select(TenantMembership.id).where(TenantMembership.tenant_id == inv.tenant_id,
                                                    TenantMembership.user_id == principal.user.id)).first():
        raise Conflict("You are already a member of this organisation.")
    entitlements.require_capacity(db, inv.tenant_id, "users")
    db.add(TenantMembership(tenant_id=inv.tenant_id, user_id=principal.user.id, role_key=inv.role_key))
    inv.accepted_at = now
    audit.record(db, "member.joined", actor=principal.actor(), tenant_id=inv.tenant_id, target_type="invitation",
                 target_id=inv.id, details={"role": inv.role_key})
    db.commit()
    return Message(message="Invitation accepted.")


# ---------------------------------------------------------------- groups


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(default="business_unit", pattern="^(business_unit|environment|client|other)$")


class GroupOut(BaseModel):
    id: uuid.UUID
    name: str
    kind: str


@router.get("/groups", response_model=list[GroupOut])
def list_groups(ctx: TenantContext = Depends(require(P.WEBSITES_READ)), db: Session = Depends(get_db)) -> list[GroupOut]:
    rows = db.execute(select(WebsiteGroup).where(WebsiteGroup.tenant_id == ctx.tenant_id).order_by(WebsiteGroup.name)).scalars()
    return [GroupOut(id=g.id, name=g.name, kind=g.kind) for g in rows]


@router.post("/groups", response_model=GroupOut, status_code=201)
def create_group(body: GroupIn, ctx: TenantContext = Depends(require(P.WEBSITES_MANAGE)),
                 db: Session = Depends(get_db)) -> GroupOut:
    if db.execute(select(WebsiteGroup.id).where(WebsiteGroup.tenant_id == ctx.tenant_id,
                                                WebsiteGroup.name == body.name)).first():
        raise Conflict("A group with this name already exists.")
    g = WebsiteGroup(tenant_id=ctx.tenant_id, name=body.name, kind=body.kind)
    db.add(g)
    db.flush()
    audit.record(db, "group.created", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="group", target_id=g.id)
    db.commit()
    return GroupOut(id=g.id, name=g.name, kind=g.kind)


@router.delete("/groups/{group_id}", response_model=Message)
def delete_group(group_id: uuid.UUID, ctx: TenantContext = Depends(require(P.WEBSITES_MANAGE)),
                 db: Session = Depends(get_db)) -> Message:
    g = db.execute(select(WebsiteGroup).where(WebsiteGroup.id == group_id,
                                              WebsiteGroup.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if g is None:
        raise NotFound("Group not found.")
    db.delete(g)
    audit.record(db, "group.deleted", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="group", target_id=group_id)
    db.commit()
    return Message(message="Group deleted.")


# ---------------------------------------------------------------- activity


class AuditOut(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    actor_type: str
    action: str
    category: str
    target_type: str | None
    target_id: str | None
    outcome: str
    ip_address: str | None
    details: dict
    via_grant_id: uuid.UUID | None


def audit_rows_out(db: Session, rows: list[AuditEvent]) -> list[AuditOut]:
    ids = {r.actor_user_id for r in rows if r.actor_user_id}
    emails = dict(db.execute(select(User.id, User.email).where(User.id.in_(ids))).all()) if ids else {}
    return [AuditOut(id=r.id, occurred_at=r.occurred_at, actor_user_id=r.actor_user_id,
                     actor_email=emails.get(r.actor_user_id), actor_type=r.actor_type, action=r.action,
                     category=r.category, target_type=r.target_type, target_id=r.target_id, outcome=r.outcome,
                     ip_address=r.ip_address, details=r.details, via_grant_id=r.via_grant_id) for r in rows]


@router.get("/audit")
def tenant_audit(
    ctx: TenantContext = Depends(require(P.AUDIT_READ)),
    db: Session = Depends(get_db),
    params: PageParams = Depends(),
    action: str | None = Query(None, max_length=80),
    category: str | None = Query(None, max_length=24),
) -> dict:
    q = select(AuditEvent).where(AuditEvent.tenant_id == ctx.tenant_id)
    if action:
        q = q.where(AuditEvent.action.ilike(f"{action}%"))
    if category:
        q = q.where(AuditEvent.category == category)
    page = paginate(db, q.order_by(AuditEvent.seq.desc()), params)
    page["items"] = audit_rows_out(db, page["items"])
    return page


# ---------------------------------------------------------------- managed-service grants


class GrantOut(BaseModel):
    id: uuid.UUID
    grantee_user_id: uuid.UUID
    grantee_email: str | None
    grantee_name: str | None
    permissions: list[str]
    reason: str
    status: str
    expires_at: datetime
    approved_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


def grant_out(db: Session, g: ManagedServiceGrant) -> GrantOut:
    u = db.get(User, g.grantee_user_id)
    status = g.status
    if status == "active" and g.expires_at <= utcnow():
        status = "expired"
    return GrantOut(id=g.id, grantee_user_id=g.grantee_user_id, grantee_email=u.email if u else None,
                    grantee_name=u.full_name if u else None, permissions=g.permissions, reason=g.reason,
                    status=status, expires_at=g.expires_at, approved_at=g.approved_at, revoked_at=g.revoked_at,
                    created_at=g.created_at)


@router.get("/grants", response_model=list[GrantOut])
def list_grants(ctx: TenantContext = Depends(require(P.TENANT_READ)), db: Session = Depends(get_db)) -> list[GrantOut]:
    rows = db.execute(select(ManagedServiceGrant).where(ManagedServiceGrant.tenant_id == ctx.tenant_id)
                      .order_by(ManagedServiceGrant.created_at.desc()).limit(100)).scalars()
    return [grant_out(db, g) for g in rows]


class GrantDecision(BaseModel):
    approve: bool
    duration_hours: int | None = Field(default=None, ge=1, le=24 * 90)


@router.post("/grants/{grant_id}/decision", response_model=GrantOut)
def decide_grant(grant_id: uuid.UUID, body: GrantDecision,
                 ctx: TenantContext = Depends(require(P.MANAGED_SERVICE_APPROVE)),
                 db: Session = Depends(get_db)) -> GrantOut:
    if ctx.grant is not None:
        raise Forbidden("Managed-service grants cannot be approved through a managed-service grant.")
    g = db.execute(select(ManagedServiceGrant).where(ManagedServiceGrant.id == grant_id,
                                                     ManagedServiceGrant.tenant_id == ctx.tenant_id)
                   .with_for_update()).scalar_one_or_none()
    if g is None:
        raise NotFound("Grant not found.")
    if g.status != "requested":
        raise ValidationFailed("Only pending requests can be decided.")
    now = utcnow()
    if body.approve:
        g.status, g.approved_by, g.approved_at, g.starts_at = "active", ctx.user.id, now, now
        if body.duration_hours:
            g.expires_at = min(g.expires_at, now + timedelta(hours=body.duration_hours))
        g.permissions = sorted(set(g.permissions) & GRANTABLE_TENANT_PERMISSIONS)
    else:
        g.status = "rejected"
    audit.record(db, "grant.approved" if body.approve else "grant.rejected", actor=ctx.actor(),
                 tenant_id=ctx.tenant_id, target_type="grant", target_id=g.id,
                 details={"grantee": str(g.grantee_user_id), "permissions": g.permissions,
                          "expires_at": g.expires_at.isoformat()})
    db.commit()
    return grant_out(db, g)


@router.post("/grants/{grant_id}/revoke", response_model=GrantOut)
def revoke_grant(grant_id: uuid.UUID, ctx: TenantContext = Depends(require(P.MANAGED_SERVICE_APPROVE)),
                 db: Session = Depends(get_db)) -> GrantOut:
    g = db.execute(select(ManagedServiceGrant).where(ManagedServiceGrant.id == grant_id,
                                                     ManagedServiceGrant.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if g is None:
        raise NotFound("Grant not found.")
    g.status, g.revoked_at, g.revoked_by = "revoked", utcnow(), ctx.user.id
    audit.record(db, "grant.revoked", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="grant", target_id=g.id)
    db.commit()
    return grant_out(db, g)


# ---------------------------------------------------------------- API tokens


class ApiTokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1)
    expires_in_days: int = Field(default=90, ge=1, le=365)


class ApiTokenOut(BaseModel):
    id: uuid.UUID
    name: str
    token_prefix: str
    scopes: list[str]
    expires_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    token: str | None = None


READ_ONLY_TOKEN_SCOPES = {
    P.TENANT_READ, P.WEBSITES_READ, P.HOSTING_READ, P.MONITORING_READ, P.INVENTORY_READ, P.INCIDENTS_READ,
    P.NOTIFICATIONS_READ, P.REPORTS_READ, P.SCANS_RUN, P.INCIDENTS_MANAGE,
}


@router.get("/api-tokens", response_model=list[ApiTokenOut])
def list_tokens(ctx: TenantContext = Depends(require(P.TENANT_READ)), db: Session = Depends(get_db)) -> list[ApiTokenOut]:
    rows = db.execute(select(ApiToken).where(ApiToken.tenant_id == ctx.tenant_id, ApiToken.user_id == ctx.user.id)
                      .order_by(ApiToken.created_at.desc())).scalars()
    return [ApiTokenOut(id=t.id, name=t.name, token_prefix=t.token_prefix, scopes=t.scopes, expires_at=t.expires_at,
                        revoked_at=t.revoked_at, last_used_at=t.last_used_at, created_at=t.created_at) for t in rows]


@router.post("/api-tokens", response_model=ApiTokenOut, status_code=201)
def create_token(body: ApiTokenIn, ctx: TenantContext = Depends(require(P.TENANT_READ)),
                 db: Session = Depends(get_db)) -> ApiTokenOut:
    if ctx.principal.api_token is not None or ctx.grant is not None:
        raise Forbidden("API tokens must be created from an interactive session by a member.")
    if not entitlements.effective(db, ctx.tenant_id).get("api_access", False):
        raise Forbidden("API access is not included in your plan.", code="plan_feature_unavailable")
    scopes = set(body.scopes)
    bad = scopes - READ_ONLY_TOKEN_SCOPES
    if bad:
        raise ValidationFailed("Unsupported token scopes.", details=sorted(bad))
    if not scopes <= ctx.permissions:
        raise Forbidden("You cannot grant a token permissions you do not hold.")
    raw = new_token("cwp_")
    tok = ApiToken(tenant_id=ctx.tenant_id, user_id=ctx.user.id, name=body.name, token_prefix=raw[:10],
                   token_digest=token_digest(raw), scopes=sorted(scopes),
                   expires_at=utcnow() + timedelta(days=body.expires_in_days))
    db.add(tok)
    db.flush()
    audit.record(db, "api_token.created", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="api_token",
                 target_id=tok.id, details={"scopes": tok.scopes, "expires_at": tok.expires_at.isoformat()})
    db.commit()
    return ApiTokenOut(id=tok.id, name=tok.name, token_prefix=tok.token_prefix, scopes=tok.scopes,
                       expires_at=tok.expires_at, revoked_at=None, last_used_at=None, created_at=tok.created_at,
                       token=raw)


@router.delete("/api-tokens/{token_id}", response_model=Message)
def revoke_token(token_id: uuid.UUID, ctx: TenantContext = Depends(require(P.TENANT_READ)),
                 db: Session = Depends(get_db)) -> Message:
    tok = db.execute(select(ApiToken).where(ApiToken.id == token_id, ApiToken.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if tok is None or (tok.user_id != ctx.user.id and P.MEMBERS_MANAGE not in ctx.permissions):
        raise NotFound("Token not found.")
    tok.revoked_at = utcnow()
    audit.record(db, "api_token.revoked", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="api_token",
                 target_id=tok.id)
    db.commit()
    return Message(message="Token revoked.")

