"""Data-subject rights under the Nigeria Data Protection Act 2023 (access, portability, erasure).

* ``export_user_data``: everything CyberWatch holds about a person as a user (self-service, JSON).
* ``anonymise_user``: erasure on request, run by Trust Data staff after checking the request. The account
  is de-identified rather than deleted so the organisation's records and the hash-chained audit trail stay
  intact; audit entries keep only the random user id (records kept for security and legal obligations, as
  the privacy notice explains).

Customer website content (files, hashes) belongs to the customer organisation as controller; CyberWatch
processes it on their behalf, and it is removed when the organisation deletes the website or closes.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.errors import NotFound, ValidationFailed
from app.core.security import hash_password
from app.db.base import utcnow
from app.models import (
    AlertRecipient,
    ApiToken,
    AuditEvent,
    LoginEvent,
    Notification,
    PlatformRoleAssignment,
    Tenant,
    TenantMembership,
    User,
    UserSession,
)
from app.services import audit
from app.services.audit import AuditActor


def export_user_data(db: Session, user: User) -> dict[str, Any]:
    memberships = db.execute(
        select(TenantMembership, Tenant).join(Tenant, Tenant.id == TenantMembership.tenant_id)
        .where(TenantMembership.user_id == user.id)
    ).all()
    sessions = db.execute(select(UserSession).where(UserSession.user_id == user.id)
                          .order_by(UserSession.created_at.desc())).scalars().all()
    logins = db.execute(select(LoginEvent).where(LoginEvent.user_id == user.id)
                        .order_by(LoginEvent.created_at.desc())).scalars().all()
    notes = db.execute(select(Notification).where(Notification.recipient.in_([user.email, user.phone or "-"]))
                       .order_by(Notification.created_at.desc()).limit(2000)).scalars().all()
    actions = db.execute(select(AuditEvent).where(AuditEvent.actor_user_id == user.id)
                         .order_by(AuditEvent.seq.desc()).limit(5000)).scalars().all()
    tokens = db.execute(select(ApiToken).where(ApiToken.user_id == user.id)).scalars().all()
    return {
        "generated_at": utcnow(),
        "about": ("Personal data TrustData CyberWatch holds about you as a user. Monitoring data about your "
                  "organisation's websites belongs to the organisation and is exported from its Reports page."),
        "profile": {
            "id": str(user.id), "email": user.email, "full_name": user.full_name, "phone": user.phone,
            "created_at": user.created_at, "email_verified_at": user.email_verified_at,
            "mfa_enabled": user.mfa_enabled, "last_login_at": user.last_login_at, "preferences": user.preferences,
            "is_platform_staff": user.is_platform_staff,
        },
        "organisations": [{"organisation": t.name, "role": m.role_key, "status": m.status, "joined_at": m.created_at}
                          for m, t in memberships],
        "sessions": [{"created_at": s.created_at, "last_seen_at": s.last_seen_at, "expires_at": s.expires_at,
                      "revoked_at": s.revoked_at, "ip_address": s.ip_address, "user_agent": s.user_agent}
                     for s in sessions],
        "sign_in_history": [{"at": e.created_at, "success": e.success, "reason": e.reason,
                             "ip_address": e.ip_address, "user_agent": e.user_agent} for e in logins],
        "api_tokens": [{"name": t.name, "created_at": t.created_at, "expires_at": t.expires_at,
                        "last_used_at": t.last_used_at, "revoked_at": t.revoked_at} for t in tokens],
        "messages_sent_to_you": [{"at": n.created_at, "channel": n.channel, "subject": n.subject, "status": n.status}
                                 for n in notes],
        "your_actions_in_the_audit_trail": [{"at": a.occurred_at, "action": a.action, "outcome": a.outcome,
                                             "ip_address": a.ip_address} for a in actions],
    }


def anonymise_user(db: Session, email: str, actor: AuditActor, reason: str) -> uuid.UUID:
    user = db.execute(select(User).where(func.lower(User.email) == email.strip().lower())).scalar_one_or_none()
    if user is None:
        raise NotFound("No user with that email address.")
    if db.execute(select(PlatformRoleAssignment).where(PlatformRoleAssignment.user_id == user.id)).first():
        raise ValidationFailed("Remove this person's Trust Data staff roles first.")
    for m in db.execute(select(TenantMembership).where(TenantMembership.user_id == user.id,
                                                       TenantMembership.status == "active",
                                                       TenantMembership.role_key == "owner")).scalars():
        owners = db.execute(select(func.count()).select_from(TenantMembership).where(
            TenantMembership.tenant_id == m.tenant_id, TenantMembership.status == "active",
            TenantMembership.role_key == "owner")).scalar_one()
        members = db.execute(select(func.count()).select_from(TenantMembership).where(
            TenantMembership.tenant_id == m.tenant_id, TenantMembership.status == "active")).scalar_one()
        if owners == 1 and members > 1:
            name = db.get(Tenant, m.tenant_id).name
            raise ValidationFailed(f"{user.email} is the only owner of {name}, which has other members. "
                                   "Transfer ownership first.")
    old_email, old_phone = user.email, user.phone
    user.email = f"deleted-{user.id.hex[:12]}@anonymised.invalid"
    user.full_name = "Deleted user"
    user.phone = None
    user.preferences = {}
    user.password_hash = hash_password(secrets.token_urlsafe(32))
    user.mfa_enabled, user.mfa_key_id, user.mfa_nonce, user.mfa_ciphertext = False, None, None, None
    user.mfa_recovery_digests, user.mfa_last_step = [], None
    user.is_active = False
    db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    db.execute(delete(LoginEvent).where((LoginEvent.user_id == user.id) | (func.lower(LoginEvent.email) == old_email.lower())))
    for t in db.execute(select(ApiToken).where(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))).scalars():
        t.revoked_at = utcnow()
    for m in db.execute(select(TenantMembership).where(TenantMembership.user_id == user.id)).scalars():
        m.status = "disabled"
    db.execute(delete(AlertRecipient).where((AlertRecipient.user_id == user.id)
                                            | (func.lower(AlertRecipient.email) == old_email.lower())))
    for n in db.execute(select(Notification).where(Notification.recipient.in_([old_email, old_phone or "-"]))).scalars():
        n.recipient = "anonymised"
    audit.record(db, "user.anonymised", actor=actor, target_type="user", target_id=user.id,
                 details={"reason": reason[:500]})
    return user.id
