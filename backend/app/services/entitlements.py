"""Plan entitlements and their enforcement.

Limits come from the tenant's current subscription plan (configurable data,
never hard-coded in endpoints). Without an active or trialing subscription,
or after the grace period, the tenant falls back to restricted entitlements:
existing data stays readable but new monitoring capacity is not granted.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import LimitExceeded
from app.db.base import utcnow
from app.models import HostingAccount, Plan, Subscription, Tenant, TenantMembership, Website
from app.services.seed import RESTRICTED_ENTITLEMENTS

SERVICE_STATUSES = ("trialing", "active", "past_due", "grace_period")


@dataclass
class EffectiveEntitlements:
    plan_key: str | None
    plan_name: str | None
    subscription_status: str | None
    in_service: bool
    limits: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        return self.limits.get(key, default)


def current_subscription(db: Session, tenant_id: uuid.UUID) -> Subscription | None:
    return db.execute(
        select(Subscription).where(Subscription.tenant_id == tenant_id, Subscription.is_current.is_(True))
    ).scalar_one_or_none()


def start_trial(db: Session, tenant: Tenant, plan_key: str = "business") -> Subscription | None:
    settings = get_settings()
    plan = db.execute(select(Plan).where(Plan.key == plan_key, Plan.is_active.is_(True))).scalar_one_or_none()
    if plan is None or settings.trial_days <= 0:
        return None
    now = utcnow()
    sub = Subscription(
        tenant_id=tenant.id,
        plan_id=plan.id,
        status="trialing",
        interval="monthly",
        current_period_start=now,
        current_period_end=now + timedelta(days=settings.trial_days),
        trial_ends_at=now + timedelta(days=settings.trial_days),
        is_current=True,
    )
    db.add(sub)
    db.flush()
    return sub


def _subscription_in_service(sub: Subscription) -> bool:
    now = utcnow()
    if sub.status == "trialing":
        return bool(sub.trial_ends_at and sub.trial_ends_at > now)
    if sub.status in ("active", "past_due"):
        return bool(sub.current_period_end and sub.current_period_end > now) or bool(
            sub.grace_until and sub.grace_until > now
        )
    if sub.status == "grace_period":
        return bool(sub.grace_until and sub.grace_until > now)
    if sub.status == "cancelled":
        # Service continues until the paid period ends.
        return bool(sub.current_period_end and sub.current_period_end > now)
    return False


def effective(db: Session, tenant_id: uuid.UUID) -> EffectiveEntitlements:
    sub = current_subscription(db, tenant_id)
    if sub is None:
        return EffectiveEntitlements(None, None, None, False, dict(RESTRICTED_ENTITLEMENTS))
    plan = db.get(Plan, sub.plan_id)
    in_service = _subscription_in_service(sub)
    limits = dict(plan.entitlements) if (plan and in_service) else dict(RESTRICTED_ENTITLEMENTS)
    return EffectiveEntitlements(
        plan.key if plan else None, plan.name if plan else None, sub.status, in_service, limits
    )


def usage(db: Session, tenant_id: uuid.UUID) -> dict[str, int]:
    websites = db.execute(select(func.count()).select_from(Website).where(Website.tenant_id == tenant_id)).scalar_one()
    accounts = db.execute(
        select(func.count()).select_from(HostingAccount).where(HostingAccount.tenant_id == tenant_id)
    ).scalar_one()
    users = db.execute(
        select(func.count()).select_from(TenantMembership).where(
            TenantMembership.tenant_id == tenant_id, TenantMembership.status == "active"
        )
    ).scalar_one()
    return {"websites": websites, "hosting_accounts": accounts, "users": users}


_LIMIT_KEYS = {"websites": "max_websites", "hosting_accounts": "max_hosting_accounts", "users": "max_users"}


def require_capacity(db: Session, tenant_id: uuid.UUID, resource: str, adding: int = 1) -> None:
    ent = effective(db, tenant_id)
    limit = int(ent.get(_LIMIT_KEYS[resource], 0))
    current = usage(db, tenant_id)[resource]
    if current + adding > limit:
        if not ent.in_service:
            raise LimitExceeded(
                "Your subscription is not active. Renew or choose a plan to add more resources.",
                details={"resource": resource, "limit": limit, "current": current},
            )
        raise LimitExceeded(
            f"Your {ent.plan_name} plan allows {limit} {resource.replace('_', ' ')}. "
            "Upgrade your plan to add more.",
            details={"resource": resource, "limit": limit, "current": current},
        )


def clamp_interval(db: Session, tenant_id: uuid.UUID, kind: str, requested: int) -> int:
    """Validate a requested monitoring interval against the plan minimum."""
    ent = effective(db, tenant_id)
    key = "min_file_scan_interval_minutes" if kind == "file_scan" else "min_availability_interval_minutes"
    minimum = int(ent.get(key, 1440))
    if requested < minimum:
        raise LimitExceeded(
            f"Your plan allows a minimum interval of {minimum} minutes for this check.",
            details={"minimum": minimum, "requested": requested, "kind": kind},
        )
    return requested
