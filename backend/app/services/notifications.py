"""Notification routing and asynchronous dispatch (email and WhatsApp).

Routing (``route_incident``) runs inside the detection transaction and only
creates ``notifications`` rows; delivery happens later in the dispatcher
(``dispatch_due``), so a provider outage never blocks monitoring.

Guarantees:

* Idempotency: each row has a unique ``idempotency_key`` derived from the
  incident, trigger, channel and recipient, so job retries cannot create
  duplicates.
* Bounded retries with exponential backoff and jitter.
* Optional email fallback when WhatsApp delivery permanently fails.
* Messages contain no secrets and no file contents.
* A channel with no configured provider records ``unconfigured`` rather than
  pretending to have sent anything.
"""

from __future__ import annotations

import random
import smtplib
import ssl
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Any
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.base import utcnow
from app.models import (
    AlertPolicy,
    AlertRecipient,
    Incident,
    Notification,
    Tenant,
    TenantMembership,
    User,
    Website,
)
from app.models.incidents import SEVERITY_RANK

log = get_logger(__name__)

SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}


@dataclass
class Target:
    channel: str
    address: str


def _in_quiet_hours(quiet: dict | None, now: datetime) -> datetime | None:
    """Return when quiet hours end if ``now`` falls inside them, else None."""
    if not quiet or not quiet.get("start") or not quiet.get("end"):
        return None
    tz = ZoneInfo(quiet.get("timezone") or "Africa/Lagos")
    local = now.astimezone(tz)
    sh, sm = (int(x) for x in quiet["start"].split(":"))
    eh, em = (int(x) for x in quiet["end"].split(":"))
    start = local.replace(hour=sh, minute=sm, second=0, microsecond=0)
    end = local.replace(hour=eh, minute=em, second=0, microsecond=0)
    if start <= end:
        inside = start <= local < end
        end_at = end
    else:  # spans midnight
        inside = local >= start or local < end
        end_at = end if local < end else end + timedelta(days=1)
    return end_at.astimezone(ZoneInfo("UTC")) if inside else None


def _policy_matches(policy: AlertPolicy, incident: Incident, website: Website | None) -> bool:
    if not policy.enabled:
        return False
    if SEVERITY_RANK[incident.severity] < SEVERITY_RANK[policy.min_severity]:
        return False
    if policy.categories and incident.category not in policy.categories:
        return False
    if policy.website_ids and incident.website_id not in policy.website_ids:
        return False
    if policy.group_ids and (website is None or website.group_id not in policy.group_ids):
        return False
    return True


def _resolve_targets(db: Session, policy: AlertPolicy, recipients: list[AlertRecipient]) -> list[Target]:
    targets: list[Target] = []
    for r in recipients:
        users: list[User] = []
        if r.user_id:
            # Only current, active members of this tenant are eligible.
            u = db.execute(
                select(User).join(TenantMembership, TenantMembership.user_id == User.id).where(
                    User.id == r.user_id,
                    User.is_active.is_(True),
                    TenantMembership.tenant_id == policy.tenant_id,
                    TenantMembership.status == "active",
                )
            ).scalar_one_or_none()
            if u:
                users.append(u)
        if r.role_key:
            users.extend(
                db.execute(
                    select(User).join(TenantMembership, TenantMembership.user_id == User.id).where(
                        TenantMembership.tenant_id == policy.tenant_id,
                        TenantMembership.role_key == r.role_key,
                        TenantMembership.status == "active",
                        User.is_active.is_(True),
                    )
                ).scalars()
            )
        for u in users:
            if "email" in policy.channels:
                targets.append(Target("email", u.email))
            if "whatsapp" in policy.channels and u.phone and u.preferences.get("whatsapp_opt_in"):
                targets.append(Target("whatsapp", u.phone))
        if r.email and "email" in policy.channels:
            targets.append(Target("email", r.email.lower()))
        if r.whatsapp_number and "whatsapp" in policy.channels and r.whatsapp_opt_in_at:
            targets.append(Target("whatsapp", r.whatsapp_number))
    seen: set[tuple[str, str]] = set()
    unique = []
    for t in targets:
        if (t.channel, t.address) not in seen:
            seen.add((t.channel, t.address))
            unique.append(t)
    return unique


def monthly_usage(db: Session, tenant_id: uuid.UUID) -> int:
    start = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return db.execute(
        select(func.count()).select_from(Notification).where(
            Notification.tenant_id == tenant_id,
            Notification.created_at >= start,
            Notification.status.notin_(["suppressed"]),
        )
    ).scalar_one()


def render_incident(incident: Incident, website: Website | None, tenant: Tenant, reason: str) -> tuple[str, str, dict[str, str]]:
    settings = get_settings()
    sev = SEVERITY_LABEL[incident.severity]
    site = website.name if website else "Platform"
    verb = {"incident_opened": "New incident", "incident_escalated": "Incident escalated",
            "incident_reminder": "Unacknowledged incident"}.get(reason, "Incident update")
    subject = f"[{sev}] {verb}: {incident.title} ({incident.reference})"
    link = f"{settings.public_base_url}/app/{tenant.id}/incidents/{incident.id}"
    demo = "\n\n[DEMONSTRATION DATA — not a real security event]" if incident.is_demo or tenant.is_demo else ""
    body = (
        f"{verb} for {tenant.name}\n\n"
        f"Reference: {incident.reference}\n"
        f"Severity: {sev}\n"
        f"Website: {site}\n"
        f"Category: {incident.category.replace('_', ' ')}\n"
        f"Detected: {incident.first_detected_at:%Y-%m-%d %H:%M} UTC\n\n"
        f"{incident.summary}\n\n"
        f"Recommended action: {incident.recommended_action}\n\n"
        f"View the incident: {link}\n\n"
        "Findings are produced by automated monitoring and may require human verification. "
        f"{settings.product_name} does not guarantee detection of every threat.{demo}\n\n"
        f"— {settings.product_name}, {settings.company_name}"
    )
    params = {"severity": sev, "title": incident.title[:60], "website": site[:60], "reference": incident.reference}
    return subject, body, params


def route_incident(db: Session, incident: Incident, reason: str) -> list[Notification]:
    tenant = db.get(Tenant, incident.tenant_id)
    if tenant is None or tenant.status != "active":
        return []
    website = db.get(Website, incident.website_id) if incident.website_id else None
    policies = db.execute(
        select(AlertPolicy).where(AlertPolicy.tenant_id == incident.tenant_id, AlertPolicy.enabled.is_(True))
    ).scalars().all()
    from app.services.entitlements import effective

    ent = effective(db, incident.tenant_id)
    quota = int(ent.get("notifications_per_month", 0))
    whatsapp_allowed = bool(ent.get("whatsapp_notifications", False))
    used = monthly_usage(db, incident.tenant_id)
    now = utcnow()
    created: list[Notification] = []
    subject, body, params = render_incident(incident, website, tenant, reason)
    for policy in policies:
        if not _policy_matches(policy, incident, website):
            continue
        recipients = db.execute(select(AlertRecipient).where(AlertRecipient.policy_id == policy.id)).scalars().all()
        due = now + timedelta(minutes=policy.escalation_delay_minutes if policy.escalation_stage > 0 else 0)
        quiet_end = _in_quiet_hours(policy.quiet_hours, due)
        bypass = (policy.quiet_hours or {}).get("bypass_severity", "critical")
        if quiet_end and SEVERITY_RANK[incident.severity] < SEVERITY_RANK.get(bypass, 4):
            due = quiet_end
        for target in _resolve_targets(db, policy, recipients):
            status = "pending"
            last_error = None
            if target.channel == "whatsapp" and not whatsapp_allowed:
                status, last_error = "suppressed", "WhatsApp notifications are not included in the current plan."
            elif used >= quota:
                status, last_error = "suppressed", "Monthly notification quota reached."
            key = f"inc:{incident.id}:{reason}:{incident.severity}:{incident.occurrence_count if reason != 'incident_opened' else 1}:p{policy.id}:{target.channel}:{target.address}"
            n = Notification(
                tenant_id=incident.tenant_id,
                incident_id=incident.id,
                policy_id=policy.id,
                channel=target.channel,
                category=reason,
                recipient=target.address,
                template="incident_alert",
                subject=subject,
                body=body,
                params={**params, "escalation_stage": policy.escalation_stage},
                status=status,
                last_error=last_error,
                next_attempt_at=due,
                idempotency_key=key[:200],
            )
            try:
                with db.begin_nested():
                    db.add(n)
                    db.flush()
            except IntegrityError:
                continue  # already queued by a previous attempt
            if status == "pending":
                used += 1
            created.append(n)
    return created


def queue_simple(
    db: Session,
    *,
    tenant_id: uuid.UUID | None,
    channel: str,
    recipient: str,
    category: str,
    subject: str,
    body: str,
    idempotency_key: str,
    template: str = "generic",
    params: dict[str, Any] | None = None,
) -> Notification | None:
    n = Notification(
        tenant_id=tenant_id, channel=channel, category=category, recipient=recipient, template=template,
        subject=subject, body=body, params=params or {}, idempotency_key=idempotency_key[:200],
    )
    try:
        with db.begin_nested():
            db.add(n)
            db.flush()
    except IntegrityError:
        return None
    return n


# --------------------------------------------------------------------------
# Provider adapters
# --------------------------------------------------------------------------


class DeliveryError(Exception):
    def __init__(self, message: str, permanent: bool = False):
        super().__init__(message)
        self.permanent = permanent


class ProviderUnconfigured(Exception):
    pass


def send_email(to: str, subject: str, body: str) -> str:
    s = get_settings()
    if not s.smtp_host:
        raise ProviderUnconfigured("SMTP is not configured.")
    msg = EmailMessage()
    msg["From"] = s.email_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=20) as smtp:
            if s.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if s.smtp_username and s.smtp_password:
                smtp.login(s.smtp_username, s.smtp_password.get_secret_value())
            refused = smtp.send_message(msg)
    except smtplib.SMTPRecipientsRefused as exc:
        raise DeliveryError("Recipient address was refused.", permanent=True) from exc
    except smtplib.SMTPAuthenticationError as exc:
        raise DeliveryError("SMTP authentication failed.") from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise DeliveryError(f"SMTP delivery failed ({type(exc).__name__}).") from exc
    if refused:
        raise DeliveryError("Recipient address was refused.", permanent=True)
    return msg.get("Message-ID") or ""


def send_whatsapp_template(to: str, template_name: str, language: str, body_params: list[str]) -> str:
    """Send an approved template message through the WhatsApp Cloud API."""
    s = get_settings()
    if not (s.whatsapp_phone_number_id and s.whatsapp_access_token):
        raise ProviderUnconfigured("WhatsApp Cloud API is not configured.")
    url = f"{s.whatsapp_api_base}/{s.whatsapp_api_version}/{s.whatsapp_phone_number_id}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": to.lstrip("+"),
        "type": "template",
        "template": {
            "name": template_name,
            "language": {"code": language},
            "components": [
                {"type": "body", "parameters": [{"type": "text", "text": p} for p in body_params]}
            ],
        },
    }
    try:
        resp = httpx.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {s.whatsapp_access_token.get_secret_value()}"},
            timeout=20,
        )
    except httpx.HTTPError as exc:
        raise DeliveryError(f"WhatsApp API unreachable ({type(exc).__name__}).") from exc
    if resp.status_code == 429:
        raise DeliveryError("WhatsApp rate limit reached.")
    if resp.status_code >= 500:
        raise DeliveryError(f"WhatsApp API error HTTP {resp.status_code}.")
    if resp.status_code >= 400:
        try:
            err = resp.json().get("error", {})
            detail = f"{err.get('code')}: {err.get('message', '')[:200]}"
        except ValueError:
            detail = f"HTTP {resp.status_code}"
        raise DeliveryError(f"WhatsApp rejected the message ({detail}).", permanent=True)
    try:
        return resp.json()["messages"][0]["id"]
    except (ValueError, KeyError, IndexError):
        return ""


WHATSAPP_TEMPLATES = {
    # template key -> (approved template name, language, ordered param names)
    "incident_alert": ("cyberwatch_incident_alert", "en", ["severity", "title", "website", "reference"]),
    "test": ("cyberwatch_test_message", "en", []),
}


def _backoff(attempt: int) -> timedelta:
    base = min(60 * (2 ** (attempt - 1)), 3600)
    return timedelta(seconds=base + random.uniform(0, base * 0.2))  # noqa: S311


def deliver(db: Session, n: Notification) -> None:
    """Attempt delivery of one notification row (caller holds the row lock)."""
    now = utcnow()
    if n.incident_id and (n.params or {}).get("escalation_stage", 0) > 0:
        inc = db.get(Incident, n.incident_id)
        if inc is None or inc.status != "new":
            n.status, n.last_error = "suppressed", "Escalation cancelled: incident was acknowledged."
            return
    n.attempts += 1
    n.status = "sending"
    try:
        if n.channel == "email":
            n.provider_message_id = send_email(n.recipient, n.subject, n.body)
        elif n.channel == "whatsapp":
            name, lang, keys = WHATSAPP_TEMPLATES.get(n.template, WHATSAPP_TEMPLATES["test"])
            n.provider_message_id = send_whatsapp_template(
                n.recipient, name, lang, [str(n.params.get(k, "")) for k in keys]
            )
        else:
            raise DeliveryError(f"Unknown channel {n.channel}", permanent=True)
        n.status, n.sent_at, n.last_error = "sent", now, None
    except ProviderUnconfigured as exc:
        n.status, n.last_error = "unconfigured", str(exc)
        _maybe_fallback(db, n)
    except DeliveryError as exc:
        n.last_error = str(exc)
        if exc.permanent or n.attempts >= n.max_attempts:
            n.status = "failed"
            _maybe_fallback(db, n)
        else:
            n.status = "pending"
            n.next_attempt_at = now + _backoff(n.attempts)


def _maybe_fallback(db: Session, n: Notification) -> None:
    if n.channel != "whatsapp" or n.policy_id is None or n.incident_id is None:
        return
    policy = db.get(AlertPolicy, n.policy_id)
    if policy is None or not policy.email_fallback:
        return
    # Fall back to the email addresses of members with this phone number.
    users = db.execute(
        select(User).join(TenantMembership, TenantMembership.user_id == User.id).where(
            User.phone == n.recipient, TenantMembership.tenant_id == n.tenant_id
        )
    ).scalars().all()
    for u in users:
        queue_simple(
            db,
            tenant_id=n.tenant_id,
            channel="email",
            recipient=u.email,
            category=n.category,
            subject=n.subject,
            body=n.body,
            template=n.template,
            params=n.params,
            idempotency_key=f"fallback:{n.id}:{u.email}",
        )


def dispatch_due(db: Session, batch: int = 50) -> dict[str, int]:
    rows = db.execute(
        select(Notification)
        .where(Notification.status == "pending", Notification.next_attempt_at <= utcnow())
        .order_by(Notification.next_attempt_at)
        .limit(batch)
        .with_for_update(skip_locked=True)
    ).scalars().all()
    stats = {"processed": 0, "sent": 0, "failed": 0, "retrying": 0, "unconfigured": 0, "suppressed": 0}
    for n in rows:
        deliver(db, n)
        stats["processed"] += 1
        key = {"pending": "retrying"}.get(n.status, n.status)
        if key in stats:
            stats[key] += 1
    db.commit()
    return stats


def channel_status() -> dict[str, dict[str, Any]]:
    s = get_settings()
    return {
        "email": {"configured": bool(s.smtp_host), "provider": "smtp", "host": s.smtp_host},
        "whatsapp": {
            "configured": bool(s.whatsapp_phone_number_id and s.whatsapp_access_token),
            "provider": "whatsapp_cloud_api",
            "api_version": s.whatsapp_api_version,
        },
    }
