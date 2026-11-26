"""WhatsApp Cloud API webhook: delivery receipts and opt-outs.

Meta calls one URL for the whole app:

* ``GET`` subscription check: answered with ``hub.challenge`` only when ``hub.verify_token`` matches
  ``CW_WHATSAPP_VERIFY_TOKEN``.
* ``POST`` events, signed with ``X-Hub-Signature-256`` (HMAC-SHA256 of the raw body with the app secret,
  ``CW_WHATSAPP_APP_SECRET``). Unsigned or wrongly signed requests are rejected.

Handled events:

* message status ``sent`` / ``delivered`` / ``read`` / ``failed`` for messages CyberWatch sent. A message
  that fails *after* Meta accepted it (e.g. the number is not on WhatsApp) is marked failed and, where the
  alert policy allows, the alert is sent by email instead.
* an incoming text ``STOP`` (or UNSUBSCRIBE / OPT OUT) from a number: WhatsApp alerts to that number stop
  for every organisation, as messaging rules require. ``START`` is not processed automatically; the person
  opts in again in CyberWatch.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.base import utcnow
from app.models import AlertRecipient, Notification, User, WebhookEvent
from app.services import audit

log = get_logger(__name__)

# Later states never move back (a late "delivered" after "read" is ignored).
RANK = {"sent": 1, "delivered": 2, "read": 3, "failed": 4}
STOP_WORDS = {"stop", "unsubscribe", "opt out", "optout", "stop alerts"}


def digits(number: str | None) -> str:
    return re.sub(r"\D", "", number or "")


def verify_subscription(mode: str | None, token: str | None, challenge: str | None) -> str | None:
    expected = get_settings().whatsapp_verify_token
    if mode != "subscribe" or not expected or not token or not challenge:
        return None
    if not hmac.compare_digest(token, expected.get_secret_value()):
        return None
    return challenge


def signature_valid(raw_body: bytes, header: str | None) -> bool:
    secret = get_settings().whatsapp_app_secret
    if not secret or not header or not header.startswith("sha256="):
        return False
    mac = hmac.new(secret.get_secret_value().encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, header[len("sha256="):])


def process(db: Session, raw_body: bytes, signature: str | None) -> tuple[int, dict[str, int]]:
    """Must run in platform scope (opt-outs update tenant-owned recipients)."""
    if not signature_valid(raw_body, signature):
        log.warning("whatsapp_webhook_bad_signature")
        return 401, {}
    try:
        payload = json.loads(raw_body)
    except ValueError:
        return 400, {}
    stats = {"statuses": 0, "failed": 0, "opt_outs": 0, "duplicates": 0, "unknown": 0}
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            value = change.get("value") or {}
            for st in value.get("statuses") or []:
                _status(db, st, stats)
            for msg in value.get("messages") or []:
                _incoming(db, msg, stats)
    db.commit()
    return 200, stats


def _dedupe(db: Session, key: str, event_type: str, payload: dict[str, Any]) -> WebhookEvent | None:
    row = WebhookEvent(provider="whatsapp", event_type=event_type[:64], dedupe_key=key[:200], signature_valid=True,
                       payload=payload)
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        return None
    return row


def _status(db: Session, st: dict[str, Any], stats: dict[str, int]) -> None:
    from app.services.notifications import _maybe_fallback

    wamid, status = str(st.get("id", "")), str(st.get("status", ""))
    if not wamid or status not in RANK:
        return
    errors = [{"code": e.get("code"), "title": str(e.get("title", ""))[:200]} for e in (st.get("errors") or [])]
    # No phone number or message content is stored: only the delivery state.
    row = _dedupe(db, f"whatsapp:{wamid}:{status}", f"status.{status}",
                  {"id": wamid, "status": status, "timestamp": st.get("timestamp"), "errors": errors})
    if row is None:
        stats["duplicates"] += 1
        return
    n = db.execute(select(Notification).where(Notification.channel == "whatsapp",
                                              Notification.provider_message_id == wamid)).scalar_one_or_none()
    row.processed_at = utcnow()
    if n is None:
        row.status, row.error = "ignored", "Unknown message"
        stats["unknown"] += 1
        return
    row.tenant_id, row.status = n.tenant_id, "processed"
    stats["statuses"] += 1
    if RANK.get(n.delivery_status or "", 0) >= RANK[status]:
        return
    at = _ts(st.get("timestamp"))
    n.delivery_status = status
    if status == "delivered":
        n.delivered_at = at
    elif status == "read":
        n.read_at = at
        n.delivered_at = n.delivered_at or at
    elif status == "failed":
        detail = "; ".join(f"{e['code']}: {e['title']}" for e in errors) or "no reason given"
        n.status, n.last_error = "failed", f"WhatsApp could not deliver the message ({detail})."[:2000]
        stats["failed"] += 1
        _maybe_fallback(db, n)


def _incoming(db: Session, msg: dict[str, Any], stats: dict[str, int]) -> None:
    text = str(((msg.get("text") or {}).get("body")) or (msg.get("button") or {}).get("text") or "").strip().lower()
    if text not in STOP_WORDS:
        return  # message content is never stored
    number = digits(msg.get("from"))
    if not number or _dedupe(db, f"whatsapp:in:{msg.get('id', '')}", "opt_out", {"id": msg.get("id")}) is None:
        return
    changed = 0
    for r in db.execute(select(AlertRecipient).where(AlertRecipient.whatsapp_opt_in_at.is_not(None))).scalars():
        if digits(r.whatsapp_number) == number:
            r.whatsapp_opt_in_at = None
            changed += 1
            audit.record(db, "whatsapp.opt_out", tenant_id=r.tenant_id, target_type="alert_recipient",
                         target_id=r.id, details={"source": "STOP reply"})
    for u in db.execute(select(User).where(User.phone.is_not(None))).scalars():
        if digits(u.phone) == number and (u.preferences or {}).get("whatsapp_opt_in"):
            u.preferences = {**u.preferences, "whatsapp_opt_in": False, "whatsapp_opt_in_at": None}
            changed += 1
            audit.record(db, "whatsapp.opt_out", target_type="user", target_id=u.id, details={"source": "STOP reply"})
    stats["opt_outs"] += changed


def _ts(value: Any) -> datetime:
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (TypeError, ValueError):
        return utcnow()
