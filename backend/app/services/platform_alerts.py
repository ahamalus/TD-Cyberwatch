"""Tell people when CyberWatch itself is unhealthy (workers, scheduler, database, Redis, disk, backups, scanner).

The conditions are the alerts of ``health.system_health`` (what the NOC wall and System Health show). This module
turns them into email to on-call staff:

* **New:** an alert must persist for ``GRACE`` before anyone is emailed, so a deploy that restarts workers for a
  minute does not page anyone.
* **Reminder:** while it stays open, again every ``REMIND_AFTER[severity]``.
* **Resolved:** one "all clear" when a notified alert goes away.

It must work when the parts it watches have failed, so it does not use Celery: a watchdog thread in each API
process (``start_watchdog``) evaluates every ``INTERVAL`` and sends email directly over SMTP. A PostgreSQL
advisory lock lets only one process evaluate at a time; state lives in ``platform_settings``. If the database
itself is unreachable there is no shared state, so each process emails that fact at most once an hour.

Recipients: active staff whose roles include ``platform:health:read`` (platform administrators, SOC analysts, NOC
monitors, auditors), plus the addresses in ``CW_PLATFORM_ALERT_EMAILS`` (e.g. an on-call mailbox).
"""

from __future__ import annotations

import copy
import re
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.permissions import ALL_ROLES, P
from app.db.base import utcnow
from app.models import PlatformRoleAssignment, PlatformSetting, User

log = get_logger("platform_alerts")

STATE_KEY = "platform_alerts_state"
GRACE = timedelta(minutes=3)
REMIND_AFTER = {"critical": timedelta(hours=2), "high": timedelta(hours=6), "medium": timedelta(hours=24),
                "low": timedelta(hours=24)}
INTERVAL = 60  # seconds between evaluations
_LOCK_KEY = 0x43574131  # "CWA1"
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

Sender = Callable[[str, str, str], Any]


def alert_key(message: str) -> str:
    """Stable identity of an alert whose message contains changing numbers ("Disk usage at 91.2%")."""
    return re.sub(r"\d+(?:\.\d+)?", "#", message)[:200]


def recipients(db: Session) -> list[str]:
    roles = [k for k, r in ALL_ROLES.items() if r.scope == "platform" and P.PLATFORM_HEALTH_READ in r.permissions]
    staff = db.execute(select(User.email).join(PlatformRoleAssignment, PlatformRoleAssignment.user_id == User.id)
                       .where(User.is_platform_staff.is_(True), User.is_active.is_(True),
                              PlatformRoleAssignment.role_key.in_(roles))).scalars().all()
    extra = [e.strip().lower() for e in get_settings().platform_alert_emails if e.strip()]
    return sorted({e.lower() for e in staff} | set(extra))


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def evaluate(db: Session, now: datetime | None = None, send: Sender | None = None,
             current: list[dict] | None = None) -> dict[str, Any]:
    """One evaluation. Returns what was sent (for tests and the CLI). Caller commits."""
    if not db.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": _LOCK_KEY}).scalar():
        return {"skipped": "another process is evaluating"}
    now = now or utcnow()
    if current is None:
        from app.services.health import system_health

        current = system_health(db)["alerts"]
    row = db.get(PlatformSetting, STATE_KEY)
    # Deep copy: mutating the loaded JSON in place would hide the change from SQLAlchemy (no UPDATE issued).
    state: dict[str, dict] = copy.deepcopy(row.value) if row else {}
    seen = {}
    for a in current:
        seen[alert_key(a["message"])] = a

    new, reminders, resolved = [], [], []
    for key, a in seen.items():
        s = state.get(key)
        if s is None:
            state[key] = {"message": a["message"], "severity": a["severity"], "first_seen": _iso(now),
                          "last_notified": None}
            continue
        s["message"], s["severity"] = a["message"], a["severity"]
        if s["last_notified"] is None:
            if now - datetime.fromisoformat(s["first_seen"]) >= GRACE:
                new.append(s)
                s["last_notified"] = _iso(now)
        elif now - datetime.fromisoformat(s["last_notified"]) >= REMIND_AFTER.get(s["severity"], REMIND_AFTER["low"]):
            reminders.append(s)
            s["last_notified"] = _iso(now)
    for key in list(state):
        if key not in seen:
            s = state.pop(key)
            if s.get("last_notified"):
                resolved.append(s)

    if row is None:
        row = PlatformSetting(key=STATE_KEY, value={}, description="Open platform alerts and when staff were told.")
        db.add(row)
    row.value, row.updated_at = state, now

    sent_to: list[str] = []
    if new or reminders or resolved:
        to = recipients(db)
        subject, body = compose(new, reminders, resolved, [s for s in state.values() if s.get("last_notified")])
        sent_to = deliver(to, subject, body, send)
        from app.services import audit

        audit.record(db, "platform.alerts_notified",
                     details={"new": [s["message"] for s in new], "reminders": [s["message"] for s in reminders],
                              "resolved": [s["message"] for s in resolved], "recipients": len(sent_to)})
    return {"new": new, "reminders": reminders, "resolved": resolved, "recipients": sent_to,
            "open": len(state)}


def compose(new: list[dict], reminders: list[dict], resolved: list[dict], still_open: list[dict]) -> tuple[str, str]:
    s = get_settings()
    problems = sorted(new + reminders, key=lambda a: _RANK.get(a["severity"], 9))
    if problems:
        worst = problems[0]
        more = f" (+{len(problems) - 1} more)" if len(problems) > 1 else ""
        subject = f"[{s.product_name}] {worst['severity'].upper()}: {worst['message']}{more}"
    else:
        subject = f"[{s.product_name}] Resolved: {resolved[0]['message']}" + (
            f" (+{len(resolved) - 1} more)" if len(resolved) > 1 else "")
    lines = []

    def section(title: str, items: list[dict], resolved_section: bool = False) -> None:
        if not items:
            return
        lines.append(title)
        for a in items:
            since = datetime.fromisoformat(a["first_seen"]).strftime("%d %b %H:%M UTC")
            lines.append(f"  - {'' if resolved_section else '[' + a['severity'] + '] '}{a['message']} (since {since})")
        lines.append("")

    section("New problems:", [a for a in sorted(new, key=lambda a: _RANK.get(a["severity"], 9))])
    section("Still not fixed:", [a for a in sorted(reminders, key=lambda a: _RANK.get(a["severity"], 9))])
    section("Resolved:", resolved, resolved_section=True)
    others = [a for a in still_open if a not in new and a not in reminders]
    section("Also still open (already reported):", others)
    lines += [
        f"Live status: {s.public_base_url.rstrip('/')}/ops/workers (System Health) and /ops/noc (NOC wall).",
        "Runbook: docs/OPERATIONS.md (Common problems).",
        "",
        "You receive this because your staff role can read platform health. Reminders are sent every 2 hours "
        "(critical), 6 hours (high) or 24 hours (medium) until fixed.",
    ]
    return subject[:250], "\n".join(lines)


def deliver(to: list[str], subject: str, body: str, send: Sender | None) -> list[str]:
    if send is None:
        from app.services.notifications import send_email as send
    ok = []
    for addr in to:
        try:
            send(addr, subject, body)
            ok.append(addr)
        except Exception as exc:  # noqa: BLE001 - one bad address or an SMTP outage must not stop the others
            log.error("platform_alert_email_failed", recipient=addr, error=str(exc)[:200])
    if not to:
        log.error("platform_alert_no_recipients", subject=subject)
    return ok


# ---------------------------------------------------------------- watchdog

_db_down_notified_at: float = 0.0
_watchdog: threading.Thread | None = None


def run_once(send: Sender | None = None) -> None:
    global _db_down_notified_at
    from app.db.session import platform_session

    try:
        with platform_session() as db:
            evaluate(db, send=send)
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.error("platform_alert_evaluation_failed", error=type(exc).__name__, detail=str(exc)[:200])
        # No database: no state and no staff list. Tell the configured addresses, at most hourly per process.
        if time.monotonic() - _db_down_notified_at >= 3600 or _db_down_notified_at == 0.0:
            s = get_settings()
            extra = [e for e in s.platform_alert_emails if e.strip()]
            if extra:
                _db_down_notified_at = time.monotonic()
                deliver(extra, f"[{s.product_name}] CRITICAL: platform alert check failed ({type(exc).__name__})",
                        "CyberWatch could not evaluate its own health, usually because the database is unreachable. "
                        "Check the db container (docker compose ps; docker compose logs db api).\n\n"
                        f"Error: {type(exc).__name__}: {str(exc)[:300]}", send)


def _loop() -> None:
    time.sleep(INTERVAL)  # let the process finish starting
    while True:
        run_once()
        time.sleep(INTERVAL)


def start_watchdog() -> None:
    """Start the evaluation thread once per process (production-like environments only)."""
    global _watchdog
    s = get_settings()
    if _watchdog is not None or not s.platform_alerts_enabled or not s.is_production_like:
        return
    _watchdog = threading.Thread(target=_loop, name="platform-alerts", daemon=True)
    _watchdog.start()
    log.info("platform_alert_watchdog_started")
