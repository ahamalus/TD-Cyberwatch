"""Platform self-alerting: grace period, one email per change, reminders by severity, all-clear, recipients."""

from __future__ import annotations

from datetime import timedelta

from app.core.config import get_settings
from app.db.base import utcnow
from app.db.session import platform_session
from app.services import platform_alerts as pa
from tests.test_security import _staff

WORKER = {"severity": "critical", "message": "No monitoring worker heartbeat in the last minute."}
DISK = {"severity": "high", "message": "Disk usage at 91.2%."}


class Outbox:
    def __init__(self):
        self.sent = []

    def __call__(self, to, subject, body):
        self.sent.append((to, subject, body))


def _eval(now, current, box):
    with platform_session() as db:
        r = pa.evaluate(db, now=now, send=box, current=current)
        db.commit()
        return r


def test_alert_lifecycle_grace_reminder_and_all_clear(monkeypatch):
    monkeypatch.setattr(get_settings(), "platform_alert_emails", ["oncall@trustdata.example.com"])
    box, t0 = Outbox(), utcnow()

    _eval(t0, [WORKER], box)
    assert box.sent == [], "a worker restart during a deploy must not page anyone"
    _eval(t0 + timedelta(minutes=1), [WORKER], box)
    assert box.sent == []
    _eval(t0 + timedelta(minutes=4), [WORKER], box)
    assert len(box.sent) == 1 and box.sent[0][1].startswith("[TrustData CyberWatch] CRITICAL: No monitoring worker")
    _eval(t0 + timedelta(minutes=30), [WORKER], box)
    assert len(box.sent) == 1, "no repeat inside the reminder interval"

    # The disk percentage changes, but it is the same alert.
    _eval(t0 + timedelta(minutes=31), [WORKER, DISK], box)
    _eval(t0 + timedelta(minutes=35), [WORKER, {"severity": "high", "message": "Disk usage at 93.0%."}], box)
    assert len(box.sent) == 2 and "Disk usage at 93.0%" in box.sent[1][1]
    assert "Also still open" in box.sent[1][2] and "No monitoring worker" in box.sent[1][2]

    # Critical reminder after 2 hours.
    _eval(t0 + timedelta(hours=2, minutes=5), [WORKER, DISK], box)
    assert len(box.sent) == 3 and "Still not fixed" in box.sent[2][2]

    # Both resolved: one all-clear.
    _eval(t0 + timedelta(hours=3), [], box)
    assert len(box.sent) == 4 and box.sent[3][1].startswith("[TrustData CyberWatch] Resolved:")
    assert "Resolved:" in box.sent[3][2]
    _eval(t0 + timedelta(hours=4), [], box)
    assert len(box.sent) == 4


def test_flapping_alert_that_clears_within_grace_sends_nothing(monkeypatch):
    monkeypatch.setattr(get_settings(), "platform_alert_emails", ["oncall@trustdata.example.com"])
    box, t0 = Outbox(), utcnow()
    _eval(t0, [WORKER], box)
    _eval(t0 + timedelta(minutes=2), [], box)
    _eval(t0 + timedelta(minutes=10), [], box)
    assert box.sent == []


def test_recipients_are_active_staff_with_health_access_plus_configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "platform_alert_emails", [" OnCall@trustdata.example.com "])
    _staff("noc1@trustdata.example.com", ["noc_monitor"])
    _staff("admin1@trustdata.example.com", ["platform_admin"])
    _staff("billing1@trustdata.example.com", ["billing_admin"])
    with platform_session() as db:
        to = pa.recipients(db)
    assert to == ["admin1@trustdata.example.com", "noc1@trustdata.example.com", "oncall@trustdata.example.com"]


def test_one_bad_address_does_not_stop_the_others():
    sent = []

    def flaky(to, subject, body):
        if to.startswith("bad"):
            raise RuntimeError("refused")
        sent.append(to)

    assert pa.deliver(["bad@x.example.com", "good@x.example.com"], "s", "b", flaky) == ["good@x.example.com"]


def test_watchdog_does_not_start_outside_production(monkeypatch):
    monkeypatch.setattr(pa, "_watchdog", None)
    pa.start_watchdog()
    assert pa._watchdog is None


def test_system_health_page_shows_alerting_and_admin_can_send_a_test(monkeypatch):
    sent = []
    monkeypatch.setattr("app.services.notifications.send_email", lambda to, subject, body, html_body=None: sent.append(to))
    admin = _staff("root3@trustdata.example.com", ["platform_admin"])
    h = admin.get("/api/v1/ops/health").json()["alerting"]
    assert "root3@trustdata.example.com" in h["recipients"] and h["active"] is False
    r = admin.post("/api/v1/admin/platform-alerts/test")
    assert r.status_code == 200 and "root3@trustdata.example.com" in r.json()["sent"]
    assert sent
    assert _staff("noc2@trustdata.example.com", ["noc_monitor"]).post("/api/v1/admin/platform-alerts/test").status_code == 403
