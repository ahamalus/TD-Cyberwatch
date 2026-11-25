"""After a power cut, daily jobs that missed their time are started once the scheduler runs again."""

from __future__ import annotations

from datetime import timedelta

from app.db.base import utcnow
from app.db.session import platform_session
from app.models import SchedulerState
from app.workers import tasks


def test_missed_daily_jobs_are_caught_up_once(monkeypatch):
    sent = []
    monkeypatch.setattr(tasks.celery_app, "send_task", lambda name, queue=None: sent.append((name, queue)))
    now = utcnow()
    with platform_session() as db:
        db.add(SchedulerState(name="retention_cleanup", last_run_at=now - timedelta(hours=40), last_result={}))
        db.add(SchedulerState(name="audit_anchor", last_run_at=now - timedelta(hours=5), last_result={}))
        db.add(SchedulerState(name="rules_selftest", last_run_at=now - timedelta(hours=50), last_result={}))
        db.commit()
    assert tasks.catch_up_daily()["started"] == ["retention_cleanup", "rules_selftest"]
    assert ("cw.rules_selftest", "checks") in sent and ("cw.retention_cleanup", "default") in sent
    # Not started again while the catch-up run is in progress.
    assert tasks.catch_up_daily()["started"] == []
    assert len(sent) == 2
