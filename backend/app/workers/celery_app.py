"""Celery application: monitoring, checks, notification and maintenance queues."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery("cyberwatch", broker=settings.redis_url, backend=None, include=["app.workers.tasks"])
celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_default_queue="default",
    task_time_limit=settings.scan_max_seconds + 300,
    task_soft_time_limit=settings.scan_max_seconds + 120,
    broker_transport_options={"visibility_timeout": settings.scan_max_seconds + 600},
    broker_connection_retry_on_startup=True,
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "schedule-due-checks": {"task": "cw.schedule_due", "schedule": 60.0, "options": {"queue": "default"}},
        "recover-stale-jobs": {"task": "cw.recover_stale_jobs", "schedule": 300.0, "options": {"queue": "default"}},
        "dispatch-notifications": {
            "task": "cw.dispatch_notifications", "schedule": 30.0, "options": {"queue": "notifications"},
        },
        "scheduler-heartbeat": {"task": "cw.scheduler_heartbeat", "schedule": 60.0, "options": {"queue": "default"}},
        "retention-cleanup": {
            "task": "cw.retention_cleanup", "schedule": crontab(hour=2, minute=17), "options": {"queue": "default"},
        },
        "subscription-maintenance": {
            "task": "cw.subscription_maintenance", "schedule": crontab(minute=7), "options": {"queue": "default"},
        },
    },
)
