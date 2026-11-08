"""Celery task entry points. Tasks carry only IDs; state lives in PostgreSQL."""

from __future__ import annotations

import os
import socket
import threading

import redis
from celery.signals import worker_ready, worker_shutdown
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.base import utcnow
from app.db.session import platform_session
from app.models import SchedulerState, WorkerHeartbeat
from app.monitoring import jobs
from app.workers.celery_app import celery_app

log = get_logger(__name__)
configure_logging()

_stop = threading.Event()


def _beat_loop(name: str, queues: list[str]) -> None:
    settings = get_settings()
    started = utcnow()
    r = redis.Redis.from_url(settings.redis_url, socket_timeout=2)
    while not _stop.is_set():
        try:
            with platform_session() as s:
                stmt = pg_insert(WorkerHeartbeat).values(
                    worker_name=name, hostname=socket.gethostname(), pid=os.getpid(), queues=queues,
                    started_at=started, last_seen_at=utcnow(), info={},
                )
                s.execute(stmt.on_conflict_do_update(
                    index_elements=["worker_name"],
                    set_={"last_seen_at": stmt.excluded.last_seen_at, "queues": stmt.excluded.queues,
                          "pid": stmt.excluded.pid},
                ))
                s.commit()
            r.setex(f"cw:worker:{name}", settings.worker_heartbeat_seconds * 3, utcnow().isoformat())
        except Exception:  # noqa: BLE001
            log.warning("worker_heartbeat_failed", worker=name)
        _stop.wait(settings.worker_heartbeat_seconds)


@worker_ready.connect
def _start_heartbeat(sender=None, **_: object) -> None:
    queues = sorted(q.name for q in sender.app.amqp.queues.consume_from.values()) if sender else []
    name = sender.hostname if sender else jobs.worker_name()
    threading.Thread(target=_beat_loop, args=(name, queues), daemon=True).start()


@worker_shutdown.connect
def _stop_heartbeat(**_: object) -> None:
    _stop.set()


@celery_app.task(name="cw.run_scan_job", acks_late=True)
def run_scan_job(job_id: str) -> str | None:
    return jobs.run_job(job_id)


@celery_app.task(name="cw.schedule_due")
def schedule_due() -> dict:
    stats = jobs.schedule_due()
    _record_scheduler("schedule_due", stats)
    return stats


@celery_app.task(name="cw.recover_stale_jobs")
def recover_stale_jobs() -> dict:
    stats = jobs.recover_stale_jobs()
    _record_scheduler("recover_stale_jobs", stats)
    return stats


@celery_app.task(name="cw.dispatch_notifications")
def dispatch_notifications() -> dict:
    from app.services.notifications import dispatch_due

    with platform_session() as s:
        return dispatch_due(s)


@celery_app.task(name="cw.scheduler_heartbeat")
def scheduler_heartbeat() -> None:
    _record_scheduler("beat", {})


@celery_app.task(name="cw.retention_cleanup")
def retention_cleanup() -> dict:
    from app.services.retention import run_retention

    with platform_session() as s:
        stats = run_retention(s)
        s.commit()
    _record_scheduler("retention_cleanup", stats)
    return stats


@celery_app.task(name="cw.subscription_maintenance")
def subscription_maintenance() -> dict:
    from app.services.billing import run_subscription_maintenance

    with platform_session() as s:
        stats = run_subscription_maintenance(s)
        s.commit()
    _record_scheduler("subscription_maintenance", stats)
    return stats


def _record_scheduler(name: str, result: dict) -> None:
    with platform_session() as s:
        stmt = pg_insert(SchedulerState).values(name=name, last_run_at=utcnow(), last_result=result)
        s.execute(stmt.on_conflict_do_update(index_elements=["name"],
                                             set_={"last_run_at": stmt.excluded.last_run_at,
                                                   "last_result": stmt.excluded.last_result}))
        s.commit()

