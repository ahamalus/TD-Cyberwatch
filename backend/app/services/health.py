"""Platform, worker and integration health (A13 / M12)."""

from __future__ import annotations

import shutil
from datetime import timedelta
from typing import Any

import redis
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import utcnow
from app.models import HostingAccount, Notification, PlatformSetting, ScanJob, SchedulerState, WorkerHeartbeat
from app.services.notifications import channel_status

QUEUES = ["monitoring", "checks", "notifications", "default"]


def check_db(db: Session) -> dict[str, Any]:
    try:
        db.execute(text("SELECT 1"))
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": type(exc).__name__}


def check_redis() -> dict[str, Any]:
    try:
        r = redis.Redis.from_url(get_settings().redis_url, socket_timeout=1)
        r.ping()
        return {"ok": True, "queues": {q: int(r.llen(q)) for q in QUEUES}}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": type(exc).__name__, "queues": {}}


def system_health(db: Session) -> dict[str, Any]:
    s = get_settings()
    now = utcnow()
    alive_after = now - timedelta(seconds=s.worker_heartbeat_seconds * 3)
    workers = [
        {"name": w.worker_name, "hostname": w.hostname, "queues": w.queues, "last_seen_at": w.last_seen_at,
         "started_at": w.started_at, "alive": w.last_seen_at >= alive_after}
        for w in db.execute(select(WorkerHeartbeat).order_by(WorkerHeartbeat.last_seen_at.desc()).limit(50)).scalars()
    ]
    sched = {r.name: {"last_run_at": r.last_run_at, "last_result": r.last_result}
             for r in db.execute(select(SchedulerState)).scalars()}
    beat = sched.get("beat")
    scheduler_ok = bool(beat and beat["last_run_at"] >= now - timedelta(minutes=3))
    redis_h = check_redis()
    db_h = check_db(db)
    try:
        du = shutil.disk_usage(s.storage_dir if __import__("os").path.exists(s.storage_dir) else ".")
        disk = {"total_bytes": du.total, "free_bytes": du.free, "used_pct": round(100 * du.used / du.total, 1)}
    except OSError:
        disk = {"error": "unavailable"}
    since = now - timedelta(hours=24)
    jobs_24h = dict(db.execute(select(ScanJob.status, func.count()).where(ScanJob.queued_at >= since)
                               .group_by(ScanJob.status)).all())
    stale = db.execute(select(func.count()).select_from(ScanJob).where(
        ScanJob.status == "running", ScanJob.heartbeat_at < now - timedelta(seconds=s.job_stale_after_seconds))).scalar_one()
    latency = db.execute(select(func.avg(func.extract("epoch", ScanJob.started_at - ScanJob.queued_at))).where(
        ScanJob.started_at >= since)).scalar()
    durations = db.execute(select(ScanJob.job_type, func.avg(func.extract("epoch", ScanJob.finished_at - ScanJob.started_at)),
                                  func.count()).where(ScanJob.finished_at >= since).group_by(ScanJob.job_type)).all()
    connector_errors = db.execute(
        select(HostingAccount.connector_type, HostingAccount.status, func.count())
        .group_by(HostingAccount.connector_type, HostingAccount.status)).all()
    notif = dict(db.execute(select(Notification.status, func.count()).where(Notification.created_at >= since)
                            .group_by(Notification.status)).all())
    backup = db.get(PlatformSetting, "backup_status")
    alerts = []
    if not db_h["ok"]:
        alerts.append({"severity": "critical", "message": "Database unreachable."})
    if not redis_h["ok"]:
        alerts.append({"severity": "critical", "message": "Redis unreachable; jobs cannot be queued."})
    if not any(w["alive"] for w in workers):
        alerts.append({"severity": "critical", "message": "No monitoring worker heartbeat in the last minute."})
    if not scheduler_ok:
        alerts.append({"severity": "high", "message": "Scheduler heartbeat is stale; scheduled checks are not running."})
    if stale:
        alerts.append({"severity": "medium", "message": f"{stale} running job(s) have no recent heartbeat."})
    if isinstance(disk.get("used_pct"), float) and disk["used_pct"] > 85:
        alerts.append({"severity": "high", "message": f"Disk usage at {disk['used_pct']}%."})
    if backup is None:
        alerts.append({"severity": "medium", "message": "No backup status has been reported."})
    elif backup.updated_at < now - timedelta(hours=36):
        alerts.append({"severity": "high", "message": "Last reported backup is older than 36 hours."})
    return {
        "checked_at": now,
        "database": db_h,
        "redis": redis_h,
        "workers": workers,
        "scheduler": {"ok": scheduler_ok, "tasks": sched},
        "jobs_24h": jobs_24h,
        "stale_running_jobs": stale,
        "avg_queue_latency_seconds": round(float(latency), 1) if latency is not None else None,
        "avg_duration_seconds_by_type": {t: {"avg": round(float(a or 0), 1), "count": n} for t, a, n in durations},
        "connector_status": [{"connector": c, "status": st, "count": n} for c, st, n in connector_errors],
        "notifications_24h": notif,
        "channels": channel_status(),
        "disk": disk,
        "backup": backup.value | {"reported_at": backup.updated_at} if backup else None,
        "alerts": alerts,
        "resource_usage": _process_resources(),
    }


def _process_resources() -> dict[str, Any]:
    try:
        import resource

        ru = resource.getrusage(resource.RUSAGE_SELF)
        load = __import__("os").getloadavg()
        return {"api_max_rss_mb": round(ru.ru_maxrss / 1024, 1), "load_avg": [round(x, 2) for x in load]}
    except (ImportError, OSError):
        return {}
