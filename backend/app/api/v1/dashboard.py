"""Customer dashboard aggregate (C01). Every figure is computed from stored data."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api.deps import TenantContext, require
from app.core.permissions import P
from app.db.base import utcnow
from app.db.session import get_db
from app.models import (
    AvailabilityCheck,
    FileChange,
    FileSnapshot,
    HostingAccount,
    Incident,
    MonitoringConfig,
    Notification,
    ScanJob,
    Website,
)
from app.models.incidents import OPEN_STATUSES, SEVERITIES
from app.services import entitlements
from app.services.coverage import website_coverage

router = APIRouter(prefix="/tenants/{tenant_id}", tags=["dashboard"])


@router.get("/dashboard")
def dashboard(ctx: TenantContext = Depends(require(P.MONITORING_READ)), db: Session = Depends(get_db),
              days: int = Query(14, ge=1, le=90)) -> dict:
    tid = ctx.tenant_id
    now = utcnow()
    since = now - timedelta(days=days)
    websites = db.execute(select(Website).where(Website.tenant_id == tid)).scalars().all()
    cfgs = {c.website_id: c for c in db.execute(select(MonitoringConfig).where(MonitoringConfig.tenant_id == tid)).scalars()}
    coverage_counts = {"full": 0, "partial": 0, "none": 0, "paused": 0}
    site_rows = []
    for w in websites:
        cov = website_coverage(db, w, cfgs.get(w.id))
        coverage_counts[cov["overall"]] += 1
        site_rows.append({
            "id": str(w.id), "name": w.name, "hostname": w.hostname, "status": w.status, "coverage": cov["overall"],
            "last_scan_at": w.last_scan_at, "last_scan_status": w.last_scan_status,
            "last_successful_scan_at": w.last_successful_scan_at,
            "availability": w.last_availability_status, "tls": w.last_tls_status, "tls_expires_at": w.tls_expires_at,
        })
    accounts = db.execute(select(HostingAccount.status, func.count()).where(HostingAccount.tenant_id == tid)
                          .group_by(HostingAccount.status)).all()
    open_by_sev = dict(db.execute(select(Incident.severity, func.count()).where(
        Incident.tenant_id == tid, Incident.status.in_(OPEN_STATUSES)).group_by(Incident.severity)).all())
    recent_incidents = db.execute(select(Incident).where(Incident.tenant_id == tid, Incident.status.in_(OPEN_STATUSES))
                                  .order_by(Incident.last_observed_at.desc()).limit(6)).scalars().all()
    names = {w.id: w.name for w in websites}
    recent_changes = db.execute(select(FileChange).where(FileChange.tenant_id == tid)
                                .order_by(FileChange.detected_at.desc()).limit(8)).scalars().all()
    recent_scans = db.execute(select(FileSnapshot).where(FileSnapshot.tenant_id == tid)
                              .order_by(FileSnapshot.started_at.desc()).limit(8)).scalars().all()
    last_success = db.execute(select(func.max(FileSnapshot.completed_at)).where(
        FileSnapshot.tenant_id == tid, FileSnapshot.status.in_(["completed", "partial"]))).scalar()

    # Daily series
    day = func.date_trunc(text("'day'"), Incident.first_detected_at)
    incident_trend = db.execute(select(day, Incident.severity, func.count()).where(
        Incident.tenant_id == tid, Incident.first_detected_at >= since).group_by(day, Incident.severity)).all()
    cday = func.date_trunc(text("'day'"), FileChange.detected_at)
    change_trend = db.execute(select(cday, func.count()).where(
        FileChange.tenant_id == tid, FileChange.detected_at >= since).group_by(cday)).all()
    jday = func.date_trunc(text("'day'"), ScanJob.finished_at)
    scan_trend = db.execute(select(jday, ScanJob.status, func.count()).where(
        ScanJob.tenant_id == tid, ScanJob.finished_at >= since, ScanJob.job_type == "file_scan")
        .group_by(jday, ScanJob.status)).all()
    aday = func.date_trunc(text("'day'"), AvailabilityCheck.checked_at)
    avail = db.execute(select(aday, AvailabilityCheck.outcome, func.count()).where(
        AvailabilityCheck.tenant_id == tid, AvailabilityCheck.checked_at >= since)
        .group_by(aday, AvailabilityCheck.outcome)).all()
    notif = dict(db.execute(select(Notification.status, func.count()).where(
        Notification.tenant_id == tid, Notification.created_at >= since).group_by(Notification.status)).all())

    def series() -> dict:
        return {(since + timedelta(days=i + 1)).date().isoformat(): {} for i in range(days)}

    inc_s = series()
    for d, sev, n in incident_trend:
        inc_s.setdefault(d.date().isoformat(), {})[sev] = n
    chg_s = series()
    for d, n in change_trend:
        chg_s.setdefault(d.date().isoformat(), {})["changes"] = n
    scan_s = series()
    for d, st, n in scan_trend:
        scan_s.setdefault(d.date().isoformat(), {})[st] = n
    av_s = series()
    for d, outcome, n in avail:
        av_s.setdefault(d.date().isoformat(), {})[outcome] = n

    ent = entitlements.effective(db, tid)
    usage = entitlements.usage(db, tid)
    return {
        "generated_at": now,
        "is_demo": ctx.tenant.is_demo,
        "organisation": {"id": str(ctx.tenant.id), "name": ctx.tenant.name, "status": ctx.tenant.status},
        "websites": {"total": len(websites), "active": sum(1 for w in websites if w.status == "active"),
                     "coverage": coverage_counts, "items": site_rows},
        "hosting_accounts": {"total": sum(n for _, n in accounts), "by_status": dict(accounts)},
        "last_successful_scan_at": last_success,
        "incidents": {"open_by_severity": {s: open_by_sev.get(s, 0) for s in SEVERITIES},
                      "open_total": sum(open_by_sev.values()),
                      "recent": [{"id": str(i.id), "reference": i.reference, "title": i.title, "severity": i.severity,
                                  "status": i.status, "website_name": names.get(i.website_id),
                                  "last_observed_at": i.last_observed_at, "category": i.category} for i in recent_incidents]},
        "recent_changes": [{"id": str(c.id), "path": c.path, "change_type": c.change_type, "severity": c.severity,
                            "website_name": names.get(c.website_id), "detected_at": c.detected_at, "flags": c.flags}
                           for c in recent_changes],
        "recent_scans": [{"id": str(s.id), "website_name": names.get(s.website_id), "status": s.status,
                          "started_at": s.started_at, "completed_at": s.completed_at, "files_seen": s.files_seen,
                          "error_count": s.error_count,
                          "changes": s.changes_added + s.changes_modified + s.changes_deleted + s.changes_renamed}
                         for s in recent_scans],
        "availability": {"up": sum(1 for w in websites if w.last_availability_status == "up"),
                         "degraded": sum(1 for w in websites if w.last_availability_status == "degraded"),
                         "down": sum(1 for w in websites if w.last_availability_status in ("down", "error")),
                         "unknown": sum(1 for w in websites if w.last_availability_status is None)},
        "tls": {"valid": sum(1 for w in websites if w.last_tls_status == "valid"),
                "expiring": sum(1 for w in websites if w.last_tls_status == "expiring"),
                "problem": sum(1 for w in websites if w.last_tls_status in ("expired", "invalid", "error")),
                "unknown": sum(1 for w in websites if w.last_tls_status is None and w.url.startswith("https://"))},
        "notifications": {"by_status": notif, "window_days": days},
        "subscription": {"plan": ent.plan_name, "status": ent.subscription_status, "in_service": ent.in_service,
                         "limits": {"websites": ent.get("max_websites"), "hosting_accounts": ent.get("max_hosting_accounts"),
                                    "users": ent.get("max_users")},
                         "usage": usage},
        "trends": {"incidents": inc_s, "file_changes": chg_s, "file_scans": scan_s, "availability": av_s},
    }
