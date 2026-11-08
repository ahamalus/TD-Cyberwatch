"""Snapshots, file inventory, change history, baseline comparison and scan jobs."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import TenantContext, require
from app.core.errors import NotFound, ValidationFailed
from app.core.permissions import P
from app.db.session import get_db
from app.models import FileChange, FileInventoryItem, FileSnapshot, ScanJob, SnapshotError, Website
from app.monitoring import jobs
from app.monitoring.file_scan import load_entries
from app.monitoring.inventory import ROOT, EntryRecord, InventoryResult, diff_inventories
from app.monitoring.rules import RULES, classify_change
from app.schemas.common import PageParams, paginate
from app.services import audit

router = APIRouter(prefix="/tenants/{tenant_id}", tags=["monitoring"])


class SnapshotOut(BaseModel):
    id: uuid.UUID
    website_id: uuid.UUID
    status: str
    connector_type: str
    root_path: str
    started_at: datetime
    completed_at: datetime | None
    files_seen: int
    dirs_seen: int
    files_hashed: int
    files_not_hashed: int
    bytes_hashed: int
    error_count: int
    limits_hit: list[str]
    exclusions: list[str]
    compared_to_snapshot_id: uuid.UUID | None
    changes_added: int
    changes_modified: int
    changes_deleted: int
    changes_renamed: int
    deletions_unverified: int
    failure_reason: str | None
    is_baseline: bool = False


def _website(db: Session, ctx: TenantContext, website_id: uuid.UUID) -> Website:
    w = db.execute(select(Website).where(Website.id == website_id, Website.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if w is None:
        raise NotFound("Website not found.")
    return w


def _snapshot(db: Session, ctx: TenantContext, snapshot_id: uuid.UUID) -> FileSnapshot:
    s = db.execute(select(FileSnapshot).where(FileSnapshot.id == snapshot_id,
                                              FileSnapshot.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if s is None:
        raise NotFound("Snapshot not found.")
    return s


def snapshot_out(s: FileSnapshot, baseline_id: uuid.UUID | None) -> SnapshotOut:
    out = SnapshotOut.model_validate(s, from_attributes=True)
    out.is_baseline = s.id == baseline_id
    return out


@router.get("/websites/{website_id}/snapshots")
def list_snapshots(website_id: uuid.UUID, ctx: TenantContext = Depends(require(P.INVENTORY_READ)),
                   db: Session = Depends(get_db), params: PageParams = Depends()) -> dict:
    w = _website(db, ctx, website_id)
    q = select(FileSnapshot).where(FileSnapshot.website_id == w.id).order_by(FileSnapshot.started_at.desc())
    return paginate(db, q, params, lambda s: snapshot_out(s, w.baseline_snapshot_id))


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotOut)
def get_snapshot(snapshot_id: uuid.UUID, ctx: TenantContext = Depends(require(P.INVENTORY_READ)),
                 db: Session = Depends(get_db)) -> SnapshotOut:
    s = _snapshot(db, ctx, snapshot_id)
    w = db.get(Website, s.website_id)
    return snapshot_out(s, w.baseline_snapshot_id if w else None)


@router.get("/snapshots/{snapshot_id}/errors")
def snapshot_errors(snapshot_id: uuid.UUID, ctx: TenantContext = Depends(require(P.INVENTORY_READ)),
                    db: Session = Depends(get_db), params: PageParams = Depends()) -> dict:
    s = _snapshot(db, ctx, snapshot_id)
    q = select(SnapshotError).where(SnapshotError.snapshot_id == s.id).order_by(SnapshotError.path)
    return paginate(db, q, params, lambda e: {"path": e.path, "error_type": e.error_type, "message": e.message,
                                              "is_directory": e.is_directory})


@router.get("/websites/{website_id}/inventory")
def inventory(
    website_id: uuid.UUID,
    ctx: TenantContext = Depends(require(P.INVENTORY_READ)),
    db: Session = Depends(get_db),
    params: PageParams = Depends(),
    q: str | None = Query(None, max_length=500),
    state: str | None = Query(None, pattern="^(present|deleted|unverified)$"),
    entry_type: str | None = Query(None, pattern="^(file|dir|symlink|other)$"),
    file_type: str | None = Query(None, max_length=32),
    hash_status: str | None = Query(None, max_length=16),
    sort: str = Query("path", pattern="^-?(path|size|mtime|last_seen_at|first_seen_at)$"),
) -> dict:
    w = _website(db, ctx, website_id)
    query = select(FileInventoryItem).where(FileInventoryItem.website_id == w.id)
    if q:
        query = query.where(FileInventoryItem.path.ilike(f"%{q}%"))
    if state:
        query = query.where(FileInventoryItem.state == state)
    if entry_type:
        query = query.where(FileInventoryItem.entry_type == entry_type)
    if file_type:
        query = query.where(FileInventoryItem.file_type == file_type)
    if hash_status:
        query = query.where(FileInventoryItem.hash_status == hash_status)
    col = getattr(FileInventoryItem, sort.lstrip("-"))
    query = query.order_by(col.desc().nulls_last() if sort.startswith("-") else col.asc().nulls_last(),
                           FileInventoryItem.id)
    return paginate(db, query, params, lambda i: {
        "path": i.path, "entry_type": i.entry_type, "size": i.size, "mtime": i.mtime, "sha256": i.sha256,
        "hash_status": i.hash_status, "file_type": i.file_type, "state": i.state, "first_seen_at": i.first_seen_at,
        "last_seen_at": i.last_seen_at,
    })


def _changes_query(ctx: TenantContext, website_id, change_type, severity, since, until, q, snapshot_id):
    query = select(FileChange).where(FileChange.tenant_id == ctx.tenant_id)
    if website_id:
        query = query.where(FileChange.website_id == website_id)
    if snapshot_id:
        query = query.where(FileChange.snapshot_id == snapshot_id)
    if change_type:
        query = query.where(FileChange.change_type == change_type)
    if severity:
        query = query.where(FileChange.severity == severity)
    if since:
        query = query.where(FileChange.detected_at >= since)
    if until:
        query = query.where(FileChange.detected_at <= until)
    if q:
        query = query.where(FileChange.path.ilike(f"%{q}%"))
    return query.order_by(FileChange.detected_at.desc(), FileChange.path)


def change_dict(c: FileChange, names: dict) -> dict:
    return {
        "id": str(c.id), "website_id": str(c.website_id), "website_name": names.get(c.website_id),
        "snapshot_id": str(c.snapshot_id), "path": c.path, "old_path": c.old_path, "change_type": c.change_type,
        "entry_type": c.entry_type, "old_sha256": c.old_sha256, "new_sha256": c.new_sha256, "old_size": c.old_size,
        "new_size": c.new_size, "old_mtime": c.old_mtime, "new_mtime": c.new_mtime, "confidence": c.confidence,
        "flags": c.flags, "severity": c.severity, "detected_at": c.detected_at,
    }


@router.get("/changes")
def list_changes(
    ctx: TenantContext = Depends(require(P.INVENTORY_READ)),
    db: Session = Depends(get_db),
    params: PageParams = Depends(),
    website_id: uuid.UUID | None = None,
    snapshot_id: uuid.UUID | None = None,
    change_type: str | None = Query(None, max_length=20),
    severity: str | None = Query(None, max_length=16),
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = Query(None, max_length=500),
) -> dict:
    names = dict(db.execute(select(Website.id, Website.name).where(Website.tenant_id == ctx.tenant_id)).all())
    query = _changes_query(ctx, website_id, change_type, severity, since, until, q, snapshot_id)
    return paginate(db, query, params, lambda c: change_dict(c, names))


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection in exported cells."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.get("/changes/export.csv")
def export_changes(
    ctx: TenantContext = Depends(require(P.REPORTS_READ, P.INVENTORY_READ)),
    db: Session = Depends(get_db),
    website_id: uuid.UUID | None = None,
    change_type: str | None = Query(None, max_length=20),
    severity: str | None = Query(None, max_length=16),
    since: datetime | None = None,
    until: datetime | None = None,
) -> StreamingResponse:
    names = dict(db.execute(select(Website.id, Website.name).where(Website.tenant_id == ctx.tenant_id)).all())
    rows = db.execute(_changes_query(ctx, website_id, change_type, severity, since, until, None, None).limit(100000)).scalars()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["detected_at_utc", "website", "path", "change", "old_path", "severity", "confidence", "flags",
                "old_sha256", "new_sha256", "old_size", "new_size"])
    for c in rows:
        w.writerow([_csv_safe(x) for x in (c.detected_at.isoformat(), names.get(c.website_id), c.path, c.change_type,
                                           c.old_path, c.severity, c.confidence, ";".join(c.flags), c.old_sha256,
                                           c.new_sha256, c.old_size, c.new_size)])
    audit.record(db, "export.changes_csv", actor=ctx.actor(), tenant_id=ctx.tenant_id,
                 details={"website_id": str(website_id) if website_id else None})
    db.commit()
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="cyberwatch-file-changes.csv"'})


@router.get("/websites/{website_id}/compare")
def compare(
    website_id: uuid.UUID,
    ctx: TenantContext = Depends(require(P.INVENTORY_READ)),
    db: Session = Depends(get_db),
    base: uuid.UUID | None = Query(None, description="Snapshot to compare from (default: approved baseline)"),
    target: uuid.UUID | None = Query(None, description="Snapshot to compare to (default: latest successful)"),
    limit: int = Query(1000, ge=1, le=10000),
) -> dict:
    w = _website(db, ctx, website_id)
    base_id = base or w.baseline_snapshot_id
    if base_id is None:
        raise ValidationFailed("No baseline has been approved for this website yet.")
    base_snap = _snapshot(db, ctx, base_id)
    if target:
        target_snap = _snapshot(db, ctx, target)
    else:
        target_snap = db.execute(select(FileSnapshot).where(
            FileSnapshot.website_id == w.id, FileSnapshot.status.in_(["completed", "partial"]))
            .order_by(FileSnapshot.started_at.desc()).limit(1)).scalar_one()
    if base_snap.website_id != w.id or target_snap.website_id != w.id:
        raise ValidationFailed("Snapshots must belong to this website.")
    prev = load_entries(db, base_snap.id)
    cur_entries = load_entries(db, target_snap.id)
    result = InventoryResult(status="completed" if target_snap.status == "completed" else "partial")
    for p, e in cur_entries.items():
        result.entries[p] = EntryRecord(p, e.entry_type, e.size, e.mtime, e.mode, e.sha256, e.hash_status, e.symlink_target)
    if ROOT not in result.entries:
        raise ValidationFailed("Target snapshot has no root entry.")
    diff = diff_inventories(prev, result, target_snap.exclusions or [])
    from app.models import MonitoringConfig

    cfg = db.execute(select(MonitoringConfig).where(MonitoringConfig.website_id == w.id)).scalar_one_or_none()
    for c in diff.changes:
        classify_change(c, list(cfg.critical_paths) if cfg else [])
    return {
        "base": snapshot_out(base_snap, w.baseline_snapshot_id),
        "target": snapshot_out(target_snap, w.baseline_snapshot_id),
        "total_changes": len(diff.changes),
        "unverified_missing": len(diff.unverified_missing),
        "first_observed": len(diff.first_observed),
        "withheld_reason": diff.withheld_reason,
        "changes": [
            {"path": c.path, "old_path": c.old_path, "change_type": c.change_type, "entry_type": c.entry_type,
             "severity": c.severity, "flags": c.flags, "confidence": c.confidence,
             "old_sha256": c.old.sha256 if c.old else None, "new_sha256": c.new.sha256 if c.new else None}
            for c in diff.changes[:limit]
        ],
    }


@router.get("/detection-rules")
def detection_rules(ctx: TenantContext = Depends(require(P.INCIDENTS_READ))) -> list[dict]:
    return [{"key": r.key, "severity": r.severity, "description": r.description} for r in RULES]


# ---------------------------------------------------------------- jobs


def job_dict(j: ScanJob, names: dict | None = None) -> dict:
    return {
        "id": str(j.id), "job_type": j.job_type, "status": j.status, "trigger": j.trigger,
        "website_id": str(j.website_id) if j.website_id else None,
        "website_name": (names or {}).get(j.website_id),
        "hosting_account_id": str(j.hosting_account_id) if j.hosting_account_id else None,
        "attempts": j.attempts, "max_attempts": j.max_attempts, "queued_at": j.queued_at, "started_at": j.started_at,
        "finished_at": j.finished_at, "heartbeat_at": j.heartbeat_at, "error_class": j.error_class,
        "error_message": j.error_message, "result_summary": j.result_summary, "cancel_requested": j.cancel_requested,
        "duration_seconds": int((j.finished_at - j.started_at).total_seconds()) if j.finished_at and j.started_at else None,
    }


@router.get("/jobs")
def list_jobs(
    ctx: TenantContext = Depends(require(P.MONITORING_READ)),
    db: Session = Depends(get_db),
    params: PageParams = Depends(),
    status: str | None = Query(None, max_length=16),
    job_type: str | None = Query(None, max_length=32),
    website_id: uuid.UUID | None = None,
    hosting_account_id: uuid.UUID | None = None,
) -> dict:
    q = select(ScanJob).where(ScanJob.tenant_id == ctx.tenant_id)
    if status:
        q = q.where(ScanJob.status == status)
    if job_type:
        q = q.where(ScanJob.job_type == job_type)
    if website_id:
        q = q.where(ScanJob.website_id == website_id)
    if hosting_account_id:
        q = q.where(ScanJob.hosting_account_id == hosting_account_id)
    names = dict(db.execute(select(Website.id, Website.name).where(Website.tenant_id == ctx.tenant_id)).all())
    return paginate(db, q.order_by(ScanJob.queued_at.desc()), params, lambda j: job_dict(j, names))


@router.get("/jobs/{job_id}")
def get_job(job_id: uuid.UUID, ctx: TenantContext = Depends(require(P.MONITORING_READ)), db: Session = Depends(get_db)) -> dict:
    j = db.execute(select(ScanJob).where(ScanJob.id == job_id, ScanJob.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if j is None:
        raise NotFound("Job not found.")
    return job_dict(j)


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: uuid.UUID, ctx: TenantContext = Depends(require(P.SCANS_RUN)), db: Session = Depends(get_db)) -> dict:
    j = db.execute(select(ScanJob).where(ScanJob.id == job_id, ScanJob.tenant_id == ctx.tenant_id)
                   .with_for_update()).scalar_one_or_none()
    if j is None:
        raise NotFound("Job not found.")
    if j.status not in ("queued", "running"):
        raise ValidationFailed("Only queued or running jobs can be cancelled.")
    jobs.request_cancel(db, j, ctx.actor())
    db.commit()
    return job_dict(j)
