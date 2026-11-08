"""Execute and persist a file-integrity scan for one website."""

from __future__ import annotations

import posixpath
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.connectors.base import Capability, ConnectorError, safe_join
from app.connectors.registry import build_connector
from app.core.config import get_settings
from app.db.base import utcnow
from app.models import (
    ConnectorCapability,
    ConnectorDefinition,
    FileChange,
    FileInventoryItem,
    FileSnapshot,
    FileSnapshotEntry,
    HostingAccount,
    HostingCredential,
    MonitoringConfig,
    ScanJob,
    SnapshotError,
    Website,
)
from app.models.incidents import SEVERITY_RANK
from app.monitoring.inventory import (
    DEFAULT_EXCLUSIONS,
    DIR_LISTED,
    ROOT,
    Change,
    InventoryResult,
    PrevEntry,
    ScanLimits,
    diff_inventories,
    walk_inventory,
)
from app.monitoring.rules import RULES_BY_KEY, classify_change
from app.services import incidents as incident_svc
from app.services.incidents import DetectionSpec, EvidenceSpec

HEURISTIC_FLAGS = {"script_in_upload_dir", "suspicious_filename", "double_extension", "hidden_script"}
FILE_TYPES = {
    ".php": "php", ".phtml": "php", ".js": "javascript", ".html": "html", ".htm": "html", ".css": "css",
    ".json": "json", ".xml": "xml", ".txt": "text", ".jpg": "image", ".jpeg": "image", ".png": "image",
    ".gif": "image", ".svg": "image", ".webp": "image", ".ico": "image", ".zip": "archive", ".gz": "archive",
    ".tar": "archive", ".sql": "sql", ".py": "python", ".sh": "shell", ".pl": "perl", ".htaccess": "config",
    ".ini": "config", ".pdf": "document",
}


class ScanPreconditionFailed(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class FileScanOutcome:
    snapshot_id: uuid.UUID
    status: str
    summary: dict[str, Any]


def file_type_of(path: str) -> str | None:
    name = posixpath.basename(path).lower()
    if name == ".htaccess":
        return "config"
    return FILE_TYPES.get(posixpath.splitext(name)[1])


def capability_status(db: Session, account_id: uuid.UUID) -> dict[str, str]:
    rows = db.execute(
        select(ConnectorCapability.capability, ConnectorCapability.status).where(
            ConnectorCapability.hosting_account_id == account_id
        )
    ).all()
    return {r.capability: r.status for r in rows}


def scan_limits(cfg: MonitoringConfig | None) -> ScanLimits:
    s = get_settings()
    return ScanLimits(
        max_file_bytes=min(cfg.max_file_bytes or s.scan_max_file_bytes, s.scan_max_file_bytes) if cfg else s.scan_max_file_bytes,
        max_total_bytes=min((cfg.max_total_mb or 10**9) * 1024 * 1024, s.scan_max_total_bytes) if cfg else s.scan_max_total_bytes,
        max_files=min(cfg.max_files or s.scan_max_files, s.scan_max_files) if cfg else s.scan_max_files,
        max_seconds=s.scan_max_seconds,
        max_depth=s.scan_max_depth,
    )


def load_previous(db: Session, website_id: uuid.UUID, exclude_snapshot: uuid.UUID) -> tuple[FileSnapshot | None, dict[str, PrevEntry]]:
    prev = db.execute(
        select(FileSnapshot)
        .where(
            FileSnapshot.website_id == website_id,
            FileSnapshot.status.in_(["completed", "partial"]),
            FileSnapshot.id != exclude_snapshot,
        )
        .order_by(FileSnapshot.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if prev is None:
        return None, {}
    return prev, load_entries(db, prev.id)


def load_entries(db: Session, snapshot_id: uuid.UUID) -> dict[str, PrevEntry]:
    rows = db.execute(select(FileSnapshotEntry).where(FileSnapshotEntry.snapshot_id == snapshot_id)).scalars()
    return {
        r.path: PrevEntry(r.entry_type, r.size, r.mtime, r.sha256, r.hash_status, r.symlink_target, r.mode)
        for r in rows
    }


def _persist_entries(db: Session, snapshot: FileSnapshot, result: InventoryResult) -> None:
    rows = [
        {
            "snapshot_id": snapshot.id,
            "tenant_id": snapshot.tenant_id,
            "path": e.path,
            "entry_type": e.entry_type,
            "size": e.size,
            "mtime": e.mtime,
            "mode": e.mode,
            "sha256": e.sha256,
            "hash_status": e.hash_status,
            "symlink_target": e.symlink_target,
        }
        for e in result.entries.values()
    ]
    for i in range(0, len(rows), 2000):
        db.execute(insert(FileSnapshotEntry), rows[i : i + 2000])
    if result.errors:
        db.execute(
            insert(SnapshotError),
            [
                {
                    "id": uuid.uuid4(),
                    "snapshot_id": snapshot.id,
                    "tenant_id": snapshot.tenant_id,
                    "path": err.path,
                    "error_type": err.error_type,
                    "message": err.message[:2000],
                    "is_directory": err.is_directory,
                }
                for err in result.errors[:5000]
            ],
        )


def _update_inventory(
    db: Session, website: Website, snapshot: FileSnapshot, result: InventoryResult, deleted: list[str], unverified: list[str]
) -> None:
    now = snapshot.completed_at or utcnow()
    rows = [
        {
            "id": uuid.uuid4(),
            "tenant_id": website.tenant_id,
            "website_id": website.id,
            "path": e.path,
            "entry_type": e.entry_type,
            "size": e.size,
            "mtime": e.mtime,
            "sha256": e.sha256,
            "hash_status": e.hash_status,
            "file_type": file_type_of(e.path) if e.entry_type == "file" else None,
            "state": "present",
            "first_seen_at": now,
            "last_seen_at": now,
            "last_snapshot_id": snapshot.id,
        }
        for e in result.entries.values()
        if e.path != ROOT
    ]
    for i in range(0, len(rows), 2000):
        stmt = pg_insert(FileInventoryItem).values(rows[i : i + 2000])
        stmt = stmt.on_conflict_do_update(
            constraint="uq_inventory_website_path",
            set_={
                "entry_type": stmt.excluded.entry_type,
                "size": stmt.excluded.size,
                "mtime": stmt.excluded.mtime,
                "sha256": stmt.excluded.sha256,
                "hash_status": stmt.excluded.hash_status,
                "file_type": stmt.excluded.file_type,
                "state": "present",
                "last_seen_at": stmt.excluded.last_seen_at,
                "last_snapshot_id": stmt.excluded.last_snapshot_id,
            },
        )
        db.execute(stmt)
    for paths, state in ((deleted, "deleted"), (unverified, "unverified")):
        for i in range(0, len(paths), 1000):
            db.execute(
                update(FileInventoryItem)
                .where(FileInventoryItem.website_id == website.id, FileInventoryItem.path.in_(paths[i : i + 1000]))
                .values(state=state, last_snapshot_id=snapshot.id)
            )


def _change_row(c: Change, snapshot: FileSnapshot, prev_id: uuid.UUID | None) -> dict[str, Any]:
    return {
        "id": uuid.uuid4(),
        "tenant_id": snapshot.tenant_id,
        "website_id": snapshot.website_id,
        "snapshot_id": snapshot.id,
        "previous_snapshot_id": prev_id,
        "path": c.path,
        "old_path": c.old_path,
        "change_type": c.change_type,
        "entry_type": c.entry_type,
        "old_sha256": c.old.sha256 if c.old else None,
        "new_sha256": c.new.sha256 if c.new else None,
        "old_size": c.old.size if c.old else None,
        "new_size": c.new.size if c.new else None,
        "old_mtime": c.old.mtime if c.old else None,
        "new_mtime": c.new.mtime if c.new else None,
        "confidence": c.confidence,
        "flags": c.flags,
        "severity": c.severity,
        "detected_at": snapshot.completed_at or utcnow(),
    }


def _raise_incidents(
    db: Session, website: Website, cfg: MonitoringConfig | None, snapshot: FileSnapshot, changes: list[Change],
    withheld_reason: str | None, tenant_is_demo: bool,
) -> list[uuid.UUID]:
    opened: list[uuid.UUID] = []
    threshold = cfg.incident_min_severity if cfg else "medium"
    aggregate: list[Change] = []
    for c in changes:
        heuristic = [f for f in c.flags if f in HEURISTIC_FLAGS]
        if heuristic and c.change_type != "deleted":
            rule = heuristic[0]
            spec = DetectionSpec(
                tenant_id=website.tenant_id,
                website_id=website.id,
                hosting_account_id=website.hosting_account_id,
                title=f"Suspicious file {c.change_type}: {c.path}"[:300],
                summary=f"{RULES_BY_KEY[rule].description} Path: {c.path}.",
                category="suspicious_file",
                finding_class="heuristic_suspicion",
                severity=c.severity,
                confidence="medium" if c.confidence == "high" else "low",
                detection_source="file_integrity_heuristic",
                rule_key=rule,
                dedupe_key=f"suspicious_file:{website.id}:{c.path}",
                recommended_action=(
                    "Review the file contents from a safe environment. Do not execute or open it in a browser. "
                    "If it is not part of the site's code, coordinate removal with your hosting administrator."
                ),
                affected_resources=[{"type": "file", "path": c.path, "sha256": c.new.sha256 if c.new else None}],
                evidence=[_change_evidence(c, snapshot)],
                path_for_suppression=c.path,
                is_demo=tenant_is_demo,
            )
            inc, created = incident_svc.raise_detection(db, spec)
            if inc and created:
                opened.append(inc.id)
        elif SEVERITY_RANK[c.severity] >= SEVERITY_RANK[threshold]:
            aggregate.append(c)

    if aggregate:
        top = max(aggregate, key=lambda c: SEVERITY_RANK[c.severity])
        counts: dict[str, int] = {}
        for c in aggregate:
            counts[c.change_type] = counts.get(c.change_type, 0) + 1
        breakdown = ", ".join(f"{n} {t}" for t, n in sorted(counts.items()))
        spec = DetectionSpec(
            tenant_id=website.tenant_id,
            website_id=website.id,
            hosting_account_id=website.hosting_account_id,
            title=f"Unexpected file changes on {website.name}",
            summary=f"File-integrity scan detected {len(aggregate)} change(s) at or above {threshold} severity ({breakdown}).",
            category="file_integrity",
            finding_class="integrity_anomaly",
            severity=top.severity,
            confidence="high" if all(c.confidence == "high" for c in aggregate) else "medium",
            detection_source="file_integrity",
            rule_key="file_changes",
            dedupe_key=f"file_integrity:{website.id}",
            recommended_action=(
                "Confirm whether these changes were made by an authorised deployment. If they were, approve a "
                "new baseline; if not, investigate the affected files and review hosting access logs."
            ),
            affected_resources=[{"type": "file", "path": c.path, "change": c.change_type} for c in aggregate[:200]],
            evidence=[
                EvidenceSpec(
                    kind="snapshot",
                    source="file_integrity_scan",
                    collection_method="connector_inventory_sha256",
                    reference_id=snapshot.id,
                    content={
                        "snapshot_id": str(snapshot.id),
                        "scan_completed_at": snapshot.completed_at,
                        "changes": [_change_summary(c) for c in aggregate[:500]],
                    },
                )
            ],
            is_demo=tenant_is_demo,
        )
        inc, created = incident_svc.raise_detection(db, spec)
        if inc and created:
            opened.append(inc.id)

    if withheld_reason == "root_unexpectedly_empty":
        spec = DetectionSpec(
            tenant_id=website.tenant_id,
            website_id=website.id,
            hosting_account_id=website.hosting_account_id,
            title=f"Monitored directory unexpectedly empty on {website.name}",
            summary=(
                "The monitored root listed no files although the previous scan found many. Deletions were NOT "
                "recorded because this may be a mount or permission problem rather than real deletion."
            ),
            category="file_integrity",
            finding_class="integrity_anomaly",
            severity="high",
            confidence="low",
            detection_source="file_integrity",
            rule_key="root_unexpectedly_empty",
            dedupe_key=f"root_empty:{website.id}",
            recommended_action="Check the website is serving content and that the hosting account root path is correct.",
            evidence=[EvidenceSpec("snapshot", "file_integrity_scan", "connector_inventory", {"snapshot_id": str(snapshot.id)}, snapshot.id)],
            is_demo=tenant_is_demo,
        )
        inc, created = incident_svc.raise_detection(db, spec)
        if inc and created:
            opened.append(inc.id)
    return opened


def _change_summary(c: Change) -> dict[str, Any]:
    return {
        "path": c.path,
        "old_path": c.old_path,
        "change": c.change_type,
        "old_sha256": c.old.sha256 if c.old else None,
        "new_sha256": c.new.sha256 if c.new else None,
        "old_size": c.old.size if c.old else None,
        "new_size": c.new.size if c.new else None,
        "flags": c.flags,
        "severity": c.severity,
        "confidence": c.confidence,
    }


def _change_evidence(c: Change, snapshot: FileSnapshot) -> EvidenceSpec:
    return EvidenceSpec(
        kind="file_change",
        source="file_integrity_scan",
        collection_method="connector_inventory_sha256",
        reference_id=snapshot.id,
        content={**_change_summary(c), "snapshot_id": str(snapshot.id), "observed_at": snapshot.completed_at},
    )


def run_file_scan(
    db: Session,
    job: ScanJob,
    heartbeat: Callable[[], None] | None = None,
) -> FileScanOutcome:
    website = db.get(Website, job.website_id)
    if website is None:
        raise ScanPreconditionFailed("website_missing", "The website no longer exists.")
    if website.hosting_account_id is None:
        raise ScanPreconditionFailed("no_hosting_account", "No hosting connection is associated with this website.")
    account = db.get(HostingAccount, website.hosting_account_id)
    if account is None or account.tenant_id != website.tenant_id:
        raise ScanPreconditionFailed("no_hosting_account", "The hosting connection is unavailable.")
    caps = capability_status(db, account.id)
    if caps.get(Capability.FILE_LISTING) != "available":
        raise ScanPreconditionFailed(
            "capability_unavailable",
            "File listing has not been verified for this hosting connection. Run a connection test first.",
        )
    hash_files = caps.get(Capability.FILE_HASHING) == "available"
    credential = db.execute(
        select(HostingCredential).where(HostingCredential.hosting_account_id == account.id)
    ).scalar_one_or_none()
    definition = db.get(ConnectorDefinition, account.connector_type)
    cfg = db.execute(select(MonitoringConfig).where(MonitoringConfig.website_id == website.id)).scalar_one_or_none()
    exclusions = list(DEFAULT_EXCLUSIONS) + list(cfg.exclusions if cfg else [])
    root = safe_join(account.root_path, website.document_root or ".")

    snapshot = FileSnapshot(
        tenant_id=website.tenant_id,
        website_id=website.id,
        scan_job_id=job.id,
        status="running",
        connector_type=account.connector_type,
        root_path=root,
        exclusions=exclusions,
    )
    db.add(snapshot)
    db.commit()

    def progress(_: InventoryResult) -> None:
        if heartbeat:
            heartbeat()

    try:
        connector = build_connector(account, credential, definition)
        with connector.open_file_source(root) as source:
            result = walk_inventory(source, exclusions, scan_limits(cfg), progress=progress, hash_files=hash_files)
    except ConnectorError as exc:
        snapshot.status = "failed"
        snapshot.failure_reason = exc.message
        snapshot.completed_at = utcnow()
        website.last_scan_at = snapshot.completed_at
        website.last_scan_status = "failed"
        if exc.code in ("auth_failed", "host_key_mismatch"):
            account.status = "auth_failed" if exc.code == "auth_failed" else "error"
            account.last_error_code, account.last_error_message = exc.code, exc.message
        db.commit()
        raise

    snapshot.completed_at = utcnow()
    snapshot.status = result.status
    snapshot.files_seen = result.files_seen
    snapshot.dirs_seen = result.dirs_seen
    snapshot.files_hashed = result.files_hashed
    snapshot.files_not_hashed = result.files_not_hashed
    snapshot.bytes_hashed = result.bytes_hashed
    snapshot.error_count = len(result.errors)
    snapshot.limits_hit = sorted(result.limits_hit)
    snapshot.failure_reason = result.failure_reason
    _persist_entries(db, snapshot, result)

    opened: list[uuid.UUID] = []
    if result.status == "failed":
        website.last_scan_at = snapshot.completed_at
        website.last_scan_status = "failed"
        db.commit()
        return FileScanOutcome(snapshot.id, "failed", {"reason": result.failure_reason, "errors": len(result.errors)})

    prev, prev_entries = load_previous(db, website.id, snapshot.id)
    diff = diff_inventories(prev_entries, result, exclusions) if prev else None
    changes = diff.changes if diff else []
    critical = list(cfg.critical_paths) if cfg else []
    for c in changes:
        classify_change(c, critical)
    if changes:
        rows = [_change_row(c, snapshot, prev.id if prev else None) for c in changes]
        for i in range(0, len(rows), 2000):
            db.execute(insert(FileChange), rows[i : i + 2000])
    deleted = [c.path for c in changes if c.change_type == "deleted"]
    unverified = diff.unverified_missing if diff else []
    _update_inventory(db, website, snapshot, result, deleted, unverified)

    snapshot.compared_to_snapshot_id = prev.id if prev else None
    snapshot.changes_added = sum(1 for c in changes if c.change_type == "added")
    snapshot.changes_modified = sum(1 for c in changes if c.change_type in ("modified", "metadata_changed", "type_changed"))
    snapshot.changes_deleted = len(deleted)
    snapshot.changes_renamed = sum(1 for c in changes if c.change_type == "renamed")
    snapshot.deletions_unverified = len(unverified)
    if diff and diff.withheld_reason:
        snapshot.status = "partial"
        snapshot.failure_reason = "Root listed as empty; deletions withheld pending review."

    # Baseline policy: the first *completed* scan becomes the trusted baseline
    # automatically. Afterwards the baseline changes only by explicit approval.
    if website.baseline_snapshot_id is None and snapshot.status == "completed":
        website.baseline_snapshot_id = snapshot.id
        website.baseline_approved_at = utcnow()
        website.baseline_approved_by = None

    from app.models import Tenant

    tenant = db.get(Tenant, website.tenant_id)
    opened = _raise_incidents(db, website, cfg, snapshot, changes, diff.withheld_reason if diff else None,
                              bool(tenant and tenant.is_demo))

    website.last_scan_at = snapshot.completed_at
    website.last_scan_status = snapshot.status
    if snapshot.status in ("completed", "partial"):
        website.last_successful_scan_at = snapshot.completed_at
    db.commit()
    return FileScanOutcome(
        snapshot.id,
        snapshot.status,
        {
            "snapshot_id": str(snapshot.id),
            "files_seen": result.files_seen,
            "files_hashed": result.files_hashed,
            "errors": len(result.errors),
            "limits_hit": sorted(result.limits_hit),
            "changes": len(changes),
            "deletions_unverified": len(unverified),
            "first_observed": len(diff.first_observed) if diff else 0,
            "compared_to": str(prev.id) if prev else None,
            "baseline": str(website.baseline_snapshot_id) if website.baseline_snapshot_id else None,
            "incidents_opened": [str(i) for i in opened],
            "dirs_listed": sum(1 for e in result.entries.values() if e.entry_type == "dir" and e.hash_status == DIR_LISTED),
        },
    )
