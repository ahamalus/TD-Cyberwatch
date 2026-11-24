"""Execute and persist a file-integrity scan for one website."""

from __future__ import annotations

import posixpath
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import Text, func, insert, select, update
from sqlalchemy.dialects.postgresql import ARRAY
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
    SoftwareInstall,
    Website,
)
from app.models.incidents import SEVERITY_RANK
from app.monitoring import guarded, malware, vendor
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
        r.path: PrevEntry(r.entry_type, r.size, r.mtime, r.sha256, r.hash_status, r.symlink_target, r.mode, r.md5)
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
            "md5": e.md5,
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


INVENTORY_COMPARED = ("entry_type", "size", "mtime", "sha256", "hash_status", "malware_status", "malware_signatures",
                      "malware_scanned_at", "vendor_status", "vendor_ref")


def _update_inventory(
    db: Session, website: Website, snapshot: FileSnapshot, result: InventoryResult, deleted: list[str], unverified: list[str],
    vendor_report: vendor.VendorReport | None = None,
) -> None:
    """Write the current state of every observed path.

    Only rows whose state changed are rewritten; for the (usually vast) unchanged remainder a single statement
    per batch refreshes ``last_seen_at``. A 200,000-file site therefore costs a few statements per scan instead
    of rewriting every row."""
    now = snapshot.completed_at or utcnow()
    vstatus = vendor_report.status if vendor_report else {}
    cols = [getattr(FileInventoryItem, c) for c in INVENTORY_COMPARED]
    existing: dict[str, tuple] = {
        r[0]: tuple(tuple(v) if isinstance(v, list) else v for v in r[1:])
        for r in db.execute(select(FileInventoryItem.path, FileInventoryItem.state, *cols)
                            .where(FileInventoryItem.website_id == website.id))
    }
    changed: list[dict[str, Any]] = []
    unchanged: list[str] = []
    for e in result.entries.values():
        if e.path == ROOT:
            continue
        v = vstatus.get(e.path, (None, None))
        sigs = e.inspection.signatures if e.inspection else []
        current = (e.entry_type, e.size, e.mtime, e.sha256, e.hash_status,
                   e.inspection.status if e.inspection else None, tuple(sigs),
                   e.inspection.scanned_at if e.inspection else None, v[0], v[1])
        before = existing.get(e.path)
        if before is not None and before[0] == "present" and before[1:] == current:
            unchanged.append(e.path)
            continue
        changed.append({
            "id": uuid.uuid4(), "tenant_id": website.tenant_id, "website_id": website.id, "path": e.path,
            "entry_type": e.entry_type, "size": e.size, "mtime": e.mtime, "sha256": e.sha256,
            "hash_status": e.hash_status, "file_type": file_type_of(e.path) if e.entry_type == "file" else None,
            "malware_status": current[5], "malware_signatures": list(sigs), "malware_scanned_at": current[7],
            "vendor_status": v[0], "vendor_ref": v[1], "state": "present",
            "first_seen_at": now, "last_seen_at": now, "last_snapshot_id": snapshot.id,
        })
    if changed:
        stmt = pg_insert(FileInventoryItem)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_inventory_website_path",
            set_={c: stmt.excluded[c] for c in (*INVENTORY_COMPARED, "file_type", "last_seen_at", "last_snapshot_id")}
            | {"state": "present"},
        )
        for i in range(0, len(changed), 5000):
            db.execute(stmt, changed[i : i + 5000])  # one prepared statement, many rows
    for i in range(0, len(unchanged), 20000):
        db.execute(
            update(FileInventoryItem)
            .where(FileInventoryItem.website_id == website.id,
                   FileInventoryItem.path == func.any(func.cast(unchanged[i : i + 20000], ARRAY(Text))))
            .values(last_seen_at=now, last_snapshot_id=snapshot.id)
            .execution_options(synchronize_session=False)
        )
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


def _mark_guarded(c: Change) -> None:
    """A guarded data file cannot execute, so the script-related heuristics do not apply to it."""
    script_flags = {"script_in_upload_dir", "suspicious_filename", "double_extension", "hidden_script",
                    "script_changed"}
    c.flags = ["guarded_data_file"] + [f for f in c.flags if f not in script_flags]
    c.severity = max(("low", *(RULES_BY_KEY[f].severity for f in c.flags if f in RULES_BY_KEY)),
                     key=lambda s: SEVERITY_RANK[s])


def _raise_incidents(
    db: Session, website: Website, cfg: MonitoringConfig | None, snapshot: FileSnapshot, changes: list[Change],
    withheld_reason: str | None, tenant_is_demo: bool, verified: set[str] | None = None,
) -> list[uuid.UUID]:
    opened: list[uuid.UUID] = []
    threshold = cfg.incident_min_severity if cfg else "medium"
    aggregate: list[Change] = []
    for c in changes:
        if c.change_type != "deleted" and verified and c.path in verified:
            continue  # new content is the publisher's official file (e.g. a WordPress or plugin update)
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
                content_sha256=c.new.sha256 if c.new else None,
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


def _raise_malware_incidents(db: Session, website: Website, snapshot: FileSnapshot, result: InventoryResult,
                             tenant_is_demo: bool, vendor_report: vendor.VendorReport | None = None,
                             previous: dict[str, PrevEntry] | None = None) -> list[uuid.UUID]:
    """One incident per flagged file that is new or changed at its path, or whose verdict was just produced
    (rescan, rule update). Unchanged files with a cached verdict do not re-alert. The verdict cache is shared
    by content hash, so a cached verdict alone must never hide a file appearing at a new path or site.

    Files identical to the publisher's official release are not reported for heuristic (YARA) matches; an
    antivirus signature hit on such a file is still reported, but as a probable signature false positive."""
    opened: list[uuid.UUID] = []
    for e in result.entries.values():
        v = e.inspection
        if v is None or v.status not in (malware.INFECTED, malware.SUSPICIOUS):
            continue
        prev = (previous or {}).get(e.path)
        if not v.fresh and prev is not None and prev.sha256 == e.sha256:
            continue
        genuine = vendor_report.status[e.path][1] if vendor_report and vendor_report.is_verified(e.path) else None
        if genuine and v.status == malware.SUSPICIOUS:
            continue
        confirmed = v.status == malware.INFECTED and not genuine
        sigs = [s for s in v.signatures if s.startswith("clamav:")] if v.status == malware.INFECTED else v.signatures
        names = ", ".join(s.partition(":")[2] for s in sigs)
        spec = DetectionSpec(
            tenant_id=website.tenant_id,
            website_id=website.id,
            hosting_account_id=website.hosting_account_id,
            title=(f"Malware detected ({names}): {e.path}" if confirmed
                   else f"Malicious code pattern ({names}): {e.path}")[:300],
            summary=(" ".join(malware.describe_signature(s) for s in sigs) + f" Path: {e.path}."
                     + (f" Note: this file is byte-for-byte identical to the official {genuine} release, so the "
                        "antivirus signature is probably a false positive; confirm before acting." if genuine else "")
                     )[:2000],
            category="malware",
            finding_class="confirmed_malware" if confirmed else "heuristic_suspicion",
            severity="critical" if confirmed else ("medium" if genuine else "high"),
            confidence="high" if confirmed else "medium",
            detection_source="clamav" if v.status == malware.INFECTED else "yara",
            rule_key=sigs[0][:120],
            dedupe_key=f"malware:{website.id}:{e.path}",
            recommended_action=(
                "Treat the site as compromised: do not open or run the file. Ask your hosting administrator to "
                "take a copy for analysis, remove or restore it from a clean backup, change hosting, CMS and "
                "database passwords, and look for how it was uploaded. CyberWatch never deletes or quarantines files."
                if confirmed else
                "Review the file from a safe environment (do not run it or open it in a browser). If it is not part "
                "of the site's legitimate code, have it removed and investigate how it was added. Mark the incident "
                "as a false positive if the code is legitimate."
            ),
            affected_resources=[{"type": "file", "path": e.path, "sha256": e.sha256}],
            evidence=[EvidenceSpec(
                kind="scan_result",
                source="malware_scan",
                collection_method="clamd_instream" if v.status == malware.INFECTED else "yara_rules",
                content={"path": e.path, "sha256": e.sha256, "size": e.size, "verdict": v.status,
                         "signatures": v.signatures, "matched_text": v.matched_text, "engine": v.engine,
                         "signature_db_version": v.db_version,
                         "scanned_at": v.scanned_at, "snapshot_id": str(snapshot.id),
                         "official_release_match": genuine},
                reference_id=snapshot.id,
            )],
            requires_human_verification=not confirmed,
            path_for_suppression=e.path,
            content_sha256=e.sha256,
            is_demo=tenant_is_demo,
        )
        inc, created = incident_svc.raise_detection(db, spec)
        if inc and created:
            opened.append(inc.id)
    return opened


VENDOR_INCIDENT_CAP = 50


def _raise_vendor_incidents(db: Session, website: Website, snapshot: FileSnapshot, report: vendor.VendorReport,
                            previous: dict[str, tuple[str | None, str | None]], entries: dict,
                            tenant_is_demo: bool) -> list[uuid.UUID]:
    """Tampering found by comparison with official checksums.

    Raised when a finding is new or the file's content changed since the last scan, so a finding that was
    reviewed and closed is not re-opened by every scan."""
    opened: list[uuid.UUID] = []

    def fresh(path: str, status: str) -> bool:
        prev_status, prev_sha = previous.get(path, (None, None))
        return prev_status != status or prev_sha != entries[path].sha256

    def raise_(spec: DetectionSpec) -> None:
        inc, created = incident_svc.raise_detection(db, spec)
        if inc and created:
            opened.append(inc.id)

    def evidence(paths: list[str], install: vendor.InstallReport) -> EvidenceSpec:
        return EvidenceSpec(
            kind="scan_result", source="vendor_checksums", collection_method="official_checksum_comparison",
            reference_id=snapshot.id,
            content={"snapshot_id": str(snapshot.id), "release": install.ref, "install_root": install.detected.root or "/",
                     "files": [{"path": p, "sha256": entries[p].sha256, "md5": entries[p].md5,
                                "comparison": report.status[p][0]} for p in paths[:500]]},
        )

    per_file = 0
    for inst in report.installs:
        d = inst.detected
        if d.product == vendor.CORE:
            findings = [(p, vendor.MODIFIED) for p in inst.modified] + [(p, vendor.UNEXPECTED) for p in inst.unexpected]
            overflow: list[str] = []
            for path, status in findings:
                if not fresh(path, status):
                    continue
                if per_file >= VENDOR_INCIDENT_CAP:
                    overflow.append(path)
                    continue
                per_file += 1
                is_code = path.lower().endswith((".php", ".phtml", ".phar", ".js", ".htaccess"))
                modified = status == vendor.MODIFIED
                raise_(DetectionSpec(
                    tenant_id=website.tenant_id, website_id=website.id, hosting_account_id=website.hosting_account_id,
                    title=(f"Modified WordPress core file: {path}" if modified
                           else f"Unexpected file in WordPress core directory: {path}")[:300],
                    summary=(
                        f"{path} differs from the official WordPress {d.version} release. Core files should never "
                        "be edited; attackers modify them to hide backdoors that survive plugin and theme clean-ups."
                        if modified else
                        f"{path} is not part of WordPress {d.version}. Nothing but core files belongs in wp-admin/ "
                        "and wp-includes/; files planted there are a common way to hide web shells."),
                    category="file_integrity", finding_class="integrity_anomaly",
                    severity="high" if (modified or is_code) else "medium", confidence="high",
                    detection_source="vendor_checksum",
                    rule_key="wordpress_core_modified" if modified else "wordpress_core_unexpected_file",
                    dedupe_key=f"vendor:{website.id}:{path}",
                    recommended_action=(
                        "Compare the file with the official copy from wordpress.org from a safe environment. If the "
                        "change was not made deliberately, reinstall the same WordPress version (Dashboard > Updates "
                        "> Re-install) and investigate how the file was changed. Mark as a false positive only if "
                        "the edit is intentional."),
                    affected_resources=[{"type": "file", "path": path, "sha256": entries[path].sha256}],
                    evidence=[evidence([path], inst)],
                    path_for_suppression=path, content_sha256=entries[path].sha256, is_demo=tenant_is_demo,
                ))
            if overflow:
                raise_(DetectionSpec(
                    tenant_id=website.tenant_id, website_id=website.id, hosting_account_id=website.hosting_account_id,
                    title=f"{len(overflow)} more WordPress core files differ from the official release",
                    summary=(f"In addition to the files reported individually, {len(overflow)} file(s) in the "
                             f"WordPress {d.version} install at /{d.root} are modified or should not be there."),
                    category="file_integrity", finding_class="integrity_anomaly", severity="high", confidence="high",
                    detection_source="vendor_checksum", rule_key="wordpress_core_modified",
                    dedupe_key=f"vendor_core_bulk:{website.id}:{d.root}",
                    recommended_action="Reinstall the same WordPress version and review how the files were changed.",
                    affected_resources=[{"type": "file", "path": p} for p in overflow[:200]],
                    evidence=[evidence(overflow, inst)], is_demo=tenant_is_demo,
                ))
        else:
            paths = inst.modified + inst.unexpected
            if not paths or not any(fresh(p, report.status[p][0]) for p in paths):
                continue
            raise_(DetectionSpec(
                tenant_id=website.tenant_id, website_id=website.id, hosting_account_id=website.hosting_account_id,
                title=f"Plugin files differ from the official release: {d.name or d.slug} {d.version}"[:300],
                summary=(f"{len(inst.modified)} file(s) of the {d.name or d.slug} plugin ({d.version}) differ from "
                         f"the copy published on wordpress.org and {len(inst.unexpected)} PHP file(s) are not part "
                         "of it. This can be a deliberate customisation, a failed update, or injected code."),
                category="file_integrity", finding_class="integrity_anomaly", severity="medium", confidence="medium",
                detection_source="vendor_checksum", rule_key="wordpress_plugin_modified",
                dedupe_key=f"vendor_plugin:{website.id}:{d.root}{d.slug}",
                recommended_action=(
                    "If nobody edited this plugin on purpose, reinstall it from wordpress.org (same version) and "
                    "review the listed files from a safe environment."),
                affected_resources=[{"type": "file", "path": p, "change": report.status[p][0]} for p in paths[:200]],
                evidence=[evidence(paths, inst)], is_demo=tenant_is_demo,
            ))
    return opened


def _persist_installs(db: Session, website: Website, report: vendor.VendorReport, complete: bool) -> None:
    now = utcnow()
    seen: set[tuple[str, str, str]] = set()
    for r in report.installs:
        d = r.detected
        seen.add((d.product, d.root, d.slug))
        values = {"version": d.version, "locale": d.locale, "name": d.name, "checksum_status": r.checksum_status,
                  "files_verified": r.verified, "files_modified": len(r.modified),
                  "files_unexpected": len(r.unexpected), "last_seen_at": now}
        stmt = pg_insert(SoftwareInstall).values(
            id=uuid.uuid4(), tenant_id=website.tenant_id, website_id=website.id, product=d.product, slug=d.slug,
            root=d.root, first_seen_at=now, **values)
        db.execute(stmt.on_conflict_do_update(constraint="uq_software_install", set_=values))
    if complete:  # only a complete scan proves an install is gone
        for row in db.execute(select(SoftwareInstall).where(SoftwareInstall.website_id == website.id)).scalars():
            if (row.product, row.root, row.slug) not in seen:
                db.delete(row)


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


def _content_mode(db: Session, website_id: uuid.UUID, has_previous: bool) -> tuple[str, bool]:
    """Decide how much content to download. Returns (mode, reuse_unchanged).

    * ``full``: download everything (first scan, or the weekly full check that catches files altered with
      a forged modification time).
    * ``full_continued``: the previous full pass stopped at the time limit; continue it, reusing what that
      pass already downloaded, so a large site completes over successive runs.
    * ``incremental``: a full pass finished within ``full_content_check_days``; reuse hashes of files whose
      size and modification time did not change.
    """
    if not has_previous:
        return "full", False
    jobs = db.execute(
        select(ScanJob.result_summary).where(
            ScanJob.website_id == website_id, ScanJob.job_type == "file_scan",
            ScanJob.status.in_(["succeeded", "partial"]),
        ).order_by(ScanJob.finished_at.desc()).limit(50)
    ).scalars().all()
    full_modes = ("full", "full_continued")
    # Scans recorded before content modes existed always downloaded everything: count them as full passes.
    if jobs and jobs[0].get("content_mode", "full") in full_modes and "time" in (jobs[0].get("limits_hit") or []):
        return "full_continued", True
    since = utcnow() - timedelta(days=get_settings().full_content_check_days)
    finished_full = db.execute(
        select(ScanJob.result_summary).where(
            ScanJob.website_id == website_id, ScanJob.job_type == "file_scan",
            ScanJob.status.in_(["succeeded", "partial"]), ScanJob.finished_at >= since,
        )
    ).scalars().all()
    if any(j.get("content_mode", "full") in full_modes and "time" not in (j.get("limits_hit") or [])
           for j in finished_full):
        return "incremental", True
    return "full", False


def run_file_scan(
    db: Session,
    job: ScanJob,
    heartbeat: Callable[..., None] | None = None,
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

    prev, prev_entries = load_previous(db, website.id, snapshot.id)
    mode, reuse_unchanged = _content_mode(db, website.id, prev is not None)
    last_beat = [0.0]

    def progress(r: InventoryResult) -> None:
        if heartbeat and time.monotonic() - last_beat[0] >= 10:
            last_beat[0] = time.monotonic()
            heartbeat({"files_seen": r.files_seen, "files_hashed": r.files_hashed, "files_reused": r.files_reused,
                       "dirs_seen": r.dirs_seen, "content_mode": mode})

    # Malware inspection reuses the bytes downloaded for hashing (no second download).
    inspector = malware.ContentInspector(db, website.id) if hash_files else None
    # Version files (wp-includes/version.php, plugin headers) are read during the walk for checksum lookup.
    observer = vendor.WordPressObserver() if hash_files else None
    # PHP files in upload folders are read to recognise guarded data files (plugin logs; see guarded.py).
    guard = guarded.GuardObserver() if hash_files else None
    try:
        connector = build_connector(account, credential, definition)
        with connector.open_file_source(root) as source:
            result = walk_inventory(source, exclusions, scan_limits(cfg), progress=progress, hash_files=hash_files,
                                    inspector=inspector, previous=prev_entries if reuse_unchanged else None,
                                    parallel=getattr(source, "parallel_reads", 1),
                                    observer=guarded.CompositeObserver(observer, guard) if observer else None)
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

    diff = diff_inventories(prev_entries, result, exclusions) if prev else None
    changes = diff.changes if diff else []
    critical = list(cfg.critical_paths) if cfg else []
    for c in changes:
        classify_change(c, critical)
        if guard is not None and c.path in guard.guarded and "script_in_upload_dir" in c.flags:
            _mark_guarded(c)
    if changes:
        rows = [_change_row(c, snapshot, prev.id if prev else None) for c in changes]
        for i in range(0, len(rows), 2000):
            db.execute(insert(FileChange), rows[i : i + 2000])
    deleted = [c.path for c in changes if c.change_type == "deleted"]
    unverified = diff.unverified_missing if diff else []

    vendor_report = None
    previous_vendor: dict[str, tuple[str | None, str | None]] = {}
    if observer is not None and observer.found:
        store = vendor.ChecksumStore(db) if get_settings().vendor_checksums_enabled else None
        vendor_report = vendor.verify(result.entries, list(observer.found.values()), store)
        previous_vendor = {
            r.path: (r.vendor_status, r.sha256) for r in db.execute(
                select(FileInventoryItem.path, FileInventoryItem.vendor_status, FileInventoryItem.sha256)
                .where(FileInventoryItem.website_id == website.id, FileInventoryItem.vendor_status.is_not(None))
            ).all()
        }
        _persist_installs(db, website, vendor_report, complete=result.status == "completed")
    _update_inventory(db, website, snapshot, result, deleted, unverified, vendor_report)

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
    demo = bool(tenant and tenant.is_demo)
    verified = {p for p, (st, _) in vendor_report.status.items() if st == vendor.VERIFIED} if vendor_report else set()
    opened = _raise_incidents(db, website, cfg, snapshot, changes, diff.withheld_reason if diff else None, demo, verified)
    if inspector is not None:
        inspector.flush()
        opened += _raise_malware_incidents(db, website, snapshot, result, demo, vendor_report,
                                           prev_entries if prev else {})
    if vendor_report is not None:
        opened += _raise_vendor_incidents(db, website, snapshot, vendor_report, previous_vendor, result.entries, demo)

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
            "files_reused": result.files_reused,
            "files_hashed_remotely": result.files_hashed_remotely,
            "content_mode": mode,
            "errors": len(result.errors),
            "limits_hit": sorted(result.limits_hit),
            "changes": len(changes),
            "deletions_unverified": len(unverified),
            "first_observed": len(diff.first_observed) if diff else 0,
            "compared_to": str(prev.id) if prev else None,
            "baseline": str(website.baseline_snapshot_id) if website.baseline_snapshot_id else None,
            "incidents_opened": [str(i) for i in opened],
            "dirs_listed": sum(1 for e in result.entries.values() if e.entry_type == "dir" and e.hash_status == DIR_LISTED),
            "malware": inspector.summary() if inspector else {"unavailable_reason": "File hashing is not available."},
            "vendor": vendor_report.summary() if vendor_report else None,
        },
    )
