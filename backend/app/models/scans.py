from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk, utcnow

JOB_TYPES = ("file_scan", "availability", "tls", "connection_test", "capability_discovery")
JOB_ACTIVE_STATUSES = ("queued", "running")
JOB_FINAL_STATUSES = ("succeeded", "partial", "failed", "cancelled")


class ScanJob(UUIDPk, Timestamps, Base):
    __tablename__ = "scan_jobs"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    website_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE")
    )
    hosting_account_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosting_accounts.id", ondelete="CASCADE")
    )
    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="queued", nullable=False)
    trigger: Mapped[str] = mapped_column(String(16), default="schedule", nullable=False)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker: Mapped[str | None] = mapped_column(String(200))
    error_class: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    result_summary: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','succeeded','partial','failed','cancelled')", name="status"
        ),
        CheckConstraint(
            "job_type IN ('file_scan','availability','tls','connection_test','capability_discovery')",
            name="job_type",
        ),
        # At most one active job of each type per website / per hosting account:
        # prevents overlapping scans from corrupting a baseline.
        Index(
            "uq_scan_jobs_active_website",
            "website_id",
            "job_type",
            unique=True,
            postgresql_where=text("status IN ('queued','running') AND website_id IS NOT NULL"),
        ),
        Index(
            "uq_scan_jobs_active_account",
            "hosting_account_id",
            "job_type",
            unique=True,
            postgresql_where=text(
                "status IN ('queued','running') AND website_id IS NULL AND hosting_account_id IS NOT NULL"
            ),
        ),
        Index("ix_scan_jobs_tenant_status", "tenant_id", "status"),
        Index("ix_scan_jobs_status_queued", "status", "queued_at"),
    )


class FileSnapshot(UUIDPk, Base):
    __tablename__ = "file_snapshots"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    # running | completed | partial | failed
    status: Mapped[str] = mapped_column(String(16), default="running", nullable=False)
    connector_type: Mapped[str] = mapped_column(String(40), nullable=False)
    root_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    files_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    dirs_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    files_hashed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    files_not_hashed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bytes_hashed: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    limits_hit: Mapped[list[str]] = mapped_column(ARRAY(String(40)), default=list, nullable=False)
    exclusions: Mapped[list[str]] = mapped_column(ARRAY(String(512)), default=list, nullable=False)
    compared_to_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    changes_added: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    changes_modified: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    changes_deleted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    changes_renamed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    deletions_unverified: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint("status IN ('running','completed','partial','failed')", name="status"),
        Index("ix_snapshots_website_started", "website_id", "started_at"),
    )


class FileSnapshotEntry(Base):
    __tablename__ = "file_snapshot_entries"

    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("file_snapshots.id", ondelete="CASCADE"), primary_key=True
    )
    path: Mapped[str] = mapped_column(String(2048), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    # file | dir | symlink | other
    entry_type: Mapped[str] = mapped_column(String(8), nullable=False)
    size: Mapped[int | None] = mapped_column(BigInteger)
    mtime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mode: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    # hashed | skipped_size | skipped_budget | error | not_applicable | metadata_only
    hash_status: Mapped[str] = mapped_column(String(16), nullable=False)
    symlink_target: Mapped[str | None] = mapped_column(String(2048))


class SnapshotError(UUIDPk, Base):
    __tablename__ = "snapshot_errors"

    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("file_snapshots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    error_type: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    is_directory: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class FileInventoryItem(UUIDPk, Base):
    """Current known state of each path, with first/last-seen times."""

    __tablename__ = "file_inventory_items"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE"), nullable=False
    )
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    entry_type: Mapped[str] = mapped_column(String(8), nullable=False)
    size: Mapped[int | None] = mapped_column(BigInteger)
    mtime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sha256: Mapped[str | None] = mapped_column(String(64))
    hash_status: Mapped[str] = mapped_column(String(16), nullable=False)
    file_type: Mapped[str | None] = mapped_column(String(32))
    # present | deleted | unverified (not observed because of an incomplete scan)
    state: Mapped[str] = mapped_column(String(16), default="present", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("website_id", "path", name="uq_inventory_website_path"),
        Index("ix_inventory_tenant_website_state", "tenant_id", "website_id", "state"),
    )


class FileChange(UUIDPk, Base):
    __tablename__ = "file_changes"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("file_snapshots.id", ondelete="CASCADE"), nullable=False
    )
    previous_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    old_path: Mapped[str | None] = mapped_column(String(2048))
    # added | modified | deleted | renamed | metadata_changed | type_changed
    change_type: Mapped[str] = mapped_column(String(20), nullable=False)
    entry_type: Mapped[str] = mapped_column(String(8), nullable=False)
    old_sha256: Mapped[str | None] = mapped_column(String(64))
    new_sha256: Mapped[str | None] = mapped_column(String(64))
    old_size: Mapped[int | None] = mapped_column(BigInteger)
    new_size: Mapped[int | None] = mapped_column(BigInteger)
    old_mtime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    new_mtime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Lower confidence when hashes were unavailable on either side.
    confidence: Mapped[str] = mapped_column(String(10), default="high", nullable=False)
    flags: Mapped[list[str]] = mapped_column(ARRAY(String(40)), default=list, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="low", nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_changes_tenant_website_time", "tenant_id", "website_id", "detected_at"),
        Index("ix_changes_snapshot", "snapshot_id"),
    )


class AvailabilityCheck(UUIDPk, Base):
    __tablename__ = "availability_checks"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    # up | degraded | down | error
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    response_ms: Mapped[int | None] = mapped_column(Integer)
    resolved_ip: Mapped[str | None] = mapped_column(String(64))
    final_url: Mapped[str | None] = mapped_column(String(2048))
    redirects: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_class: Mapped[str | None] = mapped_column(String(40))
    error_message: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_avail_website_time", "website_id", "checked_at"),)


class TlsCheck(UUIDPk, Base):
    __tablename__ = "tls_checks"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    # valid | expiring | expired | invalid | error | not_applicable
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    days_remaining: Mapped[int | None] = mapped_column(Integer)
    issuer: Mapped[str | None] = mapped_column(String(512))
    subject: Mapped[str | None] = mapped_column(String(512))
    san: Mapped[list[str]] = mapped_column(ARRAY(String(253)), default=list, nullable=False)
    protocol: Mapped[str | None] = mapped_column(String(16))
    error_message: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_tls_website_time", "website_id", "checked_at"),)


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"

    worker_name: Mapped[str] = mapped_column(String(200), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(200), nullable=False)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    queues: Mapped[list[str]] = mapped_column(ARRAY(String(40)), default=list, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    info: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class SchedulerState(Base):
    __tablename__ = "scheduler_state"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_result: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


__all__ = [
    "AvailabilityCheck",
    "FileChange",
    "FileInventoryItem",
    "FileSnapshot",
    "FileSnapshotEntry",
    "ScanJob",
    "SchedulerState",
    "SnapshotError",
    "TlsCheck",
    "WorkerHeartbeat",
]
