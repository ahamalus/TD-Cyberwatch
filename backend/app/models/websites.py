from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk


class WebsiteGroup(UUIDPk, Timestamps, Base):
    __tablename__ = "website_groups"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), default="business_unit", nullable=False)

    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_group_tenant_name"),)


class Website(UUIDPk, Timestamps, Base):
    __tablename__ = "websites"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("website_groups.id", ondelete="SET NULL")
    )
    environment: Mapped[str] = mapped_column(String(20), default="production", nullable=False)
    hosting_account_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosting_accounts.id", ondelete="SET NULL"), index=True
    )
    # Path of the site's files relative to the hosting account root.
    document_root: Mapped[str | None] = mapped_column(String(1024))
    technology: Mapped[str | None] = mapped_column(String(80))
    notes: Mapped[str | None] = mapped_column(Text)
    # active | paused
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)
    verification_status: Mapped[str] = mapped_column(String(16), default="unverified", nullable=False)
    verification_token: Mapped[str | None] = mapped_column(String(64))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Trusted baseline; changed only by explicit, audited approval.
    baseline_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("file_snapshots.id", ondelete="SET NULL", use_alter=True)
    )
    baseline_approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    baseline_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_status: Mapped[str | None] = mapped_column(String(16))
    last_successful_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_availability_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_availability_status: Mapped[str | None] = mapped_column(String(16))
    last_tls_status: Mapped[str | None] = mapped_column(String(16))
    tls_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consecutive_availability_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "url", name="uq_website_tenant_url"),
        CheckConstraint("status IN ('active','paused')", name="status"),
        CheckConstraint(
            "environment IN ('production','staging','development','other')", name="environment"
        ),
    )


class MonitoringConfig(UUIDPk, Timestamps, Base):
    __tablename__ = "monitoring_configs"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    file_scan_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    file_scan_interval_minutes: Mapped[int] = mapped_column(Integer, default=1440, nullable=False)
    availability_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    availability_interval_minutes: Mapped[int] = mapped_column(Integer, default=15, nullable=False)
    tls_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    tls_expiry_warning_days: Mapped[int] = mapped_column(Integer, default=21, nullable=False)
    availability_failure_threshold: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    slow_response_ms: Mapped[int] = mapped_column(Integer, default=5000, nullable=False)
    # File changes at or above this severity open an incident; lower ones are
    # recorded in change history only.
    incident_min_severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    exclusions: Mapped[list[str]] = mapped_column(ARRAY(String(512)), default=list, nullable=False)
    critical_paths: Mapped[list[str]] = mapped_column(ARRAY(String(512)), default=list, nullable=False)
    max_file_bytes: Mapped[int | None] = mapped_column(Integer)
    max_total_mb: Mapped[int | None] = mapped_column(Integer)
    max_files: Mapped[int | None] = mapped_column(Integer)
    # [{"weekday": 0-6|null, "start": "HH:MM", "end": "HH:MM", "timezone": "Africa/Lagos"}]
    maintenance_windows: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    next_file_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    next_availability_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
