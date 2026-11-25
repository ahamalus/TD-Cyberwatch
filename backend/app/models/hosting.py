from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk, utcnow


class ConnectorDefinition(Timestamps, Base):
    """Registry of connector types (A04). Seeded; operational settings editable."""

    __tablename__ = "connector_definitions"

    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    adapter_version: Mapped[str] = mapped_column(String(20), nullable=False)
    # implemented | planned | disabled
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    connect_timeout_seconds: Mapped[float] = mapped_column(Float, default=15.0, nullable=False)
    io_timeout_seconds: Mapped[float] = mapped_column(Float, default=60.0, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    min_poll_interval_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    max_concurrency_per_host: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    capability_notes: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class HostingAccount(UUIDPk, Timestamps, Base):
    __tablename__ = "hosting_accounts"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    connector_type: Mapped[str] = mapped_column(
        String(40), ForeignKey("connector_definitions.key"), nullable=False
    )
    provider_name: Mapped[str | None] = mapped_column(String(120))
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    # Directory on the account that monitoring is confined to (authorised scope).
    root_path: Mapped[str] = mapped_column(String(1024), default="/", nullable=False)
    # untested | connected | disconnected | auth_failed | expired | error
    status: Mapped[str] = mapped_column(String(20), default="untested", nullable=False)
    host_key_type: Mapped[str | None] = mapped_column(String(40))
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    host_key_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    last_error_message: Mapped[str | None] = mapped_column(Text)
    options: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        # A WHM login monitors several cPanel accounts, so the monitored account is part of the identity.
        Index("uq_hosting_identity", "tenant_id", "connector_type", "hostname", "username",
              text("(COALESCE(options->>'cpanel_user', ''))"), unique=True),
    )


class HostingCredential(UUIDPk, Timestamps, Base):
    """Encrypted credential material. Never serialised to API responses."""

    __tablename__ = "hosting_credentials"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hosting_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hosting_accounts.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    # password | private_key | api_token
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    display_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    rotated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("kind IN ('password','private_key','api_token')", name="kind"),
    )


class ConnectorCapability(UUIDPk, Base):
    """Current capability profile of a hosting connection."""

    __tablename__ = "connector_capabilities"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hosting_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosting_accounts.id", ondelete="CASCADE"), nullable=False
    )
    capability: Mapped[str] = mapped_column(String(40), nullable=False)
    # available | unavailable | untested | unsupported
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="", nullable=False)
    required_permission: Mapped[str | None] = mapped_column(Text)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    connector_version: Mapped[str] = mapped_column(String(20), nullable=False)

    __table_args__ = (
        UniqueConstraint("hosting_account_id", "capability", name="uq_capability_account"),
        CheckConstraint(
            "status IN ('available','unavailable','untested','unsupported')", name="status"
        ),
    )


class CapabilityDiscovery(UUIDPk, Base):
    """Immutable, timestamped record of each capability-discovery run."""

    __tablename__ = "capability_discoveries"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    hosting_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosting_accounts.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    performed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    connector_version: Mapped[str] = mapped_column(String(20), nullable=False)
    profile: Mapped[dict] = mapped_column(JSONB, nullable=False)
    diagnostics: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    __table_args__ = (Index("ix_capdisc_account_time", "hosting_account_id", "performed_at"),)


class RemediationCredential(UUIDPk, Base):
    """Optional WRITE access to a hosting account (SFTP), used only by remediation, never by monitoring.

    Separate from the monitoring credential so that customers who do not buy remediation keep a purely
    read-only connection. Encrypted like other credentials, with its own associated data, so a monitoring
    ciphertext can never be decrypted as a remediation one or vice versa."""

    __tablename__ = "remediation_credentials"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    hosting_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosting_accounts.id", ondelete="CASCADE"), nullable=False, unique=True)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    # Absolute SFTP path of the same folder as the monitoring connection's root.
    root_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    display_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="untested", nullable=False)  # untested | ok | failed
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_result: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class RemediationAction(UUIDPk, Base):
    """One change made to a customer's file, with the encrypted copy of what was there before (for undo)."""

    __tablename__ = "remediation_actions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ticket_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("support_tickets.id", ondelete="SET NULL"))
    website_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE"), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    action: Mapped[str] = mapped_column(String(24), nullable=False)  # restore_genuine | quarantine
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # done | failed | undone
    before_sha256: Mapped[str | None] = mapped_column(String(64))
    after_sha256: Mapped[str | None] = mapped_column(String(64))
    backup_key: Mapped[str | None] = mapped_column(String(300))
    backup_key_id: Mapped[str | None] = mapped_column(String(64))
    backup_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    backup_size: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    performed_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    performed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    undone_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    undone_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
