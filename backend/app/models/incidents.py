from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk, utcnow

SEVERITIES = ("critical", "high", "medium", "low", "informational")
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # informational=0 .. critical=4
INCIDENT_STATUSES = ("new", "acknowledged", "investigating", "contained", "resolved", "closed")
OPEN_STATUSES = ("new", "acknowledged", "investigating", "contained")
CATEGORIES = (
    "file_integrity",
    "malware",
    "suspicious_file",
    "availability",
    "tls",
    "connection",
    "log_activity",
    "suspected_compromise",
    "other",
)
# Distinguishes signature-confirmed detections from heuristics and anomalies.
FINDING_CLASSES = (
    "confirmed_malware",
    "heuristic_suspicion",
    "integrity_anomaly",
    "availability_problem",
    "suspected_compromise",
    "configuration_issue",
)


class Incident(UUIDPk, Timestamps, Base):
    __tablename__ = "incidents"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    website_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="SET NULL")
    )
    hosting_account_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosting_accounts.id", ondelete="SET NULL")
    )
    reference: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    finding_class: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="new", nullable=False)
    detection_source: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_key: Mapped[str] = mapped_column(String(80), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(200), nullable=False)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    affected_resources: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, default="", nullable=False)
    requires_human_verification: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    risk_explanation: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolution_notes: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical','high','medium','low','informational')", name="severity"
        ),
        CheckConstraint(
            "status IN ('new','acknowledged','investigating','contained','resolved','closed')",
            name="status",
        ),
        # One open incident per dedupe key: repeated observations update it.
        Index(
            "uq_incidents_open_dedupe",
            "tenant_id",
            "dedupe_key",
            unique=True,
            postgresql_where=text("status IN ('new','acknowledged','investigating','contained')"),
        ),
        Index("ix_incidents_tenant_status_sev", "tenant_id", "status", "severity"),
        Index("uq_incidents_reference", "tenant_id", "reference", unique=True),
    )


class IncidentEvent(UUIDPk, Base):
    """Append-only, hash-chained history of an incident (tamper-evident)."""

    __tablename__ = "incident_events"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)  # user | system | staff
    # created | observed | status_changed | note | assigned | evidence | severity_changed | approval
    event_type: Mapped[str] = mapped_column(String(24), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str | None] = mapped_column(String(16))
    body: Mapped[str | None] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # True when the action was a manual intervention rather than automated detection.
    is_manual: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (Index("uq_incident_events_seq", "incident_id", "seq", unique=True),)


class IncidentEvidence(UUIDPk, Base):
    __tablename__ = "incident_evidence"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # file_change | availability_check | tls_check | snapshot | malware_finding | log_event | note
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    reference_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    collection_method: Mapped[str] = mapped_column(String(64), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    content: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # SHA-256 of the canonical JSON of `content` at collection time.
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    object_key: Mapped[str | None] = mapped_column(String(512))


class SuppressionRule(UUIDPk, Timestamps, Base):
    __tablename__ = "suppression_rules"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    website_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE")
    )
    rule_key: Mapped[str] = mapped_column(String(80), nullable=False)
    path_glob: Mapped[str | None] = mapped_column(String(512))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
