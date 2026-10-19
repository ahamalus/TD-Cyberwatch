from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk, utcnow


class AlertPolicy(UUIDPk, Timestamps, Base):
    __tablename__ = "alert_policies"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    min_severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    categories: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list, nullable=False)
    website_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list, nullable=False)
    group_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list, nullable=False)
    channels: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=lambda: ["email"], nullable=False)
    # Escalation stage 0 fires immediately; later stages fire after the delay if
    # the incident is still un-acknowledged.
    escalation_stage: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    escalation_delay_minutes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # {"start": "22:00", "end": "07:00", "timezone": "Africa/Lagos", "bypass_severity": "critical"}
    quiet_hours: Mapped[dict | None] = mapped_column(JSONB)
    email_fallback: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class AlertRecipient(UUIDPk, Timestamps, Base):
    __tablename__ = "alert_recipients"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert_policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")
    )
    role_key: Mapped[str | None] = mapped_column(String(64))
    email: Mapped[str | None] = mapped_column(String(320))
    whatsapp_number: Mapped[str | None] = mapped_column(String(20))
    whatsapp_opt_in_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "(user_id IS NOT NULL) OR (role_key IS NOT NULL) OR (email IS NOT NULL) OR (whatsapp_number IS NOT NULL)",
            name="has_target",
        ),
    )


class Notification(UUIDPk, Timestamps, Base):
    __tablename__ = "notifications"

    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL")
    )
    policy_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    channel: Mapped[str] = mapped_column(String(16), nullable=False)  # email | whatsapp
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    template: Mapped[str] = mapped_column(String(64), nullable=False)
    subject: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    body: Mapped[str] = mapped_column(Text, default="", nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # pending | sending | sent | failed | suppressed | unconfigured
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    provider_message_id: Mapped[str | None] = mapped_column(String(200))
    idempotency_key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fallback_for_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    __table_args__ = (
        Index("ix_notifications_status_next", "status", "next_attempt_at"),
        Index("ix_notifications_tenant_created", "tenant_id", "created_at"),
    )
