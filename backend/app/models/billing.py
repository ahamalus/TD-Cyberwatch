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
    LargeBinary,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk, utcnow


class Plan(UUIDPk, Timestamps, Base):
    __tablename__ = "plans"

    key: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="NGN", nullable=False)
    # Amounts in the currency's minor unit (kobo for NGN). Null = not offered.
    price_monthly_minor: Mapped[int | None] = mapped_column(BigInteger)
    price_annual_minor: Mapped[int | None] = mapped_column(BigInteger)
    entitlements: Mapped[dict] = mapped_column(JSONB, nullable=False)
    is_public: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    contact_sales: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Subscription(UUIDPk, Timestamps, Base):
    __tablename__ = "subscriptions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("plans.id"), nullable=False)
    # trialing | active | past_due | grace_period | cancelled | expired
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    interval: Mapped[str] = mapped_column(String(8), default="monthly", nullable=False)
    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    grace_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provider: Mapped[str] = mapped_column(String(16), default="paystack", nullable=False)
    provider_customer_code: Mapped[str | None] = mapped_column(String(80))
    # Reusable card authorization (encrypted; never returned by the API).
    auth_key_id: Mapped[str | None] = mapped_column(String(64))
    auth_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    auth_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    auth_display: Mapped[str | None] = mapped_column(String(80))
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('trialing','active','past_due','grace_period','cancelled','expired')",
            name="status",
        ),
        Index(
            "uq_subscription_current",
            "tenant_id",
            unique=True,
            postgresql_where=text("is_current"),
        ),
    )


class Payment(UUIDPk, Timestamps, Base):
    __tablename__ = "payments"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subscriptions.id", ondelete="SET NULL")
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("plans.id"), nullable=False)
    interval: Mapped[str] = mapped_column(String(8), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), default="paystack", nullable=False)
    reference: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    # initialized | success | failed | abandoned | reversed | refunded
    status: Mapped[str] = mapped_column(String(16), default="initialized", nullable=False)
    purpose: Mapped[str] = mapped_column(String(16), default="new", nullable=False)  # new | renewal | upgrade
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    channel: Mapped[str | None] = mapped_column(String(32))
    gateway_response: Mapped[str | None] = mapped_column(String(200))
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    verification: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class WebhookEvent(UUIDPk, Base):
    __tablename__ = "webhook_events"

    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # received | processed | ignored | failed
    status: Mapped[str] = mapped_column(String(16), default="received", nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
