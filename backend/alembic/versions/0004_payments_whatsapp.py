"""refunds, disputes and WhatsApp delivery receipts

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-21 21:00:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004"
down_revision: Union[str, Sequence[str], None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("notifications", sa.Column("delivery_status", sa.String(length=16), nullable=True))
    op.add_column("notifications", sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("notifications", sa.Column("read_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_notifications_provider_message_id", "notifications", ["provider_message_id"])
    op.add_column("payments", sa.Column("refunded_minor", sa.BigInteger(), server_default="0", nullable=False))

    op.create_table(
        "payment_refunds",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("payment_id", sa.UUID(), nullable=False),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("provider_refund_id", sa.String(length=64), nullable=True),
        sa.Column("requested_by", sa.UUID(), nullable=True),
        sa.Column("end_subscription", sa.Boolean(), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detail", sa.String(length=300), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name=op.f("fk_payment_refunds_tenant_id_tenants"),
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["payment_id"], ["payments.id"], name=op.f("fk_payment_refunds_payment_id_payments"),
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_payment_refunds")),
        sa.UniqueConstraint("provider_refund_id", name=op.f("uq_payment_refunds_provider_refund_id")),
    )
    op.create_index(op.f("ix_payment_refunds_tenant_id"), "payment_refunds", ["tenant_id"])
    op.create_index(op.f("ix_payment_refunds_payment_id"), "payment_refunds", ["payment_id"])

    op.create_table(
        "payment_disputes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=True),
        sa.Column("payment_id", sa.UUID(), nullable=True),
        sa.Column("provider_dispute_id", sa.String(length=64), nullable=False),
        sa.Column("transaction_reference", sa.String(length=100), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("resolution", sa.String(length=40), nullable=True),
        sa.Column("category", sa.String(length=40), nullable=True),
        sa.Column("amount_minor", sa.BigInteger(), nullable=True),
        sa.Column("currency", sa.String(length=3), nullable=True),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_with_provider", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["payment_id"], ["payments.id"], name=op.f("fk_payment_disputes_payment_id_payments"),
                                ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_payment_disputes")),
        sa.UniqueConstraint("provider_dispute_id", name=op.f("uq_payment_disputes_provider_dispute_id")),
    )
    op.create_index(op.f("ix_payment_disputes_tenant_id"), "payment_disputes", ["tenant_id"])
    op.create_index(op.f("ix_payment_disputes_payment_id"), "payment_disputes", ["payment_id"])


def downgrade() -> None:
    op.drop_table("payment_disputes")
    op.drop_table("payment_refunds")
    op.drop_column("payments", "refunded_minor")
    op.drop_index("ix_notifications_provider_message_id", table_name="notifications")
    op.drop_column("notifications", "read_at")
    op.drop_column("notifications", "delivered_at")
    op.drop_column("notifications", "delivery_status")
