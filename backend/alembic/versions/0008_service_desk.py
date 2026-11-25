"""service desk: SLA, checklist, time, report and internal notes on support tickets

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-25 14:00:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: Union[str, Sequence[str], None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    add = lambda name, col: op.add_column("support_tickets", sa.Column(name, *col[0], **col[1]))  # noqa: E731
    add("incident_ids", ((postgresql.JSONB(),), {"nullable": False, "server_default": "[]"}))
    for name in ("sla_response_due", "sla_resolution_due", "first_response_at", "resolved_at"):
        add(name, ((sa.DateTime(timezone=True),), {"nullable": True}))
    add("checklist", ((postgresql.JSONB(),), {"nullable": False, "server_default": "[]"}))
    add("time_spent_minutes", ((sa.Integer(),), {"nullable": False, "server_default": "0"}))
    add("report", ((postgresql.JSONB(),), {"nullable": False, "server_default": "{}"}))
    # included (plan allowance) | quote (price to agree) | billable (price agreed) | waived
    add("billing_status", ((sa.String(16),), {"nullable": False, "server_default": "included"}))
    add("price_minor", ((sa.BigInteger(),), {"nullable": True}))
    add("grant_id", ((sa.UUID(),), {"nullable": True}))
    op.create_index("ix_support_tickets_status_due", "support_tickets", ["status", "sla_resolution_due"])
    op.add_column("ticket_messages", sa.Column("internal", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("ticket_messages", sa.Column("kind", sa.String(16), nullable=False, server_default="message"))


def downgrade() -> None:
    op.drop_column("ticket_messages", "kind")
    op.drop_column("ticket_messages", "internal")
    op.drop_index("ix_support_tickets_status_due", table_name="support_tickets")
    for name in ("grant_id", "price_minor", "billing_status", "report", "time_spent_minutes", "checklist",
                 "resolved_at", "first_response_at", "sla_resolution_due", "sla_response_due", "incident_ids"):
        op.drop_column("support_tickets", name)
