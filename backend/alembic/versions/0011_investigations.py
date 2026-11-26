"""investigations: entry-point analysis runs attached to a service request

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-26 14:00:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: Union[str, Sequence[str], None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ticket_id", sa.UUID(), sa.ForeignKey("support_tickets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("website_id", sa.UUID(), sa.ForeignKey("websites.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("requested_by", sa.UUID(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.CheckConstraint("status IN ('running','done','failed')", name="ck_investigations_status"),
    )
    op.create_index("ix_investigations_ticket", "investigations", ["ticket_id", "started_at"])
    op.execute("ALTER TABLE investigations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE investigations FORCE ROW LEVEL SECURITY")
    op.execute("""
CREATE POLICY tenant_isolation ON investigations
USING (current_setting('app.scope', true) = 'platform' OR (current_setting('app.scope', true) = 'tenant'
       AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
WITH CHECK (current_setting('app.scope', true) = 'platform' OR (current_setting('app.scope', true) = 'tenant'
       AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
""")


def downgrade() -> None:
    op.drop_table("investigations")
