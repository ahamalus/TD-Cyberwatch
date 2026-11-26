"""access-log analysis: job type, per-website settings, log cursors

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-22 12:00:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006"
down_revision: Union[str, Sequence[str], None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OLD = "job_type IN ('file_scan','availability','tls','connection_test','capability_discovery')"
NEW = "job_type IN ('file_scan','availability','tls','connection_test','capability_discovery','log_scan')"
RLS = """
CREATE POLICY tenant_isolation ON log_cursors
USING (current_setting('app.scope', true) = 'platform' OR (current_setting('app.scope', true) = 'tenant'
       AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
WITH CHECK (current_setting('app.scope', true) = 'platform' OR (current_setting('app.scope', true) = 'tenant'
       AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
"""


def upgrade() -> None:
    op.drop_constraint(op.f("ck_scan_jobs_job_type"), "scan_jobs", type_="check")
    op.create_check_constraint(op.f("ck_scan_jobs_job_type"), "scan_jobs", NEW)
    op.add_column("monitoring_configs", sa.Column("log_scan_enabled", sa.Boolean(), server_default="true", nullable=False))
    op.add_column("monitoring_configs", sa.Column("log_scan_interval_minutes", sa.Integer(), server_default="60",
                                                  nullable=False))
    op.add_column("monitoring_configs", sa.Column("next_log_scan_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "log_cursors",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("website_id", sa.UUID(), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("offset", sa.BigInteger(), nullable=False),
        sa.Column("head_sha256", sa.String(length=64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name=op.f("fk_log_cursors_tenant_id_tenants"),
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], name=op.f("fk_log_cursors_website_id_websites"),
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_log_cursors")),
        sa.UniqueConstraint("website_id", "path", name="uq_log_cursor_path"),
    )
    op.execute("ALTER TABLE log_cursors ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE log_cursors FORCE ROW LEVEL SECURITY")
    op.execute(RLS)


def downgrade() -> None:
    op.drop_table("log_cursors")
    op.drop_column("monitoring_configs", "next_log_scan_at")
    op.drop_column("monitoring_configs", "log_scan_interval_minutes")
    op.drop_column("monitoring_configs", "log_scan_enabled")
    op.execute("DELETE FROM scan_jobs WHERE job_type = 'log_scan'")
    op.drop_constraint(op.f("ck_scan_jobs_job_type"), "scan_jobs", type_="check")
    op.create_check_constraint(op.f("ck_scan_jobs_job_type"), "scan_jobs", OLD)
