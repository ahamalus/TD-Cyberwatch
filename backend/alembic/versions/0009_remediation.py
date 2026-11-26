"""remediation: separate write access per hosting connection, and the log of file changes made

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-25 18:00:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0009"
down_revision: Union[str, Sequence[str], None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _rls(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""
CREATE POLICY tenant_isolation ON {table}
USING (current_setting('app.scope', true) = 'platform' OR (current_setting('app.scope', true) = 'tenant'
       AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
WITH CHECK (current_setting('app.scope', true) = 'platform' OR (current_setting('app.scope', true) = 'tenant'
       AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
""")


def upgrade() -> None:
    op.create_table(
        "remediation_credentials",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hosting_account_id", sa.UUID(), sa.ForeignKey("hosting_accounts.id", ondelete="CASCADE"),
                  nullable=False, unique=True),
        sa.Column("hostname", sa.String(253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(120), nullable=False),
        sa.Column("root_path", sa.String(1024), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("display_fingerprint", sa.String(80), nullable=False),
        sa.Column("host_key_fingerprint", sa.String(128), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="untested"),
        sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_result", sa.Text(), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    _rls("remediation_credentials")
    op.create_table(
        "remediation_actions",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ticket_id", sa.UUID(), sa.ForeignKey("support_tickets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("website_id", sa.UUID(), sa.ForeignKey("websites.id", ondelete="CASCADE"), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("before_sha256", sa.String(64), nullable=True),
        sa.Column("after_sha256", sa.String(64), nullable=True),
        sa.Column("backup_key", sa.String(300), nullable=True),
        sa.Column("backup_key_id", sa.String(64), nullable=True),
        sa.Column("backup_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("backup_size", sa.Integer(), nullable=True),
        sa.Column("source", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("performed_by", sa.UUID(), nullable=True),
        sa.Column("performed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("undone_by", sa.UUID(), nullable=True),
        sa.Column("undone_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("action IN ('restore_genuine','quarantine')", name="ck_remediation_actions_action"),
        sa.CheckConstraint("status IN ('done','failed','undone')", name="ck_remediation_actions_status"),
    )
    op.create_index("ix_remediation_actions_ticket", "remediation_actions", ["ticket_id", "performed_at"])
    op.create_index("ix_remediation_actions_website", "remediation_actions", ["website_id", "performed_at"])
    _rls("remediation_actions")


def downgrade() -> None:
    op.drop_table("remediation_actions")
    op.drop_table("remediation_credentials")
