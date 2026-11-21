"""vendor checksum verification and content approvals: MD5 per file, official checksum cache, detected
software, suppression of one exact file content

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-21 18:00:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, Sequence[str], None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

RLS_POLICY = """
CREATE POLICY tenant_isolation ON {table}
USING (
    current_setting('app.scope', true) = 'platform'
    OR (
        current_setting('app.scope', true) = 'tenant'
        AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    )
)
WITH CHECK (
    current_setting('app.scope', true) = 'platform'
    OR (
        current_setting('app.scope', true) = 'tenant'
        AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    )
)
"""


def upgrade() -> None:
    op.add_column("file_snapshot_entries", sa.Column("md5", sa.String(length=32), nullable=True))
    op.add_column("file_inventory_items", sa.Column("vendor_status", sa.String(length=16), nullable=True))
    op.add_column("file_inventory_items", sa.Column("vendor_ref", sa.String(length=200), nullable=True))
    op.add_column("suppression_rules", sa.Column("content_sha256", sa.String(length=64), nullable=True))

    # Public data (published release checksums): not tenant-scoped.
    op.create_table(
        "vendor_checksums",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("product", sa.String(length=32), nullable=False),
        sa.Column("slug", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("locale", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("files", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("detail", sa.String(length=500), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vendor_checksums")),
        sa.UniqueConstraint("product", "slug", "version", "locale", name="uq_vendor_checksums_release"),
    )

    op.create_table(
        "software_installs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("website_id", sa.UUID(), nullable=False),
        sa.Column("product", sa.String(length=32), nullable=False),
        sa.Column("slug", sa.String(length=200), nullable=False),
        sa.Column("root", sa.String(length=1024), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("locale", sa.String(length=16), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=True),
        sa.Column("checksum_status", sa.String(length=16), nullable=True),
        sa.Column("files_verified", sa.Integer(), nullable=False),
        sa.Column("files_modified", sa.Integer(), nullable=False),
        sa.Column("files_unexpected", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name=op.f("fk_software_installs_tenant_id_tenants"),
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], name=op.f("fk_software_installs_website_id_websites"),
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_software_installs")),
        sa.UniqueConstraint("website_id", "product", "root", "slug", name="uq_software_install"),
    )
    op.create_index("ix_software_installs_tenant", "software_installs", ["tenant_id"])
    op.execute("ALTER TABLE software_installs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE software_installs FORCE ROW LEVEL SECURITY")
    op.execute(RLS_POLICY.format(table="software_installs"))


def downgrade() -> None:
    op.drop_index("ix_software_installs_tenant", table_name="software_installs")
    op.drop_table("software_installs")
    op.drop_table("vendor_checksums")
    op.drop_column("suppression_rules", "content_sha256")
    op.drop_column("file_inventory_items", "vendor_ref")
    op.drop_column("file_inventory_items", "vendor_status")
    op.drop_column("file_snapshot_entries", "md5")
