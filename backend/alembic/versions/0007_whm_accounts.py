"""WHM: one login may monitor several cPanel accounts (the account is part of a connection's identity)

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-23 20:00:00

"""

from typing import Sequence, Union

from alembic import op

revision: str = "0007"
down_revision: Union[str, Sequence[str], None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("uq_hosting_identity", "hosting_accounts", type_="unique")
    op.execute(
        "CREATE UNIQUE INDEX uq_hosting_identity ON hosting_accounts "
        "(tenant_id, connector_type, hostname, username, (COALESCE(options->>'cpanel_user', '')))"
    )


def downgrade() -> None:
    op.execute("DROP INDEX uq_hosting_identity")
    op.create_unique_constraint("uq_hosting_identity", "hosting_accounts",
                                ["tenant_id", "connector_type", "hostname", "username"])
