"""single-use TOTP codes

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-22 09:00:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005"
down_revision: Union[str, Sequence[str], None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_last_step", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_last_step")
