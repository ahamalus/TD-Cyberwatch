"""service desk: scope proposed by staff when asking the customer to authorise work

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-26 10:00:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0010"
down_revision: Union[str, Sequence[str], None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("support_tickets", sa.Column("proposed_scope", sa.Text(), nullable=True))
    op.add_column("support_tickets", sa.Column("authorisation_requested_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("support_tickets", "authorisation_requested_at")
    op.drop_column("support_tickets", "proposed_scope")
