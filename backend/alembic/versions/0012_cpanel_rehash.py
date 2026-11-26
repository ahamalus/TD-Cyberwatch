"""cPanel/WHM: forget fingerprints taken before reads were made byte-exact

cPanel's Fileman::get_file_content rewrote the <meta charset> of HTML by default, so files containing HTML were
fingerprinted from altered content (and genuine WordPress files looked modified). Clearing the stored hashes of
each such website's latest and baseline scans makes the next scan read every file again; with no old hash to
compare, an unchanged file (same size and time) is not reported as changed.

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-26 18:00:00

"""

from typing import Sequence, Union

from alembic import op

revision: str = "0012"
down_revision: Union[str, Sequence[str], None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
WITH affected AS (
    SELECT id FROM (
        SELECT DISTINCT ON (website_id) id FROM file_snapshots
        WHERE connector_type IN ('cpanel_uapi', 'whm_api') AND status IN ('completed', 'partial')
        ORDER BY website_id, started_at DESC
    ) latest
    UNION
    SELECT w.baseline_snapshot_id FROM websites w JOIN file_snapshots s ON s.id = w.baseline_snapshot_id
    WHERE s.connector_type IN ('cpanel_uapi', 'whm_api')
)
UPDATE file_snapshot_entries SET sha256 = NULL, md5 = NULL, hash_status = 'rehash'
WHERE snapshot_id IN (SELECT id FROM affected) AND entry_type = 'file' AND hash_status = 'hashed'
""")


def downgrade() -> None:
    pass  # the old hashes were wrong; nothing to restore
