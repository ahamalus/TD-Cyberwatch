"""Only the baseline and the newest scans keep their full file lists; older scans keep their summary and changes."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select

from app.db.session import platform_session
from app.models import FileChange, FileSnapshot, FileSnapshotEntry
from tests.test_monitoring_flow import _connect, _scan, _website


def _with_entries(wid) -> set:
    with platform_session() as db:
        return set(db.execute(select(FileSnapshotEntry.snapshot_id).where(
            FileSnapshotEntry.snapshot_id.in_(select(FileSnapshot.id).where(
                FileSnapshot.website_id == uuid.UUID(wid))))).scalars())


def test_old_file_lists_are_pruned_but_baseline_and_recent_kept(alice, sftp_server, sftp_root):
    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    for i in range(6):
        (sftp_root / "public_html" / f"page{i}.html").write_text(f"v{i}")
        assert _scan(sess, tid, wid) == ["succeeded"]
    site = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}").json()
    baseline = uuid.UUID(site["baseline_snapshot_id"])
    with platform_session() as db:
        snaps = db.execute(select(FileSnapshot.id).where(FileSnapshot.website_id == uuid.UUID(wid))
                           .order_by(FileSnapshot.started_at.desc())).scalars().all()
        changes = db.execute(select(func.count()).select_from(FileChange)).scalar_one()
    assert len(snaps) == 6
    assert _with_entries(wid) == set(snaps[:3]) | {baseline}, "baseline + 3 newest keep their file lists"
    assert changes >= 5, "every scan's detected changes are kept"

    # Baseline comparison still works; old scans cannot be compared or approved as baseline.
    assert sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/compare").status_code == 200
    old = next(s for s in snaps[3:] if s != baseline)
    r = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/compare", params={"target": str(old)})
    assert r.status_code == 422 and "no longer kept" in r.json()["error"]["message"]
    r = sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/baseline", json={"snapshot_id": str(old), "reason": "test old"})
    assert r.status_code == 422 and "no longer kept" in r.json()["error"]["message"]
    r = sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/baseline", json={"snapshot_id": str(snaps[1]), "reason": "recent scan"})
    assert r.status_code == 200, r.text
