"""Scan speed features: parallel cPanel reads over one vetted keep-alive session, incremental scans that
reuse hashes of unchanged files, the weekly full content check, resuming time-limited full passes, and
the default exclusion of PHP error logs."""

from __future__ import annotations

import os
import threading
import uuid
from datetime import timedelta

from sqlalchemy import select

from app.connectors.base import ConnectionParams, SecretMaterial
from app.core.config import get_settings
from app.core.http import set_transport_factory
from app.db.base import utcnow
from app.db.session import platform_session
from app.models import FileChange, ScanJob
from app.monitoring.file_scan import _content_mode
from app.monitoring.inventory import DEFAULT_EXCLUSIONS, matches_any, walk_inventory
from tests.test_monitoring_flow import _connect, _scan, _website
from tests.test_services import LIMITS, _cpanel_transport, _site, cpanel_env  # noqa: F401 - fixture


def _last_scan_summary(website_id) -> dict:
    with platform_session() as db:
        return db.execute(
            select(ScanJob.result_summary).where(ScanJob.website_id == uuid.UUID(str(website_id)),
                                                 ScanJob.job_type == "file_scan")
            .order_by(ScanJob.finished_at.desc()).limit(1)
        ).scalar_one()


def test_cpanel_file_reads_are_parallel_and_reuse_one_vetted_connection(cpanel_env, monkeypatch):  # noqa: F811
    import app.core.http as http
    from app.connectors.cpanel import CPanelUAPIConnector

    files = {f"public_html/f{i:02d}.php": f"<?php echo {i};".encode() for i in range(20)}
    threads: set[str] = set()

    def transport():
        inner = _cpanel_transport(files)

        def handler(request):
            threads.add(threading.current_thread().name)
            return inner.handle_request(request)

        return http.httpx.MockTransport(handler)

    set_transport_factory(transport)
    resolutions = []
    real = http.resolve_public_target
    monkeypatch.setattr(http, "resolve_public_target", lambda *a, **k: resolutions.append(a) or real(*a, **k))
    conn = CPanelUAPIConnector(ConnectionParams("cpanel_uapi", "server.acme-hosting.com", 2083, "acme", "/public_html"),
                               SecretMaterial("api_token", "TOKEN123"))
    with conn.open_file_source("/public_html") as src:
        assert src.parallel_reads == get_settings().cpanel_parallel_reads == 4
        res = walk_inventory(src, [], LIMITS, parallel=src.parallel_reads)
    assert res.files_hashed == 20 and not res.errors
    assert len(resolutions) == 1, "host vetted once per scan session, not per file"
    assert any(t.startswith("scan-read") for t in threads), "files were fetched by the parallel readers"


def test_incremental_scans_reuse_unchanged_files_and_full_check_catches_forged_mtime(alice, sftp_server, sftp_root,
                                                                                    monkeypatch):
    sess, tid = alice
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    site = sftp_root / "public_html"

    assert _scan(sess, tid, wid) == ["succeeded"]
    first = _last_scan_summary(wid)
    assert first["content_mode"] == "full" and first["files_reused"] == 0

    assert _scan(sess, tid, wid) == ["succeeded"]
    second = _last_scan_summary(wid)
    assert second["content_mode"] == "incremental"
    assert second["files_reused"] == second["files_hashed"] > 0 and second["changes"] == 0

    # A real change (different size) is always detected in incremental mode.
    (site / "index.php").write_text("<?php echo 'changed and longer';")
    assert _scan(sess, tid, wid) == ["succeeded"]
    assert _last_scan_summary(wid)["changes"] == 1

    # Same size and a forged modification time: invisible to an incremental scan...
    target = site / "about.html"
    st = target.stat()
    target.write_text("<h1>ABOUT</h1>")  # same length as "<h1>About</h1>"
    os.utime(target, (st.st_atime, st.st_mtime))
    assert _scan(sess, tid, wid) == ["succeeded"]
    assert _last_scan_summary(wid)["changes"] == 0

    # ...but the periodic full content check downloads everything again and catches it.
    monkeypatch.setattr(get_settings(), "full_content_check_days", 0)
    assert _scan(sess, tid, wid) == ["succeeded"]
    summary = _last_scan_summary(wid)
    assert summary["content_mode"] == "full" and summary["changes"] == 1
    with platform_session() as db:
        latest = db.execute(select(FileChange).where(FileChange.path == "about.html")).scalars().all()
    assert any(c.change_type == "modified" for c in latest)


def test_time_limited_full_pass_is_resumed_then_scans_become_incremental(alice):
    _, tid = alice
    wid = _site(tid)

    def job(mode, limits, days_ago=0):
        with platform_session() as db:
            db.add(ScanJob(tenant_id=tid, website_id=wid, job_type="file_scan", status="partial",
                           finished_at=utcnow() - timedelta(days=days_ago, seconds=-len(str(mode))),
                           result_summary={"content_mode": mode, "limits_hit": limits}))
            db.commit()

    with platform_session() as db:
        assert _content_mode(db, wid, has_previous=False) == ("full", False)
        assert _content_mode(db, wid, has_previous=True) == ("full", False), "no full pass yet"
    job("full", ["time"], days_ago=1)
    with platform_session() as db:
        assert _content_mode(db, wid, True) == ("full_continued", True), "resume, keeping what was downloaded"
    job("full_continued", [])
    with platform_session() as db:
        assert _content_mode(db, wid, True) == ("incremental", True), "full pass completed this week"


def test_full_check_is_due_again_after_the_interval(alice):
    _, tid = alice
    wid = _site(tid)
    with platform_session() as db:
        db.add(ScanJob(tenant_id=tid, website_id=wid, job_type="file_scan", status="succeeded",
                       finished_at=utcnow() - timedelta(days=8), result_summary={"content_mode": "full", "limits_hit": []}))
        db.commit()
        assert _content_mode(db, wid, True) == ("full", False)


def test_php_error_logs_are_excluded_by_default():
    for path in ("error_log", "wp-admin/error_log", "wp-content/plugins/x/error_log"):
        assert matches_any(path, DEFAULT_EXCLUSIONS), path
    assert not matches_any("wp-content/error_log.php", DEFAULT_EXCLUSIONS)


def test_time_limited_full_pass_schedules_its_own_continuation(alice, sftp_server, monkeypatch):
    sess, tid = alice
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    monkeypatch.setattr(get_settings(), "scan_max_seconds", 0)  # stop at the first directory
    statuses = _scan(sess, tid, wid)
    assert statuses[0] == "partial"
    assert statuses[1:] == [None], "continuation is queued for later (not runnable yet)"
    with platform_session() as db:
        jobs = db.execute(select(ScanJob).where(ScanJob.website_id == uuid.UUID(wid), ScanJob.job_type == "file_scan")
                          .order_by(ScanJob.queued_at)).scalars().all()
    assert [j.trigger for j in jobs] == ["manual", "continuation"]
    assert jobs[1].status == "queued" and jobs[1].not_before > utcnow() + timedelta(minutes=4)
