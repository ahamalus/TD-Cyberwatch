"""Access-log analysis end to end over SFTP: verified probe, incremental reading, rotation, incidents."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.db.session import platform_session
from app.models import ConnectorCapability, Incident, ScanJob
from tests.conftest import run_dispatched
from tests.test_malware import CMD_SHELL
from tests.test_monitoring_flow import _scan, _website

LINE = '{ip} - - [22/Nov/2026:10:{m:02d}:00 +0100] "{method} {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"\n'


def _line(path, method="GET", status=200, size=300, ip="203.0.113.9", m=0):
    return LINE.format(ip=ip, path=path, method=method, status=status, size=size, m=m)


def _connect_with_logs(sess, tid, server, log_paths):
    r = sess.post(f"/api/v1/tenants/{tid}/hosting-accounts", json={
        "name": "Hosting with logs", "connector_type": "sftp", "hostname": "127.0.0.1", "port": server.port,
        "username": server.state.username, "root_path": "/public_html", "log_paths": log_paths,
        "credential": {"kind": "password", "value": server.state.password},
    })
    assert r.status_code == 201, r.text
    assert run_dispatched() == ["succeeded"]
    return r.json()["id"]


def _cap(acct):
    with platform_session() as db:
        return db.execute(select(ConnectorCapability).where(
            ConnectorCapability.hosting_account_id == uuid.UUID(acct),
            ConnectorCapability.capability == "log_access")).scalar_one()


def _log_scan(sess, tid, wid):
    r = sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/checks", json={"check": "log_scan"})
    assert r.status_code == 202, r.text
    outcome = run_dispatched()
    with platform_session() as db:
        if outcome != ["succeeded"]:
            err = db.execute(select(ScanJob.error_message).where(ScanJob.website_id == uuid.UUID(wid))
                             .order_by(ScanJob.queued_at.desc()).limit(1)).scalar_one()
            raise AssertionError(f"log scan {outcome}: {err}")
        return db.execute(select(ScanJob.result_summary).where(ScanJob.website_id == uuid.UUID(wid),
                                                               ScanJob.job_type == "log_scan")
                          .order_by(ScanJob.finished_at.desc()).limit(1)).scalar_one()


def _log_incidents():
    with platform_session() as db:
        return {i.rule_key: i for i in db.execute(select(Incident).where(Incident.category == "log_activity")).scalars()}


def test_log_access_is_only_claimed_when_a_log_is_read_and_recognised(alice, sftp_server, sftp_root):
    sess, tid = alice
    (sftp_root / "logs").mkdir()
    (sftp_root / "logs" / "notes.txt").write_text("this is not an access log\n")
    acct = _connect_with_logs(sess, tid, sftp_server, ["/logs"])
    cap = _cap(acct)
    assert cap.status == "unavailable" and "not in a recognised access-log format" in cap.detail
    wid = _website(sess, tid, acct)
    r = sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/checks", json={"check": "log_scan"})
    assert r.status_code == 202
    assert run_dispatched() == ["failed"], "no analysis without verified log access"


def test_web_shell_use_and_brute_force_found_in_logs(alice, sftp_server, sftp_root):
    sess, tid = alice
    uploads = sftp_root / "public_html" / "wp-content" / "uploads"
    (uploads / "cache.php").write_text(CMD_SHELL)
    logdir = sftp_root / "logs"
    logdir.mkdir()
    log = logdir / "www.alpha-site.com-ssl_log"
    log.write_text("".join(_line(f"/page-{i}") for i in range(30)))
    (logdir / "other-site.com-ssl_log").write_text(_line("/.env", size=900) * 3)  # another site: not read
    acct = _connect_with_logs(sess, tid, sftp_server, ["/logs"])
    assert _cap(acct).status == "available"
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]  # flags uploads/cache.php

    first = _log_scan(sess, tid, wid)
    assert first["requests"] == 30 and first["findings"] == [] and first["files"][0]["note"] == "first read"
    assert [f["file"] for f in first["files"]] == ["/logs/www.alpha-site.com-ssl_log"]

    # New lines: the planted shell is used, and someone guesses passwords then gets in.
    with log.open("a") as fh:
        fh.write(_line("/wp-content/uploads/cache.php?cmd=id", method="POST", ip="198.51.100.66", m=5))
        fh.writelines(_line("/wp-login.php", method="POST", ip="192.0.2.50", m=6) for _ in range(25))
        fh.write(_line("/wp-login.php", method="POST", status=302, ip="192.0.2.50", m=7))
        fh.write(_line("/.git/config", status=404, size=0, ip="192.0.2.80", m=8))
    second = _log_scan(sess, tid, wid)
    assert second["requests"] == 28, "only the new lines are read"
    incs = _log_incidents()
    used = incs["log:flagged_file_accessed"]
    assert used.severity == "high" and "cache.php" in used.title and used.finding_class == "suspected_compromise"
    assert incs["log:login_bruteforce_success"].severity == "high"
    assert incs["log:login_bruteforce"].severity == "medium"
    assert "log:sensitive_file_exposed" not in incs, "a 404 probe is not an exposure"
    assert second["probes_for_sensitive_files"] == 1

    # Nothing new: nothing re-raised. Rotation: the file starts over and is read from the beginning.
    assert _log_scan(sess, tid, wid)["requests"] == 0
    log.write_text(_line("/.env", size=1200, ip="192.0.2.81"))
    rotated = _log_scan(sess, tid, wid)
    assert rotated["requests"] == 1 and "rotated" in rotated["files"][0]["note"]
    assert _log_incidents()["log:sensitive_file_exposed"].severity == "high"


def test_cpanel_style_gzip_archives_are_analysed_incrementally(alice, sftp_server, sftp_root):
    """Hosts that jail accounts make ~/access-logs unreachable; cPanel's daily archives in ~/logs are used."""
    import gzip
    import os
    import time

    sess, tid = alice
    logdir = sftp_root / "logs"
    logdir.mkdir()
    archive = logdir / "www.alpha-site.com-ssl_log-Nov-2026.gz"
    old = logdir / "www.alpha-site.com-ssl_log-Oct-2026.gz"
    old.write_bytes(gzip.compress(_line("/.env", size=500).encode()))
    os.utime(old, (time.time() - 40 * 86400, time.time() - 40 * 86400))  # previous month: not analysed
    archive.write_bytes(gzip.compress("".join(_line(f"/p{i}") for i in range(10)).encode()))
    acct = _connect_with_logs(sess, tid, sftp_server, ["/logs"])
    cap = _cap(acct)
    assert cap.status == "available" and "archive" in cap.detail
    wid = _website(sess, tid, acct)
    assert _log_scan(sess, tid, wid)["requests"] == 10
    assert "log:sensitive_file_exposed" not in _log_incidents(), "last month's archive is skipped"

    # The control panel rewrites the archive with the day's new lines appended.
    time.sleep(1.1)
    content = "".join(_line(f"/p{i}") for i in range(10)) + _line("/wp-config.php.bak", size=4000, ip="192.0.2.90")
    archive.write_bytes(gzip.compress(content.encode()))
    second = _log_scan(sess, tid, wid)
    assert second["requests"] == 1, "only lines added since the last run"
    assert _log_incidents()["log:sensitive_file_exposed"].severity == "high"
    assert _log_scan(sess, tid, wid)["requests"] == 0, "unchanged archive is not downloaded again"


def test_corrupt_archive_is_reported_not_trusted(alice, sftp_server, sftp_root):
    sess, tid = alice
    logdir = sftp_root / "logs"
    logdir.mkdir()
    (logdir / "www.alpha-site.com-ssl_log-Nov-2026.gz").write_bytes(b"\x1f\x8b\x08\x00garbage-not-gzip" * 10)
    acct = _connect_with_logs(sess, tid, sftp_server, ["/logs"])
    cap = _cap(acct)
    assert cap.status == "unavailable" and "could not be decompressed" in cap.detail
