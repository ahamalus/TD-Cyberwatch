"""SSH read-only connector: allow-listed commands only, server fingerprints cross-checked against a download,
fallback to plain SFTP downloads, and home-directory access logs."""

from __future__ import annotations

import os

import pytest

from app.connectors.base import ConnectionParams, ConnectorError, SecretMaterial
from app.connectors.ssh_readonly import SSHReadOnlyConnector, parse_digests, run_command
from app.core.config import get_settings
from tests.conftest import run_dispatched
from tests.test_monitoring_flow import _scan, _website
from tests.test_scan_performance import _last_scan_summary


def _conn(server, root="/public_html"):
    return SSHReadOnlyConnector(
        ConnectionParams("ssh_readonly", "127.0.0.1", server.port, server.state.username, root),
        SecretMaterial("password", server.state.password))


def _connect_ssh(sess, tid, server, root="/public_html"):
    r = sess.post(f"/api/v1/tenants/{tid}/hosting-accounts", json={
        "name": "SSH hosting", "connector_type": "ssh_readonly", "hostname": "127.0.0.1", "port": server.port,
        "username": server.state.username, "root_path": root,
        "credential": {"kind": "password", "value": server.state.password}})
    assert r.status_code == 201, r.text
    assert run_dispatched() == ["succeeded"]
    return r.json()["id"]


def test_only_allow_listed_commands_with_quoted_arguments(sftp_server):
    sftp_server.state.allow_exec = True
    conn = _conn(sftp_server)
    with conn.open_file_source("/public_html") as src:
        for program in ("rm", "sh", "cat", "sha256sum; rm -rf /"):
            with pytest.raises(ConnectorError):
                run_command(src._transport, program, [], 5)
        with pytest.raises(ConnectorError):
            run_command(src._transport, "sha256sum", ["--", "a\nrm -rf /"], 5)
        digests = src.remote_digests(["index.php", "about.html"])
    assert set(digests) == {"index.php", "about.html"}
    # Paths are absolute below the root and single-quoted; nothing else was ever sent.
    assert sftp_server.state.exec_commands == ["sha256sum -- /public_html/index.php /public_html/about.html",
                                               "md5sum -- /public_html/index.php /public_html/about.html"]
    assert not sftp_server.state.write_attempts


def test_paths_outside_the_root_are_refused(sftp_server):
    sftp_server.state.allow_exec = True
    with _conn(sftp_server).open_file_source("/public_html") as src:
        assert src.remote_digests(["../../etc/passwd"]) == {}
        assert not src.remote_hashing, "an unsafe path switches remote hashing off"
    assert sftp_server.state.exec_commands == []


def test_awkward_file_names_are_quoted_and_parsed(sftp_server, sftp_root):
    sftp_server.state.allow_exec = True
    (sftp_root / "public_html" / "it's a $(test).php").write_text("<?php")
    with _conn(sftp_server).open_file_source("/public_html") as src:
        assert "it's a $(test).php" in src.remote_digests(["it's a $(test).php"])
    assert parse_digests("\\" + "a" * 64 + "  /x\\ny\n" + "b" * 64 + " */bin\n", 64) == {"/bin": "b" * 64}


def test_lying_server_is_caught_by_the_cross_check(sftp_server):
    sftp_server.state.allow_exec = True
    sftp_server.state.lie_about_hashes = True
    with _conn(sftp_server).open_file_source("/public_html") as src:
        assert src.remote_digests(["index.php", "about.html"]) == {}
        assert not src.remote_hashing and "did not match" in src.remote_hash_note


def test_host_without_commands_falls_back_to_sftp(alice, sftp_server):
    sess, tid = alice  # allow_exec stays False: an SFTP-only account
    acct = _connect_ssh(sess, tid, sftp_server)
    caps = {c["capability"]: c for c in sess.get(f"/api/v1/tenants/{tid}/hosting-accounts/{acct}").json()["capabilities"]}
    assert caps["file_hashing"]["status"] == "available"
    assert "every file is downloaded" in caps["file_hashing"]["detail"]
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]
    assert _last_scan_summary(wid)["files_hashed_remotely"] == 0


def test_full_pass_skips_downloads_of_scanned_content_but_catches_forged_mtime(alice, sftp_server, sftp_root, monkeypatch):
    sftp_server.state.allow_exec = True
    sess, tid = alice
    acct = _connect_ssh(sess, tid, sftp_server)
    caps = {c["capability"]: c for c in sess.get(f"/api/v1/tenants/{tid}/hosting-accounts/{acct}").json()["capabilities"]}
    assert "computed on the server" in caps["file_hashing"]["detail"]
    assert caps["hosting_malware_scan"]["status"] == "unavailable"
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]
    first = _last_scan_summary(wid)
    assert first["files_hashed"] > 0

    target = sftp_root / "public_html" / "about.html"
    st = target.stat()
    target.write_text("<h1>ABOUT</h1>")  # same size, forged modification time
    os.utime(target, (st.st_atime, st.st_mtime))
    monkeypatch.setattr(get_settings(), "full_content_check_days", 0)
    assert _scan(sess, tid, wid) == ["succeeded"]
    full = _last_scan_summary(wid)
    assert full["content_mode"] == "full" and full["changes"] == 1, "forged mtime caught by server fingerprints"
    # Everything already scanned was recognised on the server; only new content was downloaded.
    assert full["files_hashed_remotely"] >= first["files_hashed"] - 2
    assert not sftp_server.state.write_attempts
    assert all(c.split()[0] in ("sha256sum", "md5sum") for c in sftp_server.state.exec_commands)


def test_home_access_logs_are_found_without_configuration(alice, sftp_server, sftp_root):
    sftp_server.state.allow_exec = True
    (sftp_root / "access-logs").mkdir()
    (sftp_root / "access-logs" / "www.alpha-site.com-ssl_log").write_text(
        '203.0.113.9 - - [22/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')
    sess, tid = alice
    acct = _connect_ssh(sess, tid, sftp_server)
    caps = {c["capability"]: c for c in sess.get(f"/api/v1/tenants/{tid}/hosting-accounts/{acct}").json()["capabilities"]}
    assert caps["log_access"]["status"] == "available", caps["log_access"]
    assert "access-logs" in caps["log_access"]["detail"]
