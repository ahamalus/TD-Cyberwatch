"""End-to-end Phase 1 proof of concept against a real (in-process) SFTP server.

Covers: hosting connection, capability discovery, host-key pinning, file
inventory with SHA-256 baseline, detection of controlled additions,
modifications and deletions, partial scans, and the guarantee that remote
files are never modified.
"""

from __future__ import annotations

import hashlib
import os

from sqlalchemy import select

from app.db.session import platform_session
from app.models import FileChange, FileInventoryItem, FileSnapshot, Incident, ScanJob
from tests.conftest import run_dispatched


def _connect(sess, tenant_id, server, root="/public_html"):
    r = sess.post(f"/api/v1/tenants/{tenant_id}/hosting-accounts", json={
        "name": "Main hosting", "connector_type": "sftp", "hostname": "127.0.0.1", "port": server.port,
        "username": server.state.username, "root_path": root,
        "credential": {"kind": "password", "value": server.state.password},
    })
    assert r.status_code == 201, r.text
    acct = r.json()
    assert run_dispatched() == ["succeeded"]
    return acct["id"]


def _website(sess, tenant_id, account_id, name="Site", url="https://www.alpha-site.com/"):
    r = sess.post(f"/api/v1/tenants/{tenant_id}/websites", json={
        "name": name, "url": url, "hosting_account_id": account_id})
    assert r.status_code == 201, r.text
    wid = r.json()["id"]
    r = sess.put(f"/api/v1/tenants/{tenant_id}/websites/{wid}/monitoring", json={
        "file_scan_enabled": True, "file_scan_interval_minutes": 1440, "availability_enabled": False,
        "tls_enabled": False})
    assert r.status_code == 200, r.text
    return wid


def _scan(sess, tenant_id, wid):
    r = sess.post(f"/api/v1/tenants/{tenant_id}/websites/{wid}/checks", json={"check": "file_scan"})
    assert r.status_code == 202, r.text
    return run_dispatched()


def test_connection_and_capability_discovery(alice, sftp_server):
    sess, tid = alice
    acct_id = _connect(sess, tid, sftp_server)
    acct = sess.get(f"/api/v1/tenants/{tid}/hosting-accounts/{acct_id}").json()
    assert acct["status"] == "connected"
    assert acct["host_key_fingerprint"].startswith("SHA256:")
    caps = {c["capability"]: c["status"] for c in acct["capabilities"]}
    assert caps["file_listing"] == "available"
    assert caps["file_hashing"] == "available"
    # Never assumed over SFTP:
    assert caps["hosting_malware_scan"] == "unsupported"
    assert caps["realtime_file_events"] == "unsupported"
    assert caps["log_access"] == "untested"
    # Secret never returned
    assert sftp_server.state.password not in str(acct)
    assert acct["credential_fingerprint"].startswith("SHA256:")


def test_baseline_and_change_detection(alice, sftp_server, sftp_root):
    sess, tid = alice
    acct_id = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct_id)

    assert _scan(sess, tid, wid) == ["succeeded"]
    site = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}").json()
    assert site["baseline_snapshot_id"] is not None, "first completed scan becomes the baseline"
    assert site["last_scan_status"] == "completed"
    inv = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/inventory", params={"page_size": 200}).json()
    paths = {i["path"]: i for i in inv["items"]}
    assert ".htaccess" in paths, "dotfiles are inventoried"
    expected = hashlib.sha256((sftp_root / "public_html" / "index.php").read_bytes()).hexdigest()
    assert paths["index.php"]["sha256"] == expected
    assert paths["index.php"]["hash_status"] == "hashed"

    # Controlled changes
    web = sftp_root / "public_html"
    (web / "index.php").write_text("<?php echo 'changed';")
    (web / "about.html").unlink()
    (web / "wp-content" / "uploads" / "x.php").write_text("<?php system($_GET['c']);")
    (web / "new.css").write_text("body{}")
    assert _scan(sess, tid, wid) == ["succeeded"]

    changes = sess.get(f"/api/v1/tenants/{tid}/changes", params={"website_id": wid, "page_size": 100}).json()["items"]
    by_path = {c["path"]: c for c in changes}
    assert by_path["index.php"]["change_type"] == "modified"
    assert by_path["about.html"]["change_type"] == "deleted"
    assert by_path["wp-content/uploads/x.php"]["change_type"] == "added"
    assert "script_in_upload_dir" in by_path["wp-content/uploads/x.php"]["flags"]
    assert by_path["wp-content/uploads/x.php"]["severity"] == "high"
    assert by_path["new.css"]["change_type"] == "added"

    incidents = sess.get(f"/api/v1/tenants/{tid}/incidents").json()["items"]
    cats = {i["category"] for i in incidents}
    assert "suspicious_file" in cats
    assert "file_integrity" in cats
    # Inventory state
    inv = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/inventory", params={"state": "deleted"}).json()
    assert [i["path"] for i in inv["items"]] == ["about.html"]
    # Baseline unchanged after suspicious changes
    site2 = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}").json()
    assert site2["baseline_snapshot_id"] == site["baseline_snapshot_id"]
    # Baseline comparison
    cmp_ = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/compare").json()
    assert cmp_["total_changes"] == 4
    # The connector never attempted any write or command execution.
    assert sftp_server.state.write_attempts == []


def test_rename_inferred(alice, sftp_server, sftp_root):
    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    _scan(sess, tid, wid)
    os.rename(sftp_root / "public_html" / "about.html", sftp_root / "public_html" / "about-us.html")
    _scan(sess, tid, wid)
    changes = sess.get(f"/api/v1/tenants/{tid}/changes", params={"website_id": wid}).json()["items"]
    assert len(changes) == 1
    assert changes[0]["change_type"] == "renamed"
    assert changes[0]["old_path"] == "about.html"


def test_permission_denied_directory_is_partial_not_deleted(alice, sftp_server, sftp_root):
    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    _scan(sess, tid, wid)
    # The private directory becomes unreadable: its files must NOT be reported deleted.
    sftp_server.state.deny.add(str(sftp_root / "public_html" / "private").replace(str(sftp_root), ""))
    assert _scan(sess, tid, wid) == ["partial"]
    changes = sess.get(f"/api/v1/tenants/{tid}/changes", params={"website_id": wid}).json()["items"]
    assert not [c for c in changes if c["change_type"] == "deleted"]
    inv = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/inventory", params={"state": "unverified"}).json()
    assert [i["path"] for i in inv["items"]] == ["private/secret.txt"]
    snaps = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/snapshots").json()["items"]
    assert snaps[0]["status"] == "partial"
    assert snaps[0]["deletions_unverified"] == 1
    errors = sess.get(f"/api/v1/tenants/{tid}/snapshots/{snaps[0]['id']}/errors").json()["items"]
    assert errors[0]["error_type"] == "permission_denied"


def test_failed_scan_creates_no_mass_deletion(alice, sftp_server, sftp_root):
    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    _scan(sess, tid, wid)
    # Root becomes unreadable: the scan fails; nothing is reported deleted.
    sftp_server.state.deny.add("/public_html")
    results = _scan(sess, tid, wid)
    assert results == ["failed"]
    with platform_session() as db:
        assert db.execute(select(FileChange).where(FileChange.change_type == "deleted")).first() is None
        states = {i.state for i in db.execute(select(FileInventoryItem)).scalars()}
        assert states == {"present"}
        snap = db.execute(select(FileSnapshot).order_by(FileSnapshot.started_at.desc())).scalars().first()
        assert snap.status == "failed"
    site = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}").json()
    assert site["last_scan_status"] == "failed"
    assert site["coverage"]["overall"] != "full"


def test_root_emptied_withholds_deletions(alice, sftp_server, sftp_root):
    sess, tid = alice
    web = sftp_root / "public_html"
    for i in range(12):
        (web / f"page{i}.html").write_text(str(i))
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    _scan(sess, tid, wid)
    import shutil

    shutil.rmtree(web)
    web.mkdir()
    assert _scan(sess, tid, wid) == ["partial"]
    changes = sess.get(f"/api/v1/tenants/{tid}/changes", params={"website_id": wid}).json()
    assert changes["total"] == 0
    incs = sess.get(f"/api/v1/tenants/{tid}/incidents").json()["items"]
    assert any("unexpectedly empty" in i["title"] for i in incs)


def test_wrong_password_reports_auth_failure(alice, sftp_server):
    sess, tid = alice
    r = sess.post(f"/api/v1/tenants/{tid}/hosting-accounts", json={
        "name": "Bad", "connector_type": "sftp", "hostname": "127.0.0.1", "port": sftp_server.port,
        "username": "webuser", "root_path": "/public_html", "credential": {"kind": "password", "value": "wrong-password"}})
    assert r.status_code == 201
    assert run_dispatched() == ["failed"]
    acct = sess.get(f"/api/v1/tenants/{tid}/hosting-accounts/{r.json()['id']}").json()
    assert acct["status"] == "auth_failed"
    assert acct["last_error_code"] == "auth_failed"
    assert all(c["status"] == "untested" for c in acct["capabilities"])
    assert "wrong-password" not in str(acct)


def test_host_key_change_blocks_connection(alice, sftp_server):
    import paramiko

    sess, tid = alice
    acct_id = _connect(sess, tid, sftp_server)
    sftp_server.host_key = paramiko.RSAKey.generate(2048)  # server "rebuilt" or intercepted
    r = sess.post(f"/api/v1/tenants/{tid}/hosting-accounts/{acct_id}/test")
    assert r.status_code == 202
    assert run_dispatched() == ["failed"]
    acct = sess.get(f"/api/v1/tenants/{tid}/hosting-accounts/{acct_id}").json()
    assert acct["last_error_code"] == "host_key_mismatch"
    incs = sess.get(f"/api/v1/tenants/{tid}/incidents").json()["items"]
    assert any(i["rule_key"] == "host_key_mismatch" for i in incs)


def test_overlapping_scans_are_prevented(alice, sftp_server):
    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    r1 = sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/checks", json={"check": "file_scan"}).json()
    r2 = sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/checks", json={"check": "file_scan"}).json()
    assert r1["created"] is True and r2["created"] is False
    assert r1["job_id"] == r2["job_id"]
    run_dispatched()
    with platform_session() as db:
        assert db.execute(select(ScanJob).where(ScanJob.job_type == "file_scan")).scalars().all().__len__() == 1


def test_job_cannot_be_claimed_twice(alice, sftp_server):
    from app.monitoring import jobs as j
    from tests.conftest import DISPATCHED

    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/checks", json={"check": "file_scan"})
    job_id, _ = DISPATCHED.pop(0)
    first = j.claim(job_id, "w1")
    second = j.claim(job_id, "w2")
    assert first is not None and second is None


def test_cancel_queued_job(alice, sftp_server):
    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    job = sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/checks", json={"check": "file_scan"}).json()
    r = sess.post(f"/api/v1/tenants/{tid}/jobs/{job['job_id']}/cancel")
    assert r.json()["status"] == "cancelled"
    assert run_dispatched() == [None]


def test_incident_lifecycle(alice, sftp_server, sftp_root):
    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    _scan(sess, tid, wid)
    (sftp_root / "public_html" / "shell.php").write_text("<?php")
    _scan(sess, tid, wid)
    inc = sess.get(f"/api/v1/tenants/{tid}/incidents").json()["items"][0]
    url = f"/api/v1/tenants/{tid}/incidents/{inc['id']}"
    assert sess.post(url + "/status", json={"status": "acknowledged"}).status_code == 200
    assert sess.post(url + "/notes", json={"body": "Checking with developer"}).status_code == 200
    # Resolving requires notes
    assert sess.post(url + "/status", json={"status": "resolved"}).status_code == 422
    r = sess.post(url + "/status", json={"status": "resolved", "note": "Authorised deployment", "false_positive": True})
    assert r.status_code == 200
    detail = sess.get(url).json()
    assert detail["status"] == "resolved"
    assert detail["history_verified"] is True
    assert [e["event_type"] for e in detail["events"]][:1] == ["created"]
    assert all(ev["integrity_ok"] for ev in detail["evidence"])
    # Invalid transition
    assert sess.post(url + "/status", json={"status": "acknowledged"}).status_code == 422
    with platform_session() as db:
        assert db.get(Incident, inc["id"]).is_false_positive is True


def test_baseline_approval_is_audited(alice, sftp_server, sftp_root):
    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    _scan(sess, tid, wid)
    (sftp_root / "public_html" / "index.php").write_text("v2")
    _scan(sess, tid, wid)
    snaps = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/snapshots").json()["items"]
    latest = snaps[0]["id"]
    r = sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/baseline", json={"snapshot_id": latest, "reason": "Release 2.0"})
    assert r.status_code == 200
    assert r.json()["baseline_snapshot_id"] == latest
    audit = sess.get(f"/api/v1/tenants/{tid}/audit", params={"action": "baseline"}).json()["items"]
    assert audit[0]["details"]["reason"] == "Release 2.0"
