"""Verification against official WordPress checksums: genuine vendor files are recognised (and heuristics
stay quiet on them), modified core files and files planted in core directories are reported, checksum
lists are cached, and wordpress.org being unreachable never breaks a scan."""

from __future__ import annotations

import hashlib
import socket

import httpx
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.http import set_transport_factory
from app.db.session import platform_session
from app.models import Incident, VendorChecksums
from app.monitoring.vendor import CORE, PLUGIN, _normalise, _parse
from tests.test_monitoring_flow import _connect, _scan, _website

# A genuine core file that trips a heuristic rule (as real WordPress files did in production).
CORE_FILES = {
    "wp-includes/version.php": "<?php\n$wp_version = '6.7.1';\n$wp_db_version = 58975;\n",
    "wp-includes/functions.php": "<?php function wp_x() { return " + "sys" + "tem($_GET['cmd']); }\n",
    "wp-admin/index.php": "<?php require_once __DIR__ . '/admin.php';\n",
    "wp-content/plugins/akismet/akismet.php": "<?php /* bundled */\n",
}
PLUGIN_FILES = {
    "hello.php": "<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\necho 'hi';\n",
    "readme.txt": "Hello Dolly readme\n",
}


def md5(s: str) -> str:
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class FakeWordPressOrg:
    def __init__(self):
        self.calls: list[str] = []
        self.fail = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = request.headers["host"]
        self.calls.append(f"{host}{request.url.path}?{request.url.query.decode()}")
        if self.fail:
            return httpx.Response(503)
        if host == "api.wordpress.org" and request.url.path == "/core/checksums/1.0/":
            if request.url.params.get("version") != "6.7.1":
                return httpx.Response(200, json={"checksums": False})
            return httpx.Response(200, json={"checksums": {p: md5(c) for p, c in CORE_FILES.items()}})
        if host == "downloads.wordpress.org" and request.url.path == "/plugin-checksums/hello-dolly/1.7.2.json":
            return httpx.Response(200, json={"plugin": "hello-dolly", "version": "1.7.2", "files": {
                p: {"md5": md5(c), "sha256": sha(c)} for p, c in PLUGIN_FILES.items()}})
        return httpx.Response(404)


@pytest.fixture
def wporg(monkeypatch):
    fake = FakeWordPressOrg()
    real = socket.getaddrinfo

    def resolve(host, port, *a, **k):
        if host in ("api.wordpress.org", "downloads.wordpress.org"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.143.164.251", port))]
        return real(host, port, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(get_settings(), "vendor_checksums_enabled", True)
    set_transport_factory(lambda: httpx.MockTransport(fake.handler))
    yield fake
    set_transport_factory(None)


@pytest.fixture
def wp_site(sftp_root):
    web = sftp_root / "public_html"
    for rel, content in CORE_FILES.items():
        (web / rel).parent.mkdir(parents=True, exist_ok=True)
        (web / rel).write_text(content)
    plugin = web / "wp-content" / "plugins" / "hello-dolly"
    plugin.mkdir(parents=True)
    for rel, content in PLUGIN_FILES.items():
        (plugin / rel).write_text(content)
    return web


def _inventory(sess, tid, wid, **params):
    r = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/inventory", params={"page_size": 200, **params})
    return {i["path"]: i for i in r.json()["items"]}


def _incidents(rule_prefix=""):
    with platform_session() as db:
        return [i for i in db.execute(select(Incident)).scalars() if i.rule_key.startswith(rule_prefix)]


# ---------------------------------------------------------------- parsing


def test_version_and_plugin_headers_are_parsed():
    d = _parse("blog/wp-includes/version.php", b"<?php\n$wp_version = '6.5.2';\n$wp_local_package = 'de_DE';\n")
    assert (d.product, d.root, d.version, d.locale) == (CORE, "blog/", "6.5.2", "de_DE")
    d = _parse("wp-content/plugins/woo/woo.php", b"<?php\n/**\n * Plugin Name: WooCommerce\n * Version: 9.4.1\n */")
    assert (d.product, d.slug, d.root, d.version, d.name) == (PLUGIN, "woo", "", "9.4.1", "WooCommerce")
    assert _parse("wp-content/plugins/woo/includes/x.php", b"Plugin Name: X") is None, "only top-level plugin files"
    assert _parse("wp-content/plugins/woo/helper.php", b"<?php // Version: 2") is None, "needs a Plugin Name header"


def test_both_checksum_formats_are_normalised():
    assert _normalise(CORE, "6.7.1", {"checksums": {"a.php": "ABC"}}) == {"a.php": {"md5": ["abc"], "sha256": []}}
    assert _normalise(CORE, "6.7.1", {"checksums": {"6.7.1": {"a.php": "abc"}}})["a.php"]["md5"] == ["abc"]
    assert _normalise(CORE, "9.9", {"checksums": False}) == {}
    doc = {"files": {"x.php": {"md5": ["m1", "m2"], "sha256": "s1"}}}
    assert _normalise(PLUGIN, "1.0", doc) == {"x.php": {"md5": ["m1", "m2"], "sha256": ["s1"]}}


# ---------------------------------------------------------------- end to end


def test_genuine_files_verified_and_tampering_reported(alice, sftp_server, wp_site, wporg):
    sess, tid = alice
    # Tampering: a modified core file, a file planted in wp-includes and an edited plugin file.
    (wp_site / "wp-admin" / "index.php").write_text("<?php require_once __DIR__ . '/admin.php'; @include '/tmp/x';\n")
    (wp_site / "wp-includes" / "class-wp-cache-helper.php").write_text("<?php echo 1;\n")
    (wp_site / "wp-content" / "plugins" / "hello-dolly" / "readme.txt").write_text("changed\n")
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]

    inv = _inventory(sess, tid, wid)
    fn = inv["wp-includes/functions.php"]
    assert fn["vendor_status"] == "verified" and fn["vendor_ref"] == "wordpress 6.7.1"
    assert fn["malware_status"] == "suspicious", "the heuristic match is still recorded on the file"
    assert inv["wp-admin/index.php"]["vendor_status"] == "modified"
    assert inv["wp-includes/class-wp-cache-helper.php"]["vendor_status"] == "unexpected"
    assert inv["wp-content/plugins/hello-dolly/hello.php"]["vendor_status"] == "verified"
    assert inv["wp-content/plugins/hello-dolly/hello.php"]["vendor_ref"] == "hello-dolly 1.7.2"
    assert inv["wp-content/plugins/hello-dolly/readme.txt"]["vendor_status"] == "modified"
    assert inv["index.php"]["vendor_status"] is None, "not vendor software"
    flagged = _inventory(sess, tid, wid, malware="flagged")
    assert "wp-includes/functions.php" not in flagged, "a heuristic match on genuine vendor code is not a finding"
    tampered = _inventory(sess, tid, wid, vendor="tampered")
    assert set(tampered) == {"wp-admin/index.php", "wp-includes/class-wp-cache-helper.php",
                             "wp-content/plugins/hello-dolly/readme.txt"}

    # No YARA incident for the genuine core file; tampering incidents instead.
    assert not [i for i in _incidents("yara:") if "functions.php" in i.title]
    by_rule = {}
    for i in _incidents("wordpress_"):
        by_rule.setdefault(i.rule_key, []).append(i)
    assert [i.title for i in by_rule["wordpress_core_modified"]] == ["Modified WordPress core file: wp-admin/index.php"]
    planted = by_rule["wordpress_core_unexpected_file"][0]
    assert planted.severity == "high" and "wp-includes/class-wp-cache-helper.php" in planted.title
    assert by_rule["wordpress_plugin_modified"][0].severity == "medium"

    software = {s["slug"]: s for s in sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/software").json()["items"]}
    assert software["wordpress"]["version"] == "6.7.1" and software["wordpress"]["checksum_status"] == "modified"
    assert software["wordpress"]["files_modified"] == 1 and software["wordpress"]["files_unexpected"] == 1
    assert software["hello-dolly"]["name"] == "Hello Dolly" and software["hello-dolly"]["files_verified"] == 1

    # Next scan: lists come from the cache and the same findings are not raised again.
    calls, count = len(wporg.calls), len(_incidents())
    assert _scan(sess, tid, wid) == ["succeeded"]
    assert len(wporg.calls) == calls, "checksum lists are cached per release"
    assert len(_incidents()) == count
    with platform_session() as db:
        assert {r.status for r in db.execute(select(VendorChecksums)).scalars()} == {"ok"}

    # Changing a planted file again is a new observation.
    (wp_site / "wp-includes" / "class-wp-cache-helper.php").write_text("<?php echo 2222;\n")  # different size: seen by incremental scans
    assert _scan(sess, tid, wid) == ["succeeded"]
    planted_incs = _incidents("wordpress_core_unexpected_file")
    assert len(planted_incs) == 1 and planted_incs[0].occurrence_count == 2


def test_official_update_is_not_reported_as_suspicious_change(alice, sftp_server, wp_site, wporg):
    sess, tid = alice
    (wp_site / "wp-includes" / "functions.php").write_text("<?php // older release\n")
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]
    before = {i.id for i in _incidents()}
    # The site is updated: the file now matches the official release exactly.
    (wp_site / "wp-includes" / "functions.php").write_text(CORE_FILES["wp-includes/functions.php"])
    assert _scan(sess, tid, wid) == ["succeeded"]
    new = [i for i in _incidents() if i.id not in before]
    assert new == [], [i.title for i in new]


def test_wordpress_org_unreachable_never_breaks_the_scan(alice, sftp_server, wp_site, wporg):
    sess, tid = alice
    wporg.fail = True
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]
    inv = _inventory(sess, tid, wid)
    assert inv["wp-includes/functions.php"]["vendor_status"] is None, "not verified, not assumed genuine"
    assert [i for i in _incidents("yara:") if "functions.php" in i.title], "heuristics apply as before"
    software = {s["slug"]: s for s in sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/software").json()["items"]}
    assert software["wordpress"]["checksum_status"] == "unavailable"
    with platform_session() as db:
        assert {r.status for r in db.execute(select(VendorChecksums)).scalars()} == {"error"}


def test_disabled_verification_makes_no_requests(alice, sftp_server, wp_site, wporg, monkeypatch):
    sess, tid = alice
    monkeypatch.setattr(get_settings(), "vendor_checksums_enabled", False)
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]
    assert wporg.calls == []
    software = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/software").json()["items"]
    assert {s["slug"] for s in software} == {"wordpress", "hello-dolly"}, "versions are still detected"


def test_checksum_cache_payload_is_public_data_only():
    """The cache holds published release data and nothing about tenants."""
    cols = set(VendorChecksums.__table__.columns.keys())
    assert "tenant_id" not in cols and "website_id" not in cols
