"""cPanel reads must be byte-exact: cPanel rewrites HTML <meta charset> unless told not to, some servers ignore
the charset conversion, and anything that still does not match the listed size is not fingerprinted."""

from __future__ import annotations

import hashlib
import re

import httpx

from app.connectors.base import ConnectionParams, SecretMaterial
from app.core.http import set_transport_factory
from app.monitoring.inventory import walk_inventory
from tests.test_services import LIMITS, cpanel_env  # noqa: F401 - fixture
from tests.test_vendor import wp_site, wporg  # noqa: F401 - fixtures

HTML = b'<!DOCTYPE html>\n<html lang="en">\n<head>\n\t<meta name="viewport" content="width=device-width" />\n</head>\n'
UTF8 = "<?php // café ©\n".encode()


def _server(files: dict[str, bytes], *, rewrite_html=True, ignore_charset=False, truncate=None):
    def handler(request: httpx.Request) -> httpx.Response:
        q = dict(request.url.params)
        if request.url.path.endswith("/list_files"):
            d = q["dir"].strip("/")
            items = [{"file": p.split("/")[-1], "type": "file", "size": str(len(b)), "mtime": "1760000000"}
                     for p, b in files.items() if p.rsplit("/", 1)[0] == d]
            return httpx.Response(200, json={"status": 1, "data": items})
        p = f"{q['dir'].strip('/')}/{q['file']}"
        raw = files[p]
        if truncate == p:
            raw = raw[:-5]
        if rewrite_html and q.get("update_html_document_encoding", "1") != "0" and b"<head>" in raw:
            raw = re.sub(rb"<head>\s*", b'<head><meta charset="utf-8">', raw)  # what cPanel does by default
        converted = "from_charset" in q and not ignore_charset
        text = raw.decode("latin-1") if converted else raw.decode("utf-8")
        return httpx.Response(200, json={"status": 1, "data": {"content": text}})
    return httpx.MockTransport(handler)


def _walk(files, **kw):
    from app.connectors.cpanel import CPanelUAPIConnector

    set_transport_factory(lambda: _server(files, **kw))
    conn = CPanelUAPIConnector(ConnectionParams("cpanel_uapi", "server.acme-hosting.com", 2083, "acme", "/public_html"),
                               SecretMaterial("api_token", "T"))
    with conn.open_file_source("/public_html") as src:
        return walk_inventory(src, [], LIMITS)


def test_html_is_not_rewritten(cpanel_env):  # noqa: F811
    res = _walk({"public_html/readme.html": HTML})
    assert res.entries["readme.html"].sha256 == hashlib.sha256(HTML).hexdigest()


def test_server_that_ignores_the_charset_request_still_gives_exact_bytes(cpanel_env):  # noqa: F811
    res = _walk({"public_html/x.php": UTF8}, ignore_charset=True)
    assert res.entries["x.php"].sha256 == hashlib.sha256(UTF8).hexdigest()


def test_content_that_does_not_match_the_listed_size_is_not_fingerprinted(cpanel_env):  # noqa: F811
    res = _walk({"public_html/a.php": b"<?php echo 'genuine content';\n", "public_html/b.php": b"<?php ok;\n"},
                truncate="public_html/a.php")
    assert res.entries["a.php"].hash_status == "error" and res.entries["a.php"].sha256 is None
    assert any("not byte-exact" in e.message for e in res.errors)
    assert res.entries["b.php"].hash_status == "hashed"


def test_vendor_incident_resolves_when_the_file_is_genuine_again(alice, sftp_server, wp_site, wporg):  # noqa: F811
    import time

    from sqlalchemy import select

    from app.db.session import platform_session
    from app.models import Incident
    from tests.test_monitoring_flow import _connect, _scan, _website
    from tests.test_vendor import CORE_FILES

    sess, tid = alice
    target = wp_site / "wp-admin" / "index.php"
    target.write_text("<?php require_once __DIR__ . '/admin.php'; @include '/tmp/x';\n")
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    assert _scan(sess, tid, wid) == ["succeeded"]
    with platform_session() as db:
        inc = db.execute(select(Incident).where(Incident.rule_key == "wordpress_core_modified")).scalars().first()
        assert inc is not None and inc.status == "new"
        inc_id = inc.id
    time.sleep(1.1)  # a new modification time, as a real restore would have
    target.write_text(CORE_FILES["wp-admin/index.php"])
    assert _scan(sess, tid, wid) == ["succeeded"]
    with platform_session() as db:
        inc = db.get(Incident, inc_id)
        assert inc.status == "resolved" and "identical to the official release" in inc.resolution_notes
