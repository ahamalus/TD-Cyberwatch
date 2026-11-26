"""YARA rule self-test: rules are run over official release archives; a rule matching genuine vendor code
is quarantined (its matches are ignored), administrators are alerted, and a rules change ends it."""

from __future__ import annotations

import io
import socket
import zipfile

import httpx
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.http import set_transport_factory
from app.db.base import utcnow
from app.db.session import platform_session
from app.models import RuleSelftest, SoftwareInstall
from app.monitoring import malware
from app.monitoring.selftest import quarantined_rules, run_selftest
from tests.test_malware import CMD_SHELL, WEBSHELL
from tests.test_services import _site

RULE = "php_request_input_to_command_execution"


def _zip(top: str, files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, content in files.items():
            zf.writestr(f"{top}/{path}", content)
    return buf.getvalue()


RELEASES = {
    "/release/wordpress-6.7.1.zip": _zip("wordpress", {
        "index.php": "<?php require __DIR__ . '/wp-blog-header.php';",
        "wp-includes/legacy.php": CMD_SHELL,  # genuine code that a rule wrongly matches
    }),
    "/plugin/hello-dolly.1.7.2.zip": _zip("hello-dolly", {"hello.php": "<?php echo 'Hello';"}),
}


@pytest.fixture
def downloads(monkeypatch):
    calls: list[str] = []
    real = socket.getaddrinfo

    def resolve(host, port, *a, **k):
        if host == "downloads.wordpress.org":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.143.164.252", port))]
        return real(host, port, *a, **k)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        body = RELEASES.get(request.url.path)
        return httpx.Response(200, content=body) if body else httpx.Response(404)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(get_settings(), "vendor_checksums_enabled", True)
    set_transport_factory(lambda: httpx.MockTransport(handler))
    yield calls
    set_transport_factory(None)


def _installs(tid, wid, *items):
    with platform_session() as db:
        for product, slug, version in items:
            db.add(SoftwareInstall(tenant_id=tid, website_id=wid, product=product, slug=slug, root="", version=version,
                                   first_seen_at=utcnow(), last_seen_at=utcnow()))
        db.commit()


def test_misfiring_rule_is_quarantined_and_reported(alice, downloads):
    from app import cli
    from app.services.health import system_health

    _, tid = alice
    wid = _site(tid)
    _installs(tid, wid, ("wordpress-core", "wordpress", "6.7.1"), ("wordpress-plugin", "hello-dolly", "1.7.2"))

    with platform_session() as db:
        stats = run_selftest(db)
    assert stats["tested"] == 2 and stats["misfires"] == 1 and stats["quarantined_rules"] == [RULE]
    with platform_session() as db:
        rows = {r.slug: r for r in db.execute(select(RuleSelftest)).scalars()}
        assert rows["hello-dolly"].status == "ok" and rows["hello-dolly"].files_checked == 1
        assert rows["wordpress"].status == "misfire"
        assert rows["wordpress"].matches[0]["path"] == "wp-includes/legacy.php"

        # Administrators see it in System Health and the health check fails.
        health = system_health(db)
        assert any(RULE in a["message"] and "quarantined" in a["message"] for a in health["alerts"])
        assert health["malware_scanner"]["quarantined_rules"][0]["rule"] == RULE
        ok, _, detail = cli._selftest_health(db)
        assert not ok and "wp-includes/legacy.php" in detail

        # The quarantined rule no longer produces findings; other rules still do.
        inspector = malware.ContentInspector(db)
        v = inspector.inspect("x.php", "a" * 64, CMD_SHELL.encode())
        assert v.status != malware.SUSPICIOUS and v.signatures == []
        assert inspector.inspect("y.php", "b" * 64, WEBSHELL.encode()).status == malware.SUSPICIOUS
        assert inspector.summary()["quarantined_rules"] == [RULE]

    # Tested releases are not downloaded again for the same rule set.
    before = len(downloads)
    with platform_session() as db:
        assert run_selftest(db)["already_tested"] == 2
    assert len(downloads) == before


def test_rules_change_ends_the_quarantine(alice, downloads, monkeypatch):
    _, tid = alice
    _installs(tid, _site(tid), ("wordpress-core", "wordpress", "6.7.1"))
    with platform_session() as db:
        run_selftest(db)
        _, version, _ = malware.yara_rules()
        assert quarantined_rules(db, version)
        assert quarantined_rules(db, "a-new-rules-version") == {}, "quarantine is tied to the rule-set version"


def test_unavailable_release_is_recorded_and_retried(alice, downloads):
    _, tid = alice
    _installs(tid, _site(tid), ("wordpress-plugin", "premium-thing", "2.0"))
    with platform_session() as db:
        stats = run_selftest(db)
        assert stats["errors"] == 1 and stats["quarantined_rules"] == []
        assert run_selftest(db)["already_tested"] == 0, "errors are retried on the next run"
