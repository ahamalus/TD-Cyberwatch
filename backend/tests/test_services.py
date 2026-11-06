"""Unit and integration tests for services: inventory, rules, notifications,
entitlements, audit chain, cPanel connector, scheduler, billing renewals."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, text

from app.connectors.base import ConnectionParams, ConnectorError, FileSource, RemoteEntry, SecretMaterial
from app.core.config import get_settings
from app.core.http import set_transport_factory
from app.db.base import utcnow
from app.db.session import platform_session, tenant_session
from app.models import Notification, Plan, ScanJob, Subscription, Website
from app.monitoring.inventory import ScanLimits, diff_inventories, matches_any, walk_inventory
from app.monitoring.rules import classify_change
from app.services import audit
from tests.conftest import register_and_login

LIMITS = ScanLimits(max_file_bytes=1000, max_total_bytes=10_000, max_files=100, max_seconds=60, max_depth=10)


class DictSource(FileSource):
    """In-memory file source: {'dir/': None, 'dir/file': b'content'}."""

    def __init__(self, files: dict[str, bytes], fail_dirs: set[str] | None = None):
        super().__init__("/")
        self.files = files
        self.fail_dirs = fail_dirs or set()

    def list_dir(self, rel_path: str) -> list[RemoteEntry]:
        rel = "" if rel_path == "." else rel_path
        if rel_path in self.fail_dirs:
            raise ConnectorError("permission_denied", "denied")
        children: dict[str, RemoteEntry] = {}
        for p, data in self.files.items():
            if rel and not p.startswith(rel + "/"):
                continue
            rest = p[len(rel) + 1:] if rel else p
            name = rest.split("/")[0]
            if "/" in rest:
                children[name] = RemoteEntry(name, "dir", None, None, 0o755)
            else:
                children[name] = RemoteEntry(name, "file", len(data), datetime(2026, 1, 1, tzinfo=UTC), 0o644)
        return list(children.values())

    def read_chunks(self, rel_path: str, chunk_size: int = 65536):
        yield self.files[rel_path]


def _prev(result):
    from app.monitoring.inventory import PrevEntry

    return {p: PrevEntry(e.entry_type, e.size, e.mtime, e.sha256, e.hash_status, e.symlink_target, e.mode)
            for p, e in result.entries.items()}


def test_inventory_limits_are_enforced():
    files = {f"f{i}.txt": b"x" * 10 for i in range(5)}
    files["big.bin"] = b"y" * 5000
    r = walk_inventory(DictSource(files), [], LIMITS)
    assert r.entries["big.bin"].hash_status == "skipped_size"
    assert r.files_hashed == 5
    r2 = walk_inventory(DictSource(files), [], ScanLimits(1000, 10_000, 3, 60, 10))
    assert "file_count" in r2.limits_hit and r2.status == "partial"


def test_file_count_limit_does_not_create_deletions():
    files = {f"a/f{i}.txt": b"x" for i in range(5)} | {"b/g.txt": b"y"}
    full = walk_inventory(DictSource(files), [], LIMITS)
    limited = walk_inventory(DictSource(files), [], ScanLimits(1000, 10_000, 2, 60, 10))
    diff = diff_inventories(_prev(full), limited, [])
    assert not [c for c in diff.changes if c.change_type == "deleted"]
    assert diff.unverified_missing


def test_exclusions_and_newly_excluded_not_deleted():
    files = {"a.php": b"1", "cache/x.tmp": b"2", "logs/e.log": b"3"}
    r1 = walk_inventory(DictSource(files), [], LIMITS)
    r2 = walk_inventory(DictSource(files), ["cache/**", "**/*.log"], LIMITS)
    assert "cache/x.tmp" not in r2.entries and "logs/e.log" not in r2.entries
    diff = diff_inventories(_prev(r1), r2, ["cache/**", "**/*.log"])
    assert not [c for c in diff.changes if c.change_type == "deleted" and c.path != "cache" and c.path != "logs"]
    assert matches_any("wp-content/uploads/a.php", ["**/uploads/**"])


def test_first_observed_under_previously_failed_dir_is_not_added():
    files = {"a/x.php": b"1", "b/y.php": b"2"}
    r1 = walk_inventory(DictSource(files, fail_dirs={"a"}), [], LIMITS)
    assert r1.status == "partial"
    r2 = walk_inventory(DictSource(files), [], LIMITS)
    diff = diff_inventories(_prev(r1), r2, [])
    assert [c.path for c in diff.changes] == []
    assert "a/x.php" in diff.first_observed


@pytest.mark.parametrize("path,flag,sev", [
    ("wp-content/uploads/2026/x.php", "script_in_upload_dir", "high"),
    ("c99.php", "suspicious_filename", "high"),
    ("img.php.jpg", "double_extension", "high"),
    (".cache.php", "hidden_script", "medium"),
    (".htaccess", "server_config_changed", "medium"),
    ("index.php", "script_changed", "medium"),
    ("readme.txt", "file_changed", "low"),
])
def test_rules(path, flag, sev):
    from app.monitoring.inventory import Change, EntryRecord

    c = Change(path, "added", "file", None, EntryRecord(path, "file", 1, None, 0o644, "a" * 64, "hashed"))
    classify_change(c, [])
    assert flag in c.flags and c.severity == sev


def test_critical_path_raises_severity():
    from app.monitoring.inventory import Change, EntryRecord

    c = Change("config/settings.json", "modified", "file", None, EntryRecord("config/settings.json", "file"))
    classify_change(c, ["config/**"])
    assert "critical_path" in c.flags and c.severity == "high"


# ---------------------------------------------------------------- audit


def test_audit_chain_detects_tampering():
    with platform_session() as db:
        for i in range(5):
            audit.record(db, f"test.event{i}", details={"i": i})
        db.commit()
        assert audit.verify_chain(db).valid
        # Append-only trigger blocks modification through SQL...
        with pytest.raises(Exception):
            db.execute(text("UPDATE audit_events SET action='x'"))
        db.rollback()
        # ...and if bypassed (e.g. trigger disabled by a superuser), verification fails.
        db.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
        db.execute(text("UPDATE audit_events SET details='{\"i\": 99}' WHERE action='test.event2'"))
        db.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only"))
        db.commit()
        res = audit.verify_chain(db)
        assert not res.valid and res.reason


# ---------------------------------------------------------------- notifications


def _incident(tid, wid, severity="high"):
    from app.services.incidents import DetectionSpec, raise_detection

    with tenant_session(tid) as db:
        inc, _ = raise_detection(db, DetectionSpec(
            tenant_id=tid, website_id=wid, title="Test incident", summary="Summary", category="file_integrity",
            finding_class="integrity_anomaly", severity=severity, confidence="high", detection_source="test",
            rule_key="t", dedupe_key=f"t:{uuid.uuid4()}", recommended_action="Act"))
        db.commit()
        return inc.id


def _site(tid):
    with tenant_session(tid) as db:
        w = Website(tenant_id=tid, name="S", url="https://s.example.com/", hostname="s.example.com")
        db.add(w)
        db.commit()
        return w.id


def test_notification_routing_by_severity_and_role(alice):
    s, tid = alice
    wid = _site(tid)
    r = s.post(f"/api/v1/tenants/{tid}/alert-policies", json={
        "name": "Critical to owners", "min_severity": "high", "channels": ["email", "whatsapp"],
        "recipients": [{"role_key": "owner"}, {"email": "soc@alpha.example.com"},
                       {"whatsapp_number": "+2348012345678", "whatsapp_consent": True}]})
    assert r.status_code == 201, r.text
    _incident(tid, wid, "medium")
    incident_only = select(Notification).where(Notification.incident_id.is_not(None))
    with platform_session() as db:
        assert db.execute(incident_only).first() is None  # below threshold
    _incident(tid, wid, "high")
    with platform_session() as db:
        rows = db.execute(incident_only).scalars().all()
        targets = {(n.channel, n.recipient, n.status) for n in rows}
    assert ("email", "alice@alpha.example.com", "pending") in targets
    assert ("email", "soc@alpha.example.com", "pending") in targets
    assert ("whatsapp", "+2348012345678", "pending") in targets  # Business plan trial includes WhatsApp
    for n in rows:
        assert "secret" not in n.body.lower()


def test_whatsapp_requires_consent(alice):
    s, tid = alice
    r = s.post(f"/api/v1/tenants/{tid}/alert-policies", json={
        "name": "x", "channels": ["whatsapp"], "recipients": [{"whatsapp_number": "+2348012345678"}]})
    assert r.status_code == 422


def test_dispatch_retries_with_backoff_and_falls_back(alice, monkeypatch):
    from app.services import notifications as ns

    s, tid = alice
    s.patch("/api/v1/auth/me", json={"phone": "+2348099999999", "whatsapp_opt_in": True})
    wid = _site(tid)
    s.post(f"/api/v1/tenants/{tid}/alert-policies", json={
        "name": "WA", "min_severity": "low", "channels": ["whatsapp"], "email_fallback": True,
        "recipients": [{"role_key": "owner"}]})
    calls = {"wa": 0, "email": 0}

    def wa_fail(*a, **k):
        calls["wa"] += 1
        raise ns.DeliveryError("WhatsApp API error HTTP 503.")

    def email_ok(*a, **k):
        calls["email"] += 1
        return "<msg@id>"

    monkeypatch.setattr(ns, "send_whatsapp_template", wa_fail)
    monkeypatch.setattr(ns, "send_email", email_ok)
    _incident(tid, wid)
    with platform_session() as db:
        ns.dispatch_due(db)
        n = db.execute(select(Notification).where(Notification.channel == "whatsapp")).scalar_one()
        assert n.status == "pending" and n.attempts == 1 and n.next_attempt_at > utcnow()
        # Exhaust retries
        for _ in range(10):
            n.next_attempt_at = utcnow() - timedelta(seconds=1)
            db.commit()
            ns.dispatch_due(db)
            db.refresh(n)
            if n.status != "pending":
                break
        assert n.status == "failed" and n.attempts == n.max_attempts
        ns.dispatch_due(db)
        fb = db.execute(select(Notification).where(Notification.idempotency_key.like("fallback:%"))).scalar_one()
        assert fb.status == "sent" and fb.idempotency_key.startswith("fallback:")
    assert calls["wa"] == 5 and calls["email"] >= 1


def test_unconfigured_channel_is_reported_not_faked(alice, monkeypatch):
    from app.services import notifications as ns

    s, tid = alice
    monkeypatch.setattr(get_settings(), "smtp_host", None)
    r = s.post(f"/api/v1/tenants/{tid}/notifications/test", json={"channel": "email"})
    assert r.status_code == 202
    with platform_session() as db:
        ns.dispatch_due(db)
        n = db.execute(select(Notification).where(Notification.category == "test")).scalar_one()
        assert n.status == "unconfigured" and n.sent_at is None


def test_notification_idempotent_on_repeat_routing(alice):
    from app.models import Incident
    from app.services.notifications import route_incident

    s, tid = alice
    wid = _site(tid)
    s.post(f"/api/v1/tenants/{tid}/alert-policies", json={"name": "p", "min_severity": "low",
                                                          "recipients": [{"role_key": "owner"}]})
    iid = _incident(tid, wid)
    with tenant_session(tid) as db:
        inc = db.get(Incident, iid)
        route_incident(db, inc, "incident_opened")  # simulated job retry
        route_incident(db, inc, "incident_opened")
        db.commit()
    with platform_session() as db:
        assert len(db.execute(select(Notification).where(Notification.incident_id == iid)).scalars().all()) == 1


def test_quiet_hours_defer_non_critical():
    from app.services.notifications import _in_quiet_hours

    now = datetime(2026, 10, 19, 23, 30, tzinfo=UTC)  # 00:30 Lagos
    end = _in_quiet_hours({"start": "22:00", "end": "07:00", "timezone": "Africa/Lagos"}, now)
    assert end is not None and end > now
    assert _in_quiet_hours({"start": "22:00", "end": "07:00", "timezone": "Africa/Lagos"},
                           datetime(2026, 10, 19, 12, 0, tzinfo=UTC)) is None


# ---------------------------------------------------------------- entitlements


def test_plan_limits_enforced_in_backend(alice):
    s, tid = alice
    with platform_session() as db:
        starter = db.execute(select(Plan).where(Plan.key == "starter")).scalar_one()
        sub = db.execute(select(Subscription).where(Subscription.tenant_id == tid)).scalar_one()
        sub.plan_id = starter.id  # 3 websites
        db.commit()
    for i in range(3):
        assert s.post(f"/api/v1/tenants/{tid}/websites", json={"name": f"s{i}", "url": f"https://s{i}.example.com/"}).status_code == 201
    r = s.post(f"/api/v1/tenants/{tid}/websites", json={"name": "s4", "url": "https://s4.example.com/"})
    assert r.status_code == 402 and r.json()["error"]["code"] == "plan_limit_exceeded"
    # Interval below plan minimum
    wid = s.get(f"/api/v1/tenants/{tid}/websites").json()["items"][0]["id"]
    r = s.put(f"/api/v1/tenants/{tid}/websites/{wid}/monitoring", json={"availability_enabled": True,
                                                                        "availability_interval_minutes": 1})
    assert r.status_code == 402


def test_expired_trial_restricts_new_resources(alice):
    s, tid = alice
    with platform_session() as db:
        sub = db.execute(select(Subscription).where(Subscription.tenant_id == tid)).scalar_one()
        sub.trial_ends_at = utcnow() - timedelta(days=1)
        db.commit()
    r = s.post(f"/api/v1/tenants/{tid}/websites", json={"name": "s", "url": "https://s.example.com/"})
    assert r.status_code == 402
    assert s.get(f"/api/v1/tenants/{tid}").json()["plan"]["in_service"] is False


def test_duplicate_website_detected(alice):
    s, tid = alice
    assert s.post(f"/api/v1/tenants/{tid}/websites", json={"name": "a", "url": "https://dup.example.com"}).status_code == 201
    r = s.post(f"/api/v1/tenants/{tid}/websites", json={"name": "b", "url": "https://DUP.example.com/"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "duplicate_website"


# ---------------------------------------------------------------- cPanel connector (mocked UAPI)


def _cpanel_transport(files: dict[str, bytes], token="TOKEN123", seen=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if request.headers.get("authorization") != f"cpanel acme:{token}":
            return httpx.Response(401, text="Access denied")
        q = dict(request.url.params)
        if request.url.path.endswith("/Fileman/list_files"):
            d = q["dir"].strip("/")
            items = []
            names = set()
            for p, data in files.items():
                if not p.startswith(d + "/"):
                    continue
                rest = p[len(d) + 1:]
                name = rest.split("/")[0]
                if name in names:
                    continue
                names.add(name)
                is_dir = "/" in rest
                items.append({"file": name, "fullpath": f"/home/acme/{d}/{name}", "type": "dir" if is_dir else "file",
                              "size": str(len(data)), "mtime": "1760000000", "nicemode": "0644"})
            return httpx.Response(200, json={"status": 1, "errors": None, "data": items, "metadata": {}})
        if request.url.path.endswith("/Fileman/get_file_content"):
            p = f"{q['dir'].strip('/')}/{q['file']}"
            content = files[p].decode("latin-1")
            return httpx.Response(200, json={"status": 1, "data": {"content": content}, "errors": None})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


@pytest.fixture
def cpanel_env(monkeypatch):
    import socket

    real = socket.getaddrinfo

    def fake(host, port, *a, **k):
        if host == "server.acme-hosting.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return real(host, port, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    yield
    set_transport_factory(None)


def test_cpanel_connector_listing_hashing_and_binary(cpanel_env):
    import hashlib

    from app.connectors.cpanel import CPanelUAPIConnector

    binary = bytes(range(256))
    files = {"public_html/index.php": b"<?php echo 1;", "public_html/img/a.bin": binary,
             "public_html/.htaccess": b"Deny from all"}
    seen: list = []
    set_transport_factory(lambda: _cpanel_transport(files, seen=seen))
    conn = CPanelUAPIConnector(ConnectionParams("cpanel_uapi", "server.acme-hosting.com", 2083, "acme",
                                                "/public_html"), SecretMaterial("api_token", "TOKEN123"))
    assert conn.test_connection().ok
    caps = {c.capability.value: c.status for c in conn.discover_capabilities()}
    assert caps["file_listing"] == "available" and caps["file_hashing"] == "available"
    with conn.open_file_source("/public_html") as src:
        res = walk_inventory(src, [], LIMITS)
    assert res.entries["img/a.bin"].sha256 == hashlib.sha256(binary).hexdigest()
    assert ".htaccess" in res.entries
    # Requests went to the pinned IP with the real Host header; only read functions used.
    assert all(r.url.host == "93.184.216.34" and r.headers["host"].startswith("server.acme-hosting.com") for r in seen)
    assert {r.url.path.rsplit("/", 1)[-1] for r in seen} <= {"list_files", "get_file_content"}


def test_cpanel_bad_token(cpanel_env):
    from app.connectors.cpanel import CPanelUAPIConnector

    set_transport_factory(lambda: _cpanel_transport({}, token="OTHER"))
    conn = CPanelUAPIConnector(ConnectionParams("cpanel_uapi", "server.acme-hosting.com", 2083, "acme", "/public_html"),
                               SecretMaterial("api_token", "TOKEN123"))
    res = conn.test_connection()
    assert not res.ok and res.error_code == "auth_failed"


# ---------------------------------------------------------------- availability / TLS


def test_availability_check_with_mock_http(monkeypatch):
    import socket

    from app.monitoring.availability import check_availability

    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))])
    responses = iter([httpx.Response(301, headers={"location": "https://www.example.com/home"}),
                      httpx.Response(200, text="ok")])
    set_transport_factory(lambda: httpx.MockTransport(lambda r: next(responses)))
    try:
        res = check_availability("https://example.com/")
    finally:
        set_transport_factory(None)
    assert res.outcome == "up" and res.redirects == 1 and res.final_url == "https://www.example.com/home"


def test_redirect_to_internal_address_blocked(monkeypatch):
    import socket

    from app.monitoring.availability import check_availability

    monkeypatch.setattr(get_settings(), "outbound_allow_cidrs", [])
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))])
    set_transport_factory(lambda: httpx.MockTransport(
        lambda r: httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})))
    try:
        res = check_availability("https://example.com/")
    finally:
        set_transport_factory(None)
    assert res.outcome == "error" and res.error_class == "target_not_allowed"


def test_tls_check_against_local_server(tmp_path, monkeypatch):
    """Real TLS handshake against a local server with a self-signed, expiring cert."""
    import socket
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from app.monitoring.availability import check_tls

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls.example.com")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=80)).not_valid_after(now + timedelta(days=5))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("tls.example.com")]), False)
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(2):
            try:
                conn, _ = srv.accept()
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (OSError, ssl.SSLError):
                continue

    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setattr(get_settings(), "allowed_http_ports", [port])
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p))] if h == "tls.example.com" else real(h, p, *a, **k))
    res = check_tls(f"https://tls.example.com:{port}/")
    srv.close()
    # Self-signed => invalid (verification failed) but expiry details still read.
    assert res.outcome == "invalid"
    assert res.days_remaining in (4, 5)
    assert "tls.example.com" in res.san


# ---------------------------------------------------------------- scheduler & jobs


def test_scheduler_enqueues_due_checks_and_respects_maintenance(alice):
    from app.models import MonitoringConfig
    from app.monitoring import jobs

    s, tid = alice
    wid = s.post(f"/api/v1/tenants/{tid}/websites", json={"name": "s", "url": "https://s.example.com/"}).json()["id"]
    s.put(f"/api/v1/tenants/{tid}/websites/{wid}/monitoring", json={"availability_enabled": True,
                                                                    "availability_interval_minutes": 15})
    stats = jobs.schedule_due()
    assert stats["availability"] == 1 and stats["tls"] == 1
    # Running again immediately does not duplicate (not due + active-job uniqueness).
    assert jobs.schedule_due()["availability"] == 0
    with platform_session() as db:
        cfg = db.execute(select(MonitoringConfig)).scalar_one()
        cfg.next_availability_at = utcnow() - timedelta(minutes=1)
        cfg.maintenance_windows = [{"start": "00:00", "end": "23:59", "weekday": None, "timezone": "UTC"}]
        db.commit()
    assert jobs.schedule_due()["skipped_maintenance"] == 1


def test_stale_job_recovery():
    from app.monitoring import jobs

    s, tid = register_and_login("stale@x.example.com", "Stale")
    wid = _site(tid)
    with platform_session() as db:
        job = ScanJob(tenant_id=tid, website_id=wid, job_type="availability", status="running", attempts=1,
                      max_attempts=3, started_at=utcnow() - timedelta(hours=2),
                      heartbeat_at=utcnow() - timedelta(hours=2))
        dead = ScanJob(tenant_id=tid, website_id=wid, job_type="tls", status="running", attempts=3,
                       max_attempts=3, heartbeat_at=utcnow() - timedelta(hours=2))
        db.add_all([job, dead])
        db.commit()
        jid, did = job.id, dead.id
    stats = jobs.recover_stale_jobs()
    assert stats["requeued"] == 1 and stats["failed"] == 1
    with platform_session() as db:
        assert db.get(ScanJob, jid).status == "queued"
        d = db.get(ScanJob, did)
        assert d.status == "failed" and d.error_class == "worker_lost"


def test_tenant_concurrency_limit_defers(alice, monkeypatch):
    from app.monitoring import jobs

    s, tid = alice
    monkeypatch.setattr(get_settings(), "tenant_max_concurrent_jobs", 1)
    w1, w2 = _site(tid), None
    with tenant_session(tid) as db:
        w = Website(tenant_id=tid, name="S2", url="https://s2.example.com/", hostname="s2.example.com")
        db.add(w)
        db.commit()
        w2 = w.id
    with platform_session() as db:
        db.add(ScanJob(tenant_id=tid, website_id=w1, job_type="availability", status="running", heartbeat_at=utcnow()))
        q = ScanJob(tenant_id=tid, website_id=w2, job_type="availability", status="queued")
        db.add(q)
        db.commit()
        qid = q.id
    assert jobs.claim(qid, "w") is None
    with platform_session() as db:
        assert db.get(ScanJob, qid).not_before is not None


def test_failed_job_is_never_marked_succeeded(alice, monkeypatch):
    from app.monitoring import jobs

    s, tid = alice
    wid = _site(tid)

    def boom(db, job, beat):
        raise RuntimeError("unexpected")

    monkeypatch.setitem(jobs.HANDLERS, "availability", boom)
    with platform_session() as db:
        j = ScanJob(tenant_id=tid, website_id=wid, job_type="availability", status="queued", max_attempts=1)
        db.add(j)
        db.commit()
        jid = j.id
    assert jobs.run_job(jid) == "failed"
    with platform_session() as db:
        assert db.get(ScanJob, jid).status == "failed"


# ---------------------------------------------------------------- billing maintenance


def test_trial_expiry_and_renewal_failure_grace(alice, monkeypatch):
    from pydantic import SecretStr

    from app.services import billing

    s, tid = alice
    with platform_session() as db:
        sub = db.execute(select(Subscription).where(Subscription.tenant_id == tid)).scalar_one()
        sub.trial_ends_at = utcnow() - timedelta(minutes=1)
        db.commit()
        stats = billing.run_subscription_maintenance(db)
        db.commit()
        assert stats["trials_expired"] == 1
        # Active subscription past period end with a failing saved card -> grace period.
        sub.status, sub.current_period_end = "active", utcnow() - timedelta(minutes=1)
        from app.core.crypto import CredentialVault, get_vault

        blob = get_vault().encrypt(b"AUTH_x", CredentialVault.associated_data(sub.tenant_id, sub.id, "paystack_auth"))
        sub.auth_key_id, sub.auth_nonce, sub.auth_ciphertext = blob.key_id, blob.nonce, blob.ciphertext
        db.commit()

    class Failing:
        def charge_authorization(self, **kw):
            return billing.VerifiedTransaction("failed", kw["reference"], kw["amount"], "NGN", None, "card",
                                               "Insufficient Funds", None, None, {})

    monkeypatch.setattr(get_settings(), "paystack_secret_key", SecretStr("sk_test_x"))
    billing.set_client(Failing())
    try:
        with platform_session() as db:
            stats = billing.run_subscription_maintenance(db)
            db.commit()
            sub = db.execute(select(Subscription).where(Subscription.tenant_id == tid)).scalar_one()
            assert stats["renewal_failed"] == 1 and sub.status == "grace_period" and sub.grace_until
            # Same day: no second charge attempt.
            assert billing.run_subscription_maintenance(db)["renewal_failed"] == 0
            # Grace expires -> expired, service restricted, data retained.
            sub.grace_until = utcnow() - timedelta(minutes=1)
            db.commit()
            billing.run_subscription_maintenance(db)
            db.commit()
            assert db.execute(select(Subscription).where(Subscription.tenant_id == tid)).scalar_one().status == "expired"
    finally:
        billing.set_client(None)
    assert s.get(f"/api/v1/tenants/{tid}").json()["plan"]["in_service"] is False


# ---------------------------------------------------------------- reports


def test_pdf_and_csv_reports(alice):
    s, tid = alice
    _site(tid)
    for fmt in ("csv", "pdf"):
        r = s.post(f"/api/v1/tenants/{tid}/reports", json={"report_type": "coverage", "format": fmt})
        assert r.status_code == 201 and r.json()["status"] == "ready", r.text
        d = s.get(f"/api/v1/tenants/{tid}/reports/{r.json()['id']}/download")
        assert d.status_code == 200
        import hashlib

        assert hashlib.sha256(d.content).hexdigest() == r.json()["content_sha256"]
        if fmt == "pdf":
            assert d.content.startswith(b"%PDF")
        else:
            assert b"cannot guarantee" in d.content


def test_csv_formula_injection_neutralised():
    from app.services.reports import _csv_safe

    assert _csv_safe("=HYPERLINK(1)").startswith("'")
    assert _csv_safe("+cmd").startswith("'")


def test_dashboard_reflects_real_data(alice):
    s, tid = alice
    d = s.get(f"/api/v1/tenants/{tid}/dashboard").json()
    assert d["websites"]["total"] == 0 and d["incidents"]["open_total"] == 0
    assert d["last_successful_scan_at"] is None and d["is_demo"] is False
    _incident(tid, _site(tid), "critical")
    d = s.get(f"/api/v1/tenants/{tid}/dashboard").json()
    assert d["incidents"]["open_by_severity"]["critical"] == 1 and d["websites"]["total"] == 1


def test_demo_data_refused_in_production(monkeypatch):
    from app.core.config import Settings

    assert Settings(environment="production").is_synthetic_data_allowed is False
    assert Settings(environment="demo").is_synthetic_data_allowed is True

