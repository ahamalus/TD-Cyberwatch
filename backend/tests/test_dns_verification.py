"""Website ownership by DNS TXT record: instructions, the exact record required, www/bare domain, and DNS
failures reported without verifying."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.session import platform_session
from app.models import AuditEvent
from app.services import dns_verify
from tests.test_security import _make_site


@pytest.fixture
def dns_records():
    records: dict[str, list[str]] = {}

    def lookup(name: str) -> list[str]:
        if name == "_cyberwatch.broken.example":
            raise OSError("DNS lookup failed (Timeout)")
        if name not in records:
            raise LookupError(name)
        return records[name]

    dns_verify.set_lookup(lookup)
    yield records
    dns_verify.set_lookup(None)


def test_dns_txt_record_proves_ownership(alice, dns_records):
    sess, tid = alice
    wid = _make_site(sess, tid, url="https://www.alpha-site.com/")
    info = sess.get(f"/api/v1/tenants/{tid}/websites/{wid}/verification").json()
    assert info["dns_name"] == "_cyberwatch.www.alpha-site.com"
    assert info["dns_value"] == f"cyberwatch-verification={info['token']}"

    def verify():
        return sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/verify", json={"method": "dns_txt"}).json()

    r = verify()
    assert r["status"] != "verified" and "No TXT record" in r["message"]
    dns_records["_cyberwatch.alpha-site.com"] = ["some-other-service=abc"]
    r = verify()
    assert r["status"] != "verified" and "does not contain" in r["message"]
    # The bare domain is accepted for a www site; other TXT values may sit alongside.
    dns_records["_cyberwatch.alpha-site.com"] = ["some-other-service=abc", f'"{info["dns_value"]}"']
    r = verify()
    assert r["status"] == "verified" and r["method"] == "dns_txt"
    assert sess.get(f"/api/v1/tenants/{tid}/websites/{wid}").json()["verification_status"] == "verified"
    with platform_session() as db:
        events = db.execute(select(AuditEvent).where(AuditEvent.action == "website.verification_attempt")).scalars().all()
    assert [e.details["method"] for e in events] == ["dns_txt"] * 3


def test_dns_failure_is_reported_not_verified(alice, dns_records):
    sess, tid = alice
    wid = _make_site(sess, tid, url="https://broken.example/")
    r = sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/verify", json={"method": "dns_txt"}).json()
    assert r["status"] != "verified" and "Timeout" in r["message"]


def test_another_sites_token_does_not_verify(alice, bob, dns_records):
    a, atid = alice
    b, btid = bob
    awid = _make_site(a, atid, url="https://shared.example/")
    bwid = _make_site(b, btid, url="https://shared.example/")
    a_token = a.get(f"/api/v1/tenants/{atid}/websites/{awid}/verification").json()["dns_value"]
    dns_records["_cyberwatch.shared.example"] = [a_token]
    assert b.post(f"/api/v1/tenants/{btid}/websites/{bwid}/verify", json={"method": "dns_txt"}).json()["status"] != "verified"
    assert a.post(f"/api/v1/tenants/{atid}/websites/{awid}/verify", json={"method": "dns_txt"}).json()["status"] == "verified"


def test_unknown_method_rejected(alice):
    sess, tid = alice
    wid = _make_site(sess, tid)
    assert sess.post(f"/api/v1/tenants/{tid}/websites/{wid}/verify", json={"method": "carrier_pigeon"}).status_code == 422
