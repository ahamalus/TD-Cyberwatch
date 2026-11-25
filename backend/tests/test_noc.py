"""NOC wall and staff management: a read-only NOC Monitor role, live status of every website and
connection across organisations, and disabling / re-inviting staff."""

from __future__ import annotations

from datetime import timedelta

from app.db.base import utcnow
from app.db.session import platform_session
from app.models import AvailabilityCheck, Incident, Website
from tests.test_security import _make_site, _staff


def _set(wid, **fields):
    with platform_session() as db:
        w = db.get(Website, wid)
        for k, v in fields.items():
            setattr(w, k, v)
        db.commit()


def test_noc_wall_shows_every_site_worst_first_without_customer_detail(alice, bob):
    a, atid = alice
    b, btid = bob
    up = _make_site(a, atid)
    down = _make_site(b, btid)
    _set(up, last_availability_status="up", last_availability_at=utcnow(), last_tls_status="valid",
         tls_expires_at=utcnow() + timedelta(days=60))
    _set(down, last_availability_status="down", consecutive_availability_failures=5, last_availability_at=utcnow())
    with platform_session() as db:
        for i, outcome in enumerate(["up", "up", "up", "down"]):
            db.add(AvailabilityCheck(tenant_id=atid, website_id=up, outcome=outcome, response_ms=200 + i,
                                     http_status=200, checked_at=utcnow() - timedelta(minutes=10 * (4 - i))))
        db.add(Incident(tenant_id=atid, website_id=up, reference="INC-T1", title="secret title", summary="secret",
                        category="malware", finding_class="suspected_compromise", severity="critical",
                        confidence="high", status="new", detection_source="test", rule_key="t",
                        dedupe_key="t1", first_detected_at=utcnow(), last_observed_at=utcnow()))
        db.commit()

    noc = _staff("noc@trustdata.example.com", ["noc_monitor"])
    r = noc.get("/api/v1/ops/noc")
    assert r.status_code == 200, r.text
    data = r.json()
    sites = {s["id"]: s for s in data["websites"]}
    assert set(sites) >= {str(up), str(down)}, "sites from every organisation"
    assert data["websites"][0]["id"] == str(down) and sites[str(down)]["state"] == "down"
    assert "5 failed check(s)" in sites[str(down)]["reasons"][0]
    s_up = sites[str(up)]
    assert s_up["state"] == "alert" and s_up["open_incidents"]["critical"] == 1
    assert s_up["availability"]["uptime_24h"] == 75.0 and s_up["availability"]["response_ms"] == 203
    assert s_up["tls"]["days_left"] in (59, 60)
    assert data["summary"]["down"] >= 1 and data["open_incidents"]["critical"] >= 1
    assert "secret" not in r.text, "incident content is not on the wall"

    # Read-only: the monitor cannot act on jobs, incidents or staff, and has no customer access.
    assert noc.get("/api/v1/ops/jobs").status_code == 200
    assert noc.get("/api/v1/admin/staff").status_code == 403
    assert noc.get(f"/api/v1/tenants/{atid}/websites").status_code == 404
    # Staff without operations access cannot see the wall.
    assert _staff("billing@trustdata.example.com", ["billing_admin"]).get("/api/v1/ops/noc").status_code == 403
    assert a.get("/api/v1/ops/noc").status_code in (403, 404)


def test_admin_disables_reenables_and_reinvites_staff():
    admin = _staff("root@trustdata.example.com", ["platform_admin"])
    r = admin.post("/api/v1/admin/staff", json={"email": "watcher@trustdata.example.com", "full_name": "Watcher",
                                                 "roles": ["noc_monitor"]})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert admin.post(f"/api/v1/admin/staff/{sid}/resend-invite").status_code == 200

    me = next(s for s in admin.get("/api/v1/admin/staff").json() if s["email"] == "root@trustdata.example.com")
    assert admin.put(f"/api/v1/admin/staff/{me['id']}/status", json={"is_active": False}).status_code == 422

    assert admin.put(f"/api/v1/admin/staff/{sid}/status", json={"is_active": False}).json()["is_active"] is False
    assert admin.post(f"/api/v1/admin/staff/{sid}/resend-invite").status_code == 422
    row = next(s for s in admin.get("/api/v1/admin/staff").json() if s["id"] == sid)
    assert row["is_active"] is False
    assert admin.put(f"/api/v1/admin/staff/{sid}/status", json={"is_active": True}).json()["is_active"] is True


def test_disabled_staff_is_signed_out_immediately():
    admin = _staff("root2@trustdata.example.com", ["platform_admin"])
    victim = _staff("leaver@trustdata.example.com", ["noc_monitor"])
    assert victim.get("/api/v1/ops/noc").status_code == 200
    sid = next(s["id"] for s in admin.get("/api/v1/admin/staff").json() if s["email"] == "leaver@trustdata.example.com")
    assert admin.put(f"/api/v1/admin/staff/{sid}/status", json={"is_active": False}).status_code == 200
    assert victim.get("/api/v1/ops/noc").status_code == 401
