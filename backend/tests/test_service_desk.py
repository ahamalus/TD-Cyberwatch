"""Service desk: customers request cleanup and other services; staff work a cross-organisation queue with SLA
targets, checklists, notes, time and a report. Staff see a site's data only through the access grant created
when the customer authorises the work, and lose it when the request closes."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.db.base import utcnow
from app.db.session import platform_session
from app.models import Incident, ManagedServiceGrant, Notification
from app.services import service_desk
from tests.test_security import _make_site, _staff


def _incident(tid, wid) -> str:
    with platform_session() as db:
        i = Incident(tenant_id=tid, website_id=uuid.UUID(wid), reference=f"INC-{uuid.uuid4().hex[:5]}",
                     title="Web shell in uploads", category="malware", finding_class="confirmed_malware",
                     severity="critical", confidence="high", status="new", detection_source="test", rule_key="t",
                     dedupe_key=uuid.uuid4().hex, first_detected_at=utcnow(), last_observed_at=utcnow())
        db.add(i)
        db.commit()
        return str(i.id)


def _request(sess, tid, wid, inc, **kw):
    body = {"subject": "Please clean up our hacked site", "category": "malware_cleanup", "priority": "urgent",
            "body": "Google flagged the site; there is a web shell.", "website_id": wid, "incident_ids": [inc]} | kw
    r = sess.post(f"/api/v1/tenants/{tid}/tickets", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_full_cleanup_lifecycle(alice):
    sess, tid = alice
    wid = _make_site(sess, tid)
    inc = _incident(tid, wid)
    summary = sess.get(f"/api/v1/tenants/{tid}/service-desk").json()
    assert summary["support_level"] == "standard" and summary["tasks_per_month"] == 0
    t = _request(sess, tid, wid, inc)
    assert t["reference"].startswith("SUP-") and t["is_service_request"] and t["incident_ids"] == [inc]
    assert t["billing_status"] == "quote", "standard plans include no service requests: priced separately"
    assert len(t["checklist"]) == 9 and t["sla"]["response"] == "on_track"
    agent = _staff("desk@trustdata.example.com", ["support_agent"])
    q = agent.get("/api/v1/ops/service-desk").json()
    row = next(r for r in q["items"] if r["id"] == t["id"])
    assert row["tenant"] and q["counts"]["unassigned"] >= 1 and row["priority"] == "urgent"

    # Before authorisation, being assigned gives no access to the site's data.
    assert agent.post(f"/api/v1/ops/service-desk/{t['id']}/assign", json={}).status_code == 200
    assert agent.get(f"/api/v1/tenants/{tid}/websites").status_code == 404
    detail = agent.get(f"/api/v1/ops/service-desk/{t['id']}").json()
    assert detail["status"] == "in_progress" and detail["grant"] is None
    assert detail["incidents"][0]["severity"] == "critical" and "title" not in detail["incidents"][0]

    # Staff cannot authorise on the customer's behalf; the customer does.
    r = sess.post(f"/api/v1/tenants/{tid}/tickets/{t['id']}/remediation-approval",
                  json={"scope": "Remove malware and restore genuine files on the main site.", "confirm": True})
    assert r.status_code == 200 and r.json()["access_granted"]
    detail = agent.get(f"/api/v1/ops/service-desk/{t['id']}").json()
    assert detail["grant"]["status"] == "active"
    assert agent.get(f"/api/v1/tenants/{tid}/websites").status_code == 200, "engineer can now see the site"
    assert agent.get(f"/api/v1/tenants/{tid}/incidents/{inc}").status_code == 200

    # Reply (customer sees it, first response recorded) and an internal note (customer does not).
    agent.post(f"/api/v1/ops/service-desk/{t['id']}/messages", json={"body": "Starting the cleanup now."})
    agent.post(f"/api/v1/ops/service-desk/{t['id']}/messages", json={"body": "Entry point: old revslider", "internal": True})
    agent.post(f"/api/v1/ops/service-desk/{t['id']}/time", json={"minutes": 45, "note": "triage"})
    agent.post(f"/api/v1/ops/service-desk/{t['id']}/checklist", json={"key": "c1", "done": True})
    mine = sess.get(f"/api/v1/tenants/{tid}/tickets/{t['id']}").json()
    bodies = [m["body"] for m in mine["messages"]]
    assert "Starting the cleanup now." in bodies and not any("revslider" in b for b in bodies)
    assert mine["sla"]["response"] == "met" and mine["checklist"][0]["done"] and mine["time_spent_minutes"] == 45
    with platform_session() as db:
        assert db.execute(select(Notification).where(Notification.recipient == "alice@alpha.example.com",
                                                     Notification.subject.like("%New reply%"))).first()

    # Resolving needs a report; then the customer closes and access ends.
    assert agent.post(f"/api/v1/ops/service-desk/{t['id']}/status", json={"status": "resolved"}).status_code == 422
    agent.put(f"/api/v1/ops/service-desk/{t['id']}/report", json={
        "findings": "Web shell uploaded through an outdated slider plugin.", "actions_taken": "Removed 3 files; updated plugin.",
        "recommendations": "Enable MFA for WordPress admins.", "verification": "Full rescan clean."})
    assert agent.post(f"/api/v1/ops/service-desk/{t['id']}/status", json={"status": "resolved"}).status_code == 200
    mine = sess.get(f"/api/v1/tenants/{tid}/tickets/{t['id']}").json()
    assert mine["status"] == "resolved" and mine["report"]["actions_taken"].startswith("Removed")
    assert sess.post(f"/api/v1/tenants/{tid}/tickets/{t['id']}/close").json()["status"] == "closed"
    with platform_session() as db:
        assert db.get(ManagedServiceGrant, uuid.UUID(detail["grant"]["id"])).status == "revoked"
    assert agent.get(f"/api/v1/tenants/{tid}/websites").status_code == 404, "access ends with the request"


def test_requests_cannot_reference_another_organisations_data(alice, bob):
    a, atid = alice
    b, btid = bob
    awid = _make_site(a, atid)
    inc = _incident(atid, awid)
    r = b.post(f"/api/v1/tenants/{btid}/tickets", json={"subject": "Help please", "category": "fix_site",
                                                        "body": "x", "incident_ids": [inc]})
    assert r.status_code == 422
    r = b.post(f"/api/v1/tenants/{btid}/tickets", json={"subject": "Help please", "category": "fix_site",
                                                        "body": "x", "website_id": awid})
    assert r.status_code == 422


def test_plan_allowance_and_sla_scale_with_support_level(alice, monkeypatch):
    sess, tid = alice
    terms = {"support_level": "priority", "plan": "Professional", "response_hours": 8.0, "resolution_hours": 72.0,
             "tasks_per_month": 2}
    monkeypatch.setattr(service_desk, "plan_terms", lambda db, t: terms)
    wid = _make_site(sess, tid)
    inc = _incident(tid, wid)
    first = _request(sess, tid, wid, inc, priority="high")
    second = _request(sess, tid, wid, inc, category="maintenance", priority="normal")
    third = _request(sess, tid, wid, inc, category="performance", priority="low")
    general = _request(sess, tid, wid, inc, category="general")
    assert [first["billing_status"], second["billing_status"], third["billing_status"]] == ["included", "included", "quote"]
    assert general["billing_status"] == "included" and general["checklist"] == []
    from datetime import datetime

    created = datetime.fromisoformat(first["created_at"])
    due = datetime.fromisoformat(first["sla"]["response_due"])
    assert 3.9 <= (due - created).total_seconds() / 3600 <= 4.1, "high = half of the 8 h response target"
    s = sess.get(f"/api/v1/tenants/{tid}/service-desk").json()
    assert s["used_this_month"] == 2 and s["remaining_this_month"] == 0


def test_queue_requires_the_service_desk_role(alice):
    assert _staff("noc9@trustdata.example.com", ["noc_monitor"]).get("/api/v1/ops/service-desk").status_code == 403
    assert _staff("bill9@trustdata.example.com", ["billing_admin"]).get("/api/v1/ops/service-desk").status_code == 403
    a, _ = alice
    assert a.get("/api/v1/ops/service-desk").status_code in (403, 404)


def test_customer_can_withdraw_an_unanswered_request(alice):
    sess, tid = alice
    wid = _make_site(sess, tid)
    t = _request(sess, tid, wid, _incident(tid, wid), category="migration")
    assert sess.post(f"/api/v1/tenants/{tid}/tickets/{t['id']}/close").json()["status"] == "cancelled"
    assert sess.post(f"/api/v1/tenants/{tid}/tickets/{t['id']}/messages", json={"body": "x"}).status_code == 422
