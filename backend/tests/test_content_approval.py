"""Learning from false-positive reviews: closing an incident as a false positive can approve the exact file
content, so the same bytes at the same path stop alerting for that rule, while any change is checked again."""

from __future__ import annotations

from sqlalchemy import delete, select

from app.db.session import platform_session
from app.models import AuditEvent, Incident, MalwareVerdict, SuppressionRule
from tests.test_malware import CMD_SHELL
from tests.test_monitoring_flow import _connect, _scan, _website

LEGIT = "<?php // admin tool\n" + CMD_SHELL[len("<?php "):]  # trips the command-execution rule


def _malware_incidents():
    with platform_session() as db:
        return db.execute(select(Incident).where(Incident.category == "malware")
                          .order_by(Incident.first_detected_at)).scalars().all()


def _forget_verdicts():
    """Force fresh inspection, as happens after the weekly rescan window or a rule update."""
    with platform_session() as db:
        db.execute(delete(MalwareVerdict))
        db.commit()


def test_false_positive_close_approves_exact_content_only(alice, sftp_server, sftp_root):
    sess, tid = alice
    tool = sftp_root / "public_html" / "tool.php"
    tool.write_text(LEGIT)
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]
    [inc] = _malware_incidents()
    listed = sess.get(f"/api/v1/tenants/{tid}/incidents").json()["items"]
    assert listed[0]["content_approvable"] is True

    # Approval only makes sense with a false-positive close.
    r = sess.post(f"/api/v1/tenants/{tid}/incidents/{inc.id}/status",
                  json={"status": "closed", "note": "ok", "approve_content": True})
    assert r.status_code == 422, r.text
    r = sess.post(f"/api/v1/tenants/{tid}/incidents/{inc.id}/status",
                  json={"status": "closed", "note": "Our own admin tool, reviewed.", "false_positive": True,
                        "approve_content": True})
    assert r.status_code == 200, r.text
    events = [e["body"] or "" for e in r.json()["events"]]
    assert any("Approved this exact content of tool.php" in b for b in events)
    with platform_session() as db:
        rule = db.execute(select(SuppressionRule)).scalar_one()
        assert rule.content_sha256 and rule.path_glob == "tool.php" and str(rule.website_id) == wid
        assert db.execute(select(AuditEvent).where(AuditEvent.action == "suppression.content_approved")).first()

    # Same content inspected afresh: no new incident.
    _forget_verdicts()
    assert _scan(sess, tid, wid) == ["succeeded"]
    assert len(_malware_incidents()) == 1

    # Any change to the file is checked again.
    tool.write_text(LEGIT + "// edited\n")
    assert _scan(sess, tid, wid) == ["succeeded"]
    incs = _malware_incidents()
    assert len(incs) == 2 and incs[1].status == "new"


def test_approval_does_not_cover_the_same_content_elsewhere(alice, sftp_server, sftp_root):
    sess, tid = alice
    (sftp_root / "public_html" / "tool.php").write_text(LEGIT)
    acct = _connect(sess, tid, sftp_server)
    wid = _website(sess, tid, acct)
    assert _scan(sess, tid, wid) == ["succeeded"]
    [inc] = _malware_incidents()
    r = sess.post(f"/api/v1/tenants/{tid}/incidents/bulk-status",
                  json={"incident_ids": [str(inc.id)], "status": "closed", "note": "reviewed",
                        "false_positive": True, "approve_content": True})
    assert r.json()["content_approved"] == 1
    # The identical bytes copied to another path (e.g. into uploads) still alert.
    (sftp_root / "public_html" / "wp-content" / "uploads" / "tool.php").write_text(LEGIT)
    assert _scan(sess, tid, wid) == ["succeeded"]
    assert [i.title.endswith("wp-content/uploads/tool.php") for i in _malware_incidents()] == [False, True]


def test_cached_verdict_still_alerts_a_second_customer(alice, bob, sftp_server, sftp_root):
    """Verdicts are cached by content hash across all sites; a cache hit must not hide malware on a new site."""
    (sftp_root / "public_html" / "tool.php").write_text(LEGIT)
    for sess, tid in (alice, bob):
        acct = _connect(sess, tid, sftp_server)
        wid = _website(sess, tid, acct)
        assert _scan(sess, tid, wid) == ["succeeded"]
    assert sorted(str(i.tenant_id) for i in _malware_incidents()) == sorted([str(alice[1]), str(bob[1])])
