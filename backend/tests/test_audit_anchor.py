"""Off-server audit anchors: a rewritten audit history no longer matches anchors published earlier."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select, text

from app.core.config import get_settings
from app.db.session import platform_session
from app.models import AuditEvent, Notification
from app.services import audit, audit_anchor
from tests.conftest import OWNER_URL


def _events(n: int, prefix: str = "test.event") -> None:
    with platform_session() as db:
        for i in range(n):
            audit.record(db, f"{prefix}{i}", details={"i": i})
        db.commit()


def _rewrite_history_as_owner() -> None:
    """What an attacker with full database access could do: change an event and recompute the whole chain."""
    owner = create_engine(OWNER_URL)
    with owner.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
        conn.execute(text("UPDATE audit_events SET details='{\"i\": 99}' WHERE action='test.event1'"))
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only"))
    owner.dispose()
    with platform_session() as db:
        prev = audit.GENESIS
        rows = db.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars().all()
        fixes = []
        for e in rows:
            h = audit.compute_hash(prev, audit._event_payload(e))
            fixes.append((e.seq, prev, h))
            prev = h
    owner = create_engine(OWNER_URL)
    with owner.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
        for seq, p, h in fixes:
            conn.execute(text("UPDATE audit_events SET prev_hash=:p, hash=:h WHERE seq=:s"), {"p": p, "h": h, "s": seq})
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only"))
    owner.dispose()


def test_rewritten_history_passes_the_chain_check_but_fails_anchors():
    _events(3)
    with platform_session() as db:
        old_anchor = audit_anchor.make_anchor(db)
        db.commit()
    _events(2, "later.event")
    _rewrite_history_as_owner()
    with platform_session() as db:
        assert audit.verify_chain(db).valid, "a full rewrite is internally consistent: why anchors are needed"
        [check] = audit_anchor.verify_anchors(db, f"Subject: anchor\n\n{old_anchor}\n")
        assert not check.ok and "different hash" in check.reason


def test_anchor_matches_untouched_history_and_tolerates_surrounding_text():
    _events(2)
    with platform_session() as db:
        a1 = audit_anchor.make_anchor(db)
        db.commit()
    _events(2, "more.")
    with platform_session() as db:
        a2 = audit_anchor.make_anchor(db)
        db.commit()
        checks = audit_anchor.verify_anchors(db, f"> {a1}\nsome mail quoting\n{a2}\n{a2}")
        assert audit_anchor.last_anchor_age_hours(db) < 1
    assert [c.ok for c in checks] == [True, True], "duplicates counted once"


def test_daily_publish_emails_anchor_and_reports_a_broken_chain(monkeypatch):
    monkeypatch.setattr(get_settings(), "audit_anchor_emails", ["audit@external.example.com"])
    _events(2)
    with platform_session() as db:
        result = audit_anchor.publish(db)
        db.commit()
    assert result["status"] == "published"
    with platform_session() as db:
        mail = db.execute(select(Notification).where(Notification.recipient == "audit@external.example.com")).scalar_one()
        assert result["anchor"] in mail.body
    owner = create_engine(OWNER_URL)
    with owner.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
        conn.execute(text("UPDATE audit_events SET action='tampered' WHERE action='test.event0'"))
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only"))
    owner.dispose()
    with platform_session() as db:
        assert audit_anchor.publish(db)["status"] == "chain_broken"
        db.commit()
        alert = db.execute(select(Notification).where(Notification.subject.like("%audit trail verification failed"))).scalar_one()
        assert alert.recipient == "audit@external.example.com"


def test_cli_verify_with_anchor_file(tmp_path, capsys):
    from app import cli

    _events(2)
    with platform_session() as db:
        line = audit_anchor.make_anchor(db)
        db.commit()
    good = tmp_path / "anchors.txt"
    good.write_text(line + "\n")
    cli.cmd_verify_audit(str(good))
    assert "anchors checked: 1, failed: 0" in capsys.readouterr().out
    bad = tmp_path / "bad.txt"
    bad.write_text(line.replace(line.split("hash=")[1][:8], "deadbeef") + "\n")
    with pytest.raises(SystemExit):
        cli.cmd_verify_audit(str(bad))
