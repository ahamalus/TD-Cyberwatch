"""HTML email rendering: multipart structure, incident card, contextual buttons, and escaping of
attacker-controlled text (file names end up in incident titles)."""

from __future__ import annotations

from app.services.email_templates import render_html
from tests.test_services import _FakeSMTP, fake_smtp  # noqa: F401 - fixture

EVIL = 'cache.php<script>alert(1)</script><img src=x onerror=alert(2)>"'


def _incident_params(**extra):
    return {"severity_key": "critical", "verb": "New incident", "title_full": f"Malware detected: wp-content/uploads/{EVIL}",
            "reference": "INC-00042", "website_full": "Shop (https://shop.example.com/)", "category": "Malware",
            "detected": "22 Nov 2026, 13:05 UTC", "tenant": "Acme Ltd", "summary": f"Path: {EVIL}.",
            "action": "Remove the file. See https://cyberwatch.example.com/help", "link": "https://cyberwatch.example.com/app/t/incidents/i",
            **extra}


def test_incident_email_is_a_structured_card_with_escaped_content():
    html = render_html("[Critical] New incident", "plain text", "incident_alert", _incident_params())
    assert "CRITICAL SEVERITY" in html and "#9f1239" in html, "severity badge"
    assert "INC-00042" in html and "RECOMMENDED ACTION" in html and "SECURITY EVENT" in html
    assert 'href="https://cyberwatch.example.com/app/t/incidents/i"' in html and "Review security alert" in html
    assert "<script>" not in html and "<img src=x" not in html, "attacker-chosen file names are escaped"
    assert "&lt;script&gt;" in html
    assert '<a href="https://cyberwatch.example.com/help"' in html, "links in the action are clickable"
    assert "Demonstration data" not in html
    assert "Demonstration data" in render_html("s", "b", "incident_alert", _incident_params(demo=True))


def test_incident_email_shows_the_affected_file_and_facts():
    html = render_html("s", "b", "incident_alert", _incident_params(
        severity_key="medium", resource="wp-content/advanced-headers-test.php", resource_type="file", resource_count=3,
        event="Suspicious file modified", confidence="High", headline="File change detected"))
    assert "MEDIUM SEVERITY" in html and "#9a3412" in html
    assert ">advanced-headers-test.php<" in html and "/wp-content/advanced-headers-test.php and 2 more" in html
    assert "File change detected" in html and "Suspicious file modified" in html and ">High<" in html
    assert "CyberWatch" in html and "BY TRUSTDATA" in html and ">SECURITY<" in html


def test_real_incident_renders_with_its_file(alice):
    import uuid

    from app.db.base import utcnow
    from app.db.session import platform_session
    from app.models import Incident, Tenant
    from app.services.notifications import render_incident

    _, tid = alice
    with platform_session() as db:
        inc = Incident(tenant_id=tid, reference="INC-1", title="Suspicious file modified: wp-content/x.php",
                       summary="s", category="suspicious_file", finding_class="heuristic_suspicion", severity="high",
                       confidence="medium", status="new", detection_source="t", rule_key="r", dedupe_key=uuid.uuid4().hex,
                       affected_resources=[{"type": "file", "path": "wp-content/x.php"}], requires_human_verification=True,
                       first_detected_at=utcnow(), last_observed_at=utcnow())
        _, _, params = render_incident(inc, None, db.get(Tenant, tid), "incident_opened")
    html = render_html("s", "b", "incident_alert", params)
    assert ">x.php<" in html and "Suspicious file detected" in html and "Suspicious file modified" in html
    assert "Medium (needs verification)" in html


def test_generic_email_uses_a_button_matching_the_link(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "public_base_url", "https://cyberwatch.example.com")
    html = render_html("Reset your password", "Reset it here: https://cyberwatch.example.com/reset-password?token=abc\n\nIgnore otherwise.")
    assert "Reset password</a>" in html and "Open CyberWatch" not in html
    assert ">ACCOUNT<" in render_html("Reset", "x", category="account")
    other = render_html("Hello", "See https://evil.example.net/login for details")
    assert "evil.example.net" in other and "Open CyberWatch" not in other, "no button for links outside CyberWatch"


def test_emails_are_sent_as_text_plus_html(fake_smtp):  # noqa: F811
    from app.services.notifications import send_email

    send_email("owner@customer.example.com", "Subject", "Plain body", render_html("Subject", "Plain body"))
    msg = _FakeSMTP.instances[-1].sent
    assert msg.get_content_type() == "multipart/alternative"
    parts = [p.get_content_type() for p in msg.iter_parts()]
    assert parts == ["text/plain", "text/html"], "plain text first: the complete fallback"
    assert "Plain body" in msg.get_body(("plain",)).get_content()
