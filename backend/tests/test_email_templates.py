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
    assert "Critical" in html and "#9f1239" in html, "severity banner"
    assert "INC-00042" in html and "Recommended action" in html
    assert 'href="https://cyberwatch.example.com/app/t/incidents/i"' in html and "View incident" in html
    assert "<script>" not in html and "<img src=x" not in html, "attacker-chosen file names are escaped"
    assert "&lt;script&gt;" in html
    assert '<a href="https://cyberwatch.example.com/help"' in html, "links in the action are clickable"
    assert "Demonstration data" not in html
    assert "Demonstration data" in render_html("s", "b", "incident_alert", _incident_params(demo=True))


def test_generic_email_uses_a_button_matching_the_link(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "public_base_url", "https://cyberwatch.example.com")
    html = render_html("Reset your password", "Reset it here: https://cyberwatch.example.com/reset-password?token=abc\n\nIgnore otherwise.")
    assert "Reset password</a>" in html and "Open CyberWatch" not in html
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
