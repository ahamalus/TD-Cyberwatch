"""HTML versions of CyberWatch emails.

Every email is sent as multipart/alternative: the existing plain text (unchanged, always complete) plus this
HTML rendering. The HTML is built for email clients, not browsers: table layout, inline styles only, no
external images, scripts or web fonts (Gmail, Outlook and Apple Mail all render it; images are often blocked
and hurt spam scores). Colours meet WCAG AA contrast.

Incident alerts get a structured card from the notification's params; other emails (account, billing,
reports, audit anchors) get the same frame around their text, with links made clickable and the first
CyberWatch link shown as a button.
"""

from __future__ import annotations

import html
import re
from typing import Any

from app.core.config import get_settings

NAVY = "#0b1220"
TEXT = "#1f2937"
MUTED = "#5f6b7a"
LINE = "#e2e8f0"
PAGE = "#f5f7fb"
BLUE = "#0f63db"

# Severity: (banner background, banner text, label). White on each background is >= 4.5:1.
SEVERITY = {
    "critical": ("#9f1239", "#ffffff", "Critical"),
    "high": ("#b42318", "#ffffff", "High"),
    "medium": ("#8c620b", "#ffffff", "Medium"),
    "low": ("#0b6c4b", "#ffffff", "Low"),
    "informational": ("#46597d", "#ffffff", "Informational"),
}

_URL = re.compile(r"https?://[^\s<>\"')]+")
FONT = "font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"


def _e(text: Any) -> str:
    return html.escape(str(text), quote=True)


def _linkify(escaped: str) -> str:
    return _URL.sub(lambda m: f'<a href="{m.group(0)}" style="color:{BLUE};text-decoration:underline;">{m.group(0)}</a>',
                    escaped)


def _paragraphs(text: str) -> str:
    out = []
    for block in re.split(r"\n\s*\n", text.strip()):
        lines = "<br>".join(_linkify(_e(line)) for line in block.splitlines())
        out.append(f'<p style="margin:0 0 14px 0;{FONT}font-size:15px;line-height:1.55;color:{TEXT};">{lines}</p>')
    return "".join(out)


def _button(url: str, label: str) -> str:
    return (f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:8px 0 18px 0;"><tr>'
            f'<td style="border-radius:8px;background:{BLUE};">'
            f'<a href="{_e(url)}" style="display:inline-block;padding:12px 22px;{FONT}font-size:15px;font-weight:600;'
            f'color:#ffffff;text-decoration:none;border-radius:8px;">{_e(label)}</a></td></tr></table>')


def _frame(subject: str, preheader: str, inner: str) -> str:
    s = get_settings()
    year_company = _e(s.company_name)
    base = s.public_base_url.rstrip("/")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light only"><title>{_e(subject)}</title></head>
<body style="margin:0;padding:0;background:{PAGE};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:{PAGE};">{_e(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{PAGE};">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;">
<tr><td style="padding:0 4px 14px 4px;{FONT}font-size:17px;font-weight:700;color:{NAVY};">
<span style="display:inline-block;width:22px;height:22px;line-height:22px;text-align:center;border-radius:6px;background:{BLUE};color:#ffffff;font-size:13px;margin-right:8px;vertical-align:middle;">&#10003;</span><span style="vertical-align:middle;"><span style="color:{BLUE};">TrustData</span> CyberWatch</span>
</td></tr>
<tr><td style="background:#ffffff;border:1px solid {LINE};border-radius:12px;overflow:hidden;">{inner}</td></tr>
<tr><td style="padding:16px 8px;{FONT}font-size:12px;line-height:1.5;color:{MUTED};text-align:center;">
{_e(s.product_name)} &middot; {year_company}<br>
You receive this email because of your CyberWatch account or alert settings.
<a href="{_e(base)}" style="color:{MUTED};text-decoration:underline;">Manage notifications</a>
&middot; <a href="{_e(base)}/privacy" style="color:{MUTED};text-decoration:underline;">Privacy notice</a>
</td></tr>
</table></td></tr></table></body></html>"""


def _incident(subject: str, p: dict[str, Any]) -> str:
    bg, fg, label = SEVERITY.get(str(p.get("severity_key", "")).lower(), SEVERITY["informational"])
    rows = "".join(
        f'<tr><td style="padding:7px 0;{FONT}font-size:13px;color:{MUTED};width:120px;vertical-align:top;">{_e(k)}</td>'
        f'<td style="padding:7px 0;{FONT}font-size:14px;color:{TEXT};vertical-align:top;">{_e(v)}</td></tr>'
        for k, v in (("Reference", p.get("reference")), ("Website", p.get("website_full") or p.get("website")),
                     ("Category", p.get("category")), ("Detected", p.get("detected")),
                     ("Organisation", p.get("tenant")))
        if v
    )
    demo = (f'<p style="margin:0 0 14px 0;padding:10px 12px;border-radius:8px;background:#fdf6e5;{FONT}font-size:13px;'
            f'color:#654606;"><strong>Demonstration data</strong>: not a real security event.</p>') if p.get("demo") else ""
    action = (f'<div style="margin:4px 0 18px 0;padding:14px 16px;border-left:4px solid {BLUE};background:#eaf2ff;'
              f'border-radius:6px;"><div style="{FONT}font-size:12px;font-weight:700;letter-spacing:.04em;'
              f'text-transform:uppercase;color:#0b50b3;margin-bottom:4px;">Recommended action</div>'
              f'<div style="{FONT}font-size:14px;line-height:1.5;color:{TEXT};">{_linkify(_e(p.get("action", "")))}</div></div>'
              ) if p.get("action") else ""
    inner = (
        f'<div style="background:{bg};padding:14px 24px;{FONT}">'
        f'<span style="display:inline-block;padding:3px 10px;border-radius:999px;background:rgba(255,255,255,.18);'
        f'color:{fg};font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;">{_e(label)}</span>'
        f'<span style="color:{fg};font-size:13px;margin-left:8px;">{_e(p.get("verb", "Incident"))}</span></div>'
        f'<div style="padding:22px 24px 8px 24px;">'
        f'<h1 style="margin:0 0 16px 0;{FONT}font-size:20px;line-height:1.3;color:{NAVY};">{_e(p.get("title_full") or p.get("title", ""))}</h1>'
        f'{demo}{_paragraphs(str(p.get("summary", "")))}'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="border-top:1px solid {LINE};border-bottom:1px solid {LINE};margin:4px 0 18px 0;">{rows}</table>'
        f'{action}'
        f'{_button(str(p["link"]), "View incident") if p.get("link") else ""}'
        f'<p style="margin:0 0 18px 0;{FONT}font-size:12px;line-height:1.5;color:{MUTED};">Findings come from automated '
        f'monitoring and may need human verification. CyberWatch never changes files on your server.</p></div>'
    )
    return _frame(subject, str(p.get("summary", ""))[:140], inner)


_LABELS = (("/verify-email", "Verify email address"), ("/reset-password", "Reset password"),
           ("/invite", "Accept invitation"), ("/billing", "Open billing"), ("/incidents/", "View incident"))


def _button_label(url: str) -> str:
    return next((label for part, label in _LABELS if part in url), "Open CyberWatch")


def _generic(subject: str, body: str) -> str:
    base = get_settings().public_base_url.rstrip("/")
    links = [u for u in _URL.findall(body) if u.startswith(base)]
    button = _button(links[0], _button_label(links[0])) if links else ""
    inner = (f'<div style="padding:24px 24px 8px 24px;">'
             f'<h1 style="margin:0 0 16px 0;{FONT}font-size:20px;line-height:1.3;color:{NAVY};">{_e(subject)}</h1>'
             f'{_paragraphs(body)}{button}</div>')
    return _frame(subject, body.strip().split("\n")[0][:140], inner)


def render_html(subject: str, body: str, template: str = "generic", params: dict[str, Any] | None = None) -> str:
    params = params or {}
    if template == "incident_alert" and params.get("severity_key"):
        return _incident(subject, params)
    return _generic(subject, body)
