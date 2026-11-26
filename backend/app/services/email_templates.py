"""HTML versions of CyberWatch emails.

Every email is sent as multipart/alternative: the existing plain text (unchanged, always complete) plus this
HTML rendering. The HTML is built for email clients, not browsers: table layout, inline styles only, no external
images, scripts or web fonts (Gmail, Outlook and Apple Mail all render it; images are often blocked and hurt spam
scores). Text colours meet WCAG AA contrast on their backgrounds.

Layout (all emails): a dark header with the CyberWatch mark and a category label, a white card, and a footer.
Incident alerts get a severity badge, a headline, a tinted "security event" panel with the affected file or site
and key facts, the recommended action and a full-width button. Other emails (account, billing, reports, support,
audit anchors) show their text with links made clickable and the first CyberWatch link as the button.
"""

from __future__ import annotations

import html
import posixpath
import re
from datetime import datetime
from typing import Any

from app.core.config import get_settings

NAVY = "#0f1b33"
INK = "#0f172a"
TEXT = "#1f2937"
MUTED = "#5b6577"
LINE = "#e5e9f0"
PAGE = "#eef2f7"
BRAND = "#12a37a"
FONT = "font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"

# severity: (label, badge bg, badge text, panel bg, panel border, panel accent). Text/bg pairs >= 4.5:1.
SEVERITY = {
    "critical": ("Critical", "#fde7ec", "#9f1239", "#fff1f3", "#f9c9d4", "#9f1239"),
    "high": ("High", "#fde9e7", "#b42318", "#fff4f2", "#f6cfc8", "#b42318"),
    "medium": ("Medium", "#ffedd5", "#9a3412", "#fff6ec", "#fbdcb8", "#9a3412"),
    "low": ("Low", "#dcfce7", "#166534", "#f0fdf4", "#bbf7d0", "#166534"),
    "informational": ("Informational", "#e2e8f0", "#334155", "#f8fafc", "#e2e8f0", "#334155"),
}
CATEGORY_LABEL = {"security": "SECURITY", "account": "ACCOUNT", "billing": "BILLING", "support": "SUPPORT",
                  "report": "REPORT", "test": "TEST"}

_URL = re.compile(r"https?://[^\s<>\"')]+")


def _e(text: Any) -> str:
    return html.escape(str(text), quote=True)


def _linkify(escaped: str) -> str:
    return _URL.sub(lambda m: f'<a href="{m.group(0)}" style="color:#0f63db;text-decoration:underline;">{m.group(0)}</a>',
                    escaped)


def _paragraphs(text: str, size: int = 15, color: str = TEXT) -> str:
    out = []
    for block in re.split(r"\n\s*\n", (text or "").strip()):
        if not block:
            continue
        lines = "<br>".join(_linkify(_e(line)) for line in block.splitlines())
        out.append(f'<p style="margin:0 0 14px 0;{FONT}font-size:{size}px;line-height:1.6;color:{color};">{lines}</p>')
    return "".join(out)


def _button(url: str, label: str, sub: str | None = None) -> str:
    """Full-width dark button; the whole block is the link (works in Outlook, Gmail, Apple Mail)."""
    sub_html = (f'<span style="display:block;margin-top:4px;{FONT}font-size:13px;font-weight:400;color:#cbd5e1;">'
                f'{_e(sub)}</span>') if sub else ""
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:6px 0 18px 0;">'
            f'<tr><td align="center" style="background:{NAVY};border-radius:10px;">'
            f'<a href="{_e(url)}" style="display:block;padding:16px 20px;{FONT}font-size:16px;font-weight:700;'
            f'color:#ffffff;text-decoration:none;border-radius:10px;text-align:center;">{_e(label)}{sub_html}</a>'
            f'</td></tr></table>')


def _header(label: str) -> str:
    tag = (f'<span style="display:inline-block;padding:4px 10px;border-radius:999px;background:#12352a;{FONT}'
           f'font-size:11px;font-weight:700;letter-spacing:.08em;color:#4ade80;">{_e(label)}</span>') if label else ""
    return (
        f'<tr><td style="background:{NAVY};border-radius:14px 14px 0 0;padding:18px 22px;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td width="44" style="width:44px;vertical-align:middle;">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td width="40" height="40" align="center" style="width:40px;height:40px;background:{BRAND};border-radius:10px;'
        f'{FONT}font-size:20px;line-height:40px;color:#ffffff;font-weight:700;">&#10003;</td></tr></table></td>'
        f'<td style="vertical-align:middle;padding-left:12px;">'
        f'<div style="{FONT}font-size:18px;font-weight:700;color:#ffffff;line-height:1.2;">CyberWatch</div>'
        f'<div style="{FONT}font-size:11px;letter-spacing:.08em;color:#94a3b8;margin-top:2px;">BY TRUSTDATA</div></td>'
        f'<td align="right" style="vertical-align:middle;">{tag}</td>'
        f'</tr></table></td></tr>'
    )


def _footer() -> str:
    s = get_settings()
    base = s.public_base_url.rstrip("/")
    year = datetime.now().year
    return (
        f'<tr><td style="padding:22px 16px 8px 16px;text-align:center;">'
        f'<div style="{FONT}font-size:12px;font-weight:700;letter-spacing:.08em;color:#334155;">'
        f'{_e(s.product_name.upper())}</div>'
        f'<div style="{FONT}font-size:12px;color:{MUTED};margin-top:4px;">Website security monitoring and response</div>'
        f'<div style="{FONT}font-size:12px;line-height:1.6;color:{MUTED};margin-top:10px;">'
        f'This is an automated message from CyberWatch. Replies are not monitored: for help, use '
        f'<a href="{_e(base)}" style="color:{MUTED};text-decoration:underline;">Support in CyberWatch</a>.<br>'
        f'<a href="{_e(base)}" style="color:{MUTED};text-decoration:underline;">Manage notifications</a> &middot; '
        f'<a href="{_e(base)}/privacy" style="color:{MUTED};text-decoration:underline;">Privacy notice</a></div>'
        f'<div style="{FONT}font-size:11px;color:#7b8494;margin-top:10px;">&copy; {year} {_e(s.company_name)}</div>'
        f'</td></tr>'
    )


def _frame(subject: str, preheader: str, label: str, inner: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light only"><meta name="supported-color-schemes" content="light">
<title>{_e(subject)}</title></head>
<body style="margin:0;padding:0;background:{PAGE};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:{PAGE};">{_e(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{PAGE};">
<tr><td align="center" style="padding:24px 10px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;">
{_header(label)}
<tr><td style="background:#ffffff;border:1px solid {LINE};border-top:0;border-radius:0 0 14px 14px;padding:24px 22px 8px 22px;">
{inner}
</td></tr>
{_footer()}
</table></td></tr></table></body></html>"""


def _rows(pairs: list[tuple[str, Any]], line: str) -> str:
    out = []
    for i, (k, v) in enumerate(pairs):
        border = f"border-top:1px solid {line};" if i else ""
        out.append(
            f'<tr><td style="{border}padding:9px 0;{FONT}font-size:13px;color:{MUTED};vertical-align:top;">{_e(k)}</td>'
            f'<td align="right" style="{border}padding:9px 0 9px 12px;{FONT}font-size:14px;font-weight:600;color:{INK};'
            f'vertical-align:top;word-break:break-word;">{_e(v)}</td></tr>')
    return "".join(out)


def _incident(subject: str, p: dict[str, Any]) -> str:
    label, badge_bg, badge_fg, panel_bg, panel_line, accent = SEVERITY.get(
        str(p.get("severity_key", "")).lower(), SEVERITY["informational"])
    resource = str(p.get("resource") or "")
    is_file = p.get("resource_type") == "file" and resource
    name = posixpath.basename(resource) if is_file else (p.get("website") or p.get("website_full") or "")
    detail = ("/" + resource.lstrip("/")) if is_file else (p.get("website_full") or "")
    more = int(p.get("resource_count") or 0) - 1
    facts = [("Event", p.get("event") or p.get("category") or p.get("verb")),
             ("Website", p.get("website") or p.get("website_full")),
             ("Confidence", p.get("confidence")),
             ("Detected", p.get("detected")),
             ("Reference", p.get("reference"))]
    facts = [(k, v) for k, v in facts if v]
    demo = (f'<p style="margin:0 0 14px 0;padding:10px 12px;border-radius:8px;background:#fdf6e5;{FONT}font-size:13px;'
            f'color:#654606;"><strong>Demonstration data</strong>: not a real security event.</p>') if p.get("demo") else ""
    action = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 16px 0;">'
              f'<tr><td style="border-left:4px solid #0f63db;background:#eef4ff;border-radius:8px;padding:13px 16px;">'
              f'<div style="{FONT}font-size:11px;font-weight:700;letter-spacing:.06em;color:#0b4fb3;margin-bottom:4px;">'
              f'RECOMMENDED ACTION</div><div style="{FONT}font-size:14px;line-height:1.55;color:{TEXT};">'
              f'{_linkify(_e(p.get("action", "")))}</div></td></tr></table>') if p.get("action") else ""
    inner = (
        f'<span style="display:inline-block;padding:5px 11px;border-radius:999px;background:{badge_bg};{FONT}'
        f'font-size:11px;font-weight:700;letter-spacing:.06em;color:{badge_fg};">{_e(label.upper())} SEVERITY'
        f'{" &middot; " + _e(str(p.get("verb")).upper()) if p.get("verb") else ""}</span>'
        f'<h1 style="margin:14px 0 8px 0;{FONT}font-size:24px;line-height:1.3;font-weight:700;color:{INK};">'
        f'{_e(p.get("headline") or p.get("title_full") or p.get("title", ""))}</h1>'
        f'{demo}{_paragraphs(str(p.get("summary", "")), 15, "#475569")}'
        # Security event panel
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="margin:4px 0 18px 0;background:{panel_bg};border:1px solid {panel_line};border-radius:12px;">'
        f'<tr><td style="padding:16px 18px 6px 18px;">'
        f'<div style="{FONT}font-size:11px;font-weight:700;letter-spacing:.08em;color:{accent};">SECURITY EVENT</div>'
        f'<div style="{FONT}font-size:17px;font-weight:700;color:{INK};margin-top:8px;word-break:break-all;">{_e(name)}</div>'
        f'<div style="{FONT}font-size:12px;color:{MUTED};margin-top:4px;word-break:break-all;">{_e(detail)}'
        f'{f" and {more} more" if more > 0 else ""}</div>'
        f'<div style="height:1px;background:{panel_line};margin:14px 0 4px 0;line-height:1px;font-size:1px;">&nbsp;</div>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{_rows(facts, panel_line)}</table>'
        f'</td></tr></table>'
        f'{action}'
        f'{_button(str(p["link"]), "Review security alert", "View the full details in your CyberWatch dashboard") if p.get("link") else ""}'
        f'<p style="margin:0 0 16px 0;{FONT}font-size:12px;line-height:1.55;color:{MUTED};">If this change was '
        f'authorised, review it and approve it in CyberWatch. Do not approve changes until they have been verified. '
        f'Findings come from automated monitoring and may need human verification; monitoring never changes files '
        f'on your server.</p>'
    )
    return _frame(subject, str(p.get("summary", ""))[:140], "SECURITY", inner)


_LABELS = (("/verify-email", "Verify email address"), ("/reset-password", "Reset password"),
           ("/invite", "Accept invitation"), ("/billing", "Open billing"), ("/incidents/", "View incident"),
           ("/support/", "View your request"), ("/service-desk/", "Open the request"))


def _button_label(url: str) -> str:
    return next((label for part, label in _LABELS if part in url), "Open CyberWatch")


def _generic(subject: str, body: str, category: str | None) -> str:
    base = get_settings().public_base_url.rstrip("/")
    links = [u for u in _URL.findall(body) if u.startswith(base)]
    button = _button(links[0], _button_label(links[0])) if links else ""
    inner = (f'<h1 style="margin:0 0 14px 0;{FONT}font-size:22px;line-height:1.3;font-weight:700;color:{INK};">{_e(subject)}</h1>'
             f'{_paragraphs(body)}{button}')
    return _frame(subject, body.strip().split("\n")[0][:140], CATEGORY_LABEL.get(category or "", ""), inner)


def render_html(subject: str, body: str, template: str = "generic", params: dict[str, Any] | None = None,
                category: str | None = None) -> str:
    params = params or {}
    if template == "incident_alert" and params.get("severity_key"):
        return _incident(subject, params)
    return _generic(subject, body, category)
