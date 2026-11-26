"""Entry-point investigation: how did the attacker get in?

For a website with malicious or unexpected files, this builds the evidence an engineer needs:

1. **Pivot files**: files flagged by the malware scan, files that should not exist (not part of the WordPress
   release, scripts in upload folders) and files named in the request's incidents, each with the time it appeared:
   its own modification time, unless that is later than when CyberWatch first saw it (then the sighting).
   Attackers can fake modification times, so both are shown.
2. **Requests around that time**: the site's access logs (the live log and the archives in ``~/logs``) are
   searched from ``WINDOW_BEFORE`` before to ``WINDOW_AFTER`` after each file appeared, for the requests that
   usually explain a break-in: POST requests, plugin and theme scripts, login, XML-RPC, the REST API,
   ``admin-ajax.php``, plugin/theme upload and editor pages, scripts in uploads.
3. **Who used the file**: every request to the file's URL; the addresses that used it are the attacker's.
4. **What those addresses did**: each attacker address's first appearance and first requests, which often show
   the way in.
5. **Software**: the site's WordPress and plugin versions against the latest release (wordpress.org) and, when
   ``CW_WORDFENCE_API_KEY`` is set, against the Wordfence Intelligence vulnerability feed.
6. **Hypotheses**: plain-language explanations ranked by the evidence found (exploited plugin, WordPress login
   with a guessed or stolen password, admin upload/editor, upload of a script, or nothing in the web logs, which
   points to stolen FTP/cPanel credentials or another site on the same account).

Read-only: it reads logs and CyberWatch's own records; it changes nothing on the server. Bounded: at most
``MAX_LOG_BYTES`` of log text and ``MAX_PIVOTS`` files per run.
"""

from __future__ import annotations

import json
import posixpath
import re
import uuid
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.base import ConnectorError
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.base import utcnow
from app.models import (
    FileChange,
    FileInventoryItem,
    HostingAccount,
    Incident,
    Investigation,
    SoftwareInstall,
    Website,
)
from app.monitoring import logs, vendor

log = get_logger("investigation")

WINDOW_BEFORE = timedelta(minutes=30)
WINDOW_AFTER = timedelta(minutes=5)
MAX_LOG_BYTES = 300 * 1024 * 1024
MAX_PIVOTS = 20
MAX_IPS = 15
MAX_REQUESTS_PER_IP = 25
HEURISTIC = {"script_in_upload_dir", "suspicious_filename", "double_extension", "hidden_script"}

_PLUGIN_URL = re.compile(r"^/(?:.*/)?wp-content/(plugins|themes)/([^/]+)/")
_ADMIN_WRITE = re.compile(r"/wp-admin/(plugin-install|update|theme-install|theme-editor|plugin-editor|async-upload|"
                          r"media-new|upload)\.php$")
_INTERESTING = re.compile(r"(/wp-login\.php|/xmlrpc\.php|/wp-admin/admin-ajax\.php|/wp-admin/admin-post\.php|"
                          r"/wp-json/|\?rest_route=|/wp-content/(plugins|themes)/[^/]+/.+\.php|/wp-content/uploads/.+\.ph)")


# ---------------------------------------------------------------- pivots


def _pivots(db: Session, website: Website, incident_ids: list[str]) -> list[dict[str, Any]]:
    why: dict[str, set[str]] = defaultdict(set)
    for r in db.execute(select(FileInventoryItem).where(
            FileInventoryItem.website_id == website.id, FileInventoryItem.state == "present",
            (FileInventoryItem.malware_status.in_(["infected", "suspicious"]))
            | (FileInventoryItem.vendor_status == "unexpected"))).scalars():
        if r.malware_status in ("infected", "suspicious") and r.vendor_status != "verified":
            why[r.path].add(f"malware scan: {r.malware_status}")
        if r.vendor_status == "unexpected":
            why[r.path].add(f"not part of {r.vendor_ref}")
    since = utcnow() - timedelta(days=90)
    for c in db.execute(select(FileChange).where(
            FileChange.website_id == website.id, FileChange.detected_at >= since,
            FileChange.change_type.in_(["added", "modified", "renamed"]))).scalars():
        flags = set(c.flags or []) & HEURISTIC
        if flags:
            why[c.path].add("; ".join(sorted(f.replace("_", " ") for f in flags)))
    ids = [uuid.UUID(i) for i in incident_ids]
    if ids:
        for res in db.execute(select(Incident.affected_resources).where(Incident.id.in_(ids))).scalars():
            for r in res or []:
                if isinstance(r, dict) and r.get("type") == "file" and r.get("path"):
                    why[r["path"]].add("named in a linked incident")
    out = []
    for path, reasons in why.items():
        item = db.execute(select(FileInventoryItem).where(FileInventoryItem.website_id == website.id,
                                                          FileInventoryItem.path == path)).scalar_one_or_none()
        seen = db.execute(select(FileChange.detected_at).where(
            FileChange.website_id == website.id, FileChange.path == path,
            FileChange.change_type.in_(["added", "modified", "renamed"])).order_by(FileChange.detected_at.desc())
            .limit(1)).scalar_one_or_none() or (item.first_seen_at if item else None)
        mtime = item.mtime if item else None
        if mtime and (seen is None or mtime <= seen):
            when, source = mtime, "file modification time"
        elif seen:
            when, source = seen, "first seen by CyberWatch (the file existed by then)"
        else:
            continue
        out.append({"path": path, "url": logs.url_path(path), "time": when, "time_source": source,
                    "mtime": mtime, "first_seen": seen, "reasons": sorted(reasons),
                    "present": bool(item and item.state == "present")})
    out.sort(key=lambda p: p["time"])
    return out[:MAX_PIVOTS]


# ---------------------------------------------------------------- logs


def _load_logs(db: Session, website: Website, since: datetime) -> tuple[list[logs.LogEntry], list[dict], list[str]]:
    from app.connectors.registry import build_connector
    from app.models import ConnectorDefinition, HostingCredential
    from app.monitoring.log_scan import log_dirs, site_log_file

    notes: list[str] = []
    files: list[dict] = []
    entries: list[logs.LogEntry] = []
    if website.hosting_account_id is None:
        return entries, files, ["The website has no hosting connection, so its access logs cannot be read."]
    account = db.get(HostingAccount, website.hosting_account_id)
    cred = db.execute(select(HostingCredential).where(HostingCredential.hosting_account_id == account.id)).scalar_one_or_none()
    try:
        connector = build_connector(account, cred, db.get(ConnectorDefinition, account.connector_type))
    except ConnectorError as exc:
        return entries, files, [f"Logs unavailable: {exc.message}"]
    budget = MAX_LOG_BYTES
    for directory in log_dirs(account):
        try:
            with connector.open_file_source(directory) as src:
                for e in sorted(src.list_dir(""), key=lambda x: x.name):
                    if e.entry_type != "file" or not site_log_file(e.name, website.hostname):
                        continue
                    if e.mtime is not None and e.mtime < since:
                        continue  # not touched since before the period of interest
                    if budget <= 0:
                        notes.append("Log reading limit reached; older or remaining logs were skipped.")
                        break
                    try:
                        if logs.is_archive(e.name):
                            data = logs.read_archive(src, e.name, e.size)
                        else:
                            data = src.read_range(e.name, max(0, (e.size or 0) - budget), budget)
                    except (ValueError, ConnectorError) as exc:
                        files.append({"file": posixpath.join(directory, e.name), "error": str(getattr(exc, "message", exc))})
                        continue
                    budget -= len(data)
                    parsed, _ = logs.parse(data.decode("utf-8", "replace"))
                    entries += parsed
                    files.append({"file": posixpath.join(directory, e.name), "bytes": len(data), "requests": len(parsed)})
        except ConnectorError as exc:
            files.append({"file": directory, "error": exc.message})
    entries = [e for e in entries if e.at is not None]
    entries.sort(key=lambda e: e.at)
    if not entries:
        notes.append("No access-log entries could be read for this website (check log access on the hosting connection).")
    return entries, files, notes


def _req(e: logs.LogEntry) -> dict[str, Any]:
    return {"at": e.at.isoformat(), "ip": e.ip, "method": e.method, "path": e.path,
            "query": (e.query or "")[:200], "status": e.status, "agent": (e.agent or "")[:160]}


def _interesting(e: logs.LogEntry) -> bool:
    target = e.path + (f"?{e.query}" if e.query else "")
    return e.method == "POST" or bool(_INTERESTING.search(target)) or bool(_ADMIN_WRITE.search(e.path))


# ---------------------------------------------------------------- software


def _version_key(v: str | None) -> tuple:
    parts = re.split(r"[.\-+_]", v or "")
    return tuple(int(p) if p.isdigit() else -1 for p in parts if p != "")


def _get_json(url: str, params: dict | None = None, headers: dict | None = None, max_bytes: int = 2 * 1024 * 1024) -> Any:
    from app.core.http import pinned_request

    resp = pinned_request("GET", url, allowed_ports=[443], params=params, timeout=30.0, max_body_bytes=max_bytes,
                          headers={"Accept": "application/json", **(headers or {})})
    if resp.status_code != 200 or resp.truncated:
        raise ValueError(f"HTTP {resp.status_code}")
    return json.loads(resp.body)


def _wordfence_feed() -> dict[str, list[dict]] | None:
    """slug -> vulnerabilities, from the Wordfence Intelligence scanner feed (needs a free API key)."""
    s = get_settings()
    if not s.wordfence_api_key:
        return None
    doc = _get_json(s.wordfence_feed_url, headers={"Authorization": f"Bearer {s.wordfence_api_key}"},
                    max_bytes=400 * 1024 * 1024)
    out: dict[str, list[dict]] = defaultdict(list)
    for vid, v in (doc.items() if isinstance(doc, dict) else []):
        for sw in v.get("software") or []:
            if sw.get("type") in ("plugin", "theme", "core") and sw.get("slug"):
                out[f"{sw['type']}:{sw['slug']}"].append({
                    "id": vid, "title": v.get("title"), "cvss": (v.get("cvss") or {}).get("score"),
                    "rating": (v.get("cvss") or {}).get("rating"), "cve": v.get("cve"),
                    "ranges": list((sw.get("affected_versions") or {}).values()),
                    "patched_versions": sw.get("patched_versions") or [],
                    "reference": (v.get("references") or [None])[0]})
    return out


def _affected(version: str, ranges: list[dict]) -> bool:
    v = _version_key(version)
    for r in ranges:
        lo, hi = r.get("from_version", "*"), r.get("to_version", "*")
        if lo != "*" and (v < _version_key(lo) or (v == _version_key(lo) and not r.get("from_inclusive", True))):
            continue
        if hi != "*" and (v > _version_key(hi) or (v == _version_key(hi) and not r.get("to_inclusive", True))):
            continue
        return True
    return False


def _software(db: Session, website: Website, notes: list[str]) -> list[dict[str, Any]]:
    s = get_settings()
    installs = db.execute(select(SoftwareInstall).where(SoftwareInstall.website_id == website.id)).scalars().all()
    try:
        feed = _wordfence_feed()
    except Exception as exc:  # noqa: BLE001
        feed = None
        notes.append(f"Vulnerability feed unavailable ({type(exc).__name__}); only version checks were done.")
    if feed is None and not s.wordfence_api_key:
        notes.append("Vulnerability check not configured (set CW_WORDFENCE_API_KEY); versions were compared with the "
                     "latest releases only.")
    latest_core = None
    out = []
    for inst in sorted(installs, key=lambda i: (i.product != vendor.CORE, i.root, i.slug))[:80]:
        kind = "core" if inst.product == vendor.CORE else "plugin"
        latest = None
        try:
            if kind == "core":
                if latest_core is None:
                    doc = _get_json(f"{s.wordpress_api_base}/core/version-check/1.7/")
                    latest_core = (doc.get("offers") or [{}])[0].get("current")
                latest = latest_core
            else:
                doc = _get_json(f"{s.wordpress_api_base}/plugins/info/1.2/",
                                params={"action": "plugin_information", "request[slug]": inst.slug})
                latest = doc.get("version") if isinstance(doc, dict) else None
        except Exception:  # noqa: BLE001 - a missing answer is shown as unknown
            latest = None
        vulns = []
        if feed is not None and inst.version:
            key = "core:wordpress" if kind == "core" else f"plugin:{inst.slug}"
            vulns = [{k: v for k, v in x.items() if k != "ranges"} for x in feed.get(key, [])
                     if _affected(inst.version, x["ranges"])]
            vulns.sort(key=lambda x: -(x.get("cvss") or 0))
        out.append({"type": kind, "slug": "wordpress" if kind == "core" else inst.slug, "name": inst.name,
                    "root": inst.root, "version": inst.version, "latest": latest,
                    "outdated": bool(latest and inst.version and _version_key(inst.version) < _version_key(latest)),
                    "vulnerabilities": vulns[:10]})
    return out


# ---------------------------------------------------------------- analysis


def analyse(pivots: list[dict], entries: list[logs.LogEntry], software: list[dict]) -> dict[str, Any]:
    by_url: dict[str, list[logs.LogEntry]] = defaultdict(list)
    by_ip: dict[str, list[logs.LogEntry]] = defaultdict(list)
    for e in entries:
        by_url[e.path].append(e)
        by_ip[e.ip].append(e)
    coverage = (entries[0].at, entries[-1].at) if entries else (None, None)
    times = [e.at for e in entries]  # sorted: windows are found by binary search
    vulnerable = {s["slug"] for s in software if s["type"] == "plugin" and (s["vulnerabilities"] or s["outdated"])}
    attacker_ips: dict[str, set[str]] = defaultdict(set)
    hypotheses: list[dict] = []
    out_pivots = []
    for p in pivots:
        t: datetime = p["time"]
        users = by_url.get(p["url"], [])
        ips = sorted({u.ip for u in users if 200 <= u.status < 400 or u.method == "POST"})
        for ip in ips:
            attacker_ips[ip].add(p["path"])
        lo, hi = t - WINDOW_BEFORE, t + WINDOW_AFTER
        window = [e for e in entries[bisect_left(times, lo):bisect_right(times, hi)]
                  if _interesting(e) and e.path != p["url"]]
        covered = bool(coverage[0] and coverage[0] <= t <= coverage[1] + WINDOW_AFTER)
        out_pivots.append({**{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in p.items()},
                           "logs_cover_time": covered,
                           "used_by": [{"ip": ip, "requests": sum(1 for u in users if u.ip == ip),
                                        "first": min(u.at for u in users if u.ip == ip).isoformat()} for ip in ips[:20]],
                           "requests_to_file": len(users),
                           "window": [_req(e) | {"attacker_ip": e.ip in ips} for e in window[:60]],
                           "window_total": len(window)})
        hypotheses += _explain(p, window, ips, by_ip, covered, vulnerable)

    ip_history = []
    for ip, paths in sorted(attacker_ips.items(), key=lambda kv: by_ip[kv[0]][0].at if by_ip[kv[0]] else utcnow())[:MAX_IPS]:
        reqs = by_ip.get(ip, [])
        ip_history.append({"ip": ip, "files": sorted(paths), "requests": len(reqs),
                           "first_seen": reqs[0].at.isoformat() if reqs else None,
                           "last_seen": reqs[-1].at.isoformat() if reqs else None,
                           "logins": sum(1 for r in reqs if r.path.endswith("/wp-login.php") and r.method == "POST"),
                           "first_requests": [_req(r) for r in reqs[:MAX_REQUESTS_PER_IP]],
                           "agents": sorted({(r.agent or "")[:120] for r in reqs})[:5]})
    return {"pivots": out_pivots, "attacker_ips": ip_history, "hypotheses": _rank(hypotheses),
            "logs": {"requests": len(entries), "from": coverage[0].isoformat() if coverage[0] else None,
                     "to": coverage[1].isoformat() if coverage[1] else None}}


def _explain(p: dict, window: list[logs.LogEntry], ips: list[str], by_ip: dict, covered: bool,
             vulnerable: set[str]) -> list[dict]:
    t: datetime = p["time"]
    before = [e for e in window if e.at <= t + timedelta(seconds=60)]
    by_attacker = [e for e in before if e.ip in ips]
    hyps = []

    def add(kind: str, confidence: str, title: str, detail: str, ev: list[logs.LogEntry]) -> None:
        hyps.append({"kind": kind, "confidence": confidence, "title": title, "detail": detail, "file": p["path"],
                     "evidence": [_req(e) for e in ev[:8]]})

    # A successful WordPress login from an address that then used the file (or just before the file appeared).
    attacker_logins = [e for ip in ips for e in by_ip.get(ip, [])
                       if e.path.endswith("/wp-login.php") and e.method == "POST" and e.status == 302 and e.at <= t]
    if attacker_logins:
        add("password", "high", "WordPress login with a valid password",
            f"An address that used {p['path']} signed in to WordPress successfully before it appeared. The password "
            "was guessed, reused or stolen. Reset all administrator passwords and enable MFA.", attacker_logins)
    for e in by_attacker + [x for x in before if x.method == "POST"]:
        m = _PLUGIN_URL.search(e.path)
        if m and e.method == "POST":
            slug = m.group(2)
            add("plugin", "high" if e.ip in ips or slug in vulnerable else "medium",
                f"Request to the {m.group(1)[:-1]} '{slug}' just before the file appeared",
                f"{e.method} {e.path} from {e.ip} at {e.at:%H:%M:%S}"
                + (" (this software is outdated or has known vulnerabilities)" if slug in vulnerable else "")
                + ". A vulnerable plugin or theme often lets attackers upload files without logging in.", [e])
            break
    ajax = [e for e in before if e.method == "POST" and ("admin-ajax.php" in e.path or "/wp-json/" in e.path
                                                          or "rest_route=" in (e.query or ""))]
    if ajax:
        add("plugin", "medium" if any(e.ip in ips for e in ajax) else "low",
            "AJAX or REST API requests just before the file appeared",
            "Plugins expose actions through admin-ajax.php and the REST API; a vulnerable one can be used to upload "
            "files. Match the request's action parameter with the installed plugins.", ajax)
    admin = [e for e in before if _ADMIN_WRITE.search(e.path) and e.method == "POST"]
    if admin:
        add("admin_upload", "high", "Upload or edit through the WordPress dashboard",
            "A logged-in user installed or edited a plugin/theme or uploaded a file at that time. Find which "
            "account (WordPress user activity) and treat its password as compromised.", admin)
    uploads = [e for e in before if e.method == "POST" and "/wp-content/uploads/" in e.path]
    if uploads:
        add("upload_script", "medium", "A script in the uploads folder was used",
            "An earlier planted file was used to drop this one. Investigate the earliest file in the timeline.", uploads)
    if covered and not before:
        add("no_web_request", "medium", "No web request explains this file",
            "The logs cover this time but show nothing that could have written the file. This points to stolen "
            "FTP/SFTP or cPanel credentials, another compromised site on the same hosting account, or a forged "
            "file time. Check cPanel's last-login and FTP logs and change those passwords.", [])
    if not covered:
        add("no_logs", "low", "No access logs for that time",
            f"The file appeared around {t:%d %b %Y %H:%M} UTC, outside the period the available logs cover. Hosts "
            "keep a limited history; ask the host for older logs if needed.", [])
    return hyps


def _rank(hyps: list[dict]) -> list[dict]:
    order = {"high": 0, "medium": 1, "low": 2}
    seen, out = set(), []
    for h in sorted(hyps, key=lambda h: order[h["confidence"]]):
        key = (h["kind"], h["title"])
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


# ---------------------------------------------------------------- run


def run(db: Session, investigation_id: uuid.UUID) -> Investigation:
    inv = db.get(Investigation, investigation_id)
    website = db.get(Website, inv.website_id)
    from app.models import SupportTicket

    ticket = db.get(SupportTicket, inv.ticket_id) if inv.ticket_id else None
    try:
        pivots = _pivots(db, website, (ticket.incident_ids if ticket else None) or [])
        notes: list[str] = []
        earliest = min((p["time"] for p in pivots), default=utcnow() - timedelta(days=7))
        entries, files, log_notes = _load_logs(db, website, earliest - timedelta(days=14))
        notes += log_notes
        software = _software(db, website, notes)
        result = analyse(pivots, entries, software)
        if not pivots:
            notes.append("No malicious or unexpected files are known for this website yet; scan it first, or link the "
                         "request to its incidents.")
        inv.result = json.loads(json.dumps(result | {"software": software, "log_files": files, "notes": notes},
                                           default=str))
        inv.status = "done"
    except Exception as exc:  # noqa: BLE001 - recorded on the run, never lost
        log.error("investigation_failed", investigation=str(inv.id), error=f"{type(exc).__name__}: {exc}")
        inv.status, inv.error = "failed", f"{type(exc).__name__}: {exc}"[:1000]
    inv.finished_at = utcnow()
    return inv


def dispatch(investigation_id: uuid.UUID) -> None:
    from app.workers.celery_app import celery_app

    celery_app.send_task("cw.investigate", args=[str(investigation_id)], queue="checks")


def summary_text(result: dict) -> str:
    """Plain text for the customer report's findings section."""
    lines = []
    for h in result.get("hypotheses", [])[:3]:
        lines.append(f"- {h['title']} ({h['confidence']} confidence): {h['detail']}")
    ips = [a["ip"] for a in result.get("attacker_ips", [])]
    if ips:
        lines.append(f"- Addresses that used the malicious files: {', '.join(ips[:10])}.")
    vul = [f"{s['slug']} {s['version']}" for s in result.get("software", []) if s.get("vulnerabilities")]
    old = [f"{s['slug']} {s['version']} (latest {s['latest']})" for s in result.get("software", [])
           if s.get("outdated") and not s.get("vulnerabilities")]
    if vul:
        lines.append(f"- Software with known vulnerabilities: {', '.join(vul)}.")
    if old:
        lines.append(f"- Outdated software: {', '.join(old[:10])}.")
    return "How the attacker most likely got in:\n" + "\n".join(lines) if lines else ""
