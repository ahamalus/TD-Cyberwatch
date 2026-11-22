"""Access-log analysis job: read new log lines for one website and raise incidents (see logs.py)."""

from __future__ import annotations

import hashlib
import posixpath
import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.base import Capability, ConnectorError
from app.connectors.registry import build_connector
from app.db.base import utcnow
from app.models import (
    ConnectorCapability,
    ConnectorDefinition,
    FileInventoryItem,
    HostingAccount,
    HostingCredential,
    Incident,
    LogCursor,
    ScanJob,
    Tenant,
    Website,
)
from app.models.incidents import OPEN_STATUSES
from app.monitoring import logs
from app.monitoring.file_scan import ScanPreconditionFailed
from app.services import incidents as incident_svc
from app.services.incidents import DetectionSpec, EvidenceSpec

# Where the hosting control panel keeps raw access logs when none are configured (relative to the account).
DEFAULT_LOG_DIRS = {"cpanel_uapi": ["/access-logs"]}
MAX_BYTES_PER_FILE = 20 * 1024 * 1024  # per run; the rest is read on the next run
HEAD_BYTES = 256
SKIP_SUFFIXES = (".gz", ".bz2", ".zip", "-bytes_log", ".offset", ".bkup")


def log_dirs(account: HostingAccount) -> list[str]:
    configured = [p for p in (account.options or {}).get("log_paths", []) if isinstance(p, str)]
    return configured or DEFAULT_LOG_DIRS.get(account.connector_type, [])


def site_log_file(name: str, hostname: str) -> bool:
    """cPanel names domain logs ``example.com`` and ``example.com-ssl_log``; Apache/nginx setups often use
    ``example.com.access.log`` or ``access.log``. Only files for this website's host are read."""
    n = name.lower()
    if n.endswith(SKIP_SUFFIXES) or "error" in n:
        return False
    hosts = {hostname.lower(), hostname.lower().removeprefix("www.")}
    return any(n == h or n.startswith(h + "-") or n.startswith(h + ".") or n.startswith(h + "_") for h in hosts)


def _context(db: Session, website: Website) -> logs.Context:
    ctx = logs.Context()
    rows = db.execute(select(FileInventoryItem.path, FileInventoryItem.malware_status, FileInventoryItem.malware_signatures,
                             FileInventoryItem.vendor_status)
                      .where(FileInventoryItem.website_id == website.id, FileInventoryItem.state == "present",
                             (FileInventoryItem.malware_status.in_(["infected", "suspicious"]))
                             | (FileInventoryItem.vendor_status.in_(["modified", "unexpected"])))).all()
    for path, mstatus, sigs, vstatus in rows:
        url = logs.url_path(path)
        if mstatus == "infected":
            ctx.flagged[url] = "antivirus: " + ", ".join(s.partition(":")[2] for s in sigs if s.startswith("clamav:"))
            ctx.critical.add(url)
        elif mstatus == "suspicious" and vstatus != "verified":
            ctx.flagged[url] = "suspicious code: " + ", ".join(s.partition(":")[2] for s in sigs)
        elif vstatus in ("modified", "unexpected") and logs.PHP.search(path):
            ctx.flagged[url] = "differs from the official release" if vstatus == "modified" else "not part of the official release"
    # Files with an open suspicious-file incident (e.g. a PHP file added to uploads).
    for res in db.execute(select(Incident.affected_resources).where(
            Incident.website_id == website.id, Incident.category.in_(["suspicious_file", "malware"]),
            Incident.status.in_(OPEN_STATUSES))).scalars():
        for r in res or []:
            if isinstance(r, dict) and r.get("type") == "file" and r.get("path"):
                ctx.flagged.setdefault(logs.url_path(r["path"]), "open suspicious-file incident")
    return ctx


def _read_new(db: Session, src, website: Website, directory: str, name: str, size: int | None) -> tuple[str, dict]:
    path = posixpath.join(directory, name)
    cursor = db.execute(select(LogCursor).where(LogCursor.website_id == website.id, LogCursor.path == path)).scalar_one_or_none()
    head = src.read_range(name, 0, HEAD_BYTES)
    head_hash = hashlib.sha256(head).hexdigest()
    offset = cursor.offset if cursor else 0
    note = "continued"
    if cursor is None:
        note = "first read"
    elif cursor.head_sha256 != head_hash or (size is not None and size < offset):
        offset, note = 0, "rotated or truncated: read from the start"
    data = src.read_range(name, offset, MAX_BYTES_PER_FILE) if (size is None or size > offset) else b""
    complete = data.rfind(b"\n") + 1  # only whole lines; a partial last line is read next time
    text = data[:complete].decode("utf-8", "replace")
    if cursor is None:
        cursor = LogCursor(tenant_id=website.tenant_id, website_id=website.id, path=path, offset=0)
        db.add(cursor)
    cursor.offset, cursor.head_sha256, cursor.updated_at = offset + complete, head_hash, utcnow()
    return text, {"file": path, "bytes": complete, "from_offset": offset, "note": note,
                  "more_pending": len(data) >= MAX_BYTES_PER_FILE}


def run_log_scan(db: Session, job: ScanJob, heartbeat: Callable[..., None] | None = None) -> tuple[str, dict[str, Any]]:
    website = db.get(Website, job.website_id)
    if website is None or website.hosting_account_id is None:
        raise ScanPreconditionFailed("no_hosting_account", "No hosting connection is associated with this website.")
    account = db.get(HostingAccount, website.hosting_account_id)
    cap = db.execute(select(ConnectorCapability).where(ConnectorCapability.hosting_account_id == account.id,
                                                       ConnectorCapability.capability == Capability.LOG_ACCESS)).scalar_one_or_none()
    if cap is None or cap.status != "available":
        raise ScanPreconditionFailed("capability_unavailable",
                                     "Log access has not been verified for this hosting connection. Run a connection test.")
    credential = db.execute(select(HostingCredential).where(HostingCredential.hosting_account_id == account.id)).scalar_one_or_none()
    connector = build_connector(account, credential, db.get(ConnectorDefinition, account.connector_type))

    entries: list[logs.LogEntry] = []
    unparsed, files = 0, []
    for directory in log_dirs(account):
        try:
            with connector.open_file_source(directory) as src:
                for e in src.list_dir(""):
                    if e.entry_type != "file" or not site_log_file(e.name, website.hostname):
                        continue
                    text, info = _read_new(db, src, website, directory, e.name, e.size)
                    parsed, bad = logs.parse(text)
                    entries += parsed
                    unparsed += bad
                    files.append(info | {"lines": len(parsed)})
                    if heartbeat:
                        heartbeat({"files": len(files), "requests": len(entries)})
        except ConnectorError as exc:
            files.append({"file": directory, "error": exc.message})
    if not any("error" not in f for f in files):
        raise ScanPreconditionFailed("no_log_files", f"No access log for {website.hostname} was found in "
                                     f"{', '.join(log_dirs(account)) or 'the configured log directories'}.")

    findings, stats = logs.analyse(entries, _context(db, website))
    tenant = db.get(Tenant, website.tenant_id)
    opened: list[uuid.UUID] = []
    for f in findings:
        spec = DetectionSpec(
            tenant_id=website.tenant_id, website_id=website.id, hosting_account_id=account.id,
            title=f.title[:300], summary=f.summary[:2000], category="log_activity",
            finding_class="suspected_compromise" if f.severity in ("critical", "high") else "heuristic_suspicion",
            severity=f.severity, confidence="high" if f.rule in ("flagged_file_accessed", "sensitive_file_exposed") else "medium",
            detection_source="access_log", rule_key=f"log:{f.rule}", dedupe_key=f"log:{website.id}:{f.key}",
            recommended_action=_ACTIONS[f.rule],
            affected_resources=[{"type": "file", "path": p.lstrip("/")} for p in f.paths]
            + [{"type": "ip_address", "value": ip} for ip in f.ips[:20]],
            evidence=[EvidenceSpec("log_event", "access_log", "hosting_access_log",
                                   {"rule": f.rule, "lines": f.lines, "addresses": f.ips, "files": [x["file"] for x in files]},
                                   job.id)],
            path_for_suppression=f.paths[0].lstrip("/") if f.paths else None,
            is_demo=bool(tenant and tenant.is_demo),
        )
        inc, created = incident_svc.raise_detection(db, spec)
        if inc and created:
            opened.append(inc.id)
    summary = {**stats, "first": stats["first"].isoformat() if stats["first"] else None,
               "last": stats["last"].isoformat() if stats["last"] else None,
               "unparsed_lines": unparsed, "files": files, "findings": [f.rule for f in findings],
               "incidents_opened": [str(i) for i in opened]}
    return ("partial" if any(f.get("more_pending") or f.get("error") for f in files) else "succeeded"), summary


_ACTIONS = {
    "flagged_file_accessed": ("Treat the site as compromised: block the file (or take the site offline), have the file "
                              "removed, change hosting, CMS and database passwords, and review the requests in the "
                              "evidence to see what the attacker did."),
    "php_upload_executed": ("Inspect the file from a safe environment and remove it if it is not legitimate; block PHP "
                            "execution in upload folders (e.g. an .htaccess rule)."),
    "sensitive_file_exposed": ("Remove the file from the web root at once, then rotate every password, key or token it "
                               "contained; block dotfiles and backups in the web server configuration."),
    "login_bruteforce": ("Make sure WordPress accounts use strong unique passwords and MFA; limit login attempts and "
                         "disable XML-RPC if unused. Consider blocking the listed addresses."),
    "login_bruteforce_success": ("Find which account signed in from this address (WordPress user activity / last login), "
                                 "reset its password, end its sessions and review recent changes to posts, users, "
                                 "plugins and files."),
}
