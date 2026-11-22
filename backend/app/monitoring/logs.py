"""Web server access-log analysis.

Reads the access logs the hosting connection exposes (Apache/LiteSpeed/nginx "combined" or "common"
format) and looks for signs of attack that a log can show reliably. Each rule is chosen so that a finding is
likely to matter; noisy background (scanners probing for files that do not exist) is counted in the summary,
not raised as an incident.

Rules:

* ``flagged_file_accessed``: a file CyberWatch already flagged (malware verdict, a file planted in WordPress
  core directories, a suspicious upload) answered a request successfully: someone is using it.
* ``php_upload_executed``: a POST to a PHP file under an uploads directory was answered successfully (uploads
  should never contain executable code).
* ``sensitive_file_exposed``: a configuration or secrets file (``.env``, ``.git/config``, ``wp-config.php``
  backups, SQL dumps...) was served with content.
* ``login_bruteforce`` / ``login_bruteforce_success``: many failed WordPress logins (``wp-login.php`` answers
  200 to a failed attempt) or XML-RPC calls from one address; a following 302 from the same address means a
  login probably succeeded.

Nothing here claims a site is safe: only what the provided log lines show is reported.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote, urlsplit

# host-prefixed (vhost_combined) or plain combined/common format.
_LINE = re.compile(
    r'^(?:(?P<vhost>\S+)\s+)??(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]{3,10})\s+(?P<target>\S+)(?:\s+HTTP/[0-9.]+)?"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)
_TIME = "%d/%b/%Y:%H:%M:%S %z"

BRUTEFORCE_THRESHOLD = 20
MAX_EVIDENCE_LINES = 20

SENSITIVE = re.compile(
    r"(^|/)(\.env(\.\w+)?|\.git/(config|HEAD)|\.svn/entries|\.htpasswd|wp-config\.php[.~_-]\w*|wp-config\.(bak|old|save|txt|orig)"
    r"|[^/]*\.(sql|sql\.gz|bak|backup)|id_rsa|\.aws/credentials|phpinfo\.php)$",
    re.I,
)
PHP = re.compile(r"\.(php\d?|phtml|phar)$", re.I)


@dataclass(slots=True)
class LogEntry:
    ip: str
    at: datetime | None
    method: str
    path: str
    query: str
    status: int
    size: int
    agent: str
    raw: str


def parse_line(line: str) -> LogEntry | None:
    m = _LINE.match(line.strip())
    if not m:
        return None
    target = m.group("target")
    parts = urlsplit(target if target.startswith("/") else "/" + target.split("/", 3)[-1] if "://" in target else target)
    try:
        at = datetime.strptime(m.group("time"), _TIME)
    except ValueError:
        at = None
    size = m.group("size")
    return LogEntry(
        ip=m.group("ip"), at=at, method=m.group("method"), path=unquote(parts.path or "/"), query=parts.query,
        status=int(m.group("status")), size=0 if size == "-" else int(size), agent=m.group("agent") or "",
        raw=line.strip()[:1000],
    )


def parse(text: str) -> tuple[list[LogEntry], int]:
    """Parse a block of log text. Returns (entries, number of non-empty lines not recognised)."""
    entries, bad = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        e = parse_line(line)
        if e is None:
            bad += 1
        else:
            entries.append(e)
    return entries, bad


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    summary: str
    key: str  # deduplication within a website
    lines: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)


@dataclass
class Context:
    """What CyberWatch already knows about the site's files, keyed by URL path (``/wp-content/x.php``)."""

    flagged: dict[str, str] = field(default_factory=dict)  # url path -> why it is flagged
    critical: set[str] = field(default_factory=set)  # url paths with a confirmed (antivirus) malware verdict


def _ok(e: LogEntry) -> bool:
    return 200 <= e.status < 300


def analyse(entries: list[LogEntry], ctx: Context) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []

    # Flagged files being used.
    used: dict[str, list[LogEntry]] = defaultdict(list)
    for e in entries:
        if e.path in ctx.flagged and _ok(e):
            used[e.path].append(e)
    for path, hits in used.items():
        ips = sorted({h.ip for h in hits})
        findings.append(Finding(
            rule="flagged_file_accessed", severity="critical" if path in ctx.critical else "high",
            title=f"Flagged file is being accessed: {path}",
            summary=(f"{path} ({ctx.flagged[path]}) answered {len(hits)} request(s) successfully from {len(ips)} "
                     f"address(es), including {sum(h.method == 'POST' for h in hits)} POST request(s). Someone is "
                     "using this file; treat the site as compromised until it is removed and access is investigated."),
            key=f"flagged:{path}", lines=[h.raw for h in hits[:MAX_EVIDENCE_LINES]], paths=[path], ips=ips[:50]))

    # PHP executed from an uploads directory (whether or not CyberWatch has seen the file).
    uploads: dict[str, list[LogEntry]] = defaultdict(list)
    for e in entries:
        if (e.method == "POST" and _ok(e) and "/uploads/" in e.path.lower() and PHP.search(e.path)
                and e.path not in used):
            uploads[e.path].append(e)
    for path, hits in uploads.items():
        findings.append(Finding(
            rule="php_upload_executed", severity="high",
            title=f"PHP code executed from an uploads folder: {path}",
            summary=(f"{len(hits)} POST request(s) to {path} were answered successfully. Upload folders hold media; "
                     "a PHP file there that accepts POST requests is a typical web shell."),
            key=f"upload_php:{path}", lines=[h.raw for h in hits[:MAX_EVIDENCE_LINES]], paths=[path],
            ips=sorted({h.ip for h in hits})[:50]))

    # Secrets served to the internet.
    exposed: dict[str, list[LogEntry]] = defaultdict(list)
    for e in entries:
        if _ok(e) and e.size > 0 and e.method in ("GET", "HEAD") and SENSITIVE.search(e.path):
            exposed[e.path].append(e)
    for path, hits in exposed.items():
        findings.append(Finding(
            rule="sensitive_file_exposed", severity="high",
            title=f"Sensitive file served to the internet: {path}",
            summary=(f"{path} was downloaded {len(hits)} time(s) ({max(h.size for h in hits)} bytes). Files like this "
                     "usually contain passwords or keys: remove it from the web root, then change every secret it "
                     "contains."),
            key=f"exposed:{path}", lines=[h.raw for h in hits[:MAX_EVIDENCE_LINES]], paths=[path],
            ips=sorted({h.ip for h in hits})[:50]))

    # Password guessing.
    failed: Counter[tuple[str, str]] = Counter()
    first_success: dict[str, LogEntry] = {}
    examples: dict[tuple[str, str], list[str]] = defaultdict(list)
    for e in entries:
        p = e.path.lower()
        if e.method != "POST":
            continue
        if p.endswith("/wp-login.php"):
            if e.status == 200:
                failed[(e.ip, "wp-login.php")] += 1
                if len(examples[(e.ip, "wp-login.php")]) < 5:
                    examples[(e.ip, "wp-login.php")].append(e.raw)
            elif e.status == 302 and failed[(e.ip, "wp-login.php")] >= BRUTEFORCE_THRESHOLD:
                first_success.setdefault(e.ip, e)
        elif p.endswith("/xmlrpc.php"):
            failed[(e.ip, "xmlrpc.php")] += 1
            if len(examples[(e.ip, "xmlrpc.php")]) < 5:
                examples[(e.ip, "xmlrpc.php")].append(e.raw)
    attackers = [(ip, target, n) for (ip, target), n in failed.items() if n >= BRUTEFORCE_THRESHOLD]
    for ip, target, n in attackers:
        if target == "wp-login.php" and ip in first_success:
            ok = first_success[ip]
            findings.append(Finding(
                rule="login_bruteforce_success", severity="high",
                title=f"Possible successful password guessing from {ip}",
                summary=(f"{ip} failed to log in to WordPress {n} times, then a login from the same address succeeded "
                         "(redirect after POST to wp-login.php). Check which account signed in, reset its password, "
                         "and review recent changes."),
                key=f"bruteforce_success:{ip}", lines=examples[(ip, target)] + [ok.raw], ips=[ip]))
    if attackers:
        top = sorted(attackers, key=lambda a: -a[2])
        findings.append(Finding(
            rule="login_bruteforce", severity="medium",
            title=f"Password guessing against WordPress from {len({a[0] for a in attackers})} address(es)",
            summary=("; ".join(f"{ip}: {n} attempts on {t}" for ip, t, n in top[:10])
                     + ". Use strong unique passwords and MFA for WordPress accounts, and consider limiting login "
                       "attempts or disabling XML-RPC if it is not needed."),
            key="bruteforce", lines=[ln for ip, t, _ in top[:3] for ln in examples[(ip, t)][:3]],
            ips=[a[0] for a in top[:50]]))

    by_status = Counter(e.status // 100 for e in entries)
    stats = {
        "requests": len(entries),
        "addresses": len({e.ip for e in entries}),
        "status": {f"{k}xx": v for k, v in sorted(by_status.items())},
        "top_addresses": [{"ip": ip, "requests": n} for ip, n in Counter(e.ip for e in entries).most_common(5)],
        "probes_for_sensitive_files": sum(1 for e in entries if SENSITIVE.search(e.path) and not _ok(e)),
        "first": min((e.at for e in entries if e.at), default=None),
        "last": max((e.at for e in entries if e.at), default=None),
    }
    return findings, stats


def probe(src, directory: str) -> tuple[bool, str]:
    """Verify log access for real: list the directory, read the end of an access log and recognise its format.

    ``src`` is a FileSource rooted at the log directory."""
    files = [e for e in src.list_dir("") if e.entry_type == "file" and not e.name.lower().endswith(
        (".gz", ".bz2", ".zip", "-bytes_log")) and "error" not in e.name.lower() and (e.size or 0) > 0]
    if not files:
        return False, f"{directory}: no uncompressed access log found"
    for f in sorted(files, key=lambda e: -(e.size or 0))[:3]:
        start = max(0, (f.size or 0) - 65536)
        sample = src.read_range(f.name, start, 65536).decode("utf-8", "replace")
        lines = sample.splitlines()[1:] if start else sample.splitlines()
        parsed, _ = parse("\n".join(lines[-200:]))
        if parsed:
            return True, f"{directory}: {len(files)} log file(s) readable, access-log format recognised ({f.name})"
    return False, f"{directory}: files are readable but not in a recognised access-log format"


def url_path(inventory_path: str) -> str:
    """Inventory paths are relative to the website's document root."""
    return "/" + inventory_path.lstrip("/")
