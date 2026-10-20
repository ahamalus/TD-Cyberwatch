"""Documented, deterministic rules that classify file changes.

Each rule adds a flag and may raise severity. These are heuristics: they mark
changes that deserve human attention and never assert that a site is
compromised. The rule catalogue is exposed through the API so analysts can
see exactly why a change was rated as it was.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from app.models.incidents import SEVERITY_RANK
from app.monitoring.inventory import Change, matches_any

SCRIPT_EXTENSIONS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".pht", ".phps",
    ".pl", ".py", ".cgi", ".sh", ".asp", ".aspx", ".jsp", ".exe", ".dll", ".so", ".bin",
}
UPLOAD_DIR_PATTERNS = [
    "**/uploads/**", "uploads/**", "**/upload/**", "upload/**", "**/images/**", "images/**",
    "**/media/**", "media/**", "**/files/**", "files/**", "**/cache/**", "cache/**",
]
SUSPICIOUS_NAME_RE = re.compile(
    r"(^|[._-])(c99|r57|wso|b374k|alfa|shell|webshell|backdoor|cmd|eval|indoxploit|"
    r"mini|priv8|leaf(mailer)?|adminer|filesman|uploader)([._-]|$)",
    re.IGNORECASE,
)
DOUBLE_EXT_RE = re.compile(
    r"\.(php\d?|phtml|phar|pl|cgi|sh|asp|aspx|jsp)\.(jpe?g|png|gif|ico|txt|pdf|zip|css|js)$|"
    r"\.(jpe?g|png|gif|ico|txt|pdf|zip|css|js)\.(php\d?|phtml|phar)$",
    re.IGNORECASE,
)
SERVER_CONFIG_NAMES = {".htaccess", ".user.ini", "php.ini", "web.config", ".htpasswd"}


@dataclass(frozen=True)
class RuleInfo:
    key: str
    severity: str
    description: str


RULES = [
    RuleInfo("script_in_upload_dir", "high",
             "An executable or script file was added or modified inside an upload/media/cache directory."),
    RuleInfo("suspicious_filename", "high",
             "File name matches names commonly used by web shells or attack tools."),
    RuleInfo("double_extension", "high",
             "File uses a double extension that can disguise a script as a harmless file type."),
    RuleInfo("hidden_script", "medium", "A hidden (dot-prefixed) script file was added or modified."),
    RuleInfo("server_config_changed", "medium",
             "A web-server or PHP configuration file (.htaccess, .user.ini, ...) changed."),
    RuleInfo("script_changed", "medium", "A server-side script file was added, modified or renamed."),
    RuleInfo("critical_path", "high", "The change is inside a path the customer marked as critical."),
    RuleInfo("permissions_executable", "medium", "A file in the web root became executable."),
    RuleInfo("file_changed", "low", "Any other file change."),
    RuleInfo("low_confidence", "low",
             "Change inferred from size/timestamp only because a hash was unavailable."),
]
RULES_BY_KEY = {r.key: r for r in RULES}


def _max(a: str, b: str) -> str:
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b


def classify_change(change: Change, critical_paths: list[str]) -> None:
    """Set ``flags`` and ``severity`` on a change in place."""
    path = change.path
    name = posixpath.basename(path)
    ext = posixpath.splitext(name)[1].lower()
    is_file = change.entry_type in ("file", "symlink")
    content_change = change.change_type in ("added", "modified", "renamed", "type_changed")
    flags: list[str] = []
    severity = "low"

    if is_file and content_change:
        is_script = ext in SCRIPT_EXTENSIONS
        if is_script and matches_any(path, UPLOAD_DIR_PATTERNS):
            flags.append("script_in_upload_dir")
        if SUSPICIOUS_NAME_RE.search(posixpath.splitext(name)[0]) and is_script:
            flags.append("suspicious_filename")
        if DOUBLE_EXT_RE.search(name):
            flags.append("double_extension")
        if name.startswith(".") and is_script:
            flags.append("hidden_script")
        if name.lower() in SERVER_CONFIG_NAMES:
            flags.append("server_config_changed")
        if is_script and not flags:
            flags.append("script_changed")
        new_mode = change.new.mode if change.new else None
        old_mode = change.old.mode if change.old else None
        if new_mode is not None and new_mode & 0o111 and not (old_mode or 0) & 0o111 and ext not in (".sh", ".cgi", ".pl"):
            flags.append("permissions_executable")
    if critical_paths and matches_any(path, critical_paths):
        flags.append("critical_path")
    if change.confidence == "low":
        flags.append("low_confidence")
    if not flags:
        flags.append("file_changed")

    for f in flags:
        severity = _max(severity, RULES_BY_KEY[f].severity)
    if change.change_type == "deleted" and "critical_path" not in flags:
        severity = "low"
    if change.confidence == "low" and severity == "high" and "critical_path" not in flags:
        severity = "medium"
    change.flags = flags
    change.severity = severity
