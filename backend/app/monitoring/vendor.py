"""Verification of website files against the publisher's official checksums.

WordPress publishes per-file checksums for every core release (api.wordpress.org, MD5) and for every plugin
version hosted on wordpress.org (downloads.wordpress.org, MD5 and SHA-256). Comparing scanned files with
those lists lets CyberWatch:

* recognise genuine, unmodified vendor code, so heuristic rules (YARA, file-name heuristics) do not raise
  false alarms on it;
* detect tampering that heuristics cannot see: a modified core file, or an extra file planted inside
  ``wp-admin/`` or ``wp-includes/`` (where nothing but core files belongs).

Versions are read from the files themselves (``wp-includes/version.php``, plugin headers) during the scan.
Checksum lists are public data, cached per release. A failed or missing list never blocks or fails a scan:
files are then simply "not verified".
"""

from __future__ import annotations

import json
import logging
import posixpath
import re
import threading
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import utcnow
from app.models import VendorChecksums

log = logging.getLogger(__name__)

CORE = "wordpress-core"
PLUGIN = "wordpress-plugin"

VERIFIED, MODIFIED, UNEXPECTED = "verified", "modified", "unexpected"

_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,199}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_LOCALE = re.compile(r"^[A-Za-z]{2,3}(_[A-Za-z0-9]{2,8}){0,2}$")
_PLUGIN_FILE = re.compile(r"^(?P<root>(?:.*/)?)wp-content/plugins/(?P<slug>[^/]+)/[^/]+\.php$")
_WP_VERSION = re.compile(rb"""^\s*\$wp_version\s*=\s*['"]([^'"]{1,64})['"]\s*;""", re.M)
_WP_LOCALE = re.compile(rb"""^\s*\$wp_local_package\s*=\s*['"]([^'"]{1,16})['"]\s*;""", re.M)
_HEADER = re.compile(rb"^[ \t/*#@]*(Plugin Name|Version)[ \t]*:[ \t]*(.+?)[ \t]*(?:\*/)?\r?$", re.M | re.I)

# How long a cached answer is trusted. Published lists never change; "not found" and errors are retried.
RETRY_NOT_FOUND = timedelta(days=3)
RETRY_ERROR = timedelta(hours=6)


# ------------------------------------------------------------------ detection during the walk


@dataclass
class Detected:
    product: str
    slug: str
    root: str  # install directory relative to the monitored root, "" or ending in "/"
    version: str | None
    locale: str | None = None
    name: str | None = None
    marker: str = ""  # file the version was read from


class WordPressObserver:
    """Reads version files while the scan downloads them (ContentObserver for walk_inventory)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.found: dict[tuple[str, str, str], Detected] = {}

    def wants(self, path: str) -> bool:
        return path == "wp-includes/version.php" or path.endswith("/wp-includes/version.php") or bool(
            _PLUGIN_FILE.match(path))

    def observe(self, path: str, data: bytes) -> None:
        try:
            det = _parse(path, data)
        except Exception:  # noqa: BLE001 - malformed content must never break a scan
            log.debug("could not parse %s", path, exc_info=True)
            return
        if det is None:
            return
        with self._lock:
            key = (det.product, det.root, det.slug)
            # Several files of one plugin may carry a header; keep the one named after the plugin directory.
            if key not in self.found or posixpath.basename(det.marker) == f"{det.slug}.php":
                self.found[key] = det


def _parse(path: str, data: bytes) -> Detected | None:
    if path == "wp-includes/version.php" or path.endswith("/wp-includes/version.php"):
        m = _WP_VERSION.search(data)
        if not m:
            return None
        loc = _WP_LOCALE.search(data)
        return Detected(CORE, "wordpress", path[: -len("wp-includes/version.php")], m.group(1).decode("ascii", "replace"),
                        loc.group(1).decode("ascii", "replace") if loc else None, "WordPress", path)
    m = _PLUGIN_FILE.match(path)
    if not m:
        return None
    headers: dict[str, str] = {}
    for h in _HEADER.finditer(data[:8192]):
        headers.setdefault(h.group(1).decode().lower(), h.group(2).decode("utf-8", "replace").strip())
    if "plugin name" not in headers:
        return None
    return Detected(PLUGIN, m.group("slug"), m.group("root"), headers.get("version"), None,
                    headers["plugin name"][:200], path)


# ------------------------------------------------------------------ official checksum lists


class ChecksumStore:
    """Fetches and caches official checksum lists. One instance per scan."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.memo: dict[tuple[str, str, str, str], dict[str, dict[str, list[str]]] | None] = {}
        self.fetches = 0
        self.failures: list[str] = []

    def get(self, product: str, slug: str, version: str, locale: str = "") -> dict[str, dict[str, list[str]]] | None:
        key = (product, slug, version, locale)
        if key not in self.memo:
            self.memo[key] = self._load(*key)
        return self.memo[key]

    def _load(self, product: str, slug: str, version: str, locale: str):
        if not (_SLUG.match(slug) and _VERSION.match(version) and (not locale or _LOCALE.match(locale))):
            return None
        row = self.db.execute(
            select(VendorChecksums).where(VendorChecksums.product == product, VendorChecksums.slug == slug,
                                          VendorChecksums.version == version, VendorChecksums.locale == locale)
        ).scalar_one_or_none()
        now = utcnow()
        if row is not None:
            if row.status == "ok":
                return row.files
            retry = RETRY_NOT_FOUND if row.status == "not_found" else RETRY_ERROR
            if row.fetched_at > now - retry:
                return None
        status, files, detail = self._fetch(product, slug, version, locale)
        stmt = pg_insert(VendorChecksums).values(product=product, slug=slug, version=version, locale=locale,
                                                 status=status, files=files, detail=detail, fetched_at=now)
        self.db.execute(stmt.on_conflict_do_update(
            constraint="uq_vendor_checksums_release",
            set_={"status": stmt.excluded.status, "files": stmt.excluded.files, "detail": stmt.excluded.detail,
                  "fetched_at": stmt.excluded.fetched_at},
        ))
        if status == "error":
            self.failures.append(f"{product} {slug} {version}: {detail}")
        return files if status == "ok" else None

    def _fetch(self, product: str, slug: str, version: str, locale: str) -> tuple[str, dict, str | None]:
        from app.core.http import pinned_request

        s = get_settings()
        if product == CORE:
            url = f"{s.wordpress_api_base}/core/checksums/1.0/"
            params = {"version": version, "locale": locale or "en_US"}
        else:
            url = f"{s.wordpress_downloads_base}/plugin-checksums/{slug}/{version}.json"
            params = None
        self.fetches += 1
        try:
            resp = pinned_request("GET", url, allowed_ports=[443], params=params, timeout=20.0,
                                  max_body_bytes=16 * 1024 * 1024, headers={"Accept": "application/json"})
        except Exception as exc:  # noqa: BLE001 - network problems are reported, never raised
            return "error", {}, f"{type(exc).__name__}: {exc}"[:500]
        if resp.status_code == 404:
            return "not_found", {}, "No checksum list published for this release."
        if resp.status_code != 200 or resp.truncated:
            return "error", {}, f"HTTP {resp.status_code}{' (truncated)' if resp.truncated else ''}"
        try:
            files = _normalise(product, version, json.loads(resp.body))
        except (ValueError, TypeError, AttributeError) as exc:
            return "error", {}, f"Unreadable checksum list: {exc}"[:500]
        if not files:
            return "not_found", {}, "No checksum list published for this release."
        return "ok", files, None


def _as_list(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v.lower()]
    if isinstance(v, list):
        return [x.lower() for x in v if isinstance(x, str)]
    return []


def _normalise(product: str, version: str, doc: Any) -> dict[str, dict[str, list[str]]]:
    """Both APIs -> {relative path: {"md5": [...], "sha256": [...]}}."""
    out: dict[str, dict[str, list[str]]] = {}
    if product == CORE:
        sums = doc.get("checksums")
        if isinstance(sums, dict) and isinstance(sums.get(version), dict):
            sums = sums[version]  # multi-version response shape
        if not isinstance(sums, dict):
            return {}
        for path, md5 in sums.items():
            if isinstance(path, str) and _as_list(md5):
                out[path] = {"md5": _as_list(md5), "sha256": []}
        return out
    for path, entry in (doc.get("files") or {}).items():
        if isinstance(path, str) and isinstance(entry, dict):
            out[path] = {"md5": _as_list(entry.get("md5")), "sha256": _as_list(entry.get("sha256"))}
    return out


# ------------------------------------------------------------------ verification


@dataclass
class InstallReport:
    detected: Detected
    checksum_status: str  # verified | modified | no_checksums | unavailable
    verified: int = 0
    modified: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{'wordpress' if self.detected.product == CORE else self.detected.slug} {self.detected.version}"


@dataclass
class VendorReport:
    installs: list[InstallReport] = field(default_factory=list)
    status: dict[str, tuple[str, str]] = field(default_factory=dict)  # path -> (vendor_status, vendor_ref)
    fetch_failures: list[str] = field(default_factory=list)

    def is_verified(self, path: str) -> bool:
        return self.status.get(path, ("",))[0] == VERIFIED

    def summary(self) -> dict[str, Any]:
        return {
            "installs": [
                {"product": r.detected.product, "slug": r.detected.slug, "root": r.detected.root,
                 "version": r.detected.version, "checksums": r.checksum_status, "verified": r.verified,
                 "modified": len(r.modified), "unexpected": len(r.unexpected)}
                for r in self.installs
            ],
            "files_verified": sum(1 for s, _ in self.status.values() if s == VERIFIED),
            "fetch_failures": self.fetch_failures[:10],
        }


def _matches(e, sums: dict[str, list[str]]) -> bool:
    return bool((e.md5 and e.md5 in sums.get("md5", [])) or (e.sha256 and e.sha256 in sums.get("sha256", [])))


def verify(entries: dict[str, Any], found: list[Detected], store: ChecksumStore | None) -> VendorReport:
    """Compare scanned entries (path -> EntryRecord with sha256/md5) with the official lists."""
    report = VendorReport()
    files_by_dir: dict[str, list[str]] = {}
    for path, e in entries.items():
        if e.entry_type == "file" and e.hash_status == "hashed":
            files_by_dir.setdefault(posixpath.dirname(path), []).append(path)

    def under(prefix: str) -> list[str]:
        p = prefix.rstrip("/")
        return [f for d, fs in files_by_dir.items() if d == p or d.startswith(p + "/") for f in fs]

    # Core first, plugins second: a plugin's own list is more specific than core's bundled copy.
    for det in sorted(found, key=lambda d: (d.product != CORE, d.root, d.slug)):
        if not det.version:
            report.installs.append(InstallReport(det, "no_checksums"))
            continue
        sums = None
        if store is not None:
            if det.product == CORE:
                sums = store.get(CORE, "wordpress", det.version, det.locale or "en_US")
                if sums is None and det.locale and det.locale != "en_US":
                    sums = store.get(CORE, "wordpress", det.version, "en_US")
            else:
                sums = store.get(PLUGIN, det.slug, det.version)
        if sums is None:
            failed = store is None or any(f.startswith(f"{det.product} {det.slug} {det.version}:")
                                          for f in store.failures)
            report.installs.append(InstallReport(det, "unavailable" if failed else "no_checksums"))
            continue
        rep = InstallReport(det, VERIFIED)
        ref = rep.ref
        if det.product == CORE:
            for rel, s in sums.items():
                e = entries.get(det.root + rel)
                if e is None or e.entry_type != "file" or e.hash_status != "hashed":
                    continue
                if _matches(e, s):
                    report.status[e.path] = (VERIFIED, ref)
                    rep.verified += 1
                elif not rel.startswith("wp-content/"):  # bundled themes/plugins update independently
                    report.status[e.path] = (MODIFIED, ref)
                    rep.modified.append(e.path)
            for area in ("wp-admin/", "wp-includes/"):
                for path in under(det.root + area):
                    if path[len(det.root):] not in sums:
                        report.status[path] = (UNEXPECTED, ref)
                        rep.unexpected.append(path)
        else:
            base = f"{det.root}wp-content/plugins/{det.slug}/"
            for path in under(base):
                e, rel = entries[path], path[len(base):]
                if rel in sums:
                    if _matches(e, sums[rel]):
                        report.status[path] = (VERIFIED, ref)
                        rep.verified += 1
                    else:
                        report.status[path] = (MODIFIED, ref)
                        rep.modified.append(path)
                elif path.lower().endswith((".php", ".phtml", ".phar")):
                    report.status[path] = (UNEXPECTED, ref)
                    rep.unexpected.append(path)
        if rep.modified or rep.unexpected:
            rep.checksum_status = MODIFIED
        report.installs.append(rep)
    if store is not None:
        report.fetch_failures = list(store.failures)
    return report
