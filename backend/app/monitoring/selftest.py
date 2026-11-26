"""Self-test of the bundled YARA rules against official software releases.

Every day the rules are run over the official downloads of the WordPress core and plugin versions detected
on monitored sites. Genuine vendor code must never match: a rule that does is *quarantined* for the current
rule-set version (its matches stop counting as findings everywhere) and administrators are alerted through
System Health and the health check, so the rule can be fixed. Editing the rules changes the rule-set version,
which ends the quarantine and makes the next self-test check the new rules.

Release archives are downloaded through the same SSRF-protected client as other outbound requests and are
only read in memory; nothing is extracted to disk or executed.
"""

from __future__ import annotations

import io
import logging
import zipfile
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import utcnow
from app.models import RuleSelftest, SoftwareInstall
from app.monitoring import vendor
from app.monitoring.malware import yara_rules

log = logging.getLogger(__name__)

MAX_ARCHIVE_BYTES = 80 * 1024 * 1024
MAX_UNPACKED_BYTES = 400 * 1024 * 1024  # guards against archive bombs


def quarantined_rules(db: Session, rules_version: str) -> dict[str, list[dict[str, Any]]]:
    """Rules that matched genuine vendor code for this rule-set version -> the matches that show it."""
    out: dict[str, list[dict[str, Any]]] = {}
    for row in db.execute(select(RuleSelftest).where(RuleSelftest.rules_version == rules_version,
                                                     RuleSelftest.status == "misfire")).scalars():
        for m in row.matches or []:
            out.setdefault(m["rule"], []).append({**m, "release": f"{row.slug} {row.version}"})
    return out


def _targets(db: Session, max_core: int, max_plugins: int) -> list[tuple[str, str, str]]:
    """Releases to test: the versions most often detected on monitored sites."""
    def top(product: str, limit: int) -> list[tuple[str, str, str]]:
        rows = db.execute(
            select(SoftwareInstall.slug, SoftwareInstall.version, func.count().label("n"))
            .where(SoftwareInstall.product == product, SoftwareInstall.version.is_not(None))
            .group_by(SoftwareInstall.slug, SoftwareInstall.version)
            .order_by(func.count().desc(), SoftwareInstall.slug, SoftwareInstall.version.desc())
            .limit(limit)
        ).all()
        return [(product, slug, version) for slug, version, _ in rows
                if vendor._SLUG.match(slug) and vendor._VERSION.match(version)]

    return top(vendor.CORE, max_core) + top(vendor.PLUGIN, max_plugins)


def _download(product: str, slug: str, version: str) -> bytes:
    from app.core.http import pinned_request

    base = get_settings().wordpress_downloads_base
    url = (f"{base}/release/wordpress-{version}.zip" if product == vendor.CORE
           else f"{base}/plugin/{slug}.{version}.zip")
    resp = pinned_request("GET", url, allowed_ports=[443], timeout=120.0, max_body_bytes=MAX_ARCHIVE_BYTES)
    if resp.status_code == 404:
        raise LookupError("Release archive not found.")
    if resp.status_code != 200 or resp.truncated:
        raise RuntimeError(f"HTTP {resp.status_code}{' (archive too large)' if resp.truncated else ''}")
    return resp.body


def check_archive(rules: Any, archive: bytes, max_file_bytes: int) -> tuple[int, list[dict[str, str]]]:
    """Run the rules over every file in a release archive. Returns (files checked, matches)."""
    checked, unpacked, matches = 0, 0, []
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size > max_file_bytes:
                continue
            unpacked += info.file_size
            if unpacked > MAX_UNPACKED_BYTES:
                raise RuntimeError("Archive expands beyond the self-test limit.")
            data = zf.read(info)
            checked += 1
            path = info.filename.split("/", 1)[1] if "/" in info.filename else info.filename
            for m in rules.match(data=data, timeout=10):
                excerpt = next((s.instances[0].matched_data[:160].decode("utf-8", "replace")
                                for s in m.strings if s.instances), "")
                matches.append({"rule": m.rule, "path": path, "excerpt": excerpt})
    return checked, matches


def run_selftest(db: Session, max_core: int = 5, max_plugins: int = 25) -> dict[str, Any]:
    rules, rules_version, _ = yara_rules()
    if rules is None:
        return {"status": "skipped", "reason": "YARA rules are not loaded."}
    if not get_settings().vendor_checksums_enabled:
        return {"status": "skipped", "reason": "Official release checks are disabled (CW_VENDOR_CHECKSUMS_ENABLED)."}
    done = {(r.product, r.slug, r.version) for r in db.execute(
        select(RuleSelftest).where(RuleSelftest.rules_version == rules_version,
                                   RuleSelftest.status.in_(["ok", "misfire"]))).scalars()}
    stats = {"rules_version": rules_version, "tested": 0, "misfires": 0, "errors": 0, "already_tested": 0}
    max_file = get_settings().malware_max_file_bytes
    for product, slug, version in _targets(db, max_core, max_plugins):
        if (product, slug, version) in done:
            stats["already_tested"] += 1
            continue
        status, checked, matches, detail = "ok", 0, [], None
        try:
            checked, matches = check_archive(rules, _download(product, slug, version), max_file)
            if matches:
                status = "misfire"
        except LookupError as exc:
            status, detail = "error", str(exc)
        except Exception as exc:  # noqa: BLE001 - one bad release must not stop the others
            status, detail = "error", f"{type(exc).__name__}: {exc}"[:500]
        stats["tested"] += 1
        if status == "misfire":
            stats["misfires"] += 1
            log.warning("yara_rule_misfire release=%s %s rules=%s", slug, version, sorted({m["rule"] for m in matches}))
        elif status == "error":
            stats["errors"] += 1
        values = {"status": status, "files_checked": checked, "matches": matches[:200], "detail": detail,
                  "checked_at": utcnow()}
        stmt = pg_insert(RuleSelftest).values(rules_version=rules_version, product=product, slug=slug,
                                              version=version, **values)
        db.execute(stmt.on_conflict_do_update(constraint="uq_rule_selftest_release", set_=values))
        db.commit()
    stats["quarantined_rules"] = sorted(quarantined_rules(db, rules_version))
    return stats
