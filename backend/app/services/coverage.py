"""Monitoring coverage: what is actually being monitored for a website, and why not.

Coverage is derived only from verified capabilities and real scan results. A
successful connection does not by itself imply a website is fully monitored.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.connectors.base import CAPABILITY_LABELS, Capability
from app.db.base import utcnow
from app.models import HostingAccount, MonitoringConfig, Website
from app.monitoring.file_scan import capability_status


def freshness(last_ok, interval_minutes: int | None) -> str:
    if last_ok is None:
        return "never"
    if interval_minutes is None:
        return "fresh"
    return "fresh" if utcnow() - last_ok <= timedelta(minutes=interval_minutes * 2 + 30) else "stale"


def website_coverage(db: Session, website: Website, cfg: MonitoringConfig | None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    account = db.get(HostingAccount, website.hosting_account_id) if website.hosting_account_id else None
    caps = capability_status(db, account.id) if account else {}

    # File integrity
    fi: dict[str, Any] = {"key": "file_integrity", "label": "File integrity (SHA-256)"}
    if account is None:
        fi.update(state="unavailable", detail="No hosting connection is associated with this website.")
    elif caps.get(Capability.FILE_LISTING) != "available":
        fi.update(state="unavailable", detail="File listing has not been verified for the hosting connection.")
    elif not (cfg and cfg.file_scan_enabled):
        fi.update(state="disabled", detail="File-integrity scanning is available but not enabled.")
    else:
        f = freshness(website.last_successful_scan_at, cfg.file_scan_interval_minutes)
        hashed = caps.get(Capability.FILE_HASHING) == "available"
        state = {"never": "pending", "stale": "degraded", "fresh": "active"}[f]
        if website.last_scan_status == "partial" and state == "active":
            state = "degraded"
        if website.last_scan_status == "failed":
            state = "failed" if f != "fresh" else "degraded"
        detail = "Hashing file contents." if hashed else "Metadata only (size/time) — content hashing not available."
        if website.last_scan_status == "partial":
            detail += " Last scan was partial; some paths were not inventoried."
        fi.update(state=state, detail=detail, freshness=f, last_success=website.last_successful_scan_at,
                  last_status=website.last_scan_status, hashing=hashed)
    checks.append(fi)

    av: dict[str, Any] = {"key": "availability", "label": "Availability"}
    if not (cfg and cfg.availability_enabled):
        av.update(state="disabled", detail="Availability checks are disabled.")
    else:
        f = freshness(website.last_availability_at, cfg.availability_interval_minutes)
        av.update(state={"never": "pending", "stale": "degraded", "fresh": "active"}[f],
                  detail=f"Every {cfg.availability_interval_minutes} min from the platform.",
                  freshness=f, last_status=website.last_availability_status, last_checked=website.last_availability_at)
    checks.append(av)

    tls: dict[str, Any] = {"key": "tls", "label": "TLS certificate"}
    if not website.url.startswith("https://"):
        tls.update(state="unavailable", detail="Website is not served over HTTPS.")
    elif not (cfg and cfg.tls_enabled):
        tls.update(state="disabled", detail="TLS checks are disabled.")
    else:
        tls.update(state="active" if website.last_tls_status else "pending", detail="Certificate validity and expiry.",
                   last_status=website.last_tls_status, expires_at=website.tls_expires_at)
    checks.append(tls)

    for cap, key in ((Capability.WEBSITE_MALWARE_SCAN, "malware"), (Capability.LOG_ACCESS, "log_analysis"),
                     (Capability.REALTIME_FILE_EVENTS, "realtime_events")):
        status = caps.get(cap, "unsupported" if account else "unavailable")
        checks.append({
            "key": key, "label": CAPABILITY_LABELS[cap],
            "state": "available" if status == "available" else ("unsupported" if status == "unsupported" else "unavailable"),
            "detail": {
                "malware": "Malware scanning is not enabled in this release.",
                "log_analysis": "Log analysis requires verified log access.",
                "realtime_events": "Polling-based monitoring cannot observe changes between scans.",
            }[key],
        })

    for c in checks:
        if c["state"] in ("unavailable", "failed", "degraded", "pending") and c["key"] in ("file_integrity", "availability", "tls"):
            reasons.append(f"{c['label']}: {c['detail']}")
    core = [c for c in checks if c["key"] in ("file_integrity", "availability", "tls")]
    active = sum(1 for c in core if c["state"] == "active")
    if website.status == "paused":
        overall = "paused"
    elif active == len(core):
        overall = "full"
    elif active == 0:
        overall = "none"
    else:
        overall = "partial"
    return {"overall": overall, "checks": checks, "reasons": reasons, "active_core_checks": active,
            "core_checks": len(core)}
