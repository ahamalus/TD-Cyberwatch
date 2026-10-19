"""Report generation (C10): CSV and PDF, from stored monitoring data only."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import utcnow
from app.models import (
    AvailabilityCheck,
    FileChange,
    FileSnapshot,
    Incident,
    MonitoringConfig,
    Report,
    Tenant,
    TlsCheck,
    Website,
)
from app.services import storage
from app.services.coverage import website_coverage

REPORT_TYPES = {
    "security_summary": "Website security summary",
    "file_integrity": "File-integrity report",
    "incidents": "Incident and malware report",
    "availability_tls": "Availability and TLS report",
    "coverage": "Monitoring coverage report",
}

DISCLAIMER = (
    "This report reflects automated monitoring results available to {product} at the time of generation. "
    "Monitoring detects changes between scans and cannot guarantee detection of every compromise, transient "
    "change or malware. Heuristic findings require human verification. Checks marked unavailable or partial "
    "were not performed in full."
)


def _csv_safe(value: Any) -> str:
    s = "" if value is None else (value.isoformat() if isinstance(value, datetime) else str(value))
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def collect(db: Session, tenant_id: uuid.UUID, report_type: str, website_id: uuid.UUID | None,
            start: datetime, end: datetime) -> tuple[list[str], list[list[Any]], dict[str, Any]]:
    sites_q = select(Website).where(Website.tenant_id == tenant_id)
    if website_id:
        sites_q = sites_q.where(Website.id == website_id)
    sites = db.execute(sites_q.order_by(Website.name)).scalars().all()
    ids = [w.id for w in sites]
    names = {w.id: w.name for w in sites}
    summary: dict[str, Any] = {"websites": len(sites)}

    if report_type == "file_integrity":
        header = ["detected_at_utc", "website", "path", "change", "severity", "confidence", "flags", "old_sha256", "new_sha256"]
        rows = [[c.detected_at, names.get(c.website_id), c.path, c.change_type, c.severity, c.confidence,
                 ";".join(c.flags), c.old_sha256, c.new_sha256]
                for c in db.execute(select(FileChange).where(FileChange.website_id.in_(ids), FileChange.detected_at >= start,
                                                             FileChange.detected_at <= end)
                                    .order_by(FileChange.detected_at)).scalars()]
        scans = db.execute(select(FileSnapshot.status, func.count()).where(
            FileSnapshot.website_id.in_(ids), FileSnapshot.started_at >= start, FileSnapshot.started_at <= end)
            .group_by(FileSnapshot.status)).all()
        summary.update({"changes": len(rows), "scans": dict(scans)})
    elif report_type == "incidents":
        header = ["reference", "first_detected_utc", "last_observed_utc", "website", "severity", "category",
                  "finding_class", "confidence", "status", "title", "false_positive"]
        rows = [[i.reference, i.first_detected_at, i.last_observed_at, names.get(i.website_id), i.severity, i.category,
                 i.finding_class, i.confidence, i.status, i.title, i.is_false_positive]
                for i in db.execute(select(Incident).where(Incident.tenant_id == tenant_id,
                                                           Incident.first_detected_at >= start,
                                                           Incident.first_detected_at <= end,
                                                           *( [Incident.website_id == website_id] if website_id else []))
                                    .order_by(Incident.first_detected_at)).scalars()]
        summary["incidents"] = len(rows)
    elif report_type == "availability_tls":
        header = ["website", "checks", "up", "degraded", "down_or_error", "availability_pct", "avg_response_ms",
                  "tls_status", "tls_expires_utc"]
        rows = []
        for w in sites:
            stats = dict(db.execute(select(AvailabilityCheck.outcome, func.count()).where(
                AvailabilityCheck.website_id == w.id, AvailabilityCheck.checked_at >= start,
                AvailabilityCheck.checked_at <= end).group_by(AvailabilityCheck.outcome)).all())
            total = sum(stats.values())
            avg = db.execute(select(func.avg(AvailabilityCheck.response_ms)).where(
                AvailabilityCheck.website_id == w.id, AvailabilityCheck.checked_at >= start,
                AvailabilityCheck.checked_at <= end)).scalar()
            last_tls = db.execute(select(TlsCheck).where(TlsCheck.website_id == w.id)
                                  .order_by(TlsCheck.checked_at.desc()).limit(1)).scalar_one_or_none()
            up = stats.get("up", 0) + stats.get("degraded", 0)
            rows.append([w.name, total, stats.get("up", 0), stats.get("degraded", 0),
                         stats.get("down", 0) + stats.get("error", 0),
                         f"{100 * up / total:.2f}" if total else "no data", int(avg) if avg else "",
                         last_tls.outcome if last_tls else "not checked", last_tls.valid_to if last_tls else ""])
    elif report_type in ("coverage", "security_summary"):
        header = ["website", "status", "coverage", "file_integrity", "availability", "tls", "last_successful_scan_utc",
                  "open_incidents", "baseline_approved_utc"]
        rows = []
        for w in sites:
            cfg = db.execute(select(MonitoringConfig).where(MonitoringConfig.website_id == w.id)).scalar_one_or_none()
            cov = website_coverage(db, w, cfg)
            states = {c["key"]: c["state"] for c in cov["checks"]}
            open_inc = db.execute(select(func.count()).select_from(Incident).where(
                Incident.website_id == w.id, Incident.status.in_(["new", "acknowledged", "investigating", "contained"]))).scalar_one()
            rows.append([w.name, w.status, cov["overall"], states.get("file_integrity"), states.get("availability"),
                         states.get("tls"), w.last_successful_scan_at, open_inc, w.baseline_approved_at])
        if report_type == "security_summary":
            sev = dict(db.execute(select(Incident.severity, func.count()).where(
                Incident.tenant_id == tenant_id, Incident.first_detected_at >= start, Incident.first_detected_at <= end)
                .group_by(Incident.severity)).all())
            chg = db.execute(select(func.count()).select_from(FileChange).where(
                FileChange.tenant_id == tenant_id, FileChange.detected_at >= start, FileChange.detected_at <= end)).scalar_one()
            summary.update({"incidents_by_severity": sev, "file_changes": chg})
    else:
        raise ValueError("Unknown report type")
    return header, rows, summary


def render_csv(header: list[str], rows: list[list[Any]], meta: dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([f"# {meta['title']} — {meta['tenant']} — generated {meta['generated_at']} UTC"])
    w.writerow([f"# Period: {meta['start']} to {meta['end']} UTC"])
    w.writerow([f"# {meta['disclaimer']}"])
    w.writerow(header)
    for r in rows:
        w.writerow([_csv_safe(x) for x in r])
    return buf.getvalue().encode("utf-8")


def render_pdf(header: list[str], rows: list[list[Any]], meta: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm, title=meta["title"],
                            author=get_settings().company_name)
    styles = getSampleStyleSheet()
    navy = colors.HexColor("#0B1220")
    blue = colors.HexColor("#1677FF")
    story = [
        Paragraph("<font color='#1677FF'><b>TrustData</b></font> <b>CyberWatch</b>", styles["Title"]),
        Paragraph(f"{meta['title']} — {meta['tenant']}", styles["Heading2"]),
        Paragraph(f"Period {meta['start']} to {meta['end']} (UTC). Generated {meta['generated_at']} UTC.", styles["Normal"]),
    ]
    if meta.get("is_demo"):
        story.append(Paragraph("<font color='#DC4545'><b>DEMONSTRATION DATA — not real monitoring results.</b></font>",
                               styles["Normal"]))
    story.append(Spacer(1, 6 * mm))
    small = styles["BodyText"].clone("small", fontSize=7, leading=8.5)
    data = [[Paragraph(f"<b>{h.replace('_', ' ')}</b>", small) for h in header]]
    for r in rows[:5000]:
        data.append([Paragraph(_csv_safe(x)[:200].replace("&", "&amp;").replace("<", "&lt;"), small) for x in r])
    if len(data) == 1:
        data.append([Paragraph("No records in this period.", small)] + [""] * (len(header) - 1))
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FB")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(f"<font color='#64748B'>{meta['disclaimer']}</font>", small))
    story.append(Paragraph(f"<font color='{blue.hexval()}'>{get_settings().company_name}</font>", small))
    doc.build(story)
    return buf.getvalue()


def generate(db: Session, tenant: Tenant, report_type: str, fmt: str, website_id: uuid.UUID | None,
             start: datetime, end: datetime, user_id: uuid.UUID | None) -> Report:
    s = get_settings()
    report = Report(tenant_id=tenant.id, report_type=report_type, title=REPORT_TYPES[report_type], format=fmt,
                    website_id=website_id, period_start=start, period_end=end, generated_by=user_id, status="running")
    db.add(report)
    db.flush()
    try:
        header, rows, summary = collect(db, tenant.id, report_type, website_id, start, end)
        meta = {"title": REPORT_TYPES[report_type], "tenant": tenant.name, "generated_at": f"{utcnow():%Y-%m-%d %H:%M}",
                "start": f"{start:%Y-%m-%d}", "end": f"{end:%Y-%m-%d}", "is_demo": tenant.is_demo,
                "disclaimer": DISCLAIMER.format(product=s.product_name)}
        data = render_pdf(header, rows, meta) if fmt == "pdf" else render_csv(header, rows, meta)
        key, digest, size = storage.put(tenant.id, "reports", fmt, data)
        report.object_key, report.content_sha256, report.size_bytes = key, digest, size
        report.status, report.generated_at = "ready", utcnow()
    except Exception as exc:  # noqa: BLE001
        report.status, report.error = "failed", f"Report generation failed ({type(exc).__name__})."
    return report
