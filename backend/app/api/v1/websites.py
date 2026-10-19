"""Websites, monitoring configuration, on-demand checks, baseline approval."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import TenantContext, require
from app.core.config import get_settings
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.http import pinned_request
from app.core.netguard import DNSResolutionError, TargetNotAllowed, validate_website_url
from app.core.permissions import P
from app.db.base import utcnow
from app.db.session import get_db
from app.models import (
    AvailabilityCheck,
    FileSnapshot,
    HostingAccount,
    MonitoringConfig,
    TlsCheck,
    Website,
    WebsiteGroup,
)
from app.monitoring import jobs
from app.schemas.common import Message, PageParams, paginate
from app.services import audit, entitlements
from app.services.coverage import website_coverage

router = APIRouter(prefix="/tenants/{tenant_id}/websites", tags=["websites"])

VERIFY_PATH = "/.well-known/cyberwatch-verification.txt"


def clean_document_root(v: str | None) -> str | None:
    if v is None or v.strip() in ("", "."):
        return None
    v = v.strip().replace("\\", "/").strip("/")
    if "\x00" in v or any(part == ".." for part in v.split("/")):
        raise ValueError("Document root must be a path inside the hosting account root (no '..').")
    return v


class WebsiteIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=4, max_length=2048)
    environment: str = Field(default="production", pattern="^(production|staging|development|other)$")
    group_id: uuid.UUID | None = None
    hosting_account_id: uuid.UUID | None = None
    document_root: str | None = Field(default=None, max_length=1024)
    technology: str | None = Field(default=None, max_length=80)
    notes: str | None = Field(default=None, max_length=4000)

    @field_validator("document_root")
    @classmethod
    def _docroot(cls, v: str | None) -> str | None:
        return clean_document_root(v)


class WebsitePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    environment: str | None = Field(default=None, pattern="^(production|staging|development|other)$")
    group_id: uuid.UUID | None = None
    hosting_account_id: uuid.UUID | None = None
    document_root: str | None = Field(default=None, max_length=1024)
    technology: str | None = Field(default=None, max_length=80)
    notes: str | None = Field(default=None, max_length=4000)
    clear_group: bool = False
    clear_hosting_account: bool = False

    @field_validator("document_root")
    @classmethod
    def _docroot(cls, v: str | None) -> str | None:
        return clean_document_root(v)


class MonitoringConfigIO(BaseModel):
    file_scan_enabled: bool = False
    file_scan_interval_minutes: int = Field(default=1440, ge=15, le=60 * 24 * 7)
    availability_enabled: bool = True
    availability_interval_minutes: int = Field(default=15, ge=1, le=1440)
    tls_enabled: bool = True
    tls_expiry_warning_days: int = Field(default=21, ge=1, le=90)
    availability_failure_threshold: int = Field(default=2, ge=1, le=10)
    slow_response_ms: int = Field(default=5000, ge=500, le=60000)
    incident_min_severity: str = Field(default="medium", pattern="^(critical|high|medium|low|informational)$")
    exclusions: list[str] = Field(default_factory=list, max_length=200)
    critical_paths: list[str] = Field(default_factory=list, max_length=200)
    max_file_bytes: int | None = Field(default=None, ge=1024, le=512 * 1024 * 1024)
    max_total_mb: int | None = Field(default=None, ge=1, le=100_000)
    max_files: int | None = Field(default=None, ge=10, le=1_000_000)
    maintenance_windows: list[dict] = Field(default_factory=list, max_length=20)

    @field_validator("exclusions", "critical_paths")
    @classmethod
    def _patterns(cls, v: list[str]) -> list[str]:
        out = []
        for p in v:
            p = p.strip()
            if not p:
                continue
            if len(p) > 512 or "\x00" in p or ".." in p.split("/"):
                raise ValueError(f"Invalid pattern: {p[:40]}")
            out.append(p.lstrip("/"))
        return out

    @field_validator("maintenance_windows")
    @classmethod
    def _windows(cls, v: list[dict]) -> list[dict]:
        import re

        out = []
        for w in v:
            start, end = str(w.get("start", "")), str(w.get("end", ""))
            if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", start) or not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", end):
                raise ValueError("Maintenance windows need start/end as HH:MM.")
            wd = w.get("weekday")
            if wd is not None and (not isinstance(wd, int) or not 0 <= wd <= 6):
                raise ValueError("weekday must be 0 (Monday) to 6 (Sunday) or null.")
            out.append({"start": start, "end": end, "weekday": wd, "timezone": str(w.get("timezone") or "Africa/Lagos")[:64],
                        "label": str(w.get("label") or "")[:80]})
        return out


class WebsiteOut(BaseModel):
    id: uuid.UUID
    name: str
    url: str
    hostname: str
    environment: str
    group_id: uuid.UUID | None
    group_name: str | None
    hosting_account_id: uuid.UUID | None
    hosting_account_name: str | None
    document_root: str | None
    technology: str | None
    notes: str | None
    status: str
    verification_status: str
    verified_at: datetime | None
    baseline_snapshot_id: uuid.UUID | None
    baseline_approved_at: datetime | None
    last_scan_at: datetime | None
    last_scan_status: str | None
    last_successful_scan_at: datetime | None
    last_availability_at: datetime | None
    last_availability_status: str | None
    last_tls_status: str | None
    tls_expires_at: datetime | None
    created_at: datetime
    coverage: dict | None = None
    monitoring: MonitoringConfigIO | None = None


def _cfg(db: Session, website_id: uuid.UUID) -> MonitoringConfig | None:
    return db.execute(select(MonitoringConfig).where(MonitoringConfig.website_id == website_id)).scalar_one_or_none()


def website_out(db: Session, w: Website, detail: bool = False) -> WebsiteOut:
    group = db.get(WebsiteGroup, w.group_id) if w.group_id else None
    acct = db.get(HostingAccount, w.hosting_account_id) if w.hosting_account_id else None
    cfg = _cfg(db, w.id)
    out = WebsiteOut(
        id=w.id, name=w.name, url=w.url, hostname=w.hostname, environment=w.environment, group_id=w.group_id,
        group_name=group.name if group else None, hosting_account_id=w.hosting_account_id,
        hosting_account_name=acct.name if acct else None, document_root=w.document_root, technology=w.technology,
        notes=w.notes, status=w.status, verification_status=w.verification_status, verified_at=w.verified_at,
        baseline_snapshot_id=w.baseline_snapshot_id, baseline_approved_at=w.baseline_approved_at,
        last_scan_at=w.last_scan_at, last_scan_status=w.last_scan_status,
        last_successful_scan_at=w.last_successful_scan_at, last_availability_at=w.last_availability_at,
        last_availability_status=w.last_availability_status, last_tls_status=w.last_tls_status,
        tls_expires_at=w.tls_expires_at, created_at=w.created_at,
        coverage=website_coverage(db, w, cfg),
    )
    if detail and cfg:
        out.monitoring = MonitoringConfigIO.model_validate(cfg, from_attributes=True)
    return out


def get_website(db: Session, ctx: TenantContext, website_id: uuid.UUID) -> Website:
    w = db.execute(select(Website).where(Website.id == website_id, Website.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if w is None:
        raise NotFound("Website not found.")
    return w


def _check_refs(db: Session, ctx: TenantContext, group_id: uuid.UUID | None, account_id: uuid.UUID | None) -> None:
    if group_id and not db.execute(select(WebsiteGroup.id).where(WebsiteGroup.id == group_id,
                                                                 WebsiteGroup.tenant_id == ctx.tenant_id)).first():
        raise ValidationFailed("Group not found.")
    if account_id and not db.execute(select(HostingAccount.id).where(HostingAccount.id == account_id,
                                                                     HostingAccount.tenant_id == ctx.tenant_id)).first():
        raise ValidationFailed("Hosting connection not found.")


@router.get("")
def list_websites(
    ctx: TenantContext = Depends(require(P.WEBSITES_READ)),
    db: Session = Depends(get_db),
    params: PageParams = Depends(),
    q: str | None = Query(None, max_length=200),
    status: str | None = Query(None, pattern="^(active|paused)$"),
    environment: str | None = Query(None, max_length=20),
    group_id: uuid.UUID | None = None,
    hosting_account_id: uuid.UUID | None = None,
    sort: str = Query("name", pattern="^-?(name|created_at|last_scan_at|hostname)$"),
) -> dict:
    query = select(Website).where(Website.tenant_id == ctx.tenant_id)
    if q:
        like = f"%{q.lower()}%"
        query = query.where(or_(Website.name.ilike(like), Website.hostname.ilike(like)))
    if status:
        query = query.where(Website.status == status)
    if environment:
        query = query.where(Website.environment == environment)
    if group_id:
        query = query.where(Website.group_id == group_id)
    if hosting_account_id:
        query = query.where(Website.hosting_account_id == hosting_account_id)
    col = getattr(Website, sort.lstrip("-"))
    query = query.order_by(col.desc().nulls_last() if sort.startswith("-") else col.asc().nulls_last(), Website.id)
    return paginate(db, query, params, lambda w: website_out(db, w))


@router.post("", response_model=WebsiteOut, status_code=201)
def create_website(body: WebsiteIn, ctx: TenantContext = Depends(require(P.WEBSITES_MANAGE)),
                   db: Session = Depends(get_db)) -> WebsiteOut:
    try:
        _, hostname, _, url = validate_website_url(body.url)
    except TargetNotAllowed as exc:
        raise ValidationFailed(str(exc), details=[{"field": "url", "message": str(exc)}]) from exc
    if db.execute(select(Website.id).where(Website.tenant_id == ctx.tenant_id, Website.url == url)).first():
        raise Conflict("This website is already registered in your organisation.", code="duplicate_website")
    same_host = db.execute(select(Website.name).where(Website.tenant_id == ctx.tenant_id,
                                                      Website.hostname == hostname)).scalars().first()
    entitlements.require_capacity(db, ctx.tenant_id, "websites")
    _check_refs(db, ctx, body.group_id, body.hosting_account_id)
    w = Website(tenant_id=ctx.tenant_id, name=body.name.strip(), url=url, hostname=hostname,
                environment=body.environment, group_id=body.group_id, hosting_account_id=body.hosting_account_id,
                document_root=body.document_root, technology=body.technology, notes=body.notes,
                verification_token=secrets.token_hex(16))
    db.add(w)
    db.flush()
    ent = entitlements.effective(db, ctx.tenant_id)
    min_av = int(ent.get("min_availability_interval_minutes", 15))
    min_fs = int(ent.get("min_file_scan_interval_minutes", 1440))
    db.add(MonitoringConfig(tenant_id=ctx.tenant_id, website_id=w.id,
                            availability_interval_minutes=max(15, min_av),
                            file_scan_interval_minutes=max(1440, min_fs),
                            file_scan_enabled=False))
    audit.record(db, "website.created", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="website",
                 target_id=w.id, details={"url": url, "same_hostname_as": same_host})
    db.commit()
    out = website_out(db, w, detail=True)
    return out


@router.get("/{website_id}", response_model=WebsiteOut)
def get_one(website_id: uuid.UUID, ctx: TenantContext = Depends(require(P.WEBSITES_READ)),
            db: Session = Depends(get_db)) -> WebsiteOut:
    return website_out(db, get_website(db, ctx, website_id), detail=True)


@router.patch("/{website_id}", response_model=WebsiteOut)
def patch_website(website_id: uuid.UUID, body: WebsitePatch, ctx: TenantContext = Depends(require(P.WEBSITES_MANAGE)),
                  db: Session = Depends(get_db)) -> WebsiteOut:
    w = get_website(db, ctx, website_id)
    _check_refs(db, ctx, body.group_id, body.hosting_account_id)
    data = body.model_dump(exclude_unset=True, exclude={"clear_group", "clear_hosting_account"})
    for k, v in data.items():
        if v is not None:
            setattr(w, k, v)
    if body.clear_group:
        w.group_id = None
    if body.clear_hosting_account:
        w.hosting_account_id = None
    if "hosting_account_id" in data or "document_root" in data or body.clear_hosting_account:
        # A different file source invalidates the baseline.
        w.baseline_snapshot_id = None
    audit.record(db, "website.updated", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="website",
                 target_id=w.id, details={"fields": sorted(data) + (["group_id"] if body.clear_group else [])})
    db.commit()
    return website_out(db, w, detail=True)


@router.delete("/{website_id}", response_model=Message)
def delete_website(website_id: uuid.UUID, ctx: TenantContext = Depends(require(P.WEBSITES_MANAGE)),
                   db: Session = Depends(get_db)) -> Message:
    w = get_website(db, ctx, website_id)
    audit.record(db, "website.deleted", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="website",
                 target_id=w.id, details={"url": w.url})
    db.delete(w)
    db.commit()
    return Message(message="Website removed. Its monitoring history has been deleted.")


@router.post("/{website_id}/pause", response_model=WebsiteOut)
def pause(website_id: uuid.UUID, ctx: TenantContext = Depends(require(P.WEBSITES_MANAGE)),
          db: Session = Depends(get_db)) -> WebsiteOut:
    w = get_website(db, ctx, website_id)
    w.status = "paused"
    audit.record(db, "website.paused", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="website", target_id=w.id)
    db.commit()
    return website_out(db, w, detail=True)


@router.post("/{website_id}/resume", response_model=WebsiteOut)
def resume(website_id: uuid.UUID, ctx: TenantContext = Depends(require(P.WEBSITES_MANAGE)),
           db: Session = Depends(get_db)) -> WebsiteOut:
    w = get_website(db, ctx, website_id)
    w.status = "active"
    audit.record(db, "website.resumed", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="website", target_id=w.id)
    db.commit()
    return website_out(db, w, detail=True)


@router.put("/{website_id}/monitoring", response_model=WebsiteOut)
def put_monitoring(website_id: uuid.UUID, body: MonitoringConfigIO,
                   ctx: TenantContext = Depends(require(P.MONITORING_MANAGE)),
                   db: Session = Depends(get_db)) -> WebsiteOut:
    w = get_website(db, ctx, website_id)
    if body.file_scan_enabled:
        entitlements.clamp_interval(db, ctx.tenant_id, "file_scan", body.file_scan_interval_minutes)
        if w.hosting_account_id is None:
            raise ValidationFailed("Associate a hosting connection before enabling file-integrity scans.")
        from app.monitoring.file_scan import capability_status

        if capability_status(db, w.hosting_account_id).get("file_listing") != "available":
            raise ValidationFailed(
                "File listing has not been verified for this hosting connection. Run a connection test first.",
                code="capability_unavailable",
            )
    if body.availability_enabled:
        entitlements.clamp_interval(db, ctx.tenant_id, "availability", body.availability_interval_minutes)
    cfg = _cfg(db, w.id)
    if cfg is None:
        cfg = MonitoringConfig(tenant_id=ctx.tenant_id, website_id=w.id)
        db.add(cfg)
    before = MonitoringConfigIO.model_validate(cfg, from_attributes=True).model_dump() if cfg.id else {}
    for k, v in body.model_dump().items():
        setattr(cfg, k, v)
    now = utcnow()
    if cfg.file_scan_enabled and cfg.next_file_scan_at is None:
        cfg.next_file_scan_at = now
    if cfg.availability_enabled and cfg.next_availability_at is None:
        cfg.next_availability_at = now
    changed = {k: v for k, v in body.model_dump().items() if before.get(k) != v}
    audit.record(db, "monitoring.config_updated", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="website",
                 target_id=w.id, details={"changed": changed})
    db.commit()
    return website_out(db, w, detail=True)


class ScanRequest(BaseModel):
    check: str = Field(pattern="^(file_scan|availability|tls)$")


class JobRef(BaseModel):
    job_id: uuid.UUID
    status: str
    created: bool
    message: str


@router.post("/{website_id}/checks", response_model=JobRef, status_code=202)
def run_check(website_id: uuid.UUID, body: ScanRequest, ctx: TenantContext = Depends(require(P.SCANS_RUN)),
              db: Session = Depends(get_db)) -> JobRef:
    w = get_website(db, ctx, website_id)
    if w.status != "active":
        raise ValidationFailed("Resume the website before running checks.")
    if not entitlements.effective(db, ctx.tenant_id).in_service:
        raise ValidationFailed("Your subscription is not active; on-demand checks are unavailable.", code="subscription_inactive")
    if body.check == "file_scan":
        if w.hosting_account_id is None:
            raise ValidationFailed("Associate a hosting connection first.")
    if body.check == "tls" and not w.url.startswith("https://"):
        raise ValidationFailed("TLS checks apply only to HTTPS websites.")
    job, created = jobs.enqueue(db, tenant_id=ctx.tenant_id, job_type=body.check, website_id=w.id, trigger="manual",
                                requested_by=ctx.user.id, commit=False)
    audit.record(db, "scan.requested", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="scan_job",
                 target_id=job.id, details={"check": body.check, "website": str(w.id), "created": created})
    db.commit()
    if created:
        jobs.dispatch(job)
    return JobRef(job_id=job.id, status=job.status, created=created,
                  message="Check queued." if created else "A check of this type is already queued or running.")


class BaselineIn(BaseModel):
    snapshot_id: uuid.UUID
    reason: str = Field(min_length=3, max_length=1000)


@router.post("/{website_id}/baseline", response_model=WebsiteOut)
def approve_baseline(website_id: uuid.UUID, body: BaselineIn, ctx: TenantContext = Depends(require(P.BASELINE_APPROVE)),
                     db: Session = Depends(get_db)) -> WebsiteOut:
    w = get_website(db, ctx, website_id)
    snap = db.execute(select(FileSnapshot).where(FileSnapshot.id == body.snapshot_id,
                                                 FileSnapshot.website_id == w.id)).scalar_one_or_none()
    if snap is None:
        raise NotFound("Snapshot not found.")
    if snap.status not in ("completed", "partial"):
        raise ValidationFailed("Only completed or partial snapshots can become the baseline.")
    previous = w.baseline_snapshot_id
    w.baseline_snapshot_id = snap.id
    w.baseline_approved_by = ctx.user.id
    w.baseline_approved_at = utcnow()
    audit.record(db, "baseline.approved", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="website",
                 target_id=w.id, details={"snapshot": str(snap.id), "previous": str(previous) if previous else None,
                                          "snapshot_status": snap.status, "reason": body.reason})
    db.commit()
    return website_out(db, w, detail=True)


class VerificationOut(BaseModel):
    status: str
    method: str
    path: str
    token: str | None
    message: str


@router.get("/{website_id}/verification", response_model=VerificationOut)
def verification_instructions(website_id: uuid.UUID, ctx: TenantContext = Depends(require(P.WEBSITES_READ)),
                              db: Session = Depends(get_db)) -> VerificationOut:
    w = get_website(db, ctx, website_id)
    return VerificationOut(status=w.verification_status, method="http_file", path=VERIFY_PATH,
                           token=w.verification_token,
                           message=f"Publish a file at {w.url.rstrip('/')}{VERIFY_PATH} whose content is the token.")


@router.post("/{website_id}/verify", response_model=VerificationOut)
def verify_ownership(website_id: uuid.UUID, ctx: TenantContext = Depends(require(P.WEBSITES_MANAGE)),
                     db: Session = Depends(get_db)) -> VerificationOut:
    w = get_website(db, ctx, website_id)
    scheme = "https" if w.url.startswith("https://") else "http"
    port_part = ""
    check_url = f"{scheme}://{w.hostname}{port_part}{VERIFY_PATH}"
    ok = False
    message = ""
    try:
        resp = pinned_request("GET", check_url, allowed_ports=get_settings().allowed_http_ports, timeout=10,
                              max_redirects=2, max_body_bytes=1024)
        ok = resp.status_code == 200 and resp.body.decode("utf-8", "ignore").strip() == (w.verification_token or "")
        message = "Verified." if ok else f"Token not found (HTTP {resp.status_code})."
    except (TargetNotAllowed, DNSResolutionError) as exc:
        message = str(exc)
    except Exception as exc:  # noqa: BLE001
        message = f"Could not fetch the verification file ({type(exc).__name__})."
    if ok:
        w.verification_status, w.verified_at = "verified", utcnow()
    audit.record(db, "website.verification_attempt", actor=ctx.actor(), tenant_id=ctx.tenant_id,
                 target_type="website", target_id=w.id, outcome="success" if ok else "failure",
                 details={"message": message})
    db.commit()
    return VerificationOut(status=w.verification_status, method="http_file", path=VERIFY_PATH,
                           token=w.verification_token, message=message)


class AvailabilityOut(BaseModel):
    checked_at: datetime
    outcome: str
    http_status: int | None
    response_ms: int | None
    error_class: str | None
    error_message: str | None


class TlsOut(BaseModel):
    checked_at: datetime
    outcome: str
    valid_from: datetime | None
    valid_to: datetime | None
    days_remaining: int | None
    issuer: str | None
    subject: str | None
    protocol: str | None
    error_message: str | None


@router.get("/{website_id}/availability", response_model=list[AvailabilityOut])
def availability_history(website_id: uuid.UUID, ctx: TenantContext = Depends(require(P.MONITORING_READ)),
                         db: Session = Depends(get_db), limit: int = Query(200, ge=1, le=2000)) -> list[AvailabilityOut]:
    w = get_website(db, ctx, website_id)
    rows = db.execute(select(AvailabilityCheck).where(AvailabilityCheck.website_id == w.id)
                      .order_by(AvailabilityCheck.checked_at.desc()).limit(limit)).scalars()
    return [AvailabilityOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/{website_id}/tls", response_model=list[TlsOut])
def tls_history(website_id: uuid.UUID, ctx: TenantContext = Depends(require(P.MONITORING_READ)),
                db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=500)) -> list[TlsOut]:
    w = get_website(db, ctx, website_id)
    rows = db.execute(select(TlsCheck).where(TlsCheck.website_id == w.id)
                      .order_by(TlsCheck.checked_at.desc()).limit(limit)).scalars()
    return [TlsOut.model_validate(r, from_attributes=True) for r in rows]
