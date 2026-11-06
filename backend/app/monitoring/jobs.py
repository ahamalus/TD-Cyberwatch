"""Persistent monitoring jobs: enqueue, claim, execute, retry and recover.

The ``scan_jobs`` table is the source of truth; Celery only carries job IDs.

Concurrency control:

* A partial unique index allows only one queued/running job per
  (website, job type) or (hosting account, job type), so overlapping scans
  cannot corrupt a baseline. Enqueueing a duplicate returns the active job.
* Claiming is an atomic ``UPDATE ... WHERE status='queued'`` so two workers
  cannot run the same job.
* A per-tenant cap on running jobs defers excess work.
* Stale running jobs (no heartbeat) are recovered by ``recover_stale_jobs``.

A job never ends as ``succeeded`` unless its handler returned normally; any
exception ends in ``failed`` (or a bounded retry).
"""

from __future__ import annotations

import os
import random
import socket
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.connectors.base import RETRYABLE_CODES, ConnectorError
from app.connectors.registry import build_connector
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.session import platform_session, tenant_session
from app.models import (
    AvailabilityCheck,
    CapabilityDiscovery,
    ConnectorCapability,
    ConnectorDefinition,
    HostingAccount,
    HostingCredential,
    MonitoringConfig,
    ScanJob,
    Tenant,
    TlsCheck,
    Website,
)
from app.monitoring.availability import check_availability, check_tls
from app.monitoring.file_scan import ScanPreconditionFailed, run_file_scan
from app.services import audit
from app.services import incidents as incident_svc
from app.services.audit import AuditActor
from app.services.incidents import DetectionSpec, EvidenceSpec

log = get_logger(__name__)

QUEUE_FOR = {
    "file_scan": "monitoring",
    "connection_test": "monitoring",
    "capability_discovery": "monitoring",
    "availability": "checks",
    "tls": "checks",
}

Dispatcher = Callable[[ScanJob, int], None]


def _celery_dispatch(job: ScanJob, countdown: int = 0) -> None:
    from app.workers.tasks import run_scan_job

    run_scan_job.apply_async(args=[str(job.id)], queue=QUEUE_FOR[job.job_type], countdown=countdown)


_dispatcher: Dispatcher | None = None


def set_dispatcher(dispatcher: Dispatcher | None) -> None:
    global _dispatcher
    _dispatcher = dispatcher


def dispatch(job: ScanJob, countdown: int = 0) -> None:
    (_dispatcher or _celery_dispatch)(job, countdown)


class JobCancelled(Exception):
    pass


def worker_name() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


# --------------------------------------------------------------------------
# Enqueue
# --------------------------------------------------------------------------


def enqueue(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    job_type: str,
    website_id: uuid.UUID | None = None,
    hosting_account_id: uuid.UUID | None = None,
    trigger: str = "schedule",
    requested_by: uuid.UUID | None = None,
    commit: bool = True,
) -> tuple[ScanJob, bool]:
    """Create a queued job. Returns (job, created). Duplicates return the active job."""
    job = ScanJob(
        tenant_id=tenant_id,
        job_type=job_type,
        website_id=website_id,
        hosting_account_id=hosting_account_id,
        trigger=trigger,
        requested_by=requested_by,
        status="queued",
        max_attempts=get_settings().job_max_attempts,
    )
    try:
        with db.begin_nested():
            db.add(job)
            db.flush()
    except IntegrityError:
        q = select(ScanJob).where(ScanJob.job_type == job_type, ScanJob.status.in_(["queued", "running"]))
        q = q.where(ScanJob.website_id == website_id) if website_id else q.where(
            ScanJob.hosting_account_id == hosting_account_id, ScanJob.website_id.is_(None)
        )
        existing = db.execute(q).scalar_one_or_none()
        if existing is None:
            raise
        return existing, False
    if commit:
        db.commit()
        dispatch(job)
    return job, True


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def _heartbeat_fn(job_id: uuid.UUID) -> Callable[[], None]:
    def beat() -> None:
        with platform_session() as s:
            row = s.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(heartbeat_at=utcnow())
                .returning(ScanJob.cancel_requested)
            ).first()
            s.commit()
        if row and row.cancel_requested:
            raise JobCancelled()

    return beat


def claim(job_id: uuid.UUID, worker: str) -> ScanJob | None:
    settings = get_settings()
    with platform_session() as s:
        job = s.get(ScanJob, job_id)
        if job is None or job.status != "queued":
            return None
        if job.cancel_requested:
            job.status, job.finished_at, job.error_class = "cancelled", utcnow(), "cancelled"
            s.commit()
            return None
        now = utcnow()
        if job.not_before and job.not_before > now:
            return None
        # Per-tenant concurrency: serialise the check per tenant.
        s.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"jobs:{job.tenant_id}"})
        running = s.execute(
            select(func.count()).select_from(ScanJob).where(
                ScanJob.tenant_id == job.tenant_id, ScanJob.status == "running"
            )
        ).scalar_one()
        if running >= settings.tenant_max_concurrent_jobs:
            job.not_before = now + timedelta(seconds=30 + random.randint(0, 30))  # noqa: S311
            s.commit()
            dispatch(job, countdown=45)
            return None
        res = s.execute(
            update(ScanJob)
            .where(ScanJob.id == job_id, ScanJob.status == "queued")
            .values(
                status="running",
                started_at=now,
                heartbeat_at=now,
                attempts=ScanJob.attempts + 1,
                worker=worker,
                error_class=None,
                error_message=None,
            )
        )
        s.commit()
        if res.rowcount != 1:
            return None
        s.refresh(job)
        s.expunge(job)
        return job


def _finish(job_id: uuid.UUID, status: str, *, summary: dict | None = None, error_class: str | None = None,
            error_message: str | None = None, retry_in: int | None = None) -> None:
    with platform_session() as s:
        job = s.get(ScanJob, job_id)
        if job is None:
            return
        job.heartbeat_at = utcnow()
        if retry_in is not None:
            job.status = "queued"
            job.not_before = utcnow() + timedelta(seconds=retry_in)
            job.queued_at = utcnow()
        else:
            job.status = status
            job.finished_at = utcnow()
        job.error_class = error_class
        job.error_message = (error_message or "")[:2000] or None
        if summary is not None:
            job.result_summary = summary
        s.commit()
        if retry_in is not None:
            dispatch(job, countdown=retry_in)


def backoff_seconds(attempt: int) -> int:
    base = min(60 * (2 ** max(attempt - 1, 0)), 1800)
    return int(base + random.uniform(0, base * 0.25))  # noqa: S311


HANDLERS: dict[str, Callable[[Session, ScanJob, Callable[[], None]], tuple[str, dict]]] = {}


def handler(job_type: str):
    def deco(fn):
        HANDLERS[job_type] = fn
        return fn

    return deco


def run_job(job_id: uuid.UUID | str, worker: str | None = None) -> str | None:
    """Claim and execute one job. Returns the final status, or None if not claimed."""
    job_id = uuid.UUID(str(job_id))
    job = claim(job_id, worker or worker_name())
    if job is None:
        return None
    beat = _heartbeat_fn(job.id)
    fn = HANDLERS[job.job_type]
    try:
        with tenant_session(job.tenant_id) as db:
            job_row = db.get(ScanJob, job.id)
            assert job_row is not None
            status, summary = fn(db, job_row, beat)
            db.commit()
        _finish(job.id, status, summary=summary)
        return status
    except JobCancelled:
        _finish(job.id, "cancelled", error_class="cancelled", error_message="Cancelled by an operator.")
        return "cancelled"
    except ScanPreconditionFailed as exc:
        _finish(job.id, "failed", error_class=exc.code, error_message=exc.message)
        return "failed"
    except ConnectorError as exc:
        retryable = exc.retryable or exc.code in RETRYABLE_CODES
        if retryable and job.attempts < job.max_attempts:
            _finish(job.id, "queued", error_class=exc.code, error_message=exc.message,
                    retry_in=backoff_seconds(job.attempts))
            return "retrying"
        _finish(job.id, "failed", error_class=exc.code, error_message=exc.message)
        _on_final_failure(job, exc.code, exc.message)
        return "failed"
    except Exception as exc:  # noqa: BLE001
        log.exception("job_failed", job_id=str(job.id), job_type=job.job_type)
        if job.attempts < job.max_attempts:
            _finish(job.id, "queued", error_class="internal_error", error_message=type(exc).__name__,
                    retry_in=backoff_seconds(job.attempts))
            return "retrying"
        _finish(job.id, "failed", error_class="internal_error",
                error_message=f"Unexpected error ({type(exc).__name__}). See worker logs.")
        return "failed"


def _on_final_failure(job: ScanJob, code: str, message: str) -> None:
    """Raise a monitoring-failure incident when a scan cannot run."""
    if job.job_type != "file_scan" or job.website_id is None:
        return
    with tenant_session(job.tenant_id) as db:
        website = db.get(Website, job.website_id)
        if website is None:
            return
        severity = "high" if code == "host_key_mismatch" else "medium"
        incident_svc.raise_detection(
            db,
            DetectionSpec(
                tenant_id=job.tenant_id,
                website_id=website.id,
                hosting_account_id=website.hosting_account_id,
                title=f"File-integrity monitoring failed for {website.name}",
                summary=f"The scheduled file scan could not complete: {message} Monitoring coverage is reduced until this is resolved.",
                category="connection",
                finding_class="configuration_issue",
                severity=severity,
                confidence="high",
                detection_source="monitoring_engine",
                rule_key=f"scan_failure:{code}",
                dedupe_key=f"scan_failure:{website.id}",
                recommended_action=(
                    "Verify the server's new host key with your hosting provider before re-trusting it."
                    if code == "host_key_mismatch"
                    else "Run a connection test from Hosting Connections and update the credentials if needed."
                ),
                requires_human_verification=False,
                evidence=[EvidenceSpec("note", "monitoring_engine", "job_result",
                                       {"job_id": str(job.id), "error_code": code, "message": message}, job.id)],
            ),
        )
        db.commit()


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------


def _account_bundle(db: Session, account_id: uuid.UUID):
    account = db.get(HostingAccount, account_id)
    if account is None:
        raise ScanPreconditionFailed("hosting_account_missing", "The hosting connection no longer exists.")
    cred = db.execute(
        select(HostingCredential).where(HostingCredential.hosting_account_id == account.id)
    ).scalar_one_or_none()
    definition = db.get(ConnectorDefinition, account.connector_type)
    return account, cred, definition


@handler("connection_test")
@handler("capability_discovery")
def handle_connection_test(db: Session, job: ScanJob, beat: Callable[[], None]) -> tuple[str, dict]:
    account, cred, definition = _account_bundle(db, job.hosting_account_id)
    connector = build_connector(account, cred, definition)
    now = utcnow()
    result = connector.test_connection()
    account.last_tested_at = now
    summary: dict[str, Any] = {"ok": result.ok, "diagnostics": [d.as_dict() for d in result.diagnostics]}
    if result.host_key_fingerprint and not account.host_key_fingerprint and result.ok:
        # Trust on first use; recorded and audited.
        account.host_key_fingerprint = result.host_key_fingerprint
        account.host_key_type = result.host_key_type
        account.host_key_confirmed_at = now
        audit.record(db, "hosting.host_key_trusted", tenant_id=account.tenant_id, target_type="hosting_account",
                     target_id=account.id, details={"fingerprint": result.host_key_fingerprint})
    if not result.ok:
        account.status = {
            "auth_failed": "auth_failed",
            "host_key_mismatch": "error",
            "timeout": "disconnected",
            "connection_refused": "disconnected",
            "dns_failure": "disconnected",
        }.get(result.error_code or "", "error")
        account.last_error_code = result.error_code
        account.last_error_message = result.error_message
        db.add(CapabilityDiscovery(tenant_id=account.tenant_id, hosting_account_id=account.id, scan_job_id=job.id,
                                   success=False, connector_version=connector.version, profile={},
                                   diagnostics=summary["diagnostics"]))
        db.commit()
        if result.error_code == "host_key_mismatch":
            incident_svc.raise_detection(db, DetectionSpec(
                tenant_id=account.tenant_id, website_id=None, hosting_account_id=account.id,
                title=f"SSH host key changed for {account.name}",
                summary="The server presented a different host key from the one trusted earlier. Connections are blocked until an administrator re-trusts the key.",
                category="connection", finding_class="suspected_compromise", severity="high", confidence="medium",
                detection_source="connector", rule_key="host_key_mismatch", dedupe_key=f"host_key:{account.id}",
                recommended_action="Confirm with your hosting provider whether the server was rebuilt before re-trusting the new key.",
            ))
        retryable = result.error_code in RETRYABLE_CODES
        if retryable and job.attempts < job.max_attempts:
            raise ConnectorError(result.error_code or "error", result.error_message or "Connection failed.", retryable=True)
        return "failed", summary

    account.status = "connected"
    account.last_success_at = now
    account.last_error_code = None
    account.last_error_message = None
    beat()
    try:
        caps = connector.discover_capabilities()
    except ConnectorError as exc:
        summary["capability_error"] = exc.message
        db.add(CapabilityDiscovery(tenant_id=account.tenant_id, hosting_account_id=account.id, scan_job_id=job.id,
                                   success=False, connector_version=connector.version, profile={},
                                   diagnostics=summary["diagnostics"]))
        return "partial", summary
    profile = {}
    for c in caps:
        profile[c.capability.value] = {"status": c.status, "detail": c.detail}
        row = db.execute(
            select(ConnectorCapability).where(
                ConnectorCapability.hosting_account_id == account.id,
                ConnectorCapability.capability == c.capability.value,
            )
        ).scalar_one_or_none()
        if row is None:
            row = ConnectorCapability(tenant_id=account.tenant_id, hosting_account_id=account.id,
                                      capability=c.capability.value, status=c.status, detail=c.detail,
                                      connector_version=connector.version)
            db.add(row)
        row.status, row.detail, row.required_permission = c.status, c.detail, c.required_permission
        row.discovered_at, row.connector_version = now, connector.version
    db.add(CapabilityDiscovery(tenant_id=account.tenant_id, hosting_account_id=account.id, scan_job_id=job.id,
                               success=True, connector_version=connector.version, profile=profile,
                               diagnostics=summary["diagnostics"]))
    summary["capabilities"] = profile
    audit.record(db, "hosting.capabilities_discovered", tenant_id=account.tenant_id, target_type="hosting_account",
                 target_id=account.id, details={k: v["status"] for k, v in profile.items()})
    return "succeeded", summary


@handler("file_scan")
def handle_file_scan(db: Session, job: ScanJob, beat: Callable[[], None]) -> tuple[str, dict]:
    outcome = run_file_scan(db, job, heartbeat=beat)
    status = {"completed": "succeeded", "partial": "partial", "failed": "failed"}[outcome.status]
    return status, outcome.summary


@handler("availability")
def handle_availability(db: Session, job: ScanJob, beat: Callable[[], None]) -> tuple[str, dict]:
    website = db.get(Website, job.website_id)
    if website is None:
        raise ScanPreconditionFailed("website_missing", "The website no longer exists.")
    cfg = db.execute(select(MonitoringConfig).where(MonitoringConfig.website_id == website.id)).scalar_one_or_none()
    res = check_availability(website.url, slow_ms=cfg.slow_response_ms if cfg else 5000)
    db.add(AvailabilityCheck(
        tenant_id=website.tenant_id, website_id=website.id, scan_job_id=job.id, outcome=res.outcome,
        http_status=res.http_status, response_ms=res.response_ms, resolved_ip=res.resolved_ip,
        final_url=res.final_url, redirects=res.redirects, error_class=res.error_class,
        error_message=res.error_message,
    ))
    website.last_availability_at = utcnow()
    website.last_availability_status = res.outcome
    if res.outcome in ("down", "error"):
        website.consecutive_availability_failures += 1
    else:
        website.consecutive_availability_failures = 0
    threshold = cfg.availability_failure_threshold if cfg else 2
    if res.outcome == "down" and website.consecutive_availability_failures >= threshold:
        tenant = db.get(Tenant, website.tenant_id)
        incident_svc.raise_detection(db, DetectionSpec(
            tenant_id=website.tenant_id, website_id=website.id,
            title=f"{website.name} is unavailable",
            summary=f"{website.consecutive_availability_failures} consecutive availability checks failed: {res.error_message or res.error_class}.",
            category="availability", finding_class="availability_problem",
            severity="high" if website.environment == "production" else "medium", confidence="high",
            detection_source="availability_check", rule_key=f"availability:{res.error_class}",
            dedupe_key=f"availability:{website.id}",
            recommended_action="Check the web server, hosting account status and DNS. Unexpected downtime can follow a compromise.",
            requires_human_verification=False,
            evidence=[EvidenceSpec("availability_check", "availability_check", "http_probe_from_platform", {
                "url": website.url, "outcome": res.outcome, "http_status": res.http_status,
                "error_class": res.error_class, "error": res.error_message, "resolved_ip": res.resolved_ip,
                "checked_at": utcnow()})],
            is_demo=bool(tenant and tenant.is_demo),
        ))
    return ("succeeded" if res.outcome != "error" else "failed"), {
        "outcome": res.outcome, "http_status": res.http_status, "response_ms": res.response_ms,
        "error_class": res.error_class,
    }


@handler("tls")
def handle_tls(db: Session, job: ScanJob, beat: Callable[[], None]) -> tuple[str, dict]:
    website = db.get(Website, job.website_id)
    if website is None:
        raise ScanPreconditionFailed("website_missing", "The website no longer exists.")
    cfg = db.execute(select(MonitoringConfig).where(MonitoringConfig.website_id == website.id)).scalar_one_or_none()
    res = check_tls(website.url, warning_days=cfg.tls_expiry_warning_days if cfg else 21)
    db.add(TlsCheck(
        tenant_id=website.tenant_id, website_id=website.id, scan_job_id=job.id, outcome=res.outcome,
        valid_from=res.valid_from, valid_to=res.valid_to, days_remaining=res.days_remaining, issuer=res.issuer,
        subject=res.subject, san=res.san, protocol=res.protocol, error_message=res.error_message,
    ))
    website.last_tls_status = res.outcome
    website.tls_expires_at = res.valid_to
    if res.outcome in ("expired", "invalid", "expiring"):
        sev = {"expired": "high", "invalid": "high", "expiring": "medium" if (res.days_remaining or 0) > 7 else "high"}[res.outcome]
        tenant = db.get(Tenant, website.tenant_id)
        incident_svc.raise_detection(db, DetectionSpec(
            tenant_id=website.tenant_id, website_id=website.id,
            title=f"TLS certificate {res.outcome} for {website.hostname}",
            summary=res.error_message or f"Certificate status: {res.outcome}.",
            category="tls", finding_class="configuration_issue", severity=sev, confidence="high",
            detection_source="tls_check", rule_key=f"tls:{res.outcome}", dedupe_key=f"tls:{website.id}",
            recommended_action="Renew or reinstall the certificate (for cPanel: SSL/TLS Status → Run AutoSSL).",
            requires_human_verification=False,
            evidence=[EvidenceSpec("tls_check", "tls_check", "tls_handshake_from_platform", {
                "hostname": website.hostname, "outcome": res.outcome, "valid_to": res.valid_to,
                "issuer": res.issuer, "error": res.error_message})],
            is_demo=bool(tenant and tenant.is_demo),
        ))
    return ("failed" if res.outcome == "error" else "succeeded"), {
        "outcome": res.outcome, "days_remaining": res.days_remaining, "error": res.error_message,
    }


# --------------------------------------------------------------------------
# Operator actions and maintenance
# --------------------------------------------------------------------------


def request_cancel(db: Session, job: ScanJob, actor: AuditActor) -> ScanJob:
    if job.status == "queued":
        job.status, job.finished_at, job.error_class = "cancelled", utcnow(), "cancelled"
        job.error_message = "Cancelled before start."
    elif job.status == "running":
        job.cancel_requested = True
    audit.record(db, "job.cancel_requested", actor=actor, tenant_id=job.tenant_id, target_type="scan_job",
                 target_id=job.id, details={"status": job.status})
    return job


def retry_job(db: Session, job: ScanJob, actor: AuditActor) -> tuple[ScanJob, bool]:
    if job.status not in ("failed", "cancelled", "partial"):
        from app.core.errors import ValidationFailed

        raise ValidationFailed("Only failed, partial or cancelled jobs can be retried.")
    new, created = enqueue(db, tenant_id=job.tenant_id, job_type=job.job_type, website_id=job.website_id,
                           hosting_account_id=job.hosting_account_id, trigger="manual",
                           requested_by=actor.user_id, commit=False)
    audit.record(db, "job.retried", actor=actor, tenant_id=job.tenant_id, target_type="scan_job",
                 target_id=job.id, details={"new_job": str(new.id), "created": created})
    return new, created


def recover_stale_jobs() -> dict[str, int]:
    settings = get_settings()
    cutoff = utcnow() - timedelta(seconds=settings.job_stale_after_seconds)
    stats = {"requeued": 0, "failed": 0, "redispatched": 0}
    with platform_session() as s:
        stale = s.execute(
            select(ScanJob).where(ScanJob.status == "running", ScanJob.heartbeat_at < cutoff).with_for_update(skip_locked=True)
        ).scalars().all()
        for job in stale:
            if job.attempts < job.max_attempts:
                job.status, job.not_before = "queued", utcnow()
                job.error_class, job.error_message = "worker_lost", "Worker stopped responding; job re-queued."
                stats["requeued"] += 1
            else:
                job.status, job.finished_at = "failed", utcnow()
                job.error_class, job.error_message = "worker_lost", "Worker stopped responding; retries exhausted."
                stats["failed"] += 1
        # Queued jobs whose broker message may have been lost.
        lost = s.execute(
            select(ScanJob).where(
                ScanJob.status == "queued",
                ScanJob.queued_at < utcnow() - timedelta(minutes=10),
                (ScanJob.not_before.is_(None)) | (ScanJob.not_before < utcnow() - timedelta(minutes=10)),
            ).limit(500)
        ).scalars().all()
        s.commit()
        for job in stale:
            if job.status == "queued":
                dispatch(job)
        for job in lost:
            dispatch(job)
            stats["redispatched"] += 1
    return stats


def _in_maintenance(cfg: MonitoringConfig, now) -> bool:
    from zoneinfo import ZoneInfo

    for w in cfg.maintenance_windows or []:
        try:
            tz = ZoneInfo(w.get("timezone") or "Africa/Lagos")
            local = now.astimezone(tz)
            if w.get("weekday") is not None and int(w["weekday"]) != local.weekday():
                continue
            sh, sm = (int(x) for x in w["start"].split(":"))
            eh, em = (int(x) for x in w["end"].split(":"))
            minutes = local.hour * 60 + local.minute
            start, end = sh * 60 + sm, eh * 60 + em
            if (start <= minutes < end) if start <= end else (minutes >= start or minutes < end):
                return True
        except (KeyError, ValueError):
            continue
    return False


def schedule_due(limit: int = 500) -> dict[str, int]:
    """Enqueue checks whose next run time has passed (called by the scheduler)."""
    from app.services.entitlements import effective

    now = utcnow()
    stats = {"file_scan": 0, "availability": 0, "tls": 0, "skipped_maintenance": 0, "skipped_inactive": 0}
    with platform_session() as s:
        rows = s.execute(
            select(MonitoringConfig, Website, Tenant)
            .join(Website, Website.id == MonitoringConfig.website_id)
            .join(Tenant, Tenant.id == Website.tenant_id)
            .where(
                Website.status == "active",
                (
                    (MonitoringConfig.file_scan_enabled.is_(True)
                     & ((MonitoringConfig.next_file_scan_at.is_(None)) | (MonitoringConfig.next_file_scan_at <= now)))
                    | (MonitoringConfig.availability_enabled.is_(True)
                       & ((MonitoringConfig.next_availability_at.is_(None)) | (MonitoringConfig.next_availability_at <= now)))
                ),
            )
            .limit(limit)
        ).all()
        in_service_cache: dict[uuid.UUID, bool] = {}
        to_dispatch: list[ScanJob] = []
        for cfg, website, tenant in rows:
            if tenant.status != "active":
                stats["skipped_inactive"] += 1
                continue
            if tenant.id not in in_service_cache:
                in_service_cache[tenant.id] = effective(s, tenant.id).in_service
            if not in_service_cache[tenant.id]:
                stats["skipped_inactive"] += 1
                cfg.next_file_scan_at = now + timedelta(hours=6)
                cfg.next_availability_at = now + timedelta(hours=1)
                continue
            if _in_maintenance(cfg, now):
                stats["skipped_maintenance"] += 1
                cfg.next_file_scan_at = now + timedelta(minutes=15)
                cfg.next_availability_at = now + timedelta(minutes=15)
                continue
            jitter = timedelta(seconds=random.randint(0, 60))  # noqa: S311
            if cfg.file_scan_enabled and (cfg.next_file_scan_at is None or cfg.next_file_scan_at <= now):
                if website.hosting_account_id:
                    job, created = enqueue(s, tenant_id=tenant.id, job_type="file_scan", website_id=website.id,
                                           commit=False)
                    if created:
                        to_dispatch.append(job)
                        stats["file_scan"] += 1
                cfg.next_file_scan_at = now + timedelta(minutes=cfg.file_scan_interval_minutes) + jitter
            if cfg.availability_enabled and (cfg.next_availability_at is None or cfg.next_availability_at <= now):
                job, created = enqueue(s, tenant_id=tenant.id, job_type="availability", website_id=website.id,
                                       commit=False)
                if created:
                    to_dispatch.append(job)
                    stats["availability"] += 1
                if cfg.tls_enabled and website.url.startswith("https://"):
                    last_tls = website.tls_expires_at
                    # TLS: at most every 6 hours.
                    due_tls = s.execute(
                        select(func.max(TlsCheck.checked_at)).where(TlsCheck.website_id == website.id)
                    ).scalar()
                    if due_tls is None or due_tls < now - timedelta(hours=6) or last_tls is None:
                        job, created = enqueue(s, tenant_id=tenant.id, job_type="tls", website_id=website.id,
                                               commit=False)
                        if created:
                            to_dispatch.append(job)
                            stats["tls"] += 1
                cfg.next_availability_at = now + timedelta(minutes=cfg.availability_interval_minutes) + jitter
        s.commit()
        for job in to_dispatch:
            dispatch(job)
    return stats
