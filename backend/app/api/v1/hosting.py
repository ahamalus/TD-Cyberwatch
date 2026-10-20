"""Hosting connections: create, test, discover capabilities, rotate credentials."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import TenantContext, require
from app.connectors.base import CAPABILITY_LABELS, Capability, SecretMaterial
from app.connectors.registry import ACCEPTED_SECRET_KINDS, DEFAULT_PORTS, encrypt_secret, is_implemented
from app.core.config import get_settings
from app.core.crypto import fingerprint
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.netguard import TargetNotAllowed, normalise_hostname
from app.core.permissions import P
from app.db.base import utcnow
from app.db.session import get_db
from app.models import (
    CapabilityDiscovery,
    ConnectorCapability,
    ConnectorDefinition,
    HostingAccount,
    HostingCredential,
    ScanJob,
    Website,
)
from app.monitoring import jobs
from app.schemas.common import Message
from app.services import audit, entitlements

router = APIRouter(prefix="/tenants/{tenant_id}/hosting-accounts", tags=["hosting"])
connectors_router = APIRouter(tags=["hosting"])


class CredentialIn(BaseModel):
    kind: str = Field(pattern="^(password|private_key|api_token)$")
    value: str = Field(min_length=1, max_length=16384)
    passphrase: str | None = Field(default=None, max_length=1024)

    def __repr__(self) -> str:
        return f"CredentialIn(kind={self.kind!r}, value='***')"


class HostingIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    connector_type: str = Field(max_length=40)
    provider_name: str | None = Field(default=None, max_length=120)
    hostname: str = Field(min_length=3, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=120)
    root_path: str = Field(default="/", max_length=1024)
    log_paths: list[str] = Field(default_factory=list, max_length=10)
    credential: CredentialIn

    @model_validator(mode="after")
    def _check(self) -> HostingIn:
        if "\x00" in self.root_path or ".." in self.root_path.split("/"):
            raise ValueError("Root path must not contain '..'.")
        return self


class HostingPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    provider_name: str | None = Field(default=None, max_length=120)
    root_path: str | None = Field(default=None, max_length=1024)
    log_paths: list[str] | None = Field(default=None, max_length=10)


class CapabilityOut(BaseModel):
    capability: str
    label: str
    status: str
    detail: str
    required_permission: str | None
    discovered_at: datetime | None


class HostingOut(BaseModel):
    id: uuid.UUID
    name: str
    connector_type: str
    connector_name: str
    provider_name: str | None
    hostname: str
    port: int
    username: str
    root_path: str
    status: str
    credential_kind: str | None
    credential_fingerprint: str | None
    credential_rotated_at: datetime | None
    host_key_type: str | None
    host_key_fingerprint: str | None
    host_key_confirmed_at: datetime | None
    last_tested_at: datetime | None
    last_success_at: datetime | None
    last_error_code: str | None
    last_error_message: str | None
    website_count: int
    log_paths: list[str]
    capabilities: list[CapabilityOut]
    last_test_job: dict | None = None
    created_at: datetime


def _validate_paths(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        p = p.strip()
        if not p.startswith("/") or "\x00" in p or ".." in p.split("/"):
            raise ValidationFailed("Log paths must be absolute paths without '..'.")
        out.append(p)
    return out


def hosting_out(db: Session, a: HostingAccount) -> HostingOut:
    cred = db.execute(select(HostingCredential).where(HostingCredential.hosting_account_id == a.id)).scalar_one_or_none()
    definition = db.get(ConnectorDefinition, a.connector_type)
    caps = {c.capability: c for c in db.execute(
        select(ConnectorCapability).where(ConnectorCapability.hosting_account_id == a.id)).scalars()}
    cap_out = []
    for cap in Capability:
        if cap == Capability.UPTIME_TLS:
            continue
        row = caps.get(cap.value)
        cap_out.append(CapabilityOut(
            capability=cap.value, label=CAPABILITY_LABELS[cap],
            status=row.status if row else "untested",
            detail=row.detail if row else "Not yet tested. Run a connection test to discover capabilities.",
            required_permission=row.required_permission if row else None,
            discovered_at=row.discovered_at if row else None,
        ))
    sites = db.execute(select(func.count()).select_from(Website).where(Website.hosting_account_id == a.id)).scalar_one()
    last_job = db.execute(
        select(ScanJob).where(ScanJob.hosting_account_id == a.id, ScanJob.job_type.in_(["connection_test", "capability_discovery"]))
        .order_by(ScanJob.queued_at.desc()).limit(1)
    ).scalar_one_or_none()
    return HostingOut(
        id=a.id, name=a.name, connector_type=a.connector_type,
        connector_name=definition.name if definition else a.connector_type, provider_name=a.provider_name,
        hostname=a.hostname, port=a.port, username=a.username, root_path=a.root_path, status=a.status,
        credential_kind=cred.kind if cred else None, credential_fingerprint=cred.display_fingerprint if cred else None,
        credential_rotated_at=cred.rotated_at if cred else None, host_key_type=a.host_key_type,
        host_key_fingerprint=a.host_key_fingerprint, host_key_confirmed_at=a.host_key_confirmed_at,
        last_tested_at=a.last_tested_at, last_success_at=a.last_success_at, last_error_code=a.last_error_code,
        last_error_message=a.last_error_message, website_count=sites,
        log_paths=list((a.options or {}).get("log_paths", [])), capabilities=cap_out,
        last_test_job={"id": str(last_job.id), "status": last_job.status, "queued_at": last_job.queued_at.isoformat(),
                       "finished_at": last_job.finished_at.isoformat() if last_job.finished_at else None,
                       "result": last_job.result_summary, "error": last_job.error_message} if last_job else None,
        created_at=a.created_at,
    )


def get_account(db: Session, ctx: TenantContext, account_id: uuid.UUID) -> HostingAccount:
    a = db.execute(select(HostingAccount).where(HostingAccount.id == account_id,
                                                HostingAccount.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if a is None:
        raise NotFound("Hosting connection not found.")
    return a


def _store_credential(db: Session, a: HostingAccount, cred_in: CredentialIn) -> HostingCredential:
    allowed = ACCEPTED_SECRET_KINDS.get(a.connector_type, ())
    if cred_in.kind not in allowed:
        raise ValidationFailed(f"{a.connector_type} connections accept: {', '.join(allowed)}.")
    if cred_in.kind == "private_key":
        from app.connectors.base import ConnectorError
        from app.connectors.sftp import load_private_key

        try:
            load_private_key(cred_in.value, cred_in.passphrase)
        except ConnectorError as exc:
            raise ValidationFailed(exc.message) from exc
    secret = SecretMaterial(kind=cred_in.kind, value=cred_in.value, passphrase=cred_in.passphrase)
    key_id, nonce, ct = encrypt_secret(a.tenant_id, a.id, secret)
    cred = db.execute(select(HostingCredential).where(HostingCredential.hosting_account_id == a.id)).scalar_one_or_none()
    if cred is None:
        cred = HostingCredential(tenant_id=a.tenant_id, hosting_account_id=a.id, kind=cred_in.kind, key_id=key_id,
                                 nonce=nonce, ciphertext=ct, display_fingerprint="")
        db.add(cred)
    cred.kind, cred.key_id, cred.nonce, cred.ciphertext = cred_in.kind, key_id, nonce, ct
    cred.display_fingerprint = fingerprint(cred_in.value.encode())
    cred.rotated_at = utcnow()
    return cred


@connectors_router.get("/connectors")
def list_connectors(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(ConnectorDefinition).order_by(ConnectorDefinition.status, ConnectorDefinition.name)).scalars()
    return [{"key": c.key, "name": c.name, "status": c.status, "version": c.adapter_version,
             "description": c.description, "default_port": DEFAULT_PORTS.get(c.key),
             "credential_kinds": list(ACCEPTED_SECRET_KINDS.get(c.key, ())),
             "notes": c.capability_notes} for c in rows]


@router.get("", response_model=list[HostingOut])
def list_accounts(ctx: TenantContext = Depends(require(P.HOSTING_READ)), db: Session = Depends(get_db)) -> list[HostingOut]:
    rows = db.execute(select(HostingAccount).where(HostingAccount.tenant_id == ctx.tenant_id).order_by(HostingAccount.name)).scalars()
    return [hosting_out(db, a) for a in rows]


@router.post("", response_model=HostingOut, status_code=201)
def create_account(body: HostingIn, ctx: TenantContext = Depends(require(P.HOSTING_MANAGE)),
                   db: Session = Depends(get_db)) -> HostingOut:
    definition = db.get(ConnectorDefinition, body.connector_type)
    if definition is None:
        raise ValidationFailed("Unknown connector type.")
    if definition.status != "implemented" or not is_implemented(body.connector_type):
        raise ValidationFailed(f"The {definition.name} connector is not available yet.", code="connector_unavailable")
    try:
        hostname = normalise_hostname(body.hostname)
    except TargetNotAllowed as exc:
        raise ValidationFailed(str(exc)) from exc
    port = body.port or DEFAULT_PORTS.get(body.connector_type, 22)
    settings = get_settings()
    allowed_ports = settings.allowed_sftp_ports if body.connector_type == "sftp" else settings.allowed_cpanel_ports
    if port not in allowed_ports:
        raise ValidationFailed(f"Port {port} is not permitted for {definition.name}. Allowed: {allowed_ports}.")
    entitlements.require_capacity(db, ctx.tenant_id, "hosting_accounts")
    if db.execute(select(HostingAccount.id).where(
            HostingAccount.tenant_id == ctx.tenant_id, HostingAccount.connector_type == body.connector_type,
            HostingAccount.hostname == hostname, HostingAccount.username == body.username)).first():
        raise Conflict("A connection for this host and username already exists.")
    root = "/" + body.root_path.strip().strip("/") if body.root_path.strip() not in ("", "/") else "/"
    if body.connector_type == "cpanel_uapi" and root == "/":
        root = "/public_html"
    a = HostingAccount(tenant_id=ctx.tenant_id, name=body.name, connector_type=body.connector_type,
                       provider_name=body.provider_name, hostname=hostname, port=port, username=body.username,
                       root_path=root, options={"log_paths": _validate_paths(body.log_paths)})
    db.add(a)
    db.flush()
    _store_credential(db, a, body.credential)
    audit.record(db, "hosting.created", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="hosting_account",
                 target_id=a.id, details={"connector": a.connector_type, "hostname": hostname, "port": port,
                                          "username": a.username, "credential_kind": body.credential.kind})
    db.commit()
    job, created = jobs.enqueue(db, tenant_id=ctx.tenant_id, job_type="connection_test", hosting_account_id=a.id,
                                trigger="manual", requested_by=ctx.user.id)
    return hosting_out(db, a)


@router.get("/{account_id}", response_model=HostingOut)
def get_one(account_id: uuid.UUID, ctx: TenantContext = Depends(require(P.HOSTING_READ)),
            db: Session = Depends(get_db)) -> HostingOut:
    return hosting_out(db, get_account(db, ctx, account_id))


@router.patch("/{account_id}", response_model=HostingOut)
def patch_account(account_id: uuid.UUID, body: HostingPatch, ctx: TenantContext = Depends(require(P.HOSTING_MANAGE)),
                  db: Session = Depends(get_db)) -> HostingOut:
    a = get_account(db, ctx, account_id)
    changes = body.model_dump(exclude_none=True)
    if "root_path" in changes:
        rp = changes["root_path"].strip()
        if "\x00" in rp or ".." in rp.split("/"):
            raise ValidationFailed("Root path must not contain '..'.")
        a.root_path = "/" + rp.strip("/") if rp.strip("/") else "/"
        # A new scope invalidates verified capabilities and baselines.
        for c in db.execute(select(ConnectorCapability).where(ConnectorCapability.hosting_account_id == a.id)).scalars():
            db.delete(c)
        for w in db.execute(select(Website).where(Website.hosting_account_id == a.id)).scalars():
            w.baseline_snapshot_id = None
        a.status = "untested"
    if "log_paths" in changes:
        a.options = {**(a.options or {}), "log_paths": _validate_paths(changes["log_paths"])}
    if "name" in changes:
        a.name = changes["name"]
    if "provider_name" in changes:
        a.provider_name = changes["provider_name"]
    audit.record(db, "hosting.updated", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="hosting_account",
                 target_id=a.id, details={"fields": sorted(changes)})
    db.commit()
    return hosting_out(db, a)


@router.put("/{account_id}/credential", response_model=HostingOut)
def rotate_credential(account_id: uuid.UUID, body: CredentialIn, ctx: TenantContext = Depends(require(P.HOSTING_MANAGE)),
                      db: Session = Depends(get_db)) -> HostingOut:
    a = get_account(db, ctx, account_id)
    _store_credential(db, a, body)
    a.status = "untested"
    audit.record(db, "hosting.credential_rotated", actor=ctx.actor(), tenant_id=ctx.tenant_id,
                 target_type="hosting_account", target_id=a.id, details={"credential_kind": body.kind})
    db.commit()
    jobs.enqueue(db, tenant_id=ctx.tenant_id, job_type="connection_test", hosting_account_id=a.id, trigger="manual",
                 requested_by=ctx.user.id)
    return hosting_out(db, a)


@router.post("/{account_id}/test", status_code=202)
def test_connection(account_id: uuid.UUID, ctx: TenantContext = Depends(require(P.HOSTING_MANAGE)),
                    db: Session = Depends(get_db)) -> dict:
    a = get_account(db, ctx, account_id)
    job, created = jobs.enqueue(db, tenant_id=ctx.tenant_id, job_type="connection_test", hosting_account_id=a.id,
                                trigger="manual", requested_by=ctx.user.id, commit=False)
    audit.record(db, "hosting.test_requested", actor=ctx.actor(), tenant_id=ctx.tenant_id,
                 target_type="hosting_account", target_id=a.id)
    db.commit()
    if created:
        jobs.dispatch(job)
    return {"job_id": str(job.id), "status": job.status, "created": created}


class RetrustIn(BaseModel):
    confirm_fingerprint_change: bool
    reason: str = Field(min_length=3, max_length=500)


@router.post("/{account_id}/retrust-host-key", response_model=HostingOut)
def retrust_host_key(account_id: uuid.UUID, body: RetrustIn, ctx: TenantContext = Depends(require(P.HOSTING_MANAGE)),
                     db: Session = Depends(get_db)) -> HostingOut:
    if not body.confirm_fingerprint_change:
        raise ValidationFailed("Confirmation is required.")
    a = get_account(db, ctx, account_id)
    old = a.host_key_fingerprint
    a.host_key_fingerprint = None
    a.host_key_type = None
    a.host_key_confirmed_at = None
    a.status = "untested"
    audit.record(db, "hosting.host_key_reset", actor=ctx.actor(), tenant_id=ctx.tenant_id,
                 target_type="hosting_account", target_id=a.id, details={"previous": old, "reason": body.reason})
    db.commit()
    jobs.enqueue(db, tenant_id=ctx.tenant_id, job_type="connection_test", hosting_account_id=a.id, trigger="manual",
                 requested_by=ctx.user.id)
    return hosting_out(db, a)


@router.delete("/{account_id}", response_model=Message)
def delete_account(account_id: uuid.UUID, ctx: TenantContext = Depends(require(P.HOSTING_MANAGE)),
                   db: Session = Depends(get_db)) -> Message:
    a = get_account(db, ctx, account_id)
    audit.record(db, "hosting.deleted", actor=ctx.actor(), tenant_id=ctx.tenant_id, target_type="hosting_account",
                 target_id=a.id, details={"hostname": a.hostname, "connector": a.connector_type})
    for w in db.execute(select(Website).where(Website.hosting_account_id == a.id)).scalars():
        w.baseline_snapshot_id = None
    db.delete(a)  # credential row cascades; ciphertext is destroyed
    db.commit()
    return Message(message="Hosting connection and its stored credential were deleted.")


@router.get("/{account_id}/discoveries")
def discoveries(account_id: uuid.UUID, ctx: TenantContext = Depends(require(P.HOSTING_READ)),
                db: Session = Depends(get_db)) -> list[dict]:
    a = get_account(db, ctx, account_id)
    rows = db.execute(select(CapabilityDiscovery).where(CapabilityDiscovery.hosting_account_id == a.id)
                      .order_by(CapabilityDiscovery.performed_at.desc()).limit(20)).scalars()
    return [{"id": str(r.id), "performed_at": r.performed_at, "success": r.success,
             "connector_version": r.connector_version, "profile": r.profile, "diagnostics": r.diagnostics} for r in rows]
