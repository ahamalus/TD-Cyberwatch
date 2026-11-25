"""Remediation: change customer files, safely and reversibly, as part of an authorised service request.

Two actions:

* **restore_genuine**: replace a WordPress core or plugin file that differs from the official release with the
  official copy, downloaded from wordpress.org and accepted only if it matches the published checksum.
* **quarantine**: remove a file (malware, a file that should not exist) from the server.

Every action:

1. requires the customer's separate *remediation access* (an SFTP login with write permission; the monitoring
   connection stays read-only) and an open, customer-authorised request whose assigned engineer holds an
   active access grant (checked by the API);
2. re-reads the file and refuses if it no longer has the fingerprint the engineer saw in the last scan, so a
   legitimate change made since is never overwritten;
3. keeps an encrypted copy of the original in CyberWatch storage before changing anything (undo);
4. writes atomically (temporary file, then rename) and reads the result back to confirm;
5. is recorded in the audit trail and triggers a rescan.

Undo writes the original back, but only if the file is still in the state the action left it in.
CyberWatch never runs commands on the server; it only reads, writes, renames and deletes files over SFTP.
"""

from __future__ import annotations

import hashlib
import posixpath
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import quote

import paramiko
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.base import ConnectionParams, ConnectorError, SecretMaterial, safe_join, safe_rel
from app.connectors.sftp import SFTPConnector
from app.core.config import get_settings
from app.core.crypto import CredentialVault, EncryptedBlob, get_vault
from app.db.base import utcnow
from app.models import (
    FileInventoryItem,
    HostingAccount,
    Incident,
    RemediationAction,
    RemediationCredential,
    SoftwareInstall,
    Website,
)
from app.monitoring import vendor
from app.services import storage
from app.services.audit import AuditActor, record

MAX_FILE_BYTES = 20 * 1024 * 1024
ACTIONS = ("restore_genuine", "quarantine")


class RemediationError(Exception):
    def __init__(self, message: str, code: str = "remediation_failed"):
        super().__init__(message)
        self.message, self.code = message, code


# ---------------------------------------------------------------- credentials


def _aad(cred: RemediationCredential) -> bytes:
    return CredentialVault.associated_data(cred.tenant_id, cred.hosting_account_id, "remediation_credential")


def store_secret(cred: RemediationCredential, secret: SecretMaterial) -> None:
    import json

    blob = get_vault().encrypt(json.dumps({"kind": secret.kind, "value": secret.value,
                                           "passphrase": secret.passphrase}).encode(), _aad(cred))
    cred.key_id, cred.nonce, cred.ciphertext, cred.kind = blob.key_id, blob.nonce, blob.ciphertext, secret.kind


def load_secret(cred: RemediationCredential) -> SecretMaterial:
    import json

    data = json.loads(get_vault().decrypt(EncryptedBlob(cred.key_id, cred.nonce, cred.ciphertext), _aad(cred)))
    return SecretMaterial(kind=data["kind"], value=data["value"], passphrase=data.get("passphrase"))


class Writer:
    """Read/write access below ``root`` over one SFTP session. Paths are relative to ``root``."""

    def __init__(self, sftp: paramiko.SFTPClient, root: str):
        self.sftp, self.root = sftp, root

    def abs(self, rel: str) -> str:
        try:
            return safe_join(self.root, safe_rel(rel))
        except ConnectorError as exc:
            raise RemediationError(exc.message, "bad_path") from exc

    def read(self, rel: str) -> bytes:
        path = self.abs(rel)
        try:
            st = self.sftp.lstat(path)
        except OSError as exc:
            raise RemediationError(f"{rel} is not on the server any more.", "not_found") from exc
        if st.st_mode is None or not stat.S_ISREG(st.st_mode):
            raise RemediationError(f"{rel} is not a regular file (symbolic links are never followed).", "not_a_file")
        if (st.st_size or 0) > MAX_FILE_BYTES:
            raise RemediationError(f"{rel} is larger than {MAX_FILE_BYTES // 1048576} MB.", "too_large")
        with self.sftp.open(path, "rb") as fh:
            return fh.read()

    def exists(self, rel: str) -> bool:
        try:
            self.sftp.lstat(self.abs(rel))
            return True
        except OSError:
            return False

    def mode(self, rel: str) -> int | None:
        try:
            st = self.sftp.lstat(self.abs(rel))
            return stat.S_IMODE(st.st_mode) if st.st_mode is not None else None
        except OSError:
            return None

    def write_atomic(self, rel: str, data: bytes, mode: int | None = None) -> None:
        path = self.abs(rel)
        tmp = posixpath.join(posixpath.dirname(path), f".cyberwatch-{uuid.uuid4().hex[:12]}.tmp")
        try:
            with self.sftp.open(tmp, "wb") as fh:
                fh.write(data)
            self.sftp.chmod(tmp, mode if mode is not None else 0o644)
            try:
                self.sftp.posix_rename(tmp, path)
            except OSError:
                # Servers without the posix-rename extension: plain rename does not overwrite.
                if self.exists(rel):
                    self.sftp.remove(path)
                self.sftp.rename(tmp, path)
        except OSError as exc:
            try:
                self.sftp.remove(tmp)
            except OSError:
                pass
            raise RemediationError(f"Could not write {rel}: {exc}", "write_failed") from exc

    def remove(self, rel: str) -> None:
        try:
            self.sftp.remove(self.abs(rel))
        except OSError as exc:
            raise RemediationError(f"Could not remove {rel}: {exc}", "write_failed") from exc


def _connector(cred: RemediationCredential) -> SFTPConnector:
    return SFTPConnector(ConnectionParams("sftp", cred.hostname, cred.port, cred.username, cred.root_path,
                                          expected_host_key=cred.host_key_fingerprint, connect_timeout=15.0,
                                          io_timeout=60.0), load_secret(cred))


@contextmanager
def open_writer(cred: RemediationCredential, root: str) -> Iterator[Writer]:
    try:
        transport, sftp, fp, _ = _connector(cred)._connect()
    except ConnectorError as exc:
        raise RemediationError(f"Remediation access failed: {exc.message}", exc.code) from exc
    try:
        if cred.host_key_fingerprint is None:
            cred.host_key_fingerprint = fp
        yield Writer(sftp, root)
    finally:
        transport.close()


def test_access(db: Session, cred: RemediationCredential, account: HostingAccount) -> tuple[bool, str]:
    """Connect, check the folder is the monitored one, and prove write access with a temporary file."""
    from app.connectors.registry import build_connector
    from app.models import ConnectorDefinition, HostingCredential

    cred.last_tested_at = utcnow()
    try:
        with open_writer(cred, cred.root_path) as w:
            names = {a.filename for a in w.sftp.listdir_attr(cred.root_path)}
            note = ""
            try:
                mon_cred = db.execute(select(HostingCredential).where(
                    HostingCredential.hosting_account_id == account.id)).scalar_one_or_none()
                mon = build_connector(account, mon_cred, db.get(ConnectorDefinition, account.connector_type))
                with mon.open_file_source(account.root_path) as src:
                    expected = {e.name for e in src.list_dir(".")}
                overlap = len(names & expected) / max(1, len(expected))
                if expected and overlap < 0.8:
                    raise RemediationError(
                        f"{cred.root_path} does not look like the monitored folder {account.root_path} "
                        f"(only {overlap:.0%} of its entries match). Check the path.", "root_mismatch")
                note = f" It matches the monitored folder ({len(names & expected)} of {len(expected)} entries)."
            except ConnectorError:
                note = " (The monitored folder could not be listed for comparison.)"
            probe = f".cyberwatch-write-test-{uuid.uuid4().hex[:8]}"
            w.write_atomic(probe, b"CyberWatch write test; safe to delete.\n")
            w.remove(probe)
        cred.status, cred.last_result = "ok", f"Write access confirmed in {cred.root_path}.{note}"
    except RemediationError as exc:
        cred.status, cred.last_result = "failed", exc.message
    except OSError as exc:
        cred.status, cred.last_result = "failed", f"{type(exc).__name__}: {exc}"[:500]
    cred.updated_at = utcnow()
    return cred.status == "ok", cred.last_result or ""


# ---------------------------------------------------------------- what can be fixed


def candidates(db: Session, website: Website, incident_ids: list[str]) -> list[dict[str, Any]]:
    rows = db.execute(select(FileInventoryItem).where(
        FileInventoryItem.website_id == website.id, FileInventoryItem.state == "present",
        (FileInventoryItem.vendor_status.in_(["modified", "unexpected"]))
        | (FileInventoryItem.malware_status.in_(["infected", "suspicious"])))).scalars().all()
    by_path = {r.path: r for r in rows}
    reasons: dict[str, list[str]] = {}
    for r in rows:
        why = reasons.setdefault(r.path, [])
        if r.vendor_status == "modified":
            why.append(f"differs from the official {r.vendor_ref}")
        if r.vendor_status == "unexpected":
            why.append(f"not part of {r.vendor_ref}")
        if r.malware_status in ("infected", "suspicious") and r.vendor_status != "verified":
            why.append(f"malware scan: {r.malware_status}")
    ids = [uuid.UUID(i) for i in incident_ids]
    if ids:
        for res in db.execute(select(Incident.affected_resources).where(Incident.id.in_(ids))).scalars():
            for r in res or []:
                if isinstance(r, dict) and r.get("type") == "file" and r.get("path"):
                    reasons.setdefault(r["path"], []).append("named in a linked incident")
                    if r["path"] not in by_path:
                        item = db.execute(select(FileInventoryItem).where(
                            FileInventoryItem.website_id == website.id, FileInventoryItem.path == r["path"],
                            FileInventoryItem.state == "present")).scalar_one_or_none()
                        if item:
                            by_path[item.path] = item
    done = {a.path: a for a in db.execute(select(RemediationAction).where(
        RemediationAction.website_id == website.id, RemediationAction.status == "done")
        .order_by(RemediationAction.performed_at)).scalars()}
    out = []
    for path, why in sorted(reasons.items()):
        item = by_path.get(path)
        if item is None:
            continue
        actions = []
        if item.vendor_status == "modified":
            actions.append("restore_genuine")  # never quarantine a core/plugin file: the site would break
        elif item.vendor_status != "verified":
            actions.append("quarantine")
        a = done.get(path)
        out.append({"path": path, "size": item.size, "sha256": item.sha256, "reasons": sorted(set(why)),
                    "actions": actions, "vendor_ref": item.vendor_ref,
                    "last_action": {"id": str(a.id), "action": a.action, "at": a.performed_at} if a else None})
    return out


# ---------------------------------------------------------------- official files


def official_file(db: Session, website_id: uuid.UUID, path: str) -> tuple[bytes, str]:
    from app.core.http import pinned_request

    installs = db.execute(select(SoftwareInstall).where(SoftwareInstall.website_id == website_id)).scalars().all()
    s = get_settings()
    # The deepest install containing the file owns it: a WordPress site in a subfolder (e.g. "blog/") sits inside
    # the root install's folder, and its files are relative to its own root. Plugins beat core at equal depth.
    target = None
    for inst in sorted(installs, key=lambda i: (-len(i.root), i.product != vendor.PLUGIN)):
        if inst.product == vendor.PLUGIN:
            base = f"{inst.root}wp-content/plugins/{inst.slug}/"
            if path.startswith(base):
                target = (inst, path[len(base):])
                break
        elif path.startswith(inst.root) and not path[len(inst.root):].startswith("wp-content/"):
            target = (inst, path[len(inst.root):])
            break
    if target is None or not target[0].version:
        raise RemediationError("This file does not belong to a WordPress core or plugin release CyberWatch knows.",
                               "not_vendor")
    inst, rel = target
    store = vendor.ChecksumStore(db)
    if inst.product == vendor.CORE:
        sums = store.get(vendor.CORE, "wordpress", inst.version, inst.locale or "en_US")
        if sums is None and inst.locale and inst.locale != "en_US":
            sums = store.get(vendor.CORE, "wordpress", inst.version, "en_US")
        url = f"{s.wordpress_core_svn_base.rstrip('/')}/tags/{quote(inst.version)}/{quote(rel)}"
        ref = f"WordPress {inst.version}"
    else:
        sums = store.get(vendor.PLUGIN, inst.slug, inst.version)
        url = f"{s.wordpress_plugins_svn_base.rstrip('/')}/{quote(inst.slug)}/tags/{quote(inst.version)}/{quote(rel)}"
        ref = f"{inst.name or inst.slug} {inst.version}"
    entry = (sums or {}).get(rel)
    if not entry:
        raise RemediationError(f"{rel} is not in the published checksum list for {ref}.", "not_vendor")
    try:
        resp = pinned_request("GET", url, allowed_ports=[443], timeout=30.0, max_body_bytes=MAX_FILE_BYTES)
    except Exception as exc:  # noqa: BLE001
        raise RemediationError(f"Could not download the official file: {type(exc).__name__}", "download_failed") from exc
    if resp.status_code != 200 or resp.truncated:
        raise RemediationError(f"wordpress.org returned HTTP {resp.status_code} for the official file.", "download_failed")
    data = resp.body
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    sha = hashlib.sha256(data).hexdigest()
    if not (md5 in entry.get("md5", []) or sha in entry.get("sha256", [])):
        raise RemediationError(f"The downloaded copy of {rel} does not match the published checksum for {ref}; "
                               "nothing was changed.", "checksum_mismatch")
    return data, f"{ref}: {url} (checksum verified)"


# ---------------------------------------------------------------- perform and undo


def website_root(cred: RemediationCredential, website: Website) -> str:
    return safe_join(cred.root_path, website.document_root or ".")


def _backup(action: RemediationAction, data: bytes) -> None:
    aad = CredentialVault.associated_data(action.tenant_id, action.id, "remediation_backup")
    blob = get_vault().encrypt(data, aad)
    key, _, _ = storage.put(action.tenant_id, "remediation_backup", "bin", blob.ciphertext)
    action.backup_key, action.backup_key_id, action.backup_nonce, action.backup_size = key, blob.key_id, blob.nonce, len(data)


def _restore_backup(action: RemediationAction) -> bytes:
    ct = storage.get(action.tenant_id, action.backup_key)
    aad = CredentialVault.associated_data(action.tenant_id, action.id, "remediation_backup")
    return get_vault().decrypt(EncryptedBlob(action.backup_key_id, action.backup_nonce, ct), aad)


def credential_for(db: Session, website: Website) -> RemediationCredential:
    cred = db.execute(select(RemediationCredential).where(
        RemediationCredential.hosting_account_id == website.hosting_account_id)).scalar_one_or_none() \
        if website.hosting_account_id else None
    if cred is None:
        raise RemediationError("The customer has not set up remediation access for this website's hosting.", "no_access")
    if cred.status != "ok":
        raise RemediationError("Remediation access has not passed its test; ask the customer to re-test it.", "no_access")
    return cred


def perform(db: Session, *, website: Website, ticket_id: uuid.UUID | None, action: str, path: str,
            expected_sha256: str, actor_user_id: uuid.UUID, actor: AuditActor) -> RemediationAction:
    if action not in ACTIONS:
        raise RemediationError("Unknown action.", "bad_request")
    try:
        path = safe_rel(path)
    except ConnectorError as exc:
        raise RemediationError(exc.message, "bad_path") from exc
    item = db.execute(select(FileInventoryItem).where(
        FileInventoryItem.website_id == website.id, FileInventoryItem.path == path,
        FileInventoryItem.state == "present")).scalar_one_or_none()
    if item is None or item.sha256 != expected_sha256:
        raise RemediationError("The file's last scanned fingerprint differs from the one you reviewed; reload.", "stale")
    if action == "quarantine" and item.vendor_status in ("verified", "modified"):
        raise RemediationError("Core and plugin files are restored, not removed (removing them breaks the site).",
                               "bad_request")
    cred = credential_for(db, website)
    official = official_file(db, website.id, path) if action == "restore_genuine" else None
    a = RemediationAction(id=uuid.uuid4(), tenant_id=website.tenant_id, ticket_id=ticket_id, website_id=website.id,
                          path=path, action=action, status="failed", performed_by=actor_user_id,
                          performed_at=utcnow(), source=official[1] if official else None)
    db.add(a)
    try:
        with open_writer(cred, website_root(cred, website)) as w:
            current = w.read(path)
            a.before_sha256 = hashlib.sha256(current).hexdigest()
            if a.before_sha256 != expected_sha256:
                raise RemediationError("The file changed on the server since the last scan; nothing was changed. "
                                       "Rescan, review it again, then retry.", "stale")
            _backup(a, current)
            if official:
                w.write_atomic(path, official[0], w.mode(path))
                a.after_sha256 = hashlib.sha256(w.read(path)).hexdigest()
                if a.after_sha256 != hashlib.sha256(official[0]).hexdigest():
                    raise RemediationError("The file read back differs from what was written.", "verify_failed")
            else:
                w.remove(path)
                if w.exists(path):
                    raise RemediationError("The file is still present after removal.", "verify_failed")
        a.status = "done"
    except (OSError, paramiko.SSHException, EOFError) as exc:
        a.error = f"{type(exc).__name__}: {exc}"[:500]  # recorded as failed; the saved copy (if any) is kept
    except RemediationError as exc:
        a.error = exc.message
        if exc.code == "stale" and a.backup_key is None:
            db.expunge(a)  # nothing happened: no record needed beyond the audit entry below
            record(db, "remediation.refused", actor=actor, tenant_id=website.tenant_id, target_type="file",
                   target_id=path, outcome="failure", details={"action": action, "reason": exc.message})
            raise
    record(db, f"remediation.{action}", actor=actor, tenant_id=website.tenant_id, target_type="file", target_id=path,
           outcome="success" if a.status == "done" else "failure",
           details={"website": str(website.id), "ticket": str(ticket_id) if ticket_id else None,
                    "before_sha256": a.before_sha256, "after_sha256": a.after_sha256, "source": a.source,
                    "error": a.error, "action_id": str(a.id)})
    if a.status == "done":
        _rescan(db, website, actor_user_id)
    return a


def undo(db: Session, a: RemediationAction, *, actor_user_id: uuid.UUID, actor: AuditActor) -> RemediationAction:
    if a.status != "done" or not a.backup_key:
        raise RemediationError("Only completed changes with a saved copy can be undone.", "bad_request")
    website = db.get(Website, a.website_id)
    cred = credential_for(db, website)
    original = _restore_backup(a)
    with open_writer(cred, website_root(cred, website)) as w:
        if a.action == "restore_genuine":
            now = hashlib.sha256(w.read(a.path)).hexdigest() if w.exists(a.path) else None
            if now != a.after_sha256:
                raise RemediationError("The file has changed since this fix; undo would overwrite that change.", "stale")
        elif w.exists(a.path):
            raise RemediationError("A file with this name exists again; undo would overwrite it.", "stale")
        w.write_atomic(a.path, original)
        if hashlib.sha256(w.read(a.path)).hexdigest() != a.before_sha256:
            raise RemediationError("The restored file does not match the saved copy.", "verify_failed")
    a.status, a.undone_at, a.undone_by = "undone", utcnow(), actor_user_id
    record(db, "remediation.undone", actor=actor, tenant_id=a.tenant_id, target_type="file", target_id=a.path,
           details={"action_id": str(a.id), "action": a.action, "restored_sha256": a.before_sha256})
    _rescan(db, website, actor_user_id)
    return a


def _rescan(db: Session, website: Website, user_id: uuid.UUID) -> None:
    from app.monitoring import jobs

    jobs.enqueue(db, tenant_id=website.tenant_id, job_type="file_scan", website_id=website.id, trigger="manual",
                 requested_by=user_id, commit=False)


def action_dict(db: Session, a: RemediationAction) -> dict[str, Any]:
    from app.models import User

    by = db.get(User, a.performed_by) if a.performed_by else None
    undone_by = db.get(User, a.undone_by) if a.undone_by else None
    return {"id": str(a.id), "path": a.path, "action": a.action, "status": a.status, "error": a.error,
            "before_sha256": a.before_sha256, "after_sha256": a.after_sha256, "source": a.source,
            "performed_at": a.performed_at, "performed_by": (by.full_name or by.email) if by else None,
            "undone_at": a.undone_at, "undone_by": (undone_by.full_name or undone_by.email) if undone_by else None,
            "can_undo": a.status == "done" and bool(a.backup_key)}
