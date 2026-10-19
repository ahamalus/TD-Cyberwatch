"""Protected object storage (local filesystem implementation).

Objects are stored under ``<storage_dir>/<tenant_id>/<kind>/<uuid>.<ext>``.
Keys are generated server-side only; reads verify the key belongs to the
requesting tenant and resolves inside the storage root. Replace with an S3-
compatible backend for multi-node deployments (same interface).
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

from app.core.config import get_settings


class StorageError(Exception):
    pass


def _root() -> Path:
    root = Path(get_settings().storage_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def put(tenant_id: uuid.UUID, kind: str, ext: str, data: bytes) -> tuple[str, str, int]:
    if not kind.isidentifier() or not ext.isalnum():
        raise StorageError("Invalid object key components.")
    key = f"{tenant_id}/{kind}/{uuid.uuid4()}.{ext}"
    path = _root() / key
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key, hashlib.sha256(data).hexdigest(), len(data)


def get(tenant_id: uuid.UUID, key: str) -> bytes:
    if not key.startswith(f"{tenant_id}/"):
        raise StorageError("Object does not belong to this tenant.")
    root = _root()
    path = (root / key).resolve()
    if root not in path.parents:
        raise StorageError("Invalid object key.")
    if not path.is_file():
        raise StorageError("Object not found.")
    return path.read_bytes()
