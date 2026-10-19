"""Provider-neutral hosting connector interface.

A connector is constructed from non-secret connection parameters plus
decrypted secret material, and exposes three operations:

* ``test_connection`` – verify reachability and credentials without
  disclosing secrets;
* ``discover_capabilities`` – report what this account can actually do,
  each capability as available / unavailable / untested / unsupported;
* ``open_file_source`` – a read-only view of files under an authorised root.

Connectors must never modify remote files or execute remote commands.
"""

from __future__ import annotations

import posixpath
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Capability(StrEnum):
    FILE_LISTING = "file_listing"
    FILE_METADATA = "file_metadata"
    FILE_CONTENT_READ = "file_content_read"
    FILE_HASHING = "file_hashing"
    LOG_ACCESS = "log_access"
    WEBSITE_MALWARE_SCAN = "website_malware_scan"
    HOSTING_MALWARE_SCAN = "hosting_malware_scan"
    UPTIME_TLS = "uptime_tls"
    REALTIME_FILE_EVENTS = "realtime_file_events"
    PROVIDER_SECURITY_API = "provider_security_api"


CAPABILITY_LABELS = {
    Capability.FILE_LISTING: "File and directory listing",
    Capability.FILE_METADATA: "File metadata",
    Capability.FILE_CONTENT_READ: "File content reading",
    Capability.FILE_HASHING: "SHA-256 file hashing",
    Capability.LOG_ACCESS: "Web server / security log access",
    Capability.WEBSITE_MALWARE_SCAN: "Website-level malware scanning",
    Capability.HOSTING_MALWARE_SCAN: "Hosting-level malware scanning",
    Capability.UPTIME_TLS: "Uptime and TLS monitoring",
    Capability.REALTIME_FILE_EVENTS: "Real-time file event monitoring",
    Capability.PROVIDER_SECURITY_API: "Provider security API",
}

AVAILABLE = "available"
UNAVAILABLE = "unavailable"
UNTESTED = "untested"
UNSUPPORTED = "unsupported"


class ConnectorError(Exception):
    """A classified, sanitised connector failure. ``message`` is safe to display."""

    def __init__(self, code: str, message: str, *, retryable: bool = False, detail: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.detail = detail or {}


# Error codes
E_TARGET_NOT_ALLOWED = "target_not_allowed"
E_DNS = "dns_failure"
E_REFUSED = "connection_refused"
E_TIMEOUT = "timeout"
E_AUTH = "auth_failed"
E_HOST_KEY_MISMATCH = "host_key_mismatch"
E_PERMISSION = "permission_denied"
E_NOT_FOUND = "not_found"
E_PROTOCOL = "protocol_error"
E_TLS = "tls_error"
E_RATE_LIMITED = "rate_limited"
E_PATH = "unsafe_path"
E_CONFIG = "configuration_error"
E_UNAVAILABLE = "service_unavailable"

RETRYABLE_CODES = {E_DNS, E_REFUSED, E_TIMEOUT, E_RATE_LIMITED, E_UNAVAILABLE, E_PROTOCOL}


@dataclass
class ConnectionParams:
    connector_type: str
    hostname: str
    port: int
    username: str
    root_path: str = "/"
    options: dict[str, Any] = field(default_factory=dict)
    expected_host_key: str | None = None
    connect_timeout: float = 15.0
    io_timeout: float = 60.0


@dataclass
class SecretMaterial:
    kind: str  # password | private_key | api_token
    value: str
    passphrase: str | None = None

    def __repr__(self) -> str:  # never print secrets
        return f"SecretMaterial(kind={self.kind!r}, value='***')"


@dataclass
class Diagnostic:
    step: str
    ok: bool
    message: str
    code: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"step": self.step, "ok": self.ok, "message": self.message, "code": self.code}


@dataclass
class ConnectionTestResult:
    ok: bool
    diagnostics: list[Diagnostic]
    error_code: str | None = None
    error_message: str | None = None
    host_key_type: str | None = None
    host_key_fingerprint: str | None = None
    server_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilityResult:
    capability: Capability
    status: str
    detail: str
    required_permission: str | None = None


@dataclass
class RemoteEntry:
    name: str
    entry_type: str  # file | dir | symlink | other
    size: int | None
    mtime: datetime | None
    mode: int | None
    symlink_target: str | None = None


class FileSource(ABC):
    """Read-only access to files below ``root``. Paths are relative POSIX paths."""

    def __init__(self, root: str):
        self.root = normalise_root(root)

    @abstractmethod
    def list_dir(self, rel_path: str) -> list[RemoteEntry]: ...

    @abstractmethod
    def read_chunks(self, rel_path: str, chunk_size: int = 65536) -> Iterator[bytes]: ...

    def readlink(self, rel_path: str) -> str | None:
        return None

    def close(self) -> None:  # noqa: B027
        pass

    def __enter__(self) -> FileSource:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def absolute(self, rel_path: str) -> str:
        return safe_join(self.root, rel_path)


class Connector(ABC):
    key: str = ""
    version: str = "0.0.0"

    def __init__(self, params: ConnectionParams, secret: SecretMaterial | None):
        self.params = params
        self.secret = secret

    @abstractmethod
    def test_connection(self) -> ConnectionTestResult: ...

    @abstractmethod
    def discover_capabilities(self) -> list[CapabilityResult]: ...

    @abstractmethod
    def open_file_source(self, root: str) -> FileSource: ...


# --------------------------------------------------------------------------
# Path safety
# --------------------------------------------------------------------------


def normalise_root(root: str) -> str:
    root = (root or "/").replace("\\", "/")
    if "\x00" in root:
        raise ConnectorError(E_PATH, "Root path contains invalid characters.")
    norm = posixpath.normpath(root)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return norm


def validate_name(name: str) -> bool:
    return bool(name) and name not in (".", "..") and "/" not in name and "\x00" not in name


def safe_rel(rel_path: str) -> str:
    """Normalise a relative path and reject anything escaping its root."""
    rel = (rel_path or ".").replace("\\", "/")
    if "\x00" in rel or rel.startswith("/"):
        raise ConnectorError(E_PATH, "Path must be relative to the monitored root.")
    norm = posixpath.normpath(rel)
    if norm == ".." or norm.startswith("../"):
        raise ConnectorError(E_PATH, "Path escapes the monitored root.")
    return norm


def safe_join(root: str, rel_path: str) -> str:
    root = normalise_root(root)
    rel = safe_rel(rel_path)
    joined = root if rel == "." else posixpath.normpath(posixpath.join(root, rel))
    if root != "/" and not (joined == root or joined.startswith(root.rstrip("/") + "/")):
        raise ConnectorError(E_PATH, "Path escapes the monitored root.")
    return joined


def join_rel(parent: str, name: str) -> str:
    if not validate_name(name):
        raise ConnectorError(E_PATH, "Remote returned an unsafe file name.")
    return name if parent in ("", ".") else f"{parent}/{name}"
