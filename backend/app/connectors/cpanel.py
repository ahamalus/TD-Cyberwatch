"""cPanel UAPI connector (read-only).

Uses the UAPI HTTP interface ``https://<host>:2083/execute/<Module>/<function>``
with an API token (``Authorization: cpanel <user>:<token>``).

Functions used (all read-only):

* ``Fileman::list_files`` – directory listing (``dir``, ``include_mime``,
  ``include_permissions``, ``show_hidden``)
* ``Fileman::get_file_content`` – file content (``dir``, ``file``,
  ``from_charset``, ``to_charset``). cPanel documents that non-UTF-8 content
  can be retrieved by declaring ``ISO-8859-1`` as the source charset and
  ``UTF-8`` as the target; decoding the JSON string and re-encoding it as
  Latin-1 then yields the original bytes.

VERIFICATION STATUS: parameter names ``show_hidden``/``include_permissions``
and the exact per-entry response field names could not be confirmed against
live cPanel documentation from the build environment. The parser below is
deliberately tolerant and the capability discovery reports what it actually
observes. Validate against a live cPanel account before production use
(see docs/connectors.md).
"""

from __future__ import annotations

import json
import posixpath
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx

from app.connectors.base import (
    AVAILABLE,
    E_AUTH,
    E_CONFIG,
    E_DNS,
    E_NOT_FOUND,
    E_PERMISSION,
    E_PROTOCOL,
    E_RATE_LIMITED,
    E_REFUSED,
    E_TARGET_NOT_ALLOWED,
    E_TIMEOUT,
    E_TLS,
    UNAVAILABLE,
    UNSUPPORTED,
    UNTESTED,
    Capability,
    CapabilityResult,
    ConnectionTestResult,
    Connector,
    ConnectorError,
    Diagnostic,
    FileSource,
    RemoteEntry,
    join_rel,
    safe_rel,
)
from app.core.config import get_settings
from app.core.http import PinnedSession, pinned_request
from app.core.netguard import DNSResolutionError, TargetNotAllowed

# get_file_content returns the whole file in one JSON response, so the size
# limit for this connector is intentionally lower than for SFTP.
CPANEL_MAX_CONTENT_BYTES = 5 * 1024 * 1024


class CPanelClient:
    def __init__(self, params, token: str, keep_alive: bool = False):
        self.params = params
        self._token = token
        # File scans make one request per file: keep-alive reuses one vetted, pinned connection pool
        # instead of a new DNS lookup and TLS handshake per file.
        self._keep_alive = keep_alive
        self._session: PinnedSession | None = None
        self._session_lock = threading.Lock()

    def _get_session(self) -> PinnedSession:
        with self._session_lock:
            if self._session is None:
                p = self.params
                self._session = PinnedSession(
                    f"https://{p.hostname}:{p.port}", allowed_ports=getattr(get_settings(), self.ports_setting),
                    timeout=p.io_timeout, max_connections=max(1, get_settings().cpanel_parallel_reads))
            return self._session

    def close(self) -> None:
        with self._session_lock:
            if self._session is not None:
                self._session.close()
                self._session = None

    # Overridden by the WHM client (which reaches the same UAPI functions through WHM API 1).
    label = "cPanel"
    ports_setting = "allowed_cpanel_ports"

    def _auth_header(self) -> str:
        return f"cpanel {self.params.username}:{self._token}"

    def _endpoint(self, module: str, function: str, query: dict[str, str]) -> tuple[str, dict[str, str]]:
        return f"/execute/{module}/{function}", query

    def _unwrap(self, payload: Any) -> Any:
        # /execute returns the result object directly; tolerate a wrapped form.
        return payload.get("result", payload) if isinstance(payload, dict) else {}

    def call(self, module: str, function: str, query: dict[str, str]) -> Any:
        path, params = self._endpoint(module, function, query)
        return self._uapi_result(self._get_json(path, params))

    def _get_json(self, path: str, params: dict[str, str]) -> Any:
        p = self.params
        label = self.label
        allowed_ports = getattr(get_settings(), self.ports_setting)
        headers = {"Authorization": self._auth_header()}
        max_body = CPANEL_MAX_CONTENT_BYTES * 2 + 65536
        try:
            if self._keep_alive:
                resp = self._get_session().request("GET", path, headers=headers, params=params,
                                                   max_body_bytes=max_body)
            else:
                resp = pinned_request(
                    "GET",
                    f"https://{p.hostname}:{p.port}{path}",
                    allowed_ports=allowed_ports,
                    headers=headers,
                    params=params,
                    timeout=p.io_timeout,
                    max_redirects=0,
                    max_body_bytes=max_body,
                )
        except TargetNotAllowed as exc:
            raise ConnectorError(E_TARGET_NOT_ALLOWED, str(exc)) from exc
        except DNSResolutionError as exc:
            raise ConnectorError(E_DNS, str(exc), retryable=True) from exc
        except httpx.ConnectTimeout as exc:
            raise ConnectorError(E_TIMEOUT, f"Connection to {label} timed out.", retryable=True) from exc
        except httpx.ReadTimeout as exc:
            raise ConnectorError(E_TIMEOUT, f"{label} did not respond in time.", retryable=True) from exc
        except httpx.ConnectError as exc:
            text = str(exc).lower()
            if "certificate" in text or "ssl" in text:
                raise ConnectorError(E_TLS, f"{label} TLS certificate could not be verified.") from exc
            raise ConnectorError(E_REFUSED, f"Could not connect to {label}.", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise ConnectorError(E_PROTOCOL, f"{label} request failed ({type(exc).__name__}).", retryable=True) from exc

        if resp.status_code in (401, 403):
            raise ConnectorError(E_AUTH, f"{label} rejected the API token or username.")
        if resp.status_code == 429:
            raise ConnectorError(E_RATE_LIMITED, f"{label} rate limit reached.", retryable=True)
        if resp.status_code >= 500:
            raise ConnectorError(E_PROTOCOL, f"{label} returned HTTP {resp.status_code}.", retryable=True)
        if resp.status_code != 200:
            raise ConnectorError(E_PROTOCOL, f"{label} returned HTTP {resp.status_code}.")
        if resp.truncated:
            raise ConnectorError(E_PROTOCOL, f"{label} response exceeded the permitted size.")
        try:
            return json.loads(resp.body)
        except ValueError as exc:
            raise ConnectorError(E_PROTOCOL, f"{label} returned a non-JSON response.") from exc

    def _uapi_result(self, payload: Any) -> Any:
        result = self._unwrap(payload)
        if not isinstance(result, dict):
            raise ConnectorError(E_PROTOCOL, f"Unexpected {self.label} response structure.")
        if result.get("status") in (0, "0", False):
            errors = " ".join(str(e) for e in (result.get("errors") or []))[:300]
            lowered = errors.lower()
            if "access denied" in lowered or "permission" in lowered:
                raise ConnectorError(E_PERMISSION, f"cPanel denied the request: {errors}")
            if "no such file" in lowered or "does not exist" in lowered or "not found" in lowered:
                raise ConnectorError(E_NOT_FOUND, f"cPanel reported a missing path: {errors}")
            if "feature" in lowered:
                raise ConnectorError(E_PERMISSION, f"The required cPanel feature is disabled: {errors}")
            raise ConnectorError(E_PROTOCOL, f"cPanel reported an error: {errors or 'unknown'}")
        return result.get("data")


def _parse_mtime(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=UTC) if value not in (None, "") else None
    except (TypeError, ValueError, OverflowError):
        return None


def _parse_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_mode(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value), 8) & 0o7777 if isinstance(value, str) else int(value) & 0o7777
    except ValueError:
        return None


_TYPE_MAP = {"dir": "dir", "file": "file", "link": "symlink", "symlink": "symlink"}


class CPanelFileSource(FileSource):
    def __init__(self, root: str, client: CPanelClient):
        super().__init__(root)
        self._client = client
        # UAPI fetches one file per HTTPS request; a few at a time stays within shared-hosting process limits.
        self.parallel_reads = max(1, get_settings().cpanel_parallel_reads)

    def close(self) -> None:
        self._client.close()

    def _dir_param(self, rel: str) -> str:
        # UAPI paths are relative to the account home directory.
        absolute = self.absolute(rel)
        return absolute.lstrip("/") or "."

    def list_dir(self, rel_path: str) -> list[RemoteEntry]:
        rel = safe_rel(rel_path)
        data = self._client.call(
            "Fileman",
            "list_files",
            {"dir": self._dir_param(rel), "include_mime": "0", "include_permissions": "1", "show_hidden": "1"},
        )
        if not isinstance(data, list):
            raise ConnectorError(E_PROTOCOL, "Unexpected list_files response.")
        out: list[RemoteEntry] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            name = item.get("file") or posixpath.basename(str(item.get("fullpath", "")).rstrip("/"))
            if not name:
                continue
            join_rel(rel, name)  # validates the name
            etype = _TYPE_MAP.get(str(item.get("type", "")).lower(), "other")
            out.append(
                RemoteEntry(
                    name=name,
                    entry_type=etype,
                    size=_parse_int(item.get("size")) if etype == "file" else None,
                    mtime=_parse_mtime(item.get("mtime")),
                    mode=_parse_mode(item.get("nicemode") or item.get("mode")),
                )
            )
        return out

    def read_chunks(self, rel_path: str, chunk_size: int = 65536) -> Iterator[bytes]:
        rel = safe_rel(rel_path)
        parent, name = posixpath.split(self.absolute(rel))
        data = self._client.call(
            "Fileman",
            "get_file_content",
            {
                "dir": parent.lstrip("/") or ".",
                "file": name,
                "from_charset": "ISO-8859-1",
                "to_charset": "UTF-8",
            },
        )
        content = data.get("content") if isinstance(data, dict) else None
        if not isinstance(content, str):
            raise ConnectorError(E_PROTOCOL, f"No content returned for {rel}.")
        try:
            raw = content.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ConnectorError(
                E_PROTOCOL, f"Content of {rel} could not be recovered byte-exactly; not hashed."
            ) from exc
        for i in range(0, len(raw), chunk_size):
            yield raw[i : i + chunk_size]


class CPanelUAPIConnector(Connector):
    key = "cpanel_uapi"
    version = "0.9.0"

    def _client(self, keep_alive: bool = False) -> CPanelClient:
        if self.secret is None or self.secret.kind != "api_token":
            raise ConnectorError(E_CONFIG, "cPanel UAPI requires a cPanel API token.")
        return CPanelClient(self.params, self.secret.value, keep_alive=keep_alive)

    def test_connection(self) -> ConnectionTestResult:
        diags: list[Diagnostic] = []
        try:
            source = CPanelFileSource(self.params.root_path, self._client())
            source.list_dir(".")
            diags.append(Diagnostic("authentication", True, "API token accepted."))
            diags.append(Diagnostic("root_listing", True, f"Listed authorised root {source.root}."))
            return ConnectionTestResult(True, diags)
        except ConnectorError as exc:
            step = "authentication" if exc.code == E_AUTH else "request"
            diags.append(Diagnostic(step, False, exc.message, exc.code))
            return ConnectionTestResult(False, diags, exc.code, exc.message)

    def _probe_logs(self) -> CapabilityResult:
        """Raw access logs: cPanel keeps the current ones in ~/access-logs (a link to the server's domain logs).
        Available only if a log is actually read and recognised; never assumed."""
        from app.monitoring.logs import DEFAULT_LOG_DIRS, probe

        dirs = [p for p in self.params.options.get("log_paths", []) if isinstance(p, str)] or DEFAULT_LOG_DIRS[self.key]
        ok, notes = [], []
        for d in dirs:
            src = CPanelFileSource(d, self._client())
            try:
                good, note = probe(src, d)
            except ConnectorError as exc:
                good, note = False, f"{d}: {exc.message}"
            finally:
                src.close()
            (ok if good else notes).append(note)
        return CapabilityResult(
            Capability.LOG_ACCESS, AVAILABLE if ok else UNAVAILABLE, "; ".join(ok or notes),
            required_permission="cPanel Raw Access Logs (the access-logs folder in the home directory)",
        )

    def discover_capabilities(self) -> list[CapabilityResult]:
        results: dict[Capability, CapabilityResult] = {}
        source = CPanelFileSource(self.params.root_path, self._client())
        try:
            entries = source.list_dir(".")
            results[Capability.FILE_LISTING] = CapabilityResult(
                Capability.FILE_LISTING, AVAILABLE, "Fileman::list_files permitted."
            )
            has_meta = any(e.mtime is not None for e in entries) or not entries
            results[Capability.FILE_METADATA] = CapabilityResult(
                Capability.FILE_METADATA, AVAILABLE if has_meta else UNAVAILABLE,
                "Size and modification time returned." if has_meta else "No timestamps returned by list_files.",
            )
            hidden_seen = any(e.name.startswith(".") for e in entries)
            sample = next((e.name for e in entries if e.entry_type == "file" and (e.size or 0) < 65536), None)
            if sample is None:
                for cap in (Capability.FILE_CONTENT_READ, Capability.FILE_HASHING):
                    results[cap] = CapabilityResult(cap, UNTESTED, "No small file at the root to test reading safely.")
            else:
                try:
                    list(source.read_chunks(sample))
                    detail = f"Fileman::get_file_content permitted; files up to {CPANEL_MAX_CONTENT_BYTES // (1024*1024)} MB are hashed."
                    for cap in (Capability.FILE_CONTENT_READ, Capability.FILE_HASHING):
                        results[cap] = CapabilityResult(cap, AVAILABLE, detail)
                except ConnectorError as exc:
                    for cap in (Capability.FILE_CONTENT_READ, Capability.FILE_HASHING):
                        results[cap] = CapabilityResult(cap, UNAVAILABLE, exc.message,
                                                        required_permission="cPanel File Manager feature")
            if not hidden_seen:
                results[Capability.FILE_LISTING].detail += (
                    " No dotfiles were observed at the root; confirm hidden files are listed on this server."
                )
        except ConnectorError as exc:
            for cap in (Capability.FILE_LISTING, Capability.FILE_METADATA, Capability.FILE_CONTENT_READ,
                        Capability.FILE_HASHING):
                results[cap] = CapabilityResult(cap, UNAVAILABLE, exc.message,
                                                required_permission="cPanel File Manager feature and API token")
        results[Capability.LOG_ACCESS] = self._probe_logs()
        results[Capability.WEBSITE_MALWARE_SCAN] = CapabilityResult(
            Capability.WEBSITE_MALWARE_SCAN, UNTESTED,
            "Decided by the platform scanner when capabilities are stored (see monitoring.jobs).",
        )
        results[Capability.HOSTING_MALWARE_SCAN] = CapabilityResult(
            Capability.HOSTING_MALWARE_SCAN, UNTESTED,
            "Server-side scanners (e.g. ClamAV/Imunify360 via cPanel) are not queried in this release.",
        )
        results[Capability.REALTIME_FILE_EVENTS] = CapabilityResult(
            Capability.REALTIME_FILE_EVENTS, UNSUPPORTED, "UAPI polling cannot observe file events in real time."
        )
        results[Capability.PROVIDER_SECURITY_API] = CapabilityResult(
            Capability.PROVIDER_SECURITY_API, UNSUPPORTED, "Not implemented for cPanel in this release."
        )
        return list(results.values())

    def open_file_source(self, root: str) -> CPanelFileSource:
        return CPanelFileSource(root, self._client(keep_alive=True))
