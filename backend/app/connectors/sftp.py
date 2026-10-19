"""Read-only SFTP connector (paramiko).

Security properties:

* The destination is resolved once and vetted by the outbound network policy;
  the TCP connection is made to that pinned address.
* The server host key is recorded on first contact (trust-on-first-use) and
  every later connection must present the same key; a mismatch aborts before
  any credential is sent.
* Only read operations are used: ``listdir_attr``, ``readlink`` and opening
  files in ``rb`` mode. Symbolic links are recorded, never followed.
* SSH agent and local key discovery are disabled; only the stored credential
  is offered.
"""

from __future__ import annotations

import base64
import hashlib
import io
import socket
import stat
from collections.abc import Iterator
from datetime import UTC, datetime

import paramiko

from app.connectors.base import (
    AVAILABLE,
    E_AUTH,
    E_CONFIG,
    E_DNS,
    E_HOST_KEY_MISMATCH,
    E_NOT_FOUND,
    E_PERMISSION,
    E_PROTOCOL,
    E_REFUSED,
    E_TARGET_NOT_ALLOWED,
    E_TIMEOUT,
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
from app.core.netguard import DNSResolutionError, TargetNotAllowed, resolve_public_target


def host_key_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def load_private_key(text: str, passphrase: str | None) -> paramiko.PKey:
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase)
        except paramiko.PasswordRequiredException as exc:
            raise ConnectorError(E_CONFIG, "The private key is encrypted and needs a passphrase.") from exc
        except (paramiko.SSHException, ValueError) as exc:
            errors.append(type(exc).__name__)
    raise ConnectorError(E_CONFIG, "The private key could not be parsed (supported: Ed25519, ECDSA, RSA).")


def _entry_type(mode: int | None) -> str:
    if mode is None:
        return "other"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    return "other"


def _classify_io_error(exc: Exception, rel: str) -> ConnectorError:
    if isinstance(exc, PermissionError) or (isinstance(exc, OSError) and exc.errno == 13):
        return ConnectorError(E_PERMISSION, f"Permission denied: {rel}")
    if isinstance(exc, FileNotFoundError) or (isinstance(exc, OSError) and exc.errno == 2):
        return ConnectorError(E_NOT_FOUND, f"Not found: {rel}")
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ConnectorError(E_TIMEOUT, f"Timed out reading {rel}", retryable=True)
    return ConnectorError(E_PROTOCOL, f"Could not read {rel}: {type(exc).__name__}", retryable=True)


class SFTPFileSource(FileSource):
    def __init__(self, root: str, transport: paramiko.Transport, sftp: paramiko.SFTPClient):
        super().__init__(root)
        self._transport = transport
        self._sftp = sftp

    def list_dir(self, rel_path: str) -> list[RemoteEntry]:
        rel = safe_rel(rel_path)
        try:
            attrs = self._sftp.listdir_attr(self.absolute(rel))
        except Exception as exc:  # noqa: BLE001
            raise _classify_io_error(exc, rel) from exc
        out = []
        for a in attrs:
            # validate name via join_rel (raises on unsafe names)
            join_rel(rel, a.filename)
            etype = _entry_type(a.st_mode)
            out.append(
                RemoteEntry(
                    name=a.filename,
                    entry_type=etype,
                    size=a.st_size if etype == "file" else None,
                    mtime=datetime.fromtimestamp(a.st_mtime, tz=UTC) if a.st_mtime is not None else None,
                    mode=stat.S_IMODE(a.st_mode) if a.st_mode is not None else None,
                )
            )
        return out

    def readlink(self, rel_path: str) -> str | None:
        try:
            return self._sftp.readlink(self.absolute(rel_path))
        except Exception:  # noqa: BLE001
            return None

    def read_chunks(self, rel_path: str, chunk_size: int = 65536) -> Iterator[bytes]:
        rel = safe_rel(rel_path)
        path = self.absolute(rel)
        try:
            # lstat first: never open through a symlink.
            st = self._sftp.lstat(path)
            if st.st_mode is None or not stat.S_ISREG(st.st_mode):
                raise ConnectorError(E_PERMISSION, f"Not a regular file: {rel}")
            fh = self._sftp.open(path, "rb")
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _classify_io_error(exc, rel) from exc
        try:
            fh.prefetch(st.st_size)
            while True:
                try:
                    chunk = fh.read(chunk_size)
                except Exception as exc:  # noqa: BLE001
                    raise _classify_io_error(exc, rel) from exc
                if not chunk:
                    break
                yield chunk
        finally:
            fh.close()

    def close(self) -> None:
        try:
            self._sftp.close()
        finally:
            self._transport.close()


class SFTPConnector(Connector):
    key = "sftp"
    version = "1.0.0"

    def _connect(self, diagnostics: list[Diagnostic] | None = None) -> tuple[paramiko.Transport, paramiko.SFTPClient, str, str]:
        diags = diagnostics if diagnostics is not None else []
        p = self.params
        settings = get_settings()
        try:
            target = resolve_public_target(p.hostname, p.port, settings.allowed_sftp_ports)
        except TargetNotAllowed as exc:
            diags.append(Diagnostic("network_policy", False, str(exc), E_TARGET_NOT_ALLOWED))
            raise ConnectorError(E_TARGET_NOT_ALLOWED, str(exc)) from exc
        except DNSResolutionError as exc:
            diags.append(Diagnostic("dns", False, str(exc), E_DNS))
            raise ConnectorError(E_DNS, str(exc), retryable=True) from exc
        diags.append(Diagnostic("dns", True, f"Resolved to a permitted address ({target.ip})."))

        try:
            sock = socket.create_connection((target.ip, target.port), timeout=p.connect_timeout)
        except TimeoutError as exc:
            diags.append(Diagnostic("tcp", False, "Connection timed out.", E_TIMEOUT))
            raise ConnectorError(E_TIMEOUT, "Connection timed out.", retryable=True) from exc
        except OSError as exc:
            diags.append(Diagnostic("tcp", False, "Connection refused or unreachable.", E_REFUSED))
            raise ConnectorError(E_REFUSED, "Connection refused or host unreachable.", retryable=True) from exc
        diags.append(Diagnostic("tcp", True, f"TCP connection to port {target.port} established."))

        transport = paramiko.Transport(sock)
        transport.banner_timeout = p.connect_timeout
        transport.auth_timeout = p.connect_timeout
        try:
            transport.start_client(timeout=p.connect_timeout)
            key = transport.get_remote_server_key()
            fp = host_key_fingerprint(key)
            key_type = key.get_name()
            if p.expected_host_key and p.expected_host_key != fp:
                diags.append(
                    Diagnostic(
                        "host_key",
                        False,
                        "The server's host key has changed since it was first trusted. "
                        "This may indicate a server rebuild or an interception attempt.",
                        E_HOST_KEY_MISMATCH,
                    )
                )
                raise ConnectorError(
                    E_HOST_KEY_MISMATCH,
                    "Server host key does not match the trusted fingerprint.",
                    detail={"presented": fp, "expected": p.expected_host_key},
                )
            diags.append(Diagnostic("host_key", True, f"Host key {key_type} {fp}."))

            if self.secret is None:
                raise ConnectorError(E_CONFIG, "No credential is stored for this connection.")
            try:
                if self.secret.kind == "password":
                    transport.auth_password(p.username, self.secret.value)
                elif self.secret.kind == "private_key":
                    transport.auth_publickey(p.username, load_private_key(self.secret.value, self.secret.passphrase))
                else:
                    raise ConnectorError(E_CONFIG, "SFTP requires a password or private key.")
            except paramiko.AuthenticationException as exc:
                diags.append(Diagnostic("authentication", False, "Credentials were rejected by the server.", E_AUTH))
                raise ConnectorError(E_AUTH, "Authentication failed: credentials were rejected.") from exc
            diags.append(Diagnostic("authentication", True, "Authenticated."))
            try:
                sftp = paramiko.SFTPClient.from_transport(transport)
            except paramiko.SSHException as exc:
                diags.append(Diagnostic("sftp_subsystem", False, "SFTP subsystem is not available.", E_PROTOCOL))
                raise ConnectorError(E_PROTOCOL, "The SFTP subsystem is not available on this account.") from exc
            assert sftp is not None
            sftp.get_channel().settimeout(p.io_timeout)
            diags.append(Diagnostic("sftp_subsystem", True, "SFTP session opened."))
            return transport, sftp, fp, key_type
        except ConnectorError:
            transport.close()
            raise
        except (paramiko.SSHException, EOFError, OSError) as exc:
            transport.close()
            diags.append(Diagnostic("ssh_handshake", False, "SSH handshake failed.", E_PROTOCOL))
            raise ConnectorError(E_PROTOCOL, "SSH handshake failed.", retryable=True) from exc

    def test_connection(self) -> ConnectionTestResult:
        diags: list[Diagnostic] = []
        try:
            transport, sftp, fp, key_type = self._connect(diags)
        except ConnectorError as exc:
            return ConnectionTestResult(
                False, diags, exc.code, exc.message,
                host_key_fingerprint=exc.detail.get("presented"),
            )
        try:
            source = SFTPFileSource(self.params.root_path, transport, sftp)
            try:
                source.list_dir(".")
                diags.append(Diagnostic("root_listing", True, f"Listed authorised root {source.root}."))
                ok, code, msg = True, None, None
            except ConnectorError as exc:
                diags.append(Diagnostic("root_listing", False, exc.message, exc.code))
                ok, code, msg = False, exc.code, exc.message
        finally:
            transport.close()
        return ConnectionTestResult(ok, diags, code, msg, host_key_type=key_type, host_key_fingerprint=fp,
                                    server_info={"remote_version": transport.remote_version})

    def discover_capabilities(self) -> list[CapabilityResult]:
        results: dict[Capability, CapabilityResult] = {}
        transport, sftp, _, _ = self._connect()
        source = SFTPFileSource(self.params.root_path, transport, sftp)
        try:
            try:
                entries = source.list_dir(".")
                results[Capability.FILE_LISTING] = CapabilityResult(
                    Capability.FILE_LISTING, AVAILABLE, f"Directory listing permitted under {source.root}."
                )
                has_meta = any(e.mtime is not None for e in entries) or not entries
                results[Capability.FILE_METADATA] = CapabilityResult(
                    Capability.FILE_METADATA,
                    AVAILABLE if has_meta else UNAVAILABLE,
                    "Size, modification time and permissions are returned." if has_meta
                    else "The server does not return file timestamps.",
                )
                sample = self._find_sample_file(source, entries)
                if sample is None:
                    for cap in (Capability.FILE_CONTENT_READ, Capability.FILE_HASHING):
                        results[cap] = CapabilityResult(
                            cap, UNTESTED, "No regular file found near the root to test reading safely."
                        )
                else:
                    try:
                        next(iter(source.read_chunks(sample, chunk_size=1)), b"")
                        for cap in (Capability.FILE_CONTENT_READ, Capability.FILE_HASHING):
                            results[cap] = CapabilityResult(
                                cap, AVAILABLE, "Read access verified on a sample file (content streamed, not stored)."
                            )
                    except ConnectorError as exc:
                        for cap in (Capability.FILE_CONTENT_READ, Capability.FILE_HASHING):
                            results[cap] = CapabilityResult(
                                cap, UNAVAILABLE, f"Reading files failed: {exc.message}",
                                required_permission="Read permission on website files",
                            )
            except ConnectorError as exc:
                for cap in (Capability.FILE_LISTING, Capability.FILE_METADATA, Capability.FILE_CONTENT_READ,
                            Capability.FILE_HASHING):
                    results[cap] = CapabilityResult(
                        cap, UNAVAILABLE, f"Listing the authorised root failed: {exc.message}",
                        required_permission="Read and list permission on the configured root directory",
                    )

            log_paths = [p for p in self.params.options.get("log_paths", []) if isinstance(p, str)]
            if not log_paths:
                results[Capability.LOG_ACCESS] = CapabilityResult(
                    Capability.LOG_ACCESS, UNTESTED,
                    "No log path configured. SFTP access does not imply access to web server logs.",
                    required_permission="Read access to the account's access/error log directory",
                )
            else:
                ok = []
                for lp in log_paths:
                    try:
                        sftp.listdir_attr(lp)
                        ok.append(lp)
                    except Exception:  # noqa: BLE001,S112
                        continue
                results[Capability.LOG_ACCESS] = CapabilityResult(
                    Capability.LOG_ACCESS,
                    AVAILABLE if ok else UNAVAILABLE,
                    f"Readable log locations: {', '.join(ok)}" if ok else "Configured log paths are not readable.",
                )
        finally:
            source.close()

        results[Capability.WEBSITE_MALWARE_SCAN] = CapabilityResult(
            Capability.WEBSITE_MALWARE_SCAN, UNSUPPORTED,
            "Platform-side malware scanning of retrieved files is not yet enabled in this release.",
        )
        results[Capability.HOSTING_MALWARE_SCAN] = CapabilityResult(
            Capability.HOSTING_MALWARE_SCAN, UNSUPPORTED, "SFTP cannot run or query server-side malware scanners."
        )
        results[Capability.REALTIME_FILE_EVENTS] = CapabilityResult(
            Capability.REALTIME_FILE_EVENTS, UNSUPPORTED,
            "SFTP polling detects changes between scans only; it cannot observe uploads in real time.",
        )
        results[Capability.PROVIDER_SECURITY_API] = CapabilityResult(
            Capability.PROVIDER_SECURITY_API, UNSUPPORTED, "Not available through SFTP."
        )
        return list(results.values())

    @staticmethod
    def _find_sample_file(source: SFTPFileSource, entries: list[RemoteEntry]) -> str | None:
        for e in entries:
            if e.entry_type == "file":
                return e.name
        for e in entries[:10]:
            if e.entry_type == "dir":
                try:
                    for sub in source.list_dir(e.name):
                        if sub.entry_type == "file":
                            return join_rel(e.name, sub.name)
                except ConnectorError:
                    continue
        return None

    def open_file_source(self, root: str) -> SFTPFileSource:
        transport, sftp, _, _ = self._connect()
        return SFTPFileSource(root, transport, sftp)
