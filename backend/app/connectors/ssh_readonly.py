"""SSH read-only connector: SFTP plus a short allow-list of read-only commands.

Everything the SFTP connector does (pinned address, trust-on-first-use host key, read-only SFTP operations,
no agent or local keys) applies unchanged. In addition the connector may run exactly these commands over an
SSH ``exec`` channel:

* ``sha256sum -- <files>`` and ``md5sum -- <files>``: fingerprint files on the server, so that content
  already scanned is recognised without downloading it again (the weekly full pass becomes cheap, and a
  file altered with a forged modification time is still caught because its fingerprint changes).

Commands are never built from free text: the program comes from ``ALLOWED_PROGRAMS`` and every argument is
a path that passed ``safe_join`` (it cannot leave the monitored root) and is shell-quoted. Output is size and
time limited. Nothing that writes, deletes or executes site code is ever sent.

Trust: a server that can lie about fingerprints could equally serve altered bytes over SFTP, so remote
fingerprints add no new trust in the host. They are still cross-checked: before the first batch of a scan is
used, one file is downloaded and hashed locally and must match the server's answer; on any mismatch,
error, or a host that does not allow commands (for example an SFTP-only account), the connector falls back
to downloading files exactly like the SFTP connector.
"""

from __future__ import annotations

import hashlib
import logging
import shlex
import time

import paramiko

from app.connectors.base import (
    AVAILABLE,
    E_PROTOCOL,
    E_TIMEOUT,
    UNAVAILABLE,
    Capability,
    CapabilityResult,
    ConnectorError,
    safe_rel,
)
from app.connectors.sftp import SFTPConnector, SFTPFileSource

log = logging.getLogger(__name__)

ALLOWED_PROGRAMS = frozenset({"sha256sum", "md5sum"})
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_COMMAND_BYTES = 32 * 1024  # well below ARG_MAX on any Linux host
MAX_BATCH_FILES = 200


def run_command(transport: paramiko.Transport, program: str, args: list[str], timeout: float) -> tuple[int, str, str]:
    """Run one allow-listed program with quoted arguments. Returns (exit status, stdout, stderr)."""
    if program not in ALLOWED_PROGRAMS:
        raise ConnectorError(E_PROTOCOL, f"Command '{program}' is not on the read-only allow-list.")
    if any("\x00" in a or "\n" in a for a in args):
        raise ConnectorError(E_PROTOCOL, "Command argument contains a control character.")
    command = " ".join([program, *(shlex.quote(a) for a in args)])
    if len(command.encode()) > MAX_COMMAND_BYTES:
        raise ConnectorError(E_PROTOCOL, "Command line too long.")
    try:
        chan = transport.open_session(timeout=timeout)
    except (paramiko.SSHException, OSError, EOFError) as exc:
        raise ConnectorError(E_PROTOCOL, "The server did not open a command channel.") from exc
    try:
        chan.settimeout(timeout)
        try:
            chan.exec_command(command)
        except paramiko.SSHException as exc:
            raise ConnectorError(E_PROTOCOL, "The server does not allow commands on this account.") from exc
        out, err = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        while True:
            if time.monotonic() > deadline:
                raise ConnectorError(E_TIMEOUT, f"'{program}' did not finish in time.", retryable=True)
            try:
                if chan.recv_ready():
                    out += chan.recv(65536)
                elif chan.recv_stderr_ready():
                    err += chan.recv_stderr(65536)
                elif chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                else:
                    time.sleep(0.01)
            except TimeoutError as exc:
                raise ConnectorError(E_TIMEOUT, f"'{program}' did not finish in time.", retryable=True) from exc
            if len(out) > MAX_OUTPUT_BYTES or len(err) > MAX_OUTPUT_BYTES:
                raise ConnectorError(E_PROTOCOL, f"'{program}' produced more output than permitted.")
        return chan.recv_exit_status(), out.decode("utf-8", "replace"), err.decode("utf-8", "replace")[:500]
    finally:
        chan.close()


def parse_digests(output: str, hex_len: int) -> dict[str, str]:
    """``<hex>  <path>`` lines (``*`` marks binary mode). Lines starting with a backslash have escaped names
    (newline or backslash in the name); they are skipped and those files are downloaded instead."""
    found = {}
    for line in output.splitlines():
        if line.startswith("\\") or len(line) < hex_len + 2:
            continue
        digest, sep, rest = line[:hex_len], line[hex_len:hex_len + 2], line[hex_len + 2:]
        if sep not in ("  ", " *") or any(c not in "0123456789abcdef" for c in digest):
            continue
        found[rest] = digest
    return found


class SSHFileSource(SFTPFileSource):
    """SFTP file source that can also fingerprint files on the server (see module docstring)."""

    def __init__(self, root, transport, sftp, timeout: float):
        super().__init__(root, transport, sftp)
        self._timeout = timeout
        self.remote_hashing = True
        self._verified = False
        self.remote_hash_note = "not used yet"

    def _digest_batch(self, rels: list[str]) -> dict[str, tuple[str, str]]:
        absolute = {self.absolute(safe_rel(r)): r for r in rels}
        paths = list(absolute)
        _, sha_out, _ = run_command(self._transport, "sha256sum", ["--", *paths], self._timeout)
        _, md5_out, _ = run_command(self._transport, "md5sum", ["--", *paths], self._timeout)
        sha, md5 = parse_digests(sha_out, 64), parse_digests(md5_out, 32)
        return {absolute[p]: (sha[p], md5[p]) for p in paths if p in sha and p in md5}

    def _batches(self, rels: list[str]):
        batch, length = [], 0
        for r in rels:
            n = len(shlex.quote(self.absolute(r))) + 1
            if batch and (len(batch) >= MAX_BATCH_FILES or length + n > MAX_COMMAND_BYTES - 64):
                yield batch
                batch, length = [], 0
            batch.append(r)
            length += n
        if batch:
            yield batch

    def remote_digests(self, rels: list[str], sizes: dict[str, int | None] | None = None) -> dict[str, tuple[str, str]]:
        """SHA-256 and MD5 of files, computed on the server. Files missing from the answer must be downloaded.
        Never raises: on any problem remote hashing is switched off for the rest of this source's life."""
        if not self.remote_hashing or not rels:
            return {}
        try:
            out: dict[str, tuple[str, str]] = {}
            for batch in self._batches(rels):
                out.update(self._digest_batch(batch))
            if not self._verified and out:
                self._cross_check(out, sizes or {})
            return out
        except ConnectorError as exc:
            self._disable(exc.message)
            return {}

    def _cross_check(self, digests: dict[str, tuple[str, str]], sizes: dict[str, int | None]) -> None:
        """Download the smallest file of the first batch and compare with the server's fingerprints."""
        rel = min(digests, key=lambda r: sizes.get(r) or 0)
        h, m = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
        for chunk in self.read_chunks(rel):
            h.update(chunk)
            m.update(chunk)
        if (h.hexdigest(), m.hexdigest()) != digests[rel]:
            digests.clear()
            raise ConnectorError(E_PROTOCOL, f"Server fingerprint of {rel} did not match its downloaded content.")
        self._verified = True
        self.remote_hash_note = "server fingerprints verified against a downloaded file"

    def _disable(self, reason: str) -> None:
        if self.remote_hashing:
            log.warning("ssh remote hashing disabled: %s", reason)
        self.remote_hashing = False
        self.remote_hash_note = f"not used: {reason}"


class SSHReadOnlyConnector(SFTPConnector):
    key = "ssh_readonly"
    version = "1.0.0"

    def open_file_source(self, root: str) -> SSHFileSource:
        transport, sftp, _, _ = self._connect()
        return SSHFileSource(root, transport, sftp, self.params.io_timeout)

    def _log_paths(self) -> list[str]:
        from app.monitoring.logs import DEFAULT_LOG_DIRS

        configured = [p for p in self.params.options.get("log_paths", []) if isinstance(p, str)]
        return configured or DEFAULT_LOG_DIRS[self.key]

    def discover_capabilities(self) -> list[CapabilityResult]:
        # Same file and log checks as SFTP, but with the home-directory log folders as defaults.
        configured = self.params.options.get("log_paths")
        self.params.options["log_paths"] = self._log_paths()
        try:
            results = {r.capability: r for r in super().discover_capabilities()}
        finally:
            if configured is None:
                self.params.options.pop("log_paths", None)
            else:
                self.params.options["log_paths"] = configured
        results[Capability.FILE_HASHING] = self._probe_remote_hashing(results.get(Capability.FILE_HASHING))
        results[Capability.HOSTING_MALWARE_SCAN] = CapabilityResult(
            Capability.HOSTING_MALWARE_SCAN, UNAVAILABLE,
            "Server-side scanners are not run over SSH (only fingerprinting commands are allowed). "
            "Use the hosting provider security connector where the provider offers one.",
        )
        return list(results.values())

    def _probe_remote_hashing(self, base: CapabilityResult | None) -> CapabilityResult:
        if base is None or base.status != AVAILABLE:
            return base or CapabilityResult(Capability.FILE_HASHING, UNAVAILABLE, "Files could not be read.")
        src = self.open_file_source(self.params.root_path)
        try:
            sample = self._find_sample_file(src, src.list_dir("."))
            if sample is None:
                return base
            src.remote_digests([sample])
            if src.remote_hashing:
                note = ("Files are read over SFTP; fingerprints are also computed on the server (sha256sum/md5sum, "
                        "checked against a downloaded file), so unchanged content is not downloaded again.")
            else:
                note = (f"Files are read over SFTP. Server-side fingerprinting is {src.remote_hash_note}; every "
                        "file is downloaded instead (slower full checks, same results).")
            return CapabilityResult(Capability.FILE_HASHING, AVAILABLE, note)
        except ConnectorError:
            return base
        finally:
            src.close()
