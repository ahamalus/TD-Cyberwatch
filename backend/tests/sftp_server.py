"""In-process SFTP server for tests (paramiko), serving a local directory.

The server is read-only: write operations return permission denied, which
also lets tests prove the connector never attempts to modify files. Paths
can be made unreadable via ``deny`` to simulate permission errors.
"""

from __future__ import annotations

import os
import socket
import threading
from dataclasses import dataclass, field

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface
from paramiko.sftp import SFTP_FAILURE, SFTP_NO_SUCH_FILE, SFTP_OK, SFTP_PERMISSION_DENIED


@dataclass
class ServerState:
    root: str
    username: str = "webuser"
    password: str = "correct-horse-battery"  # noqa: S105
    deny: set[str] = field(default_factory=set)  # absolute remote paths that fail
    write_attempts: list[str] = field(default_factory=list)
    authorized_key: paramiko.PKey | None = None


class _Handle(SFTPHandle):
    def stat(self):
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))


class _SFTP(SFTPServerInterface):
    def __init__(self, server, state: ServerState, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.state = state

    def _local(self, path: str) -> str:
        path = os.path.normpath("/" + path.lstrip("/"))
        return os.path.join(self.state.root, path.lstrip("/"))

    def _denied(self, path: str) -> bool:
        norm = os.path.normpath("/" + path.lstrip("/"))
        return any(norm == d or norm.startswith(d.rstrip("/") + "/") for d in self.state.deny)

    def list_folder(self, path):
        if self._denied(path):
            return SFTP_PERMISSION_DENIED
        local = self._local(path)
        try:
            out = []
            for name in os.listdir(local):
                attr = SFTPAttributes.from_stat(os.lstat(os.path.join(local, name)))
                attr.filename = name
                out.append(attr)
            return out
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        if self._denied(path):
            return SFTP_PERMISSION_DENIED
        try:
            return SFTPAttributes.from_stat(os.stat(self._local(path)))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        if self._denied(path):
            return SFTP_PERMISSION_DENIED
        try:
            return SFTPAttributes.from_stat(os.lstat(self._local(path)))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            self.state.write_attempts.append(path)
            return SFTP_PERMISSION_DENIED
        if self._denied(path):
            return SFTP_PERMISSION_DENIED
        try:
            f = open(self._local(path), "rb")  # noqa: SIM115
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        h = _Handle(flags)
        h.filename = self._local(path)
        h.readfile = f
        return h

    def readlink(self, path):
        try:
            return os.readlink(self._local(path))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def remove(self, path):
        self.state.write_attempts.append(path)
        return SFTP_PERMISSION_DENIED

    def rename(self, oldpath, newpath):
        self.state.write_attempts.append(oldpath)
        return SFTP_PERMISSION_DENIED

    def mkdir(self, path, attr):
        self.state.write_attempts.append(path)
        return SFTP_PERMISSION_DENIED

    def rmdir(self, path):
        self.state.write_attempts.append(path)
        return SFTP_PERMISSION_DENIED

    def chattr(self, path, attr):
        self.state.write_attempts.append(path)
        return SFTP_PERMISSION_DENIED

    def symlink(self, target_path, path):
        self.state.write_attempts.append(path)
        return SFTP_PERMISSION_DENIED


class _Server(paramiko.ServerInterface):
    def __init__(self, state: ServerState):
        self.state = state

    def check_auth_password(self, username, password):
        if username == self.state.username and password == self.state.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if self.state.authorized_key is not None and username == self.state.username and key == self.state.authorized_key:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        # Remote command execution is refused; the connector must never use it.
        self.state.write_attempts.append(f"exec:{command!r}")
        return False


class TestSFTPServer:
    __test__ = False

    def __init__(self, root: str, host_key: paramiko.PKey | None = None):
        self.state = ServerState(root=root)
        self.host_key = host_key or paramiko.RSAKey.generate(2048)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(20)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        t = paramiko.Transport(conn)
        t.add_server_key(self.host_key)
        t.set_subsystem_handler("sftp", paramiko.SFTPServer, _SFTP, self.state)
        try:
            t.start_server(server=_Server(self.state))
            while t.is_active() and not self._stop.is_set():
                t.join(0.2)
        except Exception:  # noqa: BLE001
            pass
        finally:
            t.close()

    def close(self) -> None:
        self._stop.set()
        self.sock.close()


__all__ = ["TestSFTPServer", "SFTP_OK", "SFTP_FAILURE", "SFTP_NO_SUCH_FILE"]
