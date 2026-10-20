"""Read-only SFTP server that publishes the sample website for local testing.

Runs inside the CyberWatch backend image (paramiko is already installed). It
serves SAMPLE_ROOT read-only on port 2222 with a username and password, so
CyberWatch can be tested end to end without a real hosting account. Every
write, rename, delete and remote command is refused.

For local testing only. Never expose this port to a network.
"""

from __future__ import annotations

import os
import socket
import threading

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface
from paramiko.sftp import SFTP_PERMISSION_DENIED

ROOT = os.environ.get("SAMPLE_ROOT", "/srv/sample-site")
USERNAME = os.environ.get("SAMPLE_SFTP_USER", "sampleuser")
PASSWORD = os.environ.get("SAMPLE_SFTP_PASSWORD", "")
HOST_KEY_PATH = os.environ.get("SAMPLE_HOST_KEY", "/var/lib/cyberwatch/storage/sample_sftp_host_key")
PORT = int(os.environ.get("SAMPLE_SFTP_PORT", "2222"))


def _host_key() -> paramiko.PKey:
    # A stable key across restarts, so CyberWatch's host-key pinning stays valid.
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey.from_private_key_file(HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(HOST_KEY_PATH)
    return key


class _Handle(SFTPHandle):
    def stat(self):
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))


class _ReadOnlySFTP(SFTPServerInterface):
    def _local(self, path: str) -> str:
        path = os.path.normpath("/" + (path or "/").lstrip("/"))
        return os.path.join(ROOT, path.lstrip("/"))

    def canonicalize(self, path):
        return os.path.normpath("/" + (path or "/").lstrip("/"))

    def list_folder(self, path):
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
        try:
            return SFTPAttributes.from_stat(os.stat(self._local(path)))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        try:
            return SFTPAttributes.from_stat(os.lstat(self._local(path)))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
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
        return SFTP_PERMISSION_DENIED

    def rename(self, oldpath, newpath):
        return SFTP_PERMISSION_DENIED

    def mkdir(self, path, attr):
        return SFTP_PERMISSION_DENIED

    def rmdir(self, path):
        return SFTP_PERMISSION_DENIED

    def chattr(self, path, attr):
        return SFTP_PERMISSION_DENIED

    def symlink(self, target_path, path):
        return SFTP_PERMISSION_DENIED


class _Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        if PASSWORD and username == USERNAME and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        return False


def _handle(conn: socket.socket, key: paramiko.PKey) -> None:
    t = paramiko.Transport(conn)
    t.add_server_key(key)
    t.set_subsystem_handler("sftp", paramiko.SFTPServer, _ReadOnlySFTP)
    try:
        t.start_server(server=_Server())
        while t.is_active():
            t.join(1)
    except Exception:  # noqa: BLE001, S110 - a dropped client must not stop the server
        pass
    finally:
        t.close()


def main() -> None:
    if not PASSWORD:
        raise SystemExit("SAMPLE_SFTP_PASSWORD must be set.")
    key = _host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))  # container-internal network only
    sock.listen(20)
    print(f"Sample SFTP server serving {ROOT} read-only on port {PORT} (user {USERNAME})", flush=True)
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=_handle, args=(conn, key), daemon=True).start()


if __name__ == "__main__":
    main()
