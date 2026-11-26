"""In-process stand-in for the ClamAV daemon (clamd) speaking its real TCP protocol.

Detects only the industry-standard EICAR test string, like a real engine would. The test string is
assembled at runtime so that antivirus software on developer machines does not flag this file.
"""

from __future__ import annotations

import socket
import struct
import threading
from datetime import UTC, datetime

EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode()


class FakeClamd:
    def __init__(self, db_date: datetime | None = None):
        self.db_date = db_date or datetime.now(UTC)
        self.scans = 0
        self.down = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(20)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

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

    @staticmethod
    def _read_exact(conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            part = conn.recv(n - len(buf))
            if not part:
                raise ConnectionError("client closed")
            buf += part
        return buf

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            if self.down:
                return  # accept then hang up, like a crashed daemon
            cmd = b""
            while not cmd.endswith(b"\0"):
                part = conn.recv(1)
                if not part:
                    return
                cmd += part
            if cmd == b"zVERSION\0":
                stamp = self.db_date.strftime("%a %b %d %H:%M:%S %Y")
                conn.sendall(f"ClamAV 1.4.1/27470/{stamp}\0".encode())
            elif cmd == b"zINSTREAM\0":
                data = b""
                while True:
                    (n,) = struct.unpack("!L", self._read_exact(conn, 4))
                    if n == 0:
                        break
                    data += self._read_exact(conn, n)
                self.scans += 1
                reply = "stream: Eicar-Test-Signature FOUND" if EICAR in data else "stream: OK"
                conn.sendall(reply.encode() + b"\0")
            else:
                conn.sendall(b"UNKNOWN COMMAND\0")

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
