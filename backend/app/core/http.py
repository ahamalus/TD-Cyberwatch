"""Outbound HTTP with SSRF protection and DNS pinning.

Requests are sent to the vetted IP address with the original hostname in the
``Host`` header and as the TLS SNI/verification name, so certificate
validation still applies to the real hostname. Redirects are followed
manually and every hop is re-validated.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from app.core.netguard import ResolvedTarget, normalise_hostname, resolve_public_target

USER_AGENT = "TrustData-CyberWatch-Monitor/1.0 (+https://trustdata.ng)"

# Tests may replace this to inject httpx.MockTransport.
TransportFactory = Callable[[], httpx.BaseTransport]
_transport_factory: TransportFactory | None = None


def set_transport_factory(factory: TransportFactory | None) -> None:
    global _transport_factory
    _transport_factory = factory


@dataclass
class PinnedResponse:
    status_code: int
    headers: httpx.Headers
    body: bytes
    final_url: str
    resolved_ip: str
    elapsed_ms: int
    redirects: int
    truncated: bool


class RedirectNotAllowed(Exception):
    pass


def _read_limited(response: httpx.Response, max_body_bytes: int) -> tuple[bytes, bool]:
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > max_body_bytes:
            del body[max_body_bytes:]
            return bytes(body), True
    return bytes(body), False


def _pinned_url(url: str, target: ResolvedTarget) -> str:
    parts = urlsplit(url)
    host = f"[{target.ip}]" if ":" in target.ip else target.ip
    netloc = f"{host}:{target.port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


def pinned_request(
    method: str,
    url: str,
    *,
    allowed_ports: list[int],
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    timeout: float = 15.0,
    max_redirects: int = 5,
    max_body_bytes: int = 1024 * 1024,
    verify_tls: bool = True,
) -> PinnedResponse:
    current = url
    redirects = 0
    started = time.monotonic()
    transport = _transport_factory() if _transport_factory else httpx.HTTPTransport(verify=verify_tls, retries=0)
    with httpx.Client(transport=transport, timeout=timeout, follow_redirects=False) as client:
        while True:
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https"):
                raise RedirectNotAllowed("Redirect to a non-HTTP scheme was blocked.")
            hostname = normalise_hostname(parts.hostname or "")
            port = parts.port or (443 if parts.scheme == "https" else 80)
            target = resolve_public_target(hostname, port, allowed_ports)
            req_headers = {"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})}
            req_headers["Host"] = hostname if parts.port is None else f"{hostname}:{port}"
            request = client.build_request(
                method,
                _pinned_url(current, target),
                headers=req_headers,
                params=params if redirects == 0 else None,
                extensions={"sni_hostname": hostname},
            )
            response = client.send(request, stream=True)
            try:
                if response.is_redirect and redirects < max_redirects:
                    location = response.headers.get("location", "")
                    current = urljoin(current, location)
                    redirects += 1
                    continue
                body, truncated = _read_limited(response, max_body_bytes)
                return PinnedResponse(
                    status_code=response.status_code,
                    headers=response.headers,
                    body=bytes(body),
                    final_url=current,
                    resolved_ip=target.ip,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    redirects=redirects,
                    truncated=truncated,
                )
            finally:
                response.close()


class PinnedSession:
    """Keep-alive HTTPS connections to one host for many requests (e.g. one request per file).

    The host is resolved and vetted against the outbound policy once, when the session is created;
    every request then goes to that pinned IP over pooled connections, with the real hostname as TLS
    SNI and certificate name. Redirects are never followed. Thread-safe.
    """

    def __init__(self, base_url: str, *, allowed_ports: list[int], timeout: float = 15.0,
                 max_connections: int = 4, verify_tls: bool = True):
        parts = urlsplit(base_url)
        self.scheme = parts.scheme
        self.hostname = normalise_hostname(parts.hostname or "")
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.target = resolve_public_target(self.hostname, self.port, allowed_ports)
        limits = httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_connections)
        transport = _transport_factory() if _transport_factory else httpx.HTTPTransport(
            verify=verify_tls, retries=0, limits=limits)
        self._client = httpx.Client(transport=transport, timeout=timeout, follow_redirects=False)

    def request(self, method: str, path: str, *, headers: dict[str, str] | None = None,
                params: dict[str, str] | None = None, max_body_bytes: int = 1024 * 1024) -> PinnedResponse:
        started = time.monotonic()
        url = f"{self.scheme}://{self.hostname}:{self.port}{path}"
        host_header = self.hostname if self.port in (80, 443) else f"{self.hostname}:{self.port}"
        request = self._client.build_request(
            method,
            _pinned_url(url, self.target),
            headers={"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {}), "Host": host_header},
            params=params,
            extensions={"sni_hostname": self.hostname},
        )
        response = self._client.send(request, stream=True)
        try:
            body, truncated = _read_limited(response, max_body_bytes)
            return PinnedResponse(response.status_code, response.headers, body, url, self.target.ip,
                                  int((time.monotonic() - started) * 1000), 0, truncated)
        finally:
            response.close()

    def close(self) -> None:
        self._client.close()

