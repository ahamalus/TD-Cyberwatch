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
                body = bytearray()
                truncated = False
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > max_body_bytes:
                        truncated = True
                        del body[max_body_bytes:]
                        break
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
