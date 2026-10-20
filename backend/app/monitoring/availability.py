"""HTTP availability and TLS certificate checks (M09).

Both checks go through the outbound network policy: only public addresses
on permitted ports are contacted, and the vetted IP is pinned for the
connection.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from app.core.config import get_settings
from app.core.http import RedirectNotAllowed, pinned_request
from app.core.netguard import DNSResolutionError, TargetNotAllowed, resolve_public_target, validate_website_url


@dataclass
class AvailabilityResult:
    outcome: str  # up | degraded | down | error
    http_status: int | None = None
    response_ms: int | None = None
    resolved_ip: str | None = None
    final_url: str | None = None
    redirects: int = 0
    error_class: str | None = None
    error_message: str | None = None


def check_availability(url: str, slow_ms: int = 5000) -> AvailabilityResult:
    settings = get_settings()
    try:
        validate_website_url(url)
        resp = pinned_request(
            "GET",
            url,
            allowed_ports=settings.allowed_http_ports,
            timeout=settings.http_check_timeout_seconds,
            max_body_bytes=256 * 1024,
        )
    except TargetNotAllowed as exc:
        return AvailabilityResult("error", error_class="target_not_allowed", error_message=str(exc))
    except DNSResolutionError as exc:
        return AvailabilityResult("down", error_class="dns_failure", error_message=str(exc))
    except RedirectNotAllowed as exc:
        return AvailabilityResult("error", error_class="redirect_blocked", error_message=str(exc))
    except httpx.TimeoutException:
        return AvailabilityResult("down", error_class="timeout", error_message="The website did not respond in time.")
    except httpx.ConnectError as exc:
        text = str(exc).lower()
        if "certificate" in text or "ssl" in text or "tls" in text:
            return AvailabilityResult("down", error_class="tls_error",
                                      error_message="TLS handshake or certificate verification failed.")
        return AvailabilityResult("down", error_class="connection_failed",
                                  error_message="Connection refused or host unreachable.")
    except httpx.HTTPError as exc:
        return AvailabilityResult("down", error_class="http_error", error_message=type(exc).__name__)

    if resp.status_code >= 500:
        outcome = "down"
    elif resp.status_code >= 400 or resp.elapsed_ms > slow_ms:
        outcome = "degraded"
    else:
        outcome = "up"
    if 300 <= resp.status_code < 400:
        outcome = "degraded"  # redirect limit exceeded
    return AvailabilityResult(
        outcome,
        http_status=resp.status_code,
        response_ms=resp.elapsed_ms,
        resolved_ip=resp.resolved_ip,
        final_url=resp.final_url,
        redirects=resp.redirects,
        error_class=None if outcome == "up" else ("slow_response" if resp.status_code < 400 else "http_status"),
        error_message=None if outcome == "up" else (
            f"Response took {resp.elapsed_ms} ms" if resp.status_code < 400 else f"HTTP {resp.status_code}"
        ),
    )


@dataclass
class TlsResult:
    outcome: str  # valid | expiring | expired | invalid | error | not_applicable
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    days_remaining: int | None = None
    issuer: str | None = None
    subject: str | None = None
    san: list[str] = field(default_factory=list)
    protocol: str | None = None
    error_message: str | None = None


def _name(n: x509.Name) -> str:
    parts = []
    for oid, label in ((NameOID.COMMON_NAME, "CN"), (NameOID.ORGANIZATION_NAME, "O")):
        for attr in n.get_attributes_for_oid(oid):
            parts.append(f"{label}={attr.value}")
    return ", ".join(parts) or n.rfc4514_string()[:200]


def _fetch_cert(ip: str, port: int, hostname: str, verify: bool, timeout: float) -> tuple[bytes, str | None]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            der = tls.getpeercert(binary_form=True)
            return der or b"", tls.version()


def check_tls(url: str, warning_days: int = 21) -> TlsResult:
    settings = get_settings()
    try:
        scheme, hostname, port, _ = validate_website_url(url)
    except TargetNotAllowed as exc:
        return TlsResult("error", error_message=str(exc))
    if scheme != "https":
        return TlsResult("not_applicable", error_message="Website is not served over HTTPS.")
    try:
        target = resolve_public_target(hostname, port, settings.allowed_http_ports)
    except TargetNotAllowed as exc:
        return TlsResult("error", error_message=str(exc))
    except DNSResolutionError as exc:
        return TlsResult("error", error_message=str(exc))

    timeout = settings.http_check_timeout_seconds
    verification_error = None
    try:
        der, proto = _fetch_cert(target.ip, port, hostname, True, timeout)
    except ssl.SSLCertVerificationError as exc:
        verification_error = exc.verify_message or "Certificate verification failed."
        try:
            der, proto = _fetch_cert(target.ip, port, hostname, False, timeout)
        except (OSError, ssl.SSLError) as exc2:
            return TlsResult("invalid", error_message=f"{verification_error}; certificate unreadable ({type(exc2).__name__}).")
    except TimeoutError:
        return TlsResult("error", error_message="TLS connection timed out.")
    except ssl.SSLError as exc:
        return TlsResult("invalid", error_message=f"TLS handshake failed ({exc.reason or type(exc).__name__}).")
    except OSError:
        return TlsResult("error", error_message="Could not connect to the HTTPS port.")

    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return TlsResult("invalid", error_message="Server presented an unparsable certificate.")
    now = datetime.now(UTC)
    vf, vt = cert.not_valid_before_utc, cert.not_valid_after_utc
    days = int((vt - now).total_seconds() // 86400)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
            x509.DNSName
        )
    except x509.ExtensionNotFound:
        san = []
    result = TlsResult(
        "valid", valid_from=vf, valid_to=vt, days_remaining=days, issuer=_name(cert.issuer),
        subject=_name(cert.subject), san=list(san)[:50], protocol=proto,
    )
    if vt <= now:
        result.outcome, result.error_message = "expired", f"Certificate expired on {vt:%Y-%m-%d}."
    elif verification_error:
        result.outcome, result.error_message = "invalid", verification_error
    elif days <= warning_days:
        result.outcome, result.error_message = "expiring", f"Certificate expires in {days} day(s)."
    return result
