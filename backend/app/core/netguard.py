"""Outbound network policy (SSRF protection).

Every outbound connection to a customer-supplied host goes through
:func:`resolve_public_target`, which resolves the hostname once, rejects
private, loopback, link-local, metadata and other non-public addresses, and
returns the vetted IP. Callers connect to that IP (pinning it), which defeats
DNS-rebinding between the check and the connection.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.config import get_settings

# Hostname rules: RFC 1123 labels, at least one dot, no trailing garbage.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})+\.?$")

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

# Networks blocked in addition to Python's is_private/is_loopback/etc.
EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("169.254.0.0/16"),  # link-local incl. 169.254.169.254
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDS IPv6
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 can map to internal IPv4
]


class TargetNotAllowed(ValueError):
    """The destination is not permitted by outbound network policy."""


@dataclass(frozen=True)
class ResolvedTarget:
    hostname: str
    ip: str
    port: int


def normalise_hostname(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        raise TargetNotAllowed("Hostname is required.")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host.strip("[]")
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetNotAllowed("Hostname is not valid.") from exc
    if not HOSTNAME_RE.match(host):
        raise TargetNotAllowed("Hostname is not a valid fully-qualified domain name.")
    return host


def _allowed_override(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for cidr in get_settings().outbound_allow_cidrs:
        if ip in ipaddress.ip_network(cidr, strict=False):
            return True
    return False


def is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return False
    return not any(ip in net for net in EXTRA_BLOCKED_NETWORKS if net.version == ip.version)


def check_ip_allowed(ip_str: str) -> None:
    ip = ipaddress.ip_address(ip_str)
    if _allowed_override(ip):
        return
    if not is_public_ip(ip_str):
        raise TargetNotAllowed("Destination address is not a permitted public address.")


def resolve_public_target(host: str, port: int, allowed_ports: list[int]) -> ResolvedTarget:
    hostname = normalise_hostname(host)
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith((".internal", ".local", ".localhost")):
        raise TargetNotAllowed("Destination hostname is not permitted.")
    if port not in allowed_ports:
        raise TargetNotAllowed(f"Port {port} is not permitted for this connection type.")
    if _is_ip_literal(hostname):
        check_ip_allowed(hostname)
        return ResolvedTarget(hostname=hostname, ip=hostname, port=port)
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise DNSResolutionError(f"DNS resolution failed for {hostname}.") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise DNSResolutionError(f"DNS resolution returned no addresses for {hostname}.")
    # Every resolved address must be allowed; otherwise an attacker could mix
    # a public and a private record and win the race.
    for addr in addresses:
        check_ip_allowed(addr)
    # Prefer IPv4 for predictability on hosting platforms.
    addresses.sort(key=lambda a: ":" in a)
    return ResolvedTarget(hostname=hostname, ip=addresses[0], port=port)


class DNSResolutionError(Exception):
    pass


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_website_url(url: str) -> tuple[str, str, int, str]:
    """Validate a website URL. Returns (scheme, hostname, port, normalised_url)."""
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https"):
        raise TargetNotAllowed("Only http and https URLs are supported.")
    if parts.username or parts.password:
        raise TargetNotAllowed("URLs containing credentials are not allowed.")
    if not parts.hostname:
        raise TargetNotAllowed("URL must include a hostname.")
    hostname = normalise_hostname(parts.hostname)
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith((".internal", ".local", ".localhost")):
        raise TargetNotAllowed("Destination hostname is not permitted.")
    if _is_ip_literal(hostname):
        check_ip_allowed(hostname)
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise TargetNotAllowed("URL port is not valid.") from exc
    if port not in get_settings().allowed_http_ports:
        raise TargetNotAllowed(f"Port {port} is not permitted for website checks.")
    path = parts.path or "/"
    netloc = hostname if parts.port is None else f"{hostname}:{port}"
    normalised = f"{parts.scheme}://{netloc}{path}"
    if parts.query:
        normalised += f"?{parts.query}"
    return parts.scheme, hostname, port, normalised
