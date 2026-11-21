"""Website ownership proof by DNS TXT record (an alternative to publishing a file on the site).

The customer adds a TXT record ``_cyberwatch.<hostname>`` with the value ``cyberwatch-verification=<token>``.
For ``www.`` hostnames the record may also be placed on the bare domain. Only DNS is queried; nothing
connects to the website.
"""

from __future__ import annotations

from collections.abc import Callable

import dns.exception
import dns.resolver

PREFIX = "_cyberwatch"
VALUE_PREFIX = "cyberwatch-verification="

# Tests replace this: (name) -> list of TXT strings, raising LookupError for "no record".
TxtLookup = Callable[[str], list[str]]


def _system_lookup(name: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
        raise LookupError("no TXT record") from exc
    except dns.exception.DNSException as exc:
        raise OSError(f"DNS lookup failed ({type(exc).__name__})") from exc
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


_lookup: TxtLookup = _system_lookup


def set_lookup(fn: TxtLookup | None) -> None:
    global _lookup
    _lookup = fn or _system_lookup


def record_names(hostname: str) -> list[str]:
    host = hostname.lower().rstrip(".")
    names = [f"{PREFIX}.{host}"]
    if host.startswith("www."):
        names.append(f"{PREFIX}.{host[4:]}")
    return names


def check(hostname: str, token: str) -> tuple[bool, str]:
    expected = f"{VALUE_PREFIX}{token}"
    errors: list[str] = []
    for name in record_names(hostname):
        try:
            values = [v.strip().strip('"') for v in _lookup(name)]
        except LookupError:
            continue
        except OSError as exc:
            errors.append(str(exc))
            continue
        if expected in values:
            return True, f"Verified by the TXT record on {name}."
        return False, f"A TXT record exists on {name} but does not contain {expected}."
    if errors:
        return False, errors[0]
    return False, f"No TXT record found on {' or '.join(record_names(hostname))} yet (DNS changes can take a while)."
