"""Password hashing, opaque tokens and TOTP helpers."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Argon2id with OWASP-recommended baseline parameters (m=19 MiB, t=2, p=1).
_hasher = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    if not password_hash:
        # Spend comparable time to avoid user-enumeration timing differences.
        _hasher.hash(password)
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, email: str | None = None) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > 256:
        problems.append("Password must be at most 256 characters.")
    if email and email.split("@")[0].lower() in password.lower() and len(email.split("@")[0]) >= 4:
        problems.append("Password must not contain your email name.")
    if len(set(password)) < 5:
        problems.append("Password is too repetitive.")
    return problems


def new_token(prefix: str = "", nbytes: int = 32) -> str:
    return prefix + secrets.token_urlsafe(nbytes)


def token_digest(token: str) -> str:
    """Tokens are stored only as SHA-256 digests."""
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, account: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def totp_step(secret: str, code: str, after_step: int | None = None) -> int | None:
    """Time step (30 s counter) a TOTP code belongs to, within one step of now, or None.

    Codes are single-use: pass the last accepted step as ``after_step`` and any code from that step or
    earlier is refused, so an observed code cannot be replayed within its validity window."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now = totp.timecode(datetime.now(UTC))
    for step in (now - 1, now, now + 1):
        if (after_step is None or step > after_step) and hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def verify_totp(secret: str, code: str) -> bool:
    return totp_step(secret, code) is not None


def new_recovery_codes(n: int = 8) -> list[str]:
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(n)]
