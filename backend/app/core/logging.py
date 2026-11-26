"""Structured JSON logging with secret redaction."""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog

SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|authorization|cookie|"
    r"credential|ciphertext|otp|totp|signature|card|cvv)",
    re.IGNORECASE,
)
# Values that look like secrets even under innocuous keys.
SENSITIVE_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)(bearer|cpanel|basic)\s+[A-Za-z0-9._:\-+/=]{8,}"),
    re.compile(r"sk_(live|test)_[A-Za-z0-9]+"),
    re.compile(r"(?i)(password|passwd|token|secret)=([^&\s]+)"),
]
REDACTED = "[REDACTED]"


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for pat in SENSITIVE_VALUE_PATTERNS:
            out = pat.sub(REDACTED, out)
        return out
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(v) for v in value)
    return value


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(key, str) and SENSITIVE_KEY_PATTERN.search(key) and key not in _ALLOWED_KEYS:
            clean[key] = REDACTED if value not in (None, "", False) else value
        else:
            clean[key] = redact_value(value)
    return clean


# Keys that match the pattern but carry no secret material.
_ALLOWED_KEYS = {"has_password", "has_private_key", "has_api_token", "token_prefix", "mfa_enabled"}


def _redaction_processor(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    return redact_mapping(event_dict)


class _RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_value(record.msg)
        if record.args:
            record.args = tuple(redact_value(a) for a in record.args) if isinstance(
                record.args, tuple
            ) else record.args
        return True


def configure_logging(level: str = "INFO", json: bool = True) -> None:
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redaction_processor,
        structlog.processors.format_exc_info,
    ]
    processors.append(
        structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )
    root = logging.getLogger()
    root.setLevel(level)
    for handler in root.handlers:
        handler.addFilter(_RedactingFilter())
    # paramiko logs at DEBUG can include protocol detail; keep it quiet.
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
