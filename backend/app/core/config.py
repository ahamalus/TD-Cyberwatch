"""Application configuration.

All configuration is environment-driven (prefix ``CW_``). Secrets are never
given usable defaults: a production start-up with missing or development
values is refused by :func:`Settings.validate_for_runtime`.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "demo", "staging", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CW_", env_file=".env", extra="ignore")

    product_name: str = "TrustData CyberWatch"
    company_name: str = "Trust Data Compliance Ltd"

    environment: Environment = "development"
    debug: bool = False

    database_url: str = "postgresql+psycopg://cyberwatch:devpassword@localhost:5432/cyberwatch"
    redis_url: str = "redis://localhost:6379/0"

    # Base64-encoded 32-byte keys, as "key_id:base64key" entries separated by
    # commas. The first entry encrypts new secrets; all entries decrypt.
    credential_keys: SecretStr = SecretStr("")

    # Browser session settings
    session_ttl_minutes: int = 60 * 8
    session_idle_minutes: int = 60
    cookie_secure: bool = True
    cookie_domain: str | None = None
    cors_origins: list[str] = Field(default_factory=list)
    public_base_url: str = "http://localhost:5173"

    # Platform-admin MFA is mandatory outside development/test.
    require_platform_mfa: bool = True

    # Rate limits (requests per window per client key)
    auth_rate_limit: int = 10
    auth_rate_window_seconds: int = 60

    # Outbound network policy (SSRF protection). CIDRs listed here are
    # permitted even when private; intended ONLY for development and tests.
    outbound_allow_cidrs: list[str] = Field(default_factory=list)
    allowed_sftp_ports: list[int] = Field(default_factory=lambda: [22, 2222])
    allowed_cpanel_ports: list[int] = Field(default_factory=lambda: [2083])
    allowed_http_ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443])

    # Scan limits (defaults; plans and website config may lower them)
    scan_max_file_bytes: int = 25 * 1024 * 1024
    scan_max_total_bytes: int = 2 * 1024 * 1024 * 1024
    scan_max_files: int = 200_000
    scan_max_seconds: int = 60 * 60
    scan_max_depth: int = 40
    connect_timeout_seconds: float = 15.0
    io_timeout_seconds: float = 60.0
    http_check_timeout_seconds: float = 15.0

    # Jobs
    job_max_attempts: int = 3
    job_stale_after_seconds: int = 60 * 20
    tenant_max_concurrent_jobs: int = 2
    worker_heartbeat_seconds: int = 20

    # Notifications
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = True
    email_from: str = "CyberWatch <no-reply@example.invalid>"

    whatsapp_api_base: str = "https://graph.facebook.com"
    whatsapp_api_version: str = "v21.0"
    whatsapp_phone_number_id: str | None = None
    whatsapp_access_token: SecretStr | None = None

    # Billing (Paystack)
    paystack_secret_key: SecretStr | None = None
    paystack_base_url: str = "https://api.paystack.co"
    trial_days: int = 14
    grace_period_days: int = 7

    # Protected local object storage for reports and large evidence objects.
    storage_dir: str = "var/storage"

    # Bootstrap administrator (only consumed by the bootstrap CLI command)
    bootstrap_admin_email: str | None = None

    @field_validator("outbound_allow_cidrs")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        for cidr in v:
            ipaddress.ip_network(cidr, strict=False)
        return v

    @property
    def is_production_like(self) -> bool:
        return self.environment in ("staging", "production")

    @property
    def is_synthetic_data_allowed(self) -> bool:
        return self.environment in ("development", "test", "demo")

    def validate_for_runtime(self) -> list[str]:
        """Return a list of fatal configuration problems for this environment."""
        problems: list[str] = []
        if not self.credential_keys.get_secret_value():
            problems.append("CW_CREDENTIAL_KEYS is not set; credentials cannot be stored.")
        if self.is_production_like:
            if self.debug:
                problems.append("Debug mode must be disabled in staging/production.")
            if "devpassword" in self.database_url:
                problems.append("Development database credentials configured in production.")
            if not self.cookie_secure:
                problems.append("CW_COOKIE_SECURE must be true in staging/production.")
            if self.outbound_allow_cidrs:
                problems.append("CW_OUTBOUND_ALLOW_CIDRS must be empty in staging/production.")
            if not self.require_platform_mfa:
                problems.append("Platform administrator MFA cannot be disabled in production.")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
