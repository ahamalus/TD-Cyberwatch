"""Idempotent seeding of reference data: permissions, roles, connectors, plans.

Run via ``python -m app.cli seed``. Existing rows are updated for built-in
definitions but administrator edits to operational settings (timeouts, plan
prices) are preserved unless ``force`` is passed.
"""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.permissions import ALL_ROLES, all_permission_codes
from app.models import ConnectorDefinition, Permission, Plan, Role, RolePermission

CONNECTOR_DEFINITIONS = [
    {
        "key": "sftp",
        "name": "SFTP",
        "adapter_version": "1.0.0",
        "status": "implemented",
        "description": "Read-only file inventory and SHA-256 hashing over SFTP (SSH File Transfer Protocol).",
        "min_poll_interval_minutes": 60,
        "capability_notes": {
            "never_assumed": [
                "log_access",
                "hosting_malware_scan",
                "realtime_file_events",
                "provider_security_api",
            ],
            "limitations": "Polling detects changes between scans only; transient changes can be missed.",
        },
    },
    {
        "key": "cpanel_uapi",
        "name": "cPanel UAPI",
        "adapter_version": "0.9.0",
        "status": "implemented",
        "description": (
            "Read-only file listing and content retrieval via cPanel UAPI Fileman functions using a "
            "cPanel API token. Requires verification against a live cPanel server before production use."
        ),
        "min_poll_interval_minutes": 120,
        "capability_notes": {
            "limitations": (
                "Content is retrieved with Fileman::get_file_content; very large or binary files may "
                "be metadata-only. API rate limits vary by host."
            )
        },
    },
    {
        "key": "http_external",
        "name": "External HTTP/TLS",
        "adapter_version": "1.0.0",
        "status": "implemented",
        "description": "Availability, response time and TLS certificate checks from the platform.",
        "min_poll_interval_minutes": 5,
        "capability_notes": {},
    },
    {
        "key": "ssh_readonly",
        "name": "SSH (read-only commands)",
        "adapter_version": "0.0.0",
        "status": "planned",
        "description": "Strictly allow-listed, read-only commands. Not yet implemented.",
    },
    {
        "key": "whm_api",
        "name": "WHM API",
        "adapter_version": "0.0.0",
        "status": "planned",
        "description": "Reseller/server-level access where the customer is authorised. Not yet implemented.",
    },
    {
        "key": "plesk_api",
        "name": "Plesk API",
        "adapter_version": "0.0.0",
        "status": "planned",
        "description": "Not yet implemented.",
    },
    {
        "key": "directadmin_api",
        "name": "DirectAdmin API",
        "adapter_version": "0.0.0",
        "status": "planned",
        "description": "Not yet implemented.",
    },
    {
        "key": "provider_security_api",
        "name": "Hosting provider security API",
        "adapter_version": "0.0.0",
        "status": "planned",
        "description": "Provider-specific security APIs (e.g. Imunify360). Not yet implemented.",
    },
    {
        "key": "agent",
        "name": "CyberWatch host agent",
        "adapter_version": "0.0.0",
        "status": "planned",
        "description": "Future customer-installed agent for real-time file events. Not yet implemented.",
    },
    {
        "key": "wordpress_plugin",
        "name": "WordPress plugin",
        "adapter_version": "0.0.0",
        "status": "planned",
        "description": "Future website-level integration. Not yet implemented.",
    },
]

# Example plans. Prices and limits are configuration, not code: administrators
# edit them in the Plans module. Amounts are in kobo (NGN minor unit).
EXAMPLE_PLANS = [
    {
        "key": "starter",
        "name": "Starter",
        "description": "Essential monitoring for a small number of websites.",
        "price_monthly_minor": 1500000,
        "price_annual_minor": 15000000,
        "sort_order": 10,
        "entitlements": {
            "max_websites": 3,
            "max_hosting_accounts": 2,
            "max_users": 3,
            "min_file_scan_interval_minutes": 1440,
            "min_availability_interval_minutes": 15,
            "retention_days": 30,
            "reports": False,
            "whatsapp_notifications": False,
            "notifications_per_month": 500,
            "managed_service": False,
            "support_level": "standard",
            "api_access": False,
        },
    },
    {
        "key": "business",
        "name": "Business",
        "description": "File-integrity monitoring and alerting for growing organisations.",
        "price_monthly_minor": 4500000,
        "price_annual_minor": 45000000,
        "sort_order": 20,
        "entitlements": {
            "max_websites": 10,
            "max_hosting_accounts": 5,
            "max_users": 10,
            "min_file_scan_interval_minutes": 360,
            "min_availability_interval_minutes": 5,
            "retention_days": 90,
            "reports": True,
            "whatsapp_notifications": True,
            "notifications_per_month": 3000,
            "managed_service": False,
            "support_level": "standard",
            "api_access": False,
        },
    },
    {
        "key": "professional",
        "name": "Professional",
        "description": "Frequent scans, extended retention and API access.",
        "price_monthly_minor": 12000000,
        "price_annual_minor": 120000000,
        "sort_order": 30,
        "entitlements": {
            "max_websites": 50,
            "max_hosting_accounts": 50,
            "max_users": 25,
            "min_file_scan_interval_minutes": 60,
            "min_availability_interval_minutes": 5,
            "retention_days": 365,
            "reports": True,
            "whatsapp_notifications": True,
            "notifications_per_month": 20000,
            "managed_service": False,
            "support_level": "priority",
            "api_access": True,
        },
    },
    {
        "key": "enterprise",
        "name": "Enterprise",
        "description": "Custom limits for large estates. Contact sales.",
        "price_monthly_minor": None,
        "price_annual_minor": None,
        "contact_sales": True,
        "sort_order": 40,
        "entitlements": {
            "max_websites": 500,
            "max_hosting_accounts": 500,
            "max_users": 200,
            "min_file_scan_interval_minutes": 30,
            "min_availability_interval_minutes": 1,
            "retention_days": 730,
            "reports": True,
            "whatsapp_notifications": True,
            "notifications_per_month": 100000,
            "managed_service": False,
            "support_level": "dedicated",
            "api_access": True,
        },
    },
    {
        "key": "managed_security",
        "name": "Managed Security",
        "description": "Monitoring operated by the Trust Data security team. Contact sales.",
        "price_monthly_minor": None,
        "price_annual_minor": None,
        "contact_sales": True,
        "sort_order": 50,
        "entitlements": {
            "max_websites": 100,
            "max_hosting_accounts": 100,
            "max_users": 50,
            "min_file_scan_interval_minutes": 60,
            "min_availability_interval_minutes": 5,
            "retention_days": 730,
            "reports": True,
            "whatsapp_notifications": True,
            "notifications_per_month": 50000,
            "managed_service": True,
            "support_level": "managed",
            "api_access": True,
        },
    },
]

# Entitlements applied to tenants with no current subscription and no trial.
RESTRICTED_ENTITLEMENTS = {
    "max_websites": 0,
    "max_hosting_accounts": 0,
    "max_users": 1,
    "min_file_scan_interval_minutes": 10**6,
    "min_availability_interval_minutes": 10**6,
    "retention_days": 30,
    "reports": False,
    "whatsapp_notifications": False,
    "notifications_per_month": 0,
    "managed_service": False,
    "support_level": "standard",
    "api_access": False,
}


def seed_reference_data(db: Session, force: bool = False) -> dict[str, int]:
    counts = {"permissions": 0, "roles": 0, "connectors": 0, "plans": 0}
    codes = all_permission_codes()
    existing_perms = set(db.execute(select(Permission.code)).scalars())
    for code in sorted(codes - existing_perms):
        db.add(Permission(code=code, description=code))
        counts["permissions"] += 1
    db.flush()

    for role in ALL_ROLES.values():
        row = db.get(Role, role.key)
        if row is None:
            row = Role(key=role.key, name=role.name, scope=role.scope, description=role.description)
            db.add(row)
            counts["roles"] += 1
        else:
            row.name, row.scope, row.description = role.name, role.scope, role.description
        db.flush()
        db.execute(delete(RolePermission).where(RolePermission.role_key == role.key))
        for code in sorted(role.permissions):
            db.add(RolePermission(role_key=role.key, permission_code=code))
    db.flush()

    for spec in CONNECTOR_DEFINITIONS:
        row = db.get(ConnectorDefinition, spec["key"])
        if row is None:
            db.add(ConnectorDefinition(**{"capability_notes": {}, **spec}))
            counts["connectors"] += 1
        else:
            row.name = spec["name"]
            row.adapter_version = spec["adapter_version"]
            row.description = spec["description"]
            row.capability_notes = spec.get("capability_notes", {})
            if force or row.status != "disabled":
                row.status = spec["status"]

    for spec in EXAMPLE_PLANS:
        row = db.execute(select(Plan).where(Plan.key == spec["key"])).scalar_one_or_none()
        if row is None:
            db.add(Plan(**spec))
            counts["plans"] += 1
        elif force:
            for k, v in spec.items():
                setattr(row, k, v)
    db.flush()
    return counts
