"""Permission catalogue and built-in role definitions.

Permissions are checked on the backend for every request. Roles are seeded
into the database (``roles``/``permissions``/``role_permissions``) from this
catalogue so that operators can inspect them, and custom roles can be added
later without code changes.

Two scopes exist:

* ``tenant`` roles are granted through ``tenant_memberships`` and only ever
  apply inside that tenant.
* ``platform`` roles are held by Trust Data personnel. They grant platform
  functions (administration, operations) but **not** blanket access to
  customer data: customer-data access requires an explicit, time-bound,
  audited ``managed_service_grant`` for the tenant.
"""

from __future__ import annotations

from dataclasses import dataclass


class P:
    # Tenant-scoped permissions
    TENANT_READ = "tenant:read"
    TENANT_MANAGE = "tenant:manage"
    MEMBERS_READ = "members:read"
    MEMBERS_MANAGE = "members:manage"
    WEBSITES_READ = "websites:read"
    WEBSITES_MANAGE = "websites:manage"
    HOSTING_READ = "hosting:read"
    HOSTING_MANAGE = "hosting:manage"
    MONITORING_READ = "monitoring:read"
    MONITORING_MANAGE = "monitoring:manage"
    SCANS_RUN = "scans:run"
    BASELINE_APPROVE = "baseline:approve"
    INVENTORY_READ = "inventory:read"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_MANAGE = "incidents:manage"
    NOTIFICATIONS_READ = "notifications:read"
    NOTIFICATIONS_MANAGE = "notifications:manage"
    REPORTS_READ = "reports:read"
    REPORTS_GENERATE = "reports:generate"
    BILLING_READ = "billing:read"
    BILLING_MANAGE = "billing:manage"
    SUPPORT_READ = "support:read"
    SUPPORT_MANAGE = "support:manage"
    AUDIT_READ = "audit:read"
    MANAGED_SERVICE_APPROVE = "managed_service:approve"

    # Platform-scoped permissions
    PLATFORM_OVERVIEW = "platform:overview"
    PLATFORM_TENANTS_READ = "platform:tenants:read"
    PLATFORM_TENANTS_MANAGE = "platform:tenants:manage"
    PLATFORM_USERS_MANAGE = "platform:users:manage"
    PLATFORM_CONNECTORS_MANAGE = "platform:connectors:manage"
    PLATFORM_PLANS_MANAGE = "platform:plans:manage"
    PLATFORM_PAYMENTS_READ = "platform:payments:read"
    PLATFORM_PAYMENTS_MANAGE = "platform:payments:manage"
    PLATFORM_MESSAGING_MANAGE = "platform:messaging:manage"
    PLATFORM_AUDIT_READ = "platform:audit:read"
    PLATFORM_CONFIG_MANAGE = "platform:config:manage"
    PLATFORM_HEALTH_READ = "platform:health:read"
    OPS_JOBS_READ = "ops:jobs:read"
    OPS_JOBS_MANAGE = "ops:jobs:manage"
    OPS_INCIDENTS_READ = "ops:incidents:read"
    OPS_INCIDENTS_MANAGE = "ops:incidents:manage"
    OPS_DIAGNOSTICS = "ops:diagnostics"
    GRANTS_REQUEST = "grants:request"
    GRANTS_ISSUE = "grants:issue"


@dataclass(frozen=True)
class RoleDef:
    key: str
    name: str
    scope: str  # "tenant" | "platform"
    description: str
    permissions: frozenset[str]


_TENANT_READ_ALL = {
    P.TENANT_READ,
    P.MEMBERS_READ,
    P.WEBSITES_READ,
    P.HOSTING_READ,
    P.MONITORING_READ,
    P.INVENTORY_READ,
    P.INCIDENTS_READ,
    P.NOTIFICATIONS_READ,
    P.REPORTS_READ,
    P.SUPPORT_READ,
}

TENANT_ROLES: list[RoleDef] = [
    RoleDef(
        "owner",
        "Organisation Owner",
        "tenant",
        "Full control of the organisation, including billing and membership.",
        frozenset(
            _TENANT_READ_ALL
            | {
                P.TENANT_MANAGE,
                P.MEMBERS_MANAGE,
                P.WEBSITES_MANAGE,
                P.HOSTING_MANAGE,
                P.MONITORING_MANAGE,
                P.SCANS_RUN,
                P.BASELINE_APPROVE,
                P.INCIDENTS_MANAGE,
                P.NOTIFICATIONS_MANAGE,
                P.REPORTS_GENERATE,
                P.BILLING_READ,
                P.BILLING_MANAGE,
                P.SUPPORT_MANAGE,
                P.AUDIT_READ,
                P.MANAGED_SERVICE_APPROVE,
            }
        ),
    ),
    RoleDef(
        "admin",
        "Organisation Administrator",
        "tenant",
        "Manages websites, hosting connections, monitoring and team members.",
        frozenset(
            _TENANT_READ_ALL
            | {
                P.MEMBERS_MANAGE,
                P.WEBSITES_MANAGE,
                P.HOSTING_MANAGE,
                P.MONITORING_MANAGE,
                P.SCANS_RUN,
                P.BASELINE_APPROVE,
                P.INCIDENTS_MANAGE,
                P.NOTIFICATIONS_MANAGE,
                P.REPORTS_GENERATE,
                P.BILLING_READ,
                P.SUPPORT_MANAGE,
                P.AUDIT_READ,
            }
        ),
    ),
    RoleDef(
        "security_lead",
        "Security Lead",
        "tenant",
        "Investigates incidents, approves baselines and manages alerting.",
        frozenset(
            _TENANT_READ_ALL
            | {
                P.SCANS_RUN,
                P.BASELINE_APPROVE,
                P.INCIDENTS_MANAGE,
                P.NOTIFICATIONS_MANAGE,
                P.REPORTS_GENERATE,
                P.SUPPORT_MANAGE,
                P.AUDIT_READ,
            }
        ),
    ),
    RoleDef(
        "analyst",
        "Analyst",
        "tenant",
        "Works incidents and runs scans.",
        frozenset(_TENANT_READ_ALL | {P.SCANS_RUN, P.INCIDENTS_MANAGE, P.SUPPORT_MANAGE}),
    ),
    RoleDef(
        "billing",
        "Billing Contact",
        "tenant",
        "Manages subscription and payments.",
        frozenset({P.TENANT_READ, P.BILLING_READ, P.BILLING_MANAGE, P.SUPPORT_READ}),
    ),
    RoleDef(
        "viewer",
        "Viewer",
        "tenant",
        "Read-only access to monitoring results.",
        frozenset(_TENANT_READ_ALL),
    ),
]

PLATFORM_ROLES: list[RoleDef] = [
    RoleDef(
        "platform_admin",
        "Platform Administrator",
        "platform",
        "Administers the platform. Customer data still requires a managed-service grant.",
        frozenset(
            {
                P.PLATFORM_OVERVIEW,
                P.PLATFORM_TENANTS_READ,
                P.PLATFORM_TENANTS_MANAGE,
                P.PLATFORM_USERS_MANAGE,
                P.PLATFORM_CONNECTORS_MANAGE,
                P.PLATFORM_PLANS_MANAGE,
                P.PLATFORM_PAYMENTS_READ,
                P.PLATFORM_MESSAGING_MANAGE,
                P.PLATFORM_AUDIT_READ,
                P.PLATFORM_CONFIG_MANAGE,
                P.PLATFORM_HEALTH_READ,
                P.OPS_JOBS_READ,
                P.OPS_JOBS_MANAGE,
                P.OPS_INCIDENTS_READ,
                P.GRANTS_ISSUE,
            }
        ),
    ),
    RoleDef(
        "soc_analyst",
        "Security Operations Analyst",
        "platform",
        "Monitors scans and incidents; tenant detail requires a grant.",
        frozenset(
            {
                P.PLATFORM_OVERVIEW,
                P.PLATFORM_HEALTH_READ,
                P.OPS_JOBS_READ,
                P.OPS_JOBS_MANAGE,
                P.OPS_INCIDENTS_READ,
                P.OPS_INCIDENTS_MANAGE,
                P.OPS_DIAGNOSTICS,
                P.GRANTS_REQUEST,
            }
        ),
    ),
    RoleDef(
        "ms_operator",
        "Managed-Service Operator",
        "platform",
        "Operates managed accounts under explicit customer grants.",
        frozenset(
            {
                P.PLATFORM_OVERVIEW,
                P.OPS_JOBS_READ,
                P.OPS_INCIDENTS_READ,
                P.OPS_DIAGNOSTICS,
                P.GRANTS_REQUEST,
            }
        ),
    ),
    RoleDef(
        "support_agent",
        "Support Agent",
        "platform",
        "Handles support tickets. No customer monitoring data without a grant.",
        frozenset({P.PLATFORM_TENANTS_READ, P.GRANTS_REQUEST}),
    ),
    RoleDef(
        "billing_admin",
        "Billing Administrator",
        "platform",
        "Manages plans, payments and reconciliation.",
        frozenset(
            {
                P.PLATFORM_TENANTS_READ,
                P.PLATFORM_PLANS_MANAGE,
                P.PLATFORM_PAYMENTS_READ,
                P.PLATFORM_PAYMENTS_MANAGE,
            }
        ),
    ),
    RoleDef(
        "auditor",
        "Read-only Auditor",
        "platform",
        "Reads audit trails and platform configuration.",
        frozenset(
            {
                P.PLATFORM_OVERVIEW,
                P.PLATFORM_TENANTS_READ,
                P.PLATFORM_AUDIT_READ,
                P.PLATFORM_HEALTH_READ,
                P.PLATFORM_PAYMENTS_READ,
            }
        ),
    ),
]

ALL_ROLES = {r.key: r for r in TENANT_ROLES + PLATFORM_ROLES}


def all_permission_codes() -> set[str]:
    return {v for k, v in vars(P).items() if not k.startswith("_") and isinstance(v, str)}


# Permissions a managed-service grant may confer inside a tenant. Grants never
# confer billing or membership management.
GRANTABLE_TENANT_PERMISSIONS = frozenset(
    _TENANT_READ_ALL
    | {P.SCANS_RUN, P.INCIDENTS_MANAGE, P.MONITORING_MANAGE, P.REPORTS_GENERATE, P.SUPPORT_MANAGE}
)
