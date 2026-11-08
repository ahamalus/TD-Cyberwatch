# Architecture and engineering decisions

## Phase 0 — repository and environment assessment

| Item | Finding |
|---|---|
| Existing work | Empty repository (README only). Nothing to preserve or migrate. |
| Stack chosen | As specified: Python 3.12+/FastAPI/Pydantic/SQLAlchemy 2/Alembic/PostgreSQL 16/Redis/Celery; React/TypeScript/Vite with Mantine 7 (accessible component library) and Recharts. |
| Build environment | Python 3.13, Node 22, PostgreSQL 16 and Redis available locally; Chromium for UI screenshots. Docker daemon **not** available in the build sandbox (images were not built here). Outbound access to some vendor documentation sites was blocked (see cPanel note in CONNECTORS.md). |
| Reusable components | None in the repo; mature libraries used for crypto (`cryptography` AES-GCM), SSH (`paramiko`), hashing (`argon2-cffi`), TOTP (`pyotp`), PDF (`reportlab`). |

### Principal risks identified up front

1. **Credential theft** – hosting credentials grant file access to customer sites. Mitigated by AES-256-GCM with keys outside the DB, tenant-bound associated data, no read-back API, worker-only decryption.
2. **SSRF** – customers supply hostnames/URLs. Mitigated by a central outbound policy with DNS pinning (see SECURITY.md).
3. **Cross-tenant leakage** – mitigated by application authorisation **and** forced PostgreSQL RLS; 404 for foreign IDs.
4. **False assurance** – misleading "all clear" or false deletions. Mitigated by explicit scan statuses, coverage computation from verified capabilities only, and deletion rules tied to complete directory listings.
5. **Deployment co-location** on a shared Windows Server with other workloads (Jitsi). Recommendation: a separate Linux VPS; see DEPLOYMENT.md.

## System overview

```
            ┌────────────── public HTTPS ──────────────┐
 Browser ──▶│ edge proxy (nginx/Caddy, TLS) ─▶ web (nginx: SPA + /api proxy) │
            └───────────────────────────┬──────────────┘
                                        ▼ internal network only
                         api (FastAPI) ──▶ PostgreSQL (RLS)  ◀── workers
                              │                ▲
                              ▼                │
                            Redis (Celery broker, rate limits)
                              │
              ┌───────────────┼───────────────────┐
              ▼               ▼                   ▼
     worker-monitoring   worker-notifications   scheduler (beat)
     (egress network:    (SMTP / WhatsApp /     (due checks, stale-job
      SFTP, cPanel,       Paystack renewals)     recovery, retention)
      HTTP/TLS checks)
```

* The **API never connects to customer systems**; only workers on the `egress` network do.
* Jobs carry only IDs. The `scan_jobs` table is the source of truth (status, attempts, heartbeat, errors).

## Backend layout

```
backend/app
  core/         config, logging (redaction), crypto vault, SSRF guard, pinned HTTP, permissions, errors, rate limiting
  db/           declarative base, session + RLS tenant context
  models/       identity, hosting, websites, scans, incidents, notifications, billing, misc (audit, reports, support)
  connectors/   base interface, path safety, SFTP, cPanel UAPI, registry (+credential encryption)
  monitoring/   inventory walk + diff, classification rules, file-scan persistence, availability/TLS, jobs
  services/     auth, audit, entitlements, incidents, notifications, billing (Paystack), reports, storage, coverage, health, retention, seed, demo
  api/v1/       routers: auth, tenants, websites, hosting, monitoring, incidents, notifications, dashboard, commerce, platform (admin+ops), health
  workers/      Celery app, tasks, worker heartbeats
  cli.py        seed, create-admin, generate-key, rotate-credentials, report-backup, demo-data, verify-audit
```

Domain logic lives in `services/` and `monitoring/`; routers validate input, enforce permissions and shape responses.

## Key decisions

| Decision | Rationale |
|---|---|
| Opaque server-side sessions in an httpOnly cookie + double-submit CSRF token | Revocable, no token in JS storage; Bearer API tokens (`cwp_…`) for automation, scoped and tenant-bound. |
| Tenant in the URL path (`/tenants/{id}/…`) resolved by a single dependency | One audited place that checks membership/grant and sets the RLS scope. Foreign tenants return 404. |
| Forced RLS on tenant tables with `app.scope`/`app.tenant_id` set per transaction | Defence in depth against a missing `WHERE`. Platform scope only for workers and platform routes. |
| Platform roles ≠ customer data access | Staff need a customer-approved, time-limited `managed_service_grant`; actions record `via_grant_id`. Platform privileges require MFA. |
| Partial unique index on active jobs per (website, type) + atomic claim | Prevents overlapping scans corrupting baselines; duplicate requests return the active job. |
| Per-snapshot entries + current inventory table | Enables comparison against any snapshot/baseline and first/last-seen tracking. Retention prunes old non-baseline snapshots. |
| First **completed** scan auto-becomes baseline; later changes need explicit approval | Documented policy; suspicious changes never auto-update the baseline. |
| Deletion only if nearest surviving ancestor directory was fully listed | A failed/partial/limited scan cannot report mass deletion. Root listed empty while previously populated ⇒ deletions withheld + incident. |
| TOFU host-key pinning for SFTP | Practical for 50+ shared-hosting accounts; mismatches block connections and raise a high-severity incident; re-trust is explicit and audited. |
| Platform-run renewals via Paystack `charge_authorization` | Grace period and retries are under our control; Paystack is not assumed to retry. |
| Hash-chained audit and incident history + DB append-only triggers | Tamper-evident; `verify-audit` and the UI check the chain. |
| Local protected object storage behind an interface | Reports/evidence objects; replaceable by S3-compatible storage for multi-node. |

## Data model (main tables)

tenants, users, tenant_memberships, roles, permissions, role_permissions, platform_role_assignments,
managed_service_grants, invitations, user_sessions, login_events, email_tokens, api_tokens,
connector_definitions, hosting_accounts, hosting_credentials, connector_capabilities, capability_discoveries,
website_groups, websites, monitoring_configs, scan_jobs, file_snapshots, file_snapshot_entries, snapshot_errors,
file_inventory_items, file_changes, availability_checks, tls_checks, incidents, incident_events, incident_evidence,
suppression_rules, alert_policies, alert_recipients, notifications, plans, subscriptions, payments, webhook_events,
support_tickets, ticket_messages, reports, audit_events, platform_settings, worker_heartbeats, scheduler_state.

UUID primary keys, UTC `timestamptz`, explicit foreign keys, check constraints and indexes are defined in
`backend/alembic/versions/0001_initial_schema.py`.
