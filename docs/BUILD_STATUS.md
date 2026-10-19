# Build status

Last updated: 2026-10-19 (session 1). Statuses: **Not Started · In Progress · Implemented · Tested · Blocked**.
"Tested" means automated tests were written **and executed** in this session with the results shown.

## Test runs executed (actual results)

| Suite | Command | Result |
|---|---|---|
| Backend (unit, integration, security) | `cd backend && pytest` | **104 passed**, 0 failed (PostgreSQL 16 + in-process SFTP server; FastAPI 0.149 / Starlette 1.9) |
| Backend lint | `ruff check app tests` | All checks passed |
| Backend dependencies | `pip-audit` (installed env) | No known vulnerabilities (after upgrading Starlette 0.46.2 → 1.9.0, which had 7 advisories) |
| Frontend unit/component | `cd frontend && npm test` | **12 passed** (Vitest 5 + Testing Library) |
| Frontend types | `npm run typecheck` | Clean |
| Frontend build | `npm run build` | Succeeds (single 1.2 MB JS bundle; code-splitting pending) |
| Frontend dependencies | `npm audit` | 0 vulnerabilities (after React Router 6.28 → 7.18.4 and Vitest/PostCSS upgrades; unused postcss-preset-mantine removed) |
| Live stack smoke test | API + Celery worker + beat + Redis + PostgreSQL + SFTP server | Connection test, capability discovery, baseline scan, detection of an injected `uploads/evil.php` (high-severity incident) all succeeded through the real queue |
| UI smoke (Chromium/Playwright) | 23 screens desktop + mobile, customer/admin/ops | All rendered against the real API with demo data; 0 console errors after fixes |
| Migrations | `alembic upgrade head` / `downgrade base` / `upgrade head` | Succeeded |
| Docker images | `docker compose config` | Valid. **Images not built**: Docker daemon cannot run in the build sandbox |

## Feature status

### Phase 1 — Monitoring foundation
| Feature | Status | Files | Tests | Outstanding |
|---|---|---|---|---|
| Backend foundation, config, structured errors, security headers | Tested | `app/main.py`, `app/core/*` | security headers, no stack traces, unsafe production config refused | — |
| PostgreSQL schema + migrations + forced RLS + append-only triggers | Tested | `alembic/versions/0001_initial_schema.py`, `app/db/session.py` | RLS cross-tenant read/write tests | — |
| Authentication (Argon2id, sessions, CSRF, lockout, rate limits, MFA, recovery codes, reset, verification) | Tested | `services/auth.py`, `api/v1/auth.py`, `api/deps.py` | `test_auth.py` (11) | Enforce MFA per organisation (option) |
| Roles/permissions, tenant context, managed-service grants | Tested | `core/permissions.py`, `api/deps.py`, `api/v1/tenants.py` | escalation, support-agent, grant tests | — |
| Connector interface + registry + credential encryption | Tested | `connectors/base.py`, `connectors/registry.py`, `core/crypto.py` | ciphertext tenant binding, secret absence | KMS/Vault integration (optional) |
| SFTP connector (read-only, host-key pinning) | Tested | `connectors/sftp.py` | 13 end-to-end tests vs real SFTP server | Verify against the reseller's real hosts |
| cPanel UAPI connector | Implemented (mock-tested) | `connectors/cpanel.py` | mocked UAPI listing/hashing/binary/bad token | **Blocked on live verification** (docs host unreachable; see CONNECTORS.md checklist) |
| Capability discovery + timestamped profiles | Tested | `monitoring/jobs.py` | capability assertions | — |
| Website & hosting registration, duplicate detection, verification (HTTP file) | Tested | `api/v1/websites.py`, `api/v1/hosting.py` | CRUD, duplicate, SSRF URL tests | DNS TXT verification |
| File inventory, streaming SHA-256, baseline, change detection, rename inference | Tested | `monitoring/inventory.py`, `monitoring/file_scan.py` | add/modify/delete/rename, limits, exclusions | — |
| Partial/failed scan handling (no false deletions) | Tested | same | permission-denied dir, failed root, emptied root, file-count limit | — |
| Scan history, snapshots, inventory, compare with baseline, CSV export | Tested | `api/v1/monitoring.py` | via flow tests | — |
| Job queue, scheduler, uniqueness, claim, retries/backoff, stale recovery, per-tenant concurrency, cancellation | Tested | `monitoring/jobs.py`, `workers/*` | overlap, double-claim, stale, concurrency, cancel, failure never succeeded | Dedicated per-host concurrency limit |
| Availability + TLS checks (SSRF-safe, pinned) | Tested | `monitoring/availability.py`, `core/http.py` | redirect, blocked redirect, real TLS handshake | — |
| Structured logging + redaction + audit chain | Tested | `core/logging.py`, `services/audit.py` | redaction, tamper detection | Off-box chain anchoring |
| Worker heartbeats + health | Implemented (live-verified) | `workers/tasks.py`, `services/health.py` | live smoke | CPU/memory per worker (only API host load shown) |

### Phase 2 — Security operations
| Feature | Status | Notes |
|---|---|---|
| Suspicious-file rules (documented, explainable) | Tested | `monitoring/rules.py` (7 rule tests) |
| Incidents: lifecycle, dedupe, assignment, notes, false positives, suppression rules | Tested | `services/incidents.py` |
| Evidence store (hashed JSON evidence, object storage for reports) | Tested | integrity verified on view |
| Risk scoring and correlation (explainable) | Implemented | Basic correlation (file changes + availability); tuning UI pending |
| Email notifications | Tested (mock SMTP) | Live SMTP not configured in session |
| WhatsApp Cloud API adapter | Implemented (mock-tested) | Needs Meta account, approved templates; delivery webhooks not processed |
| Role-based recipients, escalation, quiet hours, quotas, idempotency, retries, fallback | Tested | |
| ClamAV integration | **Not Started** | Requires sandboxed scanner service; capability shown as unsupported |
| YARA integration | **Not Started** | |
| Log analysis | **Not Started** | Shown as unavailable; never claimed |

### Phase 3 — Client portal
| Feature | Status | Notes |
|---|---|---|
| Design system, shell, responsive layouts, themes | Implemented | screenshots reviewed; WCAG audit pending |
| Dashboard (real data), websites + onboarding, hosting + discovery, monitoring config, file integrity, incidents, notifications, reports, billing, support, settings | Implemented | Component tests + browser smoke; full E2E journey tests pending |

### Phase 4 — Administration and operations portals
| Feature | Status | Notes |
|---|---|---|
| Platform overview, customers (suspend/reactivate), access control, connector registry, plans, payments, messaging, managed services, analytics, audit (+verify), configuration, health | Implemented | Backend permission tests cover access boundaries |
| Ops overview, scan queue (retry/cancel), diagnostics, global incidents (grant-gated detail), notification failures, worker health | Implemented | File/malware/log/evidence views explain grant/availability honestly |

### Phase 5 — Commercial
| Feature | Status | Notes |
|---|---|---|
| Configurable plans + backend-enforced entitlements, trials | Tested | |
| Paystack checkout, verification, idempotent webhooks, renewals, grace period, reminders, receipts | Tested (mocked Paystack) | **Needs sandbox keys** for live test; refund/dispute workflow not built |

### Phase 6 — Production readiness
| Item | Status |
|---|---|
| Dockerfiles, compose, edge proxy, backup/restore scripts | Implemented — **images not built in session** |
| Docs (deployment, security, connectors, integrations, operations) | Implemented |
| CI pipeline | Implemented (`.github/workflows/ci.yml`), not yet run on GitHub |
| Performance/resource tests at 50+ accounts | Not Started |
| Backup/restore drill | Not Started (scripts untested — need Docker host) |
| External penetration test / WCAG audit | Not Started |

## External credentials and infrastructure required
- Linux VPS or approved Hyper-V VM (DEPLOYMENT.md), domain + DNS, TLS certificate.
- SMTP account; Meta WhatsApp Business account with approved templates; Paystack test then live keys.
- At least one real SFTP account and one cPanel account (API token) for connector verification.
- `age` key pair for backups; off-site backup storage.

## Known limitations
- Polling-based detection only; no real-time file events, malware engines or log analysis yet.
- cPanel connector unverified against a live server.
- Risk scoring is a simple documented heuristic.
- Frontend bundle not code-split; UI not independently accessibility-audited.
- Report generation is synchronous (fine for pilot scale; move to worker for large estates).

## Next implementation tasks (continuation plan)
1. Deploy to a staging VPS with Docker; run backup/restore drill; run CI on GitHub.
2. Verify cPanel UAPI against a live account (CONNECTORS.md checklist); fix parser if needed.
3. Connect 2 real hosting accounts / 3 websites (Phase 1 proof of concept on real infrastructure); record results here.
4. Configure SMTP and Paystack sandbox; run end-to-end payment test.
5. ClamAV in an isolated scanner container (stream file bytes from workers; record engine/signature version; enforce size/time limits; archive handling).
6. Playwright E2E journeys in CI; code-split frontend routes.
7. Load test with synthetic 200k-file inventories; tune batch sizes and worker concurrency.
