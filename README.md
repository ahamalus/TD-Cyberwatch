# TrustData CyberWatch

**Continuous Monitoring. Smarter Protection. Greater Trust.**

TrustData CyberWatch is a multi-tenant website security monitoring and managed
cybersecurity platform by **Trust Data Compliance Ltd**. It monitors websites for
suspicious file changes, availability and TLS problems, raises evidence-backed
incidents, and notifies the right people — either self-service or operated by the
Trust Data security team.

> Status: **pilot-ready foundation, not yet production-certified.** See
> [docs/BUILD_STATUS.md](docs/BUILD_STATUS.md) for exactly what is implemented,
> tested, unverified or blocked.

## What works today

- Multi-tenant organisations, roles, invitations, MFA (TOTP), sessions, API tokens
- Provider-neutral connectors: **SFTP** (read-only, host-key pinning) and **cPanel UAPI**
  (API token), with capability discovery that never assumes unverified features
- SHA-256 file inventories, trusted baselines, change detection (added / modified /
  deleted / renamed), with strict rules so failed or partial scans never create false deletions
- Suspicious-file heuristics, availability and TLS monitoring, incidents with hashed
  evidence, tamper-evident history and explainable risk scores
- Email and WhatsApp (Cloud API) alert routing with escalation, quiet hours, retries and fallback
- Plans/entitlements, Paystack hosted checkout with server-side verification, renewals and grace periods
- CSV/PDF reports, support tickets with recorded remediation approval
- Customer portal (light), platform administration, and security operations portal (dark)
- PostgreSQL Row-Level Security, hash-chained audit trail, SSRF-safe outbound requests

## Repository layout

```
backend/    FastAPI API, SQLAlchemy models, Alembic migrations, Celery workers, tests
frontend/   React + TypeScript + Vite + Mantine portals and design system
deploy/     Edge reverse-proxy example, backup and restore scripts
docs/       Architecture, security, deployment, connectors, integrations, build status
docker-compose.yml, .env.example
```

## Try it on your computer (Docker Desktop)

```bash
./start-local.sh                                            # macOS / Linux
powershell -ExecutionPolicy Bypass -File .\start-local.ps1  # Windows
```

Starts the full platform with a sample website, a read-only sample SFTP server and a local email inbox, and
`simulate-attack` lets you watch a fake web shell get detected. See [docs/LOCAL_TESTING.md](docs/LOCAL_TESTING.md).

## Quick start (development)

Requirements: Python 3.12+, Node 20+, PostgreSQL 16, Redis 7.

```bash
# Backend
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
export CW_ENVIRONMENT=development CW_COOKIE_SECURE=false
export CW_CREDENTIAL_KEYS="$(python -m app.cli generate-key k1)"
export CW_DATABASE_URL=postgresql+psycopg://cyberwatch:devpassword@localhost:5432/cyberwatch
alembic upgrade head
python -m app.cli seed
python -m app.cli demo-data          # optional, clearly-labelled synthetic tenant
uvicorn app.main:app --reload --port 8000
# in other terminals:
celery -A app.workers.celery_app worker -Q monitoring,checks,notifications,default -n dev@%h
celery -A app.workers.celery_app beat

# Frontend
cd frontend && npm ci && npm run dev   # http://localhost:5173 (proxies /api to :8000)
```

Create the first platform administrator: `python -m app.cli create-admin you@trustdata.ng "Your Name"`.

## Tests

```bash
cd backend && pytest            # needs a local PostgreSQL test DB (see docs/DEVELOPMENT.md)
cd frontend && npm test && npm run typecheck
```

## Documentation

| Topic | Document |
|---|---|
| Architecture, decisions, Phase 0 assessment | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Build status and continuation plan | [docs/BUILD_STATUS.md](docs/BUILD_STATUS.md) |
| Development and migrations | [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) |
| Test locally with Docker Desktop (sample site, attack simulation) | [docs/LOCAL_TESTING.md](docs/LOCAL_TESTING.md) |
| Deploy to cyberwatch.trustdata.ng (runbook) | [docs/DEPLOY_CYBERWATCH_TRUSTDATA_NG.md](docs/DEPLOY_CYBERWATCH_TRUSTDATA_NG.md) |
| Production deployment, TLS, backup/restore, upgrade/rollback, Windows/Hyper-V pilot | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Security model, threat model, hardening checklist | [docs/SECURITY.md](docs/SECURITY.md) |
| Hosting connector setup and verification | [docs/CONNECTORS.md](docs/CONNECTORS.md) |
| Paystack, WhatsApp Cloud API and email configuration | [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) |
| Operations runbooks and troubleshooting | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Design system | [docs/DESIGN_SYSTEM.md](docs/DESIGN_SYSTEM.md) |

## Important limitations

CyberWatch detects many signs of compromise but does **not** guarantee detection or
prevention of every attack. Polling detects changes present at scan time, not every
transient change. Malware scanning (ClamAV/YARA), log analysis and real-time file
events are **not active** in this release. Monitoring is read-only: CyberWatch never
deletes, modifies or quarantines customer files.

© Trust Data Compliance Ltd.
