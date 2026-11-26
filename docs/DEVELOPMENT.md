# Development guide

## Prerequisites
Python 3.12+, Node 20+ (22 used), PostgreSQL 16, Redis 7.

```bash
sudo -u postgres psql -c "CREATE USER cyberwatch WITH PASSWORD 'devpassword' CREATEDB;"
sudo -u postgres createdb -O cyberwatch cyberwatch
sudo -u postgres createdb -O cyberwatch cyberwatch_test
```

## Backend
```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt          # exact transitive pins: requirements.lock
export CW_ENVIRONMENT=development CW_COOKIE_SECURE=false
export CW_CREDENTIAL_KEYS="$(python -m app.cli generate-key k1)"
alembic upgrade head && python -m app.cli seed
uvicorn app.main:app --reload --port 8000   # OpenAPI docs: http://localhost:8000/api/docs
celery -A app.workers.celery_app worker -Q monitoring,checks,notifications,default -n dev@%h
celery -A app.workers.celery_app beat
```

To monitor a local SFTP server in development set `CW_OUTBOUND_ALLOW_CIDRS='["127.0.0.0/8"]'` and add the
port to `CW_ALLOWED_SFTP_PORTS` (never in production).

### Tests and quality
```bash
pytest                       # recreates the cyberwatch_test schema, uses an in-process SFTP server
ruff check app tests
pip-audit -r requirements.txt
```
The suite needs PostgreSQL (`CW_DATABASE_URL` defaults to the local `cyberwatch_test` DB). No production
credentials are required: hosting providers are a real in-process SFTP server and mocked cPanel/HTTP/Paystack.

To test as production runs, set `CW_TEST_ADMIN_DATABASE_URL` to a superuser connection to the same database.
Migrations then run as the owner and every test runs as a restricted login that cannot bypass row-level
security (CI does this).

### Migrations
Edit models → `alembic revision --autogenerate -m "describe change"` → review → for any new tenant-owned
table add it to `RLS_TABLES` in `app/models/__init__.py` **and** create its RLS policy in the migration
(copy the pattern from `0001`). Test `alembic upgrade head` and `alembic downgrade -1`.

## Frontend
```bash
cd frontend
npm ci
npm run dev          # http://localhost:5173, proxies /api → localhost:8000
npm test             # Vitest + Testing Library
npm run typecheck
npm run build
```

### Browser tests (Playwright)
`npx playwright test` drives the real application in Chromium:
- **Customer journey:** sign up, connect the sample SFTP site, add a website, take a baseline, plant a test
  file, see the incident, close it as a false positive, then open every customer page.
- **Staff journey:** platform-admin MFA enrolment, then every admin and operations menu entry. It fails on
  console errors or pages that cannot load their data.

Playwright starts everything itself: `e2e/stack.sh` brings up migrations, a sample SFTP server, a Celery
worker and the API, and `vite preview` serves the production build. It needs local PostgreSQL (a
`cyberwatch_e2e` database owned by `cyberwatch`), Redis, and the backend Python environment
(`E2E_PYTHON=../backend/.venv/bin/python`). CI runs it on every push and keeps the HTML report when a test
fails.

## Conventions
- Business logic in `services/` / `monitoring/`; routers stay thin.
- Every tenant route depends on `require(<permission>)`; never accept `tenant_id` from a body.
- Outbound connections only through `core/netguard.py` and `core/http.py`.
- New secrets: add to `SENSITIVE_KEY_PATTERN` if the key name is unusual.
- Never fabricate monitoring results; unknown/unsupported states must be explicit.
