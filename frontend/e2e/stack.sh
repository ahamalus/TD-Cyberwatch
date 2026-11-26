#!/usr/bin/env bash
# Starts the real backend for browser tests: migrations, a sample read-only SFTP site, a Celery worker
# and the API on :8000. Playwright starts this script and waits for the API; it stops it afterwards.
# Needs PostgreSQL and Redis (CI services, or local ones) and the backend Python environment.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${E2E_PYTHON:-python}"
STATE="${E2E_STATE_DIR:-/tmp/cw-e2e}"

export CW_ENVIRONMENT=development
export CW_DATABASE_URL="${E2E_DATABASE_URL:-postgresql+psycopg://cyberwatch:devpassword@localhost:5432/cyberwatch_e2e}"
export CW_REDIS_URL="${E2E_REDIS_URL:-redis://localhost:6379/14}"
export CW_CREDENTIAL_KEYS="e2e:$(printf 'E%.0s' {1..32} | base64)"
export CW_COOKIE_SECURE=false
export CW_OUTBOUND_ALLOW_CIDRS='["127.0.0.0/8"]'
export CW_PUBLIC_BASE_URL="http://localhost:4173"
export CW_STORAGE_DIR="$STATE/storage"
export CW_CLAMAV_HOST=
export CW_VENDOR_CHECKSUMS_ENABLED=false
export CW_SMTP_HOST=
export CW_AVAILABILITY_RETRY_SECONDS=0

rm -rf "$STATE" && mkdir -p "$STATE/storage" "$STATE/site"
cp -R "$ROOT/deploy/local/sample-site-original/." "$STATE/site/"

cd "$ROOT/backend"
"$PY" - <<'PY'
import os
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
url = make_url(os.environ["CW_DATABASE_URL"])
with create_engine(url).connect() as c:  # fresh schema for every run
    c.execute(text("DROP SCHEMA IF EXISTS public CASCADE")); c.execute(text("CREATE SCHEMA public")); c.commit()
PY
"$PY" -m alembic upgrade head >/dev/null
"$PY" -m app.cli seed >/dev/null
CW_ADMIN_PASSWORD="E2e-Staff-Password-42" "$PY" -m app.cli create-admin admin@e2e.example.com "E2E Admin" >/dev/null
"$PY" - <<'PY'
import redis, os
redis.Redis.from_url(os.environ["CW_REDIS_URL"]).flushdb()
PY

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT INT TERM

SAMPLE_ROOT="$STATE/site" SAMPLE_SFTP_USER=sampleuser SAMPLE_SFTP_PASSWORD=sample-password-e2e \
  SAMPLE_HOST_KEY="$STATE/host_key" SAMPLE_SFTP_PORT=2222 "$PY" "$ROOT/deploy/local/sample_sftp_server.py" &
pids+=($!)
"$PY" -m celery -A app.workers.celery_app worker -Q monitoring,checks,notifications,default \
  --concurrency 2 --loglevel WARNING -n e2e@%h &
pids+=($!)
"$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level warning &
pids+=($!)
wait -n
