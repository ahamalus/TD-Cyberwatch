#!/usr/bin/env bash
# Switch the API and workers to the restricted database login (row-level security enforced).
# Safe to run more than once. Run from anywhere: sudo bash /opt/cyberwatch/deploy/scripts/enable-app-db-role.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }
[ -f .env ] || { echo "No .env in $(pwd)."; exit 1; }

if grep -Eq '^POSTGRES_APP_PASSWORD=.{16,}' .env && ! grep -q '^POSTGRES_APP_PASSWORD=CHANGE_ME' .env; then
  echo "==> POSTGRES_APP_PASSWORD already set in .env"
else
  cp -p .env ".env.bak-$(date +%Y%m%d%H%M%S)"
  grep -q '^POSTGRES_APP_USER=' .env || echo "POSTGRES_APP_USER=cyberwatch_app" >> .env
  sed -i '/^POSTGRES_APP_PASSWORD=/d' .env
  echo "POSTGRES_APP_PASSWORD=$(openssl rand -hex 24)" >> .env
  echo "==> Added the application database login to .env (password generated, not shown)"
fi

echo "==> Restarting: migrate creates the login, then the API and workers use it"
docker compose up -d
sleep 10
docker compose exec -T api python -m app.cli health | grep -E "database role|database " || true
