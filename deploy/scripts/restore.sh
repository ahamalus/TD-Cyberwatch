#!/usr/bin/env bash
# Restore a database backup into a STOPPED stack. Destructive: replaces the current database.
# Usage: AGE_IDENTITY=/path/to/key.txt ./restore.sh /var/backups/cyberwatch/db-<stamp>.dump.age
set -euo pipefail
cd "$(dirname "$0")/../.."
DUMP=${1:?path to db-*.dump.age}
AGE_IDENTITY=${AGE_IDENTITY:?path to the age private key}
set -a; . ./.env; set +a
read -r -p "This REPLACES database $POSTGRES_DB. Type the database name to continue: " confirm
[ "$confirm" = "$POSTGRES_DB" ] || { echo "aborted"; exit 1; }
docker compose stop api worker-monitoring worker-notifications scheduler web
age -d -i "$AGE_IDENTITY" "$DUMP" | docker compose exec -T db pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner
docker compose run --rm migrate
docker compose run --rm api python -m app.cli verify-audit
docker compose up -d
echo "Restore complete. Verify the dashboard and worker health before announcing service."
