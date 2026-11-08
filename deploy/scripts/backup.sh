#!/usr/bin/env bash
# Nightly backup: PostgreSQL dump + report/evidence storage, encrypted, with retention.
# Usage (cron, as a user that can run docker): 17 2 * * * /opt/cyberwatch/deploy/scripts/backup.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
BACKUP_DIR=${BACKUP_DIR:-/var/backups/cyberwatch}
RETENTION_DAYS=${RETENTION_DAYS:-30}
# Public key of the offline backup recipient (age). Keep the private key OFF this server.
AGE_RECIPIENT=${AGE_RECIPIENT:?set AGE_RECIPIENT to an age public key}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$BACKUP_DIR"
umask 077
set -a; . ./.env; set +a

status=ok
{
  docker compose exec -T db pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom \
    | age -r "$AGE_RECIPIENT" > "$BACKUP_DIR/db-$STAMP.dump.age"
  docker compose run --rm --no-deps -T --entrypoint tar api -C /var/lib/cyberwatch -cz storage \
    | age -r "$AGE_RECIPIENT" > "$BACKUP_DIR/storage-$STAMP.tgz.age"
  sha256sum "$BACKUP_DIR"/*-"$STAMP".* > "$BACKUP_DIR/SHA256SUMS-$STAMP"
} || status=failed

find "$BACKUP_DIR" -type f -mtime +"$RETENTION_DAYS" -delete
docker compose run --rm --no-deps api python -m app.cli report-backup "$status" "$BACKUP_DIR/db-$STAMP.dump.age" || true
[ "$status" = ok ] || { echo "backup failed" >&2; exit 1; }
echo "backup ok: $STAMP"
