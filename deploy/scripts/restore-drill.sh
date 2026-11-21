#!/usr/bin/env bash
# Restore drill: proves a backup can be decrypted and restored WITHOUT touching the live system.
# The database is restored into a temporary PostgreSQL container with no network, checked, then deleted.
#
#   sudo AGE_IDENTITY=/path/to/backup-key.txt bash /opt/cyberwatch/deploy/scripts/restore-drill.sh [db-<stamp>.dump.age]
#
# Without a file name the newest backup is used. Copy the private key onto the server only for the drill
# and delete it afterwards (shred -u /path/to/backup-key.txt).
set -euo pipefail
cd "$(dirname "$0")/../.."

BACKUP_DIR=${BACKUP_DIR:-/var/backups/cyberwatch}
AGE_IDENTITY=${AGE_IDENTITY:?set AGE_IDENTITY to the private key file (age-keygen output)}
[ -r "$AGE_IDENTITY" ] || { echo "Cannot read $AGE_IDENTITY"; exit 2; }
# Check the key before touching any backup: it must be an age private key, and the one these backups use.
if ! KEY_PUB=$(age-keygen -y "$AGE_IDENTITY" 2>/dev/null); then
  echo "$AGE_IDENTITY does not contain a valid backup private key."
  echo "It must be one line starting with AGE-SECRET-KEY-1 (the key shown once by install-backups.sh), nothing else."
  exit 2
fi
if [ -s /etc/cyberwatch/backup.pub ] && [ "$KEY_PUB" != "$(cat /etc/cyberwatch/backup.pub)" ]; then
  echo "This private key does NOT match the key the backups are encrypted with:"
  echo "    from your key:  $KEY_PUB"
  echo "    backups use:    $(cat /etc/cyberwatch/backup.pub)"
  echo "With this key the backups cannot be restored. Find the correct saved key, or create a new one"
  echo "(see docs/DEPLOYMENT.md section 5)."
  exit 2
fi
DUMP=${1:-$(ls -1t "$BACKUP_DIR"/db-*.dump.age 2>/dev/null | head -n 1)}
[ -n "$DUMP" ] && [ -f "$DUMP" ] || { echo "No backup found in $BACKUP_DIR"; exit 2; }
case "$DUMP" in /*) ;; *) DUMP="$BACKUP_DIR/$DUMP" ;; esac
STAMP=$(basename "$DUMP" | sed 's/^db-//; s/\.dump\.age$//')
STORAGE="$BACKUP_DIR/storage-$STAMP.tgz.age"
SUMS="$BACKUP_DIR/SHA256SUMS-$STAMP"
# Value of KEY in .env without surrounding quotes; empty (not an error) when the key is absent.
envval() { { grep -E "^$1=" .env || true; } | head -n 1 | cut -d= -f2- | sed "s/^['\"]//; s/['\"]$//"; }
CW_VERSION=$(envval CW_VERSION)
IMAGE="trustdata/cyberwatch-backend:${CW_VERSION:-local}"
PG_IMAGE=postgres:16-alpine
DRILL=cw-restore-drill
started=$(date +%s)
cleanup() { docker rm -f "$DRILL" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "Restore drill for backup $STAMP"
echo "== 1. Checksums"
(cd "$BACKUP_DIR" && sha256sum -c "$(basename "$SUMS")")

echo "== 2. Temporary database (no network, in memory)"
cleanup
docker run -d --name "$DRILL" --network none --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_USER=drill -e POSTGRES_PASSWORD=drill -e POSTGRES_DB=drill "$PG_IMAGE" >/dev/null
for _ in $(seq 1 60); do docker exec "$DRILL" pg_isready -U drill -d drill -q 2>/dev/null && break; sleep 1; done
# The image's entrypoint restarts PostgreSQL once after initialising; wait for the final server.
sleep 3; for _ in $(seq 1 30); do docker exec "$DRILL" pg_isready -U drill -d drill -q 2>/dev/null && break; sleep 1; done

echo "== 3. Decrypt and restore the database"
t0=$(date +%s)
age -d -i "$AGE_IDENTITY" "$DUMP" | docker exec -i "$DRILL" pg_restore -U drill -d drill --no-owner --no-privileges --exit-on-error
echo "   restored in $(( $(date +%s) - t0 ))s"

echo "== 4. Contents"
q() { docker exec "$DRILL" psql -U drill -d drill -tAc "$1"; }
for t in tenants users websites hosting_accounts file_snapshots incidents audit_events; do
  printf '   %-18s %s rows\n' "$t" "$(q "select count(*) from $t")"
done
printf '   %-18s %s\n' "schema version" "$(q 'select version_num from alembic_version')"

echo "== 5. Audit trail integrity (hash chain)"
docker run --rm --network "container:$DRILL" \
  -e CW_ENVIRONMENT=development -e CW_DATABASE_URL="postgresql+psycopg://drill:drill@localhost:5432/drill" \
  -e CW_CREDENTIAL_KEYS="$(envval CW_CREDENTIAL_KEYS)" -e CW_REDIS_URL="redis://localhost:6399/0" \
  "$IMAGE" python -m app.cli verify-audit

echo "== 6. Storage archive"
if [ -f "$STORAGE" ]; then
  files=$(age -d -i "$AGE_IDENTITY" "$STORAGE" | tar -tz | grep -vc '/$' || true)
  echo "   $files files (reports and evidence) readable"
else
  echo "   no storage archive for this backup"; exit 1
fi

echo
echo "RESTORE DRILL PASSED for $STAMP in $(( $(date +%s) - started ))s. Nothing on the live system was changed."
echo "Record the result (date, backup, duration) in docs/OPERATIONS.md, then delete the key from this server:"
echo "    shred -u $AGE_IDENTITY"
