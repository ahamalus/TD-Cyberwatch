#!/usr/bin/env bash
# Nightly backup: PostgreSQL dump + report/evidence storage, encrypted with age, with retention.
#
#   sudo /opt/cyberwatch/deploy/scripts/backup.sh          (install-backups.sh schedules it nightly)
#
# Only the PUBLIC age key is on this server (/etc/cyberwatch/backup.pub or AGE_RECIPIENT); the private key
# that can decrypt backups is kept off the server. Each step is checked: a failed or empty dump is reported
# as failed, and old backups are only pruned after a successful run, never below KEEP_MIN sets.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

BACKUP_DIR=${BACKUP_DIR:-/var/backups/cyberwatch}
RETENTION_DAYS=${RETENTION_DAYS:-30}
KEEP_MIN=${KEEP_MIN:-7}
BACKUP_GROUP=${BACKUP_GROUP:-}   # optional: group allowed to read the (encrypted) files, for off-site copies
AGE_RECIPIENT=${AGE_RECIPIENT:-$(cat /etc/cyberwatch/backup.pub 2>/dev/null || true)}
[ -n "$AGE_RECIPIENT" ] || { echo "No age public key: set AGE_RECIPIENT or run install-backups.sh" >&2; exit 2; }
command -v age >/dev/null || { echo "age is not installed (apt-get install age)" >&2; exit 2; }

# Value of KEY in .env without surrounding quotes; empty (not an error) when the key is absent.
envval() { { grep -E "^$1=" .env || true; } | head -n 1 | cut -d= -f2- | sed "s/^['\"]//; s/['\"]$//"; }
PGUSER=$(envval POSTGRES_USER); PGDB=$(envval POSTGRES_DB)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
umask 077
mkdir -p "$BACKUP_DIR"
DB_FILE="$BACKUP_DIR/db-$STAMP.dump.age"
ST_FILE="$BACKUP_DIR/storage-$STAMP.tgz.age"
SUMS="$BACKUP_DIR/SHA256SUMS-$STAMP"
status=ok
fail() { echo "FAILED: $*" >&2; status=failed; }

started=$(date +%s)
docker compose exec -T db pg_dump -U "$PGUSER" -d "$PGDB" --format=custom | age -r "$AGE_RECIPIENT" > "$DB_FILE.part"
rc=("${PIPESTATUS[@]}")
[ "${rc[0]}" -eq 0 ] || fail "pg_dump exited ${rc[0]}"
[ "${rc[1]}" -eq 0 ] || fail "age (database) exited ${rc[1]}"
[ "$status" = ok ] && [ "$(stat -c %s "$DB_FILE.part")" -lt 1024 ] && fail "database dump is suspiciously small"

if [ "$status" = ok ]; then
  docker compose run --rm --no-deps -T --entrypoint tar api -C /var/lib/cyberwatch -cz storage \
    | age -r "$AGE_RECIPIENT" > "$ST_FILE.part"
  rc=("${PIPESTATUS[@]}")
  [ "${rc[0]}" -eq 0 ] || fail "storage archive exited ${rc[0]}"
  [ "${rc[1]}" -eq 0 ] || fail "age (storage) exited ${rc[1]}"
fi

if [ "$status" = ok ]; then
  mv "$DB_FILE.part" "$DB_FILE" && mv "$ST_FILE.part" "$ST_FILE"
  (cd "$BACKUP_DIR" && sha256sum "$(basename "$DB_FILE")" "$(basename "$ST_FILE")") > "$SUMS"
  if [ -n "$BACKUP_GROUP" ]; then
    chgrp "$BACKUP_GROUP" "$BACKUP_DIR" "$DB_FILE" "$ST_FILE" "$SUMS" && chmod 750 "$BACKUP_DIR" && chmod 640 "$DB_FILE" "$ST_FILE" "$SUMS"
  fi
  # Retention: prune sets older than RETENTION_DAYS, but always keep the newest KEEP_MIN complete sets.
  mapfile -t sets < <(ls -1 "$BACKUP_DIR"/SHA256SUMS-* 2>/dev/null | sort -r)
  for i in "${!sets[@]}"; do
    [ "$i" -lt "$KEEP_MIN" ] && continue
    if [ -n "$(find "${sets[$i]}" -mtime +"$RETENTION_DAYS")" ]; then
      old=${sets[$i]#"$BACKUP_DIR"/SHA256SUMS-}
      rm -f "$BACKUP_DIR"/db-"$old".dump.age "$BACKUP_DIR"/storage-"$old".tgz.age "${sets[$i]}"
    fi
  done
else
  rm -f "$DB_FILE.part" "$ST_FILE.part"
fi

report() { docker compose exec -T api python -m app.cli report-backup "$status" "$DB_FILE" >/dev/null 2>&1 \
  || docker compose run --rm --no-deps -T api python -m app.cli report-backup "$status" "$DB_FILE" >/dev/null 2>&1; }
report || echo "WARNING: could not record the backup result in CyberWatch" >&2

# Anchor the audit trail next to the backup: the Windows host copies it off this server, so a later rewrite
# of the audit history can be detected (python -m app.cli verify-audit --anchors FILE).
ANCHOR_FILE="$BACKUP_DIR/audit-anchor-$STAMP.txt"
if docker compose exec -T api python -m app.cli audit-anchor > "$ANCHOR_FILE.part" 2>/dev/null && [ -s "$ANCHOR_FILE.part" ]; then
  mv "$ANCHOR_FILE.part" "$ANCHOR_FILE"
  [ -n "$BACKUP_GROUP" ] && chgrp "$BACKUP_GROUP" "$ANCHOR_FILE" && chmod 640 "$ANCHOR_FILE"
else
  rm -f "$ANCHOR_FILE.part"
  echo "WARNING: could not anchor the audit trail (is the API running? run: python -m app.cli verify-audit)" >&2
fi

if [ "$status" = ok ]; then
  echo "backup ok: $STAMP ($(du -h "$DB_FILE" | cut -f1) database, $(du -h "$ST_FILE" | cut -f1) storage, $(( $(date +%s) - started ))s)"
else
  echo "backup FAILED: $STAMP" >&2
  exit 1
fi
