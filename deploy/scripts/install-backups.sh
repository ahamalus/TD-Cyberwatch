#!/usr/bin/env bash
# One-time backup setup on the CyberWatch server: encryption key, nightly schedule, first backup.
#
#   sudo bash /opt/cyberwatch/deploy/scripts/install-backups.sh
#
# The private key that decrypts backups is shown ONCE and then destroyed on this server: only the public key
# stays here, so a stolen server or stolen backup files cannot be decrypted. Store the private key safely.
set -euo pipefail
APP_DIR=${APP_DIR:-/opt/cyberwatch}
cd "$APP_DIR"
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }
READER=${BACKUP_GROUP:-${SUDO_USER:-}}   # this login may read the encrypted files, for the off-site copy

command -v age >/dev/null || { echo "==> Installing age"; apt-get install -y -q age >/dev/null; }
install -d -m 0700 /etc/cyberwatch

if [ -s /etc/cyberwatch/backup.pub ]; then
  echo "==> Backup key already set up (public key: $(cat /etc/cyberwatch/backup.pub))"
else
  echo "==> Creating the backup encryption key"
  umask 077
  KEYDIR=$(mktemp -d)
  KEY="$KEYDIR/backup-key.txt"
  # Wipe the private key even if this script is interrupted.
  trap 'shred -u "$KEY" 2>/dev/null; rm -rf "$KEYDIR"' EXIT
  age-keygen -o "$KEY" 2>/dev/null
  age-keygen -y "$KEY" > /etc/cyberwatch/backup.pub
  cat <<MSG

==================================================================================================
 BACKUP PRIVATE KEY - needed to restore ANY backup. Save it now in TWO places:
   1. your password manager (as a secure note), and
   2. a USB stick or other storage kept away from this server.
 It will be deleted from this server afterwards. Without it, the backups cannot be restored.
==================================================================================================
MSG
  cat "$KEY"
  echo "=================================================================================================="
  answer=""
  until [ "$answer" = "SAVED" ]; do read -rp "Type SAVED once the key is stored in both places: " answer; done
  shred -u "$KEY"
  clear 2>/dev/null || true
  echo "==> Private key removed from this server. Public key: $(cat /etc/cyberwatch/backup.pub)"
fi

echo "==> Schedule: checked hourly; runs when the last backup is over 23 h old (nightly ~02:17 UTC, and within an hour after a power cut)"
cat > /etc/cron.d/cyberwatch-backup <<CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
17 * * * * root BACKUP_GROUP=$READER $APP_DIR/deploy/scripts/backup.sh --if-older-than 23 >> /var/log/cyberwatch-backup.log 2>&1
CRON
chmod 644 /etc/cron.d/cyberwatch-backup
cat > /etc/logrotate.d/cyberwatch-backup <<'ROT'
/var/log/cyberwatch-backup.log {
  weekly
  rotate 8
  compress
  missingok
  notifempty
}
ROT

echo "==> First backup now"
BACKUP_GROUP=$READER bash "$APP_DIR/deploy/scripts/backup.sh" | tee -a /var/log/cyberwatch-backup.log
echo
echo "Backups are stored in /var/backups/cyberwatch (encrypted) and run every night."
echo "Next: copy them off this server daily (deploy/windows-server/Pull-CyberWatchBackups.ps1 on the Windows host),"
echo "and run a restore drill (deploy/scripts/restore-drill.sh). See docs/OPERATIONS.md."
