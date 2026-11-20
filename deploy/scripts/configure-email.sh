#!/usr/bin/env bash
# Set up outgoing email (alerts, password resets, invitations) and send a test message.
#
#   sudo bash /opt/cyberwatch/deploy/scripts/configure-email.sh
#
# Defaults suit Zoho Mail for a company domain (smtppro.zoho.com, port 587, STARTTLS).
# The password is read without echoing and is never written to your shell history.
# A copy of the previous settings is kept as .env.bak-<time>.
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/cyberwatch}
cd "$APP_DIR"
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }
[ -f .env ] || { echo "$APP_DIR/.env not found."; exit 1; }

# Value of KEY in .env without surrounding quotes; empty (not an error) when the key is absent.
envval() { { grep -E "^$1=" .env || true; } | head -n 1 | cut -d= -f2- | sed "s/^['\"]//; s/['\"]$//"; }
setenv() {  # setenv KEY VALUE: replace the line or append it
  local key=$1 val=$2 tmp
  tmp=$(mktemp)
  awk -v k="$key" -v line="$key=$val" 'BEGIN{done=0} $0 ~ "^"k"=" {if(!done){print line; done=1}; next} {print} END{if(!done) print line}' .env > "$tmp"
  cat "$tmp" > .env && rm -f "$tmp"
}
ask() {  # ask VAR "Question" DEFAULT
  local __v=${!1:-}
  if [ -z "$__v" ]; then read -rp "$2 [$3]: " __v; fi
  printf -v "$1" '%s' "${__v:-$3}"
}

echo "Outgoing email for CyberWatch (press Enter to accept the value in brackets)."
ask SMTP_HOST "SMTP server" "$(d=$(envval CW_SMTP_HOST); echo "${d:-smtppro.zoho.com}")"
ask SMTP_PORT "Port (587 = STARTTLS, 465 = SSL)" "$(d=$(envval CW_SMTP_PORT); echo "${d:-587}")"
ask SMTP_USER "Mailbox address used to sign in" "$(d=$(envval CW_SMTP_USERNAME); echo "${d:-alerts@trustdata.ng}")"
if [ -z "${SMTP_PASSWORD:-}" ]; then
  read -rsp "Password for $SMTP_USER (Zoho: an application-specific password; input hidden): " SMTP_PASSWORD; echo
fi
[ -n "$SMTP_PASSWORD" ] || { echo "A password is required."; exit 1; }
case "$SMTP_PASSWORD" in *"'"*) echo "The password cannot contain a single quote (')."; exit 1 ;; esac
ask FROM_NAME "Sender name shown to recipients" "TrustData CyberWatch"
ask TEST_TO "Send the test email to" "$SMTP_USER"
case "$SMTP_PORT" in ''|*[!0-9]*) echo "Port must be a number."; exit 1 ;; esac

cp -p .env ".env.bak-$(date +%Y%m%d%H%M%S)"
setenv CW_SMTP_HOST "$SMTP_HOST"
setenv CW_SMTP_PORT "$SMTP_PORT"
setenv CW_SMTP_USERNAME "$SMTP_USER"
setenv CW_SMTP_PASSWORD "'$SMTP_PASSWORD'"   # single quotes: no $ expansion by Docker Compose or the shell
setenv CW_SMTP_STARTTLS "${SMTP_STARTTLS:-$([ "$SMTP_PORT" = 25 ] && echo false || echo true)}"
# Zoho only accepts mail "from" the signed-in mailbox (or its aliases).
setenv CW_EMAIL_FROM "\"$FROM_NAME <$SMTP_USER>\""
chmod 600 .env
unset SMTP_PASSWORD

# Same compose-file choice as healthcheck.sh.
if [ -n "$(envval COMPOSE_FILE)" ]; then
  COMPOSE=(docker compose)
elif systemctl is-enabled --quiet cyberwatch-edge-only.service 2>/dev/null; then
  COMPOSE=(docker compose -f docker-compose.yml)
else
  COMPOSE=(docker compose -f docker-compose.yml -f deploy/docker-compose.edge.yml)
fi
echo "==> Applying (restarting the API and the notification worker)"
"${COMPOSE[@]}" up -d api worker-notifications >/dev/null
for _ in $(seq 1 30); do
  "${COMPOSE[@]}" exec -T api python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/api/v1/health/ready')" >/dev/null 2>&1 && break
  sleep 2
done

echo "==> Sending a test email to $TEST_TO"
if "${COMPOSE[@]}" exec -T api python -m app.cli send-test-email "$TEST_TO"; then
  echo
  echo "Done. Alerts, password resets and invitations will now be emailed from $SMTP_USER."
else
  echo
  echo "The test failed (see the reason and hint above). Fix it and run this script again;"
  echo "the previous settings are saved as $APP_DIR/.env.bak-*."
  exit 1
fi
