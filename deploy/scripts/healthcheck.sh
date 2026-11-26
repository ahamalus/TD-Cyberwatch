#!/usr/bin/env bash
# CyberWatch server health check: one PASS/FAIL line per component.
#
#   sudo bash /opt/cyberwatch/deploy/scripts/healthcheck.sh
#
# Exits 1 if anything fails, so it can also run from cron or a monitoring agent.
set -uo pipefail

APP_DIR=${APP_DIR:-/opt/cyberwatch}
cd "$APP_DIR" || { echo "FAIL  install        $APP_DIR not found"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }

failed=0
pass() { printf 'PASS  %-20s %s\n' "$1" "$2"; }
fail() { printf 'FAIL  %-20s %s\n' "$1" "$2"; failed=1; }
envval() { grep -E "^$1=" .env 2>/dev/null | head -n 1 | cut -d= -f2-; }

# Which compose files this install uses: the local kit names them in .env; a server behind a
# shared edge (EDGE_IP mode) uses the base file only; a standalone server adds its own Caddy.
if [ -n "$(envval COMPOSE_FILE)" ]; then
  COMPOSE=(docker compose)
elif systemctl list-unit-files cyberwatch-edge-only.service >/dev/null 2>&1 && systemctl is-enabled --quiet cyberwatch-edge-only.service; then
  COMPOSE=(docker compose -f docker-compose.yml)
  EDGE_MODE=1
else
  COMPOSE=(docker compose -f docker-compose.yml -f deploy/docker-compose.edge.yml)
fi

echo "== Containers"
while read -r svc state health; do
  [ -z "$svc" ] && continue
  if [ "$svc" = "migrate" ]; then continue; fi
  if [ "$state" = "running" ] && [ "$health" != "unhealthy" ]; then pass "$svc" "running${health:+ ($health)}"
  else fail "$svc" "$state${health:+ ($health)} - see: ${COMPOSE[*]} logs --tail 50 $svc"; fi
done < <("${COMPOSE[@]}" ps -a --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null)
migrate=$("${COMPOSE[@]}" ps -a --format '{{.Service}} {{.State}} {{.Status}}' 2>/dev/null | awk '$1=="migrate"')
case "$migrate" in *"Exited (0)"*|"") pass "migrate" "database schema up to date" ;; *) fail "migrate" "$migrate" ;; esac

echo "== Application"
if out=$("${COMPOSE[@]}" exec -T api python -m app.cli health 2>&1); then echo "$out"
else echo "$out"; failed=1; fi

bind=$(envval CW_WEB_BIND); port=$(envval CW_WEB_PORT)
if [ -z "${EDGE_MODE:-}" ] && [ -z "$(envval COMPOSE_FILE)" ]; then
  # Standalone: the web container is reached through this server's own Caddy.
  url="https://$(envval CW_DOMAIN)/api/v1/health/ready"
else
  url="http://${bind:-127.0.0.1}:${port:-8080}/api/v1/health/ready"
fi
if curl -fsS --max-time 10 --noproxy '*' "$url" | grep -q '"ready"'; then pass "web + api" "$url answers ready"
else fail "web + api" "$url does not answer"; fi

echo "== Security"
perm=$(stat -c %a .env 2>/dev/null)
[ "$perm" = "600" ] && pass ".env" "permissions 600" || fail ".env" "permissions ${perm:-missing} (expected 600): chmod 600 $APP_DIR/.env"
if [ -n "${EDGE_MODE:-}" ]; then
  if systemctl is-active --quiet cyberwatch-edge-only.service && iptables -S DOCKER-USER 2>/dev/null | grep -q -- '--ctorigdstport 8080'; then
    pass "edge-only rule" "port 8080 accepts the edge proxy only"
  else
    fail "edge-only rule" "missing: sudo systemctl restart cyberwatch-edge-only"
  fi
fi
ufw status 2>/dev/null | grep -q "Status: active" && pass "firewall" "ufw active" || fail "firewall" "ufw is not active"

echo "== Host"
disk=$(df --output=pcent / | tail -1 | tr -dc 0-9)
[ "${disk:-100}" -lt 85 ] && pass "disk /" "${disk}% used" || fail "disk /" "${disk}% used"
mem=$(free -m | awk '/^Mem:/ {printf "%d", $7*100/$2}')
[ "${mem:-0}" -ge 10 ] && pass "memory" "${mem}% available" || fail "memory" "only ${mem}% available"

echo
if [ "$failed" -eq 0 ]; then echo "All checks passed."; else echo "Some checks FAILED (see above)."; fi
exit "$failed"
