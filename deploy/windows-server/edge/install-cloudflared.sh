#!/usr/bin/env bash
# Installs Cloudflare Tunnel (cloudflared) on the edge VM as a system service.
#
#   sudo bash install-cloudflared.sh
#
# It asks for the tunnel token from the Cloudflare dashboard (Zero Trust -> Networks -> Tunnels ->
# your tunnel -> the long value after "service install"). The token is read without echoing it and
# is never written to your shell history. The tunnel only makes outgoing connections, so no router
# port forwarding or fixed public IP is needed.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }

if ! command -v cloudflared >/dev/null; then
  echo "==> Installing cloudflared (Cloudflare package repository)"
  install -d -m 0755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
    > /etc/apt/sources.list.d/cloudflared.list
  apt-get update -y
  apt-get install -y cloudflared
fi
cloudflared --version

if systemctl is-active --quiet cloudflared; then
  echo "==> cloudflared is already running as a service; nothing to install."
  echo "    To replace the token: sudo cloudflared service uninstall, then run this script again."
else
  read -rsp "Paste the tunnel token (input is hidden), then press Enter: " TOKEN; echo
  TOKEN=$(printf '%s' "$TOKEN" | tr -d '[:space:]')
  # Accept either the bare token or the whole "cloudflared service install <token>" command.
  TOKEN=${TOKEN##*install}
  [ ${#TOKEN} -gt 50 ] || { echo "That does not look like a tunnel token."; exit 1; }
  cloudflared service install "$TOKEN"
  unset TOKEN
fi

echo "==> Checking"
sleep 5
systemctl is-active --quiet cloudflared && echo "    cloudflared service: running" || { journalctl -u cloudflared -n 20 --no-pager; exit 1; }
if ss -ltn | grep -q '127.0.0.1:8088 '; then
  echo "    Caddy tunnel entrance 127.0.0.1:8088: listening"
else
  echo "    WARNING: nothing listens on 127.0.0.1:8088. Apply the edge config first:"
  echo "             sudo bash install-edge.sh Caddyfile.trustdata-r630"
fi
journalctl -u cloudflared --since "2 min ago" --no-pager | grep -iE "Registered tunnel connection|error" | tail -4
echo
echo "In the Cloudflare dashboard, give the tunnel a public hostname:"
echo "    Subdomain: cyberwatch   Domain: trustdata.ng   Service: HTTP   URL: 127.0.0.1:8088"
