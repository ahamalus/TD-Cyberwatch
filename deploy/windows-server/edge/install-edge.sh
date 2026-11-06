#!/usr/bin/env bash
# Turns a fresh Ubuntu 22.04/24.04 VM into the HTTPS edge for all subdomains (Caddy).
#
# On the edge VM:
#   git clone -b claude/new-session-7dmc53 https://github.com/ahamalus/TD-Cyberwatch.git
#   cd TD-Cyberwatch/deploy/windows-server/edge
#   nano Caddyfile.example          # your subdomains and VM addresses
#   sudo bash install-edge.sh
#
# Re-run it after editing the Caddyfile to validate and apply the change.
set -euo pipefail
cd "$(dirname "$0")"

PRIVATE_NET=${PRIVATE_NET:-10.10.0.0/24}
SOURCE=${1:-Caddyfile.example}

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }
[ -f "$SOURCE" ] || { echo "Caddyfile not found: $SOURCE"; exit 1; }

if ! command -v caddy >/dev/null; then
  echo "==> Installing Caddy (official package repository)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg ufw unattended-upgrades
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy
  dpkg-reconfigure -f noninteractive unattended-upgrades || true
fi

echo "==> Firewall: web from anywhere, SSH only from the private network"
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw allow from "$PRIVATE_NET" to any port 22 proto tcp
ufw --force enable

install -d -m 0755 /var/log/caddy
chown caddy:caddy /var/log/caddy

echo "==> Validating $SOURCE"
caddy validate --adapter caddyfile --config "$SOURCE"
install -m 0644 "$SOURCE" /etc/caddy/Caddyfile
systemctl enable caddy >/dev/null
if systemctl is-active --quiet caddy; then systemctl reload caddy; else systemctl start caddy; fi

echo "==> Edge is serving:"
grep -E '^[a-zA-Z0-9.-]+\.[a-z]{2,}( |,|\{)' /etc/caddy/Caddyfile | sed 's/[ {].*//' | sed 's/^/    https:\/\//'
echo "Certificates are issued automatically once each name's DNS points at the public IP."
echo "Watch progress with:  journalctl -u caddy -f"
