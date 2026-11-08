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

# Network allowed to reach SSH: defaults to this VM's own network (e.g. 192.168.1.0/24).
if [ -z "${PRIVATE_NET:-}" ]; then
  MY_CIDR=$(ip -4 -o addr show scope global | awk 'NR==1 {print $4}')
  PRIVATE_NET=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "$MY_CIDR")
fi
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

echo "==> Firewall: web from anywhere, SSH only from $PRIVATE_NET"
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw allow from "$PRIVATE_NET" to any port 22 proto tcp
ufw --force enable

# Another web server (nginx, apache, a container) on 80/443 would stop Caddy from starting.
OTHERS=$(ss -ltnpH '( sport = :80 or sport = :443 )' | grep -v '"caddy"' || true)
if [ -n "$OTHERS" ]; then
  echo "ERROR: another program is using port 80 or 443 on this VM:"
  echo "$OTHERS"
  echo "The edge VM should only run Caddy. Stop that program first, e.g.:  sudo systemctl disable --now nginx"
  exit 1
fi

echo "==> Validating $SOURCE"
install -d -m 0755 /var/log/caddy
caddy validate --adapter caddyfile --config "$SOURCE"
# Validation runs as root and may create the log file; the service runs as "caddy" and must own it.
chown -R caddy:caddy /var/log/caddy
install -m 0644 "$SOURCE" /etc/caddy/Caddyfile
systemctl enable caddy >/dev/null
if systemctl is-active --quiet caddy; then systemctl reload caddy; else systemctl restart caddy; fi
sleep 3
if ! systemctl is-active --quiet caddy; then
  echo "ERROR: Caddy did not start. Last messages:"
  journalctl -u caddy -n 15 --no-pager
  exit 1
fi

echo "==> Edge is serving:"
# Site lines look like "name {" or "name, other {"; skip the global block, snippets and the plain-HTTP catch-all.
grep -E '^[^[:space:]#({][^{]*\{$' /etc/caddy/Caddyfile | grep -v '^http://' | sed 's/[[:space:]]*{$//' |
  tr ',' '\n' | sed 's/^[[:space:]]*//; s#^https://##; s#^#    https://#'
grep -qE '^http://[[:space:]]*\{' /etc/caddy/Caddyfile && echo "    http://<any other name or IP>  (plain HTTP catch-all)"
echo "Certificates are issued automatically once each name's DNS points at the public IP."
echo "Watch progress with:  journalctl -u caddy -f"
