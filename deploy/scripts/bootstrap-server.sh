#!/usr/bin/env bash
# One-time setup of a fresh Ubuntu 22.04/24.04 server for TrustData CyberWatch
# at https://cyberwatch.trustdata.ng (or another domain).
#
# Run as root:
#   curl -fsSL https://raw.githubusercontent.com/ahamalus/TD-Cyberwatch/main/deploy/scripts/bootstrap-server.sh -o bootstrap.sh
#   sudo CW_DOMAIN=cyberwatch.trustdata.ng ACME_EMAIL=team@trustdata.ng bash bootstrap.sh
#
# Before running: point a DNS A record for $CW_DOMAIN to this server's public IP.
#
# Behind a shared HTTPS edge (several VMs on one public IP, see docs/WINDOWS_SERVER_HYPERV.md):
#   sudo CW_DOMAIN=cyberwatch.trustdata.ng ACME_EMAIL=team@trustdata.ng EDGE_IP=10.10.0.10 bash bootstrap.sh
# CyberWatch then skips its own Caddy and serves plain HTTP on this VM's private address, port 8080,
# reachable only from the edge VM.
set -euo pipefail

CW_DOMAIN=${CW_DOMAIN:-cyberwatch.trustdata.ng}
ACME_EMAIL=${ACME_EMAIL:?set ACME_EMAIL (receives certificate expiry notices)}
REPO_URL=${REPO_URL:-https://github.com/ahamalus/TD-Cyberwatch.git}
BRANCH=${BRANCH:-main}
APP_DIR=${APP_DIR:-/opt/cyberwatch}
DEPLOY_USER=${DEPLOY_USER:-cyberwatch}
EDGE_IP=${EDGE_IP:-}

if [ -n "$EDGE_IP" ]; then
  # Private address of this VM (the one used to reach the edge).
  PRIVATE_IP=$(ip -4 route get "$EDGE_IP" | awk '{for (i=1;i<NF;i++) if ($i=="src") print $(i+1)}')
  [ -n "$PRIVATE_IP" ] || { echo "Cannot find this VM's address towards $EDGE_IP."; exit 1; }
  COMPOSE=(docker compose -f docker-compose.yml)
else
  COMPOSE=(docker compose -f docker-compose.yml -f deploy/docker-compose.edge.yml)
fi

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }

echo "==> Checking DNS for $CW_DOMAIN"
PUBLIC_IP=$(curl -fsS https://api.ipify.org || true)
DNS_IP=$(getent ahostsv4 "$CW_DOMAIN" | awk 'NR==1{print $1}' || true)
echo "    server public IP: ${PUBLIC_IP:-unknown}; $CW_DOMAIN resolves to: ${DNS_IP:-nothing}"
if [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "$DNS_IP" ]; then
  echo "WARNING: DNS does not point here yet. HTTPS certificates will be issued once it does."
fi

echo "==> Installing system packages and Docker"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl git ufw unattended-upgrades age openssl
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
dpkg-reconfigure -f noninteractive unattended-upgrades || true

ufw default deny incoming
ufw default allow outgoing
if [ -n "$EDGE_IP" ]; then
  echo "==> Firewall: SSH and CyberWatch (8080) from the private network only"
  PRIVATE_NET=$(ip -4 -o addr show | awk -v ip="$PRIVATE_IP" '$4 ~ "^"ip"/" {print $4}' | head -n 1)
  ufw allow from "${PRIVATE_NET:-$EDGE_IP}" to any port 22 proto tcp
  ufw allow from "$EDGE_IP" to any port 8080 proto tcp
else
  echo "==> Firewall: SSH, HTTP, HTTPS only"
  ufw allow OpenSSH
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 443/udp
fi
ufw --force enable

echo "==> Deploy user and code"
id "$DEPLOY_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$DEPLOY_USER"
usermod -aG docker "$DEPLOY_USER"
if [ ! -d "$APP_DIR/.git" ]; then
  git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$APP_DIR"
cd "$APP_DIR"

if [ ! -f .env ]; then
  echo "==> Generating .env with random secrets"
  KEY=$(openssl rand -base64 32)
  sed \
    -e "s|^CW_PUBLIC_BASE_URL=.*|CW_PUBLIC_BASE_URL=https://$CW_DOMAIN|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 24)|" \
    -e "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$(openssl rand -hex 24)|" \
    -e "s|^CW_CREDENTIAL_KEYS=.*|CW_CREDENTIAL_KEYS=k1:$KEY|" \
    .env.example > .env
  printf '\n# ---- Edge (Caddy) ----\nCW_DOMAIN=%s\nACME_EMAIL=%s\n' "$CW_DOMAIN" "$ACME_EMAIL" >> .env
  if [ -n "$EDGE_IP" ]; then
    # Docker-published ports bypass ufw, so bind to the private address only:
    # the private Hyper-V network is not reachable from the internet.
    sed -i "s|^CW_WEB_BIND=.*|CW_WEB_BIND=$PRIVATE_IP|" .env
  fi
  chown "$DEPLOY_USER:$DEPLOY_USER" .env
  chmod 600 .env
  echo "    IMPORTANT: back up CW_CREDENTIAL_KEYS from $APP_DIR/.env to a safe offline location."
fi

echo "==> Building and starting CyberWatch"
sudo -u "$DEPLOY_USER" "${COMPOSE[@]}" build
sudo -u "$DEPLOY_USER" "${COMPOSE[@]}" up -d

echo "==> Waiting for the API"
for _ in $(seq 1 60); do
  if sudo -u "$DEPLOY_USER" docker compose exec -T api python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/api/v1/health/ready')" 2>/dev/null; then
    echo "    API ready"; break
  fi
  sleep 5
done
sudo -u "$DEPLOY_USER" "${COMPOSE[@]}" ps
if [ -n "$EDGE_IP" ]; then
  echo "    Behind the edge: point the edge Caddyfile at http://$PRIVATE_IP:8080 for $CW_DOMAIN"
fi

cat <<MSG

CyberWatch is starting at https://$CW_DOMAIN

Next steps:
  1. Create the first platform administrator (you will be asked for a password):
       cd $APP_DIR && sudo -u $DEPLOY_USER docker compose exec api python -m app.cli create-admin you@trustdata.ng "Your Name"
  2. Sign in at https://$CW_DOMAIN/login and enrol MFA (required for staff).
  3. Configure SMTP / WhatsApp / Paystack in $APP_DIR/.env, then:
       cd $APP_DIR && sudo -u $DEPLOY_USER ${COMPOSE[*]} up -d
  4. Schedule backups (see docs/DEPLOYMENT.md §5).
MSG
