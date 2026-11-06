# Deploying to https://cyberwatch.trustdata.ng

A step-by-step runbook for the production pilot. Time needed: about 30 minutes once the server exists.

## What you need
| Item | Detail |
|---|---|
| Server | Ubuntu 24.04 (or 22.04) VPS: 4 vCPU, 8 GB RAM, 80 GB SSD, public static IPv4. Any provider (e.g. a Lagos-region provider, DigitalOcean, Hetzner, AWS Lightsail). Not the shared Windows server — see DEPLOYMENT.md §1. |
| DNS access | Ability to add a record in the trustdata.ng DNS zone (cPanel *Zone Editor* or your registrar/DNS host). |
| Email for certificates | e.g. team@trustdata.ng (Let's Encrypt expiry notices). |
| Later | SMTP account, Paystack keys, WhatsApp Cloud API (INTEGRATIONS.md). |

## Step 1 — DNS
Create an **A record**: `cyberwatch.trustdata.ng → <server public IPv4>` (TTL 300). Do not proxy it through a
CDN for the first certificate issuance. Check: `dig +short cyberwatch.trustdata.ng` returns the server IP.

The main website www.trustdata.ng is not changed.

## Step 2 — Bootstrap the server (as root)
```bash
curl -fsSL https://raw.githubusercontent.com/ahamalus/TD-Cyberwatch/main/deploy/scripts/bootstrap-server.sh -o bootstrap.sh
less bootstrap.sh                        # review before running
sudo CW_DOMAIN=cyberwatch.trustdata.ng ACME_EMAIL=team@trustdata.ng bash bootstrap.sh
```
Until pull request #1 is merged, use the feature branch:
`.../TD-Cyberwatch/claude/new-session-7dmc53/deploy/scripts/bootstrap-server.sh` and add `BRANCH=claude/new-session-7dmc53`.
If the repository is private, clone it first with a deploy key into `/opt/cyberwatch` and run the script from there.

The script: installs Docker and security updates, enables the firewall (22/80/443 only), creates the
`cyberwatch` user, clones the code to `/opt/cyberwatch`, generates `.env` with random database/Redis
passwords and a credential-encryption key, builds the images and starts all services with Caddy
issuing the HTTPS certificate automatically.

**Immediately back up** `CW_CREDENTIAL_KEYS` from `/opt/cyberwatch/.env` to an offline password manager.

## Step 3 — First administrator
```bash
cd /opt/cyberwatch
sudo -u cyberwatch docker compose exec api python -m app.cli create-admin you@trustdata.ng "Your Name"
```
Open https://cyberwatch.trustdata.ng/login, sign in, and enrol MFA (Account security page). Platform
functions unlock after MFA.

## Step 4 — Verify
- https://cyberwatch.trustdata.ng shows the landing page with a valid certificate.
- `https://cyberwatch.trustdata.ng/api/v1/health/ready` → `{"status":"ready",...}`
- Ops → Worker Health: database, Redis, scheduler and worker all *Healthy*.
- Create a test organisation, connect one real SFTP or cPanel account, add its website, run a scan.

## Step 5 — Integrations and backups
Edit `/opt/cyberwatch/.env` (SMTP, Paystack test keys first, WhatsApp), then apply:
```bash
sudo -u cyberwatch docker compose -f docker-compose.yml -f deploy/docker-compose.edge.yml up -d
```
Paystack webhook URL: `https://cyberwatch.trustdata.ng/api/v1/webhooks/paystack`.
Schedule `deploy/scripts/backup.sh` nightly (DEPLOYMENT.md §5).

## Updating later
```bash
cd /opt/cyberwatch && sudo -u cyberwatch git pull
sudo -u cyberwatch docker compose -f docker-compose.yml -f deploy/docker-compose.edge.yml up -d --build
```

## Troubleshooting
| Symptom | Fix |
|---|---|
| Browser shows certificate error | DNS not yet pointing at the server or port 80 blocked by the provider's firewall: `docker compose logs caddy` |
| 502 Bad Gateway | `docker compose ps`; `docker compose logs api web` |
| Build fails | Ensure ≥ 4 GB RAM free during build; `docker compose build --no-cache` |
| Login loops back | `CW_PUBLIC_BASE_URL` must be `https://cyberwatch.trustdata.ng` and `CW_COOKIE_SECURE=true` |
