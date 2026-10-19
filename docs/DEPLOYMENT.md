# Deployment guide

## 1. Where to run CyberWatch

**Recommendation: a dedicated Linux VPS (Ubuntu 24.04 LTS) for production**, not the shared
Windows Server 2022 host.

The Windows server (16 GB RAM, 8 cores) already carries other workloads and may host an Ubuntu VM
for the Adamawa State e-Justice Jitsi deployment. Jitsi video bridges are CPU-, bandwidth- and
latency-sensitive; CyberWatch file scans are bursty in CPU, disk and outbound connections. Co-locating
them risks degrading court hearings during scan windows, and widens the blast radius of either system.

| Component | Pilot (≤ 50 accounts / 60 websites) | Notes |
|---|---|---|
| vCPU | 4 | Monitoring worker concurrency 4 |
| RAM | 8 GB | PostgreSQL 2 GB, workers ~300 MB each |
| Disk | 80 GB SSD | Snapshot entries ≈ 150 bytes/file/scan; retention prunes |
| Network | Static IPv4, outbound 22/2083/80/443 | Inbound 80/443 only |

Before any co-location on the Windows host, record in a capacity assessment: free RAM under peak load,
CPU headroom during Jitsi sessions, Hyper-V host reserve, disk IOPS, network exposure, and backup
coverage. Only proceed if a dedicated Hyper-V Ubuntu VM can be allocated **at least** the pilot figures
above without overcommitting memory, and with its own virtual switch/VLAN. See §7.

## 2. Production deployment (Docker Compose)

```bash
# On the Linux host, as a non-root deploy user in the docker group
git clone <repo> /opt/cyberwatch && cd /opt/cyberwatch
cp .env.example .env && chmod 600 .env
docker compose run --rm --no-deps --entrypoint python api -m app.cli generate-key k1
# paste the output into CW_CREDENTIAL_KEYS, set all CHANGE_ME values and CW_PUBLIC_BASE_URL
docker compose build
docker compose up -d                  # runs migrations + seed (service "migrate") before api/workers
docker compose run --rm api python -m app.cli create-admin admin@trustdata.ng "Platform Admin"
```

Sign in, enrol MFA (required before platform functions unlock), then configure SMTP/WhatsApp/Paystack
(see INTEGRATIONS.md).

Services: `db`, `redis`, `migrate` (one-shot), `api`, `worker-monitoring` (queues `monitoring,checks`),
`worker-notifications` (queues `notifications,default`), `scheduler` (Celery beat), `web` (nginx SPA +
API proxy, bound to `127.0.0.1:8080`). Only `web` publishes a port. Scale scanning with
`docker compose up -d --scale worker-monitoring=2`.

## 3. Reverse proxy and TLS

Use `deploy/nginx/cyberwatch.conf` on the host (or Caddy) to terminate TLS and forward to
`127.0.0.1:8080`:

```bash
sudo apt install nginx certbot python3-certbot-nginx
sudo cp deploy/nginx/cyberwatch.conf /etc/nginx/sites-available/ && sudo ln -s ../sites-available/cyberwatch.conf /etc/nginx/sites-enabled/
# add the limit_req_zone and proxy snippet shown at the bottom of that file
sudo certbot --nginx -d cyberwatch.example.com
sudo nginx -t && sudo systemctl reload nginx
```

Firewall (ufw): `allow 80,443/tcp`; `allow from <admin-ip> to any port 22`; default deny inbound.
Never publish PostgreSQL (5432), Redis (6379) or the API (8000).

## 4. Database migrations

Migrations run automatically through the `migrate` service on every `up`. Manually:
`docker compose run --rm migrate`. Create new revisions in development with
`alembic revision --autogenerate -m "..."` and review them (RLS policies for new tenant tables must be
added by hand — see migration 0001).

## 5. Backup and restore

* `deploy/scripts/backup.sh` (cron nightly): encrypted `pg_dump` + storage archive with `age`, SHA-256
  manifest, retention, and reports status to System Health. Copy backups off-site.
* Back up `.env` (especially `CW_CREDENTIAL_KEYS`) **separately** — without the key, stored hosting
  credentials cannot be decrypted (customers would need to re-enter them).
* Restore: `AGE_IDENTITY=key.txt deploy/scripts/restore.sh <dump>` (stops services, restores, migrates,
  verifies the audit chain, restarts). Test a restore into a scratch environment at least quarterly and
  record the result.

## 6. Upgrade and rollback

1. Read release notes / BUILD_STATUS.md for migration changes.
2. Run `deploy/scripts/backup.sh`.
3. `git pull && docker compose build && docker compose up -d` (migrations run first).
4. Check `/api/v1/health/ready`, Admin → System Health, and a manual connection test.

Rollback: `git checkout <previous tag> && docker compose build`. If the release included a migration,
either run `docker compose run --rm migrate alembic downgrade <rev>` (only for reversible migrations) or
restore the pre-upgrade backup. Tag every deployed version (`CW_VERSION`).

## 7. Windows Server / Hyper-V pilot guide

For a time-boxed pilot only, after the capacity assessment in §1:

1. Create a Generation 2 Hyper-V VM: Ubuntu Server 24.04, 4 vCPU, **8 GB static memory** (disable dynamic
   memory to protect other workloads), 80 GB VHDX on SSD, a dedicated virtual switch.
2. Do not share the VM with Jitsi. Set Hyper-V CPU reserve/limit so the Jitsi VM keeps priority.
3. Install Docker Engine inside the VM and follow §2–§3. Do not run CyberWatch with Docker Desktop on the
   Windows host itself.
4. Expose only 443 (via the host firewall/NAT) to the VM; keep RDP/SSH management on an admin network.
5. Monitor host CPU/RAM during Jitsi sessions; reduce `CW_MONITORING_CONCURRENCY` or schedule file scans
   outside court hours (maintenance windows) if contention appears.

## 8. Development and demo environments

`CW_ENVIRONMENT=demo` allows `python -m app.cli demo-data` (synthetic, labelled tenant). Production refuses
synthetic data, debug mode, insecure cookies and private outbound overrides at start-up.
