# Deployment guide

> For the TrustData production pilot at **https://cyberwatch.trustdata.ng**, follow
> [DEPLOY_CYBERWATCH_TRUSTDATA_NG.md](DEPLOY_CYBERWATCH_TRUSTDATA_NG.md) (automatic HTTPS via Caddy,
> one-command server bootstrap). This document covers the general options.

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

**Set up (once, on the CyberWatch server):**
```bash
sudo bash /opt/cyberwatch/deploy/scripts/install-backups.sh
```
The script does the following:
- Creates an `age` key pair and shows the **private key once**, for you to store in a password manager and on offline media. It then deletes the key from the server; only the public key remains.
- Schedules `backup.sh` nightly at 02:17 UTC.
- Runs the first backup.

**What `backup.sh` does:**
- Writes an encrypted `pg_dump` and an encrypted archive of the reports/evidence storage to `/var/backups/cyberwatch`, with a SHA-256 manifest per set.
- Checks every step. A failed or empty dump is reported as **failed**, and partial files are removed.
- Removes old sets only after a successful run: sets older than 30 days are deleted, but the newest 7 are always kept.
- Records the result in CyberWatch. `healthcheck.sh` and System Health go red when the latest backup failed, or when no backup has succeeded for 36 hours.

**Copy off the server (daily).** On the Windows Hyper-V host, as administrator:
```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows-server\Pull-CyberWatchBackups.ps1 -Install
```
This creates a scheduled task (06:30 daily). It copies new encrypted sets to `C:\CyberWatch-Backups`, verifies the checksums, keeps 60 days, and logs to `C:\ProgramData\CyberWatch\backup-pull.log`. For disaster recovery, also keep a periodic copy away from the building (cloud storage or a rotated USB disk).

**Restore drill (quarterly, and after major upgrades).** This is non-destructive:
```bash
# copy the private key to the server for the drill only
sudo AGE_IDENTITY=/root/backup-key.txt bash /opt/cyberwatch/deploy/scripts/restore-drill.sh
sudo shred -u /root/backup-key.txt
```
It checks the checksums, restores the newest dump into a temporary database with no network, counts the records,
verifies the audit hash chain and reads the storage archive. Record the date and result in the log below.

**Lost or wrong private key.** `restore-drill.sh` checks the key first and says if it does not match. Backups made
with a lost key cannot be restored. Create a new key and a fresh backup straight away:
```bash
sudo rm /etc/cyberwatch/backup.pub && sudo bash /opt/cyberwatch/deploy/scripts/install-backups.sh
```
Then run the drill again with the new key.

**Real restore** (replaces the live database):
```bash
AGE_IDENTITY=key.txt deploy/scripts/restore.sh <db-*.dump.age>
```
It stops the services, restores, migrates, verifies the audit chain and restarts. Back up `.env`, especially
`CW_CREDENTIAL_KEYS`, **separately**. Without it, stored hosting credentials cannot be decrypted after a restore.

| Date | Backup set | Drill result | Duration | By |
|---|---|---|---|---|
| 2026-11-20 | test stack | PASSED (checksums, restore, audit chain, storage) | 9 s | development check |

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
