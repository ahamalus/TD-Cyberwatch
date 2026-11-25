# Operations runbooks and troubleshooting

## Daily checks
- **Ops → Security Overview**: queued/running/failed jobs, stale jobs, failing connections, alerts.
- **Ops → Worker Health**: worker heartbeats (< 60 s), scheduler heartbeat (< 3 min), queue depth, disk, backup age.
- `python -m app.cli verify-audit` (cron) — non-zero exit means the audit chain was altered: escalate.

- **Backups**: `sudo bash /opt/cyberwatch/deploy/scripts/healthcheck.sh` shows a `backup` line. The Windows host log
  `C:\ProgramData\CyberWatch\backup-pull.log` shows the daily off-server copy. Setup and drills: DEPLOYMENT.md §5.

- **Malware scanner**: the `malware scanner` line of `healthcheck.sh` (engine, signature version and age, YARA rules).
  Signatures older than 3 days or an unreachable scanner turn it red; scans then report files as "not scanned".
  Check the container with `docker compose logs --tail 50 clamav`. The first start downloads about 300 MB of signatures.

- **How file scans read content**:
  - **Full pass:** downloads and hashes every file. This happens on the first scan, and again at least every
    `CW_FULL_CONTENT_CHECK_DAYS` (default 7) to catch files altered with a forged modification time.
  - **Incremental scan:** in between, files whose size and modification time did not change keep their hash
    and malware verdict, so they are not downloaded again.
  - **Time limit:** a full pass that reaches the per-scan time limit (`CW_SCAN_MAX_SECONDS`, 1 hour) resumes
    automatically 5 minutes later, keeping what it has done (at most 12 runs in a row).
  - **Speed:** cPanel reads `CW_CPANEL_PARALLEL_READS` files at a time (default 4) over one kept-alive
    connection.
  - **PHP `error_log` files** are excluded by default.
  - **Progress** is shown on running scans.

- **Official checksum verification (WordPress)**:
  - **What it checks:** scans read `wp-includes/version.php` and plugin headers, then compare files with the
    checksums wordpress.org publishes for that exact release. Core lists come from `api.wordpress.org`
    (MD5) and plugin lists from `downloads.wordpress.org` (MD5 and SHA-256).
  - **Results:** each file is **Genuine**, **Modified** or **Not in release**; see the "Official release"
    column of the file inventory and the website's **Software** tab.
  - **Genuine files:** YARA matches are recorded on the file but not raised as incidents. A ClamAV hit on a
    genuine file is still raised, at medium severity, marked as a probable signature false positive.
  - **Incidents raised:** a modified core file (high); any file inside `wp-admin/` or `wp-includes/` that is
    not part of the release (high for code, medium otherwise); and plugin files that differ from wordpress.org
    (one medium incident per plugin). Changes to bundled `wp-content/` themes and plugins are never reported
    as core tampering.
  - **Updates:** a change whose new content matches the official release (a WordPress or plugin update) is
    not reported as a suspicious change.
  - **Caching:** checksum lists are cached per release in `vendor_checksums`. "Not found" answers are
    retried after 3 days and errors after 6 hours.
  - **When wordpress.org is unreachable:** files are simply not verified. They are never assumed genuine, and
    heuristics apply as normal.
  - **To turn it off:** set `CW_VENDOR_CHECKSUMS_ENABLED=false`. Versions are still detected.

- **YARA rule self-test (daily, 03:41 UTC)**:
  - **What it does:** the rules are run over the official downloads (`downloads.wordpress.org`) of the
    WordPress core and plugin versions found on monitored sites: the 5 most common core versions and 25
    plugins. Archives are read in memory only.
  - **When a rule misfires:** a rule that matches any genuine file is quarantined for the current rule set.
    Its matches are ignored everywhere.
  - **How admins see it:** the `rule self-test` line of `healthcheck.sh` turns FAIL, System Health shows a
    high alert, and Ops → Malware lists the matched file and text.
  - **To fix:** correct the rule in `backend/app/monitoring/yara_rules/webshells.yar`, add a regression
    sample to `tests/test_malware.py`, then deploy. The new rule set gets a new version, which ends the
    quarantine; the next self-test checks it again.
  - **Run it now:** `docker compose exec worker-monitoring python -m app.cli rules-selftest`.

- **Learning from false positives (content approvals)**:
  - **How to approve:** when closing a file finding as a false positive (single or bulk), keep "Don't alert again
    for this exact file content" ticked.
  - **What it creates:** a suppression rule for that website, rule, exact path and SHA-256. The same bytes at
    the same path stop alerting for that rule.
  - **What still alerts:** any edit to the file, the same content at another path, and other rules.
  - **Records:** each approval is added to the incident history and the audit log (`suppression.content_approved`).
  - **Where to see them:** Notifications → Suppression rules, marked "this content only". Disable one there to
    alert on that content again.

- **Access-log analysis**:
  - **When it runs:** only where the hosting connection has *verified* log access. The connection test must
    read a real access log and recognise its format: combined or common format from Apache, LiteSpeed or
    nginx, with an optional virtual-host prefix.
  - **Where it looks:** on cPanel, `~/access-logs` (live logs) and `~/logs` (daily gzip archives) are tried
    unless log folders are set on the connection; on SFTP, the configured log folders.
  - **Hosts that jail accounts:** on hosts using CloudLinux CageFS (for example trustdata.ng's host),
    `~/access-logs` points outside the account and the API cannot follow it. Only the archives in `~/logs`
    work there, so findings arrive after the control panel's daily statistics run, not within the hour.
    Turn on *Metrics → Raw Access → Archive logs in your home directory at the end of each stats run*.
    Archives untouched for 7 days (previous months) are not analysed, and an unchanged archive is not
    downloaded again.
  - **Which files:** only the website's own files, matched by host name (for example
    `example.com-ssl_log`). Compressed archives are skipped.
  - **How often:** hourly by default; set it in Website → Monitoring → Access-log analysis.
  - **How much is read:** only new lines, with a byte position per file. A rotated or truncated log is
    detected and read again from the start. At most 20 MB per file per run; the rest follows next run.
  - **The first run** reads the whole current log, so it can report events from earlier the same day.
  - **Incidents raised (category *Log activity*):**
    - *flagged file accessed*: a file CyberWatch flagged was used. The file must have a malware verdict, an
      open suspicious-file incident, or be planted in core folders. Critical when the antivirus confirmed
      malware. Traffic to a merely *modified* core file such as `wp-login.php` is not counted: the file scan
      reports the modification, and normal visitors use those files.
    - *PHP executed from uploads*: high.
    - *sensitive file served*, such as `.env`, `.git/config`, `wp-config.php` backups or SQL dumps: high.
    - *password guessing*: 20 or more failed `wp-login.php` or `xmlrpc.php` POSTs from one address. Medium,
      or high if a login from that address then succeeded.
  - **Not alerted:** probes for files that don't exist are only counted in the job summary.
  - **What evidence keeps:** up to 20 log lines and the addresses involved. Raw logs are not stored.
  - **If the hosting panel clears logs:** cPanel's "delete logs after statistics processing" means lines older
    than about a day may be gone. Keep the interval at hourly or shorter.

- **Audit-trail anchors (tamper evidence)**:
  - **What they do:** the audit trail is a hash chain, so editing one event breaks it. Someone with full
    server access could still rewrite the *whole* chain. Anchors record the chain's head (`CWANCHOR v1 seq=…
    hash=… at=…`) **off the server**: in every nightly backup set (`audit-anchor-<stamp>.txt`, which the
    Windows host copies and keeps indefinitely) and by daily email to `CW_AUDIT_ANCHOR_EMAILS`.
  - **Who should receive the emails:** use a mailbox that server administrators cannot edit, for example a
    director's mailbox.
  - **To prove the trail was not rewritten:** collect saved anchors (backup files and/or the emails pasted into
    one text file) and run
    `docker compose exec -T api python -m app.cli verify-audit --anchors - < anchors.txt`. Every line must
    say OK. A FAIL means history before that point was changed.
  - **Health:** `healthcheck.sh` shows an `audit anchor` line, which fails if no anchor was published in the
    last 36 hours. If the chain itself is broken, no anchor is published and the recipients are emailed an
    alert.

## Monitoring staff and the NOC wall

**Adding people who watch the platform:** Administration → *Access control* → **Add staff member**. Pick a role:

| Role | For | Can |
|---|---|---|
| NOC Monitor | Screen watchers, junior staff | Read-only: NOC wall, security overview, scan queue, incidents list, worker health |
| Security Operations Analyst | SOC staff who act on findings | The above, plus retry/cancel jobs, act on incidents, hosting diagnostics |
| Platform Administrator | Managers | Everything, including staff and customers |

They receive an email to set a password and must enrol MFA before anything works. No platform role opens a
customer's files, evidence or incident details; that still needs the customer's managed-service grant. From the
same page, **Disable** signs a leaver out everywhere at once (the last platform administrator cannot be
disabled), and **Resend invite** sends a fresh set-password email to someone who has never signed in.

**NOC wall** (Operations → *NOC Wall*, the start page for monitoring-only staff): every monitored website across
all organisations, worst first, refreshed every 15 seconds, with a *Full screen* button for a wall display.
Each site is **Down** (failing availability checks), **Incident** (open critical/high incident), **Degraded**
(slow, TLS expiring or invalid, last file scan failed, or its hosting connection failing), **Operational**,
**No data yet** or **Paused**, with the reasons, 24-hour uptime, response time, TLS days left, last scan and open
incident counts. Hosting connections are listed underneath, failing ones first. Demo organisations are hidden
unless *Include demo data* is selected.

## Service desk (cleanup and other services)

Customers order services under **Support & services**: malware cleanup, fixing a broken site (white screen,
errors, forms, checkout), migration, maintenance tasks and speed optimisation, or ask a question. From an open
incident, **Ask Trust Data to fix this** pre-fills a request. Staff work them in **Operations → Service Desk**
(roles: platform administrator, SOC analyst, managed-service operator, support agent).

| Plan support level | First reply (normal priority) | Finish | Service requests included / month |
|---|---|---|---|
| standard | 24 h | 5 days | 0 (priced per request) |
| priority | 8 h | 3 days | 2 |
| dedicated | 4 h | 2 days | 5 |
| managed | 2 h | 1 day | unlimited |

Urgent requests get a quarter of these times, high half, low double. A plan can override them with the
entitlements `sla_response_hours`, `sla_resolution_hours` and `service_tasks_per_month` (Administration → Plans).
Requests beyond the allowance are marked **Quote**: agree the price with the customer before starting, then set
it under *Billing* on the request.

**Working a request:** assign it (or *Assign to me*), reply to the customer (the first reply stops the response
clock), use **internal notes** for anything the customer should not see, tick the checklist, log time, and write
the **report** (what you found, what you did, how you checked, recommendations). A service request cannot be
resolved without the report. The customer then confirms and closes it.

**Access rules:** staff with the service-desk role read requests themselves, but **never change a site or look at
its monitoring data until the customer authorises the work** on the request page. Authorisation plus an assigned
engineer automatically creates a 14-day access grant for that engineer (recorded in the audit trail with the
customer's authorisation as its basis); it is revoked when the request is closed or cancelled, or when the
engineer is unassigned. Set `CW_SUPPORT_EMAILS` to a shared inbox to be told about new requests as well.

## Investigating a website that keeps failing availability checks
```
sudo -u cyberwatch docker compose exec api python -m app.cli availability-report example.com 3
```
(use any part of the hostname). It lists the last N days' checks grouped by result and cause, failures by hour,
and runs a live check. Reading it:
- `timeout` / `connection_failed` at random times: real instability at the host; scattered single failures are
  now retried after 20 s before counting.
- Failures clustered at the same hours each day: host backups or resource limits (CPU/entry processes) at those times.
- `blocked_by_firewall` (Imunify360, Cloudflare, ModSecurity, Sucuri, Wordfence, CAPTCHA): the site is fine but
  is blocking our checker; ask the host or site owner to allow-list User-Agent `TrustData-CyberWatch-Monitor` /
  the server's public IP. These show as *Degraded*, never *Down*.
- `http_status` 5xx: the site itself is returning errors (PHP errors, database down, resource limits).

## Common problems

| Symptom | Likely cause | Action |
|---|---|---|
| "No monitoring worker heartbeat" | Worker container stopped | `docker compose ps`; `docker compose logs worker-monitoring`; restart |
| "Scheduler heartbeat is stale" | Beat stopped | `docker compose restart scheduler` (run exactly **one** scheduler) |
| Jobs stuck in *queued* | Workers down, Redis unavailable, or per-tenant concurrency limit | Check Redis health; stale-job recovery re-dispatches after 10 min |
| Jobs *failed* with `worker_lost` | Worker crashed mid-job | Check memory (scan limits), retry from Scan Queue |
| Many `timeout` / `connection_refused` | Provider outage or firewall | Check from the worker host with `nc -vz host 22`; increase connector timeouts in Admin → Connectors |
| `host_key_mismatch` | Server rebuilt or MITM | Contact provider; customer re-trusts key after confirmation |
| Notifications `unconfigured` | SMTP/WhatsApp env not set | Configure per INTEGRATIONS.md, then Admin → Messaging → Retry |
| Payments stuck *initialized* | Customer abandoned checkout or webhook blocked | Admin → Payments → Re-verify |
| 502 from web | API container unhealthy | `docker compose logs api`; `/api/v1/health/ready` |

## Incident response (customer security incident)
1. Confirm the finding from evidence (hashes, timestamps). Heuristic ≠ confirmed compromise.
2. Contact the customer's security lead; open/attach a support ticket.
3. With a managed-service grant, record analyst findings as incident notes.
4. Any remediation (file removal, password resets on hosting) requires recorded customer approval on the ticket and is performed by the customer or authorised staff outside CyberWatch.
5. After remediation, run a scan; approve a new baseline only when all changes are explained.

## Credential key rotation
1. `python -m app.cli generate-key k2`; set `CW_CREDENTIAL_KEYS=k2:<new>,k1:<old>`; restart all backend services.
2. `python -m app.cli rotate-credentials` (re-encrypts hosting credentials, MFA secrets, payment authorizations).
3. After a verified backup, remove `k1` from the list and restart.

## Retention
Nightly task prunes non-baseline snapshots older than the plan's `retention_days` (keeping the 5 most recent per website), availability/TLS history and delivered notifications. Audit events and incident evidence are retained.

## Alerting on infrastructure
**Platform alerts (built in).** When a System Health alert (no worker, scheduler stale, database or Redis down,
disk above 85%, no recent backup, malware scanner down, a quarantined rule) lasts more than 3 minutes, CyberWatch
emails every active staff member whose role can read platform health (administrators, SOC analysts, NOC
monitors, auditors) plus `CW_PLATFORM_ALERT_EMAILS`. Reminders: every 2 h (critical), 6 h (high), 24 h
(medium); one "Resolved" email when it clears. The check runs inside the API process, not Celery, and sends
over SMTP directly, so it still works when workers, the scheduler or the notification queue are down. If the
database itself is unreachable, only `CW_PLATFORM_ALERT_EMAILS` can be told (hourly), so set at least one
address there. *Ops → Worker Health → Platform alerting* shows the recipients, open alerts and a **Send test
alert** button.

**External check (set this up too).** Nothing inside a server can report that the server is off. Point a free
uptime service (Cloudflare Health Checks, UptimeRobot, Better Stack) at
`https://cyberwatch.trustdata.ng/api/v1/health/ready` every 5 minutes, alerting the same people.

`/api/v1/health/ready` (DB + Redis) is suitable for that external uptime monitor. System Health alerts list critical conditions; wire them to your on-call channel by polling `/api/v1/ops/health` with a staff session or by log-based alerts on `worker_heartbeat_failed`, `job_failed`, `unhandled_error`.
