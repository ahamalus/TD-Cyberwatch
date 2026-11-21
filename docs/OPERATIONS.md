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
`/api/v1/health/ready` (DB + Redis) is suitable for an external uptime monitor. System Health alerts list critical conditions; wire them to your on-call channel by polling `/api/v1/ops/health` with a staff session or by log-based alerts on `worker_heartbeat_failed`, `job_failed`, `unhandled_error`.
