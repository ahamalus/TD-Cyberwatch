# Operations runbooks and troubleshooting

## Daily checks
- **Ops → Security Overview**: queued/running/failed jobs, stale jobs, failing connections, alerts.
- **Ops → Worker Health**: worker heartbeats (< 60 s), scheduler heartbeat (< 3 min), queue depth, disk, backup age.
- `python -m app.cli verify-audit` (cron) — non-zero exit means the audit chain was altered: escalate.

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
