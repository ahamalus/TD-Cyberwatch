# Security model, threat model and hardening checklist

## Controls implemented

| Area | Control | Where |
|---|---|---|
| Passwords | Argon2id (m=19 MiB, t=2, p=1), min 12 chars, rehash on login | `core/security.py` |
| MFA | TOTP (RFC 6238), secret encrypted at rest, 8 single-use recovery codes; **mandatory for platform staff** (platform permissions withheld until enrolled) | `services/auth.py`, `api/deps.py` |
| Sessions | Opaque token (stored as SHA-256), httpOnly + Secure + SameSite=Lax cookie, absolute (8h) and idle (60m) expiry, per-session revocation, all sessions revoked on password reset/change | `services/auth.py` |
| CSRF | Double-submit token (`cw_csrf` cookie ↔ `X-CSRF-Token` header) on every unsafe request | `api/deps.py` |
| Brute force | Per-IP and per-account rate limits (Redis), account lockout after 8 failures, identical error for unknown user/bad password, login history | `core/ratelimit.py`, `services/auth.py` |
| Authorisation | Permission checks on every route via dependencies; least-privilege role catalogue; owner-only owner changes; API tokens limited to scopes the creator holds | `core/permissions.py`, `api/deps.py` |
| Tenant isolation | Membership/grant check per request, 404 for foreign IDs (no enumeration), every query scoped by `tenant_id`, **forced PostgreSQL RLS** as second layer, jobs run in tenant scope | `api/deps.py`, `db/session.py`, migration |
| Staff access | Time-limited, customer-approved managed-service grants; permissions capped (never billing/membership); every action audited with `via_grant_id`; staff cannot approve their own grants | `api/v1/tenants.py`, `api/v1/platform.py` |
| Credentials | AES-256-GCM, keyring outside DB with rotation, associated data binds ciphertext to tenant + record, never returned by API, decrypted only in workers/connection tests, display fingerprint only | `core/crypto.py`, `connectors/registry.py` |
| SSRF | Hostname validation, block loopback/private/link-local/CGNAT/metadata/multicast/reserved/NAT64, `.internal/.local`, port allow-lists per protocol, **all resolved addresses must be public**, connection pinned to vetted IP (no DNS rebinding), redirects re-validated, SNI/cert validation preserved | `core/netguard.py`, `core/http.py` |
| Path safety | Normalised relative paths, `..`/absolute/NUL rejected, joins confined to root, remote names validated, symlinks recorded not followed, `lstat` before open | `connectors/base.py`, `connectors/sftp.py` |
| Read-only monitoring | Connectors expose only list/stat/read; SFTP server tests prove no write or exec attempts | `tests/test_monitoring_flow.py` |
| Logs | JSON logs with key- and pattern-based secret redaction (passwords, tokens, keys, Authorization, Paystack keys, PEM blocks) | `core/logging.py` |
| Errors | Structured errors with request ID; no stack traces to clients | `core/errors.py` |
| Headers | nosniff, DENY framing, strict referrer, permissions policy, `no-store` + `default-src 'none'` CSP on API, HSTS in production; SPA CSP in nginx | `main.py`, `frontend/nginx.conf` |
| Audit | Hash-chained audit events (append-only trigger), verification endpoint and CLI; incident history hash-chained; evidence content SHA-256 verified on view | `services/audit.py`, `services/incidents.py` |
| Payments | Webhook HMAC-SHA512 verification, dedup by event key, **re-verification with Paystack API before any change**, amount/currency/reference matching, no card data | `services/billing.py` |
| Exports | CSV formula-injection neutralisation; reports hashed; downloads tenant-checked and audited | `services/reports.py`, `api/v1/monitoring.py` |
| Config | Production start refused with debug, dev DB password, insecure cookies, private outbound overrides, or disabled staff MFA | `core/config.py` |
| Containers | Non-root users, read-only root FS, `no-new-privileges`, all capabilities dropped, DB/Redis on internal-only network | `docker-compose.yml` |

## Threat model (STRIDE summary)

| Threat | Scenario | Mitigation | Residual risk |
|---|---|---|---|
| Spoofing | Credential stuffing against customer/staff logins | Rate limits, lockout, MFA (mandatory for staff), login history | Customer MFA is optional; recommend enforcing per organisation (future) |
| Spoofing | Malicious server impersonating customer SFTP host | Host-key pinning, mismatch blocks + high incident | First contact is TOFU; verify fingerprint with provider for high-value accounts |
| Tampering | Attacker edits audit or incident history in DB | Append-only triggers, hash chains, verification UI/CLI | A DB superuser can disable triggers; chain verification still detects edits. Ship daily chain head hash off-box (future) |
| Tampering | Forged Paystack webhook | HMAC verification + API re-verification | Secret key compromise; rotate per INTEGRATIONS.md |
| Repudiation | Staff deny actions in customer tenant | All actions audited with actor, IP, grant ID | — |
| Information disclosure | IDOR across tenants | Tenant-scoped queries, 404s, RLS, tests | — |
| Information disclosure | Secret leakage via logs/API | Redaction, no read-back endpoints, tests | Third-party library logging at DEBUG; keep INFO in production |
| Information disclosure | SSRF to cloud metadata / internal services | Netguard + pinning + port lists; API host has no egress to customers | Workers can reach the public internet by design |
| Denial of service | Huge sites or slow hosts exhaust workers | File/byte/file-count/time/depth limits, per-tenant concurrency, task time limits | Large estates need worker sizing (see DEPLOYMENT.md) |
| Elevation of privilege | Admin makes self owner; viewer escalates | Owner-only owner changes, self-role change blocked, mass assignment ignored, tests | — |
| Elevation of privilege | Compromised customer file triggers code execution in CyberWatch | Files only hashed (streamed), never executed or parsed | Future ClamAV/YARA integration must run sandboxed |

## Security hardening checklist (production)

- [ ] `CW_ENVIRONMENT=production`, `CW_DEBUG=false`, `CW_COOKIE_SECURE=true`, `CW_OUTBOUND_ALLOW_CIDRS=[]`
- [ ] Unique strong `POSTGRES_PASSWORD`, `REDIS_PASSWORD`; `.env` mode `600`, owned by the deploy user
- [ ] `CW_CREDENTIAL_KEYS` generated on the server, stored in a secret manager / offline backup, **not** in the DB backup set
- [ ] HTTPS only at the edge (TLS 1.2+), HSTS enabled, HTTP→HTTPS redirect
- [ ] Host firewall: allow 80/443 inbound (and SSH from admin IPs only); **never** expose 5432/6379/8000
- [ ] First platform admin created via CLI, MFA enrolled immediately; additional staff via Access Control
- [ ] SMTP over STARTTLS with SPF/DKIM/DMARC on the sending domain
- [ ] Paystack live keys only on production; webhook URL `https://<host>/api/v1/webhooks/paystack`
- [ ] Backups encrypted (`age`), tested restore at least quarterly, backup status visible in System Health
- [ ] OS automatic security updates; container images rebuilt monthly; `pip-audit` and `npm audit` reviewed
- [ ] Log shipping to a central, access-controlled store; alert on `auth.login` denied spikes and audit chain failures
- [ ] Review managed-service grants weekly; revoke unused staff accounts
- [ ] Run `python -m app.cli verify-audit` daily (cron) and alert on non-zero exit

## Dependency and vulnerability checks

```bash
cd backend && pip-audit -r requirements.txt
cd frontend && npm audit --omit=dev
```
Results from the build session are recorded in BUILD_STATUS.md.
