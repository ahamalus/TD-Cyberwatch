"""Operational command-line tasks.

    python -m app.cli seed                      # reference data (roles, connectors, plans)
    python -m app.cli create-admin EMAIL NAME   # first platform administrator
                                                # (password prompted, or CW_ADMIN_PASSWORD)
    python -m app.cli generate-key [KEY_ID]     # new credential-encryption key entry
    python -m app.cli rotate-credentials        # re-encrypt secrets with the primary key
    python -m app.cli report-backup STATUS PATH # record backup outcome (used by backup script)
    python -m app.cli demo-data                 # synthetic demo tenant (non-production only)
    python -m app.cli verify-audit [--anchors FILE]  # verify the audit hash chain (and saved anchors)
    python -m app.cli audit-anchor              # record and print an anchor of the audit chain head
    python -m app.cli health                    # PASS/FAIL report of workers, scheduler, queue, audit
    python -m app.cli send-test-email ADDRESS   # send one email now and explain any SMTP failure
    python -m app.cli rules-selftest            # run the YARA rules over official WordPress releases now
    python -m app.cli anonymise-user EMAIL REASON...  # erasure request (NDPA): de-identify a user account
    python -m app.cli availability-report HOST [DAYS]  # why a website's availability checks fail (by hour/cause)
    python -m app.cli ensure-app-role           # create/repair the restricted runtime database login
                                                # (CW_APP_DB_USER / CW_APP_DB_PASSWORD; run as the owner)
"""

from __future__ import annotations

import getpass
import os
import sys

from sqlalchemy import select

from app.core.config import get_settings
from app.core.crypto import CredentialVault, EncryptedBlob, generate_key_entry, get_vault
from app.core.security import hash_password, password_problems
from app.db.base import utcnow
from app.db.session import platform_session
from app.models import HostingCredential, PlatformRoleAssignment, PlatformSetting, Subscription, User
from app.services import audit
from app.services.seed import seed_reference_data


def cmd_seed(force: bool = False) -> None:
    with platform_session() as db:
        counts = seed_reference_data(db, force=force)
        db.commit()
    print(f"Seeded: {counts}")


def cmd_create_admin(email: str, name: str) -> None:
    email = email.strip().lower()
    # Non-interactive setups (e.g. the local test kit) may pass the password in the environment.
    password = os.environ.get("CW_ADMIN_PASSWORD") or getpass.getpass("Password for the administrator: ")
    problems = password_problems(password, email)
    if problems:
        sys.exit("; ".join(problems))
    with platform_session() as db:
        if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
            sys.exit("A user with that email already exists.")
        u = User(email=email, full_name=name, password_hash=hash_password(password), is_platform_staff=True,
                 email_verified_at=utcnow(), password_changed_at=utcnow())
        db.add(u)
        db.flush()
        db.add(PlatformRoleAssignment(user_id=u.id, role_key="platform_admin"))
        audit.record(db, "admin.bootstrap_admin_created", target_type="user", target_id=u.id, details={"email": email})
        db.commit()
    print(f"Created platform administrator {email}. Sign in and enrol MFA before using platform functions.")


def cmd_rotate_credentials() -> None:
    from app.connectors.registry import credential_aad

    vault = get_vault()
    n = 0
    with platform_session() as db:
        for cred in db.execute(select(HostingCredential)).scalars():
            if not vault.needs_rotation(EncryptedBlob(cred.key_id, cred.nonce, cred.ciphertext)):
                continue
            aad = credential_aad(cred)
            plain = vault.decrypt(EncryptedBlob(cred.key_id, cred.nonce, cred.ciphertext), aad)
            blob = vault.encrypt(plain, aad)
            cred.key_id, cred.nonce, cred.ciphertext = blob.key_id, blob.nonce, blob.ciphertext
            n += 1
        for user in db.execute(select(User).where(User.mfa_ciphertext.is_not(None))).scalars():
            blob = EncryptedBlob(user.mfa_key_id or "", user.mfa_nonce or b"", user.mfa_ciphertext)
            if vault.needs_rotation(blob):
                aad = CredentialVault.associated_data("user", user.id, "totp")
                new = vault.encrypt(vault.decrypt(blob, aad), aad)
                user.mfa_key_id, user.mfa_nonce, user.mfa_ciphertext = new.key_id, new.nonce, new.ciphertext
                n += 1
        for sub in db.execute(select(Subscription).where(Subscription.auth_ciphertext.is_not(None))).scalars():
            blob = EncryptedBlob(sub.auth_key_id or "", sub.auth_nonce or b"", sub.auth_ciphertext)
            if vault.needs_rotation(blob):
                aad = CredentialVault.associated_data(sub.tenant_id, sub.id, "paystack_auth")
                new = vault.encrypt(vault.decrypt(blob, aad), aad)
                sub.auth_key_id, sub.auth_nonce, sub.auth_ciphertext = new.key_id, new.nonce, new.ciphertext
                n += 1
        audit.record(db, "admin.credentials_reencrypted", details={"count": n, "key_id": vault.primary_key_id})
        db.commit()
    print(f"Re-encrypted {n} secret(s) with key {vault.primary_key_id}.")


def cmd_report_backup(status: str, location: str) -> None:
    with platform_session() as db:
        row = db.get(PlatformSetting, "backup_status")
        now = utcnow().isoformat()
        # Keep the time of the last *successful* backup across failures, so alerts fire when backups stop working.
        previous_success = (row.value or {}).get("last_success_at") if row else None
        value = {"status": status, "location": location, "reported_at": now,
                 "last_success_at": now if status == "ok" else previous_success}
        if row is None:
            db.add(PlatformSetting(key="backup_status", value=value, description="Reported by the backup job."))
        else:
            row.value, row.updated_at = value, utcnow()
        audit.record(db, "ops.backup_reported", details=value, outcome="success" if status == "ok" else "failure")
        db.commit()
    print("Backup status recorded.")


def cmd_verify_audit(anchors_file: str | None = None) -> None:
    from app.services import audit_anchor

    with platform_session() as db:
        res = audit.verify_chain(db)
        print(f"valid={res.valid} events={res.events_checked} first_invalid={res.first_invalid_seq} {res.reason or ''}")
        checks = []
        if anchors_file:
            text = sys.stdin.read() if anchors_file == "-" else open(anchors_file, encoding="utf-8").read()  # noqa: SIM115
            checks = audit_anchor.verify_anchors(db, text)
            for c in checks:
                print(f"{'OK  ' if c.ok else 'FAIL'} {c.line}  ({c.reason})")
            print(f"anchors checked: {len(checks)}, failed: {sum(not c.ok for c in checks)}")
            if not checks:
                print("no anchor lines found in the file")
    if not res.valid or any(not c.ok for c in checks) or (anchors_file and not checks):
        sys.exit(1)


def cmd_audit_anchor() -> None:
    from app.services import audit_anchor

    with platform_session() as db:
        try:
            line = audit_anchor.make_anchor(db)
        except audit_anchor.ChainBroken as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
        db.commit()
    print(line)


def _email_hint(error: str) -> str:
    e = error.lower()
    if "authentication" in e:
        return ("Check CW_SMTP_USERNAME is the full mailbox address and CW_SMTP_PASSWORD is correct. With two-factor "
                "sign-in on, Zoho needs an application-specific password, and SMTP access must be allowed for the mailbox.")
    if "relay" in e or "sender" in e or "553" in e or "550" in e:
        return "CW_EMAIL_FROM must use the same address as CW_SMTP_USERNAME (or an alias of that mailbox)."
    if "timeout" in e or "refused" in e or "oserror" in e or "unreachable" in e:
        return "The server could not reach the SMTP host on that port. Check the host name, or try port 465."
    return "See docs/INTEGRATIONS.md (Email) for the settings."


def cmd_send_test_email(to: str) -> None:
    from email.utils import parseaddr

    from app.services.notifications import DeliveryError, ProviderUnconfigured, send_email

    s = get_settings()
    security = "implicit TLS" if s.smtp_port == 465 else ("STARTTLS" if s.smtp_starttls else "NONE (unencrypted)")
    print(f"SMTP host: {s.smtp_host or '(not set)'}:{s.smtp_port}  security: {security}")
    print(f"Login:     {s.smtp_username or '(none)'}   From: {s.email_from}")
    if not parseaddr(to)[1] or "@" not in to:
        sys.exit("FAILED: give a valid recipient address.")
    try:
        from app.services.email_templates import render_html

        subject = f"{s.product_name}: test email"
        body = (f"This is a test email from {s.product_name} ({s.public_base_url}).\n\n"
                "If you can read this, alert emails, password resets and invitations will be delivered.\n")
        message_id = send_email(to, subject, body, render_html(subject, body))
    except ProviderUnconfigured:
        sys.exit("FAILED: email is not configured (CW_SMTP_HOST is empty).")
    except DeliveryError as exc:
        sys.exit(f"FAILED: {exc}\nHint: {_email_hint(str(exc))}")
    print(f"SENT: accepted by the SMTP server (Message-ID {message_id}).")
    print(f"Check the inbox of {to}, including the spam folder.")


def _malware_health() -> tuple[bool, str, str]:
    from app.monitoring.malware import scanner_status

    st = scanner_status()
    if not st["ok"]:
        return False, "malware scanner", f"{st.get('error')} Files are reported 'not scanned', never 'clean'."
    if not st["yara_ok"]:
        return False, "malware scanner", "YARA rules not loaded (yara-python missing)"
    age = st.get("db_age_hours")
    if not st.get("db_version"):
        return False, "malware scanner", f"{st['engine']} reports no official signature database (freshclam has not run)"
    if age is not None and age > 72:
        return False, "malware scanner", f"{st['engine']}: signatures {age:.0f} hours old (freshclam not updating)"
    return True, "malware scanner", (f"{st['engine']}, signatures {st.get('db_version')} "
                                     f"({'age unknown' if age is None else f'{age:.0f}h old'}), YARA rules {st['yara_rules_version']}")


def _db_role_health(db) -> tuple[bool, str, str]:
    from app.db.roles import current_role_status

    st = current_role_status(db.connection())
    if st.rls_enforced:
        return True, "database role", f"connected as {st.name}: row-level security enforced"
    return False, "database role", (
        f"connected as {st.name}, which {'is a superuser' if st.superuser else 'has BYPASSRLS'}: row-level "
        "security is NOT enforced. Run deploy/scripts/enable-app-db-role.sh (DEPLOYMENT.md)")


def cmd_ensure_app_role() -> None:
    from sqlalchemy import create_engine

    from app.db.roles import ensure_app_role

    name = os.environ.get("CW_APP_DB_USER", "").strip()
    password = os.environ.get("CW_APP_DB_PASSWORD", "")
    if not name or not password:
        print("ensure-app-role: CW_APP_DB_USER / CW_APP_DB_PASSWORD not set; skipped (the application keeps "
              "using the owner login and the health check reports it).")
        return
    engine = create_engine(get_settings().database_url)
    try:
        with engine.begin() as conn:
            result = ensure_app_role(conn, name, password)
    finally:
        engine.dispose()
    print(f"ensure-app-role: {name} {result}; data access granted, row-level security applies.")


def _anchor_health(db) -> tuple[bool, str, str]:
    from app.services.audit_anchor import last_anchor_age_hours

    age = last_anchor_age_hours(db)
    emails = get_settings().audit_anchor_emails
    where = f"emailed to {len(emails)} address(es) and saved with backups" if emails else (
        "saved with backups only (set CW_AUDIT_ANCHOR_EMAILS for an emailed copy)")
    if age is None:
        return False, "audit anchor", "no anchor published yet (runs daily and with each backup)"
    if age > 36:
        return False, "audit anchor", f"last anchor {age:.0f} hours old: daily anchoring is not running"
    return True, "audit anchor", f"last anchor {age:.0f}h ago, {where}"


def _selftest_health(db) -> tuple[bool, str, str]:
    from app.monitoring.malware import yara_rules
    from app.monitoring.selftest import quarantined_rules

    _, version, _ = yara_rules()
    bad = quarantined_rules(db, version)
    if bad:
        detail = "; ".join(f"{r} matched {m[0]['path']} in {m[0]['release']}" for r, m in sorted(bad.items()))
        return False, "rule self-test", f"QUARANTINED (fix the rule): {detail}"[:400]
    from sqlalchemy import func

    from app.models import RuleSelftest

    n = db.execute(select(func.count()).select_from(RuleSelftest).where(
        RuleSelftest.rules_version == version, RuleSelftest.status == "ok")).scalar_one()
    return True, "rule self-test", (f"no rule matches genuine code in {n} official release(s)" if n
                                    else "no releases tested yet (runs daily once WordPress sites are scanned)")


def _email_health(db) -> tuple[bool, str, str]:
    from datetime import timedelta
    from email.utils import parseaddr

    from sqlalchemy import func

    from app.models import Notification

    s = get_settings()
    sender = parseaddr(s.email_from)[1]
    if not s.smtp_host:
        return False, "email", "not configured: alerts and password resets are not sent (deploy/scripts/configure-email.sh)"
    if sender.endswith((".invalid", "example.com", "example.org")):
        return False, "email", f"sender address {sender} is a placeholder: set CW_EMAIL_FROM"
    since = utcnow() - timedelta(hours=24)
    counts = dict(db.execute(select(Notification.status, func.count()).where(
        Notification.channel == "email", Notification.created_at >= since).group_by(Notification.status)).all())
    sent, failed = counts.get("sent", 0), counts.get("failed", 0)
    if failed and not sent:
        return False, "email", f"{failed} failed and none sent in 24h: run send-test-email"
    return True, "email", f"via {s.smtp_host}:{s.smtp_port} as {sender}; 24h: {sent} sent, {failed} failed"


def _backup_health(db) -> tuple[bool, str, str]:
    from datetime import datetime

    row = db.get(PlatformSetting, "backup_status")
    if row is None:
        return False, "backup", "no backup has run yet (deploy/scripts/backup.sh, see docs/OPERATIONS.md)"
    v = row.value or {}
    last_ok = v.get("last_success_at") or (row.updated_at.isoformat() if v.get("status") == "ok" else None)
    if not last_ok:
        return False, "backup", "no successful backup recorded"
    age_h = (utcnow() - datetime.fromisoformat(last_ok)).total_seconds() / 3600
    if age_h > 36:
        return False, "backup", f"last successful backup {age_h:.0f} hours ago"
    if v.get("status") != "ok":
        return False, "backup", f"latest backup FAILED (last success {age_h:.0f}h ago)"
    return True, "backup", f"last successful backup {age_h:.1f} hours ago"


def cmd_health() -> None:
    """Print one PASS/FAIL line per component; exit 1 if anything fails (for scripts and cron)."""
    from datetime import timedelta

    from sqlalchemy import func

    from app.models import ScanJob
    from app.services.health import system_health

    checks: list[tuple[bool, str, str]] = []
    try:
        import kombu.transport.redis  # noqa: F401 - the queue transport must import in this image

        checks.append((True, "queue library", "Celery Redis transport loads"))
    except Exception as exc:  # noqa: BLE001
        checks.append((False, "queue library", f"{type(exc).__name__}: {exc}"))
    with platform_session() as db:
        h = system_health(db)
        checks.append((h["database"]["ok"], "database", "reachable" if h["database"]["ok"] else str(h["database"])))
        checks.append((h["redis"]["ok"], "redis", "reachable" if h["redis"]["ok"] else str(h["redis"])))
        checks.append((h["scheduler"]["ok"], "scheduler", "heartbeat within 3 minutes" if h["scheduler"]["ok"] else "no recent heartbeat"))
        alive = sorted({q for w in h["workers"] if w["alive"] for q in (w["queues"] or [])})
        missing = [q for q in ("monitoring", "checks", "notifications", "default") if q not in alive]
        checks.append((not missing, "workers", f"queues served: {', '.join(alive) or 'none'}"
                       + (f"; NOT served: {', '.join(missing)}" if missing else "")))
        stuck = db.execute(select(func.count()).select_from(ScanJob).where(
            ScanJob.status == "queued", ScanJob.queued_at < utcnow() - timedelta(minutes=20))).scalar_one()
        checks.append((stuck == 0, "job queue", "no checks waiting over 20 minutes" if stuck == 0 else f"{stuck} checks waiting over 20 minutes"))
        res = audit.verify_chain(db)
        checks.append((res.valid, "audit trail", f"{res.events_checked} events, chain {'intact' if res.valid else 'BROKEN at ' + str(res.first_invalid_seq)}"))
        checks.append(_db_role_health(db))
        checks.append(_anchor_health(db))
        checks.append(_malware_health())
        checks.append(_selftest_health(db))
        checks.append(_email_health(db))
        checks.append(_backup_health(db))
        disk = h.get("disk", {})
        if "used_pct" in disk:
            checks.append((disk["used_pct"] < 85, "storage disk", f"{disk['used_pct']}% used"))
    for ok, name, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<20} {detail}")
    if not all(ok for ok, _, _ in checks):
        sys.exit(1)


def cmd_availability_report(host: str, days: int = 3) -> None:
    """Failed availability checks for one website, grouped by cause, plus a live check now."""
    from datetime import timedelta

    from sqlalchemy import func

    from app.models import AvailabilityCheck, Website
    from app.monitoring.availability import check_availability

    host = host.lower().removeprefix("https://").removeprefix("http://").strip("/")
    with platform_session() as db:
        sites = db.execute(select(Website).where(Website.hostname.ilike(f"%{host}%"))).scalars().all()
        if not sites:
            sys.exit(f"No website matches {host!r}.")
        since = utcnow() - timedelta(days=days)
        for w in sites:
            rows = db.execute(select(AvailabilityCheck.outcome, AvailabilityCheck.error_class,
                                     AvailabilityCheck.http_status, func.count(), func.min(AvailabilityCheck.checked_at),
                                     func.max(AvailabilityCheck.checked_at), func.max(AvailabilityCheck.error_message))
                              .where(AvailabilityCheck.website_id == w.id, AvailabilityCheck.checked_at >= since)
                              .group_by(AvailabilityCheck.outcome, AvailabilityCheck.error_class, AvailabilityCheck.http_status)
                              .order_by(func.count().desc())).all()
            total = sum(r[3] for r in rows)
            print(f"\n== {w.name} ({w.url}) - last {days} day(s): {total} checks")
            for outcome, cls, code, n, first, last, msg in rows:
                print(f"  {n:5d}  {outcome:9s} {cls or '-':22s} HTTP {code or '-':<4} "
                      f"{first:%d %b %H:%M} .. {last:%d %b %H:%M}  {(msg or '')[:110]}")
            hour = func.extract("hour", AvailabilityCheck.checked_at)
            hours = db.execute(select(hour, func.count())
                               .where(AvailabilityCheck.website_id == w.id, AvailabilityCheck.checked_at >= since,
                                      AvailabilityCheck.outcome.in_(["down", "error"]))
                               .group_by(hour).order_by(hour)).all()
            if hours:
                print("  Failures by hour (UTC): " + ", ".join(f"{int(h):02d}h:{n}" for h, n in hours))
            res = check_availability(w.url, retry_after=0)
            print(f"  Live check now: {res.outcome} HTTP {res.http_status or '-'} {res.response_ms or '-'} ms "
                  f"{res.error_class or ''} {res.error_message or ''}")


def main(argv: list[str]) -> None:
    if not argv:
        print(__doc__)
        return
    cmd, args = argv[0], argv[1:]
    if cmd == "seed":
        cmd_seed(force="--force" in args)
    elif cmd == "create-admin" and len(args) >= 2:
        cmd_create_admin(args[0], " ".join(args[1:]))
    elif cmd == "generate-key":
        print(generate_key_entry(args[0] if args else "k1"))
    elif cmd == "rotate-credentials":
        cmd_rotate_credentials()
    elif cmd == "report-backup" and len(args) == 2:
        cmd_report_backup(args[0], args[1])
    elif cmd == "verify-audit":
        cmd_verify_audit(args[1] if len(args) == 2 and args[0] == "--anchors" else None)
    elif cmd == "audit-anchor":
        cmd_audit_anchor()
    elif cmd == "health":
        cmd_health()
    elif cmd == "send-test-email" and len(args) == 1:
        cmd_send_test_email(args[0])
    elif cmd == "availability-report" and args:
        cmd_availability_report(args[0], int(args[1]) if len(args) > 1 else 3)
    elif cmd == "ensure-app-role":
        cmd_ensure_app_role()
    elif cmd == "anonymise-user" and len(args) >= 2:
        from app.services import privacy
        from app.services.audit import AuditActor

        with platform_session() as db:
            uid = privacy.anonymise_user(db, args[0], AuditActor(actor_type="system"), " ".join(args[1:]))
            db.commit()
        print(f"Anonymised user {uid}: profile, sign-in history, sessions and alert recipients removed; "
              "audit entries keep only the random id.")
    elif cmd == "rules-selftest":
        from app.monitoring.selftest import run_selftest

        with platform_session() as db:
            print(run_selftest(db))
    elif cmd == "demo-data":
        if not get_settings().is_synthetic_data_allowed:
            sys.exit("Synthetic demo data is only allowed in development, test or demo environments.")
        from app.services.demo import create_demo_tenant

        with platform_session() as db:
            print(create_demo_tenant(db))
            db.commit()
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
