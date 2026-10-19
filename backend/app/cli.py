"""Operational command-line tasks.

    python -m app.cli seed                      # reference data (roles, connectors, plans)
    python -m app.cli create-admin EMAIL NAME   # first platform administrator
    python -m app.cli generate-key [KEY_ID]     # new credential-encryption key entry
    python -m app.cli rotate-credentials        # re-encrypt secrets with the primary key
    python -m app.cli report-backup STATUS PATH # record backup outcome (used by backup script)
    python -m app.cli demo-data                 # synthetic demo tenant (non-production only)
    python -m app.cli verify-audit              # verify the audit hash chain
"""

from __future__ import annotations

import getpass
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
    password = getpass.getpass("Password for the administrator: ")
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
        value = {"status": status, "location": location}
        if row is None:
            db.add(PlatformSetting(key="backup_status", value=value, description="Reported by the backup job."))
        else:
            row.value, row.updated_at = value, utcnow()
        audit.record(db, "ops.backup_reported", details=value, outcome="success" if status == "ok" else "failure")
        db.commit()
    print("Backup status recorded.")


def cmd_verify_audit() -> None:
    with platform_session() as db:
        res = audit.verify_chain(db)
    print(f"valid={res.valid} events={res.events_checked} first_invalid={res.first_invalid_seq} {res.reason or ''}")
    if not res.valid:
        sys.exit(1)


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
        cmd_verify_audit()
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
