"""Synthetic demonstration tenant.

Everything created here is flagged ``is_demo`` and labelled as demonstration
data in the UI, notifications and reports. It is refused in staging and
production. Demo records are not monitoring results and no remote system is
contacted.
"""

from __future__ import annotations

import hashlib
import random
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.db.base import utcnow
from app.db.session import set_platform_scope
from app.models import (
    AvailabilityCheck,
    FileChange,
    FileSnapshot,
    MonitoringConfig,
    Tenant,
    TenantMembership,
    TlsCheck,
    User,
    Website,
)
from app.services import entitlements
from app.services.incidents import DetectionSpec, EvidenceSpec, raise_detection

DEMO_PASSWORD = "Demo-Only-Password-2026!"  # noqa: S105 - documented, demo environment only


def create_demo_tenant(db: Session) -> str:
    set_platform_scope(db)
    rnd = random.Random(42)  # noqa: S311
    existing = db.execute(select(Tenant).where(Tenant.slug == "demo-organisation")).scalar_one_or_none()
    if existing:
        return "Demo tenant already exists (slug demo-organisation)."
    now = utcnow()
    t = Tenant(name="Demo Organisation (synthetic data)", slug="demo-organisation", is_demo=True,
               contact_email="demo@demo.example.com")
    db.add(t)
    db.flush()
    user = db.execute(select(User).where(User.email == "demo@demo.example.com")).scalar_one_or_none()
    if user is None:
        user = User(email="demo@demo.example.com", full_name="Demo User", password_hash=hash_password(DEMO_PASSWORD),
                    email_verified_at=now)
        db.add(user)
        db.flush()
    db.add(TenantMembership(tenant_id=t.id, user_id=user.id, role_key="owner"))
    entitlements.start_trial(db, t, "professional")

    sites = [("Corporate website", "https://www.example.com/"), ("Customer portal", "https://portal.example.org/"),
             ("Blog", "https://blog.example.net/")]
    for idx, (name, url) in enumerate(sites):
        host = url.split("/")[2]
        w = Website(tenant_id=t.id, name=name, url=url, hostname=host, verification_status="unverified",
                    last_availability_status="up", last_tls_status="valid" if idx != 2 else "expiring",
                    tls_expires_at=now + timedelta(days=80 if idx != 2 else 12),
                    last_scan_at=now - timedelta(hours=3), last_scan_status="completed" if idx != 1 else "partial",
                    last_successful_scan_at=now - timedelta(hours=3), last_availability_at=now - timedelta(minutes=5))
        db.add(w)
        db.flush()
        db.add(MonitoringConfig(tenant_id=t.id, website_id=w.id, file_scan_enabled=False, availability_enabled=False))
        for d in range(14):
            for h in range(0, 24, 6):
                ts = now - timedelta(days=d, hours=h)
                ok = rnd.random() > 0.03
                db.add(AvailabilityCheck(tenant_id=t.id, website_id=w.id, checked_at=ts, outcome="up" if ok else "down",
                                         http_status=200 if ok else 503, response_ms=rnd.randint(180, 900)))
        db.add(TlsCheck(tenant_id=t.id, website_id=w.id, checked_at=now, outcome=w.last_tls_status,
                        valid_to=w.tls_expires_at, days_remaining=(w.tls_expires_at - now).days,
                        issuer="CN=Demo CA (synthetic)", subject=f"CN={host}"))
        snap = FileSnapshot(tenant_id=t.id, website_id=w.id, status=w.last_scan_status, connector_type="sftp",
                            root_path="/public_html", started_at=now - timedelta(hours=3),
                            completed_at=now - timedelta(hours=3) + timedelta(minutes=4),
                            files_seen=rnd.randint(800, 4000), dirs_seen=rnd.randint(60, 300), files_hashed=800,
                            changes_added=2 if idx == 0 else 0, changes_modified=1)
        db.add(snap)
        db.flush()
        if idx == 0:
            for path, ctype, sev, flags in [
                ("wp-content/uploads/2026/10/cache-img.php", "added", "high", ["script_in_upload_dir"]),
                (".htaccess", "modified", "medium", ["server_config_changed"]),
                ("index.php", "modified", "medium", ["script_changed"]),
            ]:
                db.add(FileChange(tenant_id=t.id, website_id=w.id, snapshot_id=snap.id, path=path, change_type=ctype,
                                  entry_type="file", new_sha256=hashlib.sha256(path.encode()).hexdigest(),
                                  severity=sev, flags=flags, detected_at=snap.completed_at))
            raise_detection(db, DetectionSpec(
                tenant_id=t.id, website_id=w.id, title="Suspicious file added: wp-content/uploads/2026/10/cache-img.php",
                summary="[DEMO] A script file appeared in an upload directory.", category="suspicious_file",
                finding_class="heuristic_suspicion", severity="high", confidence="medium",
                detection_source="file_integrity_heuristic", rule_key="script_in_upload_dir",
                dedupe_key=f"demo:{w.id}:upload", recommended_action="Review the file from a safe environment.",
                affected_resources=[{"type": "file", "path": "wp-content/uploads/2026/10/cache-img.php"}],
                evidence=[EvidenceSpec("file_change", "demo", "synthetic", {"note": "synthetic demonstration record"})],
                is_demo=True))
        if idx == 2:
            raise_detection(db, DetectionSpec(
                tenant_id=t.id, website_id=w.id, title=f"TLS certificate expiring for {host}",
                summary="[DEMO] Certificate expires in 12 days.", category="tls", finding_class="configuration_issue",
                severity="medium", confidence="high", detection_source="tls_check", rule_key="tls:expiring",
                dedupe_key=f"demo:{w.id}:tls", recommended_action="Renew the certificate.",
                requires_human_verification=False, is_demo=True))
    return f"Created demo tenant {t.id}. Sign in as demo@demo.example.com / {DEMO_PASSWORD} (development only)."
