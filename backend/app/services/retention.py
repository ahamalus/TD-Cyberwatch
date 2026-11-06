"""Retention: prune historical monitoring data beyond each tenant's plan limit.

Baseline snapshots are never pruned while referenced. Incident evidence and
audit events are not touched here (they follow their own, longer policy).
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import AvailabilityCheck, FileChange, FileSnapshot, Notification, Tenant, TlsCheck, Website
from app.services.entitlements import effective

KEEP_RECENT_SNAPSHOTS = 5


def run_retention(db: Session) -> dict[str, int]:
    stats = {"snapshots": 0, "availability_checks": 0, "tls_checks": 0, "file_changes": 0, "notifications": 0}
    for tenant in db.execute(select(Tenant)).scalars():
        days = int(effective(db, tenant.id).get("retention_days", 30))
        cutoff = utcnow() - timedelta(days=max(days, 7))
        baselines = set(
            db.execute(select(Website.baseline_snapshot_id).where(
                Website.tenant_id == tenant.id, Website.baseline_snapshot_id.is_not(None))).scalars()
        )
        for website_id in db.execute(select(Website.id).where(Website.tenant_id == tenant.id)).scalars():
            recent = set(
                db.execute(
                    select(FileSnapshot.id).where(FileSnapshot.website_id == website_id)
                    .order_by(FileSnapshot.started_at.desc()).limit(KEEP_RECENT_SNAPSHOTS)
                ).scalars()
            )
            old = db.execute(
                select(FileSnapshot.id).where(FileSnapshot.website_id == website_id, FileSnapshot.started_at < cutoff)
            ).scalars().all()
            doomed = [s for s in old if s not in baselines and s not in recent]
            if doomed:
                stats["file_changes"] += db.execute(
                    delete(FileChange).where(FileChange.snapshot_id.in_(doomed))
                ).rowcount or 0
                stats["snapshots"] += db.execute(delete(FileSnapshot).where(FileSnapshot.id.in_(doomed))).rowcount or 0
        stats["availability_checks"] += db.execute(
            delete(AvailabilityCheck).where(AvailabilityCheck.tenant_id == tenant.id, AvailabilityCheck.checked_at < cutoff)
        ).rowcount or 0
        stats["tls_checks"] += db.execute(
            delete(TlsCheck).where(TlsCheck.tenant_id == tenant.id, TlsCheck.checked_at < cutoff)
        ).rowcount or 0
        stats["notifications"] += db.execute(
            delete(Notification).where(Notification.tenant_id == tenant.id, Notification.created_at < cutoff,
                                       Notification.status.in_(["sent", "failed", "suppressed", "unconfigured"]))
        ).rowcount or 0
    return stats
