"""Load test of the file-scan pipeline with a synthetic site (default 200,000 files).

Runs the real ``run_file_scan`` (walk, hashing, YARA, change detection, database writes, incidents) against
an in-memory file source, so it measures CyberWatch itself rather than the network. Three scans:

1. first full scan (baseline),
2. incremental scan with nothing changed,
3. incremental scan after changing ``--changes`` files and adding a suspicious upload.

Usage (uses its own database, which it recreates):
    CW_DATABASE_URL=postgresql+psycopg://cyberwatch:devpassword@localhost:5432/cyberwatch_load \\
        python scripts/loadtest_scan.py --files 200000
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import resource
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta

os.environ.setdefault("CW_ENVIRONMENT", "development")
os.environ.setdefault("CW_CREDENTIAL_KEYS", "load:" + base64.b64encode(b"L" * 32).decode())
os.environ.setdefault("CW_CLAMAV_HOST", "")
os.environ.setdefault("CW_VENDOR_CHECKSUMS_ENABLED", "false")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, func, select, text  # noqa: E402

from app.connectors.base import FileSource, RemoteEntry  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.db.session import platform_session, reset_engine  # noqa: E402
from app.models import (  # noqa: E402
    ConnectorCapability,
    FileInventoryItem,
    FileSnapshotEntry,
    HostingAccount,
    Incident,
    MonitoringConfig,
    ScanJob,
    Tenant,
    Website,
)
from app.monitoring import file_scan  # noqa: E402

T0 = datetime(2026, 1, 1, tzinfo=UTC)


class SyntheticSite:
    """A WordPress-like tree: ``dirs`` directories of ``per_dir`` small PHP/JS/CSS/image files."""

    def __init__(self, files: int, per_dir: int = 100):
        self.per_dir = per_dir
        self.dirs = max(1, files // per_dir)
        self.version: dict[str, int] = {}  # path -> content version (changed files)
        self.extra: dict[str, bytes] = {}

    def content(self, path: str) -> bytes:
        if path in self.extra:
            return self.extra[path]
        v = self.version.get(path, 0)
        return (f"<?php // {path} v{v}\n" + "echo esc_html($title);\n" * 8).encode()


class SyntheticSource(FileSource):
    parallel_reads = 4

    def __init__(self, site: SyntheticSite):
        super().__init__("/")
        self.site = site

    def list_dir(self, rel_path: str) -> list[RemoteEntry]:
        s = self.site
        if rel_path in ("", "."):
            groups = [f"g{g:03d}" for g in range((s.dirs + 99) // 100)]
            return [RemoteEntry(g, "dir", None, T0, 0o755) for g in groups] + [
                RemoteEntry("wp-content", "dir", None, T0, 0o755)]
        if rel_path == "wp-content":
            return [RemoteEntry("uploads", "dir", None, T0, 0o755)]
        if rel_path == "wp-content/uploads":
            return [RemoteEntry(p.rsplit("/", 1)[1], "file", len(c), T0, 0o644)
                    for p, c in s.extra.items() if p.startswith("wp-content/uploads/")]
        parts = rel_path.split("/")
        if len(parts) == 1:  # group -> directories
            g = int(parts[0][1:])
            return [RemoteEntry(f"d{d:05d}", "dir", None, T0, 0o755)
                    for d in range(g * 100, min((g + 1) * 100, s.dirs))]
        out = []
        for i in range(s.per_dir):
            name = f"f{i:03d}.{('php', 'js', 'css', 'png')[i % 4]}"
            path = f"{rel_path}/{name}"
            v = s.version.get(path, 0)
            out.append(RemoteEntry(name, "file", len(s.content(path)), T0 + timedelta(seconds=v), 0o644))
        return out

    def read_chunks(self, rel_path: str, chunk_size: int = 65536):
        yield self.site.content(rel_path)


class SyntheticConnector:
    def __init__(self, site: SyntheticSite):
        self.site = site

    def open_file_source(self, root: str) -> SyntheticSource:
        return SyntheticSource(self.site)


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def setup_database() -> tuple[uuid.UUID, uuid.UUID]:
    from alembic import command
    from alembic.config import Config

    url = get_settings().database_url
    with create_engine(url).connect() as c:
        c.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
        c.commit()
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = Config(os.path.join(here, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(here, "alembic"))
    command.upgrade(cfg, "head")
    reset_engine()
    from app.services.seed import seed_reference_data

    with platform_session() as db:
        seed_reference_data(db)
        tenant = Tenant(name="Load Test", slug=f"load-{uuid.uuid4().hex[:6]}")
        db.add(tenant)
        db.flush()
        acct = HostingAccount(tenant_id=tenant.id, name="Synthetic", connector_type="sftp", hostname="load.example",
                              port=22, username="load", root_path="/", status="connected")
        db.add(acct)
        db.flush()
        for cap in ("file_listing", "file_hashing"):
            db.add(ConnectorCapability(tenant_id=tenant.id, hosting_account_id=acct.id, capability=cap,
                                       status="available", detail="", connector_version="load"))
        site = Website(tenant_id=tenant.id, name="Big site", url="https://big.example.com/",
                       hostname="big.example.com", hosting_account_id=acct.id)
        db.add(site)
        db.flush()
        db.add(MonitoringConfig(tenant_id=tenant.id, website_id=site.id, file_scan_enabled=True))
        db.commit()
        return tenant.id, site.id


def run_scan(tenant_id, website_id, label: str) -> dict:
    with platform_session() as db:
        job = ScanJob(tenant_id=tenant_id, website_id=website_id, job_type="file_scan", status="running",
                      trigger="manual")
        db.add(job)
        db.commit()
        t = time.monotonic()
        outcome = file_scan.run_file_scan(db, job)
        elapsed = time.monotonic() - t
        job.status, job.finished_at, job.result_summary = "succeeded", datetime.now(UTC), outcome.summary
        db.commit()
    s = outcome.summary
    row = {"scan": label, "seconds": round(elapsed, 1), "files_seen": s["files_seen"], "hashed": s["files_hashed"],
           "reused": s["files_reused"], "mode": s["content_mode"], "changes": s["changes"],
           "limits_hit": s["limits_hit"], "incidents": len(s["incidents_opened"]), "peak_rss_mb": round(rss_mb())}
    print(row, flush=True)
    return row


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=200_000)
    ap.add_argument("--changes", type=int, default=1_000)
    args = ap.parse_args()
    site = SyntheticSite(args.files)
    file_scan.build_connector = lambda *a, **k: SyntheticConnector(site)  # type: ignore[assignment]
    tenant_id, website_id = setup_database()
    print(f"site: {site.dirs * site.per_dir} files in {site.dirs} directories; limits: "
          f"max_files={get_settings().scan_max_files}, max_seconds={get_settings().scan_max_seconds}", flush=True)

    results = [run_scan(tenant_id, website_id, "1 full (baseline)")]
    results.append(run_scan(tenant_id, website_id, "2 incremental, unchanged"))
    for d in range(0, site.dirs, max(1, site.dirs // args.changes))[: args.changes]:
        site.version[f"g{d // 100:03d}/d{d:05d}/f000.php"] = 1
    site.extra["wp-content/uploads/cache-helper.php"] = b"<?php echo 'x';"
    results.append(run_scan(tenant_id, website_id, f"3 incremental, {args.changes} changed + 1 upload"))

    with platform_session() as db:
        entries = db.execute(select(func.count()).select_from(FileSnapshotEntry)).scalar_one()
        inventory = db.execute(select(func.count()).select_from(FileInventoryItem)).scalar_one()
        incidents = db.execute(select(Incident.title)).scalars().all()
        size = db.execute(text("SELECT pg_size_pretty(pg_database_size(current_database()))")).scalar_one()
    print({"snapshot_entries": entries, "inventory_rows": inventory, "database_size": size}, flush=True)
    print("incidents:", incidents, flush=True)
    digest = hashlib.sha256(repr(results).encode()).hexdigest()[:8]
    print(f"done ({digest})")


if __name__ == "__main__":
    main()
