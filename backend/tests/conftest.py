from __future__ import annotations

import base64
import os
import uuid
from collections.abc import Iterator

import pytest

# Configure the environment before importing the application.
os.environ.setdefault("CW_ENVIRONMENT", "test")
os.environ.setdefault(
    "CW_DATABASE_URL",
    "postgresql+psycopg://cyberwatch:devpassword@localhost:5432/cyberwatch_test",
)
os.environ.setdefault("CW_REDIS_URL", "redis://localhost:6379/15")
os.environ["CW_CREDENTIAL_KEYS"] = "test1:" + base64.b64encode(b"T" * 32).decode()
os.environ["CW_COOKIE_SECURE"] = "false"
os.environ["CW_OUTBOUND_ALLOW_CIDRS"] = '["127.0.0.0/8"]'
os.environ["CW_STORAGE_DIR"] = "/tmp/cw-test-storage"  # noqa: S108
os.environ["CW_TRIAL_DAYS"] = "14"

from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from alembic import command  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.ratelimit import get_limiter  # noqa: E402
from app.db.session import platform_session, reset_engine  # noqa: E402
from app.monitoring import jobs  # noqa: E402

REFERENCE_TABLES = {"roles", "permissions", "role_permissions", "connector_definitions", "plans", "alembic_version"}
DISPATCHED: list = []


@pytest.fixture(scope="session", autouse=True)
def _database() -> Iterator[None]:
    url = get_settings().database_url
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(os.path.dirname(__file__), "..", "alembic"))
    command.upgrade(cfg, "head")
    reset_engine()
    from app.services.seed import seed_reference_data

    with platform_session() as db:
        seed_reference_data(db)
        db.commit()
    yield
    reset_engine()


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    DISPATCHED.clear()
    jobs.set_dispatcher(lambda job, countdown=0: DISPATCHED.append((job.id, countdown)))
    get_limiter().reset()
    yield
    jobs.set_dispatcher(None)
    with platform_session() as db:
        tables = [r[0] for r in db.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname='public'")).all() if r[0] not in REFERENCE_TABLES]
        db.execute(text("TRUNCATE " + ", ".join(tables) + " CASCADE"))
        db.commit()


@pytest.fixture
def client() -> TestClient:
    from app.main import app

    return TestClient(app)


class Session:
    """A logged-in browser-like API client."""

    def __init__(self, client: TestClient):
        self.c = client

    def _headers(self) -> dict:
        csrf = self.c.cookies.get("cw_csrf")
        return {"X-CSRF-Token": csrf} if csrf else {}

    def get(self, url: str, **kw):
        return self.c.get(url, **kw)

    def post(self, url: str, json=None, **kw):
        return self.c.post(url, json=json, headers={**self._headers(), **kw.pop("headers", {})}, **kw)

    def put(self, url: str, json=None, **kw):
        return self.c.put(url, json=json, headers=self._headers(), **kw)

    def patch(self, url: str, json=None, **kw):
        return self.c.patch(url, json=json, headers=self._headers(), **kw)

    def delete(self, url: str, **kw):
        return self.c.delete(url, headers=self._headers(), **kw)


PASSWORD = "Sufficiently-Long-Passw0rd!"


def register_and_login(email: str, org: str) -> tuple[Session, uuid.UUID]:
    from app.main import app

    c = TestClient(app)
    r = c.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD, "full_name": email.split("@")[0],
                                              "organisation_name": org})
    assert r.status_code == 201, r.text
    r = c.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text
    tenant_id = uuid.UUID(r.json()["user"]["memberships"][0]["tenant_id"])
    return Session(c), tenant_id


@pytest.fixture
def alice() -> tuple[Session, uuid.UUID]:
    return register_and_login("alice@alpha.example.com", "Alpha Ltd")


@pytest.fixture
def bob() -> tuple[Session, uuid.UUID]:
    return register_and_login("bob@beta.example.com", "Beta Ltd")


@pytest.fixture
def sftp_root(tmp_path):
    root = tmp_path / "remote"
    (root / "public_html" / "wp-content" / "uploads").mkdir(parents=True)
    (root / "public_html" / "index.php").write_text("<?php echo 'hello';")
    (root / "public_html" / ".htaccess").write_text("RewriteEngine On\n")
    (root / "public_html" / "about.html").write_text("<h1>About</h1>")
    (root / "public_html" / "wp-content" / "uploads" / "logo.png").write_bytes(b"\x89PNG" + b"0" * 100)
    (root / "public_html" / "private").mkdir()
    (root / "public_html" / "private" / "secret.txt").write_text("restricted")
    return root


@pytest.fixture
def sftp_server(sftp_root):
    from tests.sftp_server import TestSFTPServer

    server = TestSFTPServer(str(sftp_root))
    settings = get_settings()
    settings.allowed_sftp_ports.append(server.port)
    yield server
    settings.allowed_sftp_ports.remove(server.port)
    server.close()


def run_dispatched() -> list[str | None]:
    """Execute queued jobs the way a worker would (synchronously)."""
    results = []
    while DISPATCHED:
        job_id, _ = DISPATCHED.pop(0)
        results.append(jobs.run_job(job_id, worker="test-worker"))
    return results
