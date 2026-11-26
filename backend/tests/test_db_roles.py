"""The runtime database login enforces row-level security (production connected as the superuser owner,
which silently bypasses RLS). Needs a superuser connection: CW_TEST_ADMIN_DATABASE_URL (set in CI)."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError

from app.core.config import get_settings
from app.db.roles import current_role_status, ensure_app_role
from tests.test_security import _make_site

ADMIN_URL = os.environ.get("CW_TEST_ADMIN_DATABASE_URL")
pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="CW_TEST_ADMIN_DATABASE_URL (superuser) not set")
ROLE, PASSWORD = "cw_test_app", "test-app-password-0123456789"


@pytest.fixture
def app_engine():
    admin = create_engine(ADMIN_URL)
    with admin.begin() as conn:
        assert current_role_status(conn).superuser, "the admin URL must be a superuser, like the production owner"
        assert not current_role_status(conn).rls_enforced
        assert ensure_app_role(conn, ROLE, PASSWORD) in ("created", "updated")
        assert ensure_app_role(conn, ROLE, PASSWORD) == "updated", "idempotent"
    url = make_url(get_settings().database_url).set(username=ROLE, password=PASSWORD)
    engine = create_engine(url)
    yield engine
    engine.dispose()
    with admin.begin() as conn:
        conn.exec_driver_sql(f'DROP OWNED BY "{ROLE}"')
        conn.exec_driver_sql(f'DROP ROLE IF EXISTS "{ROLE}"')
    admin.dispose()


def _websites(conn, scope: str | None, tenant=None) -> set:
    if scope:
        conn.execute(text("SELECT set_config('app.scope', :s, true), set_config('app.tenant_id', :t, true)"),
                     {"s": scope, "t": str(tenant) if tenant else ""})
    return {r[0] for r in conn.execute(text("SELECT tenant_id FROM websites"))}


def test_app_login_enforces_row_level_security(alice, bob, app_engine):
    a, atid = alice
    b, btid = bob
    _make_site(a, atid)
    _make_site(b, btid, url="https://www.beta-site.com/")
    with app_engine.begin() as conn:
        st = current_role_status(conn)
        assert st.name == ROLE and st.rls_enforced
        assert _websites(conn, None) == set(), "no scope set: nothing visible"
    with app_engine.begin() as conn:
        assert _websites(conn, "tenant", btid) == {btid}, "deliberately unscoped query sees one tenant only"
    with app_engine.begin() as conn:
        assert _websites(conn, "platform") == {atid, btid}


def test_app_login_cannot_change_schema_or_migration_state(app_engine):
    for stmt in ("CREATE TABLE cw_probe (id int)", "UPDATE alembic_version SET version_num = version_num",
                 "ALTER TABLE websites DISABLE ROW LEVEL SECURITY"):
        with pytest.raises(ProgrammingError), app_engine.begin() as conn:
            conn.exec_driver_sql(stmt)


def test_health_check_flags_a_login_that_bypasses_rls(app_engine):
    from app import cli

    class _DB:
        def __init__(self, conn):
            self._conn = conn

        def connection(self):
            return self._conn

    with create_engine(ADMIN_URL).begin() as conn:
        ok, _, detail = cli._db_role_health(_DB(conn))
        assert not ok and "NOT enforced" in detail
    with app_engine.begin() as conn:
        ok, _, detail = cli._db_role_health(_DB(conn))
        assert ok and "enforced" in detail


def test_rejects_unsafe_role_settings():
    with create_engine(ADMIN_URL).begin() as conn:
        for name, pw in (("Bad-Name", PASSWORD), ("cw_x", "short"), ("cw_x; drop", PASSWORD)):
            with pytest.raises(ValueError):
                ensure_app_role(conn, name, pw)
        owner = conn.execute(text("SELECT current_user")).scalar_one()
        with pytest.raises(ValueError):
            ensure_app_role(conn, owner, PASSWORD)
