"""Database login used by the application at runtime.

Migrations run as the database owner (the account the PostgreSQL container creates, which is a superuser).
A superuser skips row-level security entirely, so the API and workers must connect as a separate,
restricted login: no superuser, no BYPASSRLS, no DDL rights, only data access to the application tables.
``ensure_app_role`` creates or repairs that login; the ``migrate`` service runs it on every deployment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Connection

_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


@dataclass
class RoleStatus:
    name: str
    superuser: bool
    bypass_rls: bool

    @property
    def rls_enforced(self) -> bool:
        return not (self.superuser or self.bypass_rls)


def current_role_status(conn: Connection) -> RoleStatus:
    name, sup, bypass = conn.execute(text(
        "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")).one()
    return RoleStatus(name, bool(sup), bool(bypass))


def ensure_app_role(conn: Connection, name: str, password: str) -> str:
    """Create or update the restricted application login and grant it data access. Idempotent."""
    if not _IDENT.match(name):
        raise ValueError("The application database user must be lower-case letters, digits and underscores.")
    if len(password) < 16:
        raise ValueError("The application database password must be at least 16 characters.")
    owner = conn.execute(text("SELECT current_user")).scalar_one()
    if name == owner:
        raise ValueError("The application database user must differ from the owner (POSTGRES_USER).")
    pw = conn.execute(text("SELECT quote_literal(:p)"), {"p": password}).scalar_one()
    exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :n"), {"n": name}).first()
    attrs = "LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT"
    conn.exec_driver_sql(f'{"ALTER" if exists else "CREATE"} ROLE "{name}" WITH {attrs} PASSWORD {pw}')
    db = conn.execute(text("SELECT current_database()")).scalar_one()
    for stmt in (
        f'GRANT CONNECT ON DATABASE "{db}" TO "{name}"',
        f'GRANT USAGE ON SCHEMA public TO "{name}"',
        f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{name}"',
        f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{name}"',
        f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{name}"',
        f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "{name}"',
    ):
        conn.exec_driver_sql(stmt)
    if conn.execute(text("SELECT to_regclass('public.alembic_version')")).scalar_one():
        conn.exec_driver_sql(f'REVOKE INSERT, UPDATE, DELETE ON alembic_version FROM "{name}"')
    return "updated" if exists else "created"
