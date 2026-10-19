"""Database engine, sessions and tenant context for Row-Level Security.

Application-level authorisation is the primary control. PostgreSQL RLS is a
second layer: every tenant-owned table has a policy that only exposes rows
whose ``tenant_id`` matches the ``app.tenant_id`` setting of the current
transaction, unless ``app.scope`` is ``platform`` (set only by worker and
platform-administration code paths).

The settings are transaction-local (``set_config(..., true)``) and re-applied
at the start of every transaction from ``Session.info``, so they can never
leak between pooled connections.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None

SCOPE_TENANT = "tenant"
SCOPE_PLATFORM = "platform"
SCOPE_NONE = "none"


def get_engine() -> Engine:
    global _engine, _SessionLocal
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=10,
            future=True,
        )
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, class_=Session)
    return _engine


def reset_engine() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


def session_factory() -> sessionmaker[Session]:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal


@event.listens_for(Session, "after_begin")
def _apply_tenant_context(session: Session, transaction: Any, connection: Any) -> None:
    scope = session.info.get("scope", SCOPE_NONE)
    tenant_id = session.info.get("tenant_id")
    connection.execute(
        text("SELECT set_config('app.scope', :scope, true), set_config('app.tenant_id', :tid, true)"),
        {"scope": scope, "tid": str(tenant_id) if tenant_id else ""},
    )


def set_tenant_scope(session: Session, tenant_id: uuid.UUID) -> None:
    """Restrict RLS-protected tables to one tenant for the rest of this session."""
    session.info["scope"] = SCOPE_TENANT
    session.info["tenant_id"] = tenant_id
    if session.in_transaction():
        session.execute(
            text("SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', :tid, true)"),
            {"tid": str(tenant_id)},
        )


def set_platform_scope(session: Session) -> None:
    """Allow cross-tenant reads. Only for workers and authorised platform paths."""
    session.info["scope"] = SCOPE_PLATFORM
    session.info["tenant_id"] = None
    if session.in_transaction():
        session.execute(
            text("SELECT set_config('app.scope', 'platform', true), set_config('app.tenant_id', '', true)")
        )


@contextmanager
def platform_session() -> Iterator[Session]:
    session = session_factory()()
    set_platform_scope(session)
    try:
        yield session
    finally:
        session.close()


@contextmanager
def tenant_session(tenant_id: uuid.UUID) -> Iterator[Session]:
    session = session_factory()()
    set_tenant_scope(session, tenant_id)
    try:
        yield session
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency. Starts with no tenant scope (RLS hides tenant rows)."""
    session = session_factory()()
    session.info["scope"] = SCOPE_NONE
    try:
        yield session
    finally:
        session.close()
