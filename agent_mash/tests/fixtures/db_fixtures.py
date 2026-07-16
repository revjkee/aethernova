# agent_mash/tests/fixtures/db_fixtures.py
"""
Industrial async DB fixtures for pytest.

What this file provides:
- session-scoped AsyncEngine
- session-scoped schema create/drop via Base.metadata
- function-scoped AsyncConnection wrapped in transaction + nested savepoints
- function-scoped AsyncSession bound to that connection
- optional FastAPI dependency override hook

No project-specific assumptions are hardcoded:
- DB url is taken from env: DATABASE_URL_TEST or TEST_DATABASE_URL
- SQLAlchemy Base is imported from env: TEST_MODEL_BASE (e.g. "agent_mash.db.base:Base")
"""

from __future__ import annotations

import os
import re
import importlib
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Optional, Tuple

import pytest
from sqlalchemy import event
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool


@dataclass(frozen=True)
class TestDbConfig:
    database_url: str
    model_base_import: str


def _env_first(*keys: str) -> Optional[str]:
    for k in keys:
        v = os.getenv(k)
        if v and v.strip():
            return v.strip()
    return None


def _default_sqlite_url() -> str:
    # File-based SQLite is more predictable across asyncio event loops than in-memory.
    # Path is local to repo; adjust via DATABASE_URL_TEST if needed.
    return "sqlite+aiosqlite:///./.pytest_test.db"


def load_test_db_config() -> TestDbConfig:
    database_url = _env_first("DATABASE_URL_TEST", "TEST_DATABASE_URL") or _default_sqlite_url()
    model_base_import = _env_first("TEST_MODEL_BASE") or "agent_mash.db.base:Base"
    return TestDbConfig(database_url=database_url, model_base_import=model_base_import)


_IMPORT_RE = re.compile(r"^(?P<module>[A-Za-z0-9_.]+)(:(?P<attr>[A-Za-z0-9_]+))?$")


def import_from_string(path: str) -> Any:
    """
    Import helper for strings like:
      - "pkg.mod:Attr"
      - "pkg.mod"  (returns module)
    """
    m = _IMPORT_RE.match(path.strip())
    if not m:
        raise ImportError(f"Invalid import path format: {path!r}. Expected 'module:attr' or 'module'.")
    module_name = m.group("module")
    attr = m.group("attr")
    mod = importlib.import_module(module_name)
    if not attr:
        return mod
    try:
        return getattr(mod, attr)
    except AttributeError as e:
        raise ImportError(f"Attribute {attr!r} not found in module {module_name!r}.") from e


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite+aiosqlite://") or url.startswith("sqlite://")


def _engine_kwargs_for_url(url: str) -> dict:
    # NullPool is generally safest for tests to avoid cross-test leakage and pool state issues.
    # For SQLite file it is fine; for other DBs it is also safe though slightly slower.
    kwargs: dict = {
        "poolclass": NullPool,
        "future": True,
    }

    # SQLite needs check_same_thread=False in some async scenarios.
    if _is_sqlite(url):
        kwargs["connect_args"] = {"check_same_thread": False}

    return kwargs


@pytest.fixture(scope="session")
def test_db_config() -> TestDbConfig:
    return load_test_db_config()


@pytest.fixture(scope="session")
def sqlalchemy_metadata(test_db_config: TestDbConfig):
    """
    Loads Base.metadata from TEST_MODEL_BASE, default: "agent_mash.db.base:Base".

    The imported object must expose .metadata (declarative base).
    """
    base_obj = import_from_string(test_db_config.model_base_import)
    metadata = getattr(base_obj, "metadata", None)
    if metadata is None:
        raise RuntimeError(
            "Imported TEST_MODEL_BASE does not expose .metadata. "
            "Set env TEST_MODEL_BASE to a declarative Base, e.g. 'agent_mash.db.base:Base'."
        )
    return metadata


@pytest.fixture(scope="session")
async def async_engine(test_db_config: TestDbConfig) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(test_db_config.database_url, **_engine_kwargs_for_url(test_db_config.database_url))
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture(scope="session")
async def db_schema(async_engine: AsyncEngine, sqlalchemy_metadata) -> AsyncIterator[None]:
    """
    Create all tables once per test session, drop them after session ends.
    """
    async with async_engine.begin() as conn:
        await conn.run_sync(sqlalchemy_metadata.create_all)
    try:
        yield None
    finally:
        async with async_engine.begin() as conn:
            await conn.run_sync(sqlalchemy_metadata.drop_all)


@pytest.fixture()
async def db_connection(async_engine: AsyncEngine, db_schema: None) -> AsyncIterator[AsyncConnection]:
    """
    Function-scoped connection wrapped in a transaction and nested savepoints.

    This pattern keeps tests isolated even if code under test calls commit().
    """
    conn = await async_engine.connect()
    trans = await conn.begin()

    # Start a nested transaction (SAVEPOINT).
    nested = await conn.begin_nested()

    @event.listens_for(conn.sync_connection, "after_transaction_end")
    def _restart_savepoint(sync_conn, transaction):
        # Restart SAVEPOINT when the inner transaction ends.
        # This is the classic SQLAlchemy testing pattern adapted for async.
        nonlocal nested
        if transaction.nested and not transaction._parent.nested:
            nested = conn.begin_nested()  # type: ignore[assignment]

    try:
        yield conn
    finally:
        try:
            # Rollback outer transaction to clean state.
            if trans.is_active:
                await trans.rollback()
        finally:
            await conn.close()


@pytest.fixture()
async def db_session(db_connection: AsyncConnection) -> AsyncIterator[AsyncSession]:
    """
    Function-scoped AsyncSession bound to the test connection.
    """
    session_factory = async_sessionmaker(
        bind=db_connection,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    session = session_factory()
    try:
        yield session
    finally:
        await session.close()


@pytest.fixture()
def override_fastapi_get_db(db_session: AsyncSession):
    """
    Optional helper for FastAPI dependency override.

    Usage in tests (example, not executed here):
      app.dependency_overrides[get_db_session] = override_fastapi_get_db

    This fixture returns an async generator function yielding the same db_session.
    """
    async def _override() -> AsyncIterator[AsyncSession]:
        yield db_session

    return _override
