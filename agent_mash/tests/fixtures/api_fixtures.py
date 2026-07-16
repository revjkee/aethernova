# agent_mash/tests/fixtures/api_fixtures.py
from __future__ import annotations

import importlib
import os
import pathlib
import typing as t
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

try:
    # pytest-asyncio must be installed in test deps
    import pytest_asyncio  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "pytest-asyncio is required for async fixtures. "
        "Install it in your test dependencies."
    ) from e


# ----------------------------
# Configuration
# ----------------------------

DEFAULT_TEST_BASE_URL = os.getenv("TEST_BASE_URL", "http://testserver")

# If you want to explicitly point to your Base, set:
# TEST_BASE_IMPORT="agent_mash.db.base:Base"
TEST_BASE_IMPORT = os.getenv("TEST_BASE_IMPORT", "").strip()

# If you want to explicitly point to your FastAPI app, set:
# TEST_APP_IMPORT="agent_mash.app.main:app"
TEST_APP_IMPORT = os.getenv("TEST_APP_IMPORT", "").strip()

# The dependency name to override for DB session.
# If your app uses a different callable, set:
# TEST_DB_DEP_IMPORT="agent_mash.core.db:get_db"
TEST_DB_DEP_IMPORT = os.getenv("TEST_DB_DEP_IMPORT", "").strip()

# Database URL for tests. If not set, uses temp SQLite async DB.
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL", "").strip()


# ----------------------------
# Helpers
# ----------------------------

def _import_attr(spec: str) -> t.Any:
    """
    Import attribute by "module.path:attr" spec.
    Raises RuntimeError with a clear message if spec is invalid or import fails.
    """
    if ":" not in spec:
        raise RuntimeError(f'Invalid import spec "{spec}". Expected "module.path:attr".')
    mod_name, attr_name = spec.split(":", 1)
    try:
        mod = importlib.import_module(mod_name)
    except Exception as e:
        raise RuntimeError(f'Cannot import module "{mod_name}" from "{spec}".') from e
    try:
        return getattr(mod, attr_name)
    except Exception as e:
        raise RuntimeError(f'Cannot find attribute "{attr_name}" in "{mod_name}".') from e


def _resolve_sqlalchemy_base() -> t.Any:
    """
    Resolve SQLAlchemy Base object that has .metadata.
    Priority:
      1) TEST_BASE_IMPORT env
      2) common project paths (best-effort, without claiming correctness)
    If not found -> RuntimeError (explicit, no guessing).
    """
    if TEST_BASE_IMPORT:
        base = _import_attr(TEST_BASE_IMPORT)
        if not hasattr(base, "metadata"):
            raise RuntimeError(f'Imported Base "{TEST_BASE_IMPORT}" has no attribute "metadata".')
        return base

    candidates = (
        "agent_mash.db.base:Base",
        "agent_mash.core.db.base:Base",
        "agent_mash.infrastructure.db.base:Base",
        "agent_mash.persistence.base:Base",
        "agent_mash.models.base:Base",
    )
    for spec in candidates:
        try:
            base = _import_attr(spec)
            if hasattr(base, "metadata"):
                return base
        except Exception:
            continue

    raise RuntimeError(
        "Cannot resolve SQLAlchemy Base for tests. "
        "Set environment variable TEST_BASE_IMPORT, например: "
        'TEST_BASE_IMPORT="agent_mash.db.base:Base".'
    )


def _resolve_fastapi_app() -> t.Any:
    """
    Resolve FastAPI app instance.
    Priority:
      1) TEST_APP_IMPORT env
      2) common project paths
    If not found -> RuntimeError (explicit).
    """
    if TEST_APP_IMPORT:
        app = _import_attr(TEST_APP_IMPORT)
        return app

    candidates = (
        "agent_mash.app.main:app",
        "agent_mash.main:app",
        "agent_mash.api.main:app",
        "agent_mash.web.main:app",
        "agent_mash.backend.main:app",
    )
    for spec in candidates:
        try:
            app = _import_attr(spec)
            return app
        except Exception:
            continue

    raise RuntimeError(
        "Cannot resolve FastAPI app for tests. "
        "Set environment variable TEST_APP_IMPORT, например: "
        'TEST_APP_IMPORT="agent_mash.app.main:app".'
    )


def _resolve_db_dependency() -> t.Callable[..., t.Any]:
    """
    Resolve dependency callable used by app to provide DB session.
    Priority:
      1) TEST_DB_DEP_IMPORT env
      2) common project paths
    If not found -> RuntimeError (explicit).
    """
    if TEST_DB_DEP_IMPORT:
        dep = _import_attr(TEST_DB_DEP_IMPORT)
        if not callable(dep):
            raise RuntimeError(f'DB dependency "{TEST_DB_DEP_IMPORT}" is not callable.')
        return dep

    candidates = (
        "agent_mash.core.db:get_db",
        "agent_mash.core.db.session:get_db",
        "agent_mash.db:get_db",
        "agent_mash.db.session:get_db",
        "agent_mash.infrastructure.db:get_db",
    )
    for spec in candidates:
        try:
            dep = _import_attr(spec)
            if callable(dep):
                return dep
        except Exception:
            continue

    raise RuntimeError(
        "Cannot resolve DB dependency for override. "
        "Set environment variable TEST_DB_DEP_IMPORT, например: "
        'TEST_DB_DEP_IMPORT="agent_mash.core.db:get_db".'
    )


def _make_sqlite_test_url(tmp_dir: pathlib.Path) -> str:
    """
    Create a deterministic SQLite async URL in temp directory.
    Uses file-based DB to avoid in-memory connection/lifespan pitfalls.
    """
    db_name = f"test_{uuid.uuid4().hex}.sqlite3"
    db_path = tmp_dir / db_name
    return f"sqlite+aiosqlite:///{db_path.as_posix()}"


# ----------------------------
# Pytest fixtures
# ----------------------------

@pytest.fixture(scope="session")
def anyio_backend() -> str:
    # Ensures compatibility when anyio is used internally by httpx/fastapi stack.
    return "asyncio"


@pytest_asyncio.fixture(scope="session")
async def _test_tmp_dir(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    return tmp_path_factory.mktemp("agent_mash_tests")


@pytest.fixture(scope="session")
def test_database_url(_test_tmp_dir: pathlib.Path) -> str:
    """
    Returns DB URL for tests.
    If TEST_DATABASE_URL is set, uses it.
    Otherwise uses temporary SQLite file DB.
    """
    if TEST_DATABASE_URL:
        return TEST_DATABASE_URL
    return _make_sqlite_test_url(_test_tmp_dir)


@pytest_asyncio.fixture(scope="session")
async def engine(test_database_url: str) -> AsyncEngine:
    """
    Create async SQLAlchemy engine for tests.
    NullPool is used to avoid cross-test connection reuse surprises.
    """
    eng = create_async_engine(
        test_database_url,
        poolclass=NullPool,
        future=True,
        echo=False,
    )
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(scope="session")
async def sqlalchemy_base() -> t.Any:
    """
    Provides SQLAlchemy Base with .metadata for schema management.
    """
    return _resolve_sqlalchemy_base()


@pytest_asyncio.fixture(scope="session")
async def create_test_schema(engine: AsyncEngine, sqlalchemy_base: t.Any) -> None:
    """
    Create all tables once per test session, drop at the end.
    """
    metadata = getattr(sqlalchemy_base, "metadata", None)
    if metadata is None:
        raise RuntimeError("Resolved Base has no .metadata; cannot create schema.")

    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)

    yield

    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)


@pytest_asyncio.fixture(scope="session")
async def session_factory(engine: AsyncEngine, create_test_schema: None) -> async_sessionmaker[AsyncSession]:
    """
    Async session factory for tests.
    """
    return async_sessionmaker(
        bind=engine,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
        class_=AsyncSession,
    )


@pytest_asyncio.fixture()
async def db_session(engine: AsyncEngine, session_factory: async_sessionmaker[AsyncSession]) -> AsyncSession:
    """
    Per-test DB session with transaction rollback isolation.

    Strategy:
      - Open one connection
      - Begin outer transaction
      - Use AsyncSession bound to this connection
      - Rollback outer transaction after test
    """
    async with engine.connect() as conn:
        trans = await conn.begin()
        session = AsyncSession(bind=conn, expire_on_commit=False, autoflush=False)

        try:
            yield session
        finally:
            try:
                await session.close()
            finally:
                await trans.rollback()


@pytest_asyncio.fixture(scope="session")
async def app() -> t.Any:
    """
    FastAPI app instance.
    """
    return _resolve_fastapi_app()


@pytest_asyncio.fixture()
async def overridden_app(app: t.Any, db_session: AsyncSession) -> t.Any:
    """
    App with DB dependency overridden to use test session.
    """
    dep = _resolve_db_dependency()

    async def _override_get_db() -> t.AsyncIterator[AsyncSession]:
        yield db_session

    # FastAPI stores overrides on app.dependency_overrides (dict)
    overrides = getattr(app, "dependency_overrides", None)
    if overrides is None or not isinstance(overrides, dict):
        raise RuntimeError("Resolved app does not look like a FastAPI app (dependency_overrides missing).")

    original = overrides.get(dep)
    overrides[dep] = _override_get_db

    try:
        yield app
    finally:
        # restore previous state to avoid cross-test contamination
        if original is None:
            overrides.pop(dep, None)
        else:
            overrides[dep] = original


@pytest_asyncio.fixture()
async def api_client(overridden_app: t.Any) -> AsyncClient:
    """
    HTTPX AsyncClient bound to FastAPI ASGI app (no real network).
    """
    transport = ASGITransport(app=overridden_app)
    async with AsyncClient(
        transport=transport,
        base_url=DEFAULT_TEST_BASE_URL,
        timeout=30.0,
        headers={
            "Accept": "application/json",
        },
    ) as client:
        yield client


@pytest.fixture()
def make_auth_headers() -> t.Callable[[str], dict[str, str]]:
    """
    Helper to build Authorization header for bearer tokens.
    """
    def _make(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}
    return _make


@pytest.fixture()
def trace_id() -> str:
    """
    Per-test trace id for correlation in logs if your app supports it.
    """
    return uuid.uuid4().hex


@pytest_asyncio.fixture()
async def api_client_with_trace(api_client: AsyncClient, trace_id: str) -> AsyncClient:
    """
    Same client but with X-Trace-Id header set for the test.
    """
    api_client.headers["X-Trace-Id"] = trace_id
    return api_client
