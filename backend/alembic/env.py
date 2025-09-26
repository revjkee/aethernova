# backend/alembic/env.py
from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from types import ModuleType
from typing import Optional, Callable

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, async_engine_from_config
from sqlalchemy.orm import DeclarativeMeta

# --- Logging -----------------------------------------------------------------
config = context.config  # Alembic Config object, provides access to .ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# --- Helpers to resolve Base.metadata ----------------------------------------
def _try_import(paths: list[str]) -> Optional[ModuleType]:
    """
    Try importing first existing module from the given dotted paths.
    Returns the imported module or None.
    """
    for p in paths:
        try:
            __import__(p)
            return sys.modules[p]
        except Exception:
            continue
    return None


def _resolve_target_metadata() -> Optional["DeclarativeMeta"].metadata:  # type: ignore[valid-type]
    """
    Attempts to locate SQLAlchemy Base with metadata.
    Adjust the search order if your project uses a different layout.
    """
    # Common locations in FastAPI/async projects
    candidate_modules = [
        "app.db.base",          # e.g., app/db/base.py
        "backend.db.base",      # e.g., backend/db/base.py
        "src.db.base",          # e.g., src/db/base.py
        "app.models.base",      # e.g., app/models/base.py
        "db.base",              # e.g., db/base.py at repo root
    ]
    m = _try_import(candidate_modules)
    if m:
        # Expect module to expose Base or metadata
        base = getattr(m, "Base", None)
        if base is not None and hasattr(base, "metadata"):
            return base.metadata
        md = getattr(m, "metadata", None)
        if md is not None:
            return md

    # Fallback: try importing app.models to populate mappers then fetch from a known Base
    for pkg in ("app.models", "backend.models", "src.models", "models"):
        try:
            __import__(pkg)
        except Exception:
            pass

    # Final fallback: environment variable with dotted path to metadata
    # e.g., ALEMBIC_TARGET_METADATA=app.db.base:Base.metadata
    spec = os.getenv("ALEMBIC_TARGET_METADATA")
    if spec:
        mod_name, attr_path = spec.split(":", 1)
        __import__(mod_name)
        mod = sys.modules[mod_name]
        obj = mod
        for part in attr_path.split("."):
            obj = getattr(obj, part)
        return obj  # type: ignore[return-value]

    return None


target_metadata = _resolve_target_metadata()

# --- Database URL & schema handling ------------------------------------------
# Order of precedence:
# 1) DATABASE_URL env var
# 2) SQLALCHEMY_DATABASE_URI env var (alternative)
# 3) sqlalchemy.url from alembic.ini
env_url = os.getenv("DATABASE_URL") or os.getenv("SQLALCHEMY_DATABASE_URI")
if env_url:
    config.set_main_option("sqlalchemy.url", env_url)

# Read back the effective URL from config
DB_URL: str = config.get_main_option("sqlalchemy.url")

# Optional PostgreSQL schema configuration
DB_SCHEMA: Optional[str] = os.getenv("DB_SCHEMA") or None
# Optional custom Alembic version table and schema (defaults work fine)
VERSION_TABLE: str = os.getenv("ALEMBIC_VERSION_TABLE", "alembic_version")
VERSION_TABLE_SCHEMA: Optional[str] = os.getenv("ALEMBIC_VERSION_TABLE_SCHEMA") or DB_SCHEMA

# SQLite detection to enable render_as_batch for safe ALTER TABLE
IS_SQLITE = DB_URL.startswith("sqlite:")

# --- Include / Exclude object hook -------------------------------------------
def include_object(object_, name: str, type_: str, reflected: bool, compare_to):
    """
    Control which DB objects are included in autogenerate.

    - Exclude SQLite system tables.
    - Exclude objects with __alembic_exclude__ = True on SQLAlchemy Table/Index, etc.
    """
    # Skip SQLite internals
    if IS_SQLITE and type_ == "table" and name.startswith("sqlite_"):
        return False

    # Respect explicit per-object exclusion (e.g., Table.info["alembic_exclude"] = True)
    info = getattr(object_, "info", None)
    if isinstance(info, dict) and info.get("alembic_exclude") is True:
        return False

    return True

# --- Migration runners --------------------------------------------------------
def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode: no DB connection, SQL emitted as script.
    """
    context.configure(
        url=DB_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
        version_table=VERSION_TABLE,
        version_table_schema=VERSION_TABLE_SCHEMA,
        compare_type=True,
        compare_server_default=True,
        render_as_batch=IS_SQLITE,  # safer alters for SQLite
        include_object=include_object,
    )

    with context.begin_transaction():
        if DB_SCHEMA:
            # Ensure default schema is present for autogenerate diffs
            context.execute(f"SET SEARCH_PATH TO {DB_SCHEMA}")
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    """
    Synchronous body to be run within async connection.run_sync(...).
    """
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=True,
        version_table=VERSION_TABLE,
        version_table_schema=VERSION_TABLE_SCHEMA,
        compare_type=True,
        compare_server_default=True,
        render_as_batch=IS_SQLITE,
        include_object=include_object,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode with AsyncEngine.
    """
    # Build AsyncEngine from alembic config
    connectable: AsyncEngine = async_engine_from_config(
        config.get_section(config.config_ini_section) or {},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    async with connectable.connect() as async_conn:
        # Optionally set PostgreSQL search_path for schema-aware projects
        if DB_SCHEMA and async_conn.dialect.name == "postgresql":
            await async_conn.execute(text(f"SET search_path TO {DB_SCHEMA}"))

        await async_conn.run_sync(_do_run_migrations)

    await connectable.dispose()


# --- Entrypoint ---------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
