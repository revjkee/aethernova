# automation-core/src/automation_core/databases/migrations/env.py
"""
Alembic migration environment for Automation Core.

Highlights
----------
- Online / Offline режимы по документации Alembic.
- Поддержка синхронных и асинхронных движков (SQLAlchemy 2.x).
- target_metadata загружается из переменной окружения ALEMBIC_TARGET_METADATA
  (формат "module.path:attribute"), по умолчанию пытается
  "automation_core.databases.models:Base".
- Безопасная автогенерация: compare_type/compare_server_default, include_schemas
  (через ALEMBIC_INCLUDE_SCHEMAS=1), фильтр include_object с исключениями
  из ALEMBIC_EXCLUDE_TABLES/SCHEMAS/OBJECTS_RE.
- Автоматическое включение render_as_batch для SQLite (batch migrations).
- Пропуск пустых ревизий (Don't Generate Empty Migrations).
- Настройка версии и схемы таблицы ревизий через ALEMBIC_VERSION_TABLE(_SCHEMA)
  без изменения alembic.ini.

References: см. комментарии ниже и блок источников в конце файла.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import os
import re
from logging.config import fileConfig
from typing import Any, Callable, Iterable, Optional, Tuple

from alembic import context
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.engine.url import make_url

# ----------------------------- Logging ----------------------------------------

config = context.config  # Alembic Config proxy
if config.config_file_name is not None:
    # Настройка логирования из alembic.ini (стандартный паттерн Alembic)
    fileConfig(config.config_file_name)  # noqa: E402

logger = logging.getLogger("alembic.env")


# ----------------------------- Target metadata --------------------------------

def _import_attr(spec: str):
    """
    Import "module.sub:attr" and return attribute.
    """
    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise RuntimeError(f"Invalid ALEMBIC_TARGET_METADATA spec: {spec}")
    mod = importlib.import_module(module_name)
    return getattr(mod, attr)


def _load_target_metadata():
    """
    Try ALEMBIC_TARGET_METADATA first, else default to
    'automation_core.databases.models:Base' (if present),
    else return None (autogenerate still works for reflected objects).
    """
    spec = os.getenv("ALEMBIC_TARGET_METADATA", "automation_core.databases.models:Base")
    try:
        obj = _import_attr(spec)
        # Accept either a MetaData or a declarative Base with .metadata
        metadata = getattr(obj, "metadata", None) or obj
        return metadata
    except Exception as exc:
        logger.warning("target_metadata not loaded from %r: %s", spec, exc)
        return None


target_metadata = _load_target_metadata()


# ----------------------------- URL & config -----------------------------------

def _get_db_url() -> str:
    """
    Resolve database URL priority:
    1) $DATABASE_URL or $DB_URL
    2) alembic.ini sqlalchemy.url (if set)
    """
    env_url = os.getenv("DATABASE_URL") or os.getenv("DB_URL")
    if env_url:
        return env_url
    ini_url = config.get_main_option("sqlalchemy.url")
    if not ini_url:
        raise RuntimeError("Database URL not provided (set DATABASE_URL or sqlalchemy.url).")
    return ini_url


def _apply_runtime_toggles(url: str) -> dict:
    """
    Compute Alembic context.configure kwargs common for both modes.
    """
    url_obj = make_url(url)
    is_sqlite = url_obj.get_backend_name().startswith("sqlite")
    include_schemas = os.getenv("ALEMBIC_INCLUDE_SCHEMAS", "0") in ("1", "true", "True")

    # optional version table config from env
    version_table = os.getenv("ALEMBIC_VERSION_TABLE") or "alembic_version"
    version_table_schema = os.getenv("ALEMBIC_VERSION_TABLE_SCHEMA")

    opts = dict(
        target_metadata=target_metadata,
        compare_type=True,               # detect column type changes
        compare_server_default=True,     # detect server defaults changes
        include_schemas=include_schemas, # compare across schemas if requested
        render_as_batch=is_sqlite,       # batch mode for SQLite
        # naming_convention is expected to be set on metadata for best results
        version_table=version_table,
    )
    if version_table_schema:
        opts["version_table_schema"] = version_table_schema
    return opts


# ----------------------------- Filters / Hooks --------------------------------

_EXCLUDE_TABLES: set[str] = set(
    filter(None, (os.getenv("ALEMBIC_EXCLUDE_TABLES") or "").split(","))
)
_EXCLUDE_SCHEMAS: set[str] = set(
    filter(None, (os.getenv("ALEMBIC_EXCLUDE_SCHEMAS") or "").split(","))
)
_EXCLUDE_OBJECTS_RE: Optional[re.Pattern[str]] = None
if os.getenv("ALEMBIC_EXCLUDE_OBJECTS_RE"):
    _EXCLUDE_OBJECTS_RE = re.compile(os.getenv("ALEMBIC_EXCLUDE_OBJECTS_RE"), re.IGNORECASE)


def _include_object(obj, name: str, type_: str, reflected: bool, compare_to) -> bool:
    """
    include_object callback для автогенерации.
    Позволяет исключить объекты по имени/типу/схеме, а также через regexp.
    Документация: EnvironmentContext.configure.include_object.  # See refs
    """
    # пропуск таблицы версий Alembic всегда
    if type_ == "table" and name == (os.getenv("ALEMBIC_VERSION_TABLE") or "alembic_version"):
        return False

    if type_ == "schema" and name in _EXCLUDE_SCHEMAS:
        return False

    if type_ == "table" and name in _EXCLUDE_TABLES:
        return False

    if _EXCLUDE_OBJECTS_RE and _EXCLUDE_OBJECTS_RE.search(name or ""):
        return False

    # можно также учитывать obj.info.get("skip_autogenerate", False)
    if getattr(getattr(obj, "info", None), "get", lambda *_: False)("skip_autogenerate", False):
        return False

    return True


def _skip_empty_autogen(
    context_: MigrationContext,
    revision: tuple[str, str],
    directives: list,
) -> None:
    """
    Don't Generate Empty Migrations with Autogenerate:
    если автогенерация не обнаружила изменений — не создавать файл ревизии.
    Официальный рецепт Alembic (process_revision_directives).  # See refs
    """
    cmd_opts = getattr(config, "cmd_opts", None)
    if not cmd_opts or not getattr(cmd_opts, "autogenerate", False):
        return
    if not directives:
        return
    script = directives[0]
    if script.upgrade_ops.is_empty() and script.downgrade_ops.is_empty():
        directives[:] = []  # пустой список => файл не создается
        logger.info("Autogenerate produced no changes; skipping empty revision.")


# ----------------------------- Offline mode -----------------------------------

def run_migrations_offline() -> None:
    """
    Генерация SQL-скриптов без подключения к БД.
    Стандартный оффлайн-режим Alembic.  # See refs
    """
    url = _get_db_url()
    config.set_main_option("sqlalchemy.url", url)
    opts = _apply_runtime_toggles(url)
    context.configure(
        url=url,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_object=_include_object,
        process_revision_directives=_skip_empty_autogen,
        **opts,
    )

    with context.begin_transaction():
        context.run_migrations()


# ----------------------------- Online mode (sync) -----------------------------

def _run_migrations_sync(connection: Connection) -> None:
    url = str(connection.engine.url)
    opts = _apply_runtime_toggles(url)
    context.configure(
        connection=connection,
        include_object=_include_object,
        process_revision_directives=_skip_empty_autogen,
        **opts,
    )
    with context.begin_transaction():
        context.run_migrations()


# ----------------------------- Online mode (async) ----------------------------

async def _run_migrations_async(async_engine: AsyncEngine) -> None:
    async with async_engine.connect() as conn:
        await conn.run_sync(_run_migrations_sync)


def run_migrations_online() -> None:
    """
    Онлайн-режим: создаем (a)sync engine в зависимости от URL/настроек и запускаем миграции.
    Шаблон соответствует документации Alembic/SQLAlchemy для AsyncEngine.  # See refs
    """
    url = _get_db_url()
    config.set_main_option("sqlalchemy.url", url)

    url_obj = make_url(url)
    is_async = (
        os.getenv("ALEMBIC_ASYNC", "").lower() in ("1", "true")
        or url_obj.get_backend_name().endswith("+asyncpg")
        or url_obj.get_backend_name().endswith("+aiomysql")
        or url_obj.get_backend_name().endswith("+aiosqlite")
    )

    if is_async:
        engine = create_async_engine(url, poolclass=pool.NullPool, future=True)
        try:
            asyncio.run(_run_migrations_async(engine))
        finally:
            # dispose() у AsyncEngine — корутинный метод; закрываем пул корректно
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(engine.dispose())
                loop.close()
            except Exception:
                pass
    else:
        connectable = create_engine(url, poolclass=pool.NullPool, future=True)
        with connectable.connect() as connection:
            _run_migrations_sync(connection)
        connectable.dispose()


# ----------------------------- Entrypoint -------------------------------------

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()


# ----------------------------- Notes / Sources --------------------------------
# 1) env.py разделяется на run_migrations_offline/online; выбор по is_offline_mode()
#    и настройка через EnvironmentContext.configure().  :contentReference[oaicite:1]{index=1}
# 2) SQLite: batch-миграции (render_as_batch=True) для ALTER-ограничений.  :contentReference[oaicite:2]{index=2}
# 3) Автогенерация и необходимость передать target_metadata в configure(...).  :contentReference[oaicite:3]{index=3}
# 4) Фильтры include_object / include_schemas для отбора объектов автогенерации.  :contentReference[oaicite:4]{index=4}
# 5) Пропуск пустых ревизий через process_revision_directives (официальный рецепт).  :contentReference[oaicite:5]{index=5}
# 6) Async-движок: шаблон с create_async_engine и run_sync(...) для Alembic.  :contentReference[oaicite:6]{index=6}
# 7) Naming convention задается на уровне MetaData; см. SQLAlchemy docs (рекомендуется).
#    Хотя это делается в моделях, а не в env.py, оно влияет на корректность диффов.  :contentReference[oaicite:7]{index=7}
