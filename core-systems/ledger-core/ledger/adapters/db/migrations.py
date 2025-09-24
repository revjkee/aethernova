# ledger-core/ledger/ledger/adapters/db/migrations.py
from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import hashlib
import importlib
import inspect
import logging
import os
import pkgutil
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from types import ModuleType
from typing import Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

# --------------------------------------------------------------------------------------
# Логирование
# --------------------------------------------------------------------------------------

LOG = logging.getLogger("ledger.db.migrations")
LOG.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
if not LOG.handlers:
    LOG.addHandler(_handler)

# --------------------------------------------------------------------------------------
# Конфигурация
# --------------------------------------------------------------------------------------

DEFAULT_SCHEMA = os.getenv("DB_SCHEMA", "public")
DEFAULT_DSN = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://ledger_app:password@localhost:5432/ledger_dev",
)

MIGRATIONS_PACKAGE = os.getenv(
    "MIGRATIONS_PACKAGE",  # можно переопределить, напр. "ledger.migrations"
    "ledger.ledger.adapters.db.migrations_definitions",
)

ADVISORY_LOCK_KEY = int(hashlib.sha256(b"ledger-core:migrations").hexdigest()[:8], 16)

# --------------------------------------------------------------------------------------
# Модель миграции
# --------------------------------------------------------------------------------------

UpFunc = Callable[[AsyncConnection], Awaitable[None]]
DownFunc = Callable[[AsyncConnection], Awaitable[None]]

@dataclass(frozen=True)
class Migration:
    version: str                  # монотонный ключ, например "20250815_120000_add_tx_table"
    description: str              # краткое описание
    up: UpFunc                    # корутина применения
    down: Optional[DownFunc] = None   # корутина отката (опционально)
    transactional: bool = True        # False, если требуется DDL CONCURRENTLY
    tags: Tuple[str, ...] = ()        # произвольные метки ("ddl","seed" и т.п.)

    def checksum(self) -> str:
        """Контрольная сумма по исходнику up/down + метаданным."""
        parts = [
            self.version,
            self.description,
            inspect.getsource(self.up),
            inspect.getsource(self.down) if self.down else "",
            "tx" if self.transactional else "no-tx",
            "|".join(self.tags),
        ]
        h = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
        return h

# --------------------------------------------------------------------------------------
# Работа с БД
# --------------------------------------------------------------------------------------

def make_engine(dsn: str = DEFAULT_DSN) -> AsyncEngine:
    return create_async_engine(
        dsn,
        pool_pre_ping=True,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_POOL_OVERFLOW", "10")),
        pool_recycle=1800,
    )

SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS {DEFAULT_SCHEMA}.schema_migrations (
    version        text PRIMARY KEY,
    description    text NOT NULL,
    checksum       text NOT NULL,
    applied_at     timestamptz NOT NULL,
    execution_ms   integer NOT NULL,
    tags           text[] NOT NULL DEFAULT '{{}}'::text[]
);

CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at
ON {DEFAULT_SCHEMA}.schema_migrations (applied_at DESC);
"""

async def ensure_schema(conn: AsyncConnection) -> None:
    await conn.execute(text(SCHEMA_SQL))

@contextlib.asynccontextmanager
async def advisory_lock(conn: AsyncConnection, key: int = ADVISORY_LOCK_KEY):
    """pg_advisory_lock для сериализации запуска миграций."""
    LOG.debug("acquiring advisory lock %s", key)
    await conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": key})
    try:
        yield
    finally:
        await conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
        LOG.debug("released advisory lock %s", key)

async def current_versions(conn: AsyncConnection) -> Dict[str, str]:
    """Версия->checksum (применённые миграции)."""
    await ensure_schema(conn)
    res = await conn.execute(text(f"SELECT version, checksum FROM {DEFAULT_SCHEMA}.schema_migrations"))
    return {row.version: row.checksum for row in res}

async def insert_applied(
    conn: AsyncConnection, m: Migration, execution_ms: int
) -> None:
    await conn.execute(
        text(
            f"""INSERT INTO {DEFAULT_SCHEMA}.schema_migrations
            (version, description, checksum, applied_at, execution_ms, tags)
            VALUES (:v, :d, :c, now(), :ms, :tags)"""
        ),
        {"v": m.version, "d": m.description, "c": m.checksum(), "ms": execution_ms, "tags": list(m.tags)},
    )

async def delete_applied(conn: AsyncConnection, version: str) -> None:
    await conn.execute(
        text(f"DELETE FROM {DEFAULT_SCHEMA}.schema_migrations WHERE version = :v"),
        {"v": version},
    )

# --------------------------------------------------------------------------------------
# Исполнение DDL CONCURRENTLY (вне транзакции)
# --------------------------------------------------------------------------------------

async def exec_concurrently(conn: AsyncConnection, sql: str) -> None:
    """
    Выполнить DDL, требующий autocommit (например, CREATE INDEX CONCURRENTLY).
    """
    await conn.commit()
    await conn.exec_driver_sql(sql)
    await conn.commit()

# --------------------------------------------------------------------------------------
# Загрузка миграций
# --------------------------------------------------------------------------------------

class MigrationRegistry:
    def __init__(self, pkg: str = MIGRATIONS_PACKAGE):
        self.pkg = pkg
        self._mods: List[ModuleType] = []
        self._migs: Dict[str, Migration] = {}

    def discover(self) -> "MigrationRegistry":
        """Импортирует все модули pkg.* и собирает MIGRATIONS."""
        LOG.debug("discovering migrations in %s", self.pkg)
        pkg = importlib.import_module(self.pkg)
        for _, name, ispkg in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
            if ispkg:
                continue
            mod = importlib.import_module(name)
            self._mods.append(mod)
            migs: Sequence[Migration] = getattr(mod, "MIGRATIONS", ())
            for m in migs:
                if m.version in self._migs:
                    raise RuntimeError(f"duplicate migration version {m.version} in {name}")
                self._migs[m.version] = m
        return self

    def sorted(self) -> List[Migration]:
        return [self._migs[v] for v in sorted(self._migs.keys())]

    def get(self, version: str) -> Migration:
        return self._migs[version]

# --------------------------------------------------------------------------------------
# Раннер
# --------------------------------------------------------------------------------------

class MigrationRunner:
    def __init__(self, engine: AsyncEngine, registry: MigrationRegistry):
        self.engine = engine
        self.registry = registry

    async def _check_drift(self, conn: AsyncConnection, applied: Dict[str, str]) -> None:
        """Проверка дрейфа схемы: совпадение checksum для уже применённых миграций."""
        for v, ch in applied.items():
            if v not in self.registry._migs:
                LOG.warning("applied version %s is missing from registry (skipped)", v)
                continue
            curr = self.registry._migs[v].checksum()
            if curr != ch:
                raise RuntimeError(f"checksum drift for {v}: db={ch} code={curr}")

    async def history(self) -> List[Tuple[str, str, str]]:
        async with self.engine.begin() as conn:
            await ensure_schema(conn)
            rows = await conn.execute(
                text(
                    f"""SELECT version, description, applied_at
                        FROM {DEFAULT_SCHEMA}.schema_migrations
                        ORDER BY applied_at DESC"""
                )
            )
            return [(r.version, r.description, r.applied_at.isoformat()) for r in rows]

    async def current(self) -> List[str]:
        async with self.engine.begin() as conn:
            applied = await current_versions(conn)
            return sorted(applied.keys())

    async def upgrade(self, target: Optional[str] = None) -> None:
        """
        Применить все ещё не применённые миграции (до target включительно, если задан).
        """
        async with self.engine.begin() as conn:
            await ensure_schema(conn)
            async with advisory_lock(conn):
                applied = await current_versions(conn)
                await self._check_drift(conn, applied)
                plan = []
                for m in self.registry.sorted():
                    if m.version in applied:
                        continue
                    plan.append(m)
                    if target and m.version == target:
                        break
                if not plan:
                    LOG.info("nothing to upgrade")
                    return

                for m in plan:
                    LOG.info("applying %s: %s", m.version, m.description)
                    started = time.perf_counter()
                    if m.transactional:
                        await m.up(conn)
                    else:
                        # вне транзакции: например, CREATE INDEX CONCURRENTLY
                        await exec_concurrently(conn, f"/* {m.version} start */ SELECT 1;")
                        await m.up(conn)
                        await exec_concurrently(conn, f"/* {m.version} end */ SELECT 1;")
                    elapsed = int((time.perf_counter() - started) * 1000)
                    await insert_applied(conn, m, elapsed)
                    LOG.info("applied %s in %dms", m.version, elapsed)

    async def downgrade(self, steps: int = 1) -> None:
        """
        Откатить последние N миграций (только если у них определён down).
        """
        if steps <= 0:
            return
        async with self.engine.begin() as conn:
            await ensure_schema(conn)
            async with advisory_lock(conn):
                rows = await conn.execute(
                    text(
                        f"""SELECT version FROM {DEFAULT_SCHEMA}.schema_migrations
                            ORDER BY applied_at DESC LIMIT :n"""
                    ),
                    {"n": steps},
                )
                to_rollback = [r.version for r in rows]
                if not to_rollback:
                    LOG.info("nothing to downgrade")
                    return
                for v in to_rollback:
                    m = self.registry.get(v)
                    if not m.down:
                        raise RuntimeError(f"migration {v} has no down()")
                    LOG.info("reverting %s: %s", m.version, m.description)
                    started = time.perf_counter()
                    if m.transactional:
                        await m.down(conn)  # type: ignore[arg-type]
                    else:
                        await exec_concurrently(conn, f"/* {m.version} down start */ SELECT 1;")
                        await m.down(conn)  # type: ignore[arg-type]
                        await exec_concurrently(conn, f"/* {m.version} down end */ SELECT 1;")
                    elapsed = int((time.perf_counter() - started) * 1000)
                    await delete_applied(conn, v)
                    LOG.info("reverted %s in %dms", v, elapsed)

    async def stamp(self, version: str) -> None:
        """
        Пометить версию как применённую без выполнения (для выравнивания окружений).
        """
        m = self.registry.get(version)
        async with self.engine.begin() as conn:
            await ensure_schema(conn)
            async with advisory_lock(conn):
                applied = await current_versions(conn)
                if m.version in applied:
                    LOG.info("version already stamped: %s", version)
                    return
                await insert_applied(conn, m, execution_ms=0)
                LOG.info("stamped %s", version)

# --------------------------------------------------------------------------------------
# Пример определения миграций (по умолчанию читаются из MIGRATIONS_PACKAGE)
# Вы можете создать пакет ledger/ledger/adapters/db/migrations_definitions/*.py с MIGRATIONS.
# Ниже — резервный пакет по умолчанию, если внешний не задан.
# --------------------------------------------------------------------------------------

# Фолбэк‑пакет: если MIGRATIONS_PACKAGE отсутствует, создадим модуль на лету с базовой миграцией.
if "ledger.ledger.adapters.db.migrations_definitions" not in sys.modules:
    modname = "ledger.ledger.adapters.db.migrations_definitions"
    module = ModuleType(modname)
    sys.modules[modname] = module
    module.__path__ = []  # type: ignore[attr-defined]

    async def _base_up(conn: AsyncConnection) -> None:
        await conn.execute(
            text(f"""
            CREATE TABLE IF NOT EXISTS {DEFAULT_SCHEMA}.accounts(
                account_id  text PRIMARY KEY,
                name        text NOT NULL,
                type        text NOT NULL,
                currency    text NOT NULL,
                status      text NOT NULL,
                balance     numeric(38, 9) NOT NULL DEFAULT 0,
                created_at  timestamptz NOT NULL DEFAULT now(),
                updated_at  timestamptz NOT NULL DEFAULT now()
            );
            """)
        )

    async def _base_down(conn: AsyncConnection) -> None:
        await conn.execute(text(f"DROP TABLE IF EXISTS {DEFAULT_SCHEMA}.accounts;"))

    base_migration = Migration(
        version="20250101_000000_base_schema",
        description="create base accounts table",
        up=_base_up,
        down=_base_down,
        transactional=True,
        tags=("ddl",),
    )
    module.MIGRATIONS = (base_migration,)  # type: ignore[attr-defined]

# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ledger-migrate", description="Ledger Core DB migrations")
    p.add_argument("--dsn", default=DEFAULT_DSN, help="SQLAlchemy async DSN")
    p.add_argument("--pkg", default=MIGRATIONS_PACKAGE, help="package with MIGRATIONS")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("current", help="show applied versions")
    sub.add_parser("history", help="show history (latest first)")

    up = sub.add_parser("upgrade", help="apply pending migrations")
    up.add_argument("--to", dest="target", default=None, help="apply up to target version inclusive")

    down = sub.add_parser("downgrade", help="revert last N migrations")
    down.add_argument("--steps", type=int, default=1)

    stamp = sub.add_parser("stamp", help="mark version as applied without executing")
    stamp.add_argument("version")

    return p

async def _main_async(args: argparse.Namespace) -> int:
    engine = make_engine(args.dsn)
    try:
        registry = MigrationRegistry(args.pkg).discover()
    except Exception as e:
        LOG.error("failed to discover migrations in %s: %s", args.pkg, e)
        return 2

    runner = MigrationRunner(engine, registry)

    if args.cmd == "current":
        vers = await runner.current()
        for v in vers:
            print(v)
        return 0

    if args.cmd == "history":
        hist = await runner.history()
        for v, desc, ts in hist:
            print(f"{ts} {v} {desc}")
        return 0

    if args.cmd == "upgrade":
        await runner.upgrade(target=args.target)
        return 0

    if args.cmd == "downgrade":
        await runner.downgrade(steps=args.steps)
        return 0

    if args.cmd == "stamp":
        await runner.stamp(args.version)
        return 0

    return 1

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return asyncio.run(_main_async(args))

if __name__ == "__main__":
    raise SystemExit(main())
