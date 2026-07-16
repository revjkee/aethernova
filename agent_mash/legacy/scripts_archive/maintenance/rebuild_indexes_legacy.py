# agent_mash/legacy/scripts_archive/maintenance/rebuild_indexes_legacy.py
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Iterable, Sequence

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError


@dataclass(frozen=True)
class PlanItem:
    statement: str
    note: str


EXIT_OK = 0
EXIT_INVALID_CONFIG = 2
EXIT_DB_CONNECT = 3
EXIT_EXECUTION = 4


def _build_logger(verbosity: int) -> logging.Logger:
    logger = logging.getLogger("rebuild_indexes_legacy")
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)

    if verbosity <= 0:
        fmt = "%(levelname)s: %(message)s"
    elif verbosity == 1:
        fmt = "%(asctime)s %(levelname)s: %(message)s"
    else:
        fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"

    handler.setFormatter(logging.Formatter(fmt))
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="rebuild_indexes_legacy.py",
        description="Legacy maintenance utility to rebuild/optimize indexes depending on DB dialect.",
    )

    p.add_argument(
        "--database-url",
        default=None,
        help="SQLAlchemy database URL. If omitted, uses DATABASE_URL env var.",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Execute the plan. Without this flag, script runs in dry-run mode.",
    )
    p.add_argument(
        "--schema",
        default=None,
        help="Target schema/database name depending on engine (e.g., 'public' for Postgres).",
    )
    p.add_argument(
        "--table",
        action="append",
        default=[],
        help="Target table name (repeatable). If omitted, script may operate on whole schema depending on engine.",
    )
    p.add_argument(
        "--analyze",
        action="store_true",
        help="For PostgreSQL: run ANALYZE after REINDEX operations.",
    )
    p.add_argument(
        "--lock-timeout-ms",
        type=int,
        default=0,
        help="For PostgreSQL: set lock_timeout in milliseconds for the session (0 disables).",
    )
    p.add_argument(
        "--statement-timeout-ms",
        type=int,
        default=0,
        help="For PostgreSQL: set statement_timeout in milliseconds for the session (0 disables).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv).",
    )

    return p.parse_args(argv)


def _require_database_url(args: argparse.Namespace) -> str:
    url = args.database_url or os.getenv("DATABASE_URL")
    if not url or not str(url).strip():
        raise ValueError("DATABASE_URL is required via --database-url or environment variable.")
    return url.strip()


def _engine_from_url(database_url: str) -> Engine:
    # future=True is default in SQLAlchemy 2.x; keep explicit for clarity.
    return create_engine(database_url, future=True, pool_pre_ping=True)


def _dialect_name(engine: Engine) -> str:
    return engine.dialect.name.lower().strip()


def _quote_ident(dialect: str, name: str) -> str:
    """
    Conservative identifier quoting.
    We avoid dialect-specific quoting rules beyond the common safe patterns.
    """
    name = name.strip()
    if not name:
        raise ValueError("Empty identifier.")
    # Reject dangerous characters for safety in a maintenance script.
    bad = [";", "--", "/*", "*/", "\n", "\r", "\t"]
    if any(x in name for x in bad):
        raise ValueError(f"Unsafe identifier: {name!r}")
    # Use double quotes for Postgres/SQLite; backticks for MySQL/MariaDB.
    if dialect in {"mysql", "mariadb"}:
        return f"`{name.replace('`', '``')}`"
    return f"\"{name.replace('\"', '\"\"')}\""


def _plan_postgres(schema: str | None, tables: Sequence[str], analyze: bool) -> list[PlanItem]:
    plan: list[PlanItem] = []

    if tables:
        # REINDEX TABLE [CONCURRENTLY] is possible, but CONCURRENTLY has limitations and requirements.
        # Use non-concurrent to keep deterministic behavior for legacy tooling.
        for t in tables:
            if not schema:
                raise ValueError("PostgreSQL: --schema is required when --table is used.")
            full = f"{_quote_ident('postgresql', schema)}.{_quote_ident('postgresql', t)}"
            plan.append(PlanItem(statement=f"REINDEX TABLE {full};", note=f"reindex table {schema}.{t}"))
    else:
        if schema:
            plan.append(
                PlanItem(
                    statement=f"REINDEX SCHEMA {_quote_ident('postgresql', schema)};",
                    note=f"reindex schema {schema}",
                )
            )
        else:
            plan.append(PlanItem(statement="REINDEX DATABASE CURRENT_DATABASE();", note="reindex current database"))

    if analyze:
        if schema:
            plan.append(
                PlanItem(
                    statement=f"ANALYZE {_quote_ident('postgresql', schema)};",
                    note=f"analyze schema {schema}",
                )
            )
        else:
            plan.append(PlanItem(statement="ANALYZE;", note="analyze database"))
    return plan


def _plan_sqlite(_: str | None, __: Sequence[str]) -> list[PlanItem]:
    # SQLite supports REINDEX; schema/table targeting is not handled here to keep it simple and predictable.
    return [PlanItem(statement="REINDEX;", note="sqlite reindex")]


def _plan_mysql(schema: str | None, tables: Sequence[str]) -> list[PlanItem]:
    # MySQL/MariaDB do not have REINDEX; OPTIMIZE TABLE rebuilds and updates index statistics for many engines.
    # We require explicit table list to reduce risk.
    if not schema:
        raise ValueError("MySQL/MariaDB: --schema (database name) is required.")
    if not tables:
        raise ValueError("MySQL/MariaDB: at least one --table is required to run OPTIMIZE TABLE safely.")

    plan: list[PlanItem] = []
    for t in tables:
        full = f"{_quote_ident('mysql', schema)}.{_quote_ident('mysql', t)}"
        plan.append(PlanItem(statement=f"OPTIMIZE TABLE {full};", note=f"optimize table {schema}.{t}"))
    return plan


def _build_plan(dialect: str, schema: str | None, tables: Sequence[str], analyze: bool) -> list[PlanItem]:
    if dialect in {"postgresql", "postgres"}:
        return _plan_postgres(schema=schema, tables=tables, analyze=analyze)
    if dialect == "sqlite":
        return _plan_sqlite(schema, tables)
    if dialect in {"mysql", "mariadb"}:
        return _plan_mysql(schema=schema, tables=tables)
    raise ValueError(f"Unsupported database dialect: {dialect!r}")


def _apply_timeouts_if_supported(
    dialect: str,
    conn,
    lock_timeout_ms: int,
    statement_timeout_ms: int,
) -> None:
    if dialect not in {"postgresql", "postgres"}:
        return

    if lock_timeout_ms > 0:
        conn.execute(text("SET lock_timeout = :v"), {"v": f"{int(lock_timeout_ms)}ms"})
    if statement_timeout_ms > 0:
        conn.execute(text("SET statement_timeout = :v"), {"v": f"{int(statement_timeout_ms)}ms"})


def _print_plan(logger: logging.Logger, plan: Iterable[PlanItem]) -> None:
    logger.info("Plan:")
    for i, item in enumerate(plan, start=1):
        logger.info("%d) %s", i, item.note)
        logger.info("   %s", item.statement.strip())


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(list(argv) if argv is not None else sys.argv[1:])
    logger = _build_logger(args.verbose)

    try:
        database_url = _require_database_url(args)
    except ValueError as e:
        logger.error(str(e))
        return EXIT_INVALID_CONFIG

    try:
        engine = _engine_from_url(database_url)
    except Exception as e:
        logger.error("Failed to create engine: %s", str(e))
        return EXIT_DB_CONNECT

    try:
        dialect = _dialect_name(engine)
    except Exception as e:
        logger.error("Failed to detect dialect: %s", str(e))
        return EXIT_DB_CONNECT

    tables = [t.strip() for t in (args.table or []) if str(t).strip()]
    schema = args.schema.strip() if args.schema and str(args.schema).strip() else None

    try:
        plan = _build_plan(dialect=dialect, schema=schema, tables=tables, analyze=bool(args.analyze))
    except ValueError as e:
        logger.error(str(e))
        return EXIT_INVALID_CONFIG

    _print_plan(logger, plan)

    if not args.apply:
        logger.info("Dry-run mode: no changes applied (use --apply to execute).")
        return EXIT_OK

    started = time.monotonic()
    try:
        # Many maintenance statements require autocommit behavior in some DBs.
        # Use a connection with explicit execution and commit behavior.
        with engine.connect() as conn:
            _apply_timeouts_if_supported(
                dialect=dialect,
                conn=conn,
                lock_timeout_ms=int(args.lock_timeout_ms),
                statement_timeout_ms=int(args.statement_timeout_ms),
            )

            for item in plan:
                logger.info("Executing: %s", item.note)
                conn.execute(text(item.statement))

            # Commit if the backend uses transactional DDL; harmless otherwise.
            try:
                conn.commit()
            except Exception:
                # Some dialects/connections may not expose commit (e.g., autocommit contexts).
                pass

    except SQLAlchemyError as e:
        logger.error("Execution failed: %s", str(e))
        return EXIT_EXECUTION
    except Exception as e:
        logger.error("Unexpected error: %s", str(e))
        return EXIT_EXECUTION
    finally:
        try:
            engine.dispose()
        except Exception:
            pass

    elapsed = time.monotonic() - started
    logger.info("Done in %.3f seconds.", elapsed)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
