from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy import MetaData, Table, and_, select
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine


EXIT_OK = 0
EXIT_CONFIG_ERROR = 2
EXIT_RUNTIME_ERROR = 3


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    val = os.getenv(name)
    if val is None:
        return default
    val = val.strip()
    return val if val else default


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name, None)
    if raw is None:
        return default
    raw_l = raw.strip().lower()
    if raw_l in ("1", "true", "yes", "y", "on"):
        return True
    if raw_l in ("0", "false", "no", "n", "off"):
        return False
    return default


def _env_int(name: str, default: int) -> int:
    raw = _env(name, None)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid int env {name}={raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = _env(name, None)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid float env {name}={raw!r}") from exc


@dataclass(frozen=True, slots=True)
class MigrationConfig:
    database_url: str
    source_table: str
    target_table: str
    batch_size: int
    dry_run: bool
    stop_on_error: bool
    verify_tls: bool

    field_map: Dict[str, str]  # target_field -> source_field
    static_fields: Dict[str, Any]  # target_field -> literal value

    source_pk: str
    target_unique_key: str
    resume_from_pk: Optional[int]

    postgres_upsert: bool
    upsert_update_columns: Tuple[str, ...]  # empty => do nothing on conflict

    log_level: str
    log_json: bool

    @staticmethod
    def load() -> "MigrationConfig":
        database_url = _env("DATABASE_URL", None)
        if not database_url:
            raise ValueError("DATABASE_URL is required (async SQLAlchemy URL)")

        source_table = _env("MIGRATE_SOURCE_TABLE", "users_v1")
        target_table = _env("MIGRATE_TARGET_TABLE", "users_v2")

        batch_size = _env_int("MIGRATE_BATCH_SIZE", 500)
        if batch_size <= 0 or batch_size > 10000:
            raise ValueError("MIGRATE_BATCH_SIZE must be between 1 and 10000")

        dry_run = _env_bool("MIGRATE_DRY_RUN", False)
        stop_on_error = _env_bool("MIGRATE_STOP_ON_ERROR", True)
        verify_tls = _env_bool("MIGRATE_VERIFY_TLS", True)

        field_map_raw = _env("MIGRATE_FIELD_MAP_JSON", "{}")
        static_fields_raw = _env("MIGRATE_STATIC_FIELDS_JSON", "{}")
        try:
            field_map = json.loads(field_map_raw) if field_map_raw else {}
            static_fields = json.loads(static_fields_raw) if static_fields_raw else {}
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON in MIGRATE_FIELD_MAP_JSON or MIGRATE_STATIC_FIELDS_JSON") from exc

        if not isinstance(field_map, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in field_map.items()):
            raise ValueError("MIGRATE_FIELD_MAP_JSON must be an object of {target_field: source_field}")

        if not isinstance(static_fields, dict) or not all(isinstance(k, str) for k in static_fields.keys()):
            raise ValueError("MIGRATE_STATIC_FIELDS_JSON must be an object of {target_field: literal_value}")

        source_pk = _env("MIGRATE_SOURCE_PK", "id") or "id"
        target_unique_key = _env("MIGRATE_TARGET_UNIQUE_KEY", "id") or "id"

        resume_from_pk_raw = _env("MIGRATE_RESUME_FROM_PK", None)
        resume_from_pk: Optional[int] = None
        if resume_from_pk_raw is not None:
            try:
                resume_from_pk = int(resume_from_pk_raw)
            except ValueError as exc:
                raise ValueError("MIGRATE_RESUME_FROM_PK must be int") from exc
            if resume_from_pk < 0:
                raise ValueError("MIGRATE_RESUME_FROM_PK must be >= 0")

        postgres_upsert = _env_bool("MIGRATE_POSTGRES_UPSERT", True)
        upsert_update_cols_raw = _env("MIGRATE_UPSERT_UPDATE_COLUMNS", "") or ""
        upsert_update_columns = tuple([c.strip() for c in upsert_update_cols_raw.split(",") if c.strip()])

        log_level = (_env("MIGRATE_LOG_LEVEL", "INFO") or "INFO").upper()
        log_json = _env_bool("MIGRATE_LOG_JSON", False)

        return MigrationConfig(
            database_url=database_url,
            source_table=source_table,
            target_table=target_table,
            batch_size=batch_size,
            dry_run=dry_run,
            stop_on_error=stop_on_error,
            verify_tls=verify_tls,
            field_map=field_map,
            static_fields=static_fields,
            source_pk=source_pk,
            target_unique_key=target_unique_key,
            resume_from_pk=resume_from_pk,
            postgres_upsert=postgres_upsert,
            upsert_update_columns=upsert_update_columns,
            log_level=log_level,
            log_json=log_json,
        )


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time()),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str, json_mode: bool) -> None:
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    if json_mode:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)


def _dialect_name(conn: Connection) -> str:
    return conn.dialect.name.lower()


async def reflect_tables(aconn: AsyncConnection, source_name: str, target_name: str) -> Tuple[Table, Table]:
    md = MetaData()
    await aconn.run_sync(md.reflect, only=[source_name, target_name])
    if source_name not in md.tables:
        raise RuntimeError(f"Source table not found: {source_name}")
    if target_name not in md.tables:
        raise RuntimeError(f"Target table not found: {target_name}")
    return md.tables[source_name], md.tables[target_name]


def build_row_transformer(
    source: Table,
    target: Table,
    field_map: Mapping[str, str],
    static_fields: Mapping[str, Any],
) -> Tuple[Tuple[str, ...], Any]:
    target_cols = {c.name for c in target.columns}
    source_cols = {c.name for c in source.columns}

    unknown_target = [t for t in field_map.keys() if t not in target_cols]
    if unknown_target:
        raise ValueError(f"FIELD_MAP targets not in target table: {unknown_target}")

    unknown_source = [s for s in field_map.values() if s not in source_cols]
    if unknown_source:
        raise ValueError(f"FIELD_MAP sources not in source table: {unknown_source}")

    static_unknown_target = [t for t in static_fields.keys() if t not in target_cols]
    if static_unknown_target:
        raise ValueError(f"STATIC_FIELDS targets not in target table: {static_unknown_target}")

    used_target_columns = tuple(sorted(set(field_map.keys()) | set(static_fields.keys())))
    used_source_columns = tuple(sorted(set(field_map.values())))

    def transform(source_row: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for tgt, src in field_map.items():
            out[tgt] = source_row.get(src)
        for tgt, val in static_fields.items():
            out[tgt] = val
        return out

    return used_source_columns, transform


def _validate_key_columns(source: Table, target: Table, source_pk: str, target_unique_key: str) -> None:
    if source_pk not in source.columns:
        raise ValueError(f"source_pk column not found in source: {source_pk}")
    if target_unique_key not in target.columns:
        raise ValueError(f"target_unique_key column not found in target: {target_unique_key}")


async def fetch_batch(
    aconn: AsyncConnection,
    source: Table,
    source_pk: str,
    columns: Sequence[str],
    last_pk: Optional[int],
    limit: int,
) -> List[Mapping[str, Any]]:
    cols = [source.columns[c] for c in columns]
    stmt = select(*cols).order_by(source.columns[source_pk].asc()).limit(limit)
    if last_pk is not None:
        stmt = stmt.where(source.columns[source_pk] > last_pk)
    res = await aconn.execute(stmt)
    rows = res.mappings().all()
    return list(rows)


def _build_insert_stmt(
    conn: Connection,
    target: Table,
    rows: List[Dict[str, Any]],
    unique_key: str,
    allow_postgres_upsert: bool,
    update_columns: Tuple[str, ...],
):
    if not rows:
        return None

    dialect = _dialect_name(conn)

    if dialect == "postgresql" and allow_postgres_upsert:
        from sqlalchemy.dialects.postgresql import insert as pg_insert  # type: ignore

        stmt = pg_insert(target).values(rows)
        if update_columns:
            set_map = {c: getattr(stmt.excluded, c) for c in update_columns if c in target.columns}
            if set_map:
                stmt = stmt.on_conflict_do_update(index_elements=[target.columns[unique_key]], set_=set_map)
            else:
                stmt = stmt.on_conflict_do_nothing(index_elements=[target.columns[unique_key]])
        else:
            stmt = stmt.on_conflict_do_nothing(index_elements=[target.columns[unique_key]])
        return stmt

    return target.insert().values(rows)


async def insert_rows(
    aconn: AsyncConnection,
    target: Table,
    rows: List[Dict[str, Any]],
    unique_key: str,
    dry_run: bool,
    postgres_upsert: bool,
    upsert_update_columns: Tuple[str, ...],
    logger: logging.Logger,
) -> Tuple[int, int]:
    if not rows:
        return 0, 0

    inserted = 0
    skipped = 0

    async def _sync_insert(conn: Connection) -> Tuple[int, int]:
        nonlocal inserted, skipped
        if dry_run:
            return len(rows), 0

        stmt = _build_insert_stmt(
            conn=conn,
            target=target,
            rows=rows,
            unique_key=unique_key,
            allow_postgres_upsert=postgres_upsert,
            update_columns=upsert_update_columns,
        )
        if stmt is None:
            return 0, 0

        dialect = _dialect_name(conn)

        try:
            res = conn.execute(stmt)
            if dialect == "postgresql":
                inserted = res.rowcount if res.rowcount is not None else len(rows)
            else:
                inserted = res.rowcount if res.rowcount is not None else len(rows)
            skipped = max(0, len(rows) - inserted)
            return inserted, skipped
        except IntegrityError:
            if dialect != "postgresql":
                inserted_local = 0
                skipped_local = 0
                for r in rows:
                    try:
                        conn.execute(target.insert().values(r))
                        inserted_local += 1
                    except IntegrityError:
                        skipped_local += 1
                inserted = inserted_local
                skipped = skipped_local
                return inserted, skipped
            raise
        except SQLAlchemyError as exc:
            logger.error("DB error while inserting batch", exc_info=exc)
            raise

    return await aconn.run_sync(_sync_insert)


@dataclass
class MigrationStats:
    started_at: float
    read_rows: int = 0
    inserted_rows: int = 0
    skipped_rows: int = 0
    batches: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "duration_sec": round(time.time() - self.started_at, 3),
            "read_rows": self.read_rows,
            "inserted_rows": self.inserted_rows,
            "skipped_rows": self.skipped_rows,
            "batches": self.batches,
        }


async def run_migration(cfg: MigrationConfig) -> int:
    logger = logging.getLogger("migrate_users_v1_to_v2")
    stats = MigrationStats(started_at=time.time())

    connect_args: Dict[str, Any] = {}
    if cfg.database_url.startswith("postgresql"):
        connect_args = {}

    engine: AsyncEngine = create_async_engine(
        cfg.database_url,
        echo=False,
        pool_pre_ping=True,
        connect_args=connect_args,
    )

    last_pk: Optional[int] = cfg.resume_from_pk

    try:
        async with engine.begin() as aconn:
            source, target = await reflect_tables(aconn, cfg.source_table, cfg.target_table)
            _validate_key_columns(source, target, cfg.source_pk, cfg.target_unique_key)

            used_source_columns, transform = build_row_transformer(
                source=source,
                target=target,
                field_map=cfg.field_map,
                static_fields=cfg.static_fields,
            )

            if cfg.target_unique_key not in cfg.field_map and cfg.target_unique_key not in cfg.static_fields:
                if cfg.target_unique_key == cfg.source_pk:
                    if cfg.target_unique_key in target.columns and cfg.source_pk in source.columns:
                        pass

            while True:
                batch = await fetch_batch(
                    aconn=aconn,
                    source=source,
                    source_pk=cfg.source_pk,
                    columns=list(used_source_columns) if used_source_columns else [cfg.source_pk],
                    last_pk=last_pk,
                    limit=cfg.batch_size,
                )

                if not batch:
                    break

                stats.batches += 1
                stats.read_rows += len(batch)

                batch_last_pk_val = None
                if cfg.source_pk in batch[-1]:
                    batch_last_pk_val = batch[-1][cfg.source_pk]

                rows_to_insert: List[Dict[str, Any]] = []
                for row in batch:
                    out = transform(row)
                    if cfg.target_unique_key == cfg.source_pk and cfg.target_unique_key not in out:
                        out[cfg.target_unique_key] = row.get(cfg.source_pk)
                    rows_to_insert.append(out)

                try:
                    inserted, skipped = await insert_rows(
                        aconn=aconn,
                        target=target,
                        rows=rows_to_insert,
                        unique_key=cfg.target_unique_key,
                        dry_run=cfg.dry_run,
                        postgres_upsert=cfg.postgres_upsert,
                        upsert_update_columns=cfg.upsert_update_columns,
                        logger=logger,
                    )
                    stats.inserted_rows += inserted
                    stats.skipped_rows += skipped

                    logger.info(
                        "Batch migrated",
                        extra={
                            "batch": stats.batches,
                            "batch_size": len(batch),
                            "inserted": inserted,
                            "skipped": skipped,
                            "last_pk": batch_last_pk_val,
                        },
                    )
                except Exception as exc:
                    logger.error(
                        "Batch failed",
                        exc_info=exc,
                        extra={"batch": stats.batches, "last_pk": batch_last_pk_val},
                    )
                    if cfg.stop_on_error:
                        raise
                finally:
                    if batch_last_pk_val is not None:
                        try:
                            last_pk = int(batch_last_pk_val)
                        except Exception:
                            last_pk = last_pk

            logger.info("Migration finished", extra=stats.as_dict())

        return EXIT_OK
    except ValueError as exc:
        logging.getLogger("migrate_users_v1_to_v2").error(str(exc))
        return EXIT_CONFIG_ERROR
    except Exception as exc:
        logging.getLogger("migrate_users_v1_to_v2").error("Migration failed", exc_info=exc)
        return EXIT_RUNTIME_ERROR
    finally:
        await engine.dispose()


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="migrate_users_v1_to_v2",
        description="Async migration script from users_v1 to users_v2 using SQLAlchemy reflection and configurable field mapping.",
    )
    p.add_argument("--dry-run", action="store_true", help="Do not write into target table; just simulate inserts")
    p.add_argument("--batch-size", type=int, default=None, help="Override MIGRATE_BATCH_SIZE")
    p.add_argument("--resume-from-pk", type=int, default=None, help="Override MIGRATE_RESUME_FROM_PK")
    p.add_argument("--stop-on-error", action="store_true", help="Stop on first batch error")
    p.add_argument("--continue-on-error", action="store_true", help="Continue even if a batch fails")
    return p


def apply_cli_overrides(cfg: MigrationConfig, args: argparse.Namespace) -> MigrationConfig:
    dry_run = cfg.dry_run or bool(args.dry_run)

    batch_size = cfg.batch_size
    if args.batch_size is not None:
        if args.batch_size <= 0 or args.batch_size > 10000:
            raise ValueError("--batch-size must be between 1 and 10000")
        batch_size = args.batch_size

    resume_from_pk = cfg.resume_from_pk
    if args.resume_from_pk is not None:
        if args.resume_from_pk < 0:
            raise ValueError("--resume-from-pk must be >= 0")
        resume_from_pk = args.resume_from_pk

    stop_on_error = cfg.stop_on_error
    if args.stop_on_error and args.continue_on_error:
        raise ValueError("Use only one of --stop-on-error or --continue-on-error")
    if args.stop_on_error:
        stop_on_error = True
    if args.continue_on_error:
        stop_on_error = False

    return MigrationConfig(
        database_url=cfg.database_url,
        source_table=cfg.source_table,
        target_table=cfg.target_table,
        batch_size=batch_size,
        dry_run=dry_run,
        stop_on_error=stop_on_error,
        verify_tls=cfg.verify_tls,
        field_map=cfg.field_map,
        static_fields=cfg.static_fields,
        source_pk=cfg.source_pk,
        target_unique_key=cfg.target_unique_key,
        resume_from_pk=resume_from_pk,
        postgres_upsert=cfg.postgres_upsert,
        upsert_update_columns=cfg.upsert_update_columns,
        log_level=cfg.log_level,
        log_json=cfg.log_json,
    )


def main() -> int:
    cfg = MigrationConfig.load()

    parser = build_arg_parser()
    args = parser.parse_args()

    cfg = apply_cli_overrides(cfg, args)

    setup_logging(cfg.log_level, cfg.log_json)
    logging.getLogger("migrate_users_v1_to_v2").info(
        "Starting migration",
        extra={
            "source_table": cfg.source_table,
            "target_table": cfg.target_table,
            "batch_size": cfg.batch_size,
            "dry_run": cfg.dry_run,
            "stop_on_error": cfg.stop_on_error,
            "resume_from_pk": cfg.resume_from_pk,
        },
    )

    return asyncio.run(run_migration(cfg))


if __name__ == "__main__":
    raise SystemExit(main())
