# path: datafabric/tasks/maintenance/vacuum.py
"""
DataFabric DB Maintenance Task: VACUUM/ANALYZE/REINDEX

Features
- DBs: PostgreSQL (preferred), SQLite (best-effort)
- Operations: VACUUM [FULL], ANALYZE (threshold-aware), optional REINDEX
- Include/Exclude filters for schemas & tables with glob/regex modes
- Safety: dry-run, statement_timeout, skip read-only, minimal locking defaults
- Metrics & tracing: per-table timings, rows_estimated, dead_tuples, index_bloat_est (pg), errors
- Sync and Async APIs
- Scheduler integration helper (DataFabricScheduler)
- CLI for ops: python -m datafabric.tasks.maintenance.vacuum --help

Optional deps:
- psycopg (v3) or psycopg2 for sync PostgreSQL
- asyncpg for async PostgreSQL
- sqlite3 from stdlib

Notes
- For PostgreSQL uses lightweight VACUUM (not FULL) по умолчанию; FULL требует эксклюзивных блокировок.
- ANALYZE запускается, если таблица изменилась больше analyze_threshold_pct с прошлого анализа.
"""

from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger("datafabric.maintenance.vacuum")
logger.addHandler(logging.NullHandler())

# ---- Optional drivers
_HAS_PG = False
_HAS_ASYNC = False

try:
    import psycopg  # type: ignore
    import psycopg.rows  # type: ignore
    _HAS_PG = True
except Exception:
    try:
        import psycopg2  # type: ignore
        _HAS_PG = True
    except Exception:
        pass

try:
    import asyncpg  # type: ignore
    _HAS_ASYNC = True
except Exception:
    pass

import sqlite3  # stdlib always available


# ---------------- Config ----------------

class DBType(str):
    POSTGRES = "postgres"
    SQLITE = "sqlite"

class MatchMode(str):
    GLOB = "glob"
    REGEX = "regex"

class Operation(str):
    VACUUM = "vacuum"
    VACUUM_FULL = "vacuum_full"
    ANALYZE = "analyze"
    VACUUM_ANALYZE = "vacuum_analyze"
    REINDEX = "reindex"
    ALL = "all"  # vacuum + analyze (+ reindex if enabled)

@dataclass
class VacuumConfig:
    db_type: str = DBType.POSTGRES
    dsn: str = field(default_factory=lambda: os.getenv("DATAFABRIC_DB_DSN", ""))
    sqlite_path: str = field(default_factory=lambda: os.getenv("DATAFABRIC_SQLITE_PATH", ":memory:"))

    include_schemas: Sequence[str] = field(default_factory=lambda: ("public",))
    exclude_schemas: Sequence[str] = field(default_factory=tuple)
    include_tables: Sequence[str] = field(default_factory=tuple)     # "schema.table" patterns
    exclude_tables: Sequence[str] = field(default_factory=tuple)

    match_mode: str = MatchMode.GLOB  # or REGEX

    operation: str = Operation.VACUUM_ANALYZE
    enable_reindex: bool = False
    vacuum_full: bool = False  # stronger than operation
    analyze_threshold_pct: float = 10.0  # trigger analyze if changed >= X %

    statement_timeout_ms: Optional[int] = 600_000
    skip_system_schemas: bool = True
    max_tables: Optional[int] = None
    dry_run: bool = False

    # Logging/metrics
    log_level: int = logging.INFO

@dataclass
class TableTarget:
    schema: str
    name: str

    @property
    def fq(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass
class TableStats:
    relname: str
    n_live_tup: Optional[int] = None
    n_dead_tup: Optional[int] = None
    last_analyze: Optional[str] = None
    last_autovacuum: Optional[str] = None
    changed_pct: Optional[float] = None
    est_index_bloat_pct: Optional[float] = None


@dataclass
class RunMetrics:
    started_at: float
    finished_at: Optional[float] = None
    db_type: str = DBType.POSTGRES
    tables_considered: int = 0
    tables_processed: int = 0
    vacuum_ok: int = 0
    analyze_ok: int = 0
    reindex_ok: int = 0
    errors: int = 0
    per_table_seconds: Dict[str, float] = field(default_factory=dict)
    per_table_status: Dict[str, str] = field(default_factory=dict)

    def finish(self):
        self.finished_at = time.time()

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------- Utilities ----------------

_PG_SYS_SCHEMAS = {"pg_catalog", "pg_toast", "information_schema"}

def _match(value: str, patterns: Sequence[str], mode: str) -> bool:
    if not patterns:
        return True
    if mode == MatchMode.GLOB:
        return any(fnmatch.fnmatch(value, p) for p in patterns)
    # REGEX
    return any(re.fullmatch(p, value) for p in patterns)

def _excluded(value: str, patterns: Sequence[str], mode: str) -> bool:
    if not patterns:
        return False
    if mode == MatchMode.GLOB:
        return any(fnmatch.fnmatch(value, p) for p in patterns)
    return any(re.fullmatch(p, value) for p in patterns)

def _pg_ident(ident: str) -> str:
    # simple safe identifier quoting
    return '"' + ident.replace('"', '""') + '"'


# ---------------- Core runner ----------------

class VacuumRunner:
    def __init__(self, cfg: VacuumConfig):
        self.cfg = cfg
        logging.getLogger("datafabric.maintenance.vacuum").setLevel(cfg.log_level)

    # ---- public sync

    def run(self) -> RunMetrics:
        if self.cfg.db_type == DBType.POSTGRES:
            return self._run_postgres_sync()
        elif self.cfg.db_type == DBType.SQLITE:
            return self._run_sqlite_sync()
        else:
            raise ValueError("Unsupported db_type")

    # ---- public async (best-effort)

    async def run_async(self) -> RunMetrics:
        if self.cfg.db_type == DBType.POSTGRES and _HAS_ASYNC:
            return await self._run_postgres_async()
        # fallback to sync
        return self.run()

    # ---- Postgres paths

    def _run_postgres_sync(self) -> RunMetrics:
        if not _HAS_PG:
            raise RuntimeError("psycopg/psycopg2 not installed")
        metrics = RunMetrics(started_at=time.time(), db_type=DBType.POSTGRES)

        # open connection
        conn = None
        cur = None
        try:
            try:
                # psycopg v3
                import psycopg  # type: ignore
                conn = psycopg.connect(self.cfg.dsn)  # type: ignore
                conn.autocommit = True
                cur = conn.cursor(row_factory=getattr(psycopg.rows, "dict_row", None))  # type: ignore
            except Exception:
                # psycopg2
                import psycopg2  # type: ignore
                conn = psycopg2.connect(self.cfg.dsn)  # type: ignore
                conn.autocommit = True
                cur = conn.cursor()

            # timeouts
            if self.cfg.statement_timeout_ms is not None:
                try:
                    cur.execute(f"SET statement_timeout = {int(self.cfg.statement_timeout_ms)}")
                except Exception:
                    pass

            # read-only guard
            cur.execute("SHOW transaction_read_only")
            ro = cur.fetchone()
            if (ro[0] if isinstance(ro, tuple) else ro.get("transaction_read_only")) == "on":
                logger.warning("Cluster is read-only; skipping maintenance")
                metrics.finish()
                return metrics

            tables = self._pg_discover_tables(cur)
            metrics.tables_considered = len(tables)

            for t in tables[: (self.cfg.max_tables or len(tables))]:
                fq = f"{t.schema}.{t.name}"
                t0 = time.time()
                try:
                    stats = self._pg_table_stats(cur, t)
                    do_analyze = self._should_analyze(stats)
                    do_vacuum = True
                    do_full = self.cfg.vacuum_full or (self.cfg.operation == Operation.VACUUM_FULL)

                    if self.cfg.dry_run:
                        status = f"DRYRUN vacuum={'FULL' if do_full else 'plain'} analyze={do_analyze}"
                        logger.info("%s -> %s", fq, status)
                        metrics.per_table_status[fq] = status
                        metrics.tables_processed += 1
                        continue

                    # VACUUM
                    if self.cfg.operation in (Operation.VACUUM, Operation.VACUUM_ANALYZE, Operation.ALL) or do_full:
                        q = f"VACUUM {'(FULL, ANALYZE)' if (do_full and do_analyze) else '(FULL)' if do_full else ''} {_pg_ident(t.schema)}.{_pg_ident(t.name)}" if do_full else \
                            f"VACUUM {_pg_ident(t.schema)}.{_pg_ident(t.name)}"
                        cur.execute(q)
                        metrics.vacuum_ok += 1
                        logger.info("VACUUM ok: %s", fq)

                    # ANALYZE
                    if (self.cfg.operation in (Operation.ANALYZE, Operation.VACUUM_ANALYZE, Operation.ALL) or do_analyze) and not do_full:
                        cur.execute(f"ANALYZE {_pg_ident(t.schema)}.{_pg_ident(t.name)}")
                        metrics.analyze_ok += 1
                        logger.info("ANALYZE ok: %s", fq)

                    # REINDEX (optional)
                    if self.cfg.enable_reindex and (self.cfg.operation in (Operation.REINDEX, Operation.ALL)):
                        # safer than REINDEX TABLE CONCURRENTLY (11+)
                        try:
                            cur.execute(f"REINDEX TABLE CONCURRENTLY {_pg_ident(t.schema)}.{_pg_ident(t.name)}")
                        except Exception:
                            # fallback (blocking)
                            cur.execute(f"REINDEX TABLE {_pg_ident(t.schema)}.{_pg_ident(t.name)}")
                        metrics.reindex_ok += 1
                        logger.info("REINDEX ok: %s", fq)

                    metrics.per_table_status[fq] = "ok"
                    metrics.tables_processed += 1

                except Exception as e:
                    metrics.errors += 1
                    logger.error("Maintenance failed for %s: %s", fq, e)
                    metrics.per_table_status[fq] = f"error: {e}"
                finally:
                    metrics.per_table_seconds[fq] = time.time() - t0

        finally:
            try:
                if cur is not None:
                    cur.close()
            except Exception:
                pass
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass

        metrics.finish()
        return metrics

    async def _run_postgres_async(self) -> RunMetrics:
        if not _HAS_ASYNC:
            # should not happen
            return self._run_postgres_sync()
        metrics = RunMetrics(started_at=time.time(), db_type=DBType.POSTGRES)
        conn = await asyncpg.connect(self.cfg.dsn)  # type: ignore
        try:
            # RO guard
            ro = await conn.fetchval("SHOW transaction_read_only")
            if str(ro).lower() in ("on", "true", "1"):
                logger.warning("Cluster is read-only; skipping maintenance")
                metrics.finish()
                return metrics

            # timeout per statement through SET LOCAL (session-level not supported easily in asyncpg)
            if self.cfg.statement_timeout_ms is not None:
                try:
                    await conn.execute(f"SET statement_timeout = {int(self.cfg.statement_timeout_ms)}")
                except Exception:
                    pass

            tables = await self._pg_discover_tables_async(conn)
            metrics.tables_considered = len(tables)

            for t in tables[: (self.cfg.max_tables or len(tables))]:
                fq = f"{t.schema}.{t.name}"
                t0 = time.time()
                try:
                    stats = await self._pg_table_stats_async(conn, t)
                    do_analyze = self._should_analyze(stats)
                    do_full = self.cfg.vacuum_full or (self.cfg.operation == Operation.VACUUM_FULL)

                    if self.cfg.dry_run:
                        status = f"DRYRUN vacuum={'FULL' if do_full else 'plain'} analyze={do_analyze}"
                        logger.info("%s -> %s", fq, status)
                        metrics.per_table_status[fq] = status
                        metrics.tables_processed += 1
                        continue

                    if self.cfg.operation in (Operation.VACUUM, Operation.VACUUM_ANALYZE, Operation.ALL) or do_full:
                        if do_full:
                            await conn.execute(f'VACUUM (FULL{", ANALYZE" if do_analyze else ""}) "{t.schema}"."{t.name}"')
                        else:
                            await conn.execute(f'VACUUM "{t.schema}"."{t.name}"')
                        metrics.vacuum_ok += 1
                        logger.info("VACUUM ok: %s", fq)

                    if (self.cfg.operation in (Operation.ANALYZE, Operation.VACUUM_ANALYZE, Operation.ALL) or do_analyze) and not do_full:
                        await conn.execute(f'ANALYZE "{t.schema}"."{t.name}"')
                        metrics.analyze_ok += 1
                        logger.info("ANALYZE ok: %s", fq)

                    if self.cfg.enable_reindex and (self.cfg.operation in (Operation.REINDEX, Operation.ALL)):
                        try:
                            await conn.execute(f'REINDEX TABLE CONCURRENTLY "{t.schema}"."{t.name}"')
                        except Exception:
                            await conn.execute(f'REINDEX TABLE "{t.schema}"."{t.name}"')
                        metrics.reindex_ok += 1
                        logger.info("REINDEX ok: %s", fq)

                    metrics.per_table_status[fq] = "ok"
                    metrics.tables_processed += 1
                except Exception as e:
                    metrics.errors += 1
                    logger.error("Maintenance failed for %s: %s", fq, e)
                    metrics.per_table_status[fq] = f"error: {e}"
                finally:
                    metrics.per_table_seconds[fq] = time.time() - t0
        finally:
            await conn.close()
        metrics.finish()
        return metrics

    def _pg_discover_tables(self, cur) -> List[TableTarget]:
        q = """
        select n.nspname as schema, c.relname as name
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where c.relkind in ('r','p')  -- tables and partitions
        """
        if self.cfg.skip_system_schemas:
            q += " and n.nspname not in %s"
            params = (tuple(_PG_SYS_SCHEMAS),)
            cur.execute(q, params)
        else:
            cur.execute(q)
        rows = cur.fetchall()
        out = []
        for r in rows:
            schema = r[0] if isinstance(r, tuple) else r["schema"]
            name = r[1] if isinstance(r, tuple) else r["name"]
            fq = f"{schema}.{name}"
            if not _match(schema, self.cfg.include_schemas, self.cfg.match_mode):
                continue
            if _excluded(schema, self.cfg.exclude_schemas, self.cfg.match_mode):
                continue
            if self.cfg.include_tables and not _match(fq, self.cfg.include_tables, self.cfg.match_mode):
                continue
            if _excluded(fq, self.cfg.exclude_tables, self.cfg.match_mode):
                continue
            out.append(TableTarget(schema=schema, name=name))
        return out

    async def _pg_discover_tables_async(self, conn) -> List[TableTarget]:
        q = """
        select n.nspname as schema, c.relname as name
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where c.relkind in ('r','p')
        """
        if self.cfg.skip_system_schemas:
            q += " and n.nspname <> all($1)"
            rows = await conn.fetch(q, list(_PG_SYS_SCHEMAS))
        else:
            rows = await conn.fetch(q)
        out = []
        for r in rows:
            schema = r["schema"]
            name = r["name"]
            fq = f"{schema}.{name}"
            if not _match(schema, self.cfg.include_schemas, self.cfg.match_mode):
                continue
            if _excluded(schema, self.cfg.exclude_schemas, self.cfg.match_mode):
                continue
            if self.cfg.include_tables and not _match(fq, self.cfg.include_tables, self.cfg.match_mode):
                continue
            if _excluded(fq, self.cfg.exclude_tables, self.cfg.match_mode):
                continue
            out.append(TableTarget(schema=schema, name=name))
        return out

    def _pg_table_stats(self, cur, t: TableTarget) -> TableStats:
        # pg_stat_user_tables for dead tuples & last analyze; pg_stat_all_tables in case of non-user schemas
        q = """
        select s.relname,
               s.n_live_tup,
               s.n_dead_tup,
               s.last_analyze,
               s.last_autovacuum,
               pg_total_relation_size(format('%I.%I', %s, %s)) as total_size
        from pg_stat_all_tables s
        where s.schemaname = %s and s.relname = %s
        """
        cur.execute(q, (t.schema, t.name, t.schema, t.name))
        r = cur.fetchone()
        st = TableStats(relname=t.name)
        if r:
            if isinstance(r, tuple):
                st.n_live_tup = r[1]; st.n_dead_tup = r[2]
                st.last_analyze = str(r[3]) if r[3] else None
                st.last_autovacuum = str(r[4]) if r[4] else None
            else:
                st.n_live_tup = r.get("n_live_tup")
                st.n_dead_tup = r.get("n_dead_tup")
                st.last_analyze = str(r.get("last_analyze")) if r.get("last_analyze") else None
                st.last_autovacuum = str(r.get("last_autovacuum")) if r.get("last_autovacuum") else None

            # naive bloat estimate via dead tuple ratio
            try:
                total = (st.n_live_tup or 0) + (st.n_dead_tup or 0)
                st.est_index_bloat_pct = round(100.0 * (st.n_dead_tup or 0) / max(1, total), 2)
            except Exception:
                pass
        return st

    async def _pg_table_stats_async(self, conn, t: TableTarget) -> TableStats:
        q = """
        select s.relname,
               s.n_live_tup,
               s.n_dead_tup,
               s.last_analyze,
               s.last_autovacuum
        from pg_stat_all_tables s
        where s.schemaname = $1 and s.relname = $2
        """
        r = await conn.fetchrow(q, t.schema, t.name)
        st = TableStats(relname=t.name)
        if r:
            st.n_live_tup = r["n_live_tup"]
            st.n_dead_tup = r["n_dead_tup"]
            st.last_analyze = str(r["last_analyze"]) if r["last_analyze"] else None
            st.last_autovacuum = str(r["last_autovacuum"]) if r["last_autovacuum"] else None
            try:
                total = (st.n_live_tup or 0) + (st.n_dead_tup or 0)
                st.est_index_bloat_pct = round(100.0 * (st.n_dead_tup or 0) / max(1, total), 2)
            except Exception:
                pass
        return st

    def _should_analyze(self, st: TableStats) -> bool:
        if st.n_live_tup is None or st.n_dead_tup is None:
            return True  # unknown -> be safe
        changed = (st.n_dead_tup or 0)
        total = max(1, (st.n_live_tup or 0) + (st.n_dead_tup or 0))
        pct = 100.0 * changed / total
        st.changed_pct = round(pct, 2)
        return pct >= float(self.cfg.analyze_threshold_pct)

    # ---- SQLite path

    def _run_sqlite_sync(self) -> RunMetrics:
        metrics = RunMetrics(started_at=time.time(), db_type=DBType.SQLITE)
        path = self.cfg.sqlite_path
        if not path:
            raise ValueError("sqlite_path is required for SQLite")
        con = sqlite3.connect(path)
        try:
            cur = con.cursor()
            # SQLite VACUUM works only outside transaction and locks DB; ANALYZE is lightweight
            tables = self._sqlite_tables(cur)
            metrics.tables_considered = len(tables)
            for name in tables[: (self.cfg.max_tables or len(tables))]:
                fq = name
                t0 = time.time()
                try:
                    if self.cfg.dry_run:
                        metrics.per_table_status[fq] = "DRYRUN vacuum+analyze"
                        metrics.tables_processed += 1
                        continue
                    # ANALYZE first (improves statistics used by VACUUM decision in some edge cases)
                    if self.cfg.operation in (Operation.ANALYZE, Operation.VACUUM_ANALYZE, Operation.ALL):
                        cur.execute(f"ANALYZE {name}")
                        metrics.analyze_ok += 1
                    # VACUUM (no per-table in SQLite)
                    if self.cfg.operation in (Operation.VACUUM, Operation.VACUUM_ANALYZE, Operation.ALL) or self.cfg.vacuum_full:
                        cur.execute("VACUUM")
                        metrics.vacuum_ok += 1
                    metrics.per_table_status[fq] = "ok"
                    metrics.tables_processed += 1
                except Exception as e:
                    metrics.errors += 1
                    metrics.per_table_status[fq] = f"error: {e}"
                finally:
                    metrics.per_table_seconds[fq] = time.time() - t0
            con.commit()
        finally:
            try:
                con.close()
            except Exception:
                pass
        metrics.finish()
        return metrics

    def _sqlite_tables(self, cur) -> List[str]:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        rows = [r[0] for r in cur.fetchall()]
        out = []
        for name in rows:
            schema = ""  # SQLite has no schema
            fq = name
            if self.cfg.include_tables and not _match(fq, self.cfg.include_tables, self.cfg.match_mode):
                continue
            if _excluded(fq, self.cfg.exclude_tables, self.cfg.match_mode):
                continue
            out.append(name)
        return out


# ---------------- Scheduler integration ----------------

def schedule_vacuum(scheduler, *, cfg: Optional[VacuumConfig] = None, job_id: str = "db_maintenance_vacuum", seconds: int = 3600):
    """
    Register periodic maintenance job on DataFabricScheduler.
    """
    from ...scheduler.apscheduler import DataFabricScheduler  # lazy import

    if not isinstance(scheduler, DataFabricScheduler):
        raise TypeError("scheduler must be DataFabricScheduler")

    _cfg = cfg or VacuumConfig()

    @scheduler.scheduled_job(trigger="interval", seconds=seconds, job_id=job_id, tags=("maintenance", "db"))
    def _job():
        runner = VacuumRunner(_cfg)
        m = runner.run()
        logger.info("Maintenance finished: %s", m.as_dict())

    return job_id


# ---------------- CLI ----------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DataFabric VACUUM/ANALYZE/REINDEX maintenance")
    p.add_argument("--db-type", choices=[DBType.POSTGRES, DBType.SQLITE], default=DBType.POSTGRES)
    p.add_argument("--dsn", help="PostgreSQL DSN")
    p.add_argument("--sqlite-path", help="Path to SQLite file")
    p.add_argument("--include-schema", action="append", default=[], help="Schema to include (repeatable)")
    p.add_argument("--exclude-schema", action="append", default=[], help="Schema to exclude (repeatable)")
    p.add_argument("--include-table", action="append", default=[], help="schema.table pattern (repeatable)")
    p.add_argument("--exclude-table", action="append", default=[], help="schema.table pattern (repeatable)")
    p.add_argument("--match-mode", choices=[MatchMode.GLOB, MatchMode.REGEX], default=MatchMode.GLOB)
    p.add_argument("--op", choices=[Operation.VACUUM, Operation.VACUUM_FULL, Operation.ANALYZE, Operation.VACUUM_ANALYZE, Operation.REINDEX, Operation.ALL], default=Operation.VACUUM_ANALYZE)
    p.add_argument("--vacuum-full", action="store_true", help="Force VACUUM FULL for Postgres")
    p.add_argument("--enable-reindex", action="store_true")
    p.add_argument("--analyze-threshold-pct", type=float, default=10.0)
    p.add_argument("--statement-timeout-ms", type=int, default=600_000)
    p.add_argument("--no-skip-system", action="store_true", help="Include system schemas")
    p.add_argument("--max-tables", type=int)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--log-level", default="INFO")
    return p

def _from_args(args: argparse.Namespace) -> VacuumConfig:
    return VacuumConfig(
        db_type=args.db_type,
        dsn=args.dsn or os.getenv("DATAFABRIC_DB_DSN", ""),
        sqlite_path=args.sqlite_path or os.getenv("DATAFABRIC_SQLITE_PATH", ":memory:"),
        include_schemas=tuple(args.include_schema or (("public",) if args.db_type == DBType.POSTGRES else ())),
        exclude_schemas=tuple(args.exclude_schema or ()),
        include_tables=tuple(args.include_table or ()),
        exclude_tables=tuple(args.exclude_table or ()),
        match_mode=args.match_mode,
        operation=args.op,
        vacuum_full=bool(args.vacuum_full),
        enable_reindex=bool(args.enable_reindex),
        analyze_threshold_pct=float(args.analyze_threshold_pct),
        statement_timeout_ms=int(args.statement_timeout_ms) if args.statement_timeout_ms is not None else None,
        skip_system_schemas=not args.no_skip_system,
        max_tables=args.max_tables,
        dry_run=bool(args.dry_run),
        log_level=getattr(logging, str(args.log_level).upper(), logging.INFO),
    )

def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = argv or sys.argv[1:]
    ap = _build_parser()
    ns = ap.parse_args(argv)
    logging.basicConfig(level=getattr(logging, str(ns.log_level).upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = _from_args(ns)
    runner = VacuumRunner(cfg)
    m = runner.run()
    logger.info("Maintenance metrics: %s", m.as_dict())
    return 0

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
