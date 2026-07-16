# path: agent_mash/legacy/scripts_archive/one_off/data_patch_hotfix.py
# -*- coding: utf-8 -*-
"""
Industrial one-off data patch/hotfix runner (async).

Design goals:
- Safe-by-default: dry-run enabled unless explicitly disabled.
- Async-first: uses SQLAlchemy AsyncEngine/AsyncSession.
- Transactional: everything wrapped in a single transaction by default (configurable).
- Idempotent: supports audit table + patch run identifiers.
- Observable: structured logs + JSON report.
- Controlled: advisory lock prevents concurrent runs.
- Declarative: patch plan can be provided as JSON or YAML (optional PyYAML dependency).
- Minimal coupling: can run standalone with only SQLAlchemy installed.

Usage examples:
  python data_patch_hotfix.py --db-url "postgresql+asyncpg://user:pass@host:5432/db" --plan ./plan.yaml
  python data_patch_hotfix.py --db-url "postgresql+asyncpg://..." --plan ./plan.json --apply
  python data_patch_hotfix.py --db-url "postgresql+asyncpg://..." --apply --no-single-tx

Notes:
- This script DOES NOT assume project-specific models.
- Patch operations are expressed as raw SQL statements with parameters (safe parameter binding).
- You can extend `build_operations_from_custom_hook()` to implement bespoke logic in code.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

# SQLAlchemy is required at runtime.
try:
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
except Exception as exc:  # pragma: no cover
    raise RuntimeError(
        "SQLAlchemy (async) is required. Install: pip install 'sqlalchemy[asyncio]' asyncpg"
    ) from exc


# -----------------------------
# Logging / structured helpers
# -----------------------------

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": dt.datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach extra structured fields if present
        for key in ("run_id", "patch_id", "op_id", "event", "elapsed_ms", "details"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(verbose: bool) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler.setFormatter(JsonLogFormatter())
    root.handlers.clear()
    root.addHandler(handler)


logger = logging.getLogger("data_patch_hotfix")


# -----------------------------
# Data structures
# -----------------------------

@dataclasses.dataclass(frozen=True)
class Operation:
    """
    A single atomic operation to execute.

    op_id: unique id within run
    sql: SQL statement (text) with named params (recommended)
    params: dict of bound parameters
    expect_rowcount: optional safety guard; if set, rowcount must match
    allow_zero_rows: if False and expect_rowcount is None, rowcount must be > 0
    """
    op_id: str
    sql: str
    params: Dict[str, Any]
    expect_rowcount: Optional[int] = None
    allow_zero_rows: bool = True


@dataclasses.dataclass
class OperationResult:
    op_id: str
    ok: bool
    rowcount: Optional[int]
    error: Optional[str]
    duration_ms: int


@dataclasses.dataclass
class RunReport:
    run_id: str
    patch_id: str
    started_at_utc: str
    finished_at_utc: Optional[str]
    dry_run: bool
    single_tx: bool
    db_dialect: str
    db_host: Optional[str]
    operations_total: int
    operations_ok: int
    operations_failed: int
    results: List[OperationResult]
    notes: List[str]

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False, indent=2)


# -----------------------------
# Patch plan parsing
# -----------------------------

def _load_yaml_if_available(raw: str) -> Any:
    # Optional dependency: PyYAML
    try:
        import yaml  # type: ignore
    except Exception:
        raise RuntimeError(
            "YAML plan provided but PyYAML is not installed. Install: pip install pyyaml"
        )
    return yaml.safe_load(raw)


def load_plan(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    lower = path.lower()
    if lower.endswith(".json"):
        return json.loads(raw)
    if lower.endswith((".yml", ".yaml")):
        data = _load_yaml_if_available(raw)
        if not isinstance(data, dict):
            raise ValueError("YAML plan root must be a mapping/object.")
        return data

    # Fallback: try JSON, then YAML
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    data = _load_yaml_if_available(raw)
    if not isinstance(data, dict):
        raise ValueError("Plan root must be an object.")
    return data


def normalize_operations_from_plan(plan: Dict[str, Any]) -> Tuple[str, List[Operation], List[str]]:
    """
    Expected plan format (JSON/YAML):

    patch_id: "2026-02-03-hotfix-001"
    notes:
      - "what and why"
    operations:
      - op_id: "op-001"
        sql: "UPDATE table SET col = :v WHERE id = :id"
        params: {v: "x", id: 123}
        expect_rowcount: 1
        allow_zero_rows: false

    If patch_id missing, computed hash-based id is used.
    """
    notes: List[str] = []
    if isinstance(plan.get("notes"), list):
        notes = [str(x) for x in plan["notes"]]

    ops_raw = plan.get("operations", [])
    if not isinstance(ops_raw, list):
        raise ValueError("Plan.operations must be a list.")

    ops: List[Operation] = []
    for idx, item in enumerate(ops_raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Operation #{idx} must be an object.")
        op_id = str(item.get("op_id") or f"op-{idx:03d}")
        sql = item.get("sql")
        if not isinstance(sql, str) or not sql.strip():
            raise ValueError(f"Operation {op_id}: sql must be a non-empty string.")
        params = item.get("params") or {}
        if not isinstance(params, dict):
            raise ValueError(f"Operation {op_id}: params must be an object.")

        expect_rc = item.get("expect_rowcount", None)
        if expect_rc is not None:
            if not isinstance(expect_rc, int) or expect_rc < 0:
                raise ValueError(f"Operation {op_id}: expect_rowcount must be int >= 0.")

        allow_zero_rows = bool(item.get("allow_zero_rows", True))

        ops.append(
            Operation(
                op_id=op_id,
                sql=sql,
                params=dict(params),
                expect_rowcount=expect_rc,
                allow_zero_rows=allow_zero_rows,
            )
        )

    patch_id = plan.get("patch_id")
    if not isinstance(patch_id, str) or not patch_id.strip():
        # Deterministic patch_id from operations content
        h = hashlib.sha256()
        h.update(json.dumps(plan, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        patch_id = "patch-" + h.hexdigest()[:16]

    return patch_id, ops, notes


# -----------------------------
# Safety / environment validation
# -----------------------------

def must_get_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return v


def parse_db_host(db_url: str) -> Optional[str]:
    # best-effort host extraction without external deps
    # works for common patterns: scheme://user:pass@host:port/db
    try:
        if "@" not in db_url:
            return None
        after_at = db_url.split("@", 1)[1]
        host_port_db = after_at.split("/", 1)[0]
        host = host_port_db.split(":", 1)[0]
        return host or None
    except Exception:
        return None


def compute_lock_key(patch_id: str) -> int:
    # Advisory lock key must fit in signed 64-bit for Postgres; we use 31-bit safe int.
    h = hashlib.sha256(patch_id.encode("utf-8")).digest()
    # 4 bytes -> unsigned int32
    v = int.from_bytes(h[:4], "big", signed=False)
    # keep in 31-bit positive range
    return v & 0x7FFFFFFF


# -----------------------------
# DB helpers (audit + lock)
# -----------------------------

AUDIT_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS data_patch_audit (
    id BIGSERIAL PRIMARY KEY,
    run_id TEXT NOT NULL,
    patch_id TEXT NOT NULL,
    started_at_utc TIMESTAMPTZ NOT NULL,
    finished_at_utc TIMESTAMPTZ,
    dry_run BOOLEAN NOT NULL,
    single_tx BOOLEAN NOT NULL,
    db_dialect TEXT NOT NULL,
    db_host TEXT,
    operations_total INTEGER NOT NULL,
    operations_ok INTEGER NOT NULL,
    operations_failed INTEGER NOT NULL,
    report_json JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_data_patch_audit_patch_id ON data_patch_audit(patch_id);
CREATE INDEX IF NOT EXISTS idx_data_patch_audit_run_id ON data_patch_audit(run_id);
"""

# Postgres advisory lock (no-op on other dialects)
PG_LOCK_SQL = "SELECT pg_try_advisory_lock(:k) AS locked"
PG_UNLOCK_SQL = "SELECT pg_advisory_unlock(:k) AS unlocked"


async def ensure_audit_table(session: AsyncSession) -> None:
    # DDL is safe to run repeatedly
    for stmt in [s.strip() for s in AUDIT_TABLE_DDL.split(";") if s.strip()]:
        await session.execute(text(stmt))


async def try_advisory_lock(session: AsyncSession, dialect: str, key: int) -> bool:
    if dialect != "postgresql":
        return True
    res = await session.execute(text(PG_LOCK_SQL), {"k": key})
    row = res.mappings().first()
    return bool(row and row.get("locked") is True)


async def advisory_unlock(session: AsyncSession, dialect: str, key: int) -> None:
    if dialect != "postgresql":
        return
    try:
        await session.execute(text(PG_UNLOCK_SQL), {"k": key})
    except Exception:
        # Don't raise on unlock failure
        logger.warning("Failed to unlock advisory lock", extra={"event": "unlock_failed"})


async def audit_write(session: AsyncSession, report: RunReport) -> None:
    # report_json is stored as JSONB in Postgres; in other DBs it may become TEXT depending on backend
    await session.execute(
        text(
            """
            INSERT INTO data_patch_audit(
                run_id, patch_id, started_at_utc, finished_at_utc,
                dry_run, single_tx, db_dialect, db_host,
                operations_total, operations_ok, operations_failed, report_json
            )
            VALUES (
                :run_id, :patch_id, :started_at_utc, :finished_at_utc,
                :dry_run, :single_tx, :db_dialect, :db_host,
                :operations_total, :operations_ok, :operations_failed, :report_json
            )
            """
        ),
        {
            "run_id": report.run_id,
            "patch_id": report.patch_id,
            "started_at_utc": report.started_at_utc,
            "finished_at_utc": report.finished_at_utc,
            "dry_run": report.dry_run,
            "single_tx": report.single_tx,
            "db_dialect": report.db_dialect,
            "db_host": report.db_host,
            "operations_total": report.operations_total,
            "operations_ok": report.operations_ok,
            "operations_failed": report.operations_failed,
            "report_json": json.loads(report.to_json()),
        },
    )


# -----------------------------
# Execution engine
# -----------------------------

async def execute_operation(session: AsyncSession, run_id: str, patch_id: str, op: Operation, dry_run: bool) -> OperationResult:
    t0 = time.perf_counter()
    try:
        if dry_run:
            # Dry-run: validate SQL compilation path minimally without applying changes.
            # We still run a harmless SELECT 1 to keep a consistent flow.
            await session.execute(text("SELECT 1"))
            rowcount = None
        else:
            res = await session.execute(text(op.sql), op.params)
            # SQLAlchemy may expose rowcount for DML
            rowcount = getattr(res, "rowcount", None)

        # Safety guards
        if not dry_run:
            if op.expect_rowcount is not None and rowcount is not None and rowcount != op.expect_rowcount:
                raise RuntimeError(f"Rowcount mismatch: expected {op.expect_rowcount}, got {rowcount}")
            if op.expect_rowcount is None and (rowcount is not None) and (rowcount == 0) and (not op.allow_zero_rows):
                raise RuntimeError("Rowcount is zero but allow_zero_rows=false")

        dt_ms = int((time.perf_counter() - t0) * 1000)
        logger.info(
            "operation_ok",
            extra={
                "event": "operation_ok",
                "run_id": run_id,
                "patch_id": patch_id,
                "op_id": op.op_id,
                "elapsed_ms": dt_ms,
                "details": {"rowcount": rowcount, "dry_run": dry_run},
            },
        )
        return OperationResult(op_id=op.op_id, ok=True, rowcount=rowcount, error=None, duration_ms=dt_ms)
    except Exception as e:
        dt_ms = int((time.perf_counter() - t0) * 1000)
        logger.error(
            "operation_failed",
            extra={
                "event": "operation_failed",
                "run_id": run_id,
                "patch_id": patch_id,
                "op_id": op.op_id,
                "elapsed_ms": dt_ms,
                "details": {"error": str(e)},
            },
        )
        return OperationResult(op_id=op.op_id, ok=False, rowcount=None, error=str(e), duration_ms=dt_ms)


def build_operations_from_custom_hook() -> List[Operation]:
    """
    Optional hook for custom patch logic in code.

    By default, returns empty list. You can implement project-specific logic here,
    but keep it deterministic and safe (no external network calls).
    """
    return []


async def run_patch(
    engine: AsyncEngine,
    patch_id: str,
    operations: List[Operation],
    notes: List[str],
    dry_run: bool,
    single_tx: bool,
    require_lock: bool,
    write_audit: bool,
    output_report_path: Optional[str],
) -> int:
    run_id = str(uuid.uuid4())
    started = dt.datetime.utcnow()

    db_host = parse_db_host(str(engine.url))
    db_dialect = engine.url.get_backend_name()

    report = RunReport(
        run_id=run_id,
        patch_id=patch_id,
        started_at_utc=started.isoformat(timespec="seconds") + "Z",
        finished_at_utc=None,
        dry_run=dry_run,
        single_tx=single_tx,
        db_dialect=db_dialect,
        db_host=db_host,
        operations_total=len(operations),
        operations_ok=0,
        operations_failed=0,
        results=[],
        notes=list(notes),
    )

    lock_key = compute_lock_key(patch_id)

    async_session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session_factory() as session:
        # Ensure audit table exists if requested
        if write_audit:
            await ensure_audit_table(session)
            if not single_tx:
                await session.commit()

        # Acquire lock if requested
        locked = True
        if require_lock:
            locked = await try_advisory_lock(session, db_dialect, lock_key)
            if not locked:
                logger.error(
                    "lock_not_acquired",
                    extra={"event": "lock_not_acquired", "run_id": run_id, "patch_id": patch_id, "details": {"lock_key": lock_key}},
                )
                report.notes.append("Advisory lock not acquired; another run may be active.")
                report.finished_at_utc = dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
                if write_audit:
                    await audit_write(session, report)
                    await session.commit()
                return 2

            # On Postgres, advisory locks are session-scoped; keep same session throughout.
            logger.info(
                "lock_acquired",
                extra={"event": "lock_acquired", "run_id": run_id, "patch_id": patch_id, "details": {"lock_key": lock_key}},
            )

        try:
            if single_tx:
                async with session.begin():
                    for op in operations:
                        r = await execute_operation(session, run_id, patch_id, op, dry_run=dry_run)
                        report.results.append(r)
                        if r.ok:
                            report.operations_ok += 1
                        else:
                            report.operations_failed += 1
                            # Fail-fast inside single transaction
                            raise RuntimeError(f"Operation failed: {op.op_id}: {r.error}")
            else:
                # Each op in its own transaction
                for op in operations:
                    async with session.begin():
                        r = await execute_operation(session, run_id, patch_id, op, dry_run=dry_run)
                        report.results.append(r)
                        if r.ok:
                            report.operations_ok += 1
                        else:
                            report.operations_failed += 1
                            # Continue collecting failures, but do not apply further changes if not dry-run
                            if not dry_run:
                                raise RuntimeError(f"Operation failed: {op.op_id}: {r.error}")

            report.finished_at_utc = dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"

            if write_audit:
                # If we are in dry-run, we still record; if not dry-run, we record after successful commit path.
                await audit_write(session, report)
                await session.commit()

            # Write report to file if requested
            if output_report_path:
                os.makedirs(os.path.dirname(os.path.abspath(output_report_path)), exist_ok=True)
                with open(output_report_path, "w", encoding="utf-8") as f:
                    f.write(report.to_json())

            logger.info(
                "run_completed",
                extra={
                    "event": "run_completed",
                    "run_id": run_id,
                    "patch_id": patch_id,
                    "details": {
                        "dry_run": dry_run,
                        "ok": report.operations_ok,
                        "failed": report.operations_failed,
                        "report_path": output_report_path,
                    },
                },
            )
            return 0

        except Exception as e:
            report.finished_at_utc = dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
            report.notes.append(f"Run failed: {str(e)}")

            # Best-effort audit: if tx failed, we may still be able to insert audit in a new transaction.
            if write_audit:
                try:
                    async with session.begin():
                        await audit_write(session, report)
                except Exception:
                    # If audit fails, we still exit with failure.
                    logger.error(
                        "audit_write_failed",
                        extra={"event": "audit_write_failed", "run_id": run_id, "patch_id": patch_id, "details": {"error": "cannot persist audit"}},
                    )

            # Try report file
            if output_report_path:
                try:
                    os.makedirs(os.path.dirname(os.path.abspath(output_report_path)), exist_ok=True)
                    with open(output_report_path, "w", encoding="utf-8") as f:
                        f.write(report.to_json())
                except Exception:
                    pass

            logger.error(
                "run_failed",
                extra={"event": "run_failed", "run_id": run_id, "patch_id": patch_id, "details": {"error": str(e)}},
            )
            return 1

        finally:
            if require_lock:
                await advisory_unlock(session, db_dialect, lock_key)


# -----------------------------
# CLI
# -----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Industrial async data patch / hotfix runner")
    p.add_argument("--db-url", dest="db_url", default=os.getenv("DATABASE_URL"), help="Async SQLAlchemy DB URL (env: DATABASE_URL)")
    p.add_argument("--plan", dest="plan_path", default=None, help="Path to JSON/YAML plan file")
    p.add_argument("--patch-id", dest="patch_id", default=None, help="Override patch_id (discouraged unless controlled)")
    p.add_argument("--apply", dest="apply", action="store_true", help="Apply changes (default: dry-run)")
    p.add_argument("--no-single-tx", dest="no_single_tx", action="store_true", help="Do not wrap all ops in one transaction")
    p.add_argument("--no-lock", dest="no_lock", action="store_true", help="Disable advisory lock")
    p.add_argument("--no-audit", dest="no_audit", action="store_true", help="Disable audit table and audit writes")
    p.add_argument("--report", dest="report_path", default="./data_patch_report.json", help="Write JSON report to path")
    p.add_argument("--verbose", dest="verbose", action="store_true", help="Verbose logs")
    p.add_argument("--max-ops", dest="max_ops", type=int, default=5000, help="Safety limit: maximum operations allowed")
    p.add_argument("--require-env", dest="require_env", action="append", default=[], help="Require env var to be set (can repeat)")
    return p


async def main_async(argv: Sequence[str]) -> int:
    args = build_arg_parser().parse_args(argv)
    setup_logging(args.verbose)

    if not args.db_url:
        logger.error("db_url_missing", extra={"event": "db_url_missing"})
        return 2

    # Optional required env validation
    for env_name in args.require_env:
        try:
            must_get_env(env_name)
        except Exception as e:
            logger.error("env_missing", extra={"event": "env_missing", "details": {"name": env_name, "error": str(e)}})
            return 2

    # Load operations
    notes: List[str] = []
    operations: List[Operation] = []
    patch_id: str

    if args.plan_path:
        plan = load_plan(args.plan_path)
        patch_id, ops, notes = normalize_operations_from_plan(plan)
        operations.extend(ops)
    else:
        # Fallback to custom hook
        operations.extend(build_operations_from_custom_hook())
        if not operations:
            logger.error(
                "no_operations",
                extra={"event": "no_operations", "details": {"reason": "no --plan provided and custom hook returned empty list"}},
            )
            return 2
        # Derive patch_id from hook output deterministically
        h = hashlib.sha256()
        h.update(json.dumps([dataclasses.asdict(o) for o in operations], ensure_ascii=False, sort_keys=True).encode("utf-8"))
        patch_id = "hook-" + h.hexdigest()[:16]

    if args.patch_id:
        patch_id = str(args.patch_id)

    # Safety limits
    if len(operations) > int(args.max_ops):
        logger.error(
            "too_many_operations",
            extra={"event": "too_many_operations", "details": {"ops": len(operations), "max_ops": int(args.max_ops)}},
        )
        return 2

    dry_run = not bool(args.apply)
    single_tx = not bool(args.no_single_tx)
    require_lock = not bool(args.no_lock)
    write_audit = not bool(args.no_audit)

    # Engine
    engine = create_async_engine(
        args.db_url,
        pool_pre_ping=True,
        future=True,
    )

    try:
        logger.info(
            "run_start",
            extra={
                "event": "run_start",
                "patch_id": patch_id,
                "details": {
                    "dry_run": dry_run,
                    "single_tx": single_tx,
                    "require_lock": require_lock,
                    "write_audit": write_audit,
                    "ops": len(operations),
                    "report_path": args.report_path,
                },
            },
        )

        return await run_patch(
            engine=engine,
            patch_id=patch_id,
            operations=operations,
            notes=notes,
            dry_run=dry_run,
            single_tx=single_tx,
            require_lock=require_lock,
            write_audit=write_audit,
            output_report_path=args.report_path,
        )
    finally:
        await engine.dispose()


def main() -> None:
    try:
        code = asyncio.run(main_async(sys.argv[1:]))
    except KeyboardInterrupt:
        code = 130
    except SQLAlchemyError as e:
        setup_logging(verbose=True)
        logger.error("sqlalchemy_error", extra={"event": "sqlalchemy_error", "details": {"error": str(e)}}, exc_info=True)
        code = 1
    except Exception as e:
        setup_logging(verbose=True)
        logger.error("fatal_error", extra={"event": "fatal_error", "details": {"error": str(e)}}, exc_info=True)
        code = 1
    raise SystemExit(code)


if __name__ == "__main__":
    main()
