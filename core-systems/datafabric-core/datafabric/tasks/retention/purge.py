# datafabric/tasks/retention/purge.py
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple

from datetime import datetime, timedelta, timezone

# Internal utilities (предполагается наличие данных модулей из предыдущих шагов)
try:
    from datafabric.utils.time import (
        now_utc,
        parse_duration,
        to_utc,
        to_iso8601,
        Deadline,
        TimeBudget,
    )
except Exception:
    # Локальные упрощённые замены, если модуль недоступен (не падать в импорте)
    from datetime import datetime, timezone, timedelta
    def now_utc() -> datetime: return datetime.now(timezone.utc)
    def parse_duration(s): 
        # минимальный парсер секунд
        if isinstance(s, timedelta): return s
        return timedelta(seconds=float(s))
    def to_utc(dt: datetime) -> datetime:
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    def to_iso8601(dt: datetime, with_ms: bool = True) -> str: 
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00","Z")
    class Deadline:
        def __init__(self, timeout: timedelta): self._end = now_utc().timestamp() + timeout.total_seconds()
        @classmethod
        def in_(cls, v): return cls(parse_duration(v))
        def remaining(self) -> float: import time; return max(0.0, self._end - time.time())
        def expired(self) -> bool: return self.remaining() <= 0.0
        def remaining_td(self) -> timedelta: return timedelta(seconds=self.remaining())
    class TimeBudget:
        def __init__(self, total: timedelta): self._d = Deadline(total)
        def take(self, want): import math; w=parse_duration(want).total_seconds(); return timedelta(seconds=min(w, self._d.remaining()))
        def remaining(self): return self._d.remaining_td()
        def expired(self): return self._d.expired()

# Tracing (не обязателен, но желателен)
try:
    from datafabric.observability.tracing import start_span, add_event, set_attributes, trace_function
except Exception:
    # no-op заглушки
    from contextlib import contextmanager
    @contextmanager
    def start_span(name, attributes=None):
        yield object()
    def add_event(name, attributes=None): pass
    def set_attributes(attrs): pass
    def trace_function(name=None, attributes=None):
        def deco(fn): return fn
        return deco

# SQLAlchemy (async только, по требованиям проекта)
try:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
except Exception as exc:
    raise RuntimeError("SQLAlchemy (async) is required for purge task") from exc


# ======================
# Configuration schema
# ======================

DeletionMode = Literal["hard", "soft"]
TargetKind = Literal["postgres"]
DEFAULT_BATCH_SIZE = 5_000

@dataclass
class Rule:
    name: str
    target: TargetKind                  # 'postgres'
    table: str
    ttl: str                            # duration, e.g. "30d"
    timestamp_column: str               # e.g. "created_at" or "event_time"
    mode: DeletionMode                  # 'hard' | 'soft'
    soft_delete_column: Optional[str] = None     # required if mode='soft'
    soft_delete_value: Optional[str] = None      # e.g. 'deleted' or timestamp -> 'NOW()' handled internally
    filter_sql: Optional[str] = None    # extra WHERE predicates (safe if static)
    batch_size: int = DEFAULT_BATCH_SIZE
    vacuum: bool = False                # run VACUUM after hard delete
    drop_partitions_before: Optional[str] = None # duration for dropping partitions entirely (faster than row delete)
    connection_url: Optional[str] = None         # override global DB URL
    safety_allow: bool = False          # must be True to execute (safety guard)

@dataclass
class Config:
    rules: List[Rule] = field(default_factory=list)
    default_connection_url: Optional[str] = None
    parallel: int = 2
    dry_run: bool = True
    max_runtime: Optional[str] = None  # total task wall-clock limit, e.g. "20m"

@dataclass
class RuleReport:
    rule: str
    table: str
    started_at: str
    finished_at: Optional[str] = None
    cutoff_utc: Optional[str] = None
    rows_deleted: int = 0
    rows_marked: int = 0
    partitions_dropped: int = 0
    batches: int = 0
    errors: List[str] = field(default_factory=list)
    dry_run: bool = True
    details: Dict[str, Any] = field(default_factory=dict)


# ======================
# Config loading
# ======================

def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1","true","yes","y","on")

def _load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml  # optional; если нет — поддерживаем только ENV
    except Exception as exc:
        raise RuntimeError(f"YAML requested but PyYAML is not installed: {path}") from exc
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def load_config(path: Optional[str] = None) -> Config:
    """
    Источник правды: YAML при наличии, иначе ENV.
    ENV пример:
      DF_RETENTION_DRY_RUN=true
      DF_RETENTION_PARALLEL=2
      DF_DB_URL=postgresql+asyncpg://user:pass@host:5432/db
      DF_RULES_JSON='[{"name":"logs","target":"postgres","table":"public.logs","ttl":"30d","timestamp_column":"ts","mode":"hard","safety_allow":true}]'
    """
    if path:
        data = _load_yaml(path)
        default_url = data.get("default_connection_url") or os.getenv("DF_DB_URL")
        dry_run = bool(data.get("dry_run", True))
        parallel = int(data.get("parallel", 2))
        max_runtime = data.get("max_runtime")
        rules_in = data.get("rules", [])
    else:
        default_url = os.getenv("DF_DB_URL")
        dry_run = _env_bool("DF_RETENTION_DRY_RUN", True)
        parallel = int(os.getenv("DF_RETENTION_PARALLEL", "2"))
        max_runtime = os.getenv("DF_RETENTION_MAX_RUNTIME")
        rules_json = os.getenv("DF_RULES_JSON", "[]")
        try:
            rules_in = json.loads(rules_json)
        except Exception as exc:
            raise RuntimeError("Invalid DF_RULES_JSON") from exc

    rules: List[Rule] = []
    for r in rules_in:
        rules.append(
            Rule(
                name=r["name"],
                target=r.get("target","postgres"),
                table=r["table"],
                ttl=r["ttl"],
                timestamp_column=r["timestamp_column"],
                mode=r.get("mode","hard"),
                soft_delete_column=r.get("soft_delete_column"),
                soft_delete_value=r.get("soft_delete_value"),
                filter_sql=r.get("filter_sql"),
                batch_size=int(r.get("batch_size", DEFAULT_BATCH_SIZE)),
                vacuum=bool(r.get("vacuum", False)),
                drop_partitions_before=r.get("drop_partitions_before"),
                connection_url=r.get("connection_url"),
                safety_allow=bool(r.get("safety_allow", False)),
            )
        )

    return Config(
        rules=rules,
        default_connection_url=default_url,
        parallel=parallel,
        dry_run=dry_run,
        max_runtime=max_runtime,
    )


# ======================
# PostgreSQL runner
# ======================

class PostgresPurger:
    """
    Реализация очистки для PostgreSQL.
    Поддержка:
      - Пакетное hard delete по cutoff
      - Soft delete через обновление столбца
      - Drop старых партиций целиком (самый быстрый вариант)
    Требования:
      - Наличие простого числового PK 'id' для батчевого удаления (настраиваемо через запрос).
      - timestamp_column индексирован.
    """

    def __init__(self, engine: AsyncEngine, dry_run: bool):
        self.engine = engine
        self.dry_run = dry_run

    async def _table_pk_name(self, schema: str, table: str) -> Optional[str]:
        sql = text(
            """
            SELECT a.attname
            FROM pg_index i
            JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
            WHERE i.indrelid = :reg::regclass
              AND i.indisprimary = true
            LIMIT 1
            """
        )
        reg = f"{schema}.{table}"
        async with self.engine.connect() as conn:
            res = await conn.execute(sql.bindparams(reg=reg))
            row = res.first()
            return row[0] if row else None

    async def _count_candidate_rows(self, fqtn: str, cutoff: datetime, ts_col: str, extra_where: Optional[str]) -> int:
        clause = f"{ts_col} < :cutoff"
        if extra_where:
            clause += f" AND ({extra_where})"
        sql = text(f"SELECT COUNT(*) FROM {fqtn} WHERE {clause}")
        async with self.engine.connect() as conn:
            res = await conn.execute(sql.bindparams(cutoff=cutoff))
            return int(res.scalar_one())

    async def _drop_old_partitions(self, schema: str, table: str, ts_col: str, cutoff: datetime) -> int:
        """
        Пытаемся найти секционированные таблицы и удалить партиции полностью,
        если их верхняя граница < cutoff.
        Работает для RANGE партиционирования по дате/времени.
        """
        dropped = 0
        # Находим дочерние партиции и их границы
        sql_list = text(
            """
            SELECT
              nmsp_child.nspname as child_schema,
              child.relname as child_table,
              pg_get_expr(pg_class.relpartbound, child.oid) as bound
            FROM pg_inherits
            JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
            JOIN pg_class child  ON pg_inherits.inhrelid = child.oid
            JOIN pg_namespace nmsp_parent ON nmsp_parent.oid = parent.relnamespace
            JOIN pg_namespace nmsp_child  ON nmsp_child.oid  = child.relnamespace
            JOIN pg_class ON pg_class.oid = child.oid
            WHERE nmsp_parent.nspname = :schema AND parent.relname = :table
            """
        )
        async with self.engine.begin() as conn:
            res = await conn.execute(sql_list.bindparams(schema=schema, table=table))
            parts = res.fetchall()

        for (child_schema, child_table, bound_expr) in parts:
            # Пример bound_expr: FOR VALUES FROM ('2025-01-01') TO ('2025-02-01')
            # Эвристика: извлечь верхнюю границу и сравнить с cutoff
            upper = _parse_partition_upper(bound_expr)
            if upper and upper <= cutoff:
                fq = f'"{child_schema}"."{child_table}"'
                if self.dry_run:
                    dropped += 1
                    add_event("partition.drop.dry_run", {"table": fq})
                    continue
                async with self.engine.begin() as conn:
                    await conn.execute(text(f'DROP TABLE IF EXISTS {fq}'))
                dropped += 1
                add_event("partition.drop", {"table": fq})
        return dropped

    async def purge(self, rule: Rule, cutoff: datetime, time_budget: Optional[TimeBudget]) -> RuleReport:
        schema, table = _split_schema_table(rule.table)
        fqtn = f'"{schema}"."{table}"'
        report = RuleReport(
            rule=rule.name,
            table=rule.table,
            started_at=to_iso8601(now_utc()),
            cutoff_utc=to_iso8601(cutoff),
            dry_run=self.dry_run
        )

        with start_span("retention.postgres.rule", {"rule": rule.name, "table": rule.table}):
            # 1) Parition drop (если указано)
            if rule.drop_partitions_before:
                part_cutoff = now_utc() - parse_duration(rule.drop_partitions_before)
                with start_span("retention.postgres.drop_partitions", {"table": rule.table, "cutoff": to_iso8601(part_cutoff)}):
                    try:
                        dropped = await self._drop_old_partitions(schema, table, rule.timestamp_column, part_cutoff)
                        report.partitions_dropped = dropped
                    except Exception as exc:
                        msg = f"partition_drop_error: {exc}"
                        report.errors.append(msg)
                        add_event("partition.drop.error", {"error": str(exc)})

            # 2) Row-level purge
            with start_span("retention.postgres.rows", {"table": rule.table}):
                try:
                    candidates = await self._count_candidate_rows(fqtn, cutoff, rule.timestamp_column, rule.filter_sql)
                    report.details["candidates"] = candidates
                except Exception as exc:
                    report.errors.append(f"count_error: {exc}")
                    report.finished_at = to_iso8601(now_utc())
                    return report

                if candidates == 0:
                    report.finished_at = to_iso8601(now_utc())
                    return report

                if self.dry_run:
                    # Только считаем и выходим
                    report.finished_at = to_iso8601(now_utc())
                    return report

                # Безопасность: батчи по PK (если есть)
                pk = await self._table_pk_name(schema, table)
                if not pk and rule.mode == "hard":
                    # при hard delete без PK делаем ограниченные батчи по ts колонки
                    pk = None

                batch_size = max(1, int(rule.batch_size))
                consumed = 0
                while consumed < candidates:
                    if time_budget and time_budget.expired():
                        report.errors.append("time_budget_expired")
                        break
                    with start_span("retention.postgres.batch", {"size": batch_size}):
                        if rule.mode == "soft":
                            n = await self._batch_soft_delete(fqtn, rule, cutoff, batch_size, pk)
                            report.rows_marked += n
                        else:
                            n = await self._batch_hard_delete(fqtn, rule, cutoff, batch_size, pk)
                            report.rows_deleted += n
                        report.batches += 1
                        if n == 0:
                            break
                        consumed += n

                # VACUUM после hard delete
                if rule.mode == "hard" and rule.vacuum:
                    try:
                        async with self.engine.begin() as conn:
                            await conn.execute(text(f"VACUUM (VERBOSE, ANALYZE) {fqtn}"))
                    except Exception as exc:
                        report.errors.append(f"vacuum_error: {exc}")

        report.finished_at = to_iso8601(now_utc())
        return report

    async def _batch_hard_delete(self, fqtn: str, rule: Rule, cutoff: datetime, limit: int, pk: Optional[str]) -> int:
        clause = f"{rule.timestamp_column} < :cutoff"
        if rule.filter_sql:
            clause += f" AND ({rule.filter_sql})"

        if pk:
            # Удаляем ограниченно по PK, получая список id
            sub = text(f"SELECT {pk} FROM {fqtn} WHERE {clause} ORDER BY {pk} ASC LIMIT :lim")
            del_sql = text(f"DELETE FROM {fqtn} WHERE {pk} = ANY(:ids)")
            async with self.engine.begin() as conn:
                res = await conn.execute(sub.bindparams(cutoff=cutoff, lim=limit))
                ids = [row[0] for row in res.fetchall()]
                if not ids:
                    return 0
                await conn.execute(del_sql.bindparams(ids=ids))
                return len(ids)
        else:
            # Без PK — ограниченное удаление по ts с RETURNING (PostgreSQL)
            del_sql = text(f"DELETE FROM {fqtn} WHERE {clause} RETURNING 1 LIMIT :lim")  # LIMIT в RETURNING не поддерживается напрямую
            # Обходное решение: CTE
            del_sql = text(
                f"""
                WITH cte AS (
                  SELECT ctid FROM {fqtn}
                  WHERE {clause}
                  ORDER BY {rule.timestamp_column} ASC
                  LIMIT :lim
                )
                DELETE FROM {fqtn}
                WHERE ctid IN (SELECT ctid FROM cte)
                """
            )
            async with self.engine.begin() as conn:
                res = await conn.execute(del_sql.bindparams(cutoff=cutoff, lim=limit))
                # SQLAlchemy не всегда возвращает rowcount корректно на asyncpg; считаем примерно
                return res.rowcount if res.rowcount is not None else min(limit, 10**9)

    async def _batch_soft_delete(self, fqtn: str, rule: Rule, cutoff: datetime, limit: int, pk: Optional[str]) -> int:
        if not rule.soft_delete_column:
            raise ValueError(f"Rule {rule.name}: soft_delete_column is required for soft mode")

        clause = f"{rule.timestamp_column} < :cutoff"
        if rule.filter_sql:
            clause += f" AND ({rule.filter_sql})"

        set_expr = f"{rule.soft_delete_column} = NOW() AT TIME ZONE 'UTC'"
        if rule.soft_delete_value and rule.soft_delete_value.lower() not in ("now()", "now"):
            set_expr = f"{rule.soft_delete_column} = :sdv"

        if pk:
            sub = text(f"SELECT {pk} FROM {fqtn} WHERE {clause} AND {rule.soft_delete_column} IS NULL ORDER BY {pk} ASC LIMIT :lim")
            upd = text(f"UPDATE {fqtn} SET {set_expr} WHERE {pk} = ANY(:ids)")
            async with self.engine.begin() as conn:
                res = await conn.execute(sub.bindparams(cutoff=cutoff, lim=limit))
                ids = [row[0] for row in res.fetchall()]
                if not ids:
                    return 0
                if "sdv" in upd._bindnames:  # type: ignore
                    await conn.execute(upd.bindparams(ids=ids, sdv=rule.soft_delete_value))
                else:
                    await conn.execute(upd.bindparams(ids=ids))
                return len(ids)
        else:
            # CTE ограничение по ctid
            upd = text(
                f"""
                WITH cte AS (
                  SELECT ctid FROM {fqtn}
                  WHERE {clause}
                    AND {rule.soft_delete_column} IS NULL
                  ORDER BY {rule.timestamp_column} ASC
                  LIMIT :lim
                )
                UPDATE {fqtn}
                SET {set_expr}
                WHERE ctid IN (SELECT ctid FROM cte)
                """
            )
            async with self.engine.begin() as conn:
                if "sdv" in upd._bindnames:  # type: ignore
                    res = await conn.execute(upd.bindparams(cutoff=cutoff, lim=limit, sdv=rule.soft_delete_value))
                else:
                    res = await conn.execute(upd.bindparams(cutoff=cutoff, lim=limit))
                return res.rowcount if res.rowcount is not None else min(limit, 10**9)


# ======================
# Orchestrator
# ======================

class RetentionTask:
    """
    Оркестратор выполнения набора правил с параллелизмом и ограничением по времени.
    """

    def __init__(self, config: Config):
        self.config = config

    async def _engine(self, url: str) -> AsyncEngine:
        return create_async_engine(url, pool_size=5, max_overflow=5, pool_pre_ping=True)

    async def _run_rule(self, rule: Rule, global_url: Optional[str], deadline: Optional[Deadline]) -> RuleReport:
        with start_span("retention.rule.start", {"rule": rule.name, "table": rule.table}):
            if not rule.safety_allow:
                rep = RuleReport(rule=rule.name, table=rule.table, started_at=to_iso8601(now_utc()), dry_run=self.config.dry_run)
                rep.errors.append("safety_allow=false")
                rep.finished_at = to_iso8601(now_utc())
                return rep

            url = rule.connection_url or global_url
            if not url:
                rep = RuleReport(rule=rule.name, table=rule.table, started_at=to_iso8601(now_utc()), dry_run=self.config.dry_run)
                rep.errors.append("connection_url_not_set")
                rep.finished_at = to_iso8601(now_utc())
                return rep

            cutoff = now_utc() - parse_duration(rule.ttl)
            set_attributes({"cutoff": to_iso8601(cutoff)})

            engine = await self._engine(url)
            try:
                time_budget = TimeBudget(parse_duration(self.config.max_runtime)) if self.config.max_runtime else None
                purger = PostgresPurger(engine, self.config.dry_run)
                report = await purger.purge(rule, cutoff, time_budget)
                return report
            finally:
                await engine.dispose()

    async def run(self, only_rule: Optional[str] = None) -> Dict[str, Any]:
        started = now_utc()
        reports: List[RuleReport] = []
        errors: List[str] = []

        rules = [r for r in self.config.rules if (only_rule is None or r.name == only_rule)]
        if not rules:
            return {
                "started_at": to_iso8601(started),
                "finished_at": to_iso8601(now_utc()),
                "reports": [],
                "errors": ["no_rules_selected"],
                "dry_run": self.config.dry_run,
            }

        sem = asyncio.Semaphore(max(1, int(self.config.parallel)))

        async def worker(rule: Rule):
            async with sem:
                try:
                    rep = await self._run_rule(rule, self.config.default_connection_url, None)
                    reports.append(rep)
                except Exception as exc:
                    errors.append(f"{rule.name}: {exc}")

        await asyncio.gather(*(worker(r) for r in rules))

        return {
            "started_at": to_iso8601(started),
            "finished_at": to_iso8601(now_utc()),
            "reports": [rep.__dict__ for rep in reports],
            "errors": errors,
            "dry_run": self.config.dry_run,
        }


# ======================
# Helpers
# ======================

def _split_schema_table(fq: str) -> Tuple[str, str]:
    if "." in fq and not fq.strip().startswith('"'):
        s, t = fq.split(".", 1)
        return s.strip(), t.strip()
    # already quoted or no schema -> public
    return "public", fq.replace('"','').strip()

def _parse_partition_upper(bound_expr: str) -> Optional[datetime]:
    """
    Пример: "FOR VALUES FROM ('2025-06-01') TO ('2025-07-01')"
    Возвращает верхнюю границу как aware UTC datetime на 00:00:00.
    """
    if not bound_expr:
        return None
    import re
    m = re.search(r"TO\s*\(\s*'([^']+)'\s*\)", bound_expr, re.IGNORECASE)
    if not m:
        return None
    txt = m.group(1)
    try:
        # Дата без времени
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", txt):
            y, M, d = map(int, txt.split("-"))
            return datetime(y, M, d, tzinfo=timezone.utc)
        # Полная дата-время
        dt = datetime.fromisoformat(txt.replace("Z","+00:00"))
        return to_utc(dt)
    except Exception:
        return None


# ======================
# CLI
# ======================

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DataFabric Retention/Purge Task (async, PostgreSQL)")
    p.add_argument("--config", type=str, default=os.getenv("DF_RETENTION_CONFIG"), help="Path to YAML config")
    p.add_argument("--rule", type=str, default=None, help="Run only this rule by name")
    p.add_argument("--apply", action="store_true", help="Apply changes (disable dry-run)")
    p.add_argument("--parallel", type=int, default=None, help="Override parallelism")
    return p

async def _main_async(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.parallel is not None:
        cfg.parallel = max(1, int(args.parallel))
    if args.apply:
        cfg.dry_run = False

    with start_span("retention.run", {"dry_run": cfg.dry_run, "parallel": cfg.parallel}):
        result = await RetentionTask(cfg).run(only_rule=args.rule)
        # Печать итогов в stdout (JSON)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    # exit code: 0 если нет ошибок критичных
    has_errors = bool(result.get("errors")) or any(rep.get("errors") for rep in result.get("reports", []))
    return 1 if has_errors else 0

def main() -> None:
    args = _build_arg_parser().parse_args()
    code = asyncio.run(_main_async(args))
    sys.exit(code)

if __name__ == "__main__":
    main()
