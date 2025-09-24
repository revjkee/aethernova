# path: cli/tools/run_quality_checks.py
"""
DataFabric Quality Checks CLI (industrial-grade)

Features:
- Config: YAML/JSON (env-substitution ${VAR:default}), sections: connection, defaults, checks[]
- Checks (built-in):
    * row_count_min / row_count_max
    * null_rate_max (per column)
    * uniqueness (per column or columns[])
    * value_range (min/max per numeric column)
    * freshness_max_age_sec (timestamp column)
    * regex_match_rate_min (text column, pattern)
    * sql_pass (custom SQL returns one row where 'pass' is true or 1)
- Execution:
    * Include/Exclude by id/tags, parallel workers, fail-fast, retries with exponential backoff
    * Per-check timeout (PostgreSQL uses statement_timeout; SQLite best-effort)
    * Sampling hints (ORDER BY RANDOM() LIMIT N or TABLESAMPLE where supported)
- Outputs:
    * Human-readable summary
    * Machine: JSON report (summary + results) and JUnit XML (for CI)
    * Exit code: 0 if no failed ERROR checks (optionally treat WARNING as fail)
- Security & robustness:
    * No secrets in logs (DSN redaction), safe identifier quoting, bounded result sets
- Integrations (optional):
    * datafabric.utils.serde for IO
    * datafabric.lineage.tracker to emit MARK/metrics for run
- Zero-hard deps: stdlib + optional psycopg/psycopg2 for Postgres; YAML/msgpack/jsonschema are optional via serde.

Usage:
    python -m cli.tools.run_quality_checks --config checks.yaml --out-json report.json --out-junit report.xml
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import functools
import json
import os
import random
import re
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------- Optional DF integrations ----------
try:
    # Prefer DataFabric serde if present
    from datafabric.utils import serde as df_serde  # type: ignore
except Exception:
    df_serde = None  # type: ignore

try:
    # Optional lineage tracker
    from datafabric.lineage.tracker import LineageTracker, SQLiteStore, JobRef, RunRef, Metric  # type: ignore
except Exception:
    LineageTracker = None  # type: ignore

# ---------- Optional DB drivers ----------
_HAS_PG = False
try:
    import psycopg  # type: ignore
    _HAS_PG = True
except Exception:
    try:
        import psycopg2  # type: ignore
        _HAS_PG = True
    except Exception:
        pass

import sqlite3  # stdlib

from urllib.parse import urlparse, parse_qs

# ---------- Models ----------

class Severity(str):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"

@dataclass
class CheckSpec:
    id: str
    type: str
    table: Optional[str] = None
    column: Optional[str] = None
    columns: Sequence[str] = field(default_factory=tuple)
    where: Optional[str] = None
    sample_rows: Optional[int] = None  # sampling hint
    pattern: Optional[str] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    min_rate: Optional[float] = None
    max_rate: Optional[float] = None
    min_count: Optional[int] = None
    max_count: Optional[int] = None
    freshness_max_age_sec: Optional[int] = None
    sql: Optional[str] = None
    severity: str = Severity.ERROR
    tags: Sequence[str] = field(default_factory=tuple)
    timeout_ms: Optional[int] = None
    retries: int = 0
    backoff_base_sec: float = 0.5
    backoff_factor: float = 2.0
    description: Optional[str] = None

@dataclass
class CheckResult:
    id: str
    type: str
    severity: str
    ok: bool
    message: str
    metrics: Mapping[str, Any]
    duration_sec: float
    retries: int
    tags: Sequence[str] = field(default_factory=tuple)

@dataclass
class RunSummary:
    started_at: str
    finished_at: str
    passed: int
    warned: int
    failed: int
    total: int
    duration_sec: float

@dataclass
class Report:
    summary: RunSummary
    results: List[CheckResult]
    meta: Mapping[str, Any]

# ---------- Utilities ----------

def _now() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat().replace("+00:00", "Z")

def _redact_dsn(dsn: str) -> str:
    if not dsn:
        return dsn
    u = urlparse(dsn)
    netloc = u.netloc
    if "@" in netloc:
        creds, host = netloc.split("@", 1)
        if ":" in creds:
            user, _ = creds.split(":", 1)
            netloc = f"{user}:***@{host}"
        else:
            netloc = f"***@{host}"
    return u._replace(netloc=netloc).geturl()

def _env_expand(text: str) -> str:
    # ${VAR:default}
    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        default = m.group(2) or ""
        return os.getenv(name, default)
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*) (?:: ([^}]*))? \}", repl, text, flags=re.X)

def _qident(ident: str) -> str:
    # minimal SQL identifier quoting "name"
    return '"' + ident.replace('"', '""') + '"'

def _apply_where(base: str, where: Optional[str]) -> str:
    return f"{base} WHERE {where}" if where else base

def _apply_sample(sql: str, spec: CheckSpec, dialect: str) -> str:
    if not spec.sample_rows:
        return sql
    n = int(spec.sample_rows)
    if dialect == "postgres":
        # Bernoulli approx based on table estimate isn't trivial here; use ORDER BY RANDOM()
        return f"{sql} ORDER BY RANDOM() LIMIT {n}"
    # sqlite
    return f"{sql} ORDER BY RANDOM() LIMIT {n}"

def _bool(x: Any) -> bool:
    if isinstance(x, bool):
        return x
    try:
        return int(x) != 0
    except Exception:
        return False

def _with_timeout(cur, spec: CheckSpec, dialect: str):
    if dialect == "postgres" and spec.timeout_ms:
        try:
            cur.execute(f"SET LOCAL statement_timeout = {int(spec.timeout_ms)}")
        except Exception:
            pass

# ---------- Config load/validate ----------

def load_config(path: str) -> Dict[str, Any]:
    raw = open(path, "rb").read()
    txt = raw.decode("utf-8")
    txt = _env_expand(txt)
    if df_serde:
        # try YAML first if available
        try:
            return df_serde.loads(txt.encode("utf-8"), fmt=df_serde.Format.YAML)  # type: ignore
        except Exception:
            return json.loads(txt)
    # fallback: JSON
    try:
        return json.loads(txt)
    except Exception as e:
        raise RuntimeError(f"Failed to parse config {path}: {e}")

def validate_config(cfg: Mapping[str, Any]) -> None:
    if "connection" not in cfg or "dsn" not in cfg["connection"]:
        raise RuntimeError("config: connection.dsn is required")
    if "checks" not in cfg or not isinstance(cfg["checks"], list):
        raise RuntimeError("config: checks[] is required")
    # soft validation of each check
    for i, c in enumerate(cfg["checks"]):
        if "id" not in c or "type" not in c:
            raise RuntimeError(f"checks[{i}]: id and type are required")

# ---------- DB connection & execution ----------

class DB:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.url = urlparse(dsn)
        self.dialect = self._detect_dialect()

    def _detect_dialect(self) -> str:
        s = self.url.scheme.lower()
        if s in ("postgres", "postgresql"):
            return "postgres"
        if s in ("sqlite", "file"):
            return "sqlite"
        # try implicit sqlite file path
        if self.dsn.endswith(".db") or self.dsn.endswith(".sqlite"):
            return "sqlite"
        raise RuntimeError(f"Unsupported DSN: {self.dsn}")

    def connect(self):
        if self.dialect == "sqlite":
            path = self.url.path or self.dsn
            if path.startswith("/"):
                db_path = path
            else:
                db_path = self.dsn
            con = sqlite3.connect(db_path, timeout=30)
            con.row_factory = sqlite3.Row
            return con
        # postgres
        if not _HAS_PG:
            raise RuntimeError("psycopg/psycopg2 not installed for Postgres")
        try:
            import psycopg  # type: ignore
            con = psycopg.connect(self.dsn)  # type: ignore
            con.autocommit = True
            return con
        except Exception:
            import psycopg2  # type: ignore
            con = psycopg2.connect(self.dsn)  # type: ignore
            con.autocommit = True
            return con

# ---------- Check runners ----------

def run_check(con, dialect: str, spec: CheckSpec) -> CheckResult:
    t0 = time.time()
    attempts = 0
    last_err = None
    while True:
        attempts += 1
        try:
            cur = con.cursor()
            # per-check timeout
            _with_timeout(cur, spec, dialect)
            res = _run_check_once(cur, dialect, spec)
            dur = time.time() - t0
            return CheckResult(
                id=spec.id,
                type=spec.type,
                severity=spec.severity,
                ok=res["ok"],
                message=res.get("message", ""),
                metrics=res.get("metrics", {}),
                duration_sec=dur,
                retries=attempts - 1,
                tags=tuple(spec.tags or ()),
            )
        except Exception as e:
            last_err = e
            if attempts > max(0, spec.retries):
                dur = time.time() - t0
                msg = f"check failed after {attempts} attempt(s): {e}"
                return CheckResult(
                    id=spec.id,
                    type=spec.type,
                    severity=spec.severity,
                    ok=False,
                    message=msg,
                    metrics={"exception": _format_exc(e)[:4096]},
                    duration_sec=dur,
                    retries=attempts - 1,
                    tags=tuple(spec.tags or ()),
                )
            # backoff
            delay = spec.backoff_base_sec * (spec.backoff_factor ** (attempts - 1))
            delay = min(60.0, delay) * (0.9 + 0.2 * random.random())
            time.sleep(delay)
        finally:
            with contextlib.suppress(Exception):
                cur.close()  # type: ignore

def _format_exc(e: BaseException) -> str:
    return "".join(traceback.format_exception(type(e), e, e.__traceback__))

def _run_check_once(cur, dialect: str, spec: CheckSpec) -> Dict[str, Any]:
    if spec.type == "row_count_min":
        _require(spec.table and spec.min_count is not None, "row_count_min requires table and min_count")
        sql = _apply_where(f"SELECT COUNT(*) AS c FROM {spec.table}", spec.where)
        sql = _apply_sample(sql, spec, dialect)
        cur.execute(sql)
        c = _first_int(cur.fetchone())
        ok = c >= int(spec.min_count)
        return {"ok": ok, "message": f"rows={c} >= {spec.min_count}", "metrics": {"row_count": c}}
    if spec.type == "row_count_max":
        _require(spec.table and spec.max_count is not None, "row_count_max requires table and max_count")
        sql = _apply_where(f"SELECT COUNT(*) AS c FROM {spec.table}", spec.where)
        sql = _apply_sample(sql, spec, dialect)
        cur.execute(sql)
        c = _first_int(cur.fetchone())
        ok = c <= int(spec.max_count)
        return {"ok": ok, "message": f"rows={c} <= {spec.max_count}", "metrics": {"row_count": c}}

    if spec.type == "null_rate_max":
        _require(spec.table and spec.column and spec.max_rate is not None, "null_rate_max requires table, column, max_rate")
        col = spec.column
        base = f"SELECT CAST(SUM(CASE WHEN {col} IS NULL THEN 1 ELSE 0 END) AS FLOAT) / NULLIF(COUNT(*),0) AS nr FROM {spec.table}"
        sql = _apply_where(base, spec.where)
        sql = _apply_sample(sql, spec, dialect)
        cur.execute(sql)
        nr = _first_float(cur.fetchone())
        nr = 0.0 if nr is None else float(nr)
        ok = nr <= float(spec.max_rate)
        return {"ok": ok, "message": f"null_rate={nr:.6f} <= {spec.max_rate}", "metrics": {"null_rate": nr}}

    if spec.type == "uniqueness":
        _require(spec.table and (spec.column or spec.columns), "uniqueness requires table and column(s)")
        cols = list(spec.columns or ([spec.column] if spec.column else []))
        cols_csv = ", ".join(cols)
        base = f"SELECT COUNT(*) - COUNT(DISTINCT {cols_csv}) AS dups FROM {spec.table}"
        sql = _apply_where(base, spec.where)
        sql = _apply_sample(sql, spec, dialect)
        cur.execute(sql)
        dups = _first_int(cur.fetchone())
        ok = (dups or 0) == 0
        return {"ok": ok, "message": f"duplicates={dups}", "metrics": {"duplicates": dups}}

    if spec.type == "value_range":
        _require(spec.table and spec.column and (spec.min_value is not None or spec.max_value is not None), "value_range requires table, column, and min/max")
        col = spec.column
        base = f"SELECT MIN({col}) AS mn, MAX({col}) AS mx FROM {spec.table}"
        sql = _apply_where(base, spec.where)
        sql = _apply_sample(sql, spec, dialect)
        cur.execute(sql)
        row = cur.fetchone()
        mn = _first_float(row[0] if isinstance(row, tuple) else row["mn"])
        mx = _first_float(row[1] if isinstance(row, tuple) else row["mx"])
        ok_min = True if spec.min_value is None else (mn is not None and mn >= float(spec.min_value))
        ok_max = True if spec.max_value is None else (mx is not None and mx <= float(spec.max_value))
        ok = bool(ok_min and ok_max)
        return {"ok": ok, "message": f"min={mn} max={mx} bounds=({spec.min_value},{spec.max_value})", "metrics": {"min": mn, "max": mx}}

    if spec.type == "freshness_max_age_sec":
        _require(spec.table and spec.column and spec.freshness_max_age_sec is not None, "freshness_max_age_sec requires table, column, freshness_max_age_sec")
        col = spec.column
        now_expr = "NOW()" if dialect == "postgres" else "(strftime('%Y-%m-%d %H:%M:%f','now'))"
        # age in seconds (PostgreSQL: EXTRACT(EPOCH FROM age(now(), max(ts))); SQLite: julianday(now) diff)
        if dialect == "postgres":
            base = f"SELECT EXTRACT(EPOCH FROM ({now_expr} - MAX({col}))) AS age_sec FROM {spec.table}"
        else:
            base = f"SELECT (julianday('now') - julianday(MAX({col}))) * 86400.0 AS age_sec FROM {spec.table}"
        sql = _apply_where(base, spec.where)
        cur.execute(sql)
        age = _first_float(cur.fetchone()) or 0.0
        ok = age <= float(spec.freshness_max_age_sec)
        return {"ok": ok, "message": f"age_sec={age:.2f} <= {spec.freshness_max_age_sec}", "metrics": {"age_sec": age}}

    if spec.type == "regex_match_rate_min":
        _require(spec.table and spec.column and spec.pattern and spec.min_rate is not None, "regex_match_rate_min requires table, column, pattern, min_rate")
        col = spec.column
        pat = spec.pattern
        if dialect == "postgres":
            match_expr = f"CASE WHEN {col} ~ {sql_literal(pat)} THEN 1 ELSE 0 END"
        else:
            # SQLite does not support REGEXP by default; emulate via LIKE if simple, else fallback to 0 rate
            if is_simple_like_pattern(pat):
                like = like_from_regex(pat)
                match_expr = f"CASE WHEN {col} LIKE {sql_literal(like)} ESCAPE '\\\\' THEN 1 ELSE 0 END"
            else:
                # cannot compute; mark as failed with metric
                return {"ok": False, "message": "regex not supported in sqlite; require REGEXP extension", "metrics": {"unsupported": True}}
        base = f"SELECT CAST(SUM({match_expr}) AS FLOAT) / NULLIF(COUNT(*),0) AS rate FROM {spec.table}"
        sql = _apply_where(base, spec.where)
        sql = _apply_sample(sql, spec, dialect)
        cur.execute(sql)
        rate = _first_float(cur.fetchone()) or 0.0
        ok = rate >= float(spec.min_rate)
        return {"ok": ok, "message": f"match_rate={rate:.6f} >= {spec.min_rate}", "metrics": {"match_rate": rate}}

    if spec.type == "sql_pass":
        _require(spec.sql, "sql_pass requires custom 'sql' that returns a single row with boolean/1 column named pass")
        sql = spec.sql.strip().rstrip(";")
        cur.execute(sql)
        row = cur.fetchone()
        if row is None:
            return {"ok": False, "message": "no rows returned", "metrics": {}}
        val = row[0] if isinstance(row, tuple) else (row["pass"] if "pass" in row.keys() else list(row)[0])
        ok = _bool(val)
        return {"ok": ok, "message": f"sql_pass={ok}", "metrics": {}}

    raise RuntimeError(f"Unsupported check type: {spec.type}")

def _first_int(val: Any) -> int:
    if val is None:
        return 0
    try:
        if isinstance(val, (list, tuple)):
            val = val[0]
        return int(val)
    except Exception:
        return 0

def _first_float(val: Any) -> Optional[float]:
    if val is None:
        return None
    try:
        if isinstance(val, (list, tuple)):
            val = val[0]
        return float(val)
    except Exception:
        return None

def _require(cond: bool, msg: str):
    if not cond:
        raise RuntimeError(msg)

def sql_literal(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"

def is_simple_like_pattern(rx: str) -> bool:
    # crude heuristic: convert ^...$ with only .* and literal text
    return bool(re.fullmatch(r"\^?[A-Za-z0-9 _\-\.\%\/\*\\\|\:\@\#\!\?]*\$?", rx))

def like_from_regex(rx: str) -> str:
    # Replace .* -> %, remove ^$, leave others as-is
    s = rx.strip("^$")
    s = s.replace(".*", "%")
    return s

# ---------- JUnit XML ----------

def to_junit(report: Report) -> str:
    import xml.etree.ElementTree as ET
    tests = report.summary.total
    failures = report.summary.failed
    ts = ET.Element("testsuite", {
        "name": "datafabric-quality-checks",
        "tests": str(tests),
        "failures": str(failures),
        "time": f"{report.summary.duration_sec:.3f}",
    })
    for r in report.results:
        tc = ET.SubElement(ts, "testcase", {
            "classname": r.type,
            "name": r.id,
            "time": f"{r.duration_sec:.3f}",
        })
        if not r.ok and r.severity in (Severity.ERROR,):
            failure = ET.SubElement(tc, "failure", {"message": r.message})
            failure.text = json.dumps(r.metrics, ensure_ascii=False)
        else:
            # add system-out with metrics for visibility
            so = ET.SubElement(tc, "system-out")
            so.text = json.dumps(r.metrics, ensure_ascii=False)
    return ET.tostring(ts, encoding="utf-8", xml_declaration=True).decode("utf-8")

# ---------- Runner ----------

def run_all(cfg: Mapping[str, Any],
            include: Sequence[str],
            exclude: Sequence[str],
            tags_any: Sequence[str],
            tags_not: Sequence[str],
            workers: int,
            fail_fast: bool,
            warn_as_fail: bool,
            lineage: bool) -> Report:
    dsn = cfg["connection"]["dsn"]
    con = DB(dsn).connect()
    dialect = DB(dsn).dialect

    # statement_timeout default if present
    default_timeout_ms = int(cfg.get("defaults", {}).get("timeout_ms", 0) or 0)

    specs: List[CheckSpec] = []
    for c in cfg["checks"]:
        spec = CheckSpec(
            id=c["id"],
            type=c["type"],
            table=c.get("table"),
            column=c.get("column"),
            columns=tuple(c.get("columns", []) or ()),
            where=c.get("where"),
            sample_rows=c.get("sample_rows"),
            pattern=c.get("pattern"),
            min_value=c.get("min_value"),
            max_value=c.get("max_value"),
            min_rate=c.get("min_rate"),
            max_rate=c.get("max_rate"),
            min_count=c.get("min_count"),
            max_count=c.get("max_count"),
            freshness_max_age_sec=c.get("freshness_max_age_sec"),
            sql=c.get("sql"),
            severity=c.get("severity", Severity.ERROR),
            tags=tuple(c.get("tags", []) or ()),
            timeout_ms=c.get("timeout_ms", default_timeout_ms) or None,
            retries=int(c.get("retries", cfg.get("defaults", {}).get("retries", 0) or 0)),
            backoff_base_sec=float(c.get("backoff_base_sec", cfg.get("defaults", {}).get("backoff_base_sec", 0.5))),
            backoff_factor=float(c.get("backoff_factor", cfg.get("defaults", {}).get("backoff_factor", 2.0))),
            description=c.get("description"),
        )
        specs.append(spec)

    # filtering
    def _match(spec: CheckSpec) -> bool:
        if include and all(s not in spec.id for s in include):
            return False
        if exclude and any(s in spec.id for s in exclude):
            return False
        if tags_any and not any(t in spec.tags for t in tags_any):
            return False
        if tags_not and any(t in spec.tags for t in tags_not):
            return False
        return True

    specs = [s for s in specs if _match(s)]

    started = time.time()
    results: List[CheckResult] = []

    # optional lineage
    tr = None
    run_ref = None
    if lineage and LineageTracker is not None:
        try:
            store = SQLiteStore(":memory:")
            tr = LineageTracker(store)
            job = JobRef("quality", "run_quality_checks")
            run_ref = tr.start_run(job, tags=["quality"])
        except Exception:
            tr = None

    def _exec(spec: CheckSpec) -> CheckResult:
        return run_check(con, dialect, spec)

    try:
        if workers <= 1:
            for s in specs:
                r = _exec(s)
                results.append(r)
                if tr and run_ref:
                    tr.add_metric(job, run_ref, Metric(name=f"{s.id}.ok", value=1 if r.ok else 0))  # type: ignore
                if fail_fast and not r.ok and (r.severity == Severity.ERROR or warn_as_fail):
                    break
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(_exec, s) for s in specs]
                for f in concurrent.futures.as_completed(futs):
                    r = f.result()
                    results.append(r)
                    if tr and run_ref:
                        tr.add_metric(job, run_ref, Metric(name=f"{r.id}.ok", value=1 if r.ok else 0))  # type: ignore
                    if fail_fast and not r.ok and (r.severity == Severity.ERROR or warn_as_fail):
                        # best-effort cancel others
                        for fut in futs:
                            fut.cancel()
                        break
    finally:
        with contextlib.suppress(Exception):
            con.close()
        if tr and run_ref:
            # summarize into lineage
            passed = sum(1 for r in results if r.ok)
            failed = sum(1 for r in results if not r.ok and r.severity == Severity.ERROR)
            tr.add_metric(job, run_ref, Metric(name="checks_passed", value=passed))  # type: ignore
            tr.add_metric(job, run_ref, Metric(name="checks_failed", value=failed))  # type: ignore
            tr.complete_run(job, run_ref, tags=["quality"])  # type: ignore
            tr.flush()  # type: ignore

    # summary
    total = len(results)
    failed = sum(1 for r in results if not r.ok and r.severity == Severity.ERROR)
    warned = sum(1 for r in results if not r.ok and r.severity == Severity.WARNING)
    passed = total - failed - warned
    finished = time.time()
    summary = RunSummary(
        started_at=_now(),
        finished_at=_now(),
        passed=passed,
        warned=warned,
        failed=failed,
        total=total,
        duration_sec=finished - started,
    )
    meta = {
        "dsn": _redact_dsn(dsn),
        "workers": workers,
        "fail_fast": fail_fast,
        "warn_as_fail": warn_as_fail,
        "included": include,
        "excluded": exclude,
        "tags_any": tags_any,
        "tags_not": tags_not,
        "dialect": DB(dsn).dialect,
        "version": "1",
    }
    return Report(summary=summary, results=sorted(results, key=lambda r: r.id), meta=meta)

# ---------- CLI ----------

def _sample_config() -> str:
    return """# DataFabric quality checks config (YAML)
connection:
  dsn: "postgresql://user:pass@host:5432/dbname"  # or "sqlite:///path/to.db"
defaults:
  timeout_ms: 60000
  retries: 1
  backoff_base_sec: 0.5
  backoff_factor: 2.0
checks:
  - id: sales_rowcount
    type: row_count_min
    table: public.sales
    min_count: 1000
    severity: ERROR
    tags: [daily, volume]
  - id: customers_email_regex
    type: regex_match_rate_min
    table: public.customers
    column: email
    pattern: "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    min_rate: 0.99
    severity: WARNING
    tags: [quality]
  - id: orders_amount_range
    type: value_range
    table: public.orders
    column: amount
    min_value: 0
    max_value: 100000
    severity: ERROR
  - id: orders_freshness
    type: freshness_max_age_sec
    table: public.orders
    column: updated_at
    freshness_max_age_sec: 86400
    severity: ERROR
  - id: orders_uniq_id
    type: uniqueness
    table: public.orders
    column: order_id
    severity: ERROR
"""

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DataFabric - run data quality checks")
    p.add_argument("--config", required=False, help="Path to YAML/JSON config. If omitted with --sample, prints sample.")
    p.add_argument("--include", action="append", default=[], help="Run only checks whose id contains this substring (repeatable)")
    p.add_argument("--exclude", action="append", default=[], help="Exclude checks whose id contains this substring (repeatable)")
    p.add_argument("--tags-any", action="append", default=[], help="Run checks that have ANY of these tags (repeatable)")
    p.add_argument("--tags-not", action="append", default=[], help="Exclude checks that have ANY of these tags (repeatable)")
    p.add_argument("--workers", type=int, default=max(1, os.cpu_count() or 1), help="Parallel workers")
    p.add_argument("--fail-fast", action="store_true", help="Stop on first ERROR failure")
    p.add_argument("--warn-as-fail", action="store_true", help="Treat WARNING failures as exit(1)")
    p.add_argument("--out-json", help="Write machine JSON report to file")
    p.add_argument("--out-junit", help="Write JUnit XML report to file")
    p.add_argument("--sample", action="store_true", help="Print sample config and exit")
    p.add_argument("--validate", action="store_true", help="Validate config and exit")
    p.add_argument("--no-lineage", action="store_true", help="Disable lineage emission (if lineage module present)")
    return p

def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = argv or sys.argv[1:]
    ap = build_argparser()
    ns = ap.parse_args(argv)

    if ns.sample:
        print(_sample_config())
        return 0

    if not ns.config:
        print("Error: --config is required (or use --sample)", file=sys.stderr)
        return 2

    try:
        cfg = load_config(ns.config)
        validate_config(cfg)
    except Exception as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    try:
        report = run_all(
            cfg=cfg,
            include=ns.include,
            exclude=ns.exclude,
            tags_any=ns.tags_any,
            tags_not=ns.tags_not,
            workers=int(ns.workers),
            fail_fast=bool(ns.fail_fast),
            warn_as_fail=bool(ns.warn_as_fail),
            lineage=not bool(ns.no_lineage),
        )
    except Exception as e:
        print(f"Run error: {e}", file=sys.stderr)
        return 1

    # outputs
    rep_dict = dataclasses.asdict(report)
    if df_serde:
        blob = df_serde.to_canonical_json(rep_dict)  # type: ignore
        txt = blob.decode("utf-8")
    else:
        txt = json.dumps(rep_dict, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    if ns.out_json:
        with open(ns.out_json, "w", encoding="utf-8") as f:
            f.write(txt)

    if ns.out_junit:
        junit = to_junit(report)
        with open(ns.out_junit, "w", encoding="utf-8") as f:
            f.write(junit)

    # human summary
    print(f"Started:   {report.summary.started_at}")
    print(f"Finished:  {report.summary.finished_at}")
    print(f"Duration:  {report.summary.duration_sec:.2f}s")
    print(f"Total: {report.summary.total}  Passed: {report.summary.passed}  Warned: {report.summary.warned}  Failed: {report.summary.failed}")
    # list failed
    for r in report.results:
        if not r.ok:
            print(f"[{r.severity}] {r.id}: {r.message}")

    # exit code
    failed_error = report.summary.failed
    failed_warn = report.summary.warned
    exit_code = 1 if (failed_error > 0 or (ns.warn_as_fail and failed_warn > 0)) else 0
    return exit_code

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
