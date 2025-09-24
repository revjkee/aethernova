# omnimind-core/cli/tools/eval_suite.py
# Industrial-grade evaluation CLI for Omnimind ToolInvoker.
# Copyright (c) 2025.
# SPDX-License-Identifier: Apache-2.0
"""
Назначение
---------
Асинхронный CLI для функциональной, нагрузочной и корректностной оценки инструментов (Tool)
через ваш omnimind.executor.ToolInvoker.

Особенности
-----------
- План испытаний в JSON/YAML: кейсы, повторы, таймауты, ретраи, ассершены.
- Параллельный запуск (asyncio), общий и по-кейсовый лимит конкурентности.
- Метрики: p50/p90/p95/p99, min/max/avg, TPS, коды ошибок, распределения.
- Проверки корректности: equals/contains/regex/range/type/in по путям вида "output.field.sub".
- Отчеты: JSON (агрегат + события), CSV (пер-вызов), JUnit XML (для CI).
- Опциональные зависимости: PyYAML (YAML план), rich (красивые таблицы/прогресс).
- Безопасность: никаких eval; жёсткие таймауты; маскирование сообщений об ошибках уже на уровне ToolInvoker.

Запуск
------
python -m omnimind.cli.tools.eval_suite --spec plan.yaml \
  --invoker omnimind.executor.tool_invoker:build_default_invoker \
  --concurrency 64 --json-out results.json --csv-out invocations.csv --junit-out junit.xml

Структура плана (пример YAML)
-----------------------------
version: 1
settings:
  concurrency: 32          # общий лимит
  per_case_concurrency: 8  # лимит на кейс
  warmup_runs: 3
  idempotency: false
  default_timeout_s: 5
  retries: 0
  ramp_up_s: 0
cases:
  - name: echo-fast
    tool: echo
    args: { message: "hello", uppercase: true }
    repeats: 200
    timeout_s: 1
    assertions:
      - kind: equals
        path: output.echo
        value: "HELLO"
  - name: echo-tail
    tool: echo
    args: '{"message":"tail","uppercase":false}'
    repeats: 50
    assertions:
      - kind: contains
        path: output.echo
        value: "tail"

Совместимость
-------------
Требуется: Python 3.10+, pydantic v2 (как в проекте). YAML и rich опциональны.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import importlib
import io
import json
import math
import os
import re
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# Опциональные зависимости
try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

try:
    from rich import box  # type: ignore
    from rich.console import Console  # type: ignore
    from rich.table import Table  # type: ignore
    _RICH = True
    _CONSOLE = Console()
except Exception:
    _RICH = False
    _CONSOLE = None  # type: ignore

from pydantic import BaseModel, Field, ConfigDict, field_validator

# Интеграция с вашим Invoker
from omnimind.executor.tool_invoker import (
    ToolInvoker,
    ToolInvocationContext,
    ToolResult,
)


# ==========================
# Pydantic DTO для плана
# ==========================

class Assertion(BaseModel):
    """
    Декларативная проверка результата.
    kind: equals | contains | regex | range | type | in
    path: точка-точка путь от корня результата ToolResult.dict(): например "output.echo" или "error.type".
    value(s): см. конкретный вид.
    """
    model_config = ConfigDict(extra="forbid")

    kind: str
    path: str
    value: Any | None = None
    min: float | int | None = None
    max: float | int | None = None
    choices: List[Any] | None = None
    type: str | None = None  # "str|int|float|bool|dict|list|none"
    flags: str | None = None  # для regex: "i" (ignorecase), "m", "s"

    @field_validator("kind")
    @classmethod
    def _kind_ok(cls, v: str) -> str:
        v = v.lower()
        allowed = {"equals", "contains", "regex", "range", "type", "in"}
        if v not in allowed:
            raise ValueError(f"Unsupported assertion kind: {v}")
        return v


class Case(BaseModel):
    """
    Описание одного кейса.
    """
    model_config = ConfigDict(extra="forbid")

    name: str
    tool: str
    args: Any = Field(default_factory=dict)  # dict или JSON-строка
    repeats: int = Field(default=1, ge=1)
    timeout_s: float | None = Field(default=None, ge=0)
    retries: int | None = Field(default=None, ge=0)
    idempotency: bool | None = None
    assertions: List[Assertion] = Field(default_factory=list)
    per_case_concurrency: int | None = Field(default=None, ge=1)


class Settings(BaseModel):
    """
    Глобальные настройки запуска.
    """
    model_config = ConfigDict(extra="forbid")

    concurrency: int = Field(default=32, ge=1)
    per_case_concurrency: int = Field(default=8, ge=1)
    warmup_runs: int = Field(default=0, ge=0)
    idempotency: bool = False
    default_timeout_s: float = Field(default=5.0, ge=0)
    retries: int = Field(default=0, ge=0)
    ramp_up_s: float = Field(default=0.0, ge=0)  # ступенчатый разогрев (сек)
    seed: int | None = None


class Plan(BaseModel):
    """
    План испытаний.
    """
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    settings: Settings = Field(default_factory=Settings)
    cases: List[Case]


# ==========================
# Утилиты
# ==========================

def _load_plan(path: str) -> Plan:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is not installed; install pyyaml or provide JSON plan")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return Plan.model_validate(data)


def _import_callable(spec: str):
    """
    Загружает объект по строке "module.sub:callable".
    """
    if ":" not in spec:
        raise ValueError("Expected format 'module.sub:callable'")
    mod, fn = spec.split(":", 1)
    m = importlib.import_module(mod)
    obj = getattr(m, fn)
    return obj


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _percentiles(values: List[float], ps: Sequence[float]) -> List[float]:
    if not values:
        return [math.nan for _ in ps]
    values = sorted(values)
    out: List[float] = []
    for p in ps:
        if not values:
            out.append(math.nan)
            continue
        k = (len(values) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            out.append(values[int(k)])
        else:
            d0 = values[f] * (c - k)
            d1 = values[c] * (k - f)
            out.append(d0 + d1)
    return out


def _dot_get(obj: Any, path: str) -> Any:
    """
    Простой извлекатель по пути "a.b.c".
    Работает с dict/list/объектами Pydantic/датаклассами.
    """
    if obj is None:
        return None
    parts = [p for p in path.split(".") if p]
    cur = obj
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, list):
            try:
                idx = int(p)
                cur = cur[idx]
            except Exception:
                return None
        else:
            cur = getattr(cur, p, None)
    return cur


def _match_assertion(assertion: Assertion, result: ToolResult) -> Tuple[bool, str]:
    """
    Возвращает (ok, message).
    """
    # ToolResult -> dict
    res = result.model_dump()
    value = _dot_get(res, assertion.path)

    k = assertion.kind
    if k == "equals":
        ok = value == assertion.value
        msg = f"equals: expected {assertion.value!r}, got {value!r}"
        return ok, msg
    elif k == "contains":
        if value is None:
            return False, "contains: value is None"
        ok = str(assertion.value) in str(value)
        return ok, f"contains: '{assertion.value}' in '{value}'"
    elif k == "regex":
        flags = 0
        if assertion.flags:
            if "i" in assertion.flags.lower():
                flags |= re.IGNORECASE
            if "m" in assertion.flags.lower():
                flags |= re.MULTILINE
            if "s" in assertion.flags.lower():
                flags |= re.DOTALL
        try:
            rgx = re.compile(str(assertion.value), flags)
        except re.error as e:
            return False, f"regex: invalid pattern: {e}"
        ok = bool(rgx.search("" if value is None else str(value)))
        return ok, f"regex: /{assertion.value}/ on '{value}'"
    elif k == "range":
        v = value
        try:
            vv = float(v)
        except Exception:
            return False, f"range: not a number: {v}"
        lo = float(assertion.min) if assertion.min is not None else -math.inf
        hi = float(assertion.max) if assertion.max is not None else math.inf
        ok = (vv >= lo) and (vv <= hi)
        return ok, f"range: {lo} <= {vv} <= {hi}"
    elif k == "type":
        t = (assertion.type or "").lower()
        mapping = {
            "str": str, "int": int, "float": float, "bool": bool,
            "dict": dict, "list": list, "none": type(None),
        }
        py = mapping.get(t)
        if py is None:
            return False, f"type: unsupported type {assertion.type}"
        ok = isinstance(value, py)
        return ok, f"type: is {py.__name__}, got {type(value).__name__}"
    elif k == "in":
        choices = assertion.choices or []
        ok = value in choices
        return ok, f"in: {value!r} in {choices!r}"
    return False, "unknown assertion"


# ==========================
# Исполнитель плана
# ==========================

@dataclass
class InvocationLog:
    case: str
    idx: int
    success: bool
    error_type: str | None
    error_message: str | None
    started_at: str
    finished_at: str
    duration_ms: int
    status: str
    output_size: int


@dataclass
class CaseReport:
    name: str
    total: int
    successes: int
    failures: int
    error_kinds: Dict[str, int]
    durations_ms: List[int] = field(default_factory=list)
    assertions_passed: int = 0
    assertions_failed: int = 0


@dataclass
class PlanReport:
    settings: Dict[str, Any]
    cases: List[CaseReport]
    totals: Dict[str, Any]
    started_at: str
    finished_at: str
    duration_s: float
    events: List[InvocationLog] = field(default_factory=list)


class Runner:
    def __init__(self, invoker: ToolInvoker, plan: Plan, *, list_only: bool = False) -> None:
        self.invoker = invoker
        self.plan = plan
        self.list_only = list_only
        self._global_sem = asyncio.Semaphore(plan.settings.concurrency)

    async def _warmup(self, case: Case) -> None:
        if self.plan.settings.warmup_runs <= 0:
            return
        for _ in range(self.plan.settings.warmup_runs):
            ctx = ToolInvocationContext(
                request_id="warmup",
                user_id="eval",
                tenant_id="eval",
                idempotency_key=None,
            )
            await self.invoker.invoke(
                case.tool,
                args=case.args,
                ctx=ctx,
                timeout_s=case.timeout_s or self.plan.settings.default_timeout_s,
                retries=0,
            )

    async def _run_one(self, case: Case, idx: int, case_sem: asyncio.Semaphore, logs: List[InvocationLog], report: CaseReport) -> None:
        async with self._global_sem:
            async with case_sem:
                # Контекст + идемпотентность
                idem = case.idempotency if case.idempotency is not None else self.plan.settings.idempotency
                idk = f"{case.name}-{idx}" if idem else None
                ctx = ToolInvocationContext(
                    request_id=f"{case.name}-{idx}",
                    user_id="eval",
                    tenant_id="eval",
                    idempotency_key=idk,
                )
                t0 = time.perf_counter()
                res: ToolResult = await self.invoker.invoke(
                    case.tool,
                    args=case.args,
                    ctx=ctx,
                    timeout_s=case.timeout_s or self.plan.settings.default_timeout_s,
                    retries=case.retries if case.retries is not None else self.plan.settings.retries,
                )
                t1 = time.perf_counter()

                # Учёт
                dur_ms = int((t1 - t0) * 1000)
                out_size = 0
                if res.output is not None:
                    try:
                        out_size = len(json.dumps(res.output))  # оценка
                    except Exception:
                        out_size = 0

                ok = res.success
                err_t = None if ok else (res.error or {}).get("type")
                err_m = None if ok else (res.error or {}).get("message")

                logs.append(InvocationLog(
                    case=case.name,
                    idx=idx,
                    success=ok,
                    error_type=err_t,
                    error_message=err_m,
                    started_at=_utc_iso(res.started_at),
                    finished_at=_utc_iso(res.finished_at),
                    duration_ms=dur_ms,
                    status="success" if ok else "failure",
                    output_size=out_size,
                ))
                report.total += 1
                if ok:
                    report.successes += 1
                else:
                    report.failures += 1
                    if err_t:
                        report.error_kinds[err_t] = report.error_kinds.get(err_t, 0) + 1
                report.durations_ms.append(dur_ms)

                # Ассершены
                for a in case.assertions:
                    passed, _msg = _match_assertion(a, res)
                    if passed:
                        report.assertions_passed += 1
                    else:
                        report.assertions_failed += 1

    async def run(self, *, filter_names: set[str] | None = None) -> PlanReport:
        started = datetime.now(timezone.utc)
        case_reports: List[CaseReport] = []
        events: List[InvocationLog] = []

        # Прогрев
        for case in self.plan.cases:
            if filter_names and case.name not in filter_names:
                continue
            if self.list_only:
                continue
            await self._warmup(case)

        # Рамп-ап
        if not self.list_only and self.plan.settings.ramp_up_s > 0:
            await asyncio.sleep(self.plan.settings.ramp_up_s)

        # Основной запуск
        tasks: List[asyncio.Task] = []
        for case in self.plan.cases:
            if filter_names and case.name not in filter_names:
                continue
            case_report = CaseReport(
                name=case.name,
                total=0,
                successes=0,
                failures=0,
                error_kinds={},
                durations_ms=[],
            )
            case_reports.append(case_report)

            if self.list_only:
                continue

            sem_lim = case.per_case_concurrency or self.plan.settings.per_case_concurrency
            case_sem = asyncio.Semaphore(sem_lim)

            for i in range(case.repeats):
                tasks.append(asyncio.create_task(self._run_one(case, i, case_sem, events, case_report)))

        if tasks:
            await asyncio.gather(*tasks)

        finished = datetime.now(timezone.utc)

        totals = self._aggregate(case_reports, started, finished)
        return PlanReport(
            settings=self.plan.settings.model_dump(),
            cases=case_reports,
            totals=totals,
            started_at=_utc_iso(started),
            finished_at=_utc_iso(finished),
            duration_s=(finished - started).total_seconds(),
            events=events,
        )

    def _aggregate(self, case_reports: List[CaseReport], started: datetime, finished: datetime) -> Dict[str, Any]:
        all_durs = [d for cr in case_reports for d in cr.durations_ms]
        ps = _percentiles([float(x) for x in all_durs], [50, 90, 95, 99]) if all_durs else [math.nan] * 4
        successes = sum(cr.successes for cr in case_reports)
        total = sum(cr.total for cr in case_reports)
        failures = sum(cr.failures for cr in case_reports)
        tps = (total / max(0.001, (finished - started).total_seconds())) if total else 0.0

        return {
            "total_invocations": total,
            "successes": successes,
            "failures": failures,
            "success_rate": (successes / total) if total else 0.0,
            "latency_ms": {
                "min": min(all_durs) if all_durs else None,
                "avg": (sum(all_durs) / len(all_durs)) if all_durs else None,
                "max": max(all_durs) if all_durs else None,
                "p50": ps[0],
                "p90": ps[1],
                "p95": ps[2],
                "p99": ps[3],
            },
            "throughput_tps": tps,
        }


# ==========================
# Вывод/отчеты
# ==========================

def print_table(report: PlanReport) -> None:
    if not _RICH:
        # Простой текстовый вывод
        print("Totals:", json.dumps(report.totals, indent=2, ensure_ascii=False))
        for cr in report.cases:
            print(f"- {cr.name}: total={cr.total} ok={cr.successes} fail={cr.failures} "
                  f"p50/p90={_percentiles([float(x) for x in cr.durations_ms], [50, 90]) if cr.durations_ms else 'n/a'}")
        return

    console: Console = _CONSOLE  # type: ignore
    table = Table(title="Evaluation Summary", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Case", justify="left")
    table.add_column("Total", justify="right")
    table.add_column("OK", justify="right", style="green")
    table.add_column("Fail", justify="right", style="red")
    table.add_column("p50 ms", justify="right")
    table.add_column("p95 ms", justify="right")
    table.add_column("Max ms", justify="right")
    table.add_column("Asserts", justify="right")

    for cr in report.cases:
        durs = [float(x) for x in cr.durations_ms]
        p50, _, p95, _ = _percentiles(durs, [50, 75, 95, 99]) if durs else (math.nan, math.nan, math.nan, math.nan)
        table.add_row(
            cr.name,
            str(cr.total),
            str(cr.successes),
            str(cr.failures),
            f"{p50:.1f}" if not math.isnan(p50) else "n/a",
            f"{p95:.1f}" if not math.isnan(p95) else "n/a",
            f"{max(durs):.1f}" if durs else "n/a",
            f"{cr.assertions_passed}/{cr.assertions_passed + cr.assertions_failed}",
        )
    console.print(table)

    # Totals
    tot = report.totals
    table2 = Table(title="Totals", box=box.MINIMAL)
    for k, v in tot.items():
        table2.add_row(k, json.dumps(v, ensure_ascii=False) if isinstance(v, dict) else str(v))
    console.print(table2)


def write_json(report: PlanReport, path: str) -> None:
    data = {
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "duration_s": report.duration_s,
        "settings": report.settings,
        "totals": report.totals,
        "cases": [
            {
                "name": cr.name,
                "total": cr.total,
                "successes": cr.successes,
                "failures": cr.failures,
                "error_kinds": cr.error_kinds,
                "assertions": {"passed": cr.assertions_passed, "failed": cr.assertions_failed},
                "durations_ms": cr.durations_ms,
            }
            for cr in report.cases
        ],
        "events": [vars(ev) for ev in report.events],
    }
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(report: PlanReport, path: str) -> None:
    fields = list(vars(report.events[0]).keys()) if report.events else [
        "case", "idx", "success", "error_type", "error_message", "started_at", "finished_at", "duration_ms", "status", "output_size"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for ev in report.events:
            w.writerow(vars(ev))


def write_junit(report: PlanReport, path: str) -> None:
    """
    Простой JUnit XML (в один testsuite).
    """
    total = sum(cr.total for cr in report.cases)
    failures = sum(cr.failures for cr in report.cases)
    cases = []
    for cr in report.cases:
        # один testcase на кейс; если нужны пер-вызовные — можно включить events
        time_s = sum(cr.durations_ms) / 1000.0 if cr.durations_ms else 0.0
        case_xml = f'<testcase classname="omnimind.eval" name="{cr.name}" time="{time_s:.3f}">'
        if cr.failures:
            case_xml += f'<failure type="Failure" message="failures={cr.failures}">Failures in case {cr.name}</failure>'
        case_xml += "</testcase>"
        cases.append(case_xml)
    suite = f'''<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="omnimind-eval" tests="{len(report.cases)}" failures="{failures}" time="{report.duration_s:.3f}">
{os.linesep.join(cases)}
</testsuite>
'''
    Path(path).write_text(suite, encoding="utf-8")


# ==========================
# CLI
# ==========================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="omnimind-eval", description="Omnimind Tool evaluation suite")
    p.add_argument("--spec", required=True, help="Путь к плану (JSON/YAML)")
    p.add_argument("--invoker", required=False,
                   default="omnimind.executor.tool_invoker:build_default_invoker",
                   help="Фабрика инвокера 'module.sub:callable'")
    p.add_argument("--concurrency", type=int, help="Переопределить глобальный concurrency")
    p.add_argument("--filter", dest="filters", action="append", help="Включить только указанные кейсы (можно несколько)")
    p.add_argument("--json-out", help="Путь для агрегированного JSON-отчета")
    p.add_argument("--csv-out", help="Путь для CSV логов вызовов")
    p.add_argument("--junit-out", help="Путь для JUnit XML")
    p.add_argument("--list", action="store_true", help="Только перечислить кейсы, не запускать")
    p.add_argument("--pretty", action="store_true", help="Печатать таблицу (rich, если установлен)")
    return p


async def _amain(args: argparse.Namespace) -> int:
    plan = _load_plan(args.spec)
    if args.concurrency:
        plan.settings.concurrency = args.concurrency

    # Динамическая загрузка инвокера
    invoker_builder = _import_callable(args.invoker)
    invoker: ToolInvoker = invoker_builder()

    runner = Runner(invoker, plan, list_only=args.list)
    filter_names = set(args.filters) if args.filters else None
    report = await runner.run(filter_names=filter_names)

    # Вывод
    if args.pretty:
        print_table(report)

    if args.json_out:
        write_json(report, args.json_out)
    if args.csv_out:
        write_csv(report, args.csv_out)
    if args.junit_out:
        write_junit(report, args.junit_out)

    # Код возврата: 0 если нет фэйлов и ассершен-ошибок
    failed_cases = sum(1 for c in report.cases if c.failures > 0 or c.assertions_failed > 0)
    return 0 if failed_cases == 0 else 2


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        code = asyncio.run(_amain(args))
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    main()
