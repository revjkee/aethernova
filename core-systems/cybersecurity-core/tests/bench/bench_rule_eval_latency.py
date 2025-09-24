# cybersecurity-core/tests/bench/bench_rule_eval_latency.py
# -*- coding: utf-8 -*-
"""
Промышленный бенчмарк латентности/throughput для движка правил.

Возможности:
- Автоматическое подключение внешнего движка: cybersecurity_core.rules.engine.RuleEngine
  и типов правил (Rule). При отсутствии — безопасный fallback-движок без зависимостей.
- Генерация синтетических правил и фактов (детерминированная по --seed).
- Прогрев (warmup), контроль числа итераций и размерностей (rules × facts).
- Измерение:
  * Латентность одиночной оценки (пер-событие) с перцентилями P50/P90/P99.
  * Пропускная способность (events/sec) для пакетной и матричной оценки.
- Отчет в JSON с системной информацией, параметрами запуска и метриками.
- Опциональная конкурентность (none|thread|process) и число воркеров.
- Без внешних библиотек; кроссплатформенно.

Запуск (пример):
  python -m cybersecurity_core.tests.bench.bench_rule_eval_latency \
      --rules 1000 --facts 2000 --warmup 2000 --iters 5000 \
      --concurrency none --output bench_report.json

Примечание:
- Скрипт не делает предположений о внутренностях внешнего RuleEngine, а использует
  адаптерный интрефейс evaluate(rule, fact) и (опционально) evaluate_batch(rules, facts).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import random
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ------------------------------ Engine Adapter --------------------------------

class _EngineAdapter:
    """
    Унифицированный адаптер над внешним RuleEngine.
    Ожидаемые методы у внешнего движка:
      - evaluate(rule, fact) -> bool | dict
      - (опционально) evaluate_batch(rules: list, facts: list) -> list[bool | dict]
    """

    def __init__(self, engine: Any, use_batch: bool):
        self.engine = engine
        self.use_batch = use_batch and hasattr(engine, "evaluate_batch")

    def evaluate(self, rule: Any, fact: Dict[str, Any]) -> Any:
        return self.engine.evaluate(rule, fact)

    def evaluate_batch(self, rules: Sequence[Any], facts: Sequence[Dict[str, Any]]) -> List[Any]:
        if self.use_batch:
            return list(self.engine.evaluate_batch(list(rules), list(facts)))
        # На случай отсутствия batch — деградация к последовательной оценке
        out: List[Any] = []
        for f in facts:
            for r in rules:
                out.append(self.engine.evaluate(r, f))
        return out


# ------------------------------ Fallback Engine -------------------------------

@dataclass(frozen=True)
class _FallbackCondition:
    field: str
    op: str
    value: Any


@dataclass(frozen=True)
class _FallbackRule:
    """
    Простая безопасная модель правила:
    - aggregator: "all" (И) или "any" (ИЛИ)
    - conditions: список условий вида (field, op, value)
    Поддерживаемые op:
      - для числовых: gt, ge, lt, le, eq, ne
      - для строковых: eq, ne, contains, prefix, suffix, in (value: list[str])
    """
    aggregator: str
    conditions: Tuple[_FallbackCondition, ...]
    name: str = "rule"

class _FallbackEngine:
    def evaluate(self, rule: _FallbackRule, fact: Dict[str, Any]) -> bool:
        checks: List[bool] = []
        for c in rule.conditions:
            fv = fact.get(c.field, None)
            op = c.op
            tv = c.value
            res = False
            if op == "gt" and isinstance(fv, (int, float)) and isinstance(tv, (int, float)):
                res = fv > tv
            elif op == "ge" and isinstance(fv, (int, float)) and isinstance(tv, (int, float)):
                res = fv >= tv
            elif op == "lt" and isinstance(fv, (int, float)) and isinstance(tv, (int, float)):
                res = fv < tv
            elif op == "le" and isinstance(fv, (int, float)) and isinstance(tv, (int, float)):
                res = fv <= tv
            elif op == "eq":
                res = fv == tv
            elif op == "ne":
                res = fv != tv
            elif isinstance(fv, str):
                if op == "contains" and isinstance(tv, str):
                    res = tv in fv
                elif op == "prefix" and isinstance(tv, str):
                    res = fv.startswith(tv)
                elif op == "suffix" and isinstance(tv, str):
                    res = fv.endswith(tv)
                elif op == "in" and isinstance(tv, (list, tuple, set)):
                    res = fv in tv
            checks.append(res)

        if rule.aggregator == "all":
            return all(checks)
        return any(checks)

    def evaluate_batch(self, rules: Sequence[_FallbackRule], facts: Sequence[Dict[str, Any]]) -> List[bool]:
        out: List[bool] = []
        for f in facts:
            for r in rules:
                out.append(self.evaluate(r, f))
        return out


def _load_engine(engine_pref: str, use_batch: bool) -> Tuple[_EngineAdapter, str]:
    """
    Загружаем внешний движок (если есть) или fallback.
    """
    engine_used = "fallback"
    if engine_pref in ("auto", "external"):
        try:
            from cybersecurity_core.rules.engine import RuleEngine as _ExtEngine  # type: ignore
            engine = _ExtEngine()
            adapter = _EngineAdapter(engine, use_batch=use_batch)
            engine_used = "external"
            return adapter, engine_used
        except Exception:
            if engine_pref == "external":
                raise
    # fallback
    engine = _FallbackEngine()
    adapter = _EngineAdapter(engine, use_batch=True)
    return adapter, engine_used


# ------------------------------ Data Generator --------------------------------

@dataclass
class _GenConfig:
    rules: int
    facts: int
    num_fields: int
    str_fields: int
    seed: int

_NUM_FIELD_PREFIX = "f"
_STR_FIELD_PREFIX = "s"

def _gen_rules(cfg: _GenConfig, rng: random.Random) -> List[_FallbackRule]:
    rules: List[_FallbackRule] = []
    for i in range(cfg.rules):
        # Смешанные условия: 2 числовых + 1 строковое
        conds: List[_FallbackCondition] = []

        nf = rng.randrange(cfg.num_fields)  # numeric field index
        threshold = rng.uniform(0.0, 1000.0)
        conds.append(_FallbackCondition(field=f"{_NUM_FIELD_PREFIX}{nf}", op=rng.choice(["gt","ge","lt","le"]), value=threshold))

        nf2 = rng.randrange(cfg.num_fields)
        threshold2 = rng.uniform(0.0, 1000.0)
        conds.append(_FallbackCondition(field=f"{_NUM_FIELD_PREFIX}{nf2}", op=rng.choice(["gt","ge","lt","le"]), value=threshold2))

        sf = rng.randrange(cfg.str_fields)
        token = rng.choice(["ALPHA", "BETA", "GAMMA", "DELTA", "OMEGA"])
        op = rng.choice(["eq","ne","contains","prefix","suffix","in"])
        if op == "in":
            value = ["ALPHA","BETA","GAMMA"]
        else:
            value = token
        conds.append(_FallbackCondition(field=f"{_STR_FIELD_PREFIX}{sf}", op=op, value=value))

        aggr = rng.choice(["all","any"])
        rule = _FallbackRule(aggregator=aggr, conditions=tuple(conds), name=f"r{i}")
        rules.append(rule)
    return rules

def _gen_facts(cfg: _GenConfig, rng: random.Random) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []
    for _ in range(cfg.facts):
        row: Dict[str, Any] = {}
        for i in range(cfg.num_fields):
            row[f"{_NUM_FIELD_PREFIX}{i}"] = rng.uniform(0.0, 1000.0)
        for i in range(cfg.str_fields):
            row[f"{_STR_FIELD_PREFIX}{i}"] = rng.choice([
                "ALPHA","BETA","GAMMA","DELTA","OMEGA","THETA","SIGMA","KAPPA"
            ])
        facts.append(row)
    return facts


# ------------------------------ Stats Utilities -------------------------------

class _Reservoir:
    """
    Резервуарная выборка латентностей (наносекунды) для оценки перцентилей
    без чрезмерного расхода памяти.
    """
    def __init__(self, capacity: int = 200_000, seed: int = 1):
        self.capacity = capacity
        self.sample: List[int] = []
        self.count = 0
        self._rng = random.Random(seed)

    def add(self, v_ns: int) -> None:
        self.count += 1
        if len(self.sample) < self.capacity:
            self.sample.append(v_ns)
            return
        # Алгоритм резервуарной выборки
        j = self._rng.randrange(0, self.count)
        if j < self.capacity:
            self.sample[j] = v_ns

    def percentiles(self, ps: Sequence[float]) -> Dict[str, float]:
        if not self.sample:
            return {f"p{int(p*100)}": float("nan") for p in ps}
        data = sorted(self.sample)
        out: Dict[str, float] = {}
        n = len(data)
        for p in ps:
            if n == 1:
                val = data[0]
            else:
                rank = p * (n - 1)
                lo = int(math.floor(rank))
                hi = int(math.ceil(rank))
                if lo == hi:
                    val = data[lo]
                else:
                    val = data[lo] + (data[hi] - data[lo]) * (rank - lo)
            out[f"p{int(p*100)}"] = val / 1e6  # в миллисекундах
        return out


# ------------------------------ Benchmark Core --------------------------------

@dataclass
class _BenchParams:
    warmup: int
    iters: int
    rules: int
    facts: int
    num_fields: int
    str_fields: int
    seed: int
    concurrency: str
    workers: int
    use_batch: bool

def _single_latency(adapter: _EngineAdapter, rules: Sequence[Any], facts: Sequence[Dict[str, Any]],
                    params: _BenchParams) -> Dict[str, Any]:
    rng = random.Random(params.seed)
    res = _Reservoir(capacity=min(200_000, params.iters), seed=params.seed)
    # прогрев
    for _ in range(params.warmup):
        r = rules[rng.randrange(len(rules))]
        f = facts[rng.randrange(len(facts))]
        adapter.evaluate(r, f)

    t_start = time.perf_counter_ns()
    for _ in range(params.iters):
        r = rules[rng.randrange(len(rules))]
        f = facts[rng.randrange(len(facts))]
        t0 = time.perf_counter_ns()
        adapter.evaluate(r, f)
        dt = time.perf_counter_ns() - t0
        res.add(dt)
    t_end = time.perf_counter_ns()
    wall_ms = (t_end - t_start) / 1e6
    # агрегация
    ptiles = res.percentiles([0.50, 0.90, 0.99])
    return {
        "mode": "single_latency",
        "iter_count": params.iters,
        "wall_ms": wall_ms,
        "throughput_eps": params.iters / (wall_ms / 1e3) if wall_ms > 0 else float("inf"),
        "p50_ms": ptiles["p50"],
        "p90_ms": ptiles["p90"],
        "p99_ms": ptiles["p99"],
        "sampled": res.count,
    }

def _matrix_throughput(adapter: _EngineAdapter, rules: Sequence[Any], facts: Sequence[Dict[str, Any]],
                       params: _BenchParams) -> Dict[str, Any]:
    total = len(rules) * len(facts)
    t0 = time.perf_counter_ns()
    adapter.evaluate_batch(rules, facts)
    wall_ms = (time.perf_counter_ns() - t0) / 1e6
    return {
        "mode": "matrix_throughput",
        "evaluations": total,
        "wall_ms": wall_ms,
        "throughput_eps": total / (wall_ms / 1e3) if wall_ms > 0 else float("inf"),
    }

def _concurrent_throughput(adapter: _EngineAdapter, rules: Sequence[Any], facts: Sequence[Dict[str, Any]],
                           params: _BenchParams) -> Dict[str, Any]:
    if params.concurrency == "none":
        return _matrix_throughput(adapter, rules, facts, params)

    # Разбиваем факты на чанки по числу воркеров
    workers = max(1, params.workers)
    chunks: List[List[Dict[str, Any]]] = []
    n = len(facts)
    step = max(1, n // workers)
    for i in range(0, n, step):
        chunks.append(facts[i:i+step])

    def _job(chunk: List[Dict[str, Any]]) -> int:
        adapter.evaluate_batch(rules, chunk)
        return len(rules) * len(chunk)

    executor_cls = ThreadPoolExecutor if params.concurrency == "thread" else ProcessPoolExecutor
    t0 = time.perf_counter_ns()
    done_evals = 0
    with executor_cls(max_workers=workers) as ex:
        futs = [ex.submit(_job, ch) for ch in chunks]
        for fut in as_completed(futs):
            done_evals += fut.result()
    wall_ms = (time.perf_counter_ns() - t0) / 1e6
    return {
        "mode": f"concurrent_{params.concurrency}",
        "evaluations": done_evals,
        "wall_ms": wall_ms,
        "throughput_eps": done_evals / (wall_ms / 1e3) if wall_ms > 0 else float("inf"),
        "workers": workers,
    }


# ------------------------------ CLI / Main ------------------------------------

def _sysinfo() -> Dict[str, Any]:
    return {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "pid": os.getpid(),
    }

def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="bench_rule_eval_latency",
                                description="Benchmark rule evaluation latency/throughput")
    p.add_argument("--engine", choices=["auto", "external", "fallback"], default="auto",
                   help="Выбор движка правил.")
    p.add_argument("--use-batch", action="store_true", help="Использовать evaluate_batch если доступно.")
    p.add_argument("--rules", type=int, default=1000, help="Количество правил R.")
    p.add_argument("--facts", type=int, default=5000, help="Количество фактов F.")
    p.add_argument("--num-fields", type=int, default=8, help="Числовые поля в факте.")
    p.add_argument("--str-fields", type=int, default=4, help="Строковые поля в факте.")
    p.add_argument("--seed", type=int, default=1337, help="Seed генератора.")
    p.add_argument("--warmup", type=int, default=2000, help="Прогрев (кол-во одиночных оценок).")
    p.add_argument("--iters", type=int, default=5000, help="Одиночные оценки для латентности.")
    p.add_argument("--concurrency", choices=["none", "thread", "process"], default="none",
                   help="Режим конкурентности для throughput.")
    p.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2),
                   help="Число воркеров для конкурентного режима.")
    p.add_argument("--output", type=str, default="bench_rule_eval_latency.json", help="Путь для JSON-отчета.")
    return p.parse_args(argv)

def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    # Движок
    adapter, eng_used = _load_engine(args.engine, use_batch=args.use_batch)

    # Данные
    cfg = _GenConfig(
        rules=int(args.rules),
        facts=int(args.facts),
        num_fields=int(args.num_fields),
        str_fields=int(args.str_fields),
        seed=int(args.seed),
    )
    rng = random.Random(cfg.seed)
    rules = _gen_rules(cfg, rng)
    facts = _gen_facts(cfg, rng)

    params = _BenchParams(
        warmup=int(args.warmup),
        iters=int(args.iters),
        rules=cfg.rules,
        facts=cfg.facts,
        num_fields=cfg.num_fields,
        str_fields=cfg.str_fields,
        seed=cfg.seed,
        concurrency=str(args.concurrency),
        workers=int(args.workers),
        use_batch=bool(args.use_batch),
    )

    # Метрики
    single = _single_latency(adapter, rules, facts, params)
    matrix = _matrix_throughput(adapter, rules, facts, params)
    conc = _concurrent_throughput(adapter, rules, facts, params)

    report = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sys": _sysinfo(),
        "engine": {
            "selected": args.engine,
            "used": eng_used,
            "use_batch": bool(args.use_batch),
        },
        "params": {
            "rules": cfg.rules,
            "facts": cfg.facts,
            "num_fields": cfg.num_fields,
            "str_fields": cfg.str_fields,
            "seed": cfg.seed,
            "warmup": params.warmup,
            "iters": params.iters,
            "concurrency": params.concurrency,
            "workers": params.workers,
        },
        "results": {
            "single_latency": single,
            "matrix_throughput": matrix,
            "concurrent_throughput": conc,
        },
    }

    # Вывод
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2, sort_keys=True)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except Exception as e:
        print(f"Ошибка записи отчета: {e}", file=sys.stderr)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1

if __name__ == "__main__":
    sys.exit(main())
