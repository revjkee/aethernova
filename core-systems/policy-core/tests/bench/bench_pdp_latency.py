#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
policy-core/tests/bench/bench_pdp_latency.py

Асинхронный промышленный бенчмарк для Policy Decision Point (PDP).

Возможности:
- Динамический импорт движка PDP: --engine policy_core.pdp:AsyncPDP
- Фолбэк MockPDP при отсутствии реального движка
- Разогрев (warmup) и основная прогонка (measure)
- Конкурентные воркеры (asyncio) и ограничение параллелизма
- Высокоточные замеры perf_counter_ns, агрегаты p50/p90/p95/p99, TPS
- Экспорт результатов в JSON/CSV
- Управляемая сложность политики/запроса, "холодный/тёплый" кэш
- Повторяемость через RNG seed
- Без внешних зависимостей (stdlib-only). Опционально использует uvloop, если доступен.

Примеры:
  python bench_pdp_latency.py \
    --engine policy_core.pdp:AsyncPDP \
    --iterations 20000 --concurrency 200 \
    --policy-rules 64 --attrs 16 --warmup 2000 \
    --json-out results.json --csv-out latencies.csv

  # С фолбэком MockPDP:
  python bench_pdp_latency.py --iterations 10000 --concurrency 100

Интерфейс ожиданий к движку:
  - Класс движка должен иметь async-метод evaluate(...).
  - Метод может принимать либо один dict-запрос, либо subject/action/resource/context,
    сигнатура будет определена автоматически через inspect.
  - Возврат результата не проверяется содержательно — важно время ответа/исключения.

Лицензия: MIT
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import gc
import importlib
import inspect
import json
import logging
import os
import random
import signal
import statistics
import sys
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

# Опционально ускорим event loop, если uvloop доступен и не Windows
try:
    if os.name != "nt":
        import uvloop  # type: ignore
        uvloop.install()
except Exception:
    pass

LOG = logging.getLogger("pdp_bench")


# ----------------------------- Утилиты и модели ----------------------------- #

def ns_to_ms(ns: int) -> float:
    return ns / 1_000_000.0


def ns_to_us(ns: int) -> float:
    return ns / 1_000.0


def percentiles(values: List[int], ps: List[float]) -> Dict[str, float]:
    """
    Возвращает процентили в наносекундах как float (ns).
    ps: список процентов [50, 90, 95, 99]
    """
    if not values:
        return {f"p{int(p)}": float("nan") for p in ps}
    # Копию сортируем, чтобы не портить исходные
    arr = sorted(values)
    n = len(arr)
    out: Dict[str, float] = {}
    for p in ps:
        if n == 1:
            out[f"p{int(p)}"] = float(arr[0])
            continue
        # Индекс nearest-rank (ISO стандарт обычно ближе к этому)
        k = max(1, int(round(p / 100.0 * n)))
        k = min(k, n)
        out[f"p{int(p)}"] = float(arr[k - 1])
    return out


def fmt_num(n: Union[int, float]) -> str:
    if isinstance(n, float):
        if n != n:  # NaN
            return "NaN"
        return f"{n:,.3f}"
    return f"{n:,}"


def load_engine(engine_path: Optional[str]) -> Any:
    """
    Загружает класс движка по строке вида 'module.sub:ClassName'.
    Возвращает экземпляр класса без аргументов конструктора.
    Если не задано или не найдено — будет возвращён MockPDP.
    """
    if not engine_path:
        LOG.warning("Движок не указан, используется MockPDP.")
        return MockPDP()

    if ":" not in engine_path:
        LOG.error("Некорректный --engine. Ожидается формат 'module.path:ClassName'.")
        return MockPDP()

    mod_path, cls_name = engine_path.split(":", 1)
    try:
        module = importlib.import_module(mod_path)
        cls = getattr(module, cls_name)
        inst = cls()  # type: ignore[call-arg]
        LOG.info("Успешно загружен движок: %s.%s", mod_path, cls_name)
        return inst
    except Exception as e:
        LOG.error("Не удалось загрузить движок %s: %s. Используется MockPDP.", engine_path, e)
        return MockPDP()


def detect_evaluate_signature(evaluate: Callable[..., Awaitable[Any]]) -> str:
    """
    Пытается понять, принимает ли evaluate один словарь (request)
    или четыре аргумента (subject, action, resource, context).
    """
    sig = inspect.signature(evaluate)
    params = [p for p in sig.parameters.values() if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    # исключаем self/cls
    if params and params[0].name in ("self", "cls"):
        params = params[1:]

    if len(params) == 1:
        return "dict"
    if len(params) >= 4:
        return "sarc"
    # По умолчанию попытаемся dict
    return "dict"


# ----------------------------- Синтетический MockPDP ----------------------------- #

@dataclass
class Rule:
    """Простое правило: сравнение атрибутов и порогов."""
    attr: str
    op: str  # one of: "eq", "ge", "le", "gt", "lt", "in"
    value: Any
    effect: str  # "Permit" or "Deny"


class MockPDP:
    """
    Лёгкая синтетическая PDP для бенчмарка. Имитирует стоимость вычислений
    через набор правил. Первое совпавшее правило даёт решение.
    """

    def __init__(self, cache_enabled: bool = True) -> None:
        self.cache_enabled = cache_enabled
        self._policy: List[Rule] = []
        self._cache: Dict[str, str] = {}

    def load_policy(self, rules: List[Rule]) -> None:
        self._policy = rules
        self._cache.clear()

    async def evaluate(self, request: Dict[str, Any]) -> str:
        """
        Ожидает словарь запроса. Решение: "Permit"/"Deny"/"NotApplicable".
        """
        if self.cache_enabled:
            key = self._cache_key(request)
            hit = self._cache.get(key)
            if hit is not None:
                return hit

        # Имитируем вычисление: последовательная проверка правил
        attrs = request.get("attributes", {})
        decision = "NotApplicable"
        for rule in self._policy:
            av = attrs.get(rule.attr)
            if self._match(av, rule.op, rule.value):
                decision = rule.effect
                break

        if self.cache_enabled:
            self._cache[self._cache_key(request)] = decision
        return decision

    def _cache_key(self, request: Dict[str, Any]) -> str:
        attrs = request.get("attributes", {})
        # Быстрый стабильный ключ
        return "|".join(f"{k}={attrs.get(k)!r}" for k in sorted(attrs))

    @staticmethod
    def _match(av: Any, op: str, bv: Any) -> bool:
        try:
            if op == "eq":
                return av == bv
            if op == "ge":
                return av >= bv
            if op == "le":
                return av <= bv
            if op == "gt":
                return av > bv
            if op == "lt":
                return av < bv
            if op == "in":
                # bv ожидается как контейнер
                return av in bv
            return False
        except Exception:
            return False


# ----------------------------- Генерация политики/запросов ----------------------------- #

OPS = ("eq", "ge", "le", "gt", "lt", "in")

def gen_policy(num_rules: int, attrs_pool: List[str], rng: random.Random) -> List[Rule]:
    rules: List[Rule] = []
    for i in range(num_rules):
        attr = rng.choice(attrs_pool)
        op = rng.choice(OPS)
        # Значения: числа, строки или множества
        val_choice = rng.randint(0, 2)
        if val_choice == 0:
            value: Any = rng.randint(0, 1000)
        elif val_choice == 1:
            value = f"v{rng.randint(0, 1000)}"
        else:
            # небольшое множество
            value = {f"k{rng.randint(0, 50)}" for _ in range(rng.randint(2, 6))}
        effect = "Permit" if (i % 3) != 0 else "Deny"  # легкая разбавленность Deny
        rules.append(Rule(attr=attr, op=op, value=value, effect=effect))
    return rules


def gen_request(attrs_pool: List[str], n_attrs: int, rng: random.Random) -> Dict[str, Any]:
    # Сгенерируем подмножество атрибутов
    chosen = rng.sample(attrs_pool, k=min(n_attrs, len(attrs_pool)))
    attrs: Dict[str, Any] = {}
    for a in chosen:
        t = rng.randint(0, 2)
        if t == 0:
            attrs[a] = rng.randint(0, 1000)
        elif t == 1:
            attrs[a] = f"v{rng.randint(0, 1000)}"
        else:
            attrs[a] = f"k{rng.randint(0, 50)}"
    return {"attributes": attrs}


# ----------------------------- Механика бенчмарка ----------------------------- #

@dataclass
class BenchConfig:
    iterations: int
    concurrency: int
    warmup: int
    policy_rules: int
    attrs: int
    seed: int
    cache: str  # "hot" or "cold"
    store_latencies: bool
    csv_out: Optional[str]
    json_out: Optional[str]
    engine_path: Optional[str]
    gc_disable: bool


class PDPRunner:
    def __init__(self, engine: Any, cfg: BenchConfig) -> None:
        self.engine = engine
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        # Пул атрибутов
        self.attrs_pool = [f"a{i}" for i in range(max(cfg.attrs * 2, 16))]

        # Если движок подобен MockPDP — инициализируем политику
        if hasattr(self.engine, "load_policy"):
            rules = gen_policy(cfg.policy_rules, self.attrs_pool, self.rng)
            self.engine.load_policy(rules)  # type: ignore[attr-defined]
            if hasattr(self.engine, "cache_enabled"):
                # Холодный/тёплый сценарий
                self.engine.cache_enabled = (cfg.cache == "hot")  # type: ignore[attr-defined]

        # Определим как вызывать evaluate
        if not hasattr(self.engine, "evaluate"):
            raise RuntimeError("Движок не имеет метода evaluate(...)")
        self.evaluate = getattr(self.engine, "evaluate")
        self.call_mode = detect_evaluate_signature(self.evaluate)

    async def _call_eval(self, request: Dict[str, Any]) -> Any:
        if self.call_mode == "dict":
            return await self.evaluate(request)  # type: ignore[misc]
        # Иначе попробуем S/A/R/C
        attrs = request.get("attributes", {})
        subject = attrs
        action = request.get("action", "read")
        resource = request.get("resource", "default")
        context = request.get("context", {})
        return await self.evaluate(subject, action, resource, context)  # type: ignore[misc]

    async def _warmup(self) -> None:
        if self.cfg.warmup <= 0:
            return
        LOG.info("Разогрев: %s запросов...", self.cfg.warmup)
        reqs = [gen_request(self.attrs_pool, self.cfg.attrs, self.rng) for _ in range(self.cfg.warmup)]
        # Разогрев можно выполнить ограниченно конкурентно, чтобы не шуметь
        sem = asyncio.Semaphore(min(self.cfg.concurrency, 64))

        async def one(r: Dict[str, Any]) -> None:
            async with sem:
                try:
                    await self._call_eval(r)
                except Exception:
                    pass

        await asyncio.gather(*(one(r) for r in reqs))
        LOG.info("Разогрев завершён.")

    async def run(self) -> Tuple[List[int], int, float, int]:
        """
        Запускает основной бенч.
        Возвращает: (latencies_ns, errors, wall_time_s, total_done)
        """
        if self.cfg.gc_disable:
            gc.collect()
            gc.disable()

        await self._warmup()

        total = self.cfg.iterations
        conc = max(1, self.cfg.concurrency)

        # Предгенерируем запросы, чтобы снизить шум
        reqs = [gen_request(self.attrs_pool, self.cfg.attrs, self.rng) for _ in range(total)]

        # Разобьём на чанки по числу воркеров
        base = total // conc
        rest = total % conc
        dist = [base + (1 if i < rest else 0) for i in range(conc)]

        # Для минимизации локов собираем латентности по-воркерно
        per_worker_lat: List[List[int]] = [[] for _ in range(conc)] if self.cfg.store_latencies else [[] for _ in range(conc)]
        errors = 0

        start_ns = time.perf_counter_ns()

        async def worker(wid: int, slice_reqs: List[Dict[str, Any]]) -> Tuple[int, List[int]]:
            local_err = 0
            local_lat: List[int] = []
            for r in slice_reqs:
                t0 = time.perf_counter_ns()
                try:
                    await self._call_eval(r)
                except Exception:
                    local_err += 1
                t1 = time.perf_counter_ns()
                if self.cfg.store_latencies:
                    local_lat.append(t1 - t0)
            return local_err, local_lat

        # Раздаём запросы воркерам
        slices: List[List[Dict[str, Any]]] = []
        idx = 0
        for count in dist:
            slices.append(reqs[idx: idx + count])
            idx += count

        results = await asyncio.gather(*(worker(i, slices[i]) for i in range(conc)))

        end_ns = time.perf_counter_ns()

        if self.cfg.gc_disable:
            gc.enable()

        # Сбор
        for i, (e, lat) in enumerate(results):
            errors += e
            if self.cfg.store_latencies:
                per_worker_lat[i] = lat

        # Склейка латентностей
        latencies_ns: List[int] = []
        if self.cfg.store_latencies:
            # Избегаем гигантского промежуточного массива при очень больших итогах
            latencies_ns = [x for sub in per_worker_lat for x in sub]

        wall_time_s = (end_ns - start_ns) / 1_000_000_000.0
        total_done = total
        return latencies_ns, errors, wall_time_s, total_done


# ----------------------------- CLI и запуск ----------------------------- #

def parse_args(argv: Optional[List[str]] = None) -> BenchConfig:
    p = argparse.ArgumentParser(description="PDP Latency Benchmark")
    p.add_argument("--engine", type=str, default=os.getenv("PDP_ENGINE", None),
                   help="Движок PDP в формате module.path:ClassName")
    p.add_argument("--iterations", type=int, default=int(os.getenv("PDP_ITER", "20000")),
                   help="Число измеряемых запросов")
    p.add_argument("--concurrency", type=int, default=int(os.getenv("PDP_CONC", "200")),
                   help="Количество конкурентных воркеров")
    p.add_argument("--warmup", type=int, default=int(os.getenv("PDP_WARMUP", "2000")),
                   help="Число запросов для разогрева")
    p.add_argument("--policy-rules", type=int, default=int(os.getenv("PDP_RULES", "64")),
                   help="Количество правил в политике (для MockPDP)")
    p.add_argument("--attrs", type=int, default=int(os.getenv("PDP_ATTRS", "16")),
                   help="Количество атрибутов в запросе")
    p.add_argument("--seed", type=int, default=int(os.getenv("PDP_SEED", "42")),
                   help="Seed для генератора случайных чисел")
    p.add_argument("--cache", type=str, choices=("hot", "cold"),
                   default=os.getenv("PDP_CACHE", "hot"),
                   help="Горячий/холодный сценарий кэша")
    p.add_argument("--no-store", action="store_true",
                   help="Не сохранять сырые латентности (экономия памяти)")
    p.add_argument("--csv-out", type=str, default=os.getenv("PDP_CSV", None),
                   help="Путь для CSV с латентностями, ns")
    p.add_argument("--json-out", type=str, default=os.getenv("PDP_JSON", None),
                   help="Путь для JSON с итоговыми метриками")
    p.add_argument("--gc-disable", action="store_true",
                   help="Выключить GC на время измерения для снижения шума")

    args = p.parse_args(argv)

    return BenchConfig(
        iterations=max(1, args.iterations),
        concurrency=max(1, args.concurrency),
        warmup=max(0, args.warmup),
        policy_rules=max(1, args.policy_rules),
        attrs=max(1, args.attrs),
        seed=args.seed,
        cache=args.cache,
        store_latencies=not args.no_store,
        csv_out=args.csv_out,
        json_out=args.json_out,
        engine_path=args.engine,
        gc_disable=args.gc_disable,
    )


def setup_logging() -> None:
    level = os.getenv("PDP_LOG", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def write_csv(path: str, latencies_ns: List[int]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["latency_ns"])
        for v in latencies_ns:
            w.writerow([v])


def write_json(path: str, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def print_report(metrics: Dict[str, Any]) -> None:
    print("")
    print("PDP Latency Benchmark Report")
    print("-" * 64)
    for k in ("engine", "iterations", "concurrency", "warmup", "cache", "policy_rules", "attrs", "errors"):
        print(f"{k:>14}: {metrics.get(k)}")
    print(f"{'wall_time_s':>14}: {fmt_num(metrics.get('wall_time_s', float('nan')))}")
    print(f"{'throughput_tps':>14}: {fmt_num(metrics.get('throughput_tps', float('nan')))}")
    print("")
    print("Latency (microseconds):")
    for k in ("min_us", "p50_us", "p90_us", "p95_us", "p99_us", "max_us", "mean_us"):
        print(f"{k:>14}: {fmt_num(metrics.get(k, float('nan')))}")
    print("-" * 64)


def install_sigint_handler(loop: asyncio.AbstractEventLoop) -> None:
    def _handler():
        for task in asyncio.all_tasks(loop=loop):
            task.cancel()
    try:
        loop.add_signal_handler(signal.SIGINT, _handler)
    except NotImplementedError:
        # Windows / ограниченные среды
        pass


async def main_async(cfg: BenchConfig) -> int:
    engine = load_engine(cfg.engine_path)
    runner = PDPRunner(engine, cfg)

    latencies_ns, errors, wall_time_s, total_done = await runner.run()

    # Метрики
    tps = total_done / wall_time_s if wall_time_s > 0 else float("inf")
    mins = min(latencies_ns) if latencies_ns else 0
    maxs = max(latencies_ns) if latencies_ns else 0
    mean = statistics.mean(latencies_ns) if latencies_ns else float("nan")
    q = percentiles(latencies_ns, [50, 90, 95, 99]) if latencies_ns else {}

    metrics: Dict[str, Any] = {
        "engine": cfg.engine_path or "MockPDP",
        "iterations": cfg.iterations,
        "concurrency": cfg.concurrency,
        "warmup": cfg.warmup,
        "cache": cfg.cache,
        "policy_rules": cfg.policy_rules,
        "attrs": cfg.attrs,
        "errors": errors,
        "wall_time_s": wall_time_s,
        "throughput_tps": tps,
        "min_us": ns_to_us(mins),
        "p50_us": ns_to_us(q.get("p50", float("nan"))) if q else float("nan"),
        "p90_us": ns_to_us(q.get("p90", float("nan"))) if q else float("nan"),
        "p95_us": ns_to_us(q.get("p95", float("nan"))) if q else float("nan"),
        "p99_us": ns_to_us(q.get("p99", float("nan"))) if q else float("nan"),
        "max_us": ns_to_us(maxs),
        "mean_us": ns_to_us(mean) if mean == mean else float("nan"),
        "stored_latencies": cfg.store_latencies,
        "csv_out": cfg.csv_out,
        "json_out": cfg.json_out,
        "gc_disabled": cfg.gc_disable,
        "python_version": sys.version,
        "platform": sys.platform,
    }

    # Вывод и сохранение
    print_report(metrics)

    if cfg.csv_out and cfg.store_latencies:
        try:
            write_csv(cfg.csv_out, latencies_ns)
            LOG.info("CSV сохранён: %s", cfg.csv_out)
        except Exception as e:
            LOG.error("Не удалось сохранить CSV %s: %s", cfg.csv_out, e)

    if cfg.json_out:
        try:
            write_json(cfg.json_out, metrics)
            LOG.info("JSON сохранён: %s", cfg.json_out)
        except Exception as e:
            LOG.error("Не удалось сохранить JSON %s: %s", cfg.json_out, e)

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    setup_logging()
    cfg = parse_args(argv)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    install_sigint_handler(loop)
    try:
        return loop.run_until_complete(main_async(cfg))
    finally:
        # Корректное завершение
        pending = asyncio.all_tasks(loop=loop)
        for t in pending:
            t.cancel()
        try:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        loop.close()


if __name__ == "__main__":
    sys.exit(main())
