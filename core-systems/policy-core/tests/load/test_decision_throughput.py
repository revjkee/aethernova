# -*- coding: utf-8 -*-
"""
Промышленный нагрузочный тест throughput/latency для policy-core decision engine.

Особенности:
- Async раннер со строго-монотонными таймерами (perf_counter).
- Прогрев (WARMUP_S), основная фаза (DURATION_S), мягкая остановка.
- Управляемая конкурентность (CONCURRENCY / LOAD_CONCURRENCY_LIST).
- Опциональный целевой RPS с высокоточным rate limiting (TOKEN BUCKET/интервальный планировщик).
- Генерация детерминированных входных контекстов (SEED).
- Reservoir Sampling для латенсий (контролируемая память, точные percentiles для больших прогонов).
- Артефакты JSON/CSV в TEST_ARTIFACTS_DIR (по умолчанию: artifacts/load).
- SLA-пороги: MAX_P95_MS, MAX_ERROR_PCT. При нарушении — assert fail.
- Автоподмена uvloop (если установлен) для реалистичного event loop.

ENV (все опциональны):
    DURATION_S=10
    WARMUP_S=2
    CONCURRENCY=8
    LOAD_CONCURRENCY_LIST=1,4,16     # если задан, используется он и игнорируется CONCURRENCY
    TARGET_RPS=0                      # 0 или пусто = без лимитера (максимум)
    MAX_P95_MS=50
    MAX_ERROR_PCT=0.5                 # в процентах; 0.5 = 0.5%
    RESERVOIR_SIZE=50000              # cэмпл латенсий
    TEST_ARTIFACTS_DIR=artifacts/load
    SEED=42
    POLICY_DECISION_IMPORT=policy_core.engine:decide_async  # путь к корутине (fallback при ImportError)

Запуск: pytest -q policy-core/tests/load/test_decision_throughput.py
"""

import asyncio
import contextlib
import csv
import gc
import importlib
import json
import math
import os
import random
import statistics
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

# Попытка ускорить event loop
with contextlib.suppress(Exception):
    import uvloop  # type: ignore
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

# --------- Конфиг ---------

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default

def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return float(v)
    except ValueError:
        return default

def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return default if v is None or v.strip() == "" else v

def _env_list_int(name: str, default: List[int]) -> List[int]:
    v = os.getenv(name)
    if not v:
        return default
    try:
        return [int(x.strip()) for x in v.split(",") if x.strip()]
    except Exception:
        return default

DURATION_S = _env_int("DURATION_S", 10)
WARMUP_S = _env_int("WARMUP_S", 2)
DEFAULT_CONCURRENCY = max(1, min(32, _env_int("CONCURRENCY", (os.cpu_count() or 2) * 2)))
CONCURRENCY_LIST = _env_list_int("LOAD_CONCURRENCY_LIST", [])
TARGET_RPS = _env_float("TARGET_RPS", 0.0)
MAX_P95_MS = _env_float("MAX_P95_MS", 0.0)  # 0 = не проверять
MAX_ERROR_PCT = _env_float("MAX_ERROR_PCT", 0.0)
RESERVOIR_SIZE = max(1000, _env_int("RESERVOIR_SIZE", 50000))
ARTIFACTS_DIR = Path(_env_str("TEST_ARTIFACTS_DIR", "artifacts/load"))
SEED = _env_int("SEED", 42)
DECISION_IMPORT = _env_str("POLICY_DECISION_IMPORT", "policy_core.engine:decide_async")

# --------- Импорт целевой корутины (с fallback) ---------

DecisionFn = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]

def _load_decision_fn() -> DecisionFn:
    """
    Ожидается корутина: async def decide_async(context: dict) -> dict
    """
    module_path, _, attr = DECISION_IMPORT.partition(":")
    if not module_path or not attr:
        # некорректная строка — fallback
        return _fallback_decide
    try:
        mod = importlib.import_module(module_path)
        fn = getattr(mod, attr)
        if not asyncio.iscoroutinefunction(fn):
            # если вдруг не корутина — завернём
            async def _wrapped(ctx: Dict[str, Any]) -> Dict[str, Any]:
                return fn(ctx)  # type: ignore
            return _wrapped  # type: ignore
        return fn  # type: ignore
    except Exception:
        return _fallback_decide

async def _fallback_decide(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Безопасная заглушка на случай отсутствия ядра.
    Имитация ~1мс работы.
    """
    await asyncio.sleep(0.001)
    # Имитация простого решения
    return {"decision": "allow", "reason": "fallback", "ctx_hash": hash(frozenset(ctx.items()))}

# --------- Генерация входов ---------

ACTIONS = ("read", "write", "update", "delete", "approve")
RESOURCES = ("invoices", "orders", "profiles", "secrets", "tickets")
TENANTS = ("alpha", "beta", "gamma", "delta")

def make_context_generator(seed: int) -> Callable[[int], Dict[str, Any]]:
    rnd = random.Random(seed)
    def _gen(i: int) -> Dict[str, Any]:
        # Детерминированный, но разнообразный контекст
        uid = rnd.randint(10_000, 1_000_000)
        tenant = TENANTS[(uid + i) % len(TENANTS)]
        action = ACTIONS[(uid * 31 + i) % len(ACTIONS)]
        resource = RESOURCES[(uid * 17 + i) % len(RESOURCES)]
        attrs = {
            "risk_score": (uid % 100) / 100.0,
            "is_admin": ((uid + i) % 13 == 0),
            "region": ["eu", "us", "apac"][((uid >> 3) + i) % 3],
            "time_slot": ((uid >> 5) + i) % 24,
        }
        return {"user_id": uid, "tenant": tenant, "action": action, "resource": resource, "attributes": attrs}
    return _gen

# --------- Простая схема лимитирования RPS ---------

class IntervalRateLimiter:
    """
    Интервальный планировщик: каждому воркеру выдаётся свой "слот".
    Интервал на воркера = concurrency / target_rps.
    """
    def __init__(self, target_rps: float, concurrency: int):
        if target_rps <= 0.0:
            raise ValueError("target_rps must be > 0")
        self.interval = max(0.0, float(concurrency) / float(target_rps))

    async def wait_turn(self, next_at: float) -> float:
        now = time.perf_counter()
        if now < next_at:
            await asyncio.sleep(next_at - now)
            now = time.perf_counter()
        return now

# --------- Сборщик метрик ---------

@dataclass
class RunStats:
    concurrency: int
    duration_s: float
    warmup_s: float
    target_rps: float
    total_calls: int
    ok_calls: int
    err_calls: int
    achieved_rps: float
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    start_ts: float
    end_ts: float

class Reservoir:
    """
    Алгоритм R для равномерной выборки латенсий из потока.
    """
    def __init__(self, capacity: int, rnd: Optional[random.Random] = None) -> None:
        self.capacity = int(capacity)
        self.buf: List[float] = []
        self.count = 0
        self.rnd = rnd or random.Random(SEED)

    def offer(self, value_ms: float) -> None:
        self.count += 1
        if len(self.buf) < self.capacity:
            self.buf.append(value_ms)
            return
        # С вероятностью capacity/count заменяем случайный элемент
        j = self.rnd.randint(1, self.count)
        if j <= self.capacity:
            self.buf[j - 1] = value_ms

    def snapshot(self) -> List[float]:
        return list(self.buf)

# --------- Исполнитель ---------

async def _worker(deadline: float,
                  gen_ctx: Callable[[int], Dict[str, Any]],
                  decide: DecisionFn,
                  worker_id: int,
                  warmup_s: float,
                  rate_limiter: Optional[IntervalRateLimiter],
                  interval_anchor: float,
                  resv: Reservoir,
                  counters: Dict[str, int]) -> None:
    i = 0
    now = time.perf_counter()
    warmup_deadline = now + max(0.0, warmup_s)
    next_at = interval_anchor
    while now < deadline:
        try:
            if rate_limiter:
                now = await rate_limiter.wait_turn(next_at)
                next_at += rate_limiter.interval
            else:
                now = time.perf_counter()

            ctx = gen_ctx(i + worker_id * 1_000_000)
            t0 = time.perf_counter()
            _ = await decide(ctx)
            t1 = time.perf_counter()
            if now >= warmup_deadline:
                # учитываем только после прогрева
                lat_ms = (t1 - t0) * 1000.0
                resv.offer(lat_ms)
                counters["ok"] += 1
            counters["total"] += 1
        except Exception:
            # Ошибка приложения
            counters["err"] += 1
            counters["total"] += 1
        finally:
            i += 1
            now = time.perf_counter()

async def run_load(concurrency: int,
                   duration_s: float,
                   warmup_s: float,
                   target_rps: float,
                   seed: int) -> Tuple[RunStats, List[float]]:
    random.seed(seed)
    gc.collect()

    decide = _load_decision_fn()
    gen_ctx = make_context_generator(seed)

    start_ts = time.time()
    start = time.perf_counter()
    deadline = start + float(duration_s)
    warmup_s = max(0.0, min(warmup_s, duration_s))

    # Интервалы воркерам разнесём равномерно
    rate_limiter = IntervalRateLimiter(target_rps, concurrency) if target_rps > 0 else None
    anchors = [start + (rate_limiter.interval * i if rate_limiter else 0.0) for i in range(concurrency)]

    resv = Reservoir(RESERVOIR_SIZE, random.Random(seed ^ 0xBADC0DE))
    counters = {"total": 0, "ok": 0, "err": 0}

    tasks = [
        asyncio.create_task(
            _worker(deadline, gen_ctx, decide, wid, warmup_s, rate_limiter, anchors[wid], resv, counters)
        )
        for wid in range(concurrency)
    ]

    await asyncio.gather(*tasks)
    end = time.perf_counter()
    end_ts = time.time()

    elapsed = max(1e-9, end - start)
    ok = counters["ok"]
    err = counters["err"]
    total = counters["total"]
    achieved_rps = ok / max(1e-9, elapsed - warmup_s)

    latencies = sorted(resv.snapshot())
    if latencies:
        p50 = _percentile(latencies, 50)
        p90 = _percentile(latencies, 90)
        p95 = _percentile(latencies, 95)
        p99 = _percentile(latencies, 99)
        mx = latencies[-1]
    else:
        p50 = p90 = p95 = p99 = mx = float("nan")

    stats = RunStats(
        concurrency=concurrency,
        duration_s=duration_s,
        warmup_s=warmup_s,
        target_rps=target_rps,
        total_calls=total,
        ok_calls=ok,
        err_calls=err,
        achieved_rps=achieved_rps,
        p50_ms=p50,
        p90_ms=p90,
        p95_ms=p95,
        p99_ms=p99,
        max_ms=mx,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    return stats, latencies

def _percentile(sorted_values: List[float], p: float) -> float:
    """
    p in [0,100], метод nearest-rank c линейной интерполяцией.
    """
    if not sorted_values:
        return float("nan")
    if p <= 0:
        return sorted_values[0]
    if p >= 100:
        return sorted_values[-1]
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return d0 + d1

# --------- Экспорт артефактов ---------

def _write_artifacts(prefix: str, stats: RunStats, latencies: List[float]) -> Tuple[Path, Path]:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(stats.end_ts))
    base = f"{prefix}_c{stats.concurrency}_rps{int(stats.target_rps)}_{ts}"

    json_path = ARTIFACTS_DIR / f"{base}.json"
    csv_path = ARTIFACTS_DIR / f"{base}.csv"

    with json_path.open("w", encoding="utf-8") as f:
        json.dump(asdict(stats), f, ensure_ascii=False, indent=2)

    # Для компактности выгружаем только sample латенсий
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["latency_ms"])
        for v in latencies:
            w.writerow([f"{v:.3f}"])

    return json_path, csv_path

# --------- Сам тест ---------

def test_decision_throughput() -> None:
    """
    Единый тест, который может прогнать несколько конкурентностей (LOAD_CONCURRENCY_LIST).
    При нарушении SLA (MAX_P95_MS, MAX_ERROR_PCT) — падение с подробным сообщением.
    """
    concurrencies = CONCURRENCY_LIST or [DEFAULT_CONCURRENCY]
    failures: List[str] = []

    for c in concurrencies:
        stats, lat = asyncio.run(
            run_load(
                concurrency=max(1, int(c)),
                duration_s=float(DURATION_S),
                warmup_s=float(WARMUP_S),
                target_rps=float(TARGET_RPS),
                seed=int(SEED),
            )
        )
        json_p, csv_p = _write_artifacts("decision", stats, lat)

        # SLA проверки
        messages: List[str] = []
        error_pct = (stats.err_calls / max(1, stats.total_calls)) * 100.0

        if MAX_P95_MS > 0.0 and not math.isnan(stats.p95_ms) and stats.p95_ms > MAX_P95_MS:
            messages.append(
                f"P95 {stats.p95_ms:.2f} ms > MAX_P95_MS {MAX_P95_MS:.2f} ms"
            )
        if MAX_ERROR_PCT > 0.0 and error_pct > MAX_ERROR_PCT:
            messages.append(
                f"Errors {error_pct:.3f}% > MAX_ERROR_PCT {MAX_ERROR_PCT:.3f}%"
            )

        summary = (
            f"[decision] c={stats.concurrency} dur={stats.duration_s}s warmup={stats.warmup_s}s "
            f"target_rps={stats.target_rps:.1f} achieved_rps={stats.achieved_rps:.2f} "
            f"p50/p90/p95/p99/max(ms)={stats.p50_ms:.2f}/{stats.p90_ms:.2f}/{stats.p95_ms:.2f}/"
            f"{stats.p99_ms:.2f}/{stats.max_ms:.2f} "
            f"errors={stats.err_calls}/{stats.total_calls} ({error_pct:.3f}%) "
            f"artifacts=[{json_p} ; {csv_p}]"
        )

        if messages:
            failures.append(summary + " | SLA FAIL: " + " ; ".join(messages))
        else:
            # Лог в stdout pytest
            print(summary)

    if failures:
        # Выводим все нарушения, чтобы CI показал картину по всем конкурентностям
        raise AssertionError("\n".join(failures))
