# datafabric-core/tests/load/test_throughput.py
# Нагрузочный тест Throughput/Latency для локального "микро-пайплайна"
# Требования: pytest, стандартная библиотека. Опционально: datafabric.utils.backpressure.
#
# Запуск:
#   pytest -q -m load tests/load/test_throughput.py
#
# Маркеры:
#   @pytest.mark.load  — нагрузочные/производительные тесты
#
# Конфигурация через ENV (значения по умолчанию подобраны под CI):
#   DF_LOAD_TOTAL              — общее число событий для steady-state (default: 20000)
#   DF_LOAD_WARMUP             — warmup событий (default: 2000)
#   DF_LOAD_PARALLEL           — уровень параллелизма (default: 16)
#   DF_LOAD_TARGET_RPS         — целевой RPS лимитера (default: 500)
#   DF_LOAD_MODE               — sync|async (default: sync)
#   DF_LOAD_IO_MEAN_MS         — средняя "I/O" задержка на событие (эксп. распр.) (default: 2.0)
#   DF_LOAD_IO_P95_MS          — p95 задержка (поджимается под эксп. распр.) (default: 10.0)
#   DF_LOAD_ASSERT_RPS         — минимальный средний RPS (default: 300)
#   DF_LOAD_ASSERT_P95_MS      — максимум p95 в steady-state (default: 40.0)
#   DF_LOAD_REPORT_DIR         — путь для сохранения отчёта JSON (default: ./_perf)
#   DF_LOAD_SEED               — seed PRNG (default: 42)
#
# Что именно тестируем:
#   - Ограничиваем входной rate токен-бакетом до TARGET_RPS.
#   - Параллельная обработка с имитацией I/O (случайная задержка, heavy-tail).
#   - Сбор латентностей end-to-end для каждой записи и итоговая агрегация.
#   - Валидируем SLA по RPS и p95; сохраняем отчёт для тренда в CI.

from __future__ import annotations

import asyncio
import json
import math
import os
import random
import statistics
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

load = pytest.mark.load


# =============== Утилиты статистики и лимитирования ===============

class EWMA:
    def __init__(self, alpha: float = 0.2):
        self.alpha = alpha
        self.value: Optional[float] = None
    def update(self, x: float) -> float:
        if self.value is None:
            self.value = x
        else:
            self.value = self.alpha * x + (1 - self.alpha) * self.value
        return self.value

class Histogram:
    def __init__(self, bins: Optional[List[float]] = None):
        # Границы в мс
        self.bins = bins or [1,2,5,10,20,50,100,200,500,1000]
        self.counts = [0 for _ in self.bins] + [0]
        self.samples: List[float] = []
    def add(self, ms: float) -> None:
        self.samples.append(ms)
        for i, b in enumerate(self.bins):
            if ms <= b:
                self.counts[i] += 1
                return
        self.counts[-1] += 1
    def percentiles(self, qs=(0.5,0.95,0.99)) -> Dict[str, float]:
        if not self.samples:
            return {f"p{int(q*100)}": 0.0 for q in qs}
        s = sorted(self.samples)
        def pct(q: float) -> float:
            k = max(0, min(len(s)-1, int(math.ceil(q*len(s))-1)))
            return float(s[k])
        return {f"p{int(q*100)}": pct(q) for q in qs}
    def mean(self) -> float:
        return float(statistics.mean(self.samples)) if self.samples else 0.0

class TokenBucket:
    def __init__(self, rate: float, capacity: Optional[float] = None):
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else rate)
        self.tokens = self.capacity
        self.ts = time.monotonic()
        self.lock = threading.Lock()
    def _refill(self):
        now = time.monotonic()
        dt = now - self.ts
        if dt > 0:
            self.tokens = min(self.capacity, self.tokens + dt * self.rate)
            self.ts = now
    def wait(self, amount: float = 1.0):
        while True:
            with self.lock:
                self._refill()
                if self.tokens >= amount:
                    self.tokens -= amount
                    return
                need = (amount - self.tokens) / self.rate if self.rate > 0 else 0.001
            time.sleep(max(0.0, need))

# Попытка использовать промышленный BackpressureController из репозитория
_BP = None
try:
    from datafabric.utils.backpressure import BackpressureController  # type: ignore
    _BP = BackpressureController  # type: ignore
except Exception:
    _BP = None


# =============== Конфиг теста ===============

@dataclass
class LoadConfig:
    total: int = int(os.getenv("DF_LOAD_TOTAL", "20000"))
    warmup: int = int(os.getenv("DF_LOAD_WARMUP", "2000"))
    parallel: int = int(os.getenv("DF_LOAD_PARALLEL", "16"))
    target_rps: float = float(os.getenv("DF_LOAD_TARGET_RPS", "500"))
    mode: str = os.getenv("DF_LOAD_MODE", "sync").lower()  # sync|async
    io_mean_ms: float = float(os.getenv("DF_LOAD_IO_MEAN_MS", "2.0"))
    io_p95_ms: float = float(os.getenv("DF_LOAD_IO_P95_MS", "10.0"))
    assert_rps: float = float(os.getenv("DF_LOAD_ASSERT_RPS", "300"))
    assert_p95_ms: float = float(os.getenv("DF_LOAD_ASSERT_P95_MS", "40.0"))
    report_dir: str = os.getenv("DF_LOAD_REPORT_DIR", "./_perf")
    seed: int = int(os.getenv("DF_LOAD_SEED", "42"))

    def __post_init__(self):
        self.mode = "async" if self.mode == "async" else "sync"
        # Подгон параметров эксп. распред. под заданный p95 и mean
        # Для exp: p95 ≈ ln(20)*theta; theta≈mean => при несовпадении — используем mean, p95 как sanity.
        self.theta = max(0.0001, self.io_mean_ms / 1000.0)
        self.p95_bound = self.io_p95_ms

# =============== Имитация обработки ===============

def simulate_io_sleep_ms(rnd: random.Random, cfg: LoadConfig) -> float:
    # экспоненциальная задержка с усечением по p95_bound*3
    delay_s = rnd.expovariate(1.0 / cfg.theta)
    max_s = (cfg.p95_bound / 1000.0) * 3.0
    delay_s = min(delay_s, max_s)
    time.sleep(delay_s)
    return delay_s * 1000.0

async def simulate_io_sleep_ms_async(rnd: random.Random, cfg: LoadConfig) -> float:
    delay_s = rnd.expovariate(1.0 / cfg.theta)
    max_s = (cfg.p95_bound / 1000.0) * 3.0
    delay_s = min(delay_s, max_s)
    await asyncio.sleep(delay_s)
    return delay_s * 1000.0

# =============== Основной тест ===============

@load
def test_pipeline_throughput_and_latency(tmp_path: Path):
    """
    Нагрузочный тест: прогрев + стабильная нагрузка.
    Проверяет средний RPS и p95 latency, сохраняет отчёт JSON.
    """
    cfg = LoadConfig()
    rnd = random.Random(cfg.seed)

    # Метрики
    hist_warm = Histogram()
    hist = Histogram()
    ewma_rps = EWMA(alpha=0.3)

    # Лимитер
    if _BP is not None:
        bp = _BP(target_rps=cfg.target_rps, max_parallel=cfg.parallel)
        token_wait = lambda: None  # лимитер сам ограничит в guard
    else:
        bucket = TokenBucket(rate=cfg.target_rps, capacity=cfg.target_rps)
        token_wait = lambda: bucket.wait(1.0)
        bp = None

    # ========== Прогрев ==========
    t0 = time.monotonic()
    if cfg.mode == "sync":
        from concurrent.futures import ThreadPoolExecutor, as_completed
        def work_unit(i: int) -> float:
            t_start = time.monotonic()
            token_wait()
            if bp:
                @bp.guard()
                def _do():
                    return simulate_io_sleep_ms(rnd, cfg)
                io_ms = _do()
            else:
                io_ms = simulate_io_sleep_ms(rnd, cfg)
            return (time.monotonic() - t_start) * 1000.0

        with ThreadPoolExecutor(max_workers=cfg.parallel, thread_name_prefix="load") as ex:
            futs = [ex.submit(work_unit, i) for i in range(cfg.warmup)]
            for f in as_completed(futs):
                hist_warm.add(f.result())
    else:
        async def warmup_async():
            sem = asyncio.Semaphore(cfg.parallel)
            async def run_one(i: int):
                t_start = time.monotonic()
                token_wait()
                if bp:
                    # Используем async лимитер, если доступен; иначе — просто sem
                    res = await bp.aretry_with_backoff(lambda: simulate_io_sleep_ms_async(rnd, cfg), should_retry=lambda e: False, max_attempts=1)  # type: ignore
                    io_ms = res
                else:
                    async with sem:
                        io_ms = await simulate_io_sleep_ms_async(rnd, cfg)
                return (time.monotonic() - t_start) * 1000.0
            tasks = [asyncio.create_task(run_one(i)) for i in range(cfg.warmup)]
            for coro in asyncio.as_completed(tasks):
                hist_warm.add(await coro)
        asyncio.run(warmup_async())
    t1 = time.monotonic()

    # ========== Замер (steady-state) ==========
    produced = 0
    t_start = time.monotonic()

    if cfg.mode == "sync":
        from concurrent.futures import ThreadPoolExecutor, as_completed
        def work_unit(i: int) -> float:
            t0u = time.monotonic()
            token_wait()
            if bp:
                @bp.guard()
                def _do():
                    return simulate_io_sleep_ms(rnd, cfg)
                io_ms = _do()
            else:
                io_ms = simulate_io_sleep_ms(rnd, cfg)
            return (time.monotonic() - t0u) * 1000.0

        with ThreadPoolExecutor(max_workers=cfg.parallel, thread_name_prefix="load") as ex:
            futs = [ex.submit(work_unit, i) for i in range(cfg.total)]
            for f in as_completed(futs):
                lat = f.result()
                hist.add(lat)
                produced += 1
                elapsed = time.monotonic() - t_start
                if elapsed > 0:
                    ewma_rps.update(produced / elapsed)
    else:
        async def steady_async():
            nonlocal produced
            sem = asyncio.Semaphore(cfg.parallel)
            async def run_one(i: int):
                t0u = time.monotonic()
                token_wait()
                if bp:
                    res = await bp.aretry_with_backoff(lambda: simulate_io_sleep_ms_async(rnd, cfg), should_retry=lambda e: False, max_attempts=1)  # type: ignore
                    io_ms = res
                else:
                    async with sem:
                        io_ms = await simulate_io_sleep_ms_async(rnd, cfg)
                return (time.monotonic() - t0u) * 1000.0
            tasks = [asyncio.create_task(run_one(i)) for i in range(cfg.total)]
            for coro in asyncio.as_completed(tasks):
                lat = await coro
                hist.add(lat)
                produced += 1
                elapsed = time.monotonic() - t_start
                if elapsed > 0:
                    ewma_rps.update(produced / elapsed)
        asyncio.run(steady_async())

    t_end = time.monotonic()
    total_time = t_end - t_start
    rps = produced / total_time if total_time > 0 else 0.0
    pct = hist.percentiles((0.5, 0.95, 0.99))

    report = {
        "config": asdict(cfg),
        "warmup": {"events": cfg.warmup, "time_s": t1 - t0, "p95_ms": Histogram().percentiles().get("p95", None)},
        "results": {
            "events": produced,
            "time_s": total_time,
            "rps_avg": rps,
            "rps_ewma": ewma_rps.value or rps,
            "lat_mean_ms": hist.mean(),
            "lat_p50_ms": pct["p50"],
            "lat_p95_ms": pct["p95"],
            "lat_p99_ms": pct["p99"],
            "hist_bins_ms": hist.bins,
            "hist_counts": hist.counts,
            "mode": cfg.mode,
            "parallel": cfg.parallel,
        }
    }

    # Локальный вывод и сохранение отчёта для CI‑артефактов
    report_dir = Path(cfg.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    out_path = report_dir / f"throughput_{cfg.mode}_p{cfg.parallel}_r{int(cfg.target_rps)}.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[load] report: {out_path}  RPS={rps:.1f}  p95={pct['p95']:.1f}ms")

    # ========== Проверки SLA ==========
    assert rps >= cfg.assert_rps, f"Средний RPS ниже порога: {rps:.1f} < {cfg.assert_rps}"
    assert pct["p95"] <= cfg.assert_p95_ms, f"p95 latency выше порога: {pct['p95']:.1f}ms > {cfg.assert_p95_ms}ms"
