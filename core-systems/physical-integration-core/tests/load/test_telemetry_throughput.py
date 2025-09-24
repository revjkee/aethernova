# -*- coding: utf-8 -*-
"""
Промышленный нагрузочный тест throughput/latency для контура телеметрии.

Запуск (примеры):
  pytest -q physical-integration-core/tests/load/test_telemetry_throughput.py
  EXPECTED_RATE_FACTOR=0.92 TARGET_RATE=5000 DURATION_S=20 pytest -q ...
  INGEST_CALLABLE="my_project.ingest:ingest_async" pytest -q ...

Переменные окружения (основные):
  TARGET_RATE            целевая скорость сообщений в секунду (int, по умолч. 2000)
  CONCURRENCY            число параллельных воркеров (int, по умолч. 64)
  MSG_SIZE               размер полезной нагрузки в байтах (int, по умолч. 512)
  DURATION_S             длительность фазы измерений, сек (int, по умолч. 10)
  WARMUP_S               длительность прогрева, сек (int, по умолч. 2)
  EXPECTED_RATE_FACTOR   доля от TARGET_RATE, ниже которой фейлим (float, по умолч. 0.90)
  MAX_ERROR_RATE         максимум ошибок ACK (доля, по умолч. 0.005)
  ARTIFACTS_DIR          куда писать артефакты (по умолч. artifacts/tests/load)
  PROFILE                FAST|CI|FULL — предустановленные тайминги (опционально)
  INGEST_CALLABLE        "module.submod:function" реального асинхронного инжеста (опционально)
  SIM_ACK_MEAN_MS        средняя симулированная задержка ACK в мс (по умолч. 2.0)
  SIM_ACK_P99_MS         p99 симулированной задержки ACK в мс (по умолч. 8.0)
"""

from __future__ import annotations

import asyncio
import importlib
import json
import math
import os
import random
import signal
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, List, Optional, Tuple

try:
    import psutil  # type: ignore
except Exception:
    psutil = None  # graceful degradation

try:
    import uvloop  # type: ignore
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except Exception:
    pass

import pytest


# ------------------------- Конфиг и утилиты -------------------------

def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    return float(v) if v is not None else default

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    return int(v) if v is not None else default

def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v is not None else default


def apply_profile(defaults: dict) -> dict:
    """
    Профили под разные режимы CI/локально.
    FAST: коротко, минимально.
    CI: умеренно.
    FULL: длинная сессия.
    """
    profile = os.getenv("PROFILE", "").upper()
    cfg = defaults.copy()
    if profile == "FAST":
        cfg.update(dict(DURATION_S=5, WARMUP_S=1, TARGET_RATE=min(1000, cfg["TARGET_RATE"]), CONCURRENCY=min(16, cfg["CONCURRENCY"])))
    elif profile == "CI":
        cfg.update(dict(DURATION_S=max(8, cfg["DURATION_S"]), WARMUP_S=max(2, cfg["WARMUP_S"])))
    elif profile == "FULL":
        cfg.update(dict(DURATION_S=max(30, cfg["DURATION_S"]), WARMUP_S=max(5, cfg["WARMUP_S"]), CONCURRENCY=max(64, cfg["CONCURRENCY"])))
    return cfg


DEFAULTS = apply_profile({
    "TARGET_RATE": _env_int("TARGET_RATE", 2000),
    "CONCURRENCY": _env_int("CONCURRENCY", 64),
    "MSG_SIZE": _env_int("MSG_SIZE", 512),
    "DURATION_S": _env_int("DURATION_S", 10),
    "WARMUP_S": _env_int("WARMUP_S", 2),
    "EXPECTED_RATE_FACTOR": _env_float("EXPECTED_RATE_FACTOR", 0.90),
    "MAX_ERROR_RATE": _env_float("MAX_ERROR_RATE", 0.005),
    "ARTIFACTS_DIR": _env_str("ARTIFACTS_DIR", "artifacts/tests/load"),
    "INGEST_CALLABLE": os.getenv("INGEST_CALLABLE", ""),  # "module.submod:function"
    "SIM_ACK_MEAN_MS": _env_float("SIM_ACK_MEAN_MS", 2.0),
    "SIM_ACK_P99_MS": _env_float("SIM_ACK_P99_MS", 8.0),
})


def ensure_artifacts_dir(path: str) -> Path:
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    if p <= 0:
        return min(values)
    if p >= 100:
        return max(values)
    k = (len(values) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted(values)[int(k)])
    low, high = sorted(values)[f], sorted(values)[c]
    return float(low + (high - low) * (k - f))


# ------------------------- Rate Limiter (Token Bucket) -------------------------

class TokenBucket:
    """
    Централизованный токен‑бакет для согласованного RATE по всем воркерам.
    """
    def __init__(self, rate_per_sec: float, burst: Optional[int] = None):
        self.rate = float(rate_per_sec)
        self.capacity = float(burst if burst is not None else max(1, int(rate_per_sec)))
        self._tokens = self.capacity
        self._last = time.perf_counter()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """
        Блокирующая выдача одного токена. Ограничивает общую скорость.
        """
        while True:
            async with self._lock:
                now = time.perf_counter()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            # мелкая пауза до следующего рефилла
            await asyncio.sleep(0)


# ------------------------- CPU/RSS Sampler -------------------------

class SysSampler:
    def __init__(self, interval: float = 0.5):
        self.interval = interval
        self.samples_cpu = []  # %
        self.samples_rss = []  # bytes
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._proc = psutil.Process() if psutil else None

    async def _run(self):
        if self._proc and hasattr(self._proc, "cpu_percent"):
            self._proc.cpu_percent(None)  # reset
        while not self._stop.is_set():
            if self._proc:
                try:
                    self.samples_cpu.append(self._proc.cpu_percent(None))
                    self.samples_rss.append(self._proc.memory_info().rss)
                except Exception:
                    pass
            await asyncio.sleep(self.interval)

    async def start(self):
        if self._task is None:
            self._stop.clear()
            self._task = asyncio.create_task(self._run())

    async def stop(self):
        if self._task:
            self._stop.set()
            await self._task
            self._task = None

    def summary(self) -> dict:
        cpu = self.samples_cpu
        rss = self.samples_rss
        return {
            "cpu_avg_pct": float(statistics.fmean(cpu)) if cpu else 0.0,
            "cpu_max_pct": float(max(cpu)) if cpu else 0.0,
            "rss_avg_bytes": float(statistics.fmean(rss)) if rss else 0.0,
            "rss_max_bytes": float(max(rss)) if rss else 0.0,
        }


# ------------------------- Инжест (сим/реальный) -------------------------

IngestCallable = Callable[[bytes], Awaitable[None]]

def load_ingest_callable(cfg: dict) -> IngestCallable:
    """
    Если задан INGEST_CALLABLE="module.sub:function", импортируем и используем его.
    Иначе — быстрый симулированный ACK с параметрами SIM_ACK_MEAN_MS/P99.
    """
    spec = cfg.get("INGEST_CALLABLE") or ""
    if spec:
        mod_name, func_name = spec.split(":")
        mod = importlib.import_module(mod_name)
        func = getattr(mod, func_name)
        if not asyncio.iscoroutinefunction(func):
            raise TypeError("INGEST_CALLABLE должен быть асинхронной функцией")
        return func  # type: ignore

    # Симулятор: логнормальное распределение задержек с заданными mean/p99
    mean_ms = float(cfg["SIM_ACK_MEAN_MS"])
    p99_ms = float(cfg["SIM_ACK_P99_MS"])

    # Подбираем параметры логнормали так, чтобы 50% и 99% примерно совпали с ожиданиями
    # Эвристика: найдём sigma по p99/median, затем mu из mean.
    median_ms = max(0.5, mean_ms * 0.7)
    sigma = max(0.1, math.log(p99_ms / median_ms) / 2.326)  # 2.326 ~ z(99%)
    mu = math.log(mean_ms) - 0.5 * sigma * sigma

    async def _simulated_ingest(payload: bytes) -> None:
        # имитируем асинхронный ACK
        delay_ms = random.lognormvariate(mu, sigma)
        await asyncio.sleep(delay_ms / 1000.0)

    return _simulated_ingest


# ------------------------- Сбор метрик -------------------------

@dataclass
class Counters:
    sent: int = 0
    acks: int = 0
    errors: int = 0


@dataclass
class Metrics:
    latencies_ms: List[float]
    counters: Counters


# ------------------------- Воркеры нагрузки -------------------------

async def worker_loop(
    wid: int,
    bucket: TokenBucket,
    ingest: IngestCallable,
    payload: bytes,
    stop_at: float,
    record_latency_ms: List[float],
    counters: Counters,
) -> None:
    """
    Один воркер: получает токены, отправляет, замеряет ttfb->ack.
    """
    while True:
        now = time.perf_counter()
        if now >= stop_at:
            return
        await bucket.acquire()
        t0 = time.perf_counter()
        counters.sent += 1
        try:
            await ingest(payload)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            record_latency_ms.append(dt_ms)
            counters.acks += 1
        except Exception:
            counters.errors += 1


# ------------------------- Основной тест -------------------------

@pytest.mark.asyncio
async def test_telemetry_throughput():
    """
    Валидирует, что достигнут SLA по throughput/latency/error‑rate при заданных параметрах.
    Результаты и конфиг пишутся в artifacts для аудита.
    """
    cfg = DEFAULTS.copy()

    artifacts_dir = ensure_artifacts_dir(cfg["ARTIFACTS_DIR"])

    # Подготовка полезной нагрузки
    msg_size = int(cfg["MSG_SIZE"])
    payload = (b"x" * msg_size)

    # Инжест
    ingest = load_ingest_callable(cfg)

    # Тайминги
    warmup_s = int(cfg["WARMUP_S"])
    duration_s = int(cfg["DURATION_S"])
    target_rate = float(cfg["TARGET_RATE"])
    concurrency = int(cfg["CONCURRENCY"])
    expected_rate_factor = float(cfg["EXPECTED_RATE_FACTOR"])
    max_error_rate = float(cfg["MAX_ERROR_RATE"])

    # Токен‑бакет: небольшой burst для сглаживания квантования таймера
    bucket = TokenBucket(rate_per_sec=target_rate, burst=max(int(target_rate // 2), 1))

    # Прогрев
    if warmup_s > 0:
        stop_warm = time.perf_counter() + warmup_s
        warm_lat = []
        warm_cnt = Counters()
        tasks = [
            asyncio.create_task(worker_loop(i, bucket, ingest, payload, stop_warm, warm_lat, warm_cnt))
            for i in range(min(concurrency, 8))
        ]
        await asyncio.gather(*tasks)

    # Основная фаза измерений
    sampler = SysSampler()
    await sampler.start()
    metrics_lat = []
    counters = Counters()

    stop_main = time.perf_counter() + duration_s
    tasks = [
        asyncio.create_task(worker_loop(i, bucket, ingest, payload, stop_main, metrics_lat, counters))
        for i in range(concurrency)
    ]

    # Корректная остановка по сигналам
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_sig():
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            pass  # Windows/CI

    # Ждём завершения или сигнал
    try:
        while time.perf_counter() < stop_main and not stop_event.is_set():
            await asyncio.sleep(0.1)
    finally:
        # Останавливаем воркеров так, чтобы они сами вышли по stop_main
        await asyncio.gather(*tasks, return_exceptions=True)
        await sampler.stop()

    # Подсчёты
    elapsed = float(duration_s)  # фактически ±, но мы завершили по таймеру
    actual_rate = counters.acks / elapsed if elapsed > 0 else 0.0
    err_rate = (counters.errors / max(1, counters.sent))
    lat_p50 = percentile(metrics_lat, 50.0)
    lat_p95 = percentile(metrics_lat, 95.0)
    lat_p99 = percentile(metrics_lat, 99.0)
    lat_mean = float(statistics.fmean(metrics_lat)) if metrics_lat else 0.0
    lat_max = max(metrics_lat) if metrics_lat else 0.0

    sys_summary = sampler.summary()

    summary = {
        "config": {
            "target_rate": target_rate,
            "concurrency": concurrency,
            "msg_size": msg_size,
            "duration_s": duration_s,
            "warmup_s": warmup_s,
            "expected_rate_factor": expected_rate_factor,
            "max_error_rate": max_error_rate,
            "ingest_callable": cfg.get("INGEST_CALLABLE") or "SIMULATED",
            "profile": os.getenv("PROFILE", ""),
        },
        "results": {
            "elapsed_s": elapsed,
            "sent": counters.sent,
            "acks": counters.acks,
            "errors": counters.errors,
            "actual_rate_eps": actual_rate,
            "error_rate": err_rate,
            "lat_mean_ms": lat_mean,
            "lat_p50_ms": lat_p50,
            "lat_p95_ms": lat_p95,
            "lat_p99_ms": lat_p99,
            "lat_max_ms": lat_max,
        },
        "system": sys_summary,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # Пишем артефакты
    run_id = f"rate{int(target_rate)}-c{concurrency}-s{msg_size}-{int(time.time())}"
    summary_path = artifacts_dir / f"throughput_summary_{run_id}.json"
    lat_path = artifacts_dir / f"latencies_{run_id}.csv"

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    # Чтобы не раздувать репозиторий, ограничим выгрузку латентностей
    MAX_LAT_DUMP = 250_000
    if metrics_lat:
        with open(lat_path, "w", encoding="utf-8") as f:
            f.write("latency_ms\n")
            for v in (metrics_lat if len(metrics_lat) <= MAX_LAT_DUMP else metrics_lat[:MAX_LAT_DUMP]):
                f.write(f"{v:.6f}\n")

    # ------------------------- Ассерты SLA -------------------------
    # Throughput
    min_rate = target_rate * expected_rate_factor
    assert actual_rate >= min_rate, (
        f"Throughput SLA not met: actual={actual_rate:.1f} eps, required>={min_rate:.1f} eps "
        f"(target={target_rate:.1f}, factor={expected_rate_factor}) | summary={summary_path}"
    )

    # Error‑rate
    assert err_rate <= max_error_rate, (
        f"Error‑rate SLA not met: err_rate={err_rate:.5f}, allowed<={max_error_rate:.5f} | summary={summary_path}"
    )

    # Latency sanity‑checks (мягкие пороги для симуляции; при реальном инжесте подстройте через окружение)
    # Не жёсткие SLA, а здравый контроль, чтобы не улететь в секунды.
    assert lat_p99 < 1000.0, f"p99 latency is too high: {lat_p99:.2f} ms | summary={summary_path}"

    # Финальная печать краткого отчёта в лог pytest (удобно в CI)
    print(
        json.dumps(
            {
                "run_id": run_id,
                "actual_rate_eps": round(actual_rate, 2),
                "sent": counters.sent,
                "acks": counters.acks,
                "errors": counters.errors,
                "err_rate": round(err_rate, 6),
                "lat_ms": {"p50": round(lat_p50, 2), "p95": round(lat_p95, 2), "p99": round(lat_p99, 2)},
                "artifacts": {"summary": str(summary_path), "latencies_csv": str(lat_path)},
            },
            ensure_ascii=False,
        )
    )
