# -*- coding: utf-8 -*-
"""
Промышленный нагрузочный тест "10k клиентов, профили".

ДВА РЕЖИМА:
1) Реальный HTTP-режим (при наличии BASE_URL):
   BASE_URL=http://localhost:8080  RUN_LOAD=1 pytest -q engine/load/test_mass_clients.py

2) Dry-run (без сети, встроенный стаб-клиент):
   RUN_LOAD=1 pytest -q engine/load/test_mass_clients.py

КОНФИГУРАЦИЯ (ENV):
  RUN_LOAD=1                  — обязательный флаг для запуска (иначе skip).
  BASE_URL=...                — если задан, используем httpx AsyncClient (GET/POST /ingest).
  TARGET_PATH=/ingest         — путь ресурса для BASE_URL (по умолчанию /ingest).
  METHOD=POST                 — HTTP метод (GET|POST), по умолчанию POST.
  CLIENTS=10000               — общее число логических клиентов.
  CONCURRENCY=1000            — верхняя граница одновременных запросов (семафор).
  DURATION=60                 — целевая длительность профиля, сек (для steady/soak).
  RAMP_SECONDS=15             — фазовый разгон.
  PROFILE=steady              — steady|burst|soak.
  PAYLOAD_BYTES=512           — размер синтетического payload (POST).
  TIMEOUT=1.5                 — таймаут запроса, сек.
  MAX_QPS=0                   — глобальный лимит QPS (0 = без ограничения).
  JITTER_MS=50                — случайный джиттер межзапросных задержек.
  SEED=42                     — сид генератора.

SLO (ENV):
  SLO_P95_MS=200              — p95, мс.
  SLO_ERR_RATE=0.005          — допустимая доля ошибок (например, 0.005 = 0.5%).
  SLO_RPS_MIN=0               — минимальный RPS (0 = не проверять).

ЗАВИСИМОСТИ:
  - pytest, anyio, (опц.) httpx>=0.24, (опц.) uvloop
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import random
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Callable

import pytest

# Опциональные ускорители
try:
    import uvloop  # type: ignore
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except Exception:
    pass

# Опциональный HTTP‑клиент
try:
    import httpx  # type: ignore
    _HTTPX = True
except Exception:
    _HTTPX = False

# --------------------------------------------------------------------------------------
# Конфиг и утилиты
# --------------------------------------------------------------------------------------

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_str(name: str, default: str) -> str:
    return os.getenv(name, default)

def _pct(sorted_values: List[float], p: float) -> float:
    """Несмещённая квантиль (p в [0,100])."""
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return d0 + d1

@dataclass
class LoadConfig:
    run_load: bool = bool(int(os.getenv("RUN_LOAD", "0")))
    base_url: str = _env_str("BASE_URL", "")
    target_path: str = _env_str("TARGET_PATH", "/ingest")
    method: str = _env_str("METHOD", "POST").upper()
    clients: int = _env_int("CLIENTS", 10_000)
    concurrency: int = _env_int("CONCURRENCY", 1_000)
    duration: int = _env_int("DURATION", 60)
    ramp_seconds: int = _env_int("RAMP_SECONDS", 15)
    profile: str = _env_str("PROFILE", "steady")  # steady|burst|soak
    payload_bytes: int = _env_int("PAYLOAD_BYTES", 512)
    timeout: float = _env_float("TIMEOUT", 1.5)
    max_qps: float = _env_float("MAX_QPS", 0.0)
    jitter_ms: int = _env_int("JITTER_MS", 50)
    seed: int = _env_int("SEED", 42)

@dataclass
class SLO:
    p95_ms: float = _env_float("SLO_P95_MS", 200.0)
    err_rate: float = _env_float("SLO_ERR_RATE", 0.005)
    rps_min: float = _env_float("SLO_RPS_MIN", 0.0)

@dataclass
class Metrics:
    latencies_ms: List[float] = field(default_factory=list)
    ok: int = 0
    errors: int = 0
    timeouts: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def duration(self) -> float:
        return max(0.0001, self.finished_at - self.started_at)

    @property
    def rps(self) -> float:
        return (self.ok + self.errors) / self.duration

    def summary(self) -> Dict[str, Any]:
        lat_sorted = sorted(self.latencies_ms)
        p50 = _pct(lat_sorted, 50)
        p90 = _pct(lat_sorted, 90)
        p95 = _pct(lat_sorted, 95)
        p99 = _pct(lat_sorted, 99)
        return {
            "req_total": self.ok + self.errors,
            "ok": self.ok,
            "errors": self.errors,
            "timeouts": self.timeouts,
            "rps": round(self.rps, 2),
            "lat_ms": {
                "p50": round(p50, 2),
                "p90": round(p90, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2),
                "avg": round(statistics.fmean(lat_sorted) if lat_sorted else 0.0, 2),
            },
            "duration_s": round(self.duration, 2),
        }

# --------------------------------------------------------------------------------------
# Клиентские исполняемые единицы (HTTP и стаб)
# --------------------------------------------------------------------------------------

class TargetClient:
    """Интерфейс целевого клиента."""
    async def request(self, payload: bytes) -> Tuple[bool, float]:
        raise NotImplementedError

class HttpTargetClient(TargetClient):
    def __init__(self, base_url: str, path: str, method: str, timeout_s: float):
        if not _HTTPX:
            raise RuntimeError("httpx не установлен, а BASE_URL задан")
        self._base_url = base_url.rstrip("/")
        self._path = path if path.startswith("/") else f"/{path}"
        self._method = method.upper()
        self._timeout = httpx.Timeout(timeout_s)
        self._client = httpx.AsyncClient(http2=True, timeout=self._timeout)

    async def request(self, payload: bytes) -> Tuple[bool, float]:
        t0 = time.perf_counter()
        try:
            if self._method == "GET":
                resp = await self._client.get(f"{self._base_url}{self._path}")
            else:
                resp = await self._client.post(
                    f"{self._base_url}{self._path}",
                    headers={"content-type": "application/json"},
                    content=payload,
                )
            ok = 200 <= resp.status_code < 300
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return ok, dt_ms
        except httpx.TimeoutException:
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return False, dt_ms
        except Exception:
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return False, dt_ms

    async def aclose(self):
        await self._client.aclose()

class StubTargetClient(TargetClient):
    """Dry-run: имитация ответа сервиса без сети."""
    def __init__(self, mean_ms: float = 8.0, p95_ms: float = 20.0, err_rate: float = 0.002):
        self._mean = mean_ms
        self._p95 = p95_ms
        self._err = err_rate
        random.seed(_env_int("SEED", 42))

    async def request(self, payload: bytes) -> Tuple[bool, float]:
        # Имитация латентности: смешанная экспонента + хвост
        base = random.expovariate(1.0 / self._mean)
        tail = random.random() < 0.05
        sleep_ms = min(self._p95 * 2.5, base if not tail else base + self._p95)
        await asyncio.sleep(sleep_ms / 1000.0)
        ok = random.random() >= self._err
        return ok, sleep_ms

# --------------------------------------------------------------------------------------
# Профили нагрузки и шейпинг
# --------------------------------------------------------------------------------------

class TokenBucket:
    """Глобальный лимитер QPS."""
    def __init__(self, rate_per_sec: float):
        self.rate = max(0.0, rate_per_sec)
        self.tokens = 0.0
        self.updated = time.perf_counter()

    async def take(self):
        if self.rate <= 0.0:
            return
        while True:
            now = time.perf_counter()
            self.tokens += (now - self.updated) * self.rate
            self.updated = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            await asyncio.sleep(0.001)

def _payload(bytes_len: int, idx: int) -> bytes:
    body = {
        "id": f"client-{idx}",
        "ts": int(time.time() * 1000),
        "source": "loadtest",
        "type": "benchmark",
        "payload": {"blob": "x" * max(0, bytes_len - 64)},
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")

async def _worker(worker_id: int,
                  cfg: LoadConfig,
                  metrics: Metrics,
                  client: TargetClient,
                  sem: asyncio.Semaphore,
                  bucket: Optional[TokenBucket],
                  stop_time: float,
                  ids: List[int]):
    rng = random.Random(cfg.seed + worker_id)
    jitter = cfg.jitter_ms / 1000.0

    async with sem:
        for cid in ids:
            if time.perf_counter() >= stop_time:
                break
            if bucket:
                await bucket.take()

            # Профильные задержки между запросами
            if cfg.profile == "steady":
                if cfg.ramp_seconds > 0:
                    # во время разгона — плавное ускорение
                    pass
            elif cfg.profile == "burst":
                # волны нагрузки: 100-200мс пауза и спайки
                await asyncio.sleep(rng.uniform(0.05, 0.2))
            elif cfg.profile == "soak":
                # равномерное распределение во времени
                await asyncio.sleep(rng.uniform(0.0, 0.01))

            if jitter > 0:
                await asyncio.sleep(rng.uniform(0, jitter))

            pld = _payload(cfg.payload_bytes, cid)
            ok, dt_ms = await client.request(pld)
            metrics.latencies_ms.append(dt_ms)
            if ok:
                metrics.ok += 1
            else:
                # эвристика таймаутов
                if dt_ms >= cfg.timeout * 1000.0:
                    metrics.timeouts += 1
                metrics.errors += 1

# --------------------------------------------------------------------------------------
# Главный тест
# --------------------------------------------------------------------------------------

@pytest.mark.load
@pytest.mark.anyio
async def test_mass_clients_profiles():
    cfg = LoadConfig()
    if not cfg.run_load:
        pytest.skip("RUN_LOAD!=1 — пропуск нагрузочного теста по умолчанию")

    slo = SLO()

    # Клиент
    if cfg.base_url:
        if not _HTTPX:
            pytest.skip("BASE_URL задан, но httpx недоступен")
        client: TargetClient = HttpTargetClient(cfg.base_url, cfg.target_path, cfg.method, cfg.timeout)
        closer: Optional[Callable[[], Any]] = getattr(client, "aclose", None)
    else:
        client = StubTargetClient()
        closer = None

    # Шейпер QPS (опционально)
    bucket = TokenBucket(cfg.max_qps) if cfg.max_qps > 0 else None

    # Планирование идентификаторов "клиентов"
    client_ids = list(range(cfg.clients))
    rnd = random.Random(cfg.seed)
    rnd.shuffle(client_ids)

    # Распределение по воркерам
    concurrency = max(1, min(cfg.concurrency, cfg.clients))
    ids_per_worker = math.ceil(len(client_ids) / concurrency)
    assignments: List[List[int]] = [
        client_ids[i * ids_per_worker : (i + 1) * ids_per_worker] for i in range(concurrency)
    ]

    sem = asyncio.Semaphore(concurrency)
    metrics = Metrics()
    metrics.started_at = time.perf_counter()
    stop_time = metrics.started_at + max(1.0, cfg.duration)

    workers = [
        _worker(i, cfg, metrics, client, sem, bucket, stop_time, ids)
        for i, ids in enumerate(assignments)
        if ids
    ]

    try:
        await asyncio.gather(*workers)
    finally:
        metrics.finished_at = time.perf_counter()
        if closer:
            await closer()  # type: ignore

    summary = metrics.summary()

    # Лаконичный лог для CI
    print("\n=== LOAD SUMMARY ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    # Валидация SLO
    err_rate = (metrics.errors / max(1, (metrics.ok + metrics.errors)))
    p95 = summary["lat_ms"]["p95"]
    rps = summary["rps"]

    assert p95 <= slo.p95_ms, f"SLO p95_ms breached: {p95} > {slo.p95_ms}"
    assert err_rate <= slo.err_rate, f"SLO error_rate breached: {err_rate:.4f} > {slo.err_rate:.4f}"
    if slo.rps_min > 0:
        assert rps >= slo.rps_min, f"SLO RPS breached: {rps} < {slo.rps_min}"
