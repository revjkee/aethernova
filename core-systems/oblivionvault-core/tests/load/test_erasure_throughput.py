# oblivionvault-core/tests/load/test_erasure_throughput.py
"""
Нагрузочный тест пропускной способности крипто-стирания (crypto-shred) для OblivionVault.

Требования:
  - pytest>=7, pytest-asyncio>=0.23
  - Модуль: oblivionvault.crypto.shred

Конфигурация через окружение:
  OV_ERASURE_N               - количество объектов (default: 200)
  OV_ERASURE_CONCURRENCY     - параллелизм shred (default: 50)
  OV_ERASURE_TIMEOUT_S       - общий таймаут теста в секундах (default: 120)
  OV_ERASURE_EXPECT_OPS      - минимальная требуемая пропускная способность, ops/s (optional)
  OV_ERASURE_PCT95_MS        - максимальная допустимая p95, мс (optional)
  OV_ERASURE_REPORT_PATH     - путь к JSON-отчету метрик (optional)
  OV_ERASURE_SAMPLE_VERIFY   - сколько объектов проверить на невозможность decrypt после shred (default: 10)

Запуск:
  pytest -q -m load
Пометка теста: @pytest.mark.load
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import statistics
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pytest

pytestmark = pytest.mark.asyncio
load = pytest.mark.load

# --- Импорт тестируемого модуля шреддера (мягко) ---
shred_mod = pytest.importorskip(
    "oblivionvault.crypto.shred",
    reason="Не найден oblivionvault.crypto.shred"
)

# Исключения и конструкторы
ShreddedError = getattr(shred_mod, "ShreddedError", RuntimeError)

async def _make_shredder():
    if hasattr(shred_mod, "get_default_shredder"):
        sh = shred_mod.get_default_shredder()
        if asyncio.iscoroutine(sh):
            sh = await sh
        return sh
    if hasattr(shred_mod, "CryptoShredder"):
        try:
            sh = shred_mod.CryptoShredder()  # type: ignore
            if asyncio.iscoroutine(sh):
                sh = await sh
            return sh
        except Exception:
            pass
        if hasattr(shred_mod.CryptoShredder, "from_defaults"):  # type: ignore
            sh = shred_mod.CryptoShredder.from_defaults()  # type: ignore
            if asyncio.iscoroutine(sh):
                sh = await sh
            return sh
    pytest.skip("Нет способа инициализировать шреддер")

# --- Конфигурация теста из окружения ---
def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    return int(v) if v is not None and str(v).strip() != "" else default

def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    return float(v) if v is not None and str(v).strip() != "" else default

def _env_opt_float(name: str) -> Optional[float]:
    v = os.getenv(name)
    return float(v) if v is not None and str(v).strip() != "" else None

def _env_opt_str(name: str) -> Optional[str]:
    v = os.getenv(name)
    return str(v) if v is not None and str(v).strip() != "" else None

N_OBJECTS            = _env_int("OV_ERASURE_N", 200)
CONCURRENCY          = _env_int("OV_ERASURE_CONCURRENCY", 50)
TIMEOUT_S            = _env_float("OV_ERASURE_TIMEOUT_S", 120.0)
EXPECT_OPS           = _env_opt_float("OV_ERASURE_EXPECT_OPS")     # ops/s
EXPECT_P95_MS        = _env_opt_float("OV_ERASURE_PCT95_MS")       # ms
REPORT_PATH          = _env_opt_str("OV_ERASURE_REPORT_PATH")
SAMPLE_VERIFY        = _env_int("OV_ERASURE_SAMPLE_VERIFY", 10)

# --- Вспомогательные структуры ---
@dataclass
class Blob:
    object_id: str
    ct: bytes
    meta: Dict[str, Any]

def _percentile(sorted_values: List[float], p: float) -> float:
    """
    Простая процентильная оценка (p в [0,100]).
    """
    if not sorted_values:
        return math.nan
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

def _summarize(latencies_s: List[float]) -> Dict[str, float]:
    latencies_ms = [x * 1000.0 for x in latencies_s]
    latencies_ms.sort()
    return {
        "count": float(len(latencies_ms)),
        "avg_ms": (sum(latencies_ms) / len(latencies_ms)) if latencies_ms else math.nan,
        "p50_ms": _percentile(latencies_ms, 50),
        "p95_ms": _percentile(latencies_ms, 95),
        "p99_ms": _percentile(latencies_ms, 99),
        "max_ms": latencies_ms[-1] if latencies_ms else math.nan,
    }

async def _encrypt_many(shredder, n: int) -> List[Blob]:
    blobs: List[Blob] = []
    # Подготовка шифротекстов вне критической секции замеров
    for i in range(n):
        pt = (f"payload-{i}").encode("utf-8")  # небольшие полезные данные, достаточно для учёта накладных расходов
        object_id = f"erasure-{i:06d}"
        ct, meta = await shredder.encrypt(pt, object_id=object_id, aad=None)
        blobs.append(Blob(object_id=object_id, ct=bytes(ct), meta=dict(meta)))
    return blobs

async def _shred_with_timing(shredder, object_id: str) -> Tuple[bool, float, Optional[str]]:
    """
    Возвращает (ok, latency_seconds, error_reason).
    """
    t0 = time.perf_counter()
    try:
        await shredder.shred(object_id, reason="load-test", actor="tests:load")
        t1 = time.perf_counter()
        return True, (t1 - t0), None
    except Exception as e:
        t1 = time.perf_counter()
        return False, (t1 - t0), repr(e)

# --- Собственно нагрузочный тест ---
@load
async def test_erasure_throughput():
    """
    Измеряет:
      - throughput ops/s для shred на N_OBJECTS объектах при параллелизме CONCURRENCY
      - перцентильные метрики латентности (p50, p95, p99, max)
      - нулевую долю ошибок
    При наличии порогов EXPECT_OPS и EXPECT_P95_MS — проверяет их.
    """
    shredder = await _make_shredder()

    # Контекстный менеджер, если доступен
    if hasattr(shredder, "__aenter__") and hasattr(shredder, "__aexit__"):
        async with shredder:
            await _run_load(shredder)
    else:
        await _run_load(shredder)

async def _run_load(shredder):
    # Подготовительная фаза: шифруем N объектов
    blobs = await asyncio.wait_for(_encrypt_many(shredder, N_OBJECTS), timeout=TIMEOUT_S)

    # Фаза замера: выполняем shred параллельно
    sem = asyncio.Semaphore(CONCURRENCY)
    latencies: List[float] = []
    errors: List[str] = []

    async def worker(blob: Blob):
        async with sem:
            ok, lat, err = await _shred_with_timing(shredder, blob.object_id)
            latencies.append(lat)
            if not ok:
                errors.append(err or "unknown")

    t0 = time.perf_counter()
    await asyncio.wait_for(asyncio.gather(*(worker(b) for b in blobs)), timeout=TIMEOUT_S)
    t1 = time.perf_counter()

    duration_s = max(t1 - t0, 1e-9)
    ops = len(blobs) / duration_s
    summary = _summarize(latencies)

    # Валидации инвариантов
    assert not errors, f"Обнаружены ошибки shred: {errors[:5]} ... (total={len(errors)})"
    # Дополнительная точечная верификация безопасности: после shred decrypt должен падать
    sample = blobs[: min(SAMPLE_VERIFY, len(blobs))]
    for b in sample:
        with pytest.raises(ShreddedError):
            await shredder.decrypt(b.ct, meta=b.meta)

    # Отчет
    metrics = {
        "n": len(blobs),
        "concurrency": CONCURRENCY,
        "duration_s": duration_s,
        "ops_per_s": ops,
        **summary,
    }

    # Лаконичный вывод в stdout (удобно для CI-логов)
    print("[erasure-throughput] n=%d concurrency=%d duration=%.3fs ops=%.2f p50=%.1fms p95=%.1fms p99=%.1fms max=%.1fms"
          % (
              metrics["n"], metrics["concurrency"], metrics["duration_s"], metrics["ops_per_s"],
              metrics["p50_ms"], metrics["p95_ms"], metrics["p99_ms"], metrics["max_ms"]
          ))

    # Пороговые проверки (если заданы)
    if EXPECT_OPS is not None:
        assert ops >= EXPECT_OPS, f"Недостаточная пропускная способность: {ops:.2f} < {EXPECT_OPS:.2f} ops/s"
    if EXPECT_P95_MS is not None:
        assert metrics["p95_ms"] <= EXPECT_P95_MS, f"p95 слишком велика: {metrics['p95_ms']:.1f} > {EXPECT_P95_MS:.1f} ms"

    # JSON-отчет (если запрошено)
    if REPORT_PATH:
        try:
            with open(REPORT_PATH, "w", encoding="utf-8") as f:
                json.dump(metrics, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        except Exception as e:
            # Тест не должен падать из-за проблем записи отчета
            print(f"[erasure-throughput] Не удалось записать отчет: {e}")
