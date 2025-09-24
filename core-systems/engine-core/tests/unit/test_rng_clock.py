# engine-core/engine/tests/unit/test_rng_clock.py
import asyncio
import math
import os
import random
import statistics
import sys
import time
from typing import List, Tuple

import pytest

# ----------------------------------------------------------------------
# Опциональные утилиты движка (fallback на stdlib при отсутствии)
# ----------------------------------------------------------------------
try:
    # Гипотетический модуль будущего движка: engine.utils.rng_clock
    from engine.utils import rng_clock as eng_rc  # type: ignore
except Exception:  # pragma: no cover
    eng_rc = None  # type: ignore

# ----------------------------------------------------------------------
# Хелперы
# ----------------------------------------------------------------------

def _jitter_uniform(base: float, jitter: float) -> float:
    """
    Униформный джиттер: возвращает значение в [base*(1-jitter), base*(1+jitter)].
    """
    if base < 0 or jitter < 0:
        raise ValueError("base and jitter must be non-negative")
    lo = base * (1.0 - jitter)
    hi = base * (1.0 + jitter)
    return random.uniform(lo, hi)

def _backoff_with_jitter(retry: int, base: float = 0.05, factor: float = 2.0, cap: float = 5.0, jitter: float = 0.1) -> float:
    """
    Экспоненциальный бэкофф с ограничением и униформным джиттером.
    """
    if retry < 0:
        raise ValueError("retry must be >= 0")
    delay = min(cap, base * (factor ** retry))
    return _jitter_uniform(delay, jitter)

def _mix_entropy(seed: int) -> int:
    """
    Примитивное смешение энтропии: XOR сид с 64 бит из os.urandom.
    """
    rnd = int.from_bytes(os.urandom(8), "little")
    return (seed & 0xFFFFFFFFFFFFFFFF) ^ rnd

# ----------------------------------------------------------------------
# Блок: RNG — свойства сидирования и распределения
# ----------------------------------------------------------------------

def test_seed_determinism_same_sequence():
    r1 = random.Random(12345)
    r2 = random.Random(12345)
    seq1 = [r1.random() for _ in range(10)]
    seq2 = [r2.random() for _ in range(10)]
    assert seq1 == seq2

def test_seed_independence_different_sequences():
    r1 = random.Random(1)
    r2 = random.Random(2)
    assert [r1.random() for _ in range(5)] != [r2.random() for _ in range(5)]

def test_uniform_mean_is_reasonable():
    r = random.Random(42)
    data = [r.random() for _ in range(20000)]
    m = statistics.mean(data)
    # Для U(0,1) ожидаемое 0.5; допускаем +-0.02 для стабильности CI
    assert 0.48 <= m <= 0.52

def test_randrange_bounds_and_all_values_hit():
    r = random.Random(123)
    n = 10000
    values = [r.randrange(0, 5) for _ in range(n)]
    assert all(0 <= v < 5 for v in values)
    # Каждое значение 0..4 хотя бы раз встречается
    assert set(values) == set(range(5))

def test_os_urandom_non_repeating_short_series():
    blobs = {os.urandom(16) for _ in range(128)}
    # Вероятность коллизии для 128*128/2 пар крайне мала; тест нестрогий
    assert len(blobs) >= 120

# ----------------------------------------------------------------------
# Блок: параллельность/асинхронность и отмена
# ----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_independent_rngs_in_coroutines_no_interference():
    async def worker(seed: int) -> List[float]:
        rng = random.Random(seed)
        await asyncio.sleep(0)  # переключение задач
        return [rng.random() for _ in range(5)]

    a, b = await asyncio.gather(worker(111), worker(222))
    assert a != b
    # Повторный запуск воспроизводим
    a2, b2 = await asyncio.gather(worker(111), worker(222))
    assert a == a2 and b == b2

@pytest.mark.asyncio
async def test_async_sleep_cancellation():
    task = asyncio.create_task(asyncio.sleep(1.0))
    await asyncio.sleep(0)  # дать старт
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

# ----------------------------------------------------------------------
# Блок: часы и сон — свойства и допуски
# ----------------------------------------------------------------------

def test_monotonic_non_decreasing():
    t1 = time.monotonic()
    t2 = time.monotonic()
    assert t2 >= t1

def test_perf_counter_progress_after_sleep():
    t1 = time.perf_counter()
    time.sleep(0.01)
    t2 = time.perf_counter()
    assert t2 > t1

@pytest.mark.parametrize("target_ms,tolerance_ms", [(10, 30), (30, 60)])
def test_sleep_accuracy_with_tolerance(target_ms: int, tolerance_ms: int):
    t1 = time.perf_counter()
    time.sleep(target_ms / 1000.0)
    dt = (time.perf_counter() - t1) * 1000.0
    # Сон не должен быть короче цели и не должен «улетать» далеко за допуск
    assert dt >= target_ms - 1  # редкий ранний пробуждение допускаем 1 мс
    assert dt <= target_ms + tolerance_ms

def test_monotonic_immune_to_system_clock_jump(monkeypatch):
    # Смещаем time.time назад — monotonic не должен уменьшиться
    base_mono = time.monotonic()
    real_time_time = time.time

    def fake_time():
        return real_time_time() - 3600.0  # назад на час

    monkeypatch.setattr(time, "time", fake_time)
    # Проверяем, что monotonic не сломался (он не зависит от time.time)
    assert time.monotonic() >= base_mono

# ----------------------------------------------------------------------
# Блок: джиттер и бэкофф
# ----------------------------------------------------------------------

def test_jitter_uniform_bounds_and_spread():
    base = 0.2
    jitter = 0.3
    samples = [_jitter_uniform(base, jitter) for _ in range(2000)]
    lo, hi = base * (1 - jitter), base * (1 + jitter)
    assert all(lo <= x <= hi for x in samples)
    # Дисперсия не нулевая (все значения не одинаковые)
    assert len(set(round(x, 6) for x in samples)) > 10

def test_exponential_backoff_with_cap_and_jitter():
    cap = 1.0
    seq = [_backoff_with_jitter(i, base=0.05, factor=2.0, cap=cap, jitter=0.2) for i in range(10)]
    # Последующие значения не превосходят cap*(1+jitter)
    assert all(x <= cap * 1.2 + 1e-9 for x in seq)
    # Первое значение в ожидаемом коридоре
    assert 0.05 * 0.8 <= seq[0] <= 0.05 * 1.2

# ----------------------------------------------------------------------
# Блок: смешение энтропии
# ----------------------------------------------------------------------

def test_entropy_mixing_changes_seed(monkeypatch):
    # Зафиксируем os.urandom, чтобы проверить детерминированность mix при данном источнике
    fixed = (1234567890123456789).to_bytes(8, "little", signed=False)
    monkeypatch.setattr(os, "urandom", lambda n: fixed)
    mixed = _mix_entropy(0xABCDEF)
    assert mixed == (0xABCDEF ^ int.from_bytes(fixed, "little"))

# ----------------------------------------------------------------------
# Блок: интеграция с гипотетическим модулем движка (если он есть)
# ----------------------------------------------------------------------

def test_engine_utils_rng_clock_optional(monkeypatch):
    if not eng_rc:
        pytest.skip("engine.utils.rng_clock is not available (optional)")
    # Предполагаемые контракты (гипотетические; тесты нестрогие и не зависят от реализации)
    # 1) детерминированный RNG при одинаковом сиде
    r1 = eng_rc.Random(777)  # type: ignore[attr-defined]
    r2 = eng_rc.Random(777)  # type: ignore[attr-defined]
    assert [r1.rand() for _ in range(5)] == [r2.rand() for _ in range(5)]  # type: ignore[attr-defined]
    # 2) clock.monotonic() не убывает при смещении системного времени
    base = eng_rc.clock_monotonic()  # type: ignore[attr-defined]
    real_time_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time_time() + 10_000)
    assert eng_rc.clock_monotonic() >= base  # type: ignore[attr-defined]

# ----------------------------------------------------------------------
# Блок: асинхронные таймеры/задержки
# ----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_async_backoff_sequence_is_within_bounds():
    # Соберем 5 задержек с экспоненциальным ростом и убедимся, что все в пределах.
    delays = []
    for i in range(5):
        d = _backoff_with_jitter(i, base=0.01, factor=2.0, cap=0.2, jitter=0.25)
        delays.append(d)
        await asyncio.sleep(0)  # переключение задач
    assert all(0 <= d <= 0.25 for d in delays)

@pytest.mark.asyncio
async def test_wait_for_with_timeout_and_cleanup():
    # Создаем корутину, которая «долго» спит, и применяем жесткий таймаут.
    async def long_task():
        await asyncio.sleep(10)
        return "done"
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(long_task(), timeout=0.03)

# ----------------------------------------------------------------------
# Платформенные особенности
# ----------------------------------------------------------------------

@pytest.mark.xfail(sys.platform.startswith("win"), reason="Точность сна и тайминги на Windows нестабильны в CI")
def test_sleep_accuracy_strict():
    # Более строгая проверка, которая на Windows часто «шумит».
    t1 = time.perf_counter()
    time.sleep(0.02)
    dt = time.perf_counter() - t1
    assert 0.018 <= dt <= 0.05
