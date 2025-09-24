# -*- coding: utf-8 -*-
"""
Unit tests for Self-Inhibitor rate limiting strategy.

Требования:
  - pytest

Запуск:
  pytest -q core-systems/genius_core/security/self_inhibitor/tests/unit/test_strategies_rate_limiter.py
"""

from __future__ import annotations

import importlib
import inspect
import types
from dataclasses import dataclass
from typing import Any, Optional, Tuple

import pytest


# --------------------------------------------------------------------------------------
# Импортируем тестируемый модуль из возможных путей. При отсутствии — корректно скипаем.
# --------------------------------------------------------------------------------------

_MODULE_CANDIDATES = [
    "core_systems.genius_core.security.self_inhibitor.strategies.rate_limiter",
    "genius_core.security.self_inhibitor.strategies.rate_limiter",
]

rl_mod = None
_import_errs = []
for name in _MODULE_CANDIDATES:
    try:
        rl_mod = importlib.import_module(name)
        break
    except Exception as e:
        _import_errs.append((name, repr(e)))

if rl_mod is None:
    pytest.skip(
        "Rate limiter module not found. Tried: "
        + ", ".join(f"{n} ({err})" for n, err in _import_errs),
        allow_module_level=True,
    )


# --------------------------------------------------------------------------------------
# Вспомогательные утилиты: управляемое время и нормализация API allow()
# --------------------------------------------------------------------------------------

@dataclass
class FakeClock:
    """Простые управляемые monotonic()/time() для детерминированных тестов."""
    t: float = 0.0

    def advance(self, seconds: float) -> None:
        self.t += float(seconds)

    def monotonic(self) -> float:
        return self.t

    def time(self) -> float:
        return self.t


def _supports_now_param(obj) -> bool:
    sig = None
    try:
        sig = inspect.signature(obj)
    except Exception:
        return False
    return any(p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD) and p.name == "now" for p in sig.parameters.values())


def _call_allow(strategy, key: str, *, cost: int = 1, now: Optional[float] = None) -> Tuple[bool, Optional[float]]:
    """
    Унифицируем разные реализации:
      - bool
      - (bool, retry_after)
      - dict {"allowed": bool, "retry_after": seconds}
      - raise RateLimitedError (с атрибутом retry_after/seconds)
    """
    try:
        if _supports_now_param(strategy.allow):
            out = strategy.allow(key, cost=cost, now=now)
        else:
            out = strategy.allow(key, cost=cost)
    except Exception as e:  # исключение — считаем «заблокировано»
        name = e.__class__.__name__.lower()
        if "ratelimit" in name or "too" in name or "limit" in name:
            ra = getattr(e, "retry_after", None)
            if ra is None:
                ra = getattr(e, "retry_after_seconds", None)
            return False, float(ra) if ra is not None else None
        raise

    # tuple
    if isinstance(out, tuple):
        allowed = bool(out[0])
        ra = out[1] if len(out) > 1 else None
        return allowed, float(ra) if ra is not None else None

    # dict
    if isinstance(out, dict):
        allowed = bool(out.get("allowed", False))
        ra = out.get("retry_after") or out.get("retry_after_seconds")
        return allowed, float(ra) if ra is not None else None

    # bool или другое приведение
    return bool(out), None


# --------------------------------------------------------------------------------------
# Фикстуры
# --------------------------------------------------------------------------------------

@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    """
    Подменяем монотонное время внутри тестируемого модуля.
    Стратегия может:
      - использовать rl_mod.time.monotonic()
      - принимать параметр now (тогда мы будем явно передавать его)
    """
    fake = FakeClock()
    # Если в модуле есть атрибут time, подменяем его монотонные часы
    if hasattr(rl_mod, "time") and isinstance(rl_mod.time, types.ModuleType):
        monkeypatch.setattr(rl_mod.time, "monotonic", fake.monotonic)
        # часто стратегия также использует time.time()
        monkeypatch.setattr(rl_mod.time, "time", fake.time)
    return fake


@pytest.fixture
def make_strategy():
    """
    Фабрика стратегии лимитирования с понятными параметрами по умолчанию.
    Требуемые сигнатуры (любая из):
      - RateLimiterStrategy(limit:int, window_seconds:float, **kwargs)
      - RateLimiter(limit:int, window:float, **kwargs)
      - FixedWindowRateLimiter(...)
      - TokenBucketRateLimiter(rate_per_sec, burst, **kwargs)
    Мы пытаемся аккуратно подобрать конструктор через эвристику.
    """
    ctor = None
    # Наиболее типичные имена классов
    candidates = [
        "RateLimiterStrategy",
        "RateLimiter",
        "FixedWindowRateLimiter",
        "SlidingWindowRateLimiter",
        "TokenBucketRateLimiter",
    ]
    for name in candidates:
        if hasattr(rl_mod, name):
            ctor = getattr(rl_mod, name)
            break
    if ctor is None:
        pytest.skip("No known RateLimiter class found in module")

    def _factory(limit: int, window_seconds: float, **kwargs):
        # Пытаемся угадать параметры конструктора
        try:
            return ctor(limit=limit, window_seconds=window_seconds, **kwargs)
        except TypeError:
            # альтернативные имена аргументов
            try:
                return ctor(limit=limit, window=window_seconds, **kwargs)
            except TypeError:
                # токен-бакет: rate/burst
                rate = float(limit) / float(window_seconds) if window_seconds > 0 else float(limit)
                burst = int(limit)
                try:
                    return ctor(rate_per_sec=rate, burst=burst, **kwargs)
                except TypeError:
                    # крайний случай — позиционные
                    try:
                        return ctor(limit, window_seconds, **kwargs)
                    except TypeError:
                        return ctor(limit, window_seconds)
    return _factory


# --------------------------------------------------------------------------------------
# Тесты базовой семантики «N за T»
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("limit,window", [(5, 1.0), (10, 2.5)])
def test_basic_capacity_and_block(monkeypatch, clock: FakeClock, make_strategy, limit, window):
    s = make_strategy(limit=limit, window_seconds=window)
    # Первые 'limit' запросов — допускаются
    for i in range(limit):
        allowed, ra = _call_allow(s, "k:basic", now=clock.monotonic())
        assert allowed, f"request {i} within capacity should be allowed"
        assert ra is None or ra >= 0

    # Следующий — должен быть заблокирован
    allowed, ra = _call_allow(s, "k:basic", now=clock.monotonic())
    assert not allowed, "request exceeding capacity must be blocked"
    # retry_after должен быть неотрицательным и не превышать размер окна
    if ra is not None:
        assert 0 <= ra <= window + 0.001

    # Продвигаем время на окно — снова позволено
    clock.advance(window)
    allowed, _ = _call_allow(s, "k:basic", now=clock.monotonic())
    assert allowed, "request after full window must be allowed"


def test_isolation_between_keys(clock: FakeClock, make_strategy):
    s = make_strategy(limit=3, window_seconds=1.0)
    for i in range(3):
        assert _call_allow(s, "A", now=clock.monotonic())[0]
        assert _call_allow(s, "B", now=clock.monotonic())[0]
    # Следующий по A — блок, по B — тоже блок на 4-й
    assert not _call_allow(s, "A", now=clock.monotonic())[0]
    assert not _call_allow(s, "B", now=clock.monotonic())[0]


# --------------------------------------------------------------------------------------
# Стоимость запроса (cost) и частичное восстановление
# --------------------------------------------------------------------------------------

def test_cost_based_accounting(clock: FakeClock, make_strategy):
    s = make_strategy(limit=10, window_seconds=1.0)
    # Суммарная стоимость <= лимита — допускается
    assert _call_allow(s, "k:cost", cost=3, now=clock.monotonic())[0]
    assert _call_allow(s, "k:cost", cost=4, now=clock.monotonic())[0]
    # Осталось 3 единицы — принимаем cost=3
    assert _call_allow(s, "k:cost", cost=3, now=clock.monotonic())[0]
    # Любой cost > 0 теперь должен блокироваться
    allowed, ra = _call_allow(s, "k:cost", cost=1, now=clock.monotonic())
    assert not allowed
    assert ra is None or ra >= 0

    # Через половину окна часть емкости может восстановиться у sliding/token bucket;
    # в фиксированном окне — восстановление произойдет на границе окна.
    half = 0.5
    clock.advance(half)
    # Допускаем два корректных поведения:
    #  - либо ещё блок (fixed window),
    #  - либо разрешение на часть (token/sliding), но не больше лимита.
    allowed_half, _ = _call_allow(s, "k:cost", cost=1, now=clock.monotonic())
    if allowed_half:
        # если разрешили, не должно превысить лимит по сумме
        # добиваем остаток окна и убеждаемся, что после полного окна точно разрешает
        pass

    clock.advance(1.0 - half)
    assert _call_allow(s, "k:cost", cost=1, now=clock.monotonic())[0], "after full window some capacity must be restored"


# --------------------------------------------------------------------------------------
# Retry-After: монотонность и близость к истине
# --------------------------------------------------------------------------------------

def test_retry_after_decreases_with_time(clock: FakeClock, make_strategy):
    s = make_strategy(limit=1, window_seconds=1.0)
    assert _call_allow(s, "k:ra", now=clock.monotonic())[0]
    allowed, ra1 = _call_allow(s, "k:ra", now=clock.monotonic())
    assert not allowed
    assert ra1 is None or ra1 >= 0.0

    clock.advance(0.4)
    allowed, ra2 = _call_allow(s, "k:ra", now=clock.monotonic())
    assert not allowed
    if ra1 is not None and ra2 is not None:
        # retry_after должен уменьшаться (с учетом численной неточности)
        assert ra2 <= ra1 + 1e-6

    clock.advance(0.6)
    assert _call_allow(s, "k:ra", now=clock.monotonic())[0]


# --------------------------------------------------------------------------------------
# Детерминированность при «одновременном» доступе
# --------------------------------------------------------------------------------------

def test_atomic_burst_does_not_exceed_limit(clock: FakeClock, make_strategy):
    limit = 7
    s = make_strategy(limit=limit, window_seconds=1.0)

    # Все вызовы приходят с одинаковым now (один тик)
    results = []
    for _ in range(limit * 2):
        results.append(_call_allow(s, "k:burst", now=clock.monotonic())[0])

    # Количество разрешений не должно превышать лимит
    assert sum(1 for ok in results if ok) <= limit


# --------------------------------------------------------------------------------------
# Восстановление после нескольких окон
# --------------------------------------------------------------------------------------

def test_full_recovery_after_multiple_windows(clock: FakeClock, make_strategy):
    s = make_strategy(limit=3, window_seconds=0.5)

    # Выедаем лимит
    for _ in range(3):
        assert _call_allow(s, "k:recovery", now=clock.monotonic())[0]
    assert not _call_allow(s, "k:recovery", now=clock.monotonic())[0]

    # Прокручиваем два окна — емкость должна быть полностью восстановлена
    clock.advance(1.0)
    for _ in range(3):
        assert _call_allow(s, "k:recovery", now=clock.monotonic())[0]


# --------------------------------------------------------------------------------------
# Нагрузочный «дымовой» тест с раунд-робином по ключам
# --------------------------------------------------------------------------------------

def test_round_robin_keys_do_not_interfere(clock: FakeClock, make_strategy):
    s = make_strategy(limit=5, window_seconds=1.0)
    keys = [f"K{i}" for i in range(10)]

    # За одно окно каждый ключ может получить не более 5 разрешений
    per_key_ok = {k: 0 for k in keys}

    # 10 раундов: в каждом раунде пробуем один вызов на ключ
    for _ in range(10):
        for k in keys:
            ok, _ra = _call_allow(s, k, now=clock.monotonic())
            per_key_ok[k] += int(ok)

    # Не должно быть превышений per-key
    assert all(v <= 5 for v in per_key_ok.values())

    # После ещё одного окна некоторые ключи смогут снова пройти
    clock.advance(1.0)
    ok_after = sum(1 for k in keys if _call_allow(s, k, now=clock.monotonic())[0])
    assert ok_after >= 1, "after a full window at least some keys must regain capacity"
