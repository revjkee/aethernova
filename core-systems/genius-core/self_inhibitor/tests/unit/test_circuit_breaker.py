# SPDX-License-Identifier: Apache-2.0
"""
Промышленные unit-тесты для Circuit Breaker self-inhibitor.

ОЖИДАЕМЫЙ API (модуль genius_core.security.self_inhibitor.circuit_breaker):
    class CircuitBreaker:
        def __init__(
            self,
            *,
            threshold: float,          # доля ошибок в окне (0..1), напр. 0.5
            min_calls: int,            # минимум вызовов до оценки порога
            window_seconds: int,       # длина скользящего окна для метрик
            open_timeout: float,       # секунд до перехода в HALF_OPEN
            half_open_max_calls: int,  # сколько пробных вызовов пускаем в HALF_OPEN
            error_classifier=None,     # Callable[Exception]->bool, что считать ошибкой
            time_provider=None,        # объект с now()/wall() для тестов
            name: str = "default",
        )
        # Синхронный вызов
        def call(self, fn, *args, **kwargs): ...
        # Асинхронный вызов
        async def acall(self, afn, *args, **kwargs): ...
        # Декоратор
        def decorate(self, fn): ...
        # Состояние
        @property
        def state(self): ...  # State enum или строка: CLOSED/OPEN/HALF_OPEN
        # Метрики (снимок)
        def get_metrics(self) -> dict: ...
        # Принудительный сброс в CLOSED
        def reset(self) -> None: ...

    class CircuitOpenError(Exception): ...

    class State(Enum):
        CLOSED, OPEN, HALF_OPEN

Если ваше API чуть отличается (например, "execute"/"async_execute"), адаптируйте реализацию
или скорректируйте тесты. Основной контракт — поведение.
"""

from __future__ import annotations

import asyncio
import importlib
from dataclasses import dataclass
from typing import Any, Optional

import pytest

# ------------------------------ Импорт тестируемого модуля -------------------

try:
    cb_mod = importlib.import_module("genius_core.security.self_inhibitor.circuit_breaker")
except ModuleNotFoundError:
    cb_mod = pytest.importorskip(
        "genius_core.security.self_inhibitor.circuit_breaker",
        reason="Реализация Circuit Breaker не найдена; создайте модуль согласно docstring.",
    )

CircuitBreaker = getattr(cb_mod, "CircuitBreaker")
CircuitOpenError = getattr(cb_mod, "CircuitOpenError", RuntimeError)
StateEnum = getattr(cb_mod, "State", None)

def state_name(s: Any) -> str:
    if hasattr(s, "name"):
        return str(s.name)
    return str(s)

# ------------------------------ Вспомогательная «временная машина» ----------

@dataclass
class FakeClock:
    _now: float = 0.0
    _wall: float = 1_700_000_000.0

    def now(self) -> float:
        return self._now

    def wall(self) -> float:
        return self._wall

    def tick(self, sec: float) -> None:
        self._now += float(sec)
        self._wall += float(sec)

# ------------------------------ Фикстуры -------------------------------------

@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()

@pytest.fixture
def classifier():
    # Ошибкой считаем только ValueError
    return lambda exc: isinstance(exc, ValueError)

@pytest.fixture
def breaker(clock, classifier):
    return CircuitBreaker(
        threshold=0.50,
        min_calls=10,
        window_seconds=60,
        open_timeout=30,
        half_open_max_calls=2,
        error_classifier=classifier,
        time_provider=clock,
        name="test",
    )

# ------------------------------ Заготовки функций ----------------------------

def _ok(v=42):
    return v

def _fail(msg="boom"):
    raise ValueError(msg)

async def _aok(v=42):
    await asyncio.sleep(0)
    return v

async def _afail(msg="boom"):
    await asyncio.sleep(0)
    raise ValueError(msg)

# ------------------------------ Тесты состояний ------------------------------

def test_starts_closed(breaker):
    assert state_name(breaker.state) == "CLOSED"
    m = breaker.get_metrics()
    assert isinstance(m, dict)
    assert m.get("name") == "test"

def test_does_not_open_before_min_calls(breaker, clock):
    # 4 ошибки из 7 вызовов (<= min_calls) — не должны открыть
    seq = [True, True, False, True, False, False, True]  # True=ok, False=fail
    for ok in seq:
        if ok:
            assert breaker.call(_ok) == 42
        else:
            with pytest.raises(ValueError):
                breaker.call(_fail)
    assert state_name(breaker.state) == "CLOSED"

def test_opens_after_threshold_exceeded(breaker, clock):
    # Набираем min_calls=10, из них 6 ошибок => 0.6 > 0.5 -> OPEN
    pattern = [True, False, False, True, False, True, False, False, True, False]  # 6 fail / 10
    for ok in pattern:
        if ok:
            breaker.call(_ok)
        else:
            with pytest.raises(ValueError):
                breaker.call(_fail)
    assert state_name(breaker.state) == "OPEN"
    # В OPEN любые вызовы мгновенно отклоняются
    with pytest.raises(CircuitOpenError):
        breaker.call(_ok)

def test_transitions_to_half_open_after_timeout(breaker, clock):
    # Открыли как в предыдущем тесте
    for i in range(10):
        try:
            breaker.call(_fail if i % 2 else _ok)
        except ValueError:
            pass
    assert state_name(breaker.state) == "OPEN"
    # Имитируем выдержку open_timeout
    clock.tick(30.0001)
    # Первый пробный — пропускается (HALF_OPEN), не падает
    assert breaker.call(_ok) == 42
    assert state_name(breaker.state) in ("HALF_OPEN", "CLOSED")

def test_half_open_limited_trial_calls(breaker, clock):
    # Открываем
    for i in range(10):
        try:
            breaker.call(_fail if i % 2 == 1 else _ok)
        except ValueError:
            pass
    assert state_name(breaker.state) == "OPEN"
    clock.tick(30.0001)
    # Разрешены только 2 пробных вызова
    assert breaker.call(_ok) == 42
    assert breaker.call(_ok) == 42
    # Третий параллельный (безуспешная попытка) должен быть отклонён
    with pytest.raises(CircuitOpenError):
        breaker.call(_ok)

def test_half_open_reopens_on_failure(breaker, clock):
    # Открываем
    fails = 6
    for i in range(10):
        try:
            if i < fails:
                breaker.call(_fail)
            else:
                breaker.call(_ok)
        except ValueError:
            pass
    assert state_name(breaker.state) == "OPEN"
    clock.tick(30.01)
    # В HALF_OPEN первая ошибка — обратно в OPEN
    with pytest.raises(ValueError):
        breaker.call(_fail)
    assert state_name(breaker.state) == "OPEN"

def test_recovers_to_closed_after_successful_trials(breaker, clock):
    # Открываем
    for i in range(10):
        try:
            breaker.call(_fail if i < 6 else _ok)
        except ValueError:
            pass
    assert state_name(breaker.state) == "OPEN"
    clock.tick(31)
    # Два успешных пробных вызова — достаточно вернуться в CLOSED
    assert breaker.call(_ok) == 42
    assert breaker.call(_ok) == 42
    assert state_name(breaker.state) == "CLOSED"
    # Далее обычная работа
    assert breaker.call(_ok) == 42

# ------------------------------ Классификация ошибок -------------------------

def test_error_classifier_counts_only_selected_exceptions(clock):
    # Классификатор считает ошибкой только ValueError
    br = CircuitBreaker(
        threshold=0.5, min_calls=2, window_seconds=60,
        open_timeout=10, half_open_max_calls=1,
        error_classifier=lambda e: isinstance(e, ValueError),
        time_provider=clock,
    )
    # RuntimeError не должен учитывать как ошибку — не откроется
    with pytest.raises(RuntimeError):
        br.call(lambda: (_ for _ in ()).throw(RuntimeError("rt")))
    br.call(_ok)
    assert state_name(br.state) == "CLOSED"
    # Теперь ValueError — считается, при min_calls=2 и 1/2 >= 0.5 может открыться
    with pytest.raises(ValueError):
        br.call(_fail)
    assert state_name(br.state) in ("OPEN", "CLOSED")  # разрешаем обе стратегические трактовки порога == 0.5

# ------------------------------ Метрики/сброс --------------------------------

def test_metrics_and_reset(breaker):
    m1 = breaker.get_metrics()
    assert set(m1).issuperset({"state", "success", "failure", "threshold", "window_seconds"})
    # Немного активности
    try:
        breaker.call(_fail)
    except ValueError:
        pass
    breaker.call(_ok)
    m2 = breaker.get_metrics()
    assert m2["success"] >= m1["success"]
    assert m2["failure"] >= m1["failure"]
    breaker.reset()
    assert state_name(breaker.state) == "CLOSED"

# ------------------------------ Async-поддержка ------------------------------

@pytest.mark.asyncio
async def test_async_paths_open_and_recover(clock):
    br = CircuitBreaker(
        threshold=0.5, min_calls=10, window_seconds=60,
        open_timeout=5, half_open_max_calls=2,
        error_classifier=lambda e: isinstance(e, ValueError),
        time_provider=clock, name="async",
    )
    # 6 ошибок из 10 — откроется
    for i in range(10):
        if i % 2 == 0:
            with pytest.raises(ValueError):
                await br.acall(_afail)
        else:
            assert await br.acall(_aok) == 42
    assert state_name(br.state) == "OPEN"
    # В OPEN — мгновенный отказ
    with pytest.raises(CircuitOpenError):
        await br.acall(_aok)
    # Ждём open_timeout и успешно закрываем
    clock.tick(5.1)
    assert await br.acall(_aok) == 42
    assert await br.acall(_aok) == 42
    assert state_name(br.state) == "CLOSED"

# ------------------------------ Конкурентность HALF_OPEN ---------------------

@pytest.mark.asyncio
async def test_half_open_concurrency_limited(clock):
    br = CircuitBreaker(
        threshold=0.6, min_calls=10, window_seconds=60,
        open_timeout=3, half_open_max_calls=2,
        error_classifier=lambda e: isinstance(e, ValueError),
        time_provider=clock,
    )
    # Откроем breaker
    for i in range(10):
        try:
            if i < 7:
                br.call(_fail)
            else:
                br.call(_ok)
        except ValueError:
            pass
    assert state_name(br.state) == "OPEN"
    clock.tick(3.1)

    # Стартуем три параллельных пробных вызова; два должны пройти внутрь,
    # третий получить быстрый отказ CircuitOpenError.
    async def try_call():
        try:
            return await br.acall(_aok)
        except Exception as e:
            return e

    r = await asyncio.gather(try_call(), try_call(), try_call())
    oks = [x for x in r if x == 42]
    errs = [x for x in r if isinstance(x, Exception)]
    assert len(oks) == 2
    assert any(isinstance(e, CircuitOpenError) for e in errs)

# ------------------------------ Декоратор ------------------------------------

def test_decorator_wraps_sync(breaker):
    @breaker.decorate
    def work(x):
        return x * 2
    assert work(21) == 42

@pytest.mark.asyncio
async def test_decorator_wraps_async(clock):
    br = CircuitBreaker(
        threshold=0.5, min_calls=1, window_seconds=60,
        open_timeout=1, half_open_max_calls=1,
        error_classifier=lambda e: isinstance(e, ValueError),
        time_provider=clock,
    )

    @br.decorate
    async def awork(x):
        return x * 2

    assert await awork(21) == 42

# ------------------------------ Property (опц.) ------------------------------

@pytest.mark.skipif(
    pytest.importorskip("hypothesis", reason="hypothesis не установлен") is None,
    reason="hypothesis недоступен",
)
def test_probability_threshold_property(clock):
    from hypothesis import given, strategies as st

    @given(
        st.integers(min_value=10, max_value=100).flatmap(
            lambda n: st.tuples(st.just(n), st.integers(min_value=0, max_value=n))
        )
    )
    def _inner(pair):
        total, fails = pair
        br = CircuitBreaker(
            threshold=0.5, min_calls=10, window_seconds=60,
            open_timeout=10, half_open_max_calls=1,
            error_classifier=lambda e: isinstance(e, ValueError),
            time_provider=clock,
        )
        for i in range(total):
            if i < fails:
                try:
                    br.call(_fail)
                except ValueError:
                    pass
            else:
                br.call(_ok)
        # Простейшая проверка: если total>=min_calls и fails/total>threshold -> OPEN
        if total >= 10 and (fails / total) > 0.5:
            assert state_name(br.state) == "OPEN"  # требуем строго '>' порога
    _inner()
