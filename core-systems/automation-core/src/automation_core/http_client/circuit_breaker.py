# automation-core/src/automation_core/http_client/circuit_breaker.py
# -*- coding: utf-8 -*-
"""
Circuit Breaker для HTTP/сетевых клиентов и любых вызовов IO.

Фактическая методологическая основа (проверяемые источники):
- Паттерн Circuit Breaker: Martin Fowler. https://martinfowler.com/bliki/CircuitBreaker.html
- Паттерн Circuit Breaker (варианты, пороги, полуоткрытое состояние): Microsoft Azure Architecture Center.
  https://learn.microsoft.com/azure/architecture/patterns/circuit-breaker
- Экспоненциальный backoff и джиттер для устойчивых ретраев/ожиданий перед half-open:
  AWS Architecture Blog. https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
- Монотонные часы для измерения интервалов: Python docs `time.monotonic`.
  https://docs.python.org/3/library/time.html#time.monotonic
- Отмена coroutines и обработка CancelledError: Python docs `asyncio`.
  https://docs.python.org/3/library/asyncio-task.html#task-cancellation

Замечания:
- Модуль потокобезопасен: короткие критические секции под threading.Lock.
- Асинхронные обёртки не блокируют цикл событий во время выполнения пользовательской coroutine,
  блокировки используются только для быстрых операций обновления состояния.
- OpenTelemetry метрики включаются опционально (если установлены пакеты OTel Python).
  Не могу подтвердить это: наличие OpenTelemetry в вашей среде.

Автор: Aethernova / automation-core
Лицензия: Apache-2.0 (при необходимости скорректируйте под политику репозитория)
"""

from __future__ import annotations

import asyncio
import logging
import random
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Awaitable, Callable, Deque, Iterable, Optional, Tuple, Type, TypeVar, Union

# --------------------------- Логирование --------------------------------------

LOG = logging.getLogger(__name__)

# --------------------------- OpenTelemetry (опц.) ------------------------------

try:
    # Опционально используем OpenTelemetry Metrics, если доступно
    from opentelemetry import metrics  # type: ignore
    _METER = metrics.get_meter(__name__)  # type: ignore
    _OTEL = True
except Exception:  # pragma: no cover
    _METER = None
    _OTEL = False

# --------------------------- Типы ---------------------------------------------

T = TypeVar("T")
ExcType = Union[Type[BaseException], Tuple[Type[BaseException], ...]]

# --------------------------- Исключения ---------------------------------------

class CircuitBreakerOpenError(RuntimeError):
    """Брейкер открыт — вызов отклонён без выполнения target-функции."""


# --------------------------- Состояния ----------------------------------------

class State(Enum):
    CLOSED = auto()
    OPEN = auto()
    HALF_OPEN = auto()


@dataclass
class WindowSample:
    ts: float
    is_failure: bool


# --------------------------- Конфигурация -------------------------------------

@dataclass
class CircuitBreakerConfig:
    """
    Конфигурация Circuit Breaker.

    failure_ratio: доля неуспехов (0..1) в окне, при превышении и выполнении min_calls
                   брейкер переходит в OPEN. См. Fowler и Microsoft. Источники см. модульный docstring.
    min_calls: минимальное число вызовов в окне для принятия решения (стабилизация).
    window_seconds: длительность скользящего окна.
    half_open_max_calls: сколько пробных вызовов разрешено в HALF_OPEN одновременно (обычно 1-5).
    open_base_timeout: базовое ожидание перед переходом в HALF_OPEN.
    open_timeout_max: максимум open-таймаута при экспоненциальном росте.
    jitter: величина джиттера в секундах, добавляется к open-timeout (AWS Backoff+Jitter).
    include_exceptions: какие исключения считаем неуспехами (по умолчанию любые).
    exclude_exceptions: какие исключения не считать неуспехом (имеют приоритет над include).
    """
    name: str = "default"
    failure_ratio: float = 0.5
    min_calls: int = 20
    window_seconds: float = 60.0
    half_open_max_calls: int = 1
    open_base_timeout: float = 5.0
    open_timeout_max: float = 60.0
    jitter: float = 0.5
    include_exceptions: Optional[ExcType] = None
    exclude_exceptions: Optional[ExcType] = None


# --------------------------- Реализация ---------------------------------------

class CircuitBreaker:
    """
    Потокобезопасный Circuit Breaker с поддержкой sync/async обёрток.

    Поведение соответствует рекомендациям источников: CLOSED -> OPEN при превышении доли неуспехов
    в скользящем окне, затем по истечении таймаута OPEN -> HALF_OPEN (ограниченное число пробных вызовов),
    при успехе — CLOSE, при провале — снова OPEN. См. Martin Fowler; Microsoft Azure Architecture Center.
    """

    def __init__(
        self,
        config: CircuitBreakerConfig,
        *,
        fallback: Optional[Callable[..., Any]] = None,
        on_state_change: Optional[Callable[[State, State], None]] = None,
        on_reject: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._cfg = config
        self._fallback = fallback
        self._on_state_change = on_state_change
        self._on_reject = on_reject

        self._state: State = State.CLOSED
        self._lock = threading.Lock()

        self._samples: Deque[WindowSample] = deque()
        self._opened_at: float = 0.0
        self._open_count: int = 0  # для экспоненциального увеличения таймаута
        self._half_open_inflight: int = 0

        # Метрики (если доступны)
        if _OTEL:
            try:
                self._metric_state = _METER.create_observable_gauge(  # type: ignore
                    name=f"cb.state.{self._cfg.name}",
                    description="Circuit Breaker state: 0=CLOSED,1=OPEN,2=HALF_OPEN",
                    callbacks=[self._observe_state],  # type: ignore
                )
                self._metric_calls = _METER.create_counter(  # type: ignore
                    name=f"cb.calls.{self._cfg.name}",
                    description="Calls attempted through circuit breaker",
                )
                self._metric_rejected = _METER.create_counter(  # type: ignore
                    name=f"cb.rejected.{self._cfg.name}",
                    description="Calls rejected due to OPEN state",
                )
                self._metric_failures = _METER.create_counter(  # type: ignore
                    name=f"cb.failures.{self._cfg.name}",
                    description="Failures recorded by circuit breaker",
                )
            except Exception:  # pragma: no cover
                self._metric_state = None
                self._metric_calls = None
                self._metric_rejected = None
                self._metric_failures = None
        else:
            self._metric_state = None
            self._metric_calls = None
            self._metric_rejected = None
            self._metric_failures = None

    # ------------------------ Публичные свойства ------------------------

    @property
    def state(self) -> State:
        return self._state

    @property
    def name(self) -> str:
        return self._cfg.name

    # ------------------------ Обёртки вызовов ---------------------------

    def call(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Синхронная обёртка."""
        self._before_call()
        try:
            result = fn(*args, **kwargs)
            self._after_success()
            return result
        except BaseException as exc:
            if self._is_cancelled_error(exc):
                # Не считаем отмену ошибкой бизнес-логики; пропускаем наружу
                raise
            self._after_failure(exc)
            if self._fallback:
                LOG.warning("cb_fallback_sync", extra={"cb.name": self.name, "exc": repr(exc)})
                return self._fallback(*args, **kwargs)  # type: ignore[no-any-return]
            raise

    async def call_async(self, fn: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
        """Асинхронная обёртка coroutine-функции."""
        self._before_call()
        try:
            result = await fn(*args, **kwargs)
            self._after_success()
            return result
        except BaseException as exc:
            if self._is_cancelled_error(exc):
                raise
            self._after_failure(exc)
            if self._fallback:
                LOG.warning("cb_fallback_async", extra={"cb.name": self.name, "exc": repr(exc)})
                fb = self._fallback(*args, **kwargs)
                if asyncio.iscoroutine(fb) or isinstance(fb, asyncio.Future):
                    return await fb  # type: ignore[no-any-return]
                return fb  # type: ignore[no-any-return]
            raise

    def decorator(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Декоратор: автоматически выбирает sync/async режим."""
        if asyncio.iscoroutinefunction(fn):
            async def _wrapped(*args: Any, **kwargs: Any):
                return await self.call_async(fn, *args, **kwargs)
            return _wrapped
        else:
            def _wrapped(*args: Any, **kwargs: Any):
                return self.call(fn, *args, **kwargs)
            return _wrapped

    # ------------------------ Внутренняя логика -------------------------

    def _now(self) -> float:
        # Монотонные часы для корректного измерения интервалов. Источник: Python docs.
        # https://docs.python.org/3/library/time.html#time.monotonic
        return time.monotonic()

    def _before_call(self) -> None:
        if self._metric_calls:
            try:
                self._metric_calls.add(1)  # type: ignore
            except Exception:  # pragma: no cover
                pass

        with self._lock:
            self._prune_window()
            if self._state is State.OPEN:
                if self._now() >= self._next_half_open_time():
                    # Переходим в HALF_OPEN, разрешая ограниченное число пробных вызовов
                    self._transition(State.HALF_OPEN)
                    self._half_open_inflight = 0
                else:
                    if self._metric_rejected:
                        try:
                            self._metric_rejected.add(1)  # type: ignore
                        except Exception:  # pragma: no cover
                            pass
                    if self._on_reject:
                        try:
                            self._on_reject(self._cfg.name)
                        except Exception:
                            pass
                    LOG.info("cb_reject_open", extra={"cb.name": self.name})
                    raise CircuitBreakerOpenError(f"CircuitBreaker '{self._cfg.name}' is OPEN")
            if self._state is State.HALF_OPEN:
                if self._half_open_inflight >= max(1, self._cfg.half_open_max_calls):
                    # Пробные слоты заняты — имитируем поведение как при OPEN
                    if self._metric_rejected:
                        try:
                            self._metric_rejected.add(1)  # type: ignore
                        except Exception:  # pragma: no cover
                            pass
                    LOG.info("cb_reject_half_open_limit", extra={"cb.name": self.name})
                    raise CircuitBreakerOpenError(f"CircuitBreaker '{self._cfg.name}' half-open slots exhausted")
                self._half_open_inflight += 1

    def _after_success(self) -> None:
        with self._lock:
            self._record_sample(is_failure=False)
            if self._state is State.HALF_OPEN:
                # Любой успешный пробный вызов закрывает брейкер
                self._transition(State.CLOSED)
                self._half_open_inflight = 0
                self._open_count = 0  # сброс экспоненциального таймера

    def _after_failure(self, exc: BaseException) -> None:
        # Решаем, считать ли исключение неуспехом согласно include/exclude.
        if not self._should_record_failure(exc):
            return
        if self._metric_failures:
            try:
                self._metric_failures.add(1)  # type: ignore
            except Exception:  # pragma: no cover
                pass

        with self._lock:
            self._record_sample(is_failure=True)
            if self._state is State.HALF_OPEN:
                # Первый провал в HALF_OPEN немедленно возвращает в OPEN
                self._open_again()
                self._half_open_inflight = max(0, self._half_open_inflight - 1)
                return

            # В CLOSED анализируем окно
            self._prune_window()
            total, fails = self._window_stats()
            if total >= max(1, self._cfg.min_calls):
                ratio = fails / float(total)
                if ratio >= self._cfg.failure_ratio:
                    self._open_again()

    def _open_again(self) -> None:
        self._state = State.OPEN
        self._opened_at = self._now()
        self._open_count += 1
        LOG.warning("cb_open", extra={
            "cb.name": self.name, "open.count": self._open_count, "open.timeout": self._current_open_timeout()
        })
        if self._on_state_change:
            try:
                self._on_state_change(State.CLOSED, State.OPEN)
            except Exception:
                pass

    def _transition(self, new_state: State) -> None:
        old = self._state
        if new_state is old:
            return
        self._state = new_state
        LOG.info("cb_state_change", extra={"cb.name": self.name, "from": old.name, "to": new_state.name})
        if self._on_state_change:
            try:
                self._on_state_change(old, new_state)
            except Exception:
                pass

    def _record_sample(self, *, is_failure: bool) -> None:
        self._samples.append(WindowSample(ts=self._now(), is_failure=is_failure))
        self._prune_window()

    def _prune_window(self) -> None:
        cutoff = self._now() - self._cfg.window_seconds
        while self._samples and self._samples[0].ts < cutoff:
            self._samples.popleft()

    def _window_stats(self) -> Tuple[int, int]:
        total = len(self._samples)
        fails = sum(1 for s in self._samples if s.is_failure)
        return total, fails

    def _current_open_timeout(self) -> float:
        # Экспоненциальный рост таймаута с верхней границей + аддитивный джиттер.
        # См. AWS Backoff and Jitter.
        base = self._cfg.open_base_timeout
        factor = min(self._cfg.open_timeout_max, base * (2 ** (self._open_count - 1)))
        jitter = random.uniform(0, max(0.0, self._cfg.jitter))
        return min(self._cfg.open_timeout_max, factor + jitter)

    def _next_half_open_time(self) -> float:
        return self._opened_at + self._current_open_timeout()

    def _should_record_failure(self, exc: BaseException) -> bool:
        if self._cfg.exclude_exceptions and isinstance(exc, self._cfg.exclude_exceptions):
            return False
        if self._cfg.include_exceptions is None:
            return True
        return isinstance(exc, self._cfg.include_exceptions)

    def _is_cancelled_error(self, exc: BaseException) -> bool:
        # Отмена задач в asyncio не является бизнес-ошибкой выполнения. Источник: Python docs asyncio.
        # https://docs.python.org/3/library/asyncio-task.html#task-cancellation
        return isinstance(exc, asyncio.CancelledError)

    # ------------------------ Метрики (OTel) -----------------------------------

    def _observe_state(self, observer) -> Iterable:  # type: ignore[override]
        # Observable Gauge callback (если доступен OTel)
        mapping = {State.CLOSED: 0, State.OPEN: 1, State.HALF_OPEN: 2}
        yield observer.as_observation(mapping.get(self._state, -1))  # type: ignore

# --------------------------- Утилиты/фабрики ----------------------------------

def make_http_circuit_breaker(
    name: str,
    *,
    failure_ratio: float = 0.5,
    min_calls: int = 20,
    window_seconds: float = 60.0,
    half_open_max_calls: int = 1,
    open_base_timeout: float = 5.0,
    open_timeout_max: float = 60.0,
    jitter: float = 0.5,
    include_exceptions: Optional[ExcType] = (Exception,),
    exclude_exceptions: Optional[ExcType] = (asyncio.CancelledError,),
    fallback: Optional[Callable[..., Any]] = None,
) -> CircuitBreaker:
    """
    Фабрика брейкера с типичными настройками под HTTP/IO-клиенты. См. источники Fowler/Microsoft.
    """
    cfg = CircuitBreakerConfig(
        name=name,
        failure_ratio=failure_ratio,
        min_calls=min_calls,
        window_seconds=window_seconds,
        half_open_max_calls=half_open_max_calls,
        open_base_timeout=open_base_timeout,
        open_timeout_max=open_timeout_max,
        jitter=jitter,
        include_exceptions=include_exceptions,
        exclude_exceptions=exclude_exceptions,
    )
    return CircuitBreaker(cfg, fallback=fallback)

# --------------------------- Примеры использования -----------------------------

if __name__ == "__main__":
    # Демонстрация синхронного использования
    import requests  # пример; при отсутствии пакета закомментируйте

    cb = make_http_circuit_breaker(
        "http-bin",
        failure_ratio=0.5,
        min_calls=10,
        window_seconds=30.0,
        half_open_max_calls=1,
        open_base_timeout=2.0,
        open_timeout_max=30.0,
        jitter=0.3,
        include_exceptions=(Exception,),
        exclude_exceptions=(asyncio.CancelledError,),
    )

    @cb.decorator
    def fetch(url: str) -> int:
        resp = requests.get(url, timeout=2.0)  # пример
        if resp.status_code >= 500:
            raise RuntimeError(f"server error {resp.status_code}")
        return resp.status_code

    try:
        code = fetch("https://httpbin.org/status/200")
        print("status=", code)
    except CircuitBreakerOpenError as e:
        print("rejected:", e)

    # Демонстрация асинхронного использования
    async def main():
        import aiohttp  # пример; при отсутствии пакета закомментируйте

        cb_async = make_http_circuit_breaker("http-bin-async", min_calls=5, window_seconds=10.0)

        @cb_async.decorator
        async def afetch(url: str) -> int:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(url, timeout=2.0) as r:
                    if r.status >= 500:
                        raise RuntimeError(f"server error {r.status}")
                    return r.status

        try:
            print("a-status=", await afetch("https://httpbin.org/status/200"))
        except CircuitBreakerOpenError as e:
            print("a-rejected:", e)

    try:
        asyncio.run(main())
    except Exception:
        pass
