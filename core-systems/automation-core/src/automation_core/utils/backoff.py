# automation-core/src/automation_core/utils/backoff.py
# -*- coding: utf-8 -*-
"""
Промышленный модуль backoff/retry для sync/async кода без внешних зависимостей.

Возможности:
- Стратегии задержек: Constant, Exponential (full/equal/decorrelated jitter), cap.
- Унифицированный декоратор @retry для sync и async функций.
- Параметры: max_attempts, deadline, исключения для ретрая, give_up-предикат.
- Поддержка Retry-After (через кастомный extractor из исключения/ответа).
- Коллбек on_retry(RetryState) — sync или async.
- Строгая типизация, dataclass для состояния, без внешних зависимостей.

Важные замечания:
- Decorrelated jitter требует предыдущей задержки; для первой попытки берется базовое значение.
- deadline трактуется как "жесткий" лимит «стена-время»: окончание до начала следующего ретрая.
"""

from __future__ import annotations

import asyncio
import inspect
import math
import random
import time
from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Iterable,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

__all__ = [
    "RetryState",
    "BackoffStrategy",
    "ConstantBackoff",
    "ExponentialBackoff",
    "retry",
    "async_retry",
]

T = TypeVar("T")
R = TypeVar("R")


# =========================
#   Состояние и утилиты
# =========================

@dataclass(frozen=True)
class RetryState:
    attempt: int                   # номер попытки, начиная с 1 (первая — 1)
    exception: Optional[BaseException]
    delay: float                   # рассчитанная задержка до следующей попытки (сек)
    previous_delay: float          # задержка перед предыдущей попыткой (сек)
    elapsed: float                 # прошедшее время с начала вызова (сек)
    next_scheduled_at: float       # time.monotonic() планового старта следующей попытки


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _is_coro_fn(fn: Callable[..., Any]) -> bool:
    return inspect.iscoroutinefunction(fn)


async def _maybe_await(x: Union[R, Awaitable[R]]) -> R:
    if inspect.isawaitable(x):
        return await x  # type: ignore[return-value]
    return x  # type: ignore[return-value]


# =========================
#   Стратегии бэкоффа
# =========================

class BackoffStrategy:
    """
    Абстракция стратегии задержек.
    """
    def next_delay(
        self,
        attempt: int,
        *,
        previous_delay: float,
        retry_after: Optional[float] = None,
    ) -> float:
        raise NotImplementedError


class ConstantBackoff(BackoffStrategy):
    """
    Константная задержка.
    """
    def __init__(self, delay: float) -> None:
        assert delay >= 0.0
        self.delay = float(delay)

    def next_delay(
        self,
        attempt: int,
        *,
        previous_delay: float,
        retry_after: Optional[float] = None,
    ) -> float:
        if retry_after is not None and retry_after >= 0:
            return float(retry_after)
        return self.delay


class ExponentialBackoff(BackoffStrategy):
    """
    Экспоненциальный бэкофф с джиттером (none/full/equal/decorrelated) и "потолком" (cap).

    Параметры:
      base:  базовая задержка (сек), применяемая для attempt=1 (до джиттера).
      factor: множитель роста на каждую попытку (>0). Общая формула: base * factor**(attempt-1).
      cap:   верхний предел задержки (сек), применяется после расчета.
      jitter: "none" | "full" | "equal" | "decorrelated"
    """
    __slots__ = ("base", "factor", "cap", "jitter")

    def __init__(
        self,
        base: float = 0.5,
        factor: float = 2.0,
        cap: float = 30.0,
        jitter: str = "full",
    ) -> None:
        assert base >= 0.0 and factor > 0.0 and cap >= 0.0
        assert jitter in ("none", "full", "equal", "decorrelated")
        self.base = float(base)
        self.factor = float(factor)
        self.cap = float(cap)
        self.jitter = jitter

    def _raw(self, attempt: int) -> float:
        # base * factor^(attempt-1)
        return self.base * (self.factor ** max(0, attempt - 1))

    def _apply_jitter(
        self, value: float, *, previous_delay: float
    ) -> float:
        if self.jitter == "none":
            return value

        if self.jitter == "full":
            # равномерный [0, value]
            return random.uniform(0.0, value)

        if self.jitter == "equal":
            # value/2 + U(0, value/2)
            half = value * 0.5
            return half + random.uniform(0.0, half)

        # decorrelated:
        # классический прием: next = random(min(cap, prev*3), cap)
        # если previous_delay == 0 — берем "сырой" value как старт.
        prev = previous_delay if previous_delay > 0 else value
        low = min(self.cap, prev * 3.0)
        high = self.cap if self.cap > 0 else max(value, prev)
        if high < low:
            low, high = high, low
        return random.uniform(low, high)

    def next_delay(
        self,
        attempt: int,
        *,
        previous_delay: float,
        retry_after: Optional[float] = None,
    ) -> float:
        if retry_after is not None and retry_after >= 0:
            return float(retry_after)

        raw = self._raw(attempt)
        raw_capped = _clamp(raw, 0.0, self.cap if self.cap > 0 else float("inf"))
        d = self._apply_jitter(raw_capped, previous_delay=previous_delay)
        # финальная защита от отрицательных и NaN
        if not (d >= 0.0 and math.isfinite(d)):
            d = 0.0
        return d


# =========================
#   Декораторы retry
# =========================

RetryAfterExtractor = Callable[[BaseException], Optional[float]]
GiveUpPredicate = Callable[[BaseException], bool]
OnRetryCallback = Callable[[RetryState], Union[None, Awaitable[None]]]


def _default_retry_after(_: BaseException) -> Optional[float]:
    return None


def _now() -> float:
    return time.monotonic()


def _sleep_sync(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)


async def _sleep_async(seconds: float) -> None:
    if seconds > 0:
        await asyncio.sleep(seconds)


def retry(  # noqa: C901 - комплексная логика по делу
    *,
    exceptions: Tuple[Type[BaseException], ...] = (Exception,),
    max_attempts: int = 5,
    deadline: Optional[float] = None,  # сек, жесткий лимит "стены"
    strategy: Optional[BackoffStrategy] = None,
    retry_after_getter: RetryAfterExtractor = _default_retry_after,
    give_up: Optional[GiveUpPredicate] = None,
    on_retry: Optional[OnRetryCallback] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Универсальный декоратор ретрая для sync/async функций.

    Аргументы:
      exceptions: какие исключения ретраить (подклассы).
      max_attempts: максимум попыток (>=1).
      deadline: жесткий лимит по «стене времени», сек (None — без лимита).
      strategy: стратегия BackoffStrategy (по умолчанию экспоненциальная full jitter).
      retry_after_getter: extractor секунд из исключения (например, из HTTP Retry-After).
      give_up: предикат прекращения ретраев для конкретной ошибки.
      on_retry: коллбек, вызываемый перед сном (получает RetryState).
    """
    assert max_attempts >= 1
    strategy = strategy or ExponentialBackoff()

    def _decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        is_coro = _is_coro_fn(func)

        async def _run_async(*args: Any, **kwargs: Any) -> Any:
            start = _now()
            previous_delay = 0.0

            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as exc:  # type: ignore[misc]
                    if give_up and give_up(exc):
                        raise

                    # последний шанс — не спим, просто пробрасываем
                    if attempt >= max_attempts:
                        raise

                    # уважаем deadline
                    elapsed = _now() - start
                    remaining = None if deadline is None else max(0.0, deadline - elapsed)
                    ra = retry_after_getter(exc)
                    delay = strategy.next_delay(
                        attempt=attempt,
                        previous_delay=previous_delay,
                        retry_after=ra,
                    )

                    if remaining is not None:
                        if remaining <= 0:
                            raise
                        delay = min(delay, remaining)

                    state = RetryState(
                        attempt=attempt,
                        exception=exc,
                        delay=delay,
                        previous_delay=previous_delay,
                        elapsed=elapsed,
                        next_scheduled_at=_now() + delay,
                    )

                    if on_retry:
                        await _maybe_await(on_retry(state))

                    previous_delay = delay
                    await _sleep_async(delay)

            # логически недостижимо
            raise RuntimeError("retry: exhausted unexpectedly (async)")

        def _run_sync(*args: Any, **kwargs: Any) -> Any:
            start = _now()
            previous_delay = 0.0

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:  # type: ignore[misc]
                    if give_up and give_up(exc):
                        raise

                    if attempt >= max_attempts:
                        raise

                    elapsed = _now() - start
                    remaining = None if deadline is None else max(0.0, deadline - elapsed)
                    ra = retry_after_getter(exc)
                    delay = strategy.next_delay(
                        attempt=attempt,
                        previous_delay=previous_delay,
                        retry_after=ra,
                    )

                    if remaining is not None:
                        if remaining <= 0:
                            raise
                        delay = min(delay, remaining)

                    state = RetryState(
                        attempt=attempt,
                        exception=exc,
                        delay=delay,
                        previous_delay=previous_delay,
                        elapsed=elapsed,
                        next_scheduled_at=_now() + delay,
                    )

                    if on_retry:
                        # on_retry может быть async — корректно обработаем
                        asyncio_run_required = inspect.iscoroutinefunction(on_retry) or inspect.iscoroutine(on_retry)
                        if asyncio_run_required:
                            # без утечек цикла: создаем временный event loop
                            try:
                                loop = asyncio.get_event_loop()
                            except RuntimeError:
                                loop = asyncio.new_event_loop()
                                try:
                                    asyncio.set_event_loop(loop)
                                    loop.run_until_complete(_maybe_await(on_retry(state)))
                                finally:
                                    loop.close()
                                    asyncio.set_event_loop(None)
                            else:
                                # Уже есть активный loop (например, в тестах) — используем его.
                                fut = _maybe_await(on_retry(state))
                                loop.run_until_complete(fut)  # type: ignore[arg-type]
                        else:
                            on_retry(state)  # type: ignore[misc]

                    previous_delay = delay
                    _sleep_sync(delay)

            raise RuntimeError("retry: exhausted unexpectedly (sync)")

        return _run_async if is_coro else _run_sync

    return _decorator


# Альяс с теми же параметрами для ясности намерений
async_retry = retry
