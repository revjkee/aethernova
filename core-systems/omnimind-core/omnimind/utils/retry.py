# omnimind-core/omnimind/utils/retry.py
from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
    cast,
)

__all__ = [
    "RetryPolicy",
    "RetryError",
    "retry",
    "aretry",
    "call_with_retry",
    "async_call_with_retry",
    "exponential_backoff",
]

T = TypeVar("T")
E = TypeVar("E", bound=BaseException)

# ----------------------------- Exceptions ------------------------------------


class RetryError(RuntimeError):
    """Исключение верхнего уровня при исчерпании попыток или дедлайна."""

    def __init__(
        self,
        message: str,
        *,
        last_exception: Optional[BaseException] = None,
        attempts: int,
        elapsed_ms: float,
    ) -> None:
        super().__init__(message)
        self.last_exception = last_exception
        self.attempts = attempts
        self.elapsed_ms = elapsed_ms


# ------------------------------ Policy ---------------------------------------


@dataclass(frozen=True)
class RetryPolicy:
    """
    Политика ретраев.

    max_attempts: общее число попыток, включая первую.
    base_delay: начальная задержка в секундах.
    max_delay: верхняя граница задержки.
    multiplier: множитель экспоненты между попытками.
    jitter: режим джиттера: "none" | "full".
    retry_on_exceptions: какие исключения ретраить (по isinstance).
    retry_on_exception: дополнительный предикат по исключению.
    retry_on_result: предикат по результату; если вернёт True, будет повтор.
    give_up_on_result: предикат по результату; если True — немедленная остановка без ретрая.
    respect_retry_after: учитывать ли Retry-After в исключении/ответе.
    max_elapsed: общий бюджет времени в секундах (None — без ограничений).
    logger: опциональный логгер.
    name: произвольное имя политики в логах.
    """

    max_attempts: int = 3
    base_delay: float = 0.15
    max_delay: float = 2.0
    multiplier: float = 2.0
    jitter: str = "full"  # "none" | "full"
    retry_on_exceptions: Tuple[Type[BaseException], ...] = (Exception,)
    retry_on_exception: Optional[Callable[[BaseException], bool]] = None
    retry_on_result: Optional[Callable[[Any], bool]] = None
    give_up_on_result: Optional[Callable[[Any], bool]] = None
    respect_retry_after: bool = True
    max_elapsed: Optional[float] = None
    logger: Optional[logging.Logger] = field(default=None, compare=False)
    name: str = "default"

    def with_logger(self, logger: logging.Logger) -> "RetryPolicy":
        return RetryPolicy(
            **{**self.__dict__, "logger": logger}  # type: ignore[arg-type]
        )


def exponential_backoff(
    *,
    max_attempts: int = 3,
    base_delay: float = 0.15,
    max_delay: float = 2.0,
    multiplier: float = 2.0,
    jitter: str = "full",
    retry_on_exceptions: Tuple[Type[BaseException], ...] = (Exception,),
    retry_on_exception: Optional[Callable[[BaseException], bool]] = None,
    retry_on_result: Optional[Callable[[Any], bool]] = None,
    give_up_on_result: Optional[Callable[[Any], bool]] = None,
    respect_retry_after: bool = True,
    max_elapsed: Optional[float] = None,
    name: str = "default",
    logger: Optional[logging.Logger] = None,
) -> RetryPolicy:
    return RetryPolicy(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
        multiplier=multiplier,
        jitter=jitter,
        retry_on_exceptions=retry_on_exceptions,
        retry_on_exception=retry_on_exception,
        retry_on_result=retry_on_result,
        give_up_on_result=give_up_on_result,
        respect_retry_after=respect_retry_after,
        max_elapsed=max_elapsed,
        name=name,
        logger=logger,
    )


# ------------------------------ Utilities ------------------------------------


def _clamp(v: float, lo: float, hi: float) -> float:
    return min(max(v, lo), hi)


def _now() -> float:
    return time.monotonic()


def _parse_retry_after(value: str) -> Optional[float]:
    """
    Интерпретирует Retry-After: секунды или HTTP-дата.
    Возвращает секунды или None.
    """
    value = value.strip()
    if not value:
        return None
    try:
        secs = float(value)
        if secs >= 0:
            return secs
    except Exception:
        pass
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delta)
    except Exception:
        return None


def _get_retry_after_from_exc_or_result(err: Optional[BaseException], result: Any) -> Optional[float]:
    """
    Пытается извлечь Retry-After из исключения или результата.
    Поддерживает атрибуты:
      - err.retry_after: float|int|str
      - err.response.headers["Retry-After"]
      - result.headers["Retry-After"] (если результат похож на HTTP-ответ)
    """
    # из исключения
    if err is not None:
        ra = getattr(err, "retry_after", None)
        if isinstance(ra, (int, float)) and ra >= 0:
            return float(ra)
        if isinstance(ra, str):
            parsed = _parse_retry_after(ra)
            if parsed is not None:
                return parsed
        resp = getattr(err, "response", None)
        headers = getattr(resp, "headers", None)
        if isinstance(headers, Mapping):
            v = headers.get("Retry-After") or headers.get("retry-after")
            if isinstance(v, str):
                parsed = _parse_retry_after(v)
                if parsed is not None:
                    return parsed
    # из результата, если это ответ
    if result is not None:
        headers = getattr(result, "headers", None)
        if isinstance(headers, Mapping):
            v = headers.get("Retry-After") or headers.get("retry-after")
            if isinstance(v, str):
                parsed = _parse_retry_after(v)
                if parsed is not None:
                    return parsed
    return None


def _compute_delay(
    *,
    attempt: int,
    policy: RetryPolicy,
    retry_after: Optional[float],
) -> float:
    if retry_after is not None and policy.respect_retry_after:
        return _clamp(float(retry_after), 0.0, policy.max_delay)
    # экспоненциальный бэкофф
    base = policy.base_delay * (policy.multiplier ** max(0, attempt - 1))
    base = _clamp(base, 0.0, policy.max_delay)
    if policy.jitter == "none":
        return base
    # full jitter: [0, base]
    return random.random() * base


def _should_retry_exception(err: BaseException, policy: RetryPolicy) -> bool:
    if not isinstance(err, policy.retry_on_exceptions):
        return False
    if policy.retry_on_exception is None:
        return True
    return bool(policy.retry_on_exception(err))


def _should_retry_result(result: Any, policy: RetryPolicy) -> bool:
    if policy.give_up_on_result and policy.give_up_on_result(result):
        return False
    if policy.retry_on_result and policy.retry_on_result(result):
        return True
    return False


# ------------------------------ Sync core ------------------------------------


def call_with_retry(
    func: Callable[..., T],
    *args: Any,
    policy: Optional[RetryPolicy] = None,
    **kwargs: Any,
) -> T:
    """
    Выполняет функцию с ретраями. Блокирующая версия.
    """
    p = policy or RetryPolicy()
    log = p.logger or logging.getLogger(__name__)
    start = _now()
    attempt = 0
    last_exc: Optional[BaseException] = None

    while True:
        attempt += 1
        try:
            result = func(*args, **kwargs)
        except BaseException as e:
            last_exc = e
            can_retry = _should_retry_exception(e, p)
            elapsed = _now() - start
            budget_ok = p.max_elapsed is None or elapsed < p.max_elapsed
            attempts_left = attempt < p.max_attempts
            if not (can_retry and budget_ok and attempts_left):
                raise RetryError(
                    f"Retry attempts exhausted after {attempt} tries",
                    last_exception=e,
                    attempts=attempt,
                    elapsed_ms=round(elapsed * 1000.0, 3),
                ) from e
            delay = _compute_delay(
                attempt=attempt,
                policy=p,
                retry_after=_get_retry_after_from_exc_or_result(e, None),
            )
            log.debug(
                "retry_scheduled",
                extra={"attempt": attempt, "delay_sec": round(delay, 3), "error": str(e), "policy": p.name},
            )
            time.sleep(delay)
            continue

        # успех вызова, но возможно требуется ретрай по результату
        if _should_retry_result(result, p):
            elapsed = _now() - start
            budget_ok = p.max_elapsed is None or elapsed < p.max_elapsed
            attempts_left = attempt < p.max_attempts
            if not (budget_ok and attempts_left):
                raise RetryError(
                    f"Retry attempts exhausted on result after {attempt} tries",
                    last_exception=last_exc,
                    attempts=attempt,
                    elapsed_ms=round(elapsed * 1000.0, 3),
                )
            delay = _compute_delay(
                attempt=attempt,
                policy=p,
                retry_after=_get_retry_after_from_exc_or_result(None, result),
            )
            log.debug(
                "retry_on_result_scheduled",
                extra={"attempt": attempt, "delay_sec": round(delay, 3), "policy": p.name},
            )
            time.sleep(delay)
            continue

        # окончательный успех
        return result


# ------------------------------ Async core -----------------------------------


async def async_call_with_retry(
    func: Callable[..., Awaitable[T]],
    *args: Any,
    policy: Optional[RetryPolicy] = None,
    **kwargs: Any,
) -> T:
    """
    Выполняет функцию с ретраями. Асинхронная версия.
    """
    p = policy or RetryPolicy()
    log = p.logger or logging.getLogger(__name__)
    start = _now()
    attempt = 0
    last_exc: Optional[BaseException] = None

    while True:
        attempt += 1
        try:
            result = await func(*args, **kwargs)
        except BaseException as e:
            last_exc = e
            can_retry = _should_retry_exception(e, p)
            elapsed = _now() - start
            budget_ok = p.max_elapsed is None or elapsed < p.max_elapsed
            attempts_left = attempt < p.max_attempts
            if not (can_retry and budget_ok and attempts_left):
                raise RetryError(
                    f"Retry attempts exhausted after {attempt} tries",
                    last_exception=e,
                    attempts=attempt,
                    elapsed_ms=round(elapsed * 1000.0, 3),
                ) from e
            delay = _compute_delay(
                attempt=attempt,
                policy=p,
                retry_after=_get_retry_after_from_exc_or_result(e, None),
            )
            log.debug(
                "retry_scheduled",
                extra={"attempt": attempt, "delay_sec": round(delay, 3), "error": str(e), "policy": p.name},
            )
            await asyncio.sleep(delay)
            continue

        if _should_retry_result(result, p):
            elapsed = _now() - start
            budget_ok = p.max_elapsed is None or elapsed < p.max_elapsed
            attempts_left = attempt < p.max_attempts
            if not (budget_ok and attempts_left):
                raise RetryError(
                    f"Retry attempts exhausted on result after {attempt} tries",
                    last_exception=last_exc,
                    attempts=attempt,
                    elapsed_ms=round(elapsed * 1000.0, 3),
                )
            delay = _compute_delay(
                attempt=attempt,
                policy=p,
                retry_after=_get_retry_after_from_exc_or_result(None, result),
            )
            log.debug(
                "retry_on_result_scheduled",
                extra={"attempt": attempt, "delay_sec": round(delay, 3), "policy": p.name},
            )
            await asyncio.sleep(delay)
            continue

        return result


# ------------------------------ Decorators -----------------------------------


def retry(policy: Optional[RetryPolicy] = None) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Декоратор для синхронных функций.

    Пример:
        @retry(exponential_backoff(max_attempts=5, base_delay=0.2))
        def fetch():
            ...
    """
    p = policy or RetryPolicy()

    def _decorator(fn: Callable[..., T]) -> Callable[..., T]:
        def _wrapped(*args: Any, **kwargs: Any) -> T:
            return call_with_retry(fn, *args, policy=p, **kwargs)

        _wrapped.__name__ = getattr(fn, "__name__", "wrapped")  # служебно
        _wrapped.__doc__ = fn.__doc__
        return _wrapped

    return _decorator


def aretry(policy: Optional[RetryPolicy] = None) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Coroutine[Any, Any, T]]]:
    """
    Декоратор для асинхронных функций.

    Пример:
        @aretry(exponential_backoff(max_attempts=5, base_delay=0.2))
        async def fetch_async():
            ...
    """
    p = policy or RetryPolicy()

    def _decorator(fn: Callable[..., Awaitable[T]]) -> Callable[..., Coroutine[Any, Any, T]]:
        async def _wrapped(*args: Any, **kwargs: Any) -> T:
            return await async_call_with_retry(fn, *args, policy=p, **kwargs)

        _wrapped.__name__ = getattr(fn, "__name__", "wrapped")
        _wrapped.__doc__ = fn.__doc__
        return _wrapped

    return _decorator


# ------------------------------ Ready-made policies --------------------------

# Политика для сетевых вызовов: уважаем Retry-After, 5 попыток, джиттер
NET_POLICY = exponential_backoff(
    name="net",
    max_attempts=5,
    base_delay=0.2,
    max_delay=3.0,
    multiplier=2.0,
    jitter="full",
    respect_retry_after=True,
)

# Агрессивная политика (короткая)
FAST_POLICY = exponential_backoff(
    name="fast",
    max_attempts=3,
    base_delay=0.05,
    max_delay=0.5,
    multiplier=2.0,
    jitter="full",
    respect_retry_after=False,
)


# ------------------------------ Examples -------------------------------------

if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger("retry-demo")

    # Синхронный пример
    cnt = {"i": 0}

    @retry(NET_POLICY.with_logger(log))
    def flaky_sync() -> int:
        cnt["i"] += 1
        if cnt["i"] < 3:
            # имитируем 503 с Retry-After: 0.3
            class HttpErr(Exception):
                def __init__(self):
                    self.response = type("Resp", (), {"headers": {"Retry-After": "0.3"}})()
                def __str__(self):
                    return "503 Service Unavailable"
            raise HttpErr()
        return 42

    print("sync_result:", flaky_sync())

    # Асинхронный пример
    async def main():
        attempts = {"i": 0}

        @aretry(NET_POLICY.with_logger(log))
        async def flaky_async() -> str:
            attempts["i"] += 1
            if attempts["i"] < 2:
                raise RuntimeError("temporary")
            return "ok"

        print("async_result:", await flaky_async())

    asyncio.run(main())
