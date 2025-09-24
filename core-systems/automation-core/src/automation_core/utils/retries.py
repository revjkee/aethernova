from __future__ import annotations

"""
automation_core.utils.retries
Промышленный модуль повторов (retry) для sync/async-кода без внешних зависимостей.

Возможности:
- Sync и Async ретраи с общим ядром.
- Экспоненциальный бэкофф, варианты джиттера: none | full | equal | decorrelated.
- Ограничение по числу попыток и по общему времени выполнения (deadline).
- Таймаут на попытку: native для async (wait_for), для sync — опционально через ThreadPoolExecutor.
- Тонкая фильтрация: по типам исключений, по предикату результата, по HTTP-статусу.
- Исключения, которые нельзя ретраить (non_retry_exceptions).
- Корректная обработка asyncio.CancelledError (по умолчанию не ретраится).
- Коллбеки: on_retry, on_giveup, on_success для логирования/метрик.
- Удобные декораторы @retry(...) и @aretry(...), а также прямые вызовы retry_call/async_retry_call.
- Богатые типы и RetryError с состоянием последней попытки.

Зависимости: стандартная библиотека Python 3.11+.

Пример:
    from automation_core.utils.retries import retry, aretry, RetryConfig

    @retry(max_attempts=5, backoff_initial=0.2, jitter="full")
    def fetch_sync(url: str) -> str:
        ...

    @aretry(max_attempts=5, max_elapsed=10.0, retry_exceptions=(TimeoutError,))
    async def fetch_async(url: str) -> str:
        ...
"""

import asyncio
import random
import time
from dataclasses import dataclass
from enum import Enum
from functools import wraps, update_wrapper
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
    Generic,
    Protocol,
    runtime_checkable,
)

# ---- Типы и утилиты ----

T = TypeVar("T")
E = TypeVar("E", bound=BaseException)
P = TypeVar("P")

@runtime_checkable
class HasStatus(Protocol):
    @property
    def status(self) -> int: ...

@runtime_checkable
class HasStatusCode(Protocol):
    @property
    def status_code(self) -> int: ...

def _extract_status(obj: Any) -> Optional[int]:
    if isinstance(obj, int):
        return obj
    if isinstance(obj, HasStatus):
        try:
            return int(obj.status)
        except Exception:
            return None
    if isinstance(obj, HasStatusCode):
        try:
            return int(obj.status_code)
        except Exception:
            return None
    # Популярные поля
    for key in ("code", "status", "status_code"):
        if isinstance(obj, dict) and key in obj:
            try:
                return int(obj[key])
            except Exception:
                return None
    return None


class JitterStrategy(str, Enum):
    NONE = "none"
    FULL = "full"
    EQUAL = "equal"
    DECORRELATED = "decorrelated"


@dataclass(frozen=True)
class RetryConfig:
    # Лимиты
    max_attempts: int = 3                    # >=1
    max_elapsed: Optional[float] = None      # секунды; None = без лимита

    # Бэкофф
    backoff_initial: float = 0.2             # сек, первая задержка до джиттера
    backoff_multiplier: float = 2.0
    backoff_max: float = 15.0
    jitter: JitterStrategy = JitterStrategy.FULL

    # Таймаут попытки
    per_try_timeout: Optional[float] = None  # сек; для sync см. sync_timeout_via_thread
    sync_timeout_via_thread: bool = False    # выполнять попытки в отдельном потоке, если задан per_try_timeout

    # Фильтрация ретраев
    retry_exceptions: Tuple[Type[BaseException], ...] = (TimeoutError, )
    non_retry_exceptions: Tuple[Type[BaseException], ...] = (asyncio.CancelledError,)
    retry_if_result: Optional[Callable[[Any], bool]] = None  # True => повторить
    retry_on_status: Optional[Sequence[int]] = None          # список кодов статуса для повторов

    # Пользовательские коллбеки
    on_retry: Optional[Callable[["Attempt", float], None]] = None
    on_giveup: Optional[Callable[["Attempt"], None]] = None
    on_success: Optional[Callable[["Attempt"], None]] = None


@dataclass
class Attempt:
    attempt: int
    start_monotonic: float
    end_monotonic: float
    exception: Optional[BaseException]
    result: Any

    @property
    def elapsed(self) -> float:
        return self.end_monotonic - self.start_monotonic


class RetryError(RuntimeError):
    def __init__(self, message: str, last_attempt: Attempt, total_elapsed: float):
        super().__init__(message)
        self.last_attempt = last_attempt
        self.total_elapsed = total_elapsed

    def __str__(self) -> str:
        base = super().__str__()
        return f"{base} (attempt={self.last_attempt.attempt}, total_elapsed={self.total_elapsed:.3f}s)"


# ---- Бэкофф ----

def _cap_backoff(value: float, cfg: RetryConfig) -> float:
    return min(max(0.0, value), cfg.backoff_max)

def _compute_backoff_base(attempt: int, cfg: RetryConfig) -> float:
    # attempt начинается с 1; для первой задержки используем backoff_initial
    base = cfg.backoff_initial * (cfg.backoff_multiplier ** max(0, attempt - 1))
    return _cap_backoff(base, cfg)

def _apply_jitter(base: float, prev_sleep: float, cfg: RetryConfig) -> float:
    if cfg.jitter == JitterStrategy.NONE:
        return base
    if cfg.jitter == JitterStrategy.FULL:
        return random.uniform(0.0, base)
    if cfg.jitter == JitterStrategy.EQUAL:
        return base * 0.5 + random.uniform(0.0, base * 0.5)
    if cfg.jitter == JitterStrategy.DECORRELATED:
        lo = cfg.backoff_initial
        hi = max(prev_sleep * 3.0, lo)
        return _cap_backoff(random.uniform(lo, hi), cfg)
    return base


# ---- Общее ядро ----

def _should_retry_by_result(result: Any, cfg: RetryConfig) -> bool:
    if cfg.retry_if_result:
        try:
            if cfg.retry_if_result(result):
                return True
        except Exception:
            # предикат не должен ронять управление; трактуем как отсутствие ретрая
            return False
    if cfg.retry_on_status:
        st = _extract_status(result)
        if st is not None and st in cfg.retry_on_status:
            return True
    return False

def _exception_causes_retry(exc: BaseException, cfg: RetryConfig) -> bool:
    if isinstance(exc, cfg.non_retry_exceptions):
        return False
    return isinstance(exc, cfg.retry_exceptions) or isinstance(exc, tuple())


# ---- Sync выполнение ----
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutTimeout

def retry_call(
    func: Callable[..., T],
    *args: Any,
    config: RetryConfig | None = None,
    **kwargs: Any,
) -> T:
    """
    Вызов функции с ретраями (синхронный).
    Если задан per_try_timeout и включен sync_timeout_via_thread=True — попытка выполняется в отдельном потоке.
    ВНИМАНИЕ: прервать выполнение потока по истечении таймаута нельзя — поток может продолжить работу в фоне.
    """
    cfg = config or RetryConfig()
    if cfg.max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    started_total = time.monotonic()
    last_sleep = cfg.backoff_initial
    last_attempt: Attempt | None = None

    # Единый executor по вызову
    executor: ThreadPoolExecutor | None = None
    if cfg.per_try_timeout and cfg.sync_timeout_via_thread:
        executor = ThreadPoolExecutor(max_workers=1)

    try:
        for attempt in range(1, cfg.max_attempts + 1):
            # Проверка дедлайна перед очередной попыткой
            if cfg.max_elapsed is not None:
                if time.monotonic() - started_total > cfg.max_elapsed:
                    if last_attempt:
                        raise RetryError("max elapsed time exceeded", last_attempt, time.monotonic() - started_total)
                    raise RetryError("max elapsed time exceeded", Attempt(0, started_total, time.monotonic(), None, None), time.monotonic() - started_total)

            a_start = time.monotonic()
            exc: BaseException | None = None
            res: Any = None

            try:
                if cfg.per_try_timeout and cfg.sync_timeout_via_thread:
                    assert executor is not None
                    fut = executor.submit(func, *args, **kwargs)
                    try:
                        res = fut.result(timeout=cfg.per_try_timeout)
                    except _FutTimeout:
                        # Превращаем в TimeoutError, чтобы попало под retry_exceptions (по умолчанию включен)
                        exc = TimeoutError(f"sync per-try timeout after {cfg.per_try_timeout}s")
                    except BaseException as e:
                        exc = e
                else:
                    # Без потока. Если per_try_timeout указан — применить невозможно безопасно.
                    res = func(*args, **kwargs)

            except BaseException as e:
                exc = e

            a_end = time.monotonic()
            att = Attempt(attempt=attempt, start_monotonic=a_start, end_monotonic=a_end, exception=exc, result=res)
            last_attempt = att

            # Успех?
            if exc is None and not _should_retry_by_result(res, cfg):
                if cfg.on_success:
                    try: cfg.on_success(att)
                    except Exception: pass
                return res  # type: ignore[return-value]

            # Решение о повторе
            do_retry = False
            reason = ""

            if exc is not None:
                if _exception_causes_retry(exc, cfg):
                    do_retry = True
                    reason = f"exception: {exc.__class__.__name__}"
                else:
                    # не ретраим этот тип исключения
                    if cfg.on_giveup:
                        try: cfg.on_giveup(att)
                        except Exception: pass
                    raise exc

            elif _should_retry_by_result(res, cfg):
                do_retry = True
                reason = "unfavorable result"

            # Достигнут лимит попыток?
            if attempt >= cfg.max_attempts:
                if cfg.on_giveup:
                    try: cfg.on_giveup(att)
                    except Exception: pass
                if exc is not None:
                    raise RetryError(f"retries exhausted due to {reason}", att, time.monotonic() - started_total) from exc
                raise RetryError(f"retries exhausted due to {reason}", att, time.monotonic() - started_total)

            # Дедлайн по общему времени?
            if cfg.max_elapsed is not None and (time.monotonic() - started_total) >= cfg.max_elapsed:
                if cfg.on_giveup:
                    try: cfg.on_giveup(att)
                    except Exception: pass
                if exc is not None:
                    raise RetryError("max elapsed time exceeded", att, time.monotonic() - started_total) from exc
                raise RetryError("max elapsed time exceeded", att, time.monotonic() - started_total)

            # Сон перед следующей попыткой
            base = _compute_backoff_base(attempt, cfg)
            sleep_for = _apply_jitter(base, last_sleep, cfg)
            last_sleep = sleep_for

            if cfg.on_retry:
                try: cfg.on_retry(att, sleep_for)
                except Exception: pass

            time.sleep(sleep_for)

        # не должно дойти
        assert last_attempt is not None
        raise RetryError("unexpected fallthrough", last_attempt, time.monotonic() - started_total)
    finally:
        if executor:
            executor.shutdown(cancel_futures=False)


# ---- Async выполнение ----

async def async_retry_call(
    func: Callable[..., Awaitable[T]],
    *args: Any,
    config: RetryConfig | None = None,
    **kwargs: Any,
) -> T:
    """
    Вызов корутины с ретраями (асинхронный).
    Таймаут попытки реализован нативно через asyncio.wait_for.
    """
    cfg = config or RetryConfig()
    if cfg.max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    started_total = time.monotonic()
    last_sleep = cfg.backoff_initial
    last_attempt: Attempt | None = None

    for attempt in range(1, cfg.max_attempts + 1):
        if cfg.max_elapsed is not None:
            if time.monotonic() - started_total > cfg.max_elapsed:
                if last_attempt:
                    raise RetryError("max elapsed time exceeded", last_attempt, time.monotonic() - started_total)
                raise RetryError("max elapsed time exceeded", Attempt(0, started_total, time.monotonic(), None, None), time.monotonic() - started_total)

        a_start = time.monotonic()
        exc: BaseException | None = None
        res: Any = None

        try:
            if cfg.per_try_timeout is not None:
                res = await asyncio.wait_for(func(*args, **kwargs), timeout=cfg.per_try_timeout)
            else:
                res = await func(*args, **kwargs)
        except asyncio.CancelledError:
            # По умолчанию — не ретраим отмену
            if asyncio.CancelledError in cfg.non_retry_exceptions or cfg.non_retry_exceptions == (asyncio.CancelledError,):
                raise
            # если пользователь явно разрешил ретраи CancelledError — пропустим дальше
            exc = asyncio.CancelledError()
        except BaseException as e:
            exc = e

        a_end = time.monotonic()
        att = Attempt(attempt=attempt, start_monotonic=a_start, end_monotonic=a_end, exception=exc, result=res)
        last_attempt = att

        if exc is None and not _should_retry_by_result(res, cfg):
            if cfg.on_success:
                try: cfg.on_success(att)
                except Exception: pass
            return res  # type: ignore[return-value]

        do_retry = False
        reason = ""
        if exc is not None:
            if _exception_causes_retry(exc, cfg):
                do_retry = True
                reason = f"exception: {exc.__class__.__name__}"
            else:
                if cfg.on_giveup:
                    try: cfg.on_giveup(att)
                    except Exception: pass
                raise exc
        elif _should_retry_by_result(res, cfg):
            do_retry = True
            reason = "unfavorable result"

        if attempt >= cfg.max_attempts:
            if cfg.on_giveup:
                try: cfg.on_giveup(att)
                except Exception: pass
            if exc is not None:
                raise RetryError(f"retries exhausted due to {reason}", att, time.monotonic() - started_total) from exc
            raise RetryError(f"retries exhausted due to {reason}", att, time.monotonic() - started_total)

        if cfg.max_elapsed is not None and (time.monotonic() - started_total) >= cfg.max_elapsed:
            if cfg.on_giveup:
                try: cfg.on_giveup(att)
                except Exception: pass
            if exc is not None:
                raise RetryError("max elapsed time exceeded", att, time.monotonic() - started_total) from exc
            raise RetryError("max elapsed time exceeded", att, time.monotonic() - started_total)

        base = _compute_backoff_base(attempt, cfg)
        sleep_for = _apply_jitter(base, last_sleep, cfg)
        last_sleep = sleep_for

        if cfg.on_retry:
            try: cfg.on_retry(att, sleep_for)
            except Exception: pass

        # Сон с возможностью прерывания отменой
        try:
            await asyncio.sleep(sleep_for)
        except asyncio.CancelledError:
            # пусть отмена пробрасывается немедленно
            raise

    assert last_attempt is not None
    raise RetryError("unexpected fallthrough", last_attempt, time.monotonic() - started_total)


# ---- Декораторы ----
F = TypeVar("F", bound=Callable[..., Any])
AF = TypeVar("AF", bound=Callable[..., Awaitable[Any]])

def retry(**cfg_kwargs: Any) -> Callable[[F], F]:
    """
    Декоратор для синхронных функций.
    Пример:
        @retry(max_attempts=5, retry_exceptions=(IOError, TimeoutError))
        def op(...): ...
    """
    cfg = RetryConfig(**cfg_kwargs)
    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            return retry_call(fn, *args, config=cfg, **kwargs)
        return update_wrapper(wrapper, fn)  # type: ignore[return-value]
    return decorator

def aretry(**cfg_kwargs: Any) -> Callable[[AF], AF]:
    """
    Декоратор для асинхронных функций.
    Пример:
        @aretry(max_attempts=4, max_elapsed=10.0, jitter="decorrelated")
        async def op(...): ...
    """
    cfg = RetryConfig(**cfg_kwargs)
    def decorator(fn: AF) -> AF:
        @wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any):
            return await async_retry_call(fn, *args, config=cfg, **kwargs)
        return update_wrapper(wrapper, fn)  # type: ignore[return-value]
    return decorator


# ---- Утилиты предикатов ----

def retry_if_none(x: Any) -> bool:
    """Повторять, если результат None."""
    return x is None

def retry_if_false(x: Any) -> bool:
    """Повторять, если результат строго False."""
    return x is False

def retry_if_status_in(statuses: Sequence[int]) -> Callable[[Any], bool]:
    """Собрать предикат: повторять, если код статуса ∈ statuses."""
    sset = set(int(s) for s in statuses)
    def _pred(res: Any) -> bool:
        st = _extract_status(res)
        return st in sset if st is not None else False
    return _pred


# ---- Мини-тест вручную (можно удалить/закомментировать) ----
if __name__ == "__main__":
    # Пример sync
    calls = {"n": 0}
    def flaky() -> int:
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("simulated")
        return 42

    val = retry_call(flaky, config=RetryConfig(max_attempts=5, jitter=JitterStrategy.FULL))
    print("sync value:", val)

    # Пример async
    async def run():
        state = {"n": 0}
        @aretry(max_attempts=4, backoff_initial=0.1, jitter="equal")
        async def async_flaky() -> int:
            state["n"] += 1
            if state["n"] < 3:
                await asyncio.sleep(0.05)
                raise TimeoutError("async simulated")
            return 7
        print("async value:", await async_flaky())

    asyncio.run(run())
