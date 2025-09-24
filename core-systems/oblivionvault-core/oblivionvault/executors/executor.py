# oblivionvault/executors/executor.py
from __future__ import annotations

import abc
import asyncio
import json
import logging
import os
import random
import shlex
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Tuple,
    Union,
)
from uuid import UUID, uuid4

# --------------------------- Логирование (структурное) ---------------------------

logger = logging.getLogger("oblivionvault.executor")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def _jsonlog(event: str, **kv: Any) -> None:
    payload = {"ts": _utc_iso(_now()), "event": event, **kv}
    try:
        logger.info(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    except Exception:
        logger.info("%s | %s", event, kv)


# --------------------------- Протоколы интеграций ---------------------------

class IdempotencyStore(Protocol):
    """Хранилище результатов по ключу идемпотентности (успех/провал/иные статусы)."""

    async def get(self, key: str) -> Optional["ExecutionResult"]:
        ...

    async def put(self, key: str, result: "ExecutionResult", ttl_seconds: int = 86400) -> None:
        ...


class LockManager(Protocol):
    """Распределенная блокировка для исключения гонок."""
    async def acquire(self, key: str, ttl_seconds: int, owner: str) -> bool:
        ...
    async def release(self, key: str, owner: str) -> None:
        ...


class RateLimiter(Protocol):
    """Лимитирование запросов (например, токен-бакет)."""
    async def acquire(self, tokens: int = 1, timeout_seconds: float = 0.0) -> bool:
        ...


class AuditSink(Protocol):
    """Аудит-события исполнения."""
    async def emit(self, event: Mapping[str, Any]) -> None:
        ...


class MetricsSink(Protocol):
    """Метрики: латентность, ошибки, ретраи и т.д."""
    async def observe_duration(self, name: str, seconds: float, labels: Mapping[str, str]) -> None:
        ...
    async def inc_counter(self, name: str, inc: float = 1.0, labels: Mapping[str, str] = ...) -> None:
        ...
    async def set_gauge(self, name: str, value: float, labels: Mapping[str, str]) -> None:
        ...


# --------------------------- Вспомогательные классы ---------------------------

class ExecutionStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    RETRY = "retry"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Command:
    """Описание исполняемой команды/задачи."""
    name: str
    params: Dict[str, Any] = field(default_factory=dict)
    payload: Optional[Union[str, bytes]] = None
    idempotency_key: Optional[str] = None
    priority: int = 0
    lock_key: Optional[str] = None
    annotations: Dict[str, str] = field(default_factory=dict)  # свободные метки (evidence-id и т.п.)


@dataclass
class ExecutionContext:
    """Контекст исполнения (аудит, дедлайны, трассировка)."""
    request_id: UUID = field(default_factory=uuid4)
    trace_id: Optional[str] = None
    evidence_id: Optional[str] = None
    audit_user: Optional[str] = None
    audit_reason: Optional[str] = None
    deadline: Optional[datetime] = None
    timeout_seconds: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_now)

    def remaining_seconds(self) -> Optional[float]:
        if not self.deadline:
            return None
        return max(0.0, (self.deadline - _now()).total_seconds())


@dataclass
class ExecutionResult:
    """Результат исполнения задачи."""
    status: ExecutionStatus
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    attempt: int
    retries: int
    output: Optional[str] = None
    error: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["started_at"] = _utc_iso(self.started_at)
        d["finished_at"] = _utc_iso(self.finished_at)
        d["status"] = self.status.value
        return d


@dataclass
class RetryPolicy:
    """Стратегия ретраев с экспоненциальной задержкой и джиттером."""
    max_attempts: int = 3
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 30.0
    multiplier: float = 2.0
    jitter: float = 0.25  # доля случайного размаха от задержки
    retry_on_timeouts: bool = True
    retry_on_failures: bool = True

    def backoff(self, attempt: int) -> float:
        delay = min(self.base_delay_seconds * (self.multiplier ** (attempt - 1)), self.max_delay_seconds)
        if self.jitter > 0:
            delta = delay * self.jitter
            delay = random.uniform(delay - delta, delay + delta)
        return max(0.0, delay)


class CircuitBreaker:
    """Простой circuit breaker с состояниями closed -> open -> half-open."""
    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._failures = 0
        self._opened_at: Optional[float] = None

    def allow(self) -> bool:
        if self._opened_at is None:
            return True
        # half-open после таймаута
        return (time.monotonic() - self._opened_at) >= self.reset_timeout

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = time.monotonic()

# --------------------------- Реализации по умолчанию ---------------------------

class InMemoryIdempotencyStore:
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[ExecutionResult, float]] = {}

    async def get(self, key: str) -> Optional[ExecutionResult]:
        item = self._store.get(key)
        if not item:
            return None
        result, expires = item
        if time.time() > expires:
            self._store.pop(key, None)
            return None
        return result

    async def put(self, key: str, result: ExecutionResult, ttl_seconds: int = 86400) -> None:
        self._store[key] = (result, time.time() + ttl_seconds)


class NoopLockManager:
    async def acquire(self, key: str, ttl_seconds: int, owner: str) -> bool:
        return True
    async def release(self, key: str, owner: str) -> None:
        return None


class NoopRateLimiter:
    async def acquire(self, tokens: int = 1, timeout_seconds: float = 0.0) -> bool:
        return True


class NoopAuditSink:
    async def emit(self, event: Mapping[str, Any]) -> None:
        _jsonlog("audit", **dict(event))


class NoopMetricsSink:
    async def observe_duration(self, name: str, seconds: float, labels: Mapping[str, str]) -> None:
        return None
    async def inc_counter(self, name: str, inc: float = 1.0, labels: Mapping[str, str] = ...) -> None:
        return None
    async def set_gauge(self, name: str, value: float, labels: Mapping[str, str]) -> None:
        return None


# --------------------------- Базовый исполнитель ---------------------------

class BaseExecutor(abc.ABC):
    """
    Базовый класс безопасного исполнения команд.
    Переопределяйте _execute() для конкретной логики (SQL/HTTP/Shell/...).
    """

    def __init__(
        self,
        *,
        idempotency: Optional[IdempotencyStore] = None,
        locks: Optional[LockManager] = None,
        rate_limiter: Optional[RateLimiter] = None,
        audit: Optional[AuditSink] = None,
        metrics: Optional[MetricsSink] = None,
        retry: Optional[RetryPolicy] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        idempotency_ttl_seconds: int = 86400,
        lock_ttl_seconds: int = 300,
        name: str = "executor",
        redact_keys: Optional[List[str]] = None,
        max_output_bytes: int = 1_000_000,
    ) -> None:
        self.idempotency = idempotency or InMemoryIdempotencyStore()
        self.locks = locks or NoopLockManager()
        self.rate_limiter = rate_limiter or NoopRateLimiter()
        self.audit = audit or NoopAuditSink()
        self.metrics = metrics or NoopMetricsSink()
        self.retry = retry or RetryPolicy()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.idempotency_ttl_seconds = idempotency_ttl_seconds
        self.lock_ttl_seconds = lock_ttl_seconds
        self.name = name
        self.redact_keys = set(k.lower() for k in (redact_keys or ["password", "secret", "token", "authorization"]))
        self.max_output_bytes = max_output_bytes

    # --- API ---

    async def run(self, command: Command, ctx: ExecutionContext) -> ExecutionResult:
        """
        Основной метод исполнения: оркестрация окружения, ретраи, метрики, аудит.
        """
        labels = {
            "executor": self.name,
            "command": command.name,
            "env": os.getenv("OVC_ENV", "staging"),
        }

        # Rate limit
        if not await self.rate_limiter.acquire(tokens=1, timeout_seconds=0.5):
            res = self._finish(
                status=ExecutionStatus.SKIPPED,
                started=_now(),
                attempt=0,
                retries=0,
                error="rate_limited",
            )
            await self.metrics.inc_counter("executor_skipped", labels=labels)
            return res

        # Circuit breaker
        if not self.circuit_breaker.allow():
            res = self._finish(
                status=ExecutionStatus.SKIPPED,
                started=_now(),
                attempt=0,
                retries=0,
                error="circuit_open",
            )
            await self.metrics.inc_counter("executor_skipped", labels=labels)
            return res

        # Идемпотентность (если ключ есть)
        if command.idempotency_key:
            cached = await self.idempotency.get(command.idempotency_key)
            if cached:
                await self.metrics.inc_counter("executor_idempotent_hit", labels=labels)
                await self.audit.emit(
                    {
                        "type": "idempotent.hit",
                        "request_id": str(ctx.request_id),
                        "command": command.name,
                        "key": command.idempotency_key,
                        "result": cached.to_dict(),
                    }
                )
                return cached

        # Блокировка (если ключ есть)
        lock_owner = f"{self.name}:{ctx.request_id}"
        have_lock = False
        if command.lock_key:
            have_lock = await self.locks.acquire(command.lock_key, ttl_seconds=self.lock_ttl_seconds, owner=lock_owner)
            if not have_lock:
                res = self._finish(
                    status=ExecutionStatus.SKIPPED,
                    started=_now(),
                    attempt=0,
                    retries=0,
                    error="lock_not_acquired",
                )
                await self.metrics.inc_counter("executor_skipped", labels=labels)
                return res

        started = _now()
        await self.audit.emit(
            {
                "type": "execution.started",
                "request_id": str(ctx.request_id),
                "trace_id": ctx.trace_id,
                "evidence_id": ctx.evidence_id,
                "command": command.name,
                "started_at": _utc_iso(started),
                "params": self._safe_params(command.params),
            }
        )

        attempt = 0
        last_error: Optional[str] = None
        while True:
            attempt += 1
            try:
                # Пересчитываем эффективный таймаут с учетом дедлайна
                eff_timeout = ctx.timeout_seconds
                rem = ctx.remaining_seconds()
                if rem is not None:
                    eff_timeout = min(eff_timeout or rem, rem)
                    if eff_timeout <= 0:
                        raise asyncio.TimeoutError("deadline_exceeded")

                exec_coro = self._execute(command, ctx)
                if eff_timeout:
                    raw_output = await asyncio.wait_for(exec_coro, timeout=eff_timeout)
                else:
                    raw_output = await exec_coro

                result = self._finish(
                    status=ExecutionStatus.SUCCESS,
                    started=started,
                    attempt=attempt,
                    retries=attempt - 1,
                    output=self._truncate_output(raw_output),
                )
                await self.metrics.observe_duration("executor_duration_seconds", result.duration_seconds, labels)
                await self.metrics.inc_counter("executor_success_total", labels=labels)
                self.circuit_breaker.record_success()

                await self.audit.emit(
                    {
                        "type": "execution.succeeded",
                        "request_id": str(ctx.request_id),
                        "command": command.name,
                        "finished_at": _utc_iso(result.finished_at),
                        "attempt": attempt,
                    }
                )

                if command.idempotency_key:
                    await self.idempotency.put(command.idempotency_key, result, ttl_seconds=self.idempotency_ttl_seconds)

                return result

            except asyncio.TimeoutError as te:
                last_error = "timeout"
                await self.metrics.inc_counter("executor_timeout_total", labels=labels)
                if not self.retry.retry_on_timeouts or attempt >= self.retry.max_attempts:
                    result = self._finish(
                        status=ExecutionStatus.TIMEOUT,
                        started=started,
                        attempt=attempt,
                        retries=attempt - 1,
                        error=str(te),
                    )
                    await self._finalize_failure(command, ctx, attempt, result, labels)
                    return result
                await self._sleep_backoff(attempt)

            except asyncio.CancelledError:
                last_error = "cancelled"
                result = self._finish(
                    status=ExecutionStatus.CANCELLED,
                    started=started,
                    attempt=attempt,
                    retries=attempt - 1,
                    error="cancelled",
                )
                await self._finalize_failure(command, ctx, attempt, result, labels, cancelled=True)
                raise  # пробрасываем дальше для корректного shutdown

            except Exception as e:
                last_error = f"{type(e).__name__}: {e}"
                await self.metrics.inc_counter("executor_error_total", labels=labels)
                # Решение о ретрае
                if not self.retry.retry_on_failures or attempt >= self.retry.max_attempts:
                    result = self._finish(
                        status=ExecutionStatus.FAILED,
                        started=started,
                        attempt=attempt,
                        retries=attempt - 1,
                        error=last_error,
                    )
                    self.circuit_breaker.record_failure()
                    await self._finalize_failure(command, ctx, attempt, result, labels)
                    return result
                self.circuit_breaker.record_failure()
                await self._sleep_backoff(attempt)

            # попытка ретрая
            continue  # явное

        # unreachable
        result = self._finish(
            status=ExecutionStatus.FAILED,
            started=started,
            attempt=attempt,
            retries=attempt - 1,
            error=last_error or "unknown",
        )
        return result

    # --- Абстрактный метод исполнения конкретной логики ---
    @abc.abstractmethod
    async def _execute(self, command: Command, ctx: ExecutionContext) -> Optional[str]:
        """Выполнить команду и вернуть текстовый вывод (будет обрезан по max_output_bytes)."""
        raise NotImplementedError

    # --- Вспомогательные методы ---

    def _finish(
        self,
        *,
        status: ExecutionStatus,
        started: datetime,
        attempt: int,
        retries: int,
        output: Optional[str] = None,
        error: Optional[str] = None,
    ) -> ExecutionResult:
        finished = _now()
        return ExecutionResult(
            status=status,
            started_at=started,
            finished_at=finished,
            duration_seconds=(finished - started).total_seconds(),
            attempt=attempt,
            retries=retries,
            output=output,
            error=error,
        )

    async def _finalize_failure(
        self,
        command: Command,
        ctx: ExecutionContext,
        attempt: int,
        result: ExecutionResult,
        labels: Mapping[str, str],
        cancelled: bool = False,
    ) -> None:
        await self.metrics.observe_duration("executor_duration_seconds", result.duration_seconds, labels)
        await self.metrics.inc_counter("executor_failure_total", labels=labels)
        await self.audit.emit(
            {
                "type": "execution.failed" if not cancelled else "execution.cancelled",
                "request_id": str(ctx.request_id),
                "command": command.name,
                "attempt": attempt,
                "error": result.error,
                "finished_at": _utc_iso(result.finished_at),
            }
        )

    async def _sleep_backoff(self, attempt: int) -> None:
        delay = self.retry.backoff(attempt)
        await asyncio.sleep(delay)

    def _safe_params(self, params: Mapping[str, Any]) -> Dict[str, Any]:
        def mask(value: Any) -> Any:
            if isinstance(value, str):
                low = value.lower()
                if any(k in low for k in ("secret", "token", "password", "apikey")):
                    return "***"
            return value
        return {k: ("***" if k.lower() in self.redact_keys else mask(v)) for k, v in params.items()}

    def _truncate_output(self, out: Optional[Union[str, bytes]]) -> Optional[str]:
        if out is None:
            return None
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        if len(out.encode("utf-8")) <= self.max_output_bytes:
            return out
        # стараемся не разрезать на середине utf-8
        cut = self.max_output_bytes
        encoded = out.encode("utf-8")[:cut]
        return encoded.decode("utf-8", errors="ignore") + "\n...[truncated]"


# --------------------------- Конкретная реализация: ShellExecutor ---------------------------

class ShellExecutor(BaseExecutor):
    """
    Безопасный исполнитель shell-команд.
    Поддерживает env/dir, таймауты, возврат stdout/строгую обработку stderr.
    """

    async def _execute(self, command: Command, ctx: ExecutionContext) -> Optional[str]:
        args = command.params.get("args")
        if not args or not isinstance(args, (list, tuple)):
            raise ValueError("ShellExecutor requires params.args: List[str]")

        env: Dict[str, str] = dict(os.environ)
        extra_env: Mapping[str, str] = command.params.get("env") or {}
        for k, v in extra_env.items():
            env[str(k)] = str(v)

        cwd = command.params.get("cwd")
        check_rc: bool = bool(command.params.get("check_rc", True))
        merge_stderr: bool = bool(command.params.get("merge_stderr", True))
        stdin_data: Optional[Union[str, bytes]] = command.params.get("stdin")

        # Создаем процесс
        proc = await asyncio.create_subprocess_exec(
            *list(args),
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT if merge_stderr else asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )

        # Передаем stdin (если есть)
        if stdin_data is not None:
            if isinstance(stdin_data, str):
                stdin_data = stdin_data.encode("utf-8")
            assert proc.stdin is not None
            proc.stdin.write(stdin_data)
            await proc.stdin.drain()
            proc.stdin.close()

        # Читаем вывод
        stdout, stderr = await proc.communicate()
        rc = proc.returncode or 0

        # Собираем вывод
        out = stdout or b""
        if not merge_stderr and stderr:
            out = out + b"\n[stderr]\n" + stderr

        # Проверяем RC
        if check_rc and rc != 0:
            raise RuntimeError(f"non-zero exit code: {rc}\n{out.decode('utf-8', errors='replace')}")

        return out.decode("utf-8", errors="replace")


# --------------------------- Пример использования (комментарий) ---------------------------
"""
# Пример:
# executor = ShellExecutor(name="shell", redact_keys=["password"])
# ctx = ExecutionContext(timeout_seconds=30, audit_user="ci", audit_reason="build step")
# cmd = Command(
#     name="db_migrate",
#     params={"args": ["bash", "-lc", "echo ok && sleep 1"]},
#     idempotency_key="migrate:v2025.08.25",
#     lock_key="db:migrations",
#     annotations={"evidence_id": "EV-123"}
# )
# result = await executor.run(cmd, ctx)
# print(result.to_dict())
"""
