# omnimind-core/omnimind/executor/tool_invoker.py
# Industrial-grade tool invocation layer for Omnimind.
# Copyright (c) 2025.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, Generic, Iterable, Optional, Protocol, Tuple, Type, TypeVar, Union
from uuid import UUID, uuid4

try:
    # Optional: OpenTelemetry tracing if available
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer("omnimind.executor.tool_invoker")
except Exception:  # pragma: no cover
    _TRACER = None  # type: ignore

try:
    # Optional: Prometheus metrics if available
    from prometheus_client import Counter, Histogram  # type: ignore

    _METRICS_ENABLED = True
    _TOOL_CALLS = Counter(
        "omnimind_tool_calls_total",
        "Total tool calls",
        ["tool", "status"],
    )
    _TOOL_LATENCY = Histogram(
        "omnimind_tool_latency_seconds",
        "Tool call latency in seconds",
        ["tool"],
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60),
    )
except Exception:  # pragma: no cover
    _METRICS_ENABLED = False
    _TOOL_CALLS = None  # type: ignore
    _TOOL_LATENCY = None  # type: ignore

from pydantic import BaseModel, Field, ValidationError, ConfigDict

logger = logging.getLogger("omnimind.executor.tool_invoker")


# ==========================
# Errors
# ==========================

class ToolError(Exception):
    """Base tool invocation error."""


class ToolNotFound(ToolError):
    pass


class ToolValidationError(ToolError):
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.details = details or {}


class ToolTimeout(ToolError):
    pass


class ToolRateLimited(ToolError):
    pass


class ToolCircuitOpen(ToolError):
    pass


class ToolConcurrencyExceeded(ToolError):
    pass


class ToolIdempotentReplay(ToolError):
    """Raised internally to signal replay (returned cached result)."""
    pass


# ==========================
# DTO & Context
# ==========================

class ToolInvocationContext(BaseModel):
    """
    Контекст вызова инструмента: трассировка, идентичность, метаданные, дедлайн.
    """
    model_config = ConfigDict(extra="ignore")

    request_id: Optional[str] = Field(default=None)
    user_id: Optional[str] = Field(default=None)
    tenant_id: Optional[str] = Field(default=None)
    scopes: set[str] = Field(default_factory=set)
    idempotency_key: Optional[str] = Field(default=None, description="Идентификатор идемпотентного запроса")
    deadline_utc: Optional[datetime] = Field(default=None, description="Жёсткий дедлайн UTC")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def remaining_timeout(self, fallback_seconds: float | None) -> Optional[float]:
        if self.deadline_utc is None:
            return fallback_seconds
        # вычисляем оставшееся время
        remaining = (self.deadline_utc - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            return 0.0
        if fallback_seconds is None:
            return remaining
        return min(remaining, float(fallback_seconds))


class ToolResult(BaseModel):
    """
    Результат вызова инструмента.
    """
    model_config = ConfigDict(extra="ignore")

    tool: str
    request_id: Optional[str]
    invocation_id: str
    success: bool
    output: Any = None
    error: Optional[Dict[str, Any]] = None
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    retries: int = 0
    idempotent: bool = False
    # Полезные метрики (например, количество токенов у LLM-инструмента)
    metrics: Dict[str, Any] = Field(default_factory=dict)


# ==========================
# Secrets redaction
# ==========================

_SECRET_PATTERNS = [
    re.compile(r"(?:apikey|api_key|secret|token|password|pwd)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})", re.IGNORECASE),
    re.compile(r"(?:Bearer\s+)([A-Za-z0-9\-\._~\+\/]+=*)", re.IGNORECASE),
]

def redact_secrets(text: str) -> str:
    def repl(match: re.Match) -> str:
        full = match.group(0)
        secret = match.group(1)
        if len(secret) <= 6:
            masked = "***"
        else:
            masked = secret[:2] + "***" + secret[-2:]
        return full.replace(secret, masked)
    try:
        for pat in _SECRET_PATTERNS:
            text = pat.sub(repl, text)
    except Exception:
        pass
    return text


# ==========================
# Tool interface
# ==========================

P = TypeVar("P", bound=BaseModel)
R = TypeVar("R")

class Tool(ABC, Generic[P, R]):
    """
    Абстракция инструмента с типизированными параметрами (Pydantic) и возвращаемым значением.
    """

    name: str
    description: str
    params_model: Type[P]
    # Ограничения по умолчанию
    default_timeout_s: float = 30.0
    max_concurrency: int = 8
    rate_limit_per_minute: int = 120  # локальный rate-limit по-умолчанию
    scope: Optional[str] = None  # требуемая scope (если применимо)

    def __init__(self) -> None:
        if not hasattr(self, "name"):
            self.name = self.__class__.__name__
        if not hasattr(self, "description"):
            self.description = self.__class__.__doc__ or self.name

    @abstractmethod
    async def __call__(self, params: P, ctx: ToolInvocationContext) -> R:
        """
        Реализация инструмента (async).
        Реализуйте в наследнике. Синхронные операции выносите в asyncio.to_thread.
        """
        raise NotImplementedError

    def json_schema(self) -> Dict[str, Any]:
        """
        JSON Schema параметров для LLM (OpenAI/Anthropic function calling совместимо).
        """
        return self.params_model.model_json_schema()

    async def validate_permissions(self, ctx: ToolInvocationContext) -> None:
        """
        Базовая проверка прав доступа по scope.
        Переопределите для кастомной логики.
        """
        if self.scope and self.scope not in ctx.scopes:
            raise ToolError(f"Insufficient scope: required '{self.scope}'")


# ==========================
# Rate limiter (token bucket, in-memory)
# ==========================

@dataclass
class _Bucket:
    capacity: int
    tokens: float
    refill_rate_per_sec: float
    last_refill: float


class _RateLimiter:
    def __init__(self) -> None:
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str, rpm: int) -> bool:
        now = time.monotonic()
        async with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(capacity=rpm, tokens=float(rpm), refill_rate_per_sec=rpm / 60.0, last_refill=now)
                self._buckets[key] = bucket
            # refill
            elapsed = now - bucket.last_refill
            bucket.tokens = min(bucket.capacity, bucket.tokens + elapsed * bucket.refill_rate_per_sec)
            bucket.last_refill = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True
            return False


# ==========================
# Circuit breaker (simple half-open)
# ==========================

@dataclass
class _BreakerState:
    failures: int
    opened_at: Optional[float]
    cooldown_sec: float
    threshold: int


class _CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown_sec: float = 10.0) -> None:
        self._state: Dict[str, _BreakerState] = {}
        self._lock = asyncio.Lock()
        self._threshold = threshold
        self._cooldown = cooldown_sec

    async def on_before_call(self, key: str) -> None:
        async with self._lock:
            st = self._state.get(key)
            if not st:
                return
            if st.opened_at is None:
                return
            # check cooldown
            if time.monotonic() - st.opened_at < st.cooldown_sec:
                raise ToolCircuitOpen(f"Circuit open for '{key}'")
            # half-open: allow one call by resetting opened_at to None but keeping failures
            st.opened_at = None

    async def on_success(self, key: str) -> None:
        async with self._lock:
            self._state[key] = _BreakerState(failures=0, opened_at=None, cooldown_sec=self._cooldown, threshold=self._threshold)

    async def on_failure(self, key: str) -> None:
        async with self._lock:
            st = self._state.get(key)
            if not st:
                st = _BreakerState(failures=0, opened_at=None, cooldown_sec=self._cooldown, threshold=self._threshold)
            st.failures += 1
            if st.failures >= st.threshold and st.opened_at is None:
                st.opened_at = time.monotonic()
            self._state[key] = st


# ==========================
# Idempotency cache (in-memory default)
# ==========================

class IdempotencyCache(Protocol):
    async def get(self, key: str) -> Optional[ToolResult]: ...
    async def set(self, key: str, value: ToolResult, ttl_sec: int = 3600) -> None: ...


class _InMemoryIdemCache(IdempotencyCache):
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[ToolResult, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[ToolResult]:
        async with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            result, exp = item
            if time.monotonic() > exp:
                self._data.pop(key, None)
                return None
            return result

    async def set(self, key: str, value: ToolResult, ttl_sec: int = 3600) -> None:
        async with self._lock:
            self._data[key] = (value, time.monotonic() + max(1, ttl_sec))


# ==========================
# Tool registry & invoker
# ==========================

@dataclass
class _ToolEntry:
    tool: Tool[Any, Any]
    sem: asyncio.Semaphore  # concurrency guard


class ToolInvoker:
    """
    Регистрирует инструменты и безопасно их исполняет: валидация, таймауты, лимиты, брейкер, идемпотентность.
    """

    def __init__(
        self,
        *,
        idempotency_cache: Optional[IdempotencyCache] = None,
        rate_limiter: Optional[_RateLimiter] = None,
        circuit_breaker: Optional[_CircuitBreaker] = None,
        default_timeout_s: float = 30.0,
        idempotency_ttl_sec: int = 3600,
    ) -> None:
        self._tools: Dict[str, _ToolEntry] = {}
        self._rate = rate_limiter or _RateLimiter()
        self._breaker = circuit_breaker or _CircuitBreaker()
        self._default_timeout_s = float(default_timeout_s)
        self._idem = idempotency_cache or _InMemoryIdemCache()
        self._idem_ttl = idempotency_ttl_sec

    # -------- Registry --------

    def register(self, tool: Tool[Any, Any], *, alias: Optional[str] = None) -> None:
        name = (alias or tool.name).strip()
        if not name:
            raise ValueError("Tool name must be non-empty")
        if name in self._tools:
            raise ValueError(f"Tool '{name}' already registered")
        self._tools[name] = _ToolEntry(tool=tool, sem=asyncio.Semaphore(max(1, tool.max_concurrency)))
        logger.info("Registered tool '%s' (scope=%s, rpm=%s, concurrency=%s)", name, tool.scope, tool.rate_limit_per_minute, tool.max_concurrency)

    def registered(self) -> Dict[str, Dict[str, Any]]:
        """
        Короткая сводка по зарегистрированным инструментам (для /introspect).
        """
        out: Dict[str, Dict[str, Any]] = {}
        for name, entry in self._tools.items():
            t = entry.tool
            out[name] = {
                "description": t.description,
                "scope": t.scope,
                "rate_limit_per_minute": t.rate_limit_per_minute,
                "max_concurrency": t.max_concurrency,
                "json_schema": t.json_schema(),
            }
        return out

    # -------- Invocation --------

    async def invoke(
        self,
        tool_name: str,
        *,
        args: Union[str, Dict[str, Any], None],
        ctx: ToolInvocationContext,
        timeout_s: Optional[float] = None,
        retries: int = 0,
        retry_backoff_base_s: float = 0.2,
    ) -> ToolResult:
        """
        Вызвать инструмент по имени с параметрами (dict или JSON).
        Гарантирует:
          - валидацию параметров
          - таймаут (учитывает ctx.deadline_utc)
          - rate limit (per-tool+tenant+user)
          - ограничение конкурентности
          - circuit breaker
          - идемпотентность (если ctx.idempotency_key указан)
        """
        entry = self._tools.get(tool_name)
        if not entry:
            raise ToolNotFound(f"Tool '{tool_name}' is not registered")

        tool = entry.tool
        invocation_id = uuid4().hex
        started_at = datetime.now(timezone.utc)

        # idempotency check
        idem_key_full = None
        if ctx.idempotency_key:
            idem_key_full = f"{tool_name}:{ctx.tenant_id}:{ctx.user_id}:{ctx.idempotency_key}"
            cached = await self._idem.get(idem_key_full)
            if cached:
                # Обновляем маркер идемпотентности и возвращаем
                cached.idempotent = True
                return cached

        # validate args
        payload_raw = self._parse_args(args)
        try:
            params = tool.params_model.model_validate(payload_raw)
        except ValidationError as ve:
            raise ToolValidationError("Invalid tool parameters", details=json.loads(ve.json()))

        # permissions
        await tool.validate_permissions(ctx)

        # Rate limit
        rl_key = f"{tool_name}:{ctx.tenant_id}:{ctx.user_id}"
        if not await self._rate.allow(rl_key, max(1, tool.rate_limit_per_minute)):
            raise ToolRateLimited(f"Rate limit exceeded for '{tool_name}'")

        # Circuit breaker (pre-call)
        await self._breaker.on_before_call(tool_name)

        timeout_eff = ctx.remaining_timeout(timeout_s if timeout_s is not None else tool.default_timeout_s)
        if timeout_eff is None:
            timeout_eff = self._default_timeout_s

        # Concurrency guard
        if entry.sem.locked() and entry.sem._value <= 0:  # type: ignore[attr-defined]
            # Быстрый сигнал о переполнении (не ждём)
            raise ToolConcurrencyExceeded(f"Concurrency limit exceeded for '{tool_name}'")

        # Actual call with retries
        attempt = 0
        last_exc: Optional[Exception] = None
        while True:
            attempt += 1
            try:
                result = await self._invoke_once(
                    entry=entry,
                    tool=tool,
                    params=params,
                    ctx=ctx,
                    timeout_s=timeout_eff,
                )
                finished_at = datetime.now(timezone.utc)
                res = ToolResult(
                    tool=tool_name,
                    request_id=ctx.request_id,
                    invocation_id=invocation_id,
                    success=True,
                    output=result,
                    error=None,
                    started_at=started_at,
                    finished_at=finished_at,
                    duration_ms=int((finished_at - started_at).total_seconds() * 1000),
                    retries=attempt - 1,
                )
                # Metrics & breaker
                await self._breaker.on_success(tool_name)
                if _METRICS_ENABLED:
                    _TOOL_CALLS.labels(tool=tool_name, status="success").inc()
                    _TOOL_LATENCY.labels(tool=tool_name).observe(res.duration_ms / 1000.0)
                # Idempotency store
                if idem_key_full:
                    await self._idem.set(idem_key_full, res, ttl_sec=self._idem_ttl)
                return res
            except asyncio.TimeoutError as e:
                last_exc = ToolTimeout(f"Tool '{tool_name}' timed out after {timeout_eff:.2f}s")
            except ToolRateLimited as e:
                # не имеет смысла ретраить мгновенно — пробрасываем
                last_exc = e
            except ToolValidationError as e:
                last_exc = e
            except Exception as e:
                last_exc = e

            # Failure path
            await self._breaker.on_failure(tool_name)
            if _METRICS_ENABLED:
                _TOOL_CALLS.labels(tool=tool_name, status="failure").inc()

            if attempt > max(0, retries):
                finished_at = datetime.now(timezone.utc)
                err_payload = {
                    "type": last_exc.__class__.__name__,
                    "message": redact_secrets(str(last_exc)),
                }
                res = ToolResult(
                    tool=tool_name,
                    request_id=ctx.request_id,
                    invocation_id=invocation_id,
                    success=False,
                    output=None,
                    error=err_payload,
                    started_at=started_at,
                    finished_at=finished_at,
                    duration_ms=int((finished_at - started_at).total_seconds() * 1000),
                    retries=attempt - 1,
                )
                return res

            # Backoff
            await asyncio.sleep(retry_backoff_base_s * (2 ** (attempt - 1)))

    async def _invoke_once(
        self,
        *,
        entry: _ToolEntry,
        tool: Tool[Any, Any],
        params: BaseModel,
        ctx: ToolInvocationContext,
        timeout_s: float,
    ) -> Any:
        """
        Один вызов (без ретраев): честный таймаут, семафор, трейсинг.
        """
        # Acquire concurrency
        if not entry.sem.locked():
            # best-effort: try_acquire (не блокируем бесконечно)
            acquired = await entry.sem.acquire()
            if not acquired:  # pragma: no cover
                raise ToolConcurrencyExceeded(f"Concurrency limit exceeded for '{tool.name}'")
        else:
            # Семафор уже кем-то удерживается — ожидаем до таймаута
            try:
                await asyncio.wait_for(entry.sem.acquire(), timeout=timeout_s)
            except asyncio.TimeoutError:
                raise ToolConcurrencyExceeded(f"Concurrency wait timed out for '{tool.name}'")

        try:
            # Tracing span
            if _TRACER:
                with _TRACER.start_as_current_span(f"tool.{tool.name}") as sp:  # type: ignore
                    if ctx.request_id:
                        sp.set_attribute("request.id", ctx.request_id)  # type: ignore
                    if ctx.user_id:
                        sp.set_attribute("user.id", ctx.user_id)  # type: ignore
                    sp.set_attribute("tool.name", tool.name)  # type: ignore
                    sp.set_attribute("tool.scope", tool.scope or "")  # type: ignore
                    # Run with timeout
                    return await asyncio.wait_for(tool(params, ctx), timeout=timeout_s)
            # No tracer
            return await asyncio.wait_for(tool(params, ctx), timeout=timeout_s)
        finally:
            try:
                entry.sem.release()
            except ValueError:
                # double release guard
                pass

    @staticmethod
    def _parse_args(args: Union[str, Dict[str, Any], None]) -> Dict[str, Any]:
        if args is None:
            return {}
        if isinstance(args, dict):
            return args
        if isinstance(args, str):
            args = args.strip()
            if not args:
                return {}
            try:
                return json.loads(args)
            except json.JSONDecodeError as e:
                # допускаем "key=value" с минимальным парсером для дружелюбия (опционально)
                raise ToolValidationError(f"Arguments must be JSON object: {e}")
        raise ToolValidationError("Unsupported argument type")

    # -------- Helper for LLM tool calls --------

    async def invoke_from_llm_call(
        self,
        tool_call: Dict[str, Any],
        ctx: ToolInvocationContext,
        *,
        retries: int = 0,
    ) -> ToolResult:
        """
        Унифицированный вызов из ответа LLM (OpenAI/Anthropic совместимый):
        ожидается словарь вида {"name": "...", "arguments": "{...json...}"}.
        """
        name = str(tool_call.get("name", "")).strip()
        if not name:
            raise ToolValidationError("LLM tool call missing 'name'")
        arguments = tool_call.get("arguments", {})
        return await self.invoke(name, args=arguments, ctx=ctx, retries=retries)


# ==========================
# Example: Echo tool (sample)
# ==========================

class EchoParams(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000, description="Сообщение для эхо-ответа")
    uppercase: bool = Field(default=False, description="Вернуть в верхнем регистре")


class EchoTool(Tool[EchoParams, Dict[str, Any]]):
    """
    Демонстрационный инструмент, безопасный для smoke-тестов.
    """
    name = "echo"
    description = "Return the same message back. Useful for testing the tool pipeline."
    params_model = EchoParams
    scope = None
    max_concurrency = 32
    rate_limit_per_minute = 600
    default_timeout_s = 2.0

    async def __call__(self, params: EchoParams, ctx: ToolInvocationContext) -> Dict[str, Any]:
        text = params.message.upper() if params.uppercase else params.message
        await asyncio.sleep(0)  # cooperative yield
        return {
            "echo": text,
            "request_id": ctx.request_id,
            "user_id": ctx.user_id,
        }


# ==========================
# Bootstrap helper
# ==========================

def build_default_invoker() -> ToolInvoker:
    """
    Создает инвокер и регистрирует базовые инструменты (минимально — echo).
    Подмените/расширьте регистрацию под свои нужды.
    """
    inv = ToolInvoker()
    inv.register(EchoTool())
    return inv


# ==========================
# Minimal self-test (optional)
# ==========================

async def _selftest() -> None:  # pragma: no cover
    inv = build_default_invoker()
    ctx = ToolInvocationContext(request_id="req-1", user_id="u1", tenant_id="t1", scopes=set(), idempotency_key="abc")
    res = await inv.invoke("echo", args={"message": "hello", "uppercase": True}, ctx=ctx)
    assert res.success and res.output["echo"] == "HELLO"
    # Idempotent replay
    res2 = await inv.invoke("echo", args='{"message":"hello","uppercase":true}', ctx=ctx)
    assert res2.idempotent is True

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_selftest())
