# omnimind-core/omnimind/tools/registry.py
from __future__ import annotations

import asyncio
import contextlib
import functools
import importlib
import json
import logging
import os
import threading
import time
import types
import uuid
from dataclasses import dataclass, field
from hashlib import sha256
from inspect import iscoroutinefunction, signature
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

# --- Опциональная Pydantic-валидация (не делаем жёсткую зависимость) -----------------
try:
    from pydantic import BaseModel as _PydBaseModel, ValidationError as _PydValidationError
except Exception:  # pragma: no cover
    _PydBaseModel = object  # тип-заглушка
    class _PydValidationError(Exception): ...
# -------------------------------------------------------------------------------------

LOG = logging.getLogger("omnimind.tools.registry")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO)

# ================================== Ошибки ===========================================

class ToolError(Exception): ...
class ToolValidationError(ToolError): ...
class ToolPermissionError(ToolError): ...
class ToolTimeoutError(ToolError): ...
class ToolRateLimitError(ToolError): ...
class ToolUnavailableError(ToolError): ...
class ToolAlreadyRegistered(ToolError): ...
class ToolNotFound(ToolError): ...
class ToolContractError(ToolError): ...

# ================================== Контекст ==========================================

@dataclass(slots=True)
class ExecutionContext:
    """Контекст вызова инструмента."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    principal_id: Optional[str] = None
    scopes: Set[str] = field(default_factory=set)
    trace_id: Optional[str] = None
    deadline_ts: Optional[float] = None  # epoch seconds
    feature_flags: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def remaining_timeout(self, fallback: Optional[float] = None) -> Optional[float]:
        if self.deadline_ts is None:
            return fallback
        return max(0.0, self.deadline_ts - time.time())

# ================================ Rate limiting =======================================

@dataclass(slots=True)
class TokenBucket:
    capacity: float
    refill_per_sec: float
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        dt = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + dt * self.refill_per_sec)
        self.last_refill = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

# ================================ Circuit breaker =====================================

class BreakerState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

@dataclass(slots=True)
class CircuitBreaker:
    fail_threshold: int = 5
    recovery_cooldown_s: float = 10.0
    half_open_max_calls: int = 2

    _state: str = BreakerState.CLOSED
    _fails: int = 0
    _open_until: float = 0.0
    _half_open_calls: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def before_call(self) -> None:
        with self._lock:
            if self._state == BreakerState.OPEN:
                if time.monotonic() < self._open_until:
                    raise ToolUnavailableError("circuit open")
                # переход в HALF_OPEN
                self._state = BreakerState.HALF_OPEN
                self._half_open_calls = 0
            if self._state == BreakerState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    raise ToolUnavailableError("circuit probing exhausted")
                self._half_open_calls += 1

    def record_success(self) -> None:
        with self._lock:
            self._fails = 0
            if self._state in (BreakerState.OPEN, BreakerState.HALF_OPEN):
                self._state = BreakerState.CLOSED
                self._half_open_calls = 0

    def record_failure(self) -> None:
        with self._lock:
            self._fails += 1
            if self._fails >= self.fail_threshold:
                self._state = BreakerState.OPEN
                self._open_until = time.monotonic() + self.recovery_cooldown_s

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

# =================================== TTL Cache ========================================

@dataclass(slots=True)
class TTLCache:
    ttl_s: float
    max_items: int = 1024
    _data: Dict[str, Tuple[float, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _gc(self) -> None:
        now = time.monotonic()
        if len(self._data) > self.max_items:
            # грубая очистка: выкидываем устаревшие и излишки по FIFO
            keys = list(self._data.keys())
            for k in keys[: len(self._data) // 4]:
                self._data.pop(k, None)
        for k, (exp, _) in list(self._data.items()):
            if exp < now:
                self._data.pop(k, None)

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            exp, value = item
            if exp < time.monotonic():
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._gc()
            self._data[key] = (time.monotonic() + self.ttl_s, value)

# ================================= Спецификация инструмента ============================

TIn = TypeVar("TIn")
TOut = TypeVar("TOut")

@dataclass(slots=True)
class RateLimitConf:
    capacity: int = 60
    refill_per_sec: float = 30.0
    per_principal: bool = True

@dataclass(slots=True)
class ToolSpec:
    name: str
    version: str = "1.0.0"
    description: str = ""
    input_model: Optional[Type[_PydBaseModel]] = None
    output_model: Optional[Type[_PydBaseModel]] = None
    required_scopes: Set[str] = field(default_factory=set)
    owner: str = "omnimind"
    tags: Set[str] = field(default_factory=set)
    timeout_s: Optional[float] = None
    rate_limit: Optional[RateLimitConf] = None
    cache_ttl_s: Optional[float] = None
    breaker: Optional[CircuitBreaker] = None
    deprecated: bool = False
    entrypoint: Optional[str] = None  # dotted path для ленивой загрузки
    # сам исполняемый callable
    func: Optional[Callable[..., Any]] = None

    def fq_name(self) -> str:
        return f"{self.name}@{self.version}"

@dataclass(slots=True)
class _RuntimeState:
    buckets: Dict[str, TokenBucket] = field(default_factory=dict)  # key -> bucket
    cache: Optional[TTLCache] = None
    metrics: Dict[str, float] = field(default_factory=lambda: {
        "calls_total": 0.0,
        "errors_total": 0.0,
        "timeout_total": 0.0,
        "duration_sum_ms": 0.0,
        "cache_hits": 0.0,
        "rate_limited": 0.0,
        "breaker_open": 0.0,
    })
    lock: threading.Lock = field(default_factory=threading.Lock)

# ================================ Реестр инструментов =================================

class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}           # fq_name -> spec
        self._state: Dict[str, _RuntimeState] = {}      # fq_name -> runtime
        self._lock = threading.RLock()

    # ---------------- API регистрации ----------------

    def register(self, spec: ToolSpec) -> None:
        fq = spec.fq_name()
        with self._lock:
            if fq in self._tools:
                raise ToolAlreadyRegistered(f"Already registered: {fq}")
            if spec.input_model is not None and not issubclass(spec.input_model, _PydBaseModel):
                raise ToolContractError("input_model must subclass pydantic.BaseModel (if provided)")
            if spec.output_model is not None and not issubclass(spec.output_model, _PydBaseModel):
                raise ToolContractError("output_model must subclass pydantic.BaseModel (if provided)")
            if spec.entrypoint and spec.func:
                raise ToolContractError("Provide either entrypoint or func, not both")
            self._tools[fq] = spec
            st = _RuntimeState()
            if spec.cache_ttl_s and spec.cache_ttl_s > 0:
                st.cache = TTLCache(ttl_s=spec.cache_ttl_s)
            self._state[fq] = st
            LOG.info("Registered tool %s", fq)

    def deregister(self, name: str, version: str) -> None:
        fq = f"{name}@{version}"
        with self._lock:
            self._tools.pop(fq, None)
            self._state.pop(fq, None)

    def list_tools(self) -> List[Dict[str, Any]]:
        with self._lock:
            out = []
            for spec in self._tools.values():
                st = self._state.get(spec.fq_name())
                m = dict(st.metrics) if st else {}
                out.append({
                    "name": spec.name,
                    "version": spec.version,
                    "description": spec.description,
                    "required_scopes": sorted(spec.required_scopes),
                    "tags": sorted(spec.tags),
                    "timeout_s": spec.timeout_s,
                    "cache_ttl_s": spec.cache_ttl_s,
                    "rate_limit": vars(spec.rate_limit) if spec.rate_limit else None,
                    "breaker_state": spec.breaker.state if spec.breaker else None,
                    "metrics": m,
                    "deprecated": spec.deprecated,
                })
            return sorted(out, key=lambda x: (x["name"], x["version"]))

    # ---------------- Вызовы ----------------

    async def call(
        self,
        name: str,
        payload: Any,
        *,
        version: Optional[str] = None,
        context: Optional[ExecutionContext] = None,
        timeout_s: Optional[float] = None,
    ) -> Any:
        """
        Асинхронный вызов инструмента.
        """
        spec = self._resolve_spec(name, version)
        ctx = context or ExecutionContext()
        fn = self._resolve_callable(spec)

        # Pydantic валидация входа
        if spec.input_model is not None:
            try:
                payload = spec.input_model.model_validate(payload)  # type: ignore[attr-defined]
            except Exception as e:  # pydantic v1/v2 совместимость
                raise ToolValidationError(str(e)) from e

        # Разрешения
        if spec.required_scopes and not spec.required_scopes.issubset(ctx.scopes):
            raise ToolPermissionError("insufficient scopes")

        # Rate limit
        st = self._state[spec.fq_name()]
        rl_key = self._rate_key(spec, ctx)
        if spec.rate_limit:
            bucket = st.buckets.get(rl_key)
            if bucket is None:
                bucket = TokenBucket(
                    capacity=float(spec.rate_limit.capacity),
                    refill_per_sec=spec.rate_limit.refill_per_sec,
                )
                st.buckets[rl_key] = bucket
            if not bucket.allow():
                with st.lock:
                    st.metrics["rate_limited"] += 1
                raise ToolRateLimitError("rate limited")

        # Кэш
        cache_key = None
        if st.cache:
            cache_key = self._cache_key(spec, payload, ctx)
            cached = st.cache.get(cache_key)
            if cached is not None:
                with st.lock:
                    st.metrics["cache_hits"] += 1
                return cached

        # Circuit breaker
        if spec.breaker:
            try:
                spec.breaker.before_call()
            except ToolUnavailableError:
                with st.lock:
                    st.metrics["breaker_open"] += 1
                raise

        # Таймаут
        eff_timeout = timeout_s or spec.timeout_s
        if ctx.deadline_ts is not None:
            rem = ctx.remaining_timeout(None)
            if rem is not None:
                eff_timeout = min(eff_timeout, rem) if eff_timeout else rem

        started = time.perf_counter()
        with st.lock:
            st.metrics["calls_total"] += 1

        try:
            # Вызов (поддержка sync/async)
            if iscoroutinefunction(fn):
                coro = fn(payload, ctx)  # type: ignore[misc]
            else:
                # безопасно выполняем sync в пуле
                coro = asyncio.to_thread(fn, payload, ctx)  # type: ignore[misc]

            if eff_timeout and eff_timeout > 0:
                result = await asyncio.wait_for(coro, timeout=eff_timeout)
            else:
                result = await coro

            # Валидация выхода
            if spec.output_model is not None:
                try:
                    result = spec.output_model.model_validate(result)  # type: ignore[attr-defined]
                except Exception as e:
                    raise ToolContractError(f"invalid output: {e}") from e

            # Кэшируем
            if st.cache and cache_key is not None:
                st.cache.set(cache_key, result)

            if spec.breaker:
                spec.breaker.record_success()

            return result

        except asyncio.TimeoutError as e:
            with st.lock:
                st.metrics["timeout_total"] += 1
                st.metrics["errors_total"] += 1
            if spec.breaker:
                spec.breaker.record_failure()
            raise ToolTimeoutError("timeout") from e
        except Exception as e:
            with st.lock:
                st.metrics["errors_total"] += 1
            if spec.breaker:
                spec.breaker.record_failure()
            raise
        finally:
            took_ms = (time.perf_counter() - started) * 1000.0
            with st.lock:
                st.metrics["duration_sum_ms"] += took_ms

    def call_sync(
        self,
        name: str,
        payload: Any,
        *,
        version: Optional[str] = None,
        context: Optional[ExecutionContext] = None,
        timeout_s: Optional[float] = None,
    ) -> Any:
        """Синхронная обёртка над async call (для CLI/скриптов)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            # если уже в event loop — запускаем как таск
            return asyncio.run_coroutine_threadsafe(
                self.call(name, payload, version=version, context=context, timeout_s=timeout_s),
                loop,
            ).result()
        return asyncio.run(self.call(name, payload, version=version, context=context, timeout_s=timeout_s))

    # ---------------- Регистрация через декоратор ----------------

    def register_decorator(
        self,
        *,
        name: str,
        version: str = "1.0.0",
        description: str = "",
        input_model: Optional[Type[_PydBaseModel]] = None,
        output_model: Optional[Type[_PydBaseModel]] = None,
        required_scopes: Optional[Iterable[str]] = None,
        owner: str = "omnimind",
        tags: Optional[Iterable[str]] = None,
        timeout_s: Optional[float] = None,
        rate_limit: Optional[RateLimitConf] = None,
        cache_ttl_s: Optional[float] = None,
        breaker: Optional[CircuitBreaker] = None,
        deprecated: bool = False,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Декоратор: @tools.register(...).
        Поддерживает функции вида:
            async def tool(payload, context: ExecutionContext) -> Any
            def tool(payload, context: ExecutionContext) -> Any
        """
        def _wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
            # проверяем сигнатуру
            sig = signature(fn)
            if len(sig.parameters) < 1:
                raise ToolContractError("tool must accept at least `payload` parameter")
            spec = ToolSpec(
                name=name,
                version=version,
                description=description,
                input_model=input_model,
                output_model=output_model,
                required_scopes=set(required_scopes or []),
                owner=owner,
                tags=set(tags or []),
                timeout_s=timeout_s,
                rate_limit=rate_limit,
                cache_ttl_s=cache_ttl_s,
                breaker=breaker,
                deprecated=deprecated,
                func=fn,
            )
            self.register(spec)
            return fn
        return _wrap

    # ---------------- Загрузка/поиск ----------------

    def discover(self, package: str) -> int:
        """
        Ленивая загрузка модулей Python-пакета (импорт side-effect'ом выполнит декораторы).
        Возвращает число зарегистрированных инструментов после discover.
        """
        before = len(self._tools)
        module = importlib.import_module(package)
        pkg_path = getattr(module, "__path__", None)
        if not pkg_path:
            return len(self._tools)
        import pkgutil
        for mod in pkgutil.walk_packages(pkg_path, prefix=module.__name__ + "."):
            try:
                importlib.import_module(mod.name)
            except Exception as e:  # не срываем discover из-за одного модуля
                LOG.warning("Failed to import %s: %s", mod.name, e)
        return len(self._tools) - before

    # ---------------- Внутренние утилиты ----------------

    def _resolve_spec(self, name: str, version: Optional[str]) -> ToolSpec:
        with self._lock:
            if version:
                fq = f"{name}@{version}"
                spec = self._tools.get(fq)
                if not spec:
                    raise ToolNotFound(f"not found: {fq}")
                return spec
            # если версия не указана — берём максимальную по строковому сравнению семверс-видов
            candidates = [s for s in self._tools.values() if s.name == name]
            if not candidates:
                raise ToolNotFound(f"not found: {name}")
            # простая эвристика сортировки версий (MAJOR.MINOR.PATCH численно)
            def _semkey(v: str) -> Tuple[int, int, int]:
                parts = (v.split("+")[0].split("-")[0]).split(".")
                nums = [int(p) if p.isdigit() else 0 for p in parts[:3]]
                nums += [0] * (3 - len(nums))
                return tuple(nums)  # type: ignore[return-value]
            spec = sorted(candidates, key=lambda s: _semkey(s.version), reverse=True)[0]
            return spec

    def _resolve_callable(self, spec: ToolSpec) -> Callable[..., Any]:
        if spec.func:
            return spec.func
        if not spec.entrypoint:
            raise ToolContractError(f"tool {spec.fq_name()} has no callable or entrypoint")
        mod_path, attr = spec.entrypoint.rsplit(".", 1)
        fn = getattr(importlib.import_module(mod_path), attr)
        if not callable(fn):
            raise ToolContractError(f"entrypoint {spec.entrypoint} is not callable")
        spec.func = fn
        return fn

    def _rate_key(self, spec: ToolSpec, ctx: ExecutionContext) -> str:
        if spec.rate_limit and spec.rate_limit.per_principal and ctx.principal_id:
            return f"{spec.fq_name()}|{ctx.principal_id}"
        return f"{spec.fq_name()}|_global"

    def _cache_key(self, spec: ToolSpec, payload: Any, ctx: ExecutionContext) -> str:
        try:
            if hasattr(payload, "model_dump_json"):  # pydantic v2
                raw = payload.model_dump_json()  # type: ignore[attr-defined]
            elif hasattr(payload, "json"):  # pydantic v1
                raw = payload.json()  # type: ignore[attr-defined]
            else:
                raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        except Exception:
            raw = str(payload)
        salt = ctx.principal_id or "-"
        base = f"{spec.fq_name()}|{salt}|{raw}"
        return sha256(base.encode("utf-8")).hexdigest()

# ============================== Экземпляр и удобные шорткаты ===========================

tools = ToolRegistry()

# Удобный декоратор: @tools.register(...)
register = tools.register_decorator

# ============================== Пример контракта (типы) ===============================
# Эти классы не обязательны к импорту, показаны как референс. Оставляем для удобства.

if isinstance(_PydBaseModel, type):
    class ExampleIn(_PydBaseModel):  # type: ignore[misc]
        text: str

    class ExampleOut(_PydBaseModel):  # type: ignore[misc]
        length: int

    # Пример регистрации:
    # @register(
    #     name="text.length",
    #     version="1.0.0",
    #     description="Подсчёт длины текста",
    #     input_model=ExampleIn,
    #     output_model=ExampleOut,
    #     timeout_s=1.0,
    #     rate_limit=RateLimitConf(capacity=30, refill_per_sec=15.0),
    #     cache_ttl_s=5.0,
    #     breaker=CircuitBreaker(fail_threshold=3, recovery_cooldown_s=5.0),
    # )
    # def calc_len(payload: ExampleIn, ctx: ExecutionContext) -> ExampleOut:
    #     return ExampleOut(length=len(payload.text))
