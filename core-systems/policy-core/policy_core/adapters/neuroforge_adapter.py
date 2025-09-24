# policy-core/policy_core/adapters/neuroforge_adapter.py
# -*- coding: utf-8 -*-
"""
NeuroForge Adapter for Policy-Core

Назначение:
- Асинхронная интеграция Policy-Core с сервисом NeuroForge (оценка риска, рекомендации, обязательства).
- Минимальная зависимость от транспорта: HTTP-транспорт по умолчанию, возможность подключить gRPC.
- Производственный уровень: TTL-кэш, circuit breaker, retry с экспоненциальным бэкоффом,
  метрики Prometheus, OpenTelemetry, структурный аудит, многоарендность (tenant-aware).

API высокого уровня:
  adapter = NeuroForgeAdapter(...)
  await adapter.start()
  assessment = await adapter.assess(AssessmentInput(...))
  await adapter.notify_decision(DecisionEvent(...))
  await adapter.stop()

Пример эндпоинтов (по умолчанию, переопределяемые конфигом):
  POST {base_url}/v1/neuroforge/assess
  POST {base_url}/v1/neuroforge/events

Зависимости (опционально):
    pip install aiohttp prometheus-client opentelemetry-sdk pydantic
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

try:
    import aiohttp
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore

try:
    from pydantic import BaseModel, Field, validator, ValidationError
except Exception:  # pragma: no cover
    BaseModel = object  # type: ignore
    Field = lambda *args, **kwargs: None  # type: ignore
    def validator(*args, **kwargs):  # type: ignore
        def wrap(fn): return fn
        return wrap
    ValidationError = Exception  # type: ignore

try:
    from prometheus_client import Counter, Histogram, Gauge
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = None  # type: ignore

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
except Exception:  # pragma: no cover
    trace = None
    Status = None
    StatusCode = None

logger = logging.getLogger("policy_core.adapters.neuroforge")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s neuroforge %(message)s"))
    logger.addHandler(_h)
logger.setLevel(os.getenv("POLICY_CORE_LOG_LEVEL", "INFO").upper())


# ========================= Метрики =========================
if Counter and Histogram and Gauge:
    NF_REQ = Counter(
        "policy_neuroforge_requests_total",
        "NeuroForge requests total",
        ["endpoint", "result"]
    )
    NF_LAT = Histogram(
        "policy_neuroforge_request_seconds",
        "Latency of NeuroForge requests",
        ["endpoint"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5)
    )
    NF_CB_STATE = Gauge(
        "policy_neuroforge_circuit_state",
        "Circuit breaker state (0=closed, 1=open)",
        ["endpoint"]
    )
    NF_CACHE_HIT = Counter(
        "policy_neuroforge_cache_hits_total",
        "TTL cache hits",
        ["endpoint"]
    )
    NF_CACHE_MISS = Counter(
        "policy_neuroforge_cache_miss_total",
        "TTL cache misses",
        ["endpoint"]
    )
else:  # pragma: no cover
    NF_REQ = NF_LAT = NF_CB_STATE = NF_CACHE_HIT = NF_CACHE_MISS = None  # type: ignore


# ========================= Утилиты =========================
class _TTLCache:
    def __init__(self, ttl: float = 1.0, maxsize: int = 5000):
        self.ttl = ttl
        self.maxsize = maxsize
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            item = self._data.get(key)
            now = time.monotonic()
            if not item:
                return None
            ts, val = item
            if now - ts > self.ttl:
                self._data.pop(key, None)
                return None
            return val

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            if len(self._data) >= self.maxsize:
                # простое высвобождение: удаляем случайный/первый элемент
                self._data.pop(next(iter(self._data)), None)
            self._data[key] = (time.monotonic(), value)


class _CircuitBreaker:
    def __init__(self, fail_threshold: int = 5, reset_timeout: float = 5.0):
        self.fail_threshold = fail_threshold
        self.reset_timeout = reset_timeout
        self._fails = 0
        self._opened_at = 0.0

    @property
    def is_open(self) -> bool:
        if self._opened_at == 0.0:
            return False
        if (time.monotonic() - self._opened_at) >= self.reset_timeout:
            # half-open
            self._opened_at = 0.0
            self._fails = 0
            return False
        return True

    def ok(self) -> None:
        self._fails = 0
        self._opened_at = 0.0

    def fail(self) -> None:
        self._fails += 1
        if self._fails >= self.fail_threshold:
            self._opened_at = time.monotonic()


def _otel_span(name: str):
    if trace:
        return trace.get_tracer("policy_core.adapters.neuroforge").start_as_current_span(name)
    @contextlib.contextmanager
    def _null():
        yield None
    return _null()


@contextlib.contextmanager
def _prom_timer(hist: Optional[Histogram], endpoint: str):
    start = time.perf_counter()
    try:
        yield
    finally:
        if hist:
            hist.labels(endpoint=endpoint).observe(time.perf_counter() - start)


def _hashable(obj: Any) -> str:
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return str(obj)


# ========================= Схемы I/O =========================
class SubjectModel(BaseModel):
    id: str = Field(default="")
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    tls_subject: str = Field(default="")


class ResourceModel(BaseModel):
    type: str = Field(default="unknown")
    extras: Dict[str, Any] = Field(default_factory=dict)


class RpcModel(BaseModel):
    full_method: str
    service: str
    method: str


class ContextModel(BaseModel):
    peer_ip: str = Field(default="")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    correlation_id: str = Field(default="")


class AssessmentInput(BaseModel):
    tenant: str = Field(default="default")
    rpc: RpcModel
    subject: SubjectModel
    resource: ResourceModel
    action: str
    request_preview: Dict[str, Any] = Field(default_factory=dict)
    token_fp: str = Field(default="")

    @validator("action")
    def _not_empty(cls, v: str) -> str:  # type: ignore
        if not v:
            raise ValueError("action must be non-empty")
        return v


class AssessmentEnvelope(BaseModel):
    # Полный вход для NeuroForge (включая low-level контексты)
    input: Dict[str, Any]
    context: ContextModel


class AssessmentResponse(BaseModel):
    version: str = Field(default="1.0")
    risk_score: float = Field(ge=0.0, le=1.0)  # 0..1
    recommendation: str = Field(regex=r"^(allow|deny|review)$")
    rationale: str = Field(default="")
    obligations: Dict[str, Any] = Field(default_factory=dict)
    features: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class DecisionEvent(BaseModel):
    # Событие после принятия решения PEP/PDP (для обучения, телеметрии)
    tenant: str = Field(default="default")
    rpc: RpcModel
    decision: str = Field(regex=r"^(allow|deny)$")
    policy_id: str = Field(default="")
    rationale: str = Field(default="")
    latency_ms: int = Field(ge=0, default=0)
    context: ContextModel
    subject: SubjectModel
    resource: ResourceModel
    action: str
    obligations: Dict[str, Any] = Field(default_factory=dict)
    token_fp: str = Field(default="")
    correlation_id: str = Field(default_factory=lambda: uuid.uuid4().hex)


# ========================= Транспорты =========================
class Transport(Protocol):
    async def post(self, path: str, json_body: Mapping[str, Any], *, timeout: float) -> Mapping[str, Any]:
        ...


class HTTPTransport:
    def __init__(
        self,
        base_url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        verify_tls: bool = True,
        session: Optional["aiohttp.ClientSession"] = None,
    ):
        if aiohttp is None:
            raise RuntimeError("aiohttp is required for HTTPTransport")
        self.base_url = base_url.rstrip("/")
        self._headers = dict(headers or {})
        self._verify_tls = verify_tls
        self._external_session = session is not None
        self._session: Optional[aiohttp.ClientSession] = session

    async def start(self) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession()

    async def stop(self) -> None:
        if self._session and not self._external_session:
            await self._session.close()
            self._session = None

    async def post(self, path: str, json_body: Mapping[str, Any], *, timeout: float) -> Mapping[str, Any]:
        assert self._session is not None, "HTTPTransport is not started"
        url = f"{self.base_url}{path}"
        async with self._session.post(
            url,
            json=json_body,
            headers=self._headers,
            timeout=timeout,
            ssl=self._verify_tls,
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status}: {text}")
            try:
                return json.loads(text)
            except Exception as e:
                raise RuntimeError(f"Invalid JSON from NeuroForge: {e}")


# gRPC транспорт можно добавить аналогично при необходимости (интерфейс совместимый с Transport)


# ========================= Адаптер =========================
@dataclass
class NeuroForgeConfig:
    base_url: str = "http://localhost:8080"
    assess_path: str = "/v1/neuroforge/assess"
    events_path: str = "/v1/neuroforge/events"
    timeout: float = 0.25
    headers: Mapping[str, str] = dataclasses.field(default_factory=dict)
    verify_tls: bool = True
    cache_ttl_seconds: float = 0.5
    cache_size: int = 5000
    cb_fail_threshold: int = 5
    cb_reset_seconds: float = 5.0
    retry_attempts: int = 3
    retry_backoff_min: float = 0.02
    retry_backoff_max: float = 0.3
    dry_run: bool = False  # при ошибках возвращать безопасную рекомендацию/логировать событие, но не падать
    fail_open: bool = False  # при недоступности NeuroForge возвращать allow (не рекомендуется)


class NeuroForgeAdapter:
    """
    Производственный адаптер к NeuroForge.
    """

    def __init__(self, cfg: NeuroForgeConfig, transport: Optional[Transport] = None):
        self.cfg = cfg
        self._transport = transport or HTTPTransport(
            base_url=cfg.base_url,
            headers=cfg.headers,
            verify_tls=cfg.verify_tls,
        )
        self._cache = _TTLCache(ttl=cfg.cache_ttl_seconds, maxsize=cfg.cache_size)
        self._cb_assess = _CircuitBreaker(fail_threshold=cfg.cb_fail_threshold, reset_timeout=cfg.cb_reset_seconds)
        self._cb_events = _CircuitBreaker(fail_threshold=cfg.cb_fail_threshold, reset_timeout=cfg.cb_reset_seconds)
        self._started = False
        self._lock = asyncio.Lock()

    # ---------- Lifecycle ----------
    async def start(self) -> None:
        if hasattr(self._transport, "start"):
            await getattr(self._transport, "start")()
        self._started = True

    async def stop(self) -> None:
        if hasattr(self._transport, "stop"):
            await getattr(self._transport, "stop")()
        self._started = False

    # ---------- Public API ----------
    async def assess(self, payload: AssessmentEnvelope) -> AssessmentResponse:
        """
        Запросить у NeuroForge оценку риска/рекомендацию/обязательства.
        Использует TTL-кэш по ключу входного запроса.
        """
        assert self._started, "NeuroForgeAdapter not started"
        # Валидация схемы (мягкая, если pydantic недоступен)
        if BaseModel is object:  # pydantic отсутствует
            if not isinstance(payload.input, Mapping):
                raise ValueError("payload.input must be Mapping")
        else:
            try:
                payload = AssessmentEnvelope.parse_obj(payload) if not isinstance(payload, AssessmentEnvelope) else payload
            except ValidationError as e:
                raise RuntimeError(f"Invalid AssessmentEnvelope: {e}")

        cache_key = _hashable({"input": payload.input, "context": payload.context.dict() if hasattr(payload.context, "dict") else dict(payload.context)})
        cached = await self._cache.get(cache_key)
        if cached is not None:
            NF_CACHE_HIT and NF_CACHE_HIT.labels(endpoint="assess").inc()
            return cached
        NF_CACHE_MISS and NF_CACHE_MISS.labels(endpoint="assess").inc()

        if self._cb_assess.is_open:
            NF_CB_STATE and NF_CB_STATE.labels(endpoint="assess").set(1)
            return self._fallback_assessment(payload, reason="circuit_open")

        NF_CB_STATE and NF_CB_STATE.labels(endpoint="assess").set(0)

        with _otel_span("neuroforge.assess") as span, _prom_timer(NF_LAT, "assess"):
            if trace and span:
                span.set_attribute("neuroforge.endpoint", "assess")
                span.set_attribute("neuroforge.tenant", getattr(payload, "context", ContextModel()).correlation_id or "")

            try:
                result = await self._retrying_post(
                    path=self.cfg.assess_path,
                    body=self._build_assess_body(payload),
                    endpoint="assess",
                    cb=self._cb_assess,
                )
                # Валидация ответа
                if BaseModel is object:
                    resp = AssessmentResponse(
                        risk_score=float(result.get("risk_score", 0.0)),
                        recommendation=str(result.get("recommendation", "deny")),
                        rationale=str(result.get("rationale", "")),
                        obligations=result.get("obligations", {}) or {},
                        features=result.get("features", {}) or {},
                        tags=result.get("tags", []) or [],
                        version=str(result.get("version", "1.0")),
                    )
                else:
                    resp = AssessmentResponse.parse_obj(result)
                await self._cache.set(cache_key, resp)
                NF_REQ and NF_REQ.labels(endpoint="assess", result="ok").inc()
                return resp
            except Exception as e:
                NF_REQ and NF_REQ.labels(endpoint="assess", result="error").inc()
                logger.error(json.dumps({
                    "event": "neuroforge_assess_error",
                    "error": str(e),
                    "corr": getattr(payload.context, "correlation_id", ""),
                }, ensure_ascii=False))
                if self.cfg.dry_run or self.cfg.fail_open:
                    return self._fallback_assessment(payload, reason="exception")
                raise

    async def notify_decision(self, event: DecisionEvent) -> None:
        """
        Отправить в NeuroForge телеметрию о принятом решении (для обучения/аналитики).
        Безопасна к ошибкам: при недоступности — лог и, опционально, dry_run.
        """
        assert self._started, "NeuroForgeAdapter not started"
        # Валидация
        if BaseModel is not object:
            try:
                event = DecisionEvent.parse_obj(event) if not isinstance(event, DecisionEvent) else event
            except ValidationError as e:
                raise RuntimeError(f"Invalid DecisionEvent: {e}")

        if self._cb_events.is_open:
            NF_CB_STATE and NF_CB_STATE.labels(endpoint="events").set(1)
            logger.warning(json.dumps({"event": "neuroforge_events_circuit_open"}))
            return

        NF_CB_STATE and NF_CB_STATE.labels(endpoint="events").set(0)

        with _otel_span("neuroforge.notify_decision") as span, _prom_timer(NF_LAT, "events"):
            if trace and span:
                span.set_attribute("neuroforge.endpoint", "events")
                span.set_attribute("rpc.method", event.rpc.method)
                span.set_attribute("policy.decision", event.decision)
            try:
                body = self._build_event_body(event)
                await self._retrying_post(
                    path=self.cfg.events_path,
                    body=body,
                    endpoint="events",
                    cb=self._cb_events,
                )
                NF_REQ and NF_REQ.labels(endpoint="events", result="ok").inc()
            except Exception as e:
                NF_REQ and NF_REQ.labels(endpoint="events", result="error").inc()
                logger.error(json.dumps({
                    "event": "neuroforge_notify_error",
                    "error": str(e),
                    "corr": event.correlation_id,
                }, ensure_ascii=False))
                # Не пробрасываем исключение — телеметрия не должна ронять бизнес-вызовы

    # ---------- Health ----------
    def health(self) -> Dict[str, Any]:
        return {
            "started": self._started,
            "assess_circuit_open": self._cb_assess.is_open,
            "events_circuit_open": self._cb_events.is_open,
            "cache_ttl": self.cfg.cache_ttl_seconds,
            "base_url": self.cfg.base_url,
        }

    # ---------- Внутренние утилиты ----------
    def _fallback_assessment(self, payload: AssessmentEnvelope, *, reason: str) -> AssessmentResponse:
        # Безопасный отказ: deny-by-default, если не задан fail_open
        if self.cfg.fail_open:
            rec = "allow"
            risk = 0.0
        else:
            rec = "deny"
            risk = 1.0
        resp = AssessmentResponse(
            version="fallback-1.0",
            risk_score=risk,
            recommendation=rec,
            rationale=f"fallback: {reason}",
            obligations={},
            features={},
            tags=["fallback", reason],
        )
        logger.warning(json.dumps({
            "event": "neuroforge_fallback_assessment",
            "reason": reason,
            "recommendation": rec,
        }, ensure_ascii=False))
        return resp

    def _build_assess_body(self, payload: AssessmentEnvelope) -> Dict[str, Any]:
        # Преобразование к контракту NeuroForge (унифицировано)
        ctx = payload.context.dict() if hasattr(payload.context, "dict") else dict(payload.context)
        return {
            "input": payload.input,
            "context": ctx,
            "meta": {
                "adapter_version": "1.0.0",
                "idempotency_key": ctx.get("correlation_id") or uuid.uuid4().hex,
                "tenant": payload.input.get("tenant") if isinstance(payload.input, dict) else None,
            },
        }

    def _build_event_body(self, event: DecisionEvent) -> Dict[str, Any]:
        return {
            "event": "policy_decision",
            "tenant": event.tenant,
            "rpc": event.rpc.dict() if hasattr(event.rpc, "dict") else dataclasses.asdict(event.rpc),
            "decision": event.decision,
            "policy_id": event.policy_id,
            "rationale": event.rationale,
            "latency_ms": event.latency_ms,
            "context": event.context.dict() if hasattr(event.context, "dict") else dataclasses.asdict(event.context),
            "subject": event.subject.dict() if hasattr(event.subject, "dict") else dataclasses.asdict(event.subject),
            "resource": event.resource.dict() if hasattr(event.resource, "dict") else dataclasses.asdict(event.resource),
            "action": event.action,
            "obligations": event.obligations,
            "token_fp": event.token_fp,
            "correlation_id": event.correlation_id,
            "meta": {
                "adapter_version": "1.0.0",
                "idempotency_key": event.correlation_id,
            },
        }

    async def _retrying_post(self, *, path: str, body: Mapping[str, Any], endpoint: str, cb: _CircuitBreaker) -> Mapping[str, Any]:
        """
        Пост с экспоненциальным бэкоффом и учётом circuit breaker.
        """
        attempts = max(1, self.cfg.retry_attempts)
        delay = self.cfg.retry_backoff_min
        last_exc: Optional[Exception] = None

        for i in range(attempts):
            try:
                with _prom_timer(NF_LAT, endpoint):
                    result = await self._transport.post(path, body, timeout=self.cfg.timeout)
                cb.ok()
                return result
            except Exception as e:
                last_exc = e
                cb.fail()
                # метрики
                NF_REQ and NF_REQ.labels(endpoint=endpoint, result="retry").inc()
                logger.warning(json.dumps({
                    "event": "neuroforge_retry",
                    "endpoint": endpoint,
                    "attempt": i + 1,
                    "error": str(e),
                }, ensure_ascii=False))
                if i == attempts - 1:
                    break
                await asyncio.sleep(min(self.cfg.retry_backoff_max, delay))
                delay = min(self.cfg.retry_backoff_max, delay * 2)

        assert last_exc is not None
        raise last_exc


# ========================= Фабрика =========================
def build_default_adapter(
    *,
    base_url: str = "http://localhost:8080",
    headers: Optional[Mapping[str, str]] = None,
    verify_tls: bool = True,
    dry_run: bool = False,
    fail_open: bool = False,
) -> NeuroForgeAdapter:
    """
    Удобная фабрика для быстрого старта.
    """
    cfg = NeuroForgeConfig(
        base_url=base_url,
        headers=headers or {},
        verify_tls=verify_tls,
        dry_run=dry_run,
        fail_open=fail_open,
    )
    return NeuroForgeAdapter(cfg=cfg)
