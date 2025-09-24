# policy-core/policy_core/pep/grpc_interceptor.py
# -*- coding: utf-8 -*-
"""
Policy Enforcement Point (PEP) gRPC Async Interceptor (grpc.aio)

Возможности:
- Zero Trust, deny-by-default
- Извлечение субъекта/тенанта/ролей/скопов из gRPC metadata + TLS auth_context
- Кэш решений PDP (TTL + LRU bounding)
- Dry-run режим (логируем отказ, но пропускаем)
- Circuit Breaker к удалённому PDP (OPA HTTP API)
- Локальный fallback policy engine (правила в памяти)
- Прометей-метрики (counters + histograms + gauge)
- OpenTelemetry trace context + атрибуты
- Скоринговый аудит (структурные JSON-логи) с корреляцией
- Allowlist методов (health, reflection и т.п.)
- Поддержка unary-unary, unary-stream, stream-unary, stream-stream

Зависимости:
    pip install grpcio grpcio-tools aiohttp prometheus-client opentelemetry-sdk
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import functools
import hashlib
import json
import logging
import os
import time
import uuid
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Tuple

import grpc
from grpc.aio import ServerInterceptor, HandlerCallDetails, ServicerContext, RpcMethodHandler

try:
    # Optional, но крайне желательно
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
except Exception:  # pragma: no cover - допускаем отсутствие OTel
    trace = None
    Status = None
    StatusCode = None

try:
    from prometheus_client import Counter, Histogram, Gauge
except Exception:  # pragma: no cover - допускаем отсутствие Prometheus
    Counter = Histogram = Gauge = None  # type: ignore

try:
    import aiohttp
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore


# ---------- Логирование ----------
_LOG_LEVEL = os.getenv("POLICY_CORE_LOG_LEVEL", "INFO").upper()
logger = logging.getLogger("policy_core.pep.grpc_interceptor")
if not logger.handlers:
    handler = logging.StreamHandler()
    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s policy_core.pep %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(fmt)
    logger.addHandler(handler)
logger.setLevel(_LOG_LEVEL)

# ---------- Корреляция ----------
corr_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="")


# ---------- Метрики ----------
if Counter and Histogram and Gauge:
    METRIC_DECISIONS = Counter(
        "policy_core_pep_decisions_total",
        "Policy decisions",
        ["decision", "service", "method", "policy_id", "tenant"],
    )
    METRIC_EVAL_LATENCY = Histogram(
        "policy_core_pep_evaluation_seconds",
        "Time to evaluate policy",
        ["service", "method", "pdp"],
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5),
    )
    METRIC_DENIED = Counter(
        "policy_core_pep_denied_total",
        "Denied requests",
        ["service", "method", "reason"],
    )
    METRIC_ERRORS = Counter(
        "policy_core_pep_errors_total",
        "Interceptor errors",
        ["service", "method", "stage"],
    )
    METRIC_PDP_CIRCUIT = Gauge(
        "policy_core_pdp_circuit_state",
        "PDP circuit breaker state (0=closed,1=open)",
        ["endpoint"],
    )
else:  # pragma: no cover
    METRIC_DECISIONS = METRIC_EVAL_LATENCY = METRIC_DENIED = METRIC_ERRORS = METRIC_PDP_CIRCUIT = None  # type: ignore


# ---------- Модель решения ----------
@dataclasses.dataclass(frozen=True)
class Decision:
    allow: bool
    policy_id: str = "none"
    rationale: str = ""
    obligations: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    tags: Tuple[str, ...] = dataclasses.field(default_factory=tuple)


class PolicyEngine(Protocol):
    async def evaluate(self, payload: Mapping[str, Any]) -> Decision:
        ...


# ---------- Простая TTL LRU Cache ----------
class _TTLCache:
    def __init__(self, maxsize: int = 10000, ttl_seconds: float = 5.0):
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._data: OrderedDict[str, Tuple[float, Decision]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Decision]:
        async with self._lock:
            item = self._data.get(key)
            now = time.monotonic()
            if not item:
                return None
            ts, val = item
            if now - ts > self.ttl:
                self._data.pop(key, None)
                return None
            # move to end (LRU)
            self._data.move_to_end(key)
            return val

    async def set(self, key: str, value: Decision) -> None:
        async with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = (time.monotonic(), value)
            # trim
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)


# ---------- Circuit Breaker ----------
class _CircuitBreaker:
    def __init__(self, fail_threshold: int = 5, reset_timeout: float = 10.0):
        self.fail_threshold = fail_threshold
        self.reset_timeout = reset_timeout
        self._fail_count = 0
        self._opened_at = 0.0

    @property
    def is_open(self) -> bool:
        if self._opened_at == 0.0:
            return False
        if time.monotonic() - self._opened_at >= self.reset_timeout:
            # half-open trial
            self._opened_at = 0.0
            self._fail_count = max(0, self._fail_count - 1)
            return False
        return True

    def record_success(self) -> None:
        self._fail_count = 0
        self._opened_at = 0.0

    def record_failure(self) -> None:
        self._fail_count += 1
        if self._fail_count >= self.fail_threshold:
            self._opened_at = time.monotonic()


# ---------- OPA HTTP PDP ----------
class OPAHttpPolicyEngine:
    """
    Пример удалённого PDP (OPA). Ожидает rego rule в виде data.<package>.<rule>.
    endpoint: http(s)://host:port/v1/data/<package>/<rule>
    """

    def __init__(
        self,
        endpoint: str,
        timeout: float = 0.2,
        fail_threshold: int = 5,
        reset_timeout: float = 5.0,
        headers: Optional[Mapping[str, str]] = None,
        verify_tls: bool = True,
    ):
        if aiohttp is None:  # pragma: no cover
            raise RuntimeError("aiohttp is required for OPAHttpPolicyEngine")
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.verify_tls = verify_tls
        self._circuit = _CircuitBreaker(fail_threshold=fail_threshold, reset_timeout=reset_timeout)

    async def evaluate(self, payload: Mapping[str, Any]) -> Decision:
        if self._circuit.is_open:
            if METRIC_PDP_CIRCUIT:
                METRIC_PDP_CIRCUIT.labels(endpoint=self.endpoint).set(1)
            raise RuntimeError("PDP circuit open")

        if METRIC_PDP_CIRCUIT:
            METRIC_PDP_CIRCUIT.labels(endpoint=self.endpoint).set(0)

        started = time.monotonic()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.endpoint,
                    json={"input": payload},
                    headers=self.headers,
                    timeout=self.timeout,
                    ssl=self.verify_tls,
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        raise RuntimeError(f"OPA HTTP {resp.status}: {text}")
                    data = json.loads(text)
                    # ожидаем "result" с полями allow|policy_id|rationale|obligations|tags
                    result = data.get("result", {})
                    decision = Decision(
                        allow=bool(result.get("allow", False)),
                        policy_id=str(result.get("policy_id", "opa")),
                        rationale=str(result.get("rationale", "")),
                        obligations=result.get("obligations", {}) or {},
                        tags=tuple(result.get("tags", []) or []),
                    )
                    self._circuit.record_success()
                    return decision
        except Exception as e:
            self._circuit.record_failure()
            raise
        finally:
            if METRIC_EVAL_LATENCY:
                METRIC_EVAL_LATENCY.labels(
                    service=payload.get("rpc", {}).get("service", "unknown"),
                    method=payload.get("rpc", {}).get("method", "unknown"),
                    pdp="opa_http",
                ).observe(time.monotonic() - started)


# ---------- Локальный fallback-движок ----------
class LocalRuleEngine:
    """
    Простой декларативный движок правил:
    rules = [
      {"effect": "allow", "match": {"action": ["read","list"], "resource.type": "health"}},
      {"effect": "deny",  "match": {"tenant": "default", "action": "delete"}}
    ]
    Совпадение: равенство строк, членство в списке, "resource.*" поддерживает вложенные ключи.
    Первый сработавший rule останавливает поиск.
    """

    def __init__(self, rules: Optional[List[Mapping[str, Any]]] = None, policy_id: str = "local_rules"):
        self.rules = rules or []
        self.policy_id = policy_id

    async def evaluate(self, payload: Mapping[str, Any]) -> Decision:
        flat = _flatten(payload)
        for rule in self.rules:
            match = rule.get("match", {})
            if _match_all(flat, match):
                effect = (rule.get("effect") or "").lower()
                allow = effect == "allow"
                rationale = rule.get("rationale") or f"local rule {effect}"
                tags = tuple(rule.get("tags") or ())
                obligations = rule.get("obligations") or {}
                return Decision(
                    allow=allow,
                    policy_id=self.policy_id,
                    rationale=rationale,
                    obligations=obligations,
                    tags=tags,
                )
        # deny-by-default
        return Decision(allow=False, policy_id=self.policy_id, rationale="no rule matched", obligations={}, tags=())


def _flatten(d: Mapping[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, Mapping):
            out.update(_flatten(v, key, sep=sep))
        else:
            out[key] = v
    return out


def _match_all(flat: Mapping[str, Any], cond: Mapping[str, Any]) -> bool:
    for k, expected in cond.items():
        actual = flat.get(k)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False
    return True


# ---------- Полезные структуры ----------
@dataclasses.dataclass(frozen=True)
class PolicyTarget:
    resource_type: str
    action: str
    # Доп.поля для контекста/обязательств
    extras: Mapping[str, Any] = dataclasses.field(default_factory=dict)


# ---------- Вспомогательные утилиты ----------
_SENSITIVE_HEADERS = {"authorization", "proxy-authorization"}


def _safe_metadata(md: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    redacted = {}
    for k, v in md:
        lk = k.lower()
        if lk in _SENSITIVE_HEADERS:
            redacted[lk] = "<redacted>"
        else:
            redacted[lk] = v
    return redacted


def _hash_key(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.blake2b(raw, digest_size=16).hexdigest()


def _split_method(full: str) -> Tuple[str, str]:
    # gRPC full method: /package.Service/Method
    try:
        _, svc, meth = full.split("/", 2)
        service = svc
        method = meth
    except Exception:
        service = "unknown"
        method = full
    return service, method


def _extract_peer_ip(context: ServicerContext) -> str:
    try:
        peer = context.peer()  # e.g. ipv4:127.0.0.1:59618
        if ":" in peer:
            parts = peer.split(":")
            return parts[-2] if len(parts) >= 2 else peer
        return peer
    except Exception:
        return "unknown"


def _extract_tls_subject(context: ServicerContext) -> str:
    try:
        auth = context.auth_context()
        # auth[b'x509_common_name'] etc. В разных окружениях ключи могут отличаться.
        for k in (b"x509_common_name", b"ssl_common_name", b"transport_security_type"):
            if k in auth:
                vals = auth[k]
                if vals:
                    return vals[0].decode("utf-8", "ignore")
        return ""
    except Exception:
        return ""


def _get_trace_span():
    if trace:
        return trace.get_tracer("policy_core.pep").start_as_current_span("policy_enforcement")
    # заглушка контекста
    class _NullCtx:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
        def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): return False
    return _NullCtx()


# ---------- Основной интерсептор ----------
class PolicyEnforcementInterceptor(ServerInterceptor):
    def __init__(
        self,
        policy_engine: PolicyEngine,
        policy_map: Mapping[str, PolicyTarget],
        *,
        cache_ttl_seconds: float = 1.0,
        cache_size: int = 5000,
        dry_run: bool = False,
        fail_open: bool = False,
        allowlist_methods: Optional[Iterable[str]] = None,
        tenant_header: str = "x-tenant-id",
        subject_header: str = "x-subject",
        roles_header: str = "x-roles",
        scopes_header: str = "x-scopes",
        correlation_header: str = "x-correlation-id",
    ):
        """
        :param policy_engine: реализация PDP (удалённая OPA или локальная)
        :param policy_map: dict[full_method_name] -> PolicyTarget
        :param cache_ttl_seconds: TTL кэша решений PDP
        :param cache_size: ограничение размера LRU
        :param dry_run: если True — отказ логируется, но запрос пропускается
        :param fail_open: поведение при недоступном PDP (True — пропустить, False — отказ)
        :param allowlist_methods: методы, полностью исключённые из проверок
        """
        self.engine = policy_engine
        self.policy_map = dict(policy_map)
        self.cache = _TTLCache(maxsize=cache_size, ttl_seconds=cache_ttl_seconds)
        self.dry_run = dry_run
        self.fail_open = fail_open
        self.allowlist = set(allowlist_methods or [])
        self.tenant_header = tenant_header.lower()
        self.subject_header = subject_header.lower()
        self.roles_header = roles_header.lower()
        self.scopes_header = scopes_header.lower()
        self.correlation_header = correlation_header.lower()

    # gRPC aio API
    async def intercept_service(
        self,
        continuation: Callable[[HandlerCallDetails], Awaitable[RpcMethodHandler]],
        handler_call_details: HandlerCallDetails,
    ) -> RpcMethodHandler:
        full_method = handler_call_details.method or ""
        service, method = _split_method(full_method)

        # Pass-through для allowlist
        if full_method in self.allowlist or method in self.allowlist:
            return await continuation(handler_call_details)

        # Получаем исходный handler
        handler = await continuation(handler_call_details)

        # Оборачиваем по типам RPC
        if handler.unary_unary:
            inner = handler.unary_unary
            async def unary_unary_wrapped(request, context: ServicerContext):
                return await self._guarded_call(inner, request, context, full_method, service, method, handler_call_details)
            return grpc.aio.unary_unary_rpc_method_handler(
                unary_unary_wrapped,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            inner = handler.unary_stream
            async def unary_stream_wrapped(request, context: ServicerContext):
                async for resp in self._guarded_stream_call(inner, request, context, full_method, service, method, handler_call_details):
                    yield resp
            return grpc.aio.unary_stream_rpc_method_handler(
                unary_stream_wrapped,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            inner = handler.stream_unary
            async def stream_unary_wrapped(request_iterator, context: ServicerContext):
                return await self._guarded_call(inner, request_iterator, context, full_method, service, method, handler_call_details, streaming_in=True)
            return grpc.aio.stream_unary_rpc_method_handler(
                stream_unary_wrapped,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            inner = handler.stream_stream
            async def stream_stream_wrapped(request_iterator, context: ServicerContext):
                async for resp in self._guarded_stream_call(inner, request_iterator, context, full_method, service, method, handler_call_details, streaming_in=True, streaming_out=True):
                    yield resp
            return grpc.aio.stream_stream_rpc_method_handler(
                stream_stream_wrapped,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler  # на всякий случай

    # ---------- Общая логика проверки ----------
    async def _guarded_call(
        self,
        inner: Callable[..., Awaitable[Any]],
        request_or_iter,
        context: ServicerContext,
        full_method: str,
        service: str,
        method: str,
        details: HandlerCallDetails,
        streaming_in: bool = False,
    ):
        # Корреляция
        metadata = tuple(details.invocation_metadata or ())
        md_pairs = [(k, v) for k, v in metadata]
        safe_md = _safe_metadata(md_pairs)
        corr_id = self._get_or_create_corr_id(md_pairs)
        token_fingerprint = self._token_fingerprint(md_pairs)

        with _get_trace_span() as span:
            if trace and span:
                span.set_attribute("rpc.system", "grpc")
                span.set_attribute("rpc.service", service)
                span.set_attribute("rpc.method", method)
                span.set_attribute("policy.correlation_id", corr_id)

            # Построение policy input
            tenant, subject, roles, scopes = self._extract_identity(md_pairs)
            peer_ip = _extract_peer_ip(context)
            tls_subject = _extract_tls_subject(context)
            target = self.policy_map.get(full_method) or PolicyTarget(resource_type="unknown", action=method)

            payload = {
                "rpc": {"full_method": full_method, "service": service, "method": method},
                "tenant": tenant,
                "subject": {"id": subject, "roles": roles, "scopes": scopes, "tls_subject": tls_subject},
                "resource": {"type": target.resource_type, "extras": target.extras},
                "context": {"peer_ip": peer_ip, "metadata": safe_md, "correlation_id": corr_id},
                "request": _maybe_peek_request(request_or_iter) if not streaming_in else {"streaming": True},
                "action": target.action,
                "token_fp": token_fingerprint,
            }

            cache_key = _hash_key(payload)
            try:
                decision = await self.cache.get(cache_key)
                if not decision:
                    decision = await self.engine.evaluate(payload)
                    await self.cache.set(cache_key, decision)
            except Exception as e:
                if METRIC_ERRORS:
                    METRIC_ERRORS.labels(service=service, method=method, stage="pdp").inc()
                logger.error(json.dumps({
                    "event": "pdp_error",
                    "error": str(e),
                    "correlation_id": corr_id,
                    "rpc": {"service": service, "method": method},
                }, ensure_ascii=False))
                if self.fail_open or self.dry_run:
                    decision = Decision(allow=True, policy_id="fail_open" if self.fail_open else "dry_run")
                else:
                    await context.abort(grpc.StatusCode.UNAVAILABLE, "Policy decision unavailable")

            allowed = bool(decision.allow)
            if METRIC_DECISIONS:
                METRIC_DECISIONS.labels(
                    decision="allow" if allowed else "deny",
                    service=service,
                    method=method,
                    policy_id=decision.policy_id,
                    tenant=tenant or "none",
                ).inc()

            self._audit_log(decision, payload)

            if not allowed and not self.dry_run:
                if METRIC_DENIED:
                    METRIC_DENIED.labels(service=service, method=method, reason=decision.rationale or "denied").inc()
                if trace and span:
                    span.set_status(Status(StatusCode.ERROR, decision.rationale or "denied"))  # type: ignore
                await context.abort(grpc.StatusCode.PERMISSION_DENIED, decision.rationale or "Access denied")

            # Пропускаем в бизнес-обработчик
            return await inner(request_or_iter, context)

    async def _guarded_stream_call(
        self,
        inner: Callable[..., Awaitable[Iterable[Any]]],
        request_iterator,
        context: ServicerContext,
        full_method: str,
        service: str,
        method: str,
        details: HandlerCallDetails,
        streaming_in: bool = True,
        streaming_out: bool = True,
    ):
        # Для потоков — однократная авторизация на открытие RPC
        result = await self._guarded_call(
            inner,
            request_iterator,
            context,
            full_method,
            service,
            method,
            details,
            streaming_in=streaming_in,
        )
        # Если inner — async generator, то просто возвращаем его элементы
        if hasattr(result, "__aiter__"):
            async for item in result:
                yield item
        elif hasattr(result, "__iter__"):
            for item in result:
                yield item
        else:
            # stream_unary — единственный ответ
            if result is not None:
                yield result

    # ---------- Вспомогательные методы ----------
    def _get_or_create_corr_id(self, md_pairs: Iterable[Tuple[str, str]]) -> str:
        for k, v in md_pairs:
            if k.lower() == self.correlation_header and v:
                corr_id_var.set(v)
                return v
        v = uuid.uuid4().hex
        corr_id_var.set(v)
        return v

    def _extract_identity(self, md_pairs: Iterable[Tuple[str, str]]) -> Tuple[str, str, Tuple[str, ...], Tuple[str, ...]]:
        tenant = subject = ""
        roles: Tuple[str, ...] = ()
        scopes: Tuple[str, ...] = ()
        for k, v in md_pairs:
            lk = k.lower()
            if lk == self.tenant_header:
                tenant = v
            elif lk == self.subject_header:
                subject = v
            elif lk == self.roles_header:
                roles = tuple(x.strip() for x in v.split(",") if x.strip())
            elif lk == self.scopes_header:
                scopes = tuple(x.strip() for x in v.split(",") if x.strip())
        return tenant, subject, roles, scopes

    def _token_fingerprint(self, md_pairs: Iterable[Tuple[str, str]]) -> str:
        # Никогда не логируем сам токен; только короткий хэш
        for k, v in md_pairs:
            if k.lower() == "authorization" and v:
                # Bearer abc.def.ghi -> хэшируем всё поле
                return hashlib.blake2b(v.encode("utf-8"), digest_size=8).hexdigest()
        return ""

    def _audit_log(self, decision: Decision, payload: Mapping[str, Any]) -> None:
        try:
            record = {
                "event": "policy_decision",
                "timestamp": int(time.time() * 1000),
                "correlation_id": payload["context"]["correlation_id"],
                "tenant": payload.get("tenant"),
                "rpc": payload.get("rpc"),
                "resource": payload.get("resource"),
                "subject": {
                    "id": payload.get("subject", {}).get("id"),
                    "roles": payload.get("subject", {}).get("roles"),
                    "scopes": payload.get("subject", {}).get("scopes"),
                    "tls_subject": payload.get("subject", {}).get("tls_subject"),
                },
                "decision": dataclasses.asdict(decision),
            }
            logger.info(json.dumps(record, ensure_ascii=False))
        except Exception as e:  # pragma: no cover
            logger.error(f"audit_log_error: {e}")

# ---------- Утилита: подглянуть в unary request, но не логировать поля ----------
def _maybe_peek_request(req) -> Mapping[str, Any]:
    try:
        # Пытаемся извлечь минимально-опасный контекст (имя класса/тип)
        # Не логируем содержимое, чтобы не утекают PII/секреты.
        return {"type": type(req).__name__}
    except Exception:
        return {"type": "unknown"}


# ---------- Клиентский интерсептор (для корреляции/токена) ----------
class ClientAuthMetadataInterceptor(grpc.aio.ClientInterceptor):
    """
    Добавляет в исходящие вызовы:
      - x-correlation-id (если нет)
      - x-tenant-id / x-subject / x-roles / x-scopes (если заданы)
      - Authorization: Bearer <token> (если задан)
    """

    def __init__(
        self,
        *,
        token: Optional[str] = None,
        tenant: Optional[str] = None,
        subject: Optional[str] = None,
        roles: Optional[Iterable[str]] = None,
        scopes: Optional[Iterable[str]] = None,
        correlation_header: str = "x-correlation-id",
        tenant_header: str = "x-tenant-id",
        subject_header: str = "x-subject",
        roles_header: str = "x-roles",
        scopes_header: str = "x-scopes",
    ):
        self.token = token
        self.tenant = tenant
        self.subject = subject
        self.roles = tuple(roles or ())
        self.scopes = tuple(scopes or ())
        self.correlation_header = correlation_header
        self.tenant_header = tenant_header
        self.subject_header = subject_header
        self.roles_header = roles_header
        self.scopes_header = scopes_header

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        new_details = self._augment_details(client_call_details)
        return await continuation(new_details, request)

    async def intercept_unary_stream(self, continuation, client_call_details, request):
        new_details = self._augment_details(client_call_details)
        return await continuation(new_details, request)

    async def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
        new_details = self._augment_details(client_call_details)
        return await continuation(new_details, request_iterator)

    async def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
        new_details = self._augment_details(client_call_details)
        return await continuation(new_details, request_iterator)

    def _augment_details(self, client_call_details):
        metadata = list(client_call_details.metadata or [])
        md_keys = {k.lower() for k, _ in metadata}

        corr_id = corr_id_var.get() or uuid.uuid4().hex
        if self.correlation_header.lower() not in md_keys:
            metadata.append((self.correlation_header, corr_id))
        if self.tenant and self.tenant_header.lower() not in md_keys:
            metadata.append((self.tenant_header, self.tenant))
        if self.subject and self.subject_header.lower() not in md_keys:
            metadata.append((self.subject_header, self.subject))
        if self.roles and self.roles_header.lower() not in md_keys:
            metadata.append((self.roles_header, ",".join(self.roles)))
        if self.scopes and self.scopes_header.lower() not in md_keys:
            metadata.append((self.scopes_header, ",".join(self.scopes)))
        if self.token and "authorization" not in md_keys:
            metadata.append(("authorization", f"Bearer {self.token}"))

        # Переопределяем только metadata
        class _Details(grpc.aio.ClientCallDetails):
            def __init__(self, d, md):  # noqa
                self.method = d.method
                self.timeout = d.timeout
                self.metadata = md
                self.credentials = d.credentials
                self.wait_for_ready = d.wait_for_ready
                self.compression = getattr(d, "compression", None)

        return _Details(client_call_details, tuple(metadata))


# ---------- Пример фабрики конфигурации ----------
def build_default_interceptor(
    *,
    opa_url: Optional[str] = None,
    local_rules: Optional[List[Mapping[str, Any]]] = None,
    policy_map: Optional[Mapping[str, PolicyTarget]] = None,
    dry_run: bool = False,
    fail_open: bool = False,
) -> PolicyEnforcementInterceptor:
    """
    Быстрая фабрика: если задан opa_url — используем OPAHttpPolicyEngine, иначе LocalRuleEngine.
    """
    if opa_url:
        engine = OPAHttpPolicyEngine(opa_url)
    else:
        engine = LocalRuleEngine(local_rules or [
            {"effect": "allow", "match": {"rpc.method": "HealthCheck", "resource.type": "health"}, "rationale": "health allow"}
        ])
    default_policy_map = policy_map or {}
    allowlist = {
        "/grpc.health.v1.Health/Check",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    }
    return PolicyEnforcementInterceptor(
        policy_engine=engine,
        policy_map=default_policy_map,
        cache_ttl_seconds=1.0,
        cache_size=5000,
        dry_run=dry_run,
        fail_open=fail_open,
        allowlist_methods=allowlist,
    )
