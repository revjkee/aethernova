# policy-core/api/grpc/server.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import signal
import time
import typing as t
import uuid

import grpc
from grpc import aio

# ---------- Устойчивый импорт сгенерированных protobuf-модулей ----------
def _try_import() -> tuple[t.Any, t.Any]:
    paths = [
        ("policy_core.schemas.proto.v1.policy.decision_pb2",
         "policy_core.schemas.proto.v1.policy.decision_pb2_grpc"),
        ("aethernova.policy.v1.decision_pb2",
         "aethernova.policy.v1.decision_pb2_grpc"),
        ("decision_pb2", "decision_pb2_grpc"),
    ]
    for pb, rpc in paths:
        try:
            mod_pb = __import__(pb, fromlist=["*"])
            mod_rpc = __import__(rpc, fromlist=["*"])
            return mod_pb, mod_rpc
        except Exception:
            continue
    raise RuntimeError("Cannot import generated protobuf stubs for decision.proto")
pb2, pb2_grpc = _try_import()

# ---------- Опциональные зависимости (не обязательные для запуска) ----------
try:
    # OpenTelemetry (опционально)
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
except Exception:  # OpenTelemetry необязателен
    trace = None
    metrics = None

try:
    # Health service
    from grpc_health.v1 import health, health_pb2_grpc
except Exception:
    health = None
    health_pb2_grpc = None

try:
    # Reflection
    from grpc_reflection.v1alpha import reflection
except Exception:
    reflection = None

# ---------- Настройки через ENV ----------
def env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name, default)
    return v

GRPC_HOST = env("GRPC_HOST", "0.0.0.0")
GRPC_PORT = int(env("GRPC_PORT", "7443"))
MAX_RECV_MB = int(env("GRPC_MAX_RECV_MB", "64"))
MAX_SEND_MB = int(env("GRPC_MAX_SEND_MB", "64"))
ENABLE_REFLECTION = env("GRPC_REFLECTION", "true").lower() == "true"

TLS_CERT_FILE = env("GRPC_TLS_CERT_FILE")   # server cert chain (PEM)
TLS_KEY_FILE = env("GRPC_TLS_KEY_FILE")     # server private key (PEM)
TLS_CLIENT_CA = env("GRPC_TLS_CLIENT_CA")   # if set -> require client certs (mTLS)

AUTH_MODE = env("AUTH_MODE", "hybrid")  # none|api_key|oidc|hybrid
API_KEY_HEADER = env("AUTH_API_KEY_HEADER", "x-api-key").lower()
API_KEY_VALUES = [x.strip() for x in env("AUTH_API_KEYS", "").split(",") if x.strip()]
TENANT_HEADER = env("AUTH_TENANT_HEADER", "x-tenant-id").lower()

OIDC_ISSUER = env("AUTH_OIDC_ISSUER")
OIDC_AUDIENCE = env("AUTH_OIDC_AUDIENCE")
OIDC_JWKS_URL = env("AUTH_OIDC_JWKS_URL")
OIDC_ALGS = [a.strip() for a in env("AUTH_OIDC_ALGS", "RS256,ES256").split(",")]
OIDC_LEEWAY = int(env("AUTH_OIDC_LEEWAY", "60"))
OIDC_JWKS_TTL = int(env("AUTH_OIDC_JWKS_TTL", "600"))
OIDC_REQUIRED_SCOPES = {s.strip() for s in env("AUTH_OIDC_REQUIRED_SCOPES", "mythos.read").split(",") if s.strip()}
OIDC_REQUIRED_ROLES = {s.strip() for s in env("AUTH_OIDC_REQUIRED_ROLES", "").split(",") if s.strip()}

# ---------- Логирование ----------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='{"ts":"%(asctime)s","lvl":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
log = logging.getLogger("policy-core.grpc")

# ---------- Утилиты ----------
def _now() -> int:
    return int(time.time())

def _consteq(a: str, b: str) -> bool:
    import hmac
    try:
        return hmac.compare_digest(a.encode(), b.encode())
    except Exception:
        return False

def _split_scopes(val: t.Optional[str]) -> set[str]:
    if not val:
        return set()
    return set(s for s in val.replace(",", " ").split() if s)

def _extract_roles(claims: dict) -> set[str]:
    roles: set[str] = set()
    realm = claims.get("realm_access") or {}
    if isinstance(realm, dict):
        roles |= set(realm.get("roles") or [])
    res = claims.get("resource_access") or {}
    if isinstance(res, dict):
        for v in res.values():
            if isinstance(v, dict):
                roles |= set(v.get("roles") or [])
    if isinstance(claims.get("roles"), (list, tuple)):
        roles |= set(claims["roles"])
    return roles

# ---------- OIDC проверка токенов (минималистичная, но промышленная) ----------
class JWKSCache:
    def __init__(self, url: str, ttl: int, timeout: float = 3.0) -> None:
        self.url, self.ttl, self.timeout = url, ttl, timeout
        self._keys: dict[str, dict] = {}
        self._exp = 0
        self._lock = asyncio.Lock()

    async def _refresh(self) -> None:
        import httpx
        async with self._lock:
            if _now() < self._exp:
                return
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.get(self.url)
                r.raise_for_status()
                data = r.json()
            ks = {}
            for k in data.get("keys", []):
                kid = k.get("kid")
                if kid:
                    ks[kid] = k
            self._keys = ks
            self._exp = _now() + self.ttl

    async def get(self, kid: str | None) -> dict | None:
        if _now() >= self._exp:
            await self._refresh()
        return self._keys.get(kid) if kid else None

class ReplayCache:
    def __init__(self) -> None:
        self._data: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def seen_or_set(self, jti: str, exp_ts: int) -> bool:
        now = _now()
        async with self._lock:
            if jti in self._data and self._data[jti] > now:
                return True
            self._data[jti] = max(exp_ts, now + 60)
            # компактная очистка
            if len(self._data) > 10000:
                for k, v in list(self._data.items()):
                    if v <= now:
                        self._data.pop(k, None)
            return False

class OIDCVerifier:
    def __init__(self) -> None:
        if not OIDC_JWKS_URL:
            raise RuntimeError("AUTH_OIDC_JWKS_URL is not set for oidc/hybrid")
        self.jwks = JWKSCache(OIDC_JWKS_URL, OIDC_JWKS_TTL)
        self.replay = ReplayCache()

    async def verify(self, token: str) -> tuple[str, t.Optional[str], set[str], set[str], dict]:
        from jose import jwt

        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        if alg not in OIDC_ALGS:
            raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "invalid_token")

        key = await self.jwks.get(header.get("kid"))
        if alg.startswith("HS") and not key:
            # HMAC не поддерживаем без общего секрета
            raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "invalid_token")

        claims = jwt.decode(
            token,
            key,
            algorithms=OIDC_ALGS,
            audience=OIDC_AUDIENCE,
            issuer=OIDC_ISSUER,
            options={
                "verify_aud": OIDC_AUDIENCE is not None,
                "verify_iss": OIDC_ISSUER is not None,
                "leeway": OIDC_LEEWAY,
            },
        )

        jti = claims.get("jti")
        if jti and await self.replay.seen_or_set(jti, int(claims.get("exp", _now() + 60))):
            raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "token_replayed")

        scopes = _split_scopes(claims.get("scope") or claims.get("scp"))
        roles = _extract_roles(claims)

        miss_scopes = OIDC_REQUIRED_SCOPES - scopes
        if miss_scopes:
            raise grpc.RpcError(grpc.StatusCode.PERMISSION_DENIED, f"missing_scopes:{','.join(sorted(miss_scopes))}")
        if OIDC_REQUIRED_ROLES and not OIDC_REQUIRED_ROLES.issubset(roles):
            raise grpc.RpcError(grpc.StatusCode.PERMISSION_DENIED, "missing_roles")

        sub = str(claims.get("sub") or "anonymous")
        tenant = claims.get("tenant") or claims.get("tenant_id") or claims.get("tid")
        return sub, str(tenant) if tenant else None, scopes, roles, claims

# ---------- API-Key проверка ----------
class APIKeyValidator:
    def __init__(self) -> None:
        self._plain = [k for k in API_KEY_VALUES if not k.startswith("sha256=")]
        self._sha = [k for k in API_KEY_VALUES if k.startswith("sha256=")]

    @staticmethod
    def _sha256(s: str) -> str:
        import hashlib
        return "sha256=" + hashlib.sha256(s.encode()).hexdigest()

    def validate(self, provided: str | None) -> bool:
        if not provided:
            return False
        if any(_consteq(provided, k) for k in self._plain):
            return True
        hashed = self._sha256(provided)
        return any(_consteq(hashed, k) for k in self._sha)

# ---------- Перехватчики ----------
class AccessLogInterceptor(aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        peer = handler_call_details.invocation_metadata
        start = time.perf_counter()
        handler = await continuation(handler_call_details)

        async def _unary_unary(request, context):
            rid = _get_request_id(context)
            log.info(json.dumps({"event":"rpc_start","method":method,"rid":rid}))
            try:
                resp = await handler.unary_unary(request, context)
                return resp
            finally:
                dur = time.perf_counter() - start
                log.info(json.dumps({"event":"rpc_end","method":method,"rid":rid,"duration_ms":int(dur*1000)}))

        async def _unary_stream(request, context):
            rid = _get_request_id(context)
            log.info(json.dumps({"event":"rpc_start","method":method,"rid":rid}))
            async for resp in handler.unary_stream(request, context):
                yield resp
            dur = time.perf_counter() - start
            log.info(json.dumps({"event":"rpc_end","method":method,"rid":rid,"duration_ms":int(dur*1000)}))

        async def _stream_unary(request_iterator, context):
            rid = _get_request_id(context)
            log.info(json.dumps({"event":"rpc_start","method":method,"rid":rid}))
            resp = await handler.stream_unary(request_iterator, context)
            dur = time.perf_counter() - start
            log.info(json.dumps({"event":"rpc_end","method":method,"rid":rid,"duration_ms":int(dur*1000)}))
            return resp

        async def _stream_stream(request_iterator, context):
            rid = _get_request_id(context)
            log.info(json.dumps({"event":"rpc_start","method":method,"rid":rid}))
            async for resp in handler.stream_stream(request_iterator, context):
                yield resp
            dur = time.perf_counter() - start
            log.info(json.dumps({"event":"rpc_end","method":method,"rid":rid,"duration_ms":int(dur*1000)}))

        return aio.rpc_method_handler(
            _unary_unary if handler.unary_unary else None,
            _unary_stream if handler.unary_stream else None,
            _stream_unary if handler.stream_unary else None,
            _stream_stream if handler.stream_stream else None,
        )

def _bearer_from_metadata(md: t.Sequence[grpc.aio.Metadata]) -> str | None:
    for k, v in md:
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            return v.split(" ", 1)[1]
    return None

def _get_request_id(context: aio.ServicerContext) -> str:
    md = dict(context.invocation_metadata() or [])
    return md.get("x-request-id", str(uuid.uuid4()))

class AuthInterceptor(aio.ServerInterceptor):
    def __init__(self) -> None:
        self.oidc = None
        if AUTH_MODE in {"oidc", "hybrid"} and OIDC_JWKS_URL:
            self.oidc = OIDCVerifier()
        self.apikey = APIKeyValidator()

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)

        async def _guard(context: aio.ServicerContext) -> tuple[str, t.Optional[str], set[str], set[str], dict]:
            md = tuple(context.invocation_metadata() or [])
            rid = _get_request_id(context)
            tenant = dict(md).get(TENANT_HEADER)
            # 1) OIDC
            if AUTH_MODE in {"oidc", "hybrid"}:
                token = _bearer_from_metadata(md)
                if token and self.oidc:
                    sub, tnt, scopes, roles, claims = await self.oidc.verify(token)
                    if tenant and not tnt:
                        tnt = tenant
                    context.set_trailing_metadata((
                        ("x-auth-subject", sub),
                        ("x-tenant-id", tnt or ""),
                        ("x-auth-scopes", ",".join(sorted(scopes))),
                    ))
                    return sub, tnt, scopes, roles, claims
            # 2) API KEY
            if AUTH_MODE in {"api_key", "hybrid"}:
                key = dict(md).get(API_KEY_HEADER)
                if key and self.apikey.validate(key):
                    sub = f"api-key:{uuid.uuid5(uuid.NAMESPACE_URL, key).hex[:8]}"
                    scopes = {"mythos.read"}
                    roles = {"service"}
                    context.set_trailing_metadata((
                        ("x-auth-subject", sub),
                        ("x-tenant-id", tenant or ""),
                        ("x-auth-scopes", ",".join(sorted(scopes))),
                    ))
                    return sub, tenant, scopes, roles, {}
            if AUTH_MODE == "none":
                return "anonymous", tenant, set(), set(), {}
            # иначе
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "credentials_required")

        async def _wrap_unary_unary(request, context):
            principal = await _guard(context)
            context.set_trailing_metadata((("x-request-id", _get_request_id(context)),))
            return await handler.unary_unary(request, context)

        async def _wrap_unary_stream(request, context):
            principal = await _guard(context)
            context.set_trailing_metadata((("x-request-id", _get_request_id(context)),))
            async for resp in handler.unary_stream(request, context):
                yield resp

        async def _wrap_stream_unary(request_it, context):
            principal = await _guard(context)
            context.set_trailing_metadata((("x-request-id", _get_request_id(context)),))
            return await handler.stream_unary(request_it, context)

        async def _wrap_stream_stream(request_it, context):
            principal = await _guard(context)
            context.set_trailing_metadata((("x-request-id", _get_request_id(context)),))
            async for resp in handler.stream_stream(request_it, context):
                yield resp

        return aio.rpc_method_handler(
            _wrap_unary_unary if handler.unary_unary else None,
            _wrap_unary_stream if handler.unary_stream else None,
            _wrap_stream_unary if handler.stream_unary else None,
            _wrap_stream_stream if handler.stream_stream else None,
        )

class ValidationInterceptor(aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)

        def _validate(req: t.Any) -> None:
            # Минимальная валидация входа для Decide и DecideStream
            if hasattr(req, "subject"):
                if not req.subject.id:
                    raise grpc.RpcError(grpc.StatusCode.INVALID_ARGUMENT, "subject.id is required")
            if hasattr(req, "resource"):
                if not req.resource.id or not req.resource.type:
                    raise grpc.RpcError(grpc.StatusCode.INVALID_ARGUMENT, "resource.id and resource.type are required")
            if hasattr(req, "action"):
                if req.action == pb2.ACTION_UNSPECIFIED:
                    raise grpc.RpcError(grpc.StatusCode.INVALID_ARGUMENT, "action is required")

        async def _uu(request, context):
            _validate(request)
            return await handler.unary_unary(request, context)

        async def _us(request, context):
            _validate(request)
            async for r in handler.unary_stream(request, context):
                yield r

        async def _su(request_it, context):
            async for r in request_it:
                _validate(r.request if hasattr(r, "request") else r)
                break
            # передадим оригинальный итератор дальше
            return await handler.stream_unary(request_it, context)

        async def _ss(request_it, context):
            async for r in request_it:
                _validate(r.request if hasattr(r, "request") else r)
                yield from ()
                break
            async for resp in handler.stream_stream(request_it, context):
                yield resp

        return aio.rpc_method_handler(
            _uu if handler.unary_unary else None,
            _us if handler.unary_stream else None,
            _su if handler.stream_unary else None,
            _ss if handler.stream_stream else None,
        )

class ExceptionInterceptor(aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)

        async def _uu(request, context):
            try:
                return await handler.unary_unary(request, context)
            except grpc.RpcError:
                raise
            except Exception as e:
                log.exception("Unhandled RPC error")
                context.abort(grpc.StatusCode.INTERNAL, "internal_error")

        async def _us(request, context):
            try:
                async for r in handler.unary_stream(request, context):
                    yield r
            except grpc.RpcError:
                raise
            except Exception:
                log.exception("Unhandled RPC error")
                context.abort(grpc.StatusCode.INTERNAL, "internal_error")

        async def _su(request_it, context):
            try:
                return await handler.stream_unary(request_it, context)
            except grpc.RpcError:
                raise
            except Exception:
                log.exception("Unhandled RPC error")
                context.abort(grpc.StatusCode.INTERNAL, "internal_error")

        async def _ss(request_it, context):
            try:
                async for r in handler.stream_stream(request_it, context):
                    yield r
            except grpc.RpcError:
                raise
            except Exception:
                log.exception("Unhandled RPC error")
                context.abort(grpc.StatusCode.INTERNAL, "internal_error")

        return aio.rpc_method_handler(
            _uu if handler.unary_unary else None,
            _us if handler.unary_stream else None,
            _su if handler.stream_unary else None,
            _ss if handler.stream_stream else None,
        )

# ---------- Простая политика/движок по умолчанию (заглушка, совместимая с Decision) ----------
class PolicyEngineImpl:
    async def decide(self, req: pb2.DecisionRequest) -> pb2.Decision:
        start = time.perf_counter()
        # Простейшая логика: разрешаем READ/METADATA, остальное по роли "admin"
        effect = pb2.EFFECT_ALLOW
        reasons: list[pb2.Reason] = []

        if req.action in (pb2.ACTION_WRITE, pb2.ACTION_DELETE, pb2.ACTION_EXPORT):
            roles = set(req.subject.roles)
            if "admin" not in roles and "engineer" not in roles:
                effect = pb2.EFFECT_DENY
                reasons.append(pb2.Reason(code=pb2.REASON_ROLE_FORBIDS_ACTION, message="role_forbids_action"))

        # Базовый фильтр RLS по tenant_id
        where = []
        if req.subject.tenant_id:
            where.append(pb2.Condition(column="tenant_id", op=pb2.COMP_EQ, value=_v(req.subject.tenant_id)))
        filt = pb2.Filter(where=where, sql_preview="tenant_id = ?")

        decision = pb2.Decision(
            decision_id=req.request_id or str(uuid.uuid4()),
            effect=effect,
            reasons=reasons,
            mask=[],
            filter=filt,
            obligations=[],
            ttl_sec=900 if effect == pb2.EFFECT_ALLOW else 0,
            policy=pb2.PolicyMetadata(
                engine_name="policy-core",
                policy_package="policy_core.data_access",
                rule_path="result",
                bundle=req.policy_bundle or "default",
                bundle_hash="n/a",
                revision=req.policy_revision or "local",
            ),
            eval=pb2.EvaluationMeta(
                break_glass=req.context.emergency if req.HasField("context") else False
            ),
            cache=pb2.CacheMeta(hit=pb2.CACHE_MISS, key="", etag=""),
        )
        # Продолжительность оценки
        dur = time.perf_counter() - start
        decision.eval.eval_duration.FromSeconds(int(dur))
        return decision

# ---------- Помощник для google.protobuf.Value ----------
from google.protobuf import struct_pb2, timestamp_pb2, duration_pb2  # noqa: E402

def _v(x: t.Any) -> struct_pb2.Value:
    return struct_pb2.Value(string_value=str(x))

# ---------- Реализация gRPC сервиса ----------
class PolicyEngineService(pb2_grpc.PolicyEngineServicer):
    def __init__(self, engine: PolicyEngineImpl) -> None:
        self.engine = engine

    async def Decide(self, request: pb2.DecisionRequest, context: aio.ServicerContext) -> pb2.DecisionResponse:
        decision = await self.engine.decide(request)
        return pb2.DecisionResponse(decision=decision)

    async def DecideBatch(self, request: pb2.DecisionRequestBatch, context: aio.ServicerContext) -> pb2.DecisionBatchResponse:
        responses = []
        for r in request.requests:
            d = await self.engine.decide(r)
            responses.append(pb2.DecisionResponse(decision=d))
        return pb2.DecisionBatchResponse(responses=responses)

    async def DecideStream(self, request_iterator, context: aio.ServicerContext):
        async for msg in request_iterator:
            req: pb2.DecisionStreamRequest = msg
            d = await self.engine.decide(req.request)
            yield pb2.DecisionStreamResponse(response=pb2.DecisionResponse(decision=d))

# ---------- OpenTelemetry инициализация (опционально) ----------
def setup_otel() -> None:
    if trace is None:
        log.info("OpenTelemetry is not available; skipping OTEL setup")
        return
    service_name = os.getenv("OTEL_SERVICE_NAME", "policy-core-grpc")
    resource = Resource.create({"service.name": service_name})
    tp = TracerProvider(resource=resource)
    trace.set_tracer_provider(tp)
    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    else:
        # Silent if no exporter configured
        pass

    # Metrics
    if metrics is not None and os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        reader = PeriodicExportingMetricReader(OTLPMetricExporter())
        mp = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(mp)

# ---------- Health/Reflection регистрация ----------
def register_health(server: aio.Server) -> None:
    if health and health_pb2_grpc:
        h = health.HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(h, server)
        # Сервис будет "SERVING" после стартa
    else:
        log.info("grpc-health not available; skipping")

def register_reflection(server: aio.Server) -> None:
    if reflection and ENABLE_REFLECTION:
        service_names = (
            pb2.DESCRIPTOR.services_by_name["PolicyEngine"].full_name,
            reflection.SERVICE_NAME,
        )
        reflection.enable_server_reflection(service_names, server)
    else:
        log.info("grpc-reflection disabled or not available")

# ---------- TLS/mTLS ----------
def _server_credentials() -> grpc.ServerCredentials | None:
    if not TLS_CERT_FILE or not TLS_KEY_FILE:
        return None
    with open(TLS_CERT_FILE, "rb") as f:
        cert = f.read()
    with open(TLS_KEY_FILE, "rb") as f:
        key = f.read()
    if TLS_CLIENT_CA:
        with open(TLS_CLIENT_CA, "rb") as f:
            client_ca = f.read()
        return grpc.ssl_server_credentials(
            [(key, cert)],
            root_certificates=client_ca,
            require_client_auth=True,
        )
    return grpc.ssl_server_credentials([(key, cert)])

# ---------- Создание и запуск сервера ----------
async def serve() -> None:
    setup_otel()

    options = [
        ("grpc.max_send_message_length", MAX_SEND_MB * 1024 * 1024),
        ("grpc.max_receive_message_length", MAX_RECV_MB * 1024 * 1024),
        ("grpc.keepalive_time_ms", 20_000),
        ("grpc.keepalive_timeout_ms", 10_000),
        ("grpc.http2.max_pings_without_data", 0),
        ("grpc.keepalive_permit_without_calls", 1),
    ]

    interceptors = [
        ExceptionInterceptor(),
        AuthInterceptor(),
        ValidationInterceptor(),
        AccessLogInterceptor(),
    ]

    server = aio.server(interceptors=interceptors, options=options)

    # Основной сервис
    pb2_grpc.add_PolicyEngineServicer_to_server(PolicyEngineService(PolicyEngineImpl()), server)

    # Health и Reflection
    register_health(server)
    register_reflection(server)

    creds = _server_credentials()
    bind = f"{GRPC_HOST}:{GRPC_PORT}"
    if creds:
        server.add_secure_port(bind, creds)
        log.info(f"gRPC listening (secure) on {bind}")
    else:
        server.add_insecure_port(bind)
        log.info(f"gRPC listening (insecure) on {bind}")

    await server.start()

    # Graceful shutdown
    stop_event = asyncio.Event()

    def _handle_sig():
        log.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(s, _handle_sig)

    await stop_event.wait()
    await server.stop(grace=None)  # graceful; дождется активных RPC

if __name__ == "__main__":
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
