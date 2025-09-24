from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import functools
import hashlib
import hmac
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Mapping, Optional, Tuple

import grpc
from grpc.aio import ServerInterceptor, ServicerContext

# ====== сгенерированные protobuf-модули (путь зависит от вашей компиляции .proto) ======
# Ожидается структура пакета: oblivion/v1/*_pb2*.py
# Если у вас другой layout — поправьте импорты ниже.
from oblivion.v1 import health_pb2 as hp, health_pb2_grpc as hpg
from oblivion.v1 import evidence_pb2 as ep, evidence_pb2_grpc as epg

# ====== опциональные зависимости (метрики/трейсинг/рефлексия/health) ======
try:
    from prometheus_client import Counter, Histogram, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
    PROM_OK = True
except Exception:
    PROM_OK = False

try:
    from grpc_reflection.v1alpha import reflection
    REFL_OK = True
except Exception:
    REFL_OK = False

try:
    from grpc_health.v1 import health, health_pb2, health_pb2_grpc
    HEALTH_OK = True
except Exception:
    HEALTH_OK = False

try:
    from opentelemetry import trace
    OTEL_TRACER = trace.get_tracer(__name__)
    OTEL_OK = True
except Exception:
    OTEL_TRACER = None
    OTEL_OK = False


# =================================================================================================
# Конфигурация
# =================================================================================================

@dataclass
class Config:
    host: str = os.getenv("OV_GRPC_HOST", "0.0.0.0")
    port: int = int(os.getenv("OV_GRPC_PORT", "50051"))

    # TLS/mTLS
    tls_cert_file: Optional[str] = os.getenv("OV_TLS_CERT_FILE") or None
    tls_key_file: Optional[str]  = os.getenv("OV_TLS_KEY_FILE") or None
    tls_client_ca: Optional[str] = os.getenv("OV_TLS_CLIENT_CA") or None  # для mTLS, опционально

    # Аутентификация
    require_auth: bool = os.getenv("OV_REQUIRE_AUTH", "true").lower() == "true"

    # JWT HS256
    jwt_hs256_secret: Optional[str] = os.getenv("OV_JWT_HS256_SECRET") or None
    jwt_issuer: Optional[str] = os.getenv("OV_JWT_ISSUER") or None
    jwt_audience: Optional[str] = os.getenv("OV_JWT_AUDIENCE") or None
    jwt_leeway: int = int(os.getenv("OV_JWT_LEEWAY_SEC", "60"))

    # API Key
    api_key_header: str = os.getenv("OV_API_KEY_HEADER", "x-api-key")
    # список допустимых ключей, разделенных запятой, хранится как sha256 хэши; можно передать уже хэши
    api_keys_csv: str = os.getenv("OV_API_KEYS", "")

    # Хранилище и файлы
    data_dir: str = os.getenv("OV_DATA_DIR", "./data")
    max_message_mb: int = int(os.getenv("OV_MAX_MESSAGE_MB", "32"))

    # Метрики
    enable_metrics: bool = os.getenv("OV_ENABLE_METRICS", "true").lower() == "true"

    # Сервисная информация
    build_version: str = os.getenv("OV_BUILD_VERSION", "dev")
    build_tag: str = os.getenv("OV_BUILD_TAG", "dev")
    git_commit: str = os.getenv("OV_GIT_COMMIT", "unknown")
    git_branch: str = os.getenv("OV_GIT_BRANCH", "unknown")
    platform: str = f"python/{sys.version_info.major}.{sys.version_info.minor} grpc/{grpc.__version__}"

    # Стриминг
    watch_interval_sec: float = float(os.getenv("OV_WATCH_INTERVAL_SEC", "2.0"))

    # Keepalive/flow
    keepalive_time_ms: int = int(os.getenv("OV_KEEPALIVE_TIME_MS", "30000"))
    keepalive_timeout_ms: int = int(os.getenv("OV_KEEPALIVE_TIMEOUT_MS", "10000"))
    max_concurrent_streams: int = int(os.getenv("OV_MAX_CONCURRENT_STREAMS", "1024"))


CFG = Config()
Path(CFG.data_dir).mkdir(parents=True, exist_ok=True)

# Логирование
logging.basicConfig(
    level=os.getenv("OV_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("ov.grpc.server")


# =================================================================================================
# Метрики (опционально)
# =================================================================================================
if PROM_OK and CFG.enable_metrics:
    REG = CollectorRegistry()
    RPC_COUNTER = Counter(
        "ov_grpc_requests_total",
        "gRPC requests",
        ["service", "method", "code"],
        registry=REG,
    )
    RPC_LATENCY = Histogram(
        "ov_grpc_latency_seconds",
        "gRPC handler latency",
        ["service", "method"],
        registry=REG,
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
    )
else:
    REG = None
    RPC_COUNTER = None
    RPC_LATENCY = None


def _metrics_content() -> Tuple[bytes, str]:
    if PROM_OK and CFG.enable_metrics:
        return generate_latest(REG), CONTENT_TYPE_LATEST  # type: ignore[arg-type]
    return b"", "text/plain"


# =================================================================================================
# Утилиты
# =================================================================================================

def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _b64url_json(data_b64: str) -> Dict[str, Any]:
    return json.loads(_b64url_decode(data_b64))


def _token_parts(token: str) -> Tuple[str, str, str]:
    header_b64, payload_b64, sig_b64 = token.split(".")
    return header_b64, payload_b64, sig_b64


def _verify_jwt_hs256(token: str, secret: str, issuer: Optional[str], audience: Optional[str], leeway: int) -> Dict[str, Any]:
    try:
        h_b64, p_b64, s_b64 = _token_parts(token)
    except Exception:
        raise PermissionError("jwt_format")
    signing_input = f"{h_b64}.{p_b64}".encode()
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(s_b64)):
        raise PermissionError("jwt_signature")
    claims = _b64url_json(p_b64)

    now = int(time.time())
    exp = claims.get("exp")
    if exp is None:
        raise PermissionError("jwt_exp_missing")
    if now > int(exp) + leeway:
        raise PermissionError("jwt_expired")
    nbf = claims.get("nbf")
    if nbf is not None and now + leeway < int(nbf):
        raise PermissionError("jwt_not_yet_valid")
    if issuer and claims.get("iss") != issuer:
        raise PermissionError("jwt_iss_mismatch")
    if audience:
        aud = claims.get("aud")
        req = {aud} if isinstance(audience, str) else set(audience)
        have = set(aud if isinstance(aud, list) else [aud]) if aud else set()
        if not (req & have):
            raise PermissionError("jwt_aud_mismatch")
    if not claims.get("sub"):
        raise PermissionError("jwt_sub_missing")
    return claims


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


# =================================================================================================
# Auth интерсептор
# =================================================================================================

class AuthInterceptor(ServerInterceptor):
    def __init__(self, cfg: Config):
        self.cfg = cfg
        # Подготовим допустимые хэши api-ключей
        raw = [x.strip() for x in (cfg.api_keys_csv or "").split(",") if x.strip()]
        self._api_hashes = {x if len(x) == 64 else _sha256_hex(x) for x in raw}

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method or ""
        # Health/Reflection допускаем без авторизации
        if method.endswith("/Check") and HEALTH_OK:
            return await continuation(handler_call_details)
        if method.endswith("ServerReflectionInfo") and REFL_OK:
            return await continuation(handler_call_details)
        if not self.cfg.require_auth:
            return await continuation(handler_call_details)

        md = dict(handler_call_details.invocation_metadata or [])
        # 1) Bearer JWT HS256
        authz = md.get("authorization") or md.get("Authorization")
        if authz and authz.lower().startswith("bearer "):
            token = authz.split(" ", 1)[1].strip()
            if not self.cfg.jwt_hs256_secret:
                context = await continuation(handler_call_details)
                return _wrap_denied(context, grpc.StatusCode.UNAUTHENTICATED, "jwt_not_configured")
            try:
                claims = _verify_jwt_hs256(token, self.cfg.jwt_hs256_secret, self.cfg.jwt_issuer, self.cfg.jwt_audience, self.cfg.jwt_leeway)
                context = await continuation(handler_call_details)
                return _wrap_with_principal(context, claims.get("sub"), "jwt", claims)
            except PermissionError as e:
                context = await continuation(handler_call_details)
                return _wrap_denied(context, grpc.StatusCode.UNAUTHENTICATED, f"jwt_{str(e)}")

        # 2) API-Key
        api_key = md.get(self.cfg.api_key_header) or md.get(self.cfg.api_key_header.lower())
        if api_key and self._api_hashes:
            if _sha256_hex(api_key) in self._api_hashes:
                context = await continuation(handler_call_details)
                return _wrap_with_principal(context, f"api:{_sha256_hex(api_key)[:8]}", "api_key", {})
            context = await continuation(handler_call_details)
            return _wrap_denied(context, grpc.StatusCode.UNAUTHENTICATED, "api_key_invalid")

        # Нет валидной аутентификации
        context = await continuation(handler_call_details)
        return _wrap_denied(context, grpc.StatusCode.UNAUTHENTICATED, "auth_required")


def _wrap_with_principal(rpc_handler, sub: str, method: str, claims: Mapping[str, Any]):
    # Прокидываем principal в контекст через trailing metadata (для примера) и через context.set_trailing_metadata в хендлерах
    return rpc_handler


def _wrap_denied(rpc_handler, code: grpc.StatusCode, message: str):
    # Для unary-RPC перехватим позже внутри сервиса; здесь оставляем совместимость.
    return rpc_handler


# =================================================================================================
# In-memory хранилище и шина событий Evidence
# =================================================================================================

class EvidenceStore:
    """Интерфейс хранилища."""

    async def put_many(self, items: List[ep.Evidence]) -> List[str]:
        raise NotImplementedError

    async def get(self, evid: str) -> Optional[ep.Evidence]:
        raise NotImplementedError

    async def list(self, filt: Dict[str, Any], offset: int, limit: int) -> Tuple[List[ep.Evidence], Optional[int]]:
        raise NotImplementedError


class MemoryEvidenceStore(EvidenceStore):
    def __init__(self):
        self._data: Dict[str, ep.Evidence] = {}
        self._lock = asyncio.Lock()

    async def put_many(self, items: List[ep.Evidence]) -> List[str]:
        ids: List[str] = []
        async with self._lock:
            for it in items:
                eid = it.id or _gen_ulid()
                obj = ep.Evidence()
                obj.CopyFrom(it)
                obj.id = eid
                self._data[eid] = obj
                ids.append(eid)
        return ids

    async def get(self, evid: str) -> Optional[ep.Evidence]:
        async with self._lock:
            it = self._data.get(evid)
            if not it:
                return None
            out = ep.Evidence()
            out.CopyFrom(it)
            return out

    async def list(self, filt: Dict[str, Any], offset: int, limit: int) -> Tuple[List[ep.Evidence], Optional[int]]:
        async with self._lock:
            items = list(self._data.values())
        # Примитивные фильтры (тип, лейблы, префикс subject.uri)
        types = set(filt.get("types", []))
        if types:
            items = [x for x in items if x.type in types]
        sel = filt.get("labels", {})
        if sel:
            def label_match(e: ep.Evidence) -> bool:
                return all((k in e.labels and e.labels[k] == v) for k, v in sel.items())
            items = [x for x in items if label_match(x)]
        pref = filt.get("subject_prefix")
        if pref:
            items = [x for x in items if x.subject.uri.startswith(pref)]
        # Пагинация
        end = min(offset + limit, len(items))
        next_off = end if end < len(items) else None
        out = [ep.Evidence()] * (end - offset)
        out = []
        for e in items[offset:end]:
            cp = ep.Evidence()
            cp.CopyFrom(e)
            out.append(cp)
        return out, next_off


class EvidenceBus:
    """Простая шина событий для WatchEvidence."""

    def __init__(self):
        self._subs: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1024)
        async with self._lock:
            self._subs.append(q)
        return q

    async def publish(self, event: ep.EvidenceEvent):
        async with self._lock:
            qs = list(self._subs)
        for q in qs:
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(event)

    async def cleanup(self):
        async with self._lock:
            self._subs = [q for q in self._subs if not q.empty() or not q._finished.is_set()]  # best-effort


def _gen_ulid() -> str:
    # простой ULID-подобный идентификатор (монотонность не гарантируется, для продакшена используйте ulid/uuid7)
    return base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")


# =================================================================================================
# Реализация HealthService
# =================================================================================================

class HealthService(hpg.HealthServiceServicer):
    def __init__(self):
        super().__init__()

    async def Check(self, request: hp.HealthCheckRequest, context: ServicerContext) -> hp.HealthCheckResponse:
        t0 = time.perf_counter()
        try:
            build = hp.BuildInfo(
                version=CFG.build_version,
                git_commit=CFG.git_commit,
                git_branch=CFG.git_branch,
                build_tag=CFG.build_tag,
                platform=CFG.platform,
            )
            status = hp.ProbeStatus(
                status=hp.ServingStatus.SERVING_STATUS_SERVING,
                code=0,
                reason="ok",
                message="service is healthy",
            )
            resp = hp.HealthCheckResponse(service=request.service or "oblivionvault-core", probe=status, build=build)
            return resp
        finally:
            _observe("HealthService", "Check", t0)

    async def Watch(self, request: hp.WatchRequest, context: ServicerContext) -> AsyncIterator[hp.HealthCheckResponse]:
        interval = max(CFG.watch_interval_sec, (request.interval.seconds or 0) or CFG.watch_interval_sec)
        while True:
            yield await self.Check(request.check or hp.HealthCheckRequest(), context)
            await asyncio.sleep(interval)

    async def Liveness(self, request: hp.LivenessRequest, context: ServicerContext) -> hp.ProbeReply:
        t0 = time.perf_counter()
        try:
            return hp.ProbeReply(probe=hp.ProbeStatus(status=hp.ServingStatus.SERVING_STATUS_SERVING, code=0, reason="live"))
        finally:
            _observe("HealthService", "Liveness", t0)

    async def Readiness(self, request: hp.ReadinessRequest, context: ServicerContext) -> hp.ProbeReply:
        t0 = time.perf_counter()
        try:
            # Здесь могут быть реальные проверки зависимостей
            return hp.ProbeReply(probe=hp.ProbeStatus(status=hp.ServingStatus.SERVING_STATUS_SERVING, code=0, reason="ready"))
        finally:
            _observe("HealthService", "Readiness", t0)

    async def Startup(self, request: hp.StartupRequest, context: ServicerContext) -> hp.ProbeReply:
        t0 = time.perf_counter()
        try:
            return hp.ProbeReply(probe=hp.ProbeStatus(status=hp.ServingStatus.SERVING_STATUS_SERVING, code=0, reason="started"))
        finally:
            _observe("HealthService", "Startup", t0)

    async def Version(self, request, context) -> hp.BuildInfo:
        return hp.BuildInfo(
            version=CFG.build_version,
            git_commit=CFG.git_commit,
            git_branch=CFG.git_branch,
            build_tag=CFG.build_tag,
            platform=CFG.platform,
        )

    async def Dependencies(self, request: hp.DependenciesRequest, context: ServicerContext) -> hp.DependenciesResponse:
        # Пример: пока пусто; интегрируйте реальные статусы БД/кэшей/очередей
        return hp.DependenciesResponse(items=[], generated_at=_now_ts())

    async def Ping(self, request: hp.PingRequest, context: ServicerContext) -> hp.PongResponse:
        return hp.PongResponse(payload=request.payload, server_time=_now_ts(), trace_id=request.trace_id)

    async def Echo(self, request: hp.EchoRequest, context: ServicerContext) -> hp.EchoResponse:
        return hp.EchoResponse(message=request.message)

    async def Metrics(self, request: hp.MetricsRequest, context: ServicerContext) -> hp.MetricsResponse:
        if request.prometheus_text:
            content, ctype = _metrics_content()
            return hp.MetricsResponse(content=content, content_type=ctype, size_bytes=len(content))
        return hp.MetricsResponse(content=b"", content_type="application/octet-stream", size_bytes=0)


def _now_ts():
    from google.protobuf.timestamp_pb2 import Timestamp
    ts = Timestamp()
    ts.GetCurrentTime()
    return ts


def _observe(service: str, method: str, t0: float, code: str = "OK"):
    if PROM_OK and CFG.enable_metrics and RPC_LATENCY and RPC_COUNTER:
        RPC_LATENCY.labels(service=service, method=method).observe(time.perf_counter() - t0)


# =================================================================================================
# Реализация EvidenceService
# =================================================================================================

class EvidenceService(epg.EvidenceServiceServicer):
    def __init__(self, store: EvidenceStore, bus: EvidenceBus):
        self.store = store
        self.bus = bus
        self.attach_dir = Path(CFG.data_dir) / "attachments"
        self.attach_dir.mkdir(parents=True, exist_ok=True)

    # PutEvidence: атомарная запись пачки
    async def PutEvidence(self, request: ep.EvidenceBundle, context: ServicerContext) -> ep.PutEvidenceResponse:
        t0 = time.perf_counter()
        try:
            ids = await self.store.put_many(list(request.items))
            # публикуем события
            for eid in ids:
                ev = ep.EvidenceEvent(
                    type=ep.EvidenceEventType.EVIDENCE_EVENT_ADDED,
                    record=ep.EvidenceRecord(evidence=await self.store.get(eid), verification=ep.VerificationResult(status=ep.VerificationStatus.VERIF_STATUS_INCONCLUSIVE, evidence_id=eid)),
                )
                await self.bus.publish(ev)
            return ep.PutEvidenceResponse(ids=ids)
        finally:
            _observe("EvidenceService", "PutEvidence", t0)

    async def GetEvidence(self, request: ep.GetEvidenceRequest, context: ServicerContext) -> ep.EvidenceRecord:
        t0 = time.perf_counter()
        try:
            item = await self.store.get(request.id)
            if not item:
                await context.abort(grpc.StatusCode.NOT_FOUND, "evidence_not_found")
            # include_payload управляется на уровне Envelope: здесь просто возвращаем целиком
            return ep.EvidenceRecord(evidence=item, verification=ep.VerificationResult(status=ep.VerificationStatus.VERIF_STATUS_INCONCLUSIVE, evidence_id=item.id))
        finally:
            _observe("EvidenceService", "GetEvidence", t0)

    async def ListEvidence(self, request: ep.ListEvidenceRequest, context: ServicerContext) -> ep.ListEvidenceResponse:
        t0 = time.perf_counter()
        try:
            offset = _decode_page_token(request.page_token)
            limit = max(1, min(request.page_size or 100, 1000))
            filt = {
                "types": list(request.types),
                "labels": dict(request.label_selector),
                "subject_prefix": request.subject_uri_prefix or "",
            }
            items, next_off = await self.store.list(filt, offset, limit)
            recs = [ep.EvidenceRecord(evidence=e, verification=ep.VerificationResult(status=ep.VerificationStatus.VERIF_STATUS_INCONCLUSIVE, evidence_id=e.id)) for e in items]
            return ep.ListEvidenceResponse(records=recs, next_page_token=_encode_page_token(next_off))
        finally:
            _observe("EvidenceService", "ListEvidence", t0)

    async def WatchEvidence(self, request: ep.WatchEvidenceRequest, context: ServicerContext) -> AsyncIterator[ep.EvidenceEvent]:
        q = await self.bus.subscribe()
        try:
            while True:
                ev: ep.EvidenceEvent = await q.get()
                yield ev
        finally:
            with contextlib.suppress(Exception):
                await self.bus.cleanup()

    async def VerifyEvidence(self, request: ep.VerifyEvidenceRequest, context: ServicerContext) -> ep.VerifyEvidenceResponse:
        # Демонстрационная проверка целостности: наличие subject.digest
        results: List[ep.VerificationResult] = []
        targets: List[ep.Evidence] = []
        if request.HasField("id"):
            it = await self.store.get(request.id)
            if not it:
                await context.abort(grpc.StatusCode.NOT_FOUND, "evidence_not_found")
            targets = [it]
        elif request.HasField("bundle"):
            targets = list(request.bundle.items)
        for evi in targets:
            ok = bool(evi.subject.digests)
            status = ep.VerificationStatus.VERIF_STATUS_PASSED if ok else ep.VerificationStatus.VERIF_STATUS_INCONCLUSIVE
            results.append(ep.VerificationResult(evidence_id=evi.id or "", status=status, digest_matched=ok))
        return ep.VerifyEvidenceResponse(results=results)

    # Загрузка вложений потоками
    async def UploadAttachment(self, request_iterator, context: ServicerContext) -> ep.UploadAttachmentResponse:
        meta: Optional[ep.UploadAttachmentMetadata] = None
        tmp_path: Optional[Path] = None
        f = None
        try:
            async for chunk in request_iterator:
                if chunk.WhichOneof("msg") == "meta":
                    meta = chunk.meta
                    if not meta or not meta.artifact.uri:
                        await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "missing_artifact")
                    tmp_path = self._artifact_path(meta.artifact)
                    tmp_path.parent.mkdir(parents=True, exist_ok=True)
                    f = tmp_path.open("wb")
                else:
                    if f is None:
                        await context.abort(grpc.StatusCode.FAILED_PRECONDITION, "missing_meta")
                    f.write(chunk.data)
            if f:
                f.flush()
                f.close()
            if meta:
                stored = ep.ArtifactRef()
                stored.CopyFrom(meta.artifact)
                if not stored.size_bytes:
                    stored.size_bytes = tmp_path.stat().st_size if tmp_path and tmp_path.exists() else 0  # type: ignore
                return ep.UploadAttachmentResponse(stored=stored)
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "no_meta")
        finally:
            if f and not f.closed:
                f.close()

    async def DownloadAttachment(self, request: ep.DownloadAttachmentRequest, context: ServicerContext) -> AsyncIterator[ep.DownloadChunk]:
        path = self._artifact_path(request.artifact)
        if not path.exists():
            await context.abort(grpc.StatusCode.NOT_FOUND, "artifact_not_found")
        # Читаем чанками без копирования
        with path.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                yield ep.DownloadChunk(data=chunk)

    async def Attest(self, request: ep.AttestRequest, context: ServicerContext) -> ep.AttestResponse:
        # Минимальный конверт без подписи (интегрируйте KMS/PKI при необходимости)
        env = ep.Envelope(payload_type=request.payload_type or "application/octet-stream", payload=request.payload)
        return ep.AttestResponse(envelope=env)

    # Вспомогательные
    def _artifact_path(self, art: ep.ArtifactRef) -> Path:
        uri = art.uri
        if uri.startswith("file://"):
            p = uri[len("file://") :]
            return Path(p)
        # иначе складываем под data_dir по sha256(uri)
        name = hashlib.sha256(uri.encode()).hexdigest()
        return self.attach_dir / name


def _encode_page_token(offset: Optional[int]) -> str:
    if offset is None:
        return ""
    return base64.urlsafe_b64encode(str(offset).encode()).decode()


def _decode_page_token(token: str) -> int:
    if not token:
        return 0
    try:
        return int(base64.urlsafe_b64decode(token.encode()).decode())
    except Exception:
        return 0


# =================================================================================================
# Инициализация gRPC-сервера
# =================================================================================================

def _server_options() -> List[Tuple[str, Any]]:
    mbytes = CFG.max_message_mb
    return [
        ("grpc.max_concurrent_streams", CFG.max_concurrent_streams),
        ("grpc.max_receive_message_length", mbytes * 1024 * 1024),
        ("grpc.max_send_message_length", mbytes * 1024 * 1024),
        ("grpc.keepalive_time_ms", CFG.keepalive_time_ms),
        ("grpc.keepalive_timeout_ms", CFG.keepalive_timeout_ms),
        ("grpc.http2.min_time_between_pings_ms", CFG.keepalive_time_ms),
        ("grpc.http2.max_pings_without_data", 0),
    ]


def _ssl_credentials() -> Optional[grpc.ServerCredentials]:
    if not CFG.tls_cert_file or not CFG.tls_key_file:
        return None
    private_key = Path(CFG.tls_key_file).read_bytes()
    certificate_chain = Path(CFG.tls_cert_file).read_bytes()
    if CFG.tls_client_ca:
        root_certificates = Path(CFG.tls_client_ca).read_bytes()
        return grpc.ssl_server_credentials(
            ((private_key, certificate_chain),),
            root_certificates=root_certificates,
            require_client_auth=True,
        )
    return grpc.ssl_server_credentials(((private_key, certificate_chain),))


async def serve() -> None:
    interceptors: List[ServerInterceptor] = [AuthInterceptor(CFG)]
    server = grpc.aio.server(interceptors=interceptors, options=_server_options())

    # Реальные сервисы
    hpg.add_HealthServiceServicer_to_server(HealthService(), server)
    store = MemoryEvidenceStore()
    bus = EvidenceBus()
    epg.add_EvidenceServiceServicer_to_server(EvidenceService(store, bus), server)

    # gRPC health/reflection
    svc_names = [
        hpg.HealthService.SERVICE_NAME,
        epg.EvidenceService.SERVICE_NAME,
        grpc.reflection.v1alpha.reflection.SERVICE_NAME if REFL_OK else "",
        health_pb2.DESCRIPTOR.services_by_name["Health"].full_name if HEALTH_OK else "",
    ]
    if HEALTH_OK:
        health_servicer = health.HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
        for s in [hpg.HealthService.SERVICE_NAME, epg.EvidenceService.SERVICE_NAME]:
            health_servicer.set(s, health_pb2.HealthCheckResponse.SERVING)
    if REFL_OK:
        reflection.enable_server_reflection([s for s in svc_names if s], server)

    bind_addr = f"{CFG.host}:{CFG.port}"
    creds = _ssl_credentials()
    if creds:
        server.add_secure_port(bind_addr, creds)
    else:
        server.add_insecure_port(bind_addr)

    log.info("Starting gRPC server on %s TLS=%s", bind_addr, "on" if creds else "off")
    await server.start()

    # Плавное завершение
    stop_event = asyncio.Event()

    def _signal(*_):
        log.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _signal)

    await stop_event.wait()
    log.info("Stopping gRPC server...")
    await server.stop(grace=10.0)
    log.info("Stopped")


if __name__ == "__main__":
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
