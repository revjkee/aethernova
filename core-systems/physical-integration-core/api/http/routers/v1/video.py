from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, HttpUrl, conint, constr, validator

# Optional S3 clients
try:
    import aioboto3  # type: ignore
except Exception:  # pragma: no cover
    aioboto3 = None  # type: ignore

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore

# Optional Redis for idempotency/materialized responses
try:
    from redis.asyncio import Redis  # type: ignore
except Exception:  # pragma: no cover
    Redis = None  # type: ignore

# Prometheus metrics (no-op fallback if unavailable)
try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_): return
        def observe(self, *_): return
    Counter = Histogram = _Noop  # type: ignore


# ---------------------------------------------------------------------------
# Константы/настройки окружения
# ---------------------------------------------------------------------------

API_BEARER_TOKEN = os.getenv("API_BEARER_TOKEN", "")
API_KEYS = set([k.strip() for k in os.getenv("API_KEYS", "").split(",") if k.strip()])
REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "eu-north-1"))
VOD_INGEST_BUCKET = os.getenv("VOD_INGEST_BUCKET", "")
CDN_PUBLIC_BASE = os.getenv("CDN_PUBLIC_BASE", "")  # например, https://dXXXX.cloudfront.net
PRESIGN_EXPIRES_DEFAULT = int(os.getenv("PRESIGN_EXPIRES_DEFAULT", "900"))  # 15 мин
IDEMPOTENCY_TTL = int(os.getenv("IDEMPOTENCY_TTL", "600"))  # 10 мин
ALLOW_WEAK_ETAG = os.getenv("ALLOW_WEAK_ETAG", "false").lower() == "true"

logger = logging.getLogger("video_router")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Метрики
# ---------------------------------------------------------------------------

M_REQ = Counter("video_http_requests_total", "Video API requests", ["route", "method", "code"])
M_IDEMP = Counter("video_idempotent_hits_total", "Idempotency key hits", ["route", "result"])
M_PRESIGN = Counter("video_presign_total", "Presigned URL generation", ["bucket"])
H_LAT = Histogram("video_http_latency_seconds", "Latency seconds", ["route", "method"])


# ---------------------------------------------------------------------------
# Безопасность (Bearer или X-API-Key)
# ---------------------------------------------------------------------------

bearer_scheme = HTTPBearer(auto_error=False)
x_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class Principal(BaseModel):
    subject: str
    method: Literal["bearer", "api_key", "anonymous"]


async def auth_dependency(
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    api_key: Optional[str] = Depends(x_api_key_header),
) -> Principal:
    if cred and API_BEARER_TOKEN and cred.scheme.lower() == "bearer" and cred.credentials == API_BEARER_TOKEN:
        return Principal(subject="service:bearer", method="bearer")
    if api_key and api_key in API_KEYS:
        return Principal(subject=f"api_key:{hashlib.sha256(api_key.encode()).hexdigest()[:12]}", method="api_key")
    # Разрешаем анонимный доступ только для безопасных GET (будет проверено на уровне эндпоинтов)
    return Principal(subject="anonymous", method="anonymous")


# ---------------------------------------------------------------------------
# Доменные модели
# ---------------------------------------------------------------------------

StreamMode = Literal["live", "vod"]
LatencyProfile = Literal["ultra_low", "low", "standard"]
ManifestVariant = Literal["hls", "dash", "cmaf"]
StreamState = Literal["starting", "running", "stopping", "stopped", "failed"]

NameStr = constr(regex=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$")
KeyStr = constr(regex=r"^[a-zA-Z0-9/_.\-]{1,512}$")
ContentTypeStr = constr(regex=r"^[\w.\-+/]+$")


class StreamCreateRequest(BaseModel):
    name: NameStr = Field(..., description="Логическое имя стрима")
    mode: StreamMode = Field("live")
    latency: LatencyProfile = Field("low")
    description: Optional[constr(max_length=512)] = None
    ingest_protocols: List[Literal["SRT", "RTMP", "KINESIS"]] = Field(default_factory=lambda: ["SRT"])

    @validator("ingest_protocols")
    def validate_protocols(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("ingest_protocols must not be empty")
        return v


class StreamResource(BaseModel):
    stream_id: str
    name: str
    mode: StreamMode
    state: StreamState
    created_at: int = Field(..., description="epoch millis")
    ingest: Dict[str, Any] = Field(default_factory=dict)  # URLs/endpoints
    etag: str


class StreamsPage(BaseModel):
    items: List[StreamResource]
    next_offset: Optional[int] = None


class UploadUrlRequest(BaseModel):
    asset_name: NameStr
    content_type: ContentTypeStr
    size_bytes: conint(gt=0, le=256 * 1024 * 1024 * 1024)  # до 256 ГБ
    prefix: Optional[constr(regex=r"^[a-zA-Z0-9/_.\-]{0,128}$")] = Field(
        default="incoming/", description="Префикс ключа в бакете"
    )
    expires_seconds: conint(gt=60, le=24 * 3600) = PRESIGN_EXPIRES_DEFAULT
    storage_class: Optional[Literal["STANDARD", "STANDARD_IA", "ONEZONE_IA"]] = "STANDARD"


class UploadUrlResponse(BaseModel):
    method: Literal["PUT"] = "PUT"
    url: HttpUrl
    headers: Dict[str, str]
    key: str
    expires_at: int


class AssetFinalizeRequest(BaseModel):
    asset_id: NameStr
    source_key: KeyStr
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetResource(BaseModel):
    asset_id: str
    status: Literal["queued", "accepted"]
    locations: Dict[str, str] = Field(default_factory=dict)
    etag: str


class ManifestUrlRequest(BaseModel):
    asset_id: NameStr
    variant: ManifestVariant = "hls"
    expires_seconds: conint(gt=60, le=24 * 3600) = PRESIGN_EXPIRES_DEFAULT


class ManifestUrlResponse(BaseModel):
    url: HttpUrl
    expires_at: int


# ---------------------------------------------------------------------------
# Внутренние сервисы: потоки, идемпотентность, S3
# ---------------------------------------------------------------------------

@dataclass
class _Stream:
    id: str
    name: str
    mode: StreamMode
    state: StreamState
    created_at: int
    ingest: Dict[str, Any]


class _StreamsRegistry:
    """Потокобезопасный in-memory реестр стримов (для контроллера уровня API)."""

    def __init__(self) -> None:
        self._items: Dict[str, _Stream] = {}
        self._lock = asyncio.Lock()

    async def create(self, name: str, mode: StreamMode, ingest: Dict[str, Any]) -> _Stream:
        async with self._lock:
            sid = uuid.uuid4().hex
            now = int(time.time() * 1000)
            st = _Stream(id=sid, name=name, mode=mode, state="starting", created_at=now, ingest=ingest)
            self._items[sid] = st
            return st

    async def set_state(self, sid: str, state: StreamState) -> None:
        async with self._lock:
            if sid in self._items:
                self._items[sid].state = state

    async def get(self, sid: str) -> Optional[_Stream]:
        return self._items.get(sid)

    async def list(self, offset: int, limit: int) -> Tuple[List[_Stream], Optional[int]]:
        items = list(self._items.values())
        items.sort(key=lambda x: x.created_at, reverse=True)
        slice_ = items[offset : offset + limit]
        next_off = offset + limit if offset + limit < len(items) else None
        return slice_, next_off

    async def stop(self, sid: str) -> bool:
        async with self._lock:
            st = self._items.get(sid)
            if not st:
                return False
            st.state = "stopping"
            # В реальности — сигнал оркестратору/пайплайну; здесь — сразу остановка
            st.state = "stopped"
            return True


class _IdempotencyStore:
    """Простой материализованный кэш результатов по Idempotency-Key с TTL; опционально Redis."""

    def __init__(self, ttl_seconds: int = IDEMPOTENCY_TTL, redis: Optional[Redis] = None) -> None:  # type: ignore
        self.ttl = ttl_seconds
        self.redis = redis
        self._mem: Dict[str, Tuple[int, bytes]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[bytes]:
        if self.redis:
            try:
                v = await self.redis.get(self._rk(key))  # type: ignore
                return v if v else None
            except Exception:
                pass
        # in-memory fallback
        async with self._lock:
            rec = self._mem.get(key)
            if not rec:
                return None
            ts, data = rec
            if (time.time() - ts) > self.ttl:
                self._mem.pop(key, None)
                return None
            return data

    async def set(self, key: str, payload: bytes) -> None:
        if self.redis:
            try:
                await self.redis.set(self._rk(key), payload, ex=self.ttl)  # type: ignore
                return
            except Exception:
                pass
        async with self._lock:
            self._mem[key] = (int(time.time()), payload)

    @staticmethod
    def _rk(key: str) -> str:
        return f"idemp:{hashlib.sha256(key.encode()).hexdigest()}"


class _S3Client:
    """Упрощённый фасад для формирования presigned URL (PUT)."""

    def __init__(self, region: str) -> None:
        self.region = region

    async def presign_put(
        self,
        bucket: str,
        key: str,
        content_type: str,
        expires_seconds: int,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        params = {
            "Bucket": bucket,
            "Key": key,
            "ContentType": content_type,
        }
        headers = headers or {}
        if aioboto3:
            session = aioboto3.Session(region_name=self.region)
            async with session.client("s3", region_name=self.region) as s3:  # type: ignore
                return await s3.generate_presigned_url(
                    ClientMethod="put_object",
                    Params=params,
                    ExpiresIn=expires_seconds,
                    HttpMethod="PUT",
                )
        if boto3:
            def _gen() -> str:
                client = boto3.client("s3", region_name=self.region)  # type: ignore
                return client.generate_presigned_url(
                    ClientMethod="put_object",
                    Params=params,
                    ExpiresIn=expires_seconds,
                    HttpMethod="PUT",
                )
            return await asyncio.to_thread(_gen)
        raise HTTPException(status_code=503, detail="S3 client libraries are not available")


# ---------------------------------------------------------------------------
# Инициализация сервисов/роутера
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/video", tags=["video"])

_registry = _StreamsRegistry()
_idemp = _IdempotencyStore(
    ttl_seconds=IDEMPOTENCY_TTL,
    redis=None if Redis is None else None,  # при желании можно подключить Redis-клиент
)
_s3 = _S3Client(region=REGION)


# ---------------------------------------------------------------------------
# Вспомогательные утилиты
# ---------------------------------------------------------------------------

def _etag_for(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    h = hashlib.sha256(raw).hexdigest()
    return f'W/"{h}"' if ALLOW_WEAK_ETAG else f'"{h}"'


def _ensure_auth_read(principal: Principal, allow_anonymous: bool = True) -> None:
    if allow_anonymous and principal.method in ("bearer", "api_key", "anonymous"):
        return
    if not allow_anonymous and principal.method not in ("bearer", "api_key"):
        raise HTTPException(status_code=401, detail="Authentication required")


def _require_auth_write(principal: Principal) -> None:
    if principal.method not in ("bearer", "api_key"):
        raise HTTPException(status_code=401, detail="Authentication required")


def _route_label(request: Request) -> str:
    # для метрик/логов: простая нормализация пути
    return request.url.path.replace("/", "_").strip("_") or "root"


# ---------------------------------------------------------------------------
# Эндпоинты
# ---------------------------------------------------------------------------

@router.post(
    "/streams",
    response_model=StreamResource,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"description": "Duplicate (idempotency)"}},
)
async def create_stream(
    body: StreamCreateRequest,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    principal: Principal = Depends(auth_dependency),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    _require_auth_write(principal)
    route = _route_label(request)
    t0 = time.time()

    # Идемпотентность: если ключ есть и ранее фиксировали результат — вернём его
    if idempotency_key:
        cached = await _idemp.get(idempotency_key)
        if cached:
            M_IDEMP.labels(route=route, result="hit").inc()
            payload = json.loads(cached.decode())
            response.headers["ETag"] = payload.get("etag", "")
            response.status_code = status.HTTP_200_OK
            M_REQ.labels(route=route, method="POST", code="200").inc()
            H_LAT.labels(route=route, method="POST").observe(time.time() - t0)
            return payload
    else:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")

    # Синтез параметров ingest (в реальности — из оркестратора)
    ingest: Dict[str, Any] = {}
    if "SRT" in body.ingest_protocols:
        ingest["srt_listener"] = f"srt://0.0.0.0:10{int(time.time())%100:02d}?mode=listener&latency=50"
    if "RTMP" in body.ingest_protocols:
        ingest["rtmp"] = f"rtmp://ingest.local/live/{body.name}"
    if "KINESIS" in body.ingest_protocols:
        ingest["kinesis_stream"] = f"arn:aws:kinesisvideo:{REGION}:000000000000:stream/{body.name}/123456789"

    st = await _registry.create(name=body.name, mode=body.mode, ingest=ingest)
    # Имитация запуска в фоне
    background.add_task(_registry.set_state, st.id, "running")

    resource = StreamResource(
        stream_id=st.id,
        name=st.name,
        mode=st.mode,
        state=st.state,
        created_at=st.created_at,
        ingest=st.ingest,
        etag=_etag_for({"id": st.id, "ts": st.created_at}),
    )
    response.headers["ETag"] = resource.etag

    # Кешируем материализованный результат под Idempotency-Key
    await _idemp.set(idempotency_key, json.dumps(resource.dict()).encode())

    response.headers["Location"] = f"/api/v1/video/streams/{st.id}"
    M_IDEMP.labels(route=route, result="store").inc()
    M_REQ.labels(route=route, method="POST", code="201").inc()
    H_LAT.labels(route=route, method="POST").observe(time.time() - t0)
    return resource


@router.get(
    "/streams",
    response_model=StreamsPage,
)
async def list_streams(
    request: Request,
    response: Response,
    principal: Principal = Depends(auth_dependency),
    offset: conint(ge=0) = Query(0),
    limit: conint(gt=0, le=100) = Query(20),
):
    _ensure_auth_read(principal, allow_anonymous=True)
    route = _route_label(request)
    t0 = time.time()

    items, next_off = await _registry.list(offset=offset, limit=limit)
    resources = [
        StreamResource(
            stream_id=i.id,
            name=i.name,
            mode=i.mode,
            state=i.state,
            created_at=i.created_at,
            ingest=i.ingest,
            etag=_etag_for({"id": i.id, "ts": i.created_at, "state": i.state}),
        )
        for i in items
    ]
    page = StreamsPage(items=resources, next_offset=next_off)

    # ETag на страницу
    response.headers["ETag"] = _etag_for([r.etag for r in resources])
    if next_off is not None:
        response.headers["X-Next-Offset"] = str(next_off)

    M_REQ.labels(route=route, method="GET", code="200").inc()
    H_LAT.labels(route=route, method="GET").observe(time.time() - t0)
    return page


@router.get(
    "/streams/{stream_id}",
    response_model=StreamResource,
)
async def get_stream(
    stream_id: constr(regex=r"^[0-9a-f]{32}$") = Path(...),
    request: Request = None,
    response: Response = None,
    principal: Principal = Depends(auth_dependency),
):
    _ensure_auth_read(principal, allow_anonymous=True)
    route = _route_label(request)
    t0 = time.time()

    st = await _registry.get(stream_id)
    if not st:
        raise HTTPException(status_code=404, detail="Stream not found")

    res = StreamResource(
        stream_id=st.id,
        name=st.name,
        mode=st.mode,
        state=st.state,
        created_at=st.created_at,
        ingest=st.ingest,
        etag=_etag_for({"id": st.id, "state": st.state, "ts": st.created_at}),
    )
    response.headers["ETag"] = res.etag

    M_REQ.labels(route=route, method="GET", code="200").inc()
    H_LAT.labels(route=route, method="GET").observe(time.time() - t0)
    return res


@router.post(
    "/streams/{stream_id}:stop",
    status_code=status.HTTP_202_ACCEPTED,
)
async def stop_stream(
    stream_id: constr(regex=r"^[0-9a-f]{32}$") = Path(...),
    request: Request = None,
    principal: Principal = Depends(auth_dependency),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    _require_auth_write(principal)
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")
    route = _route_label(request)
    t0 = time.time()

    cached = await _idemp.get(idempotency_key)
    if cached:
        M_IDEMP.labels(route=route, result="hit").inc()
        M_REQ.labels(route=route, method="POST", code="200").inc()
        H_LAT.labels(route=route, method="POST").observe(time.time() - t0)
        return json.loads(cached.decode())

    ok = await _registry.stop(stream_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Stream not found")

    payload = {"status": "accepted", "stream_id": stream_id}
    await _idemp.set(idempotency_key, json.dumps(payload).encode())

    M_IDEMP.labels(route=route, result="store").inc()
    M_REQ.labels(route=route, method="POST", code="202").inc()
    H_LAT.labels(route=route, method="POST").observe(time.time() - t0)
    return payload


@router.post(
    "/assets/upload-url",
    response_model=UploadUrlResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_presigned_upload(
    body: UploadUrlRequest,
    request: Request,
    response: Response,
    principal: Principal = Depends(auth_dependency),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    _require_auth_write(principal)
    if not VOD_INGEST_BUCKET:
        raise HTTPException(status_code=503, detail="VOD ingest bucket is not configured")

    route = _route_label(request)
    t0 = time.time()

    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")

    cached = await _idemp.get(idempotency_key)
    if cached:
        M_IDEMP.labels(route=route, result="hit").inc()
        payload = json.loads(cached.decode())
        response.headers["ETag"] = payload.get("etag", "")
        response.status_code = status.HTTP_200_OK
        M_REQ.labels(route=route, method="POST", code="200").inc()
        H_LAT.labels(route=route, method="POST").observe(time.time() - t0)
        return payload

    # Генерация ключа: prefix + безопасное имя
    key = f"{body.prefix or ''}{body.asset_name}-{uuid.uuid4().hex}.bin"
    url = await _s3.presign_put(
        bucket=VOD_INGEST_BUCKET,
        key=key,
        content_type=body.content_type,
        expires_seconds=body.expires_seconds,
    )
    expires_at = int(time.time()) + int(body.expires_seconds)
    resp = UploadUrlResponse(
        url=url,
        headers={"Content-Type": body.content_type, "x-amz-server-side-encryption": "aws:kms"},
        key=key,
        expires_at=expires_at,
    )
    etag = _etag_for(resp.dict())
    response.headers["ETag"] = etag
    M_PRESIGN.labels(bucket=VOD_INGEST_BUCKET).inc()

    await _idemp.set(idempotency_key, json.dumps({**resp.dict(), "etag": etag}).encode())

    M_IDEMP.labels(route=route, result="store").inc()
    M_REQ.labels(route=route, method="POST", code="201").inc()
    H_LAT.labels(route=route, method="POST").observe(time.time() - t0)
    return resp


@router.post(
    "/assets",
    response_model=AssetResource,
    status_code=status.HTTP_202_ACCEPTED,
)
async def finalize_asset(
    body: AssetFinalizeRequest,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    principal: Principal = Depends(auth_dependency),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    _require_auth_write(principal)
    route = _route_label(request)
    t0 = time.time()

    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")

    cached = await _idemp.get(idempotency_key)
    if cached:
        M_IDEMP.labels(route=route, result="hit").inc()
        payload = json.loads(cached.decode())
        response.headers["ETag"] = payload.get("etag", "")
        response.status_code = status.HTTP_200_OK
        M_REQ.labels(route=route, method="POST", code="200").inc()
        H_LAT.labels(route=route, method="POST").observe(time.time() - t0)
        return payload

    # В проде: валидация существования объекта в S3, постановка задачи в оркестратор
    asset = AssetResource(
        asset_id=body.asset_id,
        status="queued",
        locations={"source": f"s3://{VOD_INGEST_BUCKET}/{body.source_key}"},
        etag=_etag_for({"asset": body.asset_id, "key": body.source_key}),
    )
    response.headers["ETag"] = asset.etag

    # Имитируем постановку работы в фоне
    background.add_task(lambda: None)

    await _idemp.set(idempotency_key, json.dumps(asset.dict()).encode())

    M_IDEMP.labels(route=route, result="store").inc()
    M_REQ.labels(route=route, method="POST", code="202").inc()
    H_LAT.labels(route=route, method="POST").observe(time.time() - t0)
    return asset


@router.post(
    "/manifests",
    response_model=ManifestUrlResponse,
)
async def get_manifest_url(
    body: ManifestUrlRequest,
    request: Request,
    response: Response,
    principal: Principal = Depends(auth_dependency),
):
    _ensure_auth_read(principal, allow_anonymous=True)
    route = _route_label(request)
    t0 = time.time()

    if not CDN_PUBLIC_BASE:
        raise HTTPException(status_code=503, detail="CDN base is not configured")

    ext = "m3u8" if body.variant == "hls" else "mpd"
    path = f"/vod/{body.asset_id}/master.{ext}"
    # Подписывание URL — зависит от провайдера; здесь базовый k=v токен (пример)
    exp = int(time.time()) + int(body.expires_seconds)
    token_raw = f"{body.asset_id}:{exp}:{os.getenv('CDN_SIGNING_SECRET','')}".encode()
    sig = base64.urlsafe_b64encode(hashlib.sha256(token_raw).digest()).decode().rstrip("=")
    url = f"{CDN_PUBLIC_BASE}{path}?exp={exp}&sig={sig}"
    resp = ManifestUrlResponse(url=url, expires_at=exp)

    response.headers["ETag"] = _etag_for(resp.dict())

    M_REQ.labels(route=route, method="POST", code="200").inc()
    H_LAT.labels(route=route, method="POST").observe(time.time() - t0)
    return resp
