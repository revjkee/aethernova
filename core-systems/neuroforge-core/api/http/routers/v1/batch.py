from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, AsyncIterator, Dict, Iterable, List, Mapping, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, conint, conlist, root_validator, validator

# Опциональные зависимости (без жёсткого требования инсталляции)
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None

try:
    # Если используете prometheus-client, метрики будут экспортироваться
    from prometheus_client import Counter, Histogram  # type: ignore

    _METRICS_ENABLED = True
    REQUESTS_TOTAL = Counter(
        "nf_batch_requests_total", "Total batch requests", ["route", "method", "code"]
    )
    ITEMS_TOTAL = Counter(
        "nf_batch_items_total", "Total items processed", ["route", "status"]
    )
    REQ_LATENCY = Histogram(
        "nf_batch_request_latency_seconds", "Batch request latency (s)", ["route"]
    )
except Exception:  # pragma: no cover
    _METRICS_ENABLED = False


logger = logging.getLogger("neuroforge.api.batch")
logger.setLevel(logging.INFO)


# ---------------------------
# МОДЕЛИ, совместимые с proto
# ---------------------------

class Priority(str, Enum):
    PRIORITY_UNSPECIFIED = "PRIORITY_UNSPECIFIED"
    PRIORITY_LOW = "PRIORITY_LOW"
    PRIORITY_NORMAL = "PRIORITY_NORMAL"
    PRIORITY_HIGH = "PRIORITY_HIGH"
    PRIORITY_CRITICAL = "PRIORITY_CRITICAL"


class Compression(str, Enum):
    COMPRESSION_UNSPECIFIED = "COMPRESSION_UNSPECIFIED"
    COMPRESSION_NONE = "COMPRESSION_NONE"
    COMPRESSION_GZIP = "COMPRESSION_GZIP"


class ContentType(str, Enum):
    CONTENT_TYPE_UNSPECIFIED = "CONTENT_TYPE_UNSPECIFIED"
    CONTENT_TYPE_TEXT = "CONTENT_TYPE_TEXT"
    CONTENT_TYPE_JSON = "CONTENT_TYPE_JSON"
    CONTENT_TYPE_BYTES = "CONTENT_TYPE_BYTES"
    CONTENT_TYPE_IMAGE = "CONTENT_TYPE_IMAGE"
    CONTENT_TYPE_AUDIO = "CONTENT_TYPE_AUDIO"


class KVMetadata(BaseModel):
    entries: Dict[str, str] = Field(default_factory=dict)


class TraceContext(BaseModel):
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_id: Optional[str] = None
    baggage: Dict[str, str] = Field(default_factory=dict)


class ModelSelector(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    version: Optional[str] = Field(None, max_length=128)
    tags: Dict[str, str] = Field(default_factory=dict)


class InferenceItem(BaseModel):
    item_id: str = Field(..., min_length=1, max_length=128)
    content_type: ContentType

    text: Optional[str] = None
    bytes_b64: Optional[str] = Field(
        None, description="Бинарные данные как base64, если использует bytes/image/audio"
    )
    json: Optional[Dict[str, Any]] = None

    features: Dict[str, Any] = Field(default_factory=dict)
    overrides: Dict[str, Any] = Field(default_factory=dict)
    metadata: KVMetadata = Field(default_factory=KVMetadata)

    @validator("text")
    def _text_strip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return v if len(v) <= 1_000_000 else v[:1_000_000]
        return v

    @root_validator
    def check_input_oneof(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        ct: ContentType = values.get("content_type")
        text, bytes_b64, json_obj = values.get("text"), values.get("bytes_b64"), values.get("json")
        provided = [x is not None for x in (text, bytes_b64, json_obj)]
        if sum(provided) != 1:
            raise ValueError("ровно одно из полей {text | bytes_b64 | json} должно быть задано")

        if ct == ContentType.CONTENT_TYPE_TEXT and text is None:
            raise ValueError("content_type=TEXT требует поле text")
        if ct == ContentType.CONTENT_TYPE_JSON and json_obj is None:
            raise ValueError("content_type=JSON требует поле json")
        if ct in (ContentType.CONTENT_TYPE_BYTES, ContentType.CONTENT_TYPE_IMAGE, ContentType.CONTENT_TYPE_AUDIO) and bytes_b64 is None:
            raise ValueError(f"content_type={ct} требует поле bytes_b64 (base64)")

        return values

    def materialize_bytes(self) -> Optional[bytes]:
        if self.bytes_b64 is None:
            return None
        try:
            return base64.b64decode(self.bytes_b64)
        except Exception as e:  # pragma: no cover
            raise HTTPException(status_code=400, detail=f"bytes_b64 decode error: {e}")


class ExecutionHints(BaseModel):
    priority: Priority = Priority.PRIORITY_NORMAL
    deadline_ms: Optional[conint(ge=1, le=3600_000)] = Field(
        None, description="Относительный дедлайн в мс (макс 1 час)"
    )
    max_concurrency: Optional[conint(ge=1, le=4096)] = None
    request_compression: Compression = Compression.COMPRESSION_NONE
    response_compression: Compression = Compression.COMPRESSION_NONE
    strict_ordering: bool = False
    allow_partial_results: bool = True


class BatchRequestModel(BaseModel):
    idempotency_key: Optional[str] = Field(None, max_length=200)
    model: ModelSelector
    items: conlist(InferenceItem, min_items=1, max_items=10_000)
    hints: ExecutionHints = Field(default_factory=ExecutionHints)
    metadata: KVMetadata = Field(default_factory=KVMetadata)
    trace: TraceContext = Field(default_factory=TraceContext)
    submit_time: Optional[datetime] = None
    tenant_id: Optional[str] = Field(None, max_length=200)

    @validator("submit_time", pre=True, always=True)
    def _default_submit_time(cls, v):
        return v or datetime.now(timezone.utc)


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ExecutionStats(BaseModel):
    latency_ms: int = 0
    queue_time_ms: int = 0
    compute_time_ms: int = 0
    cpu_seconds: float = 0.0
    gpu_seconds: float = 0.0
    memory_bytes: int = 0
    token_usage: Optional[TokenUsage] = None
    custom_metrics: Dict[str, float] = Field(default_factory=dict)


class RpcStatus(BaseModel):
    code: int = 0  # 0=OK, использовать коды gRPC/Google RPC при желании
    message: str = ""
    details: List[Dict[str, Any]] = Field(default_factory=list)


class InferenceResultModel(BaseModel):
    item_id: str
    index: int
    content_type: ContentType
    text: Optional[str] = None
    bytes_b64: Optional[str] = None
    json: Optional[Dict[str, Any]] = None
    annotations: Dict[str, Any] = Field(default_factory=dict)
    stats: ExecutionStats = Field(default_factory=ExecutionStats)
    error: Optional[RpcStatus] = None


class BatchResponseModel(BaseModel):
    idempotency_key: str
    results: List[InferenceResultModel]
    status: RpcStatus
    aggregate_stats: ExecutionStats
    started_at: datetime
    finished_at: datetime
    server_metadata: KVMetadata = Field(default_factory=KVMetadata)


# ---------------------------
# ПРОСТЕЙШИЙ RATE LIMIT
# ---------------------------

class _TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: int):
        self.rate = float(rate_per_sec)
        self.capacity = int(capacity)
        self.tokens = float(capacity)
        self.updated = time.monotonic()

    def allow(self, cost: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


_RATE_LIMITERS: Dict[str, _TokenBucket] = {}


async def rate_limit_dep(request: Request) -> None:
    # Ключ — по tenant_id, если есть, иначе IP
    tenant_id = request.headers.get("X-Tenant-ID") or "public"
    key = f"{tenant_id}:{request.client.host if request.client else 'unknown'}"
    limiter = _RATE_LIMITERS.get(key)
    if limiter is None:
        limiter = _TokenBucket(rate_per_sec=50.0, capacity=200)  # ~3000 rpm
        _RATE_LIMITERS[key] = limiter
    if not limiter.allow(cost=1):
        raise HTTPException(status_code=429, detail="rate limit exceeded")


# ---------------------------
# ИДЕМПОТЕНТНОСТЬ
# ---------------------------

class _IdemCacheEntry(BaseModel):
    expires_at: float
    response_json: str


_IDEMPOTENCY_CACHE: Dict[str, _IdemCacheEntry] = {}
_IDEM_TTL_SECONDS = 15 * 60  # 15 минут


def _cleanup_idem_cache() -> None:
    now = time.time()
    to_del = [k for k, v in _IDEMPOTENCY_CACHE.items() if v.expires_at <= now]
    for k in to_del:
        _IDEMPOTENCY_CACHE.pop(k, None)


def _make_idem_key(
    header_key: Optional[str], body_key: Optional[str], body_digest: str
) -> str:
    # Приоритет: заголовок -> поле в body -> digest тела
    if header_key:
        return f"h:{header_key}"
    if body_key:
        return f"b:{body_key}"
    return f"d:{body_digest}"


# ---------------------------
# ПРОВАЙДЕР ИНФЕРЕНСА (DI)
# ---------------------------

class BatchInferenceProvider:
    """
    Интерфейс провайдера инференса. Замените реализацией в проде.
    """

    async def infer_batch(
        self, req: BatchRequestModel, deadline: Optional[datetime]
    ) -> Iterable[InferenceResultModel]:
        raise NotImplementedError

    async def infer_batch_stream(
        self, req: BatchRequestModel, deadline: Optional[datetime]
    ) -> AsyncIterator[InferenceResultModel]:
        raise NotImplementedError


class EchoProvider(BatchInferenceProvider):
    """
    Демо-провайдер: эхо-ответ, только для smoke-тестов.
    """

    async def infer_batch(
        self, req: BatchRequestModel, deadline: Optional[datetime]
    ) -> Iterable[InferenceResultModel]:
        started_compute = time.monotonic()
        results: List[InferenceResultModel] = []
        for idx, it in enumerate(req.items):
            if deadline and datetime.now(timezone.utc) > deadline:
                results.append(
                    InferenceResultModel(
                        item_id=it.item_id,
                        index=idx,
                        content_type=it.content_type,
                        error=RpcStatus(code=4, message="deadline exceeded"),
                    )
                )
                continue

            out_ct = it.content_type
            text, jb, jo = None, None, None
            if it.text is not None:
                text = it.text  # эхо
            elif it.json is not None:
                jo = {"echo": it.json}
            else:
                jb = it.bytes_b64

            results.append(
                InferenceResultModel(
                    item_id=it.item_id,
                    index=idx,
                    content_type=out_ct,
                    text=text,
                    bytes_b64=jb,
                    json=jo,
                    stats=ExecutionStats(
                        latency_ms=int((time.monotonic() - started_compute) * 1000)
                    ),
                )
            )
        return results

    async def infer_batch_stream(
        self, req: BatchRequestModel, deadline: Optional[datetime]
    ) -> AsyncIterator[InferenceResultModel]:
        # Стримим элементы по мере готовности
        async def _gen():
            for idx, it in enumerate(req.items):
                await asyncio.sleep(0)  # уступить цикл
                if deadline and datetime.now(timezone.utc) > deadline:
                    yield InferenceResultModel(
                        item_id=it.item_id,
                        index=idx,
                        content_type=it.content_type,
                        error=RpcStatus(code=4, message="deadline exceeded"),
                    )
                    continue
                if it.text is not None:
                    yield InferenceResultModel(
                        item_id=it.item_id,
                        index=idx,
                        content_type=it.content_type,
                        text=it.text,
                    )
                elif it.json is not None:
                    yield InferenceResultModel(
                        item_id=it.item_id,
                        index=idx,
                        content_type=it.content_type,
                        json={"echo": it.json},
                    )
                else:
                    yield InferenceResultModel(
                        item_id=it.item_id,
                        index=idx,
                        content_type=it.content_type,
                        bytes_b64=it.bytes_b64,
                    )

        async for r in _gen():
            yield r


async def get_provider(request: Request) -> BatchInferenceProvider:
    # В проде внедрите свой провайдер через app.state.batch_provider
    provider = getattr(request.app.state, "batch_provider", None)
    if isinstance(provider, BatchInferenceProvider):
        return provider
    return EchoProvider()


# ---------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ---------------------------

def _digest_body(obj: Mapping[str, Any]) -> str:
    m = hashlib.sha256()
    m.update(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return m.hexdigest()


def _calc_deadline(hints: ExecutionHints) -> Optional[datetime]:
    if hints.deadline_ms:
        dl = datetime.now(timezone.utc) + timedelta(milliseconds=int(hints.deadline_ms))
        return dl
    return None


def _aggregate_status(results: List[InferenceResultModel], allow_partial: bool) -> RpcStatus:
    any_error = any(r.error for r in results)
    all_error = all(r.error for r in results)
    if not any_error:
        return RpcStatus(code=0, message="OK")
    if allow_partial and not all_error:
        return RpcStatus(code=0, message="PARTIAL_OK")
    # Возьмём первую ошибку как агрегат
    first_err = next(r.error for r in results if r.error is not None)
    return RpcStatus(code=first_err.code, message=first_err.message, details=first_err.details)


def _aggregate_stats(results: List[InferenceResultModel]) -> ExecutionStats:
    lat = sum(r.stats.latency_ms for r in results if r.stats)
    mem = sum(r.stats.memory_bytes for r in results if r.stats)
    cpu = sum(r.stats.cpu_seconds for r in results if r.stats)
    gpu = sum(r.stats.gpu_seconds for r in results if r.stats)
    return ExecutionStats(
        latency_ms=lat,
        memory_bytes=mem,
        cpu_seconds=cpu,
        gpu_seconds=gpu,
    )


def _trace_span(name: str):
    class _SpanCtx:
        def __init__(self, name_: str):
            self.name = name_
            self.span = None

        def __enter__(self):
            if _tracer:
                self.span = _tracer.start_span(self.name)
            return self

        def __exit__(self, exc_type, exc, tb):
            if self.span:
                self.span.end()

    return _SpanCtx(name)


# ---------------------------
# РОУТЕР
# ---------------------------

router = APIRouter(prefix="/v1/batch", tags=["batch"])


@router.post(
    "/infer",
    response_model=BatchResponseModel,
    responses={
        200: {"description": "Успешный батч-инференс"},
        400: {"description": "Неверный запрос"},
        401: {"description": "Неавторизовано"},
        403: {"description": "Доступ запрещён"},
        409: {"description": "Конфликт идемпотентности"},
        413: {"description": "Слишком большой запрос"},
        429: {"description": "Превышен лимит запросов"},
        500: {"description": "Внутренняя ошибка"},
    },
)
async def batch_infer(
    request: Request,
    body: BatchRequestModel,
    background: BackgroundTasks,
    provider: BatchInferenceProvider = Depends(get_provider),
    _rl: None = Depends(rate_limit_dep),
    idem_key_header: Optional[str] = Header(None, alias="Idempotency-Key"),
) -> JSONResponse:
    """
    Синхронная обработка батча. Возвращает весь результат целиком.
    Идемпотентность: заголовок Idempotency-Key или body.idempotency_key, иначе digest тела.
    """
    if len(body.items) > 10000:
        raise HTTPException(status_code=413, detail="too many items")

    body_digest = _digest_body(json.loads(request._body if hasattr(request, "_body") else json.dumps(body.dict(by_alias=True, exclude_none=True))))
    idem_key = _make_idem_key(idem_key_header, body.idempotency_key, body_digest)

    _cleanup_idem_cache()
    cached = _IDEMPOTENCY_CACHE.get(idem_key)
    if cached and cached.expires_at > time.time():
        if _METRICS_ENABLED:
            REQUESTS_TOTAL.labels("/v1/batch/infer", "POST", "200").inc()
        return JSONResponse(status_code=200, content=json.loads(cached.response_json))

    with _trace_span("batch_infer"):
        started_at = datetime.now(timezone.utc)
        req_start = time.monotonic()

        deadline = _calc_deadline(body.hints)
        try:
            results_list = list(await provider.infer_batch(body, deadline))
        except HTTPException:
            raise
        except Exception as e:  # pragma: no cover
            logger.exception("infer_batch failed: %s", e)
            raise HTTPException(status_code=500, detail="inference provider error")

        # Сортировка при strict_ordering
        if body.hints.strict_ordering:
            by_index = sorted(results_list, key=lambda r: r.index)
            results_list = by_index

        status_model = _aggregate_status(results_list, body.hints.allow_partial_results)
        agg_stats = _aggregate_stats(results_list)
        finished_at = datetime.now(timezone.utc)

        response_payload = BatchResponseModel(
            idempotency_key=idem_key,
            results=results_list,
            status=status_model,
            aggregate_stats=agg_stats,
            started_at=started_at,
            finished_at=finished_at,
            server_metadata=KVMetadata(
                entries={
                    "service": "neuroforge-core",
                    "route": "/v1/batch/infer",
                    "version": "1",
                }
            ),
        )

        if _METRICS_ENABLED:
            REQUESTS_TOTAL.labels("/v1/batch/infer", "POST", "200").inc()
            ITEMS_TOTAL.labels("/v1/batch/infer", "ok" if status_model.code == 0 else "error").inc(len(results_list))
            REQ_LATENCY.labels("/v1/batch/infer").observe(time.monotonic() - req_start)

        # Кэш идемпотентности
        _IDEMPOTENCY_CACHE[idem_key] = _IdemCacheEntry(
            expires_at=time.time() + _IDEM_TTL_SECONDS,
            response_json=response_payload.json(by_alias=True),
        )

        return JSONResponse(status_code=200, content=json.loads(response_payload.json()))


@router.post(
    "/infer/stream",
    responses={
        200: {"description": "Стриминговый батч-инференс (NDJSON)"},
        400: {"description": "Неверный запрос"},
        401: {"description": "Неавторизовано"},
        403: {"description": "Доступ запрещён"},
        409: {"description": "Конфликт идемпотентности"},
        413: {"description": "Слишком большой запрос"},
        429: {"description": "Превышен лимит запросов"},
        500: {"description": "Внутренняя ошибка"},
    },
)
async def batch_infer_stream(
    request: Request,
    body: BatchRequestModel,
    provider: BatchInferenceProvider = Depends(get_provider),
    _rl: None = Depends(rate_limit_dep),
    idem_key_header: Optional[str] = Header(None, alias="Idempotency-Key"),
) -> StreamingResponse:
    """
    Стриминговая обработка: NDJSON (application/x-ndjson).
    Каждая строка — объект с полем "result" или "progress" или "terminal_status".
    """
    if len(body.items) > 10000:
        raise HTTPException(status_code=413, detail="too many items")

    body_digest = _digest_body(body.dict(by_alias=True, exclude_none=True))
    idem_key = _make_idem_key(idem_key_header, body.idempotency_key, body_digest)

    with _trace_span("batch_infer_stream"):
        started_at = datetime.now(timezone.utc)
        deadline = _calc_deadline(body.hints)

        async def _gen() -> AsyncIterator[bytes]:
            try:
                idx_count = 0
                async for res in provider.infer_batch_stream(body, deadline):
                    idx_count += 1
                    frame = {"result": json.loads(res.json(exclude_none=True))}
                    yield (json.dumps(frame, separators=(",", ":")) + "\n").encode("utf-8")
                # Финальный статус
                aggregate = RpcStatus(code=0, message="OK")
                tail = {
                    "terminal_status": json.loads(aggregate.json()),
                    "started_at": started_at.isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "idempotency_key": idem_key,
                    "count": idx_count,
                }
                yield (json.dumps(tail, separators=(",", ":")) + "\n").encode("utf-8")
            except HTTPException as he:
                err = {"terminal_status": {"code": he.status_code, "message": he.detail}}
                yield (json.dumps(err, separators=(",", ":")) + "\n").encode("utf-8")
            except Exception as e:  # pragma: no cover
                logger.exception("infer_batch_stream failed: %s", e)
                err = {"terminal_status": {"code": 13, "message": "internal error"}}
                yield (json.dumps(err, separators=(",", ":")) + "\n").encode("utf-8")

        return StreamingResponse(
            _gen(), media_type="application/x-ndjson", status_code=200
        )


# ---------------------------
# ОБРАБОТЧИКИ ОШИБОК (опционально)
# ---------------------------

@router.exception_handler(HTTPException)  # type: ignore[arg-type]
async def http_exc_handler(_request: Request, exc: HTTPException):
    if _METRICS_ENABLED:
        REQUESTS_TOTAL.labels(_request.url.path, _request.method, str(exc.status_code)).inc()
    payload = {
        "status": {
            "code": exc.status_code,
            "message": exc.detail if isinstance(exc.detail, str) else "error",
            "details": [],
        }
    }
    return JSONResponse(status_code=exc.status_code, content=payload)


# ---------------------------
# ПРИМЕЧАНИЯ ПО ВКЛЮЧЕНИЮ РОУТЕРА:
# ---------------------------
# В вашем FastAPI приложении:
#
#   from fastapi import FastAPI
#   from neuroforge_core.api.http.routers.v1.batch import router as batch_router
#
#   app = FastAPI()
#   app.include_router(batch_router)
#
#   # В продакшене внедрите свой провайдер:
#   app.state.batch_provider = YourProductionProvider(...)
#
# Тесты могут подменять app.state.batch_provider на заглушку.
