# neuroforge-core/api/http/routers/v1/infer.py
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, AsyncGenerator, AsyncIterator, Dict, Iterable, Optional, Protocol

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

# ============ ЛОГИРОВАНИЕ ============

logger = logging.getLogger("neuroforge.infer")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ============ НАСТРОЙКИ ============

class Settings(BaseModel):
    base_timeout_s: float = Field(default=float(os.getenv("NEUROFORGE_MAX_REQUEST_SECONDS", "60")))
    rate_limit_rps: float = Field(default=float(os.getenv("NEUROFORGE_RATE_LIMIT_RPS", "5")))
    rate_limit_burst: int = Field(default=int(os.getenv("NEUROFORGE_RATE_LIMIT_BURST", "10")))
    allowed_api_keys: list[str] = Field(default_factory=lambda: [
        s.strip() for s in os.getenv("NEUROFORGE_API_KEYS", "").split(",") if s.strip()
    ])
    hmac_secret: Optional[str] = Field(default=os.getenv("NEUROFORGE_HMAC_SECRET") or None)
    enable_request_logging: bool = Field(default=os.getenv("NEUROFORGE_REQ_LOG", "false").lower() == "true")
    idempotency_ttl_s: int = Field(default=int(os.getenv("NEUROFORGE_IDEMPOTENCY_TTL_S", "600")))
    sse_heartbeat_s: int = Field(default=int(os.getenv("NEUROFORGE_SSE_HEARTBEAT_S", "15")))

settings = Settings()

# ============ ОТКРЫТАЯ ТЕЛЕМЕТРИЯ (опционально) ============

try:
    from opentelemetry import trace as _ot_trace  # type: ignore
    _TRACER = _ot_trace.get_tracer("neuroforge.infer")
except Exception:  # opentelemetry не обязателен
    class _NoTracer:
        def start_as_current_span(self, *_a, **_k):
            class _NoSpan:
                def __enter__(self): return self
                def __exit__(self, exc_type, exc, tb): return False
                def set_attribute(self, *_a, **_k): ...
            return _NoSpan()
    _TRACER = _NoTracer()  # type: ignore

# ============ СХЕМЫ ЗАПРОС/ОТВЕТ ============

class InferenceParams(BaseModel):
    temperature: float = Field(0.2, ge=0.0, le=2.0)
    top_k: int = Field(0, ge=0, le=1000)
    top_p: float = Field(1.0, ge=0.0, le=1.0)
    max_tokens: int = Field(256, ge=1, le=8192)
    seed: Optional[int] = Field(default=None, ge=0)
    stream: bool = Field(default=False)

class InferenceRequest(BaseModel):
    model: str = Field(..., min_length=2, max_length=128, description="Имя модели/алиас")
    version: Optional[str] = Field(None, min_length=1, max_length=32, description="Версия модели (semver/alias)")
    input_text: Optional[str] = Field(None, max_length=20000)
    input_batch: Optional[list[str]] = Field(default=None)
    context: Optional[dict[str, Any]] = None
    params: InferenceParams = Field(default_factory=InferenceParams)

    @field_validator("input_batch")
    @classmethod
    def _non_empty_batch(cls, v):
        if v is not None and len(v) == 0:
            raise ValueError("input_batch cannot be empty")
        return v

    @field_validator("input_text")
    @classmethod
    def _text_or_batch(cls, v, info):
        # Либо text, либо batch, минимум одно
        return v

    def ensure_valid(self) -> None:
        if self.input_text is None and self.input_batch is None:
            raise ValueError("Either input_text or input_batch must be provided")

class UsageInfo(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

class InferenceOutput(BaseModel):
    text: str
    latency_ms: int
    usage: UsageInfo
    model: str
    version: Optional[str] = None
    request_id: str

class ErrorPayload(BaseModel):
    code: str
    message: str
    request_id: str

# ============ ПРОТОКОЛЫ РЕЕСТРА/ДВИЖКА ============

class InferenceEngine(Protocol):
    async def infer(self, req: InferenceRequest, request_id: str) -> InferenceOutput: ...
    def stream(self, req: InferenceRequest, request_id: str) -> AsyncIterator[dict[str, Any]]: ...

class ModelRegistry(Protocol):
    def get(self, model: str, version: Optional[str] = None) -> InferenceEngine: ...

# ====== Fallback-заглушки для локального запуска (замените на реальные реализации) ======

class _EchoEngine:
    async def infer(self, req: InferenceRequest, request_id: str) -> InferenceOutput:
        txt = req.input_text or " | ".join(req.input_batch or [])
        start = time.perf_counter()
        await asyncio.sleep(0.01)
        latency = int((time.perf_counter() - start) * 1000)
        return InferenceOutput(
            text=f"[echo:{req.model}] {txt}",
            latency_ms=latency,
            usage=UsageInfo(prompt_tokens=len(txt.split()), completion_tokens=5, total_tokens=len(txt.split()) + 5),
            model=req.model,
            version=req.version,
            request_id=request_id,
        )

    async def _stream_tokens(self, content: str) -> AsyncGenerator[dict[str, Any], None]:
        for tok in content.split():
            await asyncio.sleep(0.02)
            yield {"delta": tok + " ", "finished": False}
        yield {"delta": "", "finished": True}

    def stream(self, req: InferenceRequest, request_id: str) -> AsyncIterator[dict[str, Any]]:
        content = req.input_text or " | ".join(req.input_batch or [])
        return self._stream_tokens(f"[echo:{req.model}] {content}")

class _LocalRegistry:
    def get(self, model: str, version: Optional[str] = None) -> InferenceEngine:
        # Здесь можно подключить реальные модели
        return _EchoEngine()

# ============ ИДЕМПОТЕНТНОСТЬ (in-memory) ============

@dataclass
class _IdemRecord:
    status_code: int
    headers: dict[str, str]
    body: bytes
    expires_at: float

class _IdempotencyStore:
    def __init__(self, ttl_s: int = 600) -> None:
        self._ttl = ttl_s
        self._store: dict[str, _IdemRecord] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[_IdemRecord]:
        async with self._lock:
            rec = self._store.get(key)
            if not rec:
                return None
            if rec.expires_at < time.time():
                self._store.pop(key, None)
                return None
            return rec

    async def set(self, key: str, status_code: int, headers: dict[str, str], body: bytes) -> None:
        async with self._lock:
            self._store[key] = _IdemRecord(status_code, headers, body, time.time() + self._ttl)

    async def purge_expired(self) -> None:
        async with self._lock:
            now = time.time()
            for k in list(self._store.keys()):
                if self._store[k].expires_at < now:
                    self._store.pop(k, None)

_IDEMPOTENCY = _IdempotencyStore(ttl_s=settings.idempotency_ttl_s)

# ============ RATE LIMIT (token bucket, per client) ============

class _TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            delta = now - self.updated
            self.updated = now
            self.tokens = min(self.burst, self.tokens + delta * self.rate)
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

_RATE_BUCKETS: dict[str, _TokenBucket] = {}

def _client_key(request: Request, api_key: Optional[str]) -> str:
    if api_key:
        return f"ak:{api_key}"
    # fallback: IP
    try:
        ip = request.client.host if request.client else "unknown"
        ipaddress.ip_address(ip)
    except Exception:
        ip = "unknown"
    return f"ip:{ip}"

async def rate_limit_dependency(
    request: Request,
    api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> None:
    key = _client_key(request, api_key)
    bucket = _RATE_BUCKETS.get(key)
    if bucket is None:
        bucket = _TokenBucket(settings.rate_limit_rps, settings.rate_limit_burst)
        _RATE_BUCKETS[key] = bucket
    if not await bucket.allow():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "rate_limited", "message": "Too many requests"},
            headers={"Retry-After": "1"},
        )

# ============ БЕЗОПАСНОСТЬ: API ключи и HMAC ============

def _auth_ok(api_key_header: Optional[str], auth_header: Optional[str]) -> tuple[bool, Optional[str]]:
    # Принимаем либо X-API-Key, либо Authorization: Bearer
    if settings.allowed_api_keys:
        if api_key_header and api_key_header in settings.allowed_api_keys:
            return True, api_key_header
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            if token in settings.allowed_api_keys:
                return True, token
        return False, None
    # Если список ключей пуст, считаем открытым (для разработки)
    return True, api_key_header or (auth_header or None)

async def auth_dependency(
    api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> str:
    ok, principal = _auth_ok(api_key, authorization)
    if not ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": "unauthorized", "message": "Invalid API key"})
    return principal or "anonymous"

def _compute_sig(secret: str, ts: str, method: str, path: str, body_bytes: bytes) -> str:
    # Подпись: ts + "." + method + "." + path + "." + sha256(body)
    digest = hashlib.sha256(body_bytes).hexdigest()
    msg = f"{ts}.{method.upper()}.{path}.{digest}".encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return f"{ts}.{mac.hex()}"

async def hmac_verify_dependency(
    request: Request,
    x_nf_signature: Optional[str] = Header(default=None, alias="X-NF-Signature"),
) -> None:
    if not settings.hmac_secret:
        return  # подпись не включена
    if not x_nf_signature:
        raise HTTPException(status_code=401, detail={"code": "signature_required", "message": "X-NF-Signature is required"})
    try:
        ts, _sig = x_nf_signature.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=401, detail={"code": "signature_invalid", "message": "Malformed signature"})
    # Допустимая дельта по времени ±5 минут
    try:
        ts_i = int(ts)
    except Exception:
        raise HTTPException(status_code=401, detail={"code": "signature_invalid", "message": "Invalid timestamp"})
    if abs(int(time.time()) - ts_i) > 300:
        raise HTTPException(status_code=401, detail={"code": "signature_expired", "message": "Signature expired"})
    body = await request.body()
    expected = _compute_sig(settings.hmac_secret, ts, request.method, request.url.path, body)
    # Для совместимости допускаем сравнение по hex части
    if not hmac.compare_digest(x_nf_signature, expected):
        raise HTTPException(status_code=401, detail={"code": "signature_mismatch", "message": "Signature mismatch"})

# ============ УТИЛИТЫ ============

def _request_id(x_request_id: Optional[str]) -> str:
    try:
        if x_request_id:
            uuid.UUID(x_request_id)
            return x_request_id
    except Exception:
        pass
    return str(uuid.uuid4())

def _error_response(status_code: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=ErrorPayload(code=code, message=message, request_id=request_id).model_dump(),
        headers={"X-Request-ID": request_id},
    )

# ============ РЕЕСТР МОДЕЛЕЙ (DI) ============

def get_registry() -> ModelRegistry:
    # Точка расширения для DI контейнера
    return _LocalRegistry()

# ============ РОУТЕР ============

router = APIRouter(prefix="/v1", tags=["inference"])

# Основная точка обработки — единая функция
async def request_infer(
    request: Request,
    body: InferenceRequest,
    registry: ModelRegistry,
    request_id: str,
    timeout_s: float,
) -> InferenceOutput:
    body.ensure_valid()
    engine = registry.get(body.model, body.version)

    async def _run() -> InferenceOutput:
        return await engine.infer(body, request_id)

    try:
        with _TRACER.start_as_current_span("infer") as span:  # type: ignore
            span.set_attribute("nf.model", body.model)  # type: ignore
            span.set_attribute("nf.version", body.version or "")  # type: ignore
            span.set_attribute("nf.request_id", request_id)  # type: ignore
            res: InferenceOutput = await asyncio.wait_for(_run(), timeout=timeout_s)
            return res
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail={"code": "timeout", "message": "Inference timeout"})
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Inference error: %s", ex)
        raise HTTPException(status_code=500, detail={"code": "inference_error", "message": "Internal inference error"})

# ---- Эндпоинт: обычный инференс ----

@router.post(
    "/infer",
    response_model=InferenceOutput,
    responses={
        400: {"model": ErrorPayload},
        401: {"model": ErrorPayload},
        404: {"model": ErrorPayload},
        409: {"model": ErrorPayload},
        429: {"model": ErrorPayload},
        500: {"model": ErrorPayload},
        504: {"model": ErrorPayload},
    },
)
async def infer_endpoint(
    request: Request,
    response: Response,
    payload: InferenceRequest = Body(...),
    principal: str = Depends(auth_dependency),
    _: None = Depends(hmac_verify_dependency),
    __: None = Depends(rate_limit_dependency),
    registry: ModelRegistry = Depends(get_registry),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    req_id = _request_id(x_request_id)
    response.headers["X-Request-ID"] = req_id

    # Идемпотентность
    if idempotency_key:
        cached = await _IDEMPOTENCY.get(idempotency_key)
        if cached:
            # Возвращаем сохранённый ответ
            for k, v in cached.headers.items():
                response.headers.setdefault(k, v)
            return JSONResponse(
                status_code=cached.status_code,
                content=json.loads(cached.body.decode("utf-8")),
                headers={"X-Request-ID": req_id, **cached.headers},
            )

    # Основной вызов
    try:
        result = await request_infer(request, payload, registry, req_id, settings.base_timeout_s)
    except HTTPException as he:
        return _error_response(he.status_code, he.detail.get("code", "error"), he.detail.get("message", "Error"), req_id)

    # Сохраняем для идемпотентности
    if idempotency_key:
        body_bytes = json.dumps(result.model_dump()).encode("utf-8")
        await _IDEMPOTENCY.set(
            idempotency_key,
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=body_bytes,
        )

    if settings.enable_request_logging:
        logger.info("infer ok req_id=%s model=%s principal=%s", req_id, payload.model, principal)

    return result

# ---- Эндпоинт: стриминг (SSE/NDJSON) ----

class StreamFormat(str):
    SSE = "sse"
    NDJSON = "ndjson"

def _sse_event(data: dict[str, Any]) -> bytes:
    # SSE формат: data: <json>\n\n
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n".encode("utf-8")

async def _ndjson_line(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")

async def _heartbeat(format: StreamFormat) -> bytes:
    if format == StreamFormat.SSE:
        return b": keep-alive\n\n"
    return b""  # для NDJSON heartbeat не посылаем

@router.post(
    "/infer/stream",
    responses={
        200: {"content": {"text/event-stream": {}, "application/x-ndjson": {}}},
        400: {"model": ErrorPayload},
        401: {"model": ErrorPayload},
        429: {"model": ErrorPayload},
        500: {"model": ErrorPayload},
        504: {"model": ErrorPayload},
    },
)
async def infer_stream_endpoint(
    request: Request,
    response: Response,
    payload: InferenceRequest = Body(...),
    principal: str = Depends(auth_dependency),
    _: None = Depends(hmac_verify_dependency),
    __: None = Depends(rate_limit_dependency),
    registry: ModelRegistry = Depends(get_registry),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
    stream_format: Optional[str] = Header(default="sse", alias="X-Stream-Format"),
):
    req_id = _request_id(x_request_id)
    response.headers["X-Request-ID"] = req_id

    try:
        payload.ensure_valid()
    except Exception as ex:
        return _error_response(400, "bad_request", str(ex), req_id)

    engine = registry.get(payload.model, payload.version)
    fmt = StreamFormat.SSE if (stream_format or "sse").lower() == "sse" else StreamFormat.NDJSON

    async def generator() -> AsyncGenerator[bytes, None]:
        started = time.perf_counter()
        last_hb = started
        try:
            # Отправляем стартовое событие
            start_evt = {"event": "start", "request_id": req_id, "model": payload.model, "version": payload.version}
            if fmt == StreamFormat.SSE:
                yield _sse_event(start_evt)
            else:
                yield await _ndjson_line(start_evt)

            with _TRACER.start_as_current_span("infer.stream") as span:  # type: ignore
                span.set_attribute("nf.model", payload.model)  # type: ignore
                span.set_attribute("nf.version", payload.version or "")  # type: ignore
                span.set_attribute("nf.request_id", req_id)  # type: ignore

                async def _stream():
                    async for chunk in engine.stream(payload, req_id):
                        yield chunk

                async for chunk in _stream():
                    # Heartbeat
                    now = time.perf_counter()
                    if now - last_hb > settings.sse_heartbeat_s:
                        if fmt == StreamFormat.SSE:
                            yield await _heartbeat(fmt)
                        last_hb = now

                    evt = {"event": "delta", "request_id": req_id, **chunk}
                    if fmt == StreamFormat.SSE:
                        yield _sse_event(evt)
                    else:
                        yield await _ndjson_line(evt)

            # Завершающее событие
            latency_ms = int((time.perf_counter() - started) * 1000)
            done_evt = {"event": "done", "request_id": req_id, "latency_ms": latency_ms}
            if fmt == StreamFormat.SSE:
                yield _sse_event(done_evt)
            else:
                yield await _ndjson_line(done_evt)
        except asyncio.CancelledError:
            cancel_evt = {"event": "cancelled", "request_id": req_id}
            if fmt == StreamFormat.SSE:
                yield _sse_event(cancel_evt)
            else:
                yield await _ndjson_line(cancel_evt)
            raise
        except Exception as ex:
            logger.exception("stream error: %s", ex)
            err_evt = {"event": "error", "request_id": req_id, "code": "stream_error", "message": "Internal stream error"}
            if fmt == StreamFormat.SSE:
                yield _sse_event(err_evt)
            else:
                yield await _ndjson_line(err_evt)

    media_type = "text/event-stream" if fmt == StreamFormat.SSE else "application/x-ndjson"
    headers = {
        "X-Request-ID": req_id,
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }
    return StreamingResponse(generator(), media_type=media_type, headers=headers)

# ============ ХЭНДЛЕРЫ ОШИБОК ДЛЯ ПРИЛОЖЕНИЯ (опционально) ============

def register_exception_handlers(app) -> None:
    @app.exception_handler(HTTPException)
    async def _http_exc_handler(_req: Request, exc: HTTPException):
        req_id = _request_id(_req.headers.get("X-Request-ID"))
        payload = exc.detail if isinstance(exc.detail, dict) else {"code": "error", "message": str(exc.detail)}
        return _error_response(exc.status_code, payload.get("code", "error"), payload.get("message", "error"), req_id)

    @app.exception_handler(Exception)
    async def _generic_exc_handler(_req: Request, exc: Exception):
        logger.exception("Unhandled error: %s", exc)
        req_id = _request_id(_req.headers.get("X-Request-ID"))
        return _error_response(500, "internal_error", "Unhandled server error", req_id)

# ============ ПРИМЕР ВКЛЮЧЕНИЯ РОУТЕРА ============
# from fastapi import FastAPI
# app = FastAPI()
# app.include_router(router)
# register_exception_handlers(app)
