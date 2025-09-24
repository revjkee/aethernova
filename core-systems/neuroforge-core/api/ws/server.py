# neuroforge-core/api/ws/server.py
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, AsyncIterator, Dict, Optional, Protocol

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, ValidationError

# ================== ЛОГИРОВАНИЕ ==================

logger = logging.getLogger("neuroforge.ws")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ================== ТЕЛЕМЕТРИЯ (опционально) ==================

try:
    from opentelemetry import trace as _ot_trace  # type: ignore
    _TRACER = _ot_trace.get_tracer("neuroforge.ws")
except Exception:
    class _NoTracer:
        def start_as_current_span(self, *_a, **_k):
            class _Span:
                def __enter__(self): return self
                def __exit__(self, exc_type, exc, tb): return False
                def set_attribute(self, *_a, **_k): ...
            return _Span()
    _TRACER = _NoTracer()  # type: ignore

# ================== НАСТРОЙКИ ==================

class Settings(BaseModel):
    # аутентификация
    allowed_api_keys: list[str] = Field(default_factory=lambda: [
        s.strip() for s in os.getenv("NEUROFORGE_API_KEYS", "").split(",") if s.strip()
    ])
    hmac_secret: Optional[str] = Field(default=os.getenv("NEUROFORGE_HMAC_SECRET") or None)
    # лимиты
    rate_limit_rps: float = Field(default=float(os.getenv("NEUROFORGE_WS_RPS", "10")))
    rate_limit_burst: int = Field(default=int(os.getenv("NEUROFORGE_WS_BURST", "20")))
    max_message_bytes: int = Field(default=int(os.getenv("NEUROFORGE_WS_MAX_MSG", str(512 * 1024))))  # 512 KiB
    send_queue_capacity: int = Field(default=int(os.getenv("NEUROFORGE_WS_SEND_Q", "100")))
    max_concurrent_jobs: int = Field(default=int(os.getenv("NEUROFORGE_WS_MAX_JOBS", "4")))
    # тайминги
    heartbeat_interval_s: int = Field(default=int(os.getenv("NEUROFORGE_WS_HEARTBEAT", "20")))
    idle_timeout_s: int = Field(default=int(os.getenv("NEUROFORGE_WS_IDLE_TIMEOUT", "120")))
    # логирование
    enable_frame_logging: bool = Field(default=os.getenv("NEUROFORGE_WS_FRAME_LOG", "false").lower() == "true")

settings = Settings()

# ================== ПРОТОКОЛЫ РЕЕСТРА/ДВИЖКА ==================

class InferenceParams(BaseModel):
    temperature: float = Field(0.2, ge=0.0, le=2.0)
    top_k: int = Field(0, ge=0, le=1000)
    top_p: float = Field(1.0, ge=0.0, le=1.0)
    max_tokens: int = Field(256, ge=1, le=8192)
    seed: Optional[int] = Field(default=None, ge=0)
    stream: bool = Field(default=True)

class InferenceRequest(BaseModel):
    model: str = Field(..., min_length=2, max_length=128)
    version: Optional[str] = Field(None, min_length=1, max_length=32)
    input_text: Optional[str] = Field(None, max_length=20000)
    input_batch: Optional[list[str]] = Field(default=None)
    context: Optional[dict[str, Any]] = None
    params: InferenceParams = Field(default_factory=InferenceParams)

    def ensure_valid(self) -> None:
        if self.input_text is None and (not self.input_batch):
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

class InferenceEngine(Protocol):
    async def infer(self, req: InferenceRequest, request_id: str) -> InferenceOutput: ...
    def stream(self, req: InferenceRequest, request_id: str) -> AsyncIterator[dict[str, Any]]: ...

class ModelRegistry(Protocol):
    def get(self, model: str, version: Optional[str] = None) -> InferenceEngine: ...

# ====== Локальные заглушки (замените DI на реальные реализации) ======

class _EchoEngine:
    async def infer(self, req: InferenceRequest, request_id: str) -> InferenceOutput:
        txt = req.input_text or " | ".join(req.input_batch or [])
        t0 = time.perf_counter()
        await asyncio.sleep(0.01)
        latency = int((time.perf_counter() - t0) * 1000)
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
        return _EchoEngine()

def get_registry() -> ModelRegistry:
    # Точка расширения DI
    return _LocalRegistry()

# ================== РЕЙТЛИМИТ ==================

class _TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            delta = now - self.updated
            self.updated = now
            self.tokens = min(self.burst, self.tokens + delta * self.rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

# ================== СХЕМЫ СООБЩЕНИЙ ==================

class MsgEnvelope(BaseModel):
    id: Optional[str] = Field(default=None)        # клиентский request id
    type: str                                      # "auth","ping","infer","cancel","subscribe","echo"
    data: Optional[dict[str, Any]] = Field(default=None)

class AuthOk(BaseModel):
    principal: str
    methods: list[str] = ["api_key", "bearer", "hmac"]

class ErrorPayload(BaseModel):
    code: str
    message: str
    request_id: str

# ================== УТИЛИТЫ ==================

def _safe_json_parse(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except Exception as ex:
        raise ValueError(f"invalid_json: {ex}")

def _gen_req_id() -> str:
    return str(uuid.uuid4())

def _compute_sig(secret: str, ts: str, method: str, path: str, body_hex: str = "00") -> str:
    msg = f"{ts}.{method.upper()}.{path}.{body_hex}".encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"{ts}.{mac}"

def _ok(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def _err(code: str, message: str, request_id: str, id_: Optional[str] = None) -> str:
    env = {"id": id_, "type": "error", "data": ErrorPayload(code=code, message=message, request_id=request_id).model_dump()}
    return _ok(env)

# ================== СОЕДИНЕНИЕ/КЛИЕНТ ==================

@dataclass
class ClientSession:
    ws: WebSocket
    principal: str
    bucket: _TokenBucket
    connected_at: float = field(default_factory=lambda: time.time())
    last_seen: float = field(default_factory=lambda: time.time())
    send_queue: "asyncio.Queue[str]" = field(default_factory=lambda: asyncio.Queue(maxsize=settings.send_queue_capacity))
    jobs: dict[str, asyncio.Task] = field(default_factory=dict)
    closed: bool = False

    async def send(self, text: str) -> None:
        if self.closed:
            return
        try:
            self.send_queue.put_nowait(text)
        except asyncio.QueueFull:
            # backpressure: закрываем соединение с кодом перегрузки
            logger.error("send queue overflow, closing connection")
            await self.close(code=status.WS_1011_INTERNAL_ERROR, reason="backpressure")
            raise

    async def sender_loop(self) -> None:
        try:
            while not self.closed:
                text = await self.send_queue.get()
                await self.ws.send_text(text)
                if settings.enable_frame_logging:
                    logger.debug(">> %s", text[:256])
        except Exception as ex:
            logger.debug("sender_loop exit: %s", ex)
        finally:
            await self.close()

    async def ping_loop(self) -> None:
        try:
            while not self.closed:
                await asyncio.sleep(settings.heartbeat_interval_s)
                if time.time() - self.last_seen > settings.idle_timeout_s:
                    await self.close(code=status.WS_1001_GOING_AWAY, reason="idle_timeout")
                    return
                try:
                    await self.ws.send_text(_ok({"type": "ping"}))
                except Exception:
                    await self.close()
        except Exception:
            await self.close()

    async def close(self, code: int = status.WS_1000_NORMAL_CLOSURE, reason: str = "bye") -> None:
        if self.closed:
            return
        self.closed = True
        for job_id, task in list(self.jobs.items()):
            task.cancel()
        try:
            await self.ws.close(code=code)
        finally:
            # опустошаем очередь
            while not self.send_queue.empty():
                try:
                    self.send_queue.get_nowait()
                except Exception:
                    break

# ================== АУТЕНТИФИКАЦИЯ ==================

def _auth(headers: Dict[str, str], path: str) -> tuple[bool, str]:
    api_key = headers.get("x-api-key")
    authz = headers.get("authorization")
    # API key / Bearer
    if settings.allowed_api_keys:
        if api_key and api_key in settings.allowed_api_keys:
            return True, f"ak:{api_key[:6]}***"
        if authz and authz.startswith("Bearer "):
            tok = authz.split(" ", 1)[1]
            if tok in settings.allowed_api_keys:
                return True, f"bearer:{tok[:6]}***"
        return False, ""
    # открытый режим (dev)
    principal = f"anon:{api_key or (authz or '')}"
    return True, principal

def _verify_hmac(headers: Dict[str, str], path: str) -> bool:
    if not settings.hmac_secret:
        return True
    sig = headers.get("x-nf-signature")
    if not sig:
        return False
    try:
        ts, _ = sig.split(".", 1)
        ts_i = int(ts)
    except Exception:
        return False
    if abs(int(time.time()) - ts_i) > 300:
        return False
    expected = _compute_sig(settings.hmac_secret, ts, "GET", path)
    # сравниваем по hex части либо целиком
    return hmac.compare_digest(sig, expected)

# ================== ДИСПЕТЧЕР/РОУТЕР ==================

router = APIRouter()

@router.websocket("/v1/ws")
async def websocket_entry(ws: WebSocket):
    # принять апгрейд
    await ws.accept()
    try:
        raw_headers = {k.lower(): v for k, v in ws.headers.items()}
        if not _verify_hmac(raw_headers, ws.url.path):
            await ws.send_text(_err("signature_required", "Missing or invalid X-NF-Signature", _gen_req_id()))
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        ok, principal = _auth(raw_headers, ws.url.path)
        if not ok:
            await ws.send_text(_err("unauthorized", "Invalid API credentials", _gen_req_id()))
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        session = ClientSession(
            ws=ws,
            principal=principal,
            bucket=_TokenBucket(rate=settings.rate_limit_rps, burst=settings.rate_limit_burst),
        )
        registry = get_registry()

        sender = asyncio.create_task(session.sender_loop())
        pinger = asyncio.create_task(session.ping_loop())

        # приветствие
        await session.send(_ok({"type": "auth_ok", "data": AuthOk(principal=principal).model_dump()}))

        with _TRACER.start_as_current_span("ws.session") as span:  # type: ignore
            span.set_attribute("nf.ws.principal", principal)  # type: ignore
            # приём сообщений
            while not session.closed:
                try:
                    text = await ws.receive_text()
                except WebSocketDisconnect:
                    break
                except Exception as ex:
                    logger.debug("receive error: %s", ex)
                    break

                session.last_seen = time.time()

                if settings.enable_frame_logging:
                    logger.debug("<< %s", text[:256])

                if len(text.encode("utf-8")) > settings.max_message_bytes:
                    await session.send(_err("msg_too_large", "Message exceeds max size", _gen_req_id()))
                    continue

                if not await session.bucket.allow():
                    await session.send(_err("rate_limited", "Too many messages", _gen_req_id()))
                    continue

                try:
                    env = MsgEnvelope(**_safe_json_parse(text))
                except (ValueError, ValidationError) as ex:
                    await session.send(_err("bad_request", f"{ex}", _gen_req_id()))
                    continue

                # Диспатч типов
                if env.type == "ping":
                    await session.send(_ok({"id": env.id, "type": "pong"}))
                    continue

                if env.type == "echo":
                    await session.send(_ok({"id": env.id, "type": "echo", "data": env.data or {}}))
                    continue

                if env.type == "infer":
                    await _handle_infer(env, session, registry)
                    continue

                if env.type == "cancel":
                    await _handle_cancel(env, session)
                    continue

                # неизвестный тип
                await session.send(_err("unknown_type", f"Unsupported type: {env.type}", _gen_req_id(), id_=env.id))

    finally:
        try:
            await ws.close()
        except Exception:
            pass

# ================== ОБРАБОТЧИКИ ==================

async def _handle_infer(env: MsgEnvelope, session: ClientSession, registry: ModelRegistry) -> None:
    req_id = env.id or _gen_req_id()
    data = env.data or {}
    try:
        req = InferenceRequest(**data)
        req.ensure_valid()
    except ValidationError as ve:
        await session.send(_err("bad_request", ve.json(), req_id, id_=env.id))
        return
    except Exception as ex:
        await session.send(_err("bad_request", str(ex), req_id, id_=env.id))
        return

    if len(session.jobs) >= settings.max_concurrent_jobs:
        await session.send(_err("too_many_jobs", "Max concurrent jobs reached", req_id, id_=env.id))
        return

    engine = registry.get(req.model, req.version)

    async def job_sync() -> None:
        with _TRACER.start_as_current_span("ws.infer") as span:  # type: ignore
            span.set_attribute("nf.model", req.model)  # type: ignore
            span.set_attribute("nf.version", req.version or "")  # type: ignore
            t0 = time.perf_counter()
            try:
                out = await engine.infer(req, req_id)
                await session.send(_ok({"id": req_id, "type": "result", "data": out.model_dump()}))
            except asyncio.CancelledError:
                await session.send(_ok({"id": req_id, "type": "cancelled"}))
                raise
            except Exception as ex:
                logger.exception("infer job error: %s", ex)
                await session.send(_err("inference_error", "Internal inference error", req_id, id_=env.id))
            finally:
                duration_ms = int((time.perf_counter() - t0) * 1000)
                await session.send(_ok({"id": req_id, "type": "done", "data": {"latency_ms": duration_ms}}))

    async def job_stream() -> None:
        with _TRACER.start_as_current_span("ws.stream") as span:  # type: ignore
            span.set_attribute("nf.model", req.model)  # type: ignore
            span.set_attribute("nf.version", req.version or "")  # type: ignore
            t0 = time.perf_counter()
            try:
                # стартовое событие
                await session.send(_ok({"id": req_id, "type": "start", "data": {"model": req.model, "version": req.version}}))
                async for chunk in engine.stream(req, req_id):
                    await session.send(_ok({"id": req_id, "type": "delta", "data": chunk}))
            except asyncio.CancelledError:
                await session.send(_ok({"id": req_id, "type": "cancelled"}))
                raise
            except Exception as ex:
                logger.exception("stream job error: %s", ex)
                await session.send(_err("stream_error", "Internal stream error", req_id, id_=env.id))
            finally:
                duration_ms = int((time.perf_counter() - t0) * 1000)
                await session.send(_ok({"id": req_id, "type": "done", "data": {"latency_ms": duration_ms}}))

    task = asyncio.create_task(job_stream() if req.params.stream else job_sync())
    session.jobs[req_id] = task

    def _finish(_):
        session.jobs.pop(req_id, None)
    task.add_done_callback(_finish)

    # подтверждение принятия
    await session.send(_ok({"id": req_id, "type": "accepted"}))

async def _handle_cancel(env: MsgEnvelope, session: ClientSession) -> None:
    data = env.data or {}
    job_id = data.get("job_id") or env.id
    if not job_id:
        await session.send(_err("bad_request", "job_id is required", _gen_req_id(), id_=env.id))
        return
    task = session.jobs.get(job_id)
    if not task:
        await session.send(_err("not_found", "Job not found", job_id, id_=env.id))
        return
    task.cancel()
    await session.send(_ok({"id": job_id, "type": "cancelling"}))

# ================== РЕГИСТРАЦИЯ В ПРИЛОЖЕНИИ ==================
# Пример:
# from fastapi import FastAPI
# app = FastAPI()
# app.include_router(router)
#
# Запуск: uvicorn neuroforge_core.api.ws.server:app --factory
#
# Либо экспортировать router и включить его в общий FastAPI инстанс проекта.
