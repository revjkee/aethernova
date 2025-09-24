# SPDX-License-Identifier: Apache-2.0
"""
physical-integration-core/api/http/routers/v1/devices.py

Промышленный FastAPI-роутер устройств (v1):
- CRUD /devices
- PUT /devices/{deviceId}/state — отчет состояния устройства
- SSE /devices/status/stream — поток статусов обновлений (пример)
- Идемпотентность через заголовок Idempotency-Key для POST/PUT/PATCH
- ETag/If-Match для защиты от гонок
- Пагинация курсором (base64)
- Валидация тела по JSON Schema (schemas/jsonschema/v1/unit.schema.json)
- Трейс-идентификатор X-Trace-Id в ответах
- Примитивный rate-limit (подменяемый провайдер)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator, Dict, List, Mapping, MutableMapping, Optional, Protocol, Tuple

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    Header,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, validator

# ================
# Конфигурация пути к JSON Schema Unit
# ================
SCHEMA_PATH = os.getenv(
    "PIC_UNIT_SCHEMA_PATH",
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "../../../../schemas/jsonschema/v1/unit.schema.json",
        )
    ),
)


# ==========================
# Валидация JSON Schema (Draft 2020-12)
# ==========================
class JsonSchemaValidator(Protocol):
    def __call__(self, data: Any) -> None: ...


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _compile_validator() -> JsonSchemaValidator:
    # Предпочитаем fastjsonschema (очень быстрый), fallback на jsonschema
    try:
        import fastjsonschema  # type: ignore

        schema = _load_json(SCHEMA_PATH)
        return fastjsonschema.compile(schema)  # type: ignore
    except Exception:
        try:
            import jsonschema  # type: ignore
            from jsonschema import Draft202012Validator  # type: ignore

            schema = _load_json(SCHEMA_PATH)
            validator = Draft202012Validator(schema)

            def _validate(data: Any) -> None:
                errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
                if errors:
                    # Берем первую ошибку для краткости
                    err = errors[0]
                    path = "/".join([str(p) for p in err.path])
                    raise ValueError(f"Schema validation error at '{path}': {err.message}")

            return _validate
        except Exception as e:
            # Отсутствие валидатора — критическая ошибка конфигурации
            raise RuntimeError(
                f"Cannot initialize JSON Schema validator. Ensure fastjsonschema or jsonschema is installed "
                f"and schema path is valid: {SCHEMA_PATH}"
            ) from e


SCHEMA_VALIDATE: JsonSchemaValidator = _compile_validator()


# ==========================
# Утилиты: ETag, Trace, Cursor
# ==========================
def compute_etag(obj: Mapping[str, Any]) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return '"' + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=") + '"'


def get_trace_id(request: Request) -> str:
    # Берем trace из заголовков, либо генерируем
    for key in ("x-trace-id", "x-request-id", "traceparent"):
        if key in request.headers:
            hdr = request.headers[key]
            if key == "traceparent":
                # W3C: version-traceid-spanid-flags => берем поле traceid
                try:
                    parts = hdr.split("-")
                    if len(parts) >= 2 and len(parts[1]) == 32:
                        return parts[1]
                except Exception:
                    pass
            if hdr:
                return hdr
    return uuid.uuid4().hex


def encode_cursor(ts: float, last_id: str) -> str:
    payload = json.dumps({"ts": ts, "id": last_id}).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decode_cursor(cursor: str | None) -> Tuple[float | None, str | None]:
    if not cursor:
        return None, None
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
        return float(data.get("ts")), str(data.get("id"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid pageCursor")


# ==========================
# Модели запросов/ответов (минимально необходимые)
# ==========================
class DeviceStateModel(BaseModel):
    deviceId: str = Field(..., min_length=1)
    identity: Dict[str, Any]
    currentFwVersion: str = Field(..., min_length=1)
    bootloaderVersion: Optional[str] = None
    storageTotalBytes: Optional[int] = Field(None, ge=0)
    storageFreeBytes: Optional[int] = Field(None, ge=0)
    batteryPercent: Optional[int] = Field(None, ge=0, le=100)
    onMainsPower: Optional[bool] = None
    ipAddress: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None
    reportedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @validator("reportedAt", pre=True)
    def _ensure_tz(cls, v: Any) -> datetime:
        if isinstance(v, str):
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        elif isinstance(v, datetime):
            dt = v
        else:
            dt = datetime.now(timezone.utc)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class PageMeta(BaseModel):
    nextCursor: Optional[str] = None
    pageSize: int


class PaginatedUnits(BaseModel):
    items: List[Dict[str, Any]]
    page: PageMeta


# ==========================
# Интерфейсы хранилищ
# ==========================
class DeviceRepository(Protocol):
    async def list_devices(
        self, limit: int, cursor: Tuple[float | None, str | None], label_selector: Optional[str], site: Optional[str]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]: ...

    async def get_device(self, device_id: str) -> Dict[str, Any] | None: ...

    async def create_device(self, doc: Dict[str, Any]) -> Dict[str, Any]: ...

    async def replace_device(self, device_id: str, doc: Dict[str, Any], etag_check: Optional[str]) -> Dict[str, Any]: ...

    async def patch_device(self, device_id: str, patch: Dict[str, Any], etag_check: Optional[str]) -> Dict[str, Any]: ...

    async def delete_device(self, device_id: str) -> None: ...

    async def report_state(self, state: DeviceStateModel) -> None: ...

    def sse_events(self) -> AsyncIterator[str]: ...


class IdempotencyStore(Protocol):
    async def get(self, key: str) -> Optional[Dict[str, Any]]: ...
    async def set(self, key: str, value: Dict[str, Any], ttl: int) -> None: ...


class RateLimiter(Protocol):
    async def check(self, key: str) -> None: ...


# ==========================
# In-memory реализации (замените на Redis/DB в проде)
# ==========================
class InMemoryIdempotencyStore:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires, payload = item
            if expires < time.time():
                self._data.pop(key, None)
                return None
            return payload

    async def set(self, key: str, value: Dict[str, Any], ttl: int) -> None:
        async with self._lock:
            self._data[key] = (time.time() + ttl, value)


class SimpleTokenBucketRateLimiter:
    def __init__(self, rate_per_minute: int = 600) -> None:
        self.capacity = rate_per_minute
        self.refill_per_sec = rate_per_minute / 60.0
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> None:
        now = time.time()
        async with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
            if tokens < 1.0:
                # 429 Too Many Requests
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            tokens -= 1.0
            self._buckets[key] = (tokens, now)


class InMemoryDeviceRepository:
    def __init__(self) -> None:
        self._devices: Dict[str, Dict[str, Any]] = {}
        self._states: Dict[str, DeviceStateModel] = {}
        self._events: asyncio.Queue[str] = asyncio.Queue()

    # Фильтры labelSelector/site — простая демонстрация
    async def list_devices(
        self, limit: int, cursor: Tuple[float | None, str | None], label_selector: Optional[str], site: Optional[str]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        _, last_id = cursor
        keys = sorted(self._devices.keys())
        start = keys.index(last_id) + 1 if last_id in keys else 0
        selected: List[Dict[str, Any]] = []
        for k in keys[start:]:
            doc = self._devices[k]
            if site and doc.get("location", {}).get("site") != site:
                continue
            if label_selector:
                # Примитив: key1=val1,key2=val2
                ok = True
                for pair in label_selector.split(","):
                    if "=" in pair:
                        key, val = pair.split("=", 1)
                        if doc.get("metadata", {}).get("labels", {}).get(key) != val:
                            ok = False
                            break
                if not ok:
                    continue
            selected.append(doc)
            if len(selected) >= limit:
                break
        next_cursor = None
        if len(selected) == limit:
            next_cursor = encode_cursor(time.time(), selected[-1]["metadata"]["id"])
        return selected, next_cursor

    async def get_device(self, device_id: str) -> Dict[str, Any] | None:
        return self._devices.get(device_id)

    async def create_device(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        device_id = doc["metadata"]["id"]
        if device_id in self._devices:
            raise HTTPException(status_code=409, detail="Device already exists")
        self._devices[device_id] = doc
        return doc

    async def replace_device(self, device_id: str, doc: Dict[str, Any], etag_check: Optional[str]) -> Dict[str, Any]:
        current = self._devices.get(device_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Not found")
        if etag_check and compute_etag(current) != etag_check:
            raise HTTPException(status_code=412, detail="ETag mismatch (If-Match failed)")
        self._devices[device_id] = doc
        return doc

    async def patch_device(self, device_id: str, patch: Dict[str, Any], etag_check: Optional[str]) -> Dict[str, Any]:
        current = self._devices.get(device_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Not found")
        if etag_check and compute_etag(current) != etag_check:
            raise HTTPException(status_code=412, detail="ETag mismatch (If-Match failed)")
        # JSON Merge Patch (RFC 7396) — наивная реализация
        def merge(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
            for k, v in src.items():
                if v is None:
                    dst.pop(k, None)
                elif isinstance(v, dict) and isinstance(dst.get(k), dict):
                    dst[k] = merge(dst.get(k, {}), v)
                else:
                    dst[k] = v
            return dst

        updated = merge(json.loads(json.dumps(current)), patch)
        self._devices[device_id] = updated
        return updated

    async def delete_device(self, device_id: str) -> None:
        self._devices.pop(device_id, None)

    async def report_state(self, state: DeviceStateModel) -> None:
        self._states[state.deviceId] = state
        # Эмитим событие для SSE-потребителей
        evt = {
            "deviceId": state.deviceId,
            "phase": "STATE",
            "reportedAt": state.reportedAt.astimezone(timezone.utc).isoformat(),
        }
        await self._events.put(json.dumps(evt))

    async def _event_iter(self) -> AsyncIterator[str]:
        while True:
            data = await self._events.get()
            yield f"event: update\nid: {uuid.uuid4()}\ndata: {data}\n\n"

    def sse_events(self) -> AsyncIterator[str]:
        return self._event_iter()


# ==========================
# DI-провайдеры
# ==========================
_repo_singleton = InMemoryDeviceRepository()
_idemp_singleton = InMemoryIdempotencyStore()
_rl_singleton = SimpleTokenBucketRateLimiter(rate_per_minute=600)


async def get_repo() -> DeviceRepository:
    return _repo_singleton


async def get_idemp_store() -> IdempotencyStore:
    return _idemp_singleton


async def get_rate_limiter() -> RateLimiter:
    return _rl_singleton


# ==========================
# Безопасность: API Key (минимальный пример)
# ==========================
async def require_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    expected = os.getenv("PIC_API_KEY")  # если не задан — пропускаем проверку (для интеграции с внешним OAuth)
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key or "anonymous"


# ==========================
# Идемпотентность: хелпер
# ==========================
IDEMP_TTL_SECONDS = 24 * 60 * 60


async def apply_idempotency(
    request: Request,
    store: IdempotencyStore,
    key_header: Optional[str],
    response_factory,
) -> Response:
    """
    Универсальная обертка для POST/PUT/PATCH.
    response_factory -> awaitable, возвращающее (status_code, headers_dict, body_dict)
    """
    if not key_header:
        status_code, headers, payload = await response_factory()
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        resp = Response(content=body, status_code=status_code, media_type="application/json")
        for k, v in headers.items():
            resp.headers[k] = v
        return resp

    cached = await store.get(key_header)
    if cached:
        resp = Response(
            content=json.dumps(cached["body"], ensure_ascii=False).encode("utf-8"),
            status_code=int(cached["status"]),
            media_type="application/json",
        )
        for k, v in cached.get("headers", {}).items():
            resp.headers[k] = v
        resp.headers["Idempotency-Replayed"] = "true"
        return resp

    status_code, headers, payload = await response_factory()
    record = {"status": status_code, "headers": headers, "body": payload}
    await store.set(key_header, record, ttl=IDEMP_TTL_SECONDS)

    resp = Response(content=json.dumps(payload, ensure_ascii=False).encode("utf-8"), status_code=status_code, media_type="application/json")
    for k, v in headers.items():
        resp.headers[k] = v
    resp.headers["Idempotency-Replayed"] = "false"
    return resp


# ==========================
# Роутер
# ==========================
router = APIRouter(prefix="/devices", tags=["Device"])


# List
@router.get("", response_model=PaginatedUnits)
async def list_devices(
    request: Request,
    response: Response,
    pageSize: int = Query(100, ge=1, le=1000),
    pageCursor: Optional[str] = Query(None),
    labelSelector: Optional[str] = Query(None),
    site: Optional[str] = Query(None),
    repo: DeviceRepository = Depends(get_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    api_key: str = Depends(require_api_key),
):
    await limiter.check(f"list:{api_key}")
    trace_id = get_trace_id(request)
    response.headers["X-Trace-Id"] = trace_id

    cursor = decode_cursor(pageCursor)
    items, next_cursor = await repo.list_devices(limit=pageSize, cursor=cursor, label_selector=labelSelector, site=site)
    return PaginatedUnits(items=items, page=PageMeta(nextCursor=next_cursor, pageSize=pageSize))


# Get
@router.get("/{deviceId}")
async def get_device(
    deviceId: str = Path(..., min_length=1),
    request: Request = None,
    response: Response = None,
    repo: DeviceRepository = Depends(get_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    api_key: str = Depends(require_api_key),
):
    await limiter.check(f"get:{api_key}")
    response.headers["X-Trace-Id"] = get_trace_id(request)
    doc = await repo.get_device(deviceId)
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    response.headers["ETag"] = compute_etag(doc)
    return doc


# Create (idempotent via Idempotency-Key)
@router.post("", status_code=status.HTTP_201_CREATED)
async def create_device(
    request: Request,
    response: Response,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    repo: DeviceRepository = Depends(get_repo),
    store: IdempotencyStore = Depends(get_idemp_store),
    limiter: RateLimiter = Depends(get_rate_limiter),
    api_key: str = Depends(require_api_key),
):
    await limiter.check(f"create:{api_key}")
    response.headers["X-Trace-Id"] = get_trace_id(request)

    raw = await request.json()
    # Валидация по JSON Schema Unit
    SCHEMA_VALIDATE(raw)

    # Обязательный id в metadata; если отсутствует — генерируем
    meta = raw.setdefault("metadata", {})
    if "id" not in meta or not meta["id"]:
        meta["id"] = str(uuid.uuid4())
    if "createdAt" not in meta:
        meta["createdAt"] = datetime.now(timezone.utc).isoformat()

    async def _do():
        created = await repo.create_device(raw)
        etag = compute_etag(created)
        headers = {"Location": f"/devices/{created['metadata']['id']}", "ETag": etag}
        return status.HTTP_201_CREATED, headers, created

    return await apply_idempotency(request, store, idempotency_key, _do)


# Replace (PUT) — полная замена
@router.put("/{deviceId}")
async def replace_device(
    deviceId: str,
    request: Request,
    response: Response,
    if_match: Optional[str] = Header(None, alias="If-Match"),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    repo: DeviceRepository = Depends(get_repo),
    store: IdempotencyStore = Depends(get_idemp_store),
    limiter: RateLimiter = Depends(get_rate_limiter),
    api_key: str = Depends(require_api_key),
):
    await limiter.check(f"replace:{api_key}")
    response.headers["X-Trace-Id"] = get_trace_id(request)

    raw = await request.json()
    SCHEMA_VALIDATE(raw)
    meta = raw.setdefault("metadata", {})
    meta["id"] = deviceId  # canonical

    async def _do():
        updated = await repo.replace_device(deviceId, raw, etag_check=if_match)
        etag = compute_etag(updated)
        headers = {"ETag": etag}
        return status.HTTP_200_OK, headers, updated

    return await apply_idempotency(request, store, idempotency_key, _do)


# Patch (JSON Merge Patch)
@router.patch("/{deviceId}")
async def patch_device(
    deviceId: str,
    request: Request,
    response: Response,
    if_match: Optional[str] = Header(None, alias="If-Match"),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    repo: DeviceRepository = Depends(get_repo),
    store: IdempotencyStore = Depends(get_idemp_store),
    limiter: RateLimiter = Depends(get_rate_limiter),
    api_key: str = Depends(require_api_key),
):
    await limiter.check(f"patch:{api_key}")
    response.headers["X-Trace-Id"] = get_trace_id(request)
    patch = await request.json()

    # Применим patch и провалидируем итоговый документ
    async def _do():
        updated = await repo.patch_device(deviceId, patch, etag_check=if_match)
        SCHEMA_VALIDATE(updated)  # гарантируем соответствие после патча
        etag = compute_etag(updated)
        headers = {"ETag": etag}
        return status.HTTP_200_OK, headers, updated

    return await apply_idempotency(request, store, idempotency_key, _do)


# Delete
@router.delete("/{deviceId}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    deviceId: str,
    request: Request,
    response: Response,
    repo: DeviceRepository = Depends(get_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    api_key: str = Depends(require_api_key),
):
    await limiter.check(f"delete:{api_key}")
    response.headers["X-Trace-Id"] = get_trace_id(request)
    await repo.delete_device(deviceId)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# Report Device State (PUT /devices/{deviceId}/state)
@router.put("/{deviceId}/state")
async def report_device_state(
    deviceId: str,
    state: DeviceStateModel,
    request: Request,
    response: Response,
    repo: DeviceRepository = Depends(get_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    api_key: str = Depends(require_api_key),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    store: IdempotencyStore = Depends(get_idemp_store),
):
    await limiter.check(f"state:{api_key}")
    response.headers["X-Trace-Id"] = get_trace_id(request)
    if state.deviceId != deviceId:
        raise HTTPException(status_code=400, detail="deviceId mismatch between path and body")

    async def _do():
        await repo.report_state(state)
        return status.HTTP_200_OK, {}, {"status": "ok"}

    return await apply_idempotency(request, store, idempotency_key, _do)


# SSE stream of update/status events (example implementation)
@router.get("/status/stream")
async def status_stream(
    request: Request,
    repo: DeviceRepository = Depends(get_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    api_key: str = Depends(require_api_key),
):
    await limiter.check(f"sse:{api_key}")

    async def event_generator() -> AsyncIterator[bytes]:
        # Отдаем заголовки SSE
        async for event in repo.sse_events():
            # Завершаем стрим, если клиент отключился
            if await request.is_disconnected():
                break
            yield event.encode("utf-8")

    return StreamingResponse(event_generator(), media_type="text/event-stream")
