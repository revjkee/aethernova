# neuroforge-core/api/http/routers/v1/train.py
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, AsyncIterator, Dict, Iterable, List, Literal, Optional, Protocol, Tuple

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
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, conint, constr

log = logging.getLogger("neuroforge.api.train")


# =========================
# Публичные модели API
# =========================

class ErrorPayload(BaseModel):
    code: str = Field(..., description="Короткий код ошибки")
    message: str = Field(..., description="Человекочитаемое описание")
    details: Dict[str, Any] = Field(default_factory=dict)


class TrainingJob(BaseModel):
    name: str = Field(..., example="trainingJobs/1234")
    state: str = Field(..., regex=r"^[A-Z_]+$")
    priority: Optional[str] = None
    etag: Optional[str] = None
    create_time: Optional[str] = None
    update_time: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    error: Optional[Dict[str, Any]] = None
    final_metrics: Optional[Dict[str, float]] = None


class SubmitTrainingJobRequest(BaseModel):
    idempotency_key: Optional[str] = Field(
        default=None, description="Идемпотентный ключ клиента (если не задан — сгенерируется)"
    )
    correlation_id: Optional[str] = Field(default=None, description="Внешний корреляционный идентификатор")
    validate_only: bool = False
    job: Dict[str, Any] = Field(..., description="Декларация TrainingJob (спецификация запуска)")


class SubmitTrainingJobResponse(BaseModel):
    job: TrainingJob


class CancelTrainingJobRequest(BaseModel):
    name: str
    reason: Optional[str] = ""
    etag: Optional[str] = None


class ListTrainingJobsResponse(BaseModel):
    jobs: List[TrainingJob]
    next_page_token: Optional[str] = None


# =========================
# Протоколы зависимостей
# =========================

class TrainingService(Protocol):
    """Тонкий интерфейс бизнес-логики обучения."""

    async def submit(self, payload: Dict[str, Any], validate_only: bool, principal: str, correlation_id: str) -> TrainingJob:
        ...

    async def get(self, name: str, principal: str) -> Tuple[TrainingJob, Optional[str]]:
        """Возвращает (job, etag)."""

    async def cancel(self, name: str, principal: str, reason: str, etag: Optional[str]) -> TrainingJob:
        ...

    async def list(self, principal: str, filter_expr: str, page_size: int, page_token: Optional[str]) -> Tuple[List[TrainingJob], Optional[str]]:
        ...

    async def stream_logs(self, name: str, principal: str, since_time: Optional[datetime], min_level: Optional[str]) -> AsyncIterator[bytes]:
        """Возвращает NDJSON-стрим: одна JSON-строка на событие."""

    async def stream_metrics(self, name: str, principal: str, since_time: Optional[datetime]) -> AsyncIterator[bytes]:
        """Возвращает NDJSON-стрим метрик."""

    async def upload_artifact_stream(self, parent: str, principal: str, chunks: AsyncIterator[bytes]) -> Dict[str, Any]:
        """Принимает последовательность байтов артефакта и возвращает итоговый дескриптор."""


class IdempotencyStore(Protocol):
    """Хранилище идемпотентных ответов на ограниченное окно времени."""

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        ...

    async def put(self, key: str, value: Dict[str, Any], ttl_seconds: int) -> None:
        ...


# =========================
# Вспомогательные утилиты
# =========================

_IDEMP_TTL_SECONDS = 3600
_REQUEST_ID_HEADER = "X-Request-ID"
_CORRELATION_ID_HEADER = "X-Correlation-ID"
_IDEMPOTENCY_HEADER = "Idempotency-Key"

_UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


async def _require_principal(
    authorization: Optional[str] = Header(None, description="Bearer <token> или иные схемы"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> str:
    """
    Простейшая заглушка аутентификации.
    В проде замените на зависимость, извлекающую субъекта из OIDC/ACL.
    """
    if x_api_key:
        return f"api_key:{x_api_key[:6]}…"
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        return f"bearer:{token[:8]}…"
    # Аноним не допускается для обучения
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_uuid() -> str:
    return str(uuid.uuid4())


def _parse_http_date_or_seconds(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return float(value)
    except Exception:
        return None


async def _iter_ndjson_lines(req: Request) -> AsyncIterator[bytes]:
    """
    Безопасно читает тело с Content-Type: application/x-ndjson, поблочно, без буферизации целого тела.
    Возвращает «сырой» NDJSON-поток (в байтах), который сервис может агрегировать в один артефакт.
    """
    async for chunk in req.stream():
        # Пропускаем пустые keep-alive чанки
        if chunk:
            yield chunk


# =========================
# Вспомогательная in-memory реализация идемпотентности (на проде замените)
# =========================

@dataclass
class _MemItem:
    value: Dict[str, Any]
    exp: float


class InMemoryIdempotencyStore:
    def __init__(self) -> None:
        self._data: Dict[str, _MemItem] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            if item.exp < time.time():
                self._data.pop(key, None)
                return None
            return item.value

    async def put(self, key: str, value: Dict[str, Any], ttl_seconds: int) -> None:
        async with self._lock:
            self._data[key] = _MemItem(value=value, exp=time.time() + ttl_seconds)


# =========================
# Маршруты
# =========================

def get_router(
    service: TrainingService,
    idem_store: Optional[IdempotencyStore] = None,
) -> APIRouter:
    """
    Собирает роутер v1 для операций обучения.
    Подключите зависимостью свою реализацию TrainingService и устойчивое хранилище идемпотентности.
    """
    router = APIRouter(prefix="/v1", tags=["training"])
    idem = idem_store or InMemoryIdempotencyStore()

    @router.post(
        "/trainingJobs:submit",
        response_model=SubmitTrainingJobResponse,
        status_code=status.HTTP_200_OK,
        responses={
            400: {"model": ErrorPayload},
            401: {"model": ErrorPayload},
            409: {"model": ErrorPayload},
            422: {"model": ErrorPayload},
            500: {"model": ErrorPayload},
        },
        summary="Идемпотентная постановка задания на обучение",
    )
    async def submit_training_job(
        request: SubmitTrainingJobRequest,
        response: Response,
        principal: str = Depends(_require_principal),
        idem_key: Optional[str] = Header(None, alias=_IDEMPOTENCY_HEADER),
        corr_id: Optional[str] = Header(None, alias=_CORRELATION_ID_HEADER),
        req_id: Optional[str] = Header(None, alias=_REQUEST_ID_HEADER),
    ) -> SubmitTrainingJobResponse:
        key = request.idempotency_key or idem_key or _gen_uuid()
        correlation = request.correlation_id or corr_id or _gen_uuid()
        response.headers[_REQUEST_ID_HEADER] = req_id or _gen_uuid()
        response.headers[_CORRELATION_ID_HEADER] = correlation
        response.headers[_IDEMPOTENCY_HEADER] = key

        if not _UUID_RE.match(key):
            # Жестко требуем UUID v4 — это упрощает трекинг
            raise HTTPException(status_code=422, detail="Invalid Idempotency-Key format")

        cached = await idem.get(key)
        if cached:
            # Повторяем кэшированный ответ
            return SubmitTrainingJobResponse.model_validate(cached)

        job = await service.submit(payload=request.job, validate_only=request.validate_only, principal=principal, correlation_id=correlation)
        payload = SubmitTrainingJobResponse(job=job).model_dump()
        # Кэшируем только если не validate_only
        if not request.validate_only:
            await idem.put(key, payload, ttl_seconds=_IDEMP_TTL_SECONDS)
        return SubmitTrainingJobResponse.model_validate(payload)

    @router.get(
        "/trainingJobs/{name}",
        response_model=TrainingJob,
        responses={404: {"model": ErrorPayload}},
        summary="Получить текущее состояние задания",
    )
    async def get_training_job(
        name: constr(strip_whitespace=True, min_length=1) = Path(..., description="ID ресурса вида trainingJobs/{id}"),
        response: Response = None,  # type: ignore[assignment]
        principal: str = Depends(_require_principal),
    ) -> TrainingJob:
        job, etag = await service.get(name=name, principal=principal)
        if etag:
            response.headers["ETag"] = etag
        return job

    @router.post(
        "/trainingJobs/{name}:cancel",
        response_model=TrainingJob,
        responses={404: {"model": ErrorPayload}, 412: {"model": ErrorPayload}},
        summary="Отмена задания (best effort)",
    )
    async def cancel_training_job(
        name: constr(strip_whitespace=True, min_length=1) = Path(...),
        body: CancelTrainingJobRequest = None,  # type: ignore[assignment]
        principal: str = Depends(_require_principal),
        if_match: Optional[str] = Header(None, alias="If-Match"),
    ) -> TrainingJob:
        etag = if_match or (body.etag if body else None)
        reason = (body.reason if body else "") or ""
        return await service.cancel(name=name, principal=principal, reason=reason, etag=etag)

    @router.get(
        "/trainingJobs",
        response_model=ListTrainingJobsResponse,
        summary="Список заданий с пагинацией",
    )
    async def list_training_jobs(
        principal: str = Depends(_require_principal),
        filter_expr: str = Query("", description='Фильтр (например, "state=RUNNING priority>=HIGH")'),
        page_size: conint(ge=1, le=1000) = Query(50),
        page_token: Optional[str] = Query(None),
    ) -> ListTrainingJobsResponse:
        jobs, token = await service.list(principal=principal, filter_expr=filter_expr, page_size=page_size, page_token=page_token)
        return ListTrainingJobsResponse(jobs=jobs, next_page_token=token)

    @router.get(
        "/trainingJobs/{name}:logs",
        response_class=StreamingResponse,
        summary="Поток логов в формате NDJSON",
    )
    async def stream_logs(
        name: str,
        principal: str = Depends(_require_principal),
        since_time: Optional[str] = Query(None, description="ISO8601, UTC"),
        min_level: Optional[Literal["DEBUG", "INFO", "WARN", "ERROR"]] = Query(None),
    ) -> StreamingResponse:
        dt = None
        if since_time:
            try:
                dt = datetime.fromisoformat(since_time.replace("Z", "+00:00"))
            except Exception:
                raise HTTPException(status_code=422, detail="Invalid since_time")
        stream = await service.stream_logs(name=name, principal=principal, since_time=dt, min_level=min_level)

        async def _ndjson() -> AsyncGenerator[bytes, None]:
            async for line in stream:
                # Ожидаем, что сервис отдаёт построчные JSON-объекты (без финального \n)
                yield line if line.endswith(b"\n") else line + b"\n"

        return StreamingResponse(_ndjson(), media_type="application/x-ndjson")

    @router.get(
        "/trainingJobs/{name}:metrics",
        response_class=StreamingResponse,
        summary="Поток метрик в формате NDJSON",
    )
    async def stream_metrics(
        name: str,
        principal: str = Depends(_require_principal),
        since_time: Optional[str] = Query(None, description="ISO8601, UTC"),
    ) -> StreamingResponse:
        dt = None
        if since_time:
            try:
                dt = datetime.fromisoformat(since_time.replace("Z", "+00:00"))
            except Exception:
                raise HTTPException(status_code=422, detail="Invalid since_time")
        stream = await service.stream_metrics(name=name, principal=principal, since_time=dt)

        async def _ndjson() -> AsyncGenerator[bytes, None]:
            async for line in stream:
                yield line if line.endswith(b"\n") else line + b"\n"

        return StreamingResponse(_ndjson(), media_type="application/x-ndjson")

    @router.post(
        "/trainingJobs/{parent:path}:upload",
        response_model=Dict[str, Any],
        summary="Загрузка артефактов чанками (NDJSON)",
    )
    async def upload_artifact(
        parent: str = Path(..., description='Формат: "trainingJobs/{id}/artifacts/{kind}"'),
        request: Request = None,  # type: ignore[assignment]
        principal: str = Depends(_require_principal),
        idem_key: Optional[str] = Header(None, alias=_IDEMPOTENCY_HEADER),
    ) -> Dict[str, Any]:
        """
        Тело запроса: Content-Type: application/x-ndjson
        Каждая строка — JSON: {"chunk": "<base64>", "checksum":"<hex,optional>", "last": true|false}
        """
        if not request.headers.get("content-type", "").startswith("application/x-ndjson"):
            raise HTTPException(status_code=415, detail="Unsupported Media Type, expected application/x-ndjson")

        # Идемпотентность загрузки: рекомендуем клиентам передавать Idempotency-Key
        key = idem_key or _gen_uuid()
        response = await service.upload_artifact_stream(parent=parent, principal=principal, chunks=_decode_ndjson_chunks(_iter_ndjson_lines(request)))
        return response

    return router


# =========================
# Декодер NDJSON чанков с base64
# =========================

async def _decode_ndjson_chunks(lines: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """
    Принимает поток NDJSON-строк, проверяет и декодирует base64-поля "chunk".
    Сливает в единый бинарный поток байтов артефакта.
    """
    buffer = b""
    async for raw in lines:
        buffer += raw
        # Разбираем по переводам строк; возможны частичные чанки
        while True:
            idx = buffer.find(b"\n")
            if idx < 0:
                break
            line = buffer[:idx]
            buffer = buffer[idx + 1 :]
            if not line.strip():
                continue
            try:
                obj = json.loads(line.decode("utf-8"))
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid NDJSON line")
            b64 = obj.get("chunk")
            if not isinstance(b64, str):
                raise HTTPException(status_code=422, detail="Missing chunk")
            try:
                payload = base64.b64decode(b64, validate=True)
            except Exception:
                raise HTTPException(status_code=422, detail="Invalid base64 chunk")
            # checksum и last могут использоваться реализацией сервиса; здесь просто передаем байты
            yield payload
    if buffer.strip():
        # Хвост без завершающего \n
        try:
            obj = json.loads(buffer.decode("utf-8"))
            b64 = obj.get("chunk")
            payload = base64.b64decode(b64, validate=True)
            yield payload
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid trailing NDJSON line")
