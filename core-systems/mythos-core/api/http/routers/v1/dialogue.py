from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Optional, Tuple

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, ConfigDict

# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------

def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def gen_request_id() -> str:
    u = uuid.uuid4()
    # UUIDv4 в нижнем регистре для удобства корреляции
    return str(u)

def ensure_request_id(request: Request, response: Response) -> str:
    rid = request.headers.get("x-request-id") or gen_request_id()
    response.headers["x-request-id"] = rid
    return rid

def parse_label_filters(request: Request) -> Dict[str, str]:
    # Собираем query-параметры вида label.key=value
    labels: Dict[str, str] = {}
    for k, v in request.query_params.multi_items():
        if k.startswith("label.") and v is not None:
            labels[k[6:]] = v
    return labels

# ------------------------------------------------------------------------------
# Domain enums (align with proto/TS SDK)
# ------------------------------------------------------------------------------

Actor = Literal["ACTOR_UNSPECIFIED", "ACTOR_USER", "ACTOR_ASSISTANT", "ACTOR_SYSTEM", "ACTOR_TOOL"]
DialogueStatus = Literal[
    "DIALOGUE_STATUS_UNSPECIFIED",
    "DIALOGUE_OPEN",
    "DIALOGUE_CLOSED",
    "DIALOGUE_ARCHIVED",
]
ToolCallStatus = Literal[
    "TOOL_CALL_STATUS_UNSPECIFIED",
    "TOOL_CALL_PENDING",
    "TOOL_CALL_SUCCESS",
    "TOOL_CALL_ERROR",
    "TOOL_CALL_TIMEOUT",
    "TOOL_CALL_CANCELLED",
]
Severity = Literal["SEVERITY_UNSPECIFIED", "SEVERITY_LOW", "SEVERITY_MEDIUM", "SEVERITY_HIGH", "SEVERITY_CRITICAL"]

# ------------------------------------------------------------------------------
# Pydantic models (Pydantic v2)
# ------------------------------------------------------------------------------

class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None


class SafetyLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: str
    severity: Severity
    tags: Optional[List[str]] = None
    reason: Optional[str] = None
    details: Optional[Dict[str, str]] = None


class Attachment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attachment_id: uuid.UUID
    filename: str
    mime_type: str
    size_bytes: int
    sha256_hex: Optional[str] = None
    uri: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")
    call_id: uuid.UUID
    tool_name: str
    input: Optional[Dict[str, Any]] = None
    output: Optional[Dict[str, Any]] = None
    status: Optional[ToolCallStatus] = None
    latency: Optional[str] = None
    error_message: Optional[str] = None
    attributes: Optional[Dict[str, str]] = None


class Participant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    participant_id: uuid.UUID
    display_name: str
    role: Optional[str] = None
    attributes: Optional[Dict[str, str]] = None


class Turn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    turn_id: uuid.UUID
    actor: Actor
    created_at: dt.datetime
    parent_turn_id: Optional[uuid.UUID] = None

    # oneof body
    text: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    tool: Optional[ToolCall] = None

    attachments: Optional[List[Attachment]] = None
    safety: Optional[List[SafetyLabel]] = None
    usage: Optional[TokenUsage] = None
    attributes: Optional[Dict[str, str]] = None


class Dialogue(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dialogue_id: uuid.UUID
    status: DialogueStatus
    title: Optional[str] = None
    participants: Optional[List[Participant]] = None
    created_at: dt.datetime
    updated_at: Optional[dt.datetime] = None
    last_turn_id: Optional[uuid.UUID] = None
    turns: Optional[List[Turn]] = None
    labels: Optional[Dict[str, str]] = None
    usage_total: Optional[TokenUsage] = None


# Requests / Responses

class TurnSeed(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor: Actor
    text: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    tool: Optional[ToolCall] = None
    attachments: Optional[List[Attachment]] = None
    attributes: Optional[Dict[str, str]] = None


class CreateDialogueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Optional[str] = None
    participants: Optional[List[Participant]] = None
    labels: Optional[Dict[str, str]] = None
    seed_turn: Optional[TurnSeed] = None


class CreateDialogueResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dialogue: Dialogue


class AppendTurnRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor: Actor
    text: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    tool: Optional[ToolCall] = None
    attachments: Optional[List[Attachment]] = None
    attributes: Optional[Dict[str, str]] = None
    return_dialogue: Optional[bool] = False


class AppendTurnResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    turn: Turn
    dialogue: Optional[Dialogue] = None


class GetDialogueResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dialogue: Dialogue
    turns: Optional[List[Turn]] = None
    next_page_token: Optional[str] = None


class ListDialoguesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dialogues: List[Dialogue]
    next_page_token: Optional[str] = None


# Streaming events

class DialogueCreated(BaseModel):
    dialogue: Dialogue


class TurnAppended(BaseModel):
    turn: Turn
    usage_total: Optional[TokenUsage] = None


class DialogueUpdated(BaseModel):
    status: Optional[DialogueStatus] = None
    title: Optional[str] = None
    labels: Optional[Dict[str, str]] = None


class DialogueEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: uuid.UUID
    created_at: dt.datetime
    dialogue_id: uuid.UUID
    # oneof
    dialogue_created: Optional[DialogueCreated] = None
    turn_appended: Optional[TurnAppended] = None
    dialogue_updated: Optional[DialogueUpdated] = None
    dialogue_closed: Optional[Dict[str, Any]] = None
    dialogue_archived: Optional[Dict[str, Any]] = None
    attributes: Optional[Dict[str, str]] = None


# ------------------------------------------------------------------------------
# Security dependency (Bearer). Реализацию проверки токена подключите извне.
# ------------------------------------------------------------------------------

class Principal(BaseModel):
    sub: str
    roles: List[str] = Field(default_factory=list)
    tenant: Optional[str] = None


async def get_current_user(request: Request) -> Principal:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = auth[7:].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Empty bearer token")
    # TODO: Реализуйте валидацию токена, загрузку ролей/арендатора
    return Principal(sub="anonymous", roles=["viewer"])

# ------------------------------------------------------------------------------
# Idempotency store (in-memory fallback). Подключите Redis/DB для продакшена.
# ------------------------------------------------------------------------------

class IdempotencyStore(ABC):
    @abstractmethod
    async def get(self, key: str) -> Optional[bytes]:
        ...

    @abstractmethod
    async def setnx(self, key: str, value: bytes, ttl_seconds: int) -> bool:
        ...


class InMemoryIdemStore(IdempotencyStore):
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[bytes, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[bytes]:
        async with self._lock:
            self._purge()
            item = self._store.get(key)
            return item[0] if item else None

    async def setnx(self, key: str, value: bytes, ttl_seconds: int) -> bool:
        async with self._lock:
            self._purge()
            if key in self._store:
                return False
            self._store[key] = (value, asyncio.get_event_loop().time() + ttl_seconds)
            return True

    def _purge(self) -> None:
        now = asyncio.get_event_loop().time()
        for k in list(self._store.keys()):
            if self._store[k][1] <= now:
                del self._store[k]


# ------------------------------------------------------------------------------
# Service interface (to be implemented by application layer)
# ------------------------------------------------------------------------------

class DialogueService(ABC):
    @abstractmethod
    async def create_dialogue(self, principal: Principal, req: CreateDialogueRequest) -> Dialogue:
        ...

    @abstractmethod
    async def append_turn(
        self, principal: Principal, dialogue_id: uuid.UUID, req: AppendTurnRequest
    ) -> AppendTurnResponse:
        ...

    @abstractmethod
    async def get_dialogue(
        self,
        principal: Principal,
        dialogue_id: uuid.UUID,
        include_turns: bool,
        page_size: Optional[int],
        page_token: Optional[str],
    ) -> Tuple[Dialogue, Optional[List[Turn]], Optional[str]]:
        ...

    @abstractmethod
    async def list_dialogues(
        self,
        principal: Principal,
        page_size: Optional[int],
        page_token: Optional[str],
        status: Optional[DialogueStatus],
        label_filter: Dict[str, str],
        query: Optional[str],
    ) -> Tuple[List[Dialogue], Optional[str]]:
        ...

    @abstractmethod
    async def stream_events(
        self, principal: Principal, dialogue_id: uuid.UUID, from_event_id: Optional[uuid.UUID]
    ) -> AsyncIterator[DialogueEvent]:
        ...


# ------------------------------------------------------------------------------
# Dependencies: service and idempotency store retrieval
# ------------------------------------------------------------------------------

async def get_service(request: Request) -> DialogueService:
    svc: Optional[DialogueService] = getattr(request.app.state, "dialogue_service", None)
    if not svc:
        raise HTTPException(status_code=501, detail="Dialogue service is not configured")
    return svc

async def get_idem_store(request: Request) -> IdempotencyStore:
    store: Optional[IdempotencyStore] = getattr(request.app.state, "idempotency_store", None)
    if not store:
        store = InMemoryIdemStore()
        request.app.state.idempotency_store = store
    return store

# ------------------------------------------------------------------------------
# Router
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/dialogues", tags=["dialogues"])


@router.post(
    "",
    response_model=CreateDialogueResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_dialogue(
    request: Request,
    response: Response,
    payload: CreateDialogueRequest = Body(...),
    principal: Principal = Depends(get_current_user),
    service: DialogueService = Depends(get_service),
    idem: IdempotencyStore = Depends(get_idem_store),
):
    rid = ensure_request_id(request, response)
    idem_key = request.headers.get("idempotency-key")

    # Идемпотентность: если ключ есть и уже встречался — вернём закэшированный результат
    if idem_key:
        cached = await idem.get(idem_key)
        if cached is not None:
            data = json.loads(cached.decode("utf-8"))
            # Восстанавливаем заголовок корреляции
            response.headers["x-request-id"] = data.get("_meta", {}).get("request_id", rid)
            return JSONResponse(content=data["body"], status_code=data["status"])

    dlg = await service.create_dialogue(principal, payload)
    body = CreateDialogueResponse(dialogue=dlg).model_dump(mode="json")
    status_code = status.HTTP_201_CREATED

    if idem_key:
        envelope = {"status": status_code, "body": body, "_meta": {"request_id": rid}}
        await idem.setnx(idem_key, json.dumps(envelope).encode("utf-8"), ttl_seconds=24 * 3600)

    return JSONResponse(content=body, status_code=status_code)


@router.post(
    "/{dialogue_id}/turns",
    response_model=AppendTurnResponse,
    status_code=status.HTTP_201_CREATED,
)
async def append_turn(
    dialogue_id: uuid.UUID,
    request: Request,
    response: Response,
    payload: AppendTurnRequest = Body(...),
    principal: Principal = Depends(get_current_user),
    service: DialogueService = Depends(get_service),
):
    ensure_request_id(request, response)
    result = await service.append_turn(principal, dialogue_id, payload)
    body = AppendTurnResponse(**result.model_dump()).model_dump(mode="json")
    return JSONResponse(content=body, status_code=status.HTTP_201_CREATED)


@router.get(
    "/{dialogue_id}",
    response_model=GetDialogueResponse,
    status_code=status.HTTP_200_OK,
)
async def get_dialogue(
    dialogue_id: uuid.UUID,
    request: Request,
    response: Response,
    include_turns: bool = Query(False),
    page_size: Optional[int] = Query(None, ge=1, le=1000),
    page_token: Optional[str] = Query(None, max_length=1024),
    principal: Principal = Depends(get_current_user),
    service: DialogueService = Depends(get_service),
):
    ensure_request_id(request, response)
    dlg, turns, next_token = await service.get_dialogue(
        principal, dialogue_id, include_turns, page_size, page_token
    )
    body = GetDialogueResponse(dialogue=dlg, turns=turns, next_page_token=next_token).model_dump(mode="json")
    # Простейший ETag по updated_at/id
    etag = f'W/"{dlg.dialogue_id}-{int((dlg.updated_at or dlg.created_at).timestamp())}"'
    response.headers["ETag"] = etag
    return JSONResponse(content=body)


@router.get(
    "",
    response_model=ListDialoguesResponse,
    status_code=status.HTTP_200_OK,
)
async def list_dialogues(
    request: Request,
    response: Response,
    page_size: Optional[int] = Query(50, ge=1, le=1000),
    page_token: Optional[str] = Query(None, max_length=1024),
    status_: Optional[DialogueStatus] = Query(
        None, alias="status", description="Фильтр по статусу диалога"
    ),
    query: Optional[str] = Query(None, max_length=512),
    principal: Principal = Depends(get_current_user),
    service: DialogueService = Depends(get_service),
):
    ensure_request_id(request, response)
    labels = parse_label_filters(request)
    items, next_token = await service.list_dialogues(
        principal, page_size, page_token, status_, labels, query
    )
    return JSONResponse(
        content=ListDialoguesResponse(dialogues=items, next_page_token=next_token).model_dump(mode="json")
    )


@router.get(
    "/{dialogue_id}/events",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"content": {"text/event-stream": {}}},
        400: {"model": Dict[str, Any]},
        401: {"model": Dict[str, Any]},
        404: {"model": Dict[str, Any]},
    },
)
async def stream_dialogue_events(
    dialogue_id: uuid.UUID,
    request: Request,
    response: Response,
    from_event_id: Optional[uuid.UUID] = Query(None, alias="from_event_id"),
    principal: Principal = Depends(get_current_user),
    service: DialogueService = Depends(get_service),
):
    rid = ensure_request_id(request, response)

    async def event_gen() -> AsyncIterator[bytes]:
        # Первичный заголовок SSE
        yield b": mythos-core dialogue events\n\n"
        # Периодические keepalive-комментарии каждые 20s
        keepalive = 20.0
        ka_task = None

        async def keepalive_gen():
            while True:
                await asyncio.sleep(keepalive)
                yield b": keepalive\n\n"

        # Запускаем keepalive “рядом” с основным потоком событий
        async def merged_stream():
            nonlocal ka_task
            ka_task = asyncio.create_task(asyncio.sleep(0))  # placeholder
            try:
                # keepalive как отдельный генератор
                async def ka():
                    while True:
                        await asyncio.sleep(keepalive)
                        yield b": keepalive\n\n"

                async for ev in service.stream_events(principal, dialogue_id, from_event_id):
                    payload = DialogueEvent(**ev.model_dump()).model_dump(mode="json")
                    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
                    # SSE фрейм
                    yield f"id: {payload['event_id']}\n".encode("utf-8")
                    yield b"event: message\n"
                    yield f"data: {data}\n\n".encode("utf-8")
                    await asyncio.sleep(0)
                    # Сбросим from_event_id после первого события
                    from_event_id_local = payload["event_id"]
                # По завершении события — позволим keepalive ещё раз сработать
            finally:
                if ka_task and not ka_task.done():
                    ka_task.cancel()

        # Объединяем основной поток и keepalive вручную
        last_ka = asyncio.create_task(asyncio.sleep(keepalive))

        async for item in service.stream_events(principal, dialogue_id, from_event_id):
            payload = DialogueEvent(**item.model_dump()).model_dump(mode="json")
            data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            yield f"id: {payload['event_id']}\n".encode("utf-8")
            yield b"event: message\n"
            yield f"data: {data}\n\n".encode("utf-8")
            last_ka.cancel()
            last_ka = asyncio.create_task(asyncio.sleep(keepalive))
        # В конце — финальный комментарий
        yield b": stream-end\n\n"

    headers = {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        "X-Request-Id": rid,
        "Connection": "keep-alive",
    }
    return StreamingResponse(event_gen(), headers=headers)


# ------------------------------------------------------------------------------
# Error handling helpers (uniform problem shape)
# ------------------------------------------------------------------------------

def problem(status_code: int, title: str, detail: Optional[str], request: Request, extra: Dict[str, Any] | None = None):
    rid = request.headers.get("x-request-id") or gen_request_id()
    body = {"status": status_code, "title": title, "detail": detail, "request_id": rid}
    if extra:
        body.update(extra)
    return JSONResponse(status_code=status_code, content=body)
