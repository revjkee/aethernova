# -*- coding: utf-8 -*-
"""
Mythos Core — HTTP router v1 (Canon)
FastAPI/Starlette промышленный роутер поверх домена "канон/лора".

Соответствие proto (mythos.v1):
- GetUniverse, ListUniverses
- GetCharacter, SearchCharacters
- ListTimelineEvents
- GetClaim, ListClaims
- ResolveClaims
- WatchCanon (SSE)

Зависимости:
- fastapi>=0.100 (Starlette>=0.27)
- pydantic>=1.10 (совместимо с 2.x по используемым фичам)

Интеграция:
    from fastapi import FastAPI
    from mythos_core.api.http.routers.v1.canon import router as canon_router
    app = FastAPI()
    app.include_router(canon_router, prefix="/api")

Репозиторий данных подставляется через DI:
    app.dependency_overrides[get_repository] = MyRepo(...)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from abc import abstractmethod
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, validator

router = APIRouter(prefix="/v1/canon", tags=["canon"])


# =========================
# Pydantic models (HTTP DTO)
# =========================

# Базовые value-объекты

class ResourceRef(BaseModel):
    resource_type: str = Field(..., description="universe|character|event|custom")
    universe_id: Optional[str] = None
    character_id: Optional[str] = None
    timeline_event_id: Optional[str] = None
    custom: Optional[str] = None

    @validator("resource_type")
    def _check_type(cls, v: str) -> str:
        allowed = {"universe", "character", "event", "custom"}
        if v not in allowed:
            raise ValueError(f"resource_type must be in {allowed}")
        return v


class Citation(BaseModel):
    source_id: str
    fragment_id: Optional[str] = None
    quote: Optional[str] = None
    locator: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    metadata: Dict[str, str] = Field(default_factory=dict)


class CanonClaim(BaseModel):
    id: str
    universe_id: str
    subject: ResourceRef
    predicate: str
    object: Any = Field(..., description="Значение предиката; строка/число/bool/ISO8601 и т.д.")
    confidence: Optional[str] = Field(None, description="CONF_LOW|CONF_MEDIUM|CONF_HIGH|CONF_CERTAIN")
    continuity: Optional[str] = Field(None, description="CANON_PRIMARY|...|CANON_ALTERNATE_UNIVERSE")
    citations: List[Citation] = Field(default_factory=list)
    attributes: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class LocalizedText(BaseModel):
    locale: str
    text: str


class Trait(BaseModel):
    key: str
    value: str
    weight: Optional[float] = Field(None, ge=0.0, le=1.0)


class Universe(BaseModel):
    id: str
    key: str
    name: str
    description: Optional[str] = None
    rating_cap: Optional[str] = None
    allow_alternate_universe: Optional[bool] = None
    disallowed_crossovers: List[str] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Character(BaseModel):
    id: str
    universe_id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    gender: Optional[str] = None
    species: Optional[str] = None
    description: Optional[str] = None
    continuity: Optional[str] = None
    traits: List[Trait] = Field(default_factory=list)
    claims: List[CanonClaim] = Field(default_factory=list)
    name_localized: List[LocalizedText] = Field(default_factory=list)
    description_localized: List[LocalizedText] = Field(default_factory=list)
    citations: List[Citation] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class EraRef(BaseModel):
    key: str
    offset: int


class TimeRef(BaseModel):
    granularity: Optional[str] = Field(None, description="ERA|YEAR|MONTH|DAY|HOUR|MINUTE|SECOND")
    absolute: Optional[datetime] = None
    era: Optional[EraRef] = None
    qualifier: Optional[str] = None


class TimelineEvent(BaseModel):
    id: str
    universe_id: str
    character_id: Optional[str] = None
    title: str
    summary: Optional[str] = None
    time: Optional[TimeRef] = None
    tags: List[str] = Field(default_factory=list)
    citations: List[Citation] = Field(default_factory=list)
    continuity: Optional[str] = None
    attributes: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# Пагинация

class PageRequest(BaseModel):
    page_size: Optional[int] = Field(None, ge=1, le=1000)
    page_token: Optional[str] = None


class PageResponse(BaseModel):
    next_page_token: Optional[str] = None
    total_size: Optional[int] = None


# Обёртки ответов

class ListUniversesResponse(BaseModel):
    universes: List[Universe]
    page: PageResponse


class SearchCharactersResponse(BaseModel):
    characters: List[Character]
    page: PageResponse


class ListTimelineEventsResponse(BaseModel):
    events: List[TimelineEvent]
    page: PageResponse


class ListClaimsResponse(BaseModel):
    claims: List[CanonClaim]
    page: PageResponse


class ResolveClaimsRequest(BaseModel):
    universe_id: str
    subject: ResourceRef
    predicates: List[str] = Field(default_factory=list)


class ConflictedClaims(BaseModel):
    predicate: str
    candidates: List[CanonClaim]


class ResolveClaimsResponse(BaseModel):
    resolved: List[CanonClaim]
    conflicts: List[ConflictedClaims] = Field(default_factory=list)


# =========================
# Repository Protocol (DI)
# =========================

class CanonRepository(Protocol):
    """Абстракция доступа к данным канона. Реализуйте и подставьте через DI."""
    @abstractmethod
    async def get_universe(self, *, id: Optional[str], key: Optional[str]) -> Optional[Universe]: ...

    @abstractmethod
    async def list_universes(
        self, *, page_size: Optional[int], page_token: Optional[str], label_selector: Mapping[str, str] | None
    ) -> Tuple[List[Universe], PageResponse]: ...

    @abstractmethod
    async def get_character(self, *, id: str, universe_id: Optional[str] = None, name: Optional[str] = None,
                            aliases: Optional[List[str]] = None) -> Optional[Character]: ...

    @abstractmethod
    async def search_characters(
        self, *, universe_id: str, query: Optional[str], labels_any: List[str], labels_all: List[str],
        page_size: Optional[int], page_token: Optional[str],
    ) -> Tuple[List[Character], PageResponse]: ...

    @abstractmethod
    async def list_timeline_events(
        self, *, universe_id: str, character_id: Optional[str], time_start: Optional[TimeRef],
        time_end: Optional[TimeRef], page_size: Optional[int], page_token: Optional[str],
    ) -> Tuple[List[TimelineEvent], PageResponse]: ...

    @abstractmethod
    async def get_claim(self, *, id: str) -> Optional[CanonClaim]: ...

    @abstractmethod
    async def list_claims(
        self, *, universe_id: Optional[str], subject: Optional[ResourceRef], predicate: Optional[str],
        page_size: Optional[int], page_token: Optional[str],
    ) -> Tuple[List[CanonClaim], PageResponse]: ...

    @abstractmethod
    async def resolve_claims(
        self, *, universe_id: str, subject: ResourceRef, predicates: List[str]
    ) -> ResolveClaimsResponse: ...

    @abstractmethod
    async def watch_changes(
        self, *, universe_id: Optional[str], since: Optional[datetime]
    ) -> AsyncGenerator[Dict[str, Any], None]: ...


# Заглушка-зависимость (должна быть переопределена в приложении)
async def get_repository() -> CanonRepository:
    raise HTTPException(status_code=500, detail="CanonRepository is not wired. Override dependency get_repository().")


# =========================
# Helpers
# =========================

def _parse_label_selector(items: Iterable[str] | None) -> Mapping[str, str]:
    """
    Преобразует ["k:v","a:b"] -> {"k":"v","a":"b"}; пропускает некорректные пары.
    """
    out: Dict[str, str] = {}
    for raw in items or []:
        if ":" in raw:
            k, v = raw.split(":", 1)
            if k and v:
                out[k] = v
    return out


def _set_pagination_headers(resp: Response, page: PageResponse, base_url: str) -> None:
    if page.next_page_token:
        resp.headers["X-Next-Page-Token"] = page.next_page_token
    if page.total_size is not None:
        resp.headers["X-Total-Size"] = str(page.total_size)
    # Link header (next)
    if page.next_page_token:
        sep = "&" if ("?" in base_url) else "?"
        next_link = f'<{base_url}{sep}page_token={page.next_page_token}>; rel="next"'
        resp.headers["Link"] = next_link


def _weak_etag(payload: Any) -> str:
    data = json.dumps(payload, default=str, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return 'W/"%s"' % hashlib.sha256(data).hexdigest()


# =========================
# Routes
# =========================

# Universes

@router.get("/universes/{universe_id}", response_model=Universe, responses={404: {"description": "Not Found"}})
async def get_universe_by_id(
    universe_id: str = Path(..., description="Universe ID"),
    repo: CanonRepository = Depends(get_repository),
    response: Response = None,
):
    uni = await repo.get_universe(id=universe_id, key=None)
    if not uni:
        raise HTTPException(status_code=404, detail="Universe not found")
    payload = uni.dict()
    response.headers["ETag"] = _weak_etag(payload)
    response.headers["Cache-Control"] = "private, max-age=30"
    return uni


@router.get("/universes", response_model=ListUniversesResponse)
async def list_universes(
    page_size: Optional[int] = Query(None, ge=1, le=1000),
    page_token: Optional[str] = Query(None),
    label: List[str] = Query(default_factory=list, description="Label selectors in form key:value"),
    repo: CanonRepository = Depends(get_repository),
    request: Request = None,
    response: Response = None,
):
    labels = _parse_label_selector(label)
    items, page = await repo.list_universes(page_size=page_size, page_token=page_token, label_selector=labels)
    _set_pagination_headers(response, page, str(request.url.remove_query_params("page_token")))
    return ListUniversesResponse(universes=items, page=page)


# Characters

@router.get("/characters/{character_id}", response_model=Character, responses={404: {"description": "Not Found"}})
async def get_character(
    character_id: str = Path(..., description="Character ID"),
    universe_id: Optional[str] = Query(None, description="Optional universe scope"),
    repo: CanonRepository = Depends(get_repository),
    response: Response = None,
):
    ch = await repo.get_character(id=character_id, universe_id=universe_id, name=None, aliases=None)
    if not ch:
        raise HTTPException(status_code=404, detail="Character not found")
    response.headers["ETag"] = _weak_etag(ch.dict())
    response.headers["Cache-Control"] = "private, max-age=30"
    return ch


@router.get("/characters", response_model=SearchCharactersResponse)
async def search_characters(
    universe_id: str = Query(...),
    q: Optional[str] = Query(None, description="Full-text query"),
    labels_any: List[str] = Query(default_factory=list, description="Characters having any of these labels"),
    labels_all: List[str] = Query(default_factory=list, description="Characters having all of these labels"),
    page_size: Optional[int] = Query(None, ge=1, le=1000),
    page_token: Optional[str] = Query(None),
    repo: CanonRepository = Depends(get_repository),
    request: Request = None,
    response: Response = None,
):
    items, page = await repo.search_characters(
        universe_id=universe_id, query=q, labels_any=labels_any, labels_all=labels_all,
        page_size=page_size, page_token=page_token,
    )
    _set_pagination_headers(response, page, str(request.url.remove_query_params("page_token")))
    return SearchCharactersResponse(characters=items, page=page)


# Timeline events

@router.get("/timeline/events", response_model=ListTimelineEventsResponse)
async def list_timeline_events(
    universe_id: str = Query(...),
    character_id: Optional[str] = Query(None),
    time_start: Optional[datetime] = Query(None, description="ISO 8601 start (UTC)"),
    time_end: Optional[datetime] = Query(None, description="ISO 8601 end (UTC)"),
    page_size: Optional[int] = Query(None, ge=1, le=1000),
    page_token: Optional[str] = Query(None),
    repo: CanonRepository = Depends(get_repository),
    request: Request = None,
    response: Response = None,
):
    ts = TimeRef(absolute=time_start.replace(tzinfo=timezone.utc)) if time_start else None
    te = TimeRef(absolute=time_end.replace(tzinfo=timezone.utc)) if time_end else None
    items, page = await repo.list_timeline_events(
        universe_id=universe_id, character_id=character_id, time_start=ts, time_end=te,
        page_size=page_size, page_token=page_token,
    )
    _set_pagination_headers(response, page, str(request.url.remove_query_params("page_token")))
    return ListTimelineEventsResponse(events=items, page=page)


# Claims

@router.get("/claims/{claim_id}", response_model=CanonClaim, responses={404: {"description": "Not Found"}})
async def get_claim(
    claim_id: str = Path(...),
    repo: CanonRepository = Depends(get_repository),
    response: Response = None,
):
    cl = await repo.get_claim(id=claim_id)
    if not cl:
        raise HTTPException(status_code=404, detail="Claim not found")
    response.headers["ETag"] = _weak_etag(cl.dict())
    response.headers["Cache-Control"] = "private, max-age=30"
    return cl


@router.get("/claims", response_model=ListClaimsResponse)
async def list_claims(
    universe_id: Optional[str] = Query(None),
    subject_type: Optional[str] = Query(None, regex="^(universe|character|event|custom)$"),
    subject_id: Optional[str] = Query(None),
    predicate: Optional[str] = Query(None),
    page_size: Optional[int] = Query(None, ge=1, le=1000),
    page_token: Optional[str] = Query(None),
    repo: CanonRepository = Depends(get_repository),
    request: Request = None,
    response: Response = None,
):
    subject: Optional[ResourceRef] = None
    if subject_type and subject_id:
        if subject_type == "universe":
            subject = ResourceRef(resource_type="universe", universe_id=subject_id)
        elif subject_type == "character":
            subject = ResourceRef(resource_type="character", character_id=subject_id)
        elif subject_type == "event":
            subject = ResourceRef(resource_type="event", timeline_event_id=subject_id)
        else:
            subject = ResourceRef(resource_type="custom", custom=subject_id)

    items, page = await repo.list_claims(
        universe_id=universe_id, subject=subject, predicate=predicate,
        page_size=page_size, page_token=page_token,
    )
    _set_pagination_headers(response, page, str(request.url.remove_query_params("page_token")))
    return ListClaimsResponse(claims=items, page=page)


# Resolver

@router.post("/claims:resolve", response_model=ResolveClaimsResponse, status_code=status.HTTP_200_OK)
async def resolve_claims(
    body: ResolveClaimsRequest,
    repo: CanonRepository = Depends(get_repository),
):
    return await repo.resolve_claims(universe_id=body.universe_id, subject=body.subject, predicates=body.predicates)


# Watch (SSE stream)

@router.get("/watch", response_class=StreamingResponse)
async def watch_changes(
    universe_id: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    repo: CanonRepository = Depends(get_repository),
):
    """
    Серверные события (text/event-stream) с изменениями канона.
    Формат события: data: <JSON CanonChange>\n\n
    """
    async def event_gen() -> AsyncGenerator[bytes, None]:
        async for change in repo.watch_changes(universe_id=universe_id, since=since):
            # SSE: event:canon\nid:<ts>\ndata:<json>\n\n
            payload = json.dumps(change, default=str, ensure_ascii=False)
            evt = f"event: canon\nid: {int(datetime.now(tz=timezone.utc).timestamp())}\n" \
                  f"data: {payload}\n\n"
            yield evt.encode("utf-8")
            # Лимитируем частоту в отсутствие backpressure
            await asyncio.sleep(0)

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",  # для nginx
    }
    return StreamingResponse(event_gen(), media_type="text/event-stream", headers=headers)


# =========================
# Error handlers (optional)
# =========================

@router.exception_handler(KeyError)
async def _key_error_handler(_: Request, exc: KeyError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": f"Bad key: {exc}"})
