# mythos-core/api/http/routers/v1/quests.py
# -*- coding: utf-8 -*-
"""
Quests API v1 (FastAPI router) — промышленная реализация:
- Строгие Pydantic-модели (enum'ы, oneof через Optional + валидаторы)
- Идемпотентное создание с опциональным quest_id (slug)
- ETag/If-Match для Update/Delete
- Problem Details (RFC 7807)
- Пагинация с page_token (base64 offset), фильтры и сортировка
- Жизненный цикл: activate/archive
- Soft delete по умолчанию
- In-memory потокобезопасный репозиторий (для тестов, легко заменить)
- Наблюдаемость: traceparent/request-id эхо, user-agent в логах
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, ValidationError, root_validator, validator

router = APIRouter(prefix="/v1", tags=["quests"])

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

SLUG_RE = re.compile(r"^[a-z0-9]([a-z0-9-_]{0,61}[a-z0-9])?$")  # 1..63, dns-safe-ish


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def compute_etag(payload: Dict[str, Any]) -> str:
    # Стабильный ETag: sha256(uid|version|update_time)
    uid = payload.get("uid", "")
    version = str(payload.get("version", ""))
    ut = payload.get("update_time") or ""
    key = f"{uid}|{version}|{ut}".encode("utf-8")
    return hashlib.sha256(key).hexdigest()


def b64u_encode_int(n: int) -> str:
    return base64.urlsafe_b64encode(str(n).encode()).decode()


def b64u_decode_int(s: str) -> int:
    try:
        return int(base64.urlsafe_b64decode(s.encode()).decode())
    except Exception:
        return 0


def echo_corr_headers(req: Request, resp: Response) -> None:
    tp = req.headers.get("traceparent")
    rid = req.headers.get("x-request-id")
    if tp:
        resp.headers["traceparent"] = tp
    if rid:
        resp.headers["x-request-id"] = rid


def problem(
    status_code: int,
    title: str,
    detail: Optional[str] = None,
    type_: str = "about:blank",
    extra: Optional[Dict[str, Any]] = None,
) -> HTTPException:
    payload: Dict[str, Any] = {"type": type_, "title": title, "status": status_code}
    if detail:
        payload["detail"] = detail
    if extra:
        payload.update(extra)
    return HTTPException(status_code=status_code, detail=payload)


# -----------------------------------------------------------------------------
# Domain enums and models (subset aligned with quest.proto)
# -----------------------------------------------------------------------------

class State(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class Difficulty(str, Enum):
    EASY = "EASY"
    NORMAL = "NORMAL"
    HARD = "HARD"
    EPIC = "EPIC"
    LEGENDARY = "LEGENDARY"


class Condition(BaseModel):
    all_of: Optional[List["Condition"]] = Field(default=None, description="ALL must be true")
    any_of: Optional[List["Condition"]] = Field(default=None, description="ANY must be true")
    not_: Optional["Condition"] = Field(default=None, alias="not", description="Negation")
    cel: Optional[str] = Field(default=None, description="CEL expression (server-side)")

    @root_validator
    def oneof_check(cls, values):
        present = [k for k, v in values.items() if k in {"all_of", "any_of", "not_", "cel"} and v]
        if len(present) > 1:
            raise ValueError("Condition expects exactly one of all_of/any_of/not/cel")
        if len(present) == 0:
            raise ValueError("Condition is empty")
        return values

    class Config:
        allow_population_by_field_name = True


class KillSpec(BaseModel):
    target: str
    count: int = Field(ge=1)


class CollectSpec(BaseModel):
    item: str
    count: int = Field(ge=1)


class VisitSpec(BaseModel):
    location_ids: List[str] = Field(min_items=1)


class DialogSpec(BaseModel):
    npc_id: str
    choices: List[str] = Field(default_factory=list)


class CustomSpec(BaseModel):
    data: Dict[str, Any] = Field(default_factory=dict)


class RewardKind(str, Enum):
    XP = "XP"
    CURRENCY = "CURRENCY"
    ITEM = "ITEM"
    UNLOCK = "UNLOCK"


class XpReward(BaseModel):
    amount: int = Field(ge=0)


class CurrencyReward(BaseModel):
    currency: str
    amount: int = Field(ge=0)


class ItemReward(BaseModel):
    item_id: str
    count: int = Field(ge=1)


class UnlockReward(BaseModel):
    key: str


class Reward(BaseModel):
    kind: RewardKind
    xp: Optional[XpReward] = None
    currency: Optional[CurrencyReward] = None
    item: Optional[ItemReward] = None
    unlock: Optional[UnlockReward] = None

    @root_validator
    def check_kind_payload(cls, values):
        kind = values.get("kind")
        mapping = {
            RewardKind.XP: "xp",
            RewardKind.CURRENCY: "currency",
            RewardKind.ITEM: "item",
            RewardKind.UNLOCK: "unlock",
        }
        field = mapping.get(kind)
        if not field:
            raise ValueError("Unsupported reward kind")
        if not values.get(field):
            raise ValueError(f"Reward payload '{field}' required for kind={kind}")
        # Ensure only one payload present
        payloads = [k for k in ["xp", "currency", "item", "unlock"] if values.get(k) is not None]
        if len(payloads) != 1:
            raise ValueError("Only one reward payload must be set")
        return values


class Requirement(BaseModel):
    min_level: Optional[int] = Field(default=None, ge=1)
    completed_quest: Optional[str] = None  # name: quests/{id}
    flag_key: Optional[str] = None
    flag_value: Optional[bool] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None

    @root_validator
    def check_oneof(cls, values):
        candidates = [
            v
            for v in [
                values.get("min_level"),
                values.get("completed_quest"),
                values.get("flag_key"),
                values.get("window_start"),
            ]
            if v is not None
        ]
        if len(candidates) == 0:
            raise ValueError("Requirement is empty")
        return values


class Step(BaseModel):
    id: Optional[str] = None
    title: Optional[str] = None
    narrative: Optional[str] = None
    condition: Optional[Condition] = None


class Objective(BaseModel):
    id: str = Field(regex=r"^[a-z0-9][a-z0-9-_]{0,62}$")
    title: str
    narrative: Optional[str] = None
    optional: bool = False
    success: Condition
    failure: Optional[Condition] = None
    steps: List[Step] = Field(default_factory=list)
    rewards: List[Reward] = Field(default_factory=list)
    kill: Optional[KillSpec] = None
    collect: Optional[CollectSpec] = None
    visit: Optional[VisitSpec] = None
    dialog: Optional[DialogSpec] = None
    custom: Optional[CustomSpec] = None

    @root_validator
    def oneof_spec(cls, values):
        cnt = sum(1 for k in ["kill", "collect", "visit", "dialog", "custom"] if values.get(k))
        if cnt > 1:
            raise ValueError("Only one of kill/collect/visit/dialog/custom may be set")
        return values


class Owner(BaseModel):
    owner_user_id: Optional[str] = None
    owner_org: Optional[str] = None

    @root_validator
    def exactly_one(cls, values):
        if bool(values.get("owner_user_id")) == bool(values.get("owner_org")):
            raise ValueError("Exactly one of owner_user_id or owner_org must be set")
        return values


class QuestBase(BaseModel):
    display_name: str = Field(min_length=1, max_length=128)
    description: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    owner: Owner
    state: State = State.DRAFT
    difficulty: Difficulty = Difficulty.NORMAL
    objectives: List[Objective] = Field(default_factory=list)
    rewards: List[Reward] = Field(default_factory=list)
    prerequisites: List[Requirement] = Field(default_factory=list)
    activate_time: Optional[datetime] = None
    expire_time: Optional[datetime] = None
    expected_duration_seconds: Optional[int] = Field(default=None, ge=0)
    unlisted: bool = False
    meta: Dict[str, Any] = Field(default_factory=dict)

    @validator("tags", each_item=True)
    def tag_norm(cls, v: str) -> str:
        return v.strip().lower()

    @validator("labels")
    def labels_keys_norm(cls, v: Dict[str, str]) -> Dict[str, str]:
        for k in v.keys():
            if not re.match(r"^[a-z0-9_.-]{1,64}$", k):
                raise ValueError(f"Invalid label key: {k}")
        return v

    @validator("objectives")
    def objectives_nonempty_if_active(cls, v, values):
        state = values.get("state")
        if state == State.ACTIVE and not v:
            raise ValueError("ACTIVE quest must have objectives")
        return v


class Quest(QuestBase):
    name: str  # "quests/{quest_id}"
    uid: str
    create_time: datetime
    update_time: datetime
    version: int
    etag: str


class QuestCreate(QuestBase):
    pass


class QuestUpdate(BaseModel):
    # Все поля опциональны, но валидация через отдельный apply
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None
    owner: Optional[Owner] = None
    state: Optional[State] = None
    difficulty: Optional[Difficulty] = None
    objectives: Optional[List[Objective]] = None
    rewards: Optional[List[Reward]] = None
    prerequisites: Optional[List[Requirement]] = None
    activate_time: Optional[datetime] = None
    expire_time: Optional[datetime] = None
    expected_duration_seconds: Optional[int] = Field(default=None, ge=0)
    unlisted: Optional[bool] = None
    meta: Optional[Dict[str, Any]] = None


# -----------------------------------------------------------------------------
# Repository interface and in-memory implementation
# -----------------------------------------------------------------------------

class QuestsRepository:
    """Абстрактный репозиторий (можно заменить на БД)."""

    def create(self, quest_id: str, data: QuestCreate) -> Quest:
        raise NotImplementedError

    def get(self, quest_id: str) -> Quest:
        raise NotImplementedError

    def update(self, quest_id: str, patch: QuestUpdate, if_match: Optional[str]) -> Quest:
        raise NotImplementedError

    def delete(self, quest_id: str, force: bool, if_match: Optional[str]) -> None:
        raise NotImplementedError

    def list(
        self,
        offset: int,
        limit: int,
        filters: Dict[str, Any],
        order_by: List[Tuple[str, bool]],
    ) -> Tuple[List[Quest], int]:
        raise NotImplementedError

    def batch_get(self, quest_ids: List[str]) -> List[Quest]:
        raise NotImplementedError

    def activate(self, quest_id: str) -> Quest:
        raise NotImplementedError

    def archive(self, quest_id: str, soft: bool) -> Quest:
        raise NotImplementedError


class InMemoryQuestsRepository(QuestsRepository):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._store: Dict[str, Dict[str, Any]] = {}  # quest_id -> raw dict
        self._deleted: Dict[str, Dict[str, Any]] = {}

    # Helpers

    def _serialize(self, quest_id: str, raw: Dict[str, Any]) -> Quest:
        # enrich computed fields
        raw["name"] = f"quests/{quest_id}"
        raw["etag"] = compute_etag(raw)
        return Quest(**raw)

    def _ensure_exists(self, quest_id: str) -> Dict[str, Any]:
        if quest_id not in self._store:
            raise problem(status.HTTP_404_NOT_FOUND, "Not Found", f"Quest {quest_id} not found")
        return self._store[quest_id]

    def create(self, quest_id: str, data: QuestCreate) -> Quest:
        with self._lock:
            if quest_id in self._store or quest_id in self._deleted:
                raise problem(status.HTTP_409_CONFLICT, "Already Exists", f"{quest_id} exists")
            now = utcnow()
            uid = str(uuid.uuid4())
            raw = data.dict()
            # normalize tags to unique/ordered
            raw["tags"] = sorted(set(raw.get("tags") or []))
            record = {
                **raw,
                "uid": uid,
                "create_time": now,
                "update_time": now,
                "version": 1,
                "state": raw.get("state", State.DRAFT),
            }
            self._store[quest_id] = record
            return self._serialize(quest_id, record)

    def get(self, quest_id: str) -> Quest:
        with self._lock:
            raw = self._ensure_exists(quest_id)
            return self._serialize(quest_id, raw)

    def update(self, quest_id: str, patch: QuestUpdate, if_match: Optional[str]) -> Quest:
        with self._lock:
            raw = self._ensure_exists(quest_id)
            current = self._serialize(quest_id, raw)
            if if_match and if_match != current.etag:
                raise problem(status.HTTP_412_PRECONDITION_FAILED, "Precondition Failed", "ETag mismatch")
            # apply patch
            data = patch.dict(exclude_unset=True)
            # validation snippets
            if "tags" in data and data["tags"] is not None:
                data["tags"] = sorted(set([t.strip().lower() for t in data["tags"]]))
            if "labels" in data and data["labels"] is not None:
                for k in data["labels"].keys():
                    if not re.match(r"^[a-z0-9_.-]{1,64}$", k):
                        raise problem(status.HTTP_400_BAD_REQUEST, "Invalid Label", f"Invalid label key: {k}")
            # state transition validations
            if "state" in data:
                new_state = data["state"]
                if new_state == State.ACTIVE and not (data.get("objectives") or raw.get("objectives")):
                    raise problem(status.HTTP_400_BAD_REQUEST, "Invalid State", "ACTIVE requires objectives")
            # persist
            raw.update(data)
            raw["update_time"] = utcnow()
            raw["version"] = int(raw.get("version", 1)) + 1
            return self._serialize(quest_id, raw)

    def delete(self, quest_id: str, force: bool, if_match: Optional[str]) -> None:
        with self._lock:
            raw = self._ensure_exists(quest_id)
            current = self._serialize(quest_id, raw)
            if if_match and if_match != current.etag:
                raise problem(status.HTTP_412_PRECONDITION_FAILED, "Precondition Failed", "ETag mismatch")
            if force:
                del self._store[quest_id]
            else:
                # soft delete: move to deleted, mark unlisted and ARCHIVED
                raw = self._store.pop(quest_id)
                raw["state"] = State.ARCHIVED
                raw["unlisted"] = True
                raw["update_time"] = utcnow()
                self._deleted[quest_id] = raw

    def list(
        self,
        offset: int,
        limit: int,
        filters: Dict[str, Any],
        order_by: List[Tuple[str, bool]],
    ) -> Tuple[List[Quest], int]:
        with self._lock:
            items = []
            for qid, raw in self._store.items():
                if self._match_filters(raw, filters):
                    items.append(self._serialize(qid, raw))
            total = len(items)
            # order
            for key, desc in reversed(order_by or []):
                items.sort(key=lambda x: getattr(x, key, None), reverse=desc)
            # slice
            page = items[offset : offset + limit]
            return page, total

    def _match_filters(self, raw: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        # Supported filters: state, difficulty, tag (contains), labels.<k>==v, unlisted:bool
        st = filters.get("state")
        if st and str(raw.get("state")) != st:
            return False
        df = filters.get("difficulty")
        if df and str(raw.get("difficulty")) != df:
            return False
        unl = filters.get("unlisted")
        if unl is not None and bool(raw.get("unlisted", False)) != unl:
            return False
        tag = filters.get("tag")
        if tag and tag not in (raw.get("tags") or []):
            return False
        for lk, lv in filters.get("label_eq", []):
            if (raw.get("labels") or {}).get(lk) != lv:
                return False
        return True

    def batch_get(self, quest_ids: List[str]) -> List[Quest]:
        with self._lock:
            out = []
            for qid in quest_ids:
                if qid in self._store:
                    out.append(self._serialize(qid, self._store[qid]))
            return out

    def activate(self, quest_id: str) -> Quest:
        with self._lock:
            raw = self._ensure_exists(quest_id)
            if not raw.get("objectives"):
                raise problem(status.HTTP_400_BAD_REQUEST, "Invalid State", "ACTIVE requires objectives")
            raw["state"] = State.ACTIVE
            raw["activate_time"] = utcnow()
            raw["update_time"] = utcnow()
            raw["version"] = int(raw.get("version", 1)) + 1
            return self._serialize(quest_id, raw)

    def archive(self, quest_id: str, soft: bool) -> Quest:
        with self._lock:
            raw = self._ensure_exists(quest_id)
            raw["state"] = State.ARCHIVED
            if soft:
                raw["unlisted"] = True
            raw["update_time"] = utcnow()
            raw["version"] = int(raw.get("version", 1)) + 1
            return self._serialize(quest_id, raw)


# Single repository instance for the process (replace with DI/wiring as needed)
_repo = InMemoryQuestsRepository()


def get_repo() -> QuestsRepository:
    return _repo


# -----------------------------------------------------------------------------
# Dependencies (authn placeholder)
# -----------------------------------------------------------------------------

class Principal(BaseModel):
    sub: str = "anonymous"


def get_principal(authorization: Optional[str] = Header(default=None)) -> Principal:
    # Простейший плейсхолдер; в проде заменить на OAuth/JWT проверку
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        # Не разбираем токен, только эхо subject для трассировки примеров
        return Principal(sub=f"bearer:{hashlib.sha1(token.encode()).hexdigest()[:8]}")
    return Principal()


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@router.post(
    "/quests",
    response_model=Quest,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"content": {"application/problem+json": {}}}},
)
def create_quest(
    request: Request,
    response: Response,
    payload: QuestCreate = Body(...),
    quest_id: Optional[str] = Query(default=None, regex=SLUG_RE.pattern, description="Slug id"),
    repo: QuestsRepository = Depends(get_repo),
    principal: Principal = Depends(get_principal),
):
    qid = quest_id or _make_slug(payload.display_name)
    if not SLUG_RE.match(qid):
        raise problem(status.HTTP_400_BAD_REQUEST, "Invalid quest_id", "Slug must be 1..63 dns-safe")
    created = repo.create(qid, payload)
    response.headers["ETag"] = created.etag
    echo_corr_headers(request, response)
    return created


@router.get(
    "/quests/{quest_id}",
    response_model=Quest,
    responses={404: {"content": {"application/problem+json": {}}}},
)
def get_quest(
    request: Request,
    response: Response,
    quest_id: str = Path(..., regex=SLUG_RE.pattern),
    repo: QuestsRepository = Depends(get_repo),
):
    q = repo.get(quest_id)
    response.headers["ETag"] = q.etag
    echo_corr_headers(request, response)
    return q


@router.patch(
    "/quests/{quest_id}",
    response_model=Quest,
    responses={
        400: {"content": {"application/problem+json": {}}},
        404: {"content": {"application/problem+json": {}}},
        412: {"content": {"application/problem+json": {}}},
    },
)
def update_quest(
    request: Request,
    response: Response,
    quest_id: str = Path(..., regex=SLUG_RE.pattern),
    patch: QuestUpdate = Body(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    repo: QuestsRepository = Depends(get_repo),
    principal: Principal = Depends(get_principal),
):
    updated = repo.update(quest_id, patch, if_match)
    response.headers["ETag"] = updated.etag
    echo_corr_headers(request, response)
    return updated


@router.delete(
    "/quests/{quest_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        404: {"content": {"application/problem+json": {}}},
        412: {"content": {"application/problem+json": {}}},
    },
)
def delete_quest(
    request: Request,
    response: Response,
    quest_id: str = Path(..., regex=SLUG_RE.pattern),
    force: bool = Query(default=False, description="Hard delete if true"),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    repo: QuestsRepository = Depends(get_repo),
    principal: Principal = Depends(get_principal),
):
    repo.delete(quest_id, force=force, if_match=if_match)
    echo_corr_headers(request, response)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


class ListQuestsResponse(BaseModel):
    quests: List[Quest]
    next_page_token: Optional[str] = None
    total_size: int


@router.get(
    "/quests",
    response_model=ListQuestsResponse,
)
def list_quests(
    request: Request,
    response: Response,
    page_size: int = Query(default=50, ge=1, le=500),
    page_token: Optional[str] = Query(default=None),
    filter: Optional[str] = Query(default=None, description="filter: state=ACTIVE AND tag=event AND labels.owner=ai"),
    order_by: Optional[str] = Query(default="create_time desc"),
    repo: QuestsRepository = Depends(get_repo),
):
    offset = b64u_decode_int(page_token) if page_token else 0
    filters = _parse_filter(filter or "")
    order = _parse_order(order_by)
    items, total = repo.list(offset=offset, limit=page_size, filters=filters, order_by=order)
    next_token = None
    if offset + page_size < total:
        next_token = b64u_encode_int(offset + page_size)
    echo_corr_headers(request, response)
    return ListQuestsResponse(quests=items, next_page_token=next_token, total_size=total)


class BatchGetResponse(BaseModel):
    quests: List[Quest]


@router.get(
    "/quests:batchGet",
    response_model=BatchGetResponse,
)
def batch_get(
    request: Request,
    response: Response,
    names: List[str] = Query(..., description="Repeated: names=quests/foo&names=quests/bar"),
    repo: QuestsRepository = Depends(get_repo),
):
    quest_ids = []
    for n in names:
        m = re.fullmatch(r"quests/([a-z0-9][a-z0-9-_]{0,62})", n)
        if not m:
            raise problem(status.HTTP_400_BAD_REQUEST, "Invalid name", f"Bad resource name: {n}")
        quest_ids.append(m.group(1))
    items = repo.batch_get(quest_ids)
    echo_corr_headers(request, response)
    return BatchGetResponse(quests=items)


@router.post(
    "/quests/{quest_id}:activate",
    response_model=Quest,
    responses={
        400: {"content": {"application/problem+json": {}}},
        404: {"content": {"application/problem+json": {}}},
    },
)
def activate_quest(
    request: Request,
    response: Response,
    quest_id: str = Path(..., regex=SLUG_RE.pattern),
    repo: QuestsRepository = Depends(get_repo),
):
    q = repo.activate(quest_id)
    response.headers["ETag"] = q.etag
    echo_corr_headers(request, response)
    return q


@router.post(
    "/quests/{quest_id}:archive",
    response_model=Quest,
)
def archive_quest(
    request: Request,
    response: Response,
    quest_id: str = Path(..., regex=SLUG_RE.pattern),
    soft: bool = Query(default=True),
    repo: QuestsRepository = Depends(get_repo),
):
    q = repo.archive(quest_id, soft=soft)
    response.headers["ETag"] = q.etag
    echo_corr_headers(request, response)
    return q


# -----------------------------------------------------------------------------
# Helpers (filters, ordering, slug)
# -----------------------------------------------------------------------------

def _make_slug(name: str) -> str:
    s = name.strip().lower()
    s = re.sub(r"[^a-z0-9-_]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    if not s:
        s = f"q-{int(time.time())}"
    return s[:63]


def _parse_filter(expr: str) -> Dict[str, Any]:
    """
    Поддерживаем минимальный синтаксис через 'AND':
      state=ACTIVE
      difficulty=HARD
      tag=foo
      labels.owner=ai
      unlisted=true|false
    """
    if not expr:
        return {}
    parts = [p.strip() for p in expr.split("AND")]
    out: Dict[str, Any] = {"label_eq": []}
    for p in parts:
        if not p:
            continue
        if "=" not in p:
            raise problem(status.HTTP_400_BAD_REQUEST, "Invalid filter", f"Expected key=value in '{p}'")
        key, value = [x.strip() for x in p.split("=", 1)]
        if key == "state":
            out["state"] = value.upper()
        elif key == "difficulty":
            out["difficulty"] = value.upper()
        elif key == "tag":
            out["tag"] = value.lower()
        elif key == "unlisted":
            out["unlisted"] = value.lower() in ("1", "true", "yes")
        elif key.startswith("labels."):
            out["label_eq"].append((key.split(".", 1)[1], value))
        else:
            raise problem(status.HTTP_400_BAD_REQUEST, "Invalid filter key", f"Unknown key: {key}")
    return out


def _parse_order(expr: Optional[str]) -> List[Tuple[str, bool]]:
    """
    order_by: "create_time desc, difficulty"
    Возвращает список кортежей (field, desc:bool)
    Разрешённые поля: create_time, update_time, difficulty, state, display_name
    """
    if not expr:
        return [("create_time", True)]
    out: List[Tuple[str, bool]] = []
    allowed = {"create_time", "update_time", "difficulty", "state", "display_name"}
    for part in expr.split(","):
        p = part.strip()
        if not p:
            continue
        toks = p.split()
        field = toks[0]
        if field not in allowed:
            raise problem(status.HTTP_400_BAD_REQUEST, "Invalid order_by", f"Unknown field: {field}")
        desc = len(toks) > 1 and toks[1].lower() == "desc"
        out.append((field, desc))
    return out or [("create_time", True)]
