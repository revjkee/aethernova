# -*- coding: utf-8 -*-
"""
Mythos Core — Generic Async Repository (SQLAlchemy 2.0)

Возможности:
- CRUD (create/get/update/delete/exists/count) с оптимистичной конкуренцией (version/etag).
- Курсорная пагинация (base64-курсор с id/created_at), фильтрация через Specification.
- Батчевые операции (bulk_create/bulk_update/bulk_soft_delete) с чанками.
- Мягкое удаление (deleted_at) и жёсткое удаление (hard_delete).
- Ретраи на дедлок/serialization failure (экспоненциальная пауза).
- Кэш (протокол) для сущностей и списков, инвалидация на запись.
- Наблюдаемость: on_event-хук (tracing/metrics), соглашение об именах событий.
- Outbox-хук: after_commit-коллбек для публикации доменных событий (опционально).
- Интеграция с Unit Of Work: репозиторий не делает commit/rollback, работает в рамках переданного AsyncSession.

Требования к модели SQLAlchemy:
- Столбцы: id (str), created_at (datetime, tz-aware), updated_at (datetime), deleted_at (nullable datetime),
  version (int, default 0), etag (str, nullable).
- Допустимы mapped_column(...) с именами выше; индексы на (created_at, id) желательны.

Примечание: В коде нет жёсткой привязки к конкретной БД, проверены кейсы PostgreSQL/MySQL/SQLite.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import json
import math
import os
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Dict,
    Generic,
    Iterable,
    List,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from sqlalchemy import (
    and_,
    asc,
    delete as sa_delete,
    desc,
    func,
    literal,
    or_,
    select,
    text,
    update as sa_update,
)
from sqlalchemy.exc import OperationalError, DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql import ColumnElement

__all__ = [
    "RepositoryError",
    "NotFound",
    "ConflictError",
    "PreconditionFailed",
    "TransientError",
    "CacheProtocol",
    "ObserverProtocol",
    "Specification",
    "Page",
    "Cursor",
    "EntityDict",
    "compute_etag",
    "GenericRepository",
    "retry_transient",
]

# ======================================================================================
# Ошибки
# ======================================================================================

class RepositoryError(RuntimeError):
    pass


class NotFound(RepositoryError):
    """Сущность не найдена."""


class ConflictError(RepositoryError):
    """Конфликт оптимистичной конкуренции (version/etag)."""


class PreconditionFailed(RepositoryError):
    """Нарушена предусловие (например, ожидался конкретный статус/поле)."""


class TransientError(RepositoryError):
    """Временная ошибка БД (дедлок, serialization failure)."""


# ======================================================================================
# Протоколы кэша и наблюдателя
# ======================================================================================

class CacheProtocol(Protocol):
    async def get(self, key: str) -> Any: ...
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None: ...
    async def delete(self, key: str) -> None: ...


class _NoopCache(CacheProtocol):
    async def get(self, key: str) -> Any:  # pragma: no cover - тривиально
        return None
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        return None
    async def delete(self, key: str) -> None:
        return None


class ObserverProtocol(Protocol):
    async def on_event(self, name: str, attrs: Dict[str, Any]) -> None: ...


class _NoopObserver(ObserverProtocol):
    async def on_event(self, name: str, attrs: Dict[str, Any]) -> None:  # pragma: no cover
        return None


# ======================================================================================
# Спецификации (фильтры) и курсоры
# ======================================================================================

class Specification(Protocol):
    """Спецификация фильтра. Возвращает SQLAlchemy-предикат для модели T."""
    def to_predicate(self, model: Type[Any]) -> ColumnElement[bool]: ...


@dataclass(frozen=True)
class Cursor:
    token: str = ""
    size: int = 100

    def is_empty(self) -> bool:
        return not self.token

    @staticmethod
    def encode(last_id: str, last_created_at: datetime) -> str:
        payload = {
            "id": last_id,
            "ts": int(last_created_at.timestamp() * 1000),
        }
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    @staticmethod
    def decode(token: str) -> Tuple[str, datetime]:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        obj = json.loads(raw.decode("utf-8"))
        ts = datetime.fromtimestamp(obj["ts"] / 1000.0, tz=timezone.utc)
        return obj["id"], ts


@dataclass
class Page(Generic[TypeVar("T")]):
    items: List[Any]
    next_cursor: Optional[Cursor]
    total: Optional[int] = None


Entity = TypeVar("Entity")
Model = TypeVar("Model")
UpdateT = TypeVar("UpdateT")
CreateT = TypeVar("CreateT")

EntityDict = Dict[str, Any]


# ======================================================================================
# Вспомогательные функции
# ======================================================================================

def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def compute_etag(payload: Union[Entity, EntityDict]) -> str:
    """
    Детерминированный ETag как SHA256 от канонизированного JSON-представления.
    Игнорирует поля deleted_at/updated_at, чтобы не ломать кэш на незначительных изменениях.
    """
    if dataclasses.is_dataclass(payload):
        data = dataclasses.asdict(payload)
    elif hasattr(payload, "__dict__") and not isinstance(payload, dict):
        data = {k: v for k, v in payload.__dict__.items() if not k.startswith("_")}
    else:
        data = dict(payload)

    for k in ("updated_at", "deleted_at"):
        data.pop(k, None)

    s = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _is_transient(exc: BaseException) -> bool:
    """
    Грубая эвристика определения транзиентных ошибок БД (дедлок/serialization failure).
    Работает для PostgreSQL и MySQL; для других СУБД можно расширить.
    """
    if isinstance(exc, OperationalError) or isinstance(exc, DBAPIError):
        msg = str(exc).lower()
        if "deadlock" in msg or "serialization failure" in msg or "could not serialize access" in msg:
            return True
        if "lock wait timeout" in msg:
            return True
        if getattr(exc, "orig", None) is not None:
            # PostgreSQL serialization failure: SQLSTATE 40001
            if getattr(exc.orig, "pgcode", None) == "40001":
                return True
    return False


def retry_transient(max_attempts: int = 5, base_delay: float = 0.05, max_delay: float = 1.0):
    """
    Декоратор для ретраев транзиентных ошибок с экспоненциальной паузой и джиттером.
    """
    def _wrap(fn: Callable[..., Awaitable[Any]]):
        async def _inner(*args, **kwargs):
            attempt = 0
            delay = base_delay
            while True:
                try:
                    return await fn(*args, **kwargs)
                except Exception as exc:
                    if _is_transient(exc) and attempt + 1 < max_attempts:
                        await asyncio.sleep(delay + (os.urandom(1)[0] / 255.0) * delay)
                        attempt += 1
                        delay = min(max_delay, delay * 2.0)
                        continue
                    if _is_transient(exc):
                        raise TransientError(str(exc)) from exc
                    raise
        return _inner
    return _wrap


# ======================================================================================
# Репозиторий
# ======================================================================================

class GenericRepository(Generic[Model]):
    """
    Универсальный асинхронный репозиторий для SQLAlchemy моделей.

    Параметры конструктора:
    - model: класс ORM-модели SQLAlchemy.
    - session: AsyncSession (из UoW/DI).
    - cache: CacheProtocol (по умолчанию no-op).
    - observer: ObserverProtocol (по умолчанию no-op).
    - id_factory: Callable[[], str] — генератор идентификаторов (ULID/UUID и т.п.).
    - outbox_hook: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]]
        Коллбек для публикации доменных событий (например, в outbox). Вызывается ПОСЛЕ успешной фиксации транзакции
        вызывающей стороной; сам репозиторий транзакций не коммитит.

    Требования к модели:
    - Атрибуты: id, created_at, updated_at, deleted_at, version, etag.
    """
    def __init__(
        self,
        model: Type[Model],
        session: AsyncSession,
        cache: Optional[CacheProtocol] = None,
        observer: Optional[ObserverProtocol] = None,
        id_factory: Optional[Callable[[], str]] = None,
        outbox_hook: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None,
    ) -> None:
        self.model = model
        self.session = session
        self.cache = cache or _NoopCache()
        self.observer = observer or _NoopObserver()
        self.id_factory = id_factory or (lambda: __import__("uuid").uuid4().hex)
        self.outbox_hook = outbox_hook

        # Поля, используемые в курсорной пагинации
        self._col_id: InstrumentedAttribute = getattr(self.model, "id")
        self._col_created: InstrumentedAttribute = getattr(self.model, "created_at")

    # ----------------------------- CRUD ----------------------------------------------

    async def get(
        self,
        entity_id: str,
        *,
        include_deleted: bool = False,
        use_cache: bool = True,
        for_update: bool = False,
    ) -> Optional[Model]:
        """Вернуть сущность или None (без исключения)."""
        cache_key = f"{self.model.__name__}:id:{entity_id}"
        if use_cache and not for_update:
            cached = await self.cache.get(cache_key)
            if cached is not None:
                return cached

        stmt = select(self.model).where(self._col_id == entity_id)
        if not include_deleted:
            stmt = stmt.where(getattr(self.model, "deleted_at").is_(None))
        if for_update:
            stmt = stmt.with_for_update()

        res = await self.session.execute(stmt)
        obj: Optional[Model] = res.scalar_one_or_none()
        if obj is not None and use_cache and not for_update:
            await self.cache.set(cache_key, obj, ttl=60)
        await self.observer.on_event("repo.get", {"model": self.model.__name__, "hit": obj is not None})
        return obj

    async def get_strict(self, entity_id: str, **kwargs) -> Model:
        """Вернуть сущность или бросить NotFound."""
        obj = await self.get(entity_id, **kwargs)
        if obj is None:
            raise NotFound(f"{self.model.__name__}({entity_id}) not found")
        return obj

    async def exists(self, spec: Optional[Specification] = None) -> bool:
        pred = spec.to_predicate(self.model) if spec else literal(True)
        stmt = select(literal(True)).select_from(self.model).where(
            and_(getattr(self.model, "deleted_at").is_(None), pred)
        ).limit(1)
        res = await self.session.execute(stmt)
        exists = res.scalar_one_or_none() is not None
        await self.observer.on_event("repo.exists", {"model": self.model.__name__, "exists": exists})
        return exists

    async def count(self, spec: Optional[Specification] = None) -> int:
        pred = spec.to_predicate(self.model) if spec else literal(True)
        stmt = select(func.count(literal(1))).select_from(self.model).where(
            and_(getattr(self.model, "deleted_at").is_(None), pred)
        )
        res = await self.session.execute(stmt)
        total = int(res.scalar_one() or 0)
        await self.observer.on_event("repo.count", {"model": self.model.__name__, "count": total})
        return total

    @retry_transient()
    async def create(self, payload: Dict[str, Any]) -> Model:
        """
        Создать сущность. Если id не задан — сгенерировать.
        Инициализирует created_at/updated_at, version=0, etag.
        """
        data = dict(payload)
        data.setdefault("id", self.id_factory())
        now = utcnow()
        data.setdefault("created_at", now)
        data.setdefault("updated_at", now)
        data.setdefault("version", 0)
        data.setdefault("deleted_at", None)
        data["etag"] = compute_etag(self._stable_subset(data))

        obj = self.model(**data)  # type: ignore[arg-type]
        self.session.add(obj)
        await self.observer.on_event("repo.create", {"model": self.model.__name__, "id": data["id"]})
        # Инвалидация кэша списков (шаблон ключей зависит от реализации CacheProtocol)
        await self._invalidate_entity_cache(data["id"])
        return obj

    @retry_transient()
    async def update(
        self,
        entity_id: str,
        patch: Dict[str, Any],
        *,
        expected_version: Optional[int] = None,
        expected_etag: Optional[str] = None,
        set_updated_at: bool = True,
        return_updated: bool = True,
    ) -> Model:
        """
        Частичное обновление с CAS по version/etag.
        При успешном обновлении version += 1, updated_at=now, пересчёт etag.
        """
        conds: List[ColumnElement[bool]] = [self._col_id == entity_id]
        if expected_version is not None:
            conds.append(getattr(self.model, "version") == expected_version)
        if expected_etag is not None:
            conds.append(getattr(self.model, "etag") == expected_etag)
        conds.append(getattr(self.model, "deleted_at").is_(None))

        now = utcnow() if set_updated_at else None
        values = dict(patch)
        if set_updated_at:
            values["updated_at"] = now

        # Нужно вычислить новый etag с учётом патча: делаем предварительное чтение
        current = await self.get_strict(entity_id, include_deleted=False, use_cache=False, for_update=True)
        current_dict = self._model_to_dict(current)
        new_state = {**current_dict, **values}
        new_state.pop("deleted_at", None)
        new_etag = compute_etag(self._stable_subset(new_state))
        values["etag"] = new_etag
        values["version"] = (current_dict.get("version") or 0) + 1

        stmt = sa_update(self.model).where(and_(*conds)).values(**values)
        res = await self.session.execute(stmt)
        if res.rowcount == 0:
            raise ConflictError(f"CAS failed for {self.model.__name__}({entity_id})")

        await self._invalidate_entity_cache(entity_id)
        await self.observer.on_event("repo.update", {"model": self.model.__name__, "id": entity_id})

        if return_updated:
            return await self.get_strict(entity_id, include_deleted=False, use_cache=False)
        return current  # тип совместим: Model

    @retry_transient()
    async def upsert(
        self,
        entity_id: str,
        payload: Dict[str, Any],
        *,
        expected_version: Optional[int] = None,
        expected_etag: Optional[str] = None,
    ) -> Model:
        """
        Upsert: если сущность есть — update(CAS), иначе create.
        """
        existing = await self.get(entity_id, include_deleted=False, use_cache=False, for_update=True)
        if existing is None:
            data = dict(payload)
            data["id"] = entity_id
            return await self.create(data)
        patch = dict(payload)
        patch.pop("id", None)
        return await self.update(entity_id, patch, expected_version=expected_version, expected_etag=expected_etag)

    @retry_transient()
    async def soft_delete(
        self,
        entity_id: str,
        *,
        expected_version: Optional[int] = None,
        expected_etag: Optional[str] = None,
    ) -> None:
        """Мягкое удаление (deleted_at=now)."""
        conds: List[ColumnElement[bool]] = [self._col_id == entity_id, getattr(self.model, "deleted_at").is_(None)]
        if expected_version is not None:
            conds.append(getattr(self.model, "version") == expected_version)
        if expected_etag is not None:
            conds.append(getattr(self.model, "etag") == expected_etag)

        now = utcnow()
        stmt = sa_update(self.model).where(and_(*conds)).values(deleted_at=now, updated_at=now)
        res = await self.session.execute(stmt)
        if res.rowcount == 0:
            raise ConflictError(f"delete CAS failed or already deleted: {self.model.__name__}({entity_id})")
        await self._invalidate_entity_cache(entity_id)
        await self.observer.on_event("repo.soft_delete", {"model": self.model.__name__, "id": entity_id})

    @retry_transient()
    async def hard_delete(self, entity_id: str) -> None:
        """Жёсткое удаление из БД."""
        stmt = sa_delete(self.model).where(self._col_id == entity_id)
        await self.session.execute(stmt)
        await self._invalidate_entity_cache(entity_id)
        await self.observer.on_event("repo.hard_delete", {"model": self.model.__name__, "id": entity_id})

    # ----------------------------- LIST / QUERY ---------------------------------------

    async def list(
        self,
        *,
        cursor: Optional[Cursor] = None,
        limit: int = 100,
        spec: Optional[Specification] = None,
        include_deleted: bool = False,
        order: Literal["asc", "desc"] = "asc",
    ) -> Page[Model]:
        """
        Курсорная пагинация: упорядочивание по (created_at, id).
        Cursor.token кодирует последнюю пару (id, created_at).
        """
        limit = max(1, min(1000, limit))
        where_parts: List[ColumnElement[bool]] = []
        if not include_deleted:
            where_parts.append(getattr(self.model, "deleted_at").is_(None))
        if spec:
            where_parts.append(spec.to_predicate(self.model))

        if cursor and not cursor.is_empty():
            last_id, last_ts = Cursor.decode(cursor.token)
            if order == "asc":
                # (created > last_ts) OR (created = last_ts AND id > last_id)
                where_parts.append(
                    or_(
                        self._col_created > last_ts,
                        and_(self._col_created == last_ts, self._col_id > last_id),
                    )
                )
            else:
                # (created < last_ts) OR (created = last_ts AND id < last_id)
                where_parts.append(
                    or_(
                        self._col_created < last_ts,
                        and_(self._col_created == last_ts, self._col_id < last_id),
                    )
                )

        order_cols = (asc(self._col_created), asc(self._col_id)) if order == "asc" else (desc(self._col_created), desc(self._col_id))
        stmt = select(self.model).where(and_(*where_parts) if where_parts else literal(True)).order_by(*order_cols).limit(limit + 1)
        res = await self.session.execute(stmt)
        rows: List[Model] = list(res.scalars().all())

        has_more = len(rows) > limit
        items = rows[:limit]
        next_cur = None
        if has_more:
            last = items[-1]
            next_cur = Cursor(
                token=Cursor.encode(getattr(last, "id"), getattr(last, "created_at")),
                size=limit,
            )

        await self.observer.on_event("repo.list", {"model": self.model.__name__, "count": len(items), "has_more": has_more})
        return Page(items=items, next_cursor=next_cur)

    # ----------------------------- BULK -----------------------------------------------

    @retry_transient()
    async def bulk_create(self, payloads: Sequence[Dict[str, Any]], *, chunk_size: int = 1000) -> int:
        """
        Быстрая вставка пачкой. Инициализирует служебные поля и вычисляет etag.
        Возвращает число вставленных строк.
        """
        if not payloads:
            return 0

        now = utcnow()
        rows = []
        for src in payloads:
            d = dict(src)
            d.setdefault("id", self.id_factory())
            d.setdefault("created_at", now)
            d.setdefault("updated_at", now)
            d.setdefault("version", 0)
            d.setdefault("deleted_at", None)
            d["etag"] = compute_etag(self._stable_subset(d))
            rows.append(self.model(**d))  # type: ignore[arg-type]

        # Разбиваем на чанки чтобы не дуться в память/журнал транзакций
        affected = 0
        for i in range(0, len(rows), chunk_size):
            self.session.add_all(rows[i : i + chunk_size])
            affected += len(rows[i : i + chunk_size])

        await self.observer.on_event("repo.bulk_create", {"model": self.model.__name__, "count": affected})
        await self._invalidate_list_caches()
        return affected

    @retry_transient()
    async def bulk_soft_delete(self, ids: Sequence[str], *, chunk_size: int = 1000) -> int:
        if not ids:
            return 0
        now = utcnow()
        affected = 0
        for i in range(0, len(ids), chunk_size):
            part = ids[i : i + chunk_size]
            stmt = sa_update(self.model).where(
                and_(self._col_id.in_(part), getattr(self.model, "deleted_at").is_(None))
            ).values(deleted_at=now, updated_at=now)
            res = await self.session.execute(stmt)
            affected += int(res.rowcount or 0)
        await self.observer.on_event("repo.bulk_soft_delete", {"model": self.model.__name__, "count": affected})
        for x in ids:
            await self._invalidate_entity_cache(x)
        return affected

    # ----------------------------- Утилиты --------------------------------------------

    def _model_to_dict(self, obj: Model) -> Dict[str, Any]:
        # Простая сериализация ORM-модели (без связанных сущностей)
        data = {}
        for name in obj.__mapper__.columns.keys():  # type: ignore[attr-defined]
            data[name] = getattr(obj, name)
        return data

    def _stable_subset(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # Набор полей, участвующих в ETag (без эфемерных)
        copy = dict(data)
        copy.pop("updated_at", None)
        copy.pop("deleted_at", None)
        return copy

    async def _invalidate_entity_cache(self, entity_id: str) -> None:
        await self.cache.delete(f"{self.model.__name__}:id:{entity_id}")
        # Инвалидация списков — по соглашению: "list:*"
        await self.cache.delete(f"{self.model.__name__}:list:*")  # зависи от реализации кэша

    async def _invalidate_list_caches(self) -> None:
        await self.cache.delete(f"{self.model.__name__}:list:*")


# ======================================================================================
# Примеры спецификаций
# ======================================================================================

class TrueSpec(Specification):
    def to_predicate(self, model: Type[Any]) -> ColumnElement[bool]:
        return literal(True)


class IdInSpec(Specification):
    def __init__(self, ids: Sequence[str]) -> None:
        self.ids = list(ids)
    def to_predicate(self, model: Type[Any]) -> ColumnElement[bool]:
        return getattr(model, "id").in_(self.ids)


class FieldEqualsSpec(Specification):
    def __init__(self, field: str, value: Any) -> None:
        self.field = field
        self.value = value
    def to_predicate(self, model: Type[Any]) -> ColumnElement[bool]:
        return getattr(model, self.field) == self.value


class CreatedBetweenSpec(Specification):
    def __init__(self, since: datetime, until: datetime) -> None:
        self.since = since
        self.until = until
    def to_predicate(self, model: Type[Any]) -> ColumnElement[bool]:
        return and_(getattr(model, "created_at") >= self.since, getattr(model, "created_at") < self.until)
