# ledger-core/ledger/adapters/db/repository.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Generic,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from sqlalchemy import Select, and_, delete, func, insert, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql import ColumnElement

# Логгер адаптера
log = logging.getLogger("ledger.adapters.db.repository")

# ===================== Типы и базовые датаклассы =====================

TModel = TypeVar("TModel")       # ORM класс модели
TId = TypeVar("TId", bound=Union[str, int])

@dataclass(frozen=True)
class Page(Generic[TModel]):
    items: List[TModel]
    total: Optional[int] = None
    next: Optional[str] = None  # курсор base64/строка по вашему контракту

@dataclass(frozen=True)
class Sort:
    field: InstrumentedAttribute[Any]
    direction: Literal["asc", "desc"] = "asc"

@dataclass(frozen=True)
class Cursor:
    """Простой курсор на основе составного ключа."""
    values: Tuple[Any, ...]


# ===================== Повторы транзакций при конфликте/серилизации =====================

@dataclass(frozen=True)
class RetryConfig:
    max_attempts: int = 5
    base_delay: float = 0.025
    max_delay: float = 0.5
    jitter: float = 0.2  # +/- 20%

PG_RETRY_CODES = {"40001", "40P01"}  # serialization_failure / deadlock_detected


def _sleep_backoff(attempt: int, cfg: RetryConfig) -> float:
    d = min(cfg.max_delay, cfg.base_delay * (2 ** (attempt - 1)))
    j = d * cfg.jitter
    # псевдослучайный разброс без глобальных зависимостей
    r = (time.perf_counter_ns() % 10_000) / 10_000.0
    return max(0.0, d + (r * 2 * j - j))


async def _retry_on_serialization(
    func: Callable[[], Awaitable[Any]],
    *,
    name: str,
    cfg: RetryConfig,
) -> Any:
    attempt = 1
    while True:
        try:
            return await func()
        except (OperationalError, DBAPIError) as e:
            code = getattr(getattr(e, "orig", None), "pgcode", None)
            if code in PG_RETRY_CODES and attempt < cfg.max_attempts:
                delay = _sleep_backoff(attempt, cfg)
                log.warning("DB retry %s attempt=%d code=%s delay=%.3fs", name, attempt, code, delay)
                await asyncio.sleep(delay)
                attempt += 1
                continue
            raise


# ===================== Unit Of Work =====================

@dataclass
class UnitOfWork:
    session: AsyncSession
    _closed: bool = False

    async def __aenter__(self) -> "UnitOfWork":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.dispose(exc is None)

    async def commit(self) -> None:
        await self.session.commit()

    async def rollback(self) -> None:
        with contextlib.suppress(Exception):
            await self.session.rollback()

    async def dispose(self, ok: bool) -> None:
        if self._closed:
            return
        try:
            if ok:
                with contextlib.suppress(Exception):
                    await self.session.commit()
            else:
                with contextlib.suppress(Exception):
                    await self.session.rollback()
        finally:
            self._closed = True
            with contextlib.suppress(Exception):
                await self.session.close()


# ===================== Базовый репозиторий =====================

class BaseRepository(ABC, Generic[TModel, TId]):
    """
    Базовый абстрактный репозиторий.
    Наследники определяют:
      - model: ORM класс
      - id_attr: поле первичного ключа (InstrumentedAttribute)
      - (опционально) deleted_attr для мягкого удаления (bool)
      - уникальные ключи для upsert
    """
    model: Type[TModel]
    id_attr: InstrumentedAttribute[Any]
    deleted_attr: Optional[InstrumentedAttribute[bool]] = None  # мягкое удаление

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        retry: RetryConfig | None = None,
        default_timeout_s: float = 5.0,
    ) -> None:
        self._sf = session_factory
        self._retry = retry or RetryConfig()
        self._timeout = default_timeout_s

    # ---------- контекст/юоW ----------
    async def uow(self) -> UnitOfWork:
        sess = self._sf()
        return UnitOfWork(session=sess)

    # ---------- CRUD ----------
    async def get(self, id_: TId, *, for_update: bool = False, include_deleted: bool = False) -> Optional[TModel]:
        async with self._sf() as s:
            stmt = select(self.model).where(self.id_attr == id_)
            if self.deleted_attr is not None and not include_deleted:
                stmt = stmt.where(self.deleted_attr.is_(False))
            if for_update:
                stmt = stmt.with_for_update()
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            return res.scalar_one_or_none()

    async def list(
        self,
        *,
        where: Optional[Sequence[ColumnElement[bool]]] = None,
        order: Optional[Sequence[Sort]] = None,
        limit: int = 100,
        offset: Optional[int] = None,
        include_deleted: bool = False,
    ) -> List[TModel]:
        async with self._sf() as s:
            stmt: Select[Any] = select(self.model)
            conds: List[ColumnElement[bool]] = []
            if self.deleted_attr is not None and not include_deleted:
                conds.append(self.deleted_attr.is_(False))
            if where:
                conds.extend(where)
            if conds:
                stmt = stmt.where(and_(*conds))
            if order:
                for o in order:
                    stmt = stmt.order_by(o.field.asc() if o.direction == "asc" else o.field.desc())
            stmt = stmt.limit(limit)
            if offset is not None:
                stmt = stmt.offset(offset)
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            return list(res.scalars().all())

    async def page(
        self,
        *,
        where: Optional[Sequence[ColumnElement[bool]]] = None,
        order: Optional[Sequence[Sort]] = None,
        limit: int = 100,
        count_total: bool = False,
        include_deleted: bool = False,
    ) -> Page[TModel]:
        async with self._sf() as s:
            stmt: Select[Any] = select(self.model)
            conds: List[ColumnElement[bool]] = []
            if self.deleted_attr is not None and not include_deleted:
                conds.append(self.deleted_attr.is_(False))
            if where:
                conds.extend(where)
            if conds:
                stmt = stmt.where(and_(*conds))
            if order:
                for o in order:
                    stmt = stmt.order_by(o.field.asc() if o.direction == "asc" else o.field.desc())
            stmt = stmt.limit(limit + 1)
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            items = list(res.scalars().all())
            nxt = None
            if len(items) > limit:
                last = items[limit - 1]
                nxt = self._encode_cursor(self._cursor_values(last, order))
                items = items[:limit]
            total = None
            if count_total:
                cstmt = select(func.count()).select_from(self.model)
                if conds:
                    cstmt = cstmt.where(and_(*conds))
                cres = await s.execute(cstmt.execution_options(timeout=self._timeout))
                total = int(cres.scalar_one())
            return Page(items=items, total=total, next=nxt)

    async def page_by_cursor(
        self,
        *,
        where: Optional[Sequence[ColumnElement[bool]]] = None,
        order: Sequence[Sort],
        limit: int = 100,
        cursor: Optional[str],
        include_deleted: bool = False,
    ) -> Page[TModel]:
        if not order:
            raise ValueError("order is required for cursor pagination")
        async with self._sf() as s:
            stmt: Select[Any] = select(self.model)
            conds: List[ColumnElement[bool]] = []
            if self.deleted_attr is not None and not include_deleted:
                conds.append(self.deleted_attr.is_(False))
            if where:
                conds.extend(where)
            if cursor:
                cv = self._decode_cursor(cursor)
                conds.append(self._cursor_predicate(order, cv))
            if conds:
                stmt = stmt.where(and_(*conds))
            for o in order:
                stmt = stmt.order_by(o.field.asc() if o.direction == "asc" else o.field.desc())
            stmt = stmt.limit(limit + 1)
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            items = list(res.scalars().all())
            nxt = None
            if len(items) > limit:
                last = items[limit - 1]
                nxt = self._encode_cursor(self._cursor_values(last, order))
                items = items[:limit]
            return Page(items=items, total=None, next=nxt)

    async def create(self, obj: TModel) -> TModel:
        async with self._sf() as s:
            s.add(obj)
            await s.commit()
            await s.refresh(obj)
            return obj

    async def update(self, id_: TId, values: Mapping[str, Any]) -> Optional[TModel]:
        async with self._sf() as s:
            stmt = (
                update(self.model)
                .where(self.id_attr == id_)
                .values(**values)
                .returning(self.model)
            )
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            row = res.scalar_one_or_none()
            if row is None:
                await s.rollback()
                return None
            await s.commit()
            return row

    async def delete(self, id_: TId, *, hard: bool = False) -> bool:
        async with self._sf() as s:
            if self.deleted_attr is not None and not hard:
                stmt = (
                    update(self.model)
                    .where(self.id_attr == id_)
                    .values(**{self.deleted_attr.key: True})
                )
            else:
                stmt = delete(self.model).where(self.id_attr == id_)
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            await s.commit()
            return res.rowcount and int(res.rowcount) > 0  # type: ignore[return-value]

    async def upsert(
        self,
        *,
        values: Mapping[str, Any],
        conflict_keys: Sequence[InstrumentedAttribute[Any]],
        update_fields: Sequence[str],
        returning: bool = True,
    ) -> Optional[TModel]:
        """
        Апсерт через PostgreSQL ON CONFLICT.
        conflict_keys — столбцы уникального индекса/PK.
        update_fields — поля, которые обновляем при конфликте.
        """
        async with self._sf() as s:
            table = self.model.__table__  # type: ignore[attr-defined]
            stmt = (
                pg_insert(table)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=[c.name for c in conflict_keys],
                    set_={k: getattr(stmt.excluded, k) for k in update_fields},  # type: ignore[name-defined]
                )
            )
            if returning:
                stmt = stmt.returning(self.model)
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            await s.commit()
            return res.scalar_one_or_none() if returning else None

    async def bulk_upsert(
        self,
        rows: Sequence[Mapping[str, Any]],
        *,
        conflict_keys: Sequence[InstrumentedAttribute[Any]],
        update_fields: Sequence[str],
    ) -> int:
        if not rows:
            return 0
        async with self._sf() as s:
            table = self.model.__table__  # type: ignore[attr-defined]
            stmt = (
                pg_insert(table)
                .values(list(rows))
                .on_conflict_do_update(
                    index_elements=[c.name for c in conflict_keys],
                    set_={k: getattr(stmt.excluded, k) for k in update_fields},  # type: ignore[name-defined]
                )
            )
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            await s.commit()
            return int(res.rowcount or 0)

    # ---------- блокировки ----------
    async def get_for_update(self, id_: TId, *, skip_locked: bool = False, nowait: bool = False) -> Optional[TModel]:
        async with self._sf() as s:
            stmt = select(self.model).where(self.id_attr == id_).with_for_update(skip_locked=skip_locked, nowait=nowait)
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            return res.scalar_one_or_none()

    # ---------- технические ----------
    async def health(self) -> bool:
        async with self._sf() as s:
            res = await s.execute(text("SELECT 1").execution_options(timeout=1.5))
            return res.scalar_one() == 1

    # ---------- курсорные helpers ----------
    def _cursor_values(self, item: TModel, order: Sequence[Sort]) -> Tuple[Any, ...]:
        vals: List[Any] = []
        for o in order:
            vals.append(getattr(item, o.field.key))
        return tuple(vals)

    def _cursor_predicate(self, order: Sequence[Sort], cv: Tuple[Any, ...]):
        """
        Строит предикат строгого ">" / "<" по составному ключу.
        """
        assert len(order) == len(cv)
        expr = None
        for i in range(len(order)):
            comps = []
            for j in range(i):
                comps.append(order[j].field == cv[j])
            dir_asc = order[i].direction == "asc"
            op = order[i].field > cv[i] if dir_asc else order[i].field < cv[i]
            comps.append(op)
            term = and_(*comps)
            expr = term if expr is None else (expr | term)  # type: ignore[operator]
        return expr  # type: ignore[return-value]

    def _encode_cursor(self, cv: Tuple[Any, ...]) -> str:
        # Простейшая безопасная сериализация (|‑разделитель + экранирование)
        parts = []
        for v in cv:
            s = "" if v is None else str(v)
            s = s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n")
            parts.append(s)
        return "|".join(parts)

    def _decode_cursor(self, c: str) -> Tuple[Any, ...]:
        out: List[str] = []
        cur = []
        esc = False
        for ch in c:
            if esc:
                if ch == "n":
                    cur.append("\n")
                else:
                    cur.append(ch)
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "|":
                out.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
        out.append("".join(cur))
        return tuple(out)


# ===================== Транзакционные утилиты высокого уровня =====================

class TxRunner:
    """
    Запускает пользовательский колбэк в транзакции с ретраями по serialization/deadlock.
    Используйте для сложных сценариев, где требуется несколько запросов в одной TX.
    """
    def __init__(self, session_factory: async_sessionmaker[AsyncSession], *, retry: RetryConfig | None = None) -> None:
        self._sf = session_factory
        self._retry = retry or RetryConfig()

    async def run(self, func: Callable[[AsyncSession], Awaitable[Any]], *, name: str = "tx") -> Any:
        async def _inner() -> Any:
            async with self._sf() as s:
                async with s.begin():
                    return await func(s)
        return await _retry_on_serialization(_inner, name=name, cfg=self._retry)


# ===================== Пример специализированного репозитория =====================
# Замените на свои модели. Ниже — образец, как расширять BaseRepository.

class ExampleModel:  # заглушка для документации — замените реальным ORM классом
    __tablename__ = "example"
    id: Any
    created_at: Any
    updated_at: Any
    is_deleted: Any
    # поля ...

try:
    from sqlalchemy.orm import declarative_base, Mapped, mapped_column
    Base = declarative_base()

    class ExampleORM(Base):  # type: ignore[no-redef]
        __tablename__ = "examples"
        id: Mapped[str] = mapped_column(primary_key=True)
        created_at: Mapped[Any]
        updated_at: Mapped[Any]
        is_deleted: Mapped[bool] = mapped_column(default=False)
except Exception:
    ExampleORM = ExampleModel  # type: ignore[assignment]


class ExampleRepository(BaseRepository[ExampleORM, str]):  # type: ignore[type-arg]
    model = ExampleORM
    id_attr = ExampleORM.id  # type: ignore[attr-defined]
    deleted_attr = getattr(ExampleORM, "is_deleted", None)  # type: ignore[attr-defined]

    async def get_by_external_id(self, ext_id: str) -> Optional[ExampleORM]:
        async with self._sf() as s:
            stmt = select(self.model).where(getattr(self.model, "external_id") == ext_id)  # type: ignore[attr-defined]
            if self.deleted_attr is not None:
                stmt = stmt.where(self.deleted_attr.is_(False))  # type: ignore[union-attr]
            res = await s.execute(stmt.execution_options(timeout=self._timeout))
            return res.scalar_one_or_none()


# ===================== Фабрики сессий/инжекция =====================

def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """
    Создаёт sessionmaker с безопасными дефолтами.
    """
    return async_sessionmaker(
        bind=engine,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


# ===================== Примеры использования (доктест‑подобно) =====================

async def _example_usage(repo: ExampleRepository) -> None:  # pragma: no cover
    # list с сортировкой
    items = await repo.list(order=[Sort(repo.model.created_at, "desc")], limit=50)
    # постранично (cursor)
    page = await repo.page_by_cursor(
        order=[Sort(repo.model.created_at, "desc"), Sort(repo.id_attr, "desc")],
        limit=100,
        cursor=None,
    )
    # апсерт
    obj = await repo.upsert(
        values={"id": "x1", "name": "Alice"},
        conflict_keys=[repo.id_attr],
        update_fields=["name"],
    )
    # транзакционный раннер с ретраями
    runner = TxRunner(repo._sf)
    async def _tx(sess: AsyncSession) -> str:
        await sess.execute(text("SELECT 1"))
        return "ok"
    await runner.run(_tx, name="maintenance")
