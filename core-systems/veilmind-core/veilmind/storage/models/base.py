# veilmind-core/veilmind/storage/models/base.py
# -*- coding: utf-8 -*-
"""
VeilMind Core — Storage Models Base (SQLAlchemy 2.x)

Содержимое:
- Базовые типы и соглашения для Alembic (naming_convention).
- Declarative Base с UTC‑датами, soft delete, мультиарендностью, versioning (оптимистичная блокировка).
- Кросс‑СУБД типы: JSON/JSONB, UUID, ULID (строка 26 симв., Crockford).
- Утилиты создания async‑движка/сессий и репозиторий CRUD с безопасными дефолтами.

Переменные окружения:
- DB_DSN                — DSN (пример: postgresql+asyncpg://user:pass@host:5432/veilmind?sslmode=require)
- DB_SCHEMA             — схема БД (по умолчанию "public", игнорируется для SQLite)
- DB_STATEMENT_TIMEOUT_MS — таймаут запроса (мс), если поддерживается
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Type, TypeVar, Union, overload

# ----------------------------
# Мягкая проверка зависимостей
# ----------------------------
try:
    import sqlalchemy as sa
    from sqlalchemy import event
    from sqlalchemy.orm import DeclarativeBase, declared_attr, Mapped, mapped_column
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine, AsyncSession, async_sessionmaker
    from sqlalchemy.sql import func, Select
    from sqlalchemy.inspection import inspect as sa_inspect
except Exception as _e:  # pragma: no cover
    raise SystemExit(
        "SQLAlchemy 2.x (с asyncio) обязателен для veilmind.storage.models.base.\n"
        "Установите: pip install 'sqlalchemy[asyncio]' 'alembic' 'asyncpg' 'psycopg[binary,pool]'"
    )

# Диалект‑специфичные типы (опционально)
try:
    from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB, UUID as PG_UUID
except Exception:  # pragma: no cover
    PG_JSONB = None  # type: ignore
    PG_UUID = None  # type: ignore


# ----------------------------
# Утилиты времени и ULID
# ----------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")  # Crockford, верхний регистр

def ulid_str() -> str:
    """
    Генерация ULID‑подобной строки. Пытаемся взять реализацию из zero_trust.utils.crypto_random.ulid,
    иначе fallback на uuid4().hex (не ULID, но безопасный уникальный идентификатор).
    """
    try:
        from zero_trust.utils.crypto_random import ulid  # type: ignore
        return ulid()
    except Exception:
        return uuid.uuid4().hex.upper()


# ----------------------------
# Метаданные и соглашения имён (Alembic‑friendly)
# ----------------------------

NAMING_CONVENTION: Dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

METADATA = sa.MetaData(naming_convention=NAMING_CONVENTION)

def _schema_name() -> Optional[str]:
    schema = os.getenv("DB_SCHEMA", "public").strip()
    return schema or None


# ----------------------------
# Кросс‑СУБД типы
# ----------------------------

def JSONType() -> sa.types.TypeEngine:
    """JSONB для Postgres, иначе универсальный JSON."""
    if PG_JSONB is not None:
        return PG_JSONB()  # type: ignore
    return sa.JSON()

def UUIDType() -> sa.types.TypeEngine:
    """Нативный UUID для Postgres, иначе CHAR(36)."""
    if PG_UUID is not None:
        return PG_UUID(as_uuid=True)  # type: ignore
    return sa.CHAR(36)

class ULIDType(sa.types.TypeDecorator):
    """
    Хранение ULID в CHAR(26). На вход — str; на выход — str (верхний регистр).
    Если строка не ULID, но допустима как UUID/hex — приводим к верхнему регистру.
    """
    impl = sa.CHAR(26)
    cache_ok = True

    def process_bind_param(self, value: Optional[str], dialect) -> Optional[str]:
        if value is None:
            return None
        v = str(value).strip().upper()
        if _ULID_RE.match(v):
            return v
        # fallback: uuid/hex -> усечём/приведём к 26 символам, чтобы не падало (миграции/тесты)
        return v[:26].ljust(26, "0")

    def process_result_value(self, value: Optional[str], dialect) -> Optional[str]:
        return value.strip().upper() if value else value


# ----------------------------
# Declarative Base и миксины
# ----------------------------

class Base(DeclarativeBase):
    metadata = METADATA

    # Схема может быть общей для всех таблиц (Postgres)
    @declared_attr.directive
    def __table_args__(cls) -> Tuple[Dict[str, Any], ...]:  # type: ignore[override]
        schema = _schema_name()
        return ({"schema": schema},) if schema else tuple()

    # Единообразный repr
    def __repr__(self) -> str:  # pragma: no cover - удобство дебага
        pk_vals = []
        insp = sa_inspect(self)
        for key in insp.mapper.primary_key:
            name = key.key
            pk_vals.append(f"{name}={getattr(self, name, None)!r}")
        cls = self.__class__.__name__
        return f"<{cls} {' '.join(pk_vals)}>"


class TimestampMixin:
    """UTC‑времена с серверными дефолтами."""
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Время создания (UTC)",
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        comment="Время обновления (UTC)",
    )


class SoftDeleteMixin:
    """Мягкое удаление вместо физического."""
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
        comment="Мягкое удаление (UTC); NULL если активна",
    )

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


class TenantMixin:
    """Мультиарендность (при необходимости)."""
    tenant_id: Mapped[Optional[str]] = mapped_column(
        sa.String(64),
        nullable=True,
        index=True,
        comment="Идентификатор арендатора/организации",
    )


class AuditByMixin:
    """Кто создал/обновил (логический идентификатор, без PII)."""
    created_by: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)


class VersionedMixin:
    """
    Оптимистичная блокировка — version_id автоматически увеличивается ORM.
    Требует конфигурации mapper.version_id_col.
    """
    version_id: Mapped[int] = mapped_column(
        sa.Integer,
        nullable=False,
        default=0,
        server_default=sa.text("0"),
    )

    @declared_attr.directive
    def __mapper_args__(cls) -> Dict[str, Any]:  # type: ignore[override]
        return {"version_id_col": cls.version_id}


class IDMixinUUID:
    """Первичный ключ UUID (нативный для PG)."""
    id: Mapped[uuid.UUID] = mapped_column(
        UUIDType(),
        primary_key=True,
        default=uuid.uuid4,
        comment="Первичный ключ (UUIDv4)",
    )


class IDMixinULID:
    """Первичный ключ ULID (строка 26)."""
    id: Mapped[str] = mapped_column(
        ULIDType(),
        primary_key=True,
        default=ulid_str,
        comment="Первичный ключ (ULID, 26 симв.)",
    )


# ----------------------------
# Сериализация сущностей
# ----------------------------

def to_dict(obj: Any, *, exclude: Iterable[str] = ()) -> Dict[str, Any]:
    """
    Преобразование ORM‑объекта в словарь без рекурсий и приватных атрибутов.
    Полезно для логов/ответов сервиса (не храните PII).
    """
    insp = sa_inspect(obj)
    data: Dict[str, Any] = {}
    for attr in insp.mapper.column_attrs:
        name = attr.key
        if name in exclude:
            continue
        val = getattr(obj, name)
        if isinstance(val, datetime):
            data[name] = val.astimezone(timezone.utc).isoformat()
        elif isinstance(val, uuid.UUID):
            data[name] = str(val)
        else:
            data[name] = val
    return data


# ----------------------------
# Async Engine / Session утилиты
# ----------------------------

DEFAULT_DSN = os.getenv("DB_DSN", "sqlite+aiosqlite:///./veilmind.db")
DEFAULT_TIMEOUT_MS = int(os.getenv("DB_STATEMENT_TIMEOUT_MS", "30000"))

def make_async_engine(dsn: Optional[str] = None) -> AsyncEngine:
    """
    Создаёт AsyncEngine с безопасными дефолтами.
    Для PostgreSQL добавляет statement_timeout (если возможно).
    """
    url = sa.engine.make_url(dsn or DEFAULT_DSN)
    engine = create_async_engine(
        url,
        future=True,
        pool_pre_ping=True,
    )

    # Для Postgres выставим statement_timeout на соединение
    if url.get_backend_name().startswith("postgresql"):

        @event.listens_for(engine.sync_engine, "connect")  # type: ignore
        def _pgsql_on_connect(dbapi_conn, connection_record):  # pragma: no cover
            try:
                with dbapi_conn.cursor() as cur:
                    cur.execute(f"SET statement_timeout = {DEFAULT_TIMEOUT_MS}")
            except Exception:
                pass

    return engine


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


# ----------------------------
# Универсальный Async Repository
# ----------------------------

T = TypeVar("T", bound=Base)

class Repository:
    """
    Универсальный репозиторий для CRUD‑операций.
    Используйте типизированные наследники для конкретных моделей.
    """

    model: Type[T]

    def __init__(self, model: Type[T]):
        self.model = model

    async def get(self, session: AsyncSession, id_: Any) -> Optional[T]:
        return await session.get(self.model, id_)

    async def list(
        self,
        session: AsyncSession,
        where: Optional[Sequence[Any]] = None,
        *,
        limit: int = 100,
        offset: int = 0,
        order_by: Optional[Sequence[Any]] = None,
        with_deleted: bool = False,
    ) -> List[T]:
        stmt: Select[Any] = sa.select(self.model)
        if where:
            for cond in where:
                stmt = stmt.where(cond)
        if not with_deleted and hasattr(self.model, "deleted_at"):
            stmt = stmt.where(sa.or_(sa.text("deleted_at IS NULL"), sa.false() == sa.true()))  # безопасный no-op для SQLite
            # Примечание: для кросс‑диалектности избегаем IS NULL конструкций от ORM на атрибуте
            stmt = sa.text(str(stmt))  # type: ignore  # упрощённая кросс‑совместимость
        if order_by:
            stmt = stmt.order_by(*order_by)
        stmt = stmt.limit(limit).offset(offset)
        res = await session.execute(stmt)
        return list(res.scalars().all())

    async def create(self, session: AsyncSession, data: Mapping[str, Any]) -> T:
        obj = self.model(**dict(data))  # type: ignore[arg-type]
        session.add(obj)
        await session.flush()  # получить PK
        return obj

    async def update(self, session: AsyncSession, obj: T, data: Mapping[str, Any]) -> T:
        for k, v in dict(data).items():
            if not hasattr(obj, k):
                continue
            setattr(obj, k, v)
        # version_id обновится автоматически за счёт mapper_args
        await session.flush()
        return obj

    async def soft_delete(self, session: AsyncSession, obj: T) -> None:
        if hasattr(obj, "deleted_at"):
            setattr(obj, "deleted_at", now_utc())
            await session.flush()
        else:
            await session.delete(obj)

    async def upsert_by(
        self,
        session: AsyncSession,
        where: Sequence[Any],
        data_create: Mapping[str, Any],
        data_update: Optional[Mapping[str, Any]] = None,
    ) -> T:
        """
        Простейший upsert на уровне приложения (один объект).
        Для конкурирующих апдейтов используйте транзакции/блокировки.
        """
        res = await session.execute(sa.select(self.model).where(*where).limit(1))
        obj = res.scalars().first()
        if obj:
            return await self.update(session, obj, data_update or {})
        return await self.create(session, data_create)


# ----------------------------
# Alembic helper
# ----------------------------

# Alembic будет импортировать target_metadata из этого модуля:
target_metadata = METADATA


# ----------------------------
# Пример базовой сущности (для справки; не участвует в экспорте)
# ----------------------------

class ExampleEntity(IDMixinULID, TenantMixin, TimestampMixin, SoftDeleteMixin, VersionedMixin, AuditByMixin, Base):  # pragma: no cover - пример
    __tablename__ = "example_entity"

    name: Mapped[str] = mapped_column(sa.String(255), nullable=False, index=True)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONType(), nullable=False, default=dict)

    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "name", name="uq_example_entity_tenant_name"),
        Base.__table_args__[0] if Base.__table_args__ else {},  # сохранить схему, если задана
    )
