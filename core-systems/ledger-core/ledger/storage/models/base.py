# -*- coding: utf-8 -*-
"""
ledger.storage.models.base
Промышленная база моделей для SQLAlchemy 2.x (async/PG).

Возможности:
- Единая DeclarativeBase с naming_convention (дружественно к Alembic)
- UTC-времена created_at/updated_at с автоматическим обновлением
- Оптимистическая блокировка через целочисленное поле version
- Мягкое удаление (soft delete) с отметкой deleted_at/by и флагом is_deleted
- UUID/ULID первичные ключи (ULID при наличии пакета, иначе UUIDv4)
- JSONB поля с мутабельными словарями/списками
- Аудито-поля created_by/updated_by (опционально)
- Утилиты: now_utc(), gen_ulid_or_uuid(), BaseModel.to_dict()

Зависимости:
    SQLAlchemy>=2.0
    psycopg[binary] или asyncpg (для движка)
    sqlalchemy-utils НЕ требуется
Опционально:
    ulid-py (pip install ulid-py) — для ULID
"""

from __future__ import annotations

import datetime as _dt
import os
import uuid
from typing import Any, Dict, Optional, TypedDict, TypeVar

from sqlalchemy import (
    Column,
    MetaData,
    String,
    Boolean,
    Integer,
    BigInteger,
    DateTime,
    event,
    inspect,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    declared_attr,
)

# ============================ Время/ID утилиты ============================

def now_utc() -> _dt.datetime:
    # Всегда aware‑UTC
    return _dt.datetime.now(tz=_dt.timezone.utc)

def _uuid4() -> uuid.UUID:
    return uuid.uuid4()

def gen_ulid_or_uuid() -> str:
    """
    Возвращает строковый ULID (если доступна зависимость ulid-py), иначе UUIDv4.
    Строковый формат удобен для логов/маршрутов HTTP.
    """
    try:
        import ulid as _ulid  # type: ignore
        return str(_ulid.new())
    except Exception:
        return str(_uuid4())

# ============================ Meta / Base ============================

# Именование всех ограничений — важно для Alembic autogenerate
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

SCHEMA = os.getenv("LEDGER_DB_SCHEMA", "ledger")

metadata = MetaData(naming_convention=NAMING_CONVENTION, schema=SCHEMA)

class Base(DeclarativeBase):
    """
    Базовый Declarative класс. Не содержит собственных колонок.
    """
    metadata = metadata

    # Автоматическое имя таблицы: app_model -> app_model
    @declared_attr.directive
    def __tablename__(cls) -> str:  # type: ignore
        return cls.__name__.lower()

    # Унифицированный repr/to_dict
    def __repr__(self) -> str:
        state = inspect(self)
        attrs = []
        for k in state.mapper.column_attrs.keys():
            v = getattr(self, k, None)
            if isinstance(v, _dt.datetime):
                v = v.isoformat()
            attrs.append(f"{k}={v!r}")
        return f"<{self.__class__.__name__} {' '.join(attrs)}>"

    def to_dict(self, include_relationships: bool = False) -> Dict[str, Any]:
        state = inspect(self)
        data: Dict[str, Any] = {}
        for k in state.mapper.column_attrs.keys():
            v = getattr(self, k, None)
            if isinstance(v, _dt.datetime):
                v = v.isoformat()
            data[k] = v
        if include_relationships:
            for rel in state.mapper.relationships:
                if rel.uselist:
                    data[rel.key] = [getattr(x, "id", None) or getattr(x, "uid", None) for x in getattr(self, rel.key) or []]
                else:
                    o = getattr(self, rel.key)
                    data[rel.key] = getattr(o, "id", None) or getattr(o, "uid", None) if o else None
        return data

# ============================ Миксины ============================

class PKUUIDMixin:
    """
    Первичный ключ UUID (типизированный PG UUID AS UUID).
    """
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=_uuid4,
        nullable=False,
    )

class PKULIDStrMixin:
    """
    Первичный ключ ULID/UUID строкой (для логов и читаемых URL).
    """
    id: Mapped[str] = mapped_column(
        String(36),  # ULID=26 символов; UUID=36 — берём максимум
        primary_key=True,
        default=gen_ulid_or_uuid,
    )

class TimestampMixin:
    """
    UTC‑времена создания/обновления.
    updated_at обновляется триггером onupdate и через событие before_update.
    """
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=now_utc,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP AT TIME ZONE 'UTC'"),
    )
    updated_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=now_utc,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP AT TIME ZONE 'UTC'"),
        onupdate=now_utc,
    )

class VersionedMixin:
    """
    Оптимистическая блокировка.
    """
    version: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

class SoftDeleteMixin:
    """
    Мягкое удаление: отметки и флаг.
    В запросах прикладного кода рекомендуется добавлять фильтр is_deleted = false.
    """
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, server_default=text("false"))
    deleted_at: Mapped[Optional[_dt.datetime]] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[Optional[str]] = mapped_column(String(64))

    def soft_delete(self, actor: Optional[str] = None) -> None:
        self.is_deleted = True
        self.deleted_at = now_utc()
        self.deleted_by = actor or "system"

class AuditByMixin:
    """
    Аудито‑поля — кем создано/обновлено.
    Значения проставляются на уровне сервиса/репозитория.
    """
    created_by: Mapped[Optional[str]] = mapped_column(String(64))
    updated_by: Mapped[Optional[str]] = mapped_column(String(64))

class JSONBMixin:
    """
    Мутабельные JSONB поля.
    Используйте в дочерних классах:
        metadata: Mapped[dict[str, Any]] = mapped_column(MutableDict.as_mutable(JSONB), default=dict)
    """
    @staticmethod
    def jsonb_dict_default() -> MutableDict:
        return MutableDict()

    @staticmethod
    def jsonb_list_default() -> MutableList:
        return MutableList()

# ============================ События/триггеры ============================

@event.listens_for(Base, "before_update", propagate=True)
def _stamp_updated_at(mapper, connection, target) -> None:
    if hasattr(target, "updated_at"):
        setattr(target, "updated_at", now_utc())

@event.listens_for(Base, "before_update", propagate=True)
def _bump_version(mapper, connection, target) -> None:
    if hasattr(target, "version"):
        current = getattr(target, "version", 0) or 0
        setattr(target, "version", int(current) + 1)

# ============================ Пример базовой модели (для справки) ============================
# Ниже — эталон использования миксинов. Оставьте закомментированным в прод‑коде,
# либо перенесите в отдельный модуль моделей.

# class ExampleEntity(PKUUIDMixin, TimestampMixin, VersionedMixin, SoftDeleteMixin, AuditByMixin, JSONBMixin, Base):
#     __tablename__ = "example_entity"
#     name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
#     metadata: Mapped[dict[str, Any]] = mapped_column(MutableDict.as_mutable(JSONB), default=dict, server_default=text("'{}'::jsonb"))

# Индексы/ограничения — объявляйте в дочерних моделях через Index/UniqueConstraint с учётом naming_convention.

# ============================ Подсказки по миграциям ============================
# Для Alembic:
# - используйте naming_convention из metadata
# - не забудьте установить схему через env var LEDGER_DB_SCHEMA или оставьте "ledger"
# - created_at/updated_at имеют server_default, что упрощает ручные вставки
