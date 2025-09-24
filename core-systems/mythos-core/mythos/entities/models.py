# mythos-core/mythos/entities/models.py
# -*- coding: utf-8 -*-
"""
Доменные модели Mythos Core: сущности, связи и событие-аутбокс.

Требования:
  - Python 3.11+
  - SQLAlchemy >= 2.0
  - pydantic >= 2.0
  - PostgreSQL (используются JSONB, UUID, ARRAY, частичные индексы)

Особенности:
  - EntityORM: версия (optimistic locking), etag, мягкое удаление, JSONB-атрибуты.
  - RelationshipORM: направления/веса, уникальность ребра.
  - OutboxORM: транзакционный outbox для CDC и интеграций.
  - Индексы: GIN по labels/attributes/tags, частичная уникальность по доменному ключу.
  - Pydantic-DTO: безопасная сериализация для API/SDK.
  - Хуки: авто-обновление updated_at и пересчёт etag перед flush.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ColumnElement,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ==========================
# БАЗА ДЕКЛАРАТИВНОЙ МОДЕЛИ
# ==========================

class Base(DeclarativeBase):
    pass


# ==========================
# ENUM-TYPES
# ==========================

class LifecycleEnum(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    ARCHIVED = "ARCHIVED"
    DELETED = "DELETED"


class DirectionEnum(str, Enum):
    OUTBOUND = "OUTBOUND"
    INBOUND = "INBOUND"
    BIDIRECTIONAL = "BIDIRECTIONAL"


# ==========================
# ORM МОДЕЛИ
# ==========================

class EntityORM(Base):
    """
    Базовая сущность.
    Уникальность: (tenant_id, namespace, kind, name) среди не-удалённых.
    """
    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    namespace: Mapped[str] = mapped_column(String(100), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    labels: Mapped[Dict[str, str]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    tags: Mapped[List[str]] = mapped_column(ARRAY(String(64)), nullable=False, server_default=text("ARRAY[]::varchar[]"))
    attributes: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    etag: Mapped[str] = mapped_column(String(128), nullable=False, default="")

    lifecycle: Mapped[LifecycleEnum] = mapped_column(SAEnum(LifecycleEnum, name="lifecycle_enum"), nullable=False, default=LifecycleEnum.DRAFT)
    owner: Mapped[Optional[str]] = mapped_column(String(320), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    external_refs: Mapped[Dict[str, str]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    # Отношения на самих себя (исходящие/входящие связи)
    outgoing: Mapped[List["RelationshipORM"]] = relationship(
        "RelationshipORM",
        foreign_keys="RelationshipORM.source_id",
        back_populates="source",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    incoming: Mapped[List["RelationshipORM"]] = relationship(
        "RelationshipORM",
        foreign_keys="RelationshipORM.target_id",
        back_populates="target",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    # Оптимистическая блокировка
    __mapper_args__ = {
        "version_id_col": version,
    }

    __table_args__ = (
        # Жёсткая уникальность (без частичного условия) на случай резервного движка
        UniqueConstraint("tenant_id", "namespace", "kind", "name", name="uq_entities_identity"),
        # Валидации полей
        CheckConstraint("char_length(namespace) BETWEEN 1 AND 100", name="ck_ns_len"),
        CheckConstraint("char_length(name) BETWEEN 1 AND 100", name="ck_name_len"),
        # Индексы
        Index("ix_entities_tenant_ns_kind", "tenant_id", "namespace", "kind"),
        # GIN по JSONB для быстрых фильтров
        Index("ix_entities_labels_gin", labels, postgresql_using="gin"),
        Index("ix_entities_attributes_gin", attributes, postgresql_using="gin"),
        # Полнотекстовый индекс по описанию (опционально)
        # Index("ix_entities_description_tsv", text("to_tsvector('simple', coalesce(description,''))"), postgresql_using="gin"),
        # Частичная уникальность среди не-удалённых (PostgreSQL)
        Index(
            "uq_entities_identity_active",
            "tenant_id", "namespace", "kind", "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )

    # ------------- Утилиты -------------

    def compute_etag(self) -> str:
        """
        Детерминированный ETag из существенных полей и версии.
        """
        payload = {
            "id": str(self.id),
            "ver": self.version,
            "ns": self.namespace,
            "k": self.kind,
            "n": self.name,
            "l": self.lifecycle.value if isinstance(self.lifecycle, LifecycleEnum) else self.lifecycle,
            "labels": self.labels,
            "tags": self.tags,
            "attrs": self.attributes,
            "ext": self.external_refs,
            "upd": int(self.updated_at.timestamp()) if self.updated_at else None,
        }
        b = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(b).hexdigest()[:64]

    def mark_deleted(self, *, hard: bool = False) -> None:
        if hard:
            # реальное удаление выполняет слой репозитория
            return
        self.deleted_at = datetime.now(timezone.utc)
        self.lifecycle = LifecycleEnum.DELETED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "tenantId": str(self.tenant_id) if self.tenant_id else None,
            "namespace": self.namespace,
            "kind": self.kind,
            "name": self.name,
            "displayName": self.display_name,
            "description": self.description,
            "labels": self.labels,
            "tags": self.tags,
            "attributes": self.attributes,
            "version": self.version,
            "etag": self.etag,
            "lifecycle": self.lifecycle.value if isinstance(self.lifecycle, LifecycleEnum) else self.lifecycle,
            "owner": self.owner,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None,
            "deletedAt": self.deleted_at.isoformat() if self.deleted_at else None,
            "externalRefs": self.external_refs,
        }


class RelationshipORM(Base):
    """
    Графовая связь между сущностями.
    """
    __tablename__ = "entity_relationships"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)

    type: Mapped[str] = mapped_column(String(64), nullable=False)
    direction: Mapped[DirectionEnum] = mapped_column(SAEnum(DirectionEnum, name="direction_enum"), nullable=False, default=DirectionEnum.OUTBOUND)

    weight: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    properties: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    source: Mapped[EntityORM] = relationship("EntityORM", foreign_keys=[source_id], back_populates="outgoing")
    target: Mapped[EntityORM] = relationship("EntityORM", foreign_keys=[target_id], back_populates="incoming")

    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "type", name="uq_rel_src_tgt_type"),
        Index("ix_rel_src", "source_id"),
        Index("ix_rel_tgt", "target_id"),
        Index("ix_rel_type", "type"),
    )


class OutboxORM(Base):
    """
    Транзакционный outbox для интеграций/CDC.
    Писать в него в одной транзакции с бизнес-изменениями.
    """
    __tablename__ = "outbox"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    topic: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    deliver_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_outbox_ready", "topic", postgresql_where=text("delivered = false")),
        Index("ix_outbox_created_at", "created_at"),
    )


# ==========================
# ORM СОБЫТИЯ/ХУКИ
# ==========================

@event.listens_for(EntityORM, "before_insert", propagate=True)
def _entity_before_insert(mapper, connection, target: EntityORM) -> None:  # noqa: D401
    # Обеспечить начальные значения
    if target.version is None:
        target.version = 1
    # updated_at задаст сервер; etag посчитаем уже в before_flush после установки updated_at


@event.listens_for(EntityORM, "before_update", propagate=True)
def _entity_before_update(mapper, connection, target: EntityORM) -> None:
    # version инкрементируется за счёт mapper_args.version_id_col
    # updated_at установит onupdate=func.now(); etag посчитаем в before_flush
    pass


@event.listens_for(Base, "before_flush")
def _recompute_etag(session, flush_context, instances) -> None:
    # Рассчитываем etag там, где уже выставлен updated_at серверной функцией (в памяти ещё None),
    # поэтому ориентируемся на текущее время, если updated_at пуст.
    now = datetime.now(timezone.utc)
    for obj in session.new.union(session.dirty):
        if isinstance(obj, EntityORM):
            if obj.updated_at is None:
                obj.updated_at = now
            obj.etag = obj.compute_etag()


# ==========================
# Pydantic DTO-МОДЕЛИ
# ==========================

class RelationshipDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)
    type: str
    sourceId: uuid.UUID = Field(alias="source_id")
    targetId: uuid.UUID = Field(alias="target_id")
    direction: DirectionEnum = DirectionEnum.OUTBOUND
    weight: Optional[float] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class EntityDTO(BaseModel):
    """
    Безопасная транспортная модель для API/SDK.
    """
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: uuid.UUID
    tenantId: Optional[uuid.UUID] = Field(default=None, alias="tenant_id")
    namespace: str
    kind: str
    name: str
    displayName: Optional[str] = Field(default=None, alias="display_name")
    description: Optional[str] = None

    labels: Dict[str, str] = {}
    tags: List[str] = []
    attributes: Dict[str, Any] = {}

    version: int
    etag: str
    lifecycle: LifecycleEnum
    owner: Optional[str] = None

    createdAt: datetime = Field(alias="created_at")
    updatedAt: datetime = Field(alias="updated_at")
    deletedAt: Optional[datetime] = Field(default=None, alias="deleted_at")

    externalRefs: Dict[str, str] = Field(default_factory=dict, alias="external_refs")

    # Опционально можно добавить связи, если требуется в представлении
    # relationships: List[RelationshipDTO] = Field(default_factory=list)


# ==========================
# УТИЛИТЫ ДЛЯ РАБОТЫ С OUTBOX
# ==========================

def make_entity_outbox(topic: str, entity: EntityORM) -> OutboxORM:
    """
    Сформировать запись outbox с сериализацией текущей сущности.
    """
    return OutboxORM(
        topic=topic,
        payload=entity.to_dict(),
    )
