# SPDX-License-Identifier: Apache-2.0
"""
physical_integration/twin/models.py

Промышленные доменные модели цифровых двойников.
SQLAlchemy 2.0, PostgreSQL JSONB/UUID/ENUM, GIN-индексы, оптимистическая блокировка.
Совместимы с Alembic и модулем реестра устройств.

Зависимости: sqlalchemy>=2.0, psycopg, python-dateutil (опц.)
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    UniqueConstraint,
    text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# -------------------------------
# Базовая декларация и метаданные
# -------------------------------

# Попытка переиспользовать общее metadata/Base из реестра (если модуль присутствует),
# иначе — локальные metadata/Base с тем же naming_convention для стабильных миграций.
try:  # pragma: no cover
    from ..registry.models import Base as RegistryBase, metadata_obj as registry_metadata
    Base = RegistryBase  # type: ignore
    metadata_obj = registry_metadata  # type: ignore
    NAMING_CONVENTION = metadata_obj.naming_convention  # type: ignore
except Exception:  # pragma: no cover
    NAMING_CONVENTION = {
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }

    metadata_obj = MetaData(naming_convention=NAMING_CONVENTION)

    class Base(DeclarativeBase):
        metadata = metadata_obj


# --------------
# Доменные ENUMы
# --------------

class TwinStatus(str, enum.Enum):
    active = "ACTIVE"
    disabled = "DISABLED"
    decommissioned = "DECOMMISSIONED"
    error = "ERROR"


class PropSource(str, enum.Enum):
    desired = "DESIRED"
    reported = "REPORTED"
    calculated = "CALCULATED"
    default = "DEFAULT"
    external = "EXTERNAL"


class CommandStatus(str, enum.Enum):
    pending = "PENDING"
    sending = "SENDING"
    sent = "SENT"
    acked = "ACKED"
    nacked = "NACKED"
    failed = "FAILED"
    timed_out = "TIMED_OUT"
    canceled = "CANCELED"


# ----------------
# Миксины
# ----------------

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now(), index=True
    )


class VersioningMixin:
    # Оптимистическая блокировка (версионность записей)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __mapper_args__ = {
        "version_id_col": "version",
        "version_id_generator": True,
    }


# ----------------
# Цифровой двойник
# ----------------

class Twin(Base, TimestampMixin, VersioningMixin):
    """
    Главная запись цифрового двойника.
    Держит текущее желаемое/заявленное состояние и метаданные устройства.
    """
    __tablename__ = "twin"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Опциональная связка с физическим устройством (если каталог устройств присутствует)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("device.id", ondelete="SET NULL"),
        index=True,
    )

    # Тип/модель двойника (например, совместимый с DTDL/вашими моделями)
    model_id: Mapped[str | None] = mapped_column(String(256), index=True)
    type: Mapped[str | None] = mapped_column(String(64), index=True)

    # Метаданные
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    labels: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    annotations: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    # Текущее состояние
    desired: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    reported: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    status: Mapped[TwinStatus] = mapped_column(
        Enum(TwinStatus, name="twin_status_enum"), nullable=False, server_default=TwinStatus.active.value
    )

    # Контроль версий/консистентности состояния (например, для ETag)
    desired_etag: Mapped[str | None] = mapped_column(String(64))
    reported_etag: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        UniqueConstraint("device_id", name="uq_twin_device_id"),
        Index("ix_twin_labels_gin", labels, postgresql_using="gin"),
        Index("ix_twin_desired_gin", desired, postgresql_using="gin"),
        Index("ix_twin_reported_gin", reported, postgresql_using="gin"),
        CheckConstraint("jsonb_typeof(desired) = 'object'", name="desired_json_object"),
        CheckConstraint("jsonb_typeof(reported) = 'object'", name="reported_json_object"),
    )

    # Связи
    properties: Mapped[list["TwinPropertyDef"]] = relationship(back_populates="twin", cascade="all, delete-orphan")
    events: Mapped[list["TwinPropertyEvent"]] = relationship(back_populates="twin", cascade="all, delete-orphan")
    out_relations: Mapped[list["TwinRelation"]] = relationship(
        foreign_keys="TwinRelation.source_twin_id", back_populates="source", cascade="all, delete-orphan"
    )
    in_relations: Mapped[list["TwinRelation"]] = relationship(
        foreign_keys="TwinRelation.target_twin_id", back_populates="target", cascade="all, delete-orphan"
    )
    commands: Mapped[list["TwinCommand"]] = relationship(back_populates="twin", cascade="all, delete-orphan")


# ---------------------------
# Описание свойств двойника
# ---------------------------

class TwinPropertyDef(Base, TimestampMixin, VersioningMixin):
    """
    Метаданные свойства двойника: тип, единицы измерения, допускаемые значения.
    """
    __tablename__ = "twin_property_def"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    twin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("twin.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Путь свойства (dot-notation): например, "sensors.temp1.value"
    path: Mapped[str] = mapped_column(String(256), nullable=False)

    # Тип и ограничители (используйте для валидации на прикладном уровне)
    data_type: Mapped[str] = mapped_column(String(32), nullable=False)  # boolean|integer|number|string|object|array
    unit: Mapped[str | None] = mapped_column(String(64))
    min_value: Mapped[float | None] = mapped_column()
    max_value: Mapped[float | None] = mapped_column()
    enum: Mapped[list[str] | None] = mapped_column(JSONB)  # перечень допустимых строк/значений
    writable: Mapped[bool] = mapped_column(nullable=False, server_default=text("true"))

    description: Mapped[str | None] = mapped_column(String(1024))

    twin: Mapped[Twin] = relationship(back_populates="properties")

    __table_args__ = (
        UniqueConstraint("twin_id", "path", name="uq_twin_property_path"),
        CheckConstraint("path ~ '^[A-Za-z0-9_.-]+$'", name="prop_path_format"),
        Index("ix_twin_prop_enum_gin", enum, postgresql_using="gin"),
    )


# ---------------------------
# Отношения между двойниками
# ---------------------------

class TwinRelation(Base, TimestampMixin, VersioningMixin):
    """
    Отношение twin -> twin (граф зависимостей/топология).
    """
    __tablename__ = "twin_relation"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_twin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("twin.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_twin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("twin.id", ondelete="CASCADE"), nullable=False, index=True
    )

    relation: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # e.g., "contains", "depends_on"
    props: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    source: Mapped[Twin] = relationship(foreign_keys=[source_twin_id], back_populates="out_relations")
    target: Mapped[Twin] = relationship(foreign_keys=[target_twin_id], back_populates="in_relations")

    __table_args__ = (
        UniqueConstraint("source_twin_id", "target_twin_id", "relation", name="uq_twin_relation"),
        CheckConstraint("source_twin_id <> target_twin_id", name="no_self_relation"),
        Index("ix_twin_relation_props_gin", props, postgresql_using="gin"),
    )


# --------------------------------
# История изменений свойств (events)
# --------------------------------

class TwinPropertyEvent(Base):
    """
    Факт изменения свойства двойника (append-only).
    Рекомендуется партиционирование по timestamp на уровне БД/миграций.
    """
    __tablename__ = "twin_property_event"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    twin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("twin.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Путь свойства и источник (desired/reported/...)
    path: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    source: Mapped[PropSource] = mapped_column(Enum(PropSource, name="twin_prop_source_enum"), nullable=False)

    # Значение как JSONB, плюс дельта (опц.) в формате JSON Patch (RFC 6902)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    json_patch: Mapped[dict | None] = mapped_column(JSONB)

    # Маркеры времени
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)

    # Трассировка/идемпотентность
    trace_id: Mapped[str | None] = mapped_column(String(64), index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), index=True)

    twin: Mapped[Twin] = relationship(back_populates="events")

    __table_args__ = (
        CheckConstraint("path ~ '^[A-Za-z0-9_.-]+$'", name="event_path_format"),
        CheckConstraint("jsonb_typeof(value) IS NOT NULL", name="event_value_type"),
        Index("ix_twin_event_value_gin", value, postgresql_using="gin"),
        Index("ix_twin_event_patch_gin", json_patch, postgresql_using="gin"),
        UniqueConstraint("twin_id", "path", "occurred_at", "source", name="uq_twin_event_dedup"),
    )


# ------------------------
# Очередь команд к устройству
# ------------------------

class TwinCommand(Base, TimestampMixin, VersioningMixin):
    """
    Команда к двойнику/устройству (настройка, действие).
    """
    __tablename__ = "twin_command"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    twin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("twin.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Имя/тип команды и параметризация
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    # Доставка/планирование
    status: Mapped[CommandStatus] = mapped_column(Enum(CommandStatus, name="twin_command_status_enum"), nullable=False, index=True, server_default=CommandStatus.pending.value)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("5"))  # 0..9 (0 — max)
    schedule_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("5"))

    # Ответ/ошибка (последняя попытка)
    response_code: Mapped[str | None] = mapped_column(String(64))
    response_payload: Mapped[dict | None] = mapped_column(JSONB)
    error_message: Mapped[str | None] = mapped_column(String(2048))

    # Трассировка
    trace_id: Mapped[str | None] = mapped_column(String(64), index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), index=True)

    twin: Mapped[Twin] = relationship(back_populates="commands")
    attempts_log: Mapped[list["TwinCommandAttempt"]] = relationship(
        back_populates="command", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("priority BETWEEN 0 AND 9", name="cmd_priority_range"),
        CheckConstraint("(expires_at IS NULL) OR (expires_at > created_at)", name="cmd_expiry_after_create"),
        Index("ix_twin_command_payload_gin", payload, postgresql_using="gin"),
    )


class TwinCommandAttempt(Base):
    """
    Журнал попыток доставки/выполнения команды.
    """
    __tablename__ = "twin_command_attempt"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    command_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("twin_command.id", ondelete="CASCADE"), nullable=False, index=True
    )

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[CommandStatus] = mapped_column(Enum(CommandStatus, name="twin_command_status_enum"), nullable=False, index=True)

    response_code: Mapped[str | None] = mapped_column(String(64))
    response_payload: Mapped[dict | None] = mapped_column(JSONB)
    error_message: Mapped[str | None] = mapped_column(String(2048))

    command: Mapped[TwinCommand] = relationship(back_populates="attempts_log")


# ------------------------
# Задания синхронизации twin
# ------------------------

class TwinSyncJob(Base, TimestampMixin, VersioningMixin):
    """
    Задание синхронизации desired->device и/или сбор reported<-device.
    Может исполняться воркером/оркестратором, привязано к twin.
    """
    __tablename__ = "twin_sync_job"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    twin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("twin.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Маска пути свойств (dot-notation), если None — вся проекция
    path_mask: Mapped[str | None] = mapped_column(String(256), index=True)

    # Конфигурация/статус выполнения
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'PENDING'"))
    last_error: Mapped[str | None] = mapped_column(String(2048))

    # Планирование/окна
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    tries: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    max_tries: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("10"))

    __table_args__ = (
        CheckConstraint("(path_mask IS NULL) OR (path_mask ~ '^[A-Za-z0-9_.-]+$')", name="sync_path_format"),
        Index("ix_twin_sync_payload_gin", payload, postgresql_using="gin"),
    )
