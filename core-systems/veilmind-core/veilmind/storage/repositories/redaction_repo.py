# -*- coding: utf-8 -*-
"""
VeilMind Core — Redaction Repository (PostgreSQL, async SQLAlchemy)

Назначение:
  - Управление профилями редактирования (версионирование спецификаций, активация)
  - Журнал событий редактирования (без хранения сырых PII; только masked/sample/attrs)
  - Идемпотентная запись событий (по Idempotency-Key)
  - Поиск/пагинация/агрегации/ретеншн

Зависимости:
  - python >= 3.11
  - SQLAlchemy[asyncio] >= 2.0
  - asyncpg
  - pydantic >= 2

ENV:
  VEILMIND_DB_DSN             — postgresql+asyncpg://user:pass@host:5432/db
  VEILMIND_DB_SCHEMA          — имя схемы (по умолчанию "veilmind")

Безопасность/приватность:
  - Не хранит сырые значения PII; только masked sample и метаданные.
  - Поля JSONB индексируются GIN с опцией jsonb_path_ops.
  - Все таймстемпы в UTC.

Автор: VeilMind Team. Лицензия: Apache-2.0
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import typing as t
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from pydantic import BaseModel, Field, ConfigDict, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncConnection, create_async_engine
from sqlalchemy.engine import URL


# =========================
# DTO / Domain models
# =========================

class RedactionProfile(BaseModel):
    """
    Спецификация профиля редактирования (хранится как JSONB).
    version:
      - если не задана — формируется из контент‑хэша c префиксом "v1-".
    active:
      - репозиторий позволяет иметь несколько активных версий (если нужно A/B),
        но обычно активна одна (контролируйте на прикладном уровне).
    """
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Имя профиля (например, hash_low_cardinality)")
    version: t.Optional[str] = Field(None, description="Версия профиля (строка)")
    description: t.Optional[str] = Field(None, description="Человеко‑читаемое описание")
    spec: dict = Field(default_factory=dict, description="Полная спецификация профиля (JSON‑совместимая)")
    active: bool = Field(default=True)

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("profile.name must be 1..128 chars")
        return v


class RedactionEvent(BaseModel):
    """
    Событие редактирования — только безопасные данные.
    """
    model_config = ConfigDict(extra="forbid")

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    happened_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # источники и контекст
    tenant_id: t.Optional[str] = Field(None, max_length=128)
    service: t.Optional[str] = Field(None, max_length=128)
    source: t.Optional[str] = Field(None, description="http|grpc|db|process|files")
    sink: t.Optional[str] = Field(None, description="logs|metrics|traces|other")
    correlation_id: t.Optional[str] = Field(None, max_length=128)
    # классификация
    category: t.Optional[str] = Field(None, description="denylist|pii|sensitive|weak")
    detector: t.Optional[str] = Field(None, description="имя детектора/правила")
    path: t.Optional[str] = Field(None, description="JSONPath‑подобный путь")
    # профиль
    profile_name: t.Optional[str] = None
    profile_version: t.Optional[str] = None
    # безопасный образец
    sample: t.Optional[str] = Field(None, description="маскированный/усеченный фрагмент")
    # свободные тех.атрибуты (без PII)
    attributes: dict = Field(default_factory=dict)
    # идемпотентность (уникальна при ненулевом значении)
    idempotency_key: t.Optional[str] = Field(None, max_length=128)


class EventFilter(BaseModel):
    """
    Фильтры поиска событий.
    """
    model_config = ConfigDict(extra="forbid")

    time_from: t.Optional[datetime] = None
    time_to: t.Optional[datetime] = None
    tenant_id: t.Optional[str] = None
    service: t.Optional[str] = None
    source: t.Optional[str] = None
    sink: t.Optional[str] = None
    category_in: t.Optional[list[str]] = None
    detector_like: t.Optional[str] = None
    profile_name: t.Optional[str] = None
    correlation_id: t.Optional[str] = None


class Page(BaseModel):
    """
    Результат пагинации.
    """
    model_config = ConfigDict(extra="forbid")

    items: list[dict]
    total: int
    next_offset: t.Optional[int] = None


# =========================
# Ошибки
# =========================

class RepositoryError(RuntimeError):
    pass


# =========================
# Repository
# =========================

@dataclass
class RedactionRepository:
    """
    Репозиторий на базе PostgreSQL (async).

    Примечание: миграции рекомендуется вести через Alembic.
    Метод ensure_schema() создаёт минимально необходимую структуру
    и индексы, если их нет.
    """
    dsn: str | None = None
    schema: str = "veilmind"

    def __post_init__(self) -> None:
        self.dsn = self.dsn or os.getenv("VEILMIND_DB_DSN") or ""
        if not self.dsn:
            raise RepositoryError("Database DSN is required (VEILMIND_DB_DSN)")
        self.schema = os.getenv("VEILMIND_DB_SCHEMA", self.schema)
        self.engine: AsyncEngine = create_async_engine(self.dsn, pool_pre_ping=True)

    # ---------- Schema management ----------

    async def ensure_schema(self) -> None:
        """
        Создаёт схему и таблицы/индексы, если их нет. Идемпотентно.
        """
        ddl = f"""
        CREATE SCHEMA IF NOT EXISTS "{self.schema}";

        CREATE TABLE IF NOT EXISTS "{self.schema}".redaction_profiles (
            name                TEXT        NOT NULL,
            version             TEXT        NOT NULL,
            description         TEXT        NULL,
            spec                JSONB       NOT NULL,
            active              BOOLEAN     NOT NULL DEFAULT TRUE,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (name, version)
        );

        -- Быстрый доступ к активным версиям
        CREATE INDEX IF NOT EXISTS redaction_profiles_active_idx
            ON "{self.schema}".redaction_profiles (name, active);

        -- История событий редактирования (PII не хранится)
        CREATE TABLE IF NOT EXISTS "{self.schema}".redaction_events (
            event_id           UUID         PRIMARY KEY,
            happened_at        TIMESTAMPTZ  NOT NULL,
            tenant_id          TEXT         NULL,
            service            TEXT         NULL,
            source             TEXT         NULL,
            sink               TEXT         NULL,
            correlation_id     TEXT         NULL,
            category           TEXT         NULL,
            detector           TEXT         NULL,
            path               TEXT         NULL,
            profile_name       TEXT         NULL,
            profile_version    TEXT         NULL,
            sample             TEXT         NULL,
            attributes         JSONB        NOT NULL DEFAULT '{{}}'::jsonb,
            idempotency_key    TEXT         NULL UNIQUE
        );

        CREATE INDEX IF NOT EXISTS redaction_events_time_idx
            ON "{self.schema}".redaction_events (happened_at DESC);

        CREATE INDEX IF NOT EXISTS redaction_events_class_idx
            ON "{self.schema}".redaction_events (category, detector);

        CREATE INDEX IF NOT EXISTS redaction_events_profile_idx
            ON "{self.schema}".redaction_events (profile_name, profile_version);

        CREATE INDEX IF NOT EXISTS redaction_events_tenant_idx
            ON "{self.schema}".redaction_events (tenant_id, service);

        CREATE INDEX IF NOT EXISTS redaction_events_attrs_gin
            ON "{self.schema}".redaction_events
            USING GIN (attributes jsonb_path_ops);
        """
        async with self.engine.begin() as conn:
            await conn.execute(text(ddl))

    # ---------- Profiles ----------

    @staticmethod
    def _content_version(spec: dict) -> str:
        # Каноническое представление JSON
        canon = json.dumps(spec or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        h = hashlib.sha256(canon).hexdigest()[:16]
        return f"v1-{h}"

    async def upsert_profile(self, p: RedactionProfile) -> tuple[str, str]:
        """
        Создаёт новую версию профиля или перезаписывает существующую (по (name, version)).
        Возвращает (name, version).
        """
        version = p.version or self._content_version(p.spec)
        q = text(f"""
            INSERT INTO "{self.schema}".redaction_profiles
                (name, version, description, spec, active, created_at, updated_at)
            VALUES
                (:name, :version, :description, CAST(:spec AS JSONB), :active, NOW(), NOW())
            ON CONFLICT (name, version) DO UPDATE
                SET description = EXCLUDED.description,
                    spec = EXCLUDED.spec,
                    active = EXCLUDED.active,
                    updated_at = NOW();
        """)
        async with self.engine.begin() as conn:
            await conn.execute(q, {
                "name": p.name,
                "version": version,
                "description": p.description,
                "spec": json.dumps(p.spec or {}, ensure_ascii=False, separators=(",", ":")),
                "active": bool(p.active),
            })
        return p.name, version

    async def set_profile_active(self, name: str, version: str, active: bool = True) -> None:
        q = text(f"""
            UPDATE "{self.schema}".redaction_profiles
               SET active = :active, updated_at = NOW()
             WHERE name = :name AND version = :version;
        """)
        async with self.engine.begin() as conn:
            await conn.execute(q, {"name": name, "version": version, "active": active})

    async def get_profile(self, name: str, version: str | None = None, active_only: bool = False) -> t.Optional[dict]:
        """
        Возвращает профиль в виде dict, либо None.
        Если version не указан — берём самую новую по created_at активную (или любую, если active_only=False).
        """
        if version:
            q = text(f"""
                SELECT name, version, description, spec, active, created_at, updated_at
                  FROM "{self.schema}".redaction_profiles
                 WHERE name = :name AND version = :version
                 LIMIT 1;
            """)
            params = {"name": name, "version": version}
        else:
            q = text(f"""
                SELECT name, version, description, spec, active, created_at, updated_at
                  FROM "{self.schema}".redaction_profiles
                 WHERE name = :name
                   {"AND active = TRUE" if active_only else ""}
                 ORDER BY active DESC, created_at DESC
                 LIMIT 1;
            """)
            params = {"name": name}

        async with self.engine.connect() as conn:
            row = (await conn.execute(q, params)).mappings().first()
            return dict(row) if row else None

    async def list_profiles(self, name: str | None = None, active: bool | None = None,
                            limit: int = 50, offset: int = 0) -> Page:
        cond = ["1=1"]
        params: dict[str, t.Any] = {}
        if name:
            cond.append("name = :name")
            params["name"] = name
        if active is not None:
            cond.append("active = :active")
            params["active"] = active
        where = " AND ".join(cond)

        q_items = text(f"""
            SELECT name, version, description, spec, active, created_at, updated_at
              FROM "{self.schema}".redaction_profiles
             WHERE {where}
             ORDER BY name ASC, created_at DESC
             LIMIT :limit OFFSET :offset;
        """)
        q_count = text(f"""SELECT COUNT(*) AS c FROM "{self.schema}".redaction_profiles WHERE {where};""")
        async with self.engine.connect() as conn:
            rows = (await conn.execute(q_items, {**params, "limit": limit, "offset": offset})).mappings().all()
            total = (await conn.execute(q_count, params)).scalar_one()
        next_off = offset + limit if offset + limit < total else None
        return Page(items=[dict(r) for r in rows], total=int(total), next_offset=next_off)

    # ---------- Events ----------

    async def record_event(self, ev: RedactionEvent) -> uuid.UUID:
        """
        Идемпотентная запись события. Если указан idempotency_key и запись уже есть,
        возвращается существующий event_id.
        """
        q = text(f"""
            INSERT INTO "{self.schema}".redaction_events (
                event_id, happened_at, tenant_id, service, source, sink,
                correlation_id, category, detector, path,
                profile_name, profile_version, sample, attributes, idempotency_key
            )
            VALUES (
                :event_id, :happened_at, :tenant_id, :service, :source, :sink,
                :correlation_id, :category, :detector, :path,
                :profile_name, :profile_version, :sample, CAST(:attributes AS JSONB), :idempotency_key
            )
            ON CONFLICT (idempotency_key) DO UPDATE
                SET idempotency_key = EXCLUDED.idempotency_key
            RETURNING event_id;
        """)
        payload = {
            "event_id": str(ev.event_id),
            "happened_at": ev.happened_at,
            "tenant_id": ev.tenant_id,
            "service": ev.service,
            "source": ev.source,
            "sink": ev.sink,
            "correlation_id": ev.correlation_id,
            "category": ev.category,
            "detector": ev.detector,
            "path": ev.path,
            "profile_name": ev.profile_name,
            "profile_version": ev.profile_version,
            "sample": ev.sample,
            "attributes": json.dumps(ev.attributes or {}, ensure_ascii=False, separators=(",", ":")),
            "idempotency_key": ev.idempotency_key,
        }
        async with self.engine.begin() as conn:
            rid = (await conn.execute(q, payload)).scalar_one()
            return uuid.UUID(str(rid))

    async def query_events(self, flt: EventFilter, limit: int = 100, offset: int = 0) -> Page:
        cond = ["1=1"]
        params: dict[str, t.Any] = {}
        if flt.time_from:
            cond.append("happened_at >= :t_from"); params["t_from"] = flt.time_from
        if flt.time_to:
            cond.append("happened_at < :t_to"); params["t_to"] = flt.time_to
        if flt.tenant_id:
            cond.append("tenant_id = :tenant_id"); params["tenant_id"] = flt.tenant_id
        if flt.service:
            cond.append("service = :service"); params["service"] = flt.service
        if flt.source:
            cond.append("source = :source"); params["source"] = flt.source
        if flt.sink:
            cond.append("sink = :sink"); params["sink"] = flt.sink
        if flt.profile_name:
            cond.append("profile_name = :pname"); params["pname"] = flt.profile_name
        if flt.correlation_id:
            cond.append("correlation_id = :cid"); params["cid"] = flt.correlation_id
        if flt.category_in:
            cond.append("category = ANY(:cat)")
            params["cat"] = flt.category_in
        if flt.detector_like:
            cond.append("detector ILIKE :det"); params["det"] = f"%{flt.detector_like}%"

        where = " AND ".join(cond)

        q_items = text(f"""
            SELECT event_id, happened_at, tenant_id, service, source, sink, correlation_id,
                   category, detector, path, profile_name, profile_version, sample, attributes
              FROM "{self.schema}".redaction_events
             WHERE {where}
             ORDER BY happened_at DESC
             LIMIT :limit OFFSET :offset;
        """)
        q_count = text(f"""SELECT COUNT(*) AS c FROM "{self.schema}".redaction_events WHERE {where};""")

        async with self.engine.connect() as conn:
            rows = (await conn.execute(q_items, {**params, "limit": limit, "offset": offset})).mappings().all()
            total = (await conn.execute(q_count, params)).scalar_one()

        next_off = offset + limit if offset + limit < total else None
        return Page(items=[dict(r) for r in rows], total=int(total), next_offset=next_off)

    async def aggregate_stats(self,
                              time_from: datetime | None = None,
                              time_to: datetime | None = None,
                              group_by: str = "category") -> list[dict]:
        """
        Возвращает агрегаты по периодам:
          group_by: "category" | "detector" | "profile" | "sink"
        """
        valid = {"category", "detector", "profile", "sink"}
        if group_by not in valid:
            raise RepositoryError(f"group_by must be one of {valid}")
        if group_by == "profile":
            expr = "profile_name || ':' || COALESCE(profile_version, '')"
        elif group_by == "sink":
            expr = "COALESCE(sink,'')"
        else:
            expr = group_by

        cond = ["1=1"]
        params: dict[str, t.Any] = {}
        if time_from:
            cond.append("happened_at >= :t_from"); params["t_from"] = time_from
        if time_to:
            cond.append("happened_at < :t_to"); params["t_to"] = time_to
        where = " AND ".join(cond)

        q = text(f"""
            SELECT {expr} AS key, COUNT(*) AS cnt
              FROM "{self.schema}".redaction_events
             WHERE {where}
             GROUP BY {expr}
             ORDER BY cnt DESC;
        """)
        async with self.engine.connect() as conn:
            rows = (await conn.execute(q, params)).mappings().all()
        return [dict(r) for r in rows]

    async def purge_events(self, older_than_days: int) -> int:
        """
        Удаляет события старше заданного порога. Возвращает количество удаленных строк.
        """
        q = text(f"""
            DELETE FROM "{self.schema}".redaction_events
             WHERE happened_at < (NOW() AT TIME ZONE 'UTC') - (:days || ' days')::interval;
        """)
        async with self.engine.begin() as conn:
            res = await conn.execute(q, {"days": int(older_than_days)})
            return res.rowcount or 0

    # ---------- Utilities ----------

    async def close(self) -> None:
        await self.engine.dispose()


# =========================
# Пример использования (docstring)
# =========================
"""
async def _example():
    repo = RedactionRepository()
    await repo.ensure_schema()

    # Профиль
    pr = RedactionProfile(
        name="hash_low_cardinality",
        spec={
            "sinks": {"logs": "mask", "metrics": "hash", "traces": "hash"},
            "pii": "hash",
            "sensitive": "mask",
            "denylist": "remove",
            "params": {"hash": {"algo": "sha256", "namespace": "vmc"}}
        },
        active=True,
        description="Default profile"
    )
    name, ver = await repo.upsert_profile(pr)
    await repo.set_profile_active(name, ver, True)
    prof = await repo.get_profile(name, active_only=True)

    # Событие
    ev = RedactionEvent(
        tenant_id="acme", service="api", source="http", sink="logs",
        category="pii", detector="regex:email", path="$.headers.x-user-email",
        profile_name=name, profile_version=ver,
        sample="j***@e*****.com",
        attributes={"trace_id": "00-abc-xyz", "region": "eu-west-1"},
        idempotency_key="trace-00-abc-xyz-1"
    )
    event_id = await repo.record_event(ev)

    # Поиск
    page = await repo.query_events(EventFilter(service="api"), limit=50, offset=0)

    # Агрегаты
    stats = await repo.aggregate_stats(group_by="category")

    # Ретеншн
    deleted = await repo.purge_events(older_than_days=30)

    await repo.close()
"""
__all__ = [
    "RedactionRepository",
    "RedactionProfile",
    "RedactionEvent",
    "EventFilter",
    "Page",
    "RepositoryError",
]
