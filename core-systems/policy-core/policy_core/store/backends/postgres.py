# policy_core/store/backends/postgres.py
# Async industrial PostgreSQL backend for policy store.
# Python 3.11+, SQLAlchemy 2.x (async), asyncpg driver
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

from sqlalchemy import (
    MetaData, Table, Column, String, Integer, BigInteger, text, ForeignKey,
    Index, UniqueConstraint, select, insert, update, delete, and_, or_, literal_column, func
)
from sqlalchemy.dialects.postgresql import JSONB, ARRAY, TIMESTAMP as PG_TIMESTAMP, UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncConnection, create_async_engine
from sqlalchemy.engine import URL

__all__ = [
    "PostgresPolicyStore",
    "PolicyStatus",
    "PolicyRecord",
    "PolicyVersionRecord",
    "StoreError",
    "NotFound",
    "Conflict",
    "PreconditionFailed",
]

# -----------------------------------------------------------------------------
# Логирование
# -----------------------------------------------------------------------------
log = logging.getLogger("policy_core.store.postgres")
if not log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    log.addHandler(h)
    log.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Исключения
# -----------------------------------------------------------------------------
class StoreError(RuntimeError):
    pass

class NotFound(StoreError):
    pass

class Conflict(StoreError):
    pass

class PreconditionFailed(StoreError):
    pass

# -----------------------------------------------------------------------------
# Доменные модели
# -----------------------------------------------------------------------------
class PolicyStatus:
    ACTIVE = "active"
    DRAFT = "draft"
    DEPRECATED = "deprecated"

@dataclass(slots=True)
class PolicyRecord:
    id: uuid.UUID
    tenant_id: Optional[str]
    policy_id: str
    name: str
    status: str
    current_version: Optional[int]
    created_at: float
    updated_at: float
    deleted_at: Optional[float]

@dataclass(slots=True)
class PolicyVersionRecord:
    id: int
    policy_pk: uuid.UUID
    version: int
    algorithm: str
    doc: Mapping[str, Any]
    tags: Sequence[str]
    etag: str
    created_at: float

# -----------------------------------------------------------------------------
# Таблицы и метаданные
# -----------------------------------------------------------------------------
class _Tables:
    def __init__(self, schema: str = "public") -> None:
        self.schema = schema
        self.md = MetaData(schema=schema)

        self.policies = Table(
            "policies", self.md,
            Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
            Column("tenant_id", String(128), index=True),
            Column("policy_id", String(255), nullable=False),
            Column("name", String(255), nullable=False),
            Column("status", String(32), nullable=False, server_default=text(f"'{PolicyStatus.ACTIVE}'")),
            Column("current_version", Integer),
            Column("created_at", PG_TIMESTAMP(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")),
            Column("updated_at", PG_TIMESTAMP(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")),
            Column("deleted_at", PG_TIMESTAMP(timezone=True)),
            UniqueConstraint("tenant_id", "policy_id", name="uq_policy_tenant_policyid"),
        )

        self.policy_versions = Table(
            "policy_versions", self.md,
            Column("id", BigInteger, primary_key=True, autoincrement=True),
            Column("policy_pk", PG_UUID(as_uuid=True),
                   ForeignKey(f"{schema}.policies.id", ondelete="CASCADE"),
                   nullable=False, index=True),
            Column("version", Integer, nullable=False),
            Column("algorithm", String(64), nullable=False),
            Column("doc", JSONB, nullable=False),
            Column("tags", ARRAY(String(64)), nullable=False, server_default=text("'{}'")),
            Column("etag", String(64), nullable=False),
            Column("created_at", PG_TIMESTAMP(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")),
            UniqueConstraint("policy_pk", "version", name="uq_policy_version"),
            UniqueConstraint("policy_pk", "etag", name="uq_policy_etag"),
        )

        # Индексы для поиска
        Index("ix_policy_versions_doc_gin", self.policy_versions.c.doc, postgresql_using="gin")
        Index("ix_policy_versions_tags_gin", self.policy_versions.c.tags, postgresql_using="gin")
        Index("ix_policies_status", self.policies.c.status)

# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------
def _now_unix(conn: AsyncConnection) -> Any:
    # Возвращаем SQL-выражение с NOW() в секундах UNIX для SELECT
    return func.extract("epoch", func.timezone("UTC", func.now()))

def _compute_etag(*parts: Any) -> str:
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, (dict, list, tuple)):
            h.update(json.dumps(p, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        else:
            h.update(str(p).encode("utf-8"))
        h.update(b"|")
    return h.hexdigest()

def _coalesce_tenant(tenant_id: Optional[str]) -> Optional[str]:
    return tenant_id if tenant_id else None

# -----------------------------------------------------------------------------
# Backend
# -----------------------------------------------------------------------------
class PostgresPolicyStore:
    """
    Асинхронное хранилище политик для PostgreSQL.

    Возможности:
      - Многотенантность (tenant_id nullable => глобальные политики).
      - Версионирование: неизменяемые записи в policy_versions; активная — в policies.current_version.
      - JSONB и GIN-индексы для doc и tags.
      - ETag (SHA-256) для оптимистических блокировок/идемпотентности.
      - Мягкое удаление (deleted_at) и жёсткое (cascade).
      - Инициализация схемы/таблиц (без Alembic — fast-path; в prod рекомендуется миграции).
    """

    def __init__(
        self,
        dsn: str | URL,
        *,
        schema: str = "public",
        pool_size: int = 10,
        max_overflow: int = 20,
        pool_timeout: int = 30,
        pool_recycle: int = 1800,
        application_name: str = "policy-core",
        echo: bool = False,
    ) -> None:
        self._schema = schema
        self._tables = _Tables(schema)
        self._engine: AsyncEngine = create_async_engine(
            dsn if isinstance(dsn, str) else str(dsn),
            echo=echo,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_recycle=pool_recycle,
            connect_args={"server_settings": {"application_name": application_name}},
        )
        self._inited = False

    # ---------------------------- Инициализация ----------------------------

    async def initialize(self, *, create_schema_objects: bool = True) -> None:
        """
        Инициализировать подключение и (опционально) создать схему/таблицы/индексы.
        """
        if self._inited:
            return
        async with self._engine.begin() as conn:
            if create_schema_objects:
                await conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {self._schema}"))
                # Создание таблиц и индексов
                await conn.run_sync(self._tables.md.create_all)
                # Триггер updated_at (опционально; если нет миграций)
                await conn.execute(text(f"""
                    CREATE OR REPLACE FUNCTION {self._schema}.set_updated_at()
                    RETURNS TRIGGER AS $$
                    BEGIN
                      NEW.updated_at = NOW();
                      RETURN NEW;
                    END; $$ LANGUAGE plpgsql;
                """))
                await conn.execute(text(f"""
                    DO $$
                    BEGIN
                      IF NOT EXISTS (
                        SELECT 1 FROM pg_trigger
                        WHERE tgname = 'trg_policies_updated_at'
                      ) THEN
                        CREATE TRIGGER trg_policies_updated_at
                        BEFORE UPDATE ON {self._schema}.policies
                        FOR EACH ROW EXECUTE FUNCTION {self._schema}.set_updated_at();
                      END IF;
                    END $$;
                """))
        self._inited = True
        log.info("PostgresPolicyStore initialized (schema=%s)", self._schema)

    async def close(self) -> None:
        await self._engine.dispose()

    # ---------------------------- Сервисные методы ----------------------------

    async def health_check(self) -> bool:
        async with self._engine.connect() as conn:
            res = await conn.execute(select(literal_column("1")))
            return res.scalar_one() == 1

    # ---------------------------- CRUD Политик ----------------------------

    async def upsert_policy_version(
        self,
        *,
        tenant_id: Optional[str],
        policy_id: str,
        name: str,
        algorithm: str,
        doc: Mapping[str, Any],
        tags: Sequence[str] | None = None,
        status: str = PolicyStatus.ACTIVE,
        if_match_etag: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> tuple[PolicyRecord, PolicyVersionRecord]:
        """
        Создать новую версию политики и сделать её текущей (atomic).
        Если политика не существует — создаётся заголовок. Контроль конкуренции:
        - if_match_etag: если передан и не совпадает с текущим ETag активной версии — PreconditionFailed.
        - idempotency_key: если повтор того же содержимого — вернётся существующая версия.
        """
        assert algorithm, "algorithm must be non-empty"
        tags = list(tags or [])
        tenant_id = _coalesce_tenant(tenant_id)

        # ETag учитывает doc+algorithm+tags+name+policy_id+tenant_id
        desired_etag = _compute_etag(doc, algorithm, tags, name, policy_id, tenant_id)

        async with self._engine.begin() as conn:
            t = self._tables

            # 1) Найти/создать policy header с FOR UPDATE
            q_hdr = (
                select(t.policies)
                .where(
                    and_(
                        (t.policies.c.tenant_id.is_(None) if tenant_id is None
                         else t.policies.c.tenant_id == tenant_id),
                        t.policies.c.policy_id == policy_id,
                        t.policies.c.deleted_at.is_(None),
                    )
                )
                .with_for_update()
                .limit(1)
            )
            row_hdr = (await conn.execute(q_hdr)).mappings().first()

            created_new = False
            if row_hdr is None:
                # Создаём новую политику
                pk = uuid.uuid4()
                ins = (
                    insert(t.policies)
                    .values(
                        id=pk,
                        tenant_id=tenant_id,
                        policy_id=policy_id,
                        name=name,
                        status=status,
                        current_version=None,
                    )
                    .returning(t.policies)
                )
                row_hdr = (await conn.execute(ins)).mappings().one()
                created_new = True

            # Полезные поля
            pk: uuid.UUID = row_hdr["id"]
            current_version: Optional[int] = row_hdr["current_version"]

            # 2) Проверить ETag текущей версии при необходимости
            if if_match_etag is not None and current_version is not None:
                q_etag = (
                    select(t.policy_versions.c.etag)
                    .where(and_(t.policy_versions.c.policy_pk == pk,
                                t.policy_versions.c.version == current_version))
                    .limit(1)
                )
                cur_etag = (await conn.execute(q_etag)).scalar_one_or_none()
                if cur_etag is not None and cur_etag != if_match_etag:
                    raise PreconditionFailed("ETag mismatch for current policy version")

            # 3) Idempotency: если точный etag уже существует — вернуть его
            q_same = (
                select(t.policy_versions)
                .where(and_(t.policy_versions.c.policy_pk == pk,
                            t.policy_versions.c.etag == desired_etag))
                .limit(1)
            )
            row_same = (await conn.execute(q_same)).mappings().first()
            if row_same:
                # Обновить шапку (name/status) при необходимости, но версию не трогаем
                upd = (
                    update(t.policies)
                    .where(t.policies.c.id == pk)
                    .values(name=name, status=status)
                    .returning(t.policies)
                )
                row_hdr = (await conn.execute(upd)).mappings().one()
                # Сформировать ответ
                pol = self._to_policy_record(conn, row_hdr)
                ver = self._to_version_record(row_same)
                return pol, ver

            # 4) Сгенерировать новую версию
            next_version = 1 if current_version is None else (current_version + 1)
            ins_ver = (
                insert(t.policy_versions)
                .values(
                    policy_pk=pk,
                    version=next_version,
                    algorithm=algorithm,
                    doc=dict(doc),
                    tags=tags,
                    etag=desired_etag,
                )
                .returning(t.policy_versions)
            )
            row_ver = (await conn.execute(ins_ver)).mappings().one()

            # 5) Обновить заголовок на новую текущую версию + имя/статус
            upd_hdr = (
                update(t.policies)
                .where(t.policies.c.id == pk)
                .values(
                    current_version=next_version,
                    name=name,
                    status=status,
                )
                .returning(t.policies)
            )
            row_hdr = (await conn.execute(upd_hdr)).mappings().one()

            pol = self._to_policy_record(conn, row_hdr)
            ver = self._to_version_record(row_ver)
            return pol, ver

    async def get_policy(
        self,
        *,
        tenant_id: Optional[str],
        policy_id: str,
        include_inactive: bool = False,
    ) -> tuple[PolicyRecord, PolicyVersionRecord]:
        """
        Получить активную версию политики (или NotFound). include_inactive=False исключает удалённые/неактивные шапки.
        """
        tenant_id = _coalesce_tenant(tenant_id)
        async with self._engine.connect() as conn:
            t = self._tables
            q_hdr = (
                select(t.policies)
                .where(
                    and_(
                        (t.policies.c.tenant_id.is_(None) if tenant_id is None
                         else t.policies.c.tenant_id == tenant_id),
                        t.policies.c.policy_id == policy_id,
                        t.policies.c.deleted_at.is_(None) if not include_inactive else text("true"),
                    )
                )
                .limit(1)
            )
            row_hdr = (await conn.execute(q_hdr)).mappings().first()
            if not row_hdr:
                raise NotFound("Policy not found")

            current_version: Optional[int] = row_hdr["current_version"]
            if current_version is None:
                raise NotFound("Policy has no active version")

            q_ver = (
                select(t.policy_versions)
                .where(and_(
                    t.policy_versions.c.policy_pk == row_hdr["id"],
                    t.policy_versions.c.version == current_version,
                ))
                .limit(1)
            )
            row_ver = (await conn.execute(q_ver)).mappings().first()
            if not row_ver:
                raise NotFound("Active policy version not found")

            return self._to_policy_record(conn, row_hdr), self._to_version_record(row_ver)

    async def get_policy_version(
        self,
        *,
        tenant_id: Optional[str],
        policy_id: str,
        version: int,
    ) -> tuple[PolicyRecord, PolicyVersionRecord]:
        tenant_id = _coalesce_tenant(tenant_id)
        async with self._engine.connect() as conn:
            t = self._tables
            q_hdr = (
                select(t.policies.c.id, t.policies)
                .where(
                    and_(
                        (t.policies.c.tenant_id.is_(None) if tenant_id is None
                         else t.policies.c.tenant_id == tenant_id),
                        t.policies.c.policy_id == policy_id,
                        t.policies.c.deleted_at.is_(None),
                    )
                )
                .limit(1)
            )
            row_hdr = (await conn.execute(q_hdr)).mappings().first()
            if not row_hdr:
                raise NotFound("Policy not found")

            q_ver = (
                select(t.policy_versions)
                .where(and_(t.policy_versions.c.policy_pk == row_hdr["id"], t.policy_versions.c.version == version))
                .limit(1)
            )
            row_ver = (await conn.execute(q_ver)).mappings().first()
            if not row_ver:
                raise NotFound("Policy version not found")
            return self._to_policy_record(conn, row_hdr["policies"]), self._to_version_record(row_ver)

    async def list_policies(
        self,
        *,
        tenant_id: Optional[str],
        status: Optional[str] = None,
        tag_any: Sequence[str] | None = None,
        name_like: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        include_deleted: bool = False,
    ) -> list[tuple[PolicyRecord, PolicyVersionRecord]]:
        """
        Список политик c активной версией и фильтрами.
          - tag_any: вернуть политики, где активная версия содержит хотя бы один из тегов.
          - name_like: регистронезависимый LIKE по name.
        """
        tenant_id = _coalesce_tenant(tenant_id)
        tag_any = list(tag_any or [])
        assert 0 <= limit <= 500, "limit must be between 0 and 500"
        assert 0 <= offset, "offset must be >= 0"

        async with self._engine.connect() as conn:
            t = self._tables

            # JOIN policies -> policy_versions (по текущей версии)
            pv = t.policy_versions.alias("pv")
            conditions = [
                pv.c.policy_pk == t.policies.c.id,
                pv.c.version == t.policies.c.current_version,
            ]
            if tenant_id is None:
                conditions.append(t.policies.c.tenant_id.is_(None))
            else:
                conditions.append(t.policies.c.tenant_id == tenant_id)

            if not include_deleted:
                conditions.append(t.policies.c.deleted_at.is_(None))
            if status:
                conditions.append(t.policies.c.status == status)
            if name_like:
                conditions.append(func.lower(t.policies.c.name).like(f"%{name_like.lower()}%"))
            if tag_any:
                # pv.tags && tag_any
                conditions.append(pv.c.tags.op("&&")(tag_any))  # array overlap

            q = (
                select(t.policies, pv)
                .where(and_(*conditions))
                .order_by(t.policies.c.updated_at.desc(), t.policies.c.policy_id.asc())
                .limit(limit)
                .offset(offset)
            )
            rows = (await conn.execute(q)).mappings().all()

            result: list[tuple[PolicyRecord, PolicyVersionRecord]] = []
            for r in rows:
                result.append((
                    self._to_policy_record(conn, r["policies"]),
                    self._to_version_record(r["pv"])
                ))
            return result

    async def soft_delete_policy(
        self,
        *,
        tenant_id: Optional[str],
        policy_id: str,
    ) -> PolicyRecord:
        """Мягкое удаление политики (deleted_at=NOW()) с сохранением истории версий."""
        tenant_id = _coalesce_tenant(tenant_id)
        async with self._engine.begin() as conn:
            t = self._tables
            q_hdr = (
                select(t.policies)
                .where(
                    and_(
                        (t.policies.c.tenant_id.is_(None) if tenant_id is None
                         else t.policies.c.tenant_id == tenant_id),
                        t.policies.c.policy_id == policy_id,
                        t.policies.c.deleted_at.is_(None),
                    )
                )
                .with_for_update()
                .limit(1)
            )
            row_hdr = (await conn.execute(q_hdr)).mappings().first()
            if not row_hdr:
                raise NotFound("Policy not found")

            upd = (
                update(t.policies)
                .where(t.policies.c.id == row_hdr["id"])
                .values(deleted_at=text("NOW()"))
                .returning(t.policies)
            )
            row = (await conn.execute(upd)).mappings().one()
            return self._to_policy_record(conn, row)

    async def hard_delete_policy(
        self,
        *,
        tenant_id: Optional[str],
        policy_id: str,
    ) -> None:
        """Жёсткое удаление политики и всех её версий."""
        tenant_id = _coalesce_tenant(tenant_id)
        async with self._engine.begin() as conn:
            t = self._tables
            q_hdr = (
                select(t.policies.c.id)
                .where(
                    and_(
                        (t.policies.c.tenant_id.is_(None) if tenant_id is None
                         else t.policies.c.tenant_id == tenant_id),
                        t.policies.c.policy_id == policy_id,
                    )
                )
                .with_for_update()
                .limit(1)
            )
            pk = (await conn.execute(q_hdr)).scalar_one_or_none()
            if pk is None:
                raise NotFound("Policy not found")

            await conn.execute(delete(t.policies).where(t.policies.c.id == pk))
            # policy_versions удалятся каскадно

    async def set_status(
        self,
        *,
        tenant_id: Optional[str],
        policy_id: str,
        status: str,
    ) -> PolicyRecord:
        """Сменить статус политики (active/draft/deprecated)."""
        assert status in (PolicyStatus.ACTIVE, PolicyStatus.DRAFT, PolicyStatus.DEPRECATED)
        tenant_id = _coalesce_tenant(tenant_id)
        async with self._engine.begin() as conn:
            t = self._tables
            q_hdr = (
                select(t.policies)
                .where(
                    and_(
                        (t.policies.c.tenant_id.is_(None) if tenant_id is None
                         else t.policies.c.tenant_id == tenant_id),
                        t.policies.c.policy_id == policy_id,
                        t.policies.c.deleted_at.is_(None),
                    )
                )
                .with_for_update()
                .limit(1)
            )
            row_hdr = (await conn.execute(q_hdr)).mappings().first()
            if not row_hdr:
                raise NotFound("Policy not found")

            upd = (
                update(t.policies)
                .where(t.policies.c.id == row_hdr["id"])
                .values(status=status)
                .returning(t.policies)
            )
            row = (await conn.execute(upd)).mappings().one()
            return self._to_policy_record(conn, row)

    async def versions_history(
        self,
        *,
        tenant_id: Optional[str],
        policy_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[PolicyVersionRecord]:
        """История версий (последние сначала)."""
        tenant_id = _coalesce_tenant(tenant_id)
        async with self._engine.connect() as conn:
            t = self._tables
            q_hdr = (
                select(t.policies.c.id)
                .where(
                    and_(
                        (t.policies.c.tenant_id.is_(None) if tenant_id is None
                         else t.policies.c.tenant_id == tenant_id),
                        t.policies.c.policy_id == policy_id,
                    )
                )
                .limit(1)
            )
            pk = (await conn.execute(q_hdr)).scalar_one_or_none()
            if pk is None:
                raise NotFound("Policy not found")

            q = (
                select(t.policy_versions)
                .where(t.policy_versions.c.policy_pk == pk)
                .order_by(t.policy_versions.c.version.desc())
                .limit(limit).offset(offset)
            )
            rows = (await conn.execute(q)).mappings().all()
            return [self._to_version_record(r) for r in rows]

    # ---------------------------- Приватные конвертеры ----------------------------

    def _to_policy_record(self, conn: AsyncConnection, row: Mapping[str, Any]) -> PolicyRecord:
        # Конвертируем timestamptz -> UNIX (float) через SELECT NOW() в health; здесь читаем как aware, но переносим в float
        # Поскольку SQLAlchemy отдаёт datetime, для простоты возвращаем эпоху через .timestamp()
        created_at = row["created_at"].timestamp() if row["created_at"] else 0.0
        updated_at = row["updated_at"].timestamp() if row["updated_at"] else created_at
        deleted_at = row["deleted_at"].timestamp() if row["deleted_at"] else None
        return PolicyRecord(
            id=row["id"],
            tenant_id=row["tenant_id"],
            policy_id=row["policy_id"],
            name=row["name"],
            status=row["status"],
            current_version=row["current_version"],
            created_at=created_at,
            updated_at=updated_at,
            deleted_at=deleted_at,
        )

    def _to_version_record(self, row: Mapping[str, Any]) -> PolicyVersionRecord:
        return PolicyVersionRecord(
            id=row["id"],
            policy_pk=row["policy_pk"],
            version=row["version"],
            algorithm=row["algorithm"],
            doc=row["doc"],
            tags=list(row["tags"] or []),
            etag=row["etag"],
            created_at=row["created_at"].timestamp() if row["created_at"] else 0.0,
        )

# -----------------------------------------------------------------------------
# Мини-самотест (опционально)
# -----------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    async def _demo():
        dsn = "postgresql+asyncpg://postgres:postgres@localhost:5432/policystore"
        store = PostgresPolicyStore(dsn, schema="policy_core", echo=False)
        await store.initialize()

        tenant = None
        pol_id = "base-policy"

        # Create v1
        pol, ver = await store.upsert_policy_version(
            tenant_id=tenant,
            policy_id=pol_id,
            name="Base Policy",
            algorithm="deny-overrides",
            doc={"rules": [{"id": "r1", "effect": "Permit", "when": "subject.role == 'admin'"}]},
            tags=["base", "admin"],
            status=PolicyStatus.ACTIVE,
        )
        print("v1 etag:", ver.etag)

        # Read
        pol2, ver2 = await store.get_policy(tenant_id=tenant, policy_id=pol_id)
        print("get:", pol2.policy_id, pol2.current_version, ver2.version)

        # Update to v2 with etag check
        pol3, ver3 = await store.upsert_policy_version(
            tenant_id=tenant,
            policy_id=pol_id,
            name="Base Policy",
            algorithm="deny-overrides",
            doc={"rules": [{"id": "r1", "effect": "Permit", "when": "subject.role == 'admin'"},
                           {"id": "r2", "effect": "Deny", "when": "subject.banned == true"}]},
            tags=["base", "admin"],
            status=PolicyStatus.ACTIVE,
            if_match_etag=ver2.etag,
        )
        print("v3:", pol3.current_version, ver3.version)

        # List
        items = await store.list_policies(tenant_id=tenant, tag_any=["admin"], limit=10)
        print("list:", len(items))

        # History
        hist = await store.versions_history(tenant_id=tenant, policy_id=pol_id)
        print("history:", [h.version for h in hist])

        await store.close()

    asyncio.run(_demo())
