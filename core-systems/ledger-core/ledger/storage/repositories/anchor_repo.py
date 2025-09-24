# ledger-core/ledger/storage/repositories/anchor_repo.py
# -*- coding: utf-8 -*-
"""
AnchorRepo — репозиторий PostgreSQL для анкоринга.

Зависимости:
  - SQLAlchemy>=2.0
  - asyncpg (драйвер PG)
  - Python 3.10+

Назначение:
  1) Хранение статуса элементов анкоринга (anchored/failed)
  2) Персистентное состояние «открытого» батча
  3) Хранение квитанций цепочки
  4) Идемпотентность коммитмента (idempotency_key) с TTL

Схема БД (DDL); используйте alembic в проде, но для удобства есть метод bootstrap():
---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS anchor_items (
    id              text PRIMARY KEY,
    status          text NOT NULL CHECK (status IN ('pending','anchored','failed')),
    last_error      text NULL,
    receipt         jsonb NULL,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS anchor_open_batch (
    -- ожидается ровно 1 строка с текущим открытым батчем
    batch_id        text PRIMARY KEY,
    state           jsonb NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS anchor_receipts (
    batch_id        text PRIMARY KEY,
    receipt         jsonb NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS anchor_idempotency (
    idempotency_key text PRIMARY KEY,
    processed_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL
);

-- Ускорители
CREATE INDEX IF NOT EXISTS idx_anchor_items_status ON anchor_items(status);
CREATE INDEX IF NOT EXISTS idx_anchor_idem_expires ON anchor_idempotency(expires_at);
---------------------------------------------------------------------------
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (
    JSON,
    TIMESTAMP,
    CheckConstraint,
    Column,
    Index,
    MetaData,
    String,
    Table,
    Text,
    text,
    insert,
    update,
    select,
    delete,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.exc import OperationalError, DBAPIError

LOG = logging.getLogger("ledger.storage.anchor_repo")


# Исключения уровня репозитория
class AnchorRepoError(Exception): ...
class SerializationRetryError(AnchorRepoError): ...
class NotFoundError(AnchorRepoError): ...


# ---------- Таблицы SQLAlchemy Core ----------
metadata = MetaData(schema=None)

t_anchor_items = Table(
    "anchor_items",
    metadata,
    Column("id", Text, primary_key=True),
    Column("status", String(16), nullable=False, server_default=text("'pending'")),
    Column("last_error", Text, nullable=True),
    Column("receipt", JSONB, nullable=True),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False, server_default=func.now()),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False, server_default=func.now()),
    CheckConstraint("status IN ('pending','anchored','failed')", name="ck_anchor_items_status"),
    Index("idx_anchor_items_status", "status"),
)

t_open_batch = Table(
    "anchor_open_batch",
    metadata,
    Column("batch_id", Text, primary_key=True),
    Column("state", JSONB, nullable=False),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False, server_default=func.now()),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False, server_default=func.now()),
)

t_receipts = Table(
    "anchor_receipts",
    metadata,
    Column("batch_id", Text, primary_key=True),
    Column("receipt", JSONB, nullable=False),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False, server_default=func.now()),
)

t_idempotency = Table(
    "anchor_idempotency",
    metadata,
    Column("idempotency_key", Text, primary_key=True),
    Column("processed_at", TIMESTAMP(timezone=True), nullable=False, server_default=func.now()),
    Column("expires_at", TIMESTAMP(timezone=True), nullable=False),
    Index("idx_anchor_idem_expires", "expires_at"),
)


# ---------- Политика ретраев сериализации ----------
@dataclass(frozen=True)
class TxRetryPolicy:
    max_attempts: int = 5
    base_delay_ms: int = 50

    def delay_seconds(self, attempt: int) -> float:
        # экспоненциальный с небольшим джиттером
        exp = self.base_delay_ms * (2 ** (attempt - 1))
        jitter = exp * 0.25
        return max(0.0, (exp + jitter) / 1000.0)


# ---------- Репозиторий ----------
class AnchorRepo:
    """
    Репозиторий с асинхронными транзакциями. Соответствует протоколу BatcherStore:

        async def mark_item_anchored(self, item_id: str, receipt: Dict[str, Any]) -> None
        async def mark_item_failed(self, item_id: str, reason: str) -> None
        async def save_open_batch(self, batch_id: str, state: Dict[str, Any]) -> None
        async def load_open_batch(self) -> Optional[Dict[str, Any]]
        async def delete_open_batch(self, batch_id: str) -> None
        async def save_receipt(self, batch_id: str, receipt: Dict[str, Any]) -> None
        async def is_commitment_processed(self, idempotency_key: str) -> bool

    Дополнительно:
        - bootstrap(): создать схему при необходимости
        - gc_idempotency(): удалить истёкшие ключи идемпотентности
        - upsert_pending_item(): зарегистрировать элемент в pending (например, при постановке в очередь)
    """

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        idem_ttl_seconds: int = 24 * 3600,
        retry: TxRetryPolicy = TxRetryPolicy(),
    ) -> None:
        self._engine = engine
        self._session_maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        self._idem_ttl = idem_ttl_seconds
        self._retry = retry

    # ---------- Служебное ----------

    @classmethod
    def from_dsn(cls, dsn: str, **kwargs) -> "AnchorRepo":
        """
        Создать репозиторий из DSN PostgreSQL в формате asyncpg, например:
          postgresql+asyncpg://user:pass@host:5432/dbname
        """
        engine = create_async_engine(dsn, pool_pre_ping=True)
        return cls(engine, **kwargs)

    async def bootstrap(self) -> None:
        """Создать таблицы, если их нет. В бою — используйте миграции Alembic."""
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def gc_idempotency(self) -> int:
        """Удалить истёкшие ключи идемпотентности. Возвращает число удалённых строк."""
        now = datetime.now(timezone.utc)
        async with self._session_maker() as s, s.begin():
            res = await s.execute(delete(t_idempotency).where(t_idempotency.c.expires_at <= now))
            return res.rowcount or 0

    # ---------- Реализация BatcherStore ----------

    async def mark_item_anchored(self, item_id: str, receipt: Dict[str, Any]) -> None:
        await self._run_tx(self._mark_item, item_id, "anchored", receipt, None)

    async def mark_item_failed(self, item_id: str, reason: str) -> None:
        await self._run_tx(self._mark_item, item_id, "failed", None, reason)

    async def save_open_batch(self, batch_id: str, state: Dict[str, Any]) -> None:
        async with self._session_maker() as s, s.begin():
            stmt = insert(t_open_batch).values(batch_id=batch_id, state=state).on_conflict_do_update(
                index_elements=[t_open_batch.c.batch_id],
                set_={"state": state, "updated_at": func.now()},
            )
            await s.execute(stmt)

    async def load_open_batch(self) -> Optional[Dict[str, Any]]:
        async with self._session_maker() as s:
            # Ожидается максимум одна строка — самая свежая по updated_at
            stmt = (
                select(t_open_batch.c.batch_id, t_open_batch.c.state)
                .order_by(t_open_batch.c.updated_at.desc())
                .limit(1)
            )
            row = (await s.execute(stmt)).first()
            if not row:
                return None
            return {"batch_id": row.batch_id, "state": row.state}

    async def delete_open_batch(self, batch_id: str) -> None:
        async with self._session_maker() as s, s.begin():
            await s.execute(delete(t_open_batch).where(t_open_batch.c.batch_id == batch_id))

    async def save_receipt(self, batch_id: str, receipt: Dict[str, Any]) -> None:
        async with self._session_maker() as s, s.begin():
            stmt = insert(t_receipts).values(batch_id=batch_id, receipt=receipt).on_conflict_do_update(
                index_elements=[t_receipts.c.batch_id],
                set_={"receipt": receipt},
            )
            await s.execute(stmt)

            # если в receipt присутствует idempotency_key — занесём его в таблицу идемпотентности
            idem_key = receipt.get("idempotency_key")
            if idem_key:
                await self._upsert_idempotency(s, idem_key)

    async def is_commitment_processed(self, idempotency_key: str) -> bool:
        async with self._session_maker() as s:
            q = select(t_idempotency.c.idempotency_key).where(t_idempotency.c.idempotency_key == idempotency_key)
            row = (await s.execute(q)).first()
            return bool(row)

    # ---------- Дополнительно полезные методы ----------

    async def upsert_pending_item(self, item_id: str) -> None:
        """Пометить элемент как pending, создавая запись при отсутствии."""
        async with self._session_maker() as s, s.begin():
            stmt = insert(t_anchor_items).values(id=item_id, status="pending").on_conflict_do_update(
                index_elements=[t_anchor_items.c.id],
                set_={"status": "pending", "last_error": None, "updated_at": func.now()},
            )
            await s.execute(stmt)

    # ---------- Внутренние операции ----------

    async def _mark_item(
        self,
        s: AsyncSession,
        item_id: str,
        status: str,
        receipt: Optional[Dict[str, Any]],
        reason: Optional[str],
    ) -> None:
        # upsert: создадим строку, если её не было
        if status == "anchored":
            stmt = insert(t_anchor_items).values(
                id=item_id, status="anchored", receipt=receipt, last_error=None
            ).on_conflict_do_update(
                index_elements=[t_anchor_items.c.id],
                set_={
                    "status": "anchored",
                    "receipt": receipt,
                    "last_error": None,
                    "updated_at": func.now(),
                },
            )
        else:
            stmt = insert(t_anchor_items).values(
                id=item_id, status="failed", last_error=reason
            ).on_conflict_do_update(
                index_elements=[t_anchor_items.c.id],
                set_={
                    "status": "failed",
                    "last_error": reason,
                    "updated_at": func.now(),
                },
            )
        await s.execute(stmt)

    async def _upsert_idempotency(self, s: AsyncSession, key: str) -> None:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._idem_ttl)
        stmt = insert(t_idempotency).values(
            idempotency_key=key, expires_at=expires_at
        ).on_conflict_do_update(
            index_elements=[t_idempotency.c.idempotency_key],
            set_={"processed_at": func.now(), "expires_at": expires_at},
        )
        await s.execute(stmt)

    # Транзакционная оболочка с ретраями сериализации (40001) и connection reset
    async def _run_tx(self, fn, *args, **kwargs) -> Any:
        attempt = 0
        while True:
            attempt += 1
            try:
                async with self._session_maker() as s, s.begin():
                    return await fn(s, *args, **kwargs)
            except DBAPIError as e:
                # SQLSTATE '40001' — serialization_failure; '40P01' — deadlock_detected
                code = getattr(e.orig, "sqlstate", None) if hasattr(e, "orig") else None
                if code in ("40001", "40P01") and attempt < self._retry.max_attempts:
                    delay = self._retry.delay_seconds(attempt)
                    LOG.warning("tx retry due to %s (attempt %d), sleep %.3fs", code, attempt, delay)
                    await asyncio.sleep(delay)
                    continue
                raise
            except OperationalError as e:
                if attempt < self._retry.max_attempts:
                    delay = self._retry.delay_seconds(attempt)
                    LOG.warning("operational error, retry attempt %d sleep %.3fs: %s", attempt, delay, str(e))
                    await asyncio.sleep(delay)
                    continue
                raise SerializationRetryError(str(e))


# ---------- Пример инициализации ----------
# from ledger.storage.repositories.anchor_repo import AnchorRepo
# repo = AnchorRepo.from_dsn("postgresql+asyncpg://user:pass@host:5432/db")
# await repo.bootstrap()
#
# Интеграция с AnchorBatcher:
# class PgBatcherStore(BatcherStore):
#     def __init__(self, repo: AnchorRepo): self._r = repo
#     async def mark_item_anchored(self, item_id, receipt): await self._r.mark_item_anchored(item_id, receipt)
#     async def mark_item_failed(self, item_id, reason): await self._r.mark_item_failed(item_id, reason)
#     async def save_open_batch(self, batch_id, state): await self._r.save_open_batch(batch_id, state)
#     async def load_open_batch(self): return await self._r.load_open_batch()
#     async def delete_open_batch(self, batch_id): await self._r.delete_open_batch(batch_id)
#     async def save_receipt(self, batch_id, receipt): await self._r.save_receipt(batch_id, receipt)
#     async def is_commitment_processed(self, k): return await self._r.is_commitment_processed(k)
