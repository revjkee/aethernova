# ledger-core/ledger/storage/tx_repo.py
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, AsyncIterator, Iterable, List, Optional, Sequence, Tuple, Union

from pydantic import BaseModel, Field, constr, conint, condecimal, validator
from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
    select,
    update,
    text,
    event,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, insert as pg_insert
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base, Mapped, mapped_column

# ------------------------------------------------------------------------------
# Конфигурация и базовые сущности
# ------------------------------------------------------------------------------

log = logging.getLogger(__name__)
logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.WARNING)

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------------------
# Доменные типы и статусы
# ------------------------------------------------------------------------------

class TxStatus(str):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"
    DROPPED = "DROPPED"


# ------------------------------------------------------------------------------
# ORM-модель Transaction
# ------------------------------------------------------------------------------

class Transaction(Base):
    """
    Промышленная ORM-модель транзакции.
    Идемпотентность: уникальная пара (chain_id, tx_hash).
    Оптимистическая блокировка: поле version.
    """

    __tablename__ = "transactions"

    # PK как UUID. Для кросс-цепных интеграций удобно иметь стабильный UUID.
    id: Mapped[str] = mapped_column(
        PG_UUID(as_uuid=False),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    chain_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    from_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    to_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    nonce: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    amount: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # храним как str Decimal
    fee: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)     # храним как str Decimal

    gas_used: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    status: Mapped[str] = mapped_column(
        Enum(
            TxStatus.PENDING,
            TxStatus.CONFIRMED,
            TxStatus.FAILED,
            TxStatus.DROPPED,
            name="tx_status",
        ),
        nullable=False,
        default=TxStatus.PENDING,
        server_default=TxStatus.PENDING,
    )

    block_number: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    block_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    block_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    raw_tx: Mapped[Optional[bytes]] = mapped_column(nullable=True)
    metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default=text("1"))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("chain_id", "tx_hash", name="uq_tx_chain_hash"),
        Index("ix_tx_chain_hash", "chain_id", "tx_hash"),
        Index("ix_tx_from", "from_address"),
        Index("ix_tx_to", "to_address"),
        Index("ix_tx_status", "status"),
        Index("ix_tx_block_time", "block_time"),
        CheckConstraint("version >= 1", name="ck_tx_version_positive"),
    )

    def __repr__(self) -> str:
        return f"<Transaction {self.chain_id}:{self.tx_hash} status={self.status}>"


# ------------------------------------------------------------------------------
# DTO и запросы фильтрации
# ------------------------------------------------------------------------------

class TxCreate(BaseModel):
    chain_id: constr(strip_whitespace=True, min_length=1, max_length=64)
    tx_hash: constr(strip_whitespace=True, min_length=1, max_length=128)
    from_address: Optional[constr(strip_whitespace=True, max_length=128)] = None
    to_address: Optional[constr(strip_whitespace=True, max_length=128)] = None
    nonce: Optional[conint(ge=0)] = None
    amount: Optional[condecimal(max_digits=78, decimal_places=0)] = None
    fee: Optional[condecimal(max_digits=78, decimal_places=0)] = None
    gas_used: Optional[conint(ge=0)] = None
    block_number: Optional[conint(ge=0)] = None
    block_hash: Optional[constr(strip_whitespace=True, max_length=128)] = None
    block_time: Optional[datetime] = None
    raw_tx: Optional[bytes] = None
    metadata: Optional[dict[str, Any]] = None
    status: Optional[str] = Field(default=TxStatus.PENDING)

    @validator("block_time")
    def _ensure_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @validator("status")
    def _status_valid(cls, v: Optional[str]) -> Optional[str]:
        if v and v not in {TxStatus.PENDING, TxStatus.CONFIRMED, TxStatus.FAILED, TxStatus.DROPPED}:
            raise ValueError("invalid status")
        return v

    def to_orm_payload(self) -> dict[str, Any]:
        # Decimal -> str
        return {
            "chain_id": self.chain_id,
            "tx_hash": self.tx_hash,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "nonce": int(self.nonce) if self.nonce is not None else None,
            "amount": str(self.amount) if self.amount is not None else None,
            "fee": str(self.fee) if self.fee is not None else None,
            "gas_used": int(self.gas_used) if self.gas_used is not None else None,
            "block_number": int(self.block_number) if self.block_number is not None else None,
            "block_hash": self.block_hash,
            "block_time": self.block_time,
            "raw_tx": self.raw_tx,
            "metadata": self.metadata,
            "status": self.status or TxStatus.PENDING,
        }


class TxFilter(BaseModel):
    chain_id: Optional[str] = None
    statuses: Optional[Sequence[str]] = None
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    min_block: Optional[int] = None
    max_block: Optional[int] = None
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None
    search_tx_hash: Optional[str] = None

    @validator("time_from", "time_to")
    def _ensure_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class PageResult(BaseModel):
    items: List[dict[str, Any]]
    total: Optional[int] = None
    next_cursor: Optional[Tuple[str, str, int]] = None  # (chain_id, tx_hash, block_number)


# ------------------------------------------------------------------------------
# Вспомогательные retry-утилиты
# ------------------------------------------------------------------------------

@dataclass
class RetryPolicy:
    attempts: int = 3
    base_delay: float = 0.1
    max_delay: float = 1.0
    backoff: float = 2.0

    async def run(self, fn, *args, **kwargs):
        delay = self.base_delay
        for i in range(1, self.attempts + 1):
            try:
                return await fn(*args, **kwargs)
            except Exception as ex:
                if i == self.attempts:
                    raise
                log.warning("Retrying after error (%s/%s): %s", i, self.attempts, ex)
                await asyncio.sleep(min(delay, self.max_delay))
                delay *= self.backoff


# ------------------------------------------------------------------------------
# Репозиторий транзакций
# ------------------------------------------------------------------------------

class TransactionRepository:
    """
    Асинхронный репозиторий транзакций с UPSERT, keyset-пагинацией, ретраями и метриками.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        retry: Optional[RetryPolicy] = None,
    ) -> None:
        self._session_factory = session_factory
        self._retry = retry or RetryPolicy()

    # ------------------------------ CRUD / UPSERT ------------------------------

    async def create_or_ignore(self, tx: TxCreate) -> str:
        """
        Идемпотентная вставка. Если запись уже есть — тихо игнорируем, возвращаем id существующей.
        """
        async def _impl():
            async with self._session_factory() as session:
                payload = tx.to_orm_payload()
                stmt = pg_insert(Transaction).values(**payload)
                stmt = stmt.on_conflict_do_nothing(
                    index_elements=["chain_id", "tx_hash"]
                ).returning(Transaction.id)
                res = await session.execute(stmt)
                row = res.first()
                if row:
                    await session.commit()
                    return row[0]
                # уже существовало — извлечем id
                q = select(Transaction.id).where(
                    Transaction.chain_id == tx.chain_id,
                    Transaction.tx_hash == tx.tx_hash,
                )
                row2 = (await session.execute(q)).first()
                await session.commit()
                return row2[0] if row2 else ""
        return await self._retry.run(_impl)

    async def upsert(self, tx: TxCreate) -> str:
        """
        UPSERT с обновлением основных полей и bump версии.
        """
        async def _impl():
            async with self._session_factory() as session:
                payload = tx.to_orm_payload()
                stmt = pg_insert(Transaction).values(**payload).on_conflict_do_update(
                    index_elements=["chain_id", "tx_hash"],
                    set_={
                        "from_address": stmt_excluded("from_address"),
                        "to_address": stmt_excluded("to_address"),
                        "nonce": stmt_excluded("nonce"),
                        "amount": stmt_excluded("amount"),
                        "fee": stmt_excluded("fee"),
                        "gas_used": stmt_excluded("gas_used"),
                        "status": stmt_excluded("status"),
                        "block_number": stmt_excluded("block_number"),
                        "block_hash": stmt_excluded("block_hash"),
                        "block_time": stmt_excluded("block_time"),
                        "raw_tx": stmt_excluded("raw_tx"),
                        "metadata": stmt_excluded("metadata"),
                        "updated_at": func.now(),
                        "version": Transaction.version + 1,
                    },
                ).returning(Transaction.id)
                res = await session.execute(stmt)
                row = res.first()
                await session.commit()
                return row[0]
        return await self._retry.run(_impl)

    async def bulk_upsert(self, items: Sequence[TxCreate], chunk: int = 500) -> int:
        """
        Батчевый UPSERT. Возвращает количество обработанных элементов.
        """
        async def _impl():
            processed = 0
            async with self._session_factory() as session:
                for i in range(0, len(items), chunk):
                    batch = items[i : i + chunk]
                    values = [it.to_orm_payload() for it in batch]
                    stmt = pg_insert(Transaction).values(values).on_conflict_do_update(
                        index_elements=["chain_id", "tx_hash"],
                        set_={
                            "from_address": stmt_excluded("from_address"),
                            "to_address": stmt_excluded("to_address"),
                            "nonce": stmt_excluded("nonce"),
                            "amount": stmt_excluded("amount"),
                            "fee": stmt_excluded("fee"),
                            "gas_used": stmt_excluded("gas_used"),
                            "status": stmt_excluded("status"),
                            "block_number": stmt_excluded("block_number"),
                            "block_hash": stmt_excluded("block_hash"),
                            "block_time": stmt_excluded("block_time"),
                            "raw_tx": stmt_excluded("raw_tx"),
                            "metadata": stmt_excluded("metadata"),
                            "updated_at": func.now(),
                            "version": Transaction.version + 1,
                        },
                    )
                    await session.execute(stmt)
                    await session.commit()
                    processed += len(batch)
            return processed
        return await self._retry.run(_impl)

    # ------------------------------ GETTERS ------------------------------------

    async def get_by_chain_and_hash(self, chain_id: str, tx_hash: str) -> Optional[dict[str, Any]]:
        async def _impl():
            async with self._session_factory() as session:
                q = select(Transaction).where(
                    Transaction.chain_id == chain_id,
                    Transaction.tx_hash == tx_hash,
                )
                row = (await session.execute(q)).scalar_one_or_none()
                return row_to_dict(row)
        return await self._retry.run(_impl)

    async def exists(self, chain_id: str, tx_hash: str) -> bool:
        async def _impl():
            async with self._session_factory() as session:
                q = select(func.count()).select_from(Transaction).where(
                    Transaction.chain_id == chain_id, Transaction.tx_hash == tx_hash
                )
                cnt = (await session.execute(q)).scalar_one()
                return cnt > 0
        return await self._retry.run(_impl)

    # ------------------------------ LIST / SEARCH ------------------------------

    async def list(
        self,
        flt: TxFilter,
        limit: int = 100,
        offset: Optional[int] = None,
        cursor: Optional[Tuple[str, str, int]] = None,
        with_total: bool = False,
    ) -> PageResult:
        """
        Две стратегии:
        - offset/limit (klassic)
        - keyset cursor (стабильнее при больших объемах)
        """
        async def _impl():
            async with self._session_factory() as session:
                base = select(Transaction)

                if flt.chain_id:
                    base = base.where(Transaction.chain_id == flt.chain_id)
                if flt.statuses:
                    base = base.where(Transaction.status.in_(list(flt.statuses)))
                if flt.from_address:
                    base = base.where(Transaction.from_address == flt.from_address)
                if flt.to_address:
                    base = base.where(Transaction.to_address == flt.to_address)
                if flt.min_block is not None:
                    base = base.where(Transaction.block_number >= flt.min_block)
                if flt.max_block is not None:
                    base = base.where(Transaction.block_number <= flt.max_block)
                if flt.time_from:
                    base = base.where(Transaction.block_time >= flt.time_from)
                if flt.time_to:
                    base = base.where(Transaction.block_time <= flt.time_to)
                if flt.search_tx_hash:
                    base = base.where(Transaction.tx_hash == flt.search_tx_hash)

                next_cursor = None

                if cursor:
                    # keyset: упорядочим по (block_number desc, chain_id asc, tx_hash asc)
                    c_chain, c_hash, c_block = cursor
                    base = base.where(
                        (Transaction.block_number < c_block)
                        | (
                            (Transaction.block_number == c_block)
                            & (Transaction.chain_id > c_chain)
                        )
                        | (
                            (Transaction.block_number == c_block)
                            & (Transaction.chain_id == c_chain)
                            & (Transaction.tx_hash > c_hash)
                        )
                    )

                base = base.order_by(
                    Transaction.block_number.desc().nulls_last(),
                    Transaction.chain_id.asc(),
                    Transaction.tx_hash.asc(),
                ).limit(limit)

                res = await session.execute(base)
                rows = res.scalars().all()
                items = [row_to_dict(r) for r in rows]

                if items:
                    last = items[-1]
                    next_cursor = (
                        last["chain_id"],
                        last["tx_hash"],
                        last["block_number"] or 0,
                    )

                total = None
                if with_total and offset is not None:
                    count_q = select(func.count()).select_from(Transaction)
                    # применим те же фильтры
                    if flt.chain_id:
                        count_q = count_q.where(Transaction.chain_id == flt.chain_id)
                    if flt.statuses:
                        count_q = count_q.where(Transaction.status.in_(list(flt.statuses)))
                    if flt.from_address:
                        count_q = count_q.where(Transaction.from_address == flt.from_address)
                    if flt.to_address:
                        count_q = count_q.where(Transaction.to_address == flt.to_address)
                    if flt.min_block is not None:
                        count_q = count_q.where(Transaction.block_number >= flt.min_block)
                    if flt.max_block is not None:
                        count_q = count_q.where(Transaction.block_number <= flt.max_block)
                    if flt.time_from:
                        count_q = count_q.where(Transaction.block_time >= flt.time_from)
                    if flt.time_to:
                        count_q = count_q.where(Transaction.block_time <= flt.time_to)
                    if flt.search_tx_hash:
                        count_q = count_q.where(Transaction.tx_hash == flt.search_tx_hash)

                    total = (await session.execute(count_q)).scalar_one()

                return PageResult(items=items, total=total, next_cursor=next_cursor)
        return await self._retry.run(_impl)

    # ------------------------------ MUTATIONS ----------------------------------

    async def update_status(
        self,
        chain_id: str,
        tx_hash: str,
        new_status: str,
        expected_version: Optional[int] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> bool:
        """
        Обновление статуса с оптимистической блокировкой.
        """
        if new_status not in {TxStatus.PENDING, TxStatus.CONFIRMED, TxStatus.FAILED, TxStatus.DROPPED}:
            raise ValueError("invalid status")

        async def _impl():
            async with self._session_factory() as session:
                stmt = (
                    update(Transaction)
                    .where(
                        Transaction.chain_id == chain_id,
                        Transaction.tx_hash == tx_hash,
                    )
                    .values(
                        status=new_status,
                        metadata=merge_json(Transaction.metadata, extra or {}),
                        updated_at=func.now(),
                        version=Transaction.version + 1,
                    )
                )
                if expected_version is not None:
                    stmt = stmt.where(Transaction.version == expected_version)
                res = await session.execute(stmt)
                await session.commit()
                return res.rowcount > 0
        return await self._retry.run(_impl)

    async def mark_confirmed(
        self,
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_hash: str,
        block_time: datetime,
        expected_version: Optional[int] = None,
        receipt: Optional[dict[str, Any]] = None,
    ) -> bool:
        async def _impl():
            async with self._session_factory() as session:
                stmt = (
                    update(Transaction)
                    .where(
                        Transaction.chain_id == chain_id,
                        Transaction.tx_hash == tx_hash,
                    )
                    .values(
                        status=TxStatus.CONFIRMED,
                        block_number=block_number,
                        block_hash=block_hash,
                        block_time=ensure_tz(block_time),
                        metadata=merge_json(Transaction.metadata, {"receipt": receipt} if receipt else {}),
                        updated_at=func.now(),
                        version=Transaction.version + 1,
                    )
                )
                if expected_version is not None:
                    stmt = stmt.where(Transaction.version == expected_version)
                res = await session.execute(stmt)
                await session.commit()
                return res.rowcount > 0
        return await self._retry.run(_impl)

    async def prune(
        self,
        older_than: timedelta,
        statuses: Sequence[str] = (TxStatus.CONFIRMED, TxStatus.DROPPED, TxStatus.FAILED),
        limit: int = 5_000,
    ) -> int:
        """
        Удаление старых завершенных транзакций для контроля объема таблицы.
        """
        cutoff = utcnow() - older_than

        async def _impl():
            async with self._session_factory() as session:
                # В некоторых СУБД стоит использовать DELETE ... WHERE ctid IN (SELECT ctid FROM ... LIMIT n)
                # Здесь упрощенная версия:
                q_ids = select(Transaction.id).where(
                    Transaction.updated_at < cutoff, Transaction.status.in_(list(statuses))
                ).limit(limit)
                ids = [r[0] for r in (await session.execute(q_ids)).all()]
                if not ids:
                    return 0
                del_stmt = Transaction.__table__.delete().where(Transaction.id.in_(ids))
                res = await session.execute(del_stmt)
                await session.commit()
                return res.rowcount or 0
        return await self._retry.run(_impl)

    # ------------------------------ МЕТРИКИ / СТАТИСТИКА -----------------------

    async def stats_by_status(self, chain_id: Optional[str] = None) -> dict[str, int]:
        async def _impl():
            async with self._session_factory() as session:
                q = select(Transaction.status, func.count()).group_by(Transaction.status)
                if chain_id:
                    q = q.where(Transaction.chain_id == chain_id)
                rows = (await session.execute(q)).all()
                return {status: int(cnt) for status, cnt in rows}
        return await self._retry.run(_impl)

    async def healthcheck(self) -> bool:
        async def _impl():
            async with self._session_factory() as session:
                res = await session.execute(select(func.count()).select_from(Transaction).limit(1))
                _ = res.scalar_one()
                return True
        return await self._retry.run(_impl)


# ------------------------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------------------------

def ensure_tz(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def row_to_dict(tx: Optional[Transaction]) -> Optional[dict[str, Any]]:
    if tx is None:
        return None
    return {
        "id": tx.id,
        "chain_id": tx.chain_id,
        "tx_hash": tx.tx_hash,
        "from_address": tx.from_address,
        "to_address": tx.to_address,
        "nonce": tx.nonce,
        "amount": Decimal(tx.amount) if tx.amount is not None else None,
        "fee": Decimal(tx.fee) if tx.fee is not None else None,
        "gas_used": tx.gas_used,
        "status": tx.status,
        "block_number": tx.block_number,
        "block_hash": tx.block_hash,
        "block_time": tx.block_time,
        "raw_tx": tx.raw_tx,
        "metadata": tx.metadata,
        "version": tx.version,
        "created_at": tx.created_at,
        "updated_at": tx.updated_at,
    }

def stmt_excluded(col: str):
    # helper for ON CONFLICT ... DO UPDATE SET col = EXCLUDED.col
    from sqlalchemy.dialects.postgresql import insert as _pg_insert
    # В SQLAlchemy 2.0 доступ к EXCLUDED через stmt.excluded
    # Здесь обертка, т.к. мы создаем выражения внутри метода, где stmt доступен.
    # Решаем через text() для явного EXCLUDED, т.к. fields валидны и проверены.
    return text(f"EXCLUDED.{col}")

def merge_json(column_expr, extra: dict[str, Any]):
    """
    Акуратное объединение JSON: COALESCE(metadata, '{{}}') || '{"k":"v"}'
    Для кросс-СУБД можно заменить на серверную функцию или выполнять на клиенте.
    Постгрес: jsonb || jsonb — объединение.
    """
    from sqlalchemy.dialects.postgresql import JSONB
    if not extra:
        return column_expr
    return func.coalesce(column_expr.cast(JSONB), text("'{}'::jsonb")).op("||")(text(f"'{json_escape(extra)}'::jsonb"))

def json_escape(obj: dict[str, Any]) -> str:
    import json
    s = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    # одинарные кавычки внутри text литерала экранируем
    return s.replace("'", "''")


# ------------------------------------------------------------------------------
# Фабрика подключения (опционально)
# ------------------------------------------------------------------------------

def build_engine_from_env() -> Tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """
    Вспомогательная фабрика:
    DATABASE_URL=postgresql+asyncpg://user:pass@host:port/db
    """
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL not set")
    engine = create_async_engine(
        dsn,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
        pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),
        echo=False,
        future=True,
    )
    s
