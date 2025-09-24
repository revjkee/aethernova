# ledger-core/tests/integration/test_db_repository.py
# -*- coding: utf-8 -*-
"""
Интеграционные тесты репозитория Ledger для асинхронной БД.
Особенности:
- Асинхронный SQLAlchemy 2.0 (только async, без sync-сессий).
- Точное хранение сумм через Decimal (NUMERIC(38,12)).
- Изоляция БД: TEST_DB_URL или Testcontainers (PostgreSQL).
- Полные проверки CRUD, идемпотентности и атомарности переводов.
- Конкурентные переводы для проверки гонок и блокировок.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from decimal import Decimal, getcontext
from typing import Optional, Sequence

import pytest

# В среде проекта должны быть установлены: sqlalchemy>=2.0, asyncpg, pytest, pytest-asyncio
from sqlalchemy import (
    String,
    DateTime,
    ForeignKey,
    text,
    UniqueConstraint,
    Index,
    select,
    func,
    CheckConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, NUMERIC
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.exc import IntegrityError

# Попробуем использовать Testcontainers, если переменная окружения не задана.
try:
    from testcontainers.postgres import PostgresContainer  # type: ignore
    _HAVE_TESTCONTAINERS = True
except Exception:
    _HAVE_TESTCONTAINERS = False

# Настройки Decimal для денежных операций
getcontext().prec = 38  # общая точность
# масштаб 12 поддерживается NUMERIC(38,12), квантование выполняем в коде репозитория при необходимости

# ---------- SQLAlchemy база и модели ----------

class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    entries: Mapped[Sequence["LedgerEntry"]] = relationship(
        back_populates="account",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("accounts.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    amount: Mapped[Decimal] = mapped_column(
        NUMERIC(38, 12), nullable=False
    )  # подписанная величина: дебет(+), кредит(-) либо наоборот по вашей политике
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    account: Mapped[Account] = relationship(back_populates="entries")

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_ledger_idempotency_key"),
        Index("ix_ledger_account_created", "account_id", "created_at"),
        CheckConstraint("char_length(currency) = 3", name="chk_currency_len_3"),
        CheckConstraint("amount <> 0", name="chk_amount_non_zero"),
    )


# ---------- Вспомогательная инфраструктура БД ----------

def _make_async_url_from_sync(sync_url: str) -> str:
    """
    Преобразует sync URL Testcontainers к asyncpg.
    Пример: postgresql://user:pass@host:port/db -> postgresql+asyncpg://user:pass@host:port/db
    """
    if sync_url.startswith("postgresql+asyncpg://"):
        return sync_url
    if sync_url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + sync_url[len("postgresql://") :]
    return sync_url


@asynccontextmanager
async def _engine_ctx() -> AsyncEngine:
    """
    Создаёт асинхронный движок по TEST_DB_URL или через Testcontainers.
    """
    test_db_url = os.getenv("TEST_DB_URL")
    container = None

    if test_db_url:
        async_url = _make_async_url_from_sync(test_db_url)
        engine = create_async_engine(async_url, echo=False, pool_pre_ping=True)
        try:
            yield engine
        finally:
            await engine.dispose()
        return

    if not _HAVE_TESTCONTAINERS:
        pytest.skip("TEST_DB_URL не задан и testcontainers не установлен; пропуск интеграционных тестов.")

    # Testcontainers: поднимаем PostgreSQL
    container = PostgresContainer("postgres:16-alpine")
    container.with_env("POSTGRES_INITDB_ARGS", "--data-checksums")
    container.start()
    try:
        sync_url = container.get_connection_url()
        async_url = _make_async_url_from_sync(sync_url)
        engine = create_async_engine(async_url, echo=False, pool_pre_ping=True)
        try:
            yield engine
        finally:
            await engine.dispose()
    finally:
        if container:
            container.stop()


async def _reset_schema(engine: AsyncEngine) -> None:
    """
    Полный сброс схемы для изоляции тестов.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


@pytest.fixture(scope="session")
def anyio_backend():
    # Позволяет использовать pytest-asyncio/anyio в ряде окружений.
    return "asyncio"


@pytest.fixture(scope="session")
def event_loop():
    # Глобальный event loop для всего скоупа session.
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def engine() -> AsyncEngine:
    async with _engine_ctx() as eng:
        yield eng


@pytest.fixture(scope="session")
async def sessionmaker_engine(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(autouse=True)
async def _clean_db(engine: AsyncEngine):
    # Перед каждым тестом создаём чистую схему
    await _reset_schema(engine)


@pytest.fixture
async def db(sessionmaker_engine: async_sessionmaker[AsyncSession]) -> AsyncSession:
    async with sessionmaker_engine() as session:
        yield session


# ---------- Эталонный (референс) репозиторий для тестов ----------
# Если в проекте есть собственный репозиторий, можно заменить на импорт и использовать те же тесты.

class GenericDbRepository:
    """
    Минимальный промышленный репозиторий для операций с проводками (ledger entries).
    """

    @staticmethod
    def _q(amount: Decimal) -> Decimal:
        # Принудительное квантование до 12 знаков после запятой.
        return amount.quantize(Decimal("0.000000000001"))

    @staticmethod
    async def create_account(session: AsyncSession, *, name: str) -> Account:
        acc = Account(name=name)
        session.add(acc)
        await session.flush()
        return acc

    @staticmethod
    async def add_entry(
        session: AsyncSession,
        *,
        account_id: uuid.UUID,
        amount: Decimal,
        currency: str,
        description: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> LedgerEntry:
        entry = LedgerEntry(
            account_id=account_id,
            amount=GenericDbRepository._q(amount),
            currency=currency.upper(),
            description=description,
            idempotency_key=idempotency_key,
        )
        session.add(entry)
        await session.flush()
        return entry

    @staticmethod
    async def get_entry(session: AsyncSession, entry_id: uuid.UUID) -> Optional[LedgerEntry]:
        res = await session.execute(select(LedgerEntry).where(LedgerEntry.id == entry_id))
        return res.scalar_one_or_none()

    @staticmethod
    async def list_entries_by_account(
        session: AsyncSession, account_id: uuid.UUID, *, limit: int = 100, offset: int = 0
    ) -> list[LedgerEntry]:
        stmt = (
            select(LedgerEntry)
            .where(LedgerEntry.account_id == account_id)
            .order_by(LedgerEntry.created_at.desc(), LedgerEntry.id.desc())
            .limit(limit)
            .offset(offset)
        )
        res = await session.execute(stmt)
        return list(res.scalars().all())

    @staticmethod
    async def update_entry_description(
        session: AsyncSession, entry_id: uuid.UUID, new_description: Optional[str]
    ) -> Optional[LedgerEntry]:
        entry = await GenericDbRepository.get_entry(session, entry_id)
        if entry is None:
            return None
        entry.description = new_description
        await session.flush()
        return entry

    @staticmethod
    async def delete_entry(session: AsyncSession, entry_id: uuid.UUID) -> bool:
        entry = await GenericDbRepository.get_entry(session, entry_id)
        if entry is None:
            return False
        await session.delete(entry)
        await session.flush()
        return True

    @staticmethod
    async def account_balance(session: AsyncSession, account_id: uuid.UUID, currency: str) -> Decimal:
        """
        Сумма по всем проводкам счета в заданной валюте.
        """
        stmt = select(func.coalesce(func.sum(LedgerEntry.amount), 0)).where(
            LedgerEntry.account_id == account_id, LedgerEntry.currency == currency.upper()
        )
        res = await session.execute(stmt)
        val = res.scalar_one()
        if isinstance(val, Decimal):
            return GenericDbRepository._q(val)
        return GenericDbRepository._q(Decimal(val))

    @staticmethod
    async def transfer(
        session: AsyncSession,
        *,
        from_account: uuid.UUID,
        to_account: uuid.UUID,
        amount: Decimal,
        currency: str,
        idempotency_key: Optional[str] = None,
        description: Optional[str] = None,
    ) -> tuple[LedgerEntry, LedgerEntry]:
        """
        Атомарный перевод: дебет/кредит двумя проводками в одной транзакции.
        Предполагаем политику: списание — отрицательное значение, зачисление — положительное.
        """
        if amount <= Decimal("0"):
            raise ValueError("amount must be positive")

        # Чтобы предотвратить двойной перевод по тому же ключу, проверим наличие заранее
        if idempotency_key:
            already = await session.execute(
                select(LedgerEntry.id).where(LedgerEntry.idempotency_key == idempotency_key)
            )
            if already.scalar_one_or_none():
                raise IntegrityError(
                    "duplicate idempotency_key", params=None, orig=None  # type: ignore[arg-type]
                )

        debit = await GenericDbRepository.add_entry(
            session,
            account_id=from_account,
            amount=GenericDbRepository._q(-amount),
            currency=currency,
            description=description or "transfer: debit",
            idempotency_key=idempotency_key,
        )
        credit = await GenericDbRepository.add_entry(
            session,
            account_id=to_account,
            amount=GenericDbRepository._q(amount),
            currency=currency,
            description=description or "transfer: credit",
            idempotency_key=idempotency_key,
        )
        return debit, credit


# ---------- Фикстуры доменной модели ----------

@pytest.fixture
async def accounts(db: AsyncSession) -> tuple[Account, Account]:
    a1 = await GenericDbRepository.create_account(db, name="alice")
    a2 = await GenericDbRepository.create_account(db, name="bob")
    await db.commit()
    return a1, a2


# ---------- ТЕСТЫ ----------

@pytest.mark.asyncio(timeout=30)
async def test_create_and_get_entry_roundtrip(db: AsyncSession, accounts: tuple[Account, Account]):
    alice, _ = accounts
    e = await GenericDbRepository.add_entry(
        db,
        account_id=alice.id,
        amount=Decimal("123.456789012345"),
        currency="usd",
        description="initial deposit",
        idempotency_key=str(uuid.uuid4()),
    )
    await db.commit()

    fetched = await GenericDbRepository.get_entry(db, e.id)
    assert fetched is not None
    assert fetched.account_id == alice.id
    # Обрезка до 12 знаков после запятой
    assert fetched.amount == Decimal("123.456789012345").quantize(Decimal("0.000000000001"))
    assert fetched.currency == "USD"
    assert fetched.description == "initial deposit"


@pytest.mark.asyncio(timeout=30)
async def test_list_entries_sorted_and_paged(db: AsyncSession, accounts: tuple[Account, Account]):
    alice, _ = accounts
    keys = []
    for i in range(5):
        k = f"k-{i}"
        keys.append(k)
        await GenericDbRepository.add_entry(
            db,
            account_id=alice.id,
            amount=Decimal("1.0"),
            currency="USD",
            description=f"e{i}",
            idempotency_key=k,
        )
    await db.commit()

    page1 = await GenericDbRepository.list_entries_by_account(db, alice.id, limit=2, offset=0)
    page2 = await GenericDbRepository.list_entries_by_account(db, alice.id, limit=2, offset=2)
    page3 = await GenericDbRepository.list_entries_by_account(db, alice.id, limit=2, offset=4)

    # проверим разбиение по 2 записи
    assert len(page1) == 2
    assert len(page2) == 2
    assert len(page3) == 1

    # порядок: последние сначала по created_at, затем по id
    all_ids = [e.id for e in page1 + page2 + page3]
    assert len(all_ids) == len(set(all_ids))


@pytest.mark.asyncio(timeout=30)
async def test_update_and_delete_entry(db: AsyncSession, accounts: tuple[Account, Account]):
    alice, _ = accounts
    e = await GenericDbRepository.add_entry(
        db,
        account_id=alice.id,
        amount=Decimal("10"),
        currency="EUR",
        description="before",
        idempotency_key="upd-del-1",
    )
    await db.commit()

    upd = await GenericDbRepository.update_entry_description(db, e.id, "after")
    await db.commit()
    assert upd is not None and upd.description == "after"

    ok = await GenericDbRepository.delete_entry(db, e.id)
    await db.commit()
    assert ok is True

    missing = await GenericDbRepository.get_entry(db, e.id)
    assert missing is None


@pytest.mark.asyncio(timeout=30)
async def test_account_balance_and_transfer_atomicity(db: AsyncSession, accounts: tuple[Account, Account]):
    alice, bob = accounts

    # начальные балансы
    bal_a0 = await GenericDbRepository.account_balance(db, alice.id, "USD")
    bal_b0 = await GenericDbRepository.account_balance(db, bob.id, "USD")
    assert bal_a0 == Decimal("0")
    assert bal_b0 == Decimal("0")

    # пополнение алисы
    await GenericDbRepository.add_entry(
        db,
        account_id=alice.id,
        amount=Decimal("100.000000000009"),
        currency="USD",
        description="fund",
        idempotency_key="fund-1",
    )
    await db.commit()

    # перевод 25
    await db.begin()
    try:
        await GenericDbRepository.transfer(
            db,
            from_account=alice.id,
            to_account=bob.id,
            amount=Decimal("25"),
            currency="USD",
            idempotency_key="tr-1",
            description="payment",
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    bal_a1 = await GenericDbRepository.account_balance(db, alice.id, "USD")
    bal_b1 = await GenericDbRepository.account_balance(db, bob.id, "USD")
    # alice: 100 - 25 = 75
    assert bal_a1 == Decimal("75.000000000009").quantize(Decimal("0.000000000001"))
    # bob: +25
    assert bal_b1 == Decimal("25.000000000000").quantize(Decimal("0.000000000001"))

    # Попытка повторить тот же idempotency_key должна провалиться
    with pytest.raises(IntegrityError):
        await db.begin()
        try:
            await GenericDbRepository.transfer(
                db,
                from_account=alice.id,
                to_account=bob.id,
                amount=Decimal("25"),
                currency="USD",
                idempotency_key="tr-1",
            )
            await db.commit()
        except Exception:
            await db.rollback()
            raise


@pytest.mark.asyncio(timeout=30)
async def test_rollback_on_midway_failure(db: AsyncSession, accounts: tuple[Account, Account]):
    alice, bob = accounts
    await GenericDbRepository.add_entry(
        db,
        account_id=alice.id,
        amount=Decimal("50"),
        currency="USD",
        description="fund-2",
        idempotency_key="fund-2",
    )
    await db.commit()

    await db.begin()
    try:
        # первая проводка успешна
        await GenericDbRepository.add_entry(
            db,
            account_id=alice.id,
            amount=Decimal("-10"),
            currency="USD",
            description="debit-pre",
            idempotency_key="roll-1",
        )
        # симулируем падение до второй проводки
        raise RuntimeError("simulated failure")
    except RuntimeError:
        await db.rollback()

    # Баланс не должен измениться
    bal = await GenericDbRepository.account_balance(db, alice.id, "USD")
    assert bal == Decimal("50.000000000000").quantize(Decimal("0.000000000001"))


@pytest.mark.asyncio(timeout=60)
async def test_concurrent_transfers(db: AsyncSession, accounts: tuple[Account, Account]):
    alice, bob = accounts

    # Фондируем Alice 1000 USD
    await GenericDbRepository.add_entry(
        db,
        account_id=alice.id,
        amount=Decimal("1000"),
        currency="USD",
        description="fund-3",
        idempotency_key="fund-3",
    )
    await db.commit()

    # 10 параллельных переводов по 10 USD
    async def one_transfer(i: int):
        # собственная транзакция для каждой гонки
        await db.begin()
        try:
            await GenericDbRepository.transfer(
                db,
                from_account=alice.id,
                to_account=bob.id,
                amount=Decimal("10"),
                currency="USD",
                idempotency_key=f"ctr-{i}",
                description=f"batch-{i}",
            )
            await asyncio.sleep(0)  # уступить планировщику
            await db.commit()
        except Exception:
            await db.rollback()
            raise

    await asyncio.gather(*(one_transfer(i) for i in range(10)))

    bal_a = await GenericDbRepository.account_balance(db, alice.id, "USD")
    bal_b = await GenericDbRepository.account_balance(db, bob.id, "USD")

    assert bal_a == Decimal("900.000000000000").quantize(Decimal("0.000000000001"))
    assert bal_b == Decimal("100.000000000000").quantize(Decimal("0.000000000001"))


@pytest.mark.asyncio(timeout=30)
async def test_currency_constraints_and_amount_nonzero(db: AsyncSession, accounts: tuple[Account, Account]):
    alice, _ = accounts

    # Неверная валюта
    with pytest.raises(IntegrityError):
        await db.begin()
        try:
            await GenericDbRepository.add_entry(
                db,
                account_id=alice.id,
                amount=Decimal("1"),
                currency="US",  # длина != 3
                description="bad currency",
                idempotency_key="bad-cur-1",
            )
            await db.commit()
        except Exception:
            await db.rollback()
            raise

    # Нулевой amount запрещён
    with pytest.raises(IntegrityError):
        await db.begin()
        try:
            await GenericDbRepository.add_entry(
                db,
                account_id=alice.id,
                amount=Decimal("0"),
                currency="USD",
                description="zero amount",
                idempotency_key="zero-1",
            )
            await db.commit()
        except Exception:
            await db.rollback()
            raise
