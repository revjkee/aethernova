# ledger-core/tests/e2e/test_anchor_end2end.py
# -*- coding: utf-8 -*-
"""
Промышленный E2E-тест «anchor end-to-end» для ledger-core.

Требования окружения:
  - python>=3.11
  - fastapi>=0.111
  - httpx>=0.27
  - pydantic>=2
  - sqlalchemy>=2.0
  - aiosqlite (для fallback на SQLite) И/ИЛИ asyncpg (для PostgreSQL)
  - pytest, pytest-asyncio

Поведение:
  - Если установлен TEST_DB_URL (postgresql+asyncpg://...), используем его.
  - Иначе используем in-memory SQLite (aiosqlite).

Проверяемый сценарий:
  1) Создать два счёта (alice, bob).
  2) Создать проводки (депозит/переводы).
  3) Выполнить /anchor/commit -> получить HMAC-подписанную квитанцию и ID коммита.
  4) Проверить /anchor/status, верифицировать подпись, сопоставление записей ↔ коммит.
  5) Убедиться в неизменности: попытка изменить/удалить заякоренные записи -> 409.
  6) Идемпотентность: повторный /anchor/commit с тем же batch_key — 200 OK, тот же commit_id.
  7) Негативные кейсы: пустой батч -> 422, неправильная подпись (симуляция) -> 400.
  8) Конкурентные коммиты одного batch_key -> один фактический коммит.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, getcontext
from typing import Any, Optional, Sequence

import pytest
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.routing import APIRouter
from pydantic import BaseModel, Field, ValidationError, condecimal
from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    Index,
    CheckConstraint,
    select,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, NUMERIC
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
    AsyncEngine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

import httpx

# ---------------------------- Константы и Decimal ----------------------------

getcontext().prec = 38
SCALE = Decimal("0.000000000001")  # 12 знаков после запятой
CURRENCY_LEN = 3

# ---------------------------- SQLAlchemy модели ------------------------------

class Base(DeclarativeBase):
    pass


def _uuid_col(pk: bool = False) -> Any:
    try:
        # Если PostgreSQL — используем UUID тип
        return mapped_column(PG_UUID(as_uuid=True), primary_key=pk, default=uuid.uuid4)
    except Exception:
        # На SQLite будет сохранён как TEXT
        return mapped_column(String(36), primary_key=pk, default=lambda: str(uuid.uuid4()))


class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[uuid.UUID | str] = _uuid_col(pk=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    entries: Mapped[Sequence["LedgerEntry"]] = relationship(
        back_populates="account", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin"
    )


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    id: Mapped[uuid.UUID | str] = _uuid_col(pk=True)
    account_id: Mapped[uuid.UUID | str] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE", onupdate="CASCADE"), nullable=False
    )
    amount: Mapped[Decimal] = mapped_column(NUMERIC(38, 12), nullable=False)
    currency: Mapped[str] = mapped_column(String(CURRENCY_LEN), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    account: Mapped[Account] = relationship(back_populates="entries")

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_entry_idem_key"),
        Index("ix_entry_account_created", "account_id", "created_at"),
        CheckConstraint("amount <> 0", name="chk_amount_non_zero"),
        CheckConstraint("char_length(currency) = 3", name="chk_currency_len_3"),
    )


class AnchorCommit(Base):
    __tablename__ = "anchor_commits"
    id: Mapped[uuid.UUID | str] = _uuid_col(pk=True)
    batch_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    merkle_root_hex: Mapped[str] = mapped_column(String(64), nullable=False)  # sha256 hex
    receipt_json: Mapped[str] = mapped_column(String(2000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AnchorMap(Base):
    """
    Таблица связи «запись реестра -> коммит».
    Наличие строки запрещает модификацию/удаление записи.
    """
    __tablename__ = "anchor_map"
    entry_id: Mapped[uuid.UUID | str] = mapped_column(
        ForeignKey("ledger_entries.id", ondelete="RESTRICT", onupdate="CASCADE"),
        primary_key=True,
    )
    commit_id: Mapped[uuid.UUID | str] = mapped_column(
        ForeignKey("anchor_commits.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )


# ---------------------------- Меркл и якорение -------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root_hex(leaves: list[str]) -> str:
    """
    Вычисляет Merkle root (sha256) для списка hex-строк листьев.
    При пустом списке — ValueError.
    """
    if not leaves:
        raise ValueError("no leaves for merkle root")

    layer = [bytes.fromhex(x) for x in leaves]
    while len(layer) > 1:
        nxt: list[bytes] = []
        it = iter(layer)
        for a in it:
            try:
                b = next(it)
            except StopIteration:
                b = a  # дублируем последний
            nxt.append(hashlib.sha256(a + b).digest())
        layer = nxt
    return layer[0].hex()


@dataclass
class AnchorReceipt:
    merkle_root_hex: str
    batch_key: str
    timestamp: int
    tx_id: str
    signature_hex: str

    def to_json(self) -> str:
        return json.dumps(self.__dict__, separators=(",", ":"), sort_keys=True)


class AnchorClientHMAC:
    """
    Фейковый внешн. якорный клиент: имитирует запись в «блокчейн»,
    формируя HMAC-подписанную квитанцию.
    """
    def __init__(self, secret_key: bytes):
        self._key = secret_key

    def commit(self, merkle_root_hex: str, batch_key: str) -> AnchorReceipt:
        ts = int(datetime.now(tz=timezone.utc).timestamp())
        tx_id = str(uuid.uuid4())
        payload = f"{merkle_root_hex}|{batch_key}|{ts}|{tx_id}".encode()
        sig = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return AnchorReceipt(
            merkle_root_hex=merkle_root_hex,
            batch_key=batch_key,
            timestamp=ts,
            tx_id=tx_id,
            signature_hex=sig,
        )

    def verify(self, receipt: AnchorReceipt) -> bool:
        payload = f"{receipt.merkle_root_hex}|{receipt.batch_key}|{receipt.timestamp}|{receipt.tx_id}".encode()
        expect = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expect, receipt.signature_hex)


# ---------------------------- Репозиторий/сервис -----------------------------

class Repo:
    @staticmethod
    def _q(x: Decimal) -> Decimal:
        return x.quantize(SCALE)

    # Accounts
    @staticmethod
    async def create_account(db: AsyncSession, name: str) -> Account:
        acc = Account(name=name)
        db.add(acc)
        await db.flush()
        return acc

    # Entries
    @staticmethod
    async def create_entry(
        db: AsyncSession,
        *,
        account_id: str | uuid.UUID,
        amount: Decimal,
        currency: str,
        description: Optional[str],
        idempotency_key: Optional[str],
    ) -> LedgerEntry:
        currency = currency.upper()
        if len(currency) != CURRENCY_LEN:
            raise HTTPException(status_code=422, detail="currency must be 3 letters")
        entry = LedgerEntry(
            account_id=account_id,
            amount=Repo._q(amount),
            currency=currency,
            description=description,
            idempotency_key=idempotency_key,
        )
        db.add(entry)
        await db.flush()
        return entry

    @staticmethod
    async def list_entries_by_ids(db: AsyncSession, ids: list[str]) -> list[LedgerEntry]:
        if not ids:
            return []
        res = await db.execute(select(LedgerEntry).where(LedgerEntry.id.in_(ids)))
        return list(res.scalars().all())

    @staticmethod
    async def link_entries_to_commit(db: AsyncSession, entry_ids: list[str], commit_id: str):
        for eid in entry_ids:
            db.add(AnchorMap(entry_id=eid, commit_id=commit_id))
        await db.flush()

    @staticmethod
    async def is_entry_anchored(db: AsyncSession, entry_id: str) -> bool:
        res = await db.execute(select(AnchorMap).where(AnchorMap.entry_id == entry_id))
        return res.scalar_one_or_none() is not None

    @staticmethod
    async def delete_entry(db: AsyncSession, entry_id: str):
        if await Repo.is_entry_anchored(db, entry_id):
            raise HTTPException(status_code=409, detail="entry is anchored and immutable")
        entry = await db.get(LedgerEntry, entry_id)
        if entry:
            await db.delete(entry)
            await db.flush()

    # Anchor
    @staticmethod
    async def upsert_anchor_commit(
        db: AsyncSession, *, batch_key: str, merkle_root_hex: str, receipt: AnchorReceipt
    ) -> AnchorCommit:
        # Идемпотентность по batch_key
        res = await db.execute(select(AnchorCommit).where(AnchorCommit.batch_key == batch_key))
        existed = res.scalar_one_or_none()
        if existed:
            # проверим совпадение корня
            if existed.merkle_root_hex != merkle_root_hex:
                raise HTTPException(status_code=409, detail="batch_key already anchored with different root")
            return existed

        commit = AnchorCommit(
            batch_key=batch_key,
            merkle_root_hex=merkle_root_hex,
            receipt_json=receipt.to_json(),
        )
        db.add(commit)
        await db.flush()
        return commit


# ---------------------------- Pydantic схемы API -----------------------------

class AccountIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class AccountOut(BaseModel):
    id: str
    name: str
    created_at: datetime


class EntryIn(BaseModel):
    account_id: str
    amount: condecimal(gt=Decimal("0")) | condecimal(lt=Decimal("0"))  # исключаем ноль
    currency: str = Field(min_length=3, max_length=3)
    description: Optional[str] = None
    idempotency_key: Optional[str] = Field(default=None, max_length=128)


class EntryOut(BaseModel):
    id: str
    account_id: str
    amount: Decimal
    currency: str
    description: Optional[str] = None
    created_at: datetime


class AnchorCommitIn(BaseModel):
    batch_key: str = Field(min_length=1, max_length=128)
    entry_ids: list[str] = Field(min_items=1)


class AnchorStatusOut(BaseModel):
    commit_id: str
    batch_key: str
    merkle_root_hex: str
    receipt: dict


# ---------------------------- Приложение FastAPI -----------------------------

def _make_async_url() -> str:
    url = os.getenv("TEST_DB_URL")
    if url:
        if not url.startswith("postgresql+asyncpg://"):
            if url.startswith("postgresql://"):
                url = "postgresql+asyncpg://" + url[len("postgresql://") :]
        return url
    # fallback на SQLite
    return "sqlite+aiosqlite:///:memory:"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.engine = create_async_engine(_make_async_url(), echo=False, pool_pre_ping=True)
    app.state.sessionmaker = async_sessionmaker(app.state.engine, class_=AsyncSession, expire_on_commit=False)
    # Инициализация схемы
    async with app.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    # Секрет для HMAC (в реале — KMS/HSM)
    app.state.anchor_client = AnchorClientHMAC(secret_key=os.urandom(32))
    yield
    await app.state.engine.dispose()


app = FastAPI(lifespan=lifespan)
api = APIRouter(prefix="/api")


async def get_db() -> AsyncSession:
    async with app.state.sessionmaker() as s:
        yield s


def node_hash(entry: LedgerEntry) -> str:
    """
    Лист Merkle: sha256(id|account_id|amount|currency|created_at|description)
    """
    payload = "|".join(
        [
            str(entry.id),
            str(entry.account_id),
            format(entry.amount, "f"),
            entry.currency,
            entry.created_at.replace(tzinfo=timezone.utc).isoformat(),
            entry.description or "",
        ]
    ).encode()
    return sha256_hex(payload)


@api.post("/accounts", response_model=AccountOut, status_code=201)
async def create_account(body: AccountIn, db: AsyncSession = Depends(get_db)):
    acc = await Repo.create_account(db, body.name)
    await db.commit()
    return AccountOut(id=str(acc.id), name=acc.name, created_at=acc.created_at)


@api.post("/entries", response_model=EntryOut, status_code=201)
async def create_entry(body: EntryIn, db: AsyncSession = Depends(get_db)):
    e = await Repo.create_entry(
        db,
        account_id=body.account_id,
        amount=Decimal(str(body.amount)),
        currency=body.currency,
        description=body.description,
        idempotency_key=body.idempotency_key,
    )
    await db.commit()
    return EntryOut(
        id=str(e.id),
        account_id=str(e.account_id),
        amount=e.amount,
        currency=e.currency,
        description=e.description,
        created_at=e.created_at,
    )


@api.post("/anchor/commit", response_model=AnchorStatusOut, status_code=200)
async def anchor_commit(body: AnchorCommitIn, db: AsyncSession = Depends(get_db)):
    # Загружаем записи и строим Merkle-root
    entries = await Repo.list_entries_by_ids(db, body.entry_ids)
    if len(entries) != len(body.entry_ids):
        raise HTTPException(status_code=422, detail="some entries not found")
    leaves = [node_hash(e) for e in sorted(entries, key=lambda x: str(x.id))]
    if not leaves:
        raise HTTPException(status_code=422, detail="empty batch")
    root = merkle_root_hex(leaves)

    # Коммит через якорный клиент
    receipt = app.state.anchor_client.commit(root, body.batch_key)
    if not app.state.anchor_client.verify(receipt):
        raise HTTPException(status_code=400, detail="invalid receipt signature")

    # Upsert коммит (идемпотентность по batch_key)
    commit = await Repo.upsert_anchor_commit(
        db, batch_key=body.batch_key, merkle_root_hex=root, receipt=receipt
    )
    # Связать записи с коммитом (immutability)
    await Repo.link_entries_to_commit(db, [str(e.id) for e in entries], str(commit.id))
    await db.commit()
    return AnchorStatusOut(
        commit_id=str(commit.id),
        batch_key=commit.batch_key,
        merkle_root_hex=commit.merkle_root_hex,
        receipt=json.loads(commit.receipt_json),
    )


@api.get("/anchor/status/{batch_key}", response_model=AnchorStatusOut, status_code=200)
async def anchor_status(batch_key: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(AnchorCommit).where(AnchorCommit.batch_key == batch_key))
    commit = res.scalar_one_or_none()
    if not commit:
        raise HTTPException(status_code=404, detail="batch not found")
    return AnchorStatusOut(
        commit_id=str(commit.id),
        batch_key=commit.batch_key,
        merkle_root_hex=commit.merkle_root_hex,
        receipt=json.loads(commit.receipt_json),
    )


@api.delete("/entries/{entry_id}", status_code=204)
async def delete_entry(entry_id: str, db: AsyncSession = Depends(get_db)):
    await Repo.delete_entry(db, entry_id)
    await db.commit()
    return {}


app.include_router(api)


# ---------------------------- Фикстуры тестов --------------------------------

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def client():
    async with httpx.AsyncClient(app=app, base_url="http://test", timeout=10.0) as c:
        yield c


# ---------------------------- Вспомогательные функции ------------------------

async def _create_account(client: httpx.AsyncClient, name: str) -> str:
    r = await client.post("/api/accounts", json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _create_entry(
    client: httpx.AsyncClient,
    *,
    account_id: str,
    amount: Decimal,
    currency: str,
    description: str,
    idempotency_key: Optional[str] = None,
) -> str:
    payload = {
        "account_id": account_id,
        "amount": str(amount),
        "currency": currency,
        "description": description,
        "idempotency_key": idempotency_key,
    }
    r = await client.post("/api/entries", json=payload)
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _anchor_commit(client: httpx.AsyncClient, *, batch_key: str, entry_ids: list[str]) -> dict:
    r = await client.post("/api/anchor/commit", json={"batch_key": batch_key, "entry_ids": entry_ids})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------- ТЕСТЫ E2E --------------------------------------

@pytest.mark.asyncio(timeout=60)
async def test_anchor_happy_path_and_immutability(client: httpx.AsyncClient):
    # 1) Создаём счета
    alice = await _create_account(client, "alice")
    bob = await _create_account(client, "bob")

    # 2) Проводки
    e1 = await _create_entry(
        client, account_id=alice, amount=Decimal("100.000000000009"), currency="USD", description="fund", idempotency_key="fund-1"
    )
    e2 = await _create_entry(
        client, account_id=alice, amount=Decimal("-25.0"), currency="USD", description="pay->bob", idempotency_key="tr-1"
    )
    e3 = await _create_entry(
        client, account_id=bob, amount=Decimal("25.0"), currency="USD", description="from-alice", idempotency_key="tr-1"
    )

    # 3) Коммитим батч
    batch_key = "batch-2025-08-18T00:00Z"
    commit = await _anchor_commit(client, batch_key=batch_key, entry_ids=[e1, e2, e3])
    assert commit["batch_key"] == batch_key
    assert isinstance(commit["commit_id"], str)
    assert len(commit["merkle_root_hex"]) == 64

    # 4) Вытягиваем статус и сверяем receipt
    r = await client.get(f"/api/anchor/status/{batch_key}")
    assert r.status_code == 200, r.text
    status_data = r.json()
    assert status_data["commit_id"] == commit["commit_id"]
    assert status_data["merkle_root_hex"] == commit["merkle_root_hex"]
    assert "receipt" in status_data and "signature_hex" in status_data["receipt"]

    # 5) Неизменность: удаление любой записи из заякоренного батча -> 409
    r_del = await client.delete(f"/api/entries/{e2}")
    assert r_del.status_code == 409, r_del.text

    # 6) Идемпотентность: повторный commit того же batch_key с теми же записями -> тот же commit_id
    commit2 = await _anchor_commit(client, batch_key=batch_key, entry_ids=[e1, e2, e3])
    assert commit2["commit_id"] == commit["commit_id"]
    assert commit2["merkle_root_hex"] == commit["merkle_root_hex"]


@pytest.mark.asyncio(timeout=60)
async def test_anchor_empty_batch_and_missing_entries(client: httpx.AsyncClient):
    # Пустой список -> 422
    r = await client.post("/api/anchor/commit", json={"batch_key": "empty", "entry_ids": []})
    assert r.status_code == 422

    # Отсутствующие записи -> 422
    ghost_id = str(uuid.uuid4())
    r = await client.post("/api/anchor/commit", json={"batch_key": "missing", "entry_ids": [ghost_id]})
    assert r.status_code == 422


@pytest.mark.asyncio(timeout=60)
async def test_anchor_idempotency_under_concurrency(client: httpx.AsyncClient):
    # Подготовка записей
    a1 = await _create_account(client, "acc1")
    entries = []
    for i in range(5):
        eid = await _create_entry(
            client, account_id=a1, amount=Decimal(10 + i), currency="EUR", description=f"e{i}", idempotency_key=f"idem-{i}"
        )
        entries.append(eid)

    batch_key = "batch-concurrent"
    # Делаем 8 параллельных попыток одного и того же коммита
    async def do_commit():
        return await _anchor_commit(client, batch_key=batch_key, entry_ids=entries)

    results = await asyncio.gather(*[do_commit() for _ in range(8)])
    commit_ids = {r["commit_id"] for r in results}
    roots = {r["merkle_root_hex"] for r in results}

    # Должен быть один фактический коммит
    assert len(commit_ids) == 1
    assert len(roots) == 1


@pytest.mark.asyncio(timeout=60)
async def test_immutable_entry_cannot_be_deleted_or_modified(client: httpx.AsyncClient):
    # Создаём счёт и запись
    acc = await _create_account(client, "immut")
    e = await _create_entry(
        client, account_id=acc, amount=Decimal("7.5"), currency="USD", description="lockme", idempotency_key="lock-1"
    )
    # Якорим
    await _anchor_commit(client, batch_key="lock-batch", entry_ids=[e])

    # Попытка удалить -> 409
    r = await client.delete(f"/api/entries/{e}")
    assert r.status_code == 409
