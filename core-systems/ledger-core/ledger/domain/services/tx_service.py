# ledger-core/ledger/domain/services/tx_service.py
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation, getcontext
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, runtime_checkable
from uuid import UUID, uuid4

try:
    # pydantic v2
    from pydantic import BaseModel, Field, ConfigDict, field_validator
except Exception:  # pragma: no cover
    # fallback to pydantic v1 names
    from pydantic import BaseModel, Field, validator as field_validator  # type: ignore
    class ConfigDict:  # type: ignore
        pass

# --------------------------------------------------------------------------------------
# Global money precision (high enough for multi-asset tokens)
# --------------------------------------------------------------------------------------
getcontext().prec = 38

logger = logging.getLogger("ledger.tx_service")


# --------------------------------------------------------------------------------------
# Domain primitives
# --------------------------------------------------------------------------------------

class TxType(str, Enum):
    TRANSFER = "TRANSFER"
    CREDIT = "CREDIT"
    DEBIT = "DEBIT"
    RESERVE = "RESERVE"
    RESERVE_COMMIT = "RESERVE_COMMIT"
    RESERVE_RELEASE = "RESERVE_RELEASE"
    REVERSAL = "REVERSAL"
    ADJUSTMENT = "ADJUSTMENT"


class TxStatus(str, Enum):
    PENDING = "PENDING"
    COMMITTED = "COMMITTED"
    REVERSED = "REVERSED"
    FAILED = "FAILED"


class PostingSide(str, Enum):
    DEBIT = "DR"
    CREDIT = "CR"


@dataclass(frozen=True)
class Money:
    amount: Decimal
    currency: str

    def quantize(self, scale: int) -> "Money":
        q = Decimal((0, (1,), -scale))  # e.g., scale=2 -> Decimal('0.01')
        return Money(amount=self.amount.quantize(q, rounding=ROUND_HALF_UP), currency=self.currency)

    def ensure_non_negative(self) -> "Money":
        if self.amount < 0:
            raise ValueError("Money amount must be non-negative")
        return self


# Currency scale registry (can be loaded from config)
DEFAULT_CURRENCY_SCALE: Dict[str, int] = {
    "USD": 2,
    "EUR": 2,
    "SEK": 2,
    "BTC": 8,
    "ETH": 18,
    "TON": 9,
}


# --------------------------------------------------------------------------------------
# DTOs (validated inputs/outputs)
# --------------------------------------------------------------------------------------

class TransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(..., min_length=1, max_length=200)
    from_account_id: UUID
    to_account_id: UUID
    amount: Decimal = Field(..., gt=Decimal("0"))
    currency: str = Field(..., min_length=1, max_length=16)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("currency")
    @classmethod
    def _cur_upper(cls, v: str) -> str:
        return v.upper()

    @field_validator("amount")
    @classmethod
    def _amount_decimal(cls, v: Decimal) -> Decimal:
        try:
            return Decimal(v)
        except InvalidOperation as e:
            raise ValueError("Invalid decimal amount") from e


class CreditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str
    to_account_id: UUID
    amount: Decimal = Field(..., gt=Decimal("0"))
    currency: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DebitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str
    from_account_id: UUID
    amount: Decimal = Field(..., gt=Decimal("0"))
    currency: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ReserveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str
    account_id: UUID
    amount: Decimal = Field(..., gt=Decimal("0"))
    currency: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CommitReserveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str
    reservation_id: UUID
    # Optional partial commit
    amount: Optional[Decimal] = Field(default=None, gt=Decimal("0"))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ReleaseReserveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str
    reservation_id: UUID
    amount: Optional[Decimal] = Field(default=None, gt=Decimal("0"))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ReverseTxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str
    original_tx_id: UUID
    reason: str = Field(..., min_length=1, max_length=512)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TxRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    request_id: str
    tx_type: TxType
    status: TxStatus
    currency: str
    amount: Decimal
    created_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)
    hash_chain: str


# --------------------------------------------------------------------------------------
# Repository and UoW contracts
# --------------------------------------------------------------------------------------

@runtime_checkable
class AccountsRepository(Protocol):
    async def exists(self, account_id: UUID) -> bool: ...
    async def get_currency(self, account_id: UUID) -> str: ...
    async def get_version(self, account_id: UUID) -> int: ...
    async def get_balances(self, account_id: UUID, currency: str) -> Tuple[Decimal, Decimal]:
        """returns (available, reserved)"""
        ...
    async def apply_postings(
        self,
        postings: Sequence["Posting"],
        expected_versions: Dict[UUID, int],
    ) -> None:
        """Atomically apply postings; fail on version mismatch."""
        ...


@runtime_checkable
class TransactionsRepository(Protocol):
    async def get_by_request_id(self, request_id: str) -> Optional[TxRecord]: ...
    async def get_by_id(self, tx_id: UUID) -> Optional[TxRecord]: ...
    async def insert(self, tx: TxRecord) -> None: ...
    async def mark_reversed(self, tx_id: UUID) -> None: ...


@runtime_checkable
class ReservationsRepository(Protocol):
    async def create(
        self,
        reservation_id: UUID,
        account_id: UUID,
        currency: str,
        amount: Decimal,
        request_id: str,
        metadata: Dict[str, Any],
        hash_chain: str,
    ) -> None: ...
    async def get(
        self, reservation_id: UUID
    ) -> Optional[Tuple[UUID, str, Decimal, Decimal, Dict[str, Any], str]]:
        """
        returns (account_id, currency, total_amount, remaining_amount, metadata, hash_chain)
        """
        ...
    async def add_commit(self, reservation_id: UUID, amount: Decimal, new_hash_chain: str) -> None: ...
    async def add_release(self, reservation_id: UUID, amount: Decimal, new_hash_chain: str) -> None: ...


@dataclass(frozen=True)
class Posting:
    tx_id: UUID
    account_id: UUID
    currency: str
    amount: Decimal
    side: PostingSide  # DR or CR


@runtime_checkable
class OutboxRepository(Protocol):
    async def enqueue(self, topic: str, payload: Dict[str, Any]) -> None: ...


@runtime_checkable
class UnitOfWork(Protocol):
    accounts: AccountsRepository
    tx: TransactionsRepository
    reservations: ReservationsRepository
    outbox: OutboxRepository

    async def __aenter__(self) -> "UnitOfWork": ...
    async def __aexit__(self, exc_type, exc, tb) -> None: ...
    async def commit(self) -> None: ...
    async def rollback(self) -> None: ...


# --------------------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------------------

def _currency_scale(currency: str) -> int:
    return DEFAULT_CURRENCY_SCALE.get(currency.upper(), 2)


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _hash_chain(prev_hash: Optional[str], payload: Dict[str, Any]) -> str:
    # Deterministic canonical json
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    m = hashlib.sha256()
    if prev_hash:
        m.update(prev_hash.encode("utf-8"))
    m.update(body)
    return m.hexdigest()


async def _retry_async(
    func,
    *,
    retries: int = 5,
    base_delay: float = 0.01,
    max_delay: float = 0.25,
    retriable_exceptions: Tuple[type, ...] = (AssertionError,),
):
    delay = base_delay
    for attempt in range(1, retries + 1):
        try:
            return await func()
        except retriable_exceptions as e:
            if attempt >= retries:
                raise
            await asyncio.sleep(delay)
            delay = min(max_delay, delay * 2)


# --------------------------------------------------------------------------------------
# Transaction Service
# --------------------------------------------------------------------------------------

class TxService:
    """
    High-integrity transaction service implementing:
    - double-entry postings
    - idempotency by request_id
    - optimistic concurrency with expected_versions
    - reservations lifecycle
    - reversal of committed tx
    - outbox domain events
    - audit hash-chain per tx/reservation
    """

    def __init__(
        self,
        uow_factory: Protocol,  # callable that returns UnitOfWork
        *,
        tracer: Any = None,     # optional OpenTelemetry tracer
        service_name: str = "ledger.tx_service",
    ):
        self._uow_factory = uow_factory
        self._tracer = tracer
        self._service_name = service_name

    # -----------------------
    # Public API
    # -----------------------

    async def transfer(self, req: TransferRequest) -> TxRecord:
        """
        Atomic DR from from_account and CR to to_account.
        """
        return await self._execute_idempotent(req.request_id, TxType.TRANSFER, req.metadata, self._transfer_impl, req)

    async def credit(self, req: CreditRequest) -> TxRecord:
        return await self._execute_idempotent(req.request_id, TxType.CREDIT, req.metadata, self._credit_impl, req)

    async def debit(self, req: DebitRequest) -> TxRecord:
        return await self._execute_idempotent(req.request_id, TxType.DEBIT, req.metadata, self._debit_impl, req)

    async def reserve(self, req: ReserveRequest) -> TxRecord:
        return await self._execute_idempotent(req.request_id, TxType.RESERVE, req.metadata, self._reserve_impl, req)

    async def commit_reserve(self, req: CommitReserveRequest) -> TxRecord:
        return await self._execute_idempotent(req.request_id, TxType.RESERVE_COMMIT, req.metadata, self._commit_reserve_impl, req)

    async def release_reserve(self, req: ReleaseReserveRequest) -> TxRecord:
        return await self._execute_idempotent(req.request_id, TxType.RESERVE_RELEASE, req.metadata, self._release_reserve_impl, req)

    async def reverse(self, req: ReverseTxRequest) -> TxRecord:
        return await self._execute_idempotent(req.request_id, TxType.REVERSAL, req.metadata, self._reverse_impl, req)

    async def get_tx(self, tx_id: UUID) -> Optional[TxRecord]:
        async with self._uow_factory() as uow:
            return await uow.tx.get_by_id(tx_id)

    # -----------------------
    # Core execution helpers
    # -----------------------

    async def _execute_idempotent(
        self,
        request_id: str,
        tx_type: TxType,
        metadata: Dict[str, Any],
        fn,
        req_obj: BaseModel,
    ) -> TxRecord:
        span = self._start_span(f"{tx_type.lower()}:{self._service_name}", {"request_id": request_id, "type": tx_type})
        try:
            # Fast-path: dedupe by request_id
            async with self._uow_factory() as uow:
                existing = await uow.tx.get_by_request_id(request_id)
                if existing:
                    logger.info("idempotent_hit", extra={"request_id": request_id, "tx_id": str(existing.id), "type": tx_type})
                    return existing

            # Execute with retry on optimistic lock conflicts
            async def op():
                async with self._uow_factory() as uow:
                    tx_record = await fn(uow, req_obj, tx_type)
                    await uow.commit()
                    return tx_record

            tx_record = await _retry_async(op, retriable_exceptions=(AssertionError,))
            return tx_record
        finally:
            self._end_span(span)

    # -----------------------
    # Implementations
    # -----------------------

    async def _transfer_impl(self, uow: UnitOfWork, req: TransferRequest, tx_type: TxType) -> TxRecord:
        # Validate accounts and currency
        await self._assert_account_exists(uow, req.from_account_id)
        await self._assert_account_exists(uow, req.to_account_id)

        from_ccy = await uow.accounts.get_currency(req.from_account_id)
        to_ccy = await uow.accounts.get_currency(req.to_account_id)
        if from_ccy != to_ccy or from_ccy != req.currency:
            raise ValueError("Currency mismatch for transfer")

        money = Money(req.amount, req.currency).ensure_non_negative().quantize(_currency_scale(req.currency))
        tx_id = uuid4()

        # Load versions and balances
        expected_versions = {
            req.from_account_id: await uow.accounts.get_version(req.from_account_id),
            req.to_account_id: await uow.accounts.get_version(req.to_account_id),
        }
        available_from, _ = await uow.accounts.get_balances(req.from_account_id, req.currency)
        assert available_from >= money.amount, "Insufficient funds"

        # Build postings (double-entry)
        postings = [
            Posting(tx_id=tx_id, account_id=req.from_account_id, currency=req.currency, amount=money.amount, side=PostingSide.DEBIT),
            Posting(tx_id=tx_id, account_id=req.to_account_id, currency=req.currency, amount=money.amount, side=PostingSide.CREDIT),
        ]

        # Prepare tx record with hash-chain
        payload = {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "amount": str(money.amount),
            "currency": money.currency,
            "from": str(req.from_account_id),
            "to": str(req.to_account_id),
            "metadata": req.metadata,
            "ts": _now_utc().isoformat(),
        }
        h = _hash_chain(None, payload)
        record = TxRecord(
            id=tx_id,
            request_id=req.request_id,
            tx_type=tx_type,
            status=TxStatus.COMMITTED,
            currency=money.currency,
            amount=money.amount,
            created_at=_now_utc(),
            metadata=req.metadata,
            hash_chain=h,
        )

        # Apply atomically
        await uow.accounts.apply_postings(postings, expected_versions=expected_versions)
        await uow.tx.insert(record)
        await uow.outbox.enqueue("ledger.tx.committed", {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "amount": str(money.amount),
            "currency": money.currency,
            "from": str(req.from_account_id),
            "to": str(req.to_account_id),
            "request_id": req.request_id,
            "hash": h,
        })
        logger.info("transfer_committed", extra={"tx_id": str(tx_id), "request_id": req.request_id})
        return record

    async def _credit_impl(self, uow: UnitOfWork, req: CreditRequest, tx_type: TxType) -> TxRecord:
        await self._assert_account_exists(uow, req.to_account_id)
        acc_ccy = await uow.accounts.get_currency(req.to_account_id)
        if acc_ccy != req.currency:
            raise ValueError("Currency mismatch for credit")

        money = Money(req.amount, req.currency).ensure_non_negative().quantize(_currency_scale(req.currency))
        tx_id = uuid4()

        expected_versions = {req.to_account_id: await uow.accounts.get_version(req.to_account_id)}
        postings = [
            Posting(tx_id=tx_id, account_id=req.to_account_id, currency=req.currency, amount=money.amount, side=PostingSide.CREDIT),
        ]
        payload = {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "amount": str(money.amount),
            "currency": money.currency,
            "to": str(req.to_account_id),
            "metadata": req.metadata,
            "ts": _now_utc().isoformat(),
        }
        h = _hash_chain(None, payload)
        record = TxRecord(
            id=tx_id,
            request_id=req.request_id,
            tx_type=tx_type,
            status=TxStatus.COMMITTED,
            currency=money.currency,
            amount=money.amount,
            created_at=_now_utc(),
            metadata=req.metadata,
            hash_chain=h,
        )

        await uow.accounts.apply_postings(postings, expected_versions)
        await uow.tx.insert(record)
        await uow.outbox.enqueue("ledger.tx.committed", {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "amount": str(money.amount),
            "currency": money.currency,
            "to": str(req.to_account_id),
            "request_id": req.request_id,
            "hash": h,
        })
        logger.info("credit_committed", extra={"tx_id": str(tx_id), "request_id": req.request_id})
        return record

    async def _debit_impl(self, uow: UnitOfWork, req: DebitRequest, tx_type: TxType) -> TxRecord:
        await self._assert_account_exists(uow, req.from_account_id)
        acc_ccy = await uow.accounts.get_currency(req.from_account_id)
        if acc_ccy != req.currency:
            raise ValueError("Currency mismatch for debit")

        money = Money(req.amount, req.currency).ensure_non_negative().quantize(_currency_scale(req.currency))
        tx_id = uuid4()
        expected_versions = {req.from_account_id: await uow.accounts.get_version(req.from_account_id)}

        available, _ = await uow.accounts.get_balances(req.from_account_id, req.currency)
        assert available >= money.amount, "Insufficient funds"

        postings = [
            Posting(tx_id=tx_id, account_id=req.from_account_id, currency=req.currency, amount=money.amount, side=PostingSide.DEBIT),
        ]

        payload = {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "amount": str(money.amount),
            "currency": money.currency,
            "from": str(req.from_account_id),
            "metadata": req.metadata,
            "ts": _now_utc().isoformat(),
        }
        h = _hash_chain(None, payload)
        record = TxRecord(
            id=tx_id,
            request_id=req.request_id,
            tx_type=tx_type,
            status=TxStatus.COMMITTED,
            currency=money.currency,
            amount=money.amount,
            created_at=_now_utc(),
            metadata=req.metadata,
            hash_chain=h,
        )

        await uow.accounts.apply_postings(postings, expected_versions)
        await uow.tx.insert(record)
        await uow.outbox.enqueue("ledger.tx.committed", {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "amount": str(money.amount),
            "currency": money.currency,
            "from": str(req.from_account_id),
            "request_id": req.request_id,
            "hash": h,
        })
        logger.info("debit_committed", extra={"tx_id": str(tx_id), "request_id": req.request_id})
        return record

    async def _reserve_impl(self, uow: UnitOfWork, req: ReserveRequest, tx_type: TxType) -> TxRecord:
        await self._assert_account_exists(uow, req.account_id)
        acc_ccy = await uow.accounts.get_currency(req.account_id)
        if acc_ccy != req.currency:
            raise ValueError("Currency mismatch for reserve")

        money = Money(req.amount, req.currency).ensure_non_negative().quantize(_currency_scale(req.currency))
        tx_id = uuid4()
        reservation_id = uuid4()

        expected_versions = {req.account_id: await uow.accounts.get_version(req.account_id)}
        available, reserved = await uow.accounts.get_balances(req.account_id, req.currency)
        assert available >= money.amount, "Insufficient funds to reserve"

        # Reserve represented as DR available, CR reserved (or internal reserve account)
        postings = [
            Posting(tx_id=tx_id, account_id=req.account_id, currency=req.currency, amount=money.amount, side=PostingSide.DEBIT),   # decrease available
            Posting(tx_id=tx_id, account_id=req.account_id, currency=req.currency, amount=money.amount, side=PostingSide.CREDIT),  # increase reserved bucket
        ]

        payload = {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "reservation_id": str(reservation_id),
            "amount": str(money.amount),
            "currency": money.currency,
            "account": str(req.account_id),
            "metadata": req.metadata,
            "ts": _now_utc().isoformat(),
        }
        h = _hash_chain(None, payload)

        record = TxRecord(
            id=tx_id,
            request_id=req.request_id,
            tx_type=tx_type,
            status=TxStatus.COMMITTED,
            currency=money.currency,
            amount=money.amount,
            created_at=_now_utc(),
            metadata={"reservation_id": str(reservation_id), **req.metadata},
            hash_chain=h,
        )

        await uow.accounts.apply_postings(postings, expected_versions)
        await uow.reservations.create(
            reservation_id=reservation_id,
            account_id=req.account_id,
            currency=money.currency,
            amount=money.amount,
            request_id=req.request_id,
            metadata=req.metadata,
            hash_chain=h,
        )
        await uow.tx.insert(record)
        await uow.outbox.enqueue("ledger.reserve.created", {
            "tx_id": str(tx_id),
            "reservation_id": str(reservation_id),
            "amount": str(money.amount),
            "currency": money.currency,
            "account": str(req.account_id),
            "request_id": req.request_id,
            "hash": h,
        })
        logger.info("reserve_created", extra={"tx_id": str(tx_id), "reservation_id": str(reservation_id)})
        return record

    async def _commit_reserve_impl(self, uow: UnitOfWork, req: CommitReserveRequest, tx_type: TxType) -> TxRecord:
        r = await uow.reservations.get(req.reservation_id)
        if not r:
            raise ValueError("Reservation not found")
        account_id, currency, total_amt, remaining_amt, meta, prev_hash = r

        amount_to_commit = req.amount if req.amount is not None else remaining_amt
        if amount_to_commit <= 0 or amount_to_commit > remaining_amt:
            raise ValueError("Invalid commit amount")

        scale = _currency_scale(currency)
        amount_to_commit = Decimal(amount_to_commit).quantize(Decimal((0, (1,), -scale)), rounding=ROUND_HALF_UP)

        tx_id = uuid4()
        expected_versions = {account_id: await uow.accounts.get_version(account_id)}

        # Move from reserved to outflow (final debit): DR reserved bucket, CR destination (external) is modeled by a separate posting policy.
        postings = [
            Posting(tx_id=tx_id, account_id=account_id, currency=currency, amount=amount_to_commit, side=PostingSide.DEBIT),   # decrease reserved
        ]

        payload = {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "reservation_id": str(req.reservation_id),
            "amount": str(amount_to_commit),
            "currency": currency,
            "account": str(account_id),
            "metadata": req.metadata,
            "ts": _now_utc().isoformat(),
        }
        h = _hash_chain(prev_hash, payload)

        record = TxRecord(
            id=tx_id,
            request_id=req.request_id,
            tx_type=tx_type,
            status=TxStatus.COMMITTED,
            currency=currency,
            amount=amount_to_commit,
            created_at=_now_utc(),
            metadata={"reservation_id": str(req.reservation_id), **req.metadata},
            hash_chain=h,
        )

        await uow.accounts.apply_postings(postings, expected_versions)
        await uow.reservations.add_commit(req.reservation_id, amount_to_commit, new_hash_chain=h)
        await uow.tx.insert(record)
        await uow.outbox.enqueue("ledger.reserve.committed", {
            "tx_id": str(tx_id),
            "reservation_id": str(req.reservation_id),
            "amount": str(amount_to_commit),
            "currency": currency,
            "account": str(account_id),
            "request_id": req.request_id,
            "hash": h,
        })
        logger.info("reserve_committed", extra={"tx_id": str(tx_id), "reservation_id": str(req.reservation_id)})
        return record

    async def _release_reserve_impl(self, uow: UnitOfWork, req: ReleaseReserveRequest, tx_type: TxType) -> TxRecord:
        r = await uow.reservations.get(req.reservation_id)
        if not r:
            raise ValueError("Reservation not found")
        account_id, currency, total_amt, remaining_amt, meta, prev_hash = r

        amount_to_release = req.amount if req.amount is not None else remaining_amt
        if amount_to_release <= 0 or amount_to_release > remaining_amt:
            raise ValueError("Invalid release amount")

        scale = _currency_scale(currency)
        amount_to_release = Decimal(amount_to_release).quantize(Decimal((0, (1,), -scale)), rounding=ROUND_HALF_UP)

        tx_id = uuid4()
        expected_versions = {account_id: await uow.accounts.get_version(account_id)}

        # Release: DR reserved bucket decrease is represented as CREDIT to available (refund back)
        postings = [
            Posting(tx_id=tx_id, account_id=account_id, currency=currency, amount=amount_to_release, side=PostingSide.CREDIT),
        ]

        payload = {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "reservation_id": str(req.reservation_id),
            "amount": str(amount_to_release),
            "currency": currency,
            "account": str(account_id),
            "metadata": req.metadata,
            "ts": _now_utc().isoformat(),
        }
        h = _hash_chain(prev_hash, payload)

        record = TxRecord(
            id=tx_id,
            request_id=req.request_id,
            tx_type=tx_type,
            status=TxStatus.COMMITTED,
            currency=currency,
            amount=amount_to_release,
            created_at=_now_utc(),
            metadata={"reservation_id": str(req.reservation_id), **req.metadata},
            hash_chain=h,
        )

        await uow.accounts.apply_postings(postings, expected_versions)
        await uow.reservations.add_release(req.reservation_id, amount_to_release, new_hash_chain=h)
        await uow.tx.insert(record)
        await uow.outbox.enqueue("ledger.reserve.released", {
            "tx_id": str(tx_id),
            "reservation_id": str(req.reservation_id),
            "amount": str(amount_to_release),
            "currency": currency,
            "account": str(account_id),
            "request_id": req.request_id,
            "hash": h,
        })
        logger.info("reserve_released", extra={"tx_id": str(tx_id), "reservation_id": str(req.reservation_id)})
        return record

    async def _reverse_impl(self, uow: UnitOfWork, req: ReverseTxRequest, tx_type: TxType) -> TxRecord:
        original = await uow.tx.get_by_id(req.original_tx_id)
        if not original:
            raise ValueError("Original transaction not found")
        if original.status == TxStatus.REVERSED:
            # Idempotent reversal
            existing = await uow.tx.get_by_request_id(req.request_id)
            if existing:
                return existing
            raise ValueError("Transaction already reversed")

        # NOTE: reversal postings must exactly negate original postings; here
        # we assume the account layer can reconstruct postings by tx_id.
        # To keep the service independent, we rely on accounts.apply_postings
        # being fed with a negated set resolved at this level if available, or
        # an internal mechanism at repository layer.
        tx_id = uuid4()

        # Build payload for hash chain
        payload = {
            "tx_id": str(tx_id),
            "type": tx_type.value,
            "original_tx_id": str(original.id),
            "reason": req.reason,
            "amount": str(original.amount),
            "currency": original.currency,
            "ts": _now_utc().isoformat(),
            "metadata": req.metadata,
        }
        h = _hash_chain(original.hash_chain, payload)

        # Domain rule: to avoid partial reversals here we model full reversal.
        # Repository must generate proper negating postings for original tx.
        expected_versions = {}  # repository will check all affected accounts
        await uow.accounts.apply_postings(
            postings=[],  # sentinel; implementation-specific reversal by tx_id
            expected_versions=expected_versions,
        )

        reversed_record = TxRecord(
            id=tx_id,
            request_id=req.request_id,
            tx_type=tx_type,
            status=TxStatus.COMMITTED,
            currency=original.currency,
            amount=original.amount,
            created_at=_now_utc(),
            metadata={"original_tx_id": str(original.id), "reason": req.reason, **req.metadata},
            hash_chain=h,
        )

        await uow.tx.insert(reversed_record)
        await uow.tx.mark_reversed(original.id)
        await uow.outbox.enqueue("ledger.tx.reversed", {
            "tx_id": str(tx_id),
            "original_tx_id": str(original.id),
            "amount": str(original.amount),
            "currency": original.currency,
            "request_id": req.request_id,
            "reason": req.reason,
            "hash": h,
        })
        logger.info("tx_reversed", extra={"tx_id": str(tx_id), "original_tx_id": str(original.id)})
        return reversed_record

    # -----------------------
    # Assertions & helpers
    # -----------------------

    async def _assert_account_exists(self, uow: UnitOfWork, account_id: UUID) -> None:
        if not await uow.accounts.exists(account_id):
            raise ValueError("Account not found")

    def _start_span(self, name: str, attrs: Dict[str, Any]):
        if not self._tracer:
            return None
        span = self._tracer.start_as_current_span(name)
        if hasattr(span, "set_attributes"):
            span.set_attributes(attrs)  # OpenTelemetry API
        return span

    def _end_span(self, span):
        if span is None:
            return
        with contextlib.suppress(Exception):
            span.__exit__(None, None, None)
