# agent_mash/cfo/accounting/assistant/transactions.py
# Industrial-grade accounting transactions core for CFO domain.
# Scope: immutable ledger entries, double-entry accounting, validation,
# idempotency, auditability, deterministic transaction IDs, async-safe design.

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import logging
import time
import uuid
from collections.abc import Mapping, Sequence
from decimal import Decimal, ROUND_HALF_UP, getcontext
from typing import Any, Final, Optional

try:
    from pydantic import BaseModel, Field, ConfigDict, field_validator
except Exception as _e:  # pragma: no cover
    raise RuntimeError("pydantic is required for agent_mash.cfo.accounting.assistant.transactions") from _e


_LOG: Final[logging.Logger] = logging.getLogger(__name__)

# Финансовая точность
getcontext().prec = 28


class Currency(str, enum.Enum):
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    RUB = "RUB"
    JPY = "JPY"


class AccountType(str, enum.Enum):
    ASSET = "asset"
    LIABILITY = "liability"
    EQUITY = "equity"
    REVENUE = "revenue"
    EXPENSE = "expense"


class TransactionStatus(str, enum.Enum):
    DRAFT = "draft"
    POSTED = "posted"
    REVERSED = "reversed"
    VOID = "void"


class AccountingError(RuntimeError):
    pass


class ValidationError(AccountingError):
    pass


class ImbalanceError(AccountingError):
    pass


class IdempotencyError(AccountingError):
    pass


class Money(BaseModel):
    """
    Денежная величина с фиксированной валютой.
    """
    model_config = ConfigDict(extra="forbid")

    amount: Decimal = Field(...)
    currency: Currency

    @field_validator("amount")
    @classmethod
    def normalize_amount(cls, v: Decimal) -> Decimal:
        if not isinstance(v, Decimal):
            v = Decimal(v)
        return v.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


class Account(BaseModel):
    """
    План счетов.
    """
    model_config = ConfigDict(extra="forbid")

    account_id: str = Field(min_length=4, max_length=64)
    name: str = Field(min_length=1, max_length=256)
    type: AccountType
    currency: Currency
    active: bool = True


class LedgerEntry(BaseModel):
    """
    Одна строка бухгалтерской проводки.
    """
    model_config = ConfigDict(extra="forbid")

    entry_id: str = Field(min_length=16, max_length=128)
    account_id: str = Field(min_length=4, max_length=64)
    debit: Decimal = Field(default=Decimal("0.00"))
    credit: Decimal = Field(default=Decimal("0.00"))

    @field_validator("debit", "credit")
    @classmethod
    def normalize(cls, v: Decimal) -> Decimal:
        if not isinstance(v, Decimal):
            v = Decimal(v)
        if v < 0:
            raise ValidationError("negative values are not allowed")
        return v.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    @field_validator("credit")
    @classmethod
    def debit_credit_exclusive(cls, v: Decimal, info) -> Decimal:
        debit = info.data.get("debit", Decimal("0.00"))
        if debit > 0 and v > 0:
            raise ValidationError("both debit and credit are set")
        if debit == 0 and v == 0:
            raise ValidationError("either debit or credit must be set")
        return v


class Transaction(BaseModel):
    """
    Бухгалтерская транзакция (двойная запись).
    """
    model_config = ConfigDict(extra="forbid")

    transaction_id: str = Field(min_length=16, max_length=128)
    external_id: Optional[str] = Field(default=None, max_length=128)

    description: str = Field(min_length=1, max_length=512)
    currency: Currency

    entries: list[LedgerEntry]

    status: TransactionStatus = TransactionStatus.DRAFT

    created_ts: float = Field(default_factory=lambda: time.time())
    posted_ts: Optional[float] = None

    trace_id: Optional[str] = Field(default=None, max_length=128)

    @field_validator("entries")
    @classmethod
    def validate_entries(cls, v: list[LedgerEntry]) -> list[LedgerEntry]:
        if len(v) < 2:
            raise ValidationError("transaction must have at least two ledger entries")
        return v


class TransactionResult(BaseModel):
    """
    Результат обработки транзакции.
    """
    model_config = ConfigDict(extra="forbid")

    transaction_id: str
    status: TransactionStatus
    debit_total: Decimal
    credit_total: Decimal
    imbalance: Decimal
    ts: float
    trace_id: Optional[str] = None


class IdempotencyStore:
    """
    Интерфейс идемпотентности.
    """
    def get(self, key: str) -> Optional[TransactionResult]:  # pragma: no cover
        raise NotImplementedError

    def set(self, key: str, value: TransactionResult, ttl_sec: float) -> None:  # pragma: no cover
        raise NotImplementedError


class InMemoryIdempotencyStore(IdempotencyStore):
    """
    In-memory реализация. Для продакшена заменить на Redis или БД.
    """
    def __init__(self) -> None:
        self._data: dict[str, tuple[float, TransactionResult]] = {}

    def get(self, key: str) -> Optional[TransactionResult]:
        item = self._data.get(key)
        if not item:
            return None
        exp_ts, val = item
        if time.time() > exp_ts:
            self._data.pop(key, None)
            return None
        return val

    def set(self, key: str, value: TransactionResult, ttl_sec: float) -> None:
        self._data[key] = (time.time() + float(ttl_sec), value)


class TransactionsEngine:
    """
    Ядро бухгалтерских транзакций.
    Гарантии:
    - детерминированный transaction_id
    - строгая двойная запись
    - идемпотентность
    - аудитопригодность
    """

    def __init__(
        self,
        idempotency: Optional[IdempotencyStore] = None,
        idempotency_ttl_sec: float = 3600.0,
        salt: str = "agent_mash:cfo:transactions:v1",
    ) -> None:
        self._idem = idempotency or InMemoryIdempotencyStore()
        self._ttl = float(idempotency_ttl_sec)
        self._salt = salt

    def post(self, tx: Transaction) -> TransactionResult:
        if tx.status != TransactionStatus.DRAFT:
            raise ValidationError("only draft transactions can be posted")

        idem_key = self._idempotency_key(tx)
        cached = self._idem.get(idem_key)
        if cached is not None:
            return cached

        debit_total, credit_total = self._totals(tx.entries)
        imbalance = (debit_total - credit_total).quantize(Decimal("0.01"))

        if imbalance != Decimal("0.00"):
            raise ImbalanceError(f"transaction imbalance: {imbalance}")

        tx.status = TransactionStatus.POSTED
        tx.posted_ts = time.time()

        result = TransactionResult(
            transaction_id=tx.transaction_id,
            status=tx.status,
            debit_total=debit_total,
            credit_total=credit_total,
            imbalance=imbalance,
            ts=tx.posted_ts,
            trace_id=tx.trace_id,
        )

        self._idem.set(idem_key, result, self._ttl)
        return result

    def reverse(self, tx: Transaction, reason: str) -> Transaction:
        if tx.status != TransactionStatus.POSTED:
            raise ValidationError("only posted transactions can be reversed")

        reversed_entries: list[LedgerEntry] = []
        for e in tx.entries:
            reversed_entries.append(
                LedgerEntry(
                    entry_id=uuid.uuid4().hex,
                    account_id=e.account_id,
                    debit=e.credit,
                    credit=e.debit,
                )
            )

        reversed_tx = Transaction(
            transaction_id=self._derive_transaction_id(
                base_id=tx.transaction_id,
                suffix="reversal",
            ),
            external_id=tx.external_id,
            description=f"REVERSAL: {reason}",
            currency=tx.currency,
            entries=reversed_entries,
            status=TransactionStatus.DRAFT,
            trace_id=tx.trace_id,
        )
        return reversed_tx

    def _totals(self, entries: Sequence[LedgerEntry]) -> tuple[Decimal, Decimal]:
        debit_total = Decimal("0.00")
        credit_total = Decimal("0.00")
        for e in entries:
            debit_total += e.debit
            credit_total += e.credit
        return (
            debit_total.quantize(Decimal("0.01")),
            credit_total.quantize(Decimal("0.01")),
        )

    def _idempotency_key(self, tx: Transaction) -> str:
        payload = {
            "external_id": tx.external_id,
            "transaction_id": tx.transaction_id,
            "currency": tx.currency.value,
            "entries": [
                {
                    "account_id": e.account_id,
                    "debit": str(e.debit),
                    "credit": str(e.credit),
                }
                for e in tx.entries
            ],
        }
        packed = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        h = hashlib.blake2b(digest_size=16, person=self._salt.encode("utf-8"))
        h.update(packed)
        return "idem:" + h.hexdigest()

    def _derive_transaction_id(self, base_id: str, suffix: str) -> str:
        packed = f"{base_id}:{suffix}".encode("utf-8")
        h = hashlib.blake2b(digest_size=16, person=self._salt.encode("utf-8"))
        h.update(packed)
        return h.hexdigest()


def generate_transaction_id(
    description: str,
    currency: Currency,
    entries: Sequence[LedgerEntry],
    salt: str = "agent_mash:cfo:transactions:v1",
) -> str:
    """
    Детерминированный генератор transaction_id.
    """
    payload = {
        "description": description,
        "currency": currency.value,
        "entries": [
            {
                "account_id": e.account_id,
                "debit": str(e.debit),
                "credit": str(e.credit),
            }
            for e in entries
        ],
    }
    packed = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h = hashlib.blake2b(digest_size=16, person=salt.encode("utf-8"))
    h.update(packed)
    return h.hexdigest()
