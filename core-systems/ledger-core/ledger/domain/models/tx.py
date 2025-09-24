# ledger-core/ledger/domain/models/tx.py
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN, getcontext
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field, ValidationError, computed_field, field_validator, model_validator

# Жёсткая точность Decimal для денег (достаточно для precision=20, scale<=9)
getcontext().prec = 28
getcontext().rounding = ROUND_HALF_EVEN


# ================
# Базовые типы
# ================

class Currency(str, Enum):
    USD = "USD"
    EUR = "EUR"
    SEK = "SEK"
    GBP = "GBP"
    JPY = "JPY"

# ISO 4217 scale (minor units)
_CURRENCY_SCALE: Mapping[str, int] = {
    "USD": 2, "EUR": 2, "SEK": 2, "GBP": 2, "JPY": 0
}

class EntryDirection(str, Enum):
    DEBIT = "debit"
    CREDIT = "credit"


def _scale_for(cur: str) -> int:
    try:
        return _CURRENCY_SCALE[cur]
    except KeyError:
        raise ValueError(f"unsupported currency: {cur}")


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware and in UTC")
    if dt.tzinfo != timezone.utc:
        return dt.astimezone(timezone.utc)
    return dt


def _quantize(amount: Decimal, scale: int) -> Decimal:
    q = Decimal(10) ** -scale
    return amount.quantize(q, rounding=ROUND_HALF_EVEN)


class Money(BaseModel):
    """Денежное значение с безопасной арифметикой и min/max проверками."""
    model_config = ConfigDict(frozen=True)

    amount: Decimal
    currency: Currency

    @field_validator("amount")
    @classmethod
    def _validate_amount(cls, v: Decimal) -> Decimal:
        if not isinstance(v, Decimal):
            v = Decimal(v)
        return v

    @computed_field  # type: ignore[misc]
    @property
    def scale(self) -> int:
        return _scale_for(self.currency.value)

    @computed_field  # type: ignore[misc]
    @property
    def amount_q(self) -> Decimal:
        return _quantize(self.amount, self.scale)

    @computed_field  # type: ignore[misc]
    @property
    def minor(self) -> int:
        """Возвращает целые минорные единицы (например, центы)."""
        return int(self.amount_q * (10 ** self.scale))

    @classmethod
    def from_minor(cls, minor: int, currency: Currency) -> "Money":
        scale = _scale_for(currency.value)
        amt = Decimal(minor) / (10 ** scale)
        return cls(amount=_quantize(amt, scale), currency=currency)

    def __add__(self, other: "Money") -> "Money":
        if self.currency != other.currency:
            raise ValueError("currency mismatch in Money addition")
        return Money(amount=_quantize(self.amount_q + other.amount_q, self.scale), currency=self.currency)

    def __sub__(self, other: "Money") -> "Money":
        if self.currency != other.currency:
            raise ValueError("currency mismatch in Money subtraction")
        return Money(amount=_quantize(self.amount_q - other.amount_q, self.scale), currency=self.currency)


class AccountRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    account_id: str = Field(min_length=1)


class TransactionEntry(BaseModel):
    """Одна проводка (нога двойной записи)."""
    model_config = ConfigDict(frozen=True)

    account: AccountRef
    direction: EntryDirection
    # Сумма хранится в минорных единицах, чтобы исключить ошибку округления;
    # при необходимости используем Money для человекочитаемости.
    amount_minor: int = Field(gt=0, description="Positive minor units")
    currency: Currency

    @computed_field  # type: ignore[misc]
    @property
    def money(self) -> Money:
        return Money.from_minor(self.amount_minor, self.currency)


class TxType(str, Enum):
    PAYMENT = "payment"
    REFUND = "refund"
    TRANSFER = "transfer"
    FEE = "fee"
    ADJUSTMENT = "adjustment"


class PostedTransaction(BaseModel):
    """
    Доменная транзакция с двойной записью.
    Инварианты:
      - все записи одной валюты
      - суммы > 0
      - сумма дебетов == сумма кредитов
      - posted_at в UTC (aware)
    """
    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    transaction_id: str = Field(min_length=1)
    tx_type: TxType
    posted_at: datetime
    currency: Currency
    entries: List[TransactionEntry]
    attributes: Dict[str, str] = Field(default_factory=dict)

    # -------- валидаторы --------

    @field_validator("posted_at")
    @classmethod
    def _utc_only(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    @model_validator(mode="after")
    def _check_invariants(self) -> "PostedTransaction":
        if not self.entries or len(self.entries) < 2:
            raise ValueError("entries must contain at least two legs")

        # Единая валюта
        for e in self.entries:
            if e.currency != self.currency:
                raise ValueError("entry currency mismatch with transaction currency")

        # Положительные числа уже гарантируются Field(gt=0)

        # Баланс
        if self.total_debit_minor != self.total_credit_minor:
            raise ValueError("double-entry imbalance: debit != credit")

        # Согласованная сумма транзакции как абсолют дебета (или кредита)
        if self.total_minor <= 0:
            raise ValueError("total amount must be positive")

        return self

    # -------- агрегаты/сервисы --------

    @computed_field  # type: ignore[misc]
    @property
    def total_debit_minor(self) -> int:
        return sum(e.amount_minor for e in self.entries if e.direction == EntryDirection.DEBIT)

    @computed_field  # type: ignore[misc]
    @property
    def total_credit_minor(self) -> int:
        return sum(e.amount_minor for e in self.entries if e.direction == EntryDirection.CREDIT)

    @computed_field  # type: ignore[misc]
    @property
    def total_minor(self) -> int:
        # В условиях баланса дебет == кредит
        return self.total_debit_minor

    @computed_field  # type: ignore[misc]
    @property
    def total_money(self) -> Money:
        return Money.from_minor(self.total_minor, self.currency)

    @computed_field  # type: ignore[misc]
    @property
    def idempotency_key(self) -> str:
        """
        Детеминированный ключ идемпотентности из (transaction_id, posted_at, сумм и ног).
        Изменения состава ног дают новый ключ.
        """
        h = hashlib.sha256()
        h.update(self.transaction_id.encode("utf-8"))
        h.update(str(int(self.posted_at.timestamp() * 1000)).encode("ascii"))
        h.update(self.currency.value.encode("ascii"))
        for e in self.entries:
            h.update(b"|")
            h.update(e.account.account_id.encode("utf-8"))
            h.update(e.direction.value.encode("ascii"))
            h.update(str(e.amount_minor).encode("ascii"))
        return h.hexdigest()

    # -------- фабрики --------

    @classmethod
    def transfer(cls, *, transaction_id: str, posted_at: datetime, currency: Currency,
                 from_account: str, to_account: str, amount_minor: int,
                 attributes: Optional[Dict[str, str]] = None) -> "PostedTransaction":
        """
        Удобный конструктор P2P перевода (дебет получателя, кредит отправителя).
        """
        entries = [
            TransactionEntry(account=AccountRef(account_id=to_account),
                             direction=EntryDirection.DEBIT,
                             amount_minor=amount_minor, currency=currency),
            TransactionEntry(account=AccountRef(account_id=from_account),
                             direction=EntryDirection.CREDIT,
                             amount_minor=amount_minor, currency=currency),
        ]
        return cls(
            transaction_id=transaction_id,
            tx_type=TxType.TRANSFER,
            posted_at=_ensure_utc(posted_at),
            currency=currency,
            entries=entries,
            attributes=attributes or {},
        )

    # -------- интеграция с событиями Avro --------

    def to_avro_transaction_posted(self) -> Dict[str, Any]:
        """
        Формирует payload ветки TransactionPosted из событийной схемы ledger.core.v1.LedgerEvent.
        Совместимо с events.avsc (precision=20, scale=2).
        """
        # bytes(decimal) для Avro: масштаб по currency scale
        scale = _scale_for(self.currency.value)
        total_bytes = _decimal_to_avro_bytes(self.total_money.amount_q, scale=scale)

        entries = []
        for e in self.entries:
            amount_bytes = _decimal_to_avro_bytes(e.money.amount_q, scale=scale)
            entries.append({
                "account_id": e.account.account_id,
                "direction": e.direction.value,
                "amount": amount_bytes,
                "currency": e.currency.value,
                "metadata": None,
            })

        return {
            "transaction_id": self.transaction_id,
            "posted_at": int(self.posted_at.timestamp() * 1000),
            "currency": self.currency.value,
            "amount": total_bytes,
            "entries": entries,
            "attributes": self.attributes or None,
        }

    @classmethod
    def from_avro_transaction_posted(cls, payload: Mapping[str, Any]) -> "PostedTransaction":
        """
        Обратное преобразование из ветки TransactionPosted (dict после Avro decode).
        """
        currency = Currency(payload["currency"])
        scale = _scale_for(currency.value)
        # 'amount' игнорируем как производное; используем ноги
        entries = []
        for item in payload["entries"]:
            ecur = Currency(item["currency"])
            if ecur != currency:
                raise ValueError("entry currency mismatch in Avro payload")
            amt = _avro_bytes_to_decimal(item["amount"], scale=scale)
            minor = int(_quantize(amt, scale) * (10 ** scale))
            entries.append(
                TransactionEntry(
                    account=AccountRef(account_id=item["account_id"]),
                    direction=EntryDirection(item["direction"]),
                    amount_minor=minor,
                    currency=ecur,
                )
            )

        return cls(
            transaction_id=str(payload["transaction_id"]),
            tx_type=TxType.PAYMENT if payload.get("attributes", {}).get("tx_type") == "payment" else TxType.TRANSFER,
            posted_at=_ms_to_utc(payload["posted_at"]),
            currency=currency,
            entries=entries,
            attributes=dict(payload.get("attributes") or {})  # допускаем None
        )

    # -------- интеграция с внешней политикой валидации (OPA и пр.) --------

    def assert_policy_passed(self, policy_result: Mapping[str, Any]) -> None:
        """
        Применяет результат внешней политики (например, OPA Rego).
        Ожидается структура:
            {"allow": bool, "deny": [str,...], "risk": { "score": int, "reasons": [...] }}
        """
        allow = bool(policy_result.get("allow", False))
        denials = list(policy_result.get("deny") or [])
        if not allow or denials:
            raise ValueError(f"policy denied transaction: reasons={denials}")


# ================
# Вспомогательные функции
# ================

def _decimal_to_avro_bytes(value: Decimal, *, scale: int) -> bytes:
    """
    codahale/avro decimal encoding: signed unscaled integer big-endian two's-complement.
    precision контролируется уровнем выше (у нас scale берётся из валюты).
    """
    # Нормализуем под требуемый масштаб
    q = Decimal(10) ** -scale
    qv = value.quantize(q, rounding=ROUND_HALF_EVEN)
    unscaled = int(qv * (10 ** scale))
    # Преобразуем в twos-complement big-endian (минимум 1 байт)
    if unscaled == 0:
        return b"\x00"
    n = (unscaled.bit_length() + 8) // 8
    raw = unscaled.to_bytes(n, byteorder="big", signed=True)
    # Удаляем лишний знак, если возможно (Avro допускает минимальное представление)
    if (unscaled > 0 and raw[0] == 0x00 and (raw[1] & 0x80) == 0) or (unscaled < 0 and raw[0] == 0xFF and (raw[1] & 0x80) == 0x80):
        raw = raw[1:]
    return raw


def _avro_bytes_to_decimal(data: bytes, *, scale: int) -> Decimal:
    if not data:
        return Decimal(0)
    unscaled = int.from_bytes(data, byteorder="big", signed=True)
    return Decimal(unscaled) / (10 ** scale)


def _ms_to_utc(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
