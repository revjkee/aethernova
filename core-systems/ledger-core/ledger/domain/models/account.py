# ledger-core/ledger/domain/models/account.py
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN, getcontext
from typing import Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

# Финансовая точность: достаточно 34 значащих цифр (DEC128)
getcontext().prec = 34
getcontext().rounding = ROUND_HALF_EVEN


# =========================
# Исключения домена
# =========================

class DomainError(Exception):
    """Базовое доменное исключение."""


class ValidationDomainError(DomainError):
    pass


class AccountClosedError(DomainError):
    pass


class OverdraftNotAllowedError(DomainError):
    pass


class CurrencyMismatchError(DomainError):
    pass


class DuplicatePostingError(DomainError):
    pass


class InsufficientFundsError(DomainError):
    pass


class VersionConflictError(DomainError):
    pass


# =========================
# Вспомогательные типы
# =========================

# Нормализуем масштаб по ISO 4217 (расширяйте по мере необходимости)
_CURRENCY_SCALE: Dict[str, int] = {
    "USD": 2,
    "EUR": 2,
    "GBP": 2,
    "SEK": 2,
    "JPY": 0,
    "CHF": 2,
    "AUD": 2,
    "CAD": 2,
    "NOK": 2,
    "DKK": 2,
}

def _scale_for(currency: str) -> int:
    return _CURRENCY_SCALE.get(currency.upper(), 2)


def _quantize(amount: Decimal, currency: str) -> Decimal:
    exp = Decimal(10) ** -_scale_for(currency)
    return amount.quantize(exp, rounding=ROUND_HALF_EVEN)


class Money(BaseModel):
    """Денежная величина с валютной квантизацией."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    amount: Decimal = Field(..., description="Значение как Decimal")
    currency: str = Field(..., min_length=3, max_length=3, description="ISO 4217")

    @field_validator("currency")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @field_validator("amount")
    @classmethod
    def _coerce_decimal(cls, v: Decimal) -> Decimal:
        if not isinstance(v, Decimal):
            v = Decimal(str(v))
        return v

    def quantized(self) -> "Money":
        return Money(amount=_quantize(self.amount, self.currency), currency=self.currency)

    def __add__(self, other: "Money") -> "Money":
        if self.currency != other.currency:
            raise CurrencyMismatchError("money currency mismatch on add")
        return Money(amount=_quantize(self.amount + other.amount, self.currency), currency=self.currency)

    def __sub__(self, other: "Money") -> "Money":
        if self.currency != other.currency:
            raise CurrencyMismatchError("money currency mismatch on sub")
        return Money(amount=_quantize(self.amount - other.amount, self.currency), currency=self.currency)

    def negate(self) -> "Money":
        return Money(amount=_quantize(-self.amount, self.currency), currency=self.currency)

    def is_negative(self) -> bool:
        return self.amount < 0

    def is_zero_or_positive(self) -> bool:
        return self.amount >= 0


class PostingDirection(str, enum.Enum):
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


class AccountStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class AccountType(str, enum.Enum):
    ASSET = "ASSET"
    LIABILITY = "LIABILITY"
    EQUITY = "EQUITY"
    INCOME = "INCOME"
    EXPENSE = "EXPENSE"


class Posting(BaseModel):
    """Бухгалтерская проводка на счете (односторонняя часть двойной записи)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    posting_id: str = Field(..., min_length=16, max_length=64)
    direction: PostingDirection
    amount: Money
    effective_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Для идемпотентности/повторов — ключ операции (например, из внешнего API)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
    # Метки/атрибуты для аудита
    attributes: Dict[str, str] = Field(default_factory=dict)

    @field_validator("posting_id")
    @classmethod
    def _normalize_id(cls, v: str) -> str:
        return v.strip()


class Hold(BaseModel):
    """Резерв средств (например, для платежа)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    hold_id: str = Field(..., min_length=16, max_length=64)
    amount: Money
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


# =========================
# Доменные события (immutable)
# =========================

@dataclass(frozen=True)
class AccountCreated:
    account_id: str
    occurred_at: datetime
    currency: str
    type: AccountType
    name: str
    allow_overdraft: bool
    overdraft_limit: Decimal


@dataclass(frozen=True)
class AccountCredited:
    account_id: str
    occurred_at: datetime
    posting_id: str
    amount: Money
    balance_after: Money


@dataclass(frozen=True)
class AccountDebited:
    account_id: str
    occurred_at: datetime
    posting_id: str
    amount: Money
    balance_after: Money


@dataclass(frozen=True)
class HoldPlaced:
    account_id: str
    occurred_at: datetime
    hold_id: str
    amount: Money
    available_after: Money


@dataclass(frozen=True)
class HoldReleased:
    account_id: str
    occurred_at: datetime
    hold_id: str
    amount: Money
    available_after: Money


@dataclass(frozen=True)
class AccountClosed:
    account_id: str
    occurred_at: datetime


# =========================
# Агрегат Account
# =========================

class Account(BaseModel):
    """
    Агрегат счета (aggregate root).
    Инварианты:
      - balance.amount квантован по валюте
      - available = balance - sum(holds), если овердрафт запрещен: available >= -overdraft_limit
      - при CLOSED: операции запрещены
      - идемпотентность по posting_id
    """
    model_config = ConfigDict(extra="forbid")

    account_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str = Field(..., min_length=1, max_length=200)
    type: AccountType
    currency: str = Field(..., min_length=3, max_length=3)
    status: AccountStatus = AccountStatus.ACTIVE

    balance: Money
    # Резервы (holds) — по hold_id
    _holds: Dict[str, Hold] = Field(default_factory=dict, alias="holds")
    # Идемпотентность постингов
    _postings_seen: Dict[str, datetime] = Field(default_factory=dict, alias="postings_seen")

    # Политики
    allow_overdraft: bool = False
    overdraft_limit: Decimal = Decimal("0")  # положительное число обозначает допустимую глубину

    # OCC: версия и метка времени
    version: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # События, накопленные с момента загрузки агрегата (для outbox/CQRS)
    _pending_events: List[object] = Field(default_factory=list, exclude=True)

    @field_validator("currency")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @field_validator("overdraft_limit")
    @classmethod
    def _limit_nonnegative(cls, v: Decimal) -> Decimal:
        if v < 0:
            raise ValidationDomainError("overdraft_limit must be non-negative")
        return v

    @classmethod
    def new(
        cls,
        *,
        name: str,
        type: AccountType,
        currency: str,
        allow_overdraft: bool = False,
        overdraft_limit: Decimal = Decimal("0"),
    ) -> "Account":
        currency = currency.upper()
        acc = cls(
            name=name,
            type=type,
            currency=currency,
            balance=Money(amount=Decimal("0"), currency=currency).quantized(),
            allow_overdraft=allow_overdraft,
            overdraft_limit=overdraft_limit,
        )
        acc._raise(AccountCreated(
            account_id=acc.account_id,
            occurred_at=acc.created_at,
            currency=currency,
            type=type,
            name=name,
            allow_overdraft=allow_overdraft,
            overdraft_limit=_quantize(overdraft_limit, currency),
        ))
        return acc

    # ------------- Доступные вычисления -------------

    @property
    def holds(self) -> Tuple[Hold, ...]:
        return tuple(self._holds.values())

    @property
    def postings_seen(self) -> Tuple[str, ...]:
        return tuple(self._postings_seen.keys())

    def total_holds(self) -> Money:
        total = Decimal("0")
        for h in self._holds.values():
            total += h.amount.amount
        return Money(amount=_quantize(total, self.currency), currency=self.currency)

    def available(self) -> Money:
        avail = self.balance.amount - self.total_holds().amount
        return Money(amount=_quantize(avail, self.currency), currency=self.currency)

    # ------------- Операции -------------

    def credit(self, posting: Posting, *, expected_version: Optional[int] = None) -> None:
        """Зачислить средства (увеличить баланс)."""
        self._precheck_mutation(posting, expected_version)
        if posting.amount.currency != self.currency:
            raise CurrencyMismatchError("posting currency mismatch")

        new_balance = self.balance + posting.amount
        self._apply_new_balance(new_balance)
        self._postings_seen[posting.posting_id] = posting.effective_at
        self._raise(AccountCredited(
            account_id=self.account_id,
            occurred_at=posting.effective_at,
            posting_id=posting.posting_id,
            amount=posting.amount,
            balance_after=self.balance,
        ))

    def debit(self, posting: Posting, *, expected_version: Optional[int] = None) -> None:
        """Списать средства (уменьшить баланс)."""
        self._precheck_mutation(posting, expected_version)
        if posting.amount.currency != self.currency:
            raise CurrencyMismatchError("posting currency mismatch")

        new_balance = self.balance - posting.amount
        # Проверка овердрафта с учетом резервов
        projected_available = new_balance.amount - self.total_holds().amount
        min_allowed = Decimal("0") - (self.overdraft_limit if self.allow_overdraft else Decimal("0"))
        if projected_available < min_allowed:
            raise InsufficientFundsError("insufficient funds (available would breach overdraft policy)")

        self._apply_new_balance(new_balance)
        self._postings_seen[posting.posting_id] = posting.effective_at
        self._raise(AccountDebited(
            account_id=self.account_id,
            occurred_at=posting.effective_at,
            posting_id=posting.posting_id,
            amount=posting.amount,
            balance_after=self.balance,
        ))

    def place_hold(self, hold: Hold, *, expected_version: Optional[int] = None) -> None:
        """Поставить резерв на средства (уменьшает доступный остаток, не меняя баланс)."""
        self._ensure_active()
        self._check_version(expected_version)
        if hold.amount.currency != self.currency:
            raise CurrencyMismatchError("hold currency mismatch")
        if hold.hold_id in self._holds:
            # идемпотентность
            return
        # Проверка на доступность
        projected_available = self.available().amount - hold.amount.amount
        min_allowed = Decimal("0") - (self.overdraft_limit if self.allow_overdraft else Decimal("0"))
        if projected_available < min_allowed:
            raise InsufficientFundsError("insufficient funds for hold")

        self._holds[hold.hold_id] = Hold(
            hold_id=hold.hold_id,
            amount=hold.amount.quantized(),
            created_at=hold.created_at,
            expires_at=hold.expires_at,
        )
        self._touch()
        self._raise(HoldPlaced(
            account_id=self.account_id,
            occurred_at=self.updated_at,
            hold_id=hold.hold_id,
            amount=hold.amount.quantized(),
            available_after=self.available(),
        ))

    def release_hold(self, hold_id: str, *, expected_version: Optional[int] = None) -> None:
        """Снять резерв (полностью)."""
        self._ensure_active()
        self._check_version(expected_version)
        hold = self._holds.pop(hold_id, None)
        if not hold:
            # идемпотентность — нет эффекта
            return
        self._touch()
        self._raise(HoldReleased(
            account_id=self.account_id,
            occurred_at=self.updated_at,
            hold_id=hold.hold_id,
            amount=hold.amount,
            available_after=self.available(),
        ))

    def close(self, *, expected_version: Optional[int] = None) -> None:
        """Закрыть счет. Позволено только при отсутствии активных резервов."""
        self._ensure_active(allow_suspended=True)
        self._check_version(expected_version)
        if self._holds:
            raise ValidationDomainError("cannot close account with active holds")
        self.status = AccountStatus.CLOSED
        self._touch()
        self._raise(AccountClosed(account_id=self.account_id, occurred_at=self.updated_at))

    # ------------- Вспомогательные -------------

    def _precheck_mutation(self, posting: Posting, expected_version: Optional[int]) -> None:
        self._ensure_active()
        self._check_version(expected_version)
        # Идемпотентность по posting_id
        if posting.posting_id in self._postings_seen:
            # нет эффекта
            raise DuplicatePostingError(f"posting {posting.posting_id} already applied")

    def _apply_new_balance(self, new_balance: Money) -> None:
        self.balance = Money(amount=_quantize(new_balance.amount, self.currency), currency=self.currency)
        self._touch()

    def _touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)
        self.version += 1

    def _ensure_active(self, *, allow_suspended: bool = False) -> None:
        if self.status == AccountStatus.CLOSED or self.status == AccountStatus.ARCHIVED:
            raise AccountClosedError("account is closed")
        if not allow_suspended and self.status == AccountStatus.SUSPENDED:
            raise ValidationDomainError("account is suspended")

    def _check_version(self, expected_version: Optional[int]) -> None:
        if expected_version is not None and expected_version != self.version:
            raise VersionConflictError(f"version mismatch: expected {expected_version}, actual {self.version}")

    def _raise(self, event: object) -> None:
        self._pending_events.append(event)

    # ------------- События/сериализация -------------

    def pull_events(self) -> Tuple[object, ...]:
        """Выдать и очистить накопленные события (для outbox)."""
        out = tuple(self._pending_events)
        self._pending_events.clear()
        return out

    def to_snapshot(self) -> Dict[str, object]:
        """Снапшот состояния (для сохранения агрегата как документа)."""
        return {
            "account_id": self.account_id,
            "name": self.name,
            "type": self.type.value,
            "currency": self.currency,
            "status": self.status.value,
            "balance": {"amount": str(self.balance.amount), "currency": self.currency},
            "holds": [
                {
                    "hold_id": h.hold_id,
                    "amount": {"amount": str(h.amount.amount), "currency": h.amount.currency},
                    "created_at": h.created_at.isoformat(),
                    "expires_at": h.expires_at.isoformat() if h.expires_at else None,
                }
                for h in self._holds.values()
            ],
            "postings_seen": list(self._postings_seen.keys()),
            "allow_overdraft": self.allow_overdraft,
            "overdraft_limit": str(self.overdraft_limit),
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_snapshot(cls, data: Dict[str, object]) -> "Account":
        """Восстановить агрегат из снапшота (обход репозитория)."""
        try:
            currency = str(data["currency"])
            holds_arr = data.get("holds", []) or []
            holds_map: Dict[str, Hold] = {}
            for row in holds_arr:  # type: ignore[assignment]
                amt = Money(amount=Decimal(str(row["amount"]["amount"])), currency=str(row["amount"]["currency"])).quantized()
                holds_map[str(row["hold_id"])] = Hold(
                    hold_id=str(row["hold_id"]),
                    amount=amt,
                    created_at=datetime.fromisoformat(str(row["created_at"])),
                    expires_at=datetime.fromisoformat(str(row["expires_at"])) if row.get("expires_at") else None,
                )
            acc = cls(
                account_id=str(data["account_id"]),
                name=str(data["name"]),
                type=AccountType(str(data["type"])),
                currency=currency,
                status=AccountStatus(str(data["status"])),
                balance=Money(amount=Decimal(str(data["balance"]["amount"])), currency=currency).quantized(),  # type: ignore[index]
                holds=holds_map,
                postings_seen={pid: datetime.now(timezone.utc) for pid in data.get("postings_seen", [])},  # type: ignore[arg-type]
                allow_overdraft=bool(data.get("allow_overdraft", False)),
                overdraft_limit=Decimal(str(data.get("overdraft_limit", "0"))),
                version=int(data.get("version", 0)),
                created_at=datetime.fromisoformat(str(data["created_at"])),
                updated_at=datetime.fromisoformat(str(data["updated_at"])),
            )
            return acc
        except Exception as e:
            raise ValidationDomainError(f"invalid snapshot: {e}") from e

    # ------------- Инструменты для тестов -------------

    @staticmethod
    def posting(
        *,
        amount: str | Decimal,
        currency: str,
        direction: PostingDirection,
        posting_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Posting:
        amt = Money(amount=Decimal(str(amount)), currency=currency).quantized()
        return Posting(
            posting_id=posting_id or uuid.uuid4().hex,
            direction=direction,
            amount=amt,
            idempotency_key=idempotency_key,
        )
