# agent_mash/cfo/accounting/assistant/ledger_ops.py

from __future__ import annotations

import datetime as dt
import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, getcontext
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple

getcontext().prec = 28


class LedgerError(RuntimeError):
    pass


class ValidationError(LedgerError, ValueError):
    pass


class InvariantViolation(LedgerError):
    pass


class AccountType(str, Enum):
    asset = "asset"
    liability = "liability"
    equity = "equity"
    income = "income"
    expense = "expense"


class EntrySide(str, Enum):
    debit = "debit"
    credit = "credit"


@dataclass(frozen=True)
class Account:
    account_id: str
    name: str
    type: AccountType

    def validate(self) -> None:
        if not self.account_id:
            raise ValidationError("account_id is required")
        if not self.name:
            raise ValidationError("account name is required")
        if not isinstance(self.type, AccountType):
            raise ValidationError("invalid account type")


@dataclass(frozen=True)
class LedgerEntry:
    account_id: str
    side: EntrySide
    amount: Decimal

    def validate(self) -> None:
        if not self.account_id:
            raise ValidationError("entry.account_id is required")
        if not isinstance(self.side, EntrySide):
            raise ValidationError("entry.side must be EntrySide")
        if self.amount <= Decimal("0"):
            raise ValidationError("entry.amount must be positive")


@dataclass(frozen=True)
class LedgerTransaction:
    tx_id: str
    timestamp: dt.datetime
    description: str
    entries: Tuple[LedgerEntry, ...]
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        payload = {
            "tx_id": self.tx_id,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "entries": [
                {
                    "account_id": e.account_id,
                    "side": e.side.value,
                    "amount": str(e.amount),
                }
                for e in self.entries
            ],
        }
        raw = json.dumps(payload, sort_keys=True)
        object.__setattr__(
            self,
            "fingerprint",
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        )

    def validate(self) -> None:
        if not self.tx_id:
            raise ValidationError("tx_id is required")
        if self.timestamp.tzinfo is None:
            raise ValidationError("timestamp must be timezone aware")
        if not self.entries:
            raise ValidationError("transaction must contain entries")

        debit = Decimal("0")
        credit = Decimal("0")

        for e in self.entries:
            e.validate()
            if e.side is EntrySide.debit:
                debit += e.amount
            else:
                credit += e.amount

        if debit != credit:
            raise InvariantViolation("debits must equal credits")


class Ledger:
    def __init__(self) -> None:
        self._accounts: Dict[str, Account] = {}
        self._balances: Dict[str, Decimal] = {}
        self._transactions: Dict[str, LedgerTransaction] = {}
        self._lock = threading.RLock()

    def add_account(self, account: Account) -> None:
        account.validate()
        with self._lock:
            if account.account_id in self._accounts:
                raise ValidationError("account already exists")
            self._accounts[account.account_id] = account
            self._balances[account.account_id] = Decimal("0")

    def post_transaction(self, tx: LedgerTransaction) -> None:
        tx.validate()
        with self._lock:
            if tx.fingerprint in self._transactions:
                return

            for entry in tx.entries:
                if entry.account_id not in self._accounts:
                    raise ValidationError("unknown account in entry")

            for entry in tx.entries:
                sign = Decimal("1")
                account = self._accounts[entry.account_id]

                if entry.side is EntrySide.credit:
                    sign = Decimal("-1")

                if account.type in (AccountType.liability, AccountType.equity, AccountType.income):
                    sign *= Decimal("-1")

                self._balances[entry.account_id] += sign * entry.amount

            self._transactions[tx.fingerprint] = tx

    def balance(self, account_id: str) -> Decimal:
        with self._lock:
            if account_id not in self._balances:
                raise ValidationError("unknown account")
            return self._balances[account_id]

    def trial_balance(self) -> Dict[str, Decimal]:
        with self._lock:
            return dict(self._balances)

    def audit_log(self) -> List[LedgerTransaction]:
        with self._lock:
            return list(self._transactions.values())


def new_transaction(
    description: str,
    entries: Iterable[LedgerEntry],
    timestamp: Optional[dt.datetime] = None,
) -> LedgerTransaction:
    ts = timestamp or dt.datetime.now(tz=dt.timezone.utc)
    return LedgerTransaction(
        tx_id=uuid.uuid4().hex,
        timestamp=ts,
        description=description,
        entries=tuple(entries),
    )
