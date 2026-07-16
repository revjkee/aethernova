# agent_mash/cfo/accounting/chief_accountant/agent.py
from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Optional

from agent_mash.pmo.agent import (
    BacklogItem,
    PMOAgent,
    PMOConfig,
    WorkClass,
)
from agent_mash.core.routing import DispatchResult, DispatchStatus

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AccountingError(RuntimeError):
    pass


class ValidationError(AccountingError):
    pass


class LedgerInvariantError(AccountingError):
    pass


class EntryType(str, Enum):
    DEBIT = "debit"
    CREDIT = "credit"


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    account: str
    entry_type: EntryType
    amount: float
    currency: str


@dataclass(frozen=True, slots=True)
class AccountingOperation:
    """
    Финансовая операция на уровне Chief Accountant.
    Не привязана к конкретной реализации БД или ERP.
    """

    operation_id: str
    description: str
    entries: list[LedgerEntry]
    occurred_at: datetime
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AccountingPolicy:
    """
    Политики бухгалтерского контроля.
    """

    allowed_currencies: set[str]
    max_amount: float

    def validate(self, op: AccountingOperation) -> None:
        if not op.entries:
            raise ValidationError("AccountingOperation.entries must not be empty")

        debit_sum = 0.0
        credit_sum = 0.0

        for e in op.entries:
            if e.amount <= 0:
                raise ValidationError("LedgerEntry.amount must be positive")
            if e.amount > self.max_amount:
                raise ValidationError("LedgerEntry.amount exceeds max_amount")
            if e.currency not in self.allowed_currencies:
                raise ValidationError(f"Currency not allowed: {e.currency}")

            if e.entry_type == EntryType.DEBIT:
                debit_sum += e.amount
            elif e.entry_type == EntryType.CREDIT:
                credit_sum += e.amount

        if round(debit_sum, 2) != round(credit_sum, 2):
            raise LedgerInvariantError(
                f"Unbalanced ledger: debit={debit_sum} credit={credit_sum}"
            )


@dataclass(frozen=True, slots=True)
class AccountingJournalRecord:
    operation_id: str
    posted_at: datetime
    debit_total: float
    credit_total: float
    currency_set: set[str]
    metadata: dict[str, Any]


class ChiefAccountantAgent:
    """
    Chief Accountant Agent.
    Ответственность:
    - Валидация бухгалтерских операций
    - Контроль инварианта двойной записи
    - Формирование журналов
    - Эскалация задач в workforce через PMO
    """

    def __init__(
        self,
        *,
        pmo: PMOAgent,
        policy: AccountingPolicy,
        pmo_config: Optional[PMOConfig] = None,
    ) -> None:
        self._pmo = pmo
        self._policy = policy
        self._pmo_cfg = pmo_config or PMOConfig(source="cfo.chief_accountant")

    def process_operations(
        self, operations: Iterable[AccountingOperation]
    ) -> list[AccountingJournalRecord]:
        records: list[AccountingJournalRecord] = []

        for op in operations:
            self._policy.validate(op)
            record = self._post_to_journal(op)
            records.append(record)

        return records

    def escalate_operations(
        self, operations: Iterable[AccountingOperation]
    ) -> DispatchResult:
        """
        Передача бухгалтерских операций в workforce
        для дальнейшей обработки, отчётности или хранения.
        """

        backlog: list[BacklogItem] = []

        for op in operations:
            self._policy.validate(op)

            payload = {
                "operation_id": op.operation_id,
                "description": op.description,
                "occurred_at": op.occurred_at.isoformat(),
                "entries": [
                    dataclasses.asdict(e) for e in op.entries
                ],
                "metadata": dict(op.metadata),
            }

            backlog.append(
                BacklogItem(
                    kind="accounting.posting",
                    payload=payload,
                    work_class=WorkClass.HIGH,
                    tenant_id=op.metadata.get("tenant_id"),
                    correlation_id=op.operation_id,
                    dedupe_parts={"operation_id": op.operation_id},
                )
            )

        report = self._pmo.plan_and_execute_sync(backlog)

        if report.stats.failed > 0 or report.stats.rejected > 0:
            return DispatchResult(
                status=DispatchStatus.FAILED,
                message="Some accounting operations failed during escalation",
                output={
                    "failed": report.stats.failed,
                    "rejected": report.stats.rejected,
                },
            )

        return DispatchResult(
            status=DispatchStatus.SUCCEEDED,
            message="All accounting operations escalated successfully",
            output={
                "total": len(backlog),
                "accepted": report.stats.accepted,
            },
        )

    def _post_to_journal(
        self, op: AccountingOperation
    ) -> AccountingJournalRecord:
        debit_total = sum(
            e.amount for e in op.entries if e.entry_type == EntryType.DEBIT
        )
        credit_total = sum(
            e.amount for e in op.entries if e.entry_type == EntryType.CREDIT
        )
        currencies = {e.currency for e in op.entries}

        record = AccountingJournalRecord(
            operation_id=op.operation_id,
            posted_at=utc_now(),
            debit_total=round(debit_total, 2),
            credit_total=round(credit_total, 2),
            currency_set=currencies,
            metadata=dict(op.metadata),
        )

        logger.info(
            "accounting_journal_posted operation_id=%s debit=%s credit=%s currencies=%s",
            record.operation_id,
            record.debit_total,
            record.credit_total,
            ",".join(sorted(record.currency_set)),
        )

        return record
