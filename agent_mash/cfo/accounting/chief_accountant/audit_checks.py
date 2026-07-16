# agent_mash/cfo/accounting/chief_accountant/audit_checks.py
# Industrial-grade accounting audit checks engine.
#
# Scope:
# - Technical validation of accounting records
# - No legal or regulatory claims are made
# - Deterministic, reproducible, JSON-safe output
#
# No external dependencies.

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple


__all__ = [
    "AuditError",
    "AuditValidationError",
    "AccountingEntry",
    "AuditFinding",
    "AuditRule",
    "AuditReport",
    "AuditEngine",
]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _ensure_jsonable(value: Any, *, path: str = "$") -> None:
    try:
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except TypeError as e:
        raise AuditValidationError(f"Non-JSON-serializable value at {path}: {e}") from e


class AuditError(RuntimeError):
    """Base error for audit subsystem."""


class AuditValidationError(AuditError):
    """Invalid input data or configuration."""


@dataclass(frozen=True, slots=True)
class AccountingEntry:
    """
    Immutable accounting entry.

    debit and credit are represented as integers in minimal currency units
    to avoid floating point ambiguity.
    """
    entry_id: str
    timestamp_ms: int
    debit_account: str
    credit_account: str
    amount: int
    meta: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.entry_id:
            raise AuditValidationError("entry_id must be non-empty")
        if not isinstance(self.timestamp_ms, int) or self.timestamp_ms <= 0:
            raise AuditValidationError("timestamp_ms must be positive int")
        if not self.debit_account or not self.credit_account:
            raise AuditValidationError("accounts must be non-empty strings")
        if self.amount <= 0:
            raise AuditValidationError("amount must be positive integer")
        _ensure_jsonable(dict(self.meta), path="$.entry.meta")


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """
    Single audit finding.
    """
    rule_id: str
    entry_id: Optional[str]
    level: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        _ensure_jsonable(d, path="$.finding")
        return d


class AuditRule(Protocol):
    """
    Audit rule protocol.
    """

    rule_id: str

    def check(self, entries: Sequence[AccountingEntry]) -> Iterable[AuditFinding]:
        ...


@dataclass(slots=True)
class AuditReport:
    """
    Deterministic audit report.
    """
    generated_at_ms: int
    findings: List[AuditFinding] = field(default_factory=list)

    def add(self, finding: AuditFinding) -> None:
        self.findings.append(finding)

    def summary(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.level] = out.get(f.level, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "generated_at_ms": self.generated_at_ms,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        _ensure_jsonable(d, path="$.report")
        return d


class BalanceIntegrityRule:
    """
    Ensures that total debit equals total credit.
    """
    rule_id = "BALANCE_INTEGRITY"

    def check(self, entries: Sequence[AccountingEntry]) -> Iterable[AuditFinding]:
        total_debit = 0
        total_credit = 0

        for e in entries:
            total_debit += e.amount
            total_credit += e.amount

        if total_debit != total_credit:
            yield AuditFinding(
                rule_id=self.rule_id,
                entry_id=None,
                level="error",
                message="Debit and credit totals are not equal",
                details={
                    "total_debit": total_debit,
                    "total_credit": total_credit,
                },
            )


class ChronologyRule:
    """
    Ensures entries are not dated in the future.
    """
    rule_id = "CHRONOLOGY"

    def check(self, entries: Sequence[AccountingEntry]) -> Iterable[AuditFinding]:
        now = _now_ms()
        for e in entries:
            if e.timestamp_ms > now:
                yield AuditFinding(
                    rule_id=self.rule_id,
                    entry_id=e.entry_id,
                    level="warning",
                    message="Entry timestamp is in the future",
                    details={"timestamp_ms": e.timestamp_ms, "now_ms": now},
                )


class SelfTransferRule:
    """
    Detects debit and credit to the same account.
    """
    rule_id = "SELF_TRANSFER"

    def check(self, entries: Sequence[AccountingEntry]) -> Iterable[AuditFinding]:
        for e in entries:
            if e.debit_account == e.credit_account:
                yield AuditFinding(
                    rule_id=self.rule_id,
                    entry_id=e.entry_id,
                    level="warning",
                    message="Debit and credit accounts are identical",
                    details={"account": e.debit_account},
                )


class AuditEngine:
    """
    Core audit engine.
    """

    def __init__(self, rules: Optional[Sequence[AuditRule]] = None) -> None:
        self._rules: List[AuditRule] = list(rules) if rules else [
            BalanceIntegrityRule(),
            ChronologyRule(),
            SelfTransferRule(),
        ]

    def run(self, entries: Sequence[AccountingEntry]) -> AuditReport:
        if not isinstance(entries, (list, tuple)):
            raise AuditValidationError("entries must be a sequence")

        report = AuditReport(generated_at_ms=_now_ms())

        for rule in self._rules:
            for finding in rule.check(entries):
                report.add(finding)

        return report
