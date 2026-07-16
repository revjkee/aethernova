# agent_mash/cfo/accounting/chief_accountant/controls.py
from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import threading
import uuid
from typing import Any, Optional, Iterable


class ControlViolation(Exception):
    pass


class AccountingPeriodStatus(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    LOCKED = "locked"


class Role(str, enum.Enum):
    PREPARER = "preparer"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    CHIEF_ACCOUNTANT = "chief_accountant"
    AUDITOR = "auditor"
    SYSTEM = "system"


class JournalSide(str, enum.Enum):
    DEBIT = "debit"
    CREDIT = "credit"


@dataclasses.dataclass(frozen=True)
class Actor:
    id: str
    name: str
    role: Role


@dataclasses.dataclass(frozen=True)
class AccountingPeriod:
    id: str
    year: int
    month: int
    status: AccountingPeriodStatus
    closed_at: Optional[dt.datetime] = None

    def key(self) -> str:
        return f"{self.year:04d}-{self.month:02d}"


@dataclasses.dataclass(frozen=True)
class JournalLine:
    account: str
    side: JournalSide
    amount: float

    def validate(self) -> None:
        if not self.account:
            raise ControlViolation("Account must be defined")
        if self.amount <= 0:
            raise ControlViolation("Amount must be positive")


@dataclasses.dataclass(frozen=True)
class JournalEntry:
    id: str
    period_key: str
    lines: tuple[JournalLine, ...]
    preparer: Actor
    reviewer: Optional[Actor]
    approver: Optional[Actor]
    created_at: dt.datetime
    approved_at: Optional[dt.datetime]

    def validate_balanced(self) -> None:
        debit = sum(l.amount for l in self.lines if l.side == JournalSide.DEBIT)
        credit = sum(l.amount for l in self.lines if l.side == JournalSide.CREDIT)
        if round(debit, 2) != round(credit, 2):
            raise ControlViolation("Journal entry is not balanced")


@dataclasses.dataclass(frozen=True)
class AuditEvent:
    id: str
    ts: dt.datetime
    actor: Actor
    action: str
    object_id: str
    details: dict[str, Any]


class InternalControlSystem:
    """
    Enterprise-grade internal accounting controls:
    - Accounting period governance
    - Double-entry enforcement
    - Segregation of duties
    - Approval workflow
    - Immutable audit trail
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._periods: dict[str, AccountingPeriod] = {}
        self._journals: dict[str, JournalEntry] = {}
        self._audit_log: list[AuditEvent] = []

    # --- Period Controls ---

    def open_period(self, year: int, month: int, *, actor: Actor) -> AccountingPeriod:
        self._require_role(actor, {Role.CHIEF_ACCOUNTANT, Role.SYSTEM})
        key = f"{year:04d}-{month:02d}"
        with self._lock:
            if key in self._periods:
                raise ControlViolation("Period already exists")
            period = AccountingPeriod(
                id=uuid.uuid4().hex,
                year=year,
                month=month,
                status=AccountingPeriodStatus.OPEN,
            )
            self._periods[key] = period
            self._audit(actor, "open_period", period.id, {"period": key})
            return period

    def close_period(self, period_key: str, *, actor: Actor) -> AccountingPeriod:
        self._require_role(actor, {Role.CHIEF_ACCOUNTANT})
        with self._lock:
            period = self._require_period(period_key)
            if period.status != AccountingPeriodStatus.OPEN:
                raise ControlViolation("Only open periods can be closed")
            updated = dataclasses.replace(
                period,
                status=AccountingPeriodStatus.CLOSED,
                closed_at=dt.datetime.now(dt.timezone.utc),
            )
            self._periods[period_key] = updated
            self._audit(actor, "close_period", period.id, {"period": period_key})
            return updated

    # --- Journal Controls ---

    def create_journal(
        self,
        *,
        period_key: str,
        lines: Iterable[JournalLine],
        preparer: Actor,
    ) -> JournalEntry:
        self._require_role(preparer, {Role.PREPARER, Role.CHIEF_ACCOUNTANT})
        with self._lock:
            period = self._require_period(period_key)
            if period.status != AccountingPeriodStatus.OPEN:
                raise ControlViolation("Cannot post to closed period")

            jl = tuple(lines)
            if len(jl) < 2:
                raise ControlViolation("Journal entry must have at least two lines")
            for l in jl:
                l.validate()

            entry = JournalEntry(
                id=uuid.uuid4().hex,
                period_key=period_key,
                lines=jl,
                preparer=preparer,
                reviewer=None,
                approver=None,
                created_at=dt.datetime.now(dt.timezone.utc),
                approved_at=None,
            )
            entry.validate_balanced()
            self._journals[entry.id] = entry
            self._audit(preparer, "create_journal", entry.id, {"period": period_key})
            return entry

    def review_journal(self, journal_id: str, *, reviewer: Actor) -> JournalEntry:
        self._require_role(reviewer, {Role.REVIEWER, Role.CHIEF_ACCOUNTANT})
        with self._lock:
            entry = self._require_journal(journal_id)
            if entry.preparer.id == reviewer.id:
                raise ControlViolation("Reviewer must be different from preparer")
            updated = dataclasses.replace(entry, reviewer=reviewer)
            self._journals[journal_id] = updated
            self._audit(reviewer, "review_journal", journal_id, {})
            return updated

    def approve_journal(self, journal_id: str, *, approver: Actor) -> JournalEntry:
        self._require_role(approver, {Role.APPROVER, Role.CHIEF_ACCOUNTANT})
        with self._lock:
            entry = self._require_journal(journal_id)
            if entry.reviewer is None:
                raise ControlViolation("Journal must be reviewed before approval")
            if entry.preparer.id == approver.id:
                raise ControlViolation("Approver must be different from preparer")
            if entry.reviewer and entry.reviewer.id == approver.id:
                raise ControlViolation("Approver must be different from reviewer")

            period = self._require_period(entry.period_key)
            if period.status != AccountingPeriodStatus.OPEN:
                raise ControlViolation("Cannot approve journal in closed period")

            updated = dataclasses.replace(
                entry,
                approver=approver,
                approved_at=dt.datetime.now(dt.timezone.utc),
            )
            self._journals[journal_id] = updated
            self._audit(approver, "approve_journal", journal_id, {})
            return updated

    # --- Audit Trail ---

    def audit_log(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._audit_log)

    # --- Internal helpers ---

    def _audit(self, actor: Actor, action: str, object_id: str, details: dict[str, Any]) -> None:
        self._audit_log.append(
            AuditEvent(
                id=uuid.uuid4().hex,
                ts=dt.datetime.now(dt.timezone.utc),
                actor=actor,
                action=action,
                object_id=object_id,
                details=dict(details),
            )
        )

    def _require_role(self, actor: Actor, allowed: set[Role]) -> None:
        if actor.role not in allowed:
            raise ControlViolation(f"Role {actor.role.value} not permitted for this action")

    def _require_period(self, key: str) -> AccountingPeriod:
        p = self._periods.get(key)
        if not p:
            raise ControlViolation(f"Accounting period not found: {key}")
        return p

    def _require_journal(self, journal_id: str) -> JournalEntry:
        j = self._journals.get(journal_id)
        if not j:
            raise ControlViolation(f"Journal entry not found: {journal_id}")
        return j
