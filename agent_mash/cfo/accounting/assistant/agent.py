# agent_mash/cfo/accounting/assistant/agent.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import hashlib
import json
import re
import typing as t
import uuid

try:
    # Optional integration with agent_mash contracts if present in your project.
    from agent_mash.core.contracts import (
        Envelope,
        PacketKind,
        AuditRecord,
        Severity,
        utc_now as _contracts_utc_now,
        SCHEMA_VERSION_V1,
    )
except Exception:  # pragma: no cover
    Envelope = t.Any  # type: ignore
    PacketKind = t.Any  # type: ignore
    AuditRecord = t.Any  # type: ignore
    Severity = t.Any  # type: ignore
    SCHEMA_VERSION_V1 = "1.0.0"

    def _contracts_utc_now() -> _dt.datetime:  # type: ignore
        return _dt.datetime.now(tz=_dt.timezone.utc)


__all__ = [
    "AccountingAgentError",
    "AccountingValidationError",
    "Money",
    "Currency",
    "EntrySide",
    "LedgerEntry",
    "InvoiceStatus",
    "Invoice",
    "Expense",
    "AccountingReport",
    "AccountingStorage",
    "AuditSink",
    "Clock",
    "AccountingAssistantAgent",
]


# =========================
# Errors
# =========================

class AccountingAgentError(RuntimeError):
    """Base error for CFO accounting assistant agent."""


class AccountingValidationError(AccountingAgentError):
    """Raised when validation fails for accounting entities."""


# =========================
# Utilities
# =========================

_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-:.]{7,127}$")


def _utc_now() -> _dt.datetime:
    # Prefer contracts clock if available
    return _contracts_utc_now()


def _ensure_utc(dt: _dt.datetime) -> None:
    if dt.tzinfo is None or dt.utcoffset() != _dt.timedelta(0):
        raise AccountingValidationError("datetime must be timezone-aware UTC")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _validate_id(value: str, field: str) -> None:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise AccountingValidationError(f"{field} has invalid format: {value!r}")


def _canonical_json(obj: t.Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        raise AccountingAgentError(f"canonical json failed: {e}") from e


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _as_iso(dt: _dt.datetime) -> str:
    _ensure_utc(dt)
    s = dt.isoformat(timespec="milliseconds")
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    return s


def _parse_iso(value: str) -> _dt.datetime:
    if not isinstance(value, str) or not value:
        raise AccountingValidationError("timestamp must be a non-empty string")
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = _dt.datetime.fromisoformat(value)
    except ValueError as e:
        raise AccountingValidationError(f"invalid timestamp format: {value!r}") from e
    _ensure_utc(dt)
    return dt


# =========================
# Domain Types
# =========================

class Currency(str, enum.Enum):
    USD = "USD"
    EUR = "EUR"
    SEK = "SEK"
    RUB = "RUB"
    GBP = "GBP"


@dataclasses.dataclass(frozen=True, slots=True)
class Money:
    """
    Integer minor-units money representation (e.g. cents).
    """
    amount_minor: int
    currency: Currency

    def validate(self) -> None:
        if not isinstance(self.amount_minor, int):
            raise AccountingValidationError("Money.amount_minor must be int")
        if not isinstance(self.currency, Currency):
            raise AccountingValidationError("Money.currency must be Currency enum")

    def to_dict(self) -> dict:
        self.validate()
        return {"amount_minor": self.amount_minor, "currency": self.currency.value}

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "Money":
        if not isinstance(data, dict):
            raise AccountingValidationError("Money.from_dict expects a dict")
        try:
            cur = Currency(str(data["currency"]))
        except Exception as e:
            raise AccountingValidationError(f"invalid currency: {data.get('currency')!r}") from e
        m = Money(amount_minor=int(data["amount_minor"]), currency=cur)
        m.validate()
        return m


class EntrySide(str, enum.Enum):
    DEBIT = "debit"
    CREDIT = "credit"


@dataclasses.dataclass(frozen=True, slots=True)
class LedgerEntry:
    """
    Double-entry ledger line item (single line).
    Balancing is enforced at transaction/group level by storage or agent.
    """
    entry_id: str
    at: _dt.datetime
    account: str
    side: EntrySide
    money: Money
    memo: str = ""
    ref_id: t.Optional[str] = None  # invoice_id / expense_id / external ref
    tags: t.Tuple[str, ...] = ()

    def validate(self) -> None:
        _validate_id(self.entry_id, "entry_id")
        _ensure_utc(self.at)

        if not isinstance(self.account, str) or not self.account:
            raise AccountingValidationError("account must be non-empty string")

        if not isinstance(self.side, EntrySide):
            raise AccountingValidationError("side must be EntrySide enum")

        if not isinstance(self.money, Money):
            raise AccountingValidationError("money must be Money")
        self.money.validate()

        if not isinstance(self.memo, str):
            raise AccountingValidationError("memo must be string")

        if self.ref_id is not None:
            if not isinstance(self.ref_id, str) or not self.ref_id:
                raise AccountingValidationError("ref_id must be non-empty string or None")

        for tag in self.tags:
            if not isinstance(tag, str) or not tag:
                raise AccountingValidationError("tags must be non-empty strings")

    def to_dict(self) -> dict:
        self.validate()
        return {
            "entry_id": self.entry_id,
            "at": _as_iso(self.at),
            "account": self.account,
            "side": self.side.value,
            "money": self.money.to_dict(),
            "memo": self.memo,
            "ref_id": self.ref_id,
            "tags": list(self.tags),
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "LedgerEntry":
        if not isinstance(data, dict):
            raise AccountingValidationError("LedgerEntry.from_dict expects a dict")
        try:
            side = EntrySide(str(data["side"]))
        except Exception as e:
            raise AccountingValidationError(f"invalid side: {data.get('side')!r}") from e
        entry = LedgerEntry(
            entry_id=str(data["entry_id"]),
            at=_parse_iso(str(data["at"])),
            account=str(data["account"]),
            side=side,
            money=Money.from_dict(t.cast(dict, data["money"])),
            memo=str(data.get("memo", "")),
            ref_id=(str(data["ref_id"]) if data.get("ref_id") is not None else None),
            tags=tuple(data.get("tags") or ()),
        )
        entry.validate()
        return entry


class InvoiceStatus(str, enum.Enum):
    DRAFT = "draft"
    ISSUED = "issued"
    PAID = "paid"
    VOID = "void"
    OVERDUE = "overdue"


@dataclasses.dataclass(frozen=True, slots=True)
class Invoice:
    invoice_id: str
    created_at: _dt.datetime
    customer_id: str
    total: Money
    status: InvoiceStatus = InvoiceStatus.DRAFT
    due_at: t.Optional[_dt.datetime] = None
    paid_at: t.Optional[_dt.datetime] = None
    memo: str = ""
    metadata: t.Dict[str, str] = dataclasses.field(default_factory=dict)

    def validate(self) -> None:
        _validate_id(self.invoice_id, "invoice_id")
        _ensure_utc(self.created_at)

        if not isinstance(self.customer_id, str) or not self.customer_id:
            raise AccountingValidationError("customer_id must be non-empty string")

        if not isinstance(self.total, Money):
            raise AccountingValidationError("total must be Money")
        self.total.validate()

        if not isinstance(self.status, InvoiceStatus):
            raise AccountingValidationError("status must be InvoiceStatus")

        if self.due_at is not None:
            _ensure_utc(self.due_at)
            if self.due_at < self.created_at:
                raise AccountingValidationError("due_at cannot be earlier than created_at")

        if self.paid_at is not None:
            _ensure_utc(self.paid_at)
            if self.paid_at < self.created_at:
                raise AccountingValidationError("paid_at cannot be earlier than created_at")

        if self.status == InvoiceStatus.PAID and self.paid_at is None:
            raise AccountingValidationError("paid invoice must have paid_at set")

        for k, v in self.metadata.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise AccountingValidationError("metadata keys and values must be strings")

    def to_dict(self) -> dict:
        self.validate()
        return {
            "invoice_id": self.invoice_id,
            "created_at": _as_iso(self.created_at),
            "customer_id": self.customer_id,
            "total": self.total.to_dict(),
            "status": self.status.value,
            "due_at": _as_iso(self.due_at) if self.due_at else None,
            "paid_at": _as_iso(self.paid_at) if self.paid_at else None,
            "memo": self.memo,
            "metadata": dict(self.metadata),
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "Invoice":
        if not isinstance(data, dict):
            raise AccountingValidationError("Invoice.from_dict expects a dict")
        try:
            st = InvoiceStatus(str(data.get("status", InvoiceStatus.DRAFT.value)))
        except Exception as e:
            raise AccountingValidationError(f"invalid invoice status: {data.get('status')!r}") from e
        inv = Invoice(
            invoice_id=str(data["invoice_id"]),
            created_at=_parse_iso(str(data["created_at"])),
            customer_id=str(data["customer_id"]),
            total=Money.from_dict(t.cast(dict, data["total"])),
            status=st,
            due_at=_parse_iso(str(data["due_at"])) if data.get("due_at") else None,
            paid_at=_parse_iso(str(data["paid_at"])) if data.get("paid_at") else None,
            memo=str(data.get("memo", "")),
            metadata=t.cast(dict, data.get("metadata") or {}),
        )
        inv.validate()
        return inv


@dataclasses.dataclass(frozen=True, slots=True)
class Expense:
    expense_id: str
    created_at: _dt.datetime
    vendor: str
    total: Money
    category: str
    memo: str = ""
    ref: t.Optional[str] = None
    metadata: t.Dict[str, str] = dataclasses.field(default_factory=dict)

    def validate(self) -> None:
        _validate_id(self.expense_id, "expense_id")
        _ensure_utc(self.created_at)

        if not isinstance(self.vendor, str) or not self.vendor:
            raise AccountingValidationError("vendor must be non-empty string")
        if not isinstance(self.category, str) or not self.category:
            raise AccountingValidationError("category must be non-empty string")

        if not isinstance(self.total, Money):
            raise AccountingValidationError("total must be Money")
        self.total.validate()

        if not isinstance(self.memo, str):
            raise AccountingValidationError("memo must be string")

        if self.ref is not None and (not isinstance(self.ref, str) or not self.ref):
            raise AccountingValidationError("ref must be non-empty string or None")

        for k, v in self.metadata.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise AccountingValidationError("metadata keys and values must be strings")

    def to_dict(self) -> dict:
        self.validate()
        return {
            "expense_id": self.expense_id,
            "created_at": _as_iso(self.created_at),
            "vendor": self.vendor,
            "total": self.total.to_dict(),
            "category": self.category,
            "memo": self.memo,
            "ref": self.ref,
            "metadata": dict(self.metadata),
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "Expense":
        if not isinstance(data, dict):
            raise AccountingValidationError("Expense.from_dict expects a dict")
        exp = Expense(
            expense_id=str(data["expense_id"]),
            created_at=_parse_iso(str(data["created_at"])),
            vendor=str(data["vendor"]),
            total=Money.from_dict(t.cast(dict, data["total"])),
            category=str(data["category"]),
            memo=str(data.get("memo", "")),
            ref=(str(data["ref"]) if data.get("ref") is not None else None),
            metadata=t.cast(dict, data.get("metadata") or {}),
        )
        exp.validate()
        return exp


@dataclasses.dataclass(frozen=True, slots=True)
class AccountingReport:
    """
    A minimal report: sums per currency and simple KPIs for a time window.
    """
    report_id: str
    from_at: _dt.datetime
    to_at: _dt.datetime
    revenue_by_currency: t.Dict[str, int]
    expenses_by_currency: t.Dict[str, int]
    net_by_currency: t.Dict[str, int]
    totals: t.Dict[str, t.Dict[str, int]]
    generated_at: _dt.datetime

    def validate(self) -> None:
        _validate_id(self.report_id, "report_id")
        _ensure_utc(self.from_at)
        _ensure_utc(self.to_at)
        _ensure_utc(self.generated_at)
        if self.to_at < self.from_at:
            raise AccountingValidationError("to_at must be >= from_at")
        if not isinstance(self.revenue_by_currency, dict):
            raise AccountingValidationError("revenue_by_currency must be dict")
        if not isinstance(self.expenses_by_currency, dict):
            raise AccountingValidationError("expenses_by_currency must be dict")
        if not isinstance(self.net_by_currency, dict):
            raise AccountingValidationError("net_by_currency must be dict")
        if not isinstance(self.totals, dict):
            raise AccountingValidationError("totals must be dict")

    def to_dict(self) -> dict:
        self.validate()
        return {
            "report_id": self.report_id,
            "from_at": _as_iso(self.from_at),
            "to_at": _as_iso(self.to_at),
            "revenue_by_currency": dict(self.revenue_by_currency),
            "expenses_by_currency": dict(self.expenses_by_currency),
            "net_by_currency": dict(self.net_by_currency),
            "totals": json.loads(_canonical_json(self.totals)),
            "generated_at": _as_iso(self.generated_at),
        }


# =========================
# Storage and Audit Interfaces
# =========================

class AccountingStorage(t.Protocol):
    """
    Storage contract.
    Implementations can be DB-backed, event-sourced, or in-memory.
    """

    # Idempotency
    def has_idempotency_key(self, key: str) -> bool: ...
    def mark_idempotency_key(self, key: str, at: _dt.datetime) -> None: ...

    # Invoices
    def put_invoice(self, invoice: Invoice) -> None: ...
    def get_invoice(self, invoice_id: str) -> Invoice: ...
    def list_invoices(self, from_at: _dt.datetime, to_at: _dt.datetime) -> t.Sequence[Invoice]: ...

    # Expenses
    def put_expense(self, expense: Expense) -> None: ...
    def get_expense(self, expense_id: str) -> Expense: ...
    def list_expenses(self, from_at: _dt.datetime, to_at: _dt.datetime) -> t.Sequence[Expense]: ...

    # Ledger
    def append_entries(self, entries: t.Sequence[LedgerEntry]) -> None: ...
    def list_entries(self, from_at: _dt.datetime, to_at: _dt.datetime) -> t.Sequence[LedgerEntry]: ...


class AuditSink(t.Protocol):
    def emit(self, record: t.Any) -> None: ...


class Clock(t.Protocol):
    def now_utc(self) -> _dt.datetime: ...


@dataclasses.dataclass(frozen=True, slots=True)
class SystemClock:
    def now_utc(self) -> _dt.datetime:
        return _utc_now()


# =========================
# Agent
# =========================

@dataclasses.dataclass(slots=True)
class AccountingAssistantAgent:
    """
    Contract-first CFO accounting assistant agent.

    Handles:
    - invoice.create / invoice.issue / invoice.mark_paid / invoice.void
    - expense.record
    - report.generate
    - ledger.append (internal guarded)

    Input can be plain dict commands or contract Envelope payloads.
    """

    storage: AccountingStorage
    audit: AuditSink
    clock: Clock = dataclasses.field(default_factory=SystemClock)

    agent_id: str = dataclasses.field(default_factory=lambda: _new_id("acct_agent"))

    # Schema identifiers for command routing (string-only, stable)
    SCHEMA_COMMAND: str = "agent_mash.cfo.accounting.command"
    SCHEMA_EVENT: str = "agent_mash.cfo.accounting.event"
    SCHEMA_VERSION: str = SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        _validate_id(self.agent_id, "agent_id")

    # ---------------------
    # Public entrypoint
    # ---------------------

    def handle(self, msg: t.Any) -> dict:
        """
        Handles either:
        - Envelope (preferred)
        - dict command: {"op": "...", "data": {...}, "idempotency_key": "..."}
        Returns dict result suitable for WorkResult.output.
        """
        if self._is_envelope(msg):
            return self._handle_envelope(msg)
        if isinstance(msg, dict):
            return self._handle_command_dict(msg)
        raise AccountingAgentError("unsupported message type")

    # ---------------------
    # Envelope handling
    # ---------------------

    def _is_envelope(self, msg: t.Any) -> bool:
        return hasattr(msg, "meta") and hasattr(msg, "payload") and hasattr(msg, "digest")

    def _handle_envelope(self, env: Envelope) -> dict:
        # Validate envelope integrity if possible
        try:
            if hasattr(env, "validate"):
                env.validate()
        except Exception as e:
            raise AccountingValidationError(f"invalid envelope: {e}") from e

        payload = getattr(env, "payload", None)
        if not isinstance(payload, dict):
            raise AccountingValidationError("envelope.payload must be dict")

        # Accept either direct command payload or nested command
        cmd = payload
        res = self._handle_command_dict(cmd, correlation_id=getattr(env.meta, "correlation_id", None), causation_id=getattr(env.meta, "id", None))

        # Emit audit record tied to envelope digest when available
        digest = getattr(env, "digest", None)
        self._audit(
            action="accounting.handle_envelope",
            severity="info",
            subject_id=self.agent_id,
            correlation_id=getattr(env.meta, "correlation_id", None),
            envelope_digest=str(digest) if isinstance(digest, str) else None,
            details={
                "packet_kind": getattr(getattr(env, "meta", None), "kind", None).value if hasattr(getattr(env, "meta", None), "kind") else None,
                "schema": getattr(getattr(env, "meta", None), "schema", None),
                "result_op": res.get("op"),
                "ok": res.get("ok"),
            },
        )
        return res

    # ---------------------
    # Command handling
    # ---------------------

    def _handle_command_dict(self, cmd: dict, correlation_id: t.Optional[str] = None, causation_id: t.Optional[str] = None) -> dict:
        op = cmd.get("op")
        data = cmd.get("data", {})
        idem = cmd.get("idempotency_key")

        if not isinstance(op, str) or not op:
            raise AccountingValidationError("command.op must be non-empty string")
        if not isinstance(data, dict):
            raise AccountingValidationError("command.data must be dict")
        if idem is not None and (not isinstance(idem, str) or not idem):
            raise AccountingValidationError("command.idempotency_key must be non-empty string or None")

        # Idempotency: if provided, enforce once-only semantics.
        if idem is not None:
            if self.storage.has_idempotency_key(idem):
                return {
                    "ok": True,
                    "op": op,
                    "idempotency_key": idem,
                    "idempotent_replay": True,
                    "result": {},
                }

        handler = self._get_handler(op)
        result = handler(data)

        if idem is not None:
            self.storage.mark_idempotency_key(idem, self.clock.now_utc())

        # Minimal audit for commands
        self._audit(
            action=f"accounting.command.{op}",
            severity="info",
            subject_id=self.agent_id,
            correlation_id=correlation_id,
            envelope_digest=None,
            details={
                "causation_id": causation_id,
                "idempotency_key": idem,
                "ok": True,
            },
        )

        return {
            "ok": True,
            "op": op,
            "idempotency_key": idem,
            "result": result,
        }

    def _get_handler(self, op: str) -> t.Callable[[dict], dict]:
        table: dict[str, t.Callable[[dict], dict]] = {
            "invoice.create": self._op_invoice_create,
            "invoice.issue": self._op_invoice_issue,
            "invoice.mark_paid": self._op_invoice_mark_paid,
            "invoice.void": self._op_invoice_void,
            "expense.record": self._op_expense_record,
            "report.generate": self._op_report_generate,
        }
        try:
            return table[op]
        except KeyError:
            raise AccountingAgentError(f"unknown op: {op}")

    # ---------------------
    # Operations
    # ---------------------

    def _op_invoice_create(self, data: dict) -> dict:
        customer_id = data.get("customer_id")
        total = data.get("total")
        due_at = data.get("due_at")
        memo = data.get("memo", "")
        metadata = data.get("metadata", {})

        if not isinstance(customer_id, str) or not customer_id:
            raise AccountingValidationError("customer_id must be non-empty string")
        if not isinstance(total, dict):
            raise AccountingValidationError("total must be dict")
        if not isinstance(memo, str):
            raise AccountingValidationError("memo must be string")
        if not isinstance(metadata, dict):
            raise AccountingValidationError("metadata must be dict[str,str]")

        money = Money.from_dict(total)
        now = self.clock.now_utc()

        inv = Invoice(
            invoice_id=_new_id("inv"),
            created_at=now,
            customer_id=customer_id,
            total=money,
            status=InvoiceStatus.DRAFT,
            due_at=_parse_iso(due_at) if due_at else None,
            paid_at=None,
            memo=memo,
            metadata=t.cast(dict, metadata),
        )
        inv.validate()
        self.storage.put_invoice(inv)

        self._audit(
            action="invoice.created",
            severity="info",
            subject_id=inv.invoice_id,
            correlation_id=None,
            envelope_digest=None,
            details={"customer_id": customer_id, "total": inv.total.to_dict()},
        )

        return {"invoice": inv.to_dict()}

    def _op_invoice_issue(self, data: dict) -> dict:
        invoice_id = data.get("invoice_id")
        if not isinstance(invoice_id, str) or not invoice_id:
            raise AccountingValidationError("invoice_id must be non-empty string")

        inv = self.storage.get_invoice(invoice_id)
        inv.validate()

        if inv.status in (InvoiceStatus.PAID, InvoiceStatus.VOID):
            raise AccountingAgentError("cannot issue invoice in paid/void state")

        updated = dataclasses.replace(inv, status=InvoiceStatus.ISSUED)
        updated.validate()
        self.storage.put_invoice(updated)

        # Ledger: Accounts Receivable (debit), Revenue (credit)
        entries = self._invoice_issue_entries(updated)
        self.storage.append_entries(entries)

        self._audit(
            action="invoice.issued",
            severity="info",
            subject_id=updated.invoice_id,
            correlation_id=None,
            envelope_digest=None,
            details={"entries": [e.to_dict() for e in entries]},
        )

        return {"invoice": updated.to_dict(), "entries": [e.to_dict() for e in entries]}

    def _op_invoice_mark_paid(self, data: dict) -> dict:
        invoice_id = data.get("invoice_id")
        paid_at = data.get("paid_at")
        if not isinstance(invoice_id, str) or not invoice_id:
            raise AccountingValidationError("invoice_id must be non-empty string")

        inv = self.storage.get_invoice(invoice_id)
        inv.validate()

        if inv.status == InvoiceStatus.VOID:
            raise AccountingAgentError("cannot mark paid: invoice is void")
        if inv.status == InvoiceStatus.PAID:
            return {"invoice": inv.to_dict(), "already_paid": True}

        at = _parse_iso(paid_at) if paid_at else self.clock.now_utc()
        updated = dataclasses.replace(inv, status=InvoiceStatus.PAID, paid_at=at)
        updated.validate()
        self.storage.put_invoice(updated)

        # Ledger: Cash/Bank (debit), Accounts Receivable (credit)
        entries = self._invoice_payment_entries(updated, at)
        self.storage.append_entries(entries)

        self._audit(
            action="invoice.paid",
            severity="info",
            subject_id=updated.invoice_id,
            correlation_id=None,
            envelope_digest=None,
            details={"paid_at": _as_iso(at), "entries": [e.to_dict() for e in entries]},
        )

        return {"invoice": updated.to_dict(), "entries": [e.to_dict() for e in entries]}

    def _op_invoice_void(self, data: dict) -> dict:
        invoice_id = data.get("invoice_id")
        if not isinstance(invoice_id, str) or not invoice_id:
            raise AccountingValidationError("invoice_id must be non-empty string")

        inv = self.storage.get_invoice(invoice_id)
        inv.validate()

        if inv.status == InvoiceStatus.PAID:
            raise AccountingAgentError("cannot void: invoice already paid")

        updated = dataclasses.replace(inv, status=InvoiceStatus.VOID)
        updated.validate()
        self.storage.put_invoice(updated)

        self._audit(
            action="invoice.void",
            severity="warning",
            subject_id=updated.invoice_id,
            correlation_id=None,
            envelope_digest=None,
            details={"previous_status": inv.status.value},
        )

        return {"invoice": updated.to_dict()}

    def _op_expense_record(self, data: dict) -> dict:
        vendor = data.get("vendor")
        category = data.get("category")
        total = data.get("total")
        memo = data.get("memo", "")
        ref = data.get("ref")
        metadata = data.get("metadata", {})

        if not isinstance(vendor, str) or not vendor:
            raise AccountingValidationError("vendor must be non-empty string")
        if not isinstance(category, str) or not category:
            raise AccountingValidationError("category must be non-empty string")
        if not isinstance(total, dict):
            raise AccountingValidationError("total must be dict")
        if not isinstance(memo, str):
            raise AccountingValidationError("memo must be string")
        if ref is not None and (not isinstance(ref, str) or not ref):
            raise AccountingValidationError("ref must be non-empty string or None")
        if not isinstance(metadata, dict):
            raise AccountingValidationError("metadata must be dict[str,str]")

        money = Money.from_dict(total)
        now = self.clock.now_utc()

        exp = Expense(
            expense_id=_new_id("exp"),
            created_at=now,
            vendor=vendor,
            total=money,
            category=category,
            memo=memo,
            ref=ref,
            metadata=t.cast(dict, metadata),
        )
        exp.validate()
        self.storage.put_expense(exp)

        # Ledger: Expense (debit), Cash/Bank or Accounts Payable (credit)
        entries = self._expense_entries(exp)
        self.storage.append_entries(entries)

        self._audit(
            action="expense.recorded",
            severity="info",
            subject_id=exp.expense_id,
            correlation_id=None,
            envelope_digest=None,
            details={"category": category, "entries": [e.to_dict() for e in entries]},
        )

        return {"expense": exp.to_dict(), "entries": [e.to_dict() for e in entries]}

    def _op_report_generate(self, data: dict) -> dict:
        from_at = data.get("from_at")
        to_at = data.get("to_at")
        if not isinstance(from_at, str) or not isinstance(to_at, str):
            raise AccountingValidationError("from_at and to_at must be ISO strings")

        f = _parse_iso(from_at)
        t_ = _parse_iso(to_at)
        if t_ < f:
            raise AccountingValidationError("to_at must be >= from_at")

        invoices = self.storage.list_invoices(f, t_)
        expenses = self.storage.list_expenses(f, t_)
        entries = self.storage.list_entries(f, t_)

        # Revenue: sum PAID invoices as revenue for the window.
        revenue: dict[str, int] = {}
        for inv in invoices:
            inv.validate()
            if inv.status == InvoiceStatus.PAID:
                cur = inv.total.currency.value
                revenue[cur] = revenue.get(cur, 0) + inv.total.amount_minor

        # Expenses: sum recorded expenses for the window.
        exp_sum: dict[str, int] = {}
        for exp in expenses:
            exp.validate()
            cur = exp.total.currency.value
            exp_sum[cur] = exp_sum.get(cur, 0) + exp.total.amount_minor

        # Net
        net: dict[str, int] = {}
        currencies = set(revenue.keys()) | set(exp_sum.keys())
        for c in currencies:
            net[c] = revenue.get(c, 0) - exp_sum.get(c, 0)

        report = AccountingReport(
            report_id=_new_id("rpt"),
            from_at=f,
            to_at=t_,
            revenue_by_currency=revenue,
            expenses_by_currency=exp_sum,
            net_by_currency=net,
            totals={
                "invoices_total": {"count": len(invoices)},
                "expenses_total": {"count": len(expenses)},
                "ledger_entries_total": {"count": len(entries)},
            },
            generated_at=self.clock.now_utc(),
        )
        report.validate()

        self._audit(
            action="report.generated",
            severity="info",
            subject_id=report.report_id,
            correlation_id=None,
            envelope_digest=None,
            details={"from_at": from_at, "to_at": to_at},
        )

        return {"report": report.to_dict()}

    # ---------------------
    # Ledger entry builders
    # ---------------------

    def _invoice_issue_entries(self, inv: Invoice) -> t.List[LedgerEntry]:
        at = self.clock.now_utc()
        inv.validate()
        # Accounts
        ar = "accounts_receivable"
        rev = "revenue"

        debit = LedgerEntry(
            entry_id=_new_id("le"),
            at=at,
            account=ar,
            side=EntrySide.DEBIT,
            money=inv.total,
            memo=f"Invoice issued {inv.invoice_id}",
            ref_id=inv.invoice_id,
            tags=("invoice", "issue"),
        )
        credit = LedgerEntry(
            entry_id=_new_id("le"),
            at=at,
            account=rev,
            side=EntrySide.CREDIT,
            money=inv.total,
            memo=f"Invoice issued {inv.invoice_id}",
            ref_id=inv.invoice_id,
            tags=("invoice", "issue"),
        )
        debit.validate()
        credit.validate()
        self._ensure_balanced([debit, credit])
        return [debit, credit]

    def _invoice_payment_entries(self, inv: Invoice, paid_at: _dt.datetime) -> t.List[LedgerEntry]:
        _ensure_utc(paid_at)
        inv.validate()
        # Accounts
        cash = "cash_bank"
        ar = "accounts_receivable"

        debit = LedgerEntry(
            entry_id=_new_id("le"),
            at=paid_at,
            account=cash,
            side=EntrySide.DEBIT,
            money=inv.total,
            memo=f"Invoice paid {inv.invoice_id}",
            ref_id=inv.invoice_id,
            tags=("invoice", "payment"),
        )
        credit = LedgerEntry(
            entry_id=_new_id("le"),
            at=paid_at,
            account=ar,
            side=EntrySide.CREDIT,
            money=inv.total,
            memo=f"Invoice paid {inv.invoice_id}",
            ref_id=inv.invoice_id,
            tags=("invoice", "payment"),
        )
        debit.validate()
        credit.validate()
        self._ensure_balanced([debit, credit])
        return [debit, credit]

    def _expense_entries(self, exp: Expense) -> t.List[LedgerEntry]:
        exp.validate()
        at = self.clock.now_utc()
        expense_acct = f"expense:{exp.category}"
        cash = "cash_bank"

        debit = LedgerEntry(
            entry_id=_new_id("le"),
            at=at,
            account=expense_acct,
            side=EntrySide.DEBIT,
            money=exp.total,
            memo=f"Expense {exp.expense_id} vendor={exp.vendor}",
            ref_id=exp.expense_id,
            tags=("expense", exp.category),
        )
        credit = LedgerEntry(
            entry_id=_new_id("le"),
            at=at,
            account=cash,
            side=EntrySide.CREDIT,
            money=exp.total,
            memo=f"Expense {exp.expense_id} vendor={exp.vendor}",
            ref_id=exp.expense_id,
            tags=("expense", exp.category),
        )
        debit.validate()
        credit.validate()
        self._ensure_balanced([debit, credit])
        return [debit, credit]

    def _ensure_balanced(self, entries: t.Sequence[LedgerEntry]) -> None:
        """
        Ensures sum(debits) == sum(credits) per currency for the provided group.
        """
        sums: dict[str, int] = {}
        for e in entries:
            e.validate()
            cur = e.money.currency.value
            sign = 1 if e.side == EntrySide.DEBIT else -1
            sums[cur] = sums.get(cur, 0) + sign * e.money.amount_minor

        for cur, v in sums.items():
            if v != 0:
                raise AccountingAgentError(f"ledger group not balanced for {cur}: {v}")

    # ---------------------
    # Audit
    # ---------------------

    def _audit(
        self,
        *,
        action: str,
        severity: str,
        subject_id: str,
        correlation_id: t.Optional[str],
        envelope_digest: t.Optional[str],
        details: dict,
    ) -> None:
        """
        Emits an audit record. If agent_mash.core.contracts.AuditRecord is available,
        it will use it. Otherwise, emits a plain dict.
        """
        if not isinstance(action, str) or not action:
            raise AccountingValidationError("audit action must be non-empty string")
        if not isinstance(subject_id, str) or not subject_id:
            raise AccountingValidationError("audit subject_id must be non-empty string")
        if not isinstance(details, dict):
            raise AccountingValidationError("audit details must be dict")

        at = self.clock.now_utc()
        _ensure_utc(at)

        # If AuditRecord type is available, use it for stricter structure
        try:
            sev = Severity(str(severity))  # type: ignore
            record = AuditRecord(
                audit_id=_new_id("audit"),
                at=at,
                severity=sev,
                action=action,
                subject_id=subject_id,
                correlation_id=correlation_id,
                envelope_digest=envelope_digest,
                details=details,
            )
            # Validate if method exists
            if hasattr(record, "validate"):
                record.validate()
            self.audit.emit(record)
            return
        except Exception:
            # Fall back to dict record; deterministic, verifiable structure.
            rec = {
                "audit_id": _new_id("audit"),
                "at": _as_iso(at),
                "severity": str(severity),
                "action": action,
                "subject_id": subject_id,
                "correlation_id": correlation_id,
                "envelope_digest": envelope_digest,
                "details": json.loads(_canonical_json(details)),
            }
            self.audit.emit(rec)

    # ---------------------
    # Deterministic command id helper (optional)
    # ---------------------

    @staticmethod
    def make_idempotency_key(op: str, data: dict) -> str:
        """
        Deterministic idempotency key helper based on op+data.
        """
        if not isinstance(op, str) or not op:
            raise AccountingValidationError("op must be non-empty string")
        if not isinstance(data, dict):
            raise AccountingValidationError("data must be dict")
        base = _canonical_json({"op": op, "data": data})
        return "idem_" + _sha256_hex(base)
