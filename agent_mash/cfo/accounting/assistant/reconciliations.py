# agent_mash/cfo/accounting/assistant/reconciliations.py
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


class ReconciliationError(Exception):
    pass


class ReconciliationValidationError(ReconciliationError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_decimal(value: Any, *, field_name: str) -> Decimal:
    try:
        if isinstance(value, Decimal):
            d = value
        elif isinstance(value, (int, str)):
            d = Decimal(str(value))
        elif isinstance(value, float):
            if value != value:
                raise ReconciliationValidationError(f"{field_name} must not be NaN")
            d = Decimal(repr(value))
        else:
            raise ReconciliationValidationError(
                f"{field_name} has unsupported type: {type(value).__name__}"
            )
    except (InvalidOperation, ValueError) as exc:
        raise ReconciliationValidationError(
            f"{field_name} must be numeric-convertible"
        ) from exc
    return d


def _quantize_2(d: Decimal) -> Decimal:
    return d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


@dataclass(frozen=True)
class LedgerEntry:
    source: str
    reference_id: str
    account: str
    amount: Decimal
    currency: str
    booked_at_utc: datetime
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source:
            raise ReconciliationValidationError("LedgerEntry.source must be non-empty")
        if not self.reference_id:
            raise ReconciliationValidationError("LedgerEntry.reference_id must be non-empty")
        if not self.account:
            raise ReconciliationValidationError("LedgerEntry.account must be non-empty")
        amt = _to_decimal(self.amount, field_name="amount")
        if self.booked_at_utc.tzinfo is None:
            raise ReconciliationValidationError("booked_at_utc must be timezone-aware")
        object.__setattr__(self, "amount", amt)
        object.__setattr__(self, "booked_at_utc", self.booked_at_utc.astimezone(timezone.utc))


@dataclass(frozen=True)
class ReconciliationRule:
    tolerance_abs: Decimal = Decimal("0.01")
    require_same_currency: bool = True
    require_same_account: bool = True

    def __post_init__(self) -> None:
        tol = _to_decimal(self.tolerance_abs, field_name="tolerance_abs")
        if tol < 0:
            raise ReconciliationValidationError("tolerance_abs must be >= 0")
        object.__setattr__(self, "tolerance_abs", tol)


@dataclass(frozen=True)
class Discrepancy:
    reference_id: str
    reason: str
    left_amount: Optional[Decimal]
    right_amount: Optional[Decimal]
    delta: Optional[Decimal]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "reason": self.reason,
            "left_amount": str(_quantize_2(self.left_amount)) if self.left_amount is not None else None,
            "right_amount": str(_quantize_2(self.right_amount)) if self.right_amount is not None else None,
            "delta": str(_quantize_2(self.delta)) if self.delta is not None else None,
        }


@dataclass(frozen=True)
class ReconciliationResult:
    matched: int
    discrepancies: List[Discrepancy]
    computed_at_utc: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matched": self.matched,
            "discrepancies": [d.to_dict() for d in self.discrepancies],
            "computed_at_utc": self.computed_at_utc.isoformat(),
        }


class ReconciliationEngine:
    """
    Deterministic ledger reconciliation engine.
    Designed for CFO-grade accounting automation.
    """

    def __init__(self, *, rule: Optional[ReconciliationRule] = None) -> None:
        self.rule = rule or ReconciliationRule()

    def reconcile(
        self,
        left: Iterable[LedgerEntry],
        right: Iterable[LedgerEntry],
    ) -> ReconciliationResult:
        left_map: Dict[str, LedgerEntry] = {}
        right_map: Dict[str, LedgerEntry] = {}

        for e in left:
            left_map[e.reference_id] = e
        for e in right:
            right_map[e.reference_id] = e

        discrepancies: List[Discrepancy] = []
        matched = 0

        all_keys = set(left_map.keys()) | set(right_map.keys())

        for ref in sorted(all_keys):
            l = left_map.get(ref)
            r = right_map.get(ref)

            if l is None:
                discrepancies.append(
                    Discrepancy(
                        reference_id=ref,
                        reason="missing_left",
                        left_amount=None,
                        right_amount=r.amount if r else None,
                        delta=None,
                    )
                )
                continue

            if r is None:
                discrepancies.append(
                    Discrepancy(
                        reference_id=ref,
                        reason="missing_right",
                        left_amount=l.amount if l else None,
                        right_amount=None,
                        delta=None,
                    )
                )
                continue

            if self.rule.require_same_currency and l.currency != r.currency:
                discrepancies.append(
                    Discrepancy(
                        reference_id=ref,
                        reason="currency_mismatch",
                        left_amount=l.amount,
                        right_amount=r.amount,
                        delta=None,
                    )
                )
                continue

            if self.rule.require_same_account and l.account != r.account:
                discrepancies.append(
                    Discrepancy(
                        reference_id=ref,
                        reason="account_mismatch",
                        left_amount=l.amount,
                        right_amount=r.amount,
                        delta=None,
                    )
                )
                continue

            delta = l.amount - r.amount
            if abs(delta) > self.rule.tolerance_abs:
                discrepancies.append(
                    Discrepancy(
                        reference_id=ref,
                        reason="amount_mismatch",
                        left_amount=l.amount,
                        right_amount=r.amount,
                        delta=delta,
                    )
                )
                continue

            matched += 1

        return ReconciliationResult(
            matched=matched,
            discrepancies=discrepancies,
            computed_at_utc=_utcnow(),
        )
