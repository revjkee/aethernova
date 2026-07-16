# agent_mash/cfo/accounting/chief_accountant/taxes.py
# -*- coding: utf-8 -*-
"""
Chief Accountant Tax Engine.

Industrial-grade tax accounting core.

Goals:
- Deterministic and auditable tax calculations
- Support for multiple tax types and jurisdictions
- Period-based accounting
- Strong validation and explicit error handling
- No external dependencies

This module does NOT encode real tax law values.
It provides a verifiable calculation framework only.
"""

from __future__ import annotations

import datetime as _dt
import decimal
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

Decimal = decimal.Decimal
decimal.getcontext().prec = 28


class TaxError(Exception):
    pass


class ValidationError(TaxError):
    pass


class TaxType(str, Enum):
    VAT = "vat"
    INCOME = "income"
    PROFIT = "profit"
    PAYROLL = "payroll"
    OTHER = "other"


class Jurisdiction(str, Enum):
    GENERIC = "generic"


class TaxPeriodType(str, Enum):
    MONTH = "month"
    QUARTER = "quarter"
    YEAR = "year"


@dataclass(frozen=True)
class TaxPeriod:
    year: int
    period_type: TaxPeriodType
    index: int

    def validate(self) -> None:
        if self.year < 1970:
            raise ValidationError("Invalid tax year")
        if self.period_type == TaxPeriodType.MONTH and not (1 <= self.index <= 12):
            raise ValidationError("Month index must be 1..12")
        if self.period_type == TaxPeriodType.QUARTER and not (1 <= self.index <= 4):
            raise ValidationError("Quarter index must be 1..4")
        if self.period_type == TaxPeriodType.YEAR and self.index != 1:
            raise ValidationError("Year period index must be 1")

    def label(self) -> str:
        return f"{self.year}-{self.period_type.value}-{self.index}"


@dataclass(frozen=True)
class TaxRate:
    tax_type: TaxType
    jurisdiction: Jurisdiction
    rate: Decimal

    def validate(self) -> None:
        if self.rate < Decimal("0"):
            raise ValidationError("Tax rate cannot be negative")


@dataclass(frozen=True)
class TaxBase:
    tax_type: TaxType
    amount: Decimal

    def validate(self) -> None:
        if self.amount < Decimal("0"):
            raise ValidationError("Tax base amount cannot be negative")


@dataclass
class TaxCalculationResult:
    tax_type: TaxType
    base_amount: Decimal
    rate: Decimal
    tax_amount: Decimal


@dataclass
class TaxAuditRecord:
    timestamp: _dt.datetime
    period: str
    jurisdiction: str
    results: Tuple[TaxCalculationResult, ...]


class TaxEngine:
    """
    Core tax calculation engine.
    """

    def __init__(self) -> None:
        self._rates: Dict[Tuple[TaxType, Jurisdiction], TaxRate] = {}
        self._audit_log: List[TaxAuditRecord] = []

    def register_rate(self, rate: TaxRate) -> None:
        rate.validate()
        key = (rate.tax_type, rate.jurisdiction)
        self._rates[key] = rate

    def get_rate(self, tax_type: TaxType, jurisdiction: Jurisdiction) -> TaxRate:
        try:
            return self._rates[(tax_type, jurisdiction)]
        except KeyError as e:
            raise ValidationError(
                f"No tax rate for {tax_type.value} in {jurisdiction.value}"
            ) from e

    def calculate(
        self,
        period: TaxPeriod,
        jurisdiction: Jurisdiction,
        bases: Iterable[TaxBase],
    ) -> Tuple[TaxCalculationResult, ...]:
        period.validate()

        results: List[TaxCalculationResult] = []

        for base in bases:
            base.validate()
            rate = self.get_rate(base.tax_type, jurisdiction)
            tax_amount = (base.amount * rate.rate).quantize(Decimal("0.01"))
            results.append(
                TaxCalculationResult(
                    tax_type=base.tax_type,
                    base_amount=base.amount,
                    rate=rate.rate,
                    tax_amount=tax_amount,
                )
            )

        self._audit_log.append(
            TaxAuditRecord(
                timestamp=_dt.datetime.utcnow(),
                period=period.label(),
                jurisdiction=jurisdiction.value,
                results=tuple(results),
            )
        )

        return tuple(results)

    def audit_log(self) -> Tuple[TaxAuditRecord, ...]:
        return tuple(self._audit_log)


def summarize(results: Iterable[TaxCalculationResult]) -> Decimal:
    total = Decimal("0")
    for r in results:
        total += r.tax_amount
    return total.quantize(Decimal("0.01"))


__all__ = [
    "TaxType",
    "Jurisdiction",
    "TaxPeriodType",
    "TaxPeriod",
    "TaxRate",
    "TaxBase",
    "TaxCalculationResult",
    "TaxAuditRecord",
    "TaxEngine",
    "summarize",
    "TaxError",
    "ValidationError",
]
