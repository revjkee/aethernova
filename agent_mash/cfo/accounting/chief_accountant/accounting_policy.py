# agent_mash/cfo/accounting/chief_accountant/accounting_policy.py
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Mapping, Optional, List


class AccountingPolicyError(RuntimeError):
    pass


class PolicyValidationError(AccountingPolicyError):
    pass


class InventoryValuationMethod(str, Enum):
    FIFO = "fifo"
    LIFO = "lifo"
    WEIGHTED_AVERAGE = "weighted_average"


class DepreciationMethod(str, Enum):
    STRAIGHT_LINE = "straight_line"
    DECLINING_BALANCE = "declining_balance"
    UNITS_OF_PRODUCTION = "units_of_production"


class RevenueRecognitionMethod(str, Enum):
    ACCRUAL = "accrual"
    CASH = "cash"


@dataclass(slots=True, frozen=True)
class AuditRecord:
    record_id: str
    timestamp: dt.datetime
    actor: Optional[str]
    action: str
    details: Mapping[str, Any]


@dataclass(slots=True)
class InventoryPolicy:
    valuation_method: InventoryValuationMethod

    def validate(self) -> None:
        if not isinstance(self.valuation_method, InventoryValuationMethod):
            raise PolicyValidationError("Invalid inventory valuation method")


@dataclass(slots=True)
class DepreciationPolicy:
    method: DepreciationMethod
    useful_life_years: int

    def validate(self) -> None:
        if self.useful_life_years <= 0:
            raise PolicyValidationError("useful_life_years must be greater than zero")
        if not isinstance(self.method, DepreciationMethod):
            raise PolicyValidationError("Invalid depreciation method")


@dataclass(slots=True)
class RevenuePolicy:
    recognition_method: RevenueRecognitionMethod

    def validate(self) -> None:
        if not isinstance(self.recognition_method, RevenueRecognitionMethod):
            raise PolicyValidationError("Invalid revenue recognition method")


@dataclass(slots=True)
class AccountingPolicy:
    policy_id: str
    version: int = 1

    effective_from: dt.date = field(default_factory=lambda: dt.date.today())
    created_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(tz=dt.timezone.utc))
    updated_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(tz=dt.timezone.utc))

    inventory: InventoryPolicy = field(default_factory=lambda: InventoryPolicy(InventoryValuationMethod.FIFO))
    depreciation: DepreciationPolicy = field(default_factory=lambda: DepreciationPolicy(DepreciationMethod.STRAIGHT_LINE, 5))
    revenue: RevenuePolicy = field(default_factory=lambda: RevenuePolicy(RevenueRecognitionMethod.ACCRUAL))

    currency: str = "USD"
    tax_rate_percent: float = 0.0

    audit_log: List[AuditRecord] = field(default_factory=list)

    def validate(self) -> None:
        if not self.policy_id:
            raise PolicyValidationError("policy_id is required")
        if self.tax_rate_percent < 0.0:
            raise PolicyValidationError("tax_rate_percent must be non-negative")
        self.inventory.validate()
        self.depreciation.validate()
        self.revenue.validate()

    def record_audit(self, *, actor: Optional[str], action: str, details: Mapping[str, Any]) -> None:
        self.audit_log.append(
            AuditRecord(
                record_id=f"audit_{len(self.audit_log)+1}",
                timestamp=dt.datetime.now(tz=dt.timezone.utc),
                actor=actor,
                action=action,
                details=dict(details),
            )
        )

    def update(self, *, actor: Optional[str], **changes: Any) -> None:
        for key, value in changes.items():
            if not hasattr(self, key):
                raise PolicyValidationError(f"Unknown policy field: {key}")
            setattr(self, key, value)
        self.version += 1
        self.updated_at = dt.datetime.now(tz=dt.timezone.utc)
        self.validate()
        self.record_audit(actor=actor, action="update", details=changes)

    def to_dict(self) -> Dict[str, Any]:
        def _serialize(obj: Any) -> Any:
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, dt.datetime):
                return obj.isoformat()
            if isinstance(obj, dt.date):
                return obj.isoformat()
            return obj

        raw = asdict(self)
        return json.loads(json.dumps(raw, default=_serialize))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AccountingPolicy:
        policy = cls(
            policy_id=str(data["policy_id"]),
            version=int(data.get("version", 1)),
            effective_from=dt.date.fromisoformat(data["effective_from"]),
            created_at=dt.datetime.fromisoformat(data["created_at"]),
            updated_at=dt.datetime.fromisoformat(data["updated_at"]),
            inventory=InventoryPolicy(
                InventoryValuationMethod(data["inventory"]["valuation_method"])
            ),
            depreciation=DepreciationPolicy(
                DepreciationMethod(data["depreciation"]["method"]),
                int(data["depreciation"]["useful_life_years"]),
            ),
            revenue=RevenuePolicy(
                RevenueRecognitionMethod(data["revenue"]["recognition_method"])
            ),
            currency=str(data.get("currency", "USD")),
            tax_rate_percent=float(data.get("tax_rate_percent", 0.0)),
        )

        for ar in data.get("audit_log", []):
            policy.audit_log.append(
                AuditRecord(
                    record_id=ar["record_id"],
                    timestamp=dt.datetime.fromisoformat(ar["timestamp"]),
                    actor=ar.get("actor"),
                    action=ar["action"],
                    details=dict(ar.get("details", {})),
                )
            )

        policy.validate()
        return policy

    def persist(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)

        payload = self.to_dict()
        fd, tmp = tempfile.mkstemp(prefix="accounting_policy_", suffix=".tmp", dir=directory, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    @classmethod
    def load(cls, path: str) -> AccountingPolicy:
        if not os.path.exists(path):
            raise AccountingPolicyError("Accounting policy file not found")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
