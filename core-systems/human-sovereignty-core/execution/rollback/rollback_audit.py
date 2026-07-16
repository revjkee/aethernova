# human-sovereignty-core/execution/rollback/rollback_audit.py
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RollbackAuditRecord:
    """
    Неизменяемая запись аудита rollback-операции.
    """
    record_id: str
    execution_id: str
    decision_id: str
    reason: str
    triggered_by: str
    created_at: str

    metadata: Dict[str, Any] = field(default_factory=dict)

    previous_hash: Optional[str] = None
    record_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "execution_id": self.execution_id,
            "decision_id": self.decision_id,
            "reason": self.reason,
            "triggered_by": self.triggered_by,
            "created_at": self.created_at,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
        }

    def compute_hash(self) -> str:
        return _sha256_hex(_canonical_json(self.to_dict()))


class RollbackAuditLog:
    """
    Append-only журнал rollback-аудита с хеш-цепочкой.
    Потокобезопасен.
    """

    def __init__(self) -> None:
        self._records: List[RollbackAuditRecord] = []
        self._lock = threading.Lock()

    def append(
        self,
        *,
        record_id: str,
        execution_id: str,
        decision_id: str,
        reason: str,
        triggered_by: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RollbackAuditRecord:
        with self._lock:
            prev_hash = self._records[-1].record_hash if self._records else None

            record = RollbackAuditRecord(
                record_id=record_id,
                execution_id=execution_id,
                decision_id=decision_id,
                reason=reason,
                triggered_by=triggered_by,
                created_at=_utcnow_iso(),
                metadata=metadata or {},
                previous_hash=prev_hash,
            )

            object.__setattr__(record, "record_hash", record.compute_hash())
            self._records.append(record)
            return record

    def records(self) -> Sequence[RollbackAuditRecord]:
        with self._lock:
            return tuple(self._records)

    def verify_integrity(self) -> bool:
        """
        Проверяет целостность всей цепочки.
        Возвращает False при любом нарушении.
        """
        with self._lock:
            previous_hash: Optional[str] = None
            for record in self._records:
                if record.previous_hash != previous_hash:
                    return False
                if record.compute_hash() != record.record_hash:
                    return False
                previous_hash = record.record_hash
            return True

    def export(self) -> List[Dict[str, Any]]:
        """
        Экспорт журнала для внешнего аудита.
        """
        with self._lock:
            return [
                {
                    **record.to_dict(),
                    "record_hash": record.record_hash,
                }
                for record in self._records
            ]

    @classmethod
    def import_records(cls, records: Iterable[Dict[str, Any]]) -> "RollbackAuditLog":
        """
        Импорт заранее созданного журнала.
        Используется только для проверки, не для модификации.
        """
        log = cls()
        for r in records:
            record = RollbackAuditRecord(
                record_id=r["record_id"],
                execution_id=r["execution_id"],
                decision_id=r["decision_id"],
                reason=r["reason"],
                triggered_by=r["triggered_by"],
                created_at=r["created_at"],
                metadata=r.get("metadata", {}),
                previous_hash=r.get("previous_hash"),
                record_hash=r.get("record_hash"),
            )
            log._records.append(record)
        return log
