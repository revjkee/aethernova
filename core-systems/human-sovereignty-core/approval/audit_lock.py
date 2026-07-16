# human-sovereignty-core/approval/audit_lock.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import platform
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# =========================
# Constants and guarantees
# =========================

AUDIT_VERSION = "1.0.0"
HASH_ALGORITHM = "sha256"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


# =========================
# Data model
# =========================

@dataclass(frozen=True)
class AuditRecord:
    index: int
    created_utc: str
    record_type: str
    subject_id: str
    payload_sha256: str
    approver_anchor_id: str
    previous_hash: str
    record_hash: str
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class AuditAppendResult:
    record: AuditRecord
    ledger_size: int


# =========================
# Utility
# =========================

def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).strftime(TIME_FORMAT)


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def _sha256_file(path: Path, max_bytes: int = 64 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 256)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("Audit ledger file too large")
            h.update(chunk)
    return h.hexdigest()


# =========================
# Audit Ledger
# =========================

class AuditLedger:
    """
    Append-only audit ledger with hash chaining.
    Thread-safe for single-process usage.
    """

    def __init__(self, ledger_path: Path):
        self._path = ledger_path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

        if not self._path.exists():
            self._initialize_ledger()

    def _initialize_ledger(self) -> None:
        genesis = {
            "version": AUDIT_VERSION,
            "hash_algorithm": HASH_ALGORITHM,
            "created_utc": _utc_now_iso(),
            "system": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
            "records": [],
        }
        self._path.write_text(
            json.dumps(genesis, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )

    def _load(self) -> Dict[str, Any]:
        return json.loads(self._path.read_text(encoding="utf-8"))

    def _save(self, data: Dict[str, Any]) -> None:
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, self._path)

    def _last_record_hash(self, records: List[Dict[str, Any]]) -> str:
        if not records:
            return "0" * 64
        return records[-1]["record_hash"]

    def append(
        self,
        record_type: str,
        subject_id: str,
        payload_sha256: str,
        approver_anchor_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditAppendResult:
        """
        Append a new audit record.
        """
        if metadata is None:
            metadata = {}

        with self._lock:
            ledger = self._load()
            records: List[Dict[str, Any]] = ledger.get("records", [])

            index = len(records)
            created_utc = _utc_now_iso()
            previous_hash = self._last_record_hash(records)

            record_body = {
                "index": index,
                "created_utc": created_utc,
                "record_type": record_type,
                "subject_id": subject_id,
                "payload_sha256": payload_sha256,
                "approver_anchor_id": approver_anchor_id,
                "previous_hash": previous_hash,
                "metadata": metadata,
            }

            record_hash = _sha256_bytes(_canonical_json(record_body))
            record_body["record_hash"] = record_hash

            records.append(record_body)
            ledger["records"] = records
            ledger["last_updated_utc"] = created_utc

            self._save(ledger)

            return AuditAppendResult(
                record=AuditRecord(**record_body),
                ledger_size=len(records),
            )

    def verify_integrity(self) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Verify full ledger integrity.
        Returns (ok, errors).
        """
        errors: List[Dict[str, Any]] = []
        ledger = self._load()
        records = ledger.get("records", [])

        prev_hash = "0" * 64
        for i, r in enumerate(records):
            body = dict(r)
            stored_hash = body.pop("record_hash", None)

            expected = _sha256_bytes(_canonical_json(body))
            if stored_hash != expected:
                errors.append(
                    {
                        "index": i,
                        "error": "hash_mismatch",
                        "expected": expected,
                        "actual": stored_hash,
                    }
                )

            if body.get("previous_hash") != prev_hash:
                errors.append(
                    {
                        "index": i,
                        "error": "previous_hash_mismatch",
                        "expected": prev_hash,
                        "actual": body.get("previous_hash"),
                    }
                )

            prev_hash = stored_hash

        return (len(errors) == 0), errors


# =========================
# Public API
# =========================

def lock_approval(
    ledger_path: Path,
    decision_packet_id: str,
    payload_sha256: str,
    approver_anchor_id: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditAppendResult:
    """
    High-level helper to lock a human approval into the audit ledger.
    """
    ledger = AuditLedger(ledger_path)
    return ledger.append(
        record_type="human_approval",
        subject_id=decision_packet_id,
        payload_sha256=payload_sha256,
        approver_anchor_id=approver_anchor_id,
        metadata=metadata,
    )


def verify_audit_ledger(ledger_path: Path) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Verify audit ledger integrity.
    """
    ledger = AuditLedger(ledger_path)
    return ledger.verify_integrity()
