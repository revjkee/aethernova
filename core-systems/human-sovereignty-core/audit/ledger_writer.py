# human-sovereignty-core/audit/ledger_writer.py

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional


class AuditLedgerError(Exception):
    """Base error for audit ledger."""


class AuditLedgerWriteError(AuditLedgerError):
    """Raised when an audit record cannot be written."""


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _iso(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class AuditEvent:
    """
    Canonical audit event.

    Each event is chained with previous_hash to ensure immutability.
    """

    event_id: str
    event_type: str
    created_at_utc: str
    payload: Dict[str, Any]
    previous_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "created_at_utc": self.created_at_utc,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
        }
        return {k: v for k, v in d.items() if v is not None}

    def compute_hash(self) -> str:
        return _sha256_hex(_canonical_json(self.to_dict()))


class LedgerWriter:
    """
    Append-only audit ledger with hash chaining.

    Properties:
    - Thread-safe
    - Atomic append
    - Deterministic hashing
    """

    def __init__(self, *, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def _read_last_hash(self) -> Optional[str]:
        if not os.path.exists(self._path):
            return None

        try:
            with open(self._path, "rb") as f:
                lines = f.read().splitlines()
                if not lines:
                    return None
                last = json.loads(lines[-1].decode("utf-8"))
                return last.get("event_hash")
        except Exception:
            return None

    def append(
        self,
        *,
        event_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        now: Optional[_dt.datetime] = None,
    ) -> str:
        """
        Append a new audit event.

        Returns event_hash.
        """
        with self._lock:
            prev_hash = self._read_last_hash()
            evt = AuditEvent(
                event_id=str(event_id),
                event_type=str(event_type),
                created_at_utc=_iso(now or _utc_now()),
                payload=dict(payload),
                previous_hash=prev_hash,
            )
            evt_hash = evt.compute_hash()

            record = {
                **evt.to_dict(),
                "event_hash": evt_hash,
            }

            data = _canonical_json(record) + b"\n"

            try:
                with open(self._path, "ab") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                raise AuditLedgerWriteError("Failed to append audit record") from e

            return evt_hash
