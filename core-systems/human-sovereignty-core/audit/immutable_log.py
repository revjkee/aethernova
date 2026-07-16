# human-sovereignty-core/audit/immutable_log.py
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Final, Iterable, List, Mapping


class ImmutableLogError(RuntimeError):
    pass


class IntegrityError(ImmutableLogError):
    pass


_SAFE_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_.\-]{1,128}$")


def _now_unix() -> float:
    return time.time()


def _canonical_json(obj: Any) -> str:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _require_safe_key(key: str) -> None:
    if not _SAFE_KEY_RE.fullmatch(key):
        raise ImmutableLogError(f"Unsafe key name: {key!r}")


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """
    Single immutable audit log entry.

    Fields:
    - index: monotonically increasing position
    - timestamp_unix: creation time
    - payload: structured audit data
    - prev_hash: hash of previous entry
    - entry_hash: hash of this entry
    """

    index: int
    timestamp_unix: float
    payload: Mapping[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp_unix": self.timestamp_unix,
            "payload": dict(self.payload),
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


class ImmutableAuditLog:
    """
    Append-only immutable audit log with hash chaining.

    Security properties:
    - Any modification breaks the hash chain
    - Deterministic serialization
    - Explicit integrity verification
    """

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def _compute_entry_hash(
        self,
        *,
        index: int,
        timestamp_unix: float,
        payload: Mapping[str, Any],
        prev_hash: str,
    ) -> str:
        for k in payload.keys():
            _require_safe_key(str(k))

        data = {
            "index": index,
            "timestamp_unix": timestamp_unix,
            "payload": payload,
            "prev_hash": prev_hash,
        }
        return _sha256_hex(_canonical_json(data))

    def append(self, payload: Mapping[str, Any]) -> AuditEntry:
        """
        Append a new audit entry.
        """
        index = len(self._entries)
        timestamp_unix = _now_unix()
        prev_hash = self._entries[-1].entry_hash if self._entries else "GENESIS"

        entry_hash = self._compute_entry_hash(
            index=index,
            timestamp_unix=timestamp_unix,
            payload=payload,
            prev_hash=prev_hash,
        )

        entry = AuditEntry(
            index=index,
            timestamp_unix=timestamp_unix,
            payload=dict(payload),
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

        self._entries.append(entry)
        return entry

    def verify_integrity(self) -> None:
        """
        Verify the full hash chain.
        """
        prev_hash = "GENESIS"
        for idx, entry in enumerate(self._entries):
            if entry.index != idx:
                raise IntegrityError("Index mismatch in audit log")

            expected_hash = self._compute_entry_hash(
                index=entry.index,
                timestamp_unix=entry.timestamp_unix,
                payload=entry.payload,
                prev_hash=prev_hash,
            )

            if expected_hash != entry.entry_hash:
                raise IntegrityError(f"Hash mismatch at index {idx}")

            prev_hash = entry.entry_hash

    def to_list(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._entries]

    def to_json(self) -> str:
        return _canonical_json(self.to_list())

    @classmethod
    def from_list(cls, items: Iterable[Mapping[str, Any]]) -> "ImmutableAuditLog":
        log = cls()
        for item in items:
            entry = AuditEntry(
                index=int(item["index"]),
                timestamp_unix=float(item["timestamp_unix"]),
                payload=dict(item["payload"]),
                prev_hash=str(item["prev_hash"]),
                entry_hash=str(item["entry_hash"]),
            )
            log._entries.append(entry)

        log.verify_integrity()
        return log

    @classmethod
    def from_json(cls, text: str) -> "ImmutableAuditLog":
        try:
            data = json.loads(text)
        except Exception as exc:
            raise ImmutableLogError("Invalid JSON") from exc

        if not isinstance(data, list):
            raise ImmutableLogError("Audit log JSON must be a list")

        return cls.from_list(data)


__all__ = [
    "ImmutableLogError",
    "IntegrityError",
    "AuditEntry",
    "ImmutableAuditLog",
]
