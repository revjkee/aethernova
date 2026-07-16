# agent_mash/memory/short_term.py
from __future__ import annotations

import threading
import time
import json
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


class MemoryScope(str, Enum):
    AGENT = "agent"
    TASK = "task"
    SESSION = "session"
    GLOBAL = "global"


class MemoryEvent(str, Enum):
    PUT = "put"
    GET = "get"
    DELETE = "delete"
    EXPIRE = "expire"
    CLEAR = "clear"


@dataclass(frozen=True)
class MemoryRecord:
    key: str
    value: Any
    scope: MemoryScope
    owner: str
    created_at: str
    expires_at: Optional[str]
    version: int
    checksum: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MemoryEventRecord:
    event: MemoryEvent
    key: str
    owner: str
    scope: MemoryScope
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event"] = self.event.value
        d["scope"] = self.scope.value
        return d


class ShortTermMemory:
    """
    Industrial short-term memory implementation.

    Guarantees:
    - Thread-safe
    - TTL-based expiration
    - Deterministic versioning
    - Idempotent writes via checksum
    - Audit-ready event log
    - No external side effects
    """

    def __init__(self, *, max_items: int = 10_000, default_ttl_s: int = 300) -> None:
        self._max_items = max_items
        self._default_ttl_s = default_ttl_s

        self._store: Dict[str, MemoryRecord] = {}
        self._events: List[MemoryEventRecord] = []
        self._lock = threading.RLock()

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _checksum(value: Any) -> str:
        try:
            raw = json.dumps(value, sort_keys=True, ensure_ascii=False)
        except Exception:
            raw = repr(value)
        h = hashlib.sha256()
        h.update(raw.encode("utf-8", errors="replace"))
        return h.hexdigest()

    def _emit(
        self,
        event: MemoryEvent,
        *,
        key: str,
        owner: str,
        scope: MemoryScope,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._events.append(
            MemoryEventRecord(
                event=event,
                key=key,
                owner=owner,
                scope=scope,
                timestamp=self._utc_now(),
                details=details or {},
            )
        )

    def _is_expired(self, record: MemoryRecord) -> bool:
        if record.expires_at is None:
            return False
        return record.expires_at <= self._utc_now()

    def _enforce_limits(self) -> None:
        if len(self._store) <= self._max_items:
            return
        sorted_items = sorted(
            self._store.values(),
            key=lambda r: r.created_at,
        )
        overflow = len(self._store) - self._max_items
        for rec in sorted_items[:overflow]:
            del self._store[rec.key]
            self._emit(
                MemoryEvent.EXPIRE,
                key=rec.key,
                owner=rec.owner,
                scope=rec.scope,
                details={"reason": "capacity_limit"},
            )

    def put(
        self,
        key: str,
        value: Any,
        *,
        owner: str,
        scope: MemoryScope = MemoryScope.AGENT,
        ttl_s: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryRecord:
        if not key or not owner:
            raise ValueError("key and owner must be non-empty")

        with self._lock:
            now = self._utc_now()
            ttl = self._default_ttl_s if ttl_s is None else max(0, int(ttl_s))
            expires_at = None if ttl == 0 else datetime.fromisoformat(now).replace(
                tzinfo=timezone.utc
            )
            if ttl > 0:
                expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()

            checksum = self._checksum(value)
            prev = self._store.get(key)

            if prev and prev.checksum == checksum and not self._is_expired(prev):
                return prev

            version = 1 if prev is None else prev.version + 1

            record = MemoryRecord(
                key=key,
                value=value,
                scope=scope,
                owner=owner,
                created_at=now,
                expires_at=expires_at,
                version=version,
                checksum=checksum,
                metadata=metadata or {},
            )

            self._store[key] = record
            self._emit(
                MemoryEvent.PUT,
                key=key,
                owner=owner,
                scope=scope,
                details={"version": version},
            )
            self._enforce_limits()
            return record

    def get(self, key: str, *, owner: Optional[str] = None) -> Optional[MemoryRecord]:
        with self._lock:
            rec = self._store.get(key)
            if rec is None:
                return None

            if self._is_expired(rec):
                del self._store[key]
                self._emit(
                    MemoryEvent.EXPIRE,
                    key=key,
                    owner=rec.owner,
                    scope=rec.scope,
                    details={"reason": "ttl"},
                )
                return None

            if owner is not None and rec.owner != owner:
                return None

            self._emit(
                MemoryEvent.GET,
                key=key,
                owner=rec.owner,
                scope=rec.scope,
            )
            return rec

    def delete(self, key: str, *, owner: Optional[str] = None) -> bool:
        with self._lock:
            rec = self._store.get(key)
            if rec is None:
                return False
            if owner is not None and rec.owner != owner:
                return False

            del self._store[key]
            self._emit(
                MemoryEvent.DELETE,
                key=key,
                owner=rec.owner,
                scope=rec.scope,
            )
            return True

    def clear(self, *, owner: Optional[str] = None) -> int:
        with self._lock:
            keys = list(self._store.keys())
            removed = 0
            for k in keys:
                rec = self._store.get(k)
                if rec is None:
                    continue
                if owner is not None and rec.owner != owner:
                    continue
                del self._store[k]
                removed += 1
                self._emit(
                    MemoryEvent.CLEAR,
                    key=k,
                    owner=rec.owner,
                    scope=rec.scope,
                )
            return removed

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "created_at": self._utc_now(),
                "items": [r.to_dict() for r in self._store.values()],
            }

    def events(self, *, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._lock:
            ev = self._events[-limit:] if limit else self._events
            return [e.to_dict() for e in ev]


__all__ = [
    "MemoryScope",
    "MemoryEvent",
    "MemoryRecord",
    "MemoryEventRecord",
    "ShortTermMemory",
]
