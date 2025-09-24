# -*- coding: utf-8 -*-
"""
Simple, production-grade task queue interface with two backends:
- InMemoryQueue: for tests and single-process usage
- SQLiteQueue  : durable, multi-process safe, transactional

Core semantics:
- enqueue(payload, priority, delay, dedup_key, max_attempts)
- dequeue(max_messages, visibility_timeout) -> reserved tasks
- ack(task_id, consumer_id)     : marks task as done
- nack(task_id, consumer_id, requeue=True, delay=None) : requeue or dead-letter
- extend(task_id, consumer_id, extra_seconds)          : extend visibility
- peek / stats / purge

Visibility: tasks returned by dequeue are moved to "reserved" and hidden until
reserved_until. If not acked in time, they return to "ready" on next dequeue.

Deduplication: optional dedup_key prevents multiple "active" copies (ready/reserved).

Dead-letter: after max_attempts, nack(requeue=True) places task to "dead".

Backoff: exponential with jitter by default if delay is None on nack.

No third-party dependencies. Python 3.9+.

Author: automation-core
"""

from __future__ import annotations

import json
import os
import random
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, Union


# ----------------------------- Exceptions & Types -----------------------------

class QueueError(Exception):
    """Generic queue error."""


class TaskNotFound(QueueError):
    """Task not found or not in expected state."""


class VisibilityError(QueueError):
    """Consumer attempted an operation without holding the reservation."""


Payload = Union[bytes, str, dict, list]


@dataclass(frozen=True)
class Task:
    id: str
    payload: Payload
    priority: int
    attempts: int
    max_attempts: int
    dedup_key: Optional[str]
    available_at: int
    reserved_until: Optional[int]
    inserted_at: int
    state: str               # 'ready' | 'reserved' | 'done' | 'dead'
    consumer_id: Optional[str]


# ----------------------------- Queue Interface --------------------------------

class TaskQueue(Protocol):
    """Simple task queue interface."""

    # Producer API
    def enqueue(
        self,
        payload: Payload,
        *,
        priority: int = 0,
        delay: int = 0,
        dedup_key: Optional[str] = None,
        max_attempts: int = 5,
    ) -> Task:
        ...

    # Consumer API
    def dequeue(
        self,
        *,
        max_messages: int = 1,
        visibility_timeout: int = 30,
        consumer_id: Optional[str] = None,
    ) -> List[Task]:
        ...

    def ack(self, task_id: str, consumer_id: str) -> bool:
        ...

    def nack(
        self,
        task_id: str,
        consumer_id: str,
        *,
        requeue: bool = True,
        delay: Optional[int] = None,
    ) -> bool:
        ...

    def extend(self, task_id: str, consumer_id: str, extra_seconds: int) -> bool:
        ...

    # Introspection
    def peek(self, n: int = 10) -> List[Task]:
        ...

    def stats(self) -> Dict[str, Any]:
        ...

    def purge(self, *, state: Optional[str] = None) -> int:
        ...

    def close(self) -> None:
        ...


# ----------------------------- Utility helpers --------------------------------

def _now() -> int:
    return int(time.time())


def _gen_id() -> str:
    return uuid.uuid4().hex


def _ensure_payload(p: Payload) -> Payload:
    # Ensure payload is JSON-serialisable for SQLite backend; allow bytes for InMemory
    if isinstance(p, (dict, list, str, bytes)):
        return p
    raise ValueError("Unsupported payload type; use dict/list/str/bytes")


def _backoff_delay(attempts: int, base: int = 5, cap: int = 300) -> int:
    # Exponential backoff with jitter: base * 2^(attempts-1) +/- 20%, capped
    exp = base * (2 ** max(0, attempts - 1))
    exp = min(exp, cap)
    jitter = int(exp * random.uniform(-0.2, 0.2))
    return max(1, exp + jitter)


# ----------------------------- In-memory backend ------------------------------

class InMemoryQueue(TaskQueue):
    """
    Non-persistent queue, safe for single-process tests.
    Thread-safe via a lock. Not for multi-process usage.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tasks: Dict[str, Task] = {}

    def enqueue(
        self,
        payload: Payload,
        *,
        priority: int = 0,
        delay: int = 0,
        dedup_key: Optional[str] = None,
        max_attempts: int = 5,
    ) -> Task:
        with self._lock:
            now = _now()
            if dedup_key:
                for t in self._tasks.values():
                    if t.dedup_key == dedup_key and t.state in ("ready", "reserved"):
                        return t  # idempotent
            tid = _gen_id()
            t = Task(
                id=tid,
                payload=_ensure_payload(payload),
                priority=int(priority),
                attempts=0,
                max_attempts=int(max_attempts),
                dedup_key=dedup_key,
                available_at=now + max(0, int(delay)),
                reserved_until=None,
                inserted_at=now,
                state="ready",
                consumer_id=None,
            )
            self._tasks[tid] = t
            return t

    def dequeue(
        self,
        *,
        max_messages: int = 1,
        visibility_timeout: int = 30,
        consumer_id: Optional[str] = None,
    ) -> List[Task]:
        with self._lock:
            now = _now()
            cid = consumer_id or _gen_id()
            ready = [
                t for t in self._tasks.values()
                if t.state == "ready" and t.available_at <= now
            ]
            # order by priority desc, inserted_at asc
            ready.sort(key=lambda x: (-x.priority, x.inserted_at))
            picked = ready[: max(1, int(max_messages))]
            out: List[Task] = []
            for t in picked:
                rt = Task(
                    id=t.id,
                    payload=t.payload,
                    priority=t.priority,
                    attempts=t.attempts,  # attempts increase on nack/failure, not on reservation
                    max_attempts=t.max_attempts,
                    dedup_key=t.dedup_key,
                    available_at=t.available_at,
                    reserved_until=now + max(1, int(visibility_timeout)),
                    inserted_at=t.inserted_at,
                    state="reserved",
                    consumer_id=cid,
                )
                self._tasks[t.id] = rt
                out.append(rt)
            return out

    def _get_reserved(self, task_id: str, consumer_id: str) -> Task:
        t = self._tasks.get(task_id)
        if not t:
            raise TaskNotFound(task_id)
        if t.state != "reserved" or t.consumer_id != consumer_id or (t.reserved_until or 0) < _now():
            raise VisibilityError(f"Reservation lost for task {task_id}")
        return t

    def ack(self, task_id: str, consumer_id: str) -> bool:
        with self._lock:
            _ = self._get_reserved(task_id, consumer_id)
            t = self._tasks[task_id]
            self._tasks[task_id] = Task(**{**asdict(t), "state": "done"})
            return True

    def nack(
        self,
        task_id: str,
        consumer_id: str,
        *,
        requeue: bool = True,
        delay: Optional[int] = None,
    ) -> bool:
        with self._lock:
            t = self._get_reserved(task_id, consumer_id)
            attempts = t.attempts + 1
            if not requeue or attempts >= t.max_attempts:
                # move to dead
                self._tasks[task_id] = Task(**{**asdict(t), "state": "dead", "attempts": attempts, "consumer_id": None, "reserved_until": None})
                return True
            next_delay = delay if delay is not None else _backoff_delay(attempts)
            now = _now()
            self._tasks[task_id] = Task(
                **{
                    **asdict(t),
                    "state": "ready",
                    "attempts": attempts,
                    "available_at": now + int(next_delay),
                    "consumer_id": None,
                    "reserved_until": None,
                }
            )
            return True

    def extend(self, task_id: str, consumer_id: str, extra_seconds: int) -> bool:
        with self._lock:
            t = self._get_reserved(task_id, consumer_id)
            self._tasks[task_id] = Task(
                **{**asdict(t), "reserved_until": (t.reserved_until or _now()) + max(1, int(extra_seconds))}
            )
            return True

    def peek(self, n: int = 10) -> List[Task]:
        with self._lock:
            now = _now()
            ready = [t for t in self._tasks.values() if t.state == "ready" and t.available_at <= now]
            ready.sort(key=lambda x: (-x.priority, x.inserted_at))
            return ready[: max(1, int(n))]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            s = {"ready": 0, "reserved": 0, "done": 0, "dead": 0, "total": len(self._tasks)}
            for t in self._tasks.values():
                s[t.state] += 1
            return s

    def purge(self, *, state: Optional[str] = None) -> int:
        with self._lock:
            if state is None:
                n = len(self._tasks)
                self._tasks.clear()
                return n
            keys = [k for k, v in self._tasks.items() if v.state == state]
            for k in keys:
                del self._tasks[k]
            return len(keys)

    def close(self) -> None:
        pass


# ----------------------------- SQLite backend ---------------------------------

class SQLiteQueue(TaskQueue):
    """
    Durable queue backed by SQLite. Safe for multi-process access.

    Database setup:
      - journal_mode = WAL
      - busy_timeout  = 5000 ms
      - foreign_keys  = ON

    Table 'queue':
      id TEXT PRIMARY KEY,
      payload TEXT,                 -- JSON-encoded
      priority INTEGER NOT NULL,
      attempts INTEGER NOT NULL,
      max_attempts INTEGER NOT NULL,
      dedup_key TEXT,
      available_at INTEGER NOT NULL,
      reserved_until INTEGER,
      inserted_at INTEGER NOT NULL,
      state TEXT NOT NULL,          -- ready|reserved|done|dead
      consumer_id TEXT

    Indexes:
      - ready_idx for dequeue ordering
      - dedup_active unique partial index (if supported) to prevent duplicates
    """

    def __init__(self, db_path: Union[str, Path]) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), timeout=5, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA busy_timeout=5000;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._ensure_schema()
        self._lock = threading.RLock()

    # --- schema ---

    def _ensure_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS queue (
                id TEXT PRIMARY KEY,
                payload TEXT,
                priority INTEGER NOT NULL,
                attempts INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                dedup_key TEXT,
                available_at INTEGER NOT NULL,
                reserved_until INTEGER,
                inserted_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                consumer_id TEXT
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_queue_ready ON queue(state, available_at, priority, inserted_at);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_queue_dedup ON queue(dedup_key);")
        # Partial unique index for active dedup (SQLite >= 3.8.0 supports partial indexes)
        try:
            cur.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_queue_dedup_active "
                "ON queue(dedup_key) WHERE dedup_key IS NOT NULL AND state IN ('ready','reserved');"
            )
        except sqlite3.OperationalError:
            # Older SQLite without partial unique indexes: we will emulate via transactional check.
            pass
        self._conn.commit()

    # --- helpers ---

    def _json_dump(self, payload: Payload) -> str:
        if isinstance(payload, bytes):
            # store bytes as base64 string with a small envelope
            return json.dumps({"__bytes__": True, "b64": payload.hex()})
        return json.dumps(payload)

    def _json_load(self, s: str) -> Payload:
        obj = json.loads(s)
        if isinstance(obj, dict) and obj.get("__bytes__") is True and "b64" in obj:
            try:
                return bytes.fromhex(str(obj["b64"]))
            except Exception:
                return b""
        return obj

    def _row_to_task(self, row: sqlite3.Row) -> Task:
        return Task(
            id=row["id"],
            payload=self._json_load(row["payload"]) if row["payload"] is not None else None,
            priority=row["priority"],
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            dedup_key=row["dedup_key"],
            available_at=row["available_at"],
            reserved_until=row["reserved_until"],
            inserted_at=row["inserted_at"],
            state=row["state"],
            consumer_id=row["consumer_id"],
        )

    # --- API impl ---

    def enqueue(
        self,
        payload: Payload,
        *,
        priority: int = 0,
        delay: int = 0,
        dedup_key: Optional[str] = None,
        max_attempts: int = 5,
    ) -> Task:
        with self._lock:
            now = _now()
            available_at = now + max(0, int(delay))
            tid = _gen_id()
            payload = _ensure_payload(payload)
            j = self._json_dump(payload)
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE;")
                if dedup_key:
                    # Try active dedup optimistic check
                    cur.execute(
                        "SELECT * FROM queue WHERE dedup_key=? AND state IN ('ready','reserved') LIMIT 1;",
                        (dedup_key,),
                    )
                    row = cur.fetchone()
                    if row:
                        self._conn.commit()
                        # Return existing active task
                        self._conn.row_factory = sqlite3.Row
                        return self._row_to_task(row)
                cur.execute(
                    """
                    INSERT INTO queue(id, payload, priority, attempts, max_attempts, dedup_key,
                                      available_at, reserved_until, inserted_at, state, consumer_id)
                    VALUES (?, ?, ?, 0, ?, ?, ?, NULL, ?, 'ready', NULL);
                    """,
                    (tid, j, int(priority), int(max_attempts), dedup_key, int(available_at), now),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            # Fetch back for uniform return
            self._conn.row_factory = sqlite3.Row
            cur = self._conn.execute("SELECT * FROM queue WHERE id=?;", (tid,))
            return self._row_to_task(cur.fetchone())

    def dequeue(
        self,
        *,
        max_messages: int = 1,
        visibility_timeout: int = 30,
        consumer_id: Optional[str] = None,
    ) -> List[Task]:
        with self._lock:
            now = _now()
            cid = consumer_id or _gen_id()
            limit = max(1, int(max_messages))
            vt = max(1, int(visibility_timeout))
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE;")
                # Pick candidate ids atomically
                cur.execute(
                    """
                    SELECT id FROM queue
                    WHERE state='ready' AND available_at<=?
                    ORDER BY priority DESC, inserted_at ASC
                    LIMIT ?;
                    """,
                    (now, limit),
                )
                ids = [r[0] for r in cur.fetchall()]
                if not ids:
                    self._conn.commit()
                    return []
                # Reserve them
                qmarks = ",".join("?" for _ in ids)
                cur.execute(
                    f"""
                    UPDATE queue
                    SET state='reserved', consumer_id=?, reserved_until=?
                    WHERE id IN ({qmarks}) AND state='ready';
                    """,
                    (cid, now + vt, *ids),
                )
                # Read back rows
                self._conn.row_factory = sqlite3.Row
                cur = self._conn.execute(
                    f"SELECT * FROM queue WHERE id IN ({qmarks});",
                    (*ids,),
                )
                rows = cur.fetchall()
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

            return [self._row_to_task(r) for r in rows if r["state"] == "reserved" and r["consumer_id"] == cid]

    def _get_reserved(self, task_id: str, consumer_id: str) -> sqlite3.Row:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute("SELECT * FROM queue WHERE id=?;", (task_id,))
        row = cur.fetchone()
        if not row:
            raise TaskNotFound(task_id)
        if row["state"] != "reserved" or row["consumer_id"] != consumer_id or (row["reserved_until"] or 0) < _now():
            raise VisibilityError(f"Reservation lost for task {task_id}")
        return row

    def ack(self, task_id: str, consumer_id: str) -> bool:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE;")
                _ = self._get_reserved(task_id, consumer_id)
                self._conn.execute(
                    "UPDATE queue SET state='done', consumer_id=NULL, reserved_until=NULL WHERE id=?;",
                    (task_id,),
                )
                self._conn.commit()
                return True
            except Exception:
                self._conn.rollback()
                raise

    def nack(
        self,
        task_id: str,
        consumer_id: str,
        *,
        requeue: bool = True,
        delay: Optional[int] = None,
    ) -> bool:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE;")
                row = self._get_reserved(task_id, consumer_id)
                attempts = int(row["attempts"]) + 1
                if not requeue or attempts >= int(row["max_attempts"]):
                    self._conn.execute(
                        "UPDATE queue SET state='dead', attempts=?, consumer_id=NULL, reserved_until=NULL WHERE id=?;",
                        (attempts, task_id),
                    )
                else:
                    next_delay = int(delay) if delay is not None else _backoff_delay(attempts)
                    self._conn.execute(
                        """
                        UPDATE queue
                        SET state='ready',
                            attempts=?,
                            available_at=?,
                            consumer_id=NULL,
                            reserved_until=NULL
                        WHERE id=?;
                        """,
                        (attempts, _now() + next_delay, task_id),
                    )
                self._conn.commit()
                return True
            except Exception:
                self._conn.rollback()
                raise

    def extend(self, task_id: str, consumer_id: str, extra_seconds: int) -> bool:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE;")
                _ = self._get_reserved(task_id, consumer_id)
                self._conn.execute(
                    "UPDATE queue SET reserved_until=COALESCE(reserved_until, ?) + ? WHERE id=?;",
                    (_now(), max(1, int(extra_seconds)), task_id),
                )
                self._conn.commit()
                return True
            except Exception:
                self._conn.rollback()
                raise

    def peek(self, n: int = 10) -> List[Task]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            """
            SELECT * FROM queue
            WHERE state='ready' AND available_at<=?
            ORDER BY priority DESC, inserted_at ASC
            LIMIT ?;
            """,
            (_now(), max(1, int(n))),
        )
        return [self._row_to_task(r) for r in cur.fetchall()]

    def stats(self) -> Dict[str, Any]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            "SELECT state, COUNT(*) AS cnt FROM queue GROUP BY state;"
        )
        rows = cur.fetchall()
        out = {"ready": 0, "reserved": 0, "done": 0, "dead": 0, "total": 0}
        for r in rows:
            out[r["state"]] = int(r["cnt"])
            out["total"] += int(r["cnt"])
        return out

    def purge(self, *, state: Optional[str] = None) -> int:
        if state is None:
            cur = self._conn.execute("DELETE FROM queue;")
            return cur.rowcount if cur.rowcount is not None else 0
        if state not in ("ready", "reserved", "done", "dead"):
            raise ValueError("Invalid state for purge")
        cur = self._conn.execute("DELETE FROM queue WHERE state=?;", (state,))
        return cur.rowcount if cur.rowcount is not None else 0

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


# ----------------------------- Factory & __all__ ------------------------------

def open_queue(kind: str = "sqlite", **kwargs: Any) -> TaskQueue:
    """
    Factory:
      - kind='sqlite', kwargs: db_path=Path|str
      - kind='memory'
    """
    if kind == "sqlite":
        db_path = kwargs.get("db_path") or os.environ.get("AUTOMATION_CORE_QUEUE_DB", ":memory:")
        return SQLiteQueue(db_path)
    if kind == "memory":
        return InMemoryQueue()
    raise ValueError("Unknown queue kind")


__all__ = [
    "Task",
    "TaskQueue",
    "InMemoryQueue",
    "SQLiteQueue",
    "open_queue",
    "QueueError",
    "TaskNotFound",
    "VisibilityError",
]
