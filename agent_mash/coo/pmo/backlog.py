# agent_mash/pmo/backlog.py
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


def _utcnow() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


def _new_id(prefix: str = "") -> str:
    return f"{prefix}{secrets.token_urlsafe(16)}" if prefix else secrets.token_urlsafe(16)


class BacklogError(RuntimeError):
    pass


class TaskNotFound(BacklogError):
    pass


class TaskConflict(BacklogError):
    pass


class TaskValidationError(BacklogError):
    pass


class TaskClaimError(BacklogError):
    pass


class TaskStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    READY = "ready"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    DONE = "done"
    CANCELLED = "cancelled"


class TaskPriority(int, Enum):
    P0 = 0
    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4


class TaskType(str, Enum):
    FEATURE = "feature"
    BUG = "bug"
    SECURITY = "security"
    OPS = "ops"
    RESEARCH = "research"
    DOCS = "docs"
    CHORE = "chore"


class TaskEventType(str, Enum):
    CREATED = "created"
    UPDATED = "updated"
    STATUS_CHANGED = "status_changed"
    CLAIMED = "claimed"
    RELEASED = "released"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    COMMENT = "comment"
    TAGS_CHANGED = "tags_changed"
    DEP_CHANGED = "dep_changed"
    SLA_CHANGED = "sla_changed"


@dataclass(frozen=True, slots=True)
class TaskEvent:
    event_id: str = field(default_factory=lambda: _new_id("ev_"))
    at: dt.datetime = field(default_factory=_utcnow)
    type: TaskEventType = TaskEventType.UPDATED
    task_id: str = ""
    actor: Optional[str] = None
    data: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TaskSLA:
    due_at: Optional[dt.datetime] = None
    warn_before_s: int = 0

    def validate(self) -> None:
        if self.warn_before_s < 0:
            raise TaskValidationError("SLA.warn_before_s must be >= 0")
        if self.due_at is not None and self.due_at.tzinfo is None:
            raise TaskValidationError("SLA.due_at must be timezone-aware UTC datetime")


@dataclass(slots=True)
class Task:
    task_id: str = field(default_factory=lambda: _new_id("tsk_"))

    title: str = ""
    description: str = ""
    type: TaskType = TaskType.CHORE

    priority: TaskPriority = TaskPriority.P3
    risk: int = 0
    cost: int = 1
    value: int = 1

    status: TaskStatus = TaskStatus.NEW

    created_at: dt.datetime = field(default_factory=_utcnow)
    updated_at: dt.datetime = field(default_factory=_utcnow)

    created_by: Optional[str] = None
    owner: Optional[str] = None
    assignee: Optional[str] = None

    capabilities: Set[str] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)

    deps: Set[str] = field(default_factory=set)
    blocked_reason: Optional[str] = None

    dedup_key: Optional[str] = None

    sla: TaskSLA = field(default_factory=TaskSLA)

    claim_token: Optional[str] = None
    claim_expires_at: Optional[dt.datetime] = None

    version: int = 1

    def validate(self) -> None:
        if not self.title or not self.title.strip():
            raise TaskValidationError("Task.title is required")
        if self.risk < 0 or self.cost < 0 or self.value < 0:
            raise TaskValidationError("Task.risk/cost/value must be >= 0")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise TaskValidationError("Task timestamps must be timezone-aware UTC datetimes")
        self.sla.validate()
        if self.claim_expires_at is not None and self.claim_expires_at.tzinfo is None:
            raise TaskValidationError("Task.claim_expires_at must be timezone-aware UTC datetime")
        if self.status == TaskStatus.BLOCKED and not (self.blocked_reason and self.blocked_reason.strip()):
            raise TaskValidationError("Blocked task must have blocked_reason")
        if self.status != TaskStatus.BLOCKED:
            self.blocked_reason = None

    def is_claimed(self, now: Optional[dt.datetime] = None) -> bool:
        if self.claim_token is None or self.claim_expires_at is None:
            return False
        now_ = now or _utcnow()
        return now_ < self.claim_expires_at

    def score(self, now: Optional[dt.datetime] = None) -> Tuple[int, int, int, int]:
        now_ = now or _utcnow()

        overdue_bucket = 2
        if self.sla.due_at is None:
            overdue_bucket = 2
        else:
            if now_ > self.sla.due_at:
                overdue_bucket = 0
            else:
                overdue_bucket = 1

        prio = int(self.priority)
        risk = -int(self.risk)
        roi = -(int(self.value) - int(self.cost))
        age_s = int((now_ - self.created_at).total_seconds())
        age = -age_s

        return (overdue_bucket, prio, risk, roi, age)


@dataclass(slots=True)
class BacklogConfig:
    persist_path: Optional[str] = None
    persist_every_n_events: int = 25
    claim_ttl_s: int = 120
    max_items: int = 100_000

    def validate(self) -> None:
        if self.persist_every_n_events < 1:
            raise TaskValidationError("persist_every_n_events must be >= 1")
        if self.claim_ttl_s < 1:
            raise TaskValidationError("claim_ttl_s must be >= 1")
        if self.max_items < 1:
            raise TaskValidationError("max_items must be >= 1")


@dataclass(slots=True)
class ClaimFilter:
    allowed_statuses: Set[TaskStatus] = field(default_factory=lambda: {TaskStatus.READY})
    required_capabilities: Set[str] = field(default_factory=set)
    include_tags: Set[str] = field(default_factory=set)
    exclude_tags: Set[str] = field(default_factory=set)
    types: Set[TaskType] = field(default_factory=set)
    priorities: Set[TaskPriority] = field(default_factory=set)


AuditSink = Callable[[TaskEvent], None]


class Backlog:
    def __init__(self, config: Optional[BacklogConfig] = None, *, audit_sink: Optional[AuditSink] = None) -> None:
        self._cfg = config or BacklogConfig()
        self._cfg.validate()

        self._audit_sink = audit_sink

        self._lock = asyncio.Lock()

        self._tasks: Dict[str, Task] = {}
        self._events: List[TaskEvent] = []
        self._events_since_persist = 0

        self._dedup_index: Dict[str, str] = {}
        self._tag_index: Dict[str, Set[str]] = {}
        self._cap_index: Dict[str, Set[str]] = {}

        self._loaded = False

    async def start(self) -> None:
        async with self._lock:
            if self._loaded:
                return
            if self._cfg.persist_path:
                await self._load_locked(self._cfg.persist_path)
            self._loaded = True

    async def snapshot(self) -> Dict[str, Any]:
        async with self._lock:
            return self._export_locked()

    async def list_ids(self) -> List[str]:
        async with self._lock:
            return list(self._tasks.keys())

    async def get(self, task_id: str) -> Task:
        async with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                raise TaskNotFound(task_id)
            return dataclasses.replace(t)

    async def upsert(self, task: Task, *, actor: Optional[str] = None) -> Task:
        task.validate()
        async with self._lock:
            if task.task_id not in self._tasks and len(self._tasks) >= self._cfg.max_items:
                raise TaskConflict("Backlog max_items limit exceeded")

            existing = self._tasks.get(task.task_id)
            if existing is None:
                now = _utcnow()
                task.created_at = now
                task.updated_at = now
                task.version = 1
                self._tasks[task.task_id] = task
                self._reindex_task_locked(task, old=None)

                self._emit_locked(TaskEvent(type=TaskEventType.CREATED, task_id=task.task_id, actor=actor, data={}))
                await self._maybe_persist_locked()
                return dataclasses.replace(task)

            if task.version < existing.version:
                raise TaskConflict("Task version is stale")

            task.version = existing.version + 1
            task.created_at = existing.created_at
            task.updated_at = _utcnow()

            self._tasks[task.task_id] = task
            self._reindex_task_locked(task, old=existing)

            self._emit_locked(
                TaskEvent(
                    type=TaskEventType.UPDATED,
                    task_id=task.task_id,
                    actor=actor,
                    data={"version": task.version},
                )
            )
            await self._maybe_persist_locked()
            return dataclasses.replace(task)

    async def create(
        self,
        *,
        title: str,
        description: str = "",
        type: TaskType = TaskType.CHORE,
        priority: TaskPriority = TaskPriority.P3,
        created_by: Optional[str] = None,
        owner: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        capabilities: Optional[Iterable[str]] = None,
        dedup_key: Optional[str] = None,
        sla_due_at: Optional[dt.datetime] = None,
        sla_warn_before_s: int = 0,
        actor: Optional[str] = None,
    ) -> Task:
        task = Task(
            title=title,
            description=description,
            type=type,
            priority=priority,
            created_by=created_by,
            owner=owner,
            tags=set(tags or []),
            capabilities=set(capabilities or []),
            dedup_key=dedup_key,
            sla=TaskSLA(due_at=sla_due_at, warn_before_s=sla_warn_before_s),
        )
        task.validate()

        async with self._lock:
            if dedup_key:
                existing_id = self._dedup_index.get(dedup_key)
                if existing_id and existing_id in self._tasks:
                    return dataclasses.replace(self._tasks[existing_id])

            if len(self._tasks) >= self._cfg.max_items:
                raise TaskConflict("Backlog max_items limit exceeded")

            self._tasks[task.task_id] = task
            self._reindex_task_locked(task, old=None)

            self._emit_locked(TaskEvent(type=TaskEventType.CREATED, task_id=task.task_id, actor=actor, data={}))
            await self._maybe_persist_locked()
            return dataclasses.replace(task)

    async def transition(
        self,
        task_id: str,
        new_status: TaskStatus,
        *,
        actor: Optional[str] = None,
        blocked_reason: Optional[str] = None,
    ) -> Task:
        async with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                raise TaskNotFound(task_id)

            old = dataclasses.replace(t)
            self._validate_transition(old.status, new_status)

            t.status = new_status
            if new_status == TaskStatus.BLOCKED:
                t.blocked_reason = blocked_reason or "blocked"
            else:
                t.blocked_reason = None

            t.claim_token = None
            t.claim_expires_at = None

            t.version += 1
            t.updated_at = _utcnow()
            t.validate()

            self._tasks[task_id] = t
            self._reindex_task_locked(t, old=old)

            self._emit_locked(
                TaskEvent(
                    type=TaskEventType.STATUS_CHANGED,
                    task_id=task_id,
                    actor=actor,
                    data={"from": old.status.value, "to": new_status.value},
                )
            )
            await self._maybe_persist_locked()
            return dataclasses.replace(t)

    async def set_tags(self, task_id: str, tags: Iterable[str], *, actor: Optional[str] = None) -> Task:
        async with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                raise TaskNotFound(task_id)
            old = dataclasses.replace(t)

            t.tags = set(tags)
            t.version += 1
            t.updated_at = _utcnow()
            t.validate()

            self._tasks[task_id] = t
            self._reindex_task_locked(t, old=old)

            self._emit_locked(
                TaskEvent(
                    type=TaskEventType.TAGS_CHANGED,
                    task_id=task_id,
                    actor=actor,
                    data={"tags": sorted(t.tags)},
                )
            )
            await self._maybe_persist_locked()
            return dataclasses.replace(t)

    async def set_deps(self, task_id: str, deps: Iterable[str], *, actor: Optional[str] = None) -> Task:
        async with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                raise TaskNotFound(task_id)
            old = dataclasses.replace(t)

            deps_set = set(deps)
            deps_set.discard(task_id)
            t.deps = deps_set
            t.version += 1
            t.updated_at = _utcnow()
            t.validate()

            self._tasks[task_id] = t
            self._reindex_task_locked(t, old=old)

            self._emit_locked(
                TaskEvent(
                    type=TaskEventType.DEP_CHANGED,
                    task_id=task_id,
                    actor=actor,
                    data={"deps": sorted(t.deps)},
                )
            )
            await self._maybe_persist_locked()
            return dataclasses.replace(t)

    async def set_sla(self, task_id: str, *, due_at: Optional[dt.datetime], warn_before_s: int = 0, actor: Optional[str] = None) -> Task:
        async with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                raise TaskNotFound(task_id)
            old = dataclasses.replace(t)

            t.sla = TaskSLA(due_at=due_at, warn_before_s=warn_before_s)
            t.version += 1
            t.updated_at = _utcnow()
            t.validate()

            self._tasks[task_id] = t
            self._reindex_task_locked(t, old=old)

            self._emit_locked(
                TaskEvent(
                    type=TaskEventType.SLA_CHANGED,
                    task_id=task_id,
                    actor=actor,
                    data={"due_at": t.sla.due_at.isoformat() if t.sla.due_at else None, "warn_before_s": t.sla.warn_before_s},
                )
            )
            await self._maybe_persist_locked()
            return dataclasses.replace(t)

    async def comment(self, task_id: str, text: str, *, actor: Optional[str] = None) -> None:
        if not text or not text.strip():
            return
        async with self._lock:
            if task_id not in self._tasks:
                raise TaskNotFound(task_id)
            self._emit_locked(
                TaskEvent(
                    type=TaskEventType.COMMENT,
                    task_id=task_id,
                    actor=actor,
                    data={"text": text.strip()},
                )
            )
            await self._maybe_persist_locked()

    async def cancel(self, task_id: str, *, actor: Optional[str] = None, reason: str = "cancelled") -> Task:
        async with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                raise TaskNotFound(task_id)
            old = dataclasses.replace(t)

            if t.status in {TaskStatus.DONE, TaskStatus.CANCELLED}:
                return dataclasses.replace(t)

            t.status = TaskStatus.CANCELLED
            t.blocked_reason = None
            t.claim_token = None
            t.claim_expires_at = None
            t.version += 1
            t.updated_at = _utcnow()
            t.validate()

            self._tasks[task_id] = t
            self._reindex_task_locked(t, old=old)

            self._emit_locked(
                TaskEvent(
                    type=TaskEventType.CANCELLED,
                    task_id=task_id,
                    actor=actor,
                    data={"reason": reason},
                )
            )
            await self._maybe_persist_locked()
            return dataclasses.replace(t)

    async def complete(self, task_id: str, *, actor: Optional[str] = None) -> Task:
        async with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                raise TaskNotFound(task_id)
            old = dataclasses.replace(t)

            if t.status == TaskStatus.DONE:
                return dataclasses.replace(t)
            self._validate_transition(t.status, TaskStatus.DONE)

            t.status = TaskStatus.DONE
            t.blocked_reason = None
            t.claim_token = None
            t.claim_expires_at = None
            t.version += 1
            t.updated_at = _utcnow()
            t.validate()

            self._tasks[task_id] = t
            self._reindex_task_locked(t, old=old)

            self._emit_locked(TaskEvent(type=TaskEventType.COMPLETED, task_id=task_id, actor=actor, data={}))
            await self._maybe_persist_locked()
            return dataclasses.replace(t)

    async def search(
        self,
        *,
        text: Optional[str] = None,
        status: Optional[Set[TaskStatus]] = None,
        tags_any: Optional[Set[str]] = None,
        caps_any: Optional[Set[str]] = None,
        types: Optional[Set[TaskType]] = None,
        priorities: Optional[Set[TaskPriority]] = None,
        limit: int = 200,
    ) -> List[Task]:
        q = (text or "").strip().lower()
        limit = max(1, int(limit))

        async with self._lock:
            ids: Optional[Set[str]] = None

            if tags_any:
                for tg in tags_any:
                    s = self._tag_index.get(tg, set())
                    ids = set(s) if ids is None else (ids | set(s))

            if caps_any:
                for cap in caps_any:
                    s = self._cap_index.get(cap, set())
                    ids = set(s) if ids is None else (ids | set(s))

            candidates = ids if ids is not None else set(self._tasks.keys())

            out: List[Task] = []
            for tid in candidates:
                t = self._tasks.get(tid)
                if t is None:
                    continue
                if status and t.status not in status:
                    continue
                if types and t.type not in types:
                    continue
                if priorities and t.priority not in priorities:
                    continue
                if q:
                    blob = f"{t.title}\n{t.description}".lower()
                    if q not in blob:
                        continue
                out.append(dataclasses.replace(t))
                if len(out) >= limit:
                    break
            return out

    async def claim_next(
        self,
        *,
        worker_id: str,
        filt: Optional[ClaimFilter] = None,
        now: Optional[dt.datetime] = None,
    ) -> Optional[Task]:
        if not worker_id or not worker_id.strip():
            raise TaskValidationError("worker_id is required")
        filt = filt or ClaimFilter()
        now_ = now or _utcnow()

        async with self._lock:
            candidates: List[Task] = []
            for t in self._tasks.values():
                if t.status not in filt.allowed_statuses:
                    continue
                if t.is_claimed(now_):
                    continue
                if t.deps:
                    if any((dep_id in self._tasks and self._tasks[dep_id].status != TaskStatus.DONE) for dep_id in t.deps):
                        continue
                if filt.required_capabilities and not filt.required_capabilities.issubset(t.capabilities):
                    continue
                if filt.include_tags and not (t.tags & filt.include_tags):
                    continue
                if filt.exclude_tags and (t.tags & filt.exclude_tags):
                    continue
                if filt.types and t.type not in filt.types:
                    continue
                if filt.priorities and t.priority not in filt.priorities:
                    continue
                candidates.append(t)

            if not candidates:
                return None

            candidates.sort(key=lambda x: x.score(now_))

            picked = candidates[0]
            token = _new_id("clm_")
            picked.claim_token = token
            picked.claim_expires_at = now_ + dt.timedelta(seconds=self._cfg.claim_ttl_s)
            picked.assignee = worker_id
            picked.status = TaskStatus.IN_PROGRESS
            picked.version += 1
            picked.updated_at = _utcnow()
            picked.validate()

            self._tasks[picked.task_id] = picked
            self._reindex_task_locked(picked, old=None)

            self._emit_locked(
                TaskEvent(
                    type=TaskEventType.CLAIMED,
                    task_id=picked.task_id,
                    actor=worker_id,
                    data={"claim_token": token, "expires_at": picked.claim_expires_at.isoformat()},
                )
            )
            await self._maybe_persist_locked()
            return dataclasses.replace(picked)

    async def release_claim(self, task_id: str, *, worker_id: str, claim_token: str, actor: Optional[str] = None) -> Task:
        async with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                raise TaskNotFound(task_id)

            if t.claim_token != claim_token or t.assignee != worker_id:
                raise TaskClaimError("Invalid claim token or worker_id")

            t.claim_token = None
            t.claim_expires_at = None
            t.assignee = None
            t.status = TaskStatus.READY
            t.version += 1
            t.updated_at = _utcnow()
            t.validate()

            self._tasks[task_id] = t
            self._emit_locked(
                TaskEvent(
                    type=TaskEventType.RELEASED,
                    task_id=task_id,
                    actor=actor or worker_id,
                    data={},
                )
            )
            await self._maybe_persist_locked()
            return dataclasses.replace(t)

    async def gc_expired_claims(self, *, now: Optional[dt.datetime] = None) -> int:
        now_ = now or _utcnow()
        async with self._lock:
            changed = 0
            for t in self._tasks.values():
                if t.claim_token and t.claim_expires_at and now_ >= t.claim_expires_at:
                    t.claim_token = None
                    t.claim_expires_at = None
                    if t.status == TaskStatus.IN_PROGRESS:
                        t.status = TaskStatus.READY
                    t.assignee = None
                    t.version += 1
                    t.updated_at = _utcnow()
                    t.validate()
                    changed += 1
                    self._emit_locked(
                        TaskEvent(
                            type=TaskEventType.RELEASED,
                            task_id=t.task_id,
                            actor="system",
                            data={"reason": "claim_expired"},
                        )
                    )
            if changed:
                await self._maybe_persist_locked()
            return changed

    async def persist(self) -> None:
        async with self._lock:
            await self._persist_locked()

    async def load(self, path: str) -> None:
        async with self._lock:
            await self._load_locked(path)
            self._loaded = True

    async def events(self, *, limit: int = 500) -> List[TaskEvent]:
        limit = max(1, int(limit))
        async with self._lock:
            return list(self._events[-limit:])

    def _emit_locked(self, ev: TaskEvent) -> None:
        self._events.append(ev)
        self._events_since_persist += 1
        if self._audit_sink:
            try:
                self._audit_sink(ev)
            except Exception:
                pass

    async def _maybe_persist_locked(self) -> None:
        if not self._cfg.persist_path:
            return
        if self._events_since_persist >= self._cfg.persist_every_n_events:
            await self._persist_locked()

    async def _persist_locked(self) -> None:
        path = self._cfg.persist_path
        if not path:
            return
        data = self._export_locked()
        self._atomic_write_json(path, data)
        self._events_since_persist = 0

    async def _load_locked(self, path: str) -> None:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        tasks_raw = raw.get("tasks", {})
        events_raw = raw.get("events", [])

        self._tasks.clear()
        self._events.clear()
        self._dedup_index.clear()
        self._tag_index.clear()
        self._cap_index.clear()

        for tid, tr in tasks_raw.items():
            t = self._task_from_dict(tr)
            if t.task_id != tid:
                t.task_id = tid
            t.validate()
            self._tasks[tid] = t
            self._reindex_task_locked(t, old=None)

        for er in events_raw[-5000:]:
            ev = self._event_from_dict(er)
            self._events.append(ev)

        self._events_since_persist = 0

    def _export_locked(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "exported_at": _utcnow().isoformat(),
            "tasks": {tid: self._task_to_dict(t) for tid, t in self._tasks.items()},
            "events": [self._event_to_dict(e) for e in self._events[-5000:]],
        }

    def _reindex_task_locked(self, task: Task, old: Optional[Task]) -> None:
        if old is not None:
            if old.dedup_key and self._dedup_index.get(old.dedup_key) == old.task_id:
                del self._dedup_index[old.dedup_key]
            for tg in old.tags:
                s = self._tag_index.get(tg)
                if s:
                    s.discard(old.task_id)
                    if not s:
                        self._tag_index.pop(tg, None)
            for cap in old.capabilities:
                s = self._cap_index.get(cap)
                if s:
                    s.discard(old.task_id)
                    if not s:
                        self._cap_index.pop(cap, None)

        if task.dedup_key:
            self._dedup_index[task.dedup_key] = task.task_id
        for tg in task.tags:
            self._tag_index.setdefault(tg, set()).add(task.task_id)
        for cap in task.capabilities:
            self._cap_index.setdefault(cap, set()).add(task.task_id)

    def _validate_transition(self, old: TaskStatus, new: TaskStatus) -> None:
        if old == new:
            return

        terminal = {TaskStatus.DONE, TaskStatus.CANCELLED}
        if old in terminal:
            raise TaskConflict(f"Cannot transition from terminal status {old.value}")

        allowed: Dict[TaskStatus, Set[TaskStatus]] = {
            TaskStatus.NEW: {TaskStatus.TRIAGED, TaskStatus.CANCELLED},
            TaskStatus.TRIAGED: {TaskStatus.READY, TaskStatus.BLOCKED, TaskStatus.CANCELLED},
            TaskStatus.READY: {TaskStatus.IN_PROGRESS, TaskStatus.BLOCKED, TaskStatus.CANCELLED},
            TaskStatus.IN_PROGRESS: {TaskStatus.BLOCKED, TaskStatus.DONE, TaskStatus.CANCELLED, TaskStatus.READY},
            TaskStatus.BLOCKED: {TaskStatus.TRIAGED, TaskStatus.READY, TaskStatus.CANCELLED},
        }
        if new not in allowed.get(old, set()):
            raise TaskConflict(f"Invalid transition {old.value} -> {new.value}")

    def _atomic_write_json(self, path: str, data: Mapping[str, Any]) -> None:
        folder = os.path.dirname(os.path.abspath(path))
        os.makedirs(folder, exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="backlog_", suffix=".tmp", dir=folder, text=True)
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def _task_to_dict(self, t: Task) -> Dict[str, Any]:
        return {
            "task_id": t.task_id,
            "title": t.title,
            "description": t.description,
            "type": t.type.value,
            "priority": int(t.priority),
            "risk": t.risk,
            "cost": t.cost,
            "value": t.value,
            "status": t.status.value,
            "created_at": t.created_at.isoformat(),
            "updated_at": t.updated_at.isoformat(),
            "created_by": t.created_by,
            "owner": t.owner,
            "assignee": t.assignee,
            "capabilities": sorted(t.capabilities),
            "tags": sorted(t.tags),
            "deps": sorted(t.deps),
            "blocked_reason": t.blocked_reason,
            "dedup_key": t.dedup_key,
            "sla": {
                "due_at": t.sla.due_at.isoformat() if t.sla.due_at else None,
                "warn_before_s": t.sla.warn_before_s,
            },
            "claim_token": t.claim_token,
            "claim_expires_at": t.claim_expires_at.isoformat() if t.claim_expires_at else None,
            "version": t.version,
        }

    def _task_from_dict(self, d: Mapping[str, Any]) -> Task:
        due = d.get("sla", {}).get("due_at") if isinstance(d.get("sla"), dict) else None
        due_at = dt.datetime.fromisoformat(due) if due else None

        ce = d.get("claim_expires_at")
        claim_expires_at = dt.datetime.fromisoformat(ce) if ce else None

        t = Task(
            task_id=str(d.get("task_id") or _new_id("tsk_")),
            title=str(d.get("title") or ""),
            description=str(d.get("description") or ""),
            type=TaskType(str(d.get("type") or TaskType.CHORE.value)),
            priority=TaskPriority(int(d.get("priority", int(TaskPriority.P3)))),
            risk=int(d.get("risk", 0)),
            cost=int(d.get("cost", 1)),
            value=int(d.get("value", 1)),
            status=TaskStatus(str(d.get("status") or TaskStatus.NEW.value)),
            created_at=dt.datetime.fromisoformat(str(d.get("created_at"))) if d.get("created_at") else _utcnow(),
            updated_at=dt.datetime.fromisoformat(str(d.get("updated_at"))) if d.get("updated_at") else _utcnow(),
            created_by=d.get("created_by"),
            owner=d.get("owner"),
            assignee=d.get("assignee"),
            capabilities=set(d.get("capabilities") or []),
            tags=set(d.get("tags") or []),
            deps=set(d.get("deps") or []),
            blocked_reason=d.get("blocked_reason"),
            dedup_key=d.get("dedup_key"),
            sla=TaskSLA(due_at=due_at, warn_before_s=int(d.get("sla", {}).get("warn_before_s", 0)) if isinstance(d.get("sla"), dict) else 0),
            claim_token=d.get("claim_token"),
            claim_expires_at=claim_expires_at,
            version=int(d.get("version", 1)),
        )
        return t

    def _event_to_dict(self, e: TaskEvent) -> Dict[str, Any]:
        return {
            "event_id": e.event_id,
            "at": e.at.isoformat(),
            "type": e.type.value,
            "task_id": e.task_id,
            "actor": e.actor,
            "data": dict(e.data),
        }

    def _event_from_dict(self, d: Mapping[str, Any]) -> TaskEvent:
        return TaskEvent(
            event_id=str(d.get("event_id") or _new_id("ev_")),
            at=dt.datetime.fromisoformat(str(d.get("at"))) if d.get("at") else _utcnow(),
            type=TaskEventType(str(d.get("type") or TaskEventType.UPDATED.value)),
            task_id=str(d.get("task_id") or ""),
            actor=d.get("actor"),
            data=dict(d.get("data") or {}),
        )
