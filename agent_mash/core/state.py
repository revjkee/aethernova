# agent_mash/core/state.py
# Industrial-grade agent state management (async-safe) with revisioning, transitions,
# optional atomic file persistence, TTL handling, and per-key locking.
#
# Designed for:
# - concurrent async workloads
# - deterministic state transitions
# - optimistic concurrency control (expected revision)
# - snapshot/restore
# - safe serialization (JSON)
#
# No external dependencies.

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    runtime_checkable,
)

__all__ = [
    "AgentLifecycleState",
    "StateError",
    "StateConflictError",
    "StateNotFoundError",
    "StateValidationError",
    "AgentState",
    "StatePatch",
    "TransitionPolicy",
    "StateStore",
    "InMemoryStateStore",
    "FileStateStore",
    "StateService",
]

JsonValue = Union[None, bool, int, float, str, Sequence["JsonValue"], Mapping[str, "JsonValue"]]


class AgentLifecycleState(str, Enum):
    """
    Canonical lifecycle states for an agent.

    You can extend these states, but keep transitions controlled via TransitionPolicy.
    """
    NEW = "new"
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    PAUSED = "paused"
    DEGRADED = "degraded"
    FAILED = "failed"
    STOPPED = "stopped"
    ARCHIVED = "archived"


class StateError(RuntimeError):
    """Base error for state subsystem."""


class StateNotFoundError(StateError):
    """State key was not found."""


class StateConflictError(StateError):
    """Revision conflict (optimistic concurrency failure)."""


class StateValidationError(StateError):
    """State model or transition validation failed."""


def _now_ms() -> int:
    return int(time.time() * 1000)


def _deep_merge(dst: MutableMapping[str, Any], src: Mapping[str, Any]) -> MutableMapping[str, Any]:
    """
    Deep merge dictionaries:
    - if both values are dicts => merge recursively
    - else => overwrite
    """
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)  # type: ignore[index]
        else:
            dst[k] = v
    return dst


def _ensure_jsonable(value: Any, *, path: str = "$") -> None:
    """
    Fail fast if value cannot be JSON-serialized reliably.
    """
    try:
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except TypeError as e:
        raise StateValidationError(f"Non-JSON-serializable value at {path}: {e}") from e


@dataclass(frozen=True, slots=True)
class StatePatch:
    """
    Atomic patch request.
    - set_state: move lifecycle state
    - merge_context: deep merge into context
    - set_context: overwrite context entirely
    - set_meta: overwrite/merge meta fields
    - ttl_ms: set/clear TTL (None clears expiry)
    """
    set_state: Optional[AgentLifecycleState] = None
    merge_context: Optional[Mapping[str, Any]] = None
    set_context: Optional[Mapping[str, Any]] = None
    set_meta: Optional[Mapping[str, Any]] = None
    merge_meta: Optional[Mapping[str, Any]] = None
    ttl_ms: Optional[int] = None


@dataclass(slots=True)
class AgentState:
    """
    Durable state record for a single agent instance.

    revision:
      - incremented on every successful mutation
      - used for optimistic concurrency: update(expected_revision=...)
    """
    key: str
    agent_id: str
    state: AgentLifecycleState = AgentLifecycleState.NEW
    context: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    created_at_ms: int = field(default_factory=_now_ms)
    updated_at_ms: int = field(default_factory=_now_ms)

    revision: int = 0
    expires_at_ms: Optional[int] = None

    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "AgentState":
        try:
            state_val = d.get("state", AgentLifecycleState.NEW)
            state = state_val if isinstance(state_val, AgentLifecycleState) else AgentLifecycleState(str(state_val))
        except Exception as e:
            raise StateValidationError(f"Invalid lifecycle state: {d.get('state')!r}") from e

        ctx = d.get("context", {})
        meta = d.get("meta", {})
        if not isinstance(ctx, dict) or not isinstance(meta, dict):
            raise StateValidationError("context/meta must be dict")

        expires_at_ms = d.get("expires_at_ms")
        if expires_at_ms is not None and not isinstance(expires_at_ms, int):
            raise StateValidationError("expires_at_ms must be int or None")

        revision = d.get("revision", 0)
        if not isinstance(revision, int) or revision < 0:
            raise StateValidationError("revision must be non-negative int")

        return AgentState(
            key=str(d["key"]),
            agent_id=str(d.get("agent_id") or d.get("agentId") or ""),
            state=state,
            context=dict(ctx),
            meta=dict(meta),
            created_at_ms=int(d.get("created_at_ms", _now_ms())),
            updated_at_ms=int(d.get("updated_at_ms", _now_ms())),
            revision=revision,
            expires_at_ms=expires_at_ms,
            last_error=(None if d.get("last_error") is None else str(d.get("last_error"))),
        )

    def is_expired(self, *, now_ms: Optional[int] = None) -> bool:
        n = _now_ms() if now_ms is None else now_ms
        return self.expires_at_ms is not None and n >= self.expires_at_ms


@dataclass(frozen=True, slots=True)
class TransitionPolicy:
    """
    Controls allowed state transitions.

    If allow_same_state is True, transitioning to the same state is allowed (still increments revision).
    """
    allowed: Mapping[AgentLifecycleState, Sequence[AgentLifecycleState]]
    allow_same_state: bool = True

    def validate(self, old: AgentLifecycleState, new: AgentLifecycleState) -> None:
        if old == new and self.allow_same_state:
            return
        nxt = self.allowed.get(old, ())
        if new not in nxt:
            raise StateValidationError(f"Transition not allowed: {old.value} -> {new.value}")

    @staticmethod
    def default() -> "TransitionPolicy":
        # Conservative, production-friendly baseline.
        # Adjust in your governance module if needed.
        allowed: Dict[AgentLifecycleState, Sequence[AgentLifecycleState]] = {
            AgentLifecycleState.NEW: (AgentLifecycleState.IDLE, AgentLifecycleState.FAILED, AgentLifecycleState.ARCHIVED),
            AgentLifecycleState.IDLE: (AgentLifecycleState.RUNNING, AgentLifecycleState.PAUSED, AgentLifecycleState.STOPPED, AgentLifecycleState.ARCHIVED),
            AgentLifecycleState.RUNNING: (AgentLifecycleState.WAITING, AgentLifecycleState.DEGRADED, AgentLifecycleState.FAILED, AgentLifecycleState.STOPPED),
            AgentLifecycleState.WAITING: (AgentLifecycleState.RUNNING, AgentLifecycleState.DEGRADED, AgentLifecycleState.FAILED, AgentLifecycleState.STOPPED),
            AgentLifecycleState.PAUSED: (AgentLifecycleState.IDLE, AgentLifecycleState.RUNNING, AgentLifecycleState.STOPPED),
            AgentLifecycleState.DEGRADED: (AgentLifecycleState.RUNNING, AgentLifecycleState.WAITING, AgentLifecycleState.FAILED, AgentLifecycleState.STOPPED),
            AgentLifecycleState.FAILED: (AgentLifecycleState.IDLE, AgentLifecycleState.STOPPED, AgentLifecycleState.ARCHIVED),
            AgentLifecycleState.STOPPED: (AgentLifecycleState.ARCHIVED,),
            AgentLifecycleState.ARCHIVED: (),
        }
        return TransitionPolicy(allowed=allowed, allow_same_state=True)


@runtime_checkable
class StateStore(Protocol):
    async def get(self, key: str) -> AgentState:
        ...

    async def try_get(self, key: str) -> Optional[AgentState]:
        ...

    async def put(self, st: AgentState) -> None:
        ...

    async def delete(self, key: str) -> None:
        ...

    async def list_keys(self) -> Sequence[str]:
        ...

    async def update(
        self,
        key: str,
        patch: StatePatch,
        *,
        expected_revision: Optional[int] = None,
        transition_policy: Optional[TransitionPolicy] = None,
    ) -> AgentState:
        ...

    async def cleanup_expired(self, *, limit: int = 500) -> int:
        ...


class _KeyLockRegistry:
    """
    Per-key async lock registry to avoid global lock contention.
    """
    def __init__(self) -> None:
        self._locks: Dict[str, asyncio.Lock] = {}
        self._guard = asyncio.Lock()

    async def lock_for(self, key: str) -> asyncio.Lock:
        async with self._guard:
            lk = self._locks.get(key)
            if lk is None:
                lk = asyncio.Lock()
                self._locks[key] = lk
            return lk


class InMemoryStateStore(StateStore):
    """
    High-performance in-memory store.
    Suitable for unit tests and single-process runtime.
    """
    def __init__(self) -> None:
        self._data: Dict[str, AgentState] = {}
        self._locks = _KeyLockRegistry()
        self._keys_guard = asyncio.Lock()

    async def get(self, key: str) -> AgentState:
        st = await self.try_get(key)
        if st is None:
            raise StateNotFoundError(f"State not found: {key}")
        return st

    async def try_get(self, key: str) -> Optional[AgentState]:
        # return a defensive copy to prevent external mutation
        st = self._data.get(key)
        if st is None:
            return None
        return AgentState.from_dict(st.to_dict())

    async def put(self, st: AgentState) -> None:
        _ensure_jsonable(st.to_dict(), path="$state")
        lk = await self._locks.lock_for(st.key)
        async with lk:
            self._data[st.key] = AgentState.from_dict(st.to_dict())

    async def delete(self, key: str) -> None:
        lk = await self._locks.lock_for(key)
        async with lk:
            self._data.pop(key, None)

    async def list_keys(self) -> Sequence[str]:
        async with self._keys_guard:
            return list(self._data.keys())

    async def update(
        self,
        key: str,
        patch: StatePatch,
        *,
        expected_revision: Optional[int] = None,
        transition_policy: Optional[TransitionPolicy] = None,
    ) -> AgentState:
        policy = transition_policy or TransitionPolicy.default()
        lk = await self._locks.lock_for(key)

        async with lk:
            st = self._data.get(key)
            if st is None:
                raise StateNotFoundError(f"State not found: {key}")

            if st.is_expired():
                # Treat expired as not found in update path to avoid resurrecting stale state.
                self._data.pop(key, None)
                raise StateNotFoundError(f"State expired: {key}")

            if expected_revision is not None and st.revision != expected_revision:
                raise StateConflictError(f"Revision conflict for {key}: have={st.revision}, expected={expected_revision}")

            new_st = AgentState.from_dict(st.to_dict())

            if patch.set_state is not None:
                policy.validate(new_st.state, patch.set_state)
                new_st.state = patch.set_state

            if patch.set_context is not None:
                if not isinstance(patch.set_context, dict):
                    raise StateValidationError("set_context must be dict")
                _ensure_jsonable(patch.set_context, path="$.patch.set_context")
                new_st.context = dict(patch.set_context)

            if patch.merge_context is not None:
                if not isinstance(patch.merge_context, dict):
                    raise StateValidationError("merge_context must be dict")
                _ensure_jsonable(patch.merge_context, path="$.patch.merge_context")
                _deep_merge(new_st.context, patch.merge_context)

            if patch.set_meta is not None:
                if not isinstance(patch.set_meta, dict):
                    raise StateValidationError("set_meta must be dict")
                _ensure_jsonable(patch.set_meta, path="$.patch.set_meta")
                new_st.meta = dict(patch.set_meta)

            if patch.merge_meta is not None:
                if not isinstance(patch.merge_meta, dict):
                    raise StateValidationError("merge_meta must be dict")
                _ensure_jsonable(patch.merge_meta, path="$.patch.merge_meta")
                _deep_merge(new_st.meta, patch.merge_meta)

            if patch.ttl_ms is None:
                # explicit clear
                new_st.expires_at_ms = None
            else:
                if patch.ttl_ms <= 0:
                    raise StateValidationError("ttl_ms must be positive int (or None to clear)")
                new_st.expires_at_ms = _now_ms() + int(patch.ttl_ms)

            new_st.updated_at_ms = _now_ms()
            new_st.revision = st.revision + 1

            _ensure_jsonable(new_st.to_dict(), path="$state")
            self._data[key] = AgentState.from_dict(new_st.to_dict())
            return AgentState.from_dict(new_st.to_dict())

    async def cleanup_expired(self, *, limit: int = 500) -> int:
        now = _now_ms()
        removed = 0
        keys = list(self._data.keys())
        for key in keys:
            if removed >= limit:
                break
            st = self._data.get(key)
            if st is None:
                continue
            if st.expires_at_ms is not None and now >= st.expires_at_ms:
                lk = await self._locks.lock_for(key)
                async with lk:
                    st2 = self._data.get(key)
                    if st2 is not None and st2.expires_at_ms is not None and now >= st2.expires_at_ms:
                        self._data.pop(key, None)
                        removed += 1
        return removed


class FileStateStore(StateStore):
    """
    Atomic JSON file-backed store.
    Suitable for single-node deployments where persistence across restarts is needed.

    Notes:
    - Uses per-key locks to prevent concurrent writes.
    - Writes are atomic via tmp + os.replace.
    - Async file operations are delegated to threads (asyncio.to_thread).
    """
    def __init__(self, root_dir: Union[str, Path]) -> None:
        self._root = Path(root_dir).resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._locks = _KeyLockRegistry()
        self._index_lock = asyncio.Lock()

    def _path_for(self, key: str) -> Path:
        # sanitize: keep deterministic and safe file name
        safe = "".join(c for c in key if c.isalnum() or c in ("-", "_", ".", "@"))
        if not safe:
            safe = uuid.uuid4().hex
        return self._root / f"{safe}.json"

    async def _read_json(self, path: Path) -> Optional[Dict[str, Any]]:
        if not path.exists():
            return None

        def _read() -> Dict[str, Any]:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)

        try:
            return await asyncio.to_thread(_read)
        except FileNotFoundError:
            return None
        except json.JSONDecodeError as e:
            raise StateValidationError(f"Corrupted state file: {path}: {e}") from e

    async def _write_json_atomic(self, path: Path, payload: Mapping[str, Any]) -> None:
        _ensure_jsonable(payload, path="$payload")

        tmp = path.with_suffix(path.suffix + f".tmp.{uuid.uuid4().hex}")

        def _write() -> None:
            tmp.parent.mkdir(parents=True, exist_ok=True)
            with tmp.open("w", encoding="utf-8", newline="\n") as f:
                json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)

        try:
            await asyncio.to_thread(_write)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                # best-effort cleanup
                pass

    async def get(self, key: str) -> AgentState:
        st = await self.try_get(key)
        if st is None:
            raise StateNotFoundError(f"State not found: {key}")
        return st

    async def try_get(self, key: str) -> Optional[AgentState]:
        path = self._path_for(key)
        data = await self._read_json(path)
        if data is None:
            return None
        st = AgentState.from_dict(data)
        if st.is_expired():
            # best-effort delete expired
            await self.delete(key)
            return None
        return st

    async def put(self, st: AgentState) -> None:
        _ensure_jsonable(st.to_dict(), path="$state")
        lk = await self._locks.lock_for(st.key)
        async with lk:
            await self._write_json_atomic(self._path_for(st.key), st.to_dict())

    async def delete(self, key: str) -> None:
        lk = await self._locks.lock_for(key)
        async with lk:
            path = self._path_for(key)

            def _rm() -> None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    return

            await asyncio.to_thread(_rm)

    async def list_keys(self) -> Sequence[str]:
        async with self._index_lock:
            def _list() -> Sequence[str]:
                out: list[str] = []
                for p in self._root.glob("*.json"):
                    out.append(p.stem)
                return out
            return await asyncio.to_thread(_list)

    async def update(
        self,
        key: str,
        patch: StatePatch,
        *,
        expected_revision: Optional[int] = None,
        transition_policy: Optional[TransitionPolicy] = None,
    ) -> AgentState:
        policy = transition_policy or TransitionPolicy.default()
        lk = await self._locks.lock_for(key)
        async with lk:
            st = await self.try_get(key)
            if st is None:
                raise StateNotFoundError(f"State not found: {key}")

            if expected_revision is not None and st.revision != expected_revision:
                raise StateConflictError(f"Revision conflict for {key}: have={st.revision}, expected={expected_revision}")

            new_st = AgentState.from_dict(st.to_dict())

            if patch.set_state is not None:
                policy.validate(new_st.state, patch.set_state)
                new_st.state = patch.set_state

            if patch.set_context is not None:
                if not isinstance(patch.set_context, dict):
                    raise StateValidationError("set_context must be dict")
                _ensure_jsonable(patch.set_context, path="$.patch.set_context")
                new_st.context = dict(patch.set_context)

            if patch.merge_context is not None:
                if not isinstance(patch.merge_context, dict):
                    raise StateValidationError("merge_context must be dict")
                _ensure_jsonable(patch.merge_context, path="$.patch.merge_context")
                _deep_merge(new_st.context, patch.merge_context)

            if patch.set_meta is not None:
                if not isinstance(patch.set_meta, dict):
                    raise StateValidationError("set_meta must be dict")
                _ensure_jsonable(patch.set_meta, path="$.patch.set_meta")
                new_st.meta = dict(patch.set_meta)

            if patch.merge_meta is not None:
                if not isinstance(patch.merge_meta, dict):
                    raise StateValidationError("merge_meta must be dict")
                _ensure_jsonable(patch.merge_meta, path="$.patch.merge_meta")
                _deep_merge(new_st.meta, patch.merge_meta)

            if patch.ttl_ms is None:
                new_st.expires_at_ms = None
            else:
                if patch.ttl_ms <= 0:
                    raise StateValidationError("ttl_ms must be positive int (or None to clear)")
                new_st.expires_at_ms = _now_ms() + int(patch.ttl_ms)

            new_st.updated_at_ms = _now_ms()
            new_st.revision = st.revision + 1

            payload = new_st.to_dict()
            await self._write_json_atomic(self._path_for(key), payload)
            return AgentState.from_dict(payload)

    async def cleanup_expired(self, *, limit: int = 500) -> int:
        now = _now_ms()
        removed = 0

        # Avoid long lock holds: list files first, then delete under per-key locks.
        async with self._index_lock:
            def _glob() -> Sequence[Path]:
                return list(self._root.glob("*.json"))
            files = await asyncio.to_thread(_glob)

        for p in files:
            if removed >= limit:
                break
            try:
                data = await self._read_json(p)
                if data is None:
                    continue
                st = AgentState.from_dict(data)
                if st.expires_at_ms is not None and now >= st.expires_at_ms:
                    await self.delete(st.key)
                    removed += 1
            except StateValidationError:
                # If file is corrupted, do not delete automatically here.
                # Production deployments can route this to an incident pipeline.
                continue

        return removed


T = TypeVar("T")


class StateService:
    """
    High-level API for core modules.

    Provides:
    - create/get/update
    - guarded transitions
    - safe context/meta updates
    - optional on_change hook for observability/audit
    """
    def __init__(
        self,
        store: StateStore,
        *,
        transition_policy: Optional[TransitionPolicy] = None,
        on_change: Optional[Callable[[AgentState, AgentState], Awaitable[None]]] = None,
    ) -> None:
        self._store = store
        self._policy = transition_policy or TransitionPolicy.default()
        self._on_change = on_change

    async def create(
        self,
        key: str,
        *,
        agent_id: str,
        initial_state: AgentLifecycleState = AgentLifecycleState.NEW,
        context: Optional[Mapping[str, Any]] = None,
        meta: Optional[Mapping[str, Any]] = None,
        ttl_ms: Optional[int] = None,
    ) -> AgentState:
        if not key or not isinstance(key, str):
            raise StateValidationError("key must be non-empty string")
        if not agent_id or not isinstance(agent_id, str):
            raise StateValidationError("agent_id must be non-empty string")

        ctx = dict(context or {})
        m = dict(meta or {})
        _ensure_jsonable(ctx, path="$.create.context")
        _ensure_jsonable(m, path="$.create.meta")

        st = AgentState(
            key=key,
            agent_id=agent_id,
            state=initial_state,
            context=ctx,
            meta=m,
            created_at_ms=_now_ms(),
            updated_at_ms=_now_ms(),
            revision=0,
            expires_at_ms=(_now_ms() + int(ttl_ms)) if ttl_ms is not None else None,
        )
        await self._store.put(st)
        return st

    async def get(self, key: str) -> AgentState:
        return await self._store.get(key)

    async def try_get(self, key: str) -> Optional[AgentState]:
        return await self._store.try_get(key)

    async def transition(
        self,
        key: str,
        new_state: AgentLifecycleState,
        *,
        expected_revision: Optional[int] = None,
        merge_context: Optional[Mapping[str, Any]] = None,
        merge_meta: Optional[Mapping[str, Any]] = None,
        last_error: Optional[str] = None,
        ttl_ms: Optional[int] = None,
    ) -> AgentState:
        before = await self._store.get(key)

        patch = StatePatch(
            set_state=new_state,
            merge_context=merge_context,
            merge_meta=merge_meta,
            ttl_ms=ttl_ms,
        )

        updated = await self._store.update(
            key,
            patch,
            expected_revision=expected_revision,
            transition_policy=self._policy,
        )

        if last_error is not None:
            # Store last_error as meta+context safe signal without breaking patch semantics.
            updated.context = dict(updated.context)
            updated.context["last_error"] = str(last_error)
            updated.updated_at_ms = _now_ms()
            updated.revision += 1
            await self._store.put(updated)

        if self._on_change is not None:
            await self._on_change(before, updated)

        return updated

    async def patch(
        self,
        key: str,
        patch: StatePatch,
        *,
        expected_revision: Optional[int] = None,
    ) -> AgentState:
        before = await self._store.get(key)
        updated = await self._store.update(
            key,
            patch,
            expected_revision=expected_revision,
            transition_policy=self._policy,
        )
        if self._on_change is not None:
            await self._on_change(before, updated)
        return updated

    async def delete(self, key: str) -> None:
        await self._store.delete(key)

    async def cleanup_expired(self, *, limit: int = 500) -> int:
        return await self._store.cleanup_expired(limit=limit)
