"""
Distributed leases for Chronowatch scheduler.

Design goals:
- Strong single-run guarantee per job frame using fencing tokens (monotonic version per key).
- Monotonic time for TTL/expiry decisions, independent from wall clock changes.
- Async-safe, production-grade error handling and logging.
- Pluggable backends; ships with InMemory backend for tests/dev and single-node usage.
- LeaseManager with retry/backoff and LeaseGuard for auto-renewal & loss detection.
- Multi-key acquisition with deadlock avoidance via total key ordering.

No external dependencies.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# Public exports
__all__ = [
    "Lease",
    "LeaseError",
    "LeaseNotAcquired",
    "LeaseExpired",
    "LeaseConflict",
    "LeaseBackend",
    "InMemoryLeaseBackend",
    "LeaseManager",
    "LeaseGuard",
    "make_lease_key",
    "make_multi_lease_key",
]

# --------------------------------------------------------------------------- #
# Utilities & errors
# --------------------------------------------------------------------------- #


def monotonic() -> float:
    """Monotonic seconds (float). Safe for TTL arithmetic."""
    return time.monotonic()


def utc_ms() -> int:
    """Wall-clock milliseconds (for logging/telemetry only)."""
    return int(time.time() * 1000)


class LeaseError(RuntimeError):
    """Base class for lease errors."""


class LeaseNotAcquired(LeaseError):
    """Lease could not be acquired."""


class LeaseExpired(LeaseError):
    """Lease is expired or not owned anymore."""


class LeaseConflict(LeaseError):
    """Lease conflict (e.g., wrong owner/lease_id)."""


# --------------------------------------------------------------------------- #
# Lease model
# --------------------------------------------------------------------------- #


@dataclass(slots=True, frozen=True)
class Lease:
    """
    Immutable view of a lease instance.

    Attributes:
        key: Lease key (unique resource identity).
        owner_id: Owner identity (runner/worker id).
        lease_id: Unique lease instance id (UUID string).
        token: Fencing token (monotonically increasing per key).
        ttl: Requested TTL seconds (float).
        expires_at_mono: Monotonic timestamp (seconds) when lease expires.
        created_at_mono: Monotonic timestamp when acquired.
        meta: Optional metadata (tenant, job id, labels, etc.).
    """

    key: str
    owner_id: str
    lease_id: str
    token: int
    ttl: float
    expires_at_mono: float
    created_at_mono: float
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def expired(self) -> bool:
        return monotonic() >= self.expires_at_mono

    def time_left(self) -> float:
        return max(0.0, self.expires_at_mono - monotonic())


# --------------------------------------------------------------------------- #
# Backend abstraction
# --------------------------------------------------------------------------- #


class LeaseBackend(ABC):
    """
    Abstract storage for leases.

    Contract:
      - Fencing 'token' must strictly increase at each successful acquire for a given key.
      - Renew must extend 'expires_at' only for the current live lease (lease_id match).
      - Release must drop only if lease_id matches.
      - All operations must be linearizable per-key (i.e., appear atomic).
    """

    @abstractmethod
    async def try_acquire(
        self,
        key: str,
        owner_id: str,
        ttl: float,
        *,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Optional[Lease]:
        """Try to acquire lease; return Lease on success or None if busy."""

    @abstractmethod
    async def renew(self, lease: Lease, ttl: Optional[float] = None) -> Lease:
        """Renew lease TTL (and optionally update ttl value). Raise LeaseExpired on conflict."""

    @abstractmethod
    async def release(self, lease: Lease) -> None:
        """Release lease if still owned; silently ignore if already expired/lost."""

    @abstractmethod
    async def get(self, key: str) -> Optional[Lease]:
        """Get current lease state for key (or None). Expired records may be lazily GC-ed."""

    # Optional but useful:

    async def acquire_many(
        self, keys: Sequence[str], owner_id: str, ttl: float, *, meta: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Lease]:
        """
        Best-effort multi-key acquire, deadlock-free by sorting keys.
        Acquires atomically with rollback on first failure.
        """
        if not keys:
            return {}
        acquired: Dict[str, Lease] = {}
        # total order to avoid deadlocks
        for k in sorted(keys):
            lease = await self.try_acquire(k, owner_id, ttl, meta=meta)
            if lease is None:
                # rollback acquired so far
                for l in acquired.values():
                    with context_suppress():
                        await self.release(l)
                raise LeaseNotAcquired(f"multi-acquire failed at key={k}")
            acquired[k] = lease
        return acquired

    @abstractmethod
    async def gc(self) -> int:
        """Garbage-collect expired entries if backend maintains them; return number removed."""


# --------------------------------------------------------------------------- #
# In-memory backend (reference implementation)
# --------------------------------------------------------------------------- #


class InMemoryLeaseBackend(LeaseBackend):
    """
    Async-safe in-memory backend.

    Notes:
      - Suitable for tests/dev or single-process schedulers.
      - Uses per-key fencing counters and a global asyncio.Lock for simplicity.
      - All timestamps use monotonic() for expiry decisions.
    """

    def __init__(self) -> None:
        self._log = logging.getLogger("chronowatch.leases.mem")
        # key -> (lease, fencing_counter)
        self._store: Dict[str, Tuple[Lease, int]] = {}
        self._lock = asyncio.Lock()

    async def try_acquire(
        self, key: str, owner_id: str, ttl: float, *, meta: Optional[Dict[str, Any]] = None
    ) -> Optional[Lease]:
        ttl = self._normalize_ttl(ttl)
        now = monotonic()
        async with self._lock:
            current = self._store.get(key)
            if current is not None:
                lease, counter = current
                if lease.expires_at_mono > now:
                    return None  # busy
                # expired -> eligible for takeover; increment token
                token = counter + 1
            else:
                token = 1
            new = Lease(
                key=key,
                owner_id=owner_id,
                lease_id=str(uuid.uuid4()),
                token=token,
                ttl=ttl,
                created_at_mono=now,
                expires_at_mono=now + ttl,
                meta=dict(meta or {}),
            )
            self._store[key] = (new, token)
            self._log.debug("acquired", extra={"key": key, "owner": owner_id, "token": token})
            return new

    async def renew(self, lease: Lease, ttl: Optional[float] = None) -> Lease:
        now = monotonic()
        ttl_eff = self._normalize_ttl(ttl or lease.ttl)
        async with self._lock:
            current = self._store.get(lease.key)
            if current is None:
                raise LeaseExpired("no active lease")
            active, counter = current
            if active.lease_id != lease.lease_id or active.token != lease.token:
                raise LeaseExpired("lease lost (id/token mismatch)")
            if active.expires_at_mono <= now:
                raise LeaseExpired("lease already expired")
            updated = dataclasses.replace(
                active, ttl=ttl_eff, expires_at_mono=now + ttl_eff  # keep token
            )
            self._store[lease.key] = (updated, counter)
            self._log.debug("renewed", extra={"key": lease.key, "token": lease.token})
            return updated

    async def release(self, lease: Lease) -> None:
        async with self._lock:
            current = self._store.get(lease.key)
            if current is None:
                return
            active, counter = current
            if active.lease_id == lease.lease_id and active.token == lease.token:
                self._store.pop(lease.key, None)
                self._log.debug("released", extra={"key": lease.key, "token": lease.token})

    async def get(self, key: str) -> Optional[Lease]:
        now = monotonic()
        async with self._lock:
            current = self._store.get(key)
            if current is None:
                return None
            lease, _ = current
            if lease.expires_at_mono <= now:
                # opportunistic GC
                self._store.pop(key, None)
                return None
            return lease

    async def gc(self) -> int:
        now = monotonic()
        removed = 0
        async with self._lock:
            for k in list(self._store.keys()):
                lease, _ = self._store[k]
                if lease.expires_at_mono <= now:
                    self._store.pop(k, None)
                    removed += 1
        if removed:
            self._log.debug("gc", extra={"removed": removed})
        return removed

    @staticmethod
    def _normalize_ttl(ttl: float) -> float:
        # reasonable floor/ceil to avoid pathological settings
        if ttl is None:
            ttl = 0.0
        ttl = float(ttl)
        return max(1.0, min(ttl, 3600.0))  # 1s..1h


# --------------------------------------------------------------------------- #
# LeaseManager & Guard
# --------------------------------------------------------------------------- #

OnLeaseEvent = Callable[[Lease], Awaitable[None]]


class LeaseManager:
    """
    High-level orchestration:
      - acquire with retry/backoff & jitter
      - guarded context with auto-renewal
      - multi-acquire helper

    Example:
        backend = InMemoryLeaseBackend()
        mgr = LeaseManager(backend)
        lease = await mgr.acquire_with_retry(key, owner_id="worker-1", ttl=30, deadline=10)
        async with mgr.guard(lease, renew_ratio=0.5):
            ... do work ...
    """

    def __init__(
        self,
        backend: LeaseBackend,
        *,
        logger: Optional[logging.Logger] = None,
        min_backoff_s: float = 0.2,
        max_backoff_s: float = 5.0,
        backoff_factor: float = 1.8,
        jitter_s: float = 0.3,
    ) -> None:
        self._b = backend
        self._log = logger or logging.getLogger("chronowatch.leases.manager")
        self._min_b = float(min_backoff_s)
        self._max_b = float(max_backoff_s)
        self._factor = float(backoff_factor)
        self._jitter = float(jitter_s)

    # ---------- Acquire primitives ----------

    async def acquire_once(self, key: str, *, owner_id: str, ttl: float, meta: Optional[Dict[str, Any]] = None) -> Lease:
        lease = await self._b.try_acquire(key, owner_id=owner_id, ttl=ttl, meta=meta)
        if lease is None:
            raise LeaseNotAcquired(f"busy: {key}")
        return lease

    async def acquire_with_retry(
        self,
        key: str,
        *,
        owner_id: str,
        ttl: float,
        deadline: float,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Lease:
        """
        Try to acquire lease until deadline seconds elapse (relative monotonic).
        Exponential backoff (bounded) with jitter.
        """
        start = monotonic()
        attempt = 0
        delay = self._min_b
        while True:
            attempt += 1
            lease = await self._b.try_acquire(key, owner_id=owner_id, ttl=ttl, meta=meta)
            if lease is not None:
                if attempt > 1:
                    self._log.info(
                        "acquired_after_retries",
                        extra={"key": key, "attempts": attempt, "wait_ms": int((monotonic() - start) * 1000)},
                    )
                return lease

            # busy -> wait
            remaining = deadline - (monotonic() - start)
            if remaining <= 0:
                raise LeaseNotAcquired(f"deadline exceeded: {key}")

            sleep_for = min(remaining, delay + _bounded_jitter(self._jitter))
            await asyncio.sleep(max(0.05, sleep_for))
            delay = min(self._max_b, delay * self._factor)

    # ---------- Renewal & guard ----------

    async def renew(self, lease: Lease, *, ttl: Optional[float] = None) -> Lease:
        try:
            return await self._b.renew(lease, ttl=ttl)
        except LeaseExpired as e:
            self._log.warning("renew_failed", extra={"key": lease.key, "reason": str(e)})
            raise

    async def release(self, lease: Lease) -> None:
        with context_suppress():
            await self._b.release(lease)

    def guard(
        self,
        lease: Lease,
        *,
        renew_ratio: float = 0.5,
        min_interval_s: float = 1.0,
        on_renewed: Optional[OnLeaseEvent] = None,
        on_lost: Optional[OnLeaseEvent] = None,
    ) -> "LeaseGuard":
        """
        Create an async context manager guarding the lease with periodic renewals.

        renew_ratio: schedule renew at ttl * ratio (e.g., 0.5 -> halfway).
        min_interval_s: lower bound for renewal interval.
        """
        return LeaseGuard(
            manager=self,
            lease=lease,
            renew_ratio=renew_ratio,
            min_interval_s=min_interval_s,
            on_renewed=on_renewed,
            on_lost=on_lost,
        )

    # ---------- Multi-key ----------

    async def acquire_many_with_retry(
        self,
        keys: Sequence[str],
        *,
        owner_id: str,
        ttl: float,
        deadline: float,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Lease]:
        start = monotonic()
        attempt = 0
        delay = self._min_b
        while True:
            attempt += 1
            try:
                return await self._b.acquire_many(keys, owner_id=owner_id, ttl=ttl, meta=meta)
            except LeaseNotAcquired:
                remaining = deadline - (monotonic() - start)
                if remaining <= 0:
                    raise
                sleep_for = min(remaining, delay + _bounded_jitter(self._jitter))
                await asyncio.sleep(max(0.05, sleep_for))
                delay = min(self._max_b, delay * self._factor)


class LeaseGuard:
    """
    Async context manager that renews a lease periodically and signals loss.

    Usage:
        async with LeaseGuard(manager, lease) as live_lease:
            ... do protected work ...
            # live_lease may be updated after renewals
    """

    def __init__(
        self,
        *,
        manager: LeaseManager,
        lease: Lease,
        renew_ratio: float,
        min_interval_s: float,
        on_renewed: Optional[OnLeaseEvent],
        on_lost: Optional[OnLeaseEvent],
    ) -> None:
        self._mgr = manager
        self._lease = lease
        self._renew_ratio = max(0.1, min(0.9, renew_ratio))
        self._min_interval = max(0.5, min_interval_s)
        self._on_renewed = on_renewed
        self._on_lost = on_lost
        self._task: Optional[asyncio.Task[None]] = None
        self._log = logging.getLogger("chronowatch.leases.guard")
        self._lost = asyncio.Event()
        self._updated: asyncio.Queue[Lease] = asyncio.Queue()

    async def __aenter__(self) -> Lease:
        # start renewal loop
        self._task = asyncio.create_task(self._renew_loop(), name=f"lease-guard:{self._lease.key}")
        return self._lease

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    async def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            with context_suppress():
                await self._task
        # always attempt release at the end
        with context_suppress():
            await self._mgr.release(self._lease)

    @property
    def lost(self) -> asyncio.Event:
        """Event set when lease is lost (failed renewal / expiry)."""
        return self._lost

    async def next_lease(self) -> Lease:
        """
        Await for next renewed lease snapshot.
        Useful if caller needs the fresh TTL or meta.
        """
        return await self._updated.get()

    async def _renew_loop(self) -> None:
        """
        Periodically renew lease based on ttl and renew_ratio.
        If renewal fails, set lost event; the job should abort ASAP.
        """
        try:
            while True:
                interval = max(self._min_interval, self._lease.ttl * self._renew_ratio)
                # small jitter to avoid thundering herd (±10% of interval)
                jitter = interval * 0.1
                await asyncio.sleep(max(0.1, interval + _bounded_jitter(jitter)))

                # if lease already too close to expiry, attempt immediately
                if self._lease.time_left() <= interval:
                    try:
                        refreshed = await self._mgr.renew(self._lease)
                        self._lease = refreshed
                        with context_suppress():
                            await self._updated.put(refreshed)
                        if self._on_renewed:
                            with context_suppress():
                                await self._on_renewed(refreshed)
                    except LeaseExpired:
                        self._lost.set()
                        if self._on_lost:
                            with context_suppress():
                                await self._on_lost(self._lease)
                        break
        except asyncio.CancelledError:
            # normal shutdown
            pass
        except Exception as e:  # defensive
            self._log.exception("renew_loop_error", extra={"key": self._lease.key, "err": str(e)})
            self._lost.set()


# --------------------------------------------------------------------------- #
# Keys helpers
# --------------------------------------------------------------------------- #


def make_lease_key(task_id: str, frame_start_iso: str, profile: str = "prod") -> str:
    """
    Compose a deterministic lease key for a single schedule frame.
    Example: cw:lease:prod:billing-close:2025-08-28T23:55:00+02:00
    """
    return f"cw:lease:{profile}:{task_id}:{frame_start_iso}"


def make_multi_lease_key(task_id: str, shard: int, profile: str = "prod") -> str:
    """
    Compose a key for sharded tasks where each shard is protected separately.
    Example: cw:lease:prod:reindex-from-kafka:shard-3
    """
    return f"cw:lease:{profile}:{task_id}:shard-{int(shard)}"


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _bounded_jitter(bound: float) -> float:
    """
    Symmetric jitter in [-bound, +bound].
    """
    if bound <= 0:
        return 0.0
    # Use time-based pseudo randomness to avoid importing random
    # (sufficient for de-synchronization jitter).
    frac = (time.perf_counter() % 1.0) * 2.0 - 1.0  # [-1, +1)
    return frac * bound


class context_suppress:
    """Lightweight async/regular context suppressor for best-effort cleanup."""

    def __init__(self, *exc_types: type[BaseException]) -> None:
        self._types = exc_types or (BaseException,)

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        return et is not None and issubclass(et, self._types)

    async def __aenter__(self):
        return self

    async def __aexit__(self, et, ev, tb):
        return et is not None and issubclass(et, self._types)
