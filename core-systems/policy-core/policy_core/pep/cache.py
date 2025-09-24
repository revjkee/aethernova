# policy_core/pep/cache.py
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import hashlib
import json as _json
import logging
import os
import random
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Generic, Optional, TypeVar, Union

try:  # Optional high-performance JSON
    import orjson as _fastjson  # type: ignore
except Exception:  # pragma: no cover
    _fastjson = None  # type: ignore

try:  # Optional OpenTelemetry
    from opentelemetry import trace  # type: ignore
except Exception:  # pragma: no cover
    trace = None  # type: ignore

try:  # Optional Redis
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

T = TypeVar("T")

_logger = logging.getLogger("policy_core.pep.cache")
if not _logger.handlers:
    handler = logging.StreamHandler()
    fmt = "[%(asctime)s] %(levelname)s policy_core.pep.cache: %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)

_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")

def set_request_id(rid: str) -> None:
    """Set request id for tracing correlation (optional)."""
    _request_id.set(rid)

def _now() -> float:
    return time.monotonic()


class SerializationError(Exception):
    pass


class Serializer(ABC):
    @abstractmethod
    def dumps(self, obj: Any) -> bytes: ...
    @abstractmethod
    def loads(self, data: bytes) -> Any: ...


class JsonSerializer(Serializer):
    """JSON serializer. Uses orjson if available, falls back to stdlib json."""
    def __init__(self) -> None:
        self._fast = _fastjson

    def dumps(self, obj: Any) -> bytes:
        try:
            if self._fast:
                return self._fast.dumps(obj)  # type: ignore
            return _json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except Exception as e:  # pragma: no cover
            raise SerializationError(str(e))

    def loads(self, data: bytes) -> Any:
        try:
            if self._fast:
                return self._fast.loads(data)  # type: ignore
            return _json.loads(data.decode("utf-8"))
        except Exception as e:  # pragma: no cover
            raise SerializationError(str(e))


@dataclass(slots=True)
class CacheStats:
    hits: int = 0
    misses: int = 0
    stale_hits: int = 0
    sets: int = 0
    evictions: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total) if total else 0.0


@dataclass(slots=True)
class CacheEntry(Generic[T]):
    value: T
    expiry: float  # absolute monotonic time
    created_at: float
    stale_until: float
    hits: int = 0


@dataclass(slots=True)
class CacheResult(Generic[T]):
    value: Optional[T]
    hit: bool
    stale: bool
    from_backend: str  # "memory" | "redis" | "loader" | "none"


def _calc_probabilistic_expiry(ttl: float, jitter_ratio: float) -> float:
    """Return jittered ttl to reduce stampedes."""
    if ttl <= 0:
        return 0.0
    jitter = (random.random() * 2 - 1) * jitter_ratio
    return max(0.0, ttl * (1.0 + jitter))


def stable_hash(data: Any) -> str:
    """Stable SHA256 hex of JSON-normalized data."""
    if _fastjson:
        raw = _fastjson.dumps(data)  # type: ignore
    else:
        raw = _json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_decision_key(
    scope: str,
    subject: Union[str, dict[str, Any]],
    action: str,
    resource: Union[str, dict[str, Any]],
    env: Optional[dict[str, Any]] = None,
    version_salt: str = "v1",
) -> str:
    """Build namespaced cache key for policy decision, deterministic and compact."""
    parts = {
        "sub": subject if isinstance(subject, str) else stable_hash(subject),
        "act": action,
        "res": resource if isinstance(resource, str) else stable_hash(resource),
        "env": stable_hash(env or {}),
        "ver": version_salt,
    }
    digest = stable_hash(parts)[:40]
    return f"{scope}:dec:{digest}"


class AsyncCache(ABC):
    """Abstract async cache for policy decisions."""
    @abstractmethod
    async def get(self, key: str, *, allow_stale: bool = True) -> CacheResult[Any]: ...
    @abstractmethod
    async def set(self, key: str, value: Any, *, ttl: float | None = None, stale_ttl: float | None = None) -> None: ...
    @abstractmethod
    async def invalidate(self, key: str) -> None: ...
    @abstractmethod
    async def clear_namespace(self, prefix: str) -> int: ...
    @abstractmethod
    async def read_through(
        self,
        key: str,
        loader: Callable[[], Awaitable[T]],
        *,
        ttl: float,
        stale_ttl: float | None = None,
        jitter_ratio: float = 0.1,
        dogpile_ttl: float = 10.0,
    ) -> T: ...
    @abstractmethod
    def stats(self) -> CacheStats: ...


class _KeyLock:
    """Per-key in-process lock with weak cleanup."""
    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}
        self._global = asyncio.Lock()

    async def acquire(self, key: str) -> asyncio.Lock:
        async with self._global:
            lock = self._locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[key] = lock
        await lock.acquire()
        return lock

    def release(self, key: str, lock: asyncio.Lock) -> None:
        lock.release()
        if not lock.locked() and not lock._waiters:  # type: ignore[attr-defined]
            with contextlib.suppress(KeyError):
                del self._locks[key]


class InMemoryAsyncCache(AsyncCache):
    """High-performance in-memory async cache with TTL, LRU, SWR and dogpile protection."""
    def __init__(
        self,
        *,
        maxsize: int = 10000,
        default_ttl: float = 60.0,
        default_stale_ttl: float = 300.0,
        jitter_ratio: float = 0.1,
        namespace: str = "policy",
        serializer: Optional[Serializer] = None,
    ) -> None:
        self._maxsize = maxsize
        self._default_ttl = default_ttl
        self._default_stale_ttl = default_stale_ttl
        self._jitter_ratio = jitter_ratio
        self._ns = namespace
        self._ser = serializer or JsonSerializer()

        self._data: OrderedDict[str, CacheEntry[bytes]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._keylocks = _KeyLock()
        self._stats = CacheStats()

    def _evict_if_needed(self) -> None:
        while len(self._data) > self._maxsize:
            key, _ = self._data.popitem(last=False)  # LRU
            self._stats.evictions += 1
            _logger.debug("evicted key %s due to maxsize", key)

    async def get(self, key: str, *, allow_stale: bool = True) -> CacheResult[Any]:
        now = _now()
        async with self._lock:
            entry = self._data.get(key)
            if not entry:
                self._stats.misses += 1
                return CacheResult(None, False, False, "none")
            self._data.move_to_end(key)

            if entry.expiry > now:
                entry.hits += 1
                self._stats.hits += 1
                try:
                    val = self._ser.loads(entry.value)
                except SerializationError:
                    self._stats.misses += 1
                    return CacheResult(None, False, False, "memory")
                return CacheResult(val, True, False, "memory")

            is_within_stale = now <= entry.stale_until
            if allow_stale and is_within_stale:
                self._stats.stale_hits += 1
                try:
                    val = self._ser.loads(entry.value)
                except SerializationError:
                    self._stats.misses += 1
                    return CacheResult(None, False, False, "memory")
                return CacheResult(val, True, True, "memory")
            else:
                self._stats.misses += 1
                return CacheResult(None, False, False, "memory")

    async def set(self, key: str, value: Any, *, ttl: float | None = None, stale_ttl: float | None = None) -> None:
        ttl = self._default_ttl if ttl is None else ttl
        stale_ttl = self._default_stale_ttl if stale_ttl is None else stale_ttl
        expiry = _now() + _calc_probabilistic_expiry(ttl, self._jitter_ratio)
        stale_until = expiry + max(0.0, stale_ttl)
        payload = self._ser.dumps(value)
        async with self._lock:
            self._data[key] = CacheEntry(payload, expiry, _now(), stale_until, hits=0)
            self._data.move_to_end(key)
            self._evict_if_needed()
            self._stats.sets += 1

    async def invalidate(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def clear_namespace(self, prefix: str) -> int:
        removed = 0
        async with self._lock:
            keys = [k for k in self._data.keys() if k.startswith(prefix)]
            for k in keys:
                self._data.pop(k, None)
                removed += 1
        return removed

    async def _dogpile_guard(self, key: str, dogpile_ttl: float) -> asyncio.Lock:
        """Acquire per-key lock to prevent dogpile."""
        lock = await self._keylocks.acquire(f"dp:{key}")
        return lock

    async def read_through(
        self,
        key: str,
        loader: Callable[[], Awaitable[T]],
        *,
        ttl: float,
        stale_ttl: float | None = None,
        jitter_ratio: float | None = None,
        dogpile_ttl: float = 10.0,
    ) -> T:
        res = await self.get(key, allow_stale=True)
        if res.hit and not res.stale:
            return res.value  # type: ignore[return-value]
        if res.hit and res.stale:
            try:
                lock = await asyncio.wait_for(self._dogpile_guard(key, dogpile_ttl), timeout=0.01)
            except asyncio.TimeoutError:
                return res.value  # type: ignore[return-value]
            try:
                recheck = await self.get(key, allow_stale=False)
                if recheck.hit:
                    return recheck.value  # type: ignore[return-value]
                val = await _load_with_tracing(loader, key)
                await self.set(key, val, ttl=ttl, stale_ttl=stale_ttl)
                return val
            finally:
                self._keylocks.release(f"dp:{key}", lock)

        lock = await self._dogpile_guard(key, dogpile_ttl)
        try:
            recheck = await self.get(key, allow_stale=False)
            if recheck.hit:
                return recheck.value  # type: ignore[return-value]
            val = await _load_with_tracing(loader, key)
            await self.set(key, val, ttl=ttl, stale_ttl=stale_ttl)
            return val
        finally:
            self._keylocks.release(f"dp:{key}", lock)

    def stats(self) -> CacheStats:
        return self._stats


async def _load_with_tracing(loader: Callable[[], Awaitable[T]], key: str) -> T:
    if trace:
        tracer = trace.get_tracer("policy_core.pep.cache")
        with tracer.start_as_current_span("cache.loader") as span:  # type: ignore[attr-defined]
            span.set_attribute("cache.key", key)  # type: ignore[attr-defined]
            rid = _request_id.get("")
            if rid:
                span.set_attribute("request.id", rid)  # type: ignore[attr-defined]
            return await loader()
    return await loader()


class RedisAsyncCache(AsyncCache):
    """Redis-backed cache with SWR and distributed dogpile protection.
    Requires `redis.asyncio`.
    """
    def __init__(
        self,
        redis_url: str | None = None,
        *,
        client: Any | None = None,
        namespace: str = "policy",
        default_ttl: float = 60.0,
        default_stale_ttl: float = 300.0,
        jitter_ratio: float = 0.1,
        serializer: Optional[Serializer] = None,
    ) -> None:
        if aioredis is None and client is None:
            raise RuntimeError("redis.asyncio is not installed")
        self._ns = namespace
        self._ser = serializer or JsonSerializer()
        if client is not None:
            self._r = client
        else:
            self._r = aioredis.from_url(redis_url or os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=False)
        self._default_ttl = default_ttl
        self._default_stale_ttl = default_stale_ttl
        self._jitter_ratio = jitter_ratio
        self._stats = CacheStats()
        self._locks = _KeyLock()

    def _k(self, key: str) -> str:
        return f"{self._ns}:{key}" if not key.startswith(self._ns + ":") else key

    async def get(self, key: str, *, allow_stale: bool = True) -> CacheResult[Any]:
        now = _now()
        raw = await self._r.get(self._k(key))
        if raw is None:
            self._stats.misses += 1
            return CacheResult(None, False, False, "none")
        try:
            payload = _json.loads(raw.decode("utf-8"))
            expiry = float(payload["expiry"])
            stale_until = float(payload["stale_until"])
            buf = bytes.fromhex(payload["value"])
        except Exception:
            self._stats.misses += 1
            return CacheResult(None, False, False, "redis")

        if expiry > now:
            try:
                val = self._ser.loads(buf)
            except SerializationError:
                self._stats.misses += 1
                return CacheResult(None, False, False, "redis")
            self._stats.hits += 1
            return CacheResult(val, True, False, "redis")

        if allow_stale and now <= stale_until:
            try:
                val = self._ser.loads(buf)
            except SerializationError:
                self._stats.misses += 1
                return CacheResult(None, False, False, "redis")
            self._stats.stale_hits += 1
            return CacheResult(val, True, True, "redis")

        self._stats.misses += 1
        return CacheResult(None, False, False, "redis")

    async def set(self, key: str, value: Any, *, ttl: float | None = None, stale_ttl: float | None = None) -> None:
        ttl = self._default_ttl if ttl is None else ttl
        stale_ttl = self._default_stale_ttl if stale_ttl is None else stale_ttl
        expiry = _now() + _calc_probabilistic_expiry(ttl, self._jitter_ratio)
        stale_until = expiry + max(0.0, stale_ttl)
        buf = self._ser.dumps(value)
        payload = {
            "expiry": expiry,
            "stale_until": stale_until,
            "value": buf.hex(),
        }
        ttl_total = int(max(1.0, (stale_until - _now())))
        await self._r.set(self._k(key), _json.dumps(payload, separators=(",", ":")).encode("utf-8"), ex=ttl_total)
        self._stats.sets += 1

    async def invalidate(self, key: str) -> None:
        await self._r.delete(self._k(key))

    async def clear_namespace(self, prefix: str) -> int:
        full = self._k(prefix)
        cursor = 0
        removed = 0
        while True:
            cursor, keys = await self._r.scan(cursor=cursor, match=full + "*", count=1000)
            if keys:
                removed += await self._r.delete(*keys)
            if cursor == 0:
                break
        return removed

    async def _acquire_dist_lock(self, key: str, ttl: float) -> Optional[str]:
        token = hashlib.sha256(os.urandom(16)).hexdigest()
        ok = await self._r.set(self._k(f"lock:{key}"), token.encode(), nx=True, ex=int(max(1.0, ttl)))
        if ok:
            return token
        return None

    async def _release_dist_lock(self, key: str, token: str) -> None:
        lua = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        else
            return 0
        end
        """
        try:
            await self._r.eval(lua, 1, self._k(f"lock:{key}"), token.encode())
        except Exception:
            pass

    async def read_through(
        self,
        key: str,
        loader: Callable[[], Awaitable[T]],
        *,
        ttl: float,
        stale_ttl: float | None = None,
        jitter_ratio: float | None = None,
        dogpile_ttl: float = 10.0,
    ) -> T:
        res = await self.get(key, allow_stale=True)
        if res.hit and not res.stale:
            return res.value  # type: ignore[return-value]
        if res.hit and res.stale:
            token = await self._acquire_dist_lock(key, dogpile_ttl)
            if not token:
                return res.value  # type: ignore[return-value]
            try:
                recheck = await self.get(key, allow_stale=False)
                if recheck.hit:
                    return recheck.value  # type: ignore[return-value]
                val = await _load_with_tracing(loader, key)
                await self.set(key, val, ttl=ttl, stale_ttl=stale_ttl)
                return val
            finally:
                await self._release_dist_lock(key, token)

        token = await self._acquire_dist_lock(key, dogpile_ttl)
        if token:
            try:
                recheck = await self.get(key, allow_stale=False)
                if recheck.hit:
                    return recheck.value  # type: ignore[return-value]
                val = await _load_with_tracing(loader, key)
                await self.set(key, val, ttl=ttl, stale_ttl=stale_ttl)
                return val
            finally:
                await self._release_dist_lock(key, token)
        await asyncio.sleep(0.01)
        re = await self.get(key, allow_stale=True)
        if re.hit:
            return re.value  # type: ignore[return-value]
        val = await _load_with_tracing(loader, key)
        await self.set(key, val, ttl=ttl, stale_ttl=stale_ttl)
        return val

    def stats(self) -> CacheStats:
        return self._stats


__all__ = [
    "AsyncCache",
    "InMemoryAsyncCache",
    "RedisAsyncCache",
    "JsonSerializer",
    "Serializer",
    "CacheStats",
    "CacheEntry",
    "CacheResult",
    "build_decision_key",
    "stable_hash",
    "set_request_id",
]
