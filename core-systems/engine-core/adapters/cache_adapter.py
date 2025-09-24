# engine/adapters/cache_adapter.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Generic, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, TypeVar, Union

# Optional deps
try:
    import msgpack  # type: ignore
    _HAS_MSGPACK = True
except Exception:
    _HAS_MSGPACK = False

try:
    import redis  # type: ignore
    import redis.asyncio as aioredis  # type: ignore
    _HAS_REDIS = True
except Exception:
    _HAS_REDIS = False

# Optional profiling integration
with contextlib.suppress(Exception):
    from engine.telemetry.profiling import profile_block  # type: ignore
    _HAS_PROFILING = True
if not locals().get("_HAS_PROFILING"):
    def profile_block(name: Optional[str] = None, config: Optional[Any] = None):
        @contextlib.contextmanager
        def _noop():
            yield
        return _noop()

LOG = logging.getLogger(__name__)
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(h)
    LOG.setLevel(logging.INFO)

T = TypeVar("T")

# =========================
# Конфигурация адаптера
# =========================

@dataclass(frozen=True)
class CacheConfig:
    # Общие
    namespace: str = "engine"
    default_ttl_seconds: int = 300
    jitter_ratio: float = 0.05  # 5% джиттер для распределения истечения
    max_value_bytes: int = 5 * 1024 * 1024  # защитный лимит
    enable_tags: bool = True
    # Redis URL вида: redis://:pass@host:6379/0
    redis_url: Optional[str] = None
    redis_ssl: bool = False
    redis_client_name: str = "engine-cache"
    redis_health_check_interval: float = 10.0
    redis_socket_timeout: float = 2.0
    redis_pool_size: int = 50
    # In-memory LFU fallback
    memory_capacity_items: int = 10_000
    memory_ttl_seconds: int = 120
    # Stampede protection
    lock_ttl_seconds: int = 30
    # Сериализация
    prefer_msgpack: bool = True
    # Безопасный лог
    redact_keys_in_logs: bool = False
    # Версионирование кэша (инвалидация по версии namespace)
    version: int = 1

    @staticmethod
    def from_env(prefix: str = "CACHE") -> "CacheConfig":
        def _get(key: str, default: Optional[str] = None) -> Optional[str]:
            v = os.getenv(f"{prefix}_{key}")
            return v if v is not None else default
        def _get_int(key: str, default: int) -> int:
            v = _get(key)
            return int(v) if v is not None else default
        def _get_float(key: str, default: float) -> float:
            v = _get(key)
            return float(v) if v is not None else default
        def _get_bool(key: str, default: bool) -> bool:
            v = _get(key)
            return v.lower() in ("1", "true", "yes", "on") if v is not None else default

        return CacheConfig(
            namespace=_get("NS", "engine") or "engine",
            default_ttl_seconds=_get_int("TTL", 300),
            jitter_ratio=_get_float("JITTER", 0.05),
            max_value_bytes=_get_int("MAX_BYTES", 5*1024*1024),
            enable_tags=_get_bool("TAGS", True),
            redis_url=_get("REDIS_URL"),
            redis_ssl=_get_bool("REDIS_SSL", False),
            redis_client_name=_get("REDIS_NAME", "engine-cache") or "engine-cache",
            redis_health_check_interval=_get_float("REDIS_HCHECK", 10.0),
            redis_socket_timeout=_get_float("REDIS_STO", 2.0),
            redis_pool_size=_get_int("REDIS_POOL", 50),
            memory_capacity_items=_get_int("MEM_CAP", 10_000),
            memory_ttl_seconds=_get_int("MEM_TTL", 120),
            lock_ttl_seconds=_get_int("LOCK_TTL", 30),
            prefer_msgpack=_get_bool("MSGPACK", True),
            redact_keys_in_logs=_get_bool("REDACT", False),
            version=_get_int("VER", 1),
        )

# =========================
# Сериализация
# =========================

class Serializer(abc.ABC):
    @abc.abstractmethod
    def dumps(self, obj: Any) -> bytes:
        ...
    @abc.abstractmethod
    def loads(self, data: bytes) -> Any:
        ...
    @property
    @abc.abstractmethod
    def content_type(self) -> str:
        ...

class JsonSerializer(Serializer):
    def dumps(self, obj: Any) -> bytes:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
    def loads(self, data: bytes) -> Any:
        return json.loads(data.decode("utf-8"))
    @property
    def content_type(self) -> str:
        return "application/json"

class MsgpackSerializer(Serializer):
    def dumps(self, obj: Any) -> bytes:
        return msgpack.packb(obj, use_bin_type=True)  # type: ignore
    def loads(self, data: bytes) -> Any:
        return msgpack.unpackb(data, raw=False)  # type: ignore
    @property
    def content_type(self) -> str:
        return "application/msgpack"

def pick_serializer(cfg: CacheConfig) -> Serializer:
    if _HAS_MSGPACK and cfg.prefer_msgpack:
        return MsgpackSerializer()
    return JsonSerializer()

# =========================
# Утилиты
# =========================

def _hash_key(raw: str) -> str:
    return hashlib.blake2b(raw.encode("utf-8"), digest_size=16).hexdigest()

def _ns_key(ns: str, ver: int, key: str) -> str:
    # Нормализация: namespace:v<ver>:h<hash>:<tail>
    tail = key if len(key) <= 48 else key[:24] + ":" + key[-20:]
    return f"{ns}:v{ver}:h{_hash_key(key)}:{tail}"

def _tag_key(ns: str, tag: str) -> str:
    return f"{ns}:tag:{_hash_key(tag)}:{tag}"

def _lock_key(ns: str, ver: int, key: str) -> str:
    return f"{ns}:lock:v{ver}:{_hash_key(key)}"

def _with_jitter(ttl: int, ratio: float) -> int:
    if ttl <= 0 or ratio <= 0:
        return ttl
    delta = int(ttl * ratio)
    return max(1, ttl + random.randint(-delta, delta))

def _redact(s: str) -> str:
    if s is None:
        return "None"
    if len(s) <= 4:
        return "***"
    return s[:2] + "***" + s[-2:]

# =========================
# Базовый интерфейс
# =========================

class BaseCacheAdapter(abc.ABC):
    @abc.abstractmethod
    def healthy(self) -> bool: ...
    @abc.abstractmethod
    async def healthy_async(self) -> bool: ...

    @abc.abstractmethod
    def get(self, key: str) -> Optional[Any]: ...
    @abc.abstractmethod
    async def get_async(self, key: str) -> Optional[Any]: ...

    @abc.abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None, tags: Optional[Sequence[str]] = None) -> None: ...
    @abc.abstractmethod
    async def set_async(self, key: str, value: Any, ttl: Optional[int] = None, tags: Optional[Sequence[str]] = None) -> None: ...

    @abc.abstractmethod
    def delete(self, key: str) -> None: ...
    @abc.abstractmethod
    async def delete_async(self, key: str) -> None: ...

    @abc.abstractmethod
    def invalidate_tag(self, tag: str) -> int: ...
    @abc.abstractmethod
    async def invalidate_tag_async(self, tag: str) -> int: ...

    @abc.abstractmethod
    def get_or_set(self, key: str, producer: Callable[[], T], ttl: Optional[int] = None, tags: Optional[Sequence[str]] = None) -> T: ...
    @abc.abstractmethod
    async def get_or_set_async(self, key: str, producer: Callable[[], Awaitable[T]], ttl: Optional[int] = None, tags: Optional[Sequence[str]] = None) -> T: ...

# =========================
# In-memory LFU backend
# =========================

class _LFUEntry:
    __slots__ = ("value", "freq", "expire_at", "tags")
    def __init__(self, value: Any, ttl: int, tags: Optional[Sequence[str]]):
        self.value = value
        self.freq = 1
        self.expire_at = time.monotonic() + ttl if ttl > 0 else 0
        self.tags = set(tags or [])

class InMemoryLFUBackend:
    def __init__(self, capacity: int, default_ttl: int):
        self._cap = capacity
        self._ttl = default_ttl
        self._data: Dict[str, _LFUEntry] = {}
        self._freq: Dict[int, Dict[str, None]] = {}
        self._min_freq = 0
        self._lock = asyncio.Lock()
        self._lock_sync = asyncio.get_event_loop() if asyncio.get_event_loop_policy() else None

    def _evict_if_needed(self) -> None:
        if len(self._data) < self._cap:
            return
        # Удаляем из наименьшей частоты
        keys = self._freq.get(self._min_freq)
        if not keys:
            # fallback
            victim = next(iter(self._data))
            self._remove_key(victim)
            return
        victim = next(iter(keys))
        self._remove_key(victim)

    def _remove_key(self, k: str) -> None:
        ent = self._data.pop(k, None)
        if ent is None:
            return
        bucket = self._freq.get(ent.freq)
        if bucket and k in bucket:
            bucket.pop(k, None)
            if not bucket and ent.freq == self._min_freq:
                self._min_freq += 1

    def _touch(self, k: str, ent: _LFUEntry) -> None:
        oldf = ent.freq
        ent.freq += 1
        b = self._freq.get(oldf)
        if b and k in b:
            b.pop(k, None)
        self._freq.setdefault(ent.freq, {})[k] = None
        if oldf == self._min_freq and (self._freq.get(oldf) is None or len(self._freq.get(oldf, {})) == 0):
            self._min_freq += 1

    def _expired(self, ent: _LFUEntry) -> bool:
        return ent.expire_at > 0 and time.monotonic() >= ent.expire_at

    def get(self, k: str) -> Optional[Any]:
        ent = self._data.get(k)
        if not ent:
            return None
        if self._expired(ent):
            self._remove_key(k)
            return None
        self._touch(k, ent)
        return ent.value

    def set(self, k: str, v: Any, ttl: Optional[int], tags: Optional[Sequence[str]]) -> None:
        ttl = ttl if ttl is not None else self._ttl
        ttl = max(1, ttl)
        if k in self._data:
            ent = self._data[k]
            ent.value = v
            ent.expire_at = time.monotonic() + ttl if ttl > 0 else 0
            ent.tags = set(tags or [])
            self._touch(k, ent)
        else:
            self._evict_if_needed()
            ent = _LFUEntry(v, ttl, tags)
            self._data[k] = ent
            self._freq.setdefault(1, {})[k] = None
            self._min_freq = 1 if self._min_freq == 0 else min(self._min_freq, 1)

    def delete(self, k: str) -> None:
        self._remove_key(k)

    def invalidate_tag(self, tag: str) -> int:
        removed = 0
        to_delete = [k for k, e in self._data.items() if tag in e.tags]
        for k in to_delete:
            self._remove_key(k)
            removed += 1
        return removed

# =========================
# Redis backend
# =========================

class _RedisSync:
    def __init__(self, cfg: CacheConfig, serializer: Serializer):
        self.cfg = cfg
        self.ser = serializer
        if not _HAS_REDIS:
            raise RuntimeError("Redis library is not installed")
        self._client = redis.Redis.from_url(
            cfg.redis_url, decode_responses=False, ssl=cfg.redis_ssl, client_name=cfg.redis_client_name,
            health_check_interval=int(cfg.redis_health_check_interval), socket_timeout=cfg.redis_socket_timeout,
            max_connections=cfg.redis_pool_size
        )

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            return False

    def get(self, k: str) -> Optional[Any]:
        raw = self._client.get(k)
        if raw is None:
            return None
        return self.ser.loads(raw)

    def set(self, k: str, v: Any, ttl: int, tags: Optional[Sequence[str]]) -> None:
        data = self.ser.dumps(v)
        if len(data) > self.cfg.max_value_bytes:
            raise ValueError("Value too large for cache")
        pipe = self._client.pipeline(transaction=True)
        pipe.set(k, data, ex=ttl)
        if self.cfg.enable_tags and tags:
            for t in tags:
                pipe.sadd(_tag_key(self.cfg.namespace, t), k)
                pipe.expire(_tag_key(self.cfg.namespace, t), max(ttl, 60))
        pipe.execute()

    def delete(self, k: str) -> None:
        self._client.delete(k)

    def invalidate_tag(self, tag: str) -> int:
        if not self.cfg.enable_tags:
            return 0
        tkey = _tag_key(self.cfg.namespace, tag)
        keys = list(self._client.smembers(tkey) or [])
        removed = 0
        if keys:
            pipe = self._client.pipeline(transaction=True)
            for k in keys:
                pipe.delete(k)
                removed += 1
            pipe.delete(tkey)
            pipe.execute()
        return removed

    # Stampede lock
    def acquire_lock(self, k: str, ttl: int) -> bool:
        return bool(self._client.set(k, b"1", nx=True, ex=ttl))
    def release_lock(self, k: str) -> None:
        with contextlib.suppress(Exception):
            self._client.delete(k)

class _RedisAsync:
    def __init__(self, cfg: CacheConfig, serializer: Serializer):
        self.cfg = cfg
        self.ser = serializer
        if not _HAS_REDIS:
            raise RuntimeError("Redis library is not installed")
        self._client = aioredis.from_url(
            cfg.redis_url, decode_responses=False, ssl=cfg.redis_ssl, client_name=cfg.redis_client_name,
            health_check_interval=int(cfg.redis_health_check_interval), socket_timeout=cfg.redis_socket_timeout,
            max_connections=cfg.redis_pool_size,
        )

    async def ping(self) -> bool:
        try:
            return bool(await self._client.ping())
        except Exception:
            return False

    async def get(self, k: str) -> Optional[Any]:
        raw = await self._client.get(k)
        if raw is None:
            return None
        return self.ser.loads(raw)

    async def set(self, k: str, v: Any, ttl: int, tags: Optional[Sequence[str]]) -> None:
        data = self.ser.dumps(v)
        if len(data) > self.cfg.max_value_bytes:
            raise ValueError("Value too large for cache")
        pipe = self._client.pipeline(transaction=True)
        await pipe.set(k, data, ex=ttl)
        if self.cfg.enable_tags and tags:
            for t in tags:
                await pipe.sadd(_tag_key(self.cfg.namespace, t), k)
                await pipe.expire(_tag_key(self.cfg.namespace, t), max(ttl, 60))
        await pipe.execute()

    async def delete(self, k: str) -> None:
        await self._client.delete(k)

    async def invalidate_tag(self, tag: str) -> int:
        if not self.cfg.enable_tags:
            return 0
        tkey = _tag_key(self.cfg.namespace, tag)
        members = await self._client.smembers(tkey)
        keys = list(members or [])
        removed = 0
        if keys:
            pipe = self._client.pipeline(transaction=True)
            for k in keys:
                await pipe.delete(k)
                removed += 1
            await pipe.delete(tkey)
            await pipe.execute()
        return removed

    async def acquire_lock(self, k: str, ttl: int) -> bool:
        return bool(await self._client.set(k, b"1", nx=True, ex=ttl))
    async def release_lock(self, k: str) -> None:
        with contextlib.suppress(Exception):
            await self._client.delete(k)

# =========================
# Адаптер (единый API)
# =========================

class CacheAdapter(BaseCacheAdapter):
    """
    Единый адаптер кэша:
      - при наличии redis: использует Redis sync/async
      - иначе: LFU in-memory fallback
    Защита от штормов: per-key singleflight через лок (in-proc) и Redis lock (межпроцессный).
    """

    def __init__(self, config: Optional[CacheConfig] = None):
        self.cfg = config or CacheConfig()
        self.ser = pick_serializer(self.cfg)
        self._ns = self.cfg.namespace
        self._ver = self.cfg.version
        self._mem = InMemoryLFUBackend(self.cfg.memory_capacity_items, self.cfg.memory_ttl_seconds)
        self._locks: Dict[str, asyncio.Lock] = {}
        self._locks_sync: Dict[str, asyncio.Lock] = {}
        self._redis_sync: Optional[_RedisSync] = None
        self._redis_async: Optional[_RedisAsync] = None

        if _HAS_REDIS and self.cfg.redis_url:
            with profile_block("cache.redis.init"):
                try:
                    self._redis_sync = _RedisSync(self.cfg, self.ser)
                    self._redis_async = _RedisAsync(self.cfg, self.ser)
                    LOG.info("CacheAdapter: Redis backend enabled url=%s name=%s",
                             self._safe_url(self.cfg.redis_url), self.cfg.redis_client_name)
                except Exception as e:
                    LOG.warning("CacheAdapter: Redis init failed, fallback to memory. err=%s", e)
        else:
            LOG.info("CacheAdapter: using in-memory LFU backend")

    # ---- health ----
    def healthy(self) -> bool:
        if self._redis_sync:
            return self._redis_sync.ping()
        return True
    async def healthy_async(self) -> bool:
        if self._redis_async:
            return await self._redis_async.ping()
        return True

    # ---- get ----
    def get(self, key: str) -> Optional[Any]:
        k = _ns_key(self._ns, self._ver, key)
        # Redis first
        if self._redis_sync:
            with profile_block("cache.redis.get"):
                v = self._redis_sync.get(k)
                if v is not None:
                    return v
        # Fallback
        with profile_block("cache.mem.get"):
            return self._mem.get(k)

    async def get_async(self, key: str) -> Optional[Any]:
        k = _ns_key(self._ns, self._ver, key)
        if self._redis_async:
            async with profile_block("cache.redis.get_async"):  # type: ignore
                v = await self._redis_async.get(k)
                if v is not None:
                    return v
        async with profile_block("cache.mem.get_async"):  # type: ignore
            return self._mem.get(k)

    # ---- set ----
    def set(self, key: str, value: Any, ttl: Optional[int] = None, tags: Optional[Sequence[str]] = None) -> None:
        ttl = _with_jitter(ttl if ttl is not None else self.cfg.default_ttl_seconds, self.cfg.jitter_ratio)
        k = _ns_key(self._ns, self._ver, key)
        if self._redis_sync:
            with profile_block("cache.redis.set"):
                self._redis_sync.set(k, value, ttl, tags)
        with profile_block("cache.mem.set"):
            self._mem.set(k, value, ttl, tags)

    async def set_async(self, key: str, value: Any, ttl: Optional[int] = None, tags: Optional[Sequence[str]] = None) -> None:
        ttl = _with_jitter(ttl if ttl is not None else self.cfg.default_ttl_seconds, self.cfg.jitter_ratio)
        k = _ns_key(self._ns, self._ver, key)
        if self._redis_async:
            async with profile_block("cache.redis.set_async"):  # type: ignore
                await self._redis_async.set(k, value, ttl, tags)
        async with profile_block("cache.mem.set_async"):  # type: ignore
            self._mem.set(k, value, ttl, tags)

    # ---- delete ----
    def delete(self, key: str) -> None:
        k = _ns_key(self._ns, self._ver, key)
        if self._redis_sync:
            with profile_block("cache.redis.del"):
                self._redis_sync.delete(k)
        with profile_block("cache.mem.del"):
            self._mem.delete(k)

    async def delete_async(self, key: str) -> None:
        k = _ns_key(self._ns, self._ver, key)
        if self._redis_async:
            async with profile_block("cache.redis.del_async"):  # type: ignore
                await self._redis_async.delete(k)
        async with profile_block("cache.mem.del_async"):  # type: ignore
            self._mem.delete(k)

    # ---- tags ----
    def invalidate_tag(self, tag: str) -> int:
        removed = 0
        if self._redis_sync:
            with profile_block("cache.redis.invalidate_tag"):
                removed += self._redis_sync.invalidate_tag(tag)
        with profile_block("cache.mem.invalidate_tag"):
            removed += self._mem.invalidate_tag(tag)
        return removed

    async def invalidate_tag_async(self, tag: str) -> int:
        removed = 0
        if self._redis_async:
            async with profile_block("cache.redis.invalidate_tag_async"):  # type: ignore
                removed += await self._redis_async.invalidate_tag(tag)
        async with profile_block("cache.mem.invalidate_tag_async"):  # type: ignore
            removed += self._mem.invalidate_tag(tag)
        return removed

    # ---- get_or_set (штормозащита) ----
    def get_or_set(self, key: str, producer: Callable[[], T], ttl: Optional[int] = None, tags: Optional[Sequence[str]] = None) -> T:
        cached = self.get(key)
        if cached is not None:
            return cached  # type: ignore[return-value]

        lock = self._get_lock_sync(key)
        with profile_block("cache.singleflight.sync"):
            # In-proc singleflight
            loop = asyncio.get_event_loop()
            loop.run_until_complete(lock.acquire())
            try:
                # Double check
                cached2 = self.get(key)
                if cached2 is not None:
                    return cached2  # type: ignore[return-value]
                # Inter-proc Redis lock (best-effort)
                rlock_held = False
                if self._redis_sync:
                    rkey = _lock_key(self._ns, self._ver, key)
                    rlock_held = self._redis_sync.acquire_lock(rkey, self.cfg.lock_ttl_seconds)
                try:
                    value = producer()
                    self.set(key, value, ttl=ttl, tags=tags)
                finally:
                    if self._redis_sync and rlock_held:
                        self._redis_sync.release_lock(_lock_key(self._ns, self._ver, key))
            finally:
                lock.release()
        return self.get(key)  # type: ignore[return-value]

    async def get_or_set_async(self, key: str, producer: Callable[[], Awaitable[T]], ttl: Optional[int] = None, tags: Optional[Sequence[str]] = None) -> T:
        cached = await self.get_async(key)
        if cached is not None:
            return cached  # type: ignore[return-value]

        lock = self._get_lock(key)
        async with profile_block("cache.singleflight.async"):  # type: ignore
            await lock.acquire()
            try:
                cached2 = await self.get_async(key)
                if cached2 is not None:
                    return cached2  # type: ignore[return-value]
                rlock_held = False
                if self._redis_async:
                    rkey = _lock_key(self._ns, self._ver, key)
                    rlock_held = await self._redis_async.acquire_lock(rkey, self.cfg.lock_ttl_seconds)
                try:
                    value = await producer()
                    await self.set_async(key, value, ttl=ttl, tags=tags)
                finally:
                    if self._redis_async and rlock_held:
                        await self._redis_async.release_lock(_lock_key(self._ns, self._ver, key))
            finally:
                lock.release()
        return await self.get_async(key)  # type: ignore[return-value]

    # ---- helpers ----
    def _get_lock(self, key: str) -> asyncio.Lock:
        k = _ns_key(self._ns, self._ver, key)
        lk = self._locks.get(k)
        if lk is None:
            lk = asyncio.Lock()
            self._locks[k] = lk
        return lk

    def _get_lock_sync(self, key: str) -> asyncio.Lock:
        # Используем asyncio.Lock даже в sync — блокируем через loop.run_until_complete
        k = _ns_key(self._ns, self._ver, key)
        lk = self._locks_sync.get(k)
        if lk is None:
            lk = asyncio.Lock()
            self._locks_sync[k] = lk
        return lk

    def _safe_url(self, url: Optional[str]) -> str:
        if not url:
            return "none"
        try:
            # Маскируем пароль в URL
            if "@" in url and "://" in url:
                proto, rest = url.split("://", 1)
                if "@" in rest and ":" in rest.split("@")[0]:
                    cred, host = rest.split("@", 1)
                    user, pwd = cred.split(":", 1)
                    return f"{proto}://{user}:{_redact(pwd)}@{host}"
        except Exception:
            pass
        return url

# =========================
# Декоратор cacheable (удобный API)
# =========================

def cacheable(key_func: Optional[Callable[..., str]] = None,
              ttl: Optional[int] = None,
              tags: Optional[Sequence[str]] = None,
              adapter: Optional[CacheAdapter] = None):
    """
    Декоратор для sync функций.
    """
    def _wrap(fn: Callable[..., T]) -> Callable[..., T]:
        _adapter = adapter or CacheAdapter()
        def _key(*args: Any, **kwargs: Any) -> str:
            if key_func:
                return key_func(*args, **kwargs)
            base = f"{fn.__module__}.{fn.__qualname__}:{hashlib.blake2b(repr((args, kwargs)).encode(), digest_size=12).hexdigest()}"
            return base
        @functools.wraps(fn)  # type: ignore
        def _inner(*args: Any, **kwargs: Any) -> T:
            k = _key(*args, **kwargs)
            return _adapter.get_or_set(k, lambda: fn(*args, **kwargs), ttl=ttl, tags=tags)
        import functools  # local, to keep imports minimal
        return _inner
    return _wrap

def acacheable(key_func: Optional[Callable[..., str]] = None,
               ttl: Optional[int] = None,
               tags: Optional[Sequence[str]] = None,
               adapter: Optional[CacheAdapter] = None):
    """
    Декоратор для async функций.
    """
    def _wrap(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        _adapter = adapter or CacheAdapter()
        def _key(*args: Any, **kwargs: Any) -> str:
            if key_func:
                return key_func(*args, **kwargs)
            base = f"{fn.__module__}.{fn.__qualname__}:{hashlib.blake2b(repr((args, kwargs)).encode(), digest_size=12).hexdigest()}"
            return base
        import functools
        @functools.wraps(fn)
        async def _inner(*args: Any, **kwargs: Any) -> T:
            k = _key(*args, **kwargs)
            return await _adapter.get_or_set_async(k, lambda: fn(*args, **kwargs), ttl=ttl, tags=tags)
        return _inner
    return _wrap
