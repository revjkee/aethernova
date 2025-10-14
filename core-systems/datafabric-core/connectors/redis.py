# datafabric-core/datafabric/connectors/redis.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Protocol, Sequence, Tuple, Union

try:
    from redis import asyncio as aioredis  # redis>=4.2
except Exception as e:  # pragma: no cover
    raise RuntimeError("redis-py with asyncio is required. Install: pip install 'redis>=4.2'") from e

logger = logging.getLogger("datafabric.redis")

# ======================================================================================
# Метрики (интерфейс совместим с остальными коннекторами)
# ======================================================================================

class MetricsSink(Protocol):
    async def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None: ...
    async def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None: ...

class NullMetrics:
    async def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        return
    async def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        return

# ======================================================================================
# Конфигурация
# ======================================================================================

Serializer = Callable[[Any], bytes]
Deserializer = Callable[[bytes], Any]

def json_serializer(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def json_deserializer(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))

def bytes_serializer(obj: Union[bytes, bytearray, memoryview, str]) -> bytes:
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj)
    if isinstance(obj, str):
        return obj.encode("utf-8")
    raise TypeError("bytes_serializer supports bytes or str")

def bytes_deserializer(raw: bytes) -> bytes:
    return raw

@dataclass(frozen=True)
class RedisConfig:
    # DSN пример: redis://:pass@localhost:6379/0  или rediss://... для TLS
    dsn: str = "redis://localhost:6379/0"
    decode_responses: bool = False  # оставляем байты на проводе, сериализация на уровне API
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 5.0
    socket_keepalive: bool = True
    health_check_interval: int = 30
    client_name: str = "datafabric-core"
    retry_max_attempts: int = 5
    retry_base_delay_ms: int = 50
    retry_max_delay_ms: int = 2000

# ======================================================================================
# Вспомогательные функции
# ======================================================================================

def _jit_backoff(attempt: int, base_ms: int, max_ms: int) -> float:
    exp = min(max_ms, base_ms * (2 ** attempt))
    return random.uniform(base_ms, exp) / 1000.0

def _now_ms() -> int:
    return int(time.time() * 1000)

# ======================================================================================
# RedisConnector: lifecycle, health, низкоуровневые операции
# ======================================================================================

class RedisConnector:
    def __init__(self, cfg: RedisConfig, metrics: Optional[MetricsSink] = None) -> None:
        self.cfg = cfg
        self.metrics = metrics or NullMetrics()
        self._client: Optional[aioredis.Redis] = None
        self._lock = asyncio.Lock()
        self._scripts_loaded = False
        self._lua_token_bucket_sha: Optional[str] = None
        self._lua_unlock_sha: Optional[str] = None

    @classmethod
    def create(cls, cfg: RedisConfig, metrics: Optional[MetricsSink] = None) -> "RedisConnector":
        return cls(cfg, metrics)

    async def _ensure(self) -> aioredis.Redis:
        if self._client is not None:
            return self._client
        async with self._lock:
            if self._client is None:
                client = aioredis.from_url(
                    self.cfg.dsn,
                    decode_responses=self.cfg.decode_responses,
                    socket_timeout=self.cfg.socket_timeout,
                    socket_connect_timeout=self.cfg.socket_connect_timeout,
                    health_check_interval=self.cfg.health_check_interval,
                    client_name=self.cfg.client_name,
                )
                self._client = client
                await self._load_scripts()
                logger.info("redis.client.created", extra={"dsn": self._safe_dsn(self.cfg.dsn)})
        return self._client

    def _safe_dsn(self, dsn: str) -> str:
        # Прячем пароль для логов
        if "@" in dsn and "://" in dsn:
            proto, rest = dsn.split("://", 1)
            if ":" in rest and "@" in rest:
                creds, host = rest.split("@", 1)
                return f"{proto}://***@{host}"
        return dsn

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            await self.metrics.incr("redis.closed")
            logger.info("redis.client.closed")
            self._client = None

    async def ping(self) -> bool:
        client = await self._ensure()
        try:
            t0 = time.monotonic()
            pong = await client.ping()
            await self.metrics.observe("redis.ping.ms", (time.monotonic() - t0) * 1000.0)
            return bool(pong)
        except Exception:
            logger.exception("redis.ping.failed")
            return False

    # Унифицированный вызов с ретраями
    async def _with_retry(self, op: str, fn: Callable[[aioredis.Redis], Awaitable[Any]]) -> Any:
        attempt = 0
        while True:
            client = await self._ensure()
            t0 = time.monotonic()
            try:
                res = await fn(client)
                await self.metrics.observe(f"redis.{op}.ms", (time.monotonic() - t0) * 1000.0)
                return res
            except (aioredis.ConnectionError, aioredis.TimeoutError) as e:
                if attempt >= self.cfg.retry_max_attempts:
                    await self.metrics.incr(f"redis.{op}.error")
                    raise
                await self.metrics.incr(f"redis.{op}.retry")
                await asyncio.sleep(_jit_backoff(attempt, self.cfg.retry_base_delay_ms, self.cfg.retry_max_delay_ms))
                attempt += 1

    # Скрипты Lua: токен‑бакет и корректная разблокировка
    async def _load_scripts(self) -> None:
        if self._scripts_loaded:
            return
        client = await self._ensure()
        lua_token_bucket = """
        -- KEYS[1] = bucket key
        -- ARGV[1] = now_ms, ARGV[2] = rate_per_sec, ARGV[3] = burst, ARGV[4] = tokens_required
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local rate = tonumber(ARGV[2])
        local burst = tonumber(ARGV[3])
        local need = tonumber(ARGV[4])

        local data = redis.call('HMGET', key, 'tokens', 'ts')
        local tokens = tonumber(data[1]) or burst
        local ts = tonumber(data[2]) or now
        -- refill
        local delta = math.max(0, now - ts) / 1000.0
        tokens = math.min(burst, tokens + delta * rate)

        if tokens < need then
            -- not enough
            redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
            redis.call('PEXPIRE', key, math.ceil( math.max(1000, 2 * 1000 * (burst / rate)) ))
            return {0, math.ceil((need - tokens) / rate * 1000)}
        else
            tokens = tokens - need
            redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
            redis.call('PEXPIRE', key, math.ceil( math.max(1000, 2 * 1000 * (burst / rate)) ))
            return {1, 0}
        end
        """
        lua_unlock = """
        -- KEYS[1] = lock key
        -- ARGV[1] = token
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        else
            return 0
        end
        """
        self._lua_token_bucket_sha = await client.script_load(lua_token_bucket)
        self._lua_unlock_sha = await client.script_load(lua_unlock)
        self._scripts_loaded = True

    # ==================================================================================
    # КЭШ API
    # ==================================================================================

    async def cache_get(
        self,
        key: str,
        *,
        deserializer: Deserializer = json_deserializer,
    ) -> Optional[Any]:
        def _op(cli: aioredis.Redis):
            return cli.get(name=key)
        raw = await self._with_retry("get", _op)
        if raw is None:
            return None
        if isinstance(raw, str):  # decode_responses=True
            raw = raw.encode("utf-8")
        try:
            return deserializer(raw)
        except Exception:
            # как есть
            return raw

    async def cache_set(
        self,
        key: str,
        value: Any,
        *,
        ttl_seconds: Optional[int] = None,
        serializer: Serializer = json_serializer,
    ) -> bool:
        body = serializer(value)
        def _op(cli: aioredis.Redis):
            return cli.set(name=key, value=body, ex=ttl_seconds)
        ok = await self._with_retry("set", _op)
        return bool(ok)

    async def cache_get_or_set(
        self,
        key: str,
        builder: Callable[[], Awaitable[Any]],
        *,
        ttl_seconds: int = 60,
        lock_ttl_seconds: int = 30,
        serializer: Serializer = json_serializer,
        deserializer: Deserializer = json_deserializer,
    ) -> Any:
        val = await self.cache_get(key, deserializer=deserializer)
        if val is not None:
            return val

        # stampede protection: легкий лок
        lock = await self.lock_acquire(f"lock:{key}", ttl_seconds=lock_ttl_seconds)
        try:
            val2 = await self.cache_get(key, deserializer=deserializer)
            if val2 is not None:
                return val2
            created = await builder()
            await self.cache_set(key, created, ttl_seconds=ttl_seconds, serializer=serializer)
            return created
        finally:
            await lock.release()

    async def cache_invalidate(self, key: str) -> int:
        def _op(cli: aioredis.Redis):
            return cli.delete(key)
        deleted = await self._with_retry("del", _op)
        return int(deleted or 0)

    # ==================================================================================
    # DISTRIBUTED LOCK (корректный)
    # ==================================================================================

    class _Lock:
        def __init__(self, connector: "RedisConnector", key: str, token: str) -> None:
            self._c = connector
            self.key = key
            self.token = token
            self._released = False

        async def release(self) -> bool:
            if self._released:
                return True
            self._released = True
            return await self._c._unlock(self.key, self.token)

    async def lock_acquire(self, key: str, ttl_seconds: int = 30, spin_timeout_seconds: int = 10) -> "_Lock":
        await self._load_scripts()
        token = os.urandom(16).hex()
        deadline = time.monotonic() + max(0.01, spin_timeout_seconds)

        async def try_once(cli: aioredis.Redis) -> bool:
            # NX + PX
            return bool(await cli.set(key, token, nx=True, ex=ttl_seconds))

        while True:
            ok = await self._with_retry("lock.set", lambda c: try_once(c))
            if ok:
                return RedisConnector._Lock(self, key, token)
            if time.monotonic() > deadline:
                raise TimeoutError("Failed to acquire Redis lock")
            await asyncio.sleep(0.05 + random.random() * 0.05)

    async def _unlock(self, key: str, token: str) -> bool:
        await self._load_scripts()
        async def _op(cli: aioredis.Redis):
            return await cli.evalsha(self._lua_unlock_sha, 1, key, token)  # type: ignore
        res = await self._with_retry("lock.del", _op)
        return bool(res)

    # ==================================================================================
    # RATE LIMIT (token bucket на Redis)
    # ==================================================================================

    async def rate_limit_take(
        self,
        key: str,
        *,
        rate_per_sec: float,
        burst: int,
        tokens: int = 1,
    ) -> Tuple[bool, int]:
        """
        Возвращает (ok, wait_ms), где ok=True если токены списаны,
        иначе ok=False и wait_ms рекомендуемая задержка до следующей попытки.
        """
        await self._load_scripts()
        now = _now_ms()

        async def _op(cli: aioredis.Redis):
            return await cli.evalsha(self._lua_token_bucket_sha, 1, key, now, rate_per_sec, burst, tokens)  # type: ignore

        result = await self._with_retry("ratelimit", _op)
        # result = [1/0, wait_ms]
        if isinstance(result, (list, tuple)) and len(result) == 2:
            return (bool(int(result[0])), int(result[1]))
        return (False, 0)

    # ==================================================================================
    # PUB/SUB
    # ==================================================================================

    async def publish(self, channel: str, payload: Any, serializer: Serializer = json_serializer) -> int:
        body = serializer(payload)
        def _op(cli: aioredis.Redis):
            return cli.publish(channel, body)
        return int(await self._with_retry("publish", _op) or 0)

    async def subscribe(self, channels: Sequence[str]) -> AsyncIterator[Tuple[str, bytes]]:
        """
        Асинхронный итератор сообщений (channel, payload_bytes).
        Важно: десериализация остаётся на вызывающей стороне.
        """
        client = await self._ensure()
        pubsub = client.pubsub()
        await pubsub.subscribe(*channels)
        try:
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg is None:
                    await asyncio.sleep(0.01)
                    continue
                # msg = {'type':'message','pattern':None,'channel':b'chan','data':b'...'}
                ch = msg["channel"]
                data = msg["data"]
                if isinstance(ch, bytes):
                    ch = ch.decode("utf-8", "ignore")
                if isinstance(data, str):
                    data = data.encode("utf-8")
                yield (ch, data)
        finally:
            with contextlib.suppress(Exception):
                await pubsub.unsubscribe(*channels)
                await pubsub.close()

    # ==================================================================================
    # STREAMS (XADD/XREADGROUP/ACK/создание группы)
    # ==================================================================================

    async def stream_create_group(self, stream: str, group: str, *, mkstream: bool = True, start_id: str = "$") -> bool:
        def _op(cli: aioredis.Redis):
            return cli.xgroup_create(name=stream, groupname=group, id=start_id, mkstream=mkstream)
        try:
            await self._with_retry("xgroup.create", _op)
            return True
        except aioredis.ResponseError as e:
            # BUSYGROUP
            if "BUSYGROUP" in str(e):
                return True
            raise

    async def stream_add(self, stream: str, fields: Dict[str, Any], *, maxlen: Optional[int] = None, approximate: bool = True) -> str:
        def _op(cli: aioredis.Redis):
            return cli.xadd(name=stream, fields=fields, maxlen=maxlen, approximate=approximate)
        return await self._with_retry("xadd", _op)

    async def stream_read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = 100,
        block_ms: int = 1000,
        noack: bool = False,
        deserialize: bool = True,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        def _op(cli: aioredis.Redis):
            return cli.xreadgroup(groupname=group, consumername=consumer, streams={stream: ">"}, count=count, block=block_ms, noack=noack)
        res = await self._with_retry("xreadgroup", _op)
        # Формат: [(b'stream', [(b'id', {b'k':b'v'}) , ...])]
        out: List[Tuple[str, Dict[str, Any]]] = []
        if not res:
            return out
        for s_name, entries in res:
            s_name = s_name.decode() if isinstance(s_name, bytes) else s_name
            for entry_id, kv in entries:
                entry_id = entry_id.decode() if isinstance(entry_id, bytes) else entry_id
                item: Dict[str, Any] = {}
                for k, v in kv.items():
                    k = k.decode() if isinstance(k, bytes) else k
                    if deserialize:
                        try:
                            if isinstance(v, bytes):
                                # пробуем JSON
                                item[k] = json.loads(v.decode("utf-8"))
                            else:
                                item[k] = v
                        except Exception:
                            item[k] = v
                    else:
                        item[k] = v
                out.append((entry_id, item))
        return out

    async def stream_ack(self, stream: str, group: str, *ids: str) -> int:
        if not ids:
            return 0
        def _op(cli: aioredis.Redis):
            return cli.xack(stream, group, *ids)
        return int(await self._with_retry("xack", _op) or 0)

    async def stream_claim_idle(
        self,
        stream: str,
        group: str,
        consumer: str,
        min_idle_ms: int,
        ids: Sequence[str],
        *,
        justid: bool = False,
    ) -> List[str]:
        def _op(cli: aioredis.Redis):
            return cli.xclaim(stream, group, consumer, min_idle_ms, message_ids=list(ids), justid=justid)
        res = await self._with_retry("xclaim", _op)
        if justid:
            # просто список id
            return [i.decode() if isinstance(i, bytes) else i for i in res]
        # иначе список пар (id, map)
        return [(i[0].decode() if isinstance(i[0], bytes) else i[0]) for i in res]

# ======================================================================================
# Высокоуровневые фасады для типичных задач
# ======================================================================================

class RedisCache:
    def __init__(self, connector: RedisConnector, prefix: str = "cache:") -> None:
        self.c = connector
        self.prefix = prefix

    def _k(self, key: str) -> str:
        return f"{self.prefix}{key}"

    async def get(self, key: str, *, deserializer: Deserializer = json_deserializer) -> Optional[Any]:
        return await self.c.cache_get(self._k(key), deserializer=deserializer)

    async def set(self, key: str, value: Any, *, ttl_seconds: Optional[int] = None, serializer: Serializer = json_serializer) -> bool:
        return await self.c.cache_set(self._k(key), value, ttl_seconds=ttl_seconds, serializer=serializer)

    async def get_or_set(
        self,
        key: str,
        builder: Callable[[], Awaitable[Any]],
        *,
        ttl_seconds: int = 60,
        lock_ttl_seconds: int = 30,
        serializer: Serializer = json_serializer,
        deserializer: Deserializer = json_deserializer,
    ) -> Any:
        return await self.c.cache_get_or_set(self._k(key), builder, ttl_seconds=ttl_seconds, lock_ttl_seconds=lock_ttl_seconds,
                                             serializer=serializer, deserializer=deserializer)

    async def invalidate(self, key: str) -> int:
        return await self.c.cache_invalidate(self._k(key))

# ======================================================================================
# Пример самостоятельного запуска: python -m datafabric.connectors.redis
# ======================================================================================

async def _demo() -> None:
    dsn = os.getenv("REDIS_DSN", "redis://localhost:6379/0")
    conn = RedisConnector.create(RedisConfig(dsn=dsn))
    print("ping:", await conn.ping())

    cache = RedisCache(conn)
    await cache.set("demo", {"x": 1}, ttl_seconds=10)
    print("cache.get:", await cache.get("demo"))

    ok, wait_ms = await conn.rate_limit_take("rl:demo", rate_per_sec=5.0, burst=10, tokens=3)
    print("ratelimit:", ok, wait_ms)

    lock = await conn.lock_acquire("lock:demo", ttl_seconds=5)
    print("lock acquired")
    await lock.release()
    print("lock released")

    await conn.stream_create_group("s:demo", "g1")
    _id = await conn.stream_add("s:demo", {"k": json.dumps({"hello": "world"})})
    msgs = await conn.stream_read_group("s:demo", "g1", "c1", count=10, block_ms=500)
    if msgs:
        ids = [m[0] for m in msgs]
        await conn.stream_ack("s:demo", "g1", *ids)
        print("stream acked:", ids)

    await conn.close()

if __name__ == "__main__":
    import contextlib
    asyncio.run(_demo())
