# core-systems/genius_core/security/self_inhibitor/adapters/redis_adapter.py
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Optional, Tuple, Union

# ---- Optional: redis.asyncio (required at runtime) ----
try:
    import redis.asyncio as aioredis
    from redis.asyncio.client import Redis
    from redis.asyncio.cluster import RedisCluster
    from redis.asyncio.sentinel import Sentinel
except Exception as e:  # pragma: no cover
    aioredis = None
    Redis = RedisCluster = Sentinel = object  # type: ignore


# ---- JSON helpers (orjson fallback) ----
def _json_dumps(obj: Any) -> bytes:
    try:
        import orjson  # type: ignore
        return orjson.dumps(obj)
    except Exception:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _json_loads(data: Union[bytes, str, None]) -> Any:
    if data is None:
        return None
    if isinstance(data, bytes):
        s = data
    else:
        s = data.encode("utf-8")
    try:
        import orjson  # type: ignore
        return orjson.loads(s)
    except Exception:
        return json.loads(s.decode("utf-8"))


# ---- Dataclasses ----
@dataclass
class RedisConfig:
    # Connection modes:
    #   - Standalone: url="redis://host:6379/0"
    #   - TLS:       url="rediss://host:6380/0"
    #   - Sentinel:  url=None, sentinel_hosts=["host1:26379","host2:26379"], sentinel_master="mymaster"
    #   - Cluster:   cluster_nodes=["host1:6379","host2:6379"]
    url: Optional[str] = os.getenv("REDIS_URL")  # e.g. redis://localhost:6379/0
    db: Optional[int] = None
    password: Optional[str] = None
    decode_responses: bool = False
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 5.0
    retry_on_timeout: bool = True
    # Sentinel
    sentinel_hosts: Optional[List[str]] = None
    sentinel_master: Optional[str] = None
    sentinel_password: Optional[str] = None
    # Cluster
    cluster_nodes: Optional[List[str]] = None
    cluster_password: Optional[str] = None
    # Key prefix
    namespace: str = "genius:self-inhibitor"
    # Pool sizing
    max_connections: int = 64
    # PubSub/Streams defaults
    pubsub_encoding: str = "utf-8"


class RedisAdapterError(RuntimeError):
    pass


class RedisAdapter:
    """
    Industrial-grade async Redis adapter for Self-Inhibitor:
    - Namespaced keys
    - Atomic Lua scripts for rate-limit & sliding window
    - Distributed locks (SET NX PX)
    - Pub/Sub + Streams
    - Circuit breaker state
    - JSON cache with versioning
    - Health probes
    """

    def __init__(self, cfg: RedisConfig) -> None:
        if aioredis is None:
            raise RedisAdapterError("redis.asyncio is not available. Install redis>=4.5")
        self.cfg = cfg
        self._redis: Optional[Union[Redis, RedisCluster]] = None
        self._closing = False

        # Preload Lua scripts (they bind on first use)
        self._lua_incr_ttl = None
        self._lua_sliding_window = None
        self._lua_token_bucket = None
        self._lua_circuit_trip = None
        self._lua_circuit_probe = None

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #
    async def connect(self) -> None:
        if self._redis is not None:
            return

        # Cluster mode
        if self.cfg.cluster_nodes:
            self._redis = RedisCluster.from_url(
                f"redis://{self.cfg.cluster_nodes[0]}",
                password=self.cfg.cluster_password or self.cfg.password,
                socket_timeout=self.cfg.socket_timeout,
                socket_connect_timeout=self.cfg.socket_connect_timeout,
                decode_responses=self.cfg.decode_responses,
                max_connections=self.cfg.max_connections,
                retry_on_timeout=self.cfg.retry_on_timeout,
            )
            # RedisCluster connects lazily; ping establishes cluster metadata
            await self._redis.ping()
            return

        # Sentinel mode
        if self.cfg.sentinel_hosts and self.cfg.sentinel_master:
            sent_hosts = []
            for h in self.cfg.sentinel_hosts:
                host, port = h.split(":")
                sent_hosts.append((host, int(port)))
            sentinel = Sentinel(
                sent_hosts,
                socket_timeout=self.cfg.socket_timeout,
                password=self.cfg.sentinel_password or self.cfg.password,
                decode_responses=self.cfg.decode_responses,
            )
            self._redis = sentinel.master_for(
                self.cfg.sentinel_master,
                db=self.cfg.db or 0,
                password=self.cfg.password,
                socket_timeout=self.cfg.socket_timeout,
                decode_responses=self.cfg.decode_responses,
                max_connections=self.cfg.max_connections,
            )
            await self._redis.ping()
            return

        # Standalone / rediss
        url = self.cfg.url or "redis://localhost:6379/0"
        self._redis = aioredis.from_url(
            url,
            db=self.cfg.db,
            password=self.cfg.password,
            socket_timeout=self.cfg.socket_timeout,
            socket_connect_timeout=self.cfg.socket_connect_timeout,
            decode_responses=self.cfg.decode_responses,
            max_connections=self.cfg.max_connections,
            retry_on_timeout=self.cfg.retry_on_timeout,
        )
        await self._redis.ping()

    async def close(self) -> None:
        self._closing = True
        if self._redis is not None:
            with contextlib.suppress(Exception):
                await self._redis.close()
        self._redis = None

    def _r(self) -> Union[Redis, RedisCluster]:
        if self._redis is None:
            raise RedisAdapterError("Redis not connected. Call connect() first.")
        return self._redis

    # ------------------------------------------------------------------ #
    # Namespacing helpers
    # ------------------------------------------------------------------ #
    def _k(self, *parts: str) -> str:
        # Join parts into namespaced Redis key
        return ":".join([self.cfg.namespace, *[p for p in parts if p]])

    # ------------------------------------------------------------------ #
    # Health / Info
    # ------------------------------------------------------------------ #
    async def ping(self) -> bool:
        return bool(await self._r().ping())

    async def info(self, section: str = "server") -> Dict[str, Any]:
        return await self._r().info(section=section)

    # ------------------------------------------------------------------ #
    # JSON cache with versioning
    # ------------------------------------------------------------------ #
    async def cache_set(self, group: str, key: str, value: Any, ttl_s: Optional[int] = None, version: Optional[str] = None) -> None:
        """
        Store JSON value; if version is provided, it is stored in side-key for invalidation.
        """
        r = self._r()
        data = _json_dumps(value)
        k = self._k("cache", group, key)
        pipe = r.pipeline()
        pipe.set(k, data, ex=ttl_s)
        if version:
            pipe.set(self._k("cache", group, key, "ver"), version, ex=ttl_s)
        await pipe.execute()

    async def cache_get(self, group: str, key: str, require_version: Optional[str] = None) -> Optional[Any]:
        r = self._r()
        k = self._k("cache", group, key)
        if require_version:
            vkey = self._k("cache", group, key, "ver")
            vals = await r.mget(k, vkey)
            if vals[0] is None:
                return None
            if vals[1] is not None and vals[1].decode() != require_version if isinstance(vals[1], bytes) else vals[1] != require_version:
                return None
            return _json_loads(vals[0])
        raw = await r.get(k)
        return _json_loads(raw)

    # ------------------------------------------------------------------ #
    # Atomic counters with TTL (fixed window)
    # ------------------------------------------------------------------ #
    async def incr_with_ttl(self, bucket: str, ttl_s: int) -> Tuple[int, int]:
        """
        Atomically increments a counter and ensures TTL is set.
        Returns (value, ttl_remaining_seconds).
        """
        if self._lua_incr_ttl is None:
            self._lua_incr_ttl = self._r().register_script(
                """
                local v = redis.call('INCR', KEYS[1])
                if v == 1 then
                  redis.call('PEXPIRE', KEYS[1], ARGV[1])
                  return {v, ARGV[1]}
                else
                  local ttl = redis.call('PTTL', KEYS[1])
                  return {v, ttl}
                end
                """
            )
        ttl_ms = int(ttl_s * 1000)
        res = await self._lua_incr_ttl(keys=[self._k("ctr", bucket)], args=[ttl_ms])
        val, ttl = int(res[0]), int(res[1])
        return val, max(0, ttl // 1000)

    # ------------------------------------------------------------------ #
    # Sliding window rate limit (ZSET) — exact
    # ------------------------------------------------------------------ #
    async def rate_limit_sliding(
        self,
        key: str,
        limit: int,
        window_s: int,
        now_ms: Optional[int] = None,
        cost: int = 1,
    ) -> Tuple[bool, int]:
        """
        Exact sliding window limiter using ZSET with timestamps.
        Returns (allowed, remaining).
        """
        if self._lua_sliding_window is None:
            self._lua_sliding_window = self._r().register_script(
                """
                -- KEYS[1] = zset key
                -- ARGV[1] = now_ms
                -- ARGV[2] = window_ms
                -- ARGV[3] = limit
                -- ARGV[4] = cost
                local now = tonumber(ARGV[1])
                local window = tonumber(ARGV[2])
                local limit = tonumber(ARGV[3])
                local cost = tonumber(ARGV[4])
                local minscore = now - window

                redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, minscore)
                local count = redis.call('ZCARD', KEYS[1])
                if (count + cost) > limit then
                  return {0, math.max(0, limit - count)}
                end
                for i=1,cost,1 do
                  redis.call('ZADD', KEYS[1], now, now .. '-' .. i .. '-' .. math.random(1000000))
                end
                -- keep TTL slightly above window
                redis.call('PEXPIRE', KEYS[1], window + 1000)
                local remaining = limit - (count + cost)
                return {1, remaining}
                """
            )
        now_ms = int(now_ms or time.time() * 1000)
        allowed, remaining = await self._lua_sliding_window(
            keys=[self._k("rlw", key)], args=[now_ms, int(window_s * 1000), limit, max(1, cost)]
        )
        return bool(int(allowed)), int(remaining)

    # ------------------------------------------------------------------ #
    # Token bucket limiter (approximate, O(1))
    # ------------------------------------------------------------------ #
    async def rate_limit_token_bucket(
        self,
        key: str,
        capacity: int,
        refill_tokens: int,
        refill_interval_s: int,
        now_ms: Optional[int] = None,
        cost: int = 1,
    ) -> Tuple[bool, int, int]:
        """
        Token bucket stored as HASH:
          fields: tokens, updated_ms
        Lua ensures atomic refill + consume.
        Returns (allowed, tokens_left, ttl_s)
        """
        if self._lua_token_bucket is None:
            self._lua_token_bucket = self._r().register_script(
                """
                -- KEYS[1] = hash key
                -- ARGV: now_ms, capacity, refill_tokens, refill_ms, cost
                local now = tonumber(ARGV[1])
                local capacity = tonumber(ARGV[2])
                local refill = tonumber(ARGV[3])
                local refill_ms = tonumber(ARGV[4])
                local cost = tonumber(ARGV[5])

                local h = redis.call('HMGET', KEYS[1], 'tokens', 'updated_ms')
                local tokens = tonumber(h[1]) or capacity
                local updated = tonumber(h[2]) or now

                -- compute refills
                if now > updated then
                  local elapsed = now - updated
                  local rounds = math.floor(elapsed / refill_ms)
                  if rounds > 0 then
                    tokens = math.min(capacity, tokens + rounds * refill)
                    updated = updated + rounds * refill_ms
                  end
                end

                local allowed = 0
                if tokens >= cost then
                  tokens = tokens - cost
                  allowed = 1
                end

                redis.call('HMSET', KEYS[1], 'tokens', tokens, 'updated_ms', updated)
                -- TTL > 2 * refill interval to cleanup idle buckets
                redis.call('PEXPIRE', KEYS[1], 2 * refill_ms)

                local ttl = redis.call('PTTL', KEYS[1])
                return {allowed, tokens, ttl}
                """
            )
        now_ms = int(now_ms or time.time() * 1000)
        allowed, tokens, ttl = await self._lua_token_bucket(
            keys=[self._k("tbb", key)],
            args=[now_ms, capacity, refill_tokens, int(refill_interval_s * 1000), max(1, cost)],
        )
        return bool(int(allowed)), int(tokens), max(0, int(ttl) // 1000)

    # ------------------------------------------------------------------ #
    # Distributed lock (SET NX PX) — simple Redlock variant
    # ------------------------------------------------------------------ #
    @contextlib.asynccontextmanager
    async def lock(self, name: str, ttl_ms: int = 10000, wait_timeout_ms: int = 2000, retry_ms: int = 100) -> AsyncIterator[bool]:
        """
        Async context manager that acquires a lock key and ensures delete on exit if still owner.
        Returns True if acquired, else False (context still enters).
        """
        token = uuid.uuid4().hex
        key = self._k("lock", name)
        r = self._r()
        deadline = time.time() + (wait_timeout_ms / 1000.0)
        acquired = False
        try:
            while time.time() < deadline and not self._closing:
                ok = await r.set(key, token, px=ttl_ms, nx=True)
                if ok:
                    acquired = True
                    break
                await asyncio.sleep(retry_ms / 1000.0)
            yield acquired
        finally:
            if acquired:
                # Release if owner
                lua = r.register_script(
                    """
                    if redis.call('GET', KEYS[1]) == ARGV[1] then
                      return redis.call('DEL', KEYS[1])
                    else
                      return 0
                    end
                    """
                )
                with contextlib.suppress(Exception):
                    await lua(keys=[key], args=[token])

    # ------------------------------------------------------------------ #
    # Pub/Sub
    # ------------------------------------------------------------------ #
    async def publish(self, channel: str, payload: Dict[str, Any]) -> int:
        data = _json_dumps(payload)
        return int(await self._r().publish(self._k("pub", channel), data))

    async def subscribe(self, channel: str) -> AsyncIterator[Dict[str, Any]]:
        pubkey = self._k("pub", channel)
        pubsub = self._r().pubsub()
        await pubsub.subscribe(pubkey)
        try:
            async for msg in pubsub.listen():
                if msg is None:
                    continue
                if msg.get("type") != "message":
                    continue
                yield _json_loads(msg.get("data"))
        finally:
            with contextlib.suppress(Exception):
                await pubsub.unsubscribe(pubkey)
                await pubsub.close()

    # ------------------------------------------------------------------ #
    # Streams (XADD / XREADGROUP) — for rule updates / audit pipelines
    # ------------------------------------------------------------------ #
    async def xadd_json(self, stream: str, obj: Dict[str, Any], maxlen: Optional[int] = 10000) -> str:
        fields = {"data": _json_dumps(obj)}
        return await self._r().xadd(self._k("str", stream), fields, maxlen=maxlen, approximate=True)

    async def xreadgroup_json(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int = 16,
        block_ms: int = 1000,
    ) -> List[Tuple[str, str, Dict[str, Any]]]:
        """
        Returns list of (stream, id, obj)
        """
        r = self._r()
        key = self._k("str", stream)
        with contextlib.suppress(Exception):
            await r.xgroup_create(name=key, groupname=group, id="0-0", mkstream=True)
        res = await r.xreadgroup(groupname=group, consumername=consumer, streams={key: ">"}, count=count, block=block_ms)
        out: List[Tuple[str, str, Dict[str, Any]]] = []
        for s, items in res or []:
            for mid, fields in items:
                raw = fields.get(b"data") if isinstance(fields, dict) else None
                out.append((s.decode() if isinstance(s, bytes) else str(s), mid.decode() if isinstance(mid, bytes) else str(mid), _json_loads(raw)))
        return out

    async def xack(self, stream: str, group: str, msg_id: str) -> int:
        return int(await self._r().xack(self._k("str", stream), group, msg_id))

    # ------------------------------------------------------------------ #
    # Circuit breaker state (HASH)
    # ------------------------------------------------------------------ #
    async def circuit_trip(self, name: str, failure_threshold: int, cool_down_s: int) -> Dict[str, Any]:
        """
        Increment failures; if threshold crossed, set state=open with reset_at.
        Returns current state dict.
        """
        if self._lua_circuit_trip is None:
            self._lua_circuit_trip = self._r().register_script(
                """
                -- KEYS[1] = hash key
                -- ARGV: now, threshold, cool_down
                local now = tonumber(ARGV[1])
                local th  = tonumber(ARGV[2])
                local cd  = tonumber(ARGV[3])

                local st = redis.call('HGETALL', KEYS[1])
                local state = {}
                for i=1,#st,2 do state[st[i]] = st[i+1] end

                local failures = tonumber(state['failures'] or '0') + 1
                local mode = state['state'] or 'closed'
                local reset_at = tonumber(state['reset_at'] or '0')

                if failures >= th then
                  mode = 'open'
                  reset_at = now + cd
                end

                redis.call('HMSET', KEYS[1], 'failures', failures, 'state', mode, 'reset_at', reset_at, 'updated_at', now)
                redis.call('EXPIRE', KEYS[1], math.max(cd, 60))
                return {mode, failures, reset_at}
                """
            )
        now = int(time.time())
        mode, failures, reset_at = await self._lua_circuit_trip(keys=[self._k("cb", name)], args=[now, failure_threshold, cool_down_s])
        return {"state": mode.decode() if isinstance(mode, bytes) else mode, "failures": int(failures), "reset_at": int(reset_at)}

    async def circuit_probe(self, name: str) -> Dict[str, Any]:
        """
        If open and now >= reset_at, switch to half_open, else return current.
        """
        if self._lua_circuit_probe is None:
            self._lua_circuit_probe = self._r().register_script(
                """
                local now = tonumber(ARGV[1])
                local st = redis.call('HGETALL', KEYS[1])
                local state = {}
                for i=1,#st,2 do state[st[i]] = st[i+1] end

                local mode = state['state'] or 'closed'
                local reset_at = tonumber(state['reset_at'] or '0')

                if mode == 'open' and now >= reset_at then
                  mode = 'half_open'
                  redis.call('HSET', KEYS[1], 'state', mode, 'updated_at', now)
                end
                return {mode, tonumber(state['failures'] or '0'), reset_at}
                """
            )
        now = int(time.time())
        mode, failures, reset_at = await self._lua_circuit_probe(keys=[self._k("cb", name)], args=[now])
        return {"state": mode.decode() if isinstance(mode, bytes) else mode, "failures": int(failures), "reset_at": int(reset_at)}

    async def circuit_reset_success(self, name: str) -> None:
        """
        On success in half_open => close and reset failure counter.
        """
        await self._r().hset(self._k("cb", name), mapping={"state": "closed", "failures": 0, "updated_at": int(time.time())})

    # ------------------------------------------------------------------ #
    # High-level helpers for Self-Inhibitor
    # ------------------------------------------------------------------ #
    async def publish_rules_update(self, version: str, checksum: str, by: str = "policy-service") -> int:
        """
        Publish rules version so all app instances hot-reload from cache/source.
        """
        payload = {"type": "rules.update", "version": version, "checksum": checksum, "by": by, "ts": int(time.time())}
        return await self.publish("rules", payload)

    async def get_rules_from_cache(self) -> Optional[Dict[str, Any]]:
        """
        Get current rules set (denylist) stored under cache group 'rules' key 'denylist'.
        """
        return await self.cache_get("rules", "denylist")

    async def set_rules_to_cache(self, rules: Dict[str, Any], ttl_s: int = 3600, version: Optional[str] = None) -> None:
        await self.cache_set("rules", "denylist", rules, ttl_s=ttl_s, version=version)

    # ------------------------------------------------------------------ #
    # Convenience wrappers (KV / HASH)
    # ------------------------------------------------------------------ #
    async def kv_set_json(self, name: str, value: Any, ttl_s: Optional[int] = None) -> None:
        await self._r().set(self._k("kv", name), _json_dumps(value), ex=ttl_s)

    async def kv_get_json(self, name: str) -> Any:
        raw = await self._r().get(self._k("kv", name))
        return _json_loads(raw)

    async def hset_json(self, name: str, field: str, value: Any) -> None:
        await self._r().hset(self._k("hash", name), field, _json_dumps(value))

    async def hget_json(self, name: str, field: str) -> Any:
        raw = await self._r().hget(self._k("hash", name), field)
        return _json_loads(raw)

    # ------------------------------------------------------------------ #
    # Example policies: allow() using sliding window
    # ------------------------------------------------------------------ #
    async def allow_request(self, subject: str, limit: int, window_s: int, cost: int = 1) -> Dict[str, Any]:
        """
        Convenience wrapper for a typical API limiter:
          subject: user_id|ip|tool_name
        """
        key = f"{subject}"
        allowed, remaining = await self.rate_limit_sliding(key=key, limit=limit, window_s=window_s, cost=cost)
        return {
            "allowed": allowed,
            "remaining": remaining,
            "window_seconds": window_s,
        }


# ---------------------------------------------------------------------- #
# Simple manual test (optional)
# ---------------------------------------------------------------------- #
if __name__ == "__main__":  # pragma: no cover
    async def _demo():
        cfg = RedisConfig(url=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        r = RedisAdapter(cfg)
        await r.connect()
        print("Ping:", await r.ping())

        # Sliding window
        for i in range(5):
            print("allow", i, await r.allow_request("demo-user", 3, 5))

        # Token bucket: capacity=5, +1 token/second
        for i in range(8):
            ok, tokens, ttl = await r.rate_limit_token_bucket("demo-user", 5, 1, 1, cost=1)
            print("bucket", i, ok, tokens, ttl)
            await asyncio.sleep(0.3)

        # Lock
        async with r.lock("critical-section", ttl_ms=2000, wait_timeout_ms=500) as acquired:
            print("lock acquired:", acquired)

        # Circuit breaker
        print("trip:", await r.circuit_trip("ext-api", failure_threshold=3, cool_down_s=10))
        print("probe:", await r.circuit_probe("ext-api"))

        # Pub/Sub
        async def _sub():
            async for m in r.subscribe("rules"):
                print("SUB:", m)
                break

        sub_task = asyncio.create_task(_sub())
        await asyncio.sleep(0.1)
        await r.publish_rules_update(version="1.0.0", checksum="deadbeef")
        await asyncio.sleep(0.2)
        sub_task.cancel()

        await r.close()

    asyncio.run(_demo())
