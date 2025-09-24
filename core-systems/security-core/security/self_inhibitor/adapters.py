# File: security-core/security/self_inhibitor/adapters.py
# Purpose: Industrial-grade self-inhibitor (dynamic temporary blocking) with pluggable stores.
# Python: 3.10+

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

try:
    # Optional Redis backend (install: pip install redis>=4.5)
    import redis.asyncio as aioredis  # type: ignore
except Exception:
    aioredis = None  # type: ignore


# =========================
# Errors
# =========================

class InhibitorError(Exception):
    pass


# =========================
# Domain primitives
# =========================

class Scope(str, Enum):
    USER = "user"
    IP = "ip"
    DEVICE = "device"
    TOKEN = "token"
    CREDENTIAL = "credential"
    TENANT = "tenant"
    GLOBAL = "global"


@dataclass(frozen=True)
class InhibitionKey:
    scope: Scope
    identifier: str          # raw identifier (not stored; only HMACed)
    operation: str           # e.g. "authn.login", "secrets.get"

    def normalized(self) -> str:
        # Lowercase op, strip spaces
        return f"{self.operation.strip().lower()}|{self.scope.value}"


@dataclass(frozen=True)
class Policy:
    # Sliding window threshold policy with cooldown and exponential backoff
    threshold: int                 # events per window to trigger inhibition
    window_sec: int                # sliding window size
    cooldown_sec: int              # base cooldown duration
    backoff_multiplier: float = 2.0
    max_cooldown_sec: int = 3600
    strike_ttl_sec: int = 3600     # window for counting strikes (escalation period)
    quarantine_ttl_sec: int = 30   # local fast quarantine
    min_counter_ttl_sec: int = 1   # floor TTL for window counters


class InhibitSource(str, Enum):
    NONE = "none"
    QUARANTINE = "quarantine"
    MANUAL = "manual"
    THRESHOLD = "threshold"


@dataclass(frozen=True)
class Decision:
    inhibited: bool
    source: InhibitSource = InhibitSource.NONE
    reason: str = ""
    ttl_remaining_sec: int = 0
    counter_value: int = 0
    strikes: int = 0


# =========================
# Hashing (PII-safe keys)
# =========================

@dataclass(frozen=True)
class PepperConfig:
    pepper: str
    label: str = "v1"


class Hasher:
    def __init__(self, cfg: PepperConfig) -> None:
        if not cfg.pepper or len(cfg.pepper) < 16:
            raise InhibitorError("INHIBITOR_PEPPER must be provided and be at least 16 characters")
        self.cfg = cfg

    def key(self, inh_key: InhibitionKey) -> str:
        seed = f"{self.cfg.label}|{inh_key.normalized()}|{inh_key.identifier}".encode("utf-8")
        mac = hmac.new(self.cfg.pepper.encode("utf-8"), seed, hashlib.sha256)
        digest = mac.hexdigest()
        # Redis-safe and compact key
        return f"inh:{inh_key.operation}:{inh_key.scope.value}:{digest}"


# =========================
# Stores and quarantine protocols
# =========================

class Clock(Protocol):
    def now(self) -> int: ...


class SystemClock:
    def now(self) -> int:
        return int(time.time())


class Store(Protocol):
    # Counters (sliding window with TTL)
    async def incr_window(self, key: str, ttl_sec: int) -> int: ...
    # Strikes (escalation counter)
    async def incr_strikes(self, key: str, ttl_sec: int) -> int: ...
    # Inhibition flag with TTL; set if absent
    async def set_inhibit_if_absent(self, key: str, ttl_sec: int, reason: str) -> bool: ...
    # Manual inhibit (force set/override ttl)
    async def set_inhibit(self, key: str, ttl_sec: int, reason: str) -> None: ...
    # Check inhibition TTL and reason
    async def get_inhibit(self, key: str) -> Tuple[int, Optional[str]]: ...
    # Clear all state for key (inhibit + counters + strikes)
    async def clear(self, key: str) -> None: ...


class Quarantine(Protocol):
    async def add(self, key: str, ttl_sec: int, reason: str) -> None: ...
    async def ttl(self, key: str) -> int: ...
    async def clear(self, key: str) -> None: ...


# =========================
# In-memory implementations
# =========================

class InMemoryQuarantine:
    def __init__(self) -> None:
        self._m: Dict[str, Tuple[int, str]] = {}
        self._lock = asyncio.Lock()

    async def add(self, key: str, ttl_sec: int, reason: str) -> None:
        async with self._lock:
            self._m[key] = (int(time.time()) + max(0, ttl_sec), reason)

    async def ttl(self, key: str) -> int:
        async with self._lock:
            v = self._m.get(key)
            if not v:
                return 0
            exp, _ = v
            now = int(time.time())
            if now >= exp:
                self._m.pop(key, None)
                return 0
            return exp - now

    async def clear(self, key: str) -> None:
        async with self._lock:
            self._m.pop(key, None)


class InMemoryStore:
    def __init__(self) -> None:
        self._cnt: Dict[str, Tuple[int, int]] = {}         # key -> (exp_ts, count)
        self._strikes: Dict[str, Tuple[int, int]] = {}     # key -> (exp_ts, strikes)
        self._inh: Dict[str, Tuple[int, str]] = {}         # key -> (exp_ts, reason)
        self._lock = asyncio.Lock()

    async def incr_window(self, key: str, ttl_sec: int) -> int:
        now = int(time.time())
        async with self._lock:
            exp, c = self._cnt.get(key, (0, 0))
            if now >= exp:
                exp = now + max(1, ttl_sec)
                c = 0
            c += 1
            self._cnt[key] = (exp, c)
            return c

    async def incr_strikes(self, key: str, ttl_sec: int) -> int:
        now = int(time.time())
        async with self._lock:
            exp, s = self._strikes.get(key, (0, 0))
            if now >= exp:
                exp = now + max(1, ttl_sec)
                s = 0
            s += 1
            self._strikes[key] = (exp, s)
            return s

    async def set_inhibit_if_absent(self, key: str, ttl_sec: int, reason: str) -> bool:
        now = int(time.time())
        async with self._lock:
            exp, _ = self._inh.get(key, (0, ""))
            if now < exp:
                return False
            self._inh[key] = (now + max(1, ttl_sec), reason)
            return True

    async def set_inhibit(self, key: str, ttl_sec: int, reason: str) -> None:
        now = int(time.time())
        async with self._lock:
            self._inh[key] = (now + max(1, ttl_sec), reason)

    async def get_inhibit(self, key: str) -> Tuple[int, Optional[str]]:
        now = int(time.time())
        async with self._lock:
            exp, reason = self._inh.get(key, (0, None))  # type: ignore
            if now >= exp:
                self._inh.pop(key, None)
                return 0, None
            return exp - now, reason

    async def clear(self, key: str) -> None:
        async with self._lock:
            self._inh.pop(key, None)
            self._cnt.pop(key, None)
            self._strikes.pop(key, None)


# =========================
# Redis implementation (atomic with Lua)
# =========================

class RedisStore:
    """
    Keys:
      inw:{key}       -> window counter (EX window)
      ins:{key}       -> strikes counter (EX strike_ttl)
      inh:{key}       -> "reason" string (EX cooldown)
    """
    LUA_INCR_COUNTER = """
    -- KEYS[1]=inw, KEYS[2]=inh, KEYS[3]=ins
    -- ARGV[1]=window_ttl, ARGV[2]=strike_ttl
    local c = redis.call('INCR', KEYS[1])
    if c == 1 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1])) end
    local inh_ttl = redis.call('TTL', KEYS[2])
    if inh_ttl < 0 then inh_ttl = 0 end
    return {c, inh_ttl}
    """

    def __init__(self, client, *, prefix: str = "inh") -> None:
        if aioredis is None:
            raise InhibitorError("redis.asyncio is not installed")
        self.r = client
        self.p = prefix
        self._lua_incr = None  # filled lazily

    def _k_inw(self, key: str) -> str:
        return f"{self.p}:inw:{key}"

    def _k_ins(self, key: str) -> str:
        return f"{self.p}:ins:{key}"

    def _k_inh(self, key: str) -> str:
        return f"{self.p}:inh:{key}"

    async def _ensure_scripts(self) -> None:
        if self._lua_incr is None:
            self._lua_incr = await self.r.script_load(self.LUA_INCR_COUNTER)

    async def incr_window(self, key: str, ttl_sec: int) -> int:
        await self._ensure_scripts()
        try:
            c, _inh_ttl = await self.r.evalsha(self._lua_incr, 3, self._k_inw(key), self._k_inh(key), self._k_ins(key), int(ttl_sec), 0)
            return int(c)
        except Exception:
            # Fallback non-Lua path
            c = await self.r.incr(self._k_inw(key))
            if c == 1:
                await self.r.expire(self._k_inw(key), int(ttl_sec))
            return int(c)

    async def incr_strikes(self, key: str, ttl_sec: int) -> int:
        s = await self.r.incr(self._k_ins(key))
        if s == 1:
            await self.r.expire(self._k_ins(key), int(ttl_sec))
        return int(s)

    async def set_inhibit_if_absent(self, key: str, ttl_sec: int, reason: str) -> bool:
        ok = await self.r.set(self._k_inh(key), reason, ex=int(ttl_sec), nx=True)
        return bool(ok)

    async def set_inhibit(self, key: str, ttl_sec: int, reason: str) -> None:
        await self.r.set(self._k_inh(key), reason, ex=int(ttl_sec))

    async def get_inhibit(self, key: str) -> Tuple[int, Optional[str]]:
        ttl = await self.r.ttl(self._k_inh(key))
        if ttl is None or ttl <= 0:
            return 0, None
        val = await self.r.get(self._k_inh(key))
        reason = val.decode() if isinstance(val, (bytes, bytearray)) else (val or None)
        return int(ttl), reason

    async def clear(self, key: str) -> None:
        await self.r.delete(self._k_inh(key), self._k_inw(key), self._k_ins(key))


# =========================
# Inhibitor manager (facade)
# =========================

class Inhibitor:
    def __init__(
        self,
        store: Store,
        hasher: Hasher,
        *,
        quarantine: Optional[Quarantine] = None,
        clock: Optional[Clock] = None,
    ) -> None:
        self.store = store
        self.hasher = hasher
        self.quarantine = quarantine or InMemoryQuarantine()
        self.clock = clock or SystemClock()

    async def record_event(self, key: InhibitionKey, policy: Policy) -> Decision:
        """
        Record one event for the key under the given policy.
        Returns a Decision with current state and potential inhibition.
        """
        hk = self.hasher.key(key)
        # 1) quarantine check
        q_ttl = await self.quarantine.ttl(hk)
        if q_ttl > 0:
            return Decision(True, InhibitSource.QUARANTINE, "quarantine", q_ttl, 0, 0)

        # 2) increment window counter
        counter = await self.store.incr_window(hk, max(policy.min_counter_ttl_sec, policy.window_sec))

        # 3) existing inhibit?
        inh_ttl, inh_reason = await self.store.get_inhibit(hk)
        if inh_ttl > 0:
            return Decision(True, InhibitSource.MANUAL if inh_reason and inh_reason.startswith("manual:") else InhibitSource.THRESHOLD,
                            inh_reason or "inhibited", inh_ttl, counter, 0)

        # 4) threshold check
        if counter >= policy.threshold:
            strikes = await self.store.incr_strikes(hk, policy.strike_ttl_sec)
            factor = max(1.0, policy.backoff_multiplier ** max(0, strikes - 1))
            cooldown = min(policy.max_cooldown_sec, int(policy.cooldown_sec * factor))
            # set inhibit if absent to avoid shrinking stronger bans
            created = await self.store.set_inhibit_if_absent(hk, cooldown, f"threshold:{counter}:strikes:{strikes}")
            # put into local quarantine for instant effect
            await self.quarantine.add(hk, min(policy.quarantine_ttl_sec, cooldown), "threshold")
            ttl, _ = await self.store.get_inhibit(hk)
            return Decision(True, InhibitSource.THRESHOLD, "threshold", ttl if ttl > 0 else cooldown, counter, strikes)

        # 5) not inhibited
        return Decision(False, InhibitSource.NONE, "", 0, counter, 0)

    async def is_inhibited(self, key: InhibitionKey) -> Decision:
        hk = self.hasher.key(key)
        q_ttl = await self.quarantine.ttl(hk)
        if q_ttl > 0:
            return Decision(True, InhibitSource.QUARANTINE, "quarantine", q_ttl, 0, 0)
        ttl, reason = await self.store.get_inhibit(hk)
        if ttl > 0:
            src = InhibitSource.MANUAL if reason and reason.startswith("manual:") else InhibitSource.THRESHOLD
            return Decision(True, src, reason or "inhibited", ttl, 0, 0)
        return Decision(False)

    async def inhibit(self, key: InhibitionKey, ttl_sec: int, *, reason: str = "manual") -> Decision:
        hk = self.hasher.key(key)
        await self.store.set_inhibit(hk, max(1, ttl_sec), f"manual:{reason}")
        await self.quarantine.add(hk, min(ttl_sec, 5), "manual")
        ttl, _ = await self.store.get_inhibit(hk)
        return Decision(True, InhibitSource.MANUAL, reason, ttl, 0, 0)

    async def clear(self, key: InhibitionKey) -> None:
        hk = self.hasher.key(key)
        await self.store.clear(hk)
        await self.quarantine.clear(hk)

    # Bulk helpers for convenience
    async def status(self, key: InhibitionKey, policy: Optional[Policy] = None) -> Decision:
        # Same as is_inhibited, but when policy is given, reflect counter via a no-op read (not incrementing).
        # We do not expose counters without increment in this adapter; return inhibition state only.
        return await self.is_inhibited(key)


# =========================
# Factories
# =========================

def _pepper_from_env(pepper: Optional[str]) -> PepperConfig:
    p = pepper or os.getenv("INHIBITOR_PEPPER")
    if not p or len(p) < 16:
        raise InhibitorError("INHIBITOR_PEPPER must be provided and be at least 16 characters")
    return PepperConfig(pepper=p)


def build_inmemory_inhibitor(pepper: Optional[str] = None) -> Inhibitor:
    return Inhibitor(store=InMemoryStore(), hasher=Hasher(_pepper_from_env(pepper)))


def build_redis_inhibitor(
    redis_url: str,
    *,
    pepper: Optional[str] = None,
    prefix: str = "inh",
) -> Inhibitor:
    if aioredis is None:
        raise InhibitorError("redis.asyncio is not installed")
    client = aioredis.from_url(redis_url, decode_responses=False)
    store = RedisStore(client, prefix=prefix)
    return Inhibitor(store=store, hasher=Hasher(_pepper_from_env(pepper)))
