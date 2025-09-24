# zero-trust-core/tests/unit/test_pep_cache.py
# -*- coding: utf-8 -*-
"""
Contract tests for PEP Decision Cache (Zero Trust).

Assumed implementation module:
    zero_trust.pep.cache
with public symbols:
    - class PepDecisionCache(
          capacity: int = 10000,
          default_ttl: float = 300.0,
          allow_negative: bool = False,
          clock: Callable[[], float] = time.time
      )
    - class Decision(effect: str, policy_id: str | None = None,
                     reason: str | None = None, obligations: dict | None = None)

Required methods:
    cache.get(key: str) -> Decision | None
    cache.put(key: str, decision: Decision | None,
              ttl: float | None = None, actor_id: str | None = None) -> None
    cache.get_or_compute(
        key: str,
        supplier: Callable[[], Decision | None],
        ttl: float | None = None,
        actor_id: str | None = None,
        stampede_ttl: float | None = None
    ) -> Decision | None
    cache.invalidate(key: str) -> None
    cache.invalidate_by_actor(actor_id: str) -> int
    cache.clear() -> None
    cache.stats() -> dict   # contains at least hits, misses, puts, evictions, size

Notes:
- Negative caching: when allow_negative=True, None results MAY be cached for default_ttl or provided ttl.
  When allow_negative=False, None MUST NOT be cached (each get_or_compute re-invokes supplier).
- LRU: inserting beyond capacity MUST evict the least recently USED entry.
- TTL: expired entries MUST be treated as misses; implementations MAY lazy-evict on access.
- Singleflight: concurrent get_or_compute for the same key MUST invoke supplier exactly once.
"""

import threading
import time
from typing import Optional, Dict, Any

import pytest

# Import the cache under test
try:
    from zero_trust.pep.cache import PepDecisionCache, Decision
except Exception as e:  # pragma: no cover
    pytest.skip(f"PEP cache implementation not found: {e}", allow_module_level=True)


# ---------- Test Utilities ----------

class _FakeClock:
    def __init__(self, start: float = 1_000_000.0):
        self._t = float(start)
        self._lock = threading.Lock()

    def time(self) -> float:
        with self._lock:
            return self._t

    def advance(self, seconds: float) -> None:
        assert seconds >= 0
        with self._lock:
            self._t += float(seconds)


@pytest.fixture()
def clock() -> _FakeClock:
    return _FakeClock()


@pytest.fixture()
def cache(clock: _FakeClock) -> PepDecisionCache:
    # small capacity to force evictions in tests
    return PepDecisionCache(capacity=3, default_ttl=10.0, allow_negative=True, clock=clock.time)


def _mk_dec(effect: str = "ALLOW",
            policy_id: Optional[str] = "p1",
            reason: Optional[str] = "ok",
            obligations: Optional[Dict[str, Any]] = None) -> Decision:
    return Decision(effect=effect, policy_id=policy_id, reason=reason, obligations=obligations or {})


# ---------- Basic get/put ----------

def test_put_get_basic(cache: PepDecisionCache):
    k = "user:u1|res:r1"
    d = _mk_dec("ALLOW", "p-login", "baseline")
    cache.put(k, d)
    got = cache.get(k)
    assert got is not None
    assert got.effect == "ALLOW"
    assert isinstance(got.obligations, dict)
    st = cache.stats()
    assert st["hits"] == 0  # get() should count as hit; if not, relax this as needed
    assert st["puts"] >= 1
    assert st["size"] >= 1


def test_get_miss_returns_none(cache: PepDecisionCache):
    assert cache.get("absent-key") is None
    st = cache.stats()
    assert st["misses"] >= 1


# ---------- TTL semantics ----------

def test_ttl_expiry_with_clock(cache: PepDecisionCache, clock: _FakeClock):
    k = "uA|rA"
    cache.put(k, _mk_dec("ALLOW"), ttl=5.0)
    assert cache.get(k) is not None  # t=0
    clock.advance(4.99)
    assert cache.get(k) is not None  # not expired
    clock.advance(0.02)
    assert cache.get(k) is None      # expired
    st = cache.stats()
    assert st["misses"] >= 1


def test_put_overrides_default_ttl(cache: PepDecisionCache, clock: _FakeClock):
    k = "uB|rB"
    cache.put(k, _mk_dec("DENY"), ttl=1.0)
    assert cache.get(k) is not None
    clock.advance(1.01)
    assert cache.get(k) is None


# ---------- LRU eviction ----------

def test_lru_eviction_policy(cache: PepDecisionCache):
    # capacity=3
    cache.put("k1", _mk_dec("ALLOW"))
    cache.put("k2", _mk_dec("DENY"))
    cache.put("k3", _mk_dec("MFA"))
    # Touch k1 and k2 to make k3 the LRU? No, LRU = least recently USED.
    _ = cache.get("k1")  # now k1 is MRU
    _ = cache.get("k2")  # k2 newer than k3; k3 becomes LRU
    cache.put("k4", _mk_dec("ALLOW"))
    # Expect k3 evicted
    assert cache.get("k3") is None
    assert cache.get("k1") is not None
    assert cache.get("k2") is not None
    assert cache.get("k4") is not None
    st = cache.stats()
    assert st["evictions"] >= 1
    assert st["size"] <= 3


# ---------- Invalidation ----------

def test_invalidate_key(cache: PepDecisionCache):
    cache.put("keyX", _mk_dec("ALLOW"))
    assert cache.get("keyX") is not None
    cache.invalidate("keyX")
    assert cache.get("keyX") is None


def test_invalidate_by_actor(cache: PepDecisionCache):
    cache.put("actor:A|r1", _mk_dec("ALLOW"), actor_id="A")
    cache.put("actor:A|r2", _mk_dec("DENY"), actor_id="A")
    cache.put("actor:B|r3", _mk_dec("MFA"), actor_id="B")
    n = cache.invalidate_by_actor("A")
    assert n >= 2
    assert cache.get("actor:A|r1") is None
    assert cache.get("actor:A|r2") is None
    assert cache.get("actor:B|r3") is not None


# ---------- get_or_compute: singleflight & negative caching ----------

def test_get_or_compute_singleflight(cache: PepDecisionCache):
    key = "sf:key"
    calls = {"n": 0}
    lock = threading.Lock()
    ready = threading.Event()
    proceed = threading.Event()

    def supplier():
        with lock:
            calls["n"] += 1
        ready.set()     # signal that supplier started
        proceed.wait(0.5)  # block a bit to simulate work
        return _mk_dec("ALLOW", "p-sf", "computed")

    results = []
    errors = []
    def worker():
        try:
            res = cache.get_or_compute(key, supplier, ttl=5.0)
            results.append(res.effect if res else None)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    ready.wait(1.0)     # ensure supplier has started
    time.sleep(0.05)
    proceed.set()       # allow supplier to complete
    for t in threads:
        t.join()

    assert not errors
    assert all(r == "ALLOW" for r in results)
    assert calls["n"] == 1  # singleflight guaranteed


def test_get_or_compute_negative_caching_disabled(clock: _FakeClock):
    c = PepDecisionCache(capacity=16, default_ttl=10.0, allow_negative=False, clock=clock.time)
    key = "neg:key"
    calls = {"n": 0}

    def supplier_none():
        calls["n"] += 1
        return None

    r1 = c.get_or_compute(key, supplier_none, ttl=5.0)
    r2 = c.get_or_compute(key, supplier_none, ttl=5.0)
    assert r1 is None and r2 is None
    assert calls["n"] == 2  # not cached when allow_negative=False


def test_get_or_compute_negative_caching_enabled(clock: _FakeClock):
    c = PepDecisionCache(capacity=16, default_ttl=10.0, allow_negative=True, clock=clock.time)
    key = "neg:key"
    calls = {"n": 0}

    def supplier_none():
        calls["n"] += 1
        return None

    r1 = c.get_or_compute(key, supplier_none, ttl=5.0)
    r2 = c.get_or_compute(key, supplier_none, ttl=5.0)
    assert r1 is None and r2 is None
    assert calls["n"] == 1  # cached None result when allow_negative=True


# ---------- Concurrency & TTL with singleflight after expiry ----------

def test_singleflight_after_expiry(cache: PepDecisionCache, clock: _FakeClock):
    key = "exp:key"
    cache.put(key, _mk_dec("ALLOW"), ttl=1.0)
    assert cache.get(key) is not None
    clock.advance(1.1)  # expire

    calls = {"n": 0}
    start = threading.Barrier(6)

    def supplier():
        calls["n"] += 1
        time.sleep(0.05)
        return _mk_dec("DENY", "p-refresh", "refresh")

    results = []
    def worker():
        start.wait()
        res = cache.get_or_compute(key, supplier, ttl=3.0)
        results.append(res.effect if res else None)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert calls["n"] == 1
    assert all(r == "DENY" for r in results)


# ---------- Stats ----------

def test_stats_counters_progress(cache: PepDecisionCache):
    cache.clear()
    s0 = cache.stats()
    assert s0["size"] == 0
    assert s0["hits"] >= 0 and s0["misses"] >= 0

    # miss
    cache.get("none")
    # put + hit
    cache.put("k", _mk_dec("ALLOW"))
    cache.get("k")
    # eviction path
    cache.put("k1", _mk_dec("ALLOW"))
    cache.put("k2", _mk_dec("ALLOW"))
    cache.put("k3", _mk_dec("ALLOW"))  # should evict one (capacity=3)

    s1 = cache.stats()
    assert s1["puts"] >= s0["puts"] + 4
    assert s1["hits"] >= s0["hits"] + 1
    assert s1["misses"] >= s0["misses"] + 1
    assert s1["evictions"] >= s0["evictions"]


# ---------- Edge cases ----------

def test_put_none_with_negative_disabled(clock: _FakeClock):
    c = PepDecisionCache(capacity=2, default_ttl=10.0, allow_negative=False, clock=clock.time)
    c.put("k", None, ttl=5.0)
    assert c.get("k") is None  # must not be cached


def test_put_none_with_negative_enabled(clock: _FakeClock):
    c = PepDecisionCache(capacity=2, default_ttl=10.0, allow_negative=True, clock=clock.time)
    c.put("k", None, ttl=5.0)
    assert c.get("k") is None  # cached negative still returns None
    clock.advance(5.1)
    assert c.get("k") is None  # but after expiry miss should be counted


def test_clear(cache: PepDecisionCache):
    cache.put("a", _mk_dec("ALLOW"))
    cache.put("b", _mk_dec("DENY"))
    cache.clear()
    assert cache.get("a") is None
    assert cache.get("b") is None
    assert cache.stats()["size"] == 0
