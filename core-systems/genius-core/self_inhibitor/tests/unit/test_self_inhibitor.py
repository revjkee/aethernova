import asyncio
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

# Тестируем публичные контракты
from genius_core.security.self_inhibitor.exceptions import (
    SelfInhibitorError,
    PolicyViolation,
    DataLeakDetected,
    PIIExposureDetected,
    RateLimitExceeded,
    PromptInjectionDetected,
    guard_raise_if_blocked,
)

from genius_core.security.self_inhibitor.adapters.redis_adapter import (
    RedisAdapter,
    RedisConfig,
)

# ======================================================================
#                               Fake Redis
# ======================================================================

class _FakePipeline:
    def __init__(self, parent: "_FakeRedis"):
        self._p = parent
        self._ops: List[Tuple[str, tuple, dict]] = []

    def set(self, *args, **kwargs):
        self._ops.append(("set", args, kwargs))
        return self

    async def execute(self):
        for name, args, kwargs in self._ops:
            if name == "set":
                await self._p.set(*args, **kwargs)
        self._ops.clear()
        return True


class _FakeRedis:
    """
    Минимальная эмуляция redis.asyncio, достаточная для наших тестов адаптера.
    Поддерживает: ping, get/set, mget, pexpire/pttl, pipeline, register_script,
    ZSET скользящее окно, HASH токен-бакет, простые локи.
    """
    def __init__(self):
        self.kv: Dict[str, Any] = {}
        self.pttl: Dict[str, int] = {}          # ключ -> millis to live (остаток)
        self.zsets: Dict[str, List[int]] = {}   # ключ -> список timestamps (ms)
        self.hashes: Dict[str, Dict[str, Any]] = {}

    # ---- базовые операции ----
    async def ping(self):
        return True

    async def set(self, key: str, value: Any, ex: Optional[int] = None, px: Optional[int] = None, nx: Optional[bool] = None):
        if nx:
            if key in self.kv:
                return False
        self.kv[key] = value
        if px is not None:
            self.pttl[key] = int(px)
        elif ex is not None:
            self.pttl[key] = int(ex * 1000)
        return True

    async def get(self, key: str):
        return self.kv.get(key, None)

    async def mget(self, *keys: List[str]):
        return [self.kv.get(k, None) for k in keys]

    async def hset(self, key: str, mapping: Dict[str, Any]):
        h = self.hashes.setdefault(key, {})
        h.update(mapping)
        return True

    async def hget(self, key: str, field: str):
        return self.hashes.get(key, {}).get(field, None)

    async def hmget(self, key: str, *fields: List[str]):
        h = self.hashes.get(key, {})
        return [h.get(f, None) for f in fields]

    async def hmset(self, key: str, mapping: Dict[str, Any]):
        return await self.hset(key, mapping=mapping)

    async def pexpire(self, key: str, ttl_ms: int):
        self.pttl[key] = int(ttl_ms)
        return True

    async def pttl(self, key: str):
        return int(self.pttl.get(key, -1))

    def pipeline(self):
        return _FakePipeline(self)

    async def info(self, section: str = "server"):
        return {"server": {"redis_version": "fake-0.1"}}

    async def close(self):
        return True

    # ---- Streams/Groups заглушки (не используются в этих тестах) ----
    async def xadd(self, *_, **__):
        return "0-0"

    async def xgroup_create(self, *_, **__):
        return True

    async def xreadgroup(self, *_, **__):
        return []

    async def xack(self, *_, **__):
        return 1

    def pubsub(self):
        class _PS:
            async def subscribe(self, *_): ...
            async def unsubscribe(self, *_): ...
            async def close(self): ...
            async def listen(self):
                if False:
                    yield  # pragma: no cover
        return _PS()

    async def publish(self, *_args, **_kwargs):
        return 1

    # ---- Lua script registration ----
    def register_script(self, script: str):
        if "ZREMRANGEBYSCORE" in script and "ZADD" in script:
            # Sliding window
            async def _sliding(keys: List[str], args: List[int]):
                key = keys[0]
                now_ms, window_ms, limit, cost = map(int, args)
                lst = self.zsets.setdefault(key, [])
                # очистка окна
                minscore = now_ms - window_ms
                lst[:] = [t for t in lst if t > minscore]
                count = len(lst)
                if count + cost > limit:
                    return [0, max(0, limit - count)]
                lst.extend([now_ms] * cost)
                self.pttl[key] = window_ms + 1000
                remaining = limit - (count + cost)
                return [1, remaining]
            return _sliding

        if "HMGET" in script and "tokens" in script and "updated_ms" in script:
            # Token bucket
            async def _bucket(keys: List[str], args: List[int]):
                key = keys[0]
                now_ms, capacity, refill, refill_ms, cost = map(int, args)
                h = self.hashes.setdefault(key, {})
                tokens = int(h.get("tokens", capacity))
                updated = int(h.get("updated_ms", now_ms))
                if now_ms > updated:
                    elapsed = now_ms - updated
                    rounds = elapsed // refill_ms
                    if rounds > 0:
                        tokens = min(capacity, tokens + rounds * refill)
                        updated = updated + rounds * refill_ms
                allowed = 0
                if tokens >= cost:
                    tokens -= cost
                    allowed = 1
                h["tokens"] = tokens
                h["updated_ms"] = updated
                self.pttl[key] = 2 * refill_ms
                return [allowed, tokens, self.pttl[key]]
            return _bucket

        if "INCR" in script and "PEXPIRE" in script:
            # INCR + TTL
            async def _incr(keys: List[str], args: List[int]):
                key = keys[0]
                ttl_ms = int(args[0])
                val = int(self.kv.get(key, 0)) + 1
                self.kv[key] = val
                if val == 1:
                    self.pttl[key] = ttl_ms
                    return [val, ttl_ms]
                # имитируем тиканье TTL: уменьшим на 100мс при каждом повторе
                self.pttl[key] = max(0, self.pttl.get(key, ttl_ms) - 100)
                return [val, self.pttl[key]]
            return _incr

        if "GET" in script and "DEL" in script:
            # Unlock script
            async def _unlock(keys: List[str], args: List[str]):
                key = keys[0]
                token = args[0]
                if self.kv.get(key) == token:
                    del self.kv[key]
                    if key in self.pttl:
                        del self.pttl[key]
                    return 1
                return 0
            return _unlock

        async def _noop(*_args, **_kwargs):
            return None
        return _noop


# ======================================================================
#                             Exceptions tests
# ======================================================================

def test_exceptions_problem_details_and_redaction():
    exc = DataLeakDetected(
        message="Leak suspected in output",
        context={"snippet": "email john.doe@example.com token=eyJabc...", "note": "debug"},
    )
    pd = exc.to_problem_details()
    as_dict = exc.to_dict()

    assert pd["type"].endswith(str(exc.code))
    assert pd["status"] == exc.http_status
    # Проверяем, что контекст отредактирован
    ctx = pd.get("context", {})
    s = json.dumps(ctx, ensure_ascii=False)
    assert "REDACTED" in s
    # Базовые поля словаря
    assert as_dict["http_status"] == exc.http_status
    assert as_dict["severity"] in {"HIGH", "CRITICAL", "MEDIUM", "LOW", "INFO"}

def test_http_grpc_mappings():
    e = RateLimitExceeded("too many")
    assert int(e.http_status) == 429
    assert e.grpc_status == 8  # RESOURCE_EXHAUSTED

def test_guard_raise_if_blocked():
    with pytest.raises(PolicyViolation):
        guard_raise_if_blocked({
            "allowed": False,
            "code": "policy_violation",
            "message": "blocked by rule",
            "policy_id": "pol-1",
            "rule_id": "R-TEST",
            "context": {"k": "v"},
        })


# ======================================================================
#                         Denylist (YAML) tests
# ======================================================================

@pytest.mark.parametrize("relative", ["rules/denylist.yaml"])
def test_denylist_yaml_shape(relative):
    yaml = pytest.importorskip("yaml")
    base = Path(__file__).resolve().parents[2]   # .../self_inhibitor
    path = base / relative
    assert path.exists(), f"File not found: {path}"

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["apiVersion"].startswith("genius.core/")
    assert data["kind"] in {"SelfInhibitorRules"}
    assert "metadata" in data and "spec" in data

    spec = data["spec"]
    assert "defaults" in spec and "variables" in spec and "rules" in spec

    # Проверяем компилируемость регулярных выражений (включая списки)
    vars_ = spec.get("variables", {})
    for name, pattern in vars_.items():
        if isinstance(pattern, list):
            for p in pattern:
                re.compile(p)
        elif isinstance(pattern, str):
            re.compile(pattern)

    # Смоук-тесты присутствуют и корректны по форме
    tests = spec.get("tests", [])
    assert isinstance(tests, list) and len(tests) >= 3
    for t in tests:
        assert "expect" in t
        exp = t["expect"]
        assert "decision" in exp


# ======================================================================
#                        RedisAdapter + FakeRedis tests
# ======================================================================

@pytest.fixture()
def fake_adapter(monkeypatch):
    cfg = RedisConfig(url="redis://fake/0", namespace="genius:self-inhibitor:test")
    adapter = RedisAdapter(cfg)
    # Встраиваем фейковый клиент
    fake = _FakeRedis()
    adapter._redis = fake  # присоединяем напрямую, минуя connect()
    return adapter

@pytest.mark.asyncio
async def test_incr_with_ttl(fake_adapter):
    v1, ttl1 = await fake_adapter.incr_with_ttl(bucket="api:usr:42", ttl_s=2)
    v2, ttl2 = await fake_adapter.incr_with_ttl(bucket="api:usr:42", ttl_s=2)
    assert v1 == 1 and ttl1 == 2
    assert v2 == 2 and ttl2 in (1, 2)  # фейк уменьшает TTL имитационно

@pytest.mark.asyncio
async def test_rate_limit_sliding(fake_adapter):
    # Детерминированное "время"
    allowed, rem = await fake_adapter.rate_limit_sliding(key="u1", limit=2, window_s=10, now_ms=100000, cost=1)
    assert allowed and rem == 1
    allowed, rem = await fake_adapter.rate_limit_sliding(key="u1", limit=2, window_s=10, now_ms=100001, cost=1)
    assert allowed and rem == 0
    allowed, rem = await fake_adapter.rate_limit_sliding(key="u1", limit=2, window_s=10, now_ms=100002, cost=1)
    assert not allowed and rem == 0  # превышение окна при тех же временных метках

@pytest.mark.asyncio
async def test_token_bucket(fake_adapter):
    # capacity=5, +1 токен/сек; потребляем 3 токена сразу
    ok, tokens, ttl = await fake_adapter.rate_limit_token_bucket(
        key="tb:u2", capacity=5, refill_tokens=1, refill_interval_s=1, now_ms=1_000_000, cost=3
    )
    assert ok and tokens == 2 and ttl > 0
    # попытка списать 4 при остатке 2 — отклоняется
    ok, tokens, _ = await fake_adapter.rate_limit_token_bucket(
        key="tb:u2", capacity=5, refill_tokens=1, refill_interval_s=1, now_ms=1_000_100, cost=4
    )
    assert not ok and tokens == 2
    # прошло 3 секунды — должно быть минимум 5 (емкость)
    ok, tokens, _ = await fake_adapter.rate_limit_token_bucket(
        key="tb:u2", capacity=5, refill_tokens=1, refill_interval_s=1, now_ms=1_003_100, cost=1
    )
    assert ok and tokens in (4, 5)

@pytest.mark.asyncio
async def test_lock_context_manager(fake_adapter):
    # Первый владелец получает лок
    async with fake_adapter.lock("crit", ttl_ms=1000, wait_timeout_ms=200) as acquired1:
        assert acquired1 is True
        # Второй конкурент не должен получить лок в пределах таймаута
        task_result = {"acq": None}

        async def _try_lock():
            async with fake_adapter.lock("crit", ttl_ms=1000, wait_timeout_ms=100) as acquired2:
                task_result["acq"] = acquired2

        await asyncio.wait_for(_try_lock(), timeout=1.0)
        assert task_result["acq"] is False
    # После выхода лок освобожден — следующий получает
    async with fake_adapter.lock("crit", ttl_ms=1000, wait_timeout_ms=100) as acquired3:
        assert acquired3 is True

@pytest.mark.asyncio
async def test_cache_set_get_version(fake_adapter):
    await fake_adapter.cache_set(group="rules", key="denylist", value={"v": 1}, ttl_s=60, version="abc")
    got = await fake_adapter.cache_get(group="rules", key="denylist", require_version="abc")
    assert got == {"v": 1}
    # Неверная версия -> None
    got2 = await fake_adapter.cache_get(group="rules", key="denylist", require_version="zzz")
    assert got2 is None

@pytest.mark.asyncio
async def test_kv_hash_helpers(fake_adapter):
    await fake_adapter.kv_set_json("state", {"ok": True}, ttl_s=30)
    assert await fake_adapter.kv_get_json("state") == {"ok": True}

    await fake_adapter.hset_json("agg", "last", {"ts": 123})
    assert await fake_adapter.hget_json("agg", "last") == {"ts": 123}

@pytest.mark.asyncio
async def test_circuit_breaker(fake_adapter):
    # 3 ошибки подряд переводят в open
    st1 = await fake_adapter.circuit_trip("ext", failure_threshold=3, cool_down_s=10)
    st2 = await fake_adapter.circuit_trip("ext", failure_threshold=3, cool_down_s=10)
    st3 = await fake_adapter.circuit_trip("ext", failure_threshold=3, cool_down_s=10)
    assert st3["state"] == "open" and st3["failures"] >= 3
    probe = await fake_adapter.circuit_probe("ext")
    assert probe["state"] in {"open", "half_open"}
    await fake_adapter.circuit_reset_success("ext")
    probe2 = await fake_adapter.circuit_probe("ext")
    # после reset_success состояние не "open"
    assert probe2["state"] in {"closed", "half_open"}
