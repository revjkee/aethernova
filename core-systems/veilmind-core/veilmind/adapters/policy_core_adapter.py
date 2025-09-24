# File: veilmind-core/veilmind/adapters/policy_core_adapter.py
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse

# =============================================================================
# Типы и модели
# =============================================================================

class Decision(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INDETERMINATE = "INDETERMINATE"

@dataclass(frozen=True)
class Subject:
    id: str
    tenant: Optional[str] = None
    scopes: Tuple[str, ...] = ()

@dataclass(frozen=True)
class ResourceRef:
    type: str
    id: Optional[str] = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class PolicyRequest:
    subject: Subject
    action: str
    resource: ResourceRef
    context: Mapping[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None  # идемпотентность/трассировка

@dataclass
class PolicyResult:
    decision: Decision
    reason: str = ""
    obligations: Dict[str, Any] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict)
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    source: str = "unknown"  # cache|local|remote
    eval_time_ms: float = 0.0
    cache_hit: bool = False
    hmac: str = ""

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

class PolicyError(Exception):
    pass

class PDPUnavailable(PolicyError):
    pass

# =============================================================================
# Вспомогательные утилиты
# =============================================================================

def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _redact(val: Any, max_len: int = 256) -> Any:
    if val is None:
        return None
    s = str(val)
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s

def _dict_path(data: Mapping[str, Any], path: str) -> Any:
    # путь вида "subject.tenant" / "resource.attributes.owner" / "context.ip"
    cur: Any = data
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

# =============================================================================
# LRU‑кэш с TTL
# =============================================================================

class _TTLCache:
    __slots__ = ("_cap", "_store", "_lock")

    def __init__(self, capacity: int = 10000) -> None:
        self._cap = max(1, capacity)
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        now = time.time()
        with self._lock:
            val = self._store.get(key)
            if not val:
                return None
            exp, data = val
            if now > exp:
                self._store.pop(key, None)
                return None
            # псевдо‑LRU: переустановка срока с прежним TTL, если храним TTL в data
            return data

    def set(self, key: str, value: Any, ttl_sec: int) -> None:
        exp = time.time() + max(1, ttl_sec)
        with self._lock:
            if len(self._store) >= self._cap:
                # простое выселение первого ключа
                self._store.pop(next(iter(self._store)), None)
            self._store[key] = (exp, value)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"size": len(self._store), "capacity": self._cap}

# =============================================================================
# Rate limiter (per‑tenant)
# =============================================================================

class _TokenBucket:
    __slots__ = ("rate", "capacity", "tokens", "last", "lock")

    def __init__(self, rps: float, burst: Optional[float] = None) -> None:
        self.rate = float(max(0.1, rps))
        self.capacity = float(burst if burst and burst > 0 else self.rate * 2)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

class _RateLimiter:
    def __init__(self, default_rps: float) -> None:
        self._default_rps = default_rps
        self._buckets: Dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        with self._lock:
            b = self._buckets.get(key)
            if not b:
                b = self._buckets[key] = _TokenBucket(self._default_rps)
        return b.allow()

# =============================================================================
# Circuit Breaker
# =============================================================================

class _CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_timeout_sec: int = 15) -> None:
        self.failures = 0
        self.state = "CLOSED"  # CLOSED|OPEN|HALF_OPEN
        self.failure_threshold = max(1, failure_threshold)
        self.reset_timeout = max(1, reset_timeout_sec)
        self.opened_at = 0.0
        self._lock = threading.Lock()

    def on_success(self) -> None:
        with self._lock:
            self.failures = 0
            self.state = "CLOSED"

    def on_failure(self) -> None:
        with self._lock:
            self.failures += 1
            if self.failures >= self.failure_threshold and self.state != "OPEN":
                self.state = "OPEN"
                self.opened_at = time.time()

    def allow_request(self) -> bool:
        with self._lock:
            if self.state == "OPEN":
                if time.time() - self.opened_at >= self.reset_timeout:
                    self.state = "HALF_OPEN"
                    return True
                return False
            return True

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {"state": self.state, "failures": self.failures, "reset_timeout": self.reset_timeout}

# =============================================================================
# Локальный движок (JSON‑DSL)
# =============================================================================

# Примитивные операторы
_ALLOWED_OPS = frozenset({"eq", "ne", "in", "not_in", "startswith", "endswith", "regex",
                          "contains", "gt", "lt", "gte", "lte", "subset_of", "intersects"})

_re_cache: Dict[str, re.Pattern[str]] = {}

def _safe_regex(pattern: str) -> re.Pattern[str]:
    if len(pattern) > 256:
        raise ValueError("regex too long")
    p = _re_cache.get(pattern)
    if p is None:
        p = re.compile(pattern, re.IGNORECASE)
        _re_cache[pattern] = p
    return p

def _op_eval(op: str, left: Any, right: Any) -> bool:
    if op == "eq": return left == right
    if op == "ne": return left != right
    if op == "in": return left in (right if isinstance(right, (list, tuple, set)) else [right])
    if op == "not_in": return left not in (right if isinstance(right, (list, tuple, set)) else [right])
    if op == "startswith": return isinstance(left, str) and isinstance(right, str) and left.startswith(right)
    if op == "endswith": return isinstance(left, str) and isinstance(right, str) and left.endswith(right)
    if op == "regex": return isinstance(left, str) and isinstance(right, str) and bool(_safe_regex(right).search(left))
    if op == "contains":
        if isinstance(left, (list, tuple, set)): return right in left
        if isinstance(left, str) and isinstance(right, str): return right in left
        return False
    if op == "gt": return _num(left) > _num(right)
    if op == "lt": return _num(left) < _num(right)
    if op == "gte": return _num(left) >= _num(right)
    if op == "lte": return _num(left) <= _num(right)
    if op == "subset_of":
        if not isinstance(left, (list, tuple, set)) or not isinstance(right, (list, tuple, set)):
            return False
        return set(left).issubset(set(right))
    if op == "intersects":
        if not isinstance(left, (list, tuple, set)) or not isinstance(right, (list, tuple, set)):
            return False
        return len(set(left).intersection(set(right))) > 0
    raise ValueError(f"Unsupported op: {op}")

def _num(x: Any) -> float:
    try:
        return float(x)
    except Exception:
        return float("nan")

def _eval_condition(cond: Mapping[str, Any], data: Mapping[str, Any]) -> bool:
    # Логические комбинирующие узлы
    if "all" in cond:
        lst = cond.get("all") or []
        return all(_eval_condition(c, data) for c in lst)
    if "any" in cond:
        lst = cond.get("any") or []
        return any(_eval_condition(c, data) for c in lst)
    if "not" in cond:
        return not _eval_condition(cond["not"], data)

    # Примитив: {op, left, right}
    op = cond.get("op")
    left_ref = cond.get("left")
    right = cond.get("right")
    if op not in _ALLOWED_OPS:
        raise ValueError("unsupported operator")
    left = _dict_path(data, left_ref) if isinstance(left_ref, str) else left_ref
    return _op_eval(op, left, right)

@dataclass(frozen=True)
class LocalRule:
    id: str
    effect: Decision  # PERMIT|DENY
    priority: int = 0
    when: Mapping[str, Any] = field(default_factory=dict)
    obligations: Mapping[str, Any] = field(default_factory=dict)
    attributes: Mapping[str, Any] = field(default_factory=dict)
    version: str = "1"

class LocalPolicyEngine:
    """
    Простой и безопасный локальный движок: JSON‑DSL условий, первый матч по приоритету.
    """
    def __init__(self, rules: Sequence[Mapping[str, Any]]):
        self.rules: List[LocalRule] = []
        for r in rules or []:
            eff = r.get("effect", "DENY").upper()
            if eff not in ("PERMIT", "DENY"):
                raise ValueError("effect must be PERMIT|DENY")
            self.rules.append(LocalRule(
                id=str(r.get("id", f"rule-{len(self.rules)+1}")),
                effect=Decision(eff),
                priority=int(r.get("priority", 0)),
                when=MappingProxyType(dict(r.get("when", {}))),
                obligations=MappingProxyType(dict(r.get("obligations", {}))),
                attributes=MappingProxyType(dict(r.get("attributes", {}))),
                version=str(r.get("version", "1")),
            ))
        # сортировка по убыванию приоритета, затем по id
        self.rules.sort(key=lambda x: (-x.priority, x.id))

    def evaluate(self, req: PolicyRequest) -> Optional[PolicyResult]:
        data = {
            "subject": {"id": req.subject.id, "tenant": req.subject.tenant, "scopes": list(req.subject.scopes)},
            "action": req.action,
            "resource": {"type": req.resource.type, "id": req.resource.id, "attributes": dict(req.resource.attributes or {})},
            "context": dict(req.context or {}),
        }
        for rule in self.rules:
            try:
                if _eval_condition(rule.when, data):
                    return PolicyResult(
                        decision=rule.effect,
                        reason=f"local:{rule.id}",
                        obligations=dict(rule.obligations),
                        attributes=dict(rule.attributes),
                        policy_id=rule.id,
                        policy_version=rule.version,
                        source="local",
                    )
            except Exception as e:
                # поврежденное правило пропускаем
                return PolicyResult(
                    decision=Decision.INDETERMINATE,
                    reason=f"local_error:{rule.id}:{_redact(e)}",
                    source="local",
                )
        return None

# =============================================================================
# Удалённый PDP (совместим с OPA REST)
# =============================================================================

class RemotePDPClient:
    """
    Минимальный HTTP‑клиент без внешних зависимостей.
    Для OPA ожидается endpoint: POST /v1/data/<package> с телом {"input": <request>}.
    Ответы:
      - { "result": { "allow": true/false, "obligations": {...}, "attributes": {...}, "policy_id": "...", "version": "..." } }
      - или { "result": true/false } — будет интерпретировано как allow/deny.
    """
    def __init__(self, base_url: str, package: str, timeout_sec: float = 2.0, headers: Optional[Mapping[str, str]] = None):
        self.base_url = base_url.rstrip("/")
        self.package = package.strip("/").replace(".", "/")
        self.timeout = float(timeout_sec)
        self.headers = dict(headers or {})

    def evaluate(self, req: PolicyRequest) -> PolicyResult:
        u = urlparse(self.base_url)
        path = f"/v1/data/{self.package}"
        body = _canonical_json({"input": _request_to_dict(req)}).encode("utf-8")
        conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(u.hostname, u.port or (443 if u.scheme == "https" else 80), timeout=self.timeout)
        try:
            headers = {"Content-Type": "application/json", **self.headers}
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            if resp.status >= 500:
                raise PDPUnavailable(f"PDP {resp.status}")
            data = json.loads(raw.decode("utf-8") or "{}")
        finally:
            try: conn.close()
            except Exception: pass

        res = data.get("result")
        if isinstance(res, dict):
            allow = bool(res.get("allow", False))
            return PolicyResult(
                decision=Decision.PERMIT if allow else Decision.DENY,
                reason="remote:opa",
                obligations=dict(res.get("obligations") or {}),
                attributes=dict(res.get("attributes") or {}),
                policy_id=str(res.get("policy_id") or None),
                policy_version=str(res.get("version") or None),
                source="remote",
            )
        if isinstance(res, bool):
            return PolicyResult(
                decision=Decision.PERMIT if res else Decision.DENY,
                reason="remote:opa_bool",
                source="remote",
            )
        # если структура неизвестна
        return PolicyResult(decision=Decision.INDETERMINATE, reason="remote:unknown", source="remote")

# =============================================================================
# Адаптер политики: cache → local → remote, с лимитами, breaker и HMAC
# =============================================================================

@dataclass
class AdapterMetrics:
    cache_hits: int = 0
    cache_misses: int = 0
    local_hits: int = 0
    remote_calls: int = 0
    remote_failures: int = 0

class PolicyCoreAdapter:
    """
    Единая точка принятия политик:
      1) Ключ запроса = HMAC(canonical_json(request)).
      2) Поиск в TTL‑кэше.
      3) Локальный движок (если настроен).
      4) Удалённый PDP с circuit‑breaker и rate‑limit.
      5) HMAC‑подпись результата, опционально кэширование PERMIT/DENY.
    """
    def __init__(
        self,
        local_rules: Optional[Sequence[Mapping[str, Any]]] = None,
        remote_pdp: Optional[RemotePDPClient] = None,
        *,
        cache_ttl_sec: int = int(os.getenv("POLICY_CACHE_TTL", "30")),
        cache_capacity: int = int(os.getenv("POLICY_CACHE_CAP", "10000")),
        hmac_key: str = os.getenv("POLICY_HMAC_KEY", ""),
        tenant_rps: float = float(os.getenv("POLICY_TENANT_RPS", "100")),
        breaker_failures: int = int(os.getenv("POLICY_BREAKER_FAILS", "5")),
        breaker_reset_sec: int = int(os.getenv("POLICY_BREAKER_RESET", "15")),
    ):
        self.local_engine = LocalPolicyEngine(local_rules or [])
        self.remote = remote_pdp
        self.cache = _TTLCache(cache_capacity)
        self.cache_ttl = max(1, cache_ttl_sec)
        self.hmac_key = hmac_key.encode("utf-8") if hmac_key else b""
        self.rate = _RateLimiter(tenant_rps)
        self.breaker = _CircuitBreaker(failure_threshold=breaker_failures, reset_timeout_sec=breaker_reset_sec)
        self.metrics = AdapterMetrics()

    # ------------------------------ API ---------------------------------------

    def evaluate(self, req: PolicyRequest, *, cache: bool = True) -> PolicyResult:
        started = time.perf_counter()
        key = self._cache_key(req)
        tenant = req.subject.tenant or "none"

        # 1) cache
        if cache:
            cached = self.cache.get(key)
            if cached:
                self.metrics.cache_hits += 1
                res: PolicyResult = cached
                res.cache_hit = True
                res.eval_time_ms = (time.perf_counter() - started) * 1000.0
                res.hmac = self._sign(res)
                return res
            self.metrics.cache_misses += 1

        # 2) local rules
        local = self.local_engine.evaluate(req)
        if local:
            self.metrics.local_hits += 1
            local.eval_time_ms = (time.perf_counter() - started) * 1000.0
            local.hmac = self._sign(local)
            if cache and local.decision in (Decision.PERMIT, Decision.DENY):
                self.cache.set(key, local, self.cache_ttl)
            return local

        # 3) remote PDP
        remote_res = PolicyResult(decision=Decision.INDETERMINATE, reason="remote:disabled", source="remote")
        if self.remote:
            if not self.breaker.allow_request():
                remote_res = PolicyResult(decision=Decision.INDETERMINATE, reason="remote:breaker_open", source="remote")
            elif not self.rate.check(f"tenant:{tenant}"):
                remote_res = PolicyResult(decision=Decision.INDETERMINATE, reason="remote:rate_limited", source="remote")
            else:
                try:
                    self.metrics.remote_calls += 1
                    remote_res = self.remote.evaluate(req)
                    self.breaker.on_success()
                except PDPUnavailable as e:
                    self.metrics.remote_failures += 1
                    self.breaker.on_failure()
                    remote_res = PolicyResult(decision=Decision.INDETERMINATE, reason=f"remote:unavailable:{_redact(e)}", source="remote")
                except Exception as e:
                    self.metrics.remote_failures += 1
                    self.breaker.on_failure()
                    remote_res = PolicyResult(decision=Decision.INDETERMINATE, reason=f"remote:error:{_redact(e)}", source="remote")

        # 4) finalize
        remote_res.eval_time_ms = (time.perf_counter() - started) * 1000.0
        remote_res.hmac = self._sign(remote_res)
        if cache and remote_res.decision in (Decision.PERMIT, Decision.DENY):
            self.cache.set(key, remote_res, self.cache_ttl)
        return remote_res

    def batch_evaluate(self, reqs: Iterable[PolicyRequest], *, cache: bool = True) -> Iterator[PolicyResult]:
        for r in reqs:
            yield self.evaluate(r, cache=cache)

    def health(self) -> Dict[str, Any]:
        return {
            "cache": self.cache.stats(),
            "breaker": self.breaker.to_dict(),
            "metrics": asdict(self.metrics),
            "remote_enabled": bool(self.remote is not None),
        }

    def close(self) -> None:
        # заглушка: http.client закрывается на каждом запросе
        pass

    # ------------------------------ Внутреннее -------------------------------

    def _cache_key(self, req: PolicyRequest) -> str:
        base = {
            "subject": {"id": req.subject.id, "tenant": req.subject.tenant, "scopes": list(req.subject.scopes)},
            "action": req.action,
            "resource": {"type": req.resource.type, "id": req.resource.id, "attributes": req.resource.attributes},
            "context": req.context,
        }
        raw = _canonical_json(base).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _sign(self, result: PolicyResult) -> str:
        if not self.hmac_key:
            return ""
        payload = _canonical_json(result.to_json()).encode("utf-8")
        return hmac.new(self.hmac_key, payload, hashlib.sha256).hexdigest()

# =============================================================================
# Вспомогательные преобразования
# =============================================================================

def _request_to_dict(req: PolicyRequest) -> Dict[str, Any]:
    return {
        "subject": {"id": req.subject.id, "tenant": req.subject.tenant, "scopes": list(req.subject.scopes)},
        "action": req.action,
        "resource": {"type": req.resource.type, "id": req.resource.id, "attributes": dict(req.resource.attributes or {})},
        "context": dict(req.context or {}),
        "request_id": req.request_id,
    }

# =============================================================================
# Пример применения
# =============================================================================

if __name__ == "__main__":
    # Локальные правила (пример)
    rules = [
        {
            "id": "allow_admin_on_all",
            "priority": 100,
            "effect": "PERMIT",
            "when": {"any": [
                {"op": "in", "left": "subject.scopes", "right": ["admin", "root"]},
                {"op": "eq", "left": "subject.id", "right": "superuser"},
            ]},
            "obligations": {"audit": True},
            "attributes": {"mask_level": "none"},
            "version": "1",
        },
        {
            "id": "deny_cross_tenant_write",
            "priority": 90,
            "effect": "DENY",
            "when": {"all": [
                {"op": "eq", "left": "action", "right": "write"},
                {"op": "ne", "left": "subject.tenant", "right": "resource.attributes.tenant"},
            ]},
            "obligations": {"message": "cross-tenant writes are forbidden"},
        },
        {
            "id": "permit_read_same_tenant",
            "priority": 50,
            "effect": "PERMIT",
            "when": {"all": [
                {"op": "eq", "left": "action", "right": "read"},
                {"op": "eq", "left": "subject.tenant", "right": "resource.attributes.tenant"},
            ]},
            "attributes": {"mask_level": "partial"},
        },
    ]

    # Удалённый PDP (OPA) — задайте переменные среды при необходимости
    opa_url = os.getenv("OPA_URL", "")
    remote = RemotePDPClient(opa_url, package=os.getenv("OPA_PACKAGE", "veilmind.authz")) if opa_url else None

    adapter = PolicyCoreAdapter(local_rules=rules, remote_pdp=remote, hmac_key=os.getenv("POLICY_HMAC_KEY", "change_me"))

    req = PolicyRequest(
        subject=Subject(id="alice", tenant="tenant-a", scopes=("reader",)),
        action="read",
        resource=ResourceRef(type="document", id="doc-1", attributes={"tenant": "tenant-a", "owner": "alice"}),
        context={"ip": "192.168.1.10"},
        request_id="req-123",
    )

    res = adapter.evaluate(req)
    print("Decision:", res.decision, "reason:", res.reason, "attrs:", res.attributes, "hmac:", res.hmac[:16], "…")
    print("Health:", adapter.health())
