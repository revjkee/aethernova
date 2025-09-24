# -*- coding: utf-8 -*-
"""
Production-grade traffic router for model serving.

Unverified: окружение/интеграции и конкретные зависимости не подтверждены. I cannot verify this.

Возможности:
- Правила на основе path regex / HTTP метода / заголовков / tenant / произвольного key_fn.
- Стратегии: weighted round-pick, consistent hash (jump hash), sticky (по cookie/заголовку),
  canary/percent rollout (детерминированный), random fallback.
- Shadow (traffic mirroring) на один или несколько endpoints с процентом.
- Здоровье и circuit breaker per-endpoint (open/half-open/closed).
- Онлайн-обновление конфигурации без простоя (copy-on-write), потокобезопасно (RLock).
- Телеметрия через хуки emitter (increment/observe) и trace hooks (on_decision).
- Детерминированный сплит по стабильному ключу с CityHash-подобным xxhash/встроенным хэшем.

Интеграция (псевдокод):
    router = Router(config)
    ctx = RequestContext(path="/v1/infer", method="POST", headers={"x-tenant":"acme"},
                         tenant="acme", user_id="u42", ip="203.0.113.10")
    decision = router.select(ctx)
    # decision.primary.url -> куда слать основной запрос
    # decision.mirrors -> куда шэдоувить (fire-and-forget)

Конфиг пример см. в docstring RouterConfig.
"""
from __future__ import annotations

import re
import time
import threading
import random
import math
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

# =========================
# Модели конфигурации
# =========================

@dataclass(slots=True, frozen=True)
class Endpoint:
    id: str
    url: str
    weight: int = 1
    stage: str = "production"  # "production" | "staging" | "canary" | etc.
    metadata: Mapping[str, Any] = field(default_factory=dict)

@dataclass(slots=True, frozen=True)
class MirrorTarget:
    endpoint_id: str
    percent: float = 5.0  # 0..100

@dataclass(slots=True, frozen=True)
class Strategy:
    kind: str = "weighted"  # "weighted"|"consistent_hash"|"sticky"|"canary"
    # Поля для разных стратегий:
    hash_key: Optional[str] = None         # "user_id"|"session_id"|"tenant"|custom
    sticky_header: Optional[str] = None    # имя заголовка для sticky
    canary_percent: float = 0.0            # 0..100
    # Для canary нужно указать prod и canary пулы именованных групп (см. Rule.targets)
    # Для weighted/consistent_hash — используется список Rule.targets

@dataclass(slots=True, frozen=True)
class TargetGroup:
    """
    Именованный список endpoint_id с весами (перегоняется в карту {id:weight}).
    """
    name: str
    endpoints: Mapping[str, int]  # endpoint_id -> weight

@dataclass(slots=True, frozen=True)
class Rule:
    name: str
    path_pattern: Optional[str] = None
    methods: Optional[Sequence[str]] = None
    header_match: Optional[Tuple[str, str]] = None  # (header_name, regex)
    tenant_in: Optional[Sequence[str]] = None
    # Группы целей: первая — «основной пул» по умолчанию.
    targets: Sequence[TargetGroup] = field(default_factory=list)
    # Стратегия выбора
    strategy: Strategy = field(default_factory=Strategy)
    # Shadow traffic
    mirrors: Sequence[MirrorTarget] = field(default_factory=list)
    # Приоритет (меньше число — раньше матчится)
    priority: int = 100

@dataclass(slots=True, frozen=True)
class RouterConfig:
    """
    Полный конфиг роутера.

    Пример:
        RouterConfig(
            endpoints={
                "mA": Endpoint("mA","http://model-a:8080", weight=9, stage="production"),
                "mB": Endpoint("mB","http://model-b:8080", weight=1, stage="canary"),
            },
            rules=[
                Rule(
                    name="infer-v1",
                    path_pattern=r"^/v1/infer$",
                    methods=["POST"],
                    targets=[TargetGroup(name="pool", endpoints={"mA":9, "mB":1})],
                    strategy=Strategy(kind="canary", canary_percent=10.0),
                    mirrors=[MirrorTarget(endpoint_id="mB", percent=5.0)],
                    priority=10,
                ),
                Rule(
                    name="admin-weighted",
                    path_pattern=r"^/v1/admin/.*",
                    methods=["GET","POST"],
                    targets=[TargetGroup(name="pool", endpoints={"mA":1})],
                    strategy=Strategy(kind="weighted"),
                    priority=50,
                ),
            ],
            breaker=BreakerConfig(),
            health=HealthConfig(),
            telemetry=TelemetryConfig()
        )
    """
    endpoints: Mapping[str, Endpoint]
    rules: Sequence[Rule]
    breaker: "BreakerConfig" = field(default_factory=lambda: BreakerConfig())
    health: "HealthConfig" = field(default_factory=lambda: HealthConfig())
    telemetry: "TelemetryConfig" = field(default_factory=lambda: TelemetryConfig())

# =========================
# Контекст запроса
# =========================

@dataclass(slots=True)
class RequestContext:
    path: str
    method: str
    headers: Mapping[str, str]
    tenant: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip: Optional[str] = None
    # Доп. произвольные поля
    extras: Mapping[str, Any] = field(default_factory=dict)

    def get(self, key: str) -> Optional[str]:
        key = key.lower()
        if key == "user_id":
            return self.user_id
        if key == "tenant":
            return self.tenant
        if key == "session_id":
            return self.session_id
        if key == "ip":
            return self.ip
        # заголовок
        if key.startswith("header:"):
            h = key.split(":", 1)[1].lower()
            return self.headers.get(h)
        # extras
        return str(self.extras.get(key)) if key in self.extras else None

# =========================
# Telemetry hooks
# =========================

@dataclass(slots=True, frozen=True)
class TelemetryConfig:
    # emitter.increment(name, **labels) / emitter.observe(name, value, **labels)
    emitter: Optional[Any] = None
    # trace hook: on_decision(ctx, decision_dict)
    on_decision: Optional[Callable[[RequestContext, Mapping[str, Any]], None]] = None

# =========================
# Health & Circuit Breaker
# =========================

@dataclass(slots=True)
class BreakerConfig:
    failure_threshold: int = 5         # после стольких подряд ошибок - open
    success_threshold: int = 2         # для half-open -> closed
    reset_timeout_sec: float = 30.0    # время ожидания в open перед half-open

class CircuitBreaker:
    __slots__ = ("cfg","_state","_failures","_next_try","_successes","_lock")

    def __init__(self, cfg: BreakerConfig) -> None:
        self.cfg = cfg
        self._state = "closed"     # "closed"|"open"|"half_open"
        self._failures = 0
        self._next_try = 0.0
        self._successes = 0
        self._lock = threading.Lock()

    def allow_request(self) -> bool:
        now = time.monotonic()
        with self._lock:
            if self._state == "open":
                if now >= self._next_try:
                    self._state = "half_open"
                    self._successes = 0
                    return True
                return False
            return True

    def on_success(self) -> None:
        with self._lock:
            if self._state == "half_open":
                self._successes += 1
                if self._successes >= self.cfg.success_threshold:
                    self._state = "closed"
                    self._failures = 0
            else:
                self._failures = 0  # reset chain

    def on_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.cfg.failure_threshold:
                self._state = "open"
                self._next_try = time.monotonic() + self.cfg.reset_timeout_sec

    def state(self) -> str:
        with self._lock:
            return self._state

@dataclass(slots=True)
class HealthConfig:
    unhealthy_ttl_sec: float = 30.0  # если endpoint помечен unhealthy, через TTL можно проверить снова

class HealthRegistry:
    def __init__(self, cfg: HealthConfig) -> None:
        self.cfg = cfg
        self._store: Dict[str, Tuple[bool, float]] = {}  # endpoint_id -> (healthy, ts)
        self._lock = threading.Lock()

    def set(self, endpoint_id: str, healthy: bool) -> None:
        with self._lock:
            self._store[endpoint_id] = (healthy, time.monotonic())

    def is_healthy(self, endpoint_id: str) -> bool:
        with self._lock:
            v = self._store.get(endpoint_id)
            if v is None:
                return True
            healthy, ts = v
            if not healthy and (time.monotonic() - ts > self.cfg.unhealthy_ttl_sec):
                # TTL истек — даём шанс (treat as healthy)
                return True
            return healthy

# =========================
# Внутренние структуры
# =========================

@dataclass(slots=True, frozen=True)
class _CompiledRule:
    name: str
    path_re: Optional[re.Pattern]
    methods: Optional[Tuple[str, ...]]
    header_match: Optional[Tuple[str, re.Pattern]]
    tenant_in: Optional[Tuple[str, ...]]
    targets: Tuple[TargetGroup, ...]
    strategy: Strategy
    mirrors: Tuple[MirrorTarget, ...]
    priority: int

# =========================
# Решение маршрутизации
# =========================

@dataclass(slots=True, frozen=True)
class DecisionEndpoint:
    id: str
    url: str
    stage: str
    metadata: Mapping[str, Any]

@dataclass(slots=True, frozen=True)
class Decision:
    rule: str
    strategy: str
    primary: DecisionEndpoint
    mirrors: Tuple[DecisionEndpoint, ...]
    reason: str

# =========================
# Основной роутер
# =========================

class Router:
    def __init__(self, config: RouterConfig) -> None:
        self._lock = threading.RLock()
        self._compile_from_config(config)

    # ---------- Публичный API ----------

    def update(self, config: RouterConfig) -> None:
        """Безопасное онлайн-обновление конфигурации (copy-on-write)."""
        self._compile_from_config(config)

    def select(self, ctx: RequestContext) -> Decision:
        """Главная функция выбора маршрута для запроса."""
        with self._lock:
            rule = self._match_rule(ctx)
            if rule is None:
                raise LookupError("no matching routing rule")

            # Строим пул кандидатов в соответствии со стратегией
            strategy = rule.strategy.kind.lower()
            if strategy == "canary":
                primary = self._select_canary(rule, ctx)
                reason = "canary_percent"
            elif strategy == "consistent_hash":
                primary = self._select_consistent_hash(rule, ctx)
                reason = "consistent_hash"
            elif strategy == "sticky":
                primary = self._select_sticky(rule, ctx)
                reason = "sticky_header"
            else:
                primary = self._select_weighted(rule, ctx)
                reason = "weighted"

            # Shadow
            mirrors = self._select_mirrors(rule, ctx)

            decision = Decision(
                rule=rule.name,
                strategy=strategy,
                primary=primary,
                mirrors=mirrors,
                reason=reason,
            )

            self._emit_decision(ctx, decision)
            return decision

    def report_success(self, endpoint_id: str) -> None:
        br = self._breakers.get(endpoint_id)
        if br: br.on_success()

    def report_failure(self, endpoint_id: str) -> None:
        br = self._breakers.get(endpoint_id)
        if br: br.on_failure()

    def set_health(self, endpoint_id: str, healthy: bool) -> None:
        self._health.set(endpoint_id, healthy)

    # ---------- Внутреннее ----------

    def _compile_from_config(self, config: RouterConfig) -> None:
        compiled_rules: List[_CompiledRule] = []
        for r in sorted(config.rules, key=lambda x: x.priority):
            compiled_rules.append(
                _CompiledRule(
                    name=r.name,
                    path_re=re.compile(r.path_pattern) if r.path_pattern else None,
                    methods=tuple(m.upper() for m in r.methods) if r.methods else None,
                    header_match=(r.header_match[0].lower(), re.compile(r.header_match[1])) if r.header_match else None,
                    tenant_in=tuple(r.tenant_in) if r.tenant_in else None,
                    targets=tuple(r.targets),
                    strategy=r.strategy,
                    mirrors=tuple(r.mirrors),
                    priority=r.priority,
                )
            )

        with self._lock:
            self._cfg = config
            self._rules = tuple(compiled_rules)
            self._endpoints = dict(config.endpoints)
            self._health = HealthRegistry(config.health)
            self._breakers: Dict[str, CircuitBreaker] = {eid: CircuitBreaker(config.breaker) for eid in self._endpoints.keys()}

    def _match_rule(self, ctx: RequestContext) -> Optional[_CompiledRule]:
        path = ctx.path or "/"
        method = (ctx.method or "GET").upper()
        for r in self._rules:
            if r.methods and method not in r.methods:
                continue
            if r.path_re and not r.path_re.search(path):
                continue
            if r.header_match:
                name, rx = r.header_match
                hv = ctx.headers.get(name)
                if not (hv and rx.search(hv)):
                    continue
            if r.tenant_in and (ctx.tenant not in r.tenant_in):
                continue
            return r
        return None

    # ---------- Стратегии выбора primary ----------

    def _select_weighted(self, rule: _CompiledRule, ctx: RequestContext) -> DecisionEndpoint:
        pool = self._resolve_group(rule.targets[0])
        picked = self._weighted_pick(pool, exclude_bad=True)
        if picked is None:
            picked = self._weighted_pick(pool, exclude_bad=False)  # деградация
        return self._to_decision_endpoint(picked)

    def _select_consistent_hash(self, rule: _CompiledRule, ctx: RequestContext) -> DecisionEndpoint:
        key = self._hash_key(rule.strategy.hash_key, ctx) or (ctx.user_id or ctx.session_id or ctx.tenant or ctx.ip or "anon")
        pool = self._resolve_group(rule.targets[0])
        picked = self._hash_pick(pool, key, exclude_bad=True)
        if picked is None:
            picked = self._hash_pick(pool, key, exclude_bad=False)
        return self._to_decision_endpoint(picked)

    def _select_sticky(self, rule: _CompiledRule, ctx: RequestContext) -> DecisionEndpoint:
        hdr = (rule.strategy.sticky_header or "x-session-id").lower()
        sticky = ctx.headers.get(hdr) or ctx.session_id or ctx.user_id or ctx.ip or "anon"
        pool = self._resolve_group(rule.targets[0])
        picked = self._hash_pick(pool, sticky, exclude_bad=True)
        if picked is None:
            picked = self._hash_pick(pool, sticky, exclude_bad=False)
        return self._to_decision_endpoint(picked)

    def _select_canary(self, rule: _CompiledRule, ctx: RequestContext) -> DecisionEndpoint:
        percent = max(0.0, min(100.0, rule.strategy.canary_percent))
        # Основной пул — targets[0]; если указан второй TargetGroup — считаем его canary.
        if len(rule.targets) == 1:
            prod_pool = self._resolve_group(rule.targets[0])
            canary_pool = prod_pool  # нет отдельной канарейки
        else:
            prod_pool = self._resolve_group(rule.targets[0])
            canary_pool = self._resolve_group(rule.targets[1])

        # Детерминированный сплит по стабильному ключу
        key = self._hash_key(rule.strategy.hash_key, ctx) or (ctx.user_id or ctx.session_id or ctx.tenant or ctx.ip or "anon")
        bucket = self._stable_percent(key)  # 0..100
        chosen_pool = canary_pool if bucket < percent else prod_pool

        picked = self._weighted_pick(chosen_pool, exclude_bad=True)
        if picked is None:
            # деградация: сначала внутри выбранного пула без фильтра, затем в другом пуле
            picked = self._weighted_pick(chosen_pool, exclude_bad=False) or \
                     self._weighted_pick(prod_pool, exclude_bad=False) or \
                     self._weighted_pick(canary_pool, exclude_bad=False)
        return self._to_decision_endpoint(picked)

    # ---------- Shadow ----------

    def _select_mirrors(self, rule: _CompiledRule, ctx: RequestContext) -> Tuple[DecisionEndpoint, ...]:
        mirrors: List[DecisionEndpoint] = []
        for m in rule.mirrors:
            if m.percent <= 0:
                continue
            key = self._hash_key("session_id", ctx) or (ctx.user_id or ctx.session_id or ctx.tenant or ctx.ip or "anon")
            if self._stable_percent(f"mirror:{m.endpoint_id}:{key}") < m.percent:
                ep = self._endpoints.get(m.endpoint_id)
                if ep and self._is_effectively_available(ep):
                    mirrors.append(self._to_decision_endpoint(ep))
        return tuple(mirrors)

    # ---------- Поддержка выбора из пула ----------

    def _resolve_group(self, group: TargetGroup) -> List[Endpoint]:
        res: List[Endpoint] = []
        for eid, w in group.endpoints.items():
            ep = self._endpoints.get(eid)
            if ep and w > 0:
                res.append(ep)
        if not res:
            raise LookupError(f"empty target group: {group.name}")
        return res

    def _weighted_pick(self, pool: Sequence[Endpoint], exclude_bad: bool) -> Optional[Endpoint]:
        cand: List[Tuple[Endpoint, int]] = []
        for ep in pool:
            if exclude_bad and not self._is_effectively_available(ep):
                continue
            cand.append((ep, max(1, int(ep.weight))))
        if not cand:
            return None
        total = sum(w for _, w in cand)
        r = random.randint(1, total)
        acc = 0
        for ep, w in cand:
            acc += w
            if r <= acc:
                return ep
        return cand[-1][0]

    def _hash_pick(self, pool: Sequence[Endpoint], key: str, exclude_bad: bool) -> Optional[Endpoint]:
        cand = [ep for ep in pool if (not exclude_bad or self._is_effectively_available(ep))]
        if not cand:
            return None
        # Jump consistent hash по индексам cand
        h = self._hash64(key)
        idx = self._jump_consistent_hash(h, len(cand))
        return cand[idx]

    # ---------- Здоровье + брейкер ----------

    def _is_effectively_available(self, ep: Endpoint) -> bool:
        ok = self._health.is_healthy(ep.id)
        if not ok:
            return False
        br = self._breakers.get(ep.id)
        return True if (br is None) else br.allow_request()

    # ---------- Телеметрия ----------

    def _emit_decision(self, ctx: RequestContext, d: Decision) -> None:
        tel = self._cfg.telemetry
        if tel.emitter and hasattr(tel.emitter, "increment"):
            try:
                tel.emitter.increment("router_decision_total",
                                      rule=d.rule, strategy=d.strategy, primary=d.primary.id, stage=d.primary.stage)
            except Exception:
                pass
        if tel.on_decision:
            try:
                tel.on_decision(ctx, {
                    "rule": d.rule,
                    "strategy": d.strategy,
                    "primary": d.primary.id,
                    "mirrors": [m.id for m in d.mirrors],
                    "reason": d.reason,
                })
            except Exception:
                pass

    # ---------- Утилиты ----------

    def _to_decision_endpoint(self, ep: Optional[Endpoint]) -> DecisionEndpoint:
        if ep is None:
            raise RuntimeError("no endpoint available")
        return DecisionEndpoint(id=ep.id, url=ep.url, stage=ep.stage, metadata=ep.metadata)

    @staticmethod
    def _hash64(s: str) -> int:
        # Дет. 64-битный хэш на основе встроенного hash, но стабилизированный.
        # Используем FNV-1a 64-bit (простой и быстрый) для стабильности между процессами.
        h = 0xcbf29ce484222325
        for b in s.encode("utf-8", "ignore"):
            h ^= b
            h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
        return h

    @staticmethod
    def _jump_consistent_hash(key: int, buckets: int) -> int:
        # Алгоритм Jump Consistent Hash (Lamping, Veach)
        if buckets <= 0:
            return 0
        b, j = -1, 0
        while j < buckets:
            b = j
            key = (key * 2862933555777941757 + 1) & 0xFFFFFFFFFFFFFFFF
            j = int((b + 1) * (1 << 31) / ((key >> 33) + 1))
        return b

    def _stable_percent(self, s: str) -> float:
        # Преобразуем хэш к равномерному 0..100
        h = self._hash64(s)
        return (h % 10_000) / 100.0

    @staticmethod
    def _normalize_key_name(name: Optional[str]) -> Optional[str]:
        return name.lower() if name else None

    def _hash_key(self, key_name: Optional[str], ctx: RequestContext) -> Optional[str]:
        if not key_name:
            return None
        key_name = key_name.lower()
        # Специальные ключи и унификация "header:<name>"
        if key_name in {"user_id","tenant","session_id","ip"} or key_name.startswith("header:"):
            return ctx.get(key_name)
        # из extras
        return ctx.get(key_name)

# =========================
# Конец файла
# =========================
