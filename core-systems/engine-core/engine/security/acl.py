# -*- coding: utf-8 -*-
"""
ACL / Authorization Engine (industrial-grade, RBAC + ABAC)

Возможности:
- Гибрид RBAC/ABAC: роли (включая иерархии), атрибутные условия и контекст запроса.
- Политики с правилами Allow/Deny, паттерны ресурсов/действий (glob/regex), многоарендность (tenant).
- Объединяющие алгоритмы: deny-overrides (по умолчанию), permit-overrides, first-applicable, ordered-deny-overrides.
- Условия: время/календарь, IP и подсети, сравнение атрибутов subject/resource/context, кастомные предикаты.
- Объяснимость решения: подробный trace (какая политика/правило сработало/почему).
- Кэш решений (TTL + LRU), потокобезопасность (RLock).
- Аудит-хуки и метрики (заглушки), «обязательства» (obligations) для PEP (например, маскирование полей).
- Интерфейс PolicyStore (in-memory включён), сериализация/версионирование.

Зависимости: стандартная библиотека.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, time as dtime
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Set, Tuple, Union

# =============================================================================
# Метрики/Аудит (заглушки)
# =============================================================================

class Metrics:
    @staticmethod
    def inc(name: str, **labels) -> None:
        pass

    @staticmethod
    def observe(name: str, value: float, **labels) -> None:
        pass

class Audit:
    @staticmethod
    def emit(event: str, payload: Dict[str, Any]) -> None:
        pass

# =============================================================================
# Базовые типы
# =============================================================================

Decision = Literal["Permit", "Deny", "NotApplicable", "Indeterminate"]

class CombineAlg(str, Enum):
    DENY_OVERRIDES = "deny_overrides"
    PERMIT_OVERRIDES = "permit_overrides"
    FIRST_APPLICABLE = "first_applicable"
    ORDERED_DENY_OVERRIDES = "ordered_deny_overrides"

@dataclass(frozen=True)
class Principal:
    subject_id: str
    tenant: Optional[str] = None
    roles: Set[str] = field(default_factory=set)
    attrs: Dict[str, Any] = field(default_factory=dict)   # любые атрибуты субъекта (dept, region, clearance...)

@dataclass(frozen=True)
class ResourceRef:
    resource: str                                   # строковый идентификатор, поддерживает glob (foo/*)
    tenant: Optional[str] = None
    attrs: Dict[str, Any] = field(default_factory=dict)   # атрибуты ресурса (owner_id, tags, classification...)

@dataclass(frozen=True)
class RequestCtx:
    action: str                                     # операция, поддерживает glob (read/*)
    ip: Optional[str] = None
    now_utc: Optional[datetime] = None              # можно передать для тестирования
    attrs: Dict[str, Any] = field(default_factory=dict)   # контекстные атрибуты (channel, device, mfa...)

@dataclass
class Obligation:
    key: str
    value: Any

@dataclass
class Result:
    decision: Decision
    obligations: List[Obligation] = field(default_factory=list)
    explanation: Dict[str, Any] = field(default_factory=dict)  # детальный trace

# =============================================================================
# Политики и правила
# =============================================================================

@dataclass
class Condition:
    """Условие ABAC: предикат, работающий на (principal, resource, request)."""
    name: str
    predicate: Callable[[Principal, ResourceRef, RequestCtx], bool]
    description: str = ""

@dataclass
class Rule:
    effect: Literal["Allow", "Deny"]
    # паттерны любого из полей должны совпасть, чтобы правило применилось
    actions: Set[str] = field(default_factory=set)         # поддерживает glob
    resources: Set[str] = field(default_factory=set)       # поддерживает glob
    roles: Set[str] = field(default_factory=set)           # требуется пересечение с ролями субъекта (если не пусто)
    subjects: Set[str] = field(default_factory=set)        # allow/deny для конкретных subject_id (если не пусто)
    tenant: Optional[str] = None                           # если задан — должен совпасть
    conditions: List[Condition] = field(default_factory=list)
    obligations: List[Obligation] = field(default_factory=list)
    priority: int = 0                                      # больший приоритет обрабатывается позже (в некоторых алгоритмах)
    regex_actions: List[re.Pattern] = field(default_factory=list, repr=False)
    regex_resources: List[re.Pattern] = field(default_factory=list, repr=False)
    description: str = ""

    def matches(self, p: Principal, r: ResourceRef, q: RequestCtx) -> Tuple[bool, str]:
        # tenant
        if self.tenant is not None and self.tenant != (p.tenant or r.tenant):
            return False, "tenant_mismatch"
        # subject filter
        if self.subjects and p.subject_id not in self.subjects:
            return False, "subject_filter"
        # role intersection
        if self.roles and not (self.roles & p.roles):
            return False, "role_filter"
        # action glob/regex
        if self.actions and not any(fnmatch.fnmatch(q.action, pat) for pat in self.actions):
            return False, "action_glob"
        if self.regex_actions and not any(rx.search(q.action) for rx in self.regex_actions):
            return False, "action_regex"
        # resource glob/regex
        tgt = r.resource
        if self.resources and not any(fnmatch.fnmatch(tgt, pat) for pat in self.resources):
            return False, "resource_glob"
        if self.regex_resources and not any(rx.search(tgt) for rx in self.regex_resources):
            return False, "resource_regex"
        # conditions
        for c in self.conditions:
            try:
                if not c.predicate(p, r, q):
                    return False, f"cond:{c.name}"
            except Exception:
                return False, f"cond_error:{c.name}"
        return True, "ok"

@dataclass
class Policy:
    policy_id: str
    rules: List[Rule]
    combine: CombineAlg = CombineAlg.DENY_OVERRIDES
    version: int = 1
    description: str = ""
    enabled: bool = True

    def to_json(self) -> Dict[str, Any]:
        # сериализация без предикатов (их регистрируют по имени извне)
        out = {
            "policy_id": self.policy_id,
            "combine": self.combine.value,
            "version": self.version,
            "description": self.description,
            "enabled": self.enabled,
            "rules": []
        }
        for r in self.rules:
            out["rules"].append({
                "effect": r.effect,
                "actions": list(r.actions),
                "resources": list(r.resources),
                "roles": list(r.roles),
                "subjects": list(r.subjects),
                "tenant": r.tenant,
                "obligations": [{"key": o.key, "value": o.value} for o in r.obligations],
                "priority": r.priority,
                "description": r.description,
                "regex_actions": [rx.pattern for rx in r.regex_actions],
                "regex_resources": [rx.pattern for rx in r.regex_resources],
                "conditions": [c.name for c in r.conditions],
            })
        return out

# =============================================================================
# Полезные условия (готовые предикаты)
# =============================================================================

def cond_time_between(name: str, start: dtime, end: dtime, tz: timezone = timezone.utc) -> Condition:
    def _pred(_p: Principal, _r: ResourceRef, q: RequestCtx) -> bool:
        now = q.now_utc or datetime.now(tz)
        t = now.timetz()
        # диапазон, поддерживаем "через полночь"
        if start <= end:
            return start <= t <= end
        return t >= start or t <= end
    return Condition(name=name, predicate=_pred, description=f"time between {start}-{end} {tz}")

def cond_ip_in(name: str, *nets: str) -> Condition:
    networks = [ipaddress.ip_network(n) for n in nets]
    def _pred(_p: Principal, _r: ResourceRef, q: RequestCtx) -> bool:
        if not q.ip:
            return False
        ip = ipaddress.ip_address(q.ip)
        return any(ip in n for n in networks)
    return Condition(name=name, predicate=_pred, description=f"ip in {','.join(nets)}")

def cond_attr_eq(name: str, subject_attr: Optional[str] = None, resource_attr: Optional[str] = None,
                 ctx_attr: Optional[str] = None, value: Optional[Any] = None) -> Condition:
    def _get(val: Optional[str], bag: Dict[str, Any]) -> Any:
        return bag.get(val) if val else None
    def _pred(p: Principal, r: ResourceRef, q: RequestCtx) -> bool:
        candidates = []
        if subject_attr: candidates.append(_get(subject_attr, p.attrs))
        if resource_attr: candidates.append(_get(resource_attr, r.attrs))
        if ctx_attr: candidates.append(_get(ctx_attr, q.attrs))
        if value is not None: candidates.append(value)
        # все заданные значения должны совпасть друг с другом
        norm = [json.dumps(v, sort_keys=True) for v in candidates if v is not None]
        return len(norm) <= 1 or all(n == norm[0] for n in norm)
    return Condition(name=name, predicate=_pred, description="attributes equality")

def cond_attr_in(name: str, subject_attr: Optional[str], allowed: Iterable[Any]) -> Condition:
    allowed_set = set(allowed)
    def _pred(p: Principal, _r: ResourceRef, _q: RequestCtx) -> bool:
        return p.attrs.get(subject_attr) in allowed_set
    return Condition(name=name, predicate=_pred, description=f"{subject_attr} in set")

# =============================================================================
# Policy Store
# =============================================================================

class PolicyStore:
    def get_policies(self, tenant: Optional[str]) -> List[Policy]: ...
    def upsert_policy(self, policy: Policy) -> None: ...
    def remove_policy(self, policy_id: str) -> None: ...
    def version(self) -> str: ...

class InMemoryPolicyStore(PolicyStore):
    def __init__(self):
        self._by_tenant: Dict[Optional[str], Dict[str, Policy]] = {}
        self._lock = threading.RLock()
        self._ver = 0

    def get_policies(self, tenant: Optional[str]) -> List[Policy]:
        with self._lock:
            shared = list(self._by_tenant.get(None, {}).values())
            scoped = list(self._by_tenant.get(tenant, {}).values())
            return [p for p in (shared + scoped) if p.enabled]

    def upsert_policy(self, policy: Policy) -> None:
        with self._lock:
            bag = self._by_tenant.setdefault(None, {})
            # если policyId содержит префикс "tenant:" — направим в секцию арендатора
            t = None
            if ":" in policy.policy_id:
                maybe_tenant, _ = policy.policy_id.split(":", 1)
                if maybe_tenant.startswith("tenant"):
                    t = maybe_tenant
            if t is not None:
                bag = self._by_tenant.setdefault(t, {})
            bag[policy.policy_id] = policy
            self._ver += 1

    def remove_policy(self, policy_id: str) -> None:
        with self._lock:
            for m in self._by_tenant.values():
                m.pop(policy_id, None)
            self._ver += 1

    def version(self) -> str:
        with self._lock:
            return f"mem:{self._ver}"

# =============================================================================
# Кэш решений (TTL + LRU)
# =============================================================================

@dataclass
class _CacheEntry:
    key: Tuple[Any, ...]
    value: Result
    ts: float

class DecisionCache:
    def __init__(self, ttl_s: int = 60, capacity: int = 10_000):
        self.ttl = ttl_s
        self.cap = capacity
        self._map: Dict[Tuple[Any, ...], _CacheEntry] = {}
        self._order: List[Tuple[Any, ...]] = []
        self._lock = threading.RLock()

    def _evict(self) -> None:
        while len(self._order) > self.cap:
            k = self._order.pop(0)
            self._map.pop(k, None)

    def get(self, key: Tuple[Any, ...]) -> Optional[Result]:
        now = time.time()
        with self._lock:
            ent = self._map.get(key)
            if not ent:
                return None
            if now - ent.ts > self.ttl:
                self._map.pop(key, None)
                try:
                    self._order.remove(key)
                except ValueError:
                    pass
                return None
            # LRU bump
            try:
                self._order.remove(key)
            except ValueError:
                pass
            self._order.append(key)
            return ent.value

    def put(self, key: Tuple[Any, ...], value: Result) -> None:
        with self._lock:
            self._map[key] = _CacheEntry(key, value, time.time())
            try:
                self._order.remove(key)
            except ValueError:
                pass
            self._order.append(key)
            self._evict()

# =============================================================================
# PDP (Policy Decision Point)
# =============================================================================

class ACL:
    """
    Policy Decision Point:
    - Загружает политики из PolicyStore
    - Вычисляет решение и объяснение
    - Кэширует решения
    """
    def __init__(self,
                 store: Optional[PolicyStore] = None,
                 combine_default: CombineAlg = CombineAlg.DENY_OVERRIDES,
                 cache_ttl_s: int = 60,
                 cache_capacity: int = 10_000):
        self.store = store or InMemoryPolicyStore()
        self.combine_default = combine_default
        self.cache = DecisionCache(ttl_s=cache_ttl_s, capacity=cache_capacity)
        self._lock = threading.RLock()
        self._pol_ver = self.store.version()

    # -------------------- Публичный интерфейс -------------------- #
    def is_allowed(self, principal: Principal, resource: ResourceRef, request: RequestCtx) -> bool:
        return self.decide(principal, resource, request).decision == "Permit"

    def decide(self, principal: Principal, resource: ResourceRef, request: RequestCtx) -> Result:
        # Проверим версию политик — при изменении очистим кэш (грубая но простая стратегия)
        ver = self.store.version()
        if ver != self._pol_ver:
            with self._lock:
                self.cache = DecisionCache(self.cache.ttl, self.cache.cap)
                self._pol_ver = ver

        key = self._cache_key(principal, resource, request)
        cached = self.cache.get(key)
        if cached:
            return cached

        t0 = time.perf_counter()
        pols = self.store.get_policies(principal.tenant or resource.tenant)
        # Стабильный порядок: по combine, затем по policy_id, затем priority правил
        pols = [p for p in pols if p.enabled]
        # Оценка
        results, final = self._evaluate(pols, principal, resource, request)
        elapsed = time.perf_counter() - t0

        explanation = {
            "policy_version": ver,
            "combine_default": self.combine_default.value,
            "trace": results,
            "latency_ms": round(elapsed * 1000, 3),
        }
        result = Result(decision=final[0], obligations=final[1], explanation=explanation)

        self.cache.put(key, result)
        Metrics.observe("acl_decide_latency_s", elapsed, decision=result.decision)
        return result

    # -------------------- Внутренняя логика -------------------- #

    def _cache_key(self, p: Principal, r: ResourceRef, q: RequestCtx) -> Tuple[Any, ...]:
        return (
            p.tenant, p.subject_id, tuple(sorted(p.roles)), self._freeze_dict(p.attrs),
            r.tenant, r.resource, self._freeze_dict(r.attrs),
            q.action, q.ip, self._freeze_dict(q.attrs),
        )

    @staticmethod
    def _freeze_dict(d: Dict[str, Any]) -> Tuple[Tuple[str, Any], ...]:
        return tuple(sorted((k, ACL._freeze(v)) for k, v in d.items()))

    @staticmethod
    def _freeze(v: Any) -> Any:
        if isinstance(v, dict):
            return tuple(sorted((k, ACL._freeze(x)) for k, x in v.items()))
        if isinstance(v, list):
            return tuple(ACL._freeze(x) for x in v)
        return v

    def _evaluate(self, policies: List[Policy], p: Principal, r: ResourceRef, q: RequestCtx) -> Tuple[List[Dict[str, Any]], Tuple[Decision, List[Obligation]]]:
        trace: List[Dict[str, Any]] = []
        obligations: List[Obligation] = []
        combined_decision: Decision = "NotApplicable"

        # Алгоритмы объединения на уровне всей системы: применяем combine политики в порядке их регистрации
        for pol in policies:
            pol_trace, dec, oblig = self._evaluate_policy(pol, p, r, q)
            trace.append({
                "policy": pol.policy_id,
                "combine": pol.combine.value,
                "decision": dec,
                "rules": pol_trace,
            })

            if pol.combine is CombineAlg.DENY_OVERRIDES:
                if dec == "Deny":
                    return trace, ("Deny", oblig)
                if dec == "Permit" and combined_decision != "Permit":
                    combined_decision = "Permit"; obligations = oblig
            elif pol.combine is CombineAlg.PERMIT_OVERRIDES:
                if dec == "Permit":
                    return trace, ("Permit", oblig)
                if dec == "Deny" and combined_decision != "Deny":
                    combined_decision = "Deny"; obligations = oblig
            elif pol.combine is CombineAlg.FIRST_APPLICABLE:
                if dec in ("Permit", "Deny"):
                    return trace, (dec, oblig)
            elif pol.combine is CombineAlg.ORDERED_DENY_OVERRIDES:
                # Правила уже упорядочены — если есть Deny выше приоритета, он выигрывает
                if dec == "Deny":
                    return trace, ("Deny", oblig)
                if dec == "Permit" and combined_decision != "Permit":
                    combined_decision = "Permit"; obligations = oblig

        if combined_decision in ("Permit", "Deny"):
            return trace, (combined_decision, obligations)
        return trace, ("NotApplicable", [])

    def _evaluate_policy(self, pol: Policy, p: Principal, r: ResourceRef, q: RequestCtx) -> Tuple[List[Dict[str, Any]], Decision, List[Obligation]]:
        # Упорядочим правила: сначала по priority возрастанию, затем по эффекту (Deny позже при ORDERED_DENY_OVERRIDES)
        rules = sorted(pol.rules, key=lambda rr: (rr.priority, 0 if rr.effect == "Allow" else 1))
        rule_traces: List[Dict[str, Any]] = []
        seen_applicable = False
        obligations: List[Obligation] = []

        decision: Decision = "NotApplicable"
        for i, rule in enumerate(rules):
            match, reason = rule.matches(p, r, q)
            rule_traces.append({
                "idx": i,
                "effect": rule.effect,
                "priority": rule.priority,
                "match": match,
                "reason": reason if not match else "ok",
                "desc": rule.description,
            })
            if not match:
                continue
            seen_applicable = True

            if pol.combine is CombineAlg.FIRST_APPLICABLE:
                decision = "Permit" if rule.effect == "Allow" else "Deny"
                obligations = list(rule.obligations)
                break

            if pol.combine in (CombineAlg.DENY_OVERRIDES, CombineAlg.ORDERED_DENY_OVERRIDES):
                if rule.effect == "Deny":
                    return rule_traces, "Deny", list(rule.obligations)
                if rule.effect == "Allow":
                    decision = "Permit"
                    obligations = list(rule.obligations)
            elif pol.combine is CombineAlg.PERMIT_OVERRIDES:
                if rule.effect == "Allow":
                    return rule_traces, "Permit", list(rule.obligations)
                if rule.effect == "Deny":
                    decision = "Deny"
                    obligations = list(rule.obligations)

        if not seen_applicable:
            return rule_traces, "NotApplicable", []
        return rule_traces, decision if decision != "NotApplicable" else "Indeterminate", obligations

# =============================================================================
# Вспомогательные фабрики
# =============================================================================

def rule_allow(actions: Iterable[str], resources: Iterable[str], *, roles: Iterable[str] = (),
               subjects: Iterable[str] = (), tenant: Optional[str] = None,
               conditions: Iterable[Condition] = (), obligations: Iterable[Tuple[str, Any]] = (),
               priority: int = 0, regex_actions: Iterable[str] = (), regex_resources: Iterable[str] = (),
               description: str = "") -> Rule:
    return Rule(
        effect="Allow",
        actions=set(actions),
        resources=set(resources),
        roles=set(roles),
        subjects=set(subjects),
        tenant=tenant,
        conditions=list(conditions),
        obligations=[Obligation(k, v) for k, v in obligations],
        priority=priority,
        regex_actions=[re.compile(p) for p in regex_actions],
        regex_resources=[re.compile(p) for p in regex_resources],
        description=description,
    )

def rule_deny(actions: Iterable[str], resources: Iterable[str], **kwargs) -> Rule:
    r = rule_allow(actions, resources, **kwargs)
    r.effect = "Deny"
    return r

def policy(policy_id: str, *rules: Rule, combine: CombineAlg = CombineAlg.DENY_OVERRIDES,
           version: int = 1, description: str = "", enabled: bool = True) -> Policy:
    return Policy(policy_id=policy_id, rules=list(rules), combine=combine, version=version, description=description, enabled=enabled)

# =============================================================================
# Пример использования / локальный self-test
# =============================================================================

if __name__ == "__main__":
    store = InMemoryPolicyStore()

    # Базовые условия
    business_hours = cond_time_between("business_hours", dtime(8, 0), dtime(20, 0))
    corp_net = cond_ip_in("corp_net", "10.0.0.0/8", "192.168.0.0/16")
    owner_only = Condition(
        name="owner_only",
        predicate=lambda p, r, q: p.subject_id == str(r.attrs.get("owner_id")),
        description="subject is owner of resource",
    )
    mfa_required = cond_attr_eq("mfa_required", ctx_attr="mfa", value=True)

    # Политики
    # 1) Общая: чтение любых документов сотрудниками из корпоративной сети в рабочее время
    store.upsert_policy(policy(
        "global.read.policy",
        rule_allow(actions=["read", "read/*"], resources=["doc/*"], roles={"employee"},
                   conditions=[business_hours, corp_net], description="Employees read during business hours"),
        combine=CombineAlg.DENY_OVERRIDES,
        version=1,
        description="Global read access"
    ))

    # 2) Доступ владельца: полный контроль над своим документом (с MFA для удаления)
    store.upsert_policy(policy(
        "global.owner.policy",
        rule_allow(actions=["read", "update"], resources=["doc/*"], conditions=[owner_only]),
        rule_allow(actions=["delete"], resources=["doc/*"], conditions=[owner_only, mfa_required],
                   obligations=[("redact", ["ssn", "secret"])],  # пример obligations
                   description="Owner delete requires MFA, response must redact fields"),
        combine=CombineAlg.PERMIT_OVERRIDES,
        version=3,
        description="Owner access policy"
    ))

    # 3) Явные запреты: запретить удаление классифицированных документов всем, кроме роли 'security_officer'
    store.upsert_policy(policy(
        "global.classified.policy",
        rule_deny(actions=["delete"], resources=["doc/*"], conditions=[
            Condition("classified", predicate=lambda _p, r, _q: r.attrs.get("class") == "secret")
        ]),
        rule_allow(actions=["delete"], resources=["doc/*"], roles={"security_officer"}),
        combine=CombineAlg.DENY_OVERRIDES,
        version=2,
        description="Deny delete for secret unless security officer"
    ))

    # PDP
    acl = ACL(store=store, combine_default=CombineAlg.DENY_OVERRIDES)

    # Субъекты, ресурсы, запросы
    alice = Principal(subject_id="u:alice", tenant=None, roles={"employee"}, attrs={"dept": "sales"})
    sec = Principal(subject_id="u:sofia", tenant=None, roles={"employee", "security_officer"}, attrs={})

    doc1 = ResourceRef(resource="doc/123", attrs={"owner_id": "u:alice", "class": "public"})
    doc2 = ResourceRef(resource="doc/555", attrs={"owner_id": "u:alice", "class": "secret"})

    req_read = RequestCtx(action="read", ip="10.10.1.5", attrs={"mfa": True})
    req_delete_no_mfa = RequestCtx(action="delete", ip="10.10.1.5", attrs={"mfa": False})
    req_delete_mfa = RequestCtx(action="delete", ip="10.10.1.5", attrs={"mfa": True})

    # Примеры решений
    for (who, res, req, label) in [
        (alice, doc1, req_read, "alice read public"),
        (alice, doc1, req_delete_no_mfa, "alice delete public no mfa"),
        (alice, doc1, req_delete_mfa, "alice delete public with mfa"),
        (alice, doc2, req_delete_mfa, "alice delete secret with mfa"),
        (sec, doc2, req_delete_no_mfa, "security officer delete secret"),
    ]:
        out = acl.decide(who, res, req)
        print(f"{label:32s} -> {out.decision:>14s}  obligations={[(o.key,o.value) for o in out.obligations]}")
        # Для демонстрации объяснения можно раскомментировать:
        # from pprint import pprint; pprint(out.explanation)
