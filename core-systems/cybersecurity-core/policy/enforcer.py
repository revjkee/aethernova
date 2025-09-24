# cybersecurity-core/cybersecurity/policy/enforcer.py
from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

try:
    # YAML поддержка опциональна: loader/save политик
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # будет использована JSON-ветка

from pydantic import BaseModel, Field, validator

__all__ = [
    "Subject",
    "Resource",
    "Action",
    "Environment",
    "Obligation",
    "Rule",
    "Policy",
    "Decision",
    "ExplainEntry",
    "PolicyStore",
    "Enforcer",
    "Condition",
    "ConditionAny",
    "ConditionAll",
    "ConditionExpr",
    "ConditionRef",
    "CombiningAlg",
    "PolicyError",
]

logger = logging.getLogger(__name__)


# ============================= МОДЕЛИ КОНТЕКСТА ==============================

class Subject(BaseModel):
    id: str
    tenant: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class Resource(BaseModel):
    id: str
    type: str
    owner_id: Optional[str] = None
    path: Optional[str] = None  # например: "doc/finance/q1.pdf"
    attributes: Dict[str, Any] = Field(default_factory=dict)
    # ReBAC: отношения роль->список субъектов
    relationships: Dict[str, List[str]] = Field(default_factory=dict)


class Action(BaseModel):
    action: str
    scopes: List[str] = Field(default_factory=list)


class Environment(BaseModel):
    ip: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None
    # произвольные атрибуты окружения (время, риск, канал и т.д.)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class Obligation(BaseModel):
    type: Literal["mfa", "reauth", "limit-scope", "time-limit", "context-bind", "watermark"]
    detail: Dict[str, Any] = Field(default_factory=dict)


class ExplainEntry(BaseModel):
    rule_id: str
    matched: bool
    reason: str
    data: Dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    outcome: Literal["permit", "deny"]
    policy_id: Optional[str] = None
    rule_id: Optional[str] = None
    obligations: List[Obligation] = Field(default_factory=list)
    ttl_seconds: Optional[int] = None
    explain: List[ExplainEntry] = Field(default_factory=list)
    reason: Optional[str] = None


# =========================== УСЛОВИЯ (БЕЗ eval) ==============================

class Condition(BaseModel):
    kind: Literal["any", "all", "expr", "ref"]

    def evaluate(self, ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        raise NotImplementedError


class ConditionAny(Condition):
    kind: Literal["any"] = "any"
    items: List[Condition] = Field(default_factory=list)

    def evaluate(self, ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        details = []
        for c in self.items:
            ok, det = c.evaluate(ctx)
            details.append({"kind": c.kind, "ok": ok, "detail": det})
            if ok:
                return True, {"any": details}
        return False, {"any": details}


class ConditionAll(Condition):
    kind: Literal["all"] = "all"
    items: List[Condition] = Field(default_factory=list)

    def evaluate(self, ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        details = []
        for c in self.items:
            ok, det = c.evaluate(ctx)
            details.append({"kind": c.kind, "ok": ok, "detail": det})
            if not ok:
                return False, {"all": details}
        return True, {"all": details}


class ConditionRef(Condition):
    """
    Ссылка на именованное выражение из Policy.expressions.
    """
    kind: Literal["ref"] = "ref"
    name: str

    def evaluate(self, ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        exprs: Dict[str, Condition] = ctx.get("$expressions", {})
        sub = exprs.get(self.name)
        if not sub:
            return False, {"error": f"expression '{self.name}' not found"}
        return sub.evaluate(ctx)


class ConditionExpr(Condition):
    """
    Примитивное выражение в безопасном DSL:
      op: один из
        - eq, ne, gt, ge, lt, le
        - in, nin (список/строка)
        - regex (поддержка re.match целиком)
        - prefix, suffix, contains
        - exists, nexists
        - cidr (соответствие IP списку CIDR)
    Аргументы:
      left: путь (dot-path) к значению в контексте ("subject.roles", "resource.attributes.classification", "env.ip", ...)
      right: литерал (int/float/str/bool/список/None) или dot-path "ref:<path>"
    """
    kind: Literal["expr"] = "expr"
    op: Literal[
        "eq", "ne", "gt", "ge", "lt", "le",
        "in", "nin", "regex", "prefix", "suffix", "contains",
        "exists", "nexists", "cidr"
    ]
    left: str
    right: Any = None
    flags: Dict[str, Any] = Field(default_factory=dict)

    @staticmethod
    def _get_by_path(ctx: Dict[str, Any], path: str) -> Any:
        cur: Any = ctx
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
        return cur

    @staticmethod
    def _resolve_side(ctx: Dict[str, Any], side: Any) -> Any:
        if isinstance(side, str) and side.startswith("ref:"):
            return ConditionExpr._get_by_path(ctx, side[4:])
        return side

    def evaluate(self, ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        import re

        left_val = self._get_by_path(ctx, self.left)
        right_val = self._resolve_side(ctx, self.right)

        def _as_list(v: Any) -> List[Any]:
            if v is None:
                return []
            if isinstance(v, (list, tuple, set)):
                return list(v)
            # для строк: содержимое -> список из одного элемента
            return [v]

        ok = False
        info: Dict[str, Any] = {"op": self.op, "left": self.left, "left_val": left_val, "right": self.right, "right_resolved": right_val}

        if self.op == "exists":
            ok = left_val is not None
        elif self.op == "nexists":
            ok = left_val is None
        elif self.op == "eq":
            ok = left_val == right_val
        elif self.op == "ne":
            ok = left_val != right_val
        elif self.op == "gt":
            try:
                ok = left_val > right_val  # type: ignore[operator]
            except Exception:
                ok = False
        elif self.op == "ge":
            try:
                ok = left_val >= right_val  # type: ignore[operator]
            except Exception:
                ok = False
        elif self.op == "lt":
            try:
                ok = left_val < right_val  # type: ignore[operator]
            except Exception:
                ok = False
        elif self.op == "le":
            try:
                ok = left_val <= right_val  # type: ignore[operator]
            except Exception:
                ok = False
        elif self.op == "in":
            ok = left_val in _as_list(right_val) if not isinstance(right_val, str) else str(left_val) in right_val
        elif self.op == "nin":
            ok = left_val not in _as_list(right_val) if not isinstance(right_val, str) else str(left_val) not in right_val
        elif self.op == "contains":
            rv = _as_list(right_val)
            if isinstance(left_val, str) and isinstance(right_val, str):
                ok = right_val in left_val
            elif isinstance(left_val, (list, tuple, set)):
                ok = any(x in left_val for x in rv)
            else:
                ok = False
        elif self.op == "prefix":
            ok = isinstance(left_val, str) and isinstance(right_val, str) and left_val.startswith(right_val)
        elif self.op == "suffix":
            ok = isinstance(left_val, str) and isinstance(right_val, str) and left_val.endswith(right_val)
        elif self.op == "regex":
            try:
                pattern = right_val or ""
                flags = re.IGNORECASE if self.flags.get("i") else 0
                ok = isinstance(left_val, str) and re.fullmatch(pattern, left_val, flags) is not None
            except re.error:
                ok = False
        elif self.op == "cidr":
            ok = _cidr_match(str(left_val) if left_val is not None else None, _as_list(right_val))
        else:
            ok = False

        info["ok"] = ok
        return ok, info


def _cidr_match(ip: Optional[str], cidrs: Sequence[str]) -> bool:
    if not ip or not cidrs:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for c in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(c, strict=False):
                return True
        except Exception:
            continue
    return False


# =============================== ПРАВИЛА/ПОЛИТИКИ ============================

CombiningAlg = Literal["deny-overrides", "permit-overrides", "first-applicable"]

class Rule(BaseModel):
    id: str
    effect: Literal["permit", "deny"]
    actions: List[str] = Field(default_factory=lambda: ["*"])     # glob-паттерны: "read", "write", "*"
    resources: List[str] = Field(default_factory=lambda: ["*"])   # glob по resource.path или "<type>:<id>"
    roles: List[str] = Field(default_factory=list)                # требуемые роли (или пусто для любых)
    min_device_trust: Literal["low", "medium", "high"] = "low"
    allowed_cidrs: List[str] = Field(default_factory=list)
    obligations: List[Obligation] = Field(default_factory=list)
    condition: Optional[Condition] = None                         # дополнительное условие

    def matches(self, ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        act: str = str(_get_path(ctx, "action.action") or "")
        path: str = str(_resource_path(ctx))
        subj_roles = {r.lower() for r in _get_path(ctx, "subject.roles") or []}
        # ReBAC: добавляем роли из relationships (owner, admin, editor...)
        rel_roles: List[str] = []
        rels = _get_path(ctx, "resource.relationships") or {}
        subj_id = _get_path(ctx, "subject.id")
        for rel, ids in rels.items():
            if subj_id in ids:
                rel_roles.append(rel.lower())
        if rel_roles:
            subj_roles |= set(rel_roles)

        # 1) действия и ресурс
        if not any(fnmatch.fnmatch(act, patt) for patt in self.actions):
            return False, {"reason": "action not matched"}
        if not any(fnmatch.fnmatch(path, patt) for patt in self.resources):
            return False, {"reason": "resource not matched", "resource": path}

        # 2) роли
        if self.roles:
            if not (set(r.lower() for r in self.roles) & subj_roles):
                return False, {"reason": "roles not satisfied", "have": sorted(list(subj_roles))}
        # 3) минимальный trust устройства
        trust_order = {"low": 0, "medium": 1, "high": 2}
        dev_trust: str = str(_get_path(ctx, "subject.attributes.device_trust") or "low")
        if trust_order.get(dev_trust, 0) < trust_order.get(self.min_device_trust, 0):
            return False, {"reason": "device trust too low", "required": self.min_device_trust, "got": dev_trust}
        # 4) CIDR
        client_ip: Optional[str] = _get_path(ctx, "environment.ip")
        if self.allowed_cidrs and not _cidr_match(client_ip, self.allowed_cidrs):
            return False, {"reason": "ip not in allowed_cidrs", "ip": client_ip}
        # 5) expr-условие
        if self.condition:
            ok, det = self.condition.evaluate(ctx)
            if not ok:
                return False, {"reason": "condition failed", "detail": det}
            return True, {"reason": "matched", "condition": det}
        return True, {"reason": "matched"}


class Policy(BaseModel):
    id: str
    description: Optional[str] = None
    version: str = "1.0.0"
    tenant: Optional[str] = None
    combining: CombiningAlg = "deny-overrides"
    target: Optional[Condition] = None
    expressions: Dict[str, Condition] = Field(default_factory=dict)  # именованные выражения
    rules: List[Rule] = Field(default_factory=list)
    decision_ttl_seconds: int = 300

    @validator("expressions", pre=True)
    def _coerce_exprs(cls, v):
        # разрешаем словарь python-типов -> в pydantic Condition
        if isinstance(v, dict):
            out: Dict[str, Condition] = {}
            for k, val in v.items():
                out[k] = _cond_from_dict(val)
            return out
        return v

    @validator("target", pre=True)
    def _coerce_target(cls, v):
        return _cond_from_dict(v) if isinstance(v, dict) else v

    @validator("rules", pre=True)
    def _coerce_rules(cls, v):
        if isinstance(v, list):
            return [Rule(**_expand_rule_dict(x)) if isinstance(x, dict) else x for x in v]
        return v


def _expand_rule_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    # разворачиваем condition/expressions
    dd = dict(d)
    if "condition" in dd and isinstance(dd["condition"], dict):
        dd["condition"] = _cond_from_dict(dd["condition"])
    if "obligations" in dd:
        dd["obligations"] = [Obligation(**o) if isinstance(o, dict) else o for o in dd["obligations"]]
    return dd


def _cond_from_dict(d: Optional[Dict[str, Any]]) -> Optional[Condition]:
    if not d:
        return None
    k = d.get("kind")
    if k == "any":
        return ConditionAny(items=[_cond_from_dict(x) for x in d.get("items", []) if x])
    if k == "all":
        return ConditionAll(items=[_cond_from_dict(x) for x in d.get("items", []) if x])
    if k == "expr":
        return ConditionExpr(**{kk: vv for kk, vv in d.items() if kk != "kind"})
    if k == "ref":
        return ConditionRef(name=d.get("name", ""))
    raise ValueError(f"Unknown condition kind: {k}")


# ============================== ПОЛИТИЧЕСКОЕ ХРАНИЛИЩЕ =======================

class PolicyError(Exception):
    pass


class PolicyStore:
    """
    Потокобезопасное in-memory хранилище с версионированием.
    Для продакшена может быть обёрнуто адаптером к внешнему реестру.
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._policies: Dict[str, Policy] = {}  # key=policy.id

    def upsert(self, policy: Policy) -> None:
        with self._lock:
            self._policies[policy.id] = policy

    def remove(self, policy_id: str) -> None:
        with self._lock:
            self._policies.pop(policy_id, None)

    def clear(self) -> None:
        with self._lock:
            self._policies.clear()

    def get(self, policy_id: str) -> Optional[Policy]:
        with self._lock:
            return self._policies.get(policy_id)

    def list(self, tenant: Optional[str] = None) -> List[Policy]:
        with self._lock:
            if tenant is None:
                return list(self._policies.values())
            return [p for p in self._policies.values() if p.tenant in (None, tenant)]

    # -------- загрузка/выгрузка --------

    def load_file(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        if path.endswith((".yaml", ".yml")):
            if not yaml:
                raise PolicyError("PyYAML not installed")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)

        # поддержка: один объект Policy или список
        items = data if isinstance(data, list) else [data]
        for obj in items:
            self.upsert(Policy(**obj))

    def dump_file(self, path: str, tenant: Optional[str] = None) -> None:
        items = [p.dict() for p in self.list(tenant)]
        if path.endswith((".yaml", ".yml")):
            if not yaml:
                raise PolicyError("PyYAML not installed")
            with open(path, "w", encoding="utf-8") as f:
                yaml.safe_dump(items, f, sort_keys=False, allow_unicode=True)
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(items, f, ensure_ascii=False, indent=2)


# =========================== КЭШ РЕШЕНИЙ (TTL + версия) ======================

@dataclass
class _CacheEntry:
    until: float
    policy_versions: Dict[str, str]
    decision: Decision


class _TTLDecisionCache:
    def __init__(self, maxsize: int = 10000) -> None:
        self._maxsize = maxsize
        self._lock = threading.RLock()
        self._data: Dict[str, _CacheEntry] = {}

    def _evict_if_needed(self) -> None:
        if len(self._data) <= self._maxsize:
            return
        # простая эвикция: удалить самые старые
        oldest_key = None
        oldest_t = float("inf")
        for k, v in self._data.items():
            if v.until < oldest_t:
                oldest_t = v.until
                oldest_key = k
        if oldest_key:
            self._data.pop(oldest_key, None)

    def get(self, key: str, current_versions: Dict[str, str]) -> Optional[Decision]:
        now = time.time()
        with self._lock:
            ce = self._data.get(key)
            if not ce:
                return None
            if now >= ce.until:
                self._data.pop(key, None)
                return None
            # инвалидация при смене версий политик
            if ce.policy_versions != current_versions:
                self._data.pop(key, None)
                return None
            return ce.decision

    def set(self, key: str, decision: Decision, ttl: int, current_versions: Dict[str, str]) -> None:
        with self._lock:
            self._data[key] = _CacheEntry(until=time.time() + max(1, ttl), policy_versions=current_versions, decision=decision)
            self._evict_if_needed()


# ================================ ENFORCER ===================================

def _resource_path(ctx: Dict[str, Any]) -> str:
    path = _get_path(ctx, "resource.path")
    if path:
        return str(path)
    rtype = _get_path(ctx, "resource.type") or "resource"
    rid = _get_path(ctx, "resource.id") or "*"
    return f"{rtype}:{rid}"


def _get_path(ctx: Dict[str, Any], path: str) -> Any:
    cur: Any = ctx
    for p in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _ctx_from_inputs(subject: Subject, resource: Resource, action: Action, environment: Environment, policy: Optional[Policy] = None) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "subject": json.loads(subject.json()),
        "resource": json.loads(resource.json()),
        "action": json.loads(action.json()),
        "environment": json.loads(environment.json()),
    }
    # выражения политики доступны через служебный ключ
    if policy:
        ctx["$expressions"] = policy.expressions
    return ctx


class Enforcer:
    """
    Policy Enforcement Point (PEP) + часть PDP.
    Выполняет таргетинг политики, матчит правила, применяет алгоритм комбинирования.
    """

    def __init__(self, store: PolicyStore, *, default_combining: CombiningAlg = "deny-overrides", enable_cache: bool = True) -> None:
        self.store = store
        self.default_combining = default_combining
        self.cache = _TTLDecisionCache() if enable_cache else None

    # ---------- публичный API ----------

    def decide(
        self,
        subject: Subject,
        resource: Resource,
        action: Action,
        environment: Environment,
        *,
        tenant: Optional[str] = None,
    ) -> Decision:
        """
        Синхронная оценка. Для ASGI-цепочек обычно достаточно.
        """
        return self._evaluate(subject, resource, action, environment, tenant=tenant)

    async def decide_async(
        self,
        subject: Subject,
        resource: Resource,
        action: Action,
        environment: Environment,
        *,
        tenant: Optional[str] = None,
    ) -> Decision:
        """
        Асинхронная обертка (на случай будущих внешних источников атрибутов).
        """
        return self._evaluate(subject, resource, action, environment, tenant=tenant)

    # ---------- внутренняя логика ----------

    def _evaluate(
        self,
        subject: Subject,
        resource: Resource,
        action: Action,
        environment: Environment,
        *,
        tenant: Optional[str],
    ) -> Decision:
        # Собираем список кандидатов
        tenant_key = tenant or subject.tenant
        policies = self.store.list(tenant_key)

        # Сформировать ключ кэша
        cache_key = None
        versions = {p.id: p.version for p in policies}
        if self.cache:
            cache_key = self._make_cache_key(subject, resource, action, environment, tenant_key)
            cached = self.cache.get(cache_key, versions)
            if cached:
                return cached

        # Инициализируем explain
        explains: List[ExplainEntry] = []

        # По сути — проходим политики в порядке загрузки; для честности можно сортировать по id
        outcome: Optional[Decision] = None

        for policy in policies:
            # 1) таргетинг политики
            ctx = _ctx_from_inputs(subject, resource, action, environment, policy)
            if policy.target:
                ok, det = policy.target.evaluate(ctx)
                explains.append(ExplainEntry(rule_id=f"{policy.id}::target", matched=ok, reason="policy-target", data=det))
                if not ok:
                    continue  # политика не применяется
            # 2) применение правил в рамках политики
            decision = self._evaluate_policy(policy, ctx)
            if decision is None:
                # ни одно правило не подошло — пропускаем
                continue

            decision.policy_id = policy.id
            decision.ttl_seconds = policy.decision_ttl_seconds
            outcome = self._combine(outcome, decision, policy.combining or self.default_combining)
            explains.extend(decision.explain)

            # first-applicable на уровне политики
            if policy.combining == "first-applicable":
                break

        # Если ничего не подошло — deny
        if outcome is None:
            outcome = Decision(outcome="deny", reason="no applicable policy", explain=explains)

        # Аудит
        _audit_decision(outcome, subject, resource, action, environment)

        # Кэширование
        if self.cache and cache_key and outcome.ttl_seconds:
            self.cache.set(cache_key, outcome, ttl=outcome.ttl_seconds, current_versions=versions)

        return outcome

    def _evaluate_policy(self, policy: Policy, ctx: Dict[str, Any]) -> Optional[Decision]:
        combining = policy.combining or self.default_combining
        # аккумулируем промежуточные решения
        current: Optional[Decision] = None

        for rule in policy.rules:
            matched, detail = rule.matches(ctx)
            explain = ExplainEntry(rule_id=rule.id, matched=matched, reason=("matched" if matched else "not-matched"), data=detail)
            if not matched:
                # копим только ошибки при режиме first-applicable? Мы сохраняем всё.
                if current is None:
                    current = Decision(outcome="deny", explain=[explain])  # нейтральная база
                else:
                    current.explain.append(explain)
                continue

            # Сформировать решение по правилу
            dec = Decision(
                outcome=rule.effect,
                rule_id=rule.id,
                obligations=list(rule.obligations),
                explain=[explain],
                reason="rule matched",
            )
            current = self._combine(current, dec, combining)

            if combining == "first-applicable":
                break

        return current

    @staticmethod
    def _combine(current: Optional[Decision], incoming: Decision, alg: CombiningAlg) -> Decision:
        if current is None:
            return incoming

        # deny-overrides: любое deny побеждает
        if alg == "deny-overrides":
            if current.outcome == "deny" or incoming.outcome == "deny":
                # объединяем explain и obligations, но deny приоритетен
                merged = Decision(
                    outcome="deny",
                    policy_id=incoming.policy_id or current.policy_id,
                    rule_id=incoming.rule_id if incoming.outcome == "deny" else current.rule_id,
                    obligations=(current.obligations if current.outcome == "deny" else []) + (incoming.obligations if incoming.outcome == "deny" else []),
                    explain=current.explain + incoming.explain,
                    reason="deny-overrides",
                    ttl_seconds=min(filter(None, [current.ttl_seconds, incoming.ttl_seconds])) if any([current.ttl_seconds, incoming.ttl_seconds]) else None,
                )
                return merged
            # оба permit — склеиваем
            return Decision(
                outcome="permit",
                policy_id=incoming.policy_id or current.policy_id,
                rule_id=incoming.rule_id or current.rule_id,
                obligations=current.obligations + incoming.obligations,
                explain=current.explain + incoming.explain,
                reason="both permit",
                ttl_seconds=min(filter(None, [current.ttl_seconds, incoming.ttl_seconds])) if any([current.ttl_seconds, incoming.ttl_seconds]) else None,
            )

        # permit-overrides: любое permit побеждает
        if alg == "permit-overrides":
            if current.outcome == "permit" or incoming.outcome == "permit":
                return Decision(
                    outcome="permit",
                    policy_id=incoming.policy_id or current.policy_id,
                    rule_id=incoming.rule_id if incoming.outcome == "permit" else current.rule_id,
                    obligations=(current.obligations if current.outcome == "permit" else []) + (incoming.obligations if incoming.outcome == "permit" else []),
                    explain=current.explain + incoming.explain,
                    reason="permit-overrides",
                    ttl_seconds=min(filter(None, [current.ttl_seconds, incoming.ttl_seconds])) if any([current.ttl_seconds, incoming.ttl_seconds]) else None,
                )
            return Decision(
                outcome="deny",
                policy_id=incoming.policy_id or current.policy_id,
                rule_id=incoming.rule_id or current.rule_id,
                obligations=current.obligations + incoming.obligations,
                explain=current.explain + incoming.explain,
                reason="both deny",
                ttl_seconds=min(filter(None, [current.ttl_seconds, incoming.ttl_seconds])) if any([current.ttl_seconds, incoming.ttl_seconds]) else None,
            )

        # first-applicable: берём первое решение, просто мёржим explain
        return Decision(
            outcome=incoming.outcome if current.outcome == "deny" else current.outcome,
            policy_id=incoming.policy_id or current.policy_id,
            rule_id=incoming.rule_id or current.rule_id,
            obligations=current.obligations + incoming.obligations,
            explain=current.explain + incoming.explain,
            reason="first-applicable",
            ttl_seconds=min(filter(None, [current.ttl_seconds, incoming.ttl_seconds])) if any([current.ttl_seconds, incoming.ttl_seconds]) else None,
        )

    @staticmethod
    def _make_cache_key(subject: Subject, resource: Resource, action: Action, environment: Environment, tenant: Optional[str]) -> str:
        # ключ кэша чувствителен к основным атрибутам; не кладём большие структуры
        base = {
            "t": tenant,
            "sid": subject.id,
            "roles": sorted([r.lower() for r in subject.roles]),
            "rid": resource.id,
            "rtype": resource.type,
            "rpath": resource.path,
            "act": action.action,
            "scopes": sorted(action.scopes),
            "ip": environment.ip,
            "country": environment.country,
            "atr": sorted(environment.attributes.keys())[:16],  # не утяжеляем ключ
        }
        return json.dumps(base, sort_keys=True, separators=(",", ":"))


# ================================ АУДИТ ======================================

def _audit_decision(decision: Decision, subject: Subject, resource: Resource, action: Action, environment: Environment) -> None:
    try:
        record = {
            "event": "policy_decision",
            "ts": int(time.time()),
            "outcome": decision.outcome,
            "policy_id": decision.policy_id,
            "rule_id": decision.rule_id,
            "subject": {"id": subject.id, "tenant": subject.tenant, "roles": subject.roles},
            "resource": {"id": resource.id, "type": resource.type, "path": resource.path},
            "action": action.action,
            "env": {"ip": environment.ip, "country": environment.country},
            "obligations": [o.dict() for o in decision.obligations],
            "reason": decision.reason,
            "explain": [e.dict() for e in decision.explain][:50],  # ограничим объём
        }
        logger.info(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    except Exception:  # pragma: no cover
        logger.exception("Failed to audit policy decision")
