# file: security-core/security/authz/abac.py
from __future__ import annotations

import ast
import base64
import fnmatch
import ipaddress
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel, Field, validator

# =============================================================================
# Логирование
# =============================================================================

logger = logging.getLogger("security_core.authz.abac")

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None

def _redact(v: Optional[str]) -> str:
    if not v:
        return ""
    if len(v) <= 8:
        return "****"
    return v[:4] + "…" + v[-3:]

# =============================================================================
# Ошибки/результаты
# =============================================================================

class AuthzError(Exception): ...
class PolicyNotFound(AuthzError): ...
class AttributeResolutionError(AuthzError): ...
class ConditionCompileError(AuthzError): ...
class ConditionEvalError(AuthzError): ...

class Effect(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"

class Decision(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INDETERMINATE = "INDETERMINATE"

class CombiningAlg(str, Enum):
    DENY_OVERRIDES = "DENY_OVERRIDES"
    PERMIT_OVERRIDES = "PERMIT_OVERRIDES"
    FIRST_APPLICABLE = "FIRST_APPLICABLE"

# =============================================================================
# Атрибуты запроса
# =============================================================================

AttributeBag = Dict[str, Any]

@dataclass
class AccessRequest:
    subject: AttributeBag
    resource: AttributeBag
    action: AttributeBag
    environment: AttributeBag
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

# =============================================================================
# Компилятор безопасных условий (ограниченный AST)
# =============================================================================

class _SafeNodeVisitor(ast.NodeVisitor):
    """Проверяет, что выражение использует только безопасные конструкции."""
    ALLOWED_NODES = {
        ast.Module, ast.Expr, ast.Load,
        ast.BoolOp, ast.And, ast.Or, ast.Not,
        ast.UnaryOp, ast.USub, ast.UAdd, ast.Not,
        ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.FloorDiv,
        ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Is, ast.IsNot,
        ast.Call, ast.keyword,
        ast.IfExp,
        ast.Dict, ast.List, ast.Tuple, ast.Set,
        ast.Constant, ast.Name,
        ast.Subscript, ast.Slice, ast.Index, ast.Attribute,
    }
    ALLOWED_NAMES = {
        # Контекстные переменные
        "s", "r", "a", "e",
        # Функции-helpers
        "len", "int", "float", "str", "bool",
        "contains", "starts_with", "ends_with", "regex_match",
        "has_any", "has_all", "ip_in_cidr",
        "now", "hour_in", "weekday_in", "date_between",
        "get", "exists",
    }

    def visit(self, node):
        if type(node) not in self.ALLOWED_NODES:
            raise ConditionCompileError(f"Disallowed AST node: {type(node).__name__}")
        return super().visit(node)

    def visit_Name(self, node: ast.Name):
        if node.id not in self.ALLOWED_NAMES:
            raise ConditionCompileError(f"Disallowed name: {node.id}")

def _safe_env(bags: Dict[str, AttributeBag]) -> Dict[str, Any]:
    """Предоставляет безопасные функции для условий."""
    def contains(container, item) -> bool:
        try:
            return item in container
        except Exception:
            return False

    def starts_with(sv: str, prefix: str) -> bool:
        return isinstance(sv, str) and sv.startswith(prefix)

    def ends_with(sv: str, suffix: str) -> bool:
        return isinstance(sv, str) and sv.endswith(suffix)

    def regex_match(pattern: str, sv: str, flags: str = "") -> bool:
        fl = 0
        if "i" in flags: fl |= re.IGNORECASE
        return isinstance(sv, str) and re.search(pattern, sv, fl) is not None

    def has_any(container: Iterable[Any], items: Iterable[Any]) -> bool:
        try:
            s = set(container)
            return any(i in s for i in items)
        except Exception:
            return False

    def has_all(container: Iterable[Any], items: Iterable[Any]) -> bool:
        try:
            s = set(container)
            return all(i in s for i in items)
        except Exception:
            return False

    def ip_in_cidr(ip: str, cidrs: Iterable[str]) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for c in cidrs:
                if ip_obj in ipaddress.ip_network(c, strict=False):
                    return True
            return False
        except Exception:
            return False

    def now() -> datetime:
        return _now_utc()

    def hour_in(hours: Iterable[int]) -> bool:
        return _now_utc().hour in set(int(h) for h in hours)

    def weekday_in(days: Iterable[int]) -> bool:
        # 0=Monday..6=Sunday
        return _now_utc().weekday() in set(int(d) for d in days)

    def date_between(start_iso: str, end_iso: str) -> bool:
        try:
            s = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
            e = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
            n = _now_utc()
            return s <= n <= e
        except Exception:
            return False

    def get(obj: Any, *path, default=None):
        cur = obj
        try:
            for p in path:
                if isinstance(cur, dict):
                    cur = cur.get(p)
                elif hasattr(cur, p):
                    cur = getattr(cur, p)
                else:
                    return default
            return cur if cur is not None else default
        except Exception:
            return default

    def exists(obj: Any, *path) -> bool:
        return get(obj, *path, default=None) is not None

    return {
        "s": bags["subject"],
        "r": bags["resource"],
        "a": bags["action"],
        "e": bags["environment"],
        "len": len, "int": int, "float": float, "str": str, "bool": bool,
        "contains": contains, "starts_with": starts_with, "ends_with": ends_with, "regex_match": regex_match,
        "has_any": has_any, "has_all": has_all, "ip_in_cidr": ip_in_cidr,
        "now": now, "hour_in": hour_in, "weekday_in": weekday_in, "date_between": date_between,
        "get": get, "exists": exists,
    }

def compile_condition(expr: Optional[str]) -> Callable[[Dict[str, AttributeBag]], bool]:
    """Компилирует текст условия в безопасную предикат‑функцию."""
    if not expr or not expr.strip():
        return lambda bags: True
    parsed = ast.parse(expr, mode="eval")
    _SafeNodeVisitor().visit(parsed)

    code = compile(parsed, filename="<abac-condition>", mode="eval")

    def predicate(bags: Dict[str, AttributeBag]) -> bool:
        try:
            env = _safe_env(bags)
            return bool(eval(code, {"__builtins__": {}}, env))
        except Exception as e:
            raise ConditionEvalError(str(e)) from e

    return predicate

# =============================================================================
# Таргеты (target-matchers) и правила/политики
# =============================================================================

SUPPORTED_OPERATORS = {"eq","ne","in","any","all","regex","prefix","suffix","cidr","exists"}

def _match_value(op: str, left: Any, right: Any) -> bool:
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op == "in":
        try:
            return left in right
        except Exception:
            return False
    if op == "any":
        try:
            return any(item in (left or []) for item in (right or []))
        except Exception:
            return False
    if op == "all":
        try:
            s = set(left or [])
            return all(item in s for item in (right or []))
        except Exception:
            return False
    if op == "regex":
        if not isinstance(left, str):
            return False
        pat = right if isinstance(right, str) else str(right)
        return re.search(pat, left) is not None
    if op == "prefix":
        return isinstance(left, str) and isinstance(right, str) and left.startswith(right)
    if op == "suffix":
        return isinstance(left, str) and isinstance(right, str) and left.endswith(right)
    if op == "cidr":
        # right может быть строкой или списком подсетей
        nets = right if isinstance(right, (list, tuple, set)) else [right]
        try:
            ip_obj = ipaddress.ip_address(left)
            for net in nets:
                if ip_obj in ipaddress.ip_network(net, strict=False):
                    return True
            return False
        except Exception:
            return False
    if op == "exists":
        return (left is not None) is bool(right) if isinstance(right, bool) else (left is not None)
    return False

def _get_path(bag: AttributeBag, path: str) -> Any:
    cur: Any = bag
    for p in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur

def _match_target(target: Dict[str, Any], req: AccessRequest) -> bool:
    """
    target пример:
    {
      "subject": {"roles": {"any": ["admin","manager"]}, "tenant_id": {"eq": "t1"}},
      "resource": {"type": {"in": ["doc","file"]}, "owner_id": {"eq": "$subject.id"}},
      "action": {"name": {"eq": "read"}},
      "environment": {"ip": {"cidr": ["10.0.0.0/8","192.168.0.0/16"]}}
    }
    """
    bags = {
        "subject": req.subject, "resource": req.resource, "action": req.action, "environment": req.environment
    }

    def resolve_rhs(val: Any) -> Any:
        # Подстановка ссылок вида "$subject.id"
        if isinstance(val, str) and val.startswith("$"):
            try:
                bag, path = val[1:].split(".", 1)
                return _get_path(bags[bag], path)
            except Exception:
                return None
        return val

    for bag_name, fields in (target or {}).items():
        bag = bags.get(bag_name, {})
        for path, ops in (fields or {}).items():
            left = _get_path(bag, path)
            if isinstance(ops, dict):
                # набор операторов
                for op, right in ops.items():
                    if op not in SUPPORTED_OPERATORS:
                        return False
                    r = resolve_rhs(right)
                    if not _match_value(op, left, r):
                        return False
            else:
                # сокращенная форма: равенство
                if left != resolve_rhs(ops):
                    return False
    return True

class Obligation(BaseModel):
    id: str
    data: Dict[str, Any] = Field(default_factory=dict)

class Advice(BaseModel):
    id: str
    data: Dict[str, Any] = Field(default_factory=dict)

class Rule(BaseModel):
    id: str
    effect: Effect
    condition: Optional[str] = None  # безопасное выражение
    description: Optional[str] = None

    # Компилированный предикат (инициализируется при компиляции политики)
    _compiled: Optional[Callable[[Dict[str, AttributeBag]], bool]] = Field(default=None, repr=False)

    def compile(self) -> None:
        self._compiled = compile_condition(self.condition)

    def evaluate(self, req: AccessRequest) -> Tuple[Decision, Optional[str]]:
        if self._compiled is None:
            self.compile()
        bags = {
            "subject": req.subject, "resource": req.resource, "action": req.action, "environment": req.environment
        }
        try:
            ok = bool(self._compiled(bags))
        except ConditionEvalError as e:
            return Decision.INDETERMINATE, f"condition_error:{e}"
        if ok:
            return (Decision.PERMIT if self.effect == Effect.PERMIT else Decision.DENY), None
        return Decision.NOT_APPLICABLE, None

class Policy(BaseModel):
    id: str
    version: int = 1
    algorithm: CombiningAlg = CombiningAlg.DENY_OVERRIDES
    target: Dict[str, Any] = Field(default_factory=dict)
    rules: List[Rule] = Field(default_factory=list)
    obligations_on_permit: List[Obligation] = Field(default_factory=list)
    obligations_on_deny: List[Obligation] = Field(default_factory=list)
    advice: List[Advice] = Field(default_factory=list)
    description: Optional[str] = None
    etag: Optional[str] = None

    @validator("rules")
    def _non_empty_rules(cls, v):
        if not isinstance(v, list):
            raise ValueError("rules must be list")
        return v

    def compile(self) -> None:
        for r in self.rules:
            r.compile()

    def compute_etag(self) -> str:
        raw = f"{self.id}:{self.version}:{len(self.rules)}:{self.algorithm.value}"
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

# =============================================================================
# PolicyStore In-Memory (можно заменить на БД/Registry)
# =============================================================================

class PolicyStore:
    """Минимальный in-memory store с ETag и thread‑safety."""
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_key: Dict[Tuple[Optional[str], str], Policy] = {}

    def put(self, policy: Policy, tenant_id: Optional[str] = None) -> Policy:
        with self._lock:
            policy.etag = policy.compute_etag()
            policy.compile()
            self._by_key[(tenant_id, policy.id)] = policy
            return policy

    def get(self, policy_id: str, tenant_id: Optional[str] = None) -> Policy:
        with self._lock:
            p = self._by_key.get((tenant_id, policy_id))
            if not p:
                raise PolicyNotFound(f"policy '{policy_id}' not found")
            return p

    def delete(self, policy_id: str, tenant_id: Optional[str] = None) -> None:
        with self._lock:
            self._by_key.pop((tenant_id, policy_id), None)

    def list_ids(self, tenant_id: Optional[str] = None) -> List[str]:
        with self._lock:
            return [pid for (t, pid), _ in self._by_key.items() if t == tenant_id]

# =============================================================================
# Attribute Resolvers (PIP)
# =============================================================================

class AttributeResolver:
    """Интерфейс загрузки атрибутов (например, роли, теги ресурса, гео и т. п.)."""
    def resolve(self, req: AccessRequest) -> None:
        """Должен модифицировать req.subject/resource/action/environment на месте при необходимости."""
        raise NotImplementedError

class CompositeResolver(AttributeResolver):
    def __init__(self, resolvers: List[AttributeResolver]) -> None:
        self.resolvers = resolvers

    def resolve(self, req: AccessRequest) -> None:
        for r in self.resolvers:
            r.resolve(req)

class StaticResolver(AttributeResolver):
    """Простейший резолвер, мержит статический словарь в соответствующие бэги."""
    def __init__(self, subject: dict | None = None, resource: dict | None = None,
                 action: dict | None = None, environment: dict | None = None) -> None:
        self._bags = {"subject": subject or {}, "resource": resource or {}, "action": action or {}, "environment": environment or {}}

    def resolve(self, req: AccessRequest) -> None:
        req.subject.update(self._bags["subject"])
        req.resource.update(self._bags["resource"])
        req.action.update(self._bags["action"])
        req.environment.update(self._bags["environment"])

# =============================================================================
# PDP (Policy Decision Point)
# =============================================================================

@dataclass
class RuleTrace:
    rule_id: str
    decision: Decision
    note: Optional[str] = None

@dataclass
class PolicyTrace:
    policy_id: str
    target_matched: bool
    algorithm: CombiningAlg
    rule_traces: List[RuleTrace] = field(default_factory=list)
    result: Decision = Decision.NOT_APPLICABLE

@dataclass
class DecisionResponse:
    decision: Decision
    obligations: List[Obligation] = field(default_factory=list)
    advice: List[Advice] = field(default_factory=list)
    used_policies: List[str] = field(default_factory=list)
    trace: List[PolicyTrace] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: _iso(_now_utc()) or "")

class PDP:
    def __init__(self, store: PolicyStore, resolver: Optional[AttributeResolver] = None) -> None:
        self.store = store
        self.resolver = resolver or CompositeResolver([])
        self._lock = threading.RLock()

    # Алгоритмы комбинирования

    def _combine(self, policy: Policy, req: AccessRequest, trace: Optional[PolicyTrace]) -> Tuple[Decision, List[Obligation]]:
        obligations: List[Obligation] = []
        algo = policy.algorithm

        # Быстрая проверка таргета
        tgt = _match_target(policy.target, req)
        if trace:
            trace.target_matched = tgt
        if not tgt:
            return Decision.NOT_APPLICABLE, obligations

        first_applicable_decision: Optional[Decision] = None

        for rule in policy.rules:
            d, note = rule.evaluate(req)
            if trace:
                trace.rule_traces.append(RuleTrace(rule_id=rule.id, decision=d, note=note))
            if d == Decision.INDETERMINATE:
                # В Deny-overrides INDETERMINATE трактуем как потенциальный deny‑impact
                if algo == CombiningAlg.DENY_OVERRIDES:
                    return Decision.DENY, policy.obligations_on_deny
                if algo == CombiningAlg.FIRST_APPLICABLE and first_applicable_decision is None:
                    first_applicable_decision = Decision.INDETERMINATE
                continue
            if d == Decision.DENY:
                if algo in (CombiningAlg.DENY_OVERRIDES, CombiningAlg.FIRST_APPLICABLE):
                    return Decision.DENY, policy.obligations_on_deny
                # PERMIT_OVERRIDES — продолжаем в поиске PERMIT
            if d == Decision.PERMIT:
                if algo in (CombiningAlg.PERMIT_OVERRIDES, CombiningAlg.FIRST_APPLICABLE):
                    return Decision.PERMIT, policy.obligations_on_permit
                obligations = policy.obligations_on_permit  # запомним, если не будет deny
                # DENY_OVERRIDES — продолжаем, чтобы поймать возможный deny

        # Если FIRST_APPLICABLE, но ничего явного — NotApplicable
        if algo == CombiningAlg.FIRST_APPLICABLE:
            if first_applicable_decision is not None and first_applicable_decision != Decision.NOT_APPLICABLE:
                return first_applicable_decision, obligations
            return Decision.NOT_APPLICABLE, []

        # Для DENY_OVERRIDES если был permit без deny — permit; иначе not applicable
        if algo == CombiningAlg.DENY_OVERRIDES:
            return (Decision.PERMIT, obligations) if obligations else (Decision.NOT_APPLICABLE, [])

        # Для PERMIT_OVERRIDES если не нашли permit — not applicable
        if algo == CombiningAlg.PERMIT_OVERRIDES:
            return (Decision.PERMIT, obligations) if obligations else (Decision.NOT_APPLICABLE, [])

        return Decision.NOT_APPLICABLE, []

    # Публичная оценка

    def evaluate(self, req: AccessRequest, policy_ids: List[str], tenant_id: Optional[str] = None, with_trace: bool = False) -> DecisionResponse:
        # Разрешим атрибуты через PIP
        try:
            self.resolver.resolve(req)
        except Exception as e:
            raise AttributeResolutionError(str(e)) from e

        traces: List[PolicyTrace] = []
        used: List[str] = []
        final = Decision.NOT_APPLICABLE
        collected_obl: List[Obligation] = []
        collected_advice: List[Advice] = []

        # Глобально применим Deny‑overrides поверх множества политик: если хоть одна политика даёт DENY — deny.
        # Это типичный безопасный дефолт. Можно адаптировать под нужды (например, первичная политика из списка управляет алгоритмом).
        deny_seen = False
        permit_seen = False

        for pid in policy_ids:
            policy = self.store.get(pid, tenant_id)
            used.append(pid)
            tr = PolicyTrace(policy_id=pid, target_matched=False, algorithm=policy.algorithm) if with_trace else None
            d, obls = self._combine(policy, req, tr)
            if with_trace and tr is not None:
                tr.result = d
                traces.append(tr)
            if d == Decision.DENY:
                deny_seen = True
                collected_obl = obls
                collected_advice.extend(policy.advice)
            elif d == Decision.PERMIT:
                permit_seen = True
                # аккумулируем обязательства и советы разрешающих политик
                collected_obl.extend(obls)
                collected_advice.extend(policy.advice)

        if deny_seen:
            final = Decision.DENY
        elif permit_seen:
            final = Decision.PERMIT
        else:
            final = Decision.NOT_APPLICABLE

        return DecisionResponse(
            decision=final,
            obligations=collected_obl,
            advice=collected_advice,
            used_policies=used,
            trace=traces if with_trace else [],
        )

# =============================================================================
# Пример DEV‑инициализации и базовая политика
# =============================================================================

def dev_policy_store() -> PolicyStore:
    store = PolicyStore()

    # Базовая политика: владельцы ресурсов и админы могут читать/обновлять в рабочее время; остальные — deny
    policy = Policy(
        id="base.document.access",
        version=1,
        algorithm=CombiningAlg.DENY_OVERRIDES,
        target={
            "resource": {"type": {"eq": "document"}}
        },
        rules=[
            # Администратор всегда может
            Rule(
                id="r1_admin_permit",
                effect=Effect.PERMIT,
                condition='has_any(get(s, "roles", default=[]), ["admin","superadmin"])'
            ),
            # Владелец может читать/обновлять
            Rule(
                id="r2_owner_permit",
                effect=Effect.PERMIT,
                condition='get(r,"owner_id")==get(s,"id") and get(a,"name") in ["read","update"]'
            ),
            # Разрешить read из приватной сети в рабочие часы
            Rule(
                id="r3_corp_hours_permit",
                effect=Effect.PERMIT,
                condition='a.get("name")=="read" and ip_in_cidr(get(e,"ip"), ["10.0.0.0/8","192.168.0.0/16"]) and hour_in(range(8,20)) and weekday_in(range(0,5))'
            ),
            # Явный deny на delete, если не админ
            Rule(
                id="r4_delete_deny",
                effect=Effect.DENY,
                condition='a.get("name")=="delete" and not has_any(get(s,"roles", []), ["admin","superadmin"])'
            ),
        ],
        obligations_on_permit=[Obligation(id="audit.permit", data={"severity": "info"})],
        obligations_on_deny=[Obligation(id="audit.deny", data={"severity": "warn"})],
        advice=[Advice(id="notify", data={"channel": "sec-ops"})],
        description="Base document access policy",
    )
    store.put(policy)

    return store

# =============================================================================
# Пример простого AttributeResolver (добавит ip из окружения, если отсутствует)
# =============================================================================

class RequestIpResolver(AttributeResolver):
    def resolve(self, req: AccessRequest) -> None:
        # если ip не задан, подставим loopback для DEV
        req.environment.setdefault("ip", req.environment.get("ip") or "127.0.0.1")

# =============================================================================
# Пример использования
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    store = dev_policy_store()
    pdp = PDP(store=store, resolver=CompositeResolver([RequestIpResolver()]))

    req = AccessRequest(
        subject={"id":"u1", "roles":["user"]},
        resource={"id":"doc1", "type":"document", "owner_id":"u1"},
        action={"name":"read"},
        environment={"ip":"10.12.0.5"}
    )

    res = pdp.evaluate(req, policy_ids=["base.document.access"], with_trace=True)
    print("decision:", res.decision, "obligations:", [o.id for o in res.obligations])
    for pt in res.trace:
        print(f"policy={pt.policy_id} target={pt.target_matched} alg={pt.algorithm} result={pt.result}")
        for rt in pt.rule_traces:
            print("  rule", rt.rule_id, "->", rt.decision, rt.note or "")
