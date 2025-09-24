# omnimind-core/omnimind/security/abac.py
from __future__ import annotations

import dataclasses
import fnmatch
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

LOG = logging.getLogger("omnimind.security.abac")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO)


# ==========================
# Модель атрибутов и запроса
# ==========================

class AttrView:
    """
    Безопасный доступ к атрибутам с поддержкой "точечной" адресации: subject.id, resource.owner.id и т.д.
    """

    __slots__ = ("_data",)

    def __init__(self, data: Optional[Mapping[str, Any]] = None) -> None:
        self._data = dict(data or {})

    def get(self, path: str, default: Any = None) -> Any:
        if not path:
            return default
        cur: Any = self._data
        for part in path.split("."):
            if isinstance(cur, Mapping) and part in cur:
                cur = cur[part]
            elif isinstance(cur, (list, tuple)):
                try:
                    idx = int(part)
                    cur = cur[idx]
                except Exception:
                    return default
            else:
                return default
        return cur

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._data)


@dataclass(slots=True)
class Request:
    subject: AttrView = field(default_factory=AttrView)
    resource: AttrView = field(default_factory=AttrView)
    action: AttrView = field(default_factory=AttrView)
    environment: AttrView = field(default_factory=AttrView)  # время, ip, geo и др.

    def attr(self, dotted: str, default: Any = None) -> Any:
        """
        Быстрый доступ к любому атрибуту по префиксу: subject.*, resource.*, action.*, environment.*
        """
        if not dotted or "." not in dotted:
            return default
        head, rest = dotted.split(".", 1)
        if head == "subject":
            return self.subject.get(rest, default)
        if head == "resource":
            return self.resource.get(rest, default)
        if head == "action":
            return self.action.get(rest, default)
        if head == "environment":
            return self.environment.get(rest, default)
        return default


# ==========================
# Решение, эффекты и ответ
# ==========================

class Decision(str, Enum):
    PERMIT = "Permit"
    DENY = "Deny"
    NOT_APPLICABLE = "NotApplicable"
    INDETERMINATE = "Indeterminate"


class Effect(str, Enum):
    PERMIT = "permit"
    DENY = "deny"


@dataclass(slots=True)
class Obligation:
    key: str
    value: Any


@dataclass(slots=True)
class Advice:
    key: str
    value: Any


@dataclass(slots=True)
class DecisionResult:
    decision: Decision
    obligations: List[Obligation] = field(default_factory=list)
    advice: List[Advice] = field(default_factory=list)
    used_policies: List[str] = field(default_factory=list)
    trace: List[str] = field(default_factory=list)
    metrics: Dict[str, float] = field(default_factory=dict)


# ==========================
# Мини-DSL выражений (без eval)
# ==========================

# Операторы: eq, ne, gt, ge, lt, le, in, contains, startswith, endswith, regex, subset, intersects, glob
# Логика: all, any, not
# Операнды: {"attr": "subject.id"}, {"value": 123}, {"set": [..]}
Operand = Dict[str, Any]
Expr = Dict[str, Any]

def _op_value(req: Request, operand: Any) -> Any:
    if isinstance(operand, Mapping):
        if "attr" in operand:
            return req.attr(str(operand["attr"]))
        if "value" in operand:
            return operand["value"]
        if "set" in operand:
            return list(operand["set"])
    return operand


def _ensure_iter(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, (list, tuple, set)):
        return list(x)
    return [x]


def _cmp_eq(a: Any, b: Any) -> bool:
    return a == b


def _cmp_ne(a: Any, b: Any) -> bool:
    return a != b


def _cmp_gt(a: Any, b: Any) -> bool:
    try:
        return a > b
    except Exception:
        return False


def _cmp_ge(a: Any, b: Any) -> bool:
    try:
        return a >= b
    except Exception:
        return False


def _cmp_lt(a: Any, b: Any) -> bool:
    try:
        return a < b
    except Exception:
        return False


def _cmp_le(a: Any, b: Any) -> bool:
    try:
        return a <= b
    except Exception:
        return False


def _op_in(a: Any, b: Any) -> bool:
    try:
        return a in b
    except Exception:
        return False


def _op_contains(a: Any, b: Any) -> bool:
    try:
        return b in a
    except Exception:
        return False


def _op_startswith(a: Any, b: Any) -> bool:
    try:
        return str(a).startswith(str(b))
    except Exception:
        return False


def _op_endswith(a: Any, b: Any) -> bool:
    try:
        return str(a).endswith(str(b))
    except Exception:
        return False


def _op_regex(a: Any, pattern: Any) -> bool:
    try:
        return re.search(str(pattern), str(a)) is not None
    except re.error:
        return False


def _op_subset(a: Any, b: Any) -> bool:
    try:
        return set(_ensure_iter(a)).issubset(set(_ensure_iter(b)))
    except Exception:
        return False


def _op_intersects(a: Any, b: Any) -> bool:
    try:
        return len(set(_ensure_iter(a)).intersection(set(_ensure_iter(b)))) > 0
    except Exception:
        return False


def _op_glob(a: Any, pattern: Any) -> bool:
    try:
        return fnmatch.fnmatch(str(a), str(pattern))
    except Exception:
        return False


# Карта бинарных операторов
_BIN_OPS: Dict[str, Callable[[Any, Any], bool]] = {
    "eq": _cmp_eq,
    "ne": _cmp_ne,
    "gt": _cmp_gt,
    "ge": _cmp_ge,
    "lt": _cmp_lt,
    "le": _cmp_le,
    "in": _op_in,
    "contains": _op_contains,
    "startswith": _op_startswith,
    "endswith": _op_endswith,
    "regex": _op_regex,
    "subset": _op_subset,
    "intersects": _op_intersects,
    "glob": _op_glob,
}


class Condition:
    """
    Компилируемое условие из Expr.
    Пример:
    {
      "all": [
        {"op": "eq", "left": {"attr":"action.name"}, "right": {"value": "read"}},
        {"op": "eq", "left": {"attr":"subject.id"}, "right": {"attr":"resource.owner_id"}}
      ]
    }
    """

    __slots__ = ("_expr", "_compiled", "_lock")

    def __init__(self, expr: Optional[Expr]) -> None:
        self._expr = expr or {"value": True}
        self._compiled: Callable[[Request], bool]
        self._lock = threading.Lock()
        self._compiled = self._compile(self._expr)

    def evaluate(self, req: Request) -> bool:
        return self._compiled(req)

    # --- компиляция в Python-замыкание без eval ---
    def _compile(self, expr: Any) -> Callable[[Request], bool]:
        if isinstance(expr, Mapping):
            if "all" in expr:
                subs = [self._compile(e) for e in _ensure_iter(expr["all"])]
                return lambda r: all(f(r) for f in subs)
            if "any" in expr:
                subs = [self._compile(e) for e in _ensure_iter(expr["any"])]
                return lambda r: any(f(r) for f in subs)
            if "not" in expr:
                sub = self._compile(expr["not"])
                return lambda r: not sub(r)
            if "op" in expr:
                op = str(expr["op"]).lower()
                left = expr.get("left")
                right = expr.get("right")
                fn = _BIN_OPS.get(op)
                if not fn:
                    # неизвестный оператор => false
                    return lambda r: False

                def _f(r: Request, L=left, R=right, FN=fn) -> bool:
                    a = _op_value(r, L)
                    b = _op_value(r, R)
                    return FN(a, b)

                return _f

            if "value" in expr:
                val = bool(expr["value"])
                return lambda r: val

            # пустой/неизвестный словарь — false
            return lambda r: False

        # литералы
        return lambda r, v=bool(expr): v


# ==========================
# Политики и наборы
# ==========================

@dataclass(slots=True)
class Policy:
    """
    Политика с target (быстрая фильтрация по действию/ресурсу и т.п.) и condition (основные правила).
    """
    id: str
    effect: Effect
    target: Optional[Condition] = None
    condition: Optional[Condition] = None
    obligations: List[Obligation] = field(default_factory=list)
    advice: List[Advice] = field(default_factory=list)
    priority: int = 0  # выше — раньше
    enabled: bool = True
    description: str = ""

    def matches(self, req: Request) -> bool:
        if not self.enabled:
            return False
        if self.target and not self.target.evaluate(req):
            return False
        return True

    def evaluate(self, req: Request) -> Optional[Decision]:
        if not self.matches(req):
            return None
        cond_ok = True
        if self.condition:
            cond_ok = bool(self.condition.evaluate(req))
        if cond_ok and self.effect == Effect.PERMIT:
            return Decision.PERMIT
        if (not cond_ok) and self.effect == Effect.DENY:
            return Decision.DENY
        # При несовпадении условия с эффектом — NotApplicable
        return Decision.NOT_APPLICABLE


class CombiningAlg(str, Enum):
    DENY_OVERRIDES = "deny_overrides"
    PERMIT_OVERRIDES = "permit_overrides"
    FIRST_APPLICABLE = "first_applicable"


@dataclass(slots=True)
class PolicySet:
    id: str
    policies: List[Policy] = field(default_factory=list)
    algorithm: CombiningAlg = CombiningAlg.DENY_OVERRIDES
    description: str = ""

    def sorted_policies(self) -> List[Policy]:
        # по убыванию приоритета, затем по id — детерминированность
        return sorted([p for p in self.policies if p.enabled], key=lambda p: (-p.priority, p.id))


# ==========================
# PDP (Policy Decision Point)
# ==========================

@dataclass(slots=True)
class PDP:
    policy_sets: List[PolicySet]
    metrics_enabled: bool = True

    def decide(self, req: Request) -> DecisionResult:
        t0 = time.perf_counter()
        trace: List[str] = []
        used: List[str] = []
        result = Decision.NOT_APPLICABLE
        obligations: List[Obligation] = []
        advice: List[Advice] = []

        for pset in self.policy_sets:
            trace.append(f"set:{pset.id}:{pset.algorithm}")
            decision, obs, adv, used_ids = self._evaluate_set(pset, req, trace)
            used.extend(used_ids)
            obligations.extend(obs)
            advice.extend(adv)

            # Комбинируем по результату набора (в XACML можно сложнее; здесь набор просто генерирует локальное решение)
            if decision == Decision.DENY:
                result = Decision.DENY
                if pset.algorithm == CombiningAlg.DENY_OVERRIDES:
                    break
            elif decision == Decision.PERMIT:
                # при permit мы не обнуляем deny из предыдущих set'ов — семантика упрощена до "первый значимый wins"
                if result != Decision.DENY:
                    result = Decision.PERMIT
                if pset.algorithm == CombiningAlg.PERMIT_OVERRIDES:
                    break
            elif decision in (Decision.NOT_APPLICABLE, Decision.INDETERMINATE):
                # продолжаем
                pass

        metrics = {}
        if self.metrics_enabled:
            metrics["eval_ms"] = (time.perf_counter() - t0) * 1000.0
        return DecisionResult(
            decision=result,
            obligations=obligations,
            advice=advice,
            used_policies=used,
            trace=trace,
            metrics=metrics,
        )

    def _evaluate_set(
        self, pset: PolicySet, req: Request, trace: List[str]
    ) -> Tuple[Decision, List[Obligation], List[Advice], List[str]]:
        obligations: List[Obligation] = []
        advice: List[Advice] = []
        used: List[str] = []
        local_decision: Decision = Decision.NOT_APPLICABLE

        for pol in pset.sorted_policies():
            try:
                # Быстрая проверка target
                if not pol.matches(req):
                    trace.append(f"skip:{pol.id}:target_miss")
                    continue

                used.append(pol.id)
                dec = pol.evaluate(req)
                trace.append(f"hit:{pol.id}:{dec}")

                if dec == Decision.DENY:
                    if pset.algorithm == CombiningAlg.DENY_OVERRIDES:
                        return Decision.DENY, obligations, advice, used
                    local_decision = Decision.DENY
                elif dec == Decision.PERMIT:
                    obligations.extend(pol.obligations)
                    advice.extend(pol.advice)
                    if pset.algorithm == CombiningAlg.PERMIT_OVERRIDES:
                        return Decision.PERMIT, obligations, advice, used
                    if pset.algorithm == CombiningAlg.FIRST_APPLICABLE:
                        return Decision.PERMIT, obligations, advice, used
                    local_decision = Decision.PERMIT
                else:
                    # NotApplicable — просто дальше
                    pass
            except Exception as e:
                LOG.error("policy %s error: %s", pol.id, e)
                # INDETERMINATE => для deny_overrides трактуем как deny
                if pset.algorithm == CombiningAlg.DENY_OVERRIDES:
                    return Decision.DENY, obligations, advice, used
                local_decision = Decision.INDETERMINATE

        return local_decision, obligations, advice, used


# ==========================
# Хелперы построения правил/политик
# ==========================

def attr(path: str) -> Operand:
    return {"attr": path}


def value(v: Any) -> Operand:
    return {"value": v}


def setv(vals: Iterable[Any]) -> Operand:
    return {"set": list(vals)}


def op(op_name: str, left: Operand, right: Operand) -> Expr:
    return {"op": op_name, "left": left, "right": right}


def ALL(*exprs: Expr) -> Expr:
    return {"all": list(exprs)}


def ANY(*exprs: Expr) -> Expr:
    return {"any": list(exprs)}


def NOT(expr: Expr) -> Expr:
    return {"not": expr}


def policy(
    pid: str,
    effect: Effect,
    *,
    target: Optional[Expr] = None,
    condition: Optional[Expr] = None,
    obligations: Optional[Mapping[str, Any]] = None,
    advice: Optional[Mapping[str, Any]] = None,
    priority: int = 0,
    enabled: bool = True,
    description: str = "",
) -> Policy:
    return Policy(
        id=pid,
        effect=effect,
        target=Condition(target) if target else None,
        condition=Condition(condition) if condition else None,
        obligations=[Obligation(k, v) for k, v in (obligations or {}).items()],
        advice=[Advice(k, v) for k, v in (advice or {}).items()],
        priority=priority,
        enabled=enabled,
        description=description,
    )


# ==========================
# Enforcement helpers (PEP)
# ==========================

class AuthorizationError(Exception):
    pass


def enforce(pdp: PDP, req: Request) -> DecisionResult:
    res = pdp.decide(req)
    if res.decision != Decision.PERMIT:
        raise AuthorizationError(f"Access denied: {res.decision}; used={res.used_policies}")
    return res


# ==========================
# Примеры типовых политик (готовы для использования)
# ==========================

def default_policy_set() -> PolicySet:
    """
    Набор политик с deny-overrides:
      1) deny при явном запрете resource.acl.deny содержит subject.id или любую из subject.roles
      2) permit админу по роли
      3) permit владельцу ресурса на чтение/изменение
      4) ограничение по офисным часам (9..19) для изменений (иначе NotApplicable)
    """
    ps = PolicySet(
        id="ps.default",
        algorithm=CombiningAlg.DENY_OVERRIDES,
        description="Default ABAC policy set",
    )

    # 1. Явный deny, если в ACL deny есть subject.id или его роль
    ps.policies.append(
        policy(
            "deny.explicit.acl",
            Effect.DENY,
            target=ANY(
                op("in", attr("subject.id"), attr("resource.acl.deny")),
                op("intersects", attr("subject.roles"), attr("resource.acl.deny")),
            ),
            priority=1000,
            description="Explicit deny by ACL",
        )
    )

    # 2. Администраторы — разрешено всё
    ps.policies.append(
        policy(
            "permit.role.admin",
            Effect.PERMIT,
            target=op("in", value("admin"), attr("subject.roles")),
            priority=900,
            obligations={"audit": "admin_override"},
            description="Admins are permitted",
        )
    )

    # 3. Владельцу разрешено читать/изменять
    ps.policies.append(
        policy(
            "permit.owner.readwrite",
            Effect.PERMIT,
            target=ANY(
                op("eq", attr("resource.owner_id"), attr("subject.id")),
                op("in", attr("subject.id"), attr("resource.owners")),  # поддержка множественных
            ),
            condition=ANY(
                op("in", attr("action.name"), setv(["read", "update", "delete", "write"])),
                op("glob", attr("action.name"), value("doc:*")),
            ),
            priority=800,
            description="Owner can read/write",
        )
    )

    # 4. Офисные часы: 09:00–19:59 локального времени средой окружения
    ps.policies.append(
        policy(
            "permit.business_hours.write",
            Effect.PERMIT,
            target=op("in", attr("action.name"), setv(["write", "update", "delete"])),
            condition=ALL(
                op("ge", attr("environment.local_hour"), value(9)),
                op("le", attr("environment.local_hour"), value(19)),
            ),
            priority=500,
            advice={"throttle": "soft"},
            description="Write/update/delete within business hours",
        )
    )

    return ps


# ==========================
# Утилита построения запроса
# ==========================

def make_request(
    *,
    subject: Mapping[str, Any],
    resource: Mapping[str, Any],
    action: Mapping[str, Any],
    environment: Optional[Mapping[str, Any]] = None,
) -> Request:
    env = dict(environment or {})
    # заполним полезные дефолты, если не заданы
    if "local_hour" not in env:
        try:
            import datetime as _dt
            env["local_hour"] = _dt.datetime.now().hour  # простая эвристика; при необходимости внедрите TZ
        except Exception:
            env["local_hour"] = 0
    return Request(
        subject=AttrView(subject),
        resource=AttrView(resource),
        action=AttrView(action),
        environment=AttrView(env),
    )


# ==========================
# Мини-демо (локальный запуск)
# ==========================

if __name__ == "__main__":
    pdp = PDP([default_policy_set()])

    alice_read = make_request(
        subject={"id": "u1", "roles": ["user"]},
        resource={"id": "doc42", "owner_id": "u1", "acl": {"deny": []}},
        action={"name": "read"},
        environment={"local_hour": 10},
    )
    res = pdp.decide(alice_read)
    print("alice_read:", dataclasses.asdict(res))

    bob_write_after_hours = make_request(
        subject={"id": "u2", "roles": ["user"]},
        resource={"id": "doc42", "owner_id": "u2", "acl": {"deny": []}},
        action={"name": "write"},
        environment={"local_hour": 22},
    )
    res2 = pdp.decide(bob_write_after_hours)
    print("bob_write_after_hours:", dataclasses.asdict(res2))

    admin_any = make_request(
        subject={"id": "root", "roles": ["admin"]},
        resource={"id": "vault", "owner_id": "n/a", "acl": {"deny": []}},
        action={"name": "anything"},
        environment={},
    )
    res3 = pdp.decide(admin_any)
    print("admin_any:", dataclasses.asdict(res3))
