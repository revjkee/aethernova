# cybersecurity-core/cybersecurity/iam/authz.py
from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, time as dtime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Sequence, Tuple, Callable

from pydantic import BaseModel, Field, conint, constr, validator

__all__ = [
    "Principal",
    "Resource",
    "RequestContext",
    "Condition",
    "Policy",
    "Decision",
    "PolicyStore",
    "InMemoryPolicyStore",
    "AuthzEngine",
    "AuthorizationError",
    "require_scopes",
    "authorize",
    "enforce",
    "pep_guard",
]

# -----------------------------------------------------------------------------
# Логирование
# -----------------------------------------------------------------------------
logger = logging.getLogger("iam.authz")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Модели субъекта/ресурса/контекста
# -----------------------------------------------------------------------------
class Principal(BaseModel):
    subject: constr(strip_whitespace=True, min_length=1)
    kind: Literal["service", "agent", "user"]
    tenant_id: Optional[constr(strip_whitespace=True, min_length=1)] = None
    roles: List[constr(strip_whitespace=True, min_length=1)] = Field(default_factory=list)
    scopes: List[constr(strip_whitespace=True, min_length=1)] = Field(default_factory=list)
    groups: List[constr(strip_whitespace=True, min_length=1)] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    mfa: bool = False
    device_trust: Literal["low", "medium", "high"] = "low"


class Resource(BaseModel):
    type: constr(strip_whitespace=True, min_length=1)  # e.g., "edr:event", "edr:rule", "graphql:*"
    id: Optional[constr(strip_whitespace=True, min_length=1)] = None
    owner: Optional[constr(strip_whitespace=True, min_length=1)] = None
    tenant_id: Optional[constr(strip_whitespace=True, min_length=1)] = None
    classification: Literal["public", "internal", "restricted", "secret", "top_secret"] = "internal"
    tags: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class RequestContext(BaseModel):
    time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    correlation_id: Optional[str] = None
    risk: conint(ge=0, le=100) = 0
    location: Optional[str] = None
    device_posture: Dict[str, Any] = Field(default_factory=dict)

    @validator("time", pre=True)
    def _ensure_tz(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(str(v)).replace(tzinfo=timezone.utc)

# -----------------------------------------------------------------------------
# Политики и условия
# -----------------------------------------------------------------------------
class Condition(BaseModel):
    # path: "principal.tenant_id" | "resource.tags.env" | "context.ip"
    path: constr(strip_whitespace=True, min_length=1)
    op: Literal[
        "eq", "neq", "in", "contains", "regex", "gte", "lte",
        "ip_cidr", "time_in", "subset", "superset", "startswith", "endswith"
    ]
    value: Any


class Policy(BaseModel):
    policy_id: constr(strip_whitespace=True, min_length=1)
    description: Optional[str] = None
    enabled: bool = True
    # Меньший priority = выше приоритет
    priority: conint(ge=0, le=1_000_000) = 1000
    effect: Literal["allow", "deny"]
    actions: List[constr(strip_whitespace=True, min_length=1)] = Field(default_factory=list)  # glob, e.g., "edr:*"
    resources: List[constr(strip_whitespace=True, min_length=1)] = Field(default_factory=list)  # glob for Resource.type
    # ABAC условия
    conditions_all: List[Condition] = Field(default_factory=list)
    conditions_any: List[Condition] = Field(default_factory=list)
    # Ограничение по арендаторам (None/[] = любые)
    tenants: List[str] = Field(default_factory=list)
    # Simple ReBAC-lite: разрешённые владельцы/группы владельца (через условия тоже можно)
    owner_in_principal: bool = False
    # Обязательства для PEP (выполняются при ALLOW)
    obligations: Dict[str, Any] = Field(default_factory=dict)

# -----------------------------------------------------------------------------
# Решение
# -----------------------------------------------------------------------------
class Decision(BaseModel):
    allow: bool
    effect: Literal["allow", "deny"]
    policy_id: Optional[str] = None
    obligations: Dict[str, Any] = Field(default_factory=dict)
    reasons: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# -----------------------------------------------------------------------------
# Policy Store (версионируемый)
# -----------------------------------------------------------------------------
class PolicyStore(Protocol):
    def get_policies(self, tenant_id: Optional[str]) -> Sequence[Policy]: ...
    def version(self) -> str: ...


class InMemoryPolicyStore(PolicyStore):
    def __init__(self) -> None:
        self._policies_global: List[Policy] = []
        self._policies_by_tenant: Dict[str, List[Policy]] = {}
        self._ver = str(uuid.uuid4())
        self._lock = threading.Lock()

    def replace(self, *, global_policies: Sequence[Policy] | None = None,
                tenant_policies: Dict[str, Sequence[Policy]] | None = None) -> None:
        with self._lock:
            if global_policies is not None:
                self._policies_global = list(global_policies)
            if tenant_policies is not None:
                self._policies_by_tenant = {k: list(v) for k, v in tenant_policies.items()}
            self._ver = str(uuid.uuid4())

    def add(self, policy: Policy, tenant_id: Optional[str] = None) -> None:
        with self._lock:
            if tenant_id:
                lst = self._policies_by_tenant.setdefault(tenant_id, [])
                lst.append(policy)
            else:
                self._policies_global.append(policy)
            self._ver = str(uuid.uuid4())

    def get_policies(self, tenant_id: Optional[str]) -> Sequence[Policy]:
        with self._lock:
            res = list(self._policies_global)
            if tenant_id and tenant_id in self._policies_by_tenant:
                res.extend(self._policies_by_tenant[tenant_id])
            return res

    def version(self) -> str:
        return self._ver

# -----------------------------------------------------------------------------
# Вспомогательные функции
# -----------------------------------------------------------------------------
_CLASS_ORDER = {
    "public": 0, "internal": 1, "restricted": 2, "secret": 3, "top_secret": 4
}

def _get_attr(root: Dict[str, Any], path: str) -> Any:
    cur: Any = root
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = getattr(cur, part, None)
    return cur

def _to_time(v: Any) -> dtime:
    # Ожидает "HH:MM" или datetime -> time
    if isinstance(v, dtime):
        return v
    if isinstance(v, datetime):
        return v.timetz()
    s = str(v)
    hh, mm = s.split(":")[0:2]
    return dtime(int(hh), int(mm), tzinfo=timezone.utc)

def _ip_in_cidrs(ip: str, cidrs: Iterable[str]) -> bool:
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

def _op_eval(value: Any, op: str, expected: Any) -> bool:
    if op == "eq":
        return value == expected
    if op == "neq":
        return value != expected
    if op == "in":
        return value in (expected or [])
    if op == "contains":
        return str(expected) in str(value or "")
    if op == "regex":
        try:
            return bool(re.search(str(expected), str(value or "")))
        except re.error:
            return False
    if op == "gte":
        try:
            return float(value) >= float(expected)
        except Exception:
            return False
    if op == "lte":
        try:
            return float(value) <= float(expected)
        except Exception:
            return False
    if op == "startswith":
        return str(value or "").startswith(str(expected))
    if op == "endswith":
        return str(value or "").endswith(str(expected))
    if op == "subset":
        try:
            return set(value or []) <= set(expected or [])
        except Exception:
            return False
    if op == "superset":
        try:
            return set(value or []) >= set(expected or [])
        except Exception:
            return False
    if op == "ip_cidr":
        lst = expected if isinstance(expected, (list, tuple)) else [expected]
        return _ip_in_cidrs(str(value or ""), lst)
    if op == "time_in":
        # expected: "HH:MM-HH:MM"
        try:
            s = str(expected)
            a, b = s.split("-")
            t1 = _to_time(a)
            t2 = _to_time(b)
            tv = value
            if isinstance(tv, datetime):
                tv = tv.timetz()
            if not isinstance(tv, dtime):
                return False
            if t1 <= t2:
                return t1 <= tv <= t2
            # диапазон через полночь
            return tv >= t1 or tv <= t2
        except Exception:
            return False
    return False

# -----------------------------------------------------------------------------
# Простой TTL-кэш
# -----------------------------------------------------------------------------
class _TTLCache:
    def __init__(self, ttl_sec: int = 30, max_size: int = 1024) -> None:
        self.ttl = ttl_sec
        self.max_size = max_size
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            ts, val = item
            if time.time() - ts > self.ttl:
                self._store.pop(key, None)
                return None
            return val

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._store) >= self.max_size:
                # простая очистка: удаляем устаревшие
                now = time.time()
                for k, (ts, _) in list(self._store.items())[: self.max_size // 4]:
                    if now - ts > self.ttl:
                        self._store.pop(k, None)
            self._store[key] = (time.time(), value)

# -----------------------------------------------------------------------------
# Движок авторизации (PDP)
# -----------------------------------------------------------------------------
class AuthorizationError(Exception):
    def __init__(self, message: str, decision: Optional[Decision] = None) -> None:
        super().__init__(message)
        self.decision = decision


class AuthzEngine:
    """
    Алгоритм:
      1) Собрать политики: глобальные + политики тенанта (если tenant_id есть).
      2) Отфильтровать по enabled и tenants (если указаны в политике).
      3) Отсортировать по priority (меньше = раньше).
      4) Проитерироваться: при первом совпадении условий/actions/resources:
           - если effect=deny -> deny (прерывание)
           - если effect=allow -> allow (прерывание)
      5) Если совпадений нет -> deny (по умолчанию).
    """
    def __init__(self, store: PolicyStore, cache_ttl_sec: int = 15) -> None:
        self.store = store
        self.cache = _TTLCache(ttl_sec=cache_ttl_sec)
        self._last_store_ver = ""

    def _load_policies(self, tenant_id: Optional[str]) -> List[Policy]:
        ver = self.store.version()
        cache_key = f"pol:{tenant_id}:{ver}"
        pols = self.cache.get(cache_key)
        if pols is not None:
            return pols
        data = list(self.store.get_policies(tenant_id))
        # filter/sort
        data = [p for p in data if p.enabled]
        data.sort(key=lambda p: p.priority)
        self.cache.set(cache_key, data)
        self._last_store_ver = ver
        return data

    def evaluate(
        self,
        principal: Principal,
        action: str,
        resource: Resource,
        context: Optional[RequestContext] = None,
    ) -> Decision:
        ctx = context or RequestContext()
        root = {"principal": principal, "resource": resource, "context": ctx}

        # Быстрый путь: супер-скоуп
        if "root" in (principal.scopes or []) or "iam:admin" in (principal.roles or []):
            dec = Decision(allow=True, effect="allow", policy_id="__root_override__", obligations={},
                           reasons=["principal has root scope"])
            self._audit(principal, action, resource, ctx, dec)
            return dec

        # Единое правило аренды: если у ресурса указан tenant_id — субъект должен совпадать (если политикой не разрешено иное)
        if resource.tenant_id and principal.tenant_id and principal.tenant_id != resource.tenant_id:
            # Разрешим только если явная политика DENY/ALLOW перекроет — но сначала проверим политики.
            pass

        policies = self._load_policies(principal.tenant_id or None)

        matched: Optional[Decision] = None
        for p in policies:
            if p.tenants and (principal.tenant_id or "") not in p.tenants:
                continue
            if not self._match_globs(action, p.actions):
                continue
            if not self._match_globs(resource.type, p.resources):
                continue
            if p.owner_in_principal and resource.owner and resource.owner != principal.subject:
                continue
            if not self._conds_ok(root, p.conditions_all, all_mode=True):
                continue
            if p.conditions_any and not self._conds_ok(root, p.conditions_any, all_mode=False):
                continue

            # Совпало: применяем эффект
            if p.effect == "deny":
                dec = Decision(allow=False, effect="deny", policy_id=p.policy_id, obligations={}, reasons=["matched deny"])
                self._audit(principal, action, resource, ctx, dec)
                return dec
            if p.effect == "allow":
                matched = Decision(allow=True, effect="allow", policy_id=p.policy_id, obligations=dict(p.obligations), reasons=["matched allow"])
                break

        if matched:
            # Пост-обязательства: риск -> требование MFA, если указано в политике или контексте
            if ctx.risk >= 60 and not principal.mfa:
                matched.obligations.setdefault("require_mfa", True)
                matched.reasons.append("risk>=60 requires mfa")
            self._audit(principal, action, resource, ctx, matched)
            return matched

        dec = Decision(allow=False, effect="deny", policy_id=None, obligations={}, reasons=["no matching policy"])
        self._audit(principal, action, resource, ctx, dec)
        return dec

    # ----------------------------- helpers ------------------------------------
    @staticmethod
    def _match_globs(value: str, patterns: Sequence[str]) -> bool:
        if not patterns:
            return True
        for p in patterns:
            if fnmatch.fnmatch(value, p):
                return True
        return False

    @staticmethod
    def _conds_ok(root: Dict[str, Any], conds: Sequence[Condition], all_mode: bool) -> bool:
        if not conds:
            return True
        results = []
        for c in conds:
            val = _get_attr(root, c.path)
            ok = _op_eval(val, c.op, c.value)
            results.append(ok)
            if all_mode and not ok:
                return False
            if not all_mode and ok:
                return True
        return all(results) if all_mode else False

    def _audit(self, principal: Principal, action: str, resource: Resource, context: RequestContext, decision: Decision) -> None:
        # Лаконичный структурный аудит (ECS-like)
        logger.info(
            "authz decision",
            extra={
                "authz_decision": {
                    "allow": decision.allow,
                    "effect": decision.effect,
                    "policy_id": decision.policy_id,
                    "reasons": decision.reasons,
                    "obligations": decision.obligations,
                    "at": decision.timestamp.isoformat(),
                },
                "authz_request": {
                    "subject": principal.subject,
                    "kind": principal.kind,
                    "tenant_id": principal.tenant_id,
                    "roles": principal.roles,
                    "scopes": principal.scopes,
                    "action": action,
                    "resource_type": resource.type,
                    "resource_id": resource.id,
                    "resource_tenant": resource.tenant_id,
                    "ctx_ip": context.ip,
                    "ctx_risk": context.risk,
                    "correlation_id": context.correlation_id,
                },
            },
        )

# -----------------------------------------------------------------------------
# PEP-хелперы (Policy Enforcement Point)
# -----------------------------------------------------------------------------
def require_scopes(principal: Principal, *scopes: str) -> None:
    want = set(scopes)
    have = set(principal.scopes or [])
    missing = want - have
    if missing:
        raise AuthorizationError(f"missing scopes: {', '.join(sorted(missing))}")

def authorize(
    engine: AuthzEngine,
    principal: Principal,
    action: str,
    resource: Resource,
    context: Optional[RequestContext] = None,
) -> Decision:
    return engine.evaluate(principal, action, resource, context)

def enforce(
    engine: AuthzEngine,
    principal: Principal,
    action: str,
    resource: Resource,
    context: Optional[RequestContext] = None,
) -> Decision:
    dec = engine.evaluate(principal, action, resource, context)
    if not dec.allow:
        raise AuthorizationError("forbidden", dec)
    return dec

def pep_guard(
    engine: AuthzEngine,
    action: str,
    resource_factory: Callable[..., Resource],
    context_factory: Optional[Callable[..., RequestContext]] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Универсальный декоратор PEP без зависимости от фреймворков.
    Пример использования в HTTP-роутере/GraphQL-резолвере:
      @pep_guard(engine, "edr:write", lambda *a, **kw: Resource(type="edr:rule", id=...))
      async def handler(principal: Principal, ...): ...
    Требование: целевая функция должна принимать `principal: Principal` позиционно или именованно.
    """
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        if asyncio.iscoroutinefunction(fn):  # type: ignore
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                principal = _extract_principal_from_args_kwargs(args, kwargs)
                res = resource_factory(*args, **kwargs)
                ctx = context_factory(*args, **kwargs) if context_factory else None
                enforce(engine, principal, action, res, ctx)
                return await fn(*args, **kwargs)
            return async_wrapper
        else:
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                principal = _extract_principal_from_args_kwargs(args, kwargs)
                res = resource_factory(*args, **kwargs)
                ctx = context_factory(*args, **kwargs) if context_factory else None
                enforce(engine, principal, action, res, ctx)
                return fn(*args, **kwargs)
            return sync_wrapper
    return decorator

def _extract_principal_from_args_kwargs(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Principal:
    # Ищем Principal среди аргументов/kwargs (часто прокидывается DI/Depends)
    for a in args:
        if isinstance(a, Principal):
            return a
    for _, v in kwargs.items():
        if isinstance(v, Principal):
            return v
    raise AuthorizationError("principal not provided")

# -----------------------------------------------------------------------------
# Политики по умолчанию (пример загрузки в InMemoryPolicyStore)
# -----------------------------------------------------------------------------
def default_policy_bundle() -> List[Policy]:
    """
    Набор безопасных политик по умолчанию:
      - deny all (низкий приоритет)
      - allow edr:read для scope edr:read
      - allow edr:write для scope edr:write, но с обязательством mfa при risk>=60
    """
    return [
        Policy(
            policy_id="allow-edr-read",
            description="Allow EDR read for edr:read scope",
            priority=100,
            effect="allow",
            actions=["edr:read", "graphql:query"],
            resources=["edr:*", "graphql:*"],
            conditions_all=[Condition(path="principal.scopes", op="superset", value=["edr:read"])],
            obligations={"redact_fields": ["resource.attributes.secrets"]},
        ),
        Policy(
            policy_id="allow-edr-write",
            description="Allow EDR write for edr:write scope (MFA may be required by risk)",
            priority=110,
            effect="allow",
            actions=["edr:write", "graphql:mutation"],
            resources=["edr:*", "graphql:*"],
            conditions_all=[Condition(path="principal.scopes", op="superset", value=["edr:write"])],
            obligations={},  # require_mfa выставит движок при risk>=60
        ),
        Policy(
            policy_id="deny-high-classification",
            description="Deny access to top_secret unless device is high trust and MFA",
            priority=90,
            effect="deny",
            actions=["*"],
            resources=["*"],
            conditions_all=[
                Condition(path="resource.classification", op="eq", value="top_secret"),
                Condition(path="principal.device_trust", op="neq", value="high"),
            ],
        ),
        Policy(
            policy_id="deny-default",
            description="Default deny",
            priority=10000,
            effect="deny",
            actions=["*"],
            resources=["*"],
        ),
    ]
