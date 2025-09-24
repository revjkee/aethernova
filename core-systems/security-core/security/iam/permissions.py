# security-core/security/iam/permissions.py
from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

logger = logging.getLogger("security_core.iam.permissions")


# ============================= Enums и базовые типы =============================

class Effect(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class PolicySource(Enum):
    TENANT = "TENANT"        # guardrails организации/арендатора
    RESOURCE = "RESOURCE"    # политики, прикреплённые к ресурсу
    IDENTITY = "IDENTITY"    # роли и политики субъекта
    SERVICE = "SERVICE"      # глобальные политики сервиса (как дефолты)


# ============================= Модели политик =============================

@dataclass(frozen=True)
class ConditionExpr:
    op: str              # eq, in, regex, ip_in_cidr, time_between, weekday_in, present, gt, ge, lt, le, mfa, attested, scope_any, role_any, contains
    attr: str            # путь к атрибуту контекста: principal.*, resource.*, context.*
    value: Any           # сравниваемое значение (или список, или паттерн)

@dataclass(frozen=True)
class Condition:
    """
    Логическая форма:
      all_of: все должны быть True
      any_of: достаточно одного True
      not_any_of: все должны быть False (ни один не сработал)
    Отсутствующие блоки пропускаются.
    """
    all_of: Tuple[ConditionExpr, ...] = field(default_factory=tuple)
    any_of: Tuple[ConditionExpr, ...] = field(default_factory=tuple)
    not_any_of: Tuple[ConditionExpr, ...] = field(default_factory=tuple)

@dataclass(frozen=True)
class PolicyStatement:
    sid: Optional[str]
    effect: Effect
    actions: Tuple[str, ...]       # маски вида "keys:*", "kms:Sign", "*"
    resources: Tuple[str, ...]     # маски вида "keys:tenant/{tenant}/*"
    conditions: Tuple[Condition, ...] = field(default_factory=tuple)
    obligations: Mapping[str, Any] = field(default_factory=dict)  # например, {"require_mfa": True}
    source: PolicySource = PolicySource.IDENTITY                   # заполняется при компиляции/загрузке

@dataclass(frozen=True)
class PolicyDocument:
    version: str
    statements: Tuple[PolicyStatement, ...]


# ============================= Principal / контексты =============================

@dataclass(frozen=True)
class Principal:
    tenant: str
    subject: str
    roles: Tuple[str, ...] = field(default_factory=tuple)
    groups: Tuple[str, ...] = field(default_factory=tuple)
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    attributes: Mapping[str, Any] = field(default_factory=dict)  # произвольные атрибуты субъекта (ABAC)
    mfa_present: bool = False
    attested: bool = False  # результат проверки TEE/TPM и т.п.

@dataclass(frozen=True)
class RequestContext:
    time_epoch_s: int
    ip: str
    user_agent: Optional[str] = None
    attributes: Mapping[str, Any] = field(default_factory=dict)  # любые атрибуты запроса

@dataclass(frozen=True)
class PermissionCheckRequest:
    principal: Principal
    action: str
    resource: str
    context: RequestContext

@dataclass(frozen=True)
class Decision:
    allowed: bool
    effect: Effect
    matched_statement: Optional[PolicyStatement]
    source: Optional[PolicySource]
    reasons: Tuple[str, ...]
    obligations: Mapping[str, Any] = field(default_factory=dict)


# ============================= Интерфейсы для интеграции =============================

class PolicyStore:
    """
    Интерфейс хранилища политик. Верните уже 'скомпилированные' (с проставленным source) документы.
    """
    async def get_tenant_policies(self, tenant: str) -> Sequence[PolicyDocument]:
        raise NotImplementedError

    async def get_resource_policies(self, tenant: str, resource: str) -> Sequence[PolicyDocument]:
        raise NotImplementedError

    async def get_identity_policies(self, principal: Principal) -> Sequence[PolicyDocument]:
        raise NotImplementedError

    async def get_service_policies(self) -> Sequence[PolicyDocument]:
        raise NotImplementedError


class ResourceAttributeProvider:
    """
    Интерфейс для загрузки атрибутов ресурса по его идентификатору.
    """
    async def get_attributes(self, tenant: str, resource: str) -> Mapping[str, Any]:
        raise NotImplementedError


# ============================= Кэш решений с TTL =============================

class _TTLCache:
    def __init__(self, maxsize: int = 10000, ttl_seconds: int = 5):
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._lock = threading.RLock()
        self._store: Dict[str, Tuple[float, Decision]] = {}

    def _prune(self) -> None:
        now = time.time()
        if len(self._store) <= self.maxsize:
            # удаляем протухшие
            stale = [k for k, (t, _) in self._store.items() if (now - t) > self.ttl]
            for k in stale:
                self._store.pop(k, None)
            return
        # агрессивная чистка
        items = sorted(self._store.items(), key=lambda kv: kv[1][0])
        for k, _ in items[: max(1, len(items) // 10)]:
            self._store.pop(k, None)

    def get(self, key: str) -> Optional[Decision]:
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            t, val = item
            if (time.time() - t) > self.ttl:
                self._store.pop(key, None)
                return None
            return val

    def set(self, key: str, val: Decision) -> None:
        with self._lock:
            self._store[key] = (time.time(), val)
            if len(self._store) > self.maxsize:
                self._prune()


# ============================= Утилиты: доступ к атрибутам, матчинг =============================

def _get_attr(tree: Mapping[str, Any], dotted: str) -> Any:
    """
    Достаёт атрибут по пути вида 'principal.roles', 'resource.owner', 'context.ip'
    """
    cur: Any = tree
    for part in dotted.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

def _to_strs(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, (list, tuple, set)):
        return [str(x) for x in val]
    return [str(val)]

def _match_action(patterns: Sequence[str], action: str) -> bool:
    # Пример действия: "kms:Sign", "keys:GetPublic"
    return any(fnmatch.fnmatchcase(action, p) or p == "*" for p in patterns)

_RESOURCE_SEGMENT_RE = re.compile(r"\{([a-zA-Z0-9_\.]+)\}")

def _substitute_placeholders(pattern: str, env: Mapping[str, Any]) -> str:
    """
    Меняет плейсхолдеры вида {tenant}, {principal.subject}, {context.ip} на значения из env.
    Отсутствующие оставляет без подстановки (чтобы не исказить матчинг неожиданно).
    """
    def repl(m: re.Match[str]) -> str:
        key = m.group(1)
        val = _get_attr(env, key)
        return str(val) if val is not None else m.group(0)
    return _RESOURCE_SEGMENT_RE.sub(repl, pattern)

def _match_resource(patterns: Sequence[str], resource: str, env: Mapping[str, Any]) -> bool:
    # Поддержка плейсхолдеров и масок
    for p in patterns:
        pp = _substitute_placeholders(p, env)
        if fnmatch.fnmatchcase(resource, pp) or pp == "*":
            return True
    return False


# ============================= Операторы условий =============================

class _Ops:
    @staticmethod
    def eq(left: Any, right: Any) -> bool:
        return left == right

    @staticmethod
    def ne(left: Any, right: Any) -> bool:
        return left != right

    @staticmethod
    def gt(left: Any, right: Any) -> bool:
        try:
            return float(left) > float(right)
        except Exception:
            return False

    @staticmethod
    def ge(left: Any, right: Any) -> bool:
        try:
            return float(left) >= float(right)
        except Exception:
            return False

    @staticmethod
    def lt(left: Any, right: Any) -> bool:
        try:
            return float(left) < float(right)
        except Exception:
            return False

    @staticmethod
    def le(left: Any, right: Any) -> bool:
        try:
            return float(left) <= float(right)
        except Exception:
            return False

    @staticmethod
    def isin(left: Any, right: Any) -> bool:
        right_list = right if isinstance(right, (list, tuple, set)) else [right]
        return left in right_list

    @staticmethod
    def notin(left: Any, right: Any) -> bool:
        right_list = right if isinstance(right, (list, tuple, set)) else [right]
        return left not in right_list

    @staticmethod
    def contains(left: Any, right: Any) -> bool:
        try:
            return right in left  # type: ignore[operator]
        except Exception:
            return False

    @staticmethod
    def regex(left: Any, pattern: Any) -> bool:
        try:
            return bool(re.fullmatch(str(pattern), str(left)))
        except Exception:
            return False

    @staticmethod
    def ip_in_cidr(ip: Any, cidrs: Any) -> bool:
        try:
            ipaddr = ipaddress.ip_address(str(ip))
            nets = cidrs if isinstance(cidrs, (list, tuple, set)) else [cidrs]
            for c in nets:
                net = ipaddress.ip_network(str(c), strict=False)
                if ipaddr in net:
                    return True
            return False
        except Exception:
            return False

    @staticmethod
    def time_between(epoch_s: Any, window: Any) -> bool:
        """
        window: [start_epoch_s, end_epoch_s]
        """
        try:
            now = int(epoch_s)
            start, end = int(window[0]), int(window[1])
            return start <= now <= end
        except Exception:
            return False

    @staticmethod
    def weekday_in(epoch_s: Any, days: Any) -> bool:
        """
        days: [0..6], где 0 = Понедельник (ISO weekday-1)
        """
        try:
            import datetime as _dt
            d = _dt.datetime.utcfromtimestamp(int(epoch_s)).isoweekday() - 1
            allowed = days if isinstance(days, (list, tuple, set)) else [days]
            return d in [int(x) for x in allowed]
        except Exception:
            return False

    @staticmethod
    def present(val: Any, expect: Any) -> bool:
        """
        expect: True/False — ожидание присутствия (не None и не пусто)
        """
        is_present = val is not None and (val != "" and val != [] and val != {})
        return bool(expect) == is_present

    @staticmethod
    def mfa(flag: Any, expect: Any) -> bool:
        return bool(flag) is bool(expect)

    @staticmethod
    def attested(flag: Any, expect: Any) -> bool:
        return bool(flag) is bool(expect)

    @staticmethod
    def scope_any(scopes: Any, required: Any) -> bool:
        s = set(_to_strs(scopes))
        req = set(_to_strs(required))
        return bool(s.intersection(req))

    @staticmethod
    def role_any(roles: Any, required: Any) -> bool:
        r = set(_to_strs(roles))
        req = set(_to_strs(required))
        return bool(r.intersection(req))


_OP_REGISTRY: Dict[str, Callable[[Any, Any], bool]] = {
    "eq": _Ops.eq, "ne": _Ops.ne,
    "gt": _Ops.gt, "ge": _Ops.ge, "lt": _Ops.lt, "le": _Ops.le,
    "in": _Ops.isin, "nin": _Ops.notin, "contains": _Ops.contains,
    "regex": _Ops.regex, "ip_in_cidr": _Ops.ip_in_cidr,
    "time_between": _Ops.time_between, "weekday_in": _Ops.weekday_in,
    "present": _Ops.present, "mfa": _Ops.mfa, "attested": _Ops.attested,
    "scope_any": _Ops.scope_any, "role_any": _Ops.role_any,
}


# ============================= Проверка условий и политик =============================

def _eval_expr(expr: ConditionExpr, bag: Mapping[str, Any]) -> Tuple[bool, str]:
    left = _get_attr(bag, expr.attr)
    op_fn = _OP_REGISTRY.get(expr.op)
    if not op_fn:
        return False, f"unknown_op:{expr.op}"
    try:
        ok = op_fn(left, expr.value)
        return ok, f"{expr.op}({expr.attr},{expr.value})={ok}"
    except Exception as e:
        return False, f"op_error:{expr.op}:{e}"

def _eval_condition(cond: Condition, bag: Mapping[str, Any]) -> Tuple[bool, List[str]]:
    trace: List[str] = []
    # all_of
    for ex in cond.all_of:
        ok, t = _eval_expr(ex, bag)
        trace.append(t)
        if not ok:
            return False, trace
    # any_of
    if cond.any_of:
        any_ok = False
        for ex in cond.any_of:
            ok, t = _eval_expr(ex, bag)
            trace.append(t)
            any_ok = any_ok or ok
        if not any_ok:
            return False, trace
    # not_any_of
    for ex in cond.not_any_of:
        ok, t = _eval_expr(ex, bag)
        trace.append(t)
        if ok:
            return False, trace
    return True, trace

def _eval_statement(stmt: PolicyStatement, bag: Mapping[str, Any], action: str, resource: str) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if not _match_action(stmt.actions, action):
        reasons.append(f"action_miss:{action}")
        return False, reasons
    if not _match_resource(stmt.resources, resource, bag):
        reasons.append(f"resource_miss:{resource}")
        return False, reasons
    # условия
    for cond in stmt.conditions:
        ok, tr = _eval_condition(cond, bag)
        reasons.extend(tr)
        if not ok:
            reasons.append("condition_failed")
            return False, reasons
    reasons.append("matched")
    return True, reasons


# ============================= Движок разрешений =============================

class PermissionEngine:
    def __init__(
        self,
        policy_store: PolicyStore,
        resource_attrs: ResourceAttributeProvider,
        cache_ttl_seconds: int = 3,
        cache_maxsize: int = 20000,
    ) -> None:
        self.store = policy_store
        self.res_attr = resource_attrs
        self.cache = _TTLCache(maxsize=cache_maxsize, ttl_seconds=cache_ttl_seconds)

    @staticmethod
    def _cache_key(req: PermissionCheckRequest) -> str:
        p = req.principal
        c = req.context
        # Упрощённый ключ (без всего attributes детально); при необходимости расширьте
        return "|".join([
            p.tenant, p.subject, ",".join(p.roles), ",".join(p.scopes),
            req.action, req.resource, c.ip, str(int(c.time_epoch_s // 1)), str(int(p.mfa_present)), str(int(p.attested))
        ])

    async def check(self, req: PermissionCheckRequest) -> Decision:
        ck = self._cache_key(req)
        cached = self.cache.get(ck)
        if cached is not None:
            return cached

        principal = req.principal
        # Подготовим bag атрибутов для условий
        resource_attrs = await self.res_attr.get_attributes(principal.tenant, req.resource)
        bag: Dict[str, Any] = {
            "principal": {
                "tenant": principal.tenant,
                "subject": principal.subject,
                "roles": principal.roles,
                "groups": principal.groups,
                "scopes": principal.scopes,
                "attributes": principal.attributes,
                "mfa_present": principal.mfa_present,
                "attested": principal.attested,
            },
            "resource": resource_attrs,
            "context": {
                "ip": req.context.ip,
                "time_epoch_s": req.context.time_epoch_s,
                "user_agent": req.context.user_agent,
                "attributes": req.context.attributes,
            },
            "tenant": principal.tenant,
            "action": req.action,
            "resource_id": req.resource,
        }

        # Собираем политики
        pols_tenant = await self.store.get_tenant_policies(principal.tenant)
        pols_resource = await self.store.get_resource_policies(principal.tenant, req.resource)
        pols_identity = await self.store.get_identity_policies(principal)
        pols_service = await self.store.get_service_policies()

        deny_hits: List[Tuple[PolicyStatement, List[str]]] = []
        allow_hits: List[Tuple[PolicyStatement, List[str]]] = []

        def scan(docs: Sequence[PolicyDocument]) -> None:
            for doc in docs:
                for st in doc.statements:
                    matched, trace = _eval_statement(st, bag, req.action, req.resource)
                    if matched:
                        if st.effect == Effect.DENY:
                            deny_hits.append((st, trace))
                        else:
                            allow_hits.append((st, trace))

        # Порядок сканирования не влияет на приоритет (DENY>ALLOW), но влияет на причины
        scan(pols_service)
        scan(pols_tenant)
        scan(pols_resource)
        scan(pols_identity)

        # DENY имеет абсолютный приоритет
        if deny_hits:
            st, trace = deny_hits[0]
            dec = Decision(
                allowed=False,
                effect=Effect.DENY,
                matched_statement=st,
                source=st.source,
                reasons=tuple(["deny_hit"] + trace + [f"sid={st.sid or ''}", f"source={st.source.value}"]),
                obligations={},
            )
            self.cache.set(ck, dec)
            return dec

        if allow_hits:
            # Сливаем obligations (позволяем последующим уточнять)
            obligations: Dict[str, Any] = {}
            chosen_stmt: Optional[PolicyStatement] = None
            chosen_trace: List[str] = []
            # Приоритет источников для ALLOW: TENANT > RESOURCE > IDENTITY > SERVICE (более строгие выше)
            src_rank = {PolicySource.TENANT: 0, PolicySource.RESOURCE: 1, PolicySource.IDENTITY: 2, PolicySource.SERVICE: 3}
            allow_hits.sort(key=lambda x: src_rank.get(x[0].source, 99))
            for st, tr in allow_hits:
                obligations.update(st.obligations or {})
            chosen_stmt, chosen_trace = allow_hits[0]
            dec = Decision(
                allowed=True,
                effect=Effect.ALLOW,
                matched_statement=chosen_stmt,
                source=chosen_stmt.source,
                reasons=tuple(["allow_hit"] + chosen_trace + [f"sid={chosen_stmt.sid or ''}", f"source={chosen_stmt.source.value}"]),
                obligations=obligations,
            )
            self.cache.set(ck, dec)
            return dec

        # Явной ALLOW не найдено
        dec = Decision(
            allowed=False,
            effect=Effect.DENY,
            matched_statement=None,
            source=None,
            reasons=("no_match",),
            obligations={},
        )
        self.cache.set(ck, dec)
        return dec


# ============================= Вспомогательные билдеры/парсеры =============================

def build_condition_expr(op: str, attr: str, value: Any) -> ConditionExpr:
    return ConditionExpr(op=op, attr=attr, value=value)

def build_condition(
    all_of: Optional[Iterable[ConditionExpr]] = None,
    any_of: Optional[Iterable[ConditionExpr]] = None,
    not_any_of: Optional[Iterable[ConditionExpr]] = None,
) -> Condition:
    return Condition(
        all_of=tuple(all_of or ()),
        any_of=tuple(any_of or ()),
        not_any_of=tuple(not_any_of or ()),
    )

def make_statement(
    effect: Effect,
    actions: Iterable[str],
    resources: Iterable[str],
    conditions: Optional[Iterable[Condition]] = None,
    sid: Optional[str] = None,
    obligations: Optional[Mapping[str, Any]] = None,
    source: PolicySource = PolicySource.IDENTITY,
) -> PolicyStatement:
    return PolicyStatement(
        sid=sid,
        effect=effect,
        actions=tuple(actions),
        resources=tuple(resources),
        conditions=tuple(conditions or ()),
        obligations=dict(obligations or {}),
        source=source,
    )

def make_policy(version: str, statements: Iterable[PolicyStatement]) -> PolicyDocument:
    return PolicyDocument(version=version, statements=tuple(statements))


# ============================= Пример InMemoryPolicyStore (для wiring) =============================

class InMemoryPolicyStore(PolicyStore):
    """
    Простая in-memory реализация (для тестов/прототипа).
    Ожидает предкомпилированные документы с корректно указанным source.
    """
    def __init__(
        self,
        service: Sequence[PolicyDocument] = (),
        tenants: Mapping[str, Sequence[PolicyDocument]] = (),
        identities: Mapping[str, Sequence[PolicyDocument]] = (),
        resources: Mapping[Tuple[str, str], Sequence[PolicyDocument]] = (),
    ) -> None:
        self._service = tuple(service)
        self._tenants = {k: tuple(v) for k, v in tenants.items()}
        self._ident = {k: tuple(v) for k, v in identities.items()}
        self._res = {k: tuple(v) for k, v in resources.items()}

    async def get_tenant_policies(self, tenant: str) -> Sequence[PolicyDocument]:
        return self._tenants.get(tenant, ())

    async def get_resource_policies(self, tenant: str, resource: str) -> Sequence[PolicyDocument]:
        return self._res.get((tenant, resource), ())

    async def get_identity_policies(self, principal: Principal) -> Sequence[PolicyDocument]:
        # ключом может быть subject или роль; для простоты используем subject
        return self._ident.get(principal.subject, ())

    async def get_service_policies(self) -> Sequence[PolicyDocument]:
        return self._service


# ============================= Пример провайдера атрибутов ресурса =============================

class NullResourceAttributeProvider(ResourceAttributeProvider):
    async def get_attributes(self, tenant: str, resource: str) -> Mapping[str, Any]:
        # Минимальный набор: владелец может быть заложен в идентификаторе ресурса, если используется шаблон
        return {
            "id": resource,
            "tenant": tenant,
        }


# ============================= Готовые пресеты операторов (для удобства) =============================

def cond_ip_whitelist(cidrs: Iterable[str]) -> Condition:
    return build_condition(all_of=(build_condition_expr("ip_in_cidr", "context.ip", list(cidrs)),))

def cond_mfa_required() -> Condition:
    return build_condition(all_of=(build_condition_expr("mfa", "principal.mfa_present", True),))

def cond_attested_required() -> Condition:
    return build_condition(all_of=(build_condition_expr("attested", "principal.attested", True),))

def cond_time_window(start_epoch: int, end_epoch: int) -> Condition:
    return build_condition(all_of=(build_condition_expr("time_between", "context.time_epoch_s", [start_epoch, end_epoch]),))

def cond_weekdays(days: Iterable[int]) -> Condition:
    return build_condition(all_of=(build_condition_expr("weekday_in", "context.time_epoch_s", list(days)),))


# ============================= Пример сборки политик (доп. вспомогательное) =============================

def compile_default_kms_policies(tenant: str) -> Sequence[PolicyDocument]:
    """
    Пример серверных guardrails: запрет вне белого списка IP на критические операции.
    """
    deny_outside_cidr = make_statement(
        effect=Effect.DENY,
        actions=("kms:Destroy*", "kms:Schedule*", "kms:Import*", "kms:Rotate*"),
        resources=("keys:tenant/{tenant}/*",),
        conditions=(build_condition(not_any_of=(build_condition_expr("ip_in_cidr", "context.ip", ["10.0.0.0/8", "192.168.0.0/16"]),)),),
        sid="deny-critical-outside-cidr",
        source=PolicySource.TENANT,
    )
    allow_reads = make_statement(
        effect=Effect.ALLOW,
        actions=("keys:Get*", "kms:Describe*", "kms:List*"),
        resources=("keys:tenant/{tenant}/*",),
        conditions=(),
        sid="allow-describe",
        source=PolicySource.TENANT,
    )
    return (make_policy("2025-08-01", (deny_outside_cidr, allow_reads)),)
