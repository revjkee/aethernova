from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Callable, Dict, Iterable, List, Optional, Pattern, Sequence, Set, Tuple

# ========== Опциональные метрики Prometheus ==========
_PROM_ENABLED = os.getenv("PERM_PROMETHEUS", "true").lower() == "true"
_prom = None
if _PROM_ENABLED:
    try:
        from prometheus_client import Counter, Histogram  # type: ignore

        class _Prom:
            def __init__(self):
                self.decisions = Counter(
                    "ecs_authz_decisions_total",
                    "Authorization decisions",
                    ["result", "reason"],
                )
                self.latency = Histogram(
                    "ecs_authz_check_seconds",
                    "Authorization check latency",
                    buckets=[0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02],
                )

        _prom = _Prom()
    except Exception:
        _prom = None


# ========== Эффект и приоритеты ==========
class Effect(IntEnum):
    DENY = 0
    ALLOW = 1


# ========== Условия (ABAC) ==========
class Condition:
    """Базовый интерфейс условия ABAC."""
    def match(self, principal: "PrincipalComponent", action: str, resource: str, ctx: Dict[str, Any]) -> bool:
        raise NotImplementedError


@dataclass
class AttrEquals(Condition):
    key: str
    value: Any
    def match(self, principal: "PrincipalComponent", action: str, resource: str, ctx: Dict[str, Any]) -> bool:
        return ctx.get(self.key) == self.value or principal.attributes.get(self.key) == self.value


@dataclass
class AttrIn(Condition):
    key: str
    values: Set[Any]
    def match(self, principal: "PrincipalComponent", action: str, resource: str, ctx: Dict[str, Any]) -> bool:
        val = ctx.get(self.key, principal.attributes.get(self.key))
        return val in self.values


@dataclass
class TimeWindow(Condition):
    """Разрешает только в окне [start_ts, end_ts), unix seconds."""
    start_ts: float
    end_ts: float
    def match(self, principal: "PrincipalComponent", action: str, resource: str, ctx: Dict[str, Any]) -> bool:
        now = ctx.get("now_ts", time.time())
        return self.start_ts <= float(now) < self.end_ts


@dataclass
class CIDRMatch(Condition):
    """Сопоставление IP контекста (ctx['ip']) с любым из подсетей."""
    cidrs: List[str]
    _nets: List[ipaddress._BaseNetwork] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._nets = [ipaddress.ip_network(c, strict=False) for c in self.cidrs]

    def match(self, principal: "PrincipalComponent", action: str, resource: str, ctx: Dict[str, Any]) -> bool:
        ip = ctx.get("ip")
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in n for n in self._nets)
        except ValueError:
            return False


@dataclass
class ExprCondition(Condition):
    """
    Условие на основе предиката: Callable(principal, action, resource, ctx)->bool
    Для регистрации повторно используемых предикатов используйте register_condition().
    """
    name: str
    fn: Callable[["PrincipalComponent", str, str, Dict[str, Any]], bool]

    def match(self, principal: "PrincipalComponent", action: str, resource: str, ctx: Dict[str, Any]) -> bool:
        try:
            return bool(self.fn(principal, action, resource, ctx))
        except Exception:
            return False


# Реестр именованных условий (кастомных предикатов)
_COND_REGISTRY: Dict[str, Callable[["PrincipalComponent", str, str, Dict[str, Any]], bool]] = {}

def register_condition(name: str, fn: Callable[["PrincipalComponent", str, str, Dict[str, Any]], bool]) -> None:
    _COND_REGISTRY[name] = fn

def condition_by_name(name: str) -> Optional[Callable]:
    return _COND_REGISTRY.get(name)


# ========== Правила и политики ==========
@dataclass(frozen=True)
class PermissionRule:
    """
    Одно правило политики.
    actions/resources поддерживают wildcard (*, ?, [...] через fnmatch).
    conditions — список всех условий (логическое И).
    tags — произвольные метки для аудита/поиска.
    """
    effect: Effect
    actions: Set[str]
    resources: Set[str]
    conditions: Tuple[Condition, ...] = field(default_factory=tuple)
    tags: Tuple[str, ...] = field(default_factory=tuple)


@dataclass
class RoleComponent:
    """
    Роль описывает набор правил и наследование.
    Пример имени: 'admin', 'editor', 'viewer'.
    """
    name: str
    rules: List[PermissionRule] = field(default_factory=list)
    inherits: Set[str] = field(default_factory=set)
    description: str = ""


@dataclass
class ResourcePolicyComponent:
    """
    Локальная политика на сущности‑ресурсе.
    Вызывается в дополнение к ролям субъекта.
    """
    rules: List[PermissionRule] = field(default_factory=list)
    owner_attribute: str = "owner_id"  # имя атрибута, которым владеет пользователь (для удобства)


@dataclass
class PrincipalComponent:
    """
    Субъект доступа: пользователь/сервис. Вешается на сущность‑актора.
    """
    subject: str
    tenant: Optional[str] = None
    roles: Set[str] = field(default_factory=set)
    scopes: Set[str] = field(default_factory=set)
    attributes: Dict[str, Any] = field(default_factory=dict)
    expires_at_ts: Optional[float] = None  # если задано — токен/сессия истекает

    def is_active(self, now_ts: Optional[float] = None) -> bool:
        if self.expires_at_ts is None:
            return True
        now = now_ts or time.time()
        return now < float(self.expires_at_ts)


# ========== Компиляция политик для быстрого матчинга ==========
@dataclass
class CompiledRule:
    effect: Effect
    actions: Tuple[str, ...]
    resources: Tuple[str, ...]
    action_regex: Tuple[Pattern[str], ...]
    resource_regex: Tuple[Pattern[str], ...]
    conditions: Tuple[Condition, ...]
    tags: Tuple[str, ...]


class PolicyCompiler:
    """
    Компилирует PermissionRule в быструю форму (regex fnmatch -> re).
    Кэширует результаты по id(rule) для многократного использования.
    """
    _cache: Dict[int, CompiledRule] = {}

    @classmethod
    def compile_rule(cls, rule: PermissionRule) -> CompiledRule:
        rid = id(rule)
        if rid in cls._cache:
            return cls._cache[rid]
        def to_regex(p: str) -> Pattern[str]:
            # fnmatch.translate возвращает корректный regex для glob‑паттернов.
            return re.compile(fnmatch.translate(p))
        ar = tuple(to_regex(a) for a in rule.actions)
        rr = tuple(to_regex(r) for r in rule.resources)
        cr = CompiledRule(
            effect=rule.effect,
            actions=tuple(sorted(rule.actions)),
            resources=tuple(sorted(rule.resources)),
            action_regex=ar,
            resource_regex=rr,
            conditions=rule.conditions,
            tags=rule.tags,
        )
        cls._cache[rid] = cr
        return cr

    @classmethod
    def compile_rules(cls, rules: Iterable[PermissionRule]) -> List[CompiledRule]:
        return [cls.compile_rule(r) for r in rules]


# ========== Сбор ролей и построение эффективной политики ==========
def compile_roles(
    roles: Dict[str, RoleComponent],
    principal_roles: Set[str],
    *,
    max_depth: int = 8,
) -> List[CompiledRule]:
    """
    Возвращает все скомпилированные правила с учётом наследования ролей.
    Циклы наследования обрезаются по max_depth.
    """
    out: List[PermissionRule] = []
    seen: Set[str] = set()

    def dfs(r: str, depth: int) -> None:
        if r in seen or depth > max_depth:
            return
        seen.add(r)
        role = roles.get(r)
        if not role:
            return
        out.extend(role.rules)
        for parent in role.inherits:
            dfs(parent, depth + 1)

    for rn in principal_roles:
        dfs(rn, 0)
    return PolicyCompiler.compile_rules(out)


# ========== Основной движок принятия решения ==========
@dataclass
class Decision:
    allow: bool
    reason: str
    matched_rule: Optional[CompiledRule] = None


def _match_any(regexes: Sequence[Pattern[str]], value: str) -> bool:
    # Обычно 1–4 паттерна; быстрый линейный проход.
    for rx in regexes:
        if rx.match(value) is not None:
            return True
    return False


def _conditions_ok(conds: Sequence[Condition], principal: PrincipalComponent, action: str, resource: str, ctx: Dict[str, Any]) -> bool:
    for c in conds:
        if not c.match(principal, action, resource, ctx):
            return False
    return True


def check_access(
    principal: PrincipalComponent,
    action: str,
    resource: str,
    *,
    role_index: Dict[str, RoleComponent] | None = None,
    resource_policies: Iterable[ResourcePolicyComponent] | None = None,
    ctx: Optional[Dict[str, Any]] = None,
) -> Decision:
    """
    Денормализованная проверка доступа:
      1) Проверяем активность субъекта и сроки.
      2) Собираем правила из ролей с наследованием.
      3) Добавляем локальные политики ресурса (если заданы).
      4) Применяем стратегию deny‑overrides: любой совпавший DENY побеждает,
         иначе ALLOW при первом совпавшем ALLOW.
    """
    t0 = time.perf_counter_ns()
    ctx = ctx or {}

    if not principal.is_active(ctx.get("now_ts")):
        if _prom: _prom.decisions.labels("deny", "expired").inc()  # type: ignore[attr-defined]
        return Decision(False, "principal_expired")

    compiled: List[CompiledRule] = []
    if role_index:
        compiled.extend(compile_roles(role_index, principal.roles))
    if resource_policies:
        for pol in resource_policies:
            compiled.extend(PolicyCompiler.compile_rules(pol.rules))

    # Денормализуем, применяя deny‑overrides
    deny_hit: Optional[CompiledRule] = None
    allow_hit: Optional[CompiledRule] = None

    for cr in compiled:
        if not _match_any(cr.action_regex, action):
            continue
        if not _match_any(cr.resource_regex, resource):
            continue
        if not _conditions_ok(cr.conditions, principal, action, resource, ctx):
            continue
        if cr.effect == Effect.DENY:
            deny_hit = cr
            break  # deny‑overrides: можно закончить сразу
        else:
            # ALLOW — запомним, но не прерываем: возможен более специфичный DENY дальше
            if allow_hit is None:
                allow_hit = cr

    dur_s = (time.perf_counter_ns() - t0) / 1e9
    if _prom:
        try:
            _prom.latency.observe(dur_s)  # type: ignore[attr-defined]
        except Exception:
            pass

    if deny_hit:
        if _prom:
            try: _prom.decisions.labels("deny", "rule").inc()  # type: ignore[attr-defined]
            except Exception: pass
        return Decision(False, "deny_rule", matched_rule=deny_hit)
    if allow_hit:
        if _prom:
            try: _prom.decisions.labels("allow", "rule").inc()  # type: ignore[attr-defined]
            except Exception: pass
        return Decision(True, "allow_rule", matched_rule=allow_hit)

    if _prom:
        try: _prom.decisions.labels("deny", "default").inc()  # type: ignore[attr-defined]
        except Exception: pass
    return Decision(False, "no_match")


# ========== Утилиты для создания правил/ролей ==========
def allow(actions: Iterable[str], resources: Iterable[str], *conditions: Condition, tags: Iterable[str] = ()) -> PermissionRule:
    return PermissionRule(effect=Effect.ALLOW, actions=set(actions), resources=set(resources), conditions=tuple(conditions), tags=tuple(tags))


def deny(actions: Iterable[str], resources: Iterable[str], *conditions: Condition, tags: Iterable[str] = ()) -> PermissionRule:
    return PermissionRule(effect=Effect.DENY, actions=set(actions), resources=set(resources), conditions=tuple(conditions), tags=tuple(tags))


def role(name: str, rules: Iterable[PermissionRule], inherits: Iterable[str] = (), description: str = "") -> RoleComponent:
    return RoleComponent(name=name, rules=list(rules), inherits=set(inherits), description=description)


# ========== Пример минимальной интеграции с ECS (докстрока) ==========
"""
Пример использования в системах ECS:

from engine.ecs.components.permissions import (
    PrincipalComponent, ResourcePolicyComponent, RoleComponent, check_access,
    allow, deny, AttrEquals, TimeWindow, role
)

# Реестр ролей (может жить в конфиге/БД, затем материализуется в словарь)
ROLES = {
    "viewer": role("viewer", [allow(["read:*"], ["doc:*"])]),
    "editor": role("editor", [allow(["read:*","write:*"], ["doc:*"])]),
    "owner":  role("owner",  [allow(["*"], ["doc:{principal_id}"])], inherits=["editor"]),
    "admin":  role("admin",  [allow(["*"], ["*"])]),
}

# Актор
principal = PrincipalComponent(
    subject="user:123",
    tenant="acme",
    roles={"viewer"},
    attributes={"principal_id": "123"}
)

# Локальная политика ресурса (сущность документа):
doc_policy = ResourcePolicyComponent(
    rules=[
        allow(["read:*","write:update"], ["doc:*"], AttrEquals("owner_id", "123")),  # владелец
        deny(["write:delete"], ["doc:critical/*"])  # явный запрет удаления критичных документов
    ],
    owner_attribute="owner_id"
)

# Проверка:
decision = check_access(
    principal,
    action="write:update",
    resource="doc:42",
    role_index=ROLES,
    resource_policies=[doc_policy],
    ctx={"now_ts": time.time(), "ip": "10.0.0.5", "owner_id": "123"}
)
assert decision.allow
"""

__all__ = [
    "Effect",
    "Condition",
    "AttrEquals",
    "AttrIn",
    "TimeWindow",
    "CIDRMatch",
    "ExprCondition",
    "register_condition",
    "condition_by_name",
    "PermissionRule",
    "RoleComponent",
    "ResourcePolicyComponent",
    "PrincipalComponent",
    "CompiledRule",
    "PolicyCompiler",
    "compile_roles",
    "Decision",
    "check_access",
    "allow",
    "deny",
    "role",
]
