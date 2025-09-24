# security-core/security/authz/rbac.py
# Industrial RBAC engine with hierarchy, explicit deny, contextual constraints and TTL cache.
from __future__ import annotations

import fnmatch
import ipaddress
import json
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import yaml  # type: ignore
except Exception as _e:  # pragma: no cover
    yaml = None

from pydantic import BaseModel, Field, root_validator, validator


# =========================
# Public Models
# =========================

class Effect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Weekday(str, Enum):
    MON = "MON"
    TUE = "TUE"
    WED = "WED"
    THU = "THU"
    FRI = "FRI"
    SAT = "SAT"
    SUN = "SUN"


class ConstraintSpec(BaseModel):
    tenant_equals: Optional[str] = None
    env_in: Optional[List[str]] = None
    ip_in_cidr: Optional[List[str]] = None
    # Часы в UTC, [start,end], включительно. Формат "HH:MM"
    time_between_utc: Optional[Tuple[str, str]] = None
    days_of_week: Optional[List[Weekday]] = None
    # Совпадение меток ресурса: labels[key] ∈ {values}
    resource_labels_match: Optional[Dict[str, List[str]]] = None
    # Совпадение атрибутов субъекта: subject.attrs[key] ∈ {values}
    subject_attrs_match: Optional[Dict[str, List[str]]] = None

    @validator("env_in", "ip_in_cidr", each_item=True)
    def _strip(cls, v: str) -> str:
        return v.strip()

    @validator("time_between_utc")
    def _validate_time_pair(cls, v: Optional[Tuple[str, str]]) -> Optional[Tuple[str, str]]:
        if not v:
            return v
        for t in v:
            hh, mm = t.split(":")
            if not (0 <= int(hh) <= 23 and 0 <= int(mm) <= 59):
                raise ValueError("invalid time format, expected HH:MM (00-23:00-59)")
        return v


class PermissionSpec(BaseModel):
    # Уникальный ID правила
    id: str = Field(..., min_length=1, max_length=128)
    effect: Effect = Effect.ALLOW
    # Поддерживаются шаблоны (glob): "*", "service:*", "db:orders:*"
    resource: List[str] = Field(..., description="Patterns of resource identifiers")
    # Действия (glob): "read", "write", "deploy", "*"
    action: List[str] = Field(..., description="Actions list (glob supported)")
    priority: int = Field(default=100, ge=0, le=100000)  # меньше — выше приоритет
    constraints: Optional[ConstraintSpec] = None

    @validator("resource", "action", pre=True)
    def _listify(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            return [v]
        return list(v or [])


class RoleSpec(BaseModel):
    id: str = Field(..., min_length=1, max_length=128)
    inherits: List[str] = Field(default_factory=list)
    allow: List[PermissionSpec] = Field(default_factory=list)
    deny: List[PermissionSpec] = Field(default_factory=list)


class Assignment(BaseModel):
    # subject: "user:<id>" | "service:<id>"
    subject: str = Field(..., min_length=3, max_length=256)
    roles: List[str] = Field(default_factory=list)
    tenant: Optional[str] = None
    # UNIX seconds; None = бессрочно
    expires_at: Optional[int] = None


class PolicyDoc(BaseModel):
    policy_id: str = Field(..., min_length=1, max_length=128)
    roles: List[RoleSpec] = Field(default_factory=list)
    assignments: List[Assignment] = Field(default_factory=list)
    default_decision: Effect = Effect.DENY

    @root_validator
    def _unique_ids(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        # Проверяем уникальность ID ролей и правил в пределах ролей
        seen_roles: Set[str] = set()
        for r in values.get("roles", []):
            if r.id in seen_roles:
                raise ValueError(f"duplicate role id: {r.id}")
            seen_roles.add(r.id)
            seen_rules: Set[str] = set()
            for p in [*r.allow, *r.deny]:
                if p.id in seen_rules:
                    raise ValueError(f"duplicate permission id in role {r.id}: {p.id}")
                seen_rules.add(p.id)
        return values


class SubjectContext(BaseModel):
    subject: str
    roles: List[str] = Field(default_factory=list)  # доп. роли сверх Assignment (например, системные)
    attrs: Dict[str, str] = Field(default_factory=dict)
    tenant: Optional[str] = None
    env: Optional[str] = None
    ip: Optional[str] = None
    now_utc_s: Optional[int] = None  # если None — возьмем time.time()


class ResourceContext(BaseModel):
    # Рекомендуемый формат: "<type>:<name>" или любая строка, подходящая под glob
    resource_id: str
    labels: Dict[str, str] = Field(default_factory=dict)


class Decision(BaseModel):
    allowed: bool
    effect: Effect
    policy_id: str
    reason: str
    matched_permission_id: Optional[str] = None
    matched_role_id: Optional[str] = None
    priority: int = 10**9
    cached: bool = False
    explain: Optional[List[Dict[str, Any]]] = None


# =========================
# Internal Compiled Structures
# =========================

@dataclass(frozen=True)
class _CompiledPerm:
    id: str
    effect: Effect
    resource_patterns: Tuple[str, ...]
    action_patterns: Tuple[str, ...]
    priority: int
    constraints: Optional[ConstraintSpec]
    role_id: str


class _TTLCache:
    def __init__(self, ttl_seconds: int = 5, max_items: int = 10000) -> None:
        self._ttl = ttl_seconds
        self._max = max_items
        self._data: Dict[str, Tuple[float, Decision]] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Decision]:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            exp, value = item
            if time.monotonic() > exp:
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Decision) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                # сбросим произвольный
                self._data.pop(next(iter(self._data)), None)
            self._data[key] = (time.monotonic() + self._ttl, value)


# =========================
# RBAC Engine
# =========================

class RBACEngine:
    """
    Высокопроизводительный RBAC с иерархией ролей, явными DENY‑правилами и контекстными ограничениями.
    """

    def __init__(self, ttl_cache_seconds: int = 5) -> None:
        self._policy: Optional[PolicyDoc] = None
        self._compiled_allow: Dict[str, List[_CompiledPerm]] = {}
        self._compiled_deny: Dict[str, List[_CompiledPerm]] = {}
        self._role_graph: Dict[str, Set[str]] = {}
        self._assignments_by_subject: Dict[str, List[Assignment]] = {}
        self._cache = _TTLCache(ttl_seconds=ttl_cache_seconds)
        self._policy_id = "rbac"
        self._lock = threading.RLock()
        self._source_paths: List[str] = []

    # ---------- Loading ----------

    def load_from_dict(self, data: Dict[str, Any]) -> None:
        doc = PolicyDoc(**data)
        self._compile_policy(doc)

    def load_from_yaml(self, path: str | Path) -> None:
        if yaml is None:
            raise RuntimeError("PyYAML is required to load YAML policies")
        p = Path(path)
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        self._source_paths = [str(p)]
        self.load_from_dict(raw)

    def _compile_policy(self, doc: PolicyDoc) -> None:
        with self._lock:
            self._policy = doc
            self._policy_id = doc.policy_id
            # Граф наследования ролей
            self._role_graph = {r.id: set(r.inherits or []) for r in doc.roles}
            self._detect_cycles()
            # Компиляция разрешений/запретов
            self._compiled_allow = {}
            self._compiled_deny = {}
            for r in doc.roles:
                allow_list = sorted(
                    (self._compile_perm(p, r.id) for p in r.allow),
                    key=lambda x: x.priority,
                )
                deny_list = sorted(
                    (self._compile_perm(p, r.id) for p in r.deny),
                    key=lambda x: x.priority,
                )
                self._compiled_allow[r.id] = allow_list
                self._compiled_deny[r.id] = deny_list
            # Индексация назначений
            self._assignments_by_subject = {}
            for a in doc.assignments:
                self._assignments_by_subject.setdefault(a.subject, []).append(a)
            # Очистка кэша
            self._cache = _TTLCache(ttl_seconds=self._cache._ttl, max_items=10000)

    def _compile_perm(self, p: PermissionSpec, role_id: str) -> _CompiledPerm:
        return _CompiledPerm(
            id=p.id,
            effect=p.effect,
            resource_patterns=tuple(p.resource),
            action_patterns=tuple(p.action),
            priority=p.priority,
            constraints=p.constraints,
            role_id=role_id,
        )

    def _detect_cycles(self) -> None:
        visited: Set[str] = set()
        stack: Set[str] = set()

        def dfs(node: str) -> None:
            if node in stack:
                raise ValueError(f"role inheritance cycle detected at {node}")
            if node in visited:
                return
            stack.add(node)
            for nb in self._role_graph.get(node, set()):
                dfs(nb)
            stack.remove(node)
            visited.add(node)

        for r in list(self._role_graph.keys()):
            dfs(r)

    # ---------- Role resolution ----------

    def _resolve_roles(self, seed_roles: Iterable[str]) -> Set[str]:
        resolved: Set[str] = set()
        stack = list(seed_roles)
        while stack:
            r = stack.pop()
            if r in resolved:
                continue
            resolved.add(r)
            stack.extend(self._role_graph.get(r, set()))
        return resolved

    def _roles_for_subject(self, subj: SubjectContext) -> Set[str]:
        now = int(time.time())
        roles: Set[str] = set(subj.roles or [])
        for a in self._assignments_by_subject.get(subj.subject, []):
            if a.expires_at and now > a.expires_at:
                continue
            if a.tenant and subj.tenant and a.tenant != subj.tenant:
                continue
            roles.update(a.roles)
        return self._resolve_roles(roles)

    # ---------- Constraints ----------

    @staticmethod
    def _time_in_window_utc(ts: int, start_hm: str, end_hm: str) -> bool:
        # Работает с окнами без пересечения суток и с пересечением (например, 22:00—03:00)
        import datetime as dt

        t = dt.datetime.utcfromtimestamp(ts).time()
        s_h, s_m = map(int, start_hm.split(":"))
        e_h, e_m = map(int, end_hm.split(":"))
        s = dt.time(s_h, s_m)
        e = dt.time(e_h, e_m)
        if s <= e:
            return s <= t <= e
        # Окно через полночь
        return t >= s or t <= e

    @staticmethod
    def _weekday(ts: int) -> Weekday:
        import datetime as dt

        # Monday=0
        m = dt.datetime.utcfromtimestamp(ts).weekday()
        return [Weekday.MON, Weekday.TUE, Weekday.WED, Weekday.THU, Weekday.FRI, Weekday.SAT, Weekday.SUN][m]

    @staticmethod
    def _ip_in_cidrs(ip: Optional[str], cidrs: List[str]) -> bool:
        if not ip:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for c in cidrs:
            try:
                if ip_obj in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _constraints_pass(
        self,
        c: Optional[ConstraintSpec],
        subj: SubjectContext,
        res: ResourceContext,
        now_s: int,
    ) -> bool:
        if not c:
            return True
        if c.tenant_equals and subj.tenant and c.tenant_equals != subj.tenant:
            return False
        if c.env_in and subj.env and subj.env not in c.env_in:
            return False
        if c.ip_in_cidr and not self._ip_in_cidrs(subj.ip, c.ip_in_cidr):
            return False
        if c.time_between_utc:
            if not self._time_in_window_utc(now_s, c.time_between_utc[0], c.time_between_utc[1]):
                return False
        if c.days_of_week:
            if self._weekday(now_s) not in set(c.days_of_week):
                return False
        if c.resource_labels_match:
            for k, vals in c.resource_labels_match.items():
                rv = res.labels.get(k)
                if rv is None or (vals and rv not in vals):
                    return False
        if c.subject_attrs_match:
            for k, vals in c.subject_attrs_match.items():
                sv = subj.attrs.get(k)
                if sv is None or (vals and sv not in vals):
                    return False
        return True

    # ---------- Matching ----------

    @staticmethod
    def _match_any(patterns: Iterable[str], value: str) -> bool:
        for p in patterns:
            if fnmatch.fnmatchcase(value, p):
                return True
        return False

    def _iter_perms(self, roles: Set[str]) -> Tuple[Iterable[_CompiledPerm], Iterable[_CompiledPerm]]:
        deny: List[_CompiledPerm] = []
        allow: List[_CompiledPerm] = []
        for r in roles:
            deny.extend(self._compiled_deny.get(r, ()))
            allow.extend(self._compiled_allow.get(r, ()))
        # Приоритет: меньше число — выше приоритет
        deny.sort(key=lambda x: x.priority)
        allow.sort(key=lambda x: x.priority)
        return deny, allow

    # ---------- Decision ----------

    def _cache_key(
        self,
        subj: SubjectContext,
        res: ResourceContext,
        action: str,
        resolved_roles: Set[str],
    ) -> str:
        # Учитываем все значимые поля
        payload = {
            "s": subj.subject,
            "r": sorted(list(resolved_roles)),
            "a": action,
            "res": {"id": res.resource_id, "labels": res.labels},
            "t": subj.tenant,
            "env": subj.env,
            "ip": subj.ip,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def is_allowed(
        self,
        subj: SubjectContext,
        res: ResourceContext,
        action: str,
        want_explain: bool = False,
    ) -> Decision:
        now = subj.now_utc_s or int(time.time())
        # resolve roles
        roles = self._roles_for_subject(subj)
        # cache
        key = self._cache_key(subj, res, action, roles)
        cached = self._cache.get(key)
        if cached and not want_explain:
            return cached.copy(update={"cached": True})  # type: ignore

        explain_frames: List[Dict[str, Any]] = []

        deny_perms, allow_perms = self._iter_perms(roles)

        # 1) Явные DENY (первичный приоритет)
        for p in deny_perms:
            if not self._match_any(p.resource_patterns, res.resource_id):
                continue
            if not self._match_any(p.action_patterns, action):
                continue
            if not self._constraints_pass(p.constraints, subj, res, now):
                continue
            frame = {
                "rule_id": p.id,
                "role_id": p.role_id,
                "effect": p.effect.value,
                "matched": True,
                "reason": "explicit deny matched",
                "priority": p.priority,
            }
            if want_explain:
                explain_frames.append(frame)
            decision = Decision(
                allowed=False,
                effect=Effect.DENY,
                policy_id=self._policy_id,
                reason="explicit deny",
                matched_permission_id=p.id,
                matched_role_id=p.role_id,
                priority=p.priority,
                explain=explain_frames if want_explain else None,
            )
            self._cache.set(key, decision)
            return decision

        # 2) ALLOW
        for p in allow_perms:
            if not self._match_any(p.resource_patterns, res.resource_id):
                continue
            if not self._match_any(p.action_patterns, action):
                continue
            if not self._constraints_pass(p.constraints, subj, res, now):
                continue
            frame = {
                "rule_id": p.id,
                "role_id": p.role_id,
                "effect": p.effect.value,
                "matched": True,
                "reason": "allow matched",
                "priority": p.priority,
            }
            if want_explain:
                explain_frames.append(frame)
            decision = Decision(
                allowed=True,
                effect=Effect.ALLOW,
                policy_id=self._policy_id,
                reason="allow",
                matched_permission_id=p.id,
                matched_role_id=p.role_id,
                priority=p.priority,
                explain=explain_frames if want_explain else None,
            )
            self._cache.set(key, decision)
            return decision

        # 3) Default
        def_dec = (self._policy.default_decision if self._policy else Effect.DENY)  # type: ignore
        decision = Decision(
            allowed=(def_dec == Effect.ALLOW),
            effect=def_dec,
            policy_id=self._policy_id,
            reason="no rule matched",
            matched_permission_id=None,
            matched_role_id=None,
            priority=10**9,
            explain=explain_frames if want_explain else None,
        )
        self._cache.set(key, decision)
        return decision

    # ---------- Explain ----------

    def explain(
        self,
        subj: SubjectContext,
        res: ResourceContext,
        action: str,
    ) -> Decision:
        return self.is_allowed(subj, res, action, want_explain=True)

    # ---------- Hot reload ----------

    def reload_from_yaml(self, path: str | Path) -> None:
        self.load_from_yaml(path)

    # ---------- Introspection ----------

    def policy_info(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "policy_id": self._policy_id,
                "roles": list(self._role_graph.keys()),
                "assignments": sum(len(v) for v in self._assignments_by_subject.values()),
                "source_paths": list(self._source_paths),
                "default_decision": (self._policy.default_decision.value if self._policy else "DENY"),
            }


# =========================
# YAML Policy Example (for reference)
# =========================
"""
policy_id: "rbac-baseline"
default_decision: "DENY"
roles:
  - id: "viewer"
    inherits: []
    allow:
      - id: "viewer-read"
        effect: "ALLOW"
        resource: ["service:*", "db:*", "bucket:*"]
        action: ["read", "get", "list"]
        priority: 50
        constraints:
          env_in: ["dev", "stage", "prod"]
  - id: "developer"
    inherits: ["viewer"]
    allow:
      - id: "dev-write-dev"
        effect: "ALLOW"
        resource: ["service:*", "db:*"]
        action: ["write", "update", "deploy"]
        priority: 40
        constraints:
          env_in: ["dev", "stage"]
  - id: "prod-guardian"
    inherits: []
    deny:
      - id: "deny-prod-data-export"
        effect: "DENY"
        resource: ["db:*"]
        action: ["export", "read"]
        priority: 10
        constraints:
          env_in: ["prod"]
assignments:
  - subject: "user:123"
    roles: ["developer"]
    tenant: "t1"
  - subject: "service:ingestor"
    roles: ["viewer"]
"""


# =========================
# Convenience singleton (optional)
# =========================

_engine_singleton: Optional[RBACEngine] = None
_engine_lock = threading.RLock()


def get_engine() -> RBACEngine:
    global _engine_singleton
    with _engine_lock:
        if _engine_singleton is None:
            _engine_singleton = RBACEngine(ttl_cache_seconds=5)
        return _engine_singleton


__all__ = [
    "RBACEngine",
    "PolicyDoc",
    "RoleSpec",
    "PermissionSpec",
    "ConstraintSpec",
    "Assignment",
    "SubjectContext",
    "ResourceContext",
    "Decision",
    "Effect",
    "Weekday",
    "get_engine",
]
