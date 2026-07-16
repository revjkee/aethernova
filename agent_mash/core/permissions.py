# agent_mash/core/permissions.py
from __future__ import annotations

import abc
import asyncio
import dataclasses
import fnmatch
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

__all__ = [
    "Effect",
    "Decision",
    "PermissionError",
    "PolicyError",
    "ProviderError",
    "PermissionRequest",
    "PermissionDecision",
    "Principal",
    "Resource",
    "PolicyContext",
    "AuditEvent",
    "AuditSink",
    "NullAuditSink",
    "Policy",
    "CompositePolicy",
    "RBACPolicy",
    "ABACPolicy",
    "PermissionProvider",
    "InMemoryPermissionProvider",
    "PermissionEngine",
    "compile_scope",
    "scope_implies",
]


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


class PermissionError(Exception):
    pass


class PolicyError(PermissionError):
    pass


class ProviderError(PermissionError):
    pass


@dataclass(frozen=True)
class Principal:
    """
    Кто делает запрос: человек, сервис, агент.
    """

    subject: str
    tenant_id: str
    roles: Tuple[str, ...] = ()
    scopes: Tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def normalized(self) -> "Principal":
        return Principal(
            subject=str(self.subject),
            tenant_id=str(self.tenant_id),
            roles=tuple(sorted({str(x) for x in self.roles if str(x).strip()})),
            scopes=tuple(sorted({str(x) for x in self.scopes if str(x).strip()})),
            attributes=dict(self.attributes or {}),
        )


@dataclass(frozen=True)
class Resource:
    """
    На что идет запрос: сущность/объект/модуль.
    """

    kind: str
    resource_id: str
    tenant_id: str
    owner_subject: Optional[str] = None
    tags: Tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def normalized(self) -> "Resource":
        return Resource(
            kind=str(self.kind),
            resource_id=str(self.resource_id),
            tenant_id=str(self.tenant_id),
            owner_subject=str(self.owner_subject) if self.owner_subject is not None else None,
            tags=tuple(sorted({str(x) for x in self.tags if str(x).strip()})),
            attributes=dict(self.attributes or {}),
        )


@dataclass(frozen=True)
class PermissionRequest:
    """
    Запрос на действие.
    action: строка типа "agents.execute", "workforce.assign", "vault.read"
    """

    principal: Principal
    action: str
    resource: Optional[Resource] = None
    environment: Mapping[str, Any] = field(default_factory=dict)

    def normalized(self) -> "PermissionRequest":
        return PermissionRequest(
            principal=self.principal.normalized(),
            action=str(self.action).strip(),
            resource=self.resource.normalized() if self.resource else None,
            environment=dict(self.environment or {}),
        )


@dataclass(frozen=True)
class PolicyContext:
    """
    Контекст для политик: кэшируемые поля и вычисления.
    """

    now_epoch_s: int
    request_id: str
    correlation_id: Optional[str] = None
    reason_hint: Optional[str] = None
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PermissionDecision:
    decision: Decision
    effect: Optional[Effect] = None
    policy_id: Optional[str] = None
    reason: Optional[str] = None
    obligations: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @staticmethod
    def allow(policy_id: str, reason: str = "allowed", obligations: Optional[Mapping[str, Any]] = None,
              metadata: Optional[Mapping[str, Any]] = None) -> "PermissionDecision":
        return PermissionDecision(
            decision=Decision.ALLOW,
            effect=Effect.ALLOW,
            policy_id=policy_id,
            reason=reason,
            obligations=dict(obligations or {}),
            metadata=dict(metadata or {}),
        )

    @staticmethod
    def deny(policy_id: str, reason: str = "denied", obligations: Optional[Mapping[str, Any]] = None,
             metadata: Optional[Mapping[str, Any]] = None) -> "PermissionDecision":
        return PermissionDecision(
            decision=Decision.DENY,
            effect=Effect.DENY,
            policy_id=policy_id,
            reason=reason,
            obligations=dict(obligations or {}),
            metadata=dict(metadata or {}),
        )

    @staticmethod
    def not_applicable(policy_id: str, reason: str = "not_applicable",
                       metadata: Optional[Mapping[str, Any]] = None) -> "PermissionDecision":
        return PermissionDecision(
            decision=Decision.NOT_APPLICABLE,
            effect=None,
            policy_id=policy_id,
            reason=reason,
            obligations={},
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True)
class AuditEvent:
    at_epoch_s: int
    request_id: str
    correlation_id: Optional[str]
    principal_subject: str
    principal_tenant: str
    action: str
    resource_kind: Optional[str]
    resource_id: Optional[str]
    resource_tenant: Optional[str]
    decision: str
    policy_id: Optional[str]
    reason: Optional[str]
    metadata: Mapping[str, Any] = field(default_factory=dict)


class AuditSink(abc.ABC):
    @abc.abstractmethod
    async def emit(self, event: AuditEvent) -> None:
        raise NotImplementedError


class NullAuditSink(AuditSink):
    async def emit(self, event: AuditEvent) -> None:
        return


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _hash_request(req: PermissionRequest, ctx: PolicyContext) -> str:
    payload = {
        "principal": {
            "subject": req.principal.subject,
            "tenant_id": req.principal.tenant_id,
            "roles": req.principal.roles,
            "scopes": req.principal.scopes,
            "attributes": req.principal.attributes,
        },
        "action": req.action,
        "resource": None
        if req.resource is None
        else {
            "kind": req.resource.kind,
            "resource_id": req.resource.resource_id,
            "tenant_id": req.resource.tenant_id,
            "owner_subject": req.resource.owner_subject,
            "tags": req.resource.tags,
            "attributes": req.resource.attributes,
        },
        "environment": req.environment,
        "ctx": {
            "now_epoch_s": ctx.now_epoch_s,
            "correlation_id": ctx.correlation_id,
        },
    }
    s = _stable_json(payload).encode("utf-8")
    return hashlib.sha256(s).hexdigest()


def compile_scope(scope: str) -> str:
    """
    Нормализует scope-шаблон.
    Примеры: "vault.read", "vault.*", "*"
    """
    return str(scope).strip()


def scope_implies(granted_scope: str, requested_action: str) -> bool:
    """
    Проверка: покрывает ли granted_scope действие requested_action.
    Использует fnmatch (wildcards '*' и '?').
    """
    gs = compile_scope(granted_scope)
    ra = str(requested_action).strip()
    if not gs:
        return False
    if gs == "*":
        return True
    return fnmatch.fnmatchcase(ra, gs)


class Policy(abc.ABC):
    """
    Политика авторизации. Возвращает:
    - DENY: явный запрет
    - ALLOW: явное разрешение
    - NOT_APPLICABLE: политика не применима
    """

    @property
    @abc.abstractmethod
    def policy_id(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    async def evaluate(self, request: PermissionRequest, ctx: PolicyContext) -> PermissionDecision:
        raise NotImplementedError


class CompositePolicy(Policy):
    """
    Компоновка политик по модели deny-overrides:
    - Если хоть одна политика вернула DENY, итог DENY
    - Иначе если хотя бы одна ALLOW, итог ALLOW
    - Иначе NOT_APPLICABLE (движок трактует как DENY по умолчанию)
    """

    def __init__(self, policy_id: str, policies: Sequence[Policy]) -> None:
        self._policy_id = str(policy_id).strip() or "composite"
        self._policies = list(policies)

    @property
    def policy_id(self) -> str:
        return self._policy_id

    async def evaluate(self, request: PermissionRequest, ctx: PolicyContext) -> PermissionDecision:
        any_allow: Optional[PermissionDecision] = None
        debug_meta: Dict[str, Any] = {"policies": []}

        for p in self._policies:
            d = await p.evaluate(request, ctx)
            debug_meta["policies"].append(
                {"policy_id": d.policy_id, "decision": d.decision, "reason": d.reason}
            )
            if d.decision == Decision.DENY:
                return PermissionDecision.deny(
                    policy_id=self.policy_id,
                    reason=f"deny_overrides:{d.policy_id}",
                    metadata={"source": d.policy_id, "trace": debug_meta},
                )
            if d.decision == Decision.ALLOW and any_allow is None:
                any_allow = d

        if any_allow is not None:
            return PermissionDecision.allow(
                policy_id=self.policy_id,
                reason=f"allowed_by:{any_allow.policy_id}",
                obligations=any_allow.obligations,
                metadata={"source": any_allow.policy_id, "trace": debug_meta},
            )

        return PermissionDecision.not_applicable(
            policy_id=self.policy_id,
            reason="no_applicable_policies",
            metadata={"trace": debug_meta},
        )


class PermissionProvider(abc.ABC):
    """
    Источник ролей, скоупов и политик. Должен быть безопасным и изолированным по tenant_id.
    """

    @abc.abstractmethod
    async def get_roles(self, subject: str, tenant_id: str) -> Sequence[str]:
        raise NotImplementedError

    @abc.abstractmethod
    async def get_scopes(self, subject: str, tenant_id: str) -> Sequence[str]:
        raise NotImplementedError

    @abc.abstractmethod
    async def get_role_scopes(self, role: str, tenant_id: str) -> Sequence[str]:
        raise NotImplementedError

    @abc.abstractmethod
    async def get_abac_rules(self, tenant_id: str) -> Sequence[Mapping[str, Any]]:
        """
        Возвращает правила ABAC в формате словарей.
        Минимальный контракт:
        - id: str
        - effect: "allow"|"deny"
        - actions: list[str] (wildcards разрешены)
        - resource_kinds: list[str] или ["*"]
        - conditions: dict (опционально)
        """
        raise NotImplementedError


class InMemoryPermissionProvider(PermissionProvider):
    """
    Тестовый/локальный провайдер.
    """

    def __init__(
        self,
        subject_roles: Optional[Mapping[Tuple[str, str], Sequence[str]]] = None,
        subject_scopes: Optional[Mapping[Tuple[str, str], Sequence[str]]] = None,
        role_scopes: Optional[Mapping[Tuple[str, str], Sequence[str]]] = None,
        abac_rules: Optional[Mapping[str, Sequence[Mapping[str, Any]]]] = None,
    ) -> None:
        self._subject_roles = dict(subject_roles or {})
        self._subject_scopes = dict(subject_scopes or {})
        self._role_scopes = dict(role_scopes or {})
        self._abac_rules = dict(abac_rules or {})

    async def get_roles(self, subject: str, tenant_id: str) -> Sequence[str]:
        return list(self._subject_roles.get((subject, tenant_id), ()))

    async def get_scopes(self, subject: str, tenant_id: str) -> Sequence[str]:
        return list(self._subject_scopes.get((subject, tenant_id), ()))

    async def get_role_scopes(self, role: str, tenant_id: str) -> Sequence[str]:
        return list(self._role_scopes.get((role, tenant_id), ()))

    async def get_abac_rules(self, tenant_id: str) -> Sequence[Mapping[str, Any]]:
        return list(self._abac_rules.get(tenant_id, ()))


class RBACPolicy(Policy):
    """
    RBAC: разрешение по scopes.
    Источники scopes:
    - principal.scopes
    - scopes из provider (subject scopes)
    - scopes из ролей provider (role->scopes)
    """

    def __init__(self, provider: PermissionProvider, policy_id: str = "rbac") -> None:
        self._provider = provider
        self._policy_id = str(policy_id).strip() or "rbac"

    @property
    def policy_id(self) -> str:
        return self._policy_id

    async def evaluate(self, request: PermissionRequest, ctx: PolicyContext) -> PermissionDecision:
        req = request.normalized()
        if not req.action:
            return PermissionDecision.deny(self.policy_id, reason="empty_action")

        # Zero Trust: tenant boundary must match if resource exists
        if req.resource is not None and req.resource.tenant_id != req.principal.tenant_id:
            return PermissionDecision.deny(self.policy_id, reason="tenant_mismatch")

        try:
            subject_roles = await self._provider.get_roles(req.principal.subject, req.principal.tenant_id)
            subject_scopes = await self._provider.get_scopes(req.principal.subject, req.principal.tenant_id)
        except Exception as e:
            raise ProviderError(f"provider_error:{self.policy_id}:{e}") from e

        role_scopes: List[str] = []
        try:
            for r in set(subject_roles) | set(req.principal.roles):
                rs = await self._provider.get_role_scopes(r, req.principal.tenant_id)
                role_scopes.extend(rs)
        except Exception as e:
            raise ProviderError(f"provider_error:{self.policy_id}:role_scopes:{e}") from e

        granted = set(req.principal.scopes) | set(subject_scopes) | set(role_scopes)
        if not granted:
            return PermissionDecision.not_applicable(self.policy_id, reason="no_grants")

        for g in granted:
            if scope_implies(g, req.action):
                return PermissionDecision.allow(
                    self.policy_id,
                    reason=f"scope_match:{g}",
                    metadata={"matched_scope": g},
                )

        return PermissionDecision.not_applicable(self.policy_id, reason="no_scope_match")


class ABACPolicy(Policy):
    """
    ABAC: правила на основе атрибутов principal/resource/environment.
    Поддерживает deny/allow, wildcard по actions и resource_kinds.
    """

    def __init__(self, provider: PermissionProvider, policy_id: str = "abac") -> None:
        self._provider = provider
        self._policy_id = str(policy_id).strip() or "abac"

    @property
    def policy_id(self) -> str:
        return self._policy_id

    async def evaluate(self, request: PermissionRequest, ctx: PolicyContext) -> PermissionDecision:
        req = request.normalized()

        # tenant boundary
        if req.resource is not None and req.resource.tenant_id != req.principal.tenant_id:
            return PermissionDecision.deny(self.policy_id, reason="tenant_mismatch")

        try:
            rules = await self._provider.get_abac_rules(req.principal.tenant_id)
        except Exception as e:
            raise ProviderError(f"provider_error:{self.policy_id}:{e}") from e

        if not rules:
            return PermissionDecision.not_applicable(self.policy_id, reason="no_rules")

        principal_attrs = dict(req.principal.attributes or {})
        env = dict(req.environment or {})
        resource_attrs: Dict[str, Any] = {}
        resource_kind = None
        resource_id = None
        resource_owner = None
        resource_tags: Tuple[str, ...] = ()
        if req.resource is not None:
            resource_kind = req.resource.kind
            resource_id = req.resource.resource_id
            resource_owner = req.resource.owner_subject
            resource_tags = req.resource.tags
            resource_attrs = dict(req.resource.attributes or {})

        # Evaluate all rules with deny-overrides inside ABAC itself
        any_allow: Optional[Tuple[str, str]] = None  # (rule_id, reason)

        for rule in rules:
            rid = str(rule.get("id") or "rule").strip()
            effect = str(rule.get("effect") or "").strip().lower()
            actions = list(rule.get("actions") or [])
            kinds = list(rule.get("resource_kinds") or ["*"])
            conditions = dict(rule.get("conditions") or {})

            if effect not in ("allow", "deny"):
                continue

            if not _match_any(actions, req.action):
                continue

            # Resource kind matching: if no resource, only match if kinds contains "*"
            if req.resource is None:
                if "*" not in kinds:
                    continue
            else:
                if not _match_any(kinds, resource_kind or ""):
                    continue

            ok, why = _evaluate_conditions(
                conditions=conditions,
                principal_attrs=principal_attrs,
                env=env,
                resource_attrs=resource_attrs,
                resource_kind=resource_kind,
                resource_id=resource_id,
                resource_owner=resource_owner,
                resource_tags=resource_tags,
                principal=req.principal,
                resource=req.resource,
            )
            if not ok:
                continue

            if effect == "deny":
                return PermissionDecision.deny(
                    self.policy_id,
                    reason=f"abac_deny:{rid}:{why}",
                    metadata={"rule_id": rid, "why": why},
                )

            if effect == "allow" and any_allow is None:
                any_allow = (rid, why)

        if any_allow is not None:
            rid, why = any_allow
            return PermissionDecision.allow(
                self.policy_id,
                reason=f"abac_allow:{rid}:{why}",
                metadata={"rule_id": rid, "why": why},
            )

        return PermissionDecision.not_applicable(self.policy_id, reason="no_rule_matched")


def _match_any(patterns: Sequence[str], value: str) -> bool:
    if not patterns:
        return False
    v = str(value)
    for p in patterns:
        ps = str(p).strip()
        if not ps:
            continue
        if ps == "*":
            return True
        if fnmatch.fnmatchcase(v, ps):
            return True
    return False


def _coerce_bool(x: Any) -> bool:
    if isinstance(x, bool):
        return x
    if x is None:
        return False
    if isinstance(x, (int, float)):
        return x != 0
    s = str(x).strip().lower()
    return s in ("1", "true", "yes", "y", "on")


def _evaluate_conditions(
    *,
    conditions: Mapping[str, Any],
    principal_attrs: Mapping[str, Any],
    env: Mapping[str, Any],
    resource_attrs: Mapping[str, Any],
    resource_kind: Optional[str],
    resource_id: Optional[str],
    resource_owner: Optional[str],
    resource_tags: Tuple[str, ...],
    principal: Principal,
    resource: Optional[Resource],
) -> Tuple[bool, str]:
    """
    Мини-DSL условий, намеренно ограниченный для безопасности.

    Поддерживаемые ключи:
    - require_all: dict[str, Any]  (principal.* / resource.* / env.*)
    - require_any: dict[str, Sequence[Any]]
    - subject_in: Sequence[str]
    - subject_not_in: Sequence[str]
    - role_in: Sequence[str]
    - scope_in: Sequence[str]
    - resource_owner_only: bool
    - resource_tag_in: Sequence[str]
    - time_between_utc: {"start_hhmm": "09:00", "end_hhmm": "18:00"}  (по UTC)
    - purpose_in_env: Sequence[str]  (env.purpose)
    """
    if not conditions:
        return True, "no_conditions"

    # subject lists
    if "subject_in" in conditions:
        allowed = {str(x) for x in (conditions.get("subject_in") or [])}
        if principal.subject not in allowed:
            return False, "subject_in_failed"

    if "subject_not_in" in conditions:
        blocked = {str(x) for x in (conditions.get("subject_not_in") or [])}
        if principal.subject in blocked:
            return False, "subject_not_in_failed"

    if "role_in" in conditions:
        allowed_roles = {str(x) for x in (conditions.get("role_in") or [])}
        if not set(principal.roles).intersection(allowed_roles):
            return False, "role_in_failed"

    if "scope_in" in conditions:
        allowed_scopes = {str(x) for x in (conditions.get("scope_in") or [])}
        ok = False
        for gs in principal.scopes:
            for want in allowed_scopes:
                if scope_implies(gs, want):
                    ok = True
                    break
            if ok:
                break
        if not ok:
            return False, "scope_in_failed"

    if _coerce_bool(conditions.get("resource_owner_only", False)):
        if resource is None:
            return False, "owner_only_no_resource"
        if resource.owner_subject is None or resource.owner_subject != principal.subject:
            return False, "owner_only_failed"

    if "resource_tag_in" in conditions:
        want_tags = {str(x) for x in (conditions.get("resource_tag_in") or [])}
        if not set(resource_tags).intersection(want_tags):
            return False, "resource_tag_in_failed"

    if "purpose_in_env" in conditions:
        allowed = {str(x) for x in (conditions.get("purpose_in_env") or [])}
        purpose = str(env.get("purpose") or "")
        if purpose not in allowed:
            return False, "purpose_in_env_failed"

    if "time_between_utc" in conditions:
        window = dict(conditions.get("time_between_utc") or {})
        start = str(window.get("start_hhmm") or "")
        end = str(window.get("end_hhmm") or "")
        if not start or not end:
            return False, "time_between_utc_invalid"
        if not _utc_now_in_window(start, end):
            return False, "time_between_utc_failed"

    # require_all, require_any
    if "require_all" in conditions:
        req_all = dict(conditions.get("require_all") or {})
        for k, v in req_all.items():
            actual = _resolve_selector(k, principal_attrs, resource_attrs, env, principal, resource)
            if actual != v:
                return False, f"require_all_failed:{k}"

    if "require_any" in conditions:
        req_any = dict(conditions.get("require_any") or {})
        for k, candidates in req_any.items():
            actual = _resolve_selector(k, principal_attrs, resource_attrs, env, principal, resource)
            if actual in set(candidates or []):
                return True, f"require_any_ok:{k}"
        return False, "require_any_failed"

    return True, "conditions_ok"


def _resolve_selector(
    selector: str,
    principal_attrs: Mapping[str, Any],
    resource_attrs: Mapping[str, Any],
    env: Mapping[str, Any],
    principal: Principal,
    resource: Optional[Resource],
) -> Any:
    """
    Разрешает селекторы:
    - principal.subject, principal.tenant_id
    - principal.attr.<key>
    - resource.kind, resource.resource_id, resource.tenant_id
    - resource.attr.<key>
    - env.<key>
    """
    s = str(selector).strip()
    if s == "principal.subject":
        return principal.subject
    if s == "principal.tenant_id":
        return principal.tenant_id
    if s.startswith("principal.attr."):
        return principal_attrs.get(s[len("principal.attr.") :])
    if s == "resource.kind":
        return resource.kind if resource else None
    if s == "resource.resource_id":
        return resource.resource_id if resource else None
    if s == "resource.tenant_id":
        return resource.tenant_id if resource else None
    if s.startswith("resource.attr."):
        return resource_attrs.get(s[len("resource.attr.") :])
    if s.startswith("env."):
        return env.get(s[len("env.") :])
    return None


def _utc_now_in_window(start_hhmm: str, end_hhmm: str) -> bool:
    """
    Окно по UTC. Поддерживает окно через полночь.
    """
    try:
        sh, sm = start_hhmm.split(":")
        eh, em = end_hhmm.split(":")
        sh_i, sm_i = int(sh), int(sm)
        eh_i, em_i = int(eh), int(em)
        if not (0 <= sh_i <= 23 and 0 <= eh_i <= 23 and 0 <= sm_i <= 59 and 0 <= em_i <= 59):
            return False
    except Exception:
        return False

    now = time.gmtime()
    cur = now.tm_hour * 60 + now.tm_min
    start = sh_i * 60 + sm_i
    end = eh_i * 60 + em_i

    if start <= end:
        return start <= cur <= end
    # window crosses midnight
    return cur >= start or cur <= end


class PermissionEngine:
    """
    Основной движок. По умолчанию deny (Zero Trust).
    """

    def __init__(
        self,
        *,
        provider: PermissionProvider,
        policy: Optional[Policy] = None,
        audit_sink: Optional[AuditSink] = None,
        cache_ttl_s: int = 5,
        cache_max: int = 4096,
        request_id_factory: Optional[Callable[[], str]] = None,
        correlation_id_resolver: Optional[Callable[[PermissionRequest], Optional[str]]] = None,
        secret_for_ids: Optional[bytes] = None,
    ) -> None:
        self._provider = provider
        self._policy = policy or CompositePolicy(
            "root",
            policies=[
                ABACPolicy(provider=provider, policy_id="abac"),
                RBACPolicy(provider=provider, policy_id="rbac"),
            ],
        )
        self._audit = audit_sink or NullAuditSink()
        self._cache_ttl_s = int(cache_ttl_s)
        self._cache_max = int(cache_max)
        self._cache: MutableMapping[str, Tuple[float, PermissionDecision]] = {}
        self._cache_lock = asyncio.Lock()
        self._request_id_factory = request_id_factory or self._default_request_id_factory
        self._correlation_id_resolver = correlation_id_resolver
        self._secret_for_ids = secret_for_ids or b"agent_mash.permissions"

    def _default_request_id_factory(self) -> str:
        raw = f"{time.time_ns()}:{id(self)}".encode("utf-8")
        return hmac.new(self._secret_for_ids, raw, hashlib.sha256).hexdigest()

    async def authorize(
        self,
        request: PermissionRequest,
        *,
        correlation_id: Optional[str] = None,
        reason_hint: Optional[str] = None,
        use_cache: bool = True,
    ) -> PermissionDecision:
        req = request.normalized()
        corr = correlation_id
        if corr is None and self._correlation_id_resolver is not None:
            try:
                corr = self._correlation_id_resolver(req)
            except Exception:
                corr = None

        ctx = PolicyContext(
            now_epoch_s=int(time.time()),
            request_id=self._request_id_factory(),
            correlation_id=corr,
            reason_hint=reason_hint,
            extra={},
        )

        if use_cache:
            cached = await self._cache_get(req, ctx)
            if cached is not None:
                await self._emit_audit(req, ctx, cached, cached.metadata)
                return cached

        # Default deny if invalid
        if not req.action or not req.principal.subject or not req.principal.tenant_id:
            d = PermissionDecision.deny(policy_id="engine", reason="invalid_request")
            await self._emit_audit(req, ctx, d, d.metadata)
            await self._cache_put(req, ctx, d)
            return d

        # Evaluate policy chain
        try:
            d = await self._policy.evaluate(req, ctx)
        except PermissionError:
            raise
        except Exception as e:
            raise PolicyError(f"policy_eval_error:{e}") from e

        # Zero Trust default: NOT_APPLICABLE => DENY
        if d.decision == Decision.NOT_APPLICABLE:
            d = PermissionDecision.deny(policy_id="engine", reason="default_deny", metadata={"source": d.policy_id})

        await self._emit_audit(req, ctx, d, d.metadata)
        await self._cache_put(req, ctx, d)
        return d

    async def require(
        self,
        request: PermissionRequest,
        *,
        correlation_id: Optional[str] = None,
        reason_hint: Optional[str] = None,
        use_cache: bool = True,
        on_denied: Optional[Callable[[PermissionDecision], Exception]] = None,
    ) -> None:
        d = await self.authorize(
            request,
            correlation_id=correlation_id,
            reason_hint=reason_hint,
            use_cache=use_cache,
        )
        if d.decision != Decision.ALLOW:
            if on_denied is not None:
                raise on_denied(d)
            raise PermissionError(d.reason or "permission_denied")

    async def _cache_get(self, req: PermissionRequest, ctx: PolicyContext) -> Optional[PermissionDecision]:
        if self._cache_ttl_s <= 0 or self._cache_max <= 0:
            return None
        key = _hash_request(req, ctx)
        async with self._cache_lock:
            v = self._cache.get(key)
            if v is None:
                return None
            expires_at, decision = v
            if time.time() >= expires_at:
                self._cache.pop(key, None)
                return None
            return decision

    async def _cache_put(self, req: PermissionRequest, ctx: PolicyContext, decision: PermissionDecision) -> None:
        if self._cache_ttl_s <= 0 or self._cache_max <= 0:
            return
        key = _hash_request(req, ctx)
        async with self._cache_lock:
            if len(self._cache) >= self._cache_max:
                # simple eviction: drop one arbitrary key (fast, predictable)
                try:
                    self._cache.pop(next(iter(self._cache.keys())))
                except Exception:
                    self._cache.clear()
            self._cache[key] = (time.time() + self._cache_ttl_s, decision)

    async def _emit_audit(
        self,
        req: PermissionRequest,
        ctx: PolicyContext,
        decision: PermissionDecision,
        metadata: Mapping[str, Any],
    ) -> None:
        try:
            ev = AuditEvent(
                at_epoch_s=ctx.now_epoch_s,
                request_id=ctx.request_id,
                correlation_id=ctx.correlation_id,
                principal_subject=req.principal.subject,
                principal_tenant=req.principal.tenant_id,
                action=req.action,
                resource_kind=req.resource.kind if req.resource else None,
                resource_id=req.resource.resource_id if req.resource else None,
                resource_tenant=req.resource.tenant_id if req.resource else None,
                decision=str(decision.decision.value),
                policy_id=decision.policy_id,
                reason=decision.reason,
                metadata=dict(metadata or {}),
            )
            await self._audit.emit(ev)
        except Exception:
            # Аудит не должен ломать авторизацию
            return
