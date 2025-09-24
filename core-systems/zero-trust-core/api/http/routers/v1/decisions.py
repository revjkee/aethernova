# zero-trust-core/api/http/routers/v1/decisions.py
from __future__ import annotations

import fnmatch
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, root_validator, validator

# Совместимость со state из server.py
# server.py устанавливает app.state.app_state с полями cfg, tokens, ratelimit
def _get_app_state(request: Request):
    state = getattr(request.app.state, "app_state", None)
    if state is None:
        raise HTTPException(status_code=500, detail="app state not initialized")
    return state


# ---------------------------
# Pydantic модели запроса/ответа
# ---------------------------

class SubjectModel(BaseModel):
    subject: Optional[str] = Field(None, description="Канонический ID: user:alice, service:payments-api")
    tenant_id: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class DeviceModel(BaseModel):
    device_id: Optional[str] = None
    platform: Optional[str] = Field(None, description="windows|macos|linux|ios|android")
    posture: Optional[str] = Field(None, description="healthy|out_of_date|unverified|compromised")
    compliant: Optional[bool] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)


class NetworkModel(BaseModel):
    ip: Optional[str] = None
    private_network: Optional[bool] = None
    matched_cidrs: List[str] = Field(default_factory=list)


class SessionModel(BaseModel):
    session_id: Optional[str] = None
    mfa_passed: Optional[bool] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)


class TokenMeta(BaseModel):
    token: Optional[str] = None
    token_type: Optional[str] = Field(None, description="access|refresh|id")
    kid: Optional[str] = None
    aud: List[str] = Field(default_factory=list)


class DecisionRequest(BaseModel):
    action: str = Field(..., min_length=1)
    resource: str = Field(..., min_length=1, description="URI, ARN, CRN или логический идентификатор ресурса")
    subject: SubjectModel = Field(default_factory=SubjectModel)
    device: Optional[DeviceModel] = None
    network: Optional[NetworkModel] = None
    session: Optional[SessionModel] = None
    token: Optional[TokenMeta] = None
    context: Dict[str, Any] = Field(default_factory=dict)

    @validator("action", "resource")
    def no_whitespace(cls, v: str) -> str:
        if v.strip() != v or not v:
            raise ValueError("invalid value")
        return v


class Obligation(BaseModel):
    type: str
    params: Dict[str, Any] = Field(default_factory=dict)


class MatchTrace(BaseModel):
    policy_id: Optional[str] = None
    statement_sid: Optional[str] = None
    effect: Literal["allow", "deny"]
    actions: List[str] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=list)
    reason: Optional[str] = None


class DecisionResponse(BaseModel):
    allowed: bool
    effect: Literal["allow", "deny"]
    reasons: List[str] = Field(default_factory=list)
    matched: List[MatchTrace] = Field(default_factory=list)
    used_scopes: List[str] = Field(default_factory=list)
    matched_roles: List[str] = Field(default_factory=list)
    rebac_path: List[str] = Field(default_factory=list)
    obligations: List[Obligation] = Field(default_factory=list)
    risk_level: Optional[str] = None
    at: float = Field(default_factory=lambda: time.time())
    policy_version: Optional[str] = None
    request_id: Optional[str] = None


# ---------------------------
# Политики: модель, загрузка, движок
# ---------------------------

class Statement(BaseModel):
    sid: Optional[str] = None
    effect: Literal["allow", "deny"]
    actions: List[str] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    when: Dict[str, Any] = Field(default_factory=dict)  # простые equals для subject.attributes и context

class PolicyDoc(BaseModel):
    version: str = "1"
    id: Optional[str] = None
    statements: List[Statement] = Field(default_factory=list)

    @root_validator
    def check_statements(cls, values):
        stmts = values.get("statements") or []
        if not stmts:
            raise ValueError("policy must contain at least one statement")
        return values


@dataclass
class PolicyCache:
    policy: PolicyDoc
    loaded_at: float
    ttl: float
    path: Optional[Path]


def _load_policy_from_env_or_file() -> PolicyCache:
    ttl = float(os.getenv("ZTC_DECISIONS_POLICY_TTL", "5.0"))  # сек, для горячей перезагрузки файла
    path_str = os.getenv("ZTC_DECISIONS_POLICY_PATH", "")
    if path_str:
        p = Path(path_str)
        if not p.exists():
            raise FileNotFoundError(f"policy file not found: {p}")
        doc = PolicyDoc.parse_obj(json.loads(p.read_text(encoding="utf-8")))
        return PolicyCache(policy=doc, loaded_at=time.time(), ttl=ttl, path=p)

    raw = os.getenv("ZTC_DECISIONS_POLICY_JSON")
    if raw:
        doc = PolicyDoc.parse_obj(json.loads(raw))
    else:
        # Безопасный дефолт: deny-all
        doc = PolicyDoc.parse_obj(
            {
                "version": "1",
                "id": "default-deny",
                "statements": [{"sid": "deny-all", "effect": "deny", "actions": ["*"], "resources": ["*"]}],
            }
        )
    return PolicyCache(policy=doc, loaded_at=time.time(), ttl=ttl, path=None)


def _maybe_reload(cache: PolicyCache) -> PolicyCache:
    if cache.path is None:
        return cache
    if time.time() - cache.loaded_at < cache.ttl:
        return cache
    try:
        doc = PolicyDoc.parse_obj(json.loads(cache.path.read_text(encoding="utf-8")))
        return PolicyCache(policy=doc, loaded_at=time.time(), ttl=cache.ttl, path=cache.path)
    except Exception:
        # При ошибке чтения оставляем последнюю валидную политику
        return cache


def _match_any(patterns: List[str], value: str) -> bool:
    if not patterns:
        return False
    for p in patterns:
        if p == "*" or fnmatch.fnmatchcase(value, p):
            return True
    return False


def _attrs_satisfy(when: Dict[str, Any], subject_attrs: Dict[str, Any], context: Dict[str, Any]) -> bool:
    if not when:
        return True
    # Поддерживаем адресацию "subject.attr" и "context.key"
    for k, expected in when.items():
        if k.startswith("subject."):
            key = k.split(".", 1)[1]
            actual = subject_attrs.get(key)
        elif k.startswith("context."):
            key = k.split(".", 1)[1]
            actual = context.get(key)
        else:
            # по умолчанию ищем в subject.attributes
            actual = subject_attrs.get(k)
        if actual != expected:
            return False
    return True


class PolicyEngine:
    def __init__(self) -> None:
        self.cache = _load_policy_from_env_or_file()

    def reload_if_needed(self) -> None:
        self.cache = _maybe_reload(self.cache)

    def evaluate(
        self,
        action: str,
        resource: str,
        subject: SubjectModel,
        context: Dict[str, Any],
    ) -> Tuple[Literal["allow", "deny"], List[MatchTrace], List[str], List[str]]:
        self.reload_if_needed()
        matched: List[MatchTrace] = []
        allow_hit = False
        deny_hit = False
        used_scopes: List[str] = []
        matched_roles: List[str] = []

        for st in self.cache.policy.statements:
            if not _match_any(st.actions or ["*"], action):
                continue
            if not _match_any(st.resources or ["*"], resource):
                continue
            role_ok = (not st.roles) or any(r in subject.roles for r in st.roles)
            scope_ok = (not st.scopes) or any(s in subject.scopes for s in st.scopes)
            when_ok = _attrs_satisfy(st.when, subject.attributes or {}, context or {})
            if not (role_ok and scope_ok and when_ok):
                continue

            matched.append(
                MatchTrace(
                    policy_id=self.cache.policy.id,
                    statement_sid=st.sid,
                    effect=st.effect,
                    actions=st.actions or ["*"],
                    resources=st.resources or ["*"],
                    reason="matched"
                )
            )
            if st.roles:
                matched_roles.extend([r for r in subject.roles if r in st.roles])
            if st.scopes:
                used_scopes.extend([s for s in subject.scopes if s in st.scopes])
            if st.effect == "deny":
                deny_hit = True
            elif st.effect == "allow":
                allow_hit = True

        # Deny overrides
        effect: Literal["allow", "deny"] = "deny" if deny_hit else ("allow" if allow_hit else "deny")
        return effect, matched, sorted(set(used_scopes)), sorted(set(matched_roles))

    @property
    def version(self) -> str:
        return self.cache.policy.version


# ---------------------------
# Опциональный ReBAC интерфейс
# ---------------------------

class ReBACAuthorizer:
    """
    Опциональная прослойка для движка отношений.
    Ожидается, что в app.state.app_state.rebac будет объект с методом:
      async def check(self, object_str: str, relation: str, subject_str: str, context: dict) -> CheckResult
    где CheckResult имеет поля: allowed: bool, path: List[str]
    Если отсутствует — ReBAC шаг пропускается.
    """
    def __init__(self, impl: Any | None):
        self.impl = impl

    async def check(self, resource: str, relation: str, subject: str, context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        if not self.impl:
            return True, []  # если ReBAC не сконфигурирован — пропускаем
        try:
            res = await self.impl.check(resource, relation, subject, context=context)
            return bool(getattr(res, "allowed", False)), list(getattr(res, "path", []))
        except Exception:
            return False, []


# ---------------------------
# Зависимости роутера
# ---------------------------

@dataclass
class DecisionsDeps:
    policy: PolicyEngine
    rebac: ReBACAuthorizer

def _deps(request: Request) -> DecisionsDeps:
    app_state = _get_app_state(request)
    # попытка взять внешний rebac из state; иначе None
    rebac_impl = getattr(app_state, "rebac", None)
    return DecisionsDeps(policy=PolicyEngine(), rebac=ReBACAuthorizer(rebac_impl))


# ---------------------------
# Роутер v1
# ---------------------------

router = APIRouter(prefix="/api/v1/decisions", tags=["decisions"])


@router.post("/check", response_model=DecisionResponse)
async def decisions_check(
    req: DecisionRequest,
    request: Request,
    deps: DecisionsDeps = Depends(_deps),
    authorization: Optional[str] = Header(default=None, convert_underscores=False),
):
    """
    Принимает запрос на принятие решения для пары action-resource с контекстом субъекта.
    Правила: deny-overrides, трассировка совпавших стейтментов, ReBAC-проверка (если включена).
    """
    app_state = _get_app_state(request)
    request_id = getattr(request.scope, "request_id", None) or request.headers.get("x-request-id")

    # Интроспекция токена (локальная, неблокирующая). Возвращает active=false по умолчанию.
    # Если нужно — можно отказать при inactive в политике через "when": {"context.token_active": true}.
    token_active = False
    if req.token and req.token.token:
        payload = await app_state.tokens.introspect(req.token.token)
        token_active = bool(payload.get("active", False))

    # Готовим контекст для when
    context = dict(req.context)
    context.update({
        "ip": (req.network.ip if req.network else None),
        "mfa_passed": (req.session.mfa_passed if req.session else None),
        "device_posture": (req.device.posture if req.device else None),
        "token_active": token_active,
    })

    # Оценка политики
    effect, matched, used_scopes, matched_roles = deps.policy.evaluate(
        action=req.action,
        resource=req.resource,
        subject=req.subject,
        context=context,
    )

    # Дополнительно (необязательно) проверяем ReBAC: relation=viewer для read, editor для write, owner для delete.
    # В реальном проекте маппинг relation<->action задаётся политикой. Здесь даём безопасный дефолт.
    relation_map = {
        "get": "viewer",
        "read": "viewer",
        "list": "viewer",
        "create": "editor",
        "write": "editor",
        "update": "editor",
        "delete": "owner",
        "manage": "owner",
    }
    relation = relation_map.get(req.action.lower(), "viewer")
    rebac_ok, rebac_path = await deps.rebac.check(req.resource, relation, req.subject.subject or "anonymous", context)

    # Денай-оверрайд: если политика deny — отклоняем независимо от ReBAC;
    # если политика allow, но ReBAC не подтверждает — отклоняем.
    allowed = (effect == "allow") and rebac_ok

    reasons: List[str] = []
    if effect == "deny":
        reasons.append("policy_denied")
    if effect == "allow" and not rebac_ok:
        reasons.append("rebac_denied")

    # Обязательства: если политика matched и требует MFA (пример: when: {"subject.mfa_required": true})
    obligations: List[Obligation] = []
    if not (req.session and req.session.mfa_passed):
        # Если в контексте указали, что требуется MFA для данного действия, возвращаем обязательство
        if any(st.when.get("context.mfa_required") is True for st in deps.policy.cache.policy.statements):
            obligations.append(Obligation(type="require_mfa", params={"reason": "policy_requires_mfa"}))

    return DecisionResponse(
        allowed=allowed,
        effect="allow" if allowed else "deny",
        reasons=reasons,
        matched=matched,
        used_scopes=used_scopes,
        matched_roles=matched_roles,
        rebac_path=rebac_path,
        obligations=obligations,
        risk_level=req.context.get("risk_level") if req.context else None,
        policy_version=deps.policy.version,
        request_id=request_id,
    )


class BatchDecisionRequest(BaseModel):
    requests: List[DecisionRequest]


class BatchDecisionResponse(BaseModel):
    results: List[DecisionResponse]
    at: float = Field(default_factory=lambda: time.time())


@router.post("/batch_check", response_model=BatchDecisionResponse)
async def decisions_batch_check(
    req: BatchDecisionRequest,
    request: Request,
    deps: DecisionsDeps = Depends(_deps),
):
    results: List[DecisionResponse] = []
    for r in req.requests:
        single = await decisions_check(r, request, deps)  # переиспользуем однотипную логику
        results.append(single)
    return BatchDecisionResponse(results=results)


# Утилита для подключения роутера из server.py
def get_router() -> APIRouter:
    return router
