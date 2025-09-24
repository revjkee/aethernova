# security-core/api/http/routers/v1/authz.py
# Industrial-grade Authorization Router (RBAC/ABAC, OPA fallback, cache, explain)
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

import httpx
import yaml
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, NonNegativeInt, StrictBool, StrictInt, StrictStr, constr, root_validator

logger = logging.getLogger("security_core.authz")
logger.setLevel(logging.INFO)


# =========================
# Models (Pydantic)
# =========================

TenantId = constr(strip_whitespace=True, min_length=1, max_length=128)
PrincipalId = constr(strip_whitespace=True, min_length=1, max_length=256)
ResourceId = constr(strip_whitespace=True, min_length=1, max_length=512)
ActionStr = constr(strip_whitespace=True, min_length=1, max_length=128)
LabelKey = constr(strip_whitespace=True, min_length=1, max_length=64)
LabelVal = constr(strip_whitespace=True, min_length=1, max_length=128)


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Decision(str, Enum):
    allow = "ALLOW"
    deny = "DENY"


class ActorType(str, Enum):
    user = "USER"
    service = "SERVICE"
    device = "DEVICE"
    unknown = "UNKNOWN"


class Principal(BaseModel):
    type: ActorType = Field(..., description="Тип субъекта")
    id: PrincipalId = Field(..., description="Идентификатор субъекта")
    tenant: Optional[TenantId] = Field(None, description="ID арендатора/организации")
    roles: List[StrictStr] = Field(default_factory=list, description="Роли RBAC в текущем контексте")
    attrs: Dict[StrictStr, StrictStr] = Field(default_factory=dict, description="Атрибуты субъекта (ABAC)")


class Resource(BaseModel):
    type: StrictStr = Field(..., min_length=1, max_length=128, description="Тип ресурса (service/db/bucket/pod/...)")
    id: ResourceId = Field(..., description="Уникальный ID ресурса (URI/ARN)")
    owner_tenant: Optional[TenantId] = Field(None, description="Владелец ресурса")
    labels: Dict[LabelKey, LabelVal] = Field(default_factory=dict, description="Метки/атрибуты ресурса")


class RequestContext(BaseModel):
    ip: Optional[StrictStr] = Field(None, description="IP источника")
    user_agent: Optional[StrictStr] = Field(None, description="User-Agent")
    correlation_id: Optional[StrictStr] = Field(None, description="Корреляционный ID")
    trace_id: Optional[StrictStr] = Field(None, description="W3C Trace ID")
    span_id: Optional[StrictStr] = Field(None, description="W3C Span ID")
    env: Optional[Literal["dev", "stage", "prod"]] = "prod"


class AuthzCheckRequest(BaseModel):
    subject: Principal
    action: ActionStr
    resource: Resource
    context: Optional[RequestContext] = None


class Obligation(BaseModel):
    key: StrictStr
    value: StrictStr


class ExplainFrame(BaseModel):
    rule_id: StrictStr
    effect: Decision
    matched: StrictBool
    reason: StrictStr


class AuthzCheckResponse(BaseModel):
    decision: Decision
    policy_id: StrictStr
    rule_id: Optional[StrictStr] = None
    obligations: List[Obligation] = Field(default_factory=list)
    reason: Optional[StrictStr] = None
    explain: Optional[List[ExplainFrame]] = None
    cached: StrictBool = False
    latency_ms: NonNegativeInt = 0


class BatchAuthzRequest(BaseModel):
    requests: List[AuthzCheckRequest]


class BatchAuthzResponse(BaseModel):
    decisions: List[AuthzCheckResponse]
    total_latency_ms: NonNegativeInt


# =========================
# In-memory TTL cache (async-safe)
# =========================

class _TTLCache:
    def __init__(self, ttl_seconds: int = 5, max_items: int = 10000) -> None:
        self._ttl = ttl_seconds
        self._max = max_items
        self._data: Dict[str, Tuple[float, AuthzCheckResponse]] = {}
        self._lock = asyncio.Lock()

    def _now(self) -> float:
        return time.monotonic()

    async def get(self, key: str) -> Optional[AuthzCheckResponse]:
        async with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            exp, value = item
            if self._now() > exp:
                self._data.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: AuthzCheckResponse) -> None:
        async with self._lock:
            if len(self._data) >= self._max:
                # простая эвакуация: удалить произвольный элемент
                self._data.pop(next(iter(self._data)), None)
            self._data[key] = (self._now() + self._ttl, value)


# =========================
# Policy Engine (RBAC/ABAC)
# =========================

@dataclass
class PolicyRule:
    rule_id: str
    effect: Decision
    actions: List[str]
    resource_types: List[str]
    allowed_roles: List[str]
    where: Dict[str, Any]  # простые выражения для ABAC (equal/in/tenant match)
    obligations: Dict[str, str]
    priority: int = 100  # ниже — важнее

    def matches(self, req: AuthzCheckRequest) -> Tuple[bool, str]:
        reasons: List[str] = []
        if self.actions and req.action not in self.actions and "*" not in self.actions:
            return False, f"action {req.action} not in {self.actions}"
        if self.resource_types and req.resource.type not in self.resource_types and "*" not in self.resource_types:
            return False, f"resource.type {req.resource.type} not in {self.resource_types}"

        # RBAC
        if self.allowed_roles and not (set(map(str.lower, req.subject.roles)) & set(map(str.lower, self.allowed_roles))):
            reasons.append("no intersect roles")

        # ABAC 'where' (минималистичная интерпретация)
        for key, expected in self.where.items():
            actual = _extract_attr(req, key)
            if isinstance(expected, dict):
                if "$in" in expected:
                    if actual not in expected["$in"]:
                        return False, f"{key} not in {expected['$in']}"
                elif "$neq" in expected:
                    if actual == expected["$neq"]:
                        return False, f"{key} equals forbidden {expected['$neq']}"
                elif "$exists" in expected:
                    exists = actual is not None
                    if bool(expected["$exists"]) != exists:
                        return False, f"{key} exists={exists} mismatch"
                else:
                    return False, f"unsupported operator for {key}"
            else:
                if str(actual) != str(expected):
                    return False, f"{key} != {expected}"

        # если указаны роли и ранее не было пересечения — уже видно
        if self.allowed_roles and "no intersect roles" in reasons:
            return False, reasons[0]

        return True, "matched"


def _extract_attr(req: AuthzCheckRequest, dotted: str) -> Any:
    # Поддержка путей вида subject.attrs.level, resource.labels.env, subject.tenant, resource.owner_tenant
    parts = dotted.split(".")
    obj: Any = req
    for p in parts:
        if isinstance(obj, BaseModel):
            obj = obj.dict()
        if isinstance(obj, dict):
            obj = obj.get(p)
        else:
            obj = getattr(obj, p, None)
        if obj is None:
            return None
    return obj


class PolicySet:
    def __init__(self, policy_id: str, rules: List[PolicyRule], default_decision: Decision = Decision.deny) -> None:
        self.policy_id = policy_id
        self.rules = sorted(rules, key=lambda r: r.priority)
        self.default_decision = default_decision


class LocalPolicyEngine:
    """Простой PDP: приоритетные правила, deny-by-default, explain-трассировка."""

    def __init__(self, loader: "PolicyLoader") -> None:
        self.loader = loader

    async def evaluate(self, req: AuthzCheckRequest, want_explain: bool = False) -> AuthzCheckResponse:
        start = time.perf_counter()
        policy = await self.loader.get_policy()
        frames: List[ExplainFrame] = []
        matched_rule: Optional[PolicyRule] = None
        reason = None

        for rule in policy.rules:
            ok, why = rule.matches(req)
            frame = ExplainFrame(rule_id=rule.rule_id, effect=rule.effect, matched=bool(ok), reason=why)
            if want_explain:
                frames.append(frame)
            if ok:
                matched_rule = rule
                reason = why
                decision = rule.effect
                obligations = [Obligation(key=k, value=v) for k, v in (rule.obligations or {}).items()]
                latency_ms = int((time.perf_counter() - start) * 1000)
                return AuthzCheckResponse(
                    decision=decision,
                    policy_id=self.loader.policy_id,
                    rule_id=rule.rule_id,
                    obligations=obligations,
                    reason=reason,
                    explain=frames if want_explain else None,
                    cached=False,
                    latency_ms=latency_ms,
                )

        # Default
        latency_ms = int((time.perf_counter() - start) * 1000)
        return AuthzCheckResponse(
            decision=policy.default_decision,
            policy_id=self.loader.policy_id,
            rule_id=None,
            obligations=[],
            reason="no rule matched",
            explain=frames if want_explain else None,
            cached=False,
            latency_ms=latency_ms,
        )


class OPAPolicyEngine:
    """OPA PDP. Если OPA недоступен — поднимаем исключение, чтобы вызвать fallback."""

    def __init__(self, url: str, package_path: str = "authz/allow") -> None:
        self._url = url.rstrip("/")
        self._path = package_path

    async def evaluate(self, req: AuthzCheckRequest, want_explain: bool = False) -> AuthzCheckResponse:
        start = time.perf_counter()
        payload = {"input": json.loads(req.json())}
        endpoint = f"{self._url}/v1/data/{self._path}"
        async with httpx.AsyncClient(timeout=2.5) as client:
            r = await client.post(endpoint, json=payload)
            r.raise_for_status()
            data = r.json()
        result = data.get("result", {})
        allow = bool(result.get("allow", False)) if isinstance(result, dict) else bool(result)
        reason = result.get("reason", "opa_result") if isinstance(result, dict) else "opa_result"
        rule_id = result.get("rule_id") if isinstance(result, dict) else None
        obligations = []
        if isinstance(result, dict) and "obligations" in result:
            obligations = [Obligation(key=k, value=str(v)) for k, v in result["obligations"].items()]
        latency_ms = int((time.perf_counter() - start) * 1000)
        return AuthzCheckResponse(
            decision=Decision.allow if allow else Decision.deny,
            policy_id=f"opa:{self._path}",
            rule_id=rule_id,
            obligations=obligations,
            reason=reason,
            explain=None,  # explain можно расширить через /v1/compile
            cached=False,
            latency_ms=latency_ms,
        )


# =========================
# Policy Loader (YAML with hot-reload)
# =========================

class PolicyLoader:
    """
    Загрузка политик из YAML:
    ---
    policy_id: "authz-baseline"
    default_decision: "DENY"
    rules:
      - rule_id: "allow_read_own_tenant"
        effect: "ALLOW"
        priority: 10
        actions: ["read","get","list"]
        resource_types: ["document","*"]
        allowed_roles: ["developer","viewer"]
        where:
          "subject.tenant": {"$in": ["t1","t2"]}
          "resource.labels.env": "prod"
        obligations:
          "mask_fields": "pii"
    """
    def __init__(self, path: Optional[str]) -> None:
        self._path = Path(path) if path else None
        self._cached: Optional[PolicySet] = None
        self._mtime: Optional[float] = None
        self.policy_id: str = "authz-local"

    async def get_policy(self) -> PolicySet:
        if not self._path:
            # Политика по умолчанию (все запреты)
            if not self._cached:
                self._cached = PolicySet(policy_id=self.policy_id, rules=[], default_decision=Decision.deny)
            return self._cached

        try:
            stat = self._path.stat()
        except FileNotFoundError:
            logger.warning("Policy file not found: %s", self._path)
            if not self._cached:
                self._cached = PolicySet(policy_id=self.policy_id, rules=[], default_decision=Decision.deny)
            return self._cached

        if self._cached is None or self._mtime is None or stat.st_mtime > self._mtime:
            with self._path.open("r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            pid = raw.get("policy_id", "authz-local")
            self.policy_id = pid
            default_decision = Decision(raw.get("default_decision", "DENY").upper())
            rules = []
            for r in raw.get("rules", []):
                rules.append(
                    PolicyRule(
                        rule_id=str(r.get("rule_id")),
                        effect=Decision(r.get("effect", "DENY").upper()),
                        actions=[str(a) for a in (r.get("actions") or [])] or ["*"],
                        resource_types=[str(t) for t in (r.get("resource_types") or [])] or ["*"],
                        allowed_roles=[str(x) for x in (r.get("allowed_roles") or [])],
                        where=r.get("where") or {},
                        obligations=r.get("obligations") or {},
                        priority=int(r.get("priority", 100)),
                    )
                )
            self._cached = PolicySet(policy_id=pid, rules=rules, default_decision=default_decision)
            self._mtime = stat.st_mtime
            logger.info("Policy reloaded: %s rules=%d", pid, len(rules))
        return self._cached


# =========================
# Router wiring
# =========================

router = APIRouter(prefix="/v1/authz", tags=["authz"])

# Конфигурация через ENV
OPA_URL = os.getenv("SECURITY_CORE_OPA_URL", "").strip()
POLICY_PATH = os.getenv("SECURITY_CORE_AUTHZ_POLICIES", "").strip()  # путь к YAML‑политике
CACHE_TTL = int(os.getenv("SECURITY_CORE_AUTHZ_CACHE_TTL_SECONDS", "5"))
CACHE_MAX = int(os.getenv("SECURITY_CORE_AUTHZ_CACHE_MAX_ITEMS", "10000"))

_cache = _TTLCache(ttl_seconds=CACHE_TTL, max_items=CACHE_MAX)
_loader = PolicyLoader(POLICY_PATH if POLICY_PATH else None)
_local_pdp = LocalPolicyEngine(_loader)
_opa_pdp = OPAPolicyEngine(OPA_URL) if OPA_URL else None


def _cache_key(req: AuthzCheckRequest) -> str:
    # Ключ кэша зависит от критичных полей
    payload = {
        "s": {"id": req.subject.id, "tenant": req.subject.tenant, "roles": sorted(req.subject.roles), "attrs": req.subject.attrs},
        "a": req.action,
        "r": {"type": req.resource.type, "id": req.resource.id, "owner": req.resource.owner_tenant, "labels": req.resource.labels},
        "e": req.context.env if req.context else "prod",
    }
    return uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(payload, sort_keys=True)).hex


async def _evaluate(req: AuthzCheckRequest, want_explain: bool = False) -> AuthzCheckResponse:
    # cache
    key = _cache_key(req)
    cached = await _cache.get(key)
    if cached and not want_explain:
        # Обновим latency для прозрачности не будем; пометим как cached
        return cached.copy(update={"cached": True})

    # try OPA first if configured
    if _opa_pdp:
        try:
            res = await _opa_pdp.evaluate(req, want_explain=False)
            await _cache.set(key, res)
            return res
        except Exception as e:
            logger.warning("OPA evaluate failed, fallback to local: %s", e)

    # local PDP
    res = await _local_pdp.evaluate(req, want_explain=want_explain)
    await _cache.set(key, res)
    return res


# =========================
# Dependencies (placeholder for real auth)
# =========================

async def get_request_context(request: Request) -> RequestContext:
    headers = request.headers
    return RequestContext(
        ip=headers.get("x-forwarded-for") or request.client.host if request.client else None,
        user_agent=headers.get("user-agent"),
        correlation_id=headers.get("x-correlation-id"),
        trace_id=headers.get("traceparent"),  # W3C Traceparent
        env=os.getenv("RUNTIME_ENV", "prod"),  # dev/stage/prod
    )


# =========================
# Endpoints
# =========================

@router.post("/check", response_model=AuthzCheckResponse, status_code=status.HTTP_200_OK)
async def check(req: AuthzCheckRequest, ctx: RequestContext = Depends(get_request_context)) -> AuthzCheckResponse:
    # Принудительно используем фактический контекст сети/трассировки, не доверяя клиенту
    if req.context is None:
        req.context = ctx
    else:
        # переопределяем чувствительные поля
        req.context.ip = ctx.ip
        req.context.user_agent = ctx.user_agent
        req.context.correlation_id = req.context.correlation_id or ctx.correlation_id
        req.context.trace_id = req.context.trace_id or ctx.trace_id
        req.context.env = req.context.env or ctx.env

    res = await _evaluate(req, want_explain=False)
    _log_decision("check", req, res)
    return res


@router.post("/batch", response_model=BatchAuthzResponse, status_code=status.HTTP_200_OK)
async def batch(payload: BatchAuthzRequest, ctx: RequestContext = Depends(get_request_context)) -> BatchAuthzResponse:
    start = time.perf_counter()
    requests_with_ctx = []
    for r in payload.requests:
        if r.context is None:
            r.context = ctx
        else:
            r.context.ip = ctx.ip
            r.context.user_agent = ctx.user_agent
            r.context.correlation_id = r.context.correlation_id or ctx.correlation_id
            r.context.trace_id = r.context.trace_id or ctx.trace_id
            r.context.env = r.context.env or ctx.env
        requests_with_ctx.append(r)

    results = await asyncio.gather(*[_evaluate(r, want_explain=False) for r in requests_with_ctx])
    total_latency_ms = int((time.perf_counter() - start) * 1000)
    for req, res in zip(requests_with_ctx, results):
        _log_decision("batch", req, res)
    return BatchAuthzResponse(decisions=results, total_latency_ms=total_latency_ms)


@router.post("/explain", response_model=AuthzCheckResponse, status_code=status.HTTP_200_OK)
async def explain(req: AuthzCheckRequest, ctx: RequestContext = Depends(get_request_context)) -> AuthzCheckResponse:
    if req.context is None:
        req.context = ctx
    else:
        req.context.ip = ctx.ip
        req.context.user_agent = ctx.user_agent
        req.context.correlation_id = req.context.correlation_id or ctx.correlation_id
        req.context.trace_id = req.context.trace_id or ctx.trace_id
        req.context.env = req.context.env or ctx.env

    # explain выключает кэш попадания (получим трассировку)
    res = await _local_pdp.evaluate(req, want_explain=True)
    _log_decision("explain", req, res)
    return res


@router.get("/health", status_code=status.HTTP_200_OK)
async def health() -> Dict[str, str]:
    status_local = "ok"
    status_opa = "disabled"
    if _opa_pdp:
        try:
            # быстрый ping OPA
            async with httpx.AsyncClient(timeout=1.0) as client:
                r = await client.get(f"{OPA_URL}/health")
                status_opa = "ok" if r.status_code < 500 else "degraded"
        except Exception:
            status_opa = "unreachable"
    return {"status": "ok", "local": status_local, "opa": status_opa}


@router.get("/introspect", status_code=status.HTTP_200_OK)
async def introspect() -> Dict[str, Any]:
    # Выдаем базовую информацию об активной политике
    policy = await _loader.get_policy()
    return {
        "policy_id": policy.policy_id,
        "rules": len(policy.rules),
        "default_decision": policy.default_decision,
        "cache_ttl_seconds": CACHE_TTL,
        "cache_max_items": CACHE_MAX,
        "opa_url": OPA_URL or None,
    }


# =========================
# Utilities
# =========================

def _log_decision(endpoint: str, req: AuthzCheckRequest, res: AuthzCheckResponse) -> None:
    try:
        logger.info(
            "authz decision endpoint=%s policy=%s rule=%s decision=%s subject=%s action=%s resource=%s tenant=%s cached=%s latency_ms=%s reason=%s",
            endpoint,
            res.policy_id,
            res.rule_id,
            res.decision,
            req.subject.id,
            req.action,
            f"{req.resource.type}:{req.resource.id}",
            req.subject.tenant,
            res.cached,
            res.latency_ms,
            (res.reason or "").replace("\n", " "),
        )
    except Exception:
        logger.exception("failed to log decision")


# =========================
# Example: local default policy bootstrap (optional, for dev)
# =========================
# Если переменная SECURITY_CORE_AUTHZ_POLICIES не задана, PolicyLoader загрузит пустой
# сет правил (deny-by-default). Для локальной разработки можно создать файл, например:
#
# policy_id: "authz-baseline"
# default_decision: "DENY"
# rules:
#   - rule_id: "allow_dev_read"
#     effect: "ALLOW"
#     priority: 10
#     actions: ["read","list","get"]
#     resource_types: ["*"]
#     allowed_roles: ["developer","security"]
#     where:
#       "context.env": "dev"
#     obligations: {}
#
# И задать путь:
#   export SECURITY_CORE_AUTHZ_POLICIES=./configs/authz.policy.yaml
#   export SECURITY_CORE_OPA_URL=http://opa:8181  # опционально
