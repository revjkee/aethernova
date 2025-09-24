# security-core/api/http/server.py
# Промышленный HTTP-сервер авторизации и управления политиками (Zero-Trust RBAC+ABAC)
# Зависимости: fastapi, uvicorn, pydantic, prometheus_client, (опционально) PyJWT
# Запуск: UVICORN_WORKERS=4 uvicorn server:app --host 0.0.0.0 --port 8080

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Literal

from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, Header, Path, Query, Body
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator, root_validator

try:
    import jwt  # PyJWT, опционально
except Exception:  # noqa: BLE001
    jwt = None  # будет фоллбек на анонимный режим

try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
except Exception as e:  # noqa: BLE001
    Counter = Histogram = None  # типы для mypy
    generate_latest = None
    CONTENT_TYPE_LATEST = "text/plain"
    logging.getLogger(__name__).warning("Prometheus недоступен: %s", e)

# =========================
# Конфигурация и логирование
# =========================

class Settings:
    SERVICE_NAME: str = os.getenv("SERVICE_NAME", "security-core")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    CORS_ORIGINS: List[str] = [o for o in os.getenv("CORS_ORIGINS", "*").split(",") if o]
    AUTH_JWT_SECRET: Optional[str] = os.getenv("AUTH_JWT_SECRET") or None
    AUTH_JWT_AUDIENCE: Optional[str] = os.getenv("AUTH_JWT_AUDIENCE") or None
    AUTH_JWT_ISSUER: Optional[str] = os.getenv("AUTH_JWT_ISSUER") or None
    ALLOW_ANONYMOUS: bool = os.getenv("ALLOW_ANONYMOUS", "false").lower() in ("1", "true", "yes")
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "600"))
    METRICS_ENABLED: bool = os.getenv("METRICS_ENABLED", "true").lower() in ("1", "true", "yes")


settings = Settings()

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(settings.SERVICE_NAME)

# =========================
# Метрики Prometheus
# =========================

if settings.METRICS_ENABLED and Counter and Histogram:
    HTTP_REQUESTS = Counter(
        "http_requests_total", "Total HTTP requests", ["method", "path", "status"]
    )
    HTTP_LATENCY = Histogram(
        "http_request_duration_seconds", "HTTP request latency", ["method", "path"]
    )
    DECISIONS = Counter(
        "authz_decisions_total", "Authorization decisions", ["decision", "tenant"]
    )
else:
    HTTP_REQUESTS = HTTP_LATENCY = DECISIONS = None  # type: ignore


# =========================
# Утилиты
# =========================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def gen_request_id() -> str:
    return str(uuid.uuid4())


def sha256_of(obj: Any) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sanitize_for_log(value: Any, max_len: int = 512) -> Any:
    try:
        s = json.dumps(value, ensure_ascii=False)
        if len(s) > max_len:
            return s[: max_len - 3] + "..."
        return json.loads(s)
    except Exception:
        return str(value)[:max_len]


# =========================
# Аутентификация (JWT или анонимная)
# =========================

class Principal(BaseModel):
    subject: str = "anonymous"
    scopes: List[str] = Field(default_factory=list)
    tenant: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


def auth_dependency(authorization: Optional[str] = Header(None)) -> Principal:
    if settings.AUTH_JWT_SECRET and jwt:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        try:
            options = {"verify_aud": bool(settings.AUTH_JWT_AUDIENCE)}
            decoded = jwt.decode(
                token,
                settings.AUTH_JWT_SECRET,
                algorithms=["HS256"],
                audience=settings.AUTH_JWT_AUDIENCE if settings.AUTH_JWT_AUDIENCE else None,
                issuer=settings.AUTH_JWT_ISSUER if settings.AUTH_JWT_ISSUER else None,
                options=options,
            )
            sub = decoded.get("sub") or "unknown"
            scopes = decoded.get("scope", "").split() if isinstance(decoded.get("scope"), str) else decoded.get("scopes", []) or []
            tenant = decoded.get("tenant") or decoded.get("tid")
            return Principal(subject=sub, scopes=scopes, tenant=tenant, raw=decoded)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")
    if settings.ALLOW_ANONYMOUS:
        return Principal()
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


# =========================
# Модели данных (Pydantic)
# =========================

DecisionLiteral = Literal["PERMIT", "DENY", "NOT_APPLICABLE", "INDETERMINATE"]
EffectLiteral = Literal["ALLOW", "DENY"]
EvaluationModeLiteral = Literal["DEFAULT", "DENY_BIASED", "PERMIT_BIASED"]

class DevicePosture(BaseModel):
    device_id: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    is_managed: Optional[bool] = None
    trust: Optional[str] = None
    compliance_tags: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

class SessionContext(BaseModel):
    session_id: Optional[str] = None
    mfa_level: Optional[int] = None
    auth_time: Optional[datetime] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    risk_reasons: List[str] = Field(default_factory=list)
    client_id: Optional[str] = None
    geohash: Optional[str] = None
    location: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)

class Subject(BaseModel):
    tenant_id: str
    principal_id: str
    principal_type: Optional[str] = None
    display_name: Optional[str] = None
    did: Optional[str] = None
    groups: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    device: Optional[DevicePosture] = None

class Environment(BaseModel):
    timestamp: Optional[datetime] = None
    ip: Optional[str] = None
    network_tags: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

class Resource(BaseModel):
    tenant_id: Optional[str] = None
    type: str
    id: str
    parent: Optional[str] = None
    ancestors: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    owners: List[str] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    project_id: Optional[str] = None

class Obligation(BaseModel):
    key: str = Field(regex=r"^[A-Za-z0-9_.:-]{1,64}$")
    value: Any = None

class SubjectSelector(BaseModel):
    principals: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    attributes_eq: Dict[str, Any] = Field(default_factory=dict)
    match: Optional[str] = None  # CEL-like

class ResourceSelector(BaseModel):
    type: Optional[str] = None
    ids: List[str] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    attributes_eq: Dict[str, Any] = Field(default_factory=dict)
    match: Optional[str] = None  # CEL-like

class Rule(BaseModel):
    id: str = Field(regex=r"^[A-Za-z0-9_.:-]{1,128}$")
    effect: EffectLiteral
    condition: Optional[str] = None
    subjects: Optional[SubjectSelector] = None
    resources: Optional[ResourceSelector] = None
    actions: List[str] = Field(min_items=1)
    obligations: List[Obligation] = Field(default_factory=list)
    description: Optional[str] = None
    priority: int = 0

class PolicyVersion(BaseModel):
    revision: int = Field(ge=1)
    version: str = Field(regex=r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$")
    published: bool = False
    author: Optional[str] = None
    change_notes: Optional[str] = None
    create_time: datetime = Field(default_factory=now_utc)

class SigningInfo(BaseModel):
    key_id: str
    algorithm: Literal["ed25519", "ecdsa_p256_sha256"]
    signature: str  # base64
    signed_payload: Optional[str] = None

class Target(BaseModel):
    subjects: Optional[SubjectSelector] = None
    resources: Optional[ResourceSelector] = None
    actions: List[str] = Field(default_factory=list)

class Policy(BaseModel):
    name: str = Field(regex=r"^tenants\/[A-Za-z0-9_.-]{1,128}\/policies\/[A-Za-z0-9_.-]{1,128}$")
    uid: Optional[str] = None
    tenant_id: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    priority: int = 0
    target: Optional[Target] = None
    rules: List[Rule]
    applies_to_actions: List[str] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    version: PolicyVersion
    etag: Optional[str] = None
    signature: Optional[SigningInfo] = None
    create_time: datetime = Field(default_factory=now_utc)
    update_time: datetime = Field(default_factory=now_utc)
    disabled: bool = False

    @validator("tenant_id")
    def tenant_id_non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("tenant_id must be non-empty")
        return v

class PolicyBundle(BaseModel):
    tenant_id: str
    etag: str
    policies: List[Policy]
    create_time: datetime = Field(default_factory=now_utc)

# PDP запросы/ответы

class CheckAccessRequestModel(BaseModel):
    tenant_id: str
    subject: Subject
    action: str
    resource: Resource
    session: Optional[SessionContext] = None
    environment: Optional[Environment] = None
    mode: EvaluationModeLiteral = "DEFAULT"
    include_explanation: bool = False
    include_obligations: bool = True
    policy_names: List[str] = Field(default_factory=list)
    request_id: Optional[str] = None

class PolicyMatch(BaseModel):
    policy_name: str
    rule_id: str
    effect: EffectLiteral
    matched: bool
    detail: Optional[str] = None
    condition: Optional[str] = None
    policy_priority: int = 0
    rule_priority: int = 0

class Explanation(BaseModel):
    decision: DecisionLiteral
    reasons: List[str] = Field(default_factory=list)
    matches: List[PolicyMatch] = Field(default_factory=list)

class CheckAccessResponseModel(BaseModel):
    decision: DecisionLiteral
    obligations: List[Obligation] = Field(default_factory=list)
    explanation: Optional[Explanation] = None
    status: Optional[Dict[str, Any]] = None
    bundle_etag: Optional[str] = None

class BatchCheckAccessRequestModel(BaseModel):
    requests: List[CheckAccessRequestModel]

class BatchCheckAccessResponseModel(BaseModel):
    responses: List[CheckAccessResponseModel]

class ListEffectivePermissionsRequestModel(BaseModel):
    tenant_id: str
    subject: Subject
    resource: Resource
    session: Optional[SessionContext] = None
    environment: Optional[Environment] = None
    mode: EvaluationModeLiteral = "DEFAULT"

class ListEffectivePermissionsResponseModel(BaseModel):
    permitted_actions: List[str]
    bundle_etag: Optional[str] = None
    explanation: Optional[Explanation] = None

class ExplainDecisionRequestModel(BaseModel):
    request: CheckAccessRequestModel

class ExplainDecisionResponseModel(BaseModel):
    explanation: Explanation


# =========================
# Хранилище политик (in-memory)
# =========================

class PolicyStore:
    def __init__(self) -> None:
        self._policies: Dict[str, Policy] = {}
        self._lock = threading.RLock()

    def _compute_etag(self, p: Policy) -> str:
        copy = json.loads(p.json())
        copy.pop("etag", None)
        return sha256_of(copy)

    def create(self, policy: Policy) -> Policy:
        with self._lock:
            if policy.name in self._policies:
                raise HTTPException(status_code=409, detail="Policy already exists")
            policy.uid = policy.uid or str(uuid.uuid4())
            policy.create_time = now_utc()
            policy.update_time = policy.create_time
            policy.etag = self._compute_etag(policy)
            self._policies[policy.name] = policy
            return policy

    def update(self, policy: Policy) -> Policy:
        with self._lock:
            existing = self._policies.get(policy.name)
            if not existing:
                raise HTTPException(status_code=404, detail="Policy not found")
            # Если передан etag, проверим
            if policy.etag and policy.etag != existing.etag:
                raise HTTPException(status_code=409, detail="ETag mismatch")
            # Перезапишем неизменяемые
            policy.uid = existing.uid
            policy.create_time = existing.create_time
            policy.update_time = now_utc()
            policy.etag = self._compute_etag(policy)
            self._policies[policy.name] = policy
            return policy

    def patch(self, name: str, patch_doc: Dict[str, Any]) -> Policy:
        with self._lock:
            existing = self._policies.get(name)
            if not existing:
                raise HTTPException(status_code=404, detail="Policy not found")
            # Применим частичное обновление
            base = existing.dict()
            base.update(patch_doc)
            updated = Policy(**base)
            updated.uid = existing.uid
            updated.create_time = existing.create_time
            updated.update_time = now_utc()
            updated.etag = self._compute_etag(updated)
            self._policies[name] = updated
            return updated

    def delete(self, name: str, etag: Optional[str]) -> None:
        with self._lock:
            existing = self._policies.get(name)
            if not existing:
                raise HTTPException(status_code=404, detail="Policy not found")
            if etag and etag != existing.etag:
                raise HTTPException(status_code=409, detail="ETag mismatch")
            del self._policies[name]

    def get(self, name: str) -> Policy:
        with self._lock:
            p = self._policies.get(name)
            if not p:
                raise HTTPException(status_code=404, detail="Policy not found")
            return p

    def list(self, tenant: str) -> List[Policy]:
        with self._lock:
            return sorted(
                [p for p in self._policies.values() if p.tenant_id == tenant and not p.disabled],
                key=lambda x: x.priority,
                reverse=True,
            )

    def bundle(self, tenant: str) -> PolicyBundle:
        with self._lock:
            ps = self.list(tenant)
            etag = sha256_of([p.etag for p in ps])
            return PolicyBundle(tenant_id=tenant, etag=etag, policies=ps)


POLICIES = PolicyStore()


# =========================
# Безопасный интерпретатор условий (подмножество)
# =========================

import ast

class SafeEvalError(Exception):
    pass

ALLOWED_NODES = (
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp,
    ast.Compare, ast.Name, ast.Load, ast.Constant,
    ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE,
    ast.Subscript, ast.Attribute, ast.Index, ast.In, ast.NotIn, ast.Is, ast.IsNot,
)

def safe_eval(expr: str, context: Dict[str, Any]) -> bool:
    try:
        parsed = ast.parse(expr, mode="eval")
    except Exception as e:  # noqa: BLE001
        raise SafeEvalError(f"Parse error: {e}")

    for node in ast.walk(parsed):
        if not isinstance(node, ALLOWED_NODES):
            raise SafeEvalError(f"Illegal node: {type(node).__name__}")

    def _eval(node: ast.AST) -> Any:
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id not in context:
                raise SafeEvalError(f"Unknown name: {node.id}")
            return context[node.id]
        if isinstance(node, ast.Attribute):
            obj = _eval(node.value)
            return getattr(obj, node.attr, None) if not isinstance(obj, dict) else obj.get(node.attr)
        if isinstance(node, ast.Subscript):
            obj = _eval(node.value)
            key = _eval(node.slice.value if hasattr(node.slice, "value") else node.slice)  # py39 compat
            if isinstance(obj, dict):
                return obj.get(key)
            if isinstance(obj, list) and isinstance(key, int):
                return obj[key]
            return None
        if isinstance(node, ast.UnaryOp):
            val = _eval(node.operand)
            if isinstance(node.op, ast.Not):
                return not bool(val)
            raise SafeEvalError("Unsupported unary op")
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                res = True
                for v in node.values:
                    res = res and bool(_eval(v))
                    if not res:
                        break
                return res
            if isinstance(node.op, ast.Or):
                res = False
                for v in node.values:
                    res = res or bool(_eval(v))
                    if res:
                        break
                return res
            raise SafeEvalError("Unsupported bool op")
        if isinstance(node, ast.Compare):
            left = _eval(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right = _eval(comparator)
                if isinstance(op, ast.Eq) and not (left == right):
                    return False
                elif isinstance(op, ast.NotEq) and not (left != right):
                    return False
                elif isinstance(op, ast.Gt) and not (left > right):
                    return False
                elif isinstance(op, ast.GtE) and not (left >= right):
                    return False
                elif isinstance(op, ast.Lt) and not (left < right):
                    return False
                elif isinstance(op, ast.LtE) and not (left <= right):
                    return False
                elif isinstance(op, ast.In) and not (left in right):
                    return False
                elif isinstance(op, ast.NotIn) and not (left not in right):
                    return False
                elif isinstance(op, ast.Is) and not (left is right):
                    return False
                elif isinstance(op, ast.IsNot) and not (left is not right):
                    return False
                left = right
            return True
        if isinstance(node, ast.BinOp):
            # Ограничим к арифметике чисел
            l = _eval(node.left)
            r = _eval(node.right)
            if isinstance(node.op, ast.Add):
                return l + r
            if isinstance(node.op, ast.Sub):
                return l - r
            if isinstance(node.op, ast.Mult):
                return l * r
            raise SafeEvalError("Unsupported bin op")
        raise SafeEvalError(f"Unsupported node: {type(node).__name__}")

    result = _eval(parsed)
    return bool(result)


# =========================
# Сопоставление селекторов и правил
# =========================

def _match_subject(sel: Optional[SubjectSelector], subj: Subject, session: Optional[SessionContext], env: Optional[Environment]) -> Tuple[bool, str]:
    if sel is None:
        return True, "no subject selector"
    if sel.principals and subj.principal_id not in sel.principals:
        return False, "principal mismatch"
    if sel.roles:
        if not set(sel.roles).intersection(set(subj.roles)):
            return False, "role mismatch"
    if sel.groups:
        if not set(sel.groups).intersection(set(subj.groups)):
            return False, "group mismatch"
    for k, v in sel.attributes_eq.items():
        if subj.attributes.get(k) != v:
            return False, f"subject attr {k} mismatch"
    if sel.match:
        ctx = {
            "subject": json.loads(subj.json()),
            "session": json.loads(session.json()) if session else {},
            "env": json.loads(env.json()) if env else {},
        }
        try:
            if not safe_eval(sel.match, ctx):
                return False, "subject match false"
        except SafeEvalError as e:
            return False, f"subject match error: {e}"
    return True, "subject matched"

def _match_resource(sel: Optional[ResourceSelector], res: Resource, env: Optional[Environment]) -> Tuple[bool, str]:
    if sel is None:
        return True, "no resource selector"
    if sel.type and res.type != sel.type:
        return False, "type mismatch"
    if sel.ids and res.id not in sel.ids:
        return False, "id mismatch"
    for lk, lv in sel.labels.items():
        if res.labels.get(lk) != lv:
            return False, f"label {lk} mismatch"
    for k, v in sel.attributes_eq.items():
        if res.attributes.get(k) != v:
            return False, f"resource attr {k} mismatch"
    if sel.match:
        ctx = {"resource": json.loads(res.json()), "env": json.loads(env.json()) if env else {}}
        try:
            if not safe_eval(sel.match, ctx):
                return False, "resource match false"
        except SafeEvalError as e:
            return False, f"resource match error: {e}"
    return True, "resource matched"

def _bundle_etag(tenant: str) -> str:
    return POLICIES.bundle(tenant).etag

def _evaluate_request(req: CheckAccessRequestModel) -> CheckAccessResponseModel:
    tenant = req.tenant_id
    policies = POLICIES.list(tenant)
    if req.policy_names:
        allowed = set(req.policy_names)
        policies = [p for p in policies if p.name in allowed]

    matches: List[PolicyMatch] = []
    obligations: List[Obligation] = []
    permit_found = False
    deny_found = False
    reasons: List[str] = []

    for p in policies:
        for r in sorted(p.rules, key=lambda x: x.priority, reverse=True):
            if req.action not in r.actions:
                continue
            s_ok, s_reason = _match_subject(r.subjects, req.subject, req.session, req.environment)
            if not s_ok:
                matches.append(PolicyMatch(policy_name=p.name, rule_id=r.id, effect=r.effect, matched=False,
                                           detail=s_reason, condition=r.condition or None, policy_priority=p.priority, rule_priority=r.priority))
                continue
            r_ok, r_reason = _match_resource(r.resources, req.resource, req.environment)
            if not r_ok:
                matches.append(PolicyMatch(policy_name=p.name, rule_id=r.id, effect=r.effect, matched=False,
                                           detail=r_reason, condition=r.condition or None, policy_priority=p.priority, rule_priority=r.priority))
                continue
            cond_ok = True
            cond_detail = "no condition"
            if r.condition:
                ctx = {
                    "subject": json.loads(req.subject.json()),
                    "resource": json.loads(req.resource.json()),
                    "action": req.action,
                    "session": json.loads(req.session.json()) if req.session else {},
                    "env": json.loads(req.environment.json()) if req.environment else {},
                }
                try:
                    cond_ok = safe_eval(r.condition, ctx)
                    cond_detail = "condition true" if cond_ok else "condition false"
                except SafeEvalError as e:
                    cond_ok = False
                    cond_detail = f"condition error: {e}"
            if not cond_ok:
                matches.append(PolicyMatch(policy_name=p.name, rule_id=r.id, effect=r.effect, matched=False,
                                           detail=cond_detail, condition=r.condition or None, policy_priority=p.priority, rule_priority=r.priority))
                continue

            # Условие, субъект и ресурс совпали
            matches.append(PolicyMatch(policy_name=p.name, rule_id=r.id, effect=r.effect, matched=True,
                                       detail="matched", condition=r.condition or None, policy_priority=p.priority, rule_priority=r.priority))

            if r.effect == "DENY":
                deny_found = True
                reasons.append(f"deny by {p.name}/{r.id}")
            else:
                permit_found = True
                if req.include_obligations and r.obligations:
                    obligations.extend(r.obligations)

            # Политика может иметь несколько правил. Продолжаем искать DENY с приоритетом.
            # Немедленный выход по первому DENY правила не обязателен, но оптимизируем:
            if deny_found:
                break
        if deny_found:
            break

    if deny_found:
        decision: DecisionLiteral = "DENY"
        reasons = reasons or ["explicit deny"]
    elif permit_found:
        decision = "PERMIT"
        reasons = reasons or ["explicit permit"]
    else:
        # default deny (нет правила) для безопасности
        decision = "DENY" if req.mode in ("DEFAULT", "DENY_BIASED") else "NOT_APPLICABLE"
        reasons = ["no matching rule"]

    if DECISIONS:
        DECISIONS.labels(decision=decision, tenant=tenant).inc()

    explanation = Explanation(decision=decision, reasons=reasons, matches=matches) if req.include_explanation else None
    return CheckAccessResponseModel(
        decision=decision,
        obligations=obligations if decision == "PERMIT" else [],
        explanation=explanation,
        status=None,
        bundle_etag=_bundle_etag(tenant),
    )


# =========================
# Ограничение скорости (per IP)
# =========================

class RateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self.limit = limit_per_minute
        self._lock = threading.RLock()
        self._buckets: Dict[str, Tuple[int, float]] = {}  # key -> (count, window_start_ts)

    def allow(self, key: str) -> bool:
        now = time.time()
        win = int(now // 60)
        with self._lock:
            count, start = self._buckets.get(key, (0, win))
            if start != win:
                count, start = 0, win
            if count >= self.limit:
                self._buckets[key] = (count, start)
                return False
            self._buckets[key] = (count + 1, start)
            return True

rate_limiter = RateLimiter(settings.RATE_LIMIT_PER_MINUTE)


# =========================
# Приложение FastAPI и middleware
# =========================

app = FastAPI(
    title="Aethernova Security Core",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if settings.CORS_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def middleware_chain(request: Request, call_next):
    # Request ID
    req_id = request.headers.get("X-Request-ID") or gen_request_id()
    start_time = time.time()

    # Rate limit per IP
    client_ip = request.client.host if request.client else "unknown"
    rl_key = f"{client_ip}:{request.url.path}"
    if not rate_limiter.allow(rl_key):
        return JSONResponse(status_code=429, content={"error": "rate limit exceeded"})

    # Метрики
    timer = None
    if HTTP_LATENCY:
        timer = HTTP_LATENCY.labels(method=request.method, path=request.url.path).time()

    try:
        response: Response = await call_next(request)
    except Exception as e:  # noqa: BLE001
        logger.exception("Unhandled error: %s", e)
        response = JSONResponse(status_code=500, content={"error": "internal server error"})

    # Заголовки безопасности
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

    # Метрики
    duration = time.time() - start_time
    if HTTP_REQUESTS:
        HTTP_REQUESTS.labels(method=request.method, path=request.url.path, status=str(response.status_code)).inc()
    if timer:
        timer.observe(duration)

    return response


# =========================
# Health и метрики
# =========================

@app.get("/live", response_class=PlainTextResponse)
async def live() -> str:
    return "OK"

@app.get("/ready", response_class=PlainTextResponse)
async def ready() -> str:
    # Простая проверка состояния
    return "READY"

@app.get("/metrics")
async def metrics():
    if not settings.METRICS_ENABLED or not generate_latest:
        return PlainTextResponse("metrics disabled", status_code=200)
    data = generate_latest()  # type: ignore
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


# =========================
# PDP: Authorization endpoints
# =========================

@app.post("/v1/authorize/check", response_model=CheckAccessResponseModel)
async def check_access(
    payload: CheckAccessRequestModel,
    principal: Principal = Depends(auth_dependency),
):
    # Аудит лог
    logger.info(
        "authz.check request_id=%s tenant=%s principal=%s action=%s resource=%s",
        payload.request_id or "-", payload.tenant_id, principal.subject,
        payload.action, sanitize_for_log({"type": payload.resource.type, "id": payload.resource.id})
    )
    resp = _evaluate_request(payload)
    return resp

@app.post("/v1/authorize/batch", response_model=BatchCheckAccessResponseModel)
async def batch_check(
    payload: BatchCheckAccessRequestModel,
    principal: Principal = Depends(auth_dependency),
):
    responses = []
    for req in payload.requests:
        responses.append(_evaluate_request(req))
    return BatchCheckAccessResponseModel(responses=responses)

@app.post("/v1/authorize/effective-permissions", response_model=ListEffectivePermissionsResponseModel)
async def list_effective_permissions(
    payload: ListEffectivePermissionsRequestModel,
    principal: Principal = Depends(auth_dependency),
):
    # Переберем все известные действия по правилам
    policies = POLICIES.list(payload.tenant_id)
    permitted: Set[str] = set()
    matches: List[PolicyMatch] = []

    # Для эффективности можно предварительно собрать множество всех action из правил.
    all_actions: Set[str] = set(a for p in policies for r in p.rules for a in r.actions)
    for act in sorted(all_actions):
        req = CheckAccessRequestModel(
            tenant_id=payload.tenant_id,
            subject=payload.subject,
            action=act,
            resource=payload.resource,
            session=payload.session,
            environment=payload.environment,
            include_explanation=True,
        )
        res = _evaluate_request(req)
        if res.decision == "PERMIT":
            permitted.add(act)
        if res.explanation:
            matches.extend(res.explanation.matches)

    explanation = Explanation(decision="PERMIT" if permitted else "DENY", reasons=["aggregated"], matches=matches[:2000])
    return ListEffectivePermissionsResponseModel(
        permitted_actions=sorted(permitted),
        bundle_etag=_bundle_etag(payload.tenant_id),
        explanation=explanation
    )

@app.post("/v1/authorize/explain", response_model=ExplainDecisionResponseModel)
async def explain_decision(
    payload: ExplainDecisionRequestModel,
    principal: Principal = Depends(auth_dependency),
):
    req = payload.request
    req.include_explanation = True
    res = _evaluate_request(req)
    return ExplainDecisionResponseModel(
        explanation=res.explanation or Explanation(decision=res.decision, reasons=["no explanation"], matches=[])
    )


# =========================
# Policy Admin API (CRUD, publish, bundle)
# =========================

def _policy_name(tenant: str, policy_id: str) -> str:
    return f"tenants/{tenant}/policies/{policy_id}"

@app.post("/v1/tenants/{tenant}/policies", response_model=Policy, status_code=201)
async def create_policy(
    tenant: str = Path(..., regex=r"^[A-Za-z0-9_.-]{1,128}$"),
    body: Policy = Body(...),
    principal: Principal = Depends(auth_dependency),
):
    if principal.tenant and principal.tenant != tenant:
        raise HTTPException(status_code=403, detail="Cross-tenant forbidden")
    if body.tenant_id != tenant:
        raise HTTPException(status_code=400, detail="tenant mismatch in body")
    if not body.name.startswith(f"tenants/{tenant}/policies/"):
        raise HTTPException(status_code=400, detail="invalid policy name")
    created = POLICIES.create(body)
    return created

@app.get("/v1/tenants/{tenant}/policies", response_model=List[Policy])
async def list_policies(
    tenant: str = Path(..., regex=r"^[A-Za-z0-9_.-]{1,128}$"),
    principal: Principal = Depends(auth_dependency),
):
    if principal.tenant and principal.tenant != tenant:
        raise HTTPException(status_code=403, detail="Cross-tenant forbidden")
    return POLICIES.list(tenant)

@app.get("/v1/tenants/{tenant}/policies/{policy}", response_model=Policy)
async def get_policy(
    tenant: str,
    policy: str = Path(..., regex=r"^[A-Za-z0-9_.-]{1,128}$"),
    principal: Principal = Depends(auth_dependency),
):
    name = _policy_name(tenant, policy)
    return POLICIES.get(name)

@app.put("/v1/tenants/{tenant}/policies/{policy}", response_model=Policy)
async def update_policy(
    tenant: str,
    policy: str,
    body: Policy = Body(...),
    principal: Principal = Depends(auth_dependency),
):
    if body.name != _policy_name(tenant, policy):
        raise HTTPException(status_code=400, detail="name mismatch")
    if body.tenant_id != tenant:
        raise HTTPException(status_code=400, detail="tenant mismatch")
    return POLICIES.update(body)

@app.patch("/v1/tenants/{tenant}/policies/{policy}", response_model=Policy)
async def patch_policy(
    tenant: str,
    policy: str,
    patch_doc: Dict[str, Any] = Body(...),
    principal: Principal = Depends(auth_dependency),
):
    name = _policy_name(tenant, policy)
    return POLICIES.patch(name, patch_doc)

@app.delete("/v1/tenants/{tenant}/policies/{policy}", status_code=204)
async def delete_policy(
    tenant: str,
    policy: str,
    etag: Optional[str] = Query(None),
    principal: Principal = Depends(auth_dependency),
):
    name = _policy_name(tenant, policy)
    POLICIES.delete(name, etag)
    return Response(status_code=204)

@app.post("/v1/tenants/{tenant}/policies/{policy}:publish", response_model=Dict[str, Any])
async def publish_policy(
    tenant: str,
    policy: str,
    notes: Optional[str] = Body(None),
    principal: Principal = Depends(auth_dependency),
):
    name = _policy_name(tenant, policy)
    p = POLICIES.get(name)
    if not p.version.published:
        p.version.published = True
        p.version.change_notes = notes or p.version.change_notes
        p.update_time = now_utc()
        POLICIES.update(p)
    bundle = POLICIES.bundle(tenant)
    return {"policy": p.dict(), "bundle": bundle.dict()}

@app.get("/v1/tenants/{tenant}/policyBundle", response_model=PolicyBundle)
async def get_policy_bundle(
    tenant: str,
    principal: Principal = Depends(auth_dependency),
):
    return POLICIES.bundle(tenant)


# =========================
# Точка входа
# =========================

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting %s on 0.0.0.0:8080", settings.SERVICE_NAME)
    uvicorn.run("server:app", host="0.0.0.0", port=8080, reload=False)
