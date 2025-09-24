# zero-trust-core/api/http/routers/v1/enforce.py
from __future__ import annotations

import time
import hmac
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, constr, validator

# Импорт контекста аутентификации, создаваемого middleware.
# См. zero-trust-core/api/http/middleware/auth.py
try:
    from zero_trust_core.api.http.middleware.auth import AuthContext  # type: ignore
except Exception:
    # Мягкая заглушка типов для стат. анализа/тестов
    @dataclass
    class AuthContext:  # type: ignore
        principal: str
        tenant_id: Optional[str]
        scopes: Tuple[str, ...]
        token_id: Optional[str]
        session_id: Optional[str]
        trust_level: Optional[str]
        risk_score: Optional[float]
        token_binding: Optional[str]
        token_binding_thumbprint: Optional[str]
        claims: Mapping[str, Any]

# ============================== Конфигурация/интерфейсы ==============================

class PolicyEvaluator(Protocol):
    """
    Интерфейс движка авторизационных политик.
    Должен возвращать dict: {"allowed": bool, "reasons": [..], "required_actions": [..]}.
    """
    def evaluate(self, principal: str, decision_input: Mapping[str, Any]) -> Mapping[str, Any]: ...


class Logger(Protocol):
    def __call__(self, name: str, fields: Mapping[str, Any]) -> None: ...


# Простой TTL-кэш решений (без внешних зависимостей)
class TTLCache:
    def __init__(self, ttl_seconds: int = 30, max_items: int = 10000) -> None:
        self.ttl = int(ttl_seconds)
        self.max = int(max_items)
        self._store: Dict[str, Tuple[int, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        item = self._store.get(key)
        if not item:
            return None
        ts, val = item
        if time.time() - ts > self.ttl:
            self._store.pop(key, None)
            return None
        return val

    def set(self, key: str, val: Any) -> None:
        if len(self._store) >= self.max:
            # простое LRU-подобное высвобождение
            oldest = sorted(self._store.items(), key=lambda kv: kv[1][0])[: max(1, self.max // 10)]
            for k, _ in oldest:
                self._store.pop(k, None)
        self._store[key] = (int(time.time()), val)


# Дефолтный «жёсткий» движок: deny-by-default с опциональным allow по scope:action
class DefaultPolicyEngine(PolicyEvaluator):
    def __init__(self, *, allow_scope_prefix: str = "perm:", logger: Optional[Logger] = None) -> None:
        self.allow_scope_prefix = allow_scope_prefix
        self.log = logger or (lambda n, f: None)

    def evaluate(self, principal: str, decision_input: Mapping[str, Any]) -> Mapping[str, Any]:
        # Простейшее правило: если в scope присутствует "{allow_scope_prefix}{action}", то allow,
        # иначе deny. Это безопасный дефолт; замените своим движком.
        action = str(decision_input.get("action", ""))
        scopes = tuple(decision_input.get("scopes") or ())
        needed = f"{self.allow_scope_prefix}{action}"
        allowed = any(s == needed for s in scopes)
        reasons = [] if allowed else ["no_matching_permission"]
        return {
            "allowed": allowed,
            "reasons": reasons,
            "required_actions": []  # например: ["REQUIRE_MFA"] — отдаёт реальный движок
        }


# ============================== Модели запросов/ответов ==============================

ActionStr = constr(regex=r"^[a-z][a-z0-9_:\-]{2,64}$")
ResourceStr = constr(min_length=1, max_length=512)

class EnforcementRequest(BaseModel):
    action: ActionStr = Field(..., description="Логическое действие: e.g. 'read', 'write', 'secrets:read'")
    resource: ResourceStr = Field(..., description="Идентификатор/шаблон ресурса")
    context: Dict[str, Any] = Field(default_factory=dict, description="Доп. контекст (ключи без PII)")

    @validator("context")
    def _no_pii(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        # Базовая защита от очевидных PII-ключей — для телеметрии и логов
        red_flags = {"password", "pass", "secret", "token", "ssn"}
        for k in v.keys():
            if any(bad in k.lower() for bad in red_flags):
                raise ValueError(f"forbidden key in context: {k}")
        return v


class EnforcementResponse(BaseModel):
    allowed: bool
    reasons: Tuple[str, ...] = ()
    required_actions: Tuple[str, ...] = ()
    principal: str
    tenant: Optional[str]
    trust_level: Optional[str] = None
    risk_score: Optional[float] = None
    correlation_id: str
    evaluated_at: int = Field(..., description="Unix epoch seconds")


class WhoAmIResponse(BaseModel):
    principal: str
    tenant: Optional[str]
    scopes: Tuple[str, ...]
    trust_level: Optional[str]
    risk_score: Optional[float]
    session_id: Optional[str]
    token_id: Optional[str]
    token_binding: Optional[str]


# ============================== Инициализация роутера ==============================

router = APIRouter(prefix="/api/v1", tags=["enforce"])

# Глобальные синглтоны — по месту, чтобы избежать DI-фреймворков в базовой версии
_DECISION_CACHE = TTLCache(ttl_seconds=30)
_POLICY_ENGINE: PolicyEvaluator = DefaultPolicyEngine()

def _logger(name: str, fields: Mapping[str, Any]) -> None:
    # Здесь может быть интеграция с вашей системой логирования (JSON/OTLP и т.п.)
    # По умолчанию — молча.
    _ = (name, fields)


# ============================== Зависимости ==============================

def get_auth_context(request: Request) -> AuthContext:
    ctx = getattr(request.state, "auth", None)
    if not ctx:
        # Отсутствует контекст аутентификации — клиент не прошёл AuthMiddleware
        hdr = 'Bearer realm="api", error="invalid_token"'
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "authentication required"},
            headers={"WWW-Authenticate": hdr},
        )
    return ctx  # type: ignore[return-value]


def get_correlation_id(request: Request) -> str:
    headers = request.headers
    return headers.get("x-correlation-id") or f"req-{int(time.time())}"


# ============================== Эндпоинты ==============================

@router.get("/health", summary="Liveness/Readiness probe")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@router.get("/whoami", response_model=WhoAmIResponse, summary="Кто я в контексте Zero Trust")
def whoami(ctx: AuthContext = Depends(get_auth_context)) -> WhoAmIResponse:
    return WhoAmIResponse(
        principal=ctx.principal,
        tenant=ctx.tenant_id,
        scopes=tuple(ctx.scopes or ()),
        trust_level=ctx.trust_level,
        risk_score=ctx.risk_score,
        session_id=ctx.session_id,
        token_id=ctx.token_id,
        token_binding=ctx.token_binding,
    )


@router.post("/enforce", response_model=EnforcementResponse, summary="Принудительная оценка Zero Trust политики")
def enforce(
    body: EnforcementRequest,
    request: Request,
    ctx: AuthContext = Depends(get_auth_context),
    correlation_id: str = Depends(get_correlation_id),
) -> EnforcementResponse:
    # Ключ кэша: субъект/арендатор/действие/ресурс с округлением времени
    now = int(time.time())
    window = now // 5  # 5-секундные окна для стабилизации кэша
    cache_key = f"{ctx.principal}|{ctx.tenant_id}|{body.action}|{body.resource}|{window}"

    cached = _DECISION_CACHE.get(cache_key)
    if cached is not None:
        decision = cached
    else:
        # Подготовка входа в движок
        decision_input: Dict[str, Any] = {
            "principal": ctx.principal,
            "tenant": ctx.tenant_id,
            "action": body.action,
            "resource": body.resource,
            "scopes": tuple(ctx.scopes or ()),
            "trust_level": ctx.trust_level,
            "risk_score": ctx.risk_score,
            "claims": ctx.claims,
            "client": {
                "ip": request.headers.get("x-forwarded-for") or (request.client.host if request.client else None),
                "user_agent": request.headers.get("user-agent"),
                "binding": ctx.token_binding,
            },
            "context": body.context,
            "time": now,
        }

        try:
            decision = _POLICY_ENGINE.evaluate(ctx.principal, decision_input)
        except Exception as e:
            _logger("enforce.policy_error", {"cid": correlation_id, "err": type(e).__name__})
            # Жёсткое безопасное поведение
            decision = {"allowed": False, "reasons": ["policy_engine_error"], "required_actions": []}

        _DECISION_CACHE.set(cache_key, decision)

    allowed = bool(decision.get("allowed", False))
    reasons = tuple(decision.get("reasons") or ())
    required_actions = tuple(decision.get("required_actions") or ())

    # Структурированный аудит
    _logger("enforce.decision", {
        "cid": correlation_id,
        "sub": ctx.principal,
        "tid": ctx.tenant_id,
        "act": body.action,
        "res": body.resource,
        "allowed": allowed,
        "reasons": reasons,
        "req_actions": required_actions,
        "risk": ctx.risk_score,
        "trust": ctx.trust_level,
    })

    return EnforcementResponse(
        allowed=allowed,
        reasons=reasons,
        required_actions=required_actions,
        principal=ctx.principal,
        tenant=ctx.tenant_id,
        trust_level=ctx.trust_level,
        risk_score=ctx.risk_score,
        correlation_id=correlation_id,
        evaluated_at=now,
    )


# ============================== Механизм внедрения внешнего движка ==============================

def set_policy_engine(engine: PolicyEvaluator) -> None:
    """
    Зарегистрировать внешний движок политик (например, RBAC/ABAC/PBAC).
    Вызовите один раз при старте приложения.
    """
    global _POLICY_ENGINE
    _POLICY_ENGINE = engine


def set_logger(logger: Logger) -> None:
    """
    Зарегистрировать внешний логгер (структурированный/метрики).
    """
    global _logger
    _logger = logger  # type: ignore[assignment]
