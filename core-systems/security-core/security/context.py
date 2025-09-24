# -*- coding: utf-8 -*-
"""
Security Context for security-core.

Возможности:
- Безопасное хранение контекста через contextvars (совместимо с asyncio/потоками).
- Нормализованный набор метаданных: trace, network, device, auth, risk, compliance, scope.
- Извлечение контекста из HTTP-заголовков (x-correlation-id, x-request-id, x-tenant-id, x-user-id, Authorization и т.д.).
- Опциональная верификация JWT (через пользовательский callback) и данные mTLS (передаются периметром).
- Политики допуска (RBAC/ABAC/риск) с детальным решением (allow/deny/step_up).
- Redaction PII при логировании/экспорте, сериализация в заголовки для исходящих запросов.
- Интеграция с OpenTelemetry (если доступен) для установки span-атрибутов.
- Starlette/FastAPI middleware для автоматического формирования контекста.

Зависимости: стандартная библиотека Python. OpenTelemetry — опционально (если установлен).
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple, List

try:
    # Опциональная интеграция
    from opentelemetry import trace as otel_trace  # type: ignore
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False

import contextvars

# =====================================================================================
# УТИЛИТЫ
# =====================================================================================

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _monotonic_ns() -> int:
    # Для относительных меток времени/профайлинга
    return time.monotonic_ns()

def _gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"

def _is_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except Exception:
        return False

def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)

# =====================================================================================
# МОДЕЛИ КОНТЕКСТА
# =====================================================================================

@dataclass(frozen=True)
class TraceMeta:
    correlation_id: str
    request_id: str
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None
    labels: Mapping[str, str] = field(default_factory=dict)

@dataclass(frozen=True)
class NetworkMeta:
    ip: Optional[str] = None
    forwarded_for: Optional[str] = None
    user_agent: Optional[str] = None
    asn: Optional[str] = None
    geo: Optional[str] = None
    tls_client_subject: Optional[str] = None  # для mTLS (CN/subject)
    labels: Mapping[str, str] = field(default_factory=dict)

@dataclass(frozen=True)
class DeviceMeta:
    device_id: Optional[str] = None
    platform: Optional[str] = None
    os: Optional[str] = None
    browser: Optional[str] = None
    is_trusted: bool = False
    labels: Mapping[str, str] = field(default_factory=dict)

@dataclass(frozen=True)
class AuthMeta:
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    subject: Optional[str] = None         # sub (для сервис-аккаунтов/пользователей)
    auth_type: Optional[str] = None       # oidc|mtls|api_key|anonymous
    mfa_level: Optional[str] = None       # AAL1|AAL2|AAL3
    roles: Tuple[str, ...] = field(default_factory=tuple)
    permissions: Tuple[str, ...] = field(default_factory=tuple)
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    claims: Mapping[str, Any] = field(default_factory=dict)
    is_service_account: bool = False
    labels: Mapping[str, str] = field(default_factory=dict)

@dataclass(frozen=True)
class RiskMeta:
    score: int = 0              # 0..100
    level: str = "low"          # low|medium|high|critical
    signals: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class ComplianceMeta:
    tags: Tuple[str, ...] = field(default_factory=tuple)  # nist800-63b, iso27001 и т.д.
    pii_minimization: bool = True

@dataclass(frozen=True)
class AccessScope:
    resource: str               # e.g. "project:1234" или "pii:customer"
    action: str                 # e.g. "read", "write", "delete", "approve"
    attributes: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class SecurityContext:
    trace: TraceMeta
    network: NetworkMeta = field(default_factory=NetworkMeta)
    device: DeviceMeta = field(default_factory=DeviceMeta)
    auth: AuthMeta = field(default_factory=AuthMeta)
    risk: RiskMeta = field(default_factory=RiskMeta)
    compliance: ComplianceMeta = field(default_factory=ComplianceMeta)
    scope: Optional[AccessScope] = None
    created_at: datetime = field(default_factory=_utcnow)
    created_mono_ns: int = field(default_factory=_monotonic_ns)
    labels: Mapping[str, str] = field(default_factory=dict)

    # ---- Утилиты сериализации ----
    def to_log_fields(self, redact: bool = True) -> Dict[str, Any]:
        d = asdict(self)
        if redact:
            return _redact_dict(d)
        return d

    def to_headers(self) -> Dict[str, str]:
        """
        Сериализация для исходящих HTTP вызовов (корреляция/мультисервис).
        """
        h: Dict[str, str] = {
            "x-correlation-id": self.trace.correlation_id,
            "x-request-id": self.trace.request_id,
        }
        if self.auth.tenant_id:
            h["x-tenant-id"] = self.auth.tenant_id
        if self.auth.user_id:
            h["x-user-id"] = self.auth.user_id
        if self.device.device_id:
            h["x-device-id"] = self.device.device_id
        if self.trace.service:
            h["x-service"] = self.trace.service
        for k, v in self.trace.labels.items():
            h[f"x-trace-label-{k}"] = str(v)
        return h

    # ---- Политики доступа ----
    def evaluate_policy(
        self,
        required_roles: Optional[Iterable[str]] = None,
        required_permissions: Optional[Iterable[str]] = None,
        max_risk_level: str = "high",
        abac_predicate: Optional[Callable[[Mapping[str, Any]], bool]] = None,
    ) -> "AccessDecision":
        roles = set(self.auth.roles or ())
        perms = set(self.auth.permissions or ())
        missing_roles = set(required_roles or ()) - roles
        missing_perms = set(required_permissions or ()) - perms

        risk_level_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if self.risk.level not in risk_level_order or max_risk_level not in risk_level_order:
            return AccessDecision(allowed=False, reason="invalid_risk_levels")

        risk_ok = risk_level_order[self.risk.level] <= risk_level_order[max_risk_level]
        if missing_roles or missing_perms:
            return AccessDecision(
                allowed=False,
                reason="rbac_failed",
                details={
                    "missing_roles": sorted(missing_roles),
                    "missing_permissions": sorted(missing_perms),
                },
            )

        if not risk_ok:
            # Подсказка на step-up: если у пользователя есть MFA ниже требуемого уровня.
            step_up = "mfa" if (self.auth.mfa_level or "AAL1") in ("AAL1", "AAL2") else None
            return AccessDecision(allowed=False, reason="risk_too_high", required_step_up=step_up)

        if abac_predicate:
            try:
                # ABAC получает редактированный словарь
                red = self.to_log_fields(redact=True)
                if not abac_predicate(red):
                    return AccessDecision(allowed=False, reason="abac_denied")
            except Exception:
                return AccessDecision(allowed=False, reason="abac_error")

        return AccessDecision(allowed=True, reason="ok")

@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str
    required_step_up: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)

# =====================================================================================
# КОНТЕЙНЕР КОНТЕКСТА (contextvars)
# =====================================================================================

_ctx_var: contextvars.ContextVar[Optional[SecurityContext]] = contextvars.ContextVar("security_ctx", default=None)

def current() -> Optional[SecurityContext]:
    """Текущий SecurityContext или None."""
    return _ctx_var.get()

class ContextToken:
    """Токен для восстановления предыдущего контекста."""
    def __init__(self, token: contextvars.Token):
        self._token = token
    def reset(self) -> None:
        _ctx_var.reset(self._token)

@contextlib.contextmanager
def use_context(ctx: SecurityContext):
    """
    Контекстный менеджер: устанавливает контекст в текущем task/thread.
    """
    token = _ctx_var.set(ctx)
    try:
        # Интеграция с OpenTelemetry
        if _OTEL:
            span = otel_trace.get_current_span()
            if span and span.is_recording():
                span.set_attribute("sec.correlation_id", ctx.trace.correlation_id)
                if ctx.auth.tenant_id:
                    span.set_attribute("sec.tenant_id", ctx.auth.tenant_id)
                if ctx.auth.user_id:
                    span.set_attribute("sec.user_id", ctx.auth.user_id)
                if ctx.risk.level:
                    span.set_attribute("sec.risk.level", ctx.risk.level)
        yield ctx
    finally:
        _ctx_var.reset(token)

def set_context(ctx: SecurityContext) -> ContextToken:
    """Прямое выставление контекста с возвратом токена для reset()."""
    token = _ctx_var.set(ctx)
    return ContextToken(token)

# =====================================================================================
# REDACTION
# =====================================================================================

# Поля, которые следует маскировать в логах
_REDACT_KEYS = {
    "password", "authorization", "token", "secret", "code",
    "otp", "assertion", "cookie", "set-cookie",
    "ssn", "pan", "card", "email", "phone",
}

def _redact_value(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        if len(v) <= 6:
            return "***"
        return v[:3] + "***" + v[-2:]
    if isinstance(v, (list, tuple)):
        return type(v)(_redact_value(x) for x in v)
    if isinstance(v, dict):
        return _redact_dict(v)
    return "***"

def _redact_dict(d: MutableMapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        lk = k.lower()
        if lk in _REDACT_KEYS or lk.endswith("_token") or lk.endswith("_secret"):
            out[k] = _redact_value(v)
        elif isinstance(v, dict):
            out[k] = _redact_dict(v)  # type: ignore
        elif isinstance(v, list):
            out[k] = [_redact_value(x) if isinstance(x, (str, dict, list)) else x for x in v]
        else:
            out[k] = v
    return out

# =====================================================================================
# ИЗВЛЕЧЕНИЕ КОНТЕКСТА ИЗ HTTP
# =====================================================================================

# Заголовки, используемые системой
_HDR_CORR = "x-correlation-id"
_HDR_REQ = "x-request-id"
_HDR_TENANT = "x-tenant-id"
_HDR_USER = "x-user-id"
_HDR_DEVICE = "x-device-id"
_HDR_SERVICE = "x-service"

_JWT_BEARER_RE = re.compile(r"^\s*Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)\s*$")

def _unverified_jwt_payload(token: str) -> Dict[str, Any]:
    """
    Без верификации подписи — только для обогащения. Не используйте для принятия решений!
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}

def build_context_from_headers(
    headers: Mapping[str, str],
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    *,
    jwt_verify_cb: Optional[Callable[[str], Mapping[str, Any]]] = None,
    mtls_subject: Optional[str] = None,
    default_service: Optional[str] = None,
    default_version: Optional[str] = None,
) -> SecurityContext:
    """
    Создает SecurityContext из HTTP-заголовков. Верификация JWT — через jwt_verify_cb (опционально).
    """
    # Корреляция
    corr_id = headers.get(_HDR_CORR) or _gen_id("corr")
    req_id = headers.get(_HDR_REQ) or _gen_id("req")

    # Auth
    tenant_id = headers.get(_HDR_TENANT)
    user_id = headers.get(_HDR_USER)
    device_id = headers.get(_HDR_DEVICE)

    auth_type = None
    subject = None
    mfa_level = None
    roles: Tuple[str, ...] = ()
    permissions: Tuple[str, ...] = ()
    scopes: Tuple[str, ...] = ()
    claims: Dict[str, Any] = {}

    # Authorization: Bearer
    authz = headers.get("authorization") or headers.get("Authorization")
    if authz:
        m = _JWT_BEARER_RE.match(authz)
        if m:
            jwt = m.group(1)
            if jwt_verify_cb:
                # Пользовательская проверка подписи и возврат claims
                with contextlib.suppress(Exception):
                    claims = dict(jwt_verify_cb(jwt))
            if not claims:
                # Fallback — НЕ ДОВЕРЯТЬ, чисто для enrich
                claims = _unverified_jwt_payload(jwt) or {}
            subject = str(claims.get("sub")) if "sub" in claims else user_id or None
            # Стандартизованные поля (если есть)
            if "scope" in claims:
                if isinstance(claims["scope"], str):
                    scopes = tuple(x for x in claims["scope"].split() if x)
                elif isinstance(claims["scope"], (list, tuple)):
                    scopes = tuple(str(x) for x in claims["scope"])
            if "roles" in claims:
                if isinstance(claims["roles"], (list, tuple)):
                    roles = tuple(str(x) for x in claims["roles"])
                elif isinstance(claims["roles"], str):
                    roles = tuple(x.strip() for x in claims["roles"].split(",") if x.strip())
            if "permissions" in claims:
                if isinstance(claims["permissions"], (list, tuple)):
                    permissions = tuple(str(x) for x in claims["permissions"])
            if "aal" in claims:
                mfa_level = str(claims["aal"])
            auth_type = "oidc"
        else:
            # Иные типы авторизации (например, API Key)
            auth_type = "api_key"
    elif mtls_subject:
        auth_type = "mtls"
        subject = mtls_subject

    # Trace
    trace = TraceMeta(
        correlation_id=corr_id,
        request_id=req_id,
        trace_id=None,
        span_id=None,
        service=headers.get(_HDR_SERVICE) or default_service,
        version=default_version,
        labels={},
    )

    # Network
    network = NetworkMeta(
        ip=client_ip,
        forwarded_for=headers.get("x-forwarded-for"),
        user_agent=user_agent,
        tls_client_subject=mtls_subject,
        labels={}
    )

    # Device
    device = DeviceMeta(
        device_id=device_id,
        labels={},
    )

    # Risk (базовая инициализация — расчет снаружи)
    risk = RiskMeta(score=0, level="low", signals={})

    # AuthMeta
    auth = AuthMeta(
        tenant_id=tenant_id,
        user_id=user_id,
        subject=subject or user_id,
        auth_type=auth_type,
        mfa_level=mfa_level,
        roles=roles,
        permissions=permissions,
        scopes=scopes,
        claims=claims,
        is_service_account=bool(claims.get("azp") and claims.get("sub") and claims.get("sub") != user_id),
        labels={}
    )

    return SecurityContext(
        trace=trace,
        network=network,
        device=device,
        auth=auth,
        risk=risk,
        compliance=ComplianceMeta(tags=(), pii_minimization=True),
        scope=None,
        labels={}
    )

# =====================================================================================
# MIDDLEWARE ДЛЯ STARLETTE/FASTAPI
# =====================================================================================

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
except Exception:  # pragma: no cover
    BaseHTTPMiddleware = object  # type: ignore
    Request = object  # type: ignore
    Response = object  # type: ignore

class SecurityContextMiddleware(BaseHTTPMiddleware):  # type: ignore
    """
    Starlette/FastAPI middleware: создает и публикует SecurityContext на запрос.
    Параметры:
      - jwt_verify_cb: Callable[str]->Mapping — для верификации JWT и возврата claims
      - service: имя сервиса (пишется в trace)
      - version: версия сборки (пишется в trace)
      - enrich_cb: Callable[SecurityContext, None] — кастомное обогащение (например, risk score)
    """
    def __init__(
        self,
        app,
        *,
        jwt_verify_cb: Optional[Callable[[str], Mapping[str, Any]]] = None,
        service: Optional[str] = None,
        version: Optional[str] = None,
        enrich_cb: Optional[Callable[[SecurityContext], None]] = None,
    ):
        super().__init__(app)
        self._jwt_verify_cb = jwt_verify_cb
        self._service = service or os.getenv("SERVICE_NAME")
        self._version = version or os.getenv("SERVICE_VERSION")
        self._enrich_cb = enrich_cb

    async def dispatch(self, request: "Request", call_next: Callable) -> "Response":
        headers = {k.lower(): v for k, v in request.headers.items()}
        ctx = build_context_from_headers(
            headers=headers,
            client_ip=request.client.host if request.client else None,
            user_agent=headers.get("user-agent"),
            jwt_verify_cb=self._jwt_verify_cb,
            mtls_subject=headers.get("x-mtls-subject"),
            default_service=self._service,
            default_version=self._version,
        )

        # Обогащение — например, интеграция с Risk Engine
        if self._enrich_cb:
            with contextlib.suppress(Exception):
                self._enrich_cb(ctx)

        with use_context(ctx):
            # Проставим корреляцию в ответ
            response: Response = await call_next(request)
            response.headers.setdefault(_HDR_CORR, ctx.trace.correlation_id)
            response.headers.setdefault(_HDR_REQ, ctx.trace.request_id)
            if ctx.auth.tenant_id:
                response.headers.setdefault(_HDR_TENANT, ctx.auth.tenant_id)
            return response

# =====================================================================================
# ВСПОМОГАТЕЛЬНЫЕ API
# =====================================================================================

def require(
    *,
    roles: Optional[Iterable[str]] = None,
    permissions: Optional[Iterable[str]] = None,
    max_risk_level: str = "high",
    abac_predicate: Optional[Callable[[Mapping[str, Any]], bool]] = None,
) -> AccessDecision:
    """
    Проверка допуска в текущем контексте. Используйте в end‑points/handlers.
    """
    ctx = current()
    if not ctx:
        return AccessDecision(allowed=False, reason="no_context")
    return ctx.evaluate_policy(
        required_roles=roles,
        required_permissions=permissions,
        max_risk_level=max_risk_level,
        abac_predicate=abac_predicate,
    )

def bind_scope(resource: str, action: str, attributes: Optional[Mapping[str, Any]] = None) -> SecurityContext:
    """
    Возвращает новый контекст с привязанной областью доступа (scope), не мутируя существующий.
    """
    ctx = current()
    if not ctx:
        raise RuntimeError("SecurityContext is not initialized")
    return replace(ctx, scope=AccessScope(resource=resource, action=action, attributes=dict(attributes or {})))

def update_risk(score: int, level: Optional[str] = None, signals: Optional[Mapping[str, Any]] = None) -> SecurityContext:
    """
    Обновляет risk в текущем контексте (иммутабельно) и возвращает новый контекст.
    """
    ctx = current()
    if not ctx:
        raise RuntimeError("SecurityContext is not initialized")
    lvl = level or ("critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low")
    new_ctx = replace(ctx, risk=RiskMeta(score=score, level=lvl, signals=dict(signals or {})))
    set_context(new_ctx)  # Обновляем contextvar
    return new_ctx

def as_headers() -> Dict[str, str]:
    """
    Заголовки для исходящих HTTP вызовов из текущего контекста.
    """
    ctx = current()
    return ctx.to_headers() if ctx else {}

def log_fields(redact: bool = True) -> Dict[str, Any]:
    """
    Поля для структурированных логов из текущего контекста.
    """
    ctx = current()
    return ctx.to_log_fields(redact=redact) if ctx else {}

# =====================================================================================
# ПУБЛИЧНЫЙ ИНТЕРФЕЙС
# =====================================================================================

__all__ = [
    "SecurityContext",
    "TraceMeta",
    "NetworkMeta",
    "DeviceMeta",
    "AuthMeta",
    "RiskMeta",
    "ComplianceMeta",
    "AccessScope",
    "AccessDecision",
    "current",
    "use_context",
    "set_context",
    "require",
    "bind_scope",
    "update_risk",
    "as_headers",
    "log_fields",
    "SecurityContextMiddleware",
    "build_context_from_headers",
]
