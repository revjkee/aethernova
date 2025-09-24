# zero-trust-core/zero_trust/context.py
# -*- coding: utf-8 -*-
"""
Security Context для Zero-Trust ядра.

Назначение:
- Собрать и нормализовать контекст (идентичность, устройство, mTLS/SPIFFE, риск, окружение, запрос).
- Дать безопасное представление для:
  * принятия решения (Rego input),
  * логирования (с маскированием PII),
  * межсервисного обмена (JSON).
- Поддержать contextvars, request-id, опциональные OpenTelemetry метки.

Зависимости: только стандартная библиотека (OpenTelemetry — опционально).
Совместимость: поля Rego-Input синхронизированы с access_policy.rego.
"""

from __future__ import annotations

import base64
import contextlib
import contextvars
import dataclasses
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

# Опционально: OpenTelemetry (если установлен)
try:  # pragma: no cover
    from opentelemetry import trace  # type: ignore
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False


# ------------------------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------------------------

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _now_epoch() -> int:
    return int(time.time())

def _gen_request_id() -> str:
    raw = f"{time.time_ns()}:{uuid.uuid4()}"
    return _b64u(hashlib.sha256(raw.encode("utf-8")).digest()[:12])

def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)

def _risk_level(score: float, low: float = 0.0, med: float = 0.5, high: float = 0.8) -> str:
    s = _clamp01(score)
    if s >= high:
        return "high"
    if s >= med:
        return "medium"
    return "low"

def _jwt_sub_from_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    if not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_b64u_decode(parts[1]) or b"{}")
        sub = payload.get("sub")
        if isinstance(sub, str) and sub:
            return sub
    except Exception:
        return None
    return None

def _safe_headers_map(headers: Iterable[Tuple[bytes, bytes]] | Mapping[str, str] | None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if headers is None:
        return out
    if isinstance(headers, Mapping):
        for k, v in headers.items():
            out[str(k).lower()] = str(v)
        return out
    for k, v in headers:
        out[(k.decode("latin-1")).lower()] = v.decode("latin-1")
    return out

def _first_ip_from_xff(xff: Optional[str]) -> Optional[str]:
    if not xff:
        return None
    return xff.split(",")[0].strip()

def _peer_from_asgi(scope: Mapping[str, Any]) -> str:
    cli = scope.get("client")
    if not cli:
        return "unknown"
    host, _port = cli
    return host or "unknown"

def _resource_from_path(path: str) -> str:
    # Нормализация пути в ресурс-строку
    if not path:
        return "path:/"
    return f"path:{path}"

def _sorted_unique(xs: Iterable[str]) -> List[str]:
    return sorted(set([x for x in xs if isinstance(x, str) and x]))


# ------------------------------------------------------------------------------
# Типы контекста
# ------------------------------------------------------------------------------

@dataclass
class Session:
    sid: Optional[str] = None
    jti: Optional[str] = None

@dataclass
class Identity:
    verified: bool = False
    iss: str = ""
    aud: str = ""
    sub: str = ""
    roles: List[str] = field(default_factory=list)
    amr: List[str] = field(default_factory=list)
    mfa_age_seconds: int = 10_000_000  # безопасный дефолт (очень старый)
    session: Session = field(default_factory=Session)
    claims: Dict[str, Any] = field(default_factory=dict)  # опционально, для аудита (PII редактируется)

@dataclass
class MTLSBinding:
    bound: bool = False
    spiffe_ids: List[str] = field(default_factory=list)
    x5t_s256: Optional[str] = None  # base64url отпечаток

@dataclass
class DevicePosture:
    device_id: Optional[str] = None
    posture_id: Optional[str] = None
    compliant: bool = False
    trust_level: str = "UNTRUSTED"  # UNTRUSTED|LOW|MEDIUM|HIGH

@dataclass
class Risk:
    score: float = 1.0  # безопасный дефолт — высокий риск
    level: str = "high"
    reasons: List[str] = field(default_factory=list)

@dataclass
class RequestMeta:
    method: str = "GET"
    path: str = "/"
    resource: str = "path:/"
    client_ip: str = "unknown"
    user_agent: Optional[str] = None
    authorization: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class Environment:
    env: str = os.getenv("ZT_ENV", "prod")  # dev|stage|prod

@dataclass
class Decision:
    allow: bool = False
    reasons: List[str] = field(default_factory=list)
    obligations: Dict[str, bool] = field(default_factory=lambda: {
        "require_step_up_mfa": False,
        "require_mtls": False,
        "require_device_remediation": False,
    })

@dataclass
class SecurityContext:
    request_id: str
    identity: Identity
    mtls: MTLSBinding
    device: DevicePosture
    risk: Risk
    request: RequestMeta
    environment: Environment
    decision: Decision = field(default_factory=Decision)
    created_at: int = field(default_factory=_now_epoch)

    # ----------------------
    # Представления
    # ----------------------

    def to_rego_input(self) -> Dict[str, Any]:
        """
        Готовит input для Rego-политик (совместим с access_policy.rego).
        """
        return {
            "identity": {
                "verified": bool(self.identity.verified),
                "iss": self.identity.iss,
                "aud": self.identity.aud,
                "sub": self.identity.sub,
                "roles": _sorted_unique(self.identity.roles),
                "amr": _sorted_unique(self.identity.amr),
                "mfa_age_seconds": int(self.identity.mfa_age_seconds),
            },
            "mtls": {
                "bound": bool(self.mtls.bound),
                "spiffe_ids": _sorted_unique(self.mtls.spiffe_ids),
            },
            "device": {
                "posture": {
                    "compliant": bool(self.device.compliant),
                }
            },
            "risk": {
                "score": float(_clamp01(self.risk.score)),
            },
            "request": {
                "method": self.request.method.upper(),
                "path": self.request.path,
                "resource": self.request.resource,
            },
            "environment": {
                "env": self.environment.env,
            },
        }

    def to_safe_log(self) -> Dict[str, Any]:
        """
        Безопасный для логов словарь с редактированием PII.
        """
        safe = {
            "rid": self.request_id,
            "ts": self.created_at,
            "env": self.environment.env,
            "req": {
                "method": self.request.method,
                "path": self.request.path,
                "resource": self.request.resource,
                "client_ip": self.request.client_ip,
                "ua": self.request.user_agent or "",
            },
            "id": {
                "iss": self.identity.iss,
                "aud": self.identity.aud,
                "sub_hash": _b64u(hashlib.sha256(self.identity.sub.encode("utf-8")).digest()[:12]) if self.identity.sub else "",
                "roles": _sorted_unique(self.identity.roles),
                "amr": _sorted_unique(self.identity.amr),
                "mfa_age": self.identity.mfa_age_seconds,
            },
            "mtls": {
                "bound": self.mtls.bound,
                "spiffe_count": len(self.mtls.spiffe_ids),
            },
            "device": {"compliant": self.device.compliant, "trust": self.device.trust_level},
            "risk": {"score": _clamp01(self.risk.score), "level": self.risk.level},
            "decision": {
                "allow": self.decision.allow,
                "reasons": _sorted_unique(self.decision.reasons),
                "obligations": self.decision.obligations,
            },
        }
        return safe

    def to_json(self, include_claims: bool = False) -> Dict[str, Any]:
        """
        Полное JSON-представление для межсервисного обмена.
        По умолчанию claims не включаются (PII).
        """
        out = {
            "request_id": self.request_id,
            "created_at": self.created_at,
            "environment": dataclasses.asdict(self.environment),
            "request": dataclasses.asdict(self.request),
            "identity": {
                **dataclasses.asdict(self.identity),
                "claims": (self.identity.claims if include_claims else {}),
            },
            "mtls": dataclasses.asdict(self.mtls),
            "device": dataclasses.asdict(self.device),
            "risk": dataclasses.asdict(self.risk),
            "decision": dataclasses.asdict(self.decision),
        }
        return out

    # ----------------------
    # Обновление/вывод
    # ----------------------

    def apply_decision(self, allow: bool, reasons: Iterable[str] | None = None, obligations: Mapping[str, bool] | None = None) -> None:
        self.decision.allow = bool(allow)
        if reasons:
            self.decision.reasons = _sorted_unique(list(reasons))
        if obligations:
            self.decision.obligations.update({str(k): bool(v) for k, v in obligations.items()})

    def set_risk(self, score: float, reasons: Iterable[str] | None = None, thresholds: Tuple[float, float, float] = (0.0, 0.5, 0.8)) -> None:
        self.risk.score = _clamp01(float(score))
        self.risk.level = _risk_level(self.risk.score, *thresholds)
        if reasons:
            self.risk.reasons = _sorted_unique(list(reasons))


# ------------------------------------------------------------------------------
# Builder и фабрики (ASGI / gRPC / произвольные источники)
# ------------------------------------------------------------------------------

@dataclass
class SecurityContextBuilder:
    environment: Environment = field(default_factory=lambda: Environment(env=os.getenv("ZT_ENV", "prod")))
    identity: Identity = field(default_factory=Identity)
    mtls: MTLSBinding = field(default_factory=MTLSBinding)
    device: DevicePosture = field(default_factory=DevicePosture)
    risk: Risk = field(default_factory=Risk)
    request: RequestMeta = field(default_factory=RequestMeta)
    request_id: Optional[str] = None

    def with_request_id(self, rid: Optional[str]) -> "SecurityContextBuilder":
        self.request_id = rid or self.request_id
        return self

    def with_identity(self, **kwargs: Any) -> "SecurityContextBuilder":
        for k, v in kwargs.items():
            if hasattr(self.identity, k):
                setattr(self.identity, k, v)
        return self

    def with_mtls(self, **kwargs: Any) -> "SecurityContextBuilder":
        for k, v in kwargs.items():
            if hasattr(self.mtls, k):
                setattr(self.mtls, k, v)
        return self

    def with_device(self, **kwargs: Any) -> "SecurityContextBuilder":
        for k, v in kwargs.items():
            if hasattr(self.device, k):
                setattr(self.device, k, v)
        return self

    def with_risk(self, score: Optional[float] = None, reasons: Optional[Iterable[str]] = None) -> "SecurityContextBuilder":
        if score is not None:
            self.risk.score = _clamp01(float(score))
            self.risk.level = _risk_level(self.risk.score)
        if reasons is not None:
            self.risk.reasons = _sorted_unique(list(reasons))
        return self

    def with_request(self, **kwargs: Any) -> "SecurityContextBuilder":
        for k, v in kwargs.items():
            if hasattr(self.request, k):
                setattr(self.request, k, v)
        if "resource" not in kwargs:
            self.request.resource = _resource_from_path(self.request.path)
        return self

    def build(self) -> SecurityContext:
        rid = self.request_id or _gen_request_id()
        # Пересчитать производные поля
        self.request.method = (self.request.method or "GET").upper()
        self.request.path = self.request.path or "/"
        self.request.resource = self.request.resource or _resource_from_path(self.request.path)
        self.risk.level = _risk_level(self.risk.score)
        ctx = SecurityContext(
            request_id=rid,
            identity=self.identity,
            mtls=self.mtls,
            device=self.device,
            risk=self.risk,
            request=self.request,
            environment=self.environment,
        )
        # OTEL
        if _HAS_OTEL:  # pragma: no cover
            try:
                span = trace.get_current_span()
                if span and span.is_recording():
                    span.set_attribute("zt.request_id", rid)
                    span.set_attribute("zt.env", self.environment.env)
                    span.set_attribute("zt.req.method", self.request.method)
                    span.set_attribute("zt.req.path", self.request.path)
                    if self.identity.sub:
                        span.set_attribute("zt.sub.hash", hashlib.sha256(self.identity.sub.encode()).hexdigest()[:16])
                    span.set_attribute("zt.risk.score", self.risk.score)
                    span.set_attribute("zt.mtls.bound", self.mtls.bound)
                    span.set_attribute("zt.device.compliant", self.device.compliant)
            except Exception:
                pass
        return ctx

    # ----------------------
    # Источники
    # ----------------------

    @classmethod
    def from_asgi(cls, scope: Mapping[str, Any], headers: Iterable[Tuple[bytes, bytes]] | Mapping[str, str]) -> "SecurityContextBuilder":
        """
        Собирает базовый builder из ASGI scope/headers (FastAPI/Starlette/DRF)
        """
        hdrs = _safe_headers_map(headers)
        method = (scope.get("method") or "GET").upper()
        path = scope.get("path") or "/"
        # peer IP
        client_ip = _peer_from_asgi(scope)
        # доверие к proxy
        trust_proxy = os.getenv("ZT_TRUST_PROXY", "true").lower() == "true"
        if trust_proxy:
            fwd = _first_ip_from_xff(hdrs.get("x-forwarded-for"))
            if fwd:
                client_ip = fwd
        # identity (частично на основе заголовков)
        authorization = hdrs.get("authorization")
        sub = _jwt_sub_from_bearer(authorization) or ""
        amr = []
        # user agent
        ua = hdrs.get("user-agent")
        # mTLS через прокси-заголовки (если используется TLS-терминация на прокси)
        bound = hdrs.get("ssl-client-verify", "").lower() == "success" or \
                hdrs.get("x-forwarded-client-cert") is not None
        spiffe_ids: List[str] = []
        xfcc = hdrs.get("x-forwarded-client-cert")
        if xfcc and "spiffe://" in xfcc:
            # минимальный парсинг: выделим все spiffe://… подстроки
            spiffe_ids = _sorted_unique([tok for tok in xfcc.split(";") if tok.strip().startswith("spiffe://")])
        x5t = hdrs.get("ssl-client-sha256")
        builder = cls().with_request(
            method=method,
            path=path,
            resource=_resource_from_path(path),
            client_ip=client_ip,
            user_agent=ua,
            authorization=authorization,
            headers=hdrs,
        ).with_identity(
            verified=False if not sub else True,  # истинную верификацию выполняет JWT-слой
            sub=sub,
            roles=[],
            amr=amr,
        ).with_mtls(
            bound=bool(bound),
            spiffe_ids=spiffe_ids,
            x5t_s256=x5t
        )
        return builder

    @classmethod
    def from_grpc(cls, method: str, metadata: Iterable[Tuple[str, str]] | None, peer: Optional[str]) -> "SecurityContextBuilder":
        """
        Собирает базовый builder из gRPC metadata/peer (grpc.aio ServicerContext).
        """
        md = {str(k).lower(): str(v) for (k, v) in (metadata or [])}
        authorization = md.get("authorization")
        sub = _jwt_sub_from_bearer(authorization) or ""
        # peer формат: "ipv4:127.0.0.1:12345"
        client_ip = "unknown"
        if peer:
            try:
                ptype, rest = peer.split(":", 1)
                if ptype.startswith("ipv"):
                    client_ip = rest[:rest.rfind(":")].strip("[]")
            except Exception:
                pass
        builder = cls().with_request(
            method="POST",  # unary RPC логически «модифицирующие», но это не критично
            path=method,
            resource=method,
            client_ip=client_ip,
            authorization=authorization,
            headers=md,
        ).with_identity(
            verified=bool(sub),
            sub=sub
        )
        return builder


# ------------------------------------------------------------------------------
# ContextVar и контекст-менеджер
# ------------------------------------------------------------------------------

_current_ctx: contextvars.ContextVar[Optional[SecurityContext]] = contextvars.ContextVar("zt_current_ctx", default=None)

def get_current() -> Optional[SecurityContext]:
    return _current_ctx.get()

@contextlib.contextmanager
def use_context(ctx: SecurityContext):
    token = _current_ctx.set(ctx)
    try:
        yield ctx
    finally:
        _current_ctx.reset(token)


# ------------------------------------------------------------------------------
# Пример интеграции (докстринг/комментарий)
# ------------------------------------------------------------------------------

"""
Пример (ASGI/Starlette middleware):

from starlette.requests import Request
from starlette.responses import JSONResponse
from zero_trust.context import SecurityContextBuilder, use_context

async def zt_context_middleware(request: Request, call_next):
    builder = SecurityContextBuilder.from_asgi(request.scope, request.headers)
    # Дополнить из слоёв аутентификации/JWT, posture, risk:
    # builder.with_identity(verified=True, iss="https://...", aud="api://core", roles=["role:read"], mfa_age_seconds=120)
    # builder.with_device(compliant=True, trust_level="HIGH", device_id="dev-123")
    # builder.with_risk(score=0.2, reasons=["device_posture"])
    ctx = builder.build()
    with use_context(ctx):
        response = await call_next(request)
    return response

# Получение Rego input:
# ctx = get_current()
# input_for_rego = ctx.to_rego_input() if ctx else {}
"""

# Конец файла
