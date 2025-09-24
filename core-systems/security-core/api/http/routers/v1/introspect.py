# security-core/api/http/routers/v1/introspect.py
# Промышленный роутер introspection V1 для Aethernova Security Core (FastAPI)
# Совместим с server.py (settings, POLICIES, Principal, auth_dependency, generate_latest).
# Можно подключить так:
#   from routers.v1.introspect import get_router
#   app.include_router(get_router())

from __future__ import annotations

import base64
import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, Query, Request, Response, status
from pydantic import BaseModel, Field

# ---------- Опциональные зависимости ----------
try:
    import jwt  # PyJWT
except Exception:  # noqa: BLE001
    jwt = None  # режим без верификации

try:
    import psutil  # для расширенного здоровья
except Exception:  # noqa: BLE001
    psutil = None

# Попытка подтянуть объекты из server.py (если роутер используется внутри того же приложения)
Principal = Any
auth_dependency = None
POLICIES = None
settings = None
generate_latest = None
CONTENT_TYPE_LATEST = "text/plain"

try:
    # Локальный импорт, если сервер и роутер живут в одном модуле
    from server import Principal as _Principal  # type: ignore
    from server import auth_dependency as _auth_dependency  # type: ignore
    from server import POLICIES as _POLICIES  # type: ignore
    from server import settings as _settings  # type: ignore
    try:
        from server import generate_latest as _generate_latest, CONTENT_TYPE_LATEST as _CTL  # type: ignore
        generate_latest = _generate_latest
        CONTENT_TYPE_LATEST = _CTL
    except Exception:  # noqa: BLE001
        pass
    Principal = _Principal
    auth_dependency = _auth_dependency
    POLICIES = _POLICIES
    settings = _settings
except Exception:
    # Фоллбеки, если используется отдельно — их можно передать в get_router(...)
    pass

# ---------- Вспомогательные утилиты ----------
START_TS = time.time()

SENSITIVE_KEYS = {"SECRET", "TOKEN", "PASSWORD", "KEY", "PRIVATE", "CREDENTIAL", "CERT", "COOKIE"}

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def redact(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if len(value) <= 6:
        return "*" * len(value)
    return value[:3] + "*" * (len(value) - 6) + value[-3:]

def env_to_config(prefix: str = "") -> Dict[str, Any]:
    """Собрать безопасное представление конфигурации из env."""
    cfg: Dict[str, Any] = {}
    for k, v in os.environ.items():
        if prefix and not k.startswith(prefix):
            continue
        masked = v
        upper = k.upper()
        if any(token in upper for token in SENSITIVE_KEYS):
            masked = redact(v)
        cfg[k] = masked
    return cfg

def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    sanitized: Dict[str, str] = {}
    for k, v in headers.items():
        uk = k.upper()
        if any(token in uk for token in SENSITIVE_KEYS) or uk in {"AUTHORIZATION", "PROXY-AUTHORIZATION", "COOKIE"}:
            sanitized[k] = redact(v)
        else:
            sanitized[k] = v
    return sanitized

def to_epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)

# ---------- Модели ----------
class TokenIntrospectRequest(BaseModel):
    token: Optional[str] = Field(default=None, description="JWT для introspection; если не задан — берётся из Authorization Bearer")

class TokenHeader(BaseModel):
    alg: Optional[str] = None
    typ: Optional[str] = None
    kid: Optional[str] = None

class TokenIntrospectResponse(BaseModel):
    present: bool
    verified: bool
    header: Optional[TokenHeader] = None
    payload: Optional[Dict[str, Any]] = None
    signature_present: bool = False
    error: Optional[str] = None

class WhoAmIResponse(BaseModel):
    subject: Optional[str] = None
    tenant: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_time: datetime = Field(default_factory=now_utc)
    server_time: datetime = Field(default_factory=now_utc)
    service: Optional[str] = None
    version: Optional[str] = None
    headers: Dict[str, Any] = Field(default_factory=dict)

class PolicySummary(BaseModel):
    tenant_id: str
    count: int
    priorities: Dict[str, Optional[int]]
    etag: Optional[str] = None
    updated_at: Optional[datetime] = None
    policy_names: List[str] = Field(default_factory=list)

class BundleMeta(BaseModel):
    tenant_id: str
    etag: str
    policies: int
    create_time: datetime

class HealthExt(BaseModel):
    status: str = "OK"
    server_time: datetime = Field(default_factory=now_utc)
    uptime_seconds: int = 0
    threads: int = 0
    rss_bytes: Optional[int] = None
    cpu_percent: Optional[float] = None

class FeatureFlags(BaseModel):
    metrics_enabled: bool = False
    allow_anonymous: bool = False
    jwt_enabled: bool = False
    rate_limit_per_minute: Optional[int] = None

class ConfigSnapshot(BaseModel):
    service_name: Optional[str] = None
    log_level: Optional[str] = None
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    jwt_secret_redacted: Optional[str] = None
    cors_origins: List[str] = Field(default_factory=list)
    env: Dict[str, Any] = Field(default_factory=dict)

# ---------- Функция фабрики роутера ----------
def get_router(
    *,
    policy_store=None,
    auth_dep=None,
    app_settings=None,
    prom_generate_latest=None,
    prom_content_type: str = CONTENT_TYPE_LATEST,
) -> APIRouter:
    """
    Создаёт APIRouter introspect V1.
    Параметры можно не передавать, если сервер экспортирует соответствующие объекты.
    """
    _store = policy_store or POLICIES
    _auth = auth_dep or auth_dependency
    _settings = app_settings or settings
    _gen_latest = prom_generate_latest or generate_latest

    router = APIRouter(prefix="/v1/introspect", tags=["introspect"])

    # ---------- /whoami ----------
    @router.get("/whoami", response_model=WhoAmIResponse)
    async def whoami(
        request: Request,
        principal: Principal = Depends(_auth) if _auth else None,
        x_request_id: Optional[str] = Header(None),
    ) -> WhoAmIResponse:
        client_ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")
        hdrs = sanitize_headers(dict(request.headers))
        service = getattr(_settings, "SERVICE_NAME", None) if _settings else None
        version = "1.0.0"
        subject = getattr(principal, "subject", None) if principal else None
        tenant = getattr(principal, "tenant", None) if principal else None
        scopes = getattr(principal, "scopes", []) if principal else []
        return WhoAmIResponse(
            subject=subject,
            tenant=tenant,
            scopes=scopes,
            client_ip=client_ip,
            user_agent=ua,
            request_time=now_utc(),
            server_time=now_utc(),
            service=service,
            version=version,
            headers={"x-request-id": x_request_id or hdrs.get("x-request-id"), "sample": {k: hdrs[k] for k in list(hdrs)[:10]}},
        )

    # ---------- /token ----------
    @router.post("/token", response_model=TokenIntrospectResponse)
    async def token_introspect(
        request: Request,
        body: TokenIntrospectRequest = Body(default_factory=TokenIntrospectRequest),
        authorization: Optional[str] = Header(None),
    ) -> TokenIntrospectResponse:
        token = body.token
        if not token and authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()

        if not token:
            return TokenIntrospectResponse(present=False, verified=False, error="no token provided")

        # Разбор заголовка без верификации
        header: Optional[TokenHeader] = None
        payload: Optional[Dict[str, Any]] = None
        sig_present = False
        verified = False
        error: Optional[str] = None

        try:
            parts = token.split(".")
            if len(parts) == 3:
                sig_present = True
                hdr_json = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                header = TokenHeader(**hdr_json)
            else:
                header = TokenHeader(alg=None, typ="unknown")
        except Exception as e:  # noqa: BLE001
            error = f"malformed header: {e}"

        # Попробуем верификацию, если есть секрет и PyJWT
        secret = getattr(_settings, "AUTH_JWT_SECRET", None) if _settings else None
        issuer = getattr(_settings, "AUTH_JWT_ISSUER", None) if _settings else None
        audience = getattr(_settings, "AUTH_JWT_AUDIENCE", None) if _settings else None

        if jwt and secret:
            try:
                options = {"verify_aud": bool(audience)}
                payload = jwt.decode(
                    token,
                    secret,
                    algorithms=["HS256", "HS384", "HS512"],
                    audience=audience if audience else None,
                    issuer=issuer if issuer else None,
                    options=options,
                )
                verified = True
            except Exception as e:  # noqa: BLE001
                # Если подпись не валидна — вернём полезную отладку, но без утечки секретов
                error = f"verification failed: {e}"
                try:
                    payload = jwt.decode(token, options={"verify_signature": False})
                except Exception:
                    payload = None
        else:
            # Без PyJWT или секрета: декодируем БЕЗ подписи и помечаем как unverified
            if jwt:
                try:
                    payload = jwt.decode(token, options={"verify_signature": False})
                except Exception as e:  # noqa: BLE001
                    error = f"decode failed: {e}"
                    payload = None
            else:
                error = "jwt library not available; decoded payload is unavailable"
                payload = None

        return TokenIntrospectResponse(
            present=True,
            verified=verified,
            header=header,
            payload=payload,
            signature_present=sig_present,
            error=error,
        )

    # ---------- /policies/summary ----------
    @router.get("/policies/summary", response_model=PolicySummary)
    async def policies_summary(
        tenant: str = Query(..., regex=r"^[A-Za-z0-9_.-]{1,128}$"),
    ) -> PolicySummary:
        if _store is None:
            raise HTTPException(status_code=503, detail="policy store unavailable")
        items = _store.list(tenant)
        count = len(items)
        prios = [p.priority for p in items] if items else []
        priorities = {
            "min": min(prios) if prios else None,
            "max": max(prios) if prios else None,
        }
        etag = _store.bundle(tenant).etag if count else None
        updated_at = max((p.update_time for p in items), default=None)
        names = [p.name for p in items]
        return PolicySummary(
            tenant_id=tenant,
            count=count,
            priorities=priorities,
            etag=etag,
            updated_at=updated_at,
            policy_names=names[:1000],
        )

    # ---------- /policyBundle (meta/full) ----------
    class BundleResponse(BaseModel):
        meta: BundleMeta
        policies: Optional[List[Dict[str, Any]]] = None  # full по запросу

    @router.get("/policyBundle", response_model=BundleResponse)
    async def get_policy_bundle(
        tenant: str = Query(..., regex=r"^[A-Za-z0-9_.-]{1,128}$"),
        full: bool = Query(False, description="Вернуть полный список политик"),
    ) -> BundleResponse:
        if _store is None:
            raise HTTPException(status_code=503, detail="policy store unavailable")
        bundle = _store.bundle(tenant)
        meta = BundleMeta(
            tenant_id=bundle.tenant_id,
            etag=bundle.etag,
            policies=len(bundle.policies),
            create_time=bundle.create_time,
        )
        if full:
            # Санитизация: скрываем подписи для компактности
            policies = []
            for p in bundle.policies:
                d = json.loads(p.json())
                if "signature" in d:
                    d["signature"] = {"algorithm": d["signature"].get("algorithm"), "key_id": redact(d["signature"].get("key_id"))}
                policies.append(d)
            return BundleResponse(meta=meta, policies=policies)
        return BundleResponse(meta=meta)

    # ---------- /health/ext ----------
    @router.get("/health/ext", response_model=HealthExt)
    async def health_ext() -> HealthExt:
        uptime = int(time.time() - START_TS)
        threads = threading.active_count()
        rss = None
        cpu = None
        if psutil:
            try:
                p = psutil.Process()
                rss = int(p.memory_info().rss)
                cpu = float(p.cpu_percent(interval=0.0))
            except Exception:  # noqa: BLE001
                rss = None
                cpu = None
        return HealthExt(status="OK", uptime_seconds=uptime, threads=threads, rss_bytes=rss, cpu_percent=cpu)

    # ---------- /metrics/snapshot (Prometheus) ----------
    @router.get("/metrics/snapshot")
    async def metrics_snapshot():
        if not _gen_latest:
            return Response(status_code=200, media_type="text/plain", content="metrics disabled or generator not available")
        data = _gen_latest()
        return Response(status_code=200, media_type=prom_content_type, content=data)

    # ---------- /features ----------
    @router.get("/features", response_model=FeatureFlags)
    async def features() -> FeatureFlags:
        metrics_enabled = bool(getattr(_settings, "METRICS_ENABLED", False)) if _settings else False
        allow_anonymous = bool(getattr(_settings, "ALLOW_ANONYMOUS", False)) if _settings else False
        jwt_enabled = bool(getattr(_settings, "AUTH_JWT_SECRET", None)) if _settings else False
        rate = getattr(_settings, "RATE_LIMIT_PER_MINUTE", None) if _settings else None
        return FeatureFlags(
            metrics_enabled=metrics_enabled,
            allow_anonymous=allow_anonymous,
            jwt_enabled=jwt_enabled,
            rate_limit_per_minute=rate,
        )

    # ---------- /config/snapshot ----------
    @router.get("/config/snapshot", response_model=ConfigSnapshot)
    async def config_snapshot() -> ConfigSnapshot:
        service_name = getattr(_settings, "SERVICE_NAME", None) if _settings else None
        log_level = getattr(_settings, "LOG_LEVEL", None) if _settings else None
        issuer = getattr(_settings, "AUTH_JWT_ISSUER", None) if _settings else None
        audience = getattr(_settings, "AUTH_JWT_AUDIENCE", None) if _settings else None
        secret = getattr(_settings, "AUTH_JWT_SECRET", None) if _settings else None
        cors = getattr(_settings, "CORS_ORIGINS", []) if _settings else []
        return ConfigSnapshot(
            service_name=service_name,
            log_level=log_level,
            jwt_issuer=issuer,
            jwt_audience=audience,
            jwt_secret_redacted=redact(secret) if secret else None,
            cors_origins=cors,
            env=env_to_config(),  # полная среда с маскированием чувствительных значений
        )

    # ---------- /echo (отладка запроса) ----------
    class EchoIn(BaseModel):
        data: Optional[Dict[str, Any]] = None

    class EchoOut(BaseModel):
        received_at: datetime
        client_ip: Optional[str]
        headers: Dict[str, Any]
        data: Optional[Dict[str, Any]]

    @router.post("/echo", response_model=EchoOut)
    async def echo(request: Request, payload: EchoIn = Body(default_factory=EchoIn)) -> EchoOut:
        client_ip = request.client.host if request.client else None
        hdrs = sanitize_headers(dict(request.headers))
        return EchoOut(received_at=now_utc(), client_ip=client_ip, headers=hdrs, data=payload.data)

    return router


# Экспорт для удобного импорта: from routers.v1.introspect import introspect_router
introspect_router = get_router()
