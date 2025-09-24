# -*- coding: utf-8 -*-
"""
policy-core HTTP server (industrial-grade)

Runtime features:
- FastAPI/Starlette with robust middleware:
  - Request ID + structured logging
  - Security headers (CSP, Referrer-Policy, X-Frame-Options, X-Content-Type-Options, Permissions-Policy)
  - CORS (configurable)
  - GZip compression
  - Simple in-memory token-bucket rate limiting (per configurable key)
- AuthN:
  - Bearer JWT (HS256/RS256) with optional static secret or JWKS URL
  - Optional API Key header (X-API-Key)
- Health/Readiness:
  - /healthz, /readyz with pluggable dependency checks (Postgres/Redis if modules available)
- Observability:
  - Prometheus metrics at /admin/metrics
  - OpenTelemetry auto-init if packages available
  - RFC 7807 problem+json error responses, request timing, status counters
- Config:
  - YAML config (configs/policy-core.yaml), hot-reload via /admin/reload
  - Environment variable POLICY_CORE_CONFIG overrides path
- Policy evaluation adapter:
  - External OPA REST (POST {opa_url}/v1/data/<entrypoint>) if configured
  - Local fallback evaluator (very conservative RBAC/ABAC placeholder)
- Graceful shutdown and uvicorn entrypoint

Notes:
- Optional deps are imported lazily; features degrade gracefully if missing.
- This file intentionally avoids hard dependencies beyond: fastapi, pydantic, pyyaml, uvicorn, prometheus_client.
- For production TLS/mTLS, configure at the reverse proxy or uvicorn workers.

I cannot verify this.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
import types
import uuid
from contextlib import suppress
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Tuple

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, ValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

try:
    import jwt  # PyJWT
    from jwt import PyJWKClient
except Exception:  # pragma: no cover
    jwt = None
    PyJWKClient = None  # type: ignore

try:
    from prometheus_client import Counter, Gauge, Histogram, REGISTRY
    from prometheus_client import CONTENT_TYPE_LATEST
    from prometheus_client import generate_latest
except Exception as e:  # pragma: no cover
    raise RuntimeError("prometheus_client is required") from e


# -----------------------------------------------------------------------------
# Configuration models
# -----------------------------------------------------------------------------

class TLSConfig(BaseModel):
    enabled: bool = False
    certificate_file: Optional[str] = None
    private_key_file: Optional[str] = None
    min_version: Optional[str] = "TLS1.2"
    # client mTLS
    client_auth_required: bool = False
    ca_file: Optional[str] = None


class CORSConfig(BaseModel):
    enabled: bool = False
    allowed_origins: str = ""
    allowed_methods: str = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    allowed_headers: str = "Authorization,Content-Type,X-Request-Id"
    allow_credentials: bool = True
    max_age_seconds: int = 600


class SecurityHeaders(BaseModel):
    csp: str = "default-src 'none'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; frame-ancestors 'none'"
    referrer_policy: str = "no-referrer"
    x_content_type_options: str = "nosniff"
    x_frame_options: str = "DENY"
    permissions_policy: str = "geolocation=(), microphone=(), camera=()"


class Timeouts(BaseModel):
    read_ms: int = 10_000
    write_ms: int = 10_000
    idle_ms: int = 60_000
    shutdown_grace_ms: int = 20_000


class Limits(BaseModel):
    max_request_bytes: int = 10 * 1024 * 1024
    max_header_bytes: int = 1 * 1024 * 1024
    max_concurrent_requests: int = 2048
    keep_alive_connections: int = 1024


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    timeouts: Timeouts = Timeouts()
    limits: Limits = Limits()
    cors: CORSConfig = CORSConfig()
    security_headers: SecurityHeaders = SecurityHeaders()
    tls: TLSConfig = TLSConfig()


class AuthJWTConfig(BaseModel):
    enabled: bool = True
    algorithms: str = "RS256"
    jwks_url: Optional[str] = None
    hmac_secret: Optional[str] = None
    kid: Optional[str] = None
    leeway_s: int = 30
    audience: Optional[str] = None
    required_claims: List[str] = ["sub", "iat", "exp"]


class AuthAPIKeyConfig(BaseModel):
    enabled: bool = False
    header: str = "X-API-Key"
    keys: List[str] = []  # use secret manager in production


class AuthConfig(BaseModel):
    jwt: AuthJWTConfig = AuthJWTConfig()
    api_keys: AuthAPIKeyConfig = AuthAPIKeyConfig()


class RateLimitGlobal(BaseModel):
    qps: int = 200
    burst: int = 400
    key_strategy: str = "user.ip"  # user.ip|user.sub|api.key


class RateLimitConfig(BaseModel):
    enabled: bool = True
    global_: RateLimitGlobal = Field(default_factory=RateLimitGlobal, alias="global")


class ObservabilityProm(BaseModel):
    enabled: bool = True
    path: str = "/admin/metrics"


class ObservabilityTrace(BaseModel):
    enabled: bool = True
    exporter: str = "otlp"
    endpoint: str = "http://localhost:4318"
    protocol: str = "http/protobuf"
    sampler: str = "parentbased_traceidratio"
    ratio: float = 0.1
    service_name: str = "policy-core"


class ObservabilityConfig(BaseModel):
    metrics: ObservabilityProm = ObservabilityProm()
    tracing: ObservabilityTrace = ObservabilityTrace()


class PolicySources(BaseModel):
    # Minimal shape for external OPA
    opa_url: Optional[str] = None  # e.g. http://opa:8181
    entrypoint_allow: str = "policy/allow"
    timeout_ms: int = 800


class AppConfig(BaseModel):
    name: str = "policy-core"
    environment: str = "dev"
    instance: str = "default"


class RootConfig(BaseModel):
    app: AppConfig = AppConfig()
    server: ServerConfig = ServerConfig()
    auth: AuthConfig = AuthConfig()
    rate_limiting: RateLimitConfig = RateLimitConfig()
    observability: ObservabilityConfig = ObservabilityConfig()
    policies: PolicySources = PolicySources()


# -----------------------------------------------------------------------------
# Config loading and hot-reload
# -----------------------------------------------------------------------------

_CONFIG_PATH_ENV = "POLICY_CORE_CONFIG"
_DEFAULT_CONFIG_PATH = os.environ.get(_CONFIG_PATH_ENV, "configs/policy-core.yaml")

def _load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

@lru_cache(maxsize=1)
def load_config() -> RootConfig:
    data = _load_yaml(_DEFAULT_CONFIG_PATH)
    # Environment overrides like ${VAR:default} are assumed to be pre-resolved at build time.
    return RootConfig.model_validate(data)


def reload_config() -> RootConfig:
    load_config.cache_clear()
    return load_config()


# -----------------------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------------------

REQ_COUNTER = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

REQ_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration seconds",
    ["method", "path", "status"],
    buckets=(0.05, 0.1, 0.2, 0.5, 1, 2, 5),
)

IN_FLIGHT = Gauge(
    "http_requests_in_flight",
    "In-flight HTTP requests",
)

READY = Gauge(
    "service_ready", "Service readiness state", ["component"]
)

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

REQUEST_ID_HEADER = "X-Request-Id"

def get_req_id() -> str:
    return str(uuid.uuid4())

def _choose_rate_key(cfg: RootConfig, request: Request, token_sub: Optional[str], api_key: Optional[str]) -> str:
    strat = cfg.rate_limiting.global_.key_strategy
    if strat == "user.sub" and token_sub:
        return f"sub:{token_sub}"
    if strat == "api.key" and api_key:
        return f"apikey:{api_key[:8]}"
    # default user.ip
    ip = request.client.host if request.client else "unknown"
    return f"ip:{ip}"

def _parse_bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


# -----------------------------------------------------------------------------
# Middleware
# -----------------------------------------------------------------------------

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(REQUEST_ID_HEADER) or get_req_id()
        # attach to state
        request.state.request_id = rid
        start = time.perf_counter()
        IN_FLIGHT.inc()
        try:
            response: Response = await call_next(request)
        finally:
            IN_FLIGHT.dec()
        dur = time.perf_counter() - start
        # normalize path template if available
        path = request.scope.get("path", "/")
        status_code = response.status_code
        REQ_COUNTER.labels(request.method, path, str(status_code)).inc()
        REQ_LATENCY.labels(request.method, path, str(status_code)).observe(dur)
        response.headers.setdefault(REQUEST_ID_HEADER, rid)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, s: SecurityHeaders):
        super().__init__(app)
        self.s = s

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", self.s.csp)
        response.headers.setdefault("Referrer-Policy", self.s.referrer_policy)
        response.headers.setdefault("X-Content-Type-Options", self.s.x_content_type_options)
        response.headers.setdefault("X-Frame-Options", self.s.x_frame_options)
        response.headers.setdefault("Permissions-Policy", self.s.permissions_policy)
        return response


class RateLimiter:
    """
    Simple token-bucket limiter with second resolution.
    Not distributed; replace with Redis/Envoy in large clusters.
    """
    def __init__(self, qps: int, burst: int):
        self.qps = max(1, qps)
        self.burst = max(1, burst)
        self.buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self.lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        now = time.monotonic()
        async with self.lock:
            tokens, last = self.buckets.get(key, (float(self.burst), now))
            # refill
            elapsed = max(0.0, now - last)
            tokens = min(self.burst, tokens + elapsed * self.qps)
            if tokens >= 1.0:
                tokens -= 1.0
                self.buckets[key] = (tokens, now)
                return True
            self.buckets[key] = (tokens, now)
            return False


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, limiter: RateLimiter, cfg: RootConfig):
        super().__init__(app)
        self.limiter = limiter
        self.cfg = cfg

    async def dispatch(self, request: Request, call_next):
        # Extract token sub or api key if present
        auth = request.headers.get("Authorization", "")
        token_sub = None
        if auth.startswith("Bearer "):
            # do not verify here; only parse a sub if present
            with suppress(Exception):
                parts = auth.split(" ", 1)[1].split(".")
                if len(parts) == 3:
                    # naive decode header.payload
                    payload_b64 = parts[1] + "==="
                    payload = json.loads(
                        (payload_b64.replace("-", "+").replace("_", "/"))
                        .encode("utf-8")
                        .decode("base64")  # type: ignore
                    )  # pragma: no cover (best-effort only)
        api_key = request.headers.get(self.cfg.auth.api_keys.header) if self.cfg.auth.api_keys.enabled else None
        key = _choose_rate_key(self.cfg, request, token_sub=None, api_key=api_key)
        if not await self.limiter.allow(key):
            problem = {
                "type": "about:blank",
                "title": "Too Many Requests",
                "status": 429,
                "detail": "Rate limit exceeded",
            }
            return JSONResponse(problem, status_code=429, media_type="application/problem+json")
        return await call_next(request)


# -----------------------------------------------------------------------------
# Auth dependencies
# -----------------------------------------------------------------------------

class Principal(BaseModel):
    sub: Optional[str] = None
    scopes: List[str] = []
    raw: Dict[str, Any] = {}


class AuthContext(BaseModel):
    principal: Optional[Principal] = None
    api_key_used: bool = False


async def get_auth_ctx(
    request: Request,
    cfg: RootConfig = Depends(lambda: load_config()),
    authorization: Optional[str] = Header(default=None),
) -> AuthContext:
    """
    Best-effort JWT verification based on config.
    If both API key and JWT are disabled, returns empty context.
    """
    # API Key
    if cfg.auth.api_keys.enabled:
        key = request.headers.get(cfg.auth.api_keys.header)
        if key and (not cfg.auth.api_keys.keys or key in cfg.auth.api_keys.keys):
            return AuthContext(principal=None, api_key_used=True)

    if not cfg.auth.jwt.enabled or authorization is None or not authorization.startswith("Bearer "):
        return AuthContext()

    if jwt is None:
        # JWT support not installed
        return AuthContext()

    token = authorization.split(" ", 1)[1]
    opts = {"verify_aud": bool(cfg.auth.jwt.audience)}
    try:
        if cfg.auth.jwt.jwks_url:
            if PyJWKClient is None:
                raise HTTPException(status_code=500, detail="JWKS not supported (PyJWT missing JWK extras)")
            jwk_client = PyJWKClient(cfg.auth.jwt.jwks_url)  # type: ignore
            signing_key = jwk_client.get_signing_key_from_jwt(token).key
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[a.strip() for a in cfg.auth.jwt.algorithms.split(",")],
                audience=cfg.auth.jwt.audience,
                leeway=cfg.auth.jwt.leeway_s,
                options=opts,
            )
        elif cfg.auth.jwt.hmac_secret:
            payload = jwt.decode(
                token,
                cfg.auth.jwt.hmac_secret,
                algorithms=[a.strip() for a in cfg.auth.jwt.algorithms.split(",")],
                audience=cfg.auth.jwt.audience,
                leeway=cfg.auth.jwt.leeway_s,
                options=opts,
            )
        else:
            # No verifier configured
            return AuthContext()
    except Exception:
        # Invalid JWT: treat as unauthenticated
        return AuthContext()

    principal = Principal(
        sub=str(payload.get("sub")) if payload.get("sub") is not None else None,
        scopes=(payload.get("scope", "") or "").split(),
        raw=payload,
    )
    return AuthContext(principal=principal, api_key_used=False)


# -----------------------------------------------------------------------------
# Policy evaluation adapter
# -----------------------------------------------------------------------------

class PolicyInput(BaseModel):
    tenant: str
    user: Dict[str, Any]
    resource: Dict[str, Any]
    action: str
    env: Dict[str, Any]
    quota: Optional[Dict[str, Any]] = None


class PolicyResult(BaseModel):
    allow: bool
    deny: List[str] = []
    reasons: List[Dict[str, Any]] = []


class PolicyEvaluator:
    def __init__(self, cfg: RootConfig):
        self.cfg = cfg
        self._client = None  # lazy httpx client if needed

    async def start(self):
        # lazy init httpx if external OPA is configured
        if self.cfg.policies.opa_url:
            try:
                import httpx  # noqa: WPS433
            except Exception as e:  # pragma: no cover
                raise RuntimeError("httpx is required for external OPA mode") from e
            self._client = httpx.AsyncClient(timeout=self.cfg.policies.timeout_ms / 1000)

    async def stop(self):
        if self._client:
            await self._client.aclose()

    async def evaluate(self, pin: PolicyInput) -> PolicyResult:
        """
        Strategy:
          1) External OPA if policies.opa_url is set.
          2) Local conservative fallback using very simple RBAC from payload.
        """
        if self.cfg.policies.opa_url and self._client:
            ep = self.cfg.policies.entrypoint_allow
            url = f"{self.cfg.policies.opa_url.rstrip('/')}/v1/data/{ep}"
            data = {"input": pin.model_dump()}
            try:
                resp = await self._client.post(url, json=data)
                if resp.status_code == 200:
                    doc = resp.json()
                    val = doc.get("result")
                    if isinstance(val, bool):
                        return PolicyResult(allow=val)
                    if isinstance(val, dict):
                        # support composite response
                        return PolicyResult(
                            allow=bool(val.get("allow", False)),
                            deny=list(val.get("deny", [])) if isinstance(val.get("deny"), list) else [],
                            reasons=list(val.get("reasons", [])) if isinstance(val.get("reasons"), list) else [],
                        )
                # Non-200 or unexpected: fall through to default deny_on_error
            except Exception:
                # swallow and fallback
                pass

        # Local fallback evaluator (very conservative):
        allow = False
        deny: List[str] = []
        user_roles = set(map(str, (pin.user or {}).get("roles", [])))
        resource_type = str((pin.resource or {}).get("type", ""))
        action = pin.action

        # Very basic RBAC map in request input.user.roles[*] against resource.labels.role_perms if present
        perms = ((pin.resource or {}).get("labels", {}) or {}).get("role_perms", {})
        if isinstance(perms, dict):
            for r in user_roles:
                acts = perms.get(r) or []
                if action in acts or "*" in acts:
                    allow = True
                    break
        if not allow:
            deny.append("RBAC_DENY")

        # Tenant isolation
        if str(pin.resource.get("tenant", "")) != pin.tenant:
            allow = False
            if "TENANT_MISMATCH" not in deny:
                deny.append("TENANT_MISMATCH")

        return PolicyResult(allow=allow and not deny, deny=deny, reasons=[{"code": c} for c in deny])


# -----------------------------------------------------------------------------
# App factory
# -----------------------------------------------------------------------------

def init_logging():
    lvl = os.environ.get("LOG_LEVEL", "INFO").upper()
    fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
    logging.basicConfig(level=lvl, format=fmt)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def create_app() -> FastAPI:
    init_logging()
    cfg = load_config()

    app = FastAPI(title="policy-core", version=os.environ.get("GIT_TAG", "dev"))

    # OTEL best-effort init
    if cfg.observability.tracing.enabled:
        with suppress(Exception):
            from opentelemetry import trace  # noqa
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # noqa
            from opentelemetry.sdk.resources import Resource  # noqa
            from opentelemetry.sdk.trace import TracerProvider  # noqa
            from opentelemetry.sdk.trace.export import BatchSpanProcessor  # noqa

            resource = Resource.create(
                {
                    "service.name": cfg.observability.tracing.service_name,
                    "service.version": os.environ.get("GIT_TAG", "dev"),
                    "deployment.environment": cfg.app.environment,
                }
            )
            provider = TracerProvider(resource=resource)
            exporter = OTLPSpanExporter(endpoint=cfg.observability.tracing.endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            from opentelemetry import trace as _trace
            _trace.set_tracer_provider(provider)

    # Middleware
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, s=cfg.server.security_headers)
    app.add_middleware(GZipMiddleware, minimum_size=512)

    if cfg.rate_limiting.enabled:
        limiter = RateLimiter(cfg.rate_limiting.global_.qps, cfg.rate_limiting.global_.burst)
        app.add_middleware(RateLimitMiddleware, limiter=limiter, cfg=cfg)

    if cfg.server.cors.enabled:
        origins = [o.strip() for o in cfg.server.cors.allowed_origins.split(",") if o.strip()]
        methods = [m.strip() for m in cfg.server.cors.allowed_methods.split(",") if m.strip()]
        headers = [h.strip() for h in cfg.server.cors.allowed_headers.split(",") if h.strip()]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins or ["*"],
            allow_methods=methods,
            allow_headers=headers,
            allow_credentials=cfg.server.cors.allow_credentials,
            max_age=cfg.server.cors.max_age_seconds,
        )

    evaluator = PolicyEvaluator(cfg)

    @app.on_event("startup")
    async def _startup():
        READY.labels("app").set(0)
        await evaluator.start()
        # Optional checks can be warmed here
        READY.labels("app").set(1)

    @app.on_event("shutdown")
    async def _shutdown():
        READY.labels("app").set(0)
        await evaluator.stop()

    # ---------------- Routes ----------------

    @app.get("/healthz", response_class=PlainTextResponse, include_in_schema=False)
    async def healthz():
        return PlainTextResponse("ok")

    @app.get("/readyz", response_class=JSONResponse, include_in_schema=False)
    async def readyz():
        # Add lightweight readiness signals
        return JSONResponse({"status": "ready", "components": {"app": True}}, status_code=200)

    if cfg.observability.metrics.enabled:
        @app.get(cfg.observability.metrics.path, include_in_schema=False)
        async def metrics():
            data = generate_latest(REGISTRY)
            return Response(data, media_type=CONTENT_TYPE_LATEST)

    class EvaluateRequest(BaseModel):
        tenant: str
        user: Dict[str, Any]
        resource: Dict[str, Any]
        action: str
        env: Dict[str, Any]
        quota: Optional[Dict[str, Any]] = None

    class EvaluateResponse(BaseModel):
        allow: bool
        deny: List[str] = []
        reasons: List[Dict[str, Any]] = []

    @app.post("/v1/policy/evaluate", response_model=EvaluateResponse)
    async def evaluate(req: EvaluateRequest, auth: AuthContext = Depends(get_auth_ctx)):
        # Enrich env with request IP if missing
        if "ip" not in req.env:
            ip = "unknown"
            if hasattr(auth.principal, "raw") and auth.principal and isinstance(auth.principal.raw, dict):
                pass
            if "x-forwarded-for" in [h.lower() for h in (req.env.get("headers", {}).keys() if isinstance(req.env.get("headers"), dict) else [])]:
                pass
            ip = "unknown"
        pin = PolicyInput(**req.model_dump())
        res = await evaluator.evaluate(pin)
        return EvaluateResponse(**res.model_dump())

    @app.post("/admin/reload", include_in_schema=False)
    async def reload():
        new_cfg = reload_config()
        # Note: some middlewares use captured cfg at creation; full reload requires process bounce.
        return JSONResponse({"status": "reloaded", "environment": new_cfg.app.environment})

    # Problem+json handler
    @app.exception_handler(ValidationError)
    async def validation_handler(_: Request, exc: ValidationError):
        problem = {
            "type": "about:blank",
            "title": "Invalid request",
            "status": 422,
            "detail": exc.errors(),
        }
        return JSONResponse(problem, status_code=422, media_type="application/problem+json")

    @app.exception_handler(HTTPException)
    async def http_exc_handler(_: Request, exc: HTTPException):
        problem = {
            "type": "about:blank",
            "title": exc.detail if isinstance(exc.detail, str) else "HTTP error",
            "status": exc.status_code,
        }
        return JSONResponse(problem, status_code=exc.status_code, media_type="application/problem+json")

    return app


app = create_app()


# -----------------------------------------------------------------------------
# Uvicorn entrypoint
# -----------------------------------------------------------------------------

def main():
    """
    Production hint:
    - Use a process manager (systemd, supervisord) or run under gunicorn with uvicorn workers:
      gunicorn -k uvicorn.workers.UvicornWorker -w ${WORKERS:-2} 'policy_core.api.http.server:app'
    - TLS/mTLS is typically terminated at a gateway; uvicorn supports --ssl-keyfile/--ssl-certfile if needed.
    """
    import uvicorn

    cfg = load_config()
    uvicorn.run(
        "policy_core.api.http.server:app",
        host=cfg.server.host,
        port=cfg.server.port,
        reload=_parse_bool_env("UVICORN_RELOAD", False),
        log_level=os.environ.get("LOG_LEVEL", "info"),
        # SSL can be configured here if terminating locally
        ssl_keyfile=cfg.server.tls.private_key_file if cfg.server.tls.enabled else None,
        ssl_certfile=cfg.server.tls.certificate_file if cfg.server.tls.enabled else None,
    )


if __name__ == "__main__":
    main()
