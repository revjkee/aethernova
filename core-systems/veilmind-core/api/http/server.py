# veilmind-core/api/http/server.py
# -*- coding: utf-8 -*-
"""
VeilMind Core HTTP API (Zero Trust Gateway)
-------------------------------------------

Функции:
- FastAPI сервер (порт 8080 по умолчанию).
- /v1/detect/evaluate — интеграция с риск‑скорером (CLI/HTTP/off), объяснимость факторов.
- Health: /healthz/live, /healthz/ready.
- Метрики Prometheus на отдельном порту (9090 по умолчанию).
- JWT OIDC валидация (опционально), CORS, GZip, request id, структурные логи.
- Rate limiting (in‑memory, опционально Redis).
- Опциональный PEP‑кэш (если установлен zero_trust.pep.cache).

Зависимости (опциональны, если присутствуют в окружении):
- fastapi, uvicorn, pydantic, prometheus_client, httpx, PyJWT (или python-jose), redis
Все зависимости помечены как "мягкие": при их отсутствии функционал деградирует безопасно
(например, метрики/валидация JWT отключатся, но сервер продолжит работу).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

# ----------------------------
# Опциональные зависимости
# ----------------------------
try:
    from fastapi import FastAPI, Depends, HTTPException, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field, ValidationError
except Exception as _e:  # pragma: no cover
    raise SystemExit(
        "Требуются пакеты fastapi и pydantic. Установите их: pip install fastapi pydantic uvicorn"
    )

try:
    import httpx  # HTTP клиент для OIDC JWKS и режима risk=http
except Exception:
    httpx = None  # type: ignore

try:
    import jwt  # PyJWT
except Exception:
    jwt = None  # type: ignore

try:
    import prometheus_client  # noqa: F401
    from prometheus_client import Counter, Histogram, Gauge, start_http_server
except Exception:
    prometheus_client = None  # type: ignore
    Counter = Histogram = Gauge = start_http_server = None  # type: ignore

try:
    import redis  # type: ignore
except Exception:
    redis = None  # type: ignore

# Опциональный PEP‑кэш
PepDecisionCache = None
Decision = None
try:  # pragma: no cover
    from zero_trust.pep.cache import PepDecisionCache as _PepCache, Decision as _Decision  # type: ignore

    PepDecisionCache = _PepCache
    Decision = _Decision
except Exception:
    pass

# ULID генератор из утилит (опционально)
def _ulid() -> str:
    try:
        from zero_trust.utils.crypto_random import ulid  # type: ignore

        return ulid()
    except Exception:
        return uuid.uuid4().hex


# ----------------------------
# Конфиг
# ----------------------------

@dataclass(frozen=True)
class AppConfig:
    app_name: str = os.getenv("APP_NAME", "veilmind-core")
    env: str = os.getenv("APP_ENV", "dev")
    host: str = os.getenv("HTTP_HOST", "0.0.0.0")
    port: int = int(os.getenv("HTTP_PORT", "8080"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_json: bool = os.getenv("LOG_JSON", "true").lower() == "true"

    # CORS
    cors_enabled: bool = os.getenv("CORS_ENABLED", "true").lower() == "true"
    cors_allow_origins: str = os.getenv("CORS_ALLOW_ORIGINS", "*")
    cors_allow_methods: str = os.getenv("CORS_ALLOW_METHODS", "GET,POST,OPTIONS")
    cors_allow_headers: str = os.getenv("CORS_ALLOW_HEADERS", "Authorization,Content-Type,Accept")
    cors_allow_credentials: bool = os.getenv("CORS_ALLOW_CREDENTIALS", "false").lower() == "true"

    # OIDC / Auth
    auth_mode: str = os.getenv("AUTH_MODE", "oidc")  # local|oidc
    oidc_issuer: str = os.getenv("OIDC_ISSUER_URL", "")
    oidc_audience: str = os.getenv("OIDC_AUDIENCE", "")
    oidc_cache_sec: int = int(os.getenv("OIDC_JWKS_CACHE_SEC", "300"))

    # Rate limit
    ratelimit_enabled: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    ratelimit_default: str = os.getenv("RATE_LIMIT_DEFAULT", "100r/m")  # токенов в минуту
    ratelimit_burst: int = int(os.getenv("RATE_LIMIT_BURST", "50"))
    redis_url: str = os.getenv("REDIS_URL", "")

    # Prometheus
    metrics_enabled: bool = os.getenv("METRICS_ENABLED", "true").lower() == "true"
    metrics_port: int = int(os.getenv("PROMETHEUS_PORT", "9090"))

    # Risk scoring
    risk_mode: str = os.getenv("ZT_RISK_SCORE_MODE", "cli")  # cli|http|off
    risk_cli_bin: str = os.getenv("ZT_RISK_SCORE_CLI_BIN", "python3")
    risk_cli_script: str = os.getenv("ZT_RISK_SCORE_CLI_SCRIPT", "cli/tools/risk_score.py")
    risk_state_path: str = os.getenv("ZT_RISK_SCORE_STATE_PATH", "/var/lib/veilmind/risk_state.sqlite")
    risk_weights: Optional[str] = os.getenv("ZT_RISK_WEIGHTS_PATH", None)
    risk_http_url: str = os.getenv("ZT_RISK_HTTP_URL", "http://localhost:8182/v1/evaluate")
    # Пороговые значения для local enforcement (дублируют risk конфиг как safety‑net)
    thr_allow: float = float(os.getenv("ZT_RISK_THRESH_ALLOW", "40"))
    thr_mfa: float = float(os.getenv("ZT_RISK_THRESH_MFA", "70"))
    thr_deny: float = float(os.getenv("ZT_RISK_THRESH_DENY", "85"))
    thr_quarantine: float = float(os.getenv("ZT_RISK_THRESH_QUARANTINE", "95"))

    # PEP cache
    pep_cache_ttl_sec: int = int(os.getenv("ZT_PEP_CACHE_TTL_SEC", "300"))
    pep_cache_capacity: int = int(os.getenv("ZT_PEP_CACHE_CAPACITY", "50000"))
    pep_negative_cache: bool = os.getenv("ZT_NEGATIVE_CACHE", "true").lower() == "true"


CFG = AppConfig()


# ----------------------------
# Логирование
# ----------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k in ("request_id", "path", "method", "status", "latency_ms", "actor_id"):
            v = getattr(record, k, None)
            if v is not None:
                payload[k] = v
        return json.dumps(payload, ensure_ascii=False)


def setup_logging() -> None:
    level = getattr(logging, CFG.log_level.upper(), logging.INFO)
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter() if CFG.log_json else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(level)


setup_logging()
log = logging.getLogger("veilmind.api")


# ----------------------------
# Метрики
# ----------------------------
if CFG.metrics_enabled and prometheus_client:
    HTTP_REQUESTS = Counter(
        "http_requests_total", "HTTP requests", ["method", "path", "status"]
    )
    HTTP_LATENCY = Histogram(
        "http_request_duration_seconds", "HTTP request latency", ["method", "path"]
    )
    RISK_EVALS = Counter(
        "risk_evaluations_total", "Risk evaluations", ["decision", "status"]
    )
    READY = Gauge("ready", "Readiness state (1 ready, 0 not)")
else:
    HTTP_REQUESTS = HTTP_LATENCY = RISK_EVALS = READY = None  # type: ignore


def _start_metrics_server() -> None:
    if CFG.metrics_enabled and start_http_server:
        start_http_server(CFG.metrics_port)
        log.info("metrics server started", extra={"path": "/metrics", "status": 200})


# ----------------------------
# Модели Pydantic
# ----------------------------

class RiskSignalsModel(BaseModel):
    identity_risk: float = 0
    device_posture: float = 0
    network_risk: float = 0
    resource_sensitivity: float = 0
    behavior_risk: float = 0
    threat_intel: float = 0
    time_risk: float = 0
    extra: Dict[str, float] = {}


class GeoModel(BaseModel):
    lat: float
    lon: float


class DetectEventModel(BaseModel):
    correlation_id: Optional[str] = None
    timestamp: Optional[str | int | float] = None
    source: Optional[str] = "API"

    actor_id: Optional[str] = None
    device_id: Optional[str] = None

    network_ip: Optional[str] = None
    geo: Optional[GeoModel] = None

    resource_id: Optional[str] = None
    resource_kind: Optional[str] = None
    resource_action: Optional[str] = None
    resource_path: Optional[str] = None

    signals: RiskSignalsModel = Field(default_factory=RiskSignalsModel)
    context: Dict[str, Any] = Field(default_factory=dict)


class EvaluateRequestModel(BaseModel):
    event: DetectEventModel
    explain: bool = True


# ----------------------------
# JWT / OIDC валидация (опционально)
# ----------------------------

class JwtValidator:
    def __init__(self, issuer: str, audience: str, cache_ttl: int = 300):
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.cache_ttl = cache_ttl
        self._jwks: Optional[Dict[str, Any]] = None
        self._jwks_exp: float = 0.0

    async def _get_jwks(self) -> Dict[str, Any]:
        if not httpx or not jwt:
            raise RuntimeError("JWT/OIDC недоступны: отсутствуют httpx/PyJWT")
        now = time.time()
        if self._jwks and now < self._jwks_exp:
            return self._jwks
        # OIDC Discovery
        well_known = f"{self.issuer}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(well_known)
            r.raise_for_status()
            jwks_uri = r.json()["jwks_uri"]
            jwks = (await client.get(jwks_uri)).json()
        self._jwks = jwks
        self._jwks_exp = now + self.cache_ttl
        return jwks

    async def validate(self, token: str) -> Dict[str, Any]:
        if not self.issuer:
            raise HTTPException(status_code=401, detail="OIDC issuer not configured")
        if not jwt:
            raise HTTPException(status_code=501, detail="JWT library not available")
        jwks = await self._get_jwks()
        try:
            # PyJWT>=2.8 supports JWKS via algorithms & options
            decoded = jwt.decode(
                token,
                key=jwt.PyJWKClient(jwks_url="").get_signing_key_from_jwt,  # type: ignore
                algorithms=["RS256", "ES256", "PS256", "RS512", "ES512"],
                audience=self.audience or None,
                options={"verify_aud": bool(self.audience)},
                issuer=self.issuer,
            )
        except Exception as e:
            # Fallback: manual JWKS
            try:
                headers = jwt.get_unverified_header(token)
                kid = headers.get("kid")
                key = None
                for k in jwks.get("keys", []):
                    if k.get("kid") == kid:
                        key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))  # type: ignore
                        break
                if not key:
                    raise
                decoded = jwt.decode(
                    token,
                    key=key,
                    algorithms=["RS256", "ES256", "PS256", "RS512", "ES512"],
                    audience=self.audience or None,
                    options={"verify_aud": bool(self.audience)},
                    issuer=self.issuer,
                )
            except Exception as e2:
                log.warning("jwt validation failed: %s", str(e2))
                raise HTTPException(status_code=401, detail="invalid token")
        return decoded


jwt_validator = JwtValidator(CFG.oidc_issuer, CFG.oidc_audience, CFG.oidc_cache_sec) if CFG.auth_mode == "oidc" else None


async def auth_dependency(request: Request) -> Dict[str, Any]:
    if CFG.auth_mode == "local":
        return {"sub": "dev-user"}
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    if not jwt_validator:
        raise HTTPException(status_code=501, detail="OIDC not configured")
    return await jwt_validator.validate(token)


# ----------------------------
# Rate limiting
# ----------------------------

class TokenBucket:
    def __init__(self, rate_per_min: int, burst: int):
        self.capacity = burst
        self.tokens = burst
        self.rate = rate_per_min / 60.0
        self.ts = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        delta = now - self.ts
        self.ts = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    def __init__(self, default_rate: str, burst: int):
        self._buckets: Dict[str, TokenBucket] = {}
        self.rate = self._parse_rate(default_rate)
        self.burst = burst
        self._redis = None
        if CFG.redis_url and redis:
            try:
                self._redis = redis.Redis.from_url(CFG.redis_url, decode_responses=True)
            except Exception as e:
                log.warning("redis unavailable: %s", str(e))

    @staticmethod
    def _parse_rate(s: str) -> int:
        # "100r/m" -> 100
        try:
            return int(s.split("r/")[0])
        except Exception:
            return 100

    async def check(self, key: str) -> bool:
        if self._redis:
            # простой инкремент с TTL
            k = f"rl:{key}"
            pipe = self._redis.pipeline()
            pipe.incr(k, 1)
            pipe.expire(k, 60)
            count, _ = pipe.execute()
            return int(count) <= self.rate + CFG.ratelimit_burst
        # in-memory
        bucket = self._buckets.get(key)
        if not bucket:
            bucket = self._buckets.setdefault(key, TokenBucket(self.rate, self.burst))
        return bucket.allow()


rate_limiter = RateLimiter(CFG.ratelimit_default, CFG.ratelimit_burst) if CFG.ratelimit_enabled else None


# ----------------------------
# Risk scoring client
# ----------------------------

class RiskClient:
    def __init__(self):
        self.mode = CFG.risk_mode
        self._http = httpx.AsyncClient(timeout=3.0) if (self.mode == "http" and httpx) else None
        self._pep = None
        if PepDecisionCache:
            try:
                self._pep = PepDecisionCache(
                    capacity=CFG.pep_cache_capacity,
                    default_ttl=float(CFG.pep_cache_ttl_sec),
                    allow_negative=CFG.pep_negative_cache,
                )
            except Exception:
                self._pep = None

    async def close(self) -> None:
        if self._http:
            await self._http.aclose()

    async def evaluate(self, event: Dict[str, Any], explain: bool = True) -> Dict[str, Any]:
        key = f"{event.get('actor_id','')}|{event.get('device_id','')}|{event.get('resource_id','')}"
        # Попытка кэша: только для позитивных результатов
        if self._pep:
            res = self._pep.get(key)
            if res:
                return {
                    "correlation_id": _ulid(),
                    "decision": res.effect,
                    "score": 0.0,
                    "score_raw": 0.0,
                    "factors": [] if not explain else [],
                    "hard_rule_triggered": None,
                    "thresholds": {
                        "allow": CFG.thr_allow,
                        "mfa": CFG.thr_mfa,
                        "deny": CFG.thr_deny,
                        "quarantine": CFG.thr_quarantine,
                    },
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "cached": True,
                }

        if self.mode == "off":
            result = {
                "correlation_id": event.get("correlation_id") or _ulid(),
                "score_raw": 0.0,
                "score": 0.0,
                "decision": "ALLOW",
                "hard_rule_triggered": None,
                "thresholds": {
                    "allow": CFG.thr_allow,
                    "mfa": CFG.thr_mfa,
                    "deny": CFG.thr_deny,
                    "quarantine": CFG.thr_quarantine,
                },
                "factors": [] if not explain else [],
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        elif self.mode == "http":
            if not self._http:
                raise HTTPException(status_code=503, detail="risk http client unavailable")
            try:
                r = await self._http.post(CFG.risk_http_url, json={"event": event, "explain": explain})
                r.raise_for_status()
                result = r.json()
            except Exception as e:
                log.error("risk http error: %s", str(e))
                raise HTTPException(status_code=502, detail="risk scorer http error")
        else:  # cli
            try:
                args = [CFG.risk_cli_bin, CFG.risk_cli_script, "evaluate", "--format", "json", "--state", CFG.risk_state_path]
                if CFG.risk_weights:
                    args.extend(["--weights", CFG.risk_weights])
                proc = subprocess.run(
                    args,
                    input=json.dumps(event).encode("utf-8"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5.0,
                )
                if proc.returncode != 0:
                    log.error("risk cli exit=%s stderr=%s", proc.returncode, proc.stderr.decode("utf-8", "ignore"))
                    raise HTTPException(status_code=502, detail="risk scorer cli error")
                result = json.loads(proc.stdout.decode("utf-8"))
            except subprocess.TimeoutExpired:
                raise HTTPException(status_code=504, detail="risk scorer timeout")
            except Exception as e:
                log.error("risk cli exception: %s", str(e))
                raise HTTPException(status_code=502, detail="risk scorer failure")

        # Сохранение в кэш
        if self._pep:
            try:
                eff = result.get("decision")
                if eff in ("ALLOW", "MFA", "LIMITED", "DENY", "QUARANTINE"):
                    self._pep.put(key, Decision(effect=eff, policy_id="api", reason="risk"), ttl=float(CFG.pep_cache_ttl_sec))  # type: ignore
            except Exception:
                pass

        return result


risk_client = RiskClient()


# ----------------------------
# FastAPI приложение
# ----------------------------

app = FastAPI(
    title="VeilMind Core API",
    version=os.getenv("APP_VERSION", "0.1.0"),
    docs_url="/docs" if CFG.env != "prod" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if CFG.env != "prod" else None,
)

# CORS
if CFG.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in CFG.cors_allow_origins.split(",") if o.strip()],
        allow_methods=[m.strip() for m in CFG.cors_allow_methods.split(",") if m.strip()],
        allow_headers=[h.strip() for h in CFG.cors_allow_headers.split(",") if h.strip()],
        allow_credentials=CFG.cors_allow_credentials,
    )

# GZip
app.add_middleware(GZipMiddleware, minimum_size=1024)


# Middleware: request id + логирование + метрики
@app.middleware("http")
async def _logging_and_metrics(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or _ulid()
    start = time.perf_counter()
    try:
        response: Response = await call_next(request)
        status = response.status_code
    except Exception as e:
        status = 500
        raise
    finally:
        dur = (time.perf_counter() - start)
        path = request.url.path
        method = request.method
        extra = {"request_id": rid, "path": path, "method": method, "status": status, "latency_ms": round(dur * 1000, 2)}
        log.info("request", extra=extra)
        if HTTP_REQUESTS and HTTP_LATENCY:
            HTTP_REQUESTS.labels(method=method, path=path, status=str(status)).inc()
            HTTP_LATENCY.labels(method=method, path=path).observe(dur)
    # проставляем request id
    response.headers["X-Request-ID"] = rid
    return response


# Health
@app.get("/healthz/live", include_in_schema=False)
async def live():
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}


@app.get("/healthz/ready", include_in_schema=False)
async def ready():
    ok = True
    if CFG.auth_mode == "oidc" and not jwt:
        ok = False
    if READY:
        READY.set(1 if ok else 0)
    return {"status": "ok" if ok else "degraded", "ts": datetime.now(timezone.utc).isoformat()}


# Основной эндпоинт детекции
@app.post("/v1/detect/evaluate")
async def evaluate(req: EvaluateRequestModel, principal: Dict[str, Any] = Depends(auth_dependency) if CFG.auth_mode != "local" else {}):
    # Rate limit
    if rate_limiter:
        key = principal.get("sub") if principal else req.event.actor_id or (req.event.network_ip or "anon")
        allowed = await rate_limiter.check(f"eval:{key}")
        if not allowed:
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    # Сбор и нормализация события
    ev = req.event.dict()
    ev["correlation_id"] = ev.get("correlation_id") or _ulid()
    ev["timestamp"] = ev.get("timestamp") or datetime.now(timezone.utc).isoformat()
    if principal and not ev.get("actor_id"):
        ev["actor_id"] = principal.get("sub") or principal.get("email") or "user"
    # Сопоставление ресурсных атрибутов
    resource = {
        "resource_id": ev.get("resource_id") or "",
        "resource_kind": ev.get("resource_kind") or "http",
        "resource_action": ev.get("resource_action") or "access",
        "resource_path": ev.get("resource_path") or "",
    }
    ev.update(resource)

    # Вызов риск‑скорера
    result = await risk_client.evaluate(
        event={
            "actor_id": ev.get("actor_id"),
            "device_id": ev.get("device_id"),
            "timestamp": ev.get("timestamp"),
            "identity_risk": ev["signals"]["identity_risk"],
            "device_posture": ev["signals"]["device_posture"],
            "network_risk": ev["signals"]["network_risk"],
            "resource_sensitivity": ev["signals"]["resource_sensitivity"],
            "behavior_risk": ev["signals"]["behavior_risk"],
            "threat_intel": ev["signals"]["threat_intel"],
            "time_risk": ev["signals"]["time_risk"],
            "geo": ev.get("geo"),
            "ip": ev.get("network_ip"),
        },
        explain=req.explain,
    )

    # Общее оформление ответа и метрики
    decision = result.get("decision", "ALLOW")
    if RISK_EVALS:
        RISK_EVALS.labels(decision=decision, status="ok").inc()
    return JSONResponse(result, status_code=200)


# Глобальные обработчики ошибок
@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if RISK_EVALS and request.url.path.endswith("/v1/detect/evaluate"):
        RISK_EVALS.labels(decision="n/a", status=str(exc.status_code)).inc()
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.exception_handler(ValidationError)
async def validation_exc_handler(request: Request, exc: ValidationError):
    return JSONResponse({"error": "validation error", "details": exc.errors()}, status_code=422)


@app.on_event("startup")
async def on_startup():
    _start_metrics_server()
    if READY:
        READY.set(1)


@app.on_event("shutdown")
async def on_shutdown():
    await risk_client.close()


# ----------------------------
# Точка входа
# ----------------------------
def run() -> None:  # pragma: no cover
    """
    Запуск: uvicorn veilmind_core.api.http.server:app --host 0.0.0.0 --port 8080
    или:    python -m veilmind_core.api.http.server
    """
    try:
        import uvicorn  # type: ignore
    except Exception:
        log.error("uvicorn не установлен. Установите: pip install uvicorn[standard]")
        sys.exit(1)

    uvicorn.run(
        "veilmind_core.api.http.server:app",
        host=CFG.host,
        port=CFG.port,
        log_level=CFG.log_level.lower(),
        reload=CFG.env in ("dev", "local"),
        workers=1,
    )


if __name__ == "__main__":  # pragma: no cover
    run()
