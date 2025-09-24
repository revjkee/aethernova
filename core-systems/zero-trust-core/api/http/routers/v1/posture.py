# -*- coding: utf-8 -*-
"""
Zero Trust Core — Device Posture & Attestation Router (FastAPI).

Функции:
  - POST /v1/posture/attest    — верификация аттестации + оценка позы
  - POST /v1/posture/evaluate  — оценка позы (без аттестации)
  - GET  /v1/posture/policy    — публикация активной политики позы

Безопасность:
  - HMAC подпись тела запроса (x-zt-signature: sha256=<hex>) — опционно
  - mTLS SPKI pin (x-client-spki) — опционно, при включении обязателен
  - Rate limit per-IP (token bucket)
  - Idempotency по nonce (защита от повторной аттестации)
  - Редакция чувствительных полей в логах
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import logging
import os
import socket
import threading
import time
import typing as t
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, conint, constr, validator

# ------------------------------------------------------------------------------
# Конфигурация через ENV
# ------------------------------------------------------------------------------

@dataclass(frozen=True)
class Settings:
    # Транспорт/защита
    hmac_header: str = os.getenv("ZTC_HMAC_HEADER", "x-zt-signature")
    hmac_secret_b64: str | None = os.getenv("ZTC_HMAC_B64")  # если задано — HMAC обязателен
    mtls_pins_csv: str | None = os.getenv("ZTC_SPKI_PINS_B64")  # "b64sha256A,b64sha256B"
    # Пороговая политика
    os_patch_max_days: int = int(os.getenv("ZTC_OS_PATCH_MAX_DAYS", "30"))
    allowed_os_csv: str = os.getenv("ZTC_ALLOWED_OS", "ios,android,macos,windows,linux")
    require_secure_boot: bool = os.getenv("ZTC_REQUIRE_SECURE_BOOT", "true").lower() == "true"
    require_disk_encryption: bool = os.getenv("ZTC_REQUIRE_DISK_ENCRYPTION", "true").lower() == "true"
    # Шаг‑ап и риск‑пороги
    risk_stepup_threshold: int = int(os.getenv("ZTC_RISK_STEPUP", "40"))
    risk_critical_threshold: int = int(os.getenv("ZTC_RISK_CRITICAL", "90"))
    # Внешний сервис аттестации
    attestation_url: str | None = os.getenv("ZTC_ATTEST_URL")  # если None — аттестация оценивается как unsupported
    attestation_timeout_sec: float = float(os.getenv("ZTC_ATTEST_TIMEOUT", "3"))
    # Rate limit
    rl_per_minute: int = int(os.getenv("ZTC_RL_PER_MIN", "120"))
    rl_burst: int = int(os.getenv("ZTC_RL_BURST", "40"))
    # Логирование
    log_level: str = os.getenv("ZTC_LOG_LEVEL", "INFO")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    s = Settings()
    logging.getLogger(__name__).setLevel(getattr(logging, s.log_level.upper(), logging.INFO))
    return s


# ------------------------------------------------------------------------------
# Утилиты
# ------------------------------------------------------------------------------

logger = logging.getLogger("ztc.posture")
if not logger.handlers:
    h = logging.StreamHandler()
    fmt = logging.Formatter("%(asctime)s %(levelname)s ztc.posture %(message)s")
    h.setFormatter(fmt)
    logger.addHandler(h)
logger.setLevel(logging.INFO)


def redact(obj: t.Any) -> t.Any:
    """
    Минимальная редакция PII/секретов в логах.
    """
    try:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in ("authorization", "cookie", "set-cookie", "token", "secret", "assertion", "evidence"):
                    out[k] = "***"
                else:
                    out[k] = redact(v)
            return out
        if isinstance(obj, list):
            return [redact(x) for x in obj]
        if isinstance(obj, str) and len(obj) > 128:
            return obj[:64] + "…"
        return obj
    except Exception:
        return "<unloggable>"


def client_ip(req: Request) -> str:
    return req.headers.get("x-real-ip") or req.client.host or "0.0.0.0"  # type: ignore[union-attr]


def require_hmac(req: Request, body_bytes: bytes, settings: Settings) -> None:
    if not settings.hmac_secret_b64:
        return
    header = req.headers.get(settings.hmac_header.lower()) or req.headers.get(settings.hmac_header)
    if not header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="signature required")
    if not header.startswith("sha256="):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature scheme")
    key = base64.b64decode(settings.hmac_secret_b64)
    expected = hmac.new(key, body_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, header.split("=", 1)[1]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature")


def check_spki_pin(req: Request, settings: Settings) -> None:
    pins = tuple((settings.mtls_pins_csv or "").split(",")) if settings.mtls_pins_csv else ()
    if not pins:
        return
    spki = req.headers.get("x-client-spki")
    if not spki or spki not in pins:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="mTLS pin mismatch")


# ------------------------------------------------------------------------------
# Rate limit (in‑memory token bucket per IP)
# ------------------------------------------------------------------------------

class _Bucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, tokens: float, updated: float):
        self.tokens = tokens
        self.updated = updated


class RateLimiter:
    def __init__(self, per_minute: int, burst: int):
        self.rate = float(per_minute) / 60.0
        self.burst = float(burst)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(key)
            if not b:
                b = _Bucket(tokens=self.burst, updated=now)
                self._buckets[key] = b
            # refill
            delta = now - b.updated
            b.tokens = min(self.burst, b.tokens + delta * self.rate)
            b.updated = now
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True
            return False


_rl = None
def get_rl(settings: Settings = Depends(get_settings)) -> RateLimiter:
    global _rl
    if _rl is None:
        _rl = RateLimiter(settings.rl_per_minute, settings.rl_burst)
    return _rl


# ------------------------------------------------------------------------------
# Схемы запросов/ответов
# ------------------------------------------------------------------------------

class Attestation(BaseModel):
    kind: constr(strip_whitespace=True, to_lower=True) = Field(..., description="android_play_integrity|apple_devicecheck|tpm|custom|none")
    format: constr(strip_whitespace=True, to_lower=True) = Field(..., description="jwt|cbor|json|binary")
    evidence: str = Field(..., description="JWT/COSE/Quote/Blob в виде строки (base64/jws)")
    nonce: constr(min_length=8, max_length=128) = Field(..., description="Уникальный одноразовый nonce клиента")
    timestamp: int = Field(..., description="Unix epoch сек")

class DevicePosture(BaseModel):
    device_id: constr(strip_whitespace=True, min_length=3, max_length=128)
    os: constr(to_lower=True) = Field(..., description="ios|android|macos|windows|linux")
    os_version: constr(strip_whitespace=True, min_length=1, max_length=64)
    os_patch_age_days: conint(ge=0, le=3650) = 0
    secure_boot: bool = True
    disk_encrypted: bool = True
    jailbroken: bool | None = None
    rooted: bool | None = None
    attestation: Attestation | None = None

    @validator("os")
    def _os_allowed(cls, v: str) -> str:
        return v.lower()

class ContextHeaders(BaseModel):
    tenant_id: str = "default"
    user_id: str = "anonymous"
    roles: list[str] = []
    correlation_id: str | None = None
    spki_b64: str | None = None
    ip: str | None = None
    ua: str | None = None

class PostureEvaluateRequest(BaseModel):
    posture: DevicePosture

class PostureAttestRequest(BaseModel):
    posture: DevicePosture

class PolicyView(BaseModel):
    allowed_os: list[str]
    require_secure_boot: bool
    require_disk_encryption: bool
    os_patch_max_days: int
    risk_stepup_threshold: int
    risk_critical_threshold: int

class PostureDecision(BaseModel):
    compliance: bool
    reasons: list[str]
    risk_score: conint(ge=0, le=100)
    step_up_required: bool
    required_aal: str = "AAL1"
    attestation:
        dict | None = None
    cache_ttl_sec: int = 60
    server_time_utc: int


# ------------------------------------------------------------------------------
# Контекст и зависимости
# ------------------------------------------------------------------------------

def get_ctx(req: Request, settings: Settings = Depends(get_settings)) -> ContextHeaders:
    hdr = req.headers
    roles = [r for r in (hdr.get("x-roles") or "").split(",") if r]
    return ContextHeaders(
        tenant_id=hdr.get("x-tenant-id", "default"),
        user_id=hdr.get("x-user-id", "anonymous"),
        roles=roles,
        correlation_id=hdr.get("x-correlation-id"),
        spki_b64=hdr.get("x-client-spki"),
        ip=client_ip(req),
        ua=hdr.get("user-agent", "unknown"),
    )


# ------------------------------------------------------------------------------
# Внешний валидатор аттестации (гейтвей)
# ------------------------------------------------------------------------------

class AttestationGateway:
    def __init__(self, base_url: str, timeout: float):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def verify(self, att: Attestation, ctx: ContextHeaders) -> dict:
        """
        Вызывает внешний сервис валидации аттестации. Ожидаемый ответ:
        { "result": "PASSED|FAILED|UNSUPPORTED", "vendor": "...", "details": { ... } }
        """
        payload = {
            "kind": att.kind,
            "format": att.format,
            "evidence": att.evidence,
            "nonce": att.nonce,
            "timestamp": att.timestamp,
            "tenant_id": ctx.tenant_id,
            "user_id": ctx.user_id,
        }
        data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self.base + "/v1/attest/verify", data=data, method="POST")
        req.add_header("content-type", "application/json")
        req.add_header("accept", "application/json")
        req.add_header("x-tenant-id", ctx.tenant_id)
        if ctx.correlation_id:
            req.add_header("x-correlation-id", ctx.correlation_id)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                code = resp.getcode()
            if code // 100 != 2:
                raise HTTPException(status_code=502, detail="attestation gateway error")
            return json.loads(raw.decode("utf-8") or "{}")
        except (urllib.error.URLError, socket.timeout) as e:
            raise HTTPException(status_code=504, detail="attestation gateway timeout")


# ------------------------------------------------------------------------------
# Оценка комплаенса и риска
# ------------------------------------------------------------------------------

def evaluate_policy(posture: DevicePosture, settings: Settings) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    allowlist = [x.strip().lower() for x in settings.allowed_os_csv.split(",") if x.strip()]
    if posture.os.lower() not in allowlist:
        reasons.append("os_not_allowed")
    if settings.require_secure_boot and not posture.secure_boot:
        reasons.append("secure_boot_required")
    if settings.require_disk_encryption and not posture.disk_encrypted:
        reasons.append("disk_encryption_required")
    if posture.os_patch_age_days > settings.os_patch_max_days:
        reasons.append("os_patch_outdated")
    if posture.jailbroken is True or posture.rooted is True:
        reasons.append("device_compromised")
    return (len(reasons) == 0, reasons)


def score_risk(
    *,
    posture: DevicePosture,
    attestation_result: str | None,
    ctx: ContextHeaders,
    settings: Settings,
) -> int:
    """
    Простая детерминированная модель риска (0..100) в духе risk_engine.yaml.
    """
    score = 10
    # device posture
    if posture.os_patch_age_days > settings.os_patch_max_days:
        score += 15
    if not posture.secure_boot:
        score += 20
    if not posture.disk_encrypted:
        score += 20
    if posture.jailbroken or posture.rooted:
        score += 25
    # attestation
    if attestation_result == "FAILED":
        score += 30
    elif attestation_result == "UNSUPPORTED":
        score += 5
    # сетевые/контекстные эвристики (упрощённые)
    if ctx.ip and any(ctx.ip.startswith(pfx) for pfx in ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.")):
        score += 0
    else:
        score += 4  # неизвестная сеть
    return max(0, min(100, score))


def decision_from_score(score: int, settings: Settings) -> tuple[bool, str]:
    stepup = score >= settings.risk_stepup_threshold
    aal = "AAL2" if stepup else "AAL1"
    return stepup, aal


# ------------------------------------------------------------------------------
# Анти‑replay/идемпотентность по nonce
# ------------------------------------------------------------------------------

_nonce_cache: dict[str, float] = {}
_nonce_lock = threading.Lock()

def nonce_seen(nonce: str, ttl_sec: int = 60) -> bool:
    now = time.time()
    with _nonce_lock:
        # очистка по пути
        for k, ts in list(_nonce_cache.items()):
            if now - ts > ttl_sec:
                _nonce_cache.pop(k, None)
        if nonce in _nonce_cache:
            return True
        _nonce_cache[nonce] = now
        return False


# ------------------------------------------------------------------------------
# Роутер
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/posture", tags=["posture"])


@router.get("/policy", response_model=PolicyView)
def get_policy(settings: Settings = Depends(get_settings)):
    """
    Возвращает активную политику позы (для клиентов/агентов).
    """
    return PolicyView(
        allowed_os=[x.strip().lower() for x in settings.allowed_os_csv.split(",") if x.strip()],
        require_secure_boot=settings.require_secure_boot,
        require_disk_encryption=settings.require_disk_encryption,
        os_patch_max_days=settings.os_patch_max_days,
        risk_stepup_threshold=settings.risk_stepup_threshold,
        risk_critical_threshold=settings.risk_critical_threshold,
    )


@router.post("/evaluate", response_model=PostureDecision, status_code=200)
async def evaluate(
    req: Request,
    payload: PostureEvaluateRequest,
    ctx: ContextHeaders = Depends(get_ctx),
    settings: Settings = Depends(get_settings),
    rl: RateLimiter = Depends(get_rl),
):
    """
    Оценка позы устройства без аттестации (быстрый путь).
    """
    # Rate limit
    ip = ctx.ip or "unknown"
    if not rl.allow(f"eval:{ip}"):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    # Транспортные проверки
    raw = await req.body()
    require_hmac(req, raw, settings)
    check_spki_pin(req, settings)

    posture = payload.posture
    compliance, reasons = evaluate_policy(posture, settings)
    risk = score_risk(posture=posture, attestation_result=None, ctx=ctx, settings=settings)
    stepup, aal = decision_from_score(risk, settings)

    logger.info("posture.evaluate ctx=%s body=%s result=%s",
                redact(ctx.dict()), redact(posture.dict()), redact({"risk": risk, "compliance": compliance}))

    return PostureDecision(
        compliance=compliance,
        reasons=reasons,
        risk_score=risk,
        step_up_required=stepup,
        required_aal=aal,
        attestation=None,
        cache_ttl_sec=60,
        server_time_utc=int(time.time()),
    )


@router.post("/attest", response_model=PostureDecision, status_code=200)
async def attest(
    req: Request,
    payload: PostureAttestRequest,
    ctx: ContextHeaders = Depends(get_ctx),
    settings: Settings = Depends(get_settings),
    rl: RateLimiter = Depends(get_rl),
):
    """
    Полная проверка: аттестация устройства + оценка позы.
    """
    # Rate limit
    ip = ctx.ip or "unknown"
    if not rl.allow(f"attest:{ip}"):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    # Транспортные проверки
    raw = await req.body()
    require_hmac(req, raw, settings)
    check_spki_pin(req, settings)

    posture = payload.posture
    att = posture.attestation
    if not att:
        raise HTTPException(status_code=400, detail="attestation required")

    # Защита от повторов
    if nonce_seen(att.nonce):
        raise HTTPException(status_code=409, detail="duplicate nonce")

    # Вызов внешнего валидатора (если сконфигурирован)
    att_result = {"result": "UNSUPPORTED", "vendor": "", "details": {}}
    if settings.attestation_url:
        gw = AttestationGateway(settings.attestation_url, settings.attestation_timeout_sec)
        att_result = gw.verify(att, ctx)
        # Ожидаются значения: PASSED|FAILED|UNSUPPORTED
        if att_result.get("result") not in ("PASSED", "FAILED", "UNSUPPORTED"):
            raise HTTPException(status_code=502, detail="invalid attestation gateway response")

    # Политика и риск
    compliance, reasons = evaluate_policy(posture, settings)
    # Если аттестация FAIL — добавим причину non_compliant
    if att_result.get("result") == "FAILED":
        reasons.append("attestation_failed")
        compliance = False

    risk = score_risk(posture=posture, attestation_result=att_result.get("result"), ctx=ctx, settings=settings)
    stepup, aal = decision_from_score(risk, settings)

    logger.info("posture.attest ctx=%s posture=%s attestation=%s decision=%s",
                redact(ctx.dict()),
                redact(posture.dict()),
                redact(att_result),
                redact({"risk": risk, "compliance": compliance, "stepup": stepup}),
                )

    return PostureDecision(
        compliance=compliance,
        reasons=reasons,
        risk_score=risk,
        step_up_required=stepup,
        required_aal=aal,
        attestation=att_result,
        cache_ttl_sec=60,
        server_time_utc=int(time.time()),
    )
