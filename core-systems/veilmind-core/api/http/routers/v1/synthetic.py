# -*- coding: utf-8 -*-
"""
Synthetic router (v1) for veilmind-core.
Назначение:
  - Простейший детерминированный PEP/PDP для dev/smoke/канареек
  - Health/ready пробы
  - Эхо/хаос для проверки сетевой плоскости, редактирования, прокси
  - Буферная телеметрия
Особенности:
  - Problem+JSON ошибки (RFC 7807)
  - X-Trace-Id корреляция (+ генерация при отсутствии)
  - Idempotency-Key с TTL-кэшем для POST
  - Строгая валидация входа, ограничение размера телеметрии
  - Без внешних зависимостей, кроме FastAPI/Pydantic/Starlette
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import random
import re
import time
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, validator

router = APIRouter(prefix="/v1/synthetic", tags=["synthetic"])

# ----------------------------- УТИЛИТЫ/КОНСТАНТЫ -----------------------------

VERSION = os.getenv("VEILMIND_VERSION", "dev")
STARTED_AT = time.time()
TRACE_HEADER = "X-Trace-Id"
AGENT_HEADER = "X-Server-Agent"
IDEMPOTENCY_HEADER = "Idempotency-Key"

SAFE_RESPONSE_HEADERS = {
    AGENT_HEADER: f"veilmind-synthetic/{VERSION}",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}

RISK_BANDS = [
    ("low", (0, 29.999), "allow"),
    ("medium", (30, 59.999), "step_up"),
    ("high", (60, 79.999), "quarantine"),
    ("critical", (80, 100), "deny"),
]


def now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def gen_trace_id() -> str:
    # 128-бит в hex
    r = os.urandom(16)
    return r.hex()


def pick_headers(headers: Iterable[Tuple[str, str]], allow: Iterable[str]) -> Dict[str, str]:
    allow_lc = {h.lower() for h in allow}
    out: Dict[str, str] = {}
    for k, v in headers:
        if k.lower() in allow_lc:
            out[k] = v
    return out


def problem(status_code: int, title: str, detail: Optional[str] = None, trace_id: Optional[str] = None) -> JSONResponse:
    body = {
        "type": "about:blank",
        "title": title,
        "status": status_code,
        "detail": detail,
    }
    if trace_id:
        body["traceId"] = trace_id
    return JSONResponse(status_code=status_code, content=body, headers=SAFE_RESPONSE_HEADERS)


# ----------------------------- TTL-LRU для идемпотентности -------------------

class _TtlLru:
    """Простой TTL-LRU кэш для Idempotency-Key."""
    def __init__(self, maxsize: int = 2048, ttl_seconds: int = 300) -> None:
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._store: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()

    def _purge(self) -> None:
        now = time.time()
        # удалить просроченные
        to_del: List[str] = []
        for k, (ts, _) in self._store.items():
            if now - ts > self.ttl:
                to_del.append(k)
            else:
                break  # порядок гарантирует, что дальше свежее
        for k in to_del:
            self._store.pop(k, None)
        # ограничить размер
        while len(self._store) > self.maxsize:
            self._store.popitem(last=False)

    def get(self, key: Optional[str]) -> Optional[Any]:
        if not key:
            return None
        self._purge()
        val = self._store.get(key)
        if not val:
            return None
        ts, data = val
        # move-to-end
        self._store.move_to_end(key, last=True)
        return data

    def put(self, key: Optional[str], value: Any) -> None:
        if not key:
            return
        self._purge()
        self._store[key] = (time.time(), value)
        self._store.move_to_end(key, last=True)


IDEMPOTENCY_CACHE = _TtlLru()

# ----------------------------- Pydantic модели --------------------------------

class Subject(BaseModel):
    user: Optional[Dict[str, Any]] = None
    device: Optional[Dict[str, Any]] = None
    session: Optional[Dict[str, Any]] = None


class ResourceRef(BaseModel):
    id: Optional[str] = None
    labels: Optional[Dict[str, str]] = None


Action = Literal["read", "list", "write", "delete", "admin"]


class EnvironmentCtx(BaseModel):
    ip: Optional[str] = None
    geo: Optional[str] = None
    asn: Optional[int] = None
    userAgent: Optional[str] = None
    timestamp: Optional[str] = None


class DecisionRequest(BaseModel):
    subject: Subject
    action: Action
    resource: ResourceRef
    environment: Optional[EnvironmentCtx] = None
    context: Optional[Dict[str, Any]] = None

    idempotencyKey: Optional[str] = Field(default=None, alias="idempotencyKey")


class Obligation(BaseModel):
    type: Literal["mfa", "header", "mask", "route", "log"]
    params: Optional[Dict[str, Any]] = None


DecisionAction = Literal["allow", "step_up", "quarantine", "deny"]


class DecisionResponse(BaseModel):
    decision: DecisionAction
    reason: Optional[str] = None
    score: Optional[Dict[str, Any]] = None
    obligations: Optional[List[Obligation]] = None
    policy: Optional[Dict[str, Any]] = None
    traceId: Optional[str] = None


class RiskScoreRequest(BaseModel):
    subject: Subject
    resource: Optional[ResourceRef] = None
    action: Optional[Action] = None
    environment: Optional[EnvironmentCtx] = None
    signals: Optional[Dict[str, Any]] = None


class RiskScoreResponse(BaseModel):
    total: float
    band: Literal["low", "medium", "high", "critical"]
    explanations: Optional[List[Dict[str, Any]]] = None
    traceId: Optional[str] = None


class TelemetryEvent(BaseModel):
    type: Literal["access", "risk", "audit", "custom"]
    ts: Optional[str] = None
    subject: Optional[Dict[str, Any]] = None
    fields: Optional[Dict[str, Any]] = None

    @validator("ts", always=True)
    def _ensure_ts(cls, v: Optional[str]) -> str:
        return v or now_rfc3339()


class TelemetryBatch(BaseModel):
    events: List[TelemetryEvent]

    @validator("events")
    def _limit(cls, v: List[TelemetryEvent]) -> List[TelemetryEvent]:
        if len(v) > 1000:
            raise ValueError("too many events (max 1000)")
        return v


# ----------------------------- РИСК/ПОЛИТИКА (детерминированные) --------------

def _band_from_score(score: float) -> str:
    for name, (lo, hi), _ in RISK_BANDS:
        if lo <= score <= hi:
            return name
    return "critical"


def _action_from_band(band: str) -> DecisionAction:
    for name, _, action in RISK_BANDS:
        if band == name:
            return action  # type: ignore[return-value]
    return "deny"


def _score_components(req: RiskScoreRequest) -> Tuple[float, List[Dict[str, Any]]]:
    """Простая модель скоринга, совместимая с ранее описанной политикой."""
    comps: List[Tuple[str, float]] = []

    # user privilege
    priv = (req.subject.user or {}).get("privilege")
    priv_score = {"admin": 15, "ops": 8, "user": 0}.get(priv, 0)
    comps.append(("user.privilege_level", priv_score))

    # action risk
    if req.action:
        action_score = {"read": 0, "list": 2, "write": 10, "delete": 16, "admin": 22}.get(req.action, 0)
        comps.append(("app.action_risk", action_score))

    # resource sensitivity
    sens = ((req.resource or ResourceRef()).labels or {}).get("sensitivity")
    sens_score = {"low": 0, "medium": 6, "high": 12, "secret": 20}.get(sens, 0)
    comps.append(("app.resource_sensitivity", sens_score))

    # ip reputation (0..1 -> 0..18)
    ti = (req.signals or {}).get("threat_intel", {})
    rep = float(ti.get("score", 0.0)) if isinstance(ti, dict) else 0.0
    comps.append(("network.ip_reputation", max(0.0, min(1.0, rep)) * 18.0))

    # idp risk (0..1 -> 0..25)
    idp = (req.signals or {}).get("idp", {})
    idp_risk = float(idp.get("risk_score", 0.0)) if isinstance(idp, dict) else 0.0
    comps.append(("user.risk.idp_last_login", max(0.0, min(1.0, idp_risk)) * 25.0))

    # device posture score 0..100 -> 0..30
    posture = (req.signals or {}).get("posture", {})
    posture_score = float(posture.get("score", 0.0)) if isinstance(posture, dict) else 0.0
    comps.append(("device.posture_score", max(0.0, min(100.0, posture_score)) * 0.30))

    total = sum(v for _, v in comps)
    expl = [{"key": k, "score": round(v, 3)} for k, v in comps]
    return total, expl


# ----------------------------- МИДДЛВАРЬ/ДЕКОР -------------------------------

def _extract_trace_id(request: Request) -> str:
    tid = request.headers.get(TRACE_HEADER)
    return tid or gen_trace_id()


def _with_trace_headers(resp: Response, trace_id: str) -> None:
    resp.headers.update(SAFE_RESPONSE_HEADERS)
    resp.headers[TRACE_HEADER] = trace_id


# ---------------------------------- РОУТЫ -------------------------------------

@router.get("/healthz", summary="Liveness probe")
async def healthz(request: Request) -> JSONResponse:
    trace_id = _extract_trace_id(request)
    body = {
        "status": "ok",
        "version": VERSION,
        "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(STARTED_AT)),
        "uptimeSeconds": round(time.time() - STARTED_AT, 3),
        "now": now_rfc3339(),
    }
    resp = JSONResponse(content=body)
    _with_trace_headers(resp, trace_id)
    return resp


@router.get("/readyz", summary="Readiness probe")
async def readyz(request: Request) -> JSONResponse:
    # Здесь можно добавить быстрые проверки зависимостей (БД, очередь) — опционально
    trace_id = _extract_trace_id(request)
    body = {"ready": True, "version": VERSION, "now": now_rfc3339()}
    resp = JSONResponse(content=body)
    _with_trace_headers(resp, trace_id)
    return resp


@router.get("/echo", summary="Echo request (headers/query)")
async def echo_get(
    request: Request,
    delay_ms: Optional[int] = 0,
    status_code: Optional[int] = None,
) -> JSONResponse:
    trace_id = _extract_trace_id(request)
    if delay_ms and delay_ms > 0:
        await asyncio.sleep(min(delay_ms, 10_000) / 1000.0)
    content = {
        "method": request.method,
        "path": request.url.path,
        "query": dict(request.query_params),
        "client": getattr(request.client, "host", None),
        "headers": pick_headers(request.headers.items(), ["accept", "user-agent", TRACE_HEADER]),
        "now": now_rfc3339(),
        "traceId": trace_id,
    }
    code = status_code or 200
    resp = JSONResponse(status_code=code, content=content)
    _with_trace_headers(resp, trace_id)
    return resp


@router.post("/echo", summary="Echo body back")
async def echo_post(
    request: Request,
    delay_ms: Optional[int] = 0,
    status_code: Optional[int] = None,
) -> Response:
    trace_id = _extract_trace_id(request)
    if delay_ms and delay_ms > 0:
        await asyncio.sleep(min(delay_ms, 10_000) / 1000.0)
    raw = await request.body()
    ct = request.headers.get("content-type", "")
    # Попробуем отдать как JSON, если это JSON
    if ct.lower().startswith("application/json"):
        try:
            payload = json.loads(raw.decode("utf-8") or "null")
        except Exception:
            return problem(status.HTTP_400_BAD_REQUEST, "Invalid JSON", trace_id=trace_id)
        resp = JSONResponse(status_code=status_code or 200, content={"echo": payload, "traceId": trace_id})
        _with_trace_headers(resp, trace_id)
        return resp
    # Иначе — как текст
    resp = PlainTextResponse(status_code=status_code or 200, content=raw.decode("utf-8", "replace"))
    _with_trace_headers(resp, trace_id)
    return resp


@router.get("/chaos", summary="Chaos: induce latency/errors")
async def chaos(
    request: Request,
    kind: Literal["latency", "error", "jitter"] = "latency",
    ms: Optional[int] = 250,
    code: Optional[int] = 500,
) -> JSONResponse:
    trace_id = _extract_trace_id(request)
    if kind == "latency":
        await asyncio.sleep(max(0, (ms or 0)) / 1000.0)
        resp = JSONResponse({"ok": True, "delayMs": ms, "traceId": trace_id})
        _with_trace_headers(resp, trace_id)
        return resp
    if kind == "jitter":
        actual = random.randint(0, max(0, ms or 0))
        await asyncio.sleep(actual / 1000.0)
        resp = JSONResponse({"ok": True, "delayMs": actual, "traceId": trace_id})
        _with_trace_headers(resp, trace_id)
        return resp
    # error
    resp = problem(int(code or 500), "Synthetic error", "chaos requested", trace_id)
    _with_trace_headers(resp, trace_id)
    return resp


@router.post("/risk/score", response_model=RiskScoreResponse, summary="Synthetic risk scoring")
async def risk_score(
    request: Request,
    payload: RiskScoreRequest,
) -> JSONResponse:
    trace_id = _extract_trace_id(request)
    total, expl = _score_components(payload)
    band = _band_from_score(total)
    body = RiskScoreResponse(total=round(total, 3), band=band, explanations=expl, traceId=trace_id).dict()
    resp = JSONResponse(content=body)
    _with_trace_headers(resp, trace_id)
    return resp


@router.post("/decision", response_model=DecisionResponse, summary="Synthetic PEP decision")
async def decision(
    request: Request,
    payload: DecisionRequest,
    response: Response,
    background: BackgroundTasks,
    idempotency_key_header: Optional[str] = Header(None, alias=IDEMPOTENCY_HEADER),
) -> JSONResponse:
    trace_id = _extract_trace_id(request)
    # Идемпотентность: заголовок приоритетнее содержимого
    key = payload.idempotencyKey or idempotency_key_header
    cached = IDEMPOTENCY_CACHE.get(key)
    if cached:
        resp = JSONResponse(content={**cached, "policy": {"matchedRule": "replayed"}, "traceId": trace_id})
        resp.headers[IDEMPOTENCY_HEADER] = key or ""
        resp.headers["Idempotency-Replayed"] = "true"
        _with_trace_headers(resp, trace_id)
        return resp

    # Вычислим риск и базовое действие
    rreq = RiskScoreRequest(
        subject=payload.subject,
        resource=payload.resource,
        action=payload.action,
        environment=payload.environment,
        signals=(payload.context or {}).get("signals") if payload.context else None,
    )
    total, expl = _score_components(rreq)
    band = _band_from_score(total)
    action = _action_from_band(band)

    # Простой guardrail: admin + delete/secret -> минимум step_up/deny
    sens = (payload.resource.labels or {}).get("sensitivity") if payload.resource.labels else None
    priv = (payload.subject.user or {}).get("privilege")
    if priv == "admin" and payload.action in ("delete", "admin") and sens in ("high", "secret"):
        action = "deny"

    obligations: List[Obligation] = []
    if action == "step_up":
        obligations.append(Obligation(type="mfa", params={"methods": ["webauthn", "totp"], "timeoutSeconds": 120}))

    body = DecisionResponse(
        decision=action,
        reason="synthetic_policy",
        score={"total": round(total, 3), "band": band, "explanations": expl},
        obligations=obligations,
        policy={"version": "synthetic-1", "matchedRule": f"band:{band}"},
        traceId=trace_id,
    ).dict()

    # Кэшируем результат для того же Idempotency-Key
    IDEMPOTENCY_CACHE.put(key, body)

    resp = JSONResponse(content=body)
    if key:
        resp.headers[IDEMPOTENCY_HEADER] = key
    _with_trace_headers(resp, trace_id)
    return resp


@router.post("/telemetry/events", summary="Accept telemetry batch")
async def telemetry(
    request: Request,
    batch: TelemetryBatch,
) -> JSONResponse:
    trace_id = _extract_trace_id(request)
    # Простейшая защита от слишком больших тел
    raw_len = int(request.headers.get("content-length") or "0")
    if raw_len and raw_len > 1_000_000:
        return problem(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large", trace_id=trace_id)

    accepted = len(batch.events)
    body = {"accepted": accepted, "traceId": trace_id, "ts": now_rfc3339()}
    resp = JSONResponse(content=body)
    _with_trace_headers(resp, trace_id)
    return resp


@router.post("/echo/redact", summary="Echo with regex redaction")
async def echo_redact(
    request: Request,
    pattern: str = Field(regex=".+"),
    replacement: str = "[REDACTED]",
    flags: Optional[str] = None,
) -> JSONResponse:
    trace_id = _extract_trace_id(request)
    raw = (await request.body()).decode("utf-8", "replace")
    try:
        fl = 0
        if flags:
            for ch in flags:
                fl |= {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}.get(ch, 0)
        rx = re.compile(pattern, fl)
        redacted = rx.sub(replacement, raw)
    except re.error as e:
        return problem(status.HTTP_400_BAD_REQUEST, "invalid regex", str(e), trace_id)
    resp = JSONResponse(content={"inputLen": len(raw), "outputLen": len(redacted), "output": redacted, "traceId": trace_id})
    _with_trace_headers(resp, trace_id)
    return resp
