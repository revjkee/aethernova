# veilmind-core/api/http/routers/v1/risk.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, ValidationError

# Вытягиваем конфигурацию/зависимости и (если есть) метрики из основного сервера.
# Путь относительного импорта: ... = вверх до veilmind_core.api.http
from ...server import CFG, risk_client, rate_limiter, auth_dependency  # type: ignore
try:
    from ...server import RISK_EVALS  # type: ignore
except Exception:  # pragma: no cover
    RISK_EVALS = None  # type: ignore

router = APIRouter(prefix="/v1/risk", tags=["risk"])

# ----------------------------
# Pydantic модели
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


class BatchEvaluateRequestModel(BaseModel):
    events: List[DetectEventModel]
    explain: bool = True
    concurrency: int = Field(default=10, ge=1, le=64)


class BatchItemModel(BaseModel):
    index: int
    status: str  # ok | error
    message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


class BatchEvaluateResponseModel(BaseModel):
    items: List[BatchItemModel]
    partial_failure: bool = False


class DecideRequestModel(BaseModel):
    score: float = Field(ge=0, le=100)
    thresholds: Optional[Dict[str, float]] = None  # allow/mfa/deny/quarantine


class InvalidateCacheRequestModel(BaseModel):
    key: Optional[str] = None
    actor_id: Optional[str] = None

    def ensure_any(self) -> None:
        if not self.key and not self.actor_id:
            raise ValidationError([{
                "type": "value_error",
                "loc": ("key",),
                "msg": "either key or actor_id must be provided",
                "input": None
            }], InvalidateCacheRequestModel)


# ----------------------------
# Вспомогательные функции
# ----------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ulid_like() -> str:
    # допускаем ULID или uuid.hex для корреляции
    import uuid as _uuid
    return _uuid.uuid4().hex


async def _rate_check(principal: Dict[str, Any] | None, ev: DetectEventModel) -> None:
    if not rate_limiter:
        return
    key = (principal or {}).get("sub") or ev.actor_id or (ev.network_ip or "anon")
    ok = await rate_limiter.check(f"eval:{key}")
    if not ok:
        raise HTTPException(status_code=429, detail="rate limit exceeded")


def _normalize_event(ev: DetectEventModel, principal: Dict[str, Any] | None) -> Dict[str, Any]:
    data = ev.dict()
    data["correlation_id"] = data.get("correlation_id") or _ulid_like()
    data["timestamp"] = data.get("timestamp") or _now_iso()
    if principal and not data.get("actor_id"):
        data["actor_id"] = principal.get("sub") or principal.get("email") or "user"
    # Минимальный ресурсный контур
    data["resource_kind"] = data.get("resource_kind") or "http"
    data["resource_action"] = data.get("resource_action") or "access"
    data["resource_path"] = data.get("resource_path") or (data.get("resource_id") or "")
    return data


def _apply_thresholds(score: float, thr: Dict[str, float]) -> str:
    # Решение по возрастающим порогам
    if score < thr["allow"]:
        return "ALLOW"
    if score < thr["mfa"]:
        return "MFA"
    if score < thr["deny"]:
        return "LIMITED"
    if score < thr["quarantine"]:
        return "DENY"
    return "QUARANTINE"


# ----------------------------
# Маршруты
# ----------------------------

@router.post("/evaluate")
async def evaluate_endpoint(body: EvaluateRequestModel,
                            principal: Dict[str, Any] = Depends(auth_dependency) if CFG.auth_mode != "local" else {}):
    await _rate_check(principal, body.event)
    ev = _normalize_event(body.event, principal)
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
        explain=body.explain,
    )
    if RISK_EVALS:
        RISK_EVALS.labels(decision=result.get("decision", "ALLOW"), status="ok").inc()
    return JSONResponse(result, status_code=200)


@router.post("/batch", response_model=BatchEvaluateResponseModel)
async def batch_endpoint(body: BatchEvaluateRequestModel,
                         principal: Dict[str, Any] = Depends(auth_dependency) if CFG.auth_mode != "local" else {}):
    sem = asyncio.Semaphore(body.concurrency)
    items: List[BatchItemModel] = []

    async def worker(idx: int, ev: DetectEventModel):
        await _rate_check(principal, ev)
        data = _normalize_event(ev, principal)
        try:
            async with sem:
                res = await risk_client.evaluate(
                    event={
                        "actor_id": data.get("actor_id"),
                        "device_id": data.get("device_id"),
                        "timestamp": data.get("timestamp"),
                        "identity_risk": data["signals"]["identity_risk"],
                        "device_posture": data["signals"]["device_posture"],
                        "network_risk": data["signals"]["network_risk"],
                        "resource_sensitivity": data["signals"]["resource_sensitivity"],
                        "behavior_risk": data["signals"]["behavior_risk"],
                        "threat_intel": data["signals"]["threat_intel"],
                        "time_risk": data["signals"]["time_risk"],
                        "geo": data.get("geo"),
                        "ip": data.get("network_ip"),
                    },
                    explain=body.explain,
                )
            if RISK_EVALS:
                RISK_EVALS.labels(decision=res.get("decision", "ALLOW"), status="ok").inc()
            items.append(BatchItemModel(index=idx, status="ok", result=res))
        except HTTPException as he:
            items.append(BatchItemModel(index=idx, status="error", message=str(he.detail)))
            if RISK_EVALS:
                RISK_EVALS.labels(decision="n/a", status=str(he.status_code)).inc()
        except Exception as e:  # pragma: no cover
            items.append(BatchItemModel(index=idx, status="error", message="internal error"))
            if RISK_EVALS:
                RISK_EVALS.labels(decision="n/a", status="500").inc()

    await asyncio.gather(*(worker(i, ev) for i, ev in enumerate(body.events)))
    partial = any(i.status == "error" for i in items)
    return BatchEvaluateResponseModel(items=sorted(items, key=lambda x: x.index), partial_failure=partial)


@router.post("/batch-ndjson")
async def batch_ndjson_endpoint(request: Request,
                                principal: Dict[str, Any] = Depends(auth_dependency) if CFG.auth_mode != "local" else {}):
    """
    Вход: application/x-ndjson — по одному JSON‑событию в строке.
    Выход: application/x-ndjson — по одному JSON‑ответу/ошибке на строку.
    """
    body = await request.body()
    lines = [l for l in body.decode("utf-8", "ignore").splitlines() if l.strip()]
    out_lines: List[str] = []
    partial = False

    for idx, line in enumerate(lines):
        try:
            payload = json.loads(line)
            ev = DetectEventModel(**payload)
        except Exception:
            out_lines.append(json.dumps({"index": idx, "status": "error", "message": "invalid json"}))
            partial = True
            continue

        try:
            await _rate_check(principal, ev)
            data = _normalize_event(ev, principal)
            res = await risk_client.evaluate(
                event={
                    "actor_id": data.get("actor_id"),
                    "device_id": data.get("device_id"),
                    "timestamp": data.get("timestamp"),
                    "identity_risk": data["signals"]["identity_risk"],
                    "device_posture": data["signals"]["device_posture"],
                    "network_risk": data["signals"]["network_risk"],
                    "resource_sensitivity": data["signals"]["resource_sensitivity"],
                    "behavior_risk": data["signals"]["behavior_risk"],
                    "threat_intel": data["signals"]["threat_intel"],
                    "time_risk": data["signals"]["time_risk"],
                    "geo": data.get("geo"),
                    "ip": data.get("network_ip"),
                },
                explain=True,
            )
            out_lines.append(json.dumps({"index": idx, "status": "ok", "result": res}))
            if RISK_EVALS:
                RISK_EVALS.labels(decision=res.get("decision", "ALLOW"), status="ok").inc()
        except HTTPException as he:
            out_lines.append(json.dumps({"index": idx, "status": "error", "message": str(he.detail)}))
            partial = True
            if RISK_EVALS:
                RISK_EVALS.labels(decision="n/a", status=str(he.status_code)).inc()
        except Exception:
            out_lines.append(json.dumps({"index": idx, "status": "error", "message": "internal error"}))
            partial = True
            if RISK_EVALS:
                RISK_EVALS.labels(decision="n/a", status="500").inc()

    resp = PlainTextResponse("\n".join(out_lines) + ("\n" if out_lines else ""), media_type="application/x-ndjson")
    if partial:
        resp.headers["X-Partial-Failure"] = "true"
    return resp


@router.get("/thresholds")
async def get_thresholds():
    return {
        "allow": CFG.thr_allow,
        "mfa": CFG.thr_mfa,
        "deny": CFG.thr_deny,
        "quarantine": CFG.thr_quarantine,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/model-info")
async def model_info():
    """
    Возвращает информацию о версии детектора/политики, если доступна.
    Для режима http пытается получить {risk_http_url}/model-info (если endpoint есть).
    Для режима cli запускает 'self-test' и возвращает полезные поля, если реализованы.
    """
    if CFG.risk_mode == "http" and getattr(risk_client, "_http", None):
        try:
            import httpx  # type: ignore
            url = CFG.risk_http_url
            if url.endswith("/evaluate"):
                url = url[: -len("/evaluate")] + "/model-info"
            else:
                url = url.rstrip("/") + "/model-info"
            async with risk_client._http as client:  # type: ignore
                r = await client.get(url)
                r.raise_for_status()
                return r.json()
        except Exception:
            raise HTTPException(status_code=503, detail="model info unavailable")
    elif CFG.risk_mode == "cli":
        import subprocess
        try:
            proc = subprocess.run(
                [CFG.risk_cli_bin, CFG.risk_cli_script, "self-test"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5.0,
                check=False,
            )
            if proc.returncode != 0:
                raise HTTPException(status_code=503, detail="model self-test failed")
            payload = json.loads(proc.stdout.decode("utf-8", "ignore"))
            # Нормализуем ответ
            return {
                "ok": bool(payload.get("ok", True)),
                "detector_version": payload.get("version") or payload.get("detector_version") or "unknown",
                "policy_version": payload.get("policy_version") or "unknown",
                "ts": _now_iso(),
            }
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=503, detail="model info unavailable")
    else:
        # risk_mode == off
        return {
            "ok": True,
            "detector_version": "off",
            "policy_version": "off",
            "ts": _now_iso(),
        }


@router.post("/decide")
async def decide_endpoint(body: DecideRequestModel):
    thr = {
        "allow": CFG.thr_allow,
        "mfa": CFG.thr_mfa,
        "deny": CFG.thr_deny,
        "quarantine": CFG.thr_quarantine,
    }
    if body.thresholds:
        thr.update(body.thresholds)
    # sanity
    for k in ("allow", "mfa", "deny", "quarantine"):
        if k not in thr:
            raise HTTPException(status_code=400, detail=f"missing threshold {k}")
    decision = _apply_thresholds(body.score, thr)
    return {"decision": decision, "score": body.score, "thresholds": thr, "ts": _now_iso()}


@router.post("/cache/invalidate")
async def cache_invalidate(body: InvalidateCacheRequestModel):
    body.ensure_any()
    pep = getattr(risk_client, "_pep", None)
    if not pep:
        raise HTTPException(status_code=501, detail="pep cache not available")
    count = 0
    if body.key:
        try:
            pep.invalidate(body.key)
            count += 1
        except Exception:
            pass
    if body.actor_id:
        try:
            count += int(pep.invalidate_by_actor(body.actor_id) or 0)
        except Exception:
            pass
    return {"ok": True, "invalidated": count}
