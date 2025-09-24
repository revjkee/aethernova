# physical-integration-core/api/http/routers/v1/calibration.py
from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, root_validator, validator

router = APIRouter(prefix="/calibration", tags=["calibration"])

# =========================
# Models
# =========================

class CalibrationSpec(BaseModel):
    """
    Универсальная спецификация калибровки.
    Поддерживаемые стратегии:
      - identity: y = x
      - linear:   y = a * x + b
      - two_point: по двум точкам (x1->y1, x2->y2)
      - polynomial: y = sum(ci * x^i), i=0..n, n<=6
      - piecewise_linear: набор (x,y) с монотонными x, линейная интерполяция
      - lookup_table: дискретное соответствие значений, с режимом on_miss
    """
    strategy: str = Field(..., regex=r"^(identity|linear|two_point|polynomial|piecewise_linear|lookup_table)$")

    # linear
    a: Optional[float] = None
    b: Optional[float] = None

    # two_point
    x1: Optional[float] = None
    y1: Optional[float] = None
    x2: Optional[float] = None
    y2: Optional[float] = None

    # polynomial
    coefficients: Optional[List[float]] = None  # c0..cn, n<=6

    # piecewise_linear
    points: Optional[List[Tuple[float, float]]] = None  # [(x,y),...]

    # lookup_table
    table: Optional[Dict[str, float]] = None
    on_miss: Optional[str] = Field("error", regex=r"^(error|nearest|identity)$")

    @root_validator
    def _validate_by_strategy(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        s = values.get("strategy")
        if s == "identity":
            return values
        if s == "linear":
            a, b = values.get("a"), values.get("b")
            if a is None or b is None:
                raise ValueError("linear requires a and b")
        elif s == "two_point":
            for f in ("x1", "y1", "x2", "y2"):
                if values.get(f) is None:
                    raise ValueError("two_point requires x1,y1,x2,y2")
            if values["x1"] == values["x2"]:
                raise ValueError("two_point requires x1 != x2")
        elif s == "polynomial":
            coeffs = values.get("coefficients")
            if not coeffs or len(coeffs) < 2:
                raise ValueError("polynomial requires >=2 coefficients")
            if len(coeffs) > 7:
                raise ValueError("polynomial degree must be <=6 (<=7 coefficients)")
        elif s == "piecewise_linear":
            pts = values.get("points")
            if not pts or len(pts) < 2:
                raise ValueError("piecewise_linear requires >=2 points")
            xs = [p[0] for p in pts]
            if any(math.isnan(x) or math.isinf(x) for x in xs):
                raise ValueError("piecewise_linear contains invalid x")
            if any(xs[i] >= xs[i+1] for i in range(len(xs)-1)):
                raise ValueError("piecewise_linear requires strictly increasing x")
        elif s == "lookup_table":
            tbl = values.get("table")
            if not tbl:
                raise ValueError("lookup_table requires non-empty table")
            # keys must parse to float
            try:
                _ = [float(k) for k in tbl.keys()]
            except Exception:
                raise ValueError("lookup_table keys must be numeric (stringified)")
        return values


class CalibrationVersion(BaseModel):
    version_id: str = Field(..., description="ULID/UUID версии")
    version: int = Field(..., ge=1, description="Номер версии по возрастанию")
    etag: str = Field(..., description="Контроль содержимого")
    created_at: float = Field(..., description="Unix epoch seconds")
    created_by: str = Field(..., description="Инициатор изменения")
    valid_from: Optional[float] = None
    valid_to: Optional[float] = None
    active: bool = True
    spec: CalibrationSpec
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CreateCalibrationRequest(BaseModel):
    spec: CalibrationSpec
    valid_from: Optional[float] = None
    valid_to: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ApplyCalibrationRequest(BaseModel):
    value: float


class PreviewCalibrationRequest(BaseModel):
    spec: CalibrationSpec
    values: List[float]


class HistoryResponse(BaseModel):
    items: List[CalibrationVersion]


# =========================
# In-memory storage (replace with DB in real deployment)
# =========================

# ключ: (twin_name, sensor_id) -> список версий (последняя активная в конце списка)
_STORE: Dict[Tuple[str, str], List[CalibrationVersion]] = {}
# идемпотентность: (tenant,twin,sensor,idem_key) -> version_id
_IDEMP: Dict[Tuple[str, str, str, str], str] = {}


# =========================
# Helpers
# =========================

def _ulid_like() -> str:
    # Для простоты используем UUID4; ULID можно добавить внешней библиотекой
    return uuid.uuid4().hex

def _etag_for_spec(spec: CalibrationSpec, meta: Dict[str, Any]) -> str:
    raw = json.dumps({"spec": json.loads(spec.json()), "meta": meta}, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def _actor_from_headers(x_actor: Optional[str]) -> str:
    return x_actor or "unknown"

def _tenant_from_headers(x_tenant_id: Optional[str]) -> str:
    return x_tenant_id or "-"

def _now() -> float:
    return time.time()

def _choose_active(versions: List[CalibrationVersion], at: Optional[float]) -> Optional[CalibrationVersion]:
    if not versions:
        return None
    ts = at or _now()
    # выбираем активную по времени и флагу active (последняя подходящая)
    for v in reversed(versions):
        if not v.active:
            continue
        if (v.valid_from is None or v.valid_from <= ts) and (v.valid_to is None or ts < v.valid_to):
            return v
    # fallback: последняя active вне окна
    for v in reversed(versions):
        if v.active:
            return v
    return None


def _apply(spec: CalibrationSpec, x: float) -> float:
    s = spec.strategy
    if s == "identity":
        return x
    if s == "linear":
        return spec.a * x + spec.b  # type: ignore
    if s == "two_point":
        # y = y1 + (x - x1) * (y2 - y1) / (x2 - x1)
        return float(spec.y1 + (x - spec.x1) * (spec.y2 - spec.y1) / (spec.x2 - spec.x1))  # type: ignore
    if s == "polynomial":
        y = 0.0
        for i, c in enumerate(spec.coefficients or []):
            y += c * (x ** i)
        return float(y)
    if s == "piecewise_linear":
        pts = spec.points or []
        # экстраполяция по крайним отрезкам
        if x <= pts[0][0]:
            x0, y0 = pts[0]
            x1, y1 = pts[1]
        elif x >= pts[-1][0]:
            x0, y0 = pts[-2]
            x1, y1 = pts[-1]
        else:
            # бинарный поиск сегмента
            lo, hi = 0, len(pts) - 1
            while lo + 1 < hi:
                mid = (lo + hi) // 2
                if x >= pts[mid][0]:
                    lo = mid
                else:
                    hi = mid
            x0, y0 = pts[lo]
            x1, y1 = pts[lo + 1]
        if x1 == x0:
            return float(y0)
        return float(y0 + (x - x0) * (y1 - y0) / (x1 - x0))
    if s == "lookup_table":
        tbl = spec.table or {}
        # ключи таблицы строковые — приводим вход к строке с нормализацией
        key = str(x)
        if key in tbl:
            return float(tbl[key])
        mode = spec.on_miss or "error"
        if mode == "identity":
            return x
        if mode == "nearest":
            # ищем ближайший ключ
            keys = [(float(k), float(v)) for k, v in tbl.items()]
            if not keys:
                raise HTTPException(status_code=422, detail="lookup_table is empty")
            nearest = min(keys, key=lambda kv: abs(kv[0] - x))
            return float(nearest[1])
        raise HTTPException(status_code=422, detail=f"value {x} not found in lookup_table")
    # на случай расширения
    return x


# =========================
# Dependencies
# =========================

def ctx(request: Request, x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
        x_actor: Optional[str] = Header(None, alias="X-Actor")) -> Dict[str, str]:
    return {"tenant": _tenant_from_headers(x_tenant_id), "actor": _actor_from_headers(x_actor)}


# =========================
# Routes
# =========================

@router.get("/{twin_name}/{sensor_id}", response_model=CalibrationVersion, summary="Получить активную калибровку")
def get_active(twin_name: str, sensor_id: str, response: Response,
               at: Optional[float] = None,
               if_none_match: Optional[str] = Header(None, alias="If-None-Match")):
    key = (twin_name, sensor_id)
    versions = _STORE.get(key, [])
    v = _choose_active(versions, at)
    if not v:
        raise HTTPException(status_code=404, detail="calibration not found")
    # ETag
    response.headers["ETag"] = v.etag
    if if_none_match and if_none_match.strip('"') == v.etag:
        # 304 Not Modified
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return v
    return v


@router.get("/{twin_name}/{sensor_id}/history", response_model=HistoryResponse, summary="История версий калибровок")
def history(twin_name: str, sensor_id: str):
    key = (twin_name, sensor_id)
    items = sorted(_STORE.get(key, []), key=lambda x: (x.version, x.created_at))
    return HistoryResponse(items=items)


@router.post("/{twin_name}/{sensor_id}", response_model=CalibrationVersion, status_code=201,
             summary="Создать новую версию калибровки (идемпотентно)")
def create_or_update(twin_name: str, sensor_id: str,
                     body: CreateCalibrationRequest,
                     context=Depends(ctx),
                     idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key")):
    tenant = context["tenant"]
    actor = context["actor"]

    if idempotency_key:
        idem_key = (tenant, twin_name, sensor_id, idempotency_key)
        if idem_key in _IDEMP:
            # вернуть уже созданную версию
            vid = _IDEMP[idem_key]
            for v in _STORE.get((twin_name, sensor_id), []):
                if v.version_id == vid:
                    return v

    key = (twin_name, sensor_id)
    versions = _STORE.setdefault(key, [])

    etag = _etag_for_spec(body.spec, body.metadata)
    now = _now()
    next_version = (versions[-1].version + 1) if versions else 1
    version_id = _ulid_like()

    # деактивируем предыдущие при необходимости (параллельной активности не допускаем)
    for v in versions:
        v.active = False

    cv = CalibrationVersion(
        version_id=version_id,
        version=next_version,
        etag=etag,
        created_at=now,
        created_by=actor,
        valid_from=body.valid_from,
        valid_to=body.valid_to,
        active=True,
        spec=body.spec,
        metadata=body.metadata or {},
    )
    versions.append(cv)

    if idempotency_key:
        _IDEMP[(tenant, twin_name, sensor_id, idempotency_key)] = version_id

    return cv


@router.post("/{twin_name}/{sensor_id}/activate", response_model=CalibrationVersion, summary="Активировать существующую версию")
def activate(twin_name: str, sensor_id: str, version_id: str):
    key = (twin_name, sensor_id)
    versions = _STORE.get(key, [])
    if not versions:
        raise HTTPException(status_code=404, detail="calibration not found")
    target = None
    for v in versions:
        if v.version_id == version_id:
            target = v
            break
    if not target:
        raise HTTPException(status_code=404, detail="version not found")
    for v in versions:
        v.active = (v.version_id == version_id)
    return target


@router.delete("/{twin_name}/{sensor_id}/{version_id}", status_code=204, summary="Удалить/деактивировать версию")
def delete_version(twin_name: str, sensor_id: str, version_id: str):
    key = (twin_name, sensor_id)
    versions = _STORE.get(key, [])
    if not versions:
        raise HTTPException(status_code=404, detail="calibration not found")
    remain = [v for v in versions if v.version_id != version_id]
    if len(remain) == len(versions):
        raise HTTPException(status_code=404, detail="version not found")
    # Если удалили активную — активируем последнюю оставшуюся
    deleted_active = any(v.version_id == version_id and v.active for v in versions)
    _STORE[key] = remain
    if deleted_active and remain:
        remain[-1].active = True
    return Response(status_code=204)


@router.post("/{twin_name}/{sensor_id}:apply", summary="Применить активную калибровку к значению")
def apply_value(twin_name: str, sensor_id: str, body: ApplyCalibrationRequest, at: Optional[float] = None):
    v = _choose_active(_STORE.get((twin_name, sensor_id), []), at)
    if not v:
        raise HTTPException(status_code=404, detail="calibration not found")
    try:
        y = _apply(v.spec, float(body.value))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"value": body.value, "calibrated": y, "version_id": v.version_id, "etag": v.etag}


@router.post("/preview", summary="Превью: применить спецификацию к массиву значений")
def preview(body: PreviewCalibrationRequest):
    try:
        out = [_apply(body.spec, float(x)) for x in body.values]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"values": body.values, "calibrated": out, "etag": _etag_for_spec(body.spec, {})}
