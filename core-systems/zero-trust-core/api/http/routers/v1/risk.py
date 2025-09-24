# file: zero-trust-core/api/http/routers/v1/risk.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, Response, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, conint, constr

log = logging.getLogger(__name__)
router = APIRouter(prefix="/risk", tags=["risk"])

# ======================================================================================
# Security / Scopes
# ======================================================================================

bearer_scheme = HTTPBearer(auto_error=False)

def _now_ms() -> int:
    return int(time.time() * 1000)

def _iso_z(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")

def require_scope(creds: Optional[HTTPAuthorizationCredentials], scope: str) -> str:
    """
    Простая проверка скоупа. В проде замените на полноценную валидацию JWT (aud/iss/exp/nbf/scope).
    Возвращает subject (sub) или подставной идентификатор.
    """
    if creds is None or not creds.scheme.lower() == "bearer" or not creds.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    token = creds.credentials
    # Лёгкая проверка скоупа по 'scope' в payload JWT (без криптопроверки) — безопасно только при наличии гейтвея/фильтра.
    # TODO: заменить на проверку подписи и claim'ов (используйте ваш JWT-вэлидатор).
    try:
        parts = token.split(".")
        if len(parts) == 3:
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8"))
            scopes = set(str(payload.get("scope", "")).split())
            if scope not in scopes:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient scope")
            return str(payload.get("sub") or payload.get("client_id") or "subject")
    except Exception:
        # Если парсинг не удался, опираемся на внешний слой авторизации
        pass
    # Бэкстоп: разрешаем при наличии токена (ожидается, что API защищён обратным прокси, проверяющим JWT)
    return "subject"

# ======================================================================================
# ULID (монотонная реализация для стабильных курсоров/ID)
# ======================================================================================

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ulid_lock = threading.Lock()
_ulid_last_ms = -1
_ulid_rand80 = 0

def _b32_crockford_encode(b: bytes) -> str:
    bits = 0
    acc = 0
    out: List[str] = []
    for byte in b:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_CROCKFORD[(acc >> bits) & 0x1F])
    if bits:
        out.append(_CROCKFORD[(acc << (5 - bits)) & 0x1F])
    return "".join(out)

def new_ulid_mono() -> str:
    global _ulid_last_ms, _ulid_rand80
    t = _now_ms() & ((1 << 48) - 1)
    with _ulid_lock:
        if t > _ulid_last_ms:
            _ulid_last_ms = t
            _ulid_rand80 = int.from_bytes(uuid.uuid4().bytes + uuid.uuid4().bytes[: -2], "big") & ((1 << 80) - 1)
        else:
            _ulid_rand80 = (_ulid_rand80 + 1) & ((1 << 80) - 1)
            if _ulid_rand80 == 0:
                while True:
                    t2 = _now_ms() & ((1 << 48) - 1)
                    if t2 != t:
                        t = t2
                        _ulid_last_ms = t
                        _ulid_rand80 = int.from_bytes(uuid.uuid4().bytes + uuid.uuid4().bytes[: -2], "big") & ((1 << 80) - 1)
                        break
        b = t.to_bytes(6, "big") + _ulid_rand80.to_bytes(10, "big")
    return _b32_crockford_encode(b)[:26]

# ======================================================================================
# Idempotency (in-memory TTL store). В проде вынесите в Redis/DB.
# ======================================================================================

class IdempotencyStore:
    def __init__(self, ttl_seconds: int = 600, secret: Optional[bytes] = None) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._data: Dict[str, Tuple[int, int]] = {}
        self._secret = secret or hashlib.sha256(b"ztc-idem-default").digest()

    def _hash(self, key: str) -> str:
        mac = hmac.new(self._secret, key.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

    def check_and_put(self, key: str) -> bool:
        """Возвращает True, если ключ новый; False — если уже использовался и ещё не истёк."""
        now = _now_ms()
        h = self._hash(key)
        with self._lock:
            # очистка устаревших ключей (ленивая)
            to_del = [k for k, (ts, _) in self._data.items() if now - ts > self._ttl * 1000]
            for k in to_del:
                self._data.pop(k, None)
            if h in self._data:
                ts, cnt = self._data[h]
                if now - ts <= self._ttl * 1000:
                    self._data[h] = (ts, cnt + 1)
                    return False
            self._data[h] = (now, 1)
            return True

IDEMPOTENCY = IdempotencyStore()

# ======================================================================================
# Модели (Pydantic)
# ======================================================================================

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]

class RiskSignal(BaseModel):
    name: constr(strip_whitespace=True, min_length=1) = Field(..., description="Имя источника сигнала (например, ip_reputation)")
    value: float = Field(..., ge=0.0, le=1.0, description="Нормализованная величина [0..1]")
    weight: float = Field(0.2, ge=0.0, le=1.0, description="Вес влияния сигнала на общий риск")
    reason: Optional[str] = Field(None, description="Человекочитаемая причина для аудита")

class NetworkContext(BaseModel):
    ip: Optional[str] = Field(None, description="Внешний IP")
    asn: Optional[int] = Field(None, description="Autonomous System Number")
    geo_country: Optional[constr(min_length=2, max_length=2)] = Field(None, description="ISO-3166-1 alpha-2")
    vpn_or_tor: Optional[bool] = Field(None, description="Признак VPN/Tor/Proxy")

class DevicePosture(BaseModel):
    platform: Optional[Literal["WINDOWS","MACOS","LINUX","IOS","ANDROID","OTHER"]] = None
    os_version: Optional[str] = None
    disk_encryption: Optional[Literal["YES","NO","UNKNOWN"]] = None
    screen_lock: Optional[Literal["YES","NO","UNKNOWN"]] = None
    firewall: Optional[Literal["YES","NO","UNKNOWN"]] = None
    av_realtime: Optional[Literal["YES","NO","UNKNOWN"]] = None
    mdm_enrolled: Optional[Literal["YES","NO","UNKNOWN"]] = None
    labels: Dict[str, str] = Field(default_factory=dict)

class RiskEvaluationRequest(BaseModel):
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    network: Optional[NetworkContext] = None
    posture: Optional[DevicePosture] = None
    signals: List[RiskSignal] = Field(default_factory=list)
    thresholds: Optional[Dict[Literal["medium","high","critical"], float]] = Field(
        None, description="Переопределение порогов: значения в [0..1]"
    )

class RiskDecision(BaseModel):
    score: float = Field(..., ge=0.0, le=1.0)
    level: RiskLevel
    action: Literal["allow","step_up","deny","quarantine"]
    reasons: List[str] = Field(default_factory=list)

class RiskEvaluationResponse(BaseModel):
    request_id: str
    evaluated_at: str
    subject: Optional[str] = None
    decision: RiskDecision

class RiskEventIngest(BaseModel):
    event_id: Optional[str] = Field(None, description="Если не задан — ULID")
    occurred_at: Optional[int] = Field(None, description="UNIX epoch ms; по умолчанию now")
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    network: Optional[NetworkContext] = None
    posture: Optional[DevicePosture] = None
    signals: List[RiskSignal] = Field(default_factory=list)
    note: Optional[str] = None
    producer: Optional[str] = Field(None, description="Источник события (AGENT/MDM/EDR/API)")

class RiskEventOut(BaseModel):
    id: str
    occurred_at: str
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    network: Optional[NetworkContext] = None
    posture: Optional[DevicePosture] = None
    score: float
    level: RiskLevel
    reasons: List[str] = Field(default_factory=list)
    note: Optional[str] = None
    producer: Optional[str] = None

class PageOut(BaseModel):
    items: List[RiskEventOut]
    next_page_cursor: Optional[str] = None

# ======================================================================================
# Risk Engine (плагинируемый)
# ======================================================================================

class RiskEngine:
    """
    Базовый компоновочный движок: нормализованная сумма value*weight с простыми штрафами.
    В проде можно подключить ML/поведенческую аналитику — реализуйте тот же интерфейс.
    """

    def __init__(self, thresholds: Optional[Dict[str, float]] = None) -> None:
        th = thresholds or {}
        self.th_medium = float(th.get("medium", 0.35))
        self.th_high = float(th.get("high", 0.65))
        self.th_critical = float(th.get("critical", 0.85))

    def evaluate(self, req: RiskEvaluationRequest) -> RiskDecision:
        score, reasons = self._aggregate(req.signals, req.network, req.posture)
        level: RiskLevel
        action: Literal["allow","step_up","deny","quarantine"]

        if score >= self.th_critical:
            level, action = "CRITICAL", "deny"
            reasons.append("RISK_CRITICAL")
        elif score >= self.th_high:
            level, action = "HIGH", "step_up"
            reasons.append("RISK_HIGH")
        elif score >= self.th_medium:
            level, action = "MEDIUM", "step_up"
            reasons.append("RISK_MEDIUM")
        else:
            level, action = "LOW", "allow"
            reasons.append("RISK_LOW")

        return RiskDecision(score=round(score, 6), level=level, action=action, reasons=reasons)

    def _aggregate(
        self,
        signals: Iterable[RiskSignal],
        network: Optional[NetworkContext],
        posture: Optional[DevicePosture],
    ) -> Tuple[float, List[str]]:
        total_w = 0.0
        total = 0.0
        reasons: List[str] = []

        for s in signals:
            w = max(0.0, min(1.0, float(s.weight)))
            v = max(0.0, min(1.0, float(s.value)))
            total += w * v
            total_w += w
            if s.reason:
                reasons.append(s.reason)

        base = (total / total_w) if total_w > 0 else 0.0

        # Штрафы/бонусы контекста
        if network:
            if network.vpn_or_tor:
                base = min(1.0, base + 0.2)
                reasons.append("VPN_OR_TOR")
            if network.geo_country and network.geo_country.upper() in {"RU","BY","KP","IR"}:
                base = min(1.0, base + 0.25)
                reasons.append(f"GEO_{network.geo_country.upper()}")

        if posture:
            tri_penalty = {
                "NO": 0.15,
                "UNKNOWN": 0.05,
                "YES": 0.0,
                None: 0.0,
            }
            base = min(1.0, base + tri_penalty.get(posture.disk_encryption, 0.0))
            base = min(1.0, base + tri_penalty.get(posture.screen_lock, 0.0))
            base = min(1.0, base + tri_penalty.get(posture.firewall, 0.0))
            # лёгкий бонус за корпоративное устройство (если явно указано меткой)
            if posture.labels.get("device.is_corporate") == "true":
                base = max(0.0, base - 0.05)
                reasons.append("CORPORATE_DEVICE")

        return (max(0.0, min(1.0, base))), reasons

ENGINE = RiskEngine()

# ======================================================================================
# Хранилище событий (in-memory; интерфейс совместим с заменой на БД/стрим)
# ======================================================================================

class RiskEventStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        # список хранится по возрастанию времени; элементы: (ts_ms:int, id:str, data:RiskEventOut)
        self._items: List[Tuple[int, str, RiskEventOut]] = []

    def add(self, item: RiskEventOut) -> None:
        ts = _parse_iso_ms(item.occurred_at)
        with self._lock:
            self._items.append((ts, item.id, item))
            # уборка по размеру/времени — для демо. В проде вынести в БД/стрим.
            if len(self._items) > 200_000:
                self._items = self._items[-100_000:]

    def list(self, page_size: int, cursor: Optional[str]) -> Tuple[List[RiskEventOut], Optional[str]]:
        """
        Курсор — base64("ts:id"), указывает последний включённый элемент.
        """
        with self._lock:
            idx_start = 0
            if cursor:
                try:
                    raw = base64.urlsafe_b64decode(cursor.encode("ascii") + b"==").decode("utf-8")
                    ts_s, id_s = raw.split(":", 1)
                    ts_c = int(ts_s)
                    # находим позицию строго после курсора
                    for i, (ts, id_, _) in enumerate(self._items):
                        if ts > ts_c or (ts == ts_c and id_ > id_s):
                            idx_start = i
                            break
                        idx_start = i + 1
                except Exception:
                    idx_start = 0
            slice_ = self._items[idx_start : idx_start + page_size]
            items = [it[2] for it in slice_]
            if not items or idx_start + page_size >= len(self._items):
                next_cur = None
            else:
                last_ts, last_id, _ = slice_[-1]
                next_cur = base64.urlsafe_b64encode(f"{last_ts}:{last_id}".encode("utf-8")).decode("ascii").rstrip("=")
            return items, next_cur

def _parse_iso_ms(iso: str) -> int:
    # iso вида 2025-08-20T12:34:56Z
    dt = datetime.strptime(iso.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z")
    return int(dt.timestamp() * 1000)

EVENTS = RiskEventStore()

# ======================================================================================
# ETag utils
# ======================================================================================

def compute_etag(obj: Any) -> str:
    data = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    h = hashlib.sha256(data).hexdigest()
    return f'W/"{h}"'

# ======================================================================================
# Endpoints
# ======================================================================================

@router.get("/providers", summary="Список доступных провайдеров риска")
def list_providers(
    request: Request,
    response: Response,
    creds: HTTPAuthorizationCredentials = Security(bearer_scheme),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
):
    subject = require_scope(creds, scope="ztc.risk.read")
    providers = {
        "providers": [
            {"name": "composite", "version": "1.0.0", "weights_default": {"ip_reputation": 0.25, "impossible_travel": 0.20, "device_posture_gap": 0.25, "behavioral_anomaly": 0.30}},
        ],
        "subject": subject,
    }
    etag = compute_etag(providers)
    if if_none_match and if_none_match == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    response.headers["ETag"] = etag
    return providers


@router.post(
    "/evaluate",
    summary="Оценить риск в текущем контексте",
    response_model=RiskEvaluationResponse,
    status_code=status.HTTP_200_OK,
)
def evaluate_risk(
    request: Request,
    payload: RiskEvaluationRequest = Body(...),
    response: Response = None,  # type: ignore
    creds: HTTPAuthorizationCredentials = Security(bearer_scheme),
    idem_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    subject = require_scope(creds, scope="ztc.risk.evaluate")
    # Переопределяем пороги на время запроса, не меняя глобальный движок
    engine = ENGINE if not payload.thresholds else RiskEngine(payload.thresholds)

    if idem_key:
        fresh = IDEMPOTENCY.check_and_put(f"risk:evaluate:{idem_key}:{subject}:{payload.session_id or ''}")
        if not fresh:
            # Идемпотентный повтор — тот же результат для стабильности (без кэша, но с одинаковым результатом для детерминированной функции)
            log.debug("Idempotent replay for evaluate with key=%s", idem_key)

    decision = engine.evaluate(payload)

    resp = RiskEvaluationResponse(
        request_id=x_request_id or str(uuid.uuid4()),
        evaluated_at=_iso_z(_now_ms()),
        subject=subject,
        decision=decision,
    )
    # Добавим слабый ETag для кэширующих клиентов
    response.headers["ETag"] = compute_etag(resp.dict())
    return resp


@router.post(
    "/events",
    summary="Ингест события сигналов/постуры для риска (идемпотентно по Idempotency-Key или event_id)",
    response_model=RiskEventOut,
    status_code=status.HTTP_201_CREATED,
)
def ingest_event(
    request: Request,
    payload: RiskEventIngest = Body(...),
    response: Response = None,  # type: ignore
    creds: HTTPAuthorizationCredentials = Security(bearer_scheme),
    idem_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    subject = require_scope(creds, scope="ztc.risk.write")

    # Идемпотентность: приоритет event_id, затем Idempotency-Key
    key = payload.event_id or idem_key
    if key:
        fresh = IDEMPOTENCY.check_and_put(f"risk:event:{key}")
        if not fresh:
            # Уже принимали — отвечаем 200/OK? Вариантов два: 200 или 201 c тем же объектом.
            # Для простоты — 200 OK. В проде сохраните и верните ранее записанный объект.
            log.info("Idempotent re-ingest for key=%s", key)

    occurred_ms = payload.occurred_at or _now_ms()
    evt_id = payload.event_id or new_ulid_mono()

    # Оценим риск и нормализуем причины
    tmp_req = RiskEvaluationRequest(
        tenant_id=payload.tenant_id,
        session_id=payload.session_id,
        user_id=payload.user_id,
        device_id=payload.device_id,
        network=payload.network,
        posture=payload.posture,
        signals=payload.signals,
    )
    decision = ENGINE.evaluate(tmp_req)

    out = RiskEventOut(
        id=evt_id,
        occurred_at=_iso_z(occurred_ms),
        tenant_id=payload.tenant_id,
        user_id=payload.user_id,
        device_id=payload.device_id,
        session_id=payload.session_id,
        network=payload.network,
        posture=payload.posture,
        score=decision.score,
        level=decision.level,
        reasons=decision.reasons,
        note=payload.note,
        producer=payload.producer or "API",
    )

    EVENTS.add(out)
    response.headers["Location"] = f"{request.url_for('get_event')}/{evt_id}"
    response.headers["ETag"] = compute_etag(out.dict())
    return out


@router.get(
    "/events",
    summary="Список событий риска (курсорная пагинация, консистентная по времени)",
    response_model=PageOut,
    status_code=status.HTTP_200_OK,
)
def list_events(
    request: Request,
    response: Response,
    creds: HTTPAuthorizationCredentials = Security(bearer_scheme),
    page_size: conint(ge=1, le=500) = Query(100, alias="page_size"),
    page_cursor: Optional[str] = Query(None, alias="page_cursor"),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
):
    require_scope(creds, scope="ztc.risk.read")

    items, next_cur = EVENTS.list(page_size=page_size, cursor=page_cursor)
    payload = PageOut(items=items, next_page_cursor=next_cur)
    etag = compute_etag(payload.dict())

    if if_none_match and if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    response.headers["ETag"] = etag
    return payload


@router.get(
    "/events/{event_id}",
    name="get_event",
    summary="Получить событие риска по ID",
    response_model=RiskEventOut,
)
def get_event(
    event_id: str,
    response: Response,
    creds: HTTPAuthorizationCredentials = Security(bearer_scheme),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
):
    require_scope(creds, scope="ztc.risk.read")
    # Линейный поиск в демо-хранилище. В проде — SELECT по первичному ключу.
    for _, id_, obj in EVENTS._items:  # noqa: SLF001 (осознанный доступ для простой реализации)
        if id_ == event_id:
            etag = compute_etag(obj.dict())
            if if_none_match and if_none_match == etag:
                return Response(status_code=status.HTTP_304_NOT_MODIFIED)
            response.headers["ETag"] = etag
            return obj
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


@router.get(
    "/score/{session_id}",
    summary="Текущая оценка риска по session_id (агрегация последних сигналов)",
    response_model=RiskDecision,
)
def current_risk_by_session(
    session_id: str,
    creds: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    require_scope(creds, scope="ztc.risk.read")

    # В демо вычислим по последнему событию этой сессии; в проде возьмите нормализованный агрегат из хранилища.
    last_evt: Optional[RiskEventOut] = None
    for _, _, obj in reversed(EVENTS._items):  # noqa: SLF001
        if obj.session_id == session_id:
            last_evt = obj
            break
    if not last_evt:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No signals for session")

    # Уровень/скор — из события
    return RiskDecision(score=last_evt.score, level=last_evt.level, action="allow" if last_evt.level in ("LOW","UNKNOWN") else "step_up", reasons=last_evt.reasons)

# ======================================================================================
# Готово. Подключите роутер в приложении:
#
# from fastapi import FastAPI
# from zero_trust_core.api.http.routers.v1 import risk
# app = FastAPI()
# app.include_router(risk.router)
#
# TODO (прод):
# - заменить in-memory IdempotencyStore и RiskEventStore на Redis/DB/стрим
# - использовать проверку JWT (JWKS, подпись, aud/iss/exp/nbf/scope)
# - вынести пороги и веса сигналов в конфиг и/или политический движок
# - снабдить событиями шину (Kafka/NATS) для downstream-аналитики
