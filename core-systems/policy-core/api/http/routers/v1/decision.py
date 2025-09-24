# policy-core/api/http/routers/v1/decision.py
"""
Decision API v1 — промышленный FastAPI роутер.

Функциональность:
  - POST /v1/decision/evaluate: оценка политики (идемпотентность по Idempotency-Key)
  - GET  /v1/decision/{id}   : получение решения
  - GET  /v1/decision        : поиск решений (Relay-like пагинация)
  - GET  /v1/decision/stream : SSE поток решений (если поддержан репозиторием)

Безопасность и эксплуатация:
  - Извлечение correlation-id, traceparent, user-principal
  - Простое in-memory rate limit (per principal + route), легко заменить
  - Единый формат ошибок и коды
  - Контракты DI для PDP и DecisionRepository
  - Строгие Pydantic-схемы совместимые с GraphQL/Avro моделями домена
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import time
import uuid
from typing import Any, AsyncGenerator, Dict, Iterable, List, Literal, Optional, Protocol, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, Json, validator

# ------------------------- Константы/утилиты -------------------------

ISO8601 = "%Y-%m-%dT%H:%M:%S.%fZ"


def now_utc() -> dt.datetime:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)


def to_ts_micros(ts: Optional[dt.datetime] = None) -> int:
    t = (ts or now_utc()).timestamp()
    return int(t * 1_000_000)


# ------------------------- Простое лимитирование -------------------------

class _TokenBucket:
    def __init__(self, rate: int, per_sec: int) -> None:
        self.rate = rate
        self.per_sec = per_sec
        self.allowance = rate
        self.last_check = time.monotonic()
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            current = time.monotonic()
            elapsed = current - self.last_check
            self.last_check = current
            self.allowance += elapsed * (self.rate / self.per_sec)
            if self.allowance > self.rate:
                self.allowance = self.rate
            if self.allowance < 1.0:
                return False
            self.allowance -= 1.0
            return True


_rate_buckets: Dict[str, _TokenBucket] = {}


async def rate_limit(principal: str, route: str, rate: int = 120, per_sec: int = 60) -> None:
    key = f"{principal}:{route}:{rate}:{per_sec}"
    bucket = _rate_buckets.get(key)
    if bucket is None:
        bucket = _TokenBucket(rate=rate, per_sec=per_sec)
        _rate_buckets[key] = bucket
    if not await bucket.allow():
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")


# ------------------------- Идемпотентность (in-memory) -------------------------

class _IdemStore:
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            exp, payload = item
            if exp < time.time():
                # истёк
                self._store.pop(key, None)
                return None
            return payload

    async def put(self, key: str, payload: Dict[str, Any], ttl_sec: int = 600) -> None:
        async with self._lock:
            self._store[key] = (time.time() + ttl_sec, payload)


_idem_store = _IdemStore()


# ------------------------- Доменные модели API -------------------------

Effect = Literal["Allow", "Deny", "Challenge", "Unknown"]
RiskLevel = Literal["low", "medium", "high", "critical", "unknown"]
ObligationStatus = Literal["Succeeded", "Failed", "Skipped", "Timeout", "Unknown"]
Severity = Literal["debug", "info", "warning", "error", "critical", "unknown"]


class DecisionReason(BaseModel):
    code: str
    message: Optional[str] = None
    details: Json[Any] = Field(default="{}")


class Risk(BaseModel):
    level: RiskLevel = "unknown"
    score: int = Field(0, ge=0, le=100)


class Entity(BaseModel):
    id: str
    type: str
    labels: List[str] = Field(default_factory=list)
    attributes: Json[Any] = Field(default="{}")


class SourceInfo(BaseModel):
    service_name: str
    service_version: Optional[str] = None
    cluster: Optional[str] = None
    namespace: Optional[str] = None
    host: Optional[str] = None


class Integrity(BaseModel):
    bundle_sha256: Optional[str] = None
    image_digest: Optional[str] = None
    cosign_verified: bool = False
    sbom_ref: Optional[str] = None
    sbom_max_severity: Optional[str] = None


class ObligationResult(BaseModel):
    id: str
    status: ObligationStatus = "Unknown"
    duration_ms: int = 0
    severity: Severity = "info"
    error: Optional[Dict[str, Any]] = None


class ResponseMutations(BaseModel):
    redactions: int = 0
    masked: int = 0
    watermarks: int = 0


class PolicyRef(BaseModel):
    id: str
    version: str
    hash: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class EvaluatePolicyInput(BaseModel):
    policyId: Optional[str] = None
    policyTag: Optional[str] = None
    subject: Entity
    resource: Entity
    action: str
    context: Json[Any] = Field(default="{}")

    @validator("policyId", always=True)
    def _one_of_policyid_or_tag(cls, v, values):  # type: ignore[override]
        if v is None and not values.get("policyTag"):
            raise ValueError("Either policyId or policyTag must be provided")
        return v


class EvaluationResult(BaseModel):
    effect: Effect
    latencyMs: int
    reasons: List[DecisionReason] = Field(default_factory=list)
    risk: Risk = Risk()
    obligationsPlan: List[str] = Field(default_factory=list)
    decisionId: uuid.UUID
    correlationId: Optional[str] = None


class Decision(BaseModel):
    id: str
    decisionId: uuid.UUID
    correlationId: Optional[str] = None
    traceId: Optional[str] = None
    spanId: Optional[str] = None
    eventTime: dt.datetime
    ingestTime: dt.datetime
    environment: str = "unknown"
    tenantId: Optional[str] = None
    source: SourceInfo
    policy: PolicyRef
    effect: Effect
    latencyMs: int
    risk: Risk = Risk()
    reasons: List[DecisionReason] = Field(default_factory=list)
    subject: Entity
    action: str
    resource: Entity
    context: Json[Any] = Field(default="{}")
    compliance: List[Dict[str, str]] = Field(default_factory=list)
    obligations: List[ObligationResult] = Field(default_factory=list)
    responseMutations: ResponseMutations = ResponseMutations()
    integrity: Optional[Integrity] = None


# ------------------------- Контракты DI -------------------------

class PDP(Protocol):
    async def evaluate(self, payload: EvaluatePolicyInput, correlation_id: str, trace: Dict[str, str]) -> EvaluationResult:
        ...


class DecisionRepository(Protocol):
    async def get_by_id(self, id_: str) -> Optional[Decision]:
        ...

    async def search(
        self,
        *,
        effects: Optional[List[Effect]] = None,
        policy_ids: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
        ts_from: Optional[dt.datetime] = None,
        ts_to: Optional[dt.datetime] = None,
        subject_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        limit: int = 20,
        cursor: Optional[str] = None,
        sort_desc: bool = True,
    ) -> Tuple[List[Decision], Optional[str], int]:
        ...

    async def save_decision(self, decision: Decision) -> None:
        ...

    async def subscribe(self, *, filters: Dict[str, Any]) -> AsyncGenerator[Decision, None]:
        """
        Должен возвращать асинхронный генератор решений. Если не поддерживается — может поднять NotImplementedError.
        """
        ...


# ------------------------- Зависимости (заглушки по умолчанию) -------------------------

async def get_pdp() -> PDP:
    raise HTTPException(status_code=501, detail="PDP is not wired")


async def get_decision_repo() -> DecisionRepository:
    raise HTTPException(status_code=501, detail="DecisionRepository is not wired")


async def get_principal(
    authorization: Optional[str] = Header(default=None),
) -> str:
    """
    Простейшее извлечение субъекта. Замените на ваш провайдер аутентификации.
    """
    if not authorization:
        return "anonymous"
    # Пример: "Bearer user:alice"
    return authorization.split()[-1]


# ------------------------- Инициализация роутера -------------------------

router = APIRouter(prefix="/v1/decision", tags=["decision"])


# ------------------------- Хелперы ответов/ошибок -------------------------

def _error_response(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"ok": False, "code": code, "message": message, "errors": []},
    )


# ------------------------- Роуты -------------------------

@router.post(
    "/evaluate",
    response_model=EvaluationResult,
    status_code=status.HTTP_200_OK,
    summary="Оценка политики (идемпотентно по заголовку Idempotency-Key)",
)
async def evaluate_policy(
    req: Request,
    body: EvaluatePolicyInput,
    background: BackgroundTasks,
    response: Response,
    pdp: PDP = Depends(get_pdp),
    repo: DecisionRepository = Depends(get_decision_repo),
    principal: str = Depends(get_principal),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    x_correlation_id: Optional[str] = Header(default=None, alias="X-Correlation-Id"),
    traceparent: Optional[str] = Header(default=None),
) -> EvaluationResult:
    # Лимитирование
    await rate_limit(principal=principal, route="POST:/v1/decision/evaluate", rate=120, per_sec=60)

    # Корреляция/трейс
    correlation_id = x_correlation_id or str(uuid.uuid4())
    trace = {
        "traceparent": traceparent or "",
        "request_id": req.headers.get("X-Request-Id", ""),
    }
    response.headers["X-Correlation-Id"] = correlation_id

    # Идемпотентность
    if idempotency_key:
        cached = await _idem_store.get(idempotency_key)
        if cached:
            # Возврат кэшированного результата
            return EvaluationResult(**cached)

    started = time.perf_counter()
    result = await pdp.evaluate(body, correlation_id=correlation_id, trace=trace)
    latency_ms = int((time.perf_counter() - started) * 1000)

    # Готовим и сохраняем решение для аудита
    decision = Decision(
        id=str(uuid.uuid4()),
        decisionId=result.decisionId,
        correlationId=result.correlationId or correlation_id,
        traceId=None,
        spanId=None,
        eventTime=now_utc(),
        ingestTime=now_utc(),
        environment=req.headers.get("X-Env", "unknown"),
        tenantId=req.headers.get("X-Tenant-Id"),
        source=SourceInfo(
            service_name="policy-core",
            service_version=req.headers.get("X-Service-Version"),
            cluster=req.headers.get("X-Cluster"),
            namespace=req.headers.get("X-Namespace"),
            host=req.client.host if req.client else None,
        ),
        policy=PolicyRef(id=body.policyId or body.policyTag or "unknown", version="unknown"),
        effect=result.effect,
        latencyMs=latency_ms,
        risk=result.risk,
        reasons=result.reasons,
        subject=body.subject,
        action=body.action,
        resource=body.resource,
        context=body.context,
    )

    # Асинхронно сохраняем (не блокируем ответ)
    background.add_task(repo.save_decision, decision)

    # Кэшируем идемпотентный результат
    payload = result.dict()
    if idempotency_key:
        await _idem_store.put(idempotency_key, payload, ttl_sec=600)

    return result


@router.get(
    "/{id}",
    response_model=Decision,
    summary="Получить решение по идентификатору",
)
async def get_decision(
    id: str = Path(..., description="Идентификатор решения"),
    repo: DecisionRepository = Depends(get_decision_repo),
    principal: str = Depends(get_principal),
) -> Decision:
    await rate_limit(principal=principal, route="GET:/v1/decision/{id}", rate=240, per_sec=60)
    item = await repo.get_by_id(id)
    if not item:
        raise HTTPException(status_code=404, detail="Decision not found")
    return item


class DecisionsQueryParams(BaseModel):
    effects: Optional[List[Effect]] = Field(default=None)
    policyIds: Optional[List[str]] = Field(default=None)
    tenantId: Optional[str] = Field(default=None)
    fromTs: Optional[dt.datetime] = Field(default=None, description="UTC ISO timestamp")
    toTs: Optional[dt.datetime] = Field(default=None, description="UTC ISO timestamp")
    subjectId: Optional[str] = None
    resourceId: Optional[str] = None
    first: int = Field(default=20, gt=0, le=200)
    after: Optional[str] = None
    sortDesc: bool = True


class DecisionsConnection(BaseModel):
    edges: List[Decision] = Field(default_factory=list)
    cursor: Optional[str] = None
    totalCount: int = 0


@router.get(
    "",
    response_model=DecisionsConnection,
    summary="Поиск решений (пагинация cursor-based)",
)
async def list_decisions(
    effects: Optional[List[Effect]] = Query(default=None),
    policyIds: Optional[List[str]] = Query(default=None),
    tenantId: Optional[str] = Query(default=None),
    fromTs: Optional[dt.datetime] = Query(default=None),
    toTs: Optional[dt.datetime] = Query(default=None),
    subjectId: Optional[str] = Query(default=None),
    resourceId: Optional[str] = Query(default=None),
    first: int = Query(default=20, gt=1, le=200),
    after: Optional[str] = Query(default=None),
    repo: DecisionRepository = Depends(get_decision_repo),
    principal: str = Depends(get_principal),
) -> DecisionsConnection:
    await rate_limit(principal=principal, route="GET:/v1/decision", rate=180, per_sec=60)
    items, cursor, total = await repo.search(
        effects=effects,
        policy_ids=policyIds,
        tenant_id=tenantId,
        ts_from=fromTs,
        ts_to=toTs,
        subject_id=subjectId,
        resource_id=resourceId,
        limit=first,
        cursor=after,
        sort_desc=True,
    )
    return DecisionsConnection(edges=items, cursor=cursor, totalCount=total)


@router.get(
    "/stream",
    summary="SSE поток решений (если поддержан хранилищем)",
)
async def stream_decisions(
    response: Response,
    repo: DecisionRepository = Depends(get_decision_repo),
    principal: str = Depends(get_principal),
    effects: Optional[List[Effect]] = Query(default=None),
    policyIds: Optional[List[str]] = Query(default=None),
    tenantId: Optional[str] = Query(default=None),
    minRisk: Optional[RiskLevel] = Query(default=None),
) -> StreamingResponse:
    await rate_limit(principal=principal, route="GET:/v1/decision/stream", rate=60, per_sec=60)
    filters = {"effects": effects, "policyIds": policyIds, "tenantId": tenantId, "minRisk": minRisk}

    async def _gen() -> AsyncGenerator[bytes, None]:
        try:
            async for d in repo.subscribe(filters=filters):
                payload = d.json()
                yield f"event: decision\ndata: {payload}\n\n".encode()
        except NotImplementedError:
            # 501 для неподдерживаемой функциональности SSE
            # Прерываем поток корректным завершением
            yield b"event: end\ndata: not-implemented\n\n"
            return

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Content-Type": "text/event-stream",
    }
    return StreamingResponse(_gen(), headers=headers, media_type="text/event-stream")


# ------------------------- Глобальные обработчики ошибок (опционально) -------------------------

@router.exception_handler(HTTPException)  # type: ignore[arg-type]
async def _http_exc_handler(_: Request, exc: HTTPException) -> JSONResponse:
    code = "http_error"
    if exc.status_code == 404:
        code = "not_found"
    elif exc.status_code == 429:
        code = "rate_limited"
    elif exc.status_code == 401:
        code = "unauthorized"
    return _error_response(code=code, message=str(exc.detail), status_code=exc.status_code)


# Примечания по интеграции:
# 1) Зарегистрируйте роутер в приложении:
#       app.include_router(router)
# 2) Реализуйте get_pdp и get_decision_repo (DI):
#       app.dependency_overrides[get_pdp] = lambda: MyPDP(...)
#       app.dependency_overrides[get_decision_repo] = lambda: MyDecisionRepo(...)
# 3) Замените get_principal на интеграцию с вашей аутентификацией.
