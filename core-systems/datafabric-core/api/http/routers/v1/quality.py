from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Literal, Optional, Protocol, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, RootModel, conint, constr

# ---------------------------
# RBAC / Auth (упрощенная заглушка как в admin.py)
# ---------------------------

class Principal(BaseModel):
    sub: str
    roles: List[str] = Field(default_factory=list)
    tenant: Optional[str] = None
    region: Optional[str] = None

PLATFORM_ADMIN = "platform.admin"
TENANT_ADMIN = "tenant.admin"
TENANT_READER = "tenant.reader"

def _auth_ctx() -> Principal:
    # Подключите реальный OIDC/JWT провайдер в проде
    return Principal(sub="system", roles=[PLATFORM_ADMIN], tenant=None, region=None)

def require_admin(principal: Principal = Depends(lambda: _auth_ctx())) -> Principal:
    r = set(principal.roles or [])
    if PLATFORM_ADMIN in r or TENANT_ADMIN in r:
        return principal
    raise HTTPException(status_code=403, detail="forbidden: admin role required")

def require_reader(principal: Principal = Depends(lambda: _auth_ctx())) -> Principal:
    r = set(principal.roles or [])
    if PLATFORM_ADMIN in r or TENANT_ADMIN in r or TENANT_READER in r:
        return principal
    raise HTTPException(status_code=403, detail="forbidden: reader role required")

# ---------------------------
# Idempotency cache (как в admin.py)
# ---------------------------

class IdempotencyCache(Protocol):
    def get(self, key: str) -> Optional[Dict[str, Any]]: ...
    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int) -> None: ...

class InMemoryIdemCache:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[float, Dict[str, Any]]] = {}
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        it = self._data.get(key)
        if not it:
            return None
        exp, payload = it
        if time.time() > exp:
            self._data.pop(key, None)
            return None
        return payload
    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int) -> None:
        self._data[key] = (time.time() + ttl_seconds, value)

# ---------------------------
# DTOs в духе checks.proto
# ---------------------------

CheckKind = Literal["SCHEMA", "CONSTRAINT", "STATISTICAL", "FRESHNESS", "COMPLETENESS", "CONSISTENCY", "PIISAFETY"]
Severity = Literal["INFO", "WARN", "ERROR", "CRITICAL"]
Status = Literal["PASS", "WARN", "FAIL", "ERROR"]
Aggregation = Literal["NONE","COUNT","COUNT_DISTINCT","MIN","MAX","MEAN","MEDIAN","STDDEV","PERCENTILE","SUM","RATE"]
WindowKind = Literal["TUMBLING","SLIDING","SESSION"]
Comparator = Literal["EQ","NE","LT","LE","GT","GE","IN_SET","NOT_IN_SET","MATCHES","NOT_MATCHES","BETWEEN"]
DataType = Literal["BOOL","INT64","DOUBLE","STRING","BYTES","TIMESTAMP","DECIMAL"]
MissingPolicy = Literal["FORBID","ALLOW","DEFAULT"]

class IdentityDTO(BaseModel):
    id: constr(min_length=3, max_length=128)
    name: constr(min_length=3, max_length=128)
    owner: constr(min_length=1)
    tags: List[str] = Field(default_factory=list)

class DatasetRefDTO(BaseModel):
    system: constr(min_length=2)                # kafka|s3|postgres|...
    name: constr(min_length=1)
    namespace: constr(min_length=1)
    schema_ref: constr(min_length=1)
    classification: Literal["public","internal","confidential","restricted"]
    pii: bool
    pii_level: Literal["none","weak","strong"]
    labels: Dict[str, str] = Field(default_factory=dict)

class WindowDTO(BaseModel):
    kind: WindowKind
    size: Optional[float] = Field(default=None, description="seconds for tumbling/sliding")
    slide: Optional[float] = Field(default=None, description="seconds for sliding")
    session_gap: Optional[float] = Field(default=None, description="seconds for session windows")
    allowed_lateness: Optional[float] = Field(default=None, description="seconds of lateness")

class SamplingDTO(BaseModel):
    ratio: float = Field(ge=0.0, le=1.0, default=1.0)
    max_records: Optional[conint(ge=1)] = None

class FieldRefDTO(BaseModel):
    path: constr(min_length=1)
    type: DataType
    missing: MissingPolicy = "ALLOW"
    default_value: Optional[Any] = None

class ThresholdDTO(BaseModel):
    comparator: Comparator
    value: Optional[Any] = None
    range_min: Optional[Any] = None
    range_max: Optional[Any] = None
    percentile: Optional[float] = Field(default=None, ge=0.0, le=100.0)

class ExpectationDTO(BaseModel):
    id: constr(min_length=1)
    kind: CheckKind
    severity: Severity = "WARN"
    aggregation: Aggregation = "NONE"
    field: Optional[FieldRefDTO] = None
    group_by: List[FieldRefDTO] = Field(default_factory=list)
    threshold: ThresholdDTO
    allowed_set: List[str] = Field(default_factory=list)
    regex: Optional[str] = None
    expression: Optional[str] = None
    drift_percent_max: Optional[float] = None
    completeness_min: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    freshness_max: Optional[float] = None

class PolicyDTO(BaseModel):
    fail_ratio_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    fail_count_threshold: Optional[int] = Field(default=None, ge=0)
    actions_on_fail: List[str] = Field(default_factory=list)
    actions_on_critical: List[str] = Field(default_factory=list)
    warmup: Optional[float] = None

class CheckSpecDTO(BaseModel):
    identity: IdentityDTO
    dataset: DatasetRefDTO
    window: WindowDTO
    sampling: SamplingDTO = SamplingDTO()
    expectations: List[ExpectationDTO]
    policy: Optional[PolicyDTO] = None
    lineage_policy_ref: Optional[str] = None
    retention_policy_ref: Optional[str] = None
    extern_refs: Dict[str, str] = Field(default_factory=dict)
    revision: Optional[str] = None
    updated_at: Optional[str] = None  # RFC3339

class CheckSpecRecord(CheckSpecDTO):
    etag: str

class PageSpecs(BaseModel):
    items: List[CheckSpecRecord]
    next_cursor: Optional[str] = None
    total: Optional[int] = None

# Результаты проверки (нормировано)
class ViolationSampleDTO(BaseModel):
    keys: List[str] = Field(default_factory=list)
    fields: Dict[str, Any] = Field(default_factory=dict)

class ViolationDTO(BaseModel):
    expectation_id: str
    kind: CheckKind
    severity: Severity
    status: Status
    message: str
    observed: Dict[str, Any] = Field(default_factory=dict)
    affected_count: int
    affected_ratio: float
    samples: List[ViolationSampleDTO] = Field(default_factory=list)
    attributes: Dict[str, str] = Field(default_factory=dict)

class MetricDTO(BaseModel):
    name: str
    value: Any
    aggregation: Aggregation
    window: Dict[str, Any] = Field(default_factory=dict)
    attributes: Dict[str, str] = Field(default_factory=dict)

class CheckResultDTO(BaseModel):
    identity: Dict[str, Any]
    dataset: Dict[str, Any]
    window: Dict[str, Any]
    status: Status
    max_severity: Severity
    total_records: int
    checked_records: int
    fail_ratio: float
    metrics: List[MetricDTO] = Field(default_factory=list)
    violations: List[ViolationDTO] = Field(default_factory=list)
    started_at: str
    finished_at: str
    executor: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)

class PageResults(BaseModel):
    items: List[CheckResultDTO]
    next_cursor: Optional[str] = None
    total: Optional[int] = None

# ---------------------------
# Repository / Executor Protocols
# ---------------------------

class QualitySpecRepo(Protocol):
    async def list(self, *, cursor: Optional[str], limit: int, filters: Dict[str, Any]) -> PageSpecs: ...
    async def get(self, spec_id: str) -> Optional[CheckSpecRecord]: ...
    async def upsert(self, spec: CheckSpecDTO, *, expected_etag: Optional[str]) -> CheckSpecRecord: ...
    async def patch(self, spec_id: str, patch: Dict[str, Any], *, expected_etag: Optional[str]) -> CheckSpecRecord: ...
    async def delete(self, spec_id: str, *, expected_etag: Optional[str]) -> bool: ...

class QualityExecutor(Protocol):
    async def validate_record(self, spec: CheckSpecDTO, record: Dict[str, Any]) -> CheckResultDTO: ...
    async def validate_batch(self, spec: CheckSpecDTO, records: List[Dict[str, Any]]) -> CheckResultDTO: ...
    async def results(self, *, spec_id: Optional[str], dataset: Optional[str], cursor: Optional[str], limit: int) -> PageResults: ...

# ---------------------------
# Вспомогательные функции
# ---------------------------

def _calc_etag(obj: Dict[str, Any]) -> str:
    j = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(j).hexdigest()

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _idem_key_or_none(key: Optional[str]) -> Optional[str]:
    if not key:
        return None
    k = key.strip()
    if not k:
        return None
    if len(k) > 256:
        raise HTTPException(status_code=400, detail="invalid Idempotency-Key length")
    return k

# ---------------------------
# Router
# ---------------------------

router = APIRouter(prefix="/api/v1/quality", tags=["quality"])

# DI placeholders — замените при инициализации приложения
_IDEM = InMemoryIdemCache()
_REPO: QualitySpecRepo  # DI из приложения
_EXEC: QualityExecutor  # DI из приложения

def get_repo() -> QualitySpecRepo:
    try:
        return _REPO  # type: ignore
    except Exception:
        raise HTTPException(status_code=500, detail="quality repo is not initialized")

def get_exec() -> QualityExecutor:
    try:
        return _EXEC  # type: ignore
    except Exception:
        raise HTTPException(status_code=500, detail="quality executor is not initialized")

# ---------------------------
# Endpoints — Specs
# ---------------------------

@router.get("/specs", response_model=PageSpecs)
async def list_specs(
    cursor: Optional[str] = None,
    limit: int = 50,
    namespace: Optional[str] = None,
    owner: Optional[str] = None,
    dataset_name: Optional[str] = None,
    tenant: Optional[str] = None,
    principal: Principal = Depends(require_reader),
    repo: QualitySpecRepo = Depends(get_repo),
) -> PageSpecs:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be 1..500")
    filters = {
        "namespace": namespace,
        "owner": owner,
        "dataset_name": dataset_name,
        "tenant": tenant or principal.tenant,
    }
    filters = {k: v for k, v in filters.items() if v is not None}
    return await repo.list(cursor=cursor, limit=limit, filters=filters)

@router.get("/specs/{spec_id}", response_model=CheckSpecRecord)
async def get_spec(
    spec_id: str,
    response: Response,
    principal: Principal = Depends(require_reader),
    repo: QualitySpecRepo = Depends(get_repo),
) -> CheckSpecRecord:
    rec = await repo.get(spec_id)
    if not rec:
        raise HTTPException(status_code=404, detail="spec not found")
    response.headers["ETag"] = rec.etag
    return rec

@router.post("/specs", response_model=CheckSpecRecord, status_code=201)
async def upsert_spec(
    spec: CheckSpecDTO,
    response: Response,
    principal: Principal = Depends(require_admin),
    idem_key: Optional[str] = Header(default=None, convert_underscores=False, alias="Idempotency-Key"),
    if_match: Optional[str] = Header(default=None, convert_underscores=False, alias="If-Match"),
    repo: QualitySpecRepo = Depends(get_repo),
) -> CheckSpecRecord:
    key = _idem_key_or_none(idem_key)
    if key:
        cached = _IDEM.get(key)
        if cached:
            response.headers["Idempotency-Replayed"] = "true"
            response.headers["ETag"] = cached.get("etag", "")
            return CheckSpecRecord(**cached["record"])

    # Тенант‑гард — при наличии multi-tenant политики
    if principal.tenant and spec.dataset.labels.get("tenant") and spec.dataset.labels["tenant"] != principal.tenant:
        raise HTTPException(status_code=403, detail="cross-tenant modification is not allowed")

    # Мини‑валидатор согласованности PII/класса
    if spec.dataset.pii and spec.dataset.pii_level == "none":
        raise HTTPException(status_code=400, detail="pii_level cannot be 'none' when pii=true")

    rec = await repo.upsert(spec, expected_etag=if_match)
    response.headers["ETag"] = rec.etag
    if key:
        _IDEM.set(key, {"record": rec.model_dump(mode="json"), "etag": rec.etag}, ttl_seconds=300)
    return rec

@router.patch("/specs/{spec_id}", response_model=CheckSpecRecord)
async def patch_spec(
    spec_id: str,
    patch: Dict[str, Any],
    response: Response,
    principal: Principal = Depends(require_admin),
    idem_key: Optional[str] = Header(default=None, convert_underscores=False, alias="Idempotency-Key"),
    if_match: Optional[str] = Header(default=None, convert_underscores=False, alias="If-Match"),
    repo: QualitySpecRepo = Depends(get_repo),
) -> CheckSpecRecord:
    key = _idem_key_or_none(idem_key)
    if key:
        cached = _IDEM.get(key)
        if cached:
            response.headers["Idempotency-Replayed"] = "true"
            response.headers["ETag"] = cached.get("etag", "")
            return CheckSpecRecord(**cached["record"])
    rec = await repo.patch(spec_id, patch, expected_etag=if_match)
    response.headers["ETag"] = rec.etag
    if key:
        _IDEM.set(key, {"record": rec.model_dump(mode="json"), "etag": rec.etag}, ttl_seconds=300)
    return rec

@router.delete("/specs/{spec_id}", status_code=204)
async def delete_spec(
    spec_id: str,
    principal: Principal = Depends(require_admin),
    if_match: Optional[str] = Header(default=None, convert_underscores=False, alias="If-Match"),
    repo: QualitySpecRepo = Depends(get_repo),
) -> Response:
    ok = await repo.delete(spec_id, expected_etag=if_match)
    if not ok:
        raise HTTPException(status_code=404, detail="spec not found")
    return Response(status_code=204)

# ---------------------------
# Endpoints — Execution
# ---------------------------

class ValidateRecordInput(BaseModel):
    spec_id: Optional[str] = None
    inline_spec: Optional[CheckSpecDTO] = None
    record: Dict[str, Any]

class ValidateBatchInput(BaseModel):
    spec_id: Optional[str] = None
    inline_spec: Optional[CheckSpecDTO] = None
    records: List[Dict[str, Any]]

def _resolve_spec_for_exec(spec_id: Optional[str], inline_spec: Optional[CheckSpecDTO], repo: QualitySpecRepo) -> CheckSpecDTO:
    if inline_spec:
        return inline_spec
    if not spec_id:
        raise HTTPException(status_code=400, detail="either spec_id or inline_spec must be provided")
    # блокирующий вызов в асинхронном контексте не используем — будет await в хэндлерах
    raise RuntimeError("resolve_spec_for_exec must be awaited in handler")

@router.post("/validate/record", response_model=CheckResultDTO)
async def validate_record(
    payload: ValidateRecordInput,
    principal: Principal = Depends(require_reader),
    repo: QualitySpecRepo = Depends(get_repo),
    executor: QualityExecutor = Depends(get_exec),
) -> CheckResultDTO:
    if payload.inline_spec:
        spec = payload.inline_spec
    else:
        if not payload.spec_id:
            raise HTTPException(status_code=400, detail="spec_id or inline_spec required")
        rec = await repo.get(payload.spec_id)
        if not rec:
            raise HTTPException(status_code=404, detail="spec not found")
        spec = CheckSpecDTO(**rec.model_dump(exclude={"etag"}))
    return await executor.validate_record(spec, payload.record)

@router.post("/validate/batch", response_model=CheckResultDTO)
async def validate_batch(
    payload: ValidateBatchInput,
    principal: Principal = Depends(require_reader),
    repo: QualitySpecRepo = Depends(get_repo),
    executor: QualityExecutor = Depends(get_exec),
) -> CheckResultDTO:
    if payload.inline_spec:
        spec = payload.inline_spec
    else:
        if not payload.spec_id:
            raise HTTPException(status_code=400, detail="spec_id or inline_spec required")
        rec = await repo.get(payload.spec_id)
        if not rec:
            raise HTTPException(status_code=404, detail="spec not found")
        spec = CheckSpecDTO(**rec.model_dump(exclude={"etag"}))
    return await executor.validate_batch(spec, payload.records)

@router.get("/results", response_model=PageResults)
async def list_results(
    spec_id: Optional[str] = None,
    dataset: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    principal: Principal = Depends(require_reader),
    executor: QualityExecutor = Depends(get_exec),
) -> PageResults:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be 1..500")
    return await executor.results(spec_id=spec_id, dataset=dataset, cursor=cursor, limit=limit)

# ---------------------------
# InMemory реализации для dev/test (опционально)
# ---------------------------

class InMemoryQualitySpecRepo(QualitySpecRepo):
    def __init__(self) -> None:
        self._items: Dict[str, Dict[str, Any]] = {}

    async def list(self, *, cursor: Optional[str], limit: int, filters: Dict[str, Any]) -> PageSpecs:
        items = list(self._items.values())

        def _match(it: Dict[str, Any]) -> bool:
            if ns := filters.get("namespace"):
                if it["dataset"]["namespace"] != ns:
                    return False
            if own := filters.get("owner"):
                if it["identity"]["owner"] != own:
                    return False
            if dsn := filters.get("dataset_name"):
                if it["dataset"]["name"] != dsn:
                    return False
            if tenant := filters.get("tenant"):
                if it["dataset"]["labels"].get("tenant") not in (tenant, None, "*"):
                    return False
            return True

        filtered = [it for it in items if _match(it)]
        offset = int(cursor or 0)
        window = filtered[offset : offset + limit]
        next_cursor = str(offset + limit) if offset + limit < len(filtered) else None
        return PageSpecs(items=[CheckSpecRecord(**it) for it in window], next_cursor=next_cursor, total=len(filtered))

    async def get(self, spec_id: str) -> Optional[CheckSpecRecord]:
        it = self._items.get(spec_id)
        return CheckSpecRecord(**it) if it else None

    async def upsert(self, spec: CheckSpecDTO, *, expected_etag: Optional[str]) -> CheckSpecRecord:
        sid = spec.identity.id
        existing = self._items.get(sid)
        if existing and expected_etag and expected_etag != existing["etag"]:
            raise HTTPException(status_code=412, detail="precondition failed (etag mismatch)")
        now = _now_iso()
        rec = existing or {}
        rec.update(spec.model_dump(mode="json"))
        rec.setdefault("identity", {})  # safety
        rec["identity"]["id"] = sid
        rec.setdefault("updated_at", now)
        rec["etag"] = _calc_etag({k: v for k, v in rec.items() if k not in ("etag",)})
        self._items[sid] = rec
        return CheckSpecRecord(**rec)

    async def patch(self, spec_id: str, patch: Dict[str, Any], *, expected_etag: Optional[str]) -> CheckSpecRecord:
        existing = self._items.get(spec_id)
        if not existing:
            raise HTTPException(status_code=404, detail="spec not found")
        if expected_etag and expected_etag != existing["etag"]:
            raise HTTPException(status_code=412, detail="precondition failed (etag mismatch)")
        existing.update(patch)
        existing["updated_at"] = _now_iso()
        existing["etag"] = _calc_etag({k: v for k, v in existing.items() if k not in ("etag",)})
        return CheckSpecRecord(**existing)

    async def delete(self, spec_id: str, *, expected_etag: Optional[str]) -> bool:
        existing = self._items.get(spec_id)
        if not existing:
            return False
        if expected_etag and expected_etag != existing["etag"]:
            raise HTTPException(status_code=412, detail="precondition failed (etag mismatch)")
        self._items.pop(spec_id, None)
        return True

class InMemoryExecutor(QualityExecutor):
    async def validate_record(self, spec: CheckSpecDTO, record: Dict[str, Any]) -> CheckResultDTO:
        # Dev stub: всегда PASS, считает одну запись
        now = _now_iso()
        return CheckResultDTO(
            identity={"id": spec.identity.id, "name": spec.identity.name},
            dataset=spec.dataset.model_dump(),
            window=spec.window.model_dump(),
            status="PASS",
            max_severity="INFO",
            total_records=1,
            checked_records=1,
            fail_ratio=0.0,
            metrics=[],
            violations=[],
            started_at=now,
            finished_at=now,
            executor="inmemory"
        )

    async def validate_batch(self, spec: CheckSpecDTO, records: List[Dict[str, Any]]) -> CheckResultDTO:
        now = _now_iso()
        n = len(records)
        return CheckResultDTO(
            identity={"id": spec.identity.id, "name": spec.identity.name},
            dataset=spec.dataset.model_dump(),
            window=spec.window.model_dump(),
            status="PASS",
            max_severity="INFO",
            total_records=n,
            checked_records=n,
            fail_ratio=0.0,
            metrics=[MetricDTO(name="count", value=n, aggregation="COUNT").model_dump()],
            violations=[],
            started_at=now,
            finished_at=now,
            executor="inmemory"
        )

    async def results(self, *, spec_id: Optional[str], dataset: Optional[str], cursor: Optional[str], limit: int) -> PageResults:
        # Dev stub: пустая страница
        return PageResults(items=[], next_cursor=None, total=0)
