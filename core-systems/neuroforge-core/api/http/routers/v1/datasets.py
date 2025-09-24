# neuroforge-core/api/http/routers/v1/datasets.py
from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Tuple

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, EmailStr, Field, HttpUrl, conint, constr, validator

try:
    import httpx  # для OPA/внешних вызовов (опционально)
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

# ------------------------------------------------------------------------------
# Вспомогательные типы и утилиты
# ------------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def sha256_hex(obj: Any) -> str:
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def etag_for(obj: Any) -> str:
    return f'W/"{sha256_hex(obj)}"'

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

def encode_page_token(offset: int) -> str:
    return b64url_encode(json.dumps({"o": offset, "t": int(time.time())}).encode("utf-8"))

def decode_page_token(token: Optional[str]) -> int:
    if not token:
        return 0
    try:
        payload = json.loads(b64url_decode(token).decode("utf-8"))
        return int(payload.get("o", 0))
    except Exception as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid page_token: {e}")

# ------------------------------------------------------------------------------
# Модели (Pydantic) — согласованы с ранее предложенным dataset.proto (упрощено)
# ------------------------------------------------------------------------------

class DatasetLifecycle(str, Enum):
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"

class Owner(BaseModel):
    team: constr(strip_whitespace=True, min_length=1)  # type: ignore
    email: EmailStr
    slack: Optional[constr(strip_whitespace=True, min_length=1)] = None  # type: ignore

class License(BaseModel):
    spdx_id: constr(strip_whitespace=True, min_length=1)  # type: ignore
    url: Optional[HttpUrl] = None
    name: Optional[str] = None
    redistributable: Optional[bool] = None

class Compliance(BaseModel):
    standards: List[str] = []
    restrictions: List[str] = []
    legal_refs: List[str] = []

class PiiCategory(str, Enum):
    NAME = "NAME"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    GEO = "GEO"
    BIOMETRIC = "BIOMETRIC"
    FINANCIAL = "FINANCIAL"
    HEALTH = "HEALTH"

class PiiProfile(BaseModel):
    has_pii: bool = False
    categories: List[PiiCategory] = []
    detection_tool: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)

class Governance(BaseModel):
    license: Optional[License] = None
    compliance: Optional[Compliance] = None
    security_tier: Optional[str] = Field(default=None, regex=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    pii: Optional[PiiProfile] = None

class ContentAddress(BaseModel):
    uri: constr(strip_whitespace=True, min_length=1)  # type: ignore
    checksum_algo: str = Field(default="SHA256", regex=r"^(SHA256|SHA512|BLAKE3)$")
    checksum_hex: constr(strip_whitespace=True, min_length=16)  # type: ignore
    size_bytes: Optional[int] = Field(default=None, ge=0)
    etag: Optional[str] = None

class StorageLocation(BaseModel):
    # Используем унифицированное описание (один из вариантов)
    kind: str = Field(regex=r"^(s3|gcs|azure|hf|local|http)$")
    bucket_or_account: Optional[str] = None
    container_or_prefix: Optional[str] = None
    region_or_project: Optional[str] = None
    base_url: Optional[str] = None
    path: Optional[str] = None

class StorageDescriptor(BaseModel):
    base: StorageLocation
    format: str = Field(regex=r"^(CSV|TSV|JSONL|PARQUET|ORC|AVRO|TFRECORD|ARROW)$")
    objects: List[ContentAddress] = []

class DataSchemaField(BaseModel):
    name: constr(strip_whitespace=True, min_length=1)  # type: ignore
    type: str = Field(regex=r"^(STRING|INT64|FLOAT|DOUBLE|BOOL|BYTES|TIMESTAMP|DATE|STRUCT|ARRAY)$")
    required: bool = False
    description: Optional[str] = None
    tags: Dict[str, str] = {}
    element: Optional["DataSchemaField"] = None
    fields: List["DataSchemaField"] = []

DataSchemaField.update_forward_refs()

class DataSchema(BaseModel):
    fields: List[DataSchemaField]
    version: Optional[str] = None
    uri: Optional[str] = None

class DatasetSplit(BaseModel):
    name: constr(strip_whitespace=True, min_length=1)  # type: ignore
    fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    records: Optional[int] = Field(default=None, ge=0)

class DataQualityMetrics(BaseModel):
    row_count: Optional[int] = Field(default=None, ge=0)
    invalid_rows: Optional[int] = Field(default=None, ge=0)
    invalid_fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    missing_fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    duplicate_fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)

class BiasMetrics(BaseModel):
    demographic_parity_diff: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    equalized_odds_diff: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    subgroup_error_rates: Dict[str, float] = {}

class DriftMetrics(BaseModel):
    population_stability_index: Optional[float] = Field(default=None, ge=0.0)
    kl_divergence: Optional[float] = Field(default=None, ge=0.0)
    reference_start: Optional[str] = None
    reference_end: Optional[str] = None
    current_start: Optional[str] = None
    current_end: Optional[str] = None

class ValidationReport(BaseModel):
    status: str = Field(regex=r"^(PASS|WARN|FAIL)$")
    errors: List[str] = []
    warnings: List[str] = []

class DatasetVersion(BaseModel):
    version: constr(strip_whitespace=True, min_length=1)  # type: ignore
    revision: Optional[str] = None
    created_at: Optional[str] = None
    created_by: Optional[str] = None
    immutable: bool = False

    modalities: List[str] = []  # TEXT/IMAGE/...
    schema: DataSchema
    storage: StorageDescriptor

    size_bytes: Optional[int] = Field(default=None, ge=0)
    record_count: Optional[int] = Field(default=None, ge=0)
    splits: List[DatasetSplit] = []

    quality: Optional[DataQualityMetrics] = None
    bias: Optional[BiasMetrics] = None
    drift: Optional[DriftMetrics] = None

    provenance: Dict[str, Any] = {}
    governance: Optional[Governance] = None

    validation: Optional[ValidationReport] = None

    labels: Dict[str, str] = {}
    annotations: Dict[str, Any] = {}

class AccessPolicy(BaseModel):
    opa_package: Optional[str] = None
    policy_version: Optional[str] = None
    allowed_audiences: List[str] = []
    allowed_purposes: List[str] = []
    attributes: Dict[str, str] = {}

class Dataset(BaseModel):
    id: constr(strip_whitespace=True, min_length=1, max_length=128)  # type: ignore
    name: constr(strip_whitespace=True, min_length=1, max_length=256)  # type: ignore
    description: Optional[str] = None

    lifecycle: DatasetLifecycle = DatasetLifecycle.DRAFT
    owner: Owner

    tags: List[str] = []
    labels: Dict[str, str] = {}

    current_version_id: Optional[str] = None
    current: Optional[DatasetVersion] = None
    versions: List[DatasetVersion] = []

    access_policy: Optional[AccessPolicy] = None

    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @validator("tags")
    def _uniq_tags(cls, v: List[str]) -> List[str]:
        return list(dict.fromkeys(v))[:128]

# Запросы/ответы API

class ListDatasetsResponse(BaseModel):
    items: List[Dataset]
    next_page_token: Optional[str] = None

class ValidateRequest(BaseModel):
    dataset: Dataset

class ValidateResponse(BaseModel):
    report: ValidationReport
    etag: str

class UpsertRequest(BaseModel):
    dataset: Dataset
    upsert: bool = True

class VersionAppendRequest(BaseModel):
    version: DatasetVersion
    make_current: bool = True

# ------------------------------------------------------------------------------
# Репозиторий (интерфейс + InMemory реализация для примеров)
# ------------------------------------------------------------------------------

class DatasetRepository(Protocol):
    async def get(self, dataset_id: str) -> Optional[Dataset]: ...
    async def list(self, offset: int, limit: int, filters: Dict[str, str]) -> Tuple[List[Dataset], int]: ...
    async def put(self, ds: Dataset, if_match: Optional[str]) -> Tuple[Dataset, str]: ...
    async def delete(self, dataset_id: str) -> None: ...
    async def append_version(self, dataset_id: str, v: DatasetVersion, make_current: bool) -> Dataset: ...

class InMemoryDatasetRepository:
    def __init__(self) -> None:
        self._items: Dict[str, Dict[str, Any]] = {}  # id -> {"doc": Dataset, "etag": str}

    async def get(self, dataset_id: str) -> Optional[Dataset]:
        item = self._items.get(dataset_id)
        return item["doc"] if item else None

    async def list(self, offset: int, limit: int, filters: Dict[str, str]) -> Tuple[List[Dataset], int]:
        arr = [x["doc"] for x in self._items.values()]
        # простая фильтрация
        lf = filters.get("lifecycle")
        owner_team = filters.get("owner_team")
        tag = filters.get("tag")
        name_contains = filters.get("name_contains")
        def ok(d: Dataset) -> bool:
            if lf and d.lifecycle.value != lf:
                return False
            if owner_team and d.owner.team != owner_team:
                return False
            if tag and tag not in d.tags:
                return False
            if name_contains and name_contains.lower() not in d.name.lower():
                return False
            return True
        arr = [d for d in arr if ok(d)]
        total = len(arr)
        page = arr[offset: offset + limit]
        return page, total

    async def put(self, ds: Dataset, if_match: Optional[str]) -> Tuple[Dataset, str]:
        # Optimistic concurrency with ETag
        existing = self._items.get(ds.id)
        if existing:
            current_etag = existing["etag"]
            if if_match and if_match != current_etag:
                raise HTTPException(status.HTTP_412_PRECONDITION_FAILED, "ETag mismatch (If-Match failed)")
        doc = ds.copy(deep=True)
        et = etag_for(json.loads(doc.json()))
        self._items[ds.id] = {"doc": doc, "etag": et}
        return doc, et

    async def delete(self, dataset_id: str) -> None:
        self._items.pop(dataset_id, None)

    async def append_version(self, dataset_id: str, v: DatasetVersion, make_current: bool) -> Dataset:
        existing = self._items.get(dataset_id)
        if not existing:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "dataset not found")
        ds: Dataset = existing["doc"]
        # присвоим системные поля
        v = v.copy(deep=True)
        if not v.created_at:
            v.created_at = utc_now_iso()
        ds.versions = ds.versions or []
        # уникальность по version
        if any(_v.version == v.version for _v in ds.versions):
            raise HTTPException(status.HTTP_409_CONFLICT, f"version {v.version} already exists")
        ds.versions.append(v)
        if make_current:
            ds.current = v
            ds.current_version_id = v.version
        ds.updated_at = utc_now_iso()
        et = etag_for(json.loads(ds.json()))
        self._items[dataset_id] = {"doc": ds, "etag": et}
        return ds

# ------------------------------------------------------------------------------
# OPA Policy Gate (опционально)
# ------------------------------------------------------------------------------

class OpaClient:
    def __init__(self, base_url: Optional[str] = None, package: str = "neuroforge.policies.dataset_admission"):
        self.base_url = base_url
        self.package = package

    async def check(self, environment: str, ds: Dataset) -> Tuple[bool, List[str], List[str]]:
        if not self.base_url or not httpx:
            return True, [], []
        url = f"{self.base_url}/v1/data/{self.package.replace('.', '/')}"
        payload = {
            "input": {
                "environment": environment,
                "dataset": json.loads(ds.json()),
            }
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(url, json=payload)
                r.raise_for_status()
                out = r.json()
        except Exception as e:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"OPA check failed: {e}")
        result = out.get("result") or {}
        allow = bool(result.get("allow", False))
        violations = result.get("violations", [])
        warnings = result.get("warnings", [])
        return allow, violations, warnings

# ------------------------------------------------------------------------------
# Зависимости/настройки
# ------------------------------------------------------------------------------

class RouterSettings(BaseModel):
    opa_base_url: Optional[str] = None
    environment: str = "dev"

_repo = InMemoryDatasetRepository()
_opa = OpaClient(base_url=None)  # по умолчанию выключено

def get_repo() -> DatasetRepository:
    return _repo

def get_rsettings() -> RouterSettings:
    # Подхват из ENV при необходимости
    return RouterSettings(
        opa_base_url=os.getenv("OPA_URL") if "OPA_URL" in __import__("os").environ else None,  # type: ignore
        environment=__import__("os").environ.get("ENVIRONMENT", "dev"),  # type: ignore
    )

# ------------------------------------------------------------------------------
# Бизнес-валидация (дополнительно к Pydantic)
# ------------------------------------------------------------------------------

def validate_dataset_semantics(ds: Dataset) -> ValidationReport:
    errors: List[str] = []
    warnings: List[str] = []

    if ds.current and not ds.current_version_id:
        errors.append("current_version_id must be set when current is present")

    if ds.current:
        # требуем хранилище и схему
        if not ds.current.schema or not ds.current.storage:
            errors.append("current.version requires schema and storage")
        # проверка checksums
        for obj in ds.current.storage.objects:
            if len(obj.checksum_hex) < 32:
                errors.append(f"content checksum too short for uri={obj.uri}")
        # простая сумма сплитов
        splits = [s for s in ds.current.splits or [] if s.fraction is not None]
        if splits:
            s = sum(s.fraction for s in splits)  # type: ignore
            if s > 1.0001:
                errors.append(f"splits fraction sum {s:.3f} > 1.0")

    status = "PASS" if not errors else ("WARN" if not errors and warnings else "FAIL")
    # Если нет ошибок, но есть предупреждения — WARN
    if not errors and warnings:
        status = "WARN"
    elif errors:
        status = "FAIL"
    else:
        status = "PASS"

    return ValidationReport(status=status, errors=errors, warnings=warnings)

# ------------------------------------------------------------------------------
# Router
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/datasets", tags=["datasets"])

# GET /v1/datasets
@router.get("", response_model=ListDatasetsResponse)
async def list_datasets(
    request: Request,
    page_size: conint(ge=1, le=1000) = Query(25),
    page_token: Optional[str] = Query(None),
    lifecycle: Optional[DatasetLifecycle] = Query(None),
    owner_team: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    name_contains: Optional[str] = Query(None),
    repo: DatasetRepository = Depends(get_repo),
):
    offset = decode_page_token(page_token)
    filters = {}
    if lifecycle: filters["lifecycle"] = lifecycle.value
    if owner_team: filters["owner_team"] = owner_team
    if tag: filters["tag"] = tag
    if name_contains: filters["name_contains"] = name_contains

    items, total = await repo.list(offset=offset, limit=page_size, filters=filters)
    next_token = encode_page_token(offset + page_size) if (offset + page_size) < total else None
    return ListDatasetsResponse(items=items, next_page_token=next_token)

# GET /v1/datasets/{id}
@router.get("/{dataset_id}", response_model=Dataset)
async def get_dataset(
    dataset_id: str,
    request: Request,
    repo: DatasetRepository = Depends(get_repo),
    response: Response = None,  # type: ignore
):
    ds = await repo.get(dataset_id)
    if not ds:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "dataset not found")
    et = etag_for(json.loads(ds.json()))
    if response:
        response.headers["ETag"] = et
    return ds

# POST /v1/datasets:validate
@router.post(":validate", response_model=ValidateResponse)
async def validate_dataset(
    req: ValidateRequest,
    request: Request,
):
    report = validate_dataset_semantics(req.dataset)
    return ValidateResponse(report=report, etag=etag_for(json.loads(req.dataset.json())))

# PUT /v1/datasets/{id}
@router.put("/{dataset_id}", response_model=Dataset, status_code=status.HTTP_200_OK)
async def upsert_dataset(
    dataset_id: str,
    req: UpsertRequest,
    request: Request,
    repo: DatasetRepository = Depends(get_repo),
    rset: RouterSettings = Depends(get_rsettings),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    response: Response = None,  # type: ignore
):
    ds = req.dataset
    if ds.id != dataset_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "id mismatch between path and payload")

    # системные поля
    now = utc_now_iso()
    if not ds.created_at:
        ds.created_at = now
    ds.updated_at = now

    # Семантическая валидация
    report = validate_dataset_semantics(ds)
    if report.status == "FAIL":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, {"validation": report.dict()})

    # OPA (опционально): запрещаем перевод в VALIDATED/RETired без allow
    want_prod_gate = (ds.lifecycle in {DatasetLifecycle.VALIDATED, DatasetLifecycle.RETIRED})
    opa_client = OpaClient(base_url=rset.opa_base_url)
    if want_prod_gate:
        ok, violations, warnings = await opa_client.check(rset.environment, ds)
        if not ok:
            raise HTTPException(status.HTTP_403_FORBIDDEN, {"violations": violations, "warnings": warnings})

    # Сохранение
    saved, et = await repo.put(ds, if_match=if_match)
    if response:
        response.headers["ETag"] = et
    return saved

# DELETE /v1/datasets/{id}
@router.delete("/{dataset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dataset(
    dataset_id: str,
    request: Request,
    repo: DatasetRepository = Depends(get_repo),
):
    ds = await repo.get(dataset_id)
    if not ds:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "dataset not found")
    await repo.delete(dataset_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# POST /v1/datasets/{id}/versions
@router.post("/{dataset_id}/versions", response_model=Dataset, status_code=status.HTTP_201_CREATED)
async def add_version(
    dataset_id: str,
    req: VersionAppendRequest,
    request: Request,
    repo: DatasetRepository = Depends(get_repo),
    response: Response = None,  # type: ignore
):
    v = req.version
    # минимальные проверки
    if not v.schema or not v.storage:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "version requires schema and storage")
    if not v.created_at:
        v.created_at = utc_now_iso()

    ds = await repo.append_version(dataset_id, v, make_current=req.make_current)
    if response:
        response.headers["ETag"] = etag_for(json.loads(ds.json()))
        response.headers["Location"] = f"/v1/datasets/{dataset_id}/versions/{v.version}"
    return ds

# GET /v1/datasets/{id}/versions/{ver}
@router.get("/{dataset_id}/versions/{version}", response_model=DatasetVersion)
async def get_version(
    dataset_id: str,
    version: str,
    request: Request,
    repo: DatasetRepository = Depends(get_repo),
):
    ds = await repo.get(dataset_id)
    if not ds:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "dataset not found")
    for v in ds.versions or []:
        if v.version == version:
            return v
    raise HTTPException(status.HTTP_404_NOT_FOUND, "version not found")

# POST /v1/datasets/{id}:deprecate
@router.post("/{dataset_id}:deprecate", response_model=Dataset)
async def deprecate_dataset(
    dataset_id: str,
    reason: Optional[str] = Body(default=None, embed=True),
    request: Request = None,  # type: ignore
    repo: DatasetRepository = Depends(get_repo),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    response: Response = None,  # type: ignore
):
    ds = await repo.get(dataset_id)
    if not ds:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "dataset not found")
    ds.lifecycle = DatasetLifecycle.DEPRECATED
    ds.labels = dict(ds.labels or {})
    if reason:
        ds.labels["deprecation_reason"] = reason
    ds.updated_at = utc_now_iso()
    saved, et = await repo.put(ds, if_match=if_match)
    if response:
        response.headers["ETag"] = et
    return saved
