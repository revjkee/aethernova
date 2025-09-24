from __future__ import annotations

import hashlib
import json
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, ValidationError, constr

# ---------------------------
# RBAC / Auth dependencies
# ---------------------------

class Principal(BaseModel):
    sub: str
    roles: List[str] = Field(default_factory=list)
    tenant: Optional[str] = None
    region: Optional[str] = None

PLATFORM_ADMIN = "platform.admin"
TENANT_ADMIN = "tenant.admin"

def require_admin(principal: Principal = Depends(lambda: _auth_ctx())) -> Principal:
    roles = set(principal.roles or [])
    if PLATFORM_ADMIN in roles or TENANT_ADMIN in roles:
        return principal
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden: admin role required")

def _auth_ctx() -> Principal:
    """
    В реальном проекте замените на интеграцию с провайдером (OIDC/JWT).
    Здесь — заглушка для DI.
    """
    # Пример: извлечение из контекста/заголовков (omitted)
    return Principal(sub="system", roles=[PLATFORM_ADMIN], tenant=None, region=None)

# ---------------------------
# Idempotency cache interface
# ---------------------------

class IdempotencyCache(Protocol):
    def get(self, key: str) -> Optional[Dict[str, Any]]: ...
    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int) -> None: ...

class InMemoryIdemCache:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        item = self._data.get(key)
        if not item:
            return None
        expires_at, payload = item
        if time.time() > expires_at:
            self._data.pop(key, None)
            return None
        return payload

    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int) -> None:
        self._data[key] = (time.time() + ttl_seconds, value)

# ---------------------------
# Repository abstraction
# ---------------------------

class DatasetRecord(BaseModel):
    id: str
    identity: Dict[str, Any]
    classification: Literal["public", "internal", "confidential", "restricted"]
    pii: bool
    pii_level: Optional[Literal["none", "weak", "strong"]] = None
    versioning: Dict[str, Any]
    schema_refs: List[Dict[str, Any]]
    storage: List[Dict[str, Any]]
    partitioning: Optional[Dict[str, Any]] = None
    export_policy: Optional[Dict[str, Any]] = None
    retention: Optional[Dict[str, Any]] = None
    lineage: Optional[Dict[str, Any]] = None
    quality: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list)
    annotations: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str
    etag: str

class Page(BaseModel):
    items: List[DatasetRecord]
    next_cursor: Optional[str] = None
    total: Optional[int] = None

class DatasetRepo(Protocol):
    async def list(self, *, cursor: Optional[str], limit: int, filters: Dict[str, Any]) -> Page: ...
    async def get(self, dataset_id: str) -> Optional[DatasetRecord]: ...
    async def upsert(self, payload: Dict[str, Any], *, expected_etag: Optional[str]) -> DatasetRecord: ...
    async def patch(self, dataset_id: str, patch: Dict[str, Any], *, expected_etag: Optional[str]) -> DatasetRecord: ...
    async def delete(self, dataset_id: str, *, expected_etag: Optional[str]) -> bool: ...

# ---------------------------
# DTOs (input/output)
# ---------------------------

class IdentityDTO(BaseModel):
    name: constr(min_length=3, max_length=128)
    namespace: constr(min_length=3, max_length=64)
    owner: constr(min_length=1)
    tenant: Optional[str] = None
    domain: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)

class VersioningDTO(BaseModel):
    datasetVersion: constr(regex=r"^\d+\.\d+\.\d+([-.][0-9A-Za-z.]+)?$")
    schemaVersion: Optional[str] = None
    revision: Optional[str] = None
    updatedAt: Optional[str] = None  # RFC3339

class SchemaRefDTO(BaseModel):
    type: Literal["jsonschema", "avro", "protobuf"]
    uri: constr(min_length=3)
    message: Optional[str] = None

class StorageTargetDTO(BaseModel):
    # Гибридный DTO — пропускает объект-таргет; валидация глубже — на уровне схемы JSON
    kind: Literal["s3", "postgres", "kafka", "elastic", "filesystem"]
    spec: Dict[str, Any]

class RetentionRefDTO(BaseModel):
    uri: constr(min_length=3)

class LineageRefDTO(BaseModel):
    uri: constr(min_length=3)

class ExportPolicyDTO(BaseModel):
    allowPublic: bool = False
    dlpRequired: bool = True
    approvals: List[str] = Field(default_factory=lambda: ["DPO", "Security"])

class QualityRefDTO(BaseModel):
    checksRef: Optional[str] = None
    slo: Optional[Dict[str, Any]] = None

class UpsertDatasetInput(BaseModel):
    id: Optional[constr(min_length=3, max_length=256)] = None
    identity: IdentityDTO
    classification: Literal["public", "internal", "confidential", "restricted"]
    pii: bool
    piiLevel: Optional[Literal["none", "weak", "strong"]] = None
    versioning: VersioningDTO
    schemaRefs: List[SchemaRefDTO]
    storage: List[StorageTargetDTO]
    partitioning: Optional[Dict[str, Any]] = None
    exportPolicy: Optional[ExportPolicyDTO] = None
    retention: Optional[RetentionRefDTO] = None
    lineage: Optional[LineageRefDTO] = None
    quality: Optional[QualityRefDTO] = None
    tags: List[str] = Field(default_factory=list)
    annotations: Dict[str, Any] = Field(default_factory=dict)

class PatchDatasetInput(BaseModel):
    identity: Optional[IdentityDTO] = None
    classification: Optional[Literal["public", "internal", "confidential", "restricted"]] = None
    pii: Optional[bool] = None
    piiLevel: Optional[Literal["none", "weak", "strong"]] = None
    versioning: Optional[VersioningDTO] = None
    schemaRefs: Optional[List[SchemaRefDTO]] = None
    storage: Optional[List[StorageTargetDTO]] = None
    partitioning: Optional[Dict[str, Any]] = None
    exportPolicy: Optional[ExportPolicyDTO] = None
    retention: Optional[RetentionRefDTO] = None
    lineage: Optional[LineageRefDTO] = None
    quality: Optional[QualityRefDTO] = None
    tags: Optional[List[str]] = None
    annotations: Optional[Dict[str, Any]] = None

class ListFilter(BaseModel):
    namespace: Optional[str] = None
    owner: Optional[str] = None
    tenant: Optional[str] = None
    classificationIn: Optional[List[Literal["public","internal","confidential","restricted"]]] = None
    pii: Optional[bool] = None
    tagIn: Optional[List[str]] = None
    updatedAfter: Optional[str] = None
    storageKindAny: Optional[List[Literal["s3","postgres","kafka","elastic","filesystem"]]] = None

# ---------------------------
# Utilities
# ---------------------------

def _calc_etag(obj: Dict[str, Any]) -> str:
    # стабильный ETag из нормализованного JSON (без полей аудита)
    j = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(j).hexdigest()

def _idem_key_or_none(key: Optional[str]) -> Optional[str]:
    if not key:
        return None
    key = key.strip()
    if not key:
        return None
    if len(key) > 256:
        raise HTTPException(status_code=400, detail="invalid Idempotency-Key length")
    return key

# ---------------------------
# Router
# ---------------------------

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

# DI placeholders (замените при интеграции)
_IDEM_CACHE = InMemoryIdemCache()
_REPO: DatasetRepo  # будет внедрён при инициализации приложения через dependency_overrides


def get_repo() -> DatasetRepo:
    try:
        return _REPO  # type: ignore
    except Exception:
        raise HTTPException(status_code=500, detail="repository is not initialized")

# ---------- Endpoints ----------

@router.get("/datasets", response_model=Page)
async def list_datasets(
    cursor: Optional[str] = None,
    limit: int = 50,
    namespace: Optional[str] = None,
    owner: Optional[str] = None,
    tenant: Optional[str] = None,
    classificationIn: Optional[str] = None,  # CSV
    pii: Optional[bool] = None,
    tagIn: Optional[str] = None,             # CSV
    updatedAfter: Optional[str] = None,
    storageKindAny: Optional[str] = None,    # CSV
    principal: Principal = Depends(require_admin),
    repo: DatasetRepo = Depends(get_repo),
) -> Page:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be 1..500")

    filters = ListFilter(
        namespace=namespace,
        owner=owner,
        tenant=tenant or principal.tenant,
        classificationIn=(classificationIn.split(",") if classificationIn else None),  # type: ignore
        pii=pii,
        tagIn=(tagIn.split(",") if tagIn else None),
        updatedAfter=updatedAfter,
        storageKindAny=(storageKindAny.split(",") if storageKindAny else None)  # type: ignore
    ).model_dump(exclude_none=True)

    return await repo.list(cursor=cursor, limit=limit, filters=filters)


@router.get("/datasets/{dataset_id}", response_model=DatasetRecord)
async def get_dataset(
    dataset_id: str,
    principal: Principal = Depends(require_admin),
    repo: DatasetRepo = Depends(get_repo),
    response: Response = None,  # type: ignore
) -> DatasetRecord:
    rec = await repo.get(dataset_id)
    if not rec:
        raise HTTPException(status_code=404, detail="dataset not found")
    # ETag для клиента
    response.headers["ETag"] = rec.etag
    return rec


@router.post("/datasets", response_model=DatasetRecord, status_code=201)
async def upsert_dataset(
    payload: UpsertDatasetInput,
    request: Request,
    response: Response,
    principal: Principal = Depends(require_admin),
    idem_key: Optional[str] = Header(default=None, convert_underscores=False, alias="Idempotency-Key"),
    if_match: Optional[str] = Header(default=None, convert_underscores=False, alias="If-Match"),
    repo: DatasetRepo = Depends(get_repo),
) -> DatasetRecord:
    # Idempotency
    key = _idem_key_or_none(idem_key)
    if key:
        cached = _IDEM_CACHE.get(key)
        if cached:
            response.headers["Idempotency-Replayed"] = "true"
            response.headers["ETag"] = cached.get("etag", "")
            return DatasetRecord(**cached["record"])

    # Тенант‑гард: tenant из principal доминирует
    if principal.tenant and payload.identity.tenant and payload.identity.tenant != principal.tenant:
        raise HTTPException(status_code=403, detail="cross-tenant modification is not allowed")

    # Валидация соответствия PII/level (минимальные бизнес‑правила)
    if payload.pii and payload.piiLevel == "none":
        raise HTTPException(status_code=400, detail="piiLevel cannot be 'none' when pii=true")

    # Конструируем "сырой" объект для репозитория
    raw = payload.model_dump(mode="json")
    # upsert c ETag (optimistic concurrency)
    rec = await repo.upsert(raw, expected_etag=if_match)
    response.headers["ETag"] = rec.etag

    # Кэш идемпотентности (5 минут)
    if key:
        _IDEM_CACHE.set(key, {"record": rec.model_dump(mode="json"), "etag": rec.etag}, ttl_seconds=300)

    # Аудит (через логгер/шину событий — опущено)
    return rec


@router.patch("/datasets/{dataset_id}", response_model=DatasetRecord)
async def patch_dataset(
    dataset_id: str,
    patch: PatchDatasetInput,
    response: Response,
    principal: Principal = Depends(require_admin),
    idem_key: Optional[str] = Header(default=None, convert_underscores=False, alias="Idempotency-Key"),
    if_match: Optional[str] = Header(default=None, convert_underscores=False, alias="If-Match"),
    repo: DatasetRepo = Depends(get_repo),
) -> DatasetRecord:
    key = _idem_key_or_none(idem_key)
    if key:
        cached = _IDEM_CACHE.get(key)
        if cached:
            response.headers["Idempotency-Replayed"] = "true"
            response.headers["ETag"] = cached.get("etag", "")
            return DatasetRecord(**cached["record"])

    if patch.pii is True and patch.piiLevel == "none":
        raise HTTPException(status_code=400, detail="piiLevel cannot be 'none' when pii=true")

    rec = await repo.patch(dataset_id, patch.model_dump(exclude_none=True), expected_etag=if_match)
    response.headers["ETag"] = rec.etag

    if key:
        _IDEM_CACHE.set(key, {"record": rec.model_dump(mode="json"), "etag": rec.etag}, ttl_seconds=300)
    return rec


@router.delete("/datasets/{dataset_id}", status_code=204)
async def delete_dataset(
    dataset_id: str,
    principal: Principal = Depends(require_admin),
    if_match: Optional[str] = Header(default=None, convert_underscores=False, alias="If-Match"),
    repo: DatasetRepo = Depends(get_repo),
) -> Response:
    ok = await repo.delete(dataset_id, expected_etag=if_match)
    if not ok:
        raise HTTPException(status_code=404, detail="dataset not found")
    return Response(status_code=204)


@router.post("/policies/retention/sync", status_code=202)
async def retention_sync(
    principal: Principal = Depends(require_admin),
    idem_key: Optional[str] = Header(default=None, convert_underscores=False, alias="Idempotency-Key"),
) -> Dict[str, Any]:
    """
    Триггер синхронизации правил S3 Lifecycle/SQL purge/Kafka TTL с configs/policies/retention.yaml.
    Реализация асинхронного джоба — вне данного файла.
    """
    key = _idem_key_or_none(idem_key)
    job_id = uuid.uuid4().hex
    result = {"accepted": True, "job_id": job_id}
    if key:
        _IDEM_CACHE.set(key, {"record": result, "etag": ""}, ttl_seconds=300)
    return result

# ---------------------------
# Example memory repo (for dev/test) — optional
# ---------------------------

class InMemoryDatasetRepo(DatasetRepo):
    def __init__(self) -> None:
        self._items: Dict[str, Dict[str, Any]] = {}

    async def list(self, *, cursor: Optional[str], limit: int, filters: Dict[str, Any]) -> Page:
        items = list(self._items.values())

        # простая фильтрация по нескольким полям
        def _match(it: Dict[str, Any]) -> bool:
            if ns := filters.get("namespace"):
                if it["identity"].get("namespace") != ns:
                    return False
            if own := filters.get("owner"):
                if it["identity"].get("owner") != own:
                    return False
            if tenant := filters.get("tenant"):
                if it["identity"].get("tenant") not in (tenant, None, "*"):
                    return False
            if cset := filters.get("classificationIn"):
                if it["classification"] not in cset:
                    return False
            if pii := filters.get("pii"):
                if bool(it.get("pii")) != bool(pii):
                    return False
            if tags := filters.get("tagIn"):
                if not set(tags).intersection(set(it.get("tags", []))):
                    return False
            if kinds := filters.get("storageKindAny"):
                kinds_lower = set(kinds)
                sk = [t.get("kind") for t in it.get("storage", [])]
                if not set(sk).intersection(kinds_lower):
                    return False
            return True

        filtered = [it for it in items if _match(it)]
        # cursor = простой смещение (для примера)
        offset = int(cursor or 0)
        window = filtered[offset : offset + limit]
        next_cursor = str(offset + limit) if offset + limit < len(filtered) else None

        page_items = [DatasetRecord(**it) for it in window]
        return Page(items=page_items, next_cursor=next_cursor, total=len(filtered))

    async def get(self, dataset_id: str) -> Optional[DatasetRecord]:
        it = self._items.get(dataset_id)
        return DatasetRecord(**it) if it else None

    async def upsert(self, payload: Dict[str, Any], *, expected_etag: Optional[str]) -> DatasetRecord:
        ds_id = payload.get("id") or self._gen_id(payload)
        existing = self._items.get(ds_id)

        # optimistic concurrency
        if existing and expected_etag and expected_etag != existing["etag"]:
            raise HTTPException(status_code=412, detail="precondition failed (etag mismatch)")

        now = _now_rfc3339()
        rec = existing or {}
        rec.update(
            {
                "id": ds_id,
                "identity": payload["identity"],
                "classification": payload["classification"],
                "pii": payload["pii"],
                "pii_level": payload.get("piiLevel"),
                "versioning": payload["versioning"],
                "schema_refs": payload["schemaRefs"],
                "storage": payload["storage"],
                "partitioning": payload.get("partitioning"),
                "export_policy": payload.get("exportPolicy"),
                "retention": payload.get("retention"),
                "lineage": payload.get("lineage"),
                "quality": payload.get("quality"),
                "tags": payload.get("tags", []),
                "annotations": payload.get("annotations", {}),
                "created_at": existing["created_at"] if existing else now,
                "updated_at": now,
            }
        )
        rec["etag"] = _calc_etag({k: v for k, v in rec.items() if k not in ("etag", "created_at", "updated_at")})
        self._items[ds_id] = rec
        return DatasetRecord(**rec)

    async def patch(self, dataset_id: str, patch: Dict[str, Any], *, expected_etag: Optional[str]) -> DatasetRecord:
        existing = self._items.get(dataset_id)
        if not existing:
            raise HTTPException(status_code=404, detail="dataset not found")
        if expected_etag and expected_etag != existing["etag"]:
            raise HTTPException(status_code=412, detail="precondition failed (etag mismatch)")

        # Простое обновление с маппингом ключей из DTO в record
        mapping = {
            "piiLevel": "pii_level",
            "schemaRefs": "schema_refs",
            "exportPolicy": "export_policy",
        }
        for k, v in list(patch.items()):
            key = mapping.get(k, k)
            existing[key] = v

        existing["updated_at"] = _now_rfc3339()
        existing["etag"] = _calc_etag({k: v for k, v in existing.items() if k not in ("etag", "created_at", "updated_at")})
        return DatasetRecord(**existing)

    async def delete(self, dataset_id: str, *, expected_etag: Optional[str]) -> bool:
        existing = self._items.get(dataset_id)
        if not existing:
            return False
        if expected_etag and expected_etag != existing["etag"]:
            raise HTTPException(status_code=412, detail="precondition failed (etag mismatch)")
        self._items.pop(dataset_id, None)
        return True

    def _gen_id(self, payload: Dict[str, Any]) -> str:
        ns = payload["identity"]["namespace"]
        name = payload["identity"]["name"]
        return f"{ns}:{name}"

def _now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
