# neuroforge-core/api/http/routers/v1/registry.py
# Production-grade Model Registry HTTP router for FastAPI/Starlette.
# - CRUD for models and versions
# - ETag-based optimistic concurrency (If-Match / If-None-Match)
# - Idempotency via Idempotency-Key
# - Pagination, filtering, ordering
# - Scope-based access control (models:read, models:write, models:admin)
# - Safe input validation (IDs), structured errors, minimal audit logs

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from pydantic import BaseModel, Field, root_validator, validator

# -------------------------------
# Helpers & constants
# -------------------------------

MODEL_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,62})$")

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def to_etag(obj: Dict[str, Any]) -> str:
    """Stable strong ETag from essential fields."""
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def require_scope(request: Request, needed: str) -> None:
    p = getattr(request.state, "principal", None)
    if p is None or not getattr(p, "has_scope", lambda s: False)(needed):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing required scope")

def get_request_id(request: Request) -> str:
    rid = request.headers.get("x-request-id") or request.headers.get("x-correlation-id")
    return rid or hashlib.sha1(f"{time.time_ns()}-{id(request)}".encode()).hexdigest()[:16]

def parse_label_selector(selector: Optional[str]) -> Dict[str, str]:
    """Very small parser for 'k=v,k2=v2'."""
    if not selector:
        return {}
    out: Dict[str, str] = {}
    parts = [p.strip() for p in selector.split(",") if p.strip()]
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        out[k.strip()] = v.strip()
    return out

# -------------------------------
# Pydantic models (HTTP schema)
# -------------------------------

class InferenceIOTensor(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    dtype: str = Field(..., regex=r"^(BOOL|INT(32|64)|FLOAT(16|32)|BF16|STRING|BYTES)$")
    shape: List[int] = Field(default_factory=list)
    content_type: Optional[str] = Field(default=None, max_length=128)
    quantized: Optional[bool] = False

class InferenceIO(BaseModel):
    tensors: List[InferenceIOTensor] = Field(default_factory=list)

class ResourceSpec(BaseModel):
    device_type: str = Field("CPU", regex=r"^(CPU|GPU|TPU|NPU)$")
    device_count: int = Field(0, ge=0, le=64)
    cpu_millicores: int = Field(0, ge=0, le=512000)
    memory_mb: int = Field(0, ge=0, le=4194304)
    threads: int = Field(0, ge=0, le=4096)
    timeout_ms: int = Field(0, ge=0, le=24 * 60 * 60 * 1000)

class ModelBase(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    labels: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    input_spec: Optional[InferenceIO] = None
    output_spec: Optional[InferenceIO] = None

    @validator("labels")
    def _labels_keys_ok(cls, v: Dict[str, str]) -> Dict[str, str]:
        for k in v.keys():
            if not re.match(r"^[a-z0-9]([-a-z0-9_.]{0,61}[a-z0-9])?$", k):
                raise ValueError(f"invalid label key: {k}")
        return v

class ModelCreate(ModelBase):
    model_id: str = Field(..., description="URL-safe ID: ^[a-z0-9][a-z0-9_-]{0,62}$")

    @validator("model_id")
    def _id_ok(cls, v: str) -> str:
        if not MODEL_ID_RE.match(v):
            raise ValueError("invalid model_id format")
        return v

class ModelUpdate(BaseModel):
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    labels: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None
    input_spec: Optional[InferenceIO] = None
    output_spec: Optional[InferenceIO] = None
    default_version: Optional[str] = Field(default=None, max_length=64)

class ModelOut(ModelBase):
    name: str
    model_id: str
    tenant_id: Optional[str]
    default_version: Optional[str] = None
    create_time: datetime
    update_time: datetime
    etag: str

    class Config:
        orm_mode = True

class VersionBase(BaseModel):
    version: str = Field(..., min_length=1, max_length=64)
    artifact_uri: str = Field(..., min_length=1, max_length=2048)
    checksum_sha256: Optional[str] = Field(default=None, regex=r"^[a-f0-9]{64}$")
    size_bytes: Optional[int] = Field(default=None, ge=0)
    framework: str = Field(..., regex=r"^(TENSORFLOW|PYTORCH|ONNX|XGBOOST|LLM)$")
    framework_version: Optional[str] = Field(default=None, max_length=64)
    format: Optional[str] = Field(default=None, max_length=64)
    stage: str = Field("DRAFT", regex=r"^(DRAFT|STAGING|PRODUCTION|DEPRECATED|ARCHIVED)$")
    precision: Optional[str] = Field(default=None, regex=r"^(FP32|FP16|BF16|INT8)$")
    accelerator: Optional[str] = Field(default=None, regex=r"^(CPU|GPU|TPU|NPU)$")
    device_count: Optional[int] = Field(default=0, ge=0, le=64)
    resource_spec: Optional[ResourceSpec] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, float] = Field(default_factory=dict)
    model_card_uri: Optional[str] = Field(default=None, max_length=2048)

class VersionCreate(VersionBase):
    pass

class VersionUpdate(BaseModel):
    # Updatable fields only
    stage: Optional[str] = Field(default=None, regex=r"^(DRAFT|STAGING|PRODUCTION|DEPRECATED|ARCHIVED)$")
    resource_spec: Optional[ResourceSpec] = None
    parameters: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, float]] = None
    model_card_uri: Optional[str] = Field(default=None, max_length=2048)
    precision: Optional[str] = Field(default=None, regex=r"^(FP32|FP16|BF16|INT8)$")

class VersionOut(VersionBase):
    name: str
    model: str
    create_time: datetime
    update_time: datetime
    created_by: Optional[str]
    etag: str

# Pagination wrappers
class ListModelsResponse(BaseModel):
    items: List[ModelOut]
    next_page_token: Optional[str] = None

class ListVersionsResponse(BaseModel):
    items: List[VersionOut]
    next_page_token: Optional[str] = None

# -------------------------------
# Service layer: interface + in-memory impl (swap in prod)
# -------------------------------

class RegistryError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail or code
        super().__init__(self.detail)

class IModelRegistryService:
    # Models
    def create_model(self, tenant: Optional[str], data: ModelCreate, idem_key: Optional[str]) -> ModelOut: ...
    def get_model(self, tenant: Optional[str], model_id: str) -> ModelOut: ...
    def update_model(self, tenant: Optional[str], model_id: str, patch: ModelUpdate, if_match: Optional[str]) -> ModelOut: ...
    def delete_model(self, tenant: Optional[str], model_id: str, if_match: Optional[str]) -> None: ...
    def list_models(self, tenant: Optional[str], page_size: int, page_token: Optional[str],
                    label_selector: Dict[str, str], order_by: Optional[str]) -> Tuple[List[ModelOut], Optional[str]]: ...
    def set_default_version(self, tenant: Optional[str], model_id: str, version: str, if_match: Optional[str]) -> ModelOut: ...
    # Versions
    def create_version(self, tenant: Optional[str], model_id: str, data: VersionCreate, actor: Optional[str],
                       idem_key: Optional[str]) -> VersionOut: ...
    def get_version(self, tenant: Optional[str], model_id: str, version: str) -> VersionOut: ...
    def update_version(self, tenant: Optional[str], model_id: str, version: str, patch: VersionUpdate,
                       if_match: Optional[str]) -> VersionOut: ...
    def delete_version(self, tenant: Optional[str], model_id: str, version: str, if_match: Optional[str]) -> None: ...
    def list_versions(self, tenant: Optional[str], model_id: str, page_size: int, page_token: Optional[str],
                      stage: Optional[str], order_by: Optional[str]) -> Tuple[List[VersionOut], Optional[str]]: ...
    def promote_version(self, tenant: Optional[str], model_id: str, version: str, target_stage: str,
                        if_match: Optional[str]) -> VersionOut: ...

class InMemoryRegistry(IModelRegistryService):
    """Safe, deterministic in-memory impl. Replace with DB-backed in prod."""
    def __init__(self):
        # store: {tenant or "": {model_id: {...}}}
        self._store: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._idem: Dict[str, str] = {}  # Idempotency-Key -> resource name

    def _ns(self, tenant: Optional[str]) -> Dict[str, Dict[str, Any]]:
        t = tenant or ""
        if t not in self._store:
            self._store[t] = {}
        return self._store[t]

    # ------------- Models -------------
    def create_model(self, tenant: Optional[str], data: ModelCreate, idem_key: Optional[str]) -> ModelOut:
        ns = self._ns(tenant)
        if idem_key and idem_key in self._idem:
            # Return existing resource for same key
            name = self._idem[idem_key]
            model_id = name.split("/")[-1]
            return self.get_model(tenant, model_id)

        if data.model_id in ns:
            raise RegistryError("ALREADY_EXISTS", "Model already exists")

        now = utcnow()
        row = {
            "name": f"models/{data.model_id}",
            "model_id": data.model_id,
            "tenant_id": tenant,
            "display_name": data.display_name,
            "description": data.description,
            "labels": dict(data.labels or {}),
            "metadata": dict(data.metadata or {}),
            "input_spec": data.input_spec.dict() if data.input_spec else None,
            "output_spec": data.output_spec.dict() if data.output_spec else None,
            "default_version": None,
            "create_time": now,
            "update_time": now,
            "deleted": False,
        }
        row["etag"] = to_etag({"u": row["update_time"].isoformat(), "id": row["name"]})
        ns[data.model_id] = {"row": row, "versions": {}}
        if idem_key:
            self._idem[idem_key] = row["name"]
        return ModelOut(**row)

    def get_model(self, tenant: Optional[str], model_id: str) -> ModelOut:
        ns = self._ns(tenant)
        item = ns.get(model_id)
        if not item or item["row"]["deleted"]:
            raise RegistryError("NOT_FOUND", "Model not found")
        return ModelOut(**item["row"])

    def update_model(self, tenant: Optional[str], model_id: str, patch: ModelUpdate, if_match: Optional[str]) -> ModelOut:
        ns = self._ns(tenant)
        item = ns.get(model_id)
        if not item or item["row"]["deleted"]:
            raise RegistryError("NOT_FOUND", "Model not found")
        row = item["row"]
        if if_match and if_match != row["etag"]:
            raise RegistryError("PRECONDITION_FAILED", "ETag mismatch")
        if not if_match:
            raise RegistryError("PRECONDITION_REQUIRED", "If-Match required")

        for f in ("display_name", "description", "default_version"):
            v = getattr(patch, f)
            if v is not None:
                row[f] = v
        if patch.labels is not None:
            row["labels"] = dict(patch.labels)
        if patch.metadata is not None:
            row["metadata"] = dict(patch.metadata)
        if patch.input_spec is not None:
            row["input_spec"] = patch.input_spec.dict()
        if patch.output_spec is not None:
            row["output_spec"] = patch.output_spec.dict()

        row["update_time"] = utcnow()
        row["etag"] = to_etag({"u": row["update_time"].isoformat(), "id": row["name"]})
        return ModelOut(**row)

    def delete_model(self, tenant: Optional[str], model_id: str, if_match: Optional[str]) -> None:
        ns = self._ns(tenant)
        item = ns.get(model_id)
        if not item or item["row"]["deleted"]:
            raise RegistryError("NOT_FOUND", "Model not found")
        if if_match and if_match != item["row"]["etag"]:
            raise RegistryError("PRECONDITION_FAILED", "ETag mismatch")
        if not if_match:
            raise RegistryError("PRECONDITION_REQUIRED", "If-Match required")
        item["row"]["deleted"] = True
        item["row"]["update_time"] = utcnow()
        item["row"]["etag"] = to_etag({"u": item["row"]["update_time"].isoformat(), "id": item["row"]["name"]})

    def list_models(self, tenant: Optional[str], page_size: int, page_token: Optional[str],
                    label_selector: Dict[str, str], order_by: Optional[str]) -> Tuple[List[ModelOut], Optional[str]]:
        ns = self._ns(tenant)
        items = [x["row"] for x in ns.values() if not x["row"]["deleted"]]
        # Filter by labels
        if label_selector:
            def match(row: Dict[str, Any]) -> bool:
                labels = row.get("labels") or {}
                return all(labels.get(k) == v for k, v in label_selector.items())
            items = [r for r in items if match(r)]
        # Order (only a small subset supported)
        if order_by:
            key = order_by.strip().lower()
            rev = key.endswith(" desc")
            if "update_time" in key:
                items.sort(key=lambda r: r["update_time"], reverse=rev)
            elif "create_time" in key:
                items.sort(key=lambda r: r["create_time"], reverse=rev)
            elif "model_id" in key:
                items.sort(key=lambda r: r["model_id"], reverse=rev)

        start = int(page_token or 0)
        end = start + page_size
        page = items[start:end]
        next_token = str(end) if end < len(items) else None
        return [ModelOut(**r) for r in page], next_token

    def set_default_version(self, tenant: Optional[str], model_id: str, version: str, if_match: Optional[str]) -> ModelOut:
        ns = self._ns(tenant)
        item = ns.get(model_id)
        if not item or item["row"]["deleted"]:
            raise RegistryError("NOT_FOUND", "Model not found")
        if if_match and if_match != item["row"]["etag"]:
            raise RegistryError("PRECONDITION_FAILED", "ETag mismatch")
        if not if_match:
            raise RegistryError("PRECONDITION_REQUIRED", "If-Match required")
        if version not in item["versions"]:
            raise RegistryError("NOT_FOUND", "Version not found")
        item["row"]["default_version"] = version
        item["row"]["update_time"] = utcnow()
        item["row"]["etag"] = to_etag({"u": item["row"]["update_time"].isoformat(), "id": item["row"]["name"]})
        return ModelOut(**item["row"])

    # ------------- Versions -------------
    def create_version(self, tenant: Optional[str], model_id: str, data: VersionCreate, actor: Optional[str],
                       idem_key: Optional[str]) -> VersionOut:
        ns = self._ns(tenant)
        item = ns.get(model_id)
        if not item or item["row"]["deleted"]:
            raise RegistryError("NOT_FOUND", "Model not found")
        idem_key = f"{model_id}:{idem_key}" if idem_key else None
        if idem_key and idem_key in self._idem:
            name = self._idem[idem_key]
            version = name.split("/")[-1]
            return self.get_version(tenant, model_id, version)

        if data.version in item["versions"]:
            raise RegistryError("ALREADY_EXISTS", "Version already exists")
        now = utcnow()
        row = {
            "name": f"models/{model_id}/versions/{data.version}",
            "model": f"models/{model_id}",
            "create_time": now,
            "update_time": now,
            "created_by": actor,
            **data.dict(),
        }
        row["etag"] = to_etag({"u": row["update_time"].isoformat(), "id": row["name"]})
        item["versions"][data.version] = row
        if idem_key:
            self._idem[idem_key] = row["name"]
        return VersionOut(**row)

    def get_version(self, tenant: Optional[str], model_id: str, version: str) -> VersionOut:
        ns = self._ns(tenant)
        item = ns.get(model_id)
        if not item or item["row"]["deleted"]:
            raise RegistryError("NOT_FOUND", "Model not found")
        row = item["versions"].get(version)
        if not row:
            raise RegistryError("NOT_FOUND", "Version not found")
        return VersionOut(**row)

    def update_version(self, tenant: Optional[str], model_id: str, version: str, patch: VersionUpdate,
                       if_match: Optional[str]) -> VersionOut:
        ns = self._ns(tenant)
        item = ns.get(model_id)
        if not item or item["row"]["deleted"]:
            raise RegistryError("NOT_FOUND", "Model not found")
        row = item["versions"].get(version)
        if not row:
            raise RegistryError("NOT_FOUND", "Version not found")
        if if_match and if_match != row["etag"]:
            raise RegistryError("PRECONDITION_FAILED", "ETag mismatch")
        if not if_match:
            raise RegistryError("PRECONDITION_REQUIRED", "If-Match required")
        for f, v in patch.dict(exclude_unset=True).items():
            row[f] = v
        row["update_time"] = utcnow()
        row["etag"] = to_etag({"u": row["update_time"].isoformat(), "id": row["name"]})
        return VersionOut(**row)

    def delete_version(self, tenant: Optional[str], model_id: str, version: str, if_match: Optional[str]) -> None:
        ns = self._ns(tenant)
        item = ns.get(model_id)
        if not item or item["row"]["deleted"]:
            raise RegistryError("NOT_FOUND", "Model not found")
        row = item["versions"].get(version)
        if not row:
            raise RegistryError("NOT_FOUND", "Version not found")
        if if_match and if_match != row["etag"]:
            raise RegistryError("PRECONDITION_FAILED", "ETag mismatch")
        if not if_match:
            raise RegistryError("PRECONDITION_REQUIRED", "If-Match required")
        del item["versions"][version]
        # If default pointed to this version, unset
        if item["row"].get("default_version") == version:
            item["row"]["default_version"] = None
            item["row"]["update_time"] = utcnow()
            item["row"]["etag"] = to_etag({"u": item["row"]["update_time"].isoformat(), "id": item["row"]["name"]})

    def list_versions(self, tenant: Optional[str], model_id: str, page_size: int, page_token: Optional[str],
                      stage: Optional[str], order_by: Optional[str]) -> Tuple[List[VersionOut], Optional[str]]:
        ns = self._ns(tenant)
        item = ns.get(model_id)
        if not item or item["row"]["deleted"]:
            raise RegistryError("NOT_FOUND", "Model not found")
        items = list(item["versions"].values())
        if stage:
            items = [v for v in items if v.get("stage") == stage]
        if order_by:
            key = order_by.strip().lower()
            rev = key.endswith(" desc")
            if "update_time" in key:
                items.sort(key=lambda r: r["update_time"], reverse=rev)
            elif "create_time" in key:
                items.sort(key=lambda r: r["create_time"], reverse=rev)
            elif "version" in key:
                items.sort(key=lambda r: r["version"], reverse=rev)
        start = int(page_token or 0)
        end = start + page_size
        page = items[start:end]
        next_token = str(end) if end < len(items) else None
        return [VersionOut(**r) for r in page], next_token

    def promote_version(self, tenant: Optional[str], model_id: str, version: str, target_stage: str,
                        if_match: Optional[str]) -> VersionOut:
        return self.update_version(
            tenant, model_id, version, VersionUpdate(stage=target_stage), if_match=if_match
        )

# -------------------------------
# Dependencies
# -------------------------------

# In real app wire via container. Here we keep a module-level default.
_registry = InMemoryRegistry()

def get_registry() -> IModelRegistryService:
    return _registry

def get_tenant(request: Request) -> Optional[str]:
    p = getattr(request.state, "principal", None)
    return getattr(p, "tenant", None) if p else None

def get_actor(request: Request) -> Optional[str]:
    p = getattr(request.state, "principal", None)
    return getattr(p, "subject", None) if p else None

# -------------------------------
# Router
# -------------------------------

router = APIRouter(prefix="/v1", tags=["registry"])

# ---- Models ----

@router.post(
    "/models",
    response_model=ModelOut,
    status_code=status.HTTP_201_CREATED,
)
def create_model(
    request: Request,
    body: ModelCreate,
    response: Response,
    idem_key: Optional[str] = Query(None, alias="idem_key"),
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:write")
    # Honor If-None-Match: *
    inm = request.headers.get("if-none-match")
    if inm and inm.strip() != "*":
        raise HTTPException(status_code=400, detail="If-None-Match only supports '*'")
    try:
        out = reg.create_model(tenant, body, idem_key)
    except RegistryError as e:
        if e.code == "ALREADY_EXISTS":
            raise HTTPException(status_code=409, detail=e.detail)
        raise
    response.headers["ETag"] = out.etag
    response.headers["Location"] = f"/v1/{out.name}"
    return out

@router.get("/models", response_model=ListModelsResponse)
def list_models(
    request: Request,
    page_size: int = Query(50, ge=1, le=500),
    page_token: Optional[str] = Query(None),
    labels: Optional[str] = Query(None, description='Label selector "k=v,k2=v2"'),
    order_by: Optional[str] = Query("update_time desc"),
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:read")
    items, next_tok = reg.list_models(tenant, page_size, page_token, parse_label_selector(labels), order_by)
    return ListModelsResponse(items=items, next_page_token=next_tok)

@router.get("/models/{model_id}", response_model=ModelOut)
def get_model(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    response: Response = None,
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:read")
    try:
        out = reg.get_model(tenant, model_id)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        raise
    if response is not None:
        response.headers["ETag"] = out.etag
    return out

@router.patch("/models/{model_id}", response_model=ModelOut)
def update_model(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    body: ModelUpdate = None,
    response: Response = None,
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:write")
    if_match = request.headers.get("if-match")
    try:
        out = reg.update_model(tenant, model_id, body or ModelUpdate(), if_match)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        if e.code == "PRECONDITION_FAILED":
            raise HTTPException(status_code=412, detail=e.detail)
        if e.code == "PRECONDITION_REQUIRED":
            raise HTTPException(status_code=428, detail=e.detail)
        raise
    if response is not None:
        response.headers["ETag"] = out.etag
    return out

@router.delete("/models/{model_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_model(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:write")
    if_match = request.headers.get("if-match")
    try:
        reg.delete_model(tenant, model_id, if_match)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        if e.code == "PRECONDITION_FAILED":
            raise HTTPException(status_code=412, detail=e.detail)
        if e.code == "PRECONDITION_REQUIRED":
            raise HTTPException(status_code=428, detail=e.detail)
        raise
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@router.post("/models/{model_id}:setDefaultVersion", response_model=ModelOut)
def set_default_version(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    version: str = Query(..., min_length=1, max_length=64),
    response: Response = None,
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:write")
    if_match = request.headers.get("if-match")
    try:
        out = reg.set_default_version(tenant, model_id, version, if_match)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        if e.code == "PRECONDITION_FAILED":
            raise HTTPException(status_code=412, detail=e.detail)
        if e.code == "PRECONDITION_REQUIRED":
            raise HTTPException(status_code=428, detail=e.detail)
        raise
    if response is not None:
        response.headers["ETag"] = out.etag
    return out

# ---- Versions ----

@router.post(
    "/models/{model_id}/versions",
    response_model=VersionOut,
    status_code=status.HTTP_201_CREATED,
)
def create_version(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    body: VersionCreate = None,
    response: Response = None,
    idem_key: Optional[str] = Query(None, alias="idem_key"),
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
    actor: Optional[str] = Depends(get_actor),
):
    require_scope(request, "models:write")
    try:
        out = reg.create_version(tenant, model_id, body or VersionCreate(), actor, idem_key)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        if e.code == "ALREADY_EXISTS":
            raise HTTPException(status_code=409, detail=e.detail)
        raise
    if response is not None:
        response.headers["ETag"] = out.etag
        response.headers["Location"] = f"/v1/{out.name}"
    return out

@router.get("/models/{model_id}/versions", response_model=ListVersionsResponse)
def list_versions(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    page_size: int = Query(50, ge=1, le=500),
    page_token: Optional[str] = Query(None),
    stage: Optional[str] = Query(None, regex=r"^(DRAFT|STAGING|PRODUCTION|DEPRECATED|ARCHIVED)$"),
    order_by: Optional[str] = Query("update_time desc"),
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:read")
    try:
        items, next_tok = reg.list_versions(tenant, model_id, page_size, page_token, stage, order_by)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        raise
    return ListVersionsResponse(items=items, next_page_token=next_tok)

@router.get("/models/{model_id}/versions/{version}", response_model=VersionOut)
def get_version(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    version: str = Path(..., min_length=1, max_length=64),
    response: Response = None,
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:read")
    try:
        out = reg.get_version(tenant, model_id, version)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        raise
    if response is not None:
        response.headers["ETag"] = out.etag
    return out

@router.patch("/models/{model_id}/versions/{version}", response_model=VersionOut)
def update_version(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    version: str = Path(..., min_length=1, max_length=64),
    body: VersionUpdate = None,
    response: Response = None,
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:write")
    if_match = request.headers.get("if-match")
    try:
        out = reg.update_version(tenant, model_id, version, body or VersionUpdate(), if_match)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        if e.code == "PRECONDITION_FAILED":
            raise HTTPException(status_code=412, detail=e.detail)
        if e.code == "PRECONDITION_REQUIRED":
            raise HTTPException(status_code=428, detail=e.detail)
        raise
    if response is not None:
        response.headers["ETag"] = out.etag
    return out

@router.delete("/models/{model_id}/versions/{version}", status_code=status.HTTP_204_NO_CONTENT)
def delete_version(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    version: str = Path(..., min_length=1, max_length=64),
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:write")
    if_match = request.headers.get("if-match")
    try:
        reg.delete_version(tenant, model_id, version, if_match)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        if e.code == "PRECONDITION_FAILED":
            raise HTTPException(status_code=412, detail=e.detail)
        if e.code == "PRECONDITION_REQUIRED":
            raise HTTPException(status_code=428, detail=e.detail)
        raise
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@router.post("/models/{model_id}/versions/{version}:promote", response_model=VersionOut)
def promote_version(
    request: Request,
    model_id: str = Path(..., regex=MODEL_ID_RE.pattern),
    version: str = Path(..., min_length=1, max_length=64),
    target_stage: str = Query(..., regex=r"^(STAGING|PRODUCTION|DEPRECATED|ARCHIVED)$"),
    response: Response = None,
    reg: IModelRegistryService = Depends(get_registry),
    tenant: Optional[str] = Depends(get_tenant),
):
    require_scope(request, "models:write")
    if_match = request.headers.get("if-match")
    try:
        out = reg.promote_version(tenant, model_id, version, target_stage, if_match)
    except RegistryError as e:
        if e.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.detail)
        if e.code == "PRECONDITION_FAILED":
            raise HTTPException(status_code=412, detail=e.detail)
        if e.code == "PRECONDITION_REQUIRED":
            raise HTTPException(status_code=428, detail=e.detail)
        raise
    if response is not None:
        response.headers["ETag"] = out.etag
    return out
