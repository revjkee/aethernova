# physical-integration-core/api/http/routers/v1/firmware.py
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, constr, validator
from packaging.version import Version, InvalidVersion

# ============================
# Abstractions & Dependencies
# ============================

class StorageBackend:
    async def put_object(
        self, key: str, stream: AsyncIterator[bytes], size: Optional[int], content_type: Optional[str]
    ) -> str:
        """Stores object and returns canonical URI (e.g., s3://bucket/key or file:///...)."""
        raise NotImplementedError

    async def presign_get(self, key: str, expires_seconds: int = 3600) -> str:
        """Returns a pre-signed download URL for GET."""
        raise NotImplementedError


class LocalFSStorage(StorageBackend):
    """Simple local FS storage; use for dev/tests. Not for untrusted multi-tenant without hardening."""
    def __init__(self, base_dir: str = "/var/lib/pic/firmware"):
        self.base_dir = base_dir

    async def put_object(self, key: str, stream: AsyncIterator[bytes], size: Optional[int], content_type: Optional[str]) -> str:
        abs_path = os.path.join(self.base_dir, key)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        hasher = hashlib.sha256()
        # write streaming
        with open(abs_path, "wb") as f:
            async for chunk in stream:
                hasher.update(chunk)
                f.write(chunk)
        return f"file://{abs_path}"

    async def presign_get(self, key: str, expires_seconds: int = 3600) -> str:
        return f"file://{os.path.join(self.base_dir, key)}"


class OPAClient:
    """Minimal OPA/external policy client adapter."""
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def evaluate(self, request: Request, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        # Reuse app's HTTP client if available, else use httpx from app state
        httpx_client = getattr(request.app.state, "httpx", None)
        if httpx_client is None:
            raise HTTPException(status_code=500, detail="Policy client not configured")
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            r = await httpx_client.post(url, json=payload, timeout=10.0)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Policy evaluation failed: {e}")


class Principal(BaseModel):
    subject: str
    roles: List[str] = Field(default_factory=list)


async def get_principal(authorization: Optional[str] = Header(None)) -> Principal:
    # Placeholder: real impl should verify JWT/mTLS and map to roles.
    # For example purposes, a simple static mapping:
    roles = ["ot-maintainer", "ot-operator"] if authorization else []
    return Principal(subject="unknown" if not authorization else "caller", roles=roles)


# Repository abstraction to decouple persistence
class FirmwareRecord(BaseModel):
    id: str
    version: str
    model: str
    hw_revision: Optional[str]
    sha256: str
    signature_alg: Optional[str] = None
    signature_b64: Optional[str] = None
    pubkey_id: Optional[str] = None
    size_bytes: int
    content_type: Optional[str]
    uri: str
    created_at: datetime
    created_by: str
    release_notes: Optional[str] = None
    sbom_uri: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)


class RolloutRecord(BaseModel):
    id: str
    firmware_id: str
    status: constr(regex="^(draft|scheduled|in_progress|paused|completed|failed)$") = "draft"
    canary_percent: int = 0
    target_percent: int = 100
    sites: List[str] = Field(default_factory=list)
    start_after: Optional[datetime] = None
    maintenance_windows: List[str] = Field(default_factory=list)  # cron or RFC3339 ranges
    constraints: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    created_by: str


class FirmwareRepo:
    # Firmware
    async def get_by_sha_or_idem(self, sha256: str, idem_key: Optional[str]) -> Optional[FirmwareRecord]: ...
    async def insert_firmware(self, rec: FirmwareRecord, idem_key: Optional[str]) -> FirmwareRecord: ...
    async def get_firmware(self, fid: str) -> Optional[FirmwareRecord]: ...
    async def list_firmware(self, model: Optional[str], q: Optional[str], offset: int, limit: int) -> Tuple[List[FirmwareRecord], Optional[int]]: ...
    # SBOM
    async def attach_sbom(self, fid: str, uri: str) -> None: ...
    # Rollout
    async def create_rollout(self, r: RolloutRecord) -> RolloutRecord: ...
    async def get_rollout(self, fid: str, rid: str) -> Optional[RolloutRecord]: ...


def get_repo(request: Request) -> FirmwareRepo:
    repo = getattr(request.app.state, "firmware_repo", None)
    if repo is None:
        raise HTTPException(status_code=500, detail="Repository not configured")
    return repo


def get_storage(request: Request) -> StorageBackend:
    st = getattr(request.app.state, "storage", None)
    if st is None:
        # Safe default to local FS for dev
        st = LocalFSStorage()
    return st


def get_policy(request: Request) -> OPAClient:
    pc = getattr(request.app.state, "policy_client", None)
    if pc is None:
        raise HTTPException(status_code=500, detail="Policy client not configured")
    return pc


# ============================
# Pydantic I/O models
# ============================

class FirmwareMeta(BaseModel):
    version: str = Field(..., description="SemVer version, e.g., 1.2.3")
    model: str = Field(..., description="Device model identifier")
    hw_revision: Optional[str] = Field(None, description="Hardware revision")
    sha256: Optional[str] = Field(None, description="Hex SHA-256 of the artifact (optional; will be computed if omitted)")
    signature_alg: Optional[constr(regex="^(ed25519|rsa-pkcs1v15|rsa-pss)$")] = None
    signature_b64: Optional[str] = None
    pubkey_id: Optional[str] = Field(None, description="Key identifier for verification")
    release_notes: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)

    @validator("version")
    def _valid_semver(cls, v: str) -> str:
        try:
            _ = Version(v)
        except InvalidVersion as e:
            raise ValueError(f"Invalid version: {e}")
        return v

    @validator("sha256")
    def _sha_or_none(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            if len(v) != 64 or int(v, 16) < 0:
                raise ValueError
        except Exception:
            raise ValueError("sha256 must be 64 hex chars")
        return v


class FirmwareOut(FirmwareRecord):
    download_url: Optional[str] = None


class RolloutCreate(BaseModel):
    canary_percent: int = Field(5, ge=0, le=100)
    target_percent: int = Field(100, ge=1, le=100)
    sites: List[str] = Field(default_factory=list)
    start_after: Optional[datetime] = None
    maintenance_windows: List[str] = Field(default_factory=list)
    constraints: Dict[str, Any] = Field(
        default_factory=lambda: {
            "min_battery": 30,
            "min_signal_dbm": -90,
            "min_current_fw": None,
            "max_retries": 3,
        }
    )


class RolloutOut(RolloutRecord):
    pass


class CompatCheckRequest(BaseModel):
    model: str
    hw_revision: Optional[str] = None
    current_fw: Optional[str] = None
    battery: Optional[int] = Field(None, ge=0, le=100)
    signal_dbm: Optional[int] = Field(None, ge=-200, le=0)


class CompatCheckResponse(BaseModel):
    ok: bool
    reasons: List[str] = Field(default_factory=list)


# ============================
# Router
# ============================

router = APIRouter(prefix="/v1/firmware", tags=["firmware"])

# ---------- Helpers ----------

async def stream_file(file: UploadFile, chunk_size: int = 1024 * 1024) -> AsyncIterator[bytes]:
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        yield chunk

async def compute_sha256(file: UploadFile) -> Tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    await file.seek(0)
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        hasher.update(chunk)
    await file.seek(0)
    return hasher.hexdigest(), size

def _require_roles(p: Principal, needed: List[str]) -> None:
    if not any(r in p.roles for r in needed):
        raise HTTPException(status_code=403, detail=f"Required roles: {','.join(needed)}")

def _b64_to_bytes(b64: str) -> bytes:
    return base64.b64decode(b64.encode("ascii"), validate=True)

def _verify_signature_ed25519(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        # Requires 'cryptography' library
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
        return True
    except Exception:
        return False

# ---------- Endpoints ----------

@router.post(
    "",
    response_model=FirmwareOut,
    status_code=status.HTTP_201_CREATED,
    summary="Загрузка прошивки (идемпотентная, с проверкой подписи и SHA-256)",
)
async def upload_firmware(
    request: Request,
    repo: FirmwareRepo = Depends(get_repo),
    storage: StorageBackend = Depends(get_storage),
    principal: Principal = Depends(get_principal),
    metadata_json: str = Form(..., description="JSON с метаданными FirmwareMeta"),
    file: UploadFile = File(..., description="Бинарник прошивки"),
    sbom: Optional[UploadFile] = File(None, description="SBOM файл, опционально"),
    idempotency_key: Optional[str] = Header(None, convert_underscores=False),
):
    _require_roles(principal, ["ot-maintainer"])

    try:
        meta = FirmwareMeta.parse_obj(json.loads(metadata_json))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid metadata: {e}")

    # Compute checksum/size
    sha256_calc, size = await compute_sha256(file)
    if meta.sha256 and meta.sha256.lower() != sha256_calc.lower():
        raise HTTPException(status_code=422, detail="Checksum mismatch: provided sha256 does not match uploaded file")
    meta.sha256 = sha256_calc

    # Idempotency: return existing if same sha or same Idempotency-Key known
    existing = await repo.get_by_sha_or_idem(meta.sha256, idempotency_key)
    if existing:
        # Optionally provide presigned URL
        presigned = None
        try:
            presigned = await storage.presign_get(key=f"{existing.id}/artifact")
        except Exception:
            presigned = None
        return FirmwareOut(**existing.dict(), download_url=presigned)

    # Signature verification (optional but recommended)
    if meta.signature_alg and meta.signature_b64 and meta.pubkey_id:
        # Retrieve public key by id from app state or repository of keys
        key_store: Dict[str, str] = getattr(request.app.state, "pubkeys", {})
        pub_hex = key_store.get(meta.pubkey_id)
        if not pub_hex:
            raise HTTPException(status_code=400, detail="Unknown pubkey_id")
        pub_bytes = bytes.fromhex(pub_hex)
        sig_bytes = _b64_to_bytes(meta.signature_b64)

        # Verify over the digest (or file bytes). We verify over sha256 to avoid loading file twice.
        msg = bytes.fromhex(meta.sha256)
        ok = False
        if meta.signature_alg == "ed25519":
            ok = _verify_signature_ed25519(pub_bytes, msg, sig_bytes)
        else:
            raise HTTPException(status_code=400, detail="Unsupported signature_alg")
        if not ok:
            raise HTTPException(status_code=400, detail="Signature verification failed")

    # Store artifact
    key = f"{sha256_calc[:2]}/{sha256_calc[2:4]}/{sha256_calc}/artifact"
    uri = await storage.put_object(key=key, stream=stream_file(file), size=size, content_type=file.content_type)

    # Store SBOM if provided
    sbom_uri = None
    if sbom is not None:
        sb_key = f"{sha256_calc[:2]}/{sha256_calc[2:4]}/{sha256_calc}/sbom"
        sbom_uri = await storage.put_object(key=sb_key, stream=stream_file(sbom), size=None, content_type=sbom.content_type)

    rec = FirmwareRecord(
        id=sha256_calc,  # deterministic id by sha256
        version=meta.version,
        model=meta.model,
        hw_revision=meta.hw_revision,
        sha256=meta.sha256,
        signature_alg=meta.signature_alg,
        signature_b64=meta.signature_b64,
        pubkey_id=meta.pubkey_id,
        size_bytes=size,
        content_type=file.content_type,
        uri=uri,
        created_at=datetime.now(timezone.utc),
        created_by=principal.subject,
        release_notes=meta.release_notes,
        sbom_uri=sbom_uri,
        labels=meta.labels or {},
    )

    saved = await repo.insert_firmware(rec, idempotency_key)

    # Pre-sign download URL
    download = None
    try:
        download = await storage.presign_get(key=f"{rec.id}/artifact")
    except Exception:
        download = None

    return FirmwareOut(**saved.dict(), download_url=download)


@router.get(
    "",
    response_model=List[FirmwareOut],
    summary="Список прошивок с фильтрами и пагинацией",
)
async def list_firmware(
    request: Request,
    repo: FirmwareRepo = Depends(get_repo),
    model: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="substring по версии/меткам"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    offset = (page - 1) * page_size
    rows, total = await repo.list_firmware(model=model, q=q, offset=offset, limit=page_size)

    # Pre-sign in batch if storage supports it (best-effort)
    storage = get_storage(request)
    out: List[FirmwareOut] = []
    for r in rows:
        try:
            url = await storage.presign_get(key=f"{r.id}/artifact")
        except Exception:
            url = None
        out.append(FirmwareOut(**r.dict(), download_url=url))
    # X-Total-Count header for clients
    headers = {}
    if total is not None:
        headers["X-Total-Count"] = str(total)
    return JSONResponse([o.dict() for o in out], headers=headers)


@router.get(
    "/{fid}",
    response_model=FirmwareOut,
    summary="Получить прошивку по id (sha256)",
)
async def get_firmware(
    fid: constr(min_length=64, max_length=64),
    repo: FirmwareRepo = Depends(get_repo),
    request: Request = None,
):
    r = await repo.get_firmware(fid)
    if not r:
        raise HTTPException(status_code=404, detail="Firmware not found")
    storage = get_storage(request)
    try:
        url = await storage.presign_get(key=f"{r.id}/artifact")
    except Exception:
        url = None
    return FirmwareOut(**r.dict(), download_url=url)


@router.post(
    "/{fid}/rollouts",
    response_model=RolloutOut,
    status_code=status.HTTP_201_CREATED,
    summary="Создать rollout-план (canary/проценты/окна/constraints) с проверкой политики OPA",
)
async def create_rollout(
    fid: constr(min_length=64, max_length=64),
    body: RolloutCreate,
    repo: FirmwareRepo = Depends(get_repo),
    policy: OPAClient = Depends(get_policy),
    principal: Principal = Depends(get_principal),
    request: Request = None,
):
    _require_roles(principal, ["ot-maintainer"])

    fw = await repo.get_firmware(fid)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware not found")

    # Evaluate policy (command_guard.rego expects 'firmware_update' high impact)
    opa_input = {
        "authn": {"subject": principal.subject, "mfa": True},
        "authz": {"roles": principal.roles, "ticket": {"status": "Approved"}},
        "env": {"environment": os.getenv("PIC_ENV", "prod"), "time": datetime.now(timezone.utc).isoformat()},
        "request": {
            "command": "firmware_update",
            "impact_level": "high",
            "device": {"class": fw.model},
        },
        "context": {"maintenance_window": {"active": bool(body.maintenance_windows)}},
    }
    decision = await policy.evaluate(request, "/policy/command/decide", opa_input)
    if not decision.get("allow", False):
        reasons = decision.get("deny_reasons") or decision.get("deny_soft") or decision.get("deny_hard") or ["policy denied"]
        raise HTTPException(status_code=403, detail={"message": "Policy denied firmware rollout", "reasons": reasons})

    rid = hashlib.sha1(f"{fid}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()
    rec = RolloutRecord(
        id=rid,
        firmware_id=fid,
        status="scheduled" if body.start_after else "draft",
        canary_percent=body.canary_percent,
        target_percent=body.target_percent,
        sites=body.sites,
        start_after=body.start_after,
        maintenance_windows=body.maintenance_windows,
        constraints=body.constraints,
        created_at=datetime.now(timezone.utc),
        created_by=principal.subject,
    )
    saved = await repo.create_rollout(rec)
    return RolloutOut(**saved.dict())


@router.get(
    "/{fid}/rollouts/{rid}",
    response_model=RolloutOut,
    summary="Статус rollout-плана",
)
async def get_rollout(
    fid: constr(min_length=64, max_length=64),
    rid: constr(min_length=40, max_length=40),
    repo: FirmwareRepo = Depends(get_repo),
):
    r = await repo.get_rollout(fid, rid)
    if not r:
        raise HTTPException(status_code=404, detail="Rollout not found")
    return RolloutOut(**r.dict())


@router.post(
    "/compat/check",
    response_model=CompatCheckResponse,
    summary="Проверка совместимости устройства с прошивкой и ограничениями",
)
async def compat_check(
    body: CompatCheckRequest,
    target_fw: str = Query(..., description="Целевая версия прошивки"),
):
    reasons: List[str] = []
    ok = True
    try:
        target = Version(target_fw)
    except InvalidVersion as e:
        raise HTTPException(status_code=422, detail=f"Invalid target_fw: {e}")

    # Basic semantic checks
    if body.current_fw:
        try:
            cur = Version(body.current_fw)
            if cur >= target:
                ok = False
                reasons.append("current firmware is equal or newer than target")
        except InvalidVersion:
            reasons.append("current_fw is not a valid version")

    if body.battery is not None and body.battery < 30:
        ok = False
        reasons.append("battery below 30%")

    if body.signal_dbm is not None and body.signal_dbm < -100:
        ok = False
        reasons.append("radio signal too weak (< -100 dBm)")

    # Model/hw filtering can be extended via external catalog
    if not body.model:
        ok = False
        reasons.append("device model is required")

    return CompatCheckResponse(ok=ok, reasons=reasons)


# ================
# Error handlers
# ================

@router.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


# ================
# OpenTelemetry (optional; no-op if not installed)
# ================

def _otel_span(name: str):
    def decorator(fn):
        async def wrapper(*args, **kwargs):
            try:
                from opentelemetry import trace
                tracer = trace.get_tracer("pic.api.firmware")
                with tracer.start_as_current_span(name) as span:
                    try:
                        return await fn(*args, **kwargs)
                    finally:
                        pass
            except Exception:
                # OTEL not installed or span creation failed; proceed silently
                return await fn(*args, **kwargs)
        return wrapper
    return decorator

# Optionally wrap heavy endpoints
upload_firmware.__wrapped__ = upload_firmware  # for linters
upload_firmware = _otel_span("firmware.upload")(upload_firmware)
create_rollout.__wrapped__ = create_rollout
create_rollout = _otel_span("firmware.rollout.create")(create_rollout)
