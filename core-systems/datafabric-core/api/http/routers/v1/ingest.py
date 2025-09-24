# datafabric-core/api/http/routers/v1/ingest.py
# Industrial-grade Ingest API (v1) for DataFabric Core
# Features:
# - Ingest sessions lifecycle (create, upload chunk, complete, status, abort)
# - Streaming chunk uploads with Content-Range validation
# - Idempotent session creation via Idempotency-Key
# - Size limits, media-type validation, SHA-256 checksums
# - Atomic finalize with rename, final checksum verification
# - Storage abstraction with robust local filesystem fallback
# - Unified error taxonomy via errors.py (RFC 7807)

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

from fastapi import (
    APIRouter,
    Depends,
    Header,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ConfigDict, constr

try:
    # Prefer project error helpers
    from api.http.errors import (
        bad_request,
        conflict,
        not_found,
        too_many_requests,
        unprocessable,
        service_unavailable,
    )
except Exception:
    from fastapi import HTTPException
    def bad_request(msg, **_): raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=msg)  # type: ignore
    def conflict(msg="Conflict", **_): raise HTTPException(status.HTTP_409_CONFLICT, detail=msg)  # type: ignore
    def not_found(**_): raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not Found")  # type: ignore
    def too_many_requests(): raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too Many Requests")  # type: ignore
    def unprocessable(msg, **_): raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)  # type: ignore
    def service_unavailable(msg="Service Unavailable", **_): raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=msg)  # type: ignore

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])

# ------------------------------------------------------------------------------
# Settings (env-driven with sane defaults; can be moved to global settings)
# ------------------------------------------------------------------------------

DFC_ENV = os.getenv("DFC_ENVIRONMENT", "production")
INGEST_ROOT = Path(os.getenv("DFC_INGEST_ROOT", tempfile.gettempdir())) / "datafabric_ingest"
FINAL_ROOT = Path(os.getenv("DFC_INGEST_FINAL_ROOT", str(INGEST_ROOT / "final")))
MAX_SIZE = int(os.getenv("DFC_INGEST_MAX_SIZE", str(50 * 1024 * 1024 * 1024)))  # 50 GiB default
MAX_PART = int(os.getenv("DFC_INGEST_MAX_PART", str(64 * 1024 * 1024)))          # 64 MiB per upload chunk (advisory)
ALLOWED_MEDIA = {m.strip().lower() for m in os.getenv("DFC_INGEST_MEDIA", "application/octet-stream").split(",")}
SESSION_TTL_SEC = int(os.getenv("DFC_INGEST_SESSION_TTL_SEC", "86400"))          # 24h
CONCURRENCY_LIMIT = int(os.getenv("DFC_INGEST_CONCURRENCY", "8"))

INGEST_ROOT.mkdir(parents=True, exist_ok=True)
FINAL_ROOT.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class IngestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: constr(min_length=1, max_length=512)
    size: int = Field(..., ge=1, le=MAX_SIZE)
    media_type: constr(min_length=1, max_length=100) = "application/octet-stream"
    dataset_id: constr(min_length=1, max_length=128) | None = None
    expected_sha256: constr(min_length=64, max_length=64) | None = None  # optional client-provided checksum

class IngestSession(BaseModel):
    id: str
    filename: str
    media_type: str
    size: int
    received: int
    sha256_so_far: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    dataset_id: str | None
    status: constr(pattern="^(open|finalizing|completed|aborted)$")
    next_offset: int

class IngestStatusResponse(BaseModel):
    session: IngestSession

class IngestCompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Optional explicit checksum for verification at finalize (overrides initial expected if provided)
    sha256: constr(min_length=64, max_length=64) | None = None

class IngestArtifact(BaseModel):
    session_id: str
    artifact_id: str
    path: str
    size: int
    media_type: str
    sha256: str
    filename: str
    dataset_id: str | None
    created_at: datetime

class IngestCompleteResponse(BaseModel):
    artifact: IngestArtifact

# ------------------------------------------------------------------------------
# Storage abstraction
# ------------------------------------------------------------------------------

class StorageAdapter:
    async def open_temp(self, session_id: str) -> Path: ...
    async def append(self, temp_path: Path, data: bytes, offset: int) -> None: ...
    async def flush(self, temp_path: Path) -> None: ...
    async def finalize(self, temp_path: Path, final_name: str) -> Path: ...
    async def remove(self, temp_path: Path) -> None: ...

class LocalFSStorage(StorageAdapter):
    def __init__(self, tmp_root: Path, final_root: Path):
        self.tmp_root = tmp_root
        self.final_root = final_root
        self.tmp_root.mkdir(parents=True, exist_ok=True)
        self.final_root.mkdir(parents=True, exist_ok=True)

    async def open_temp(self, session_id: str) -> Path:
        path = self.tmp_root / f"{session_id}.part"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        return path

    async def append(self, temp_path: Path, data: bytes, offset: int) -> None:
        # Append at exact offset (support retries / sparse writes with seek)
        with open(temp_path, "r+b") as f:
            f.seek(offset)
            f.write(data)

    async def flush(self, temp_path: Path) -> None:
        with open(temp_path, "rb") as f:
            os.fsync(f.fileno())

    async def finalize(self, temp_path: Path, final_name: str) -> Path:
        final_path = self.final_root / final_name
        final_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic move
        shutil.move(str(temp_path), str(final_path))
        return final_path

    async def remove(self, temp_path: Path) -> None:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass

# ------------------------------------------------------------------------------
# Session repository (in-memory with file-backed temp objects)
# ------------------------------------------------------------------------------

@dataclass
class _SessionState:
    id: str
    filename: str
    media_type: str
    size: int
    received: int = 0
    sha256: hashlib._hashlib.HASH = field(default_factory=lambda: hashlib.sha256())
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + SESSION_TTL_SEC)
    status: str = "open"  # open|finalizing|completed|aborted
    dataset_id: Optional[str] = None
    expected_sha256: Optional[str] = None
    temp_path: Optional[Path] = None

class IngestRepository:
    def __init__(self, storage: StorageAdapter):
        self._storage = storage
        self._lock = asyncio.Lock()
        self._sessions: Dict[str, _SessionState] = {}
        self._idem: Dict[str, str] = {}  # Idempotency-Key -> session_id
        self._sem = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def create(self, req: IngestCreate, idem_key: Optional[str]) -> IngestSession:
        async with self._lock:
            if idem_key and idem_key in self._idem:
                sid = self._idem[idem_key]
                return self._as_api(self._sessions[sid])

            if req.media_type.lower() not in ALLOWED_MEDIA:
                raise unprocessable("Unsupported media type", supported=list(ALLOWED_MEDIA))
            if req.size > MAX_SIZE:
                raise bad_request("Declared size exceeds limit", limit=MAX_SIZE)

            sid = base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")
            state = _SessionState(
                id=sid,
                filename=req.filename,
                media_type=req.media_type,
                size=req.size,
                dataset_id=req.dataset_id,
                expected_sha256=req.expected_sha256,
            )
            state.temp_path = await self._storage.open_temp(sid)
            self._sessions[sid] = state
            if idem_key:
                self._idem[idem_key] = sid
            return self._as_api(state)

    async def status(self, session_id: str) -> IngestSession:
        async with self._lock:
            st = self._sessions.get(session_id)
            if not st:
                raise not_found(resource="ingest_session", id_=session_id)
            return self._as_api(st)

    async def append_chunk(
        self,
        session_id: str,
        content: bytes,
        content_range: Tuple[int, int, int],  # (start, end_inclusive, total)
        chunk_sha256: Optional[str],
    ) -> IngestSession:
        start, end, total = content_range
        if end < start:
            raise bad_request("Invalid Content-Range", reason="end_before_start")
        length = end - start + 1
        if length != len(content):
            raise bad_request("Content-Range length mismatch", reason="range_len_mismatch")
        if total > MAX_SIZE:
            raise bad_request("Declared total exceeds limit", limit=MAX_SIZE)

        async with self._sem:  # throttle concurrent writes
            async with self._lock:
                st = self._sessions.get(session_id)
                if not st:
                    raise not_found(resource="ingest_session", id_=session_id)
                if st.status != "open":
                    raise conflict("Session is not open", resource="ingest_session", id=session_id)
                if total != st.size:
                    raise bad_request("Total size mismatch with session", reason="total_mismatch")
                if time.time() > st.expires_at:
                    raise conflict("Session expired", resource="ingest_session", id=session_id)
                # Accept retries / out-of-order limited: only allow start == st.received
                if start != st.received:
                    # If retrying last written window, allow identical overlap
                    if not (start < st.received and end < st.received):
                        raise bad_request("Invalid offset", reason="non_contiguous")
                # Optional per-part checksum
                if chunk_sha256:
                    calc = hashlib.sha256(content).hexdigest()
                    if calc != chunk_sha256.lower():
                        raise bad_request("Chunk checksum mismatch", reason="sha256_mismatch")

                # Append and update
                await self._storage.append(st.temp_path, content, start)  # type: ignore[arg-type]
                st.sha256.update(content)
                st.received = max(st.received, end + 1)
                st.updated_at = time.time()
                return self._as_api(st)

    async def finalize(self, session_id: str, provided_sha256: Optional[str]) -> Tuple[IngestSession, IngestArtifact]:
        async with self._lock:
            st = self._sessions.get(session_id)
            if not st:
                raise not_found(resource="ingest_session", id_=session_id)
            if st.status == "completed":
                # Idempotent finalize: return existing artifact info if already completed
                art = self._artifact_from_final(st)
                return self._as_api(st), art
            if st.status != "open":
                raise conflict("Session not open for finalize", resource="ingest_session", id=session_id)
            if st.received != st.size:
                raise bad_request("Not all bytes received", reason="incomplete_upload")
            st.status = "finalizing"

        # Flush and compute checksum (already incremental, but ensure persistence)
        await self._storage.flush(st.temp_path)  # type: ignore

        async with self._lock:
            # Final checksum
            checksum = st.sha256.hexdigest()
            expected = provided_sha256 or st.expected_sha256
            if expected and checksum.lower() != expected.lower():
                st.status = "open"
                raise bad_request("Final checksum mismatch", reason="sha256_mismatch")

            # Atomic move
            final_name = f"{st.id}__{_safe_name(st.filename)}"
            final_path = await self._storage.finalize(st.temp_path, final_name)  # type: ignore
            st.status = "completed"
            st.updated_at = time.time()

            art = IngestArtifact(
                session_id=st.id,
                artifact_id=st.id,
                path=str(final_path),
                size=st.size,
                media_type=st.media_type,
                sha256=checksum,
                filename=st.filename,
                dataset_id=st.dataset_id,
                created_at=_utc_now(),
            )
            return self._as_api(st), art

    async def abort(self, session_id: str) -> None:
        async with self._lock:
            st = self._sessions.get(session_id)
            if not st:
                raise not_found(resource="ingest_session", id_=session_id)
            if st.status in ("completed", "aborted"):
                return
            st.status = "aborted"
            st.updated_at = time.time()
            if st.temp_path:
                await self._storage.remove(st.temp_path)

    def _as_api(self, st: _SessionState) -> IngestSession:
        return IngestSession(
            id=st.id,
            filename=st.filename,
            media_type=st.media_type,
            size=st.size,
            received=st.received,
            sha256_so_far=st.sha256.hexdigest(),
            created_at=_dt(st.created_at),
            updated_at=_dt(st.updated_at),
            expires_at=_dt(st.expires_at),
            dataset_id=st.dataset_id,
            status=st.status,
            next_offset=st.received,
        )

    def _artifact_from_final(self, st: _SessionState) -> IngestArtifact:
        # Derive final path by convention
        final_name = f"{st.id}__{_safe_name(st.filename)}"
        final_path = FINAL_ROOT / final_name
        return IngestArtifact(
            session_id=st.id,
            artifact_id=st.id,
            path=str(final_path),
            size=st.size,
            media_type=st.media_type,
            sha256=st.sha256.hexdigest(),
            filename=st.filename,
            dataset_id=st.dataset_id,
            created_at=_utc_now(),
        )

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)

def _safe_name(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in (".", "_", "-", "+") else "_" for ch in name)
    return safe[:200] or "file"

def _parse_content_range(header: str | None, total_expected: int) -> Tuple[int, int, int]:
    # Format: "bytes start-end/total"
    if not header:
        raise bad_request("Missing Content-Range", reason="missing_header")
    try:
        unit, rest = header.split(" ", 1)
        if unit.lower() != "bytes":
            raise ValueError("bad unit")
        range_part, total_part = rest.split("/", 1)
        start_s, end_s = range_part.split("-", 1)
        start = int(start_s)
        end = int(end_s)
        total = int(total_part)
    except Exception:
        raise bad_request("Malformed Content-Range", reason="malformed")
    if total != total_expected:
        raise bad_request("Total mismatch", reason="total_mismatch")
    if start < 0 or end < 0 or total <= 0:
        raise bad_request("Invalid range values", reason="invalid_values")
    if end < start:
        raise bad_request("Invalid range order", reason="invalid_order")
    if (end - start + 1) > MAX_PART:
        # advisory guardrail; clients should split parts smaller than MAX_PART
        pass
    return start, end, total

# ------------------------------------------------------------------------------
# DI
# ------------------------------------------------------------------------------

async def get_repo(request: Request) -> IngestRepository:
    repo = getattr(request.app.state, "ingest_repo", None)
    if repo is None:
        storage = LocalFSStorage(INGEST_ROOT, FINAL_ROOT)
        repo = IngestRepository(storage=storage)
        request.app.state.ingest_repo = repo
    return repo

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

class CreateSessionResponse(BaseModel):
    session: IngestSession

@router.post(
    "/sessions",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateSessionResponse,
    summary="Create ingest session (idempotent by Idempotency-Key)",
)
async def create_session(
    payload: IngestCreate,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    repo: IngestRepository = Depends(get_repo),
):
    if idempotency_key is not None and (len(idempotency_key) == 0 or len(idempotency_key) > 256):
        raise bad_request("Invalid Idempotency-Key", reason="invalid_idem_key")
    session = await repo.create(payload, idem_key=idempotency_key)
    return CreateSessionResponse(session=session)

@router.get(
    "/sessions/{session_id}",
    response_model=IngestStatusResponse,
    summary="Get ingest session status",
)
async def get_session_status(
    session_id: str,
    repo: IngestRepository = Depends(get_repo),
):
    session = await repo.status(session_id)
    return IngestStatusResponse(session=session)

@router.put(
    "/sessions/{session_id}/parts",
    response_model=IngestStatusResponse,
    summary="Upload a chunk with Content-Range",
)
async def upload_part(
    session_id: str,
    request: Request,
    file: UploadFile,  # the chunk payload
    content_range: str | None = Header(default=None, alias="Content-Range"),
    chunk_sha256: str | None = Header(default=None, alias="X-Chunk-SHA256"),
    repo: IngestRepository = Depends(get_repo),
):
    # Media type validation (ingest pipeline consumes binary octet-stream chunks)
    media = (file.content_type or "").lower()
    if media and media not in ("application/octet-stream",):
        raise unprocessable("Unsupported chunk media type", supported=["application/octet-stream"])

    # Read bytes safely (starlette already keeps to memory/disk depending on size)
    content = await file.read()
    if not content:
        raise bad_request("Empty chunk", reason="empty_chunk")

    # Validate header and total from session
    st = await repo.status(session_id)
    start, end, total = _parse_content_range(content_range, st.size)
    # Append chunk
    session = await repo.append_chunk(session_id, content, (start, end, total), chunk_sha256)
    # Set resumable hints
    resp = IngestStatusResponse(session=session)
    response = JSONResponse(status_code=status.HTTP_200_OK, content=resp.model_dump())
    response.headers["X-Next-Offset"] = str(session.next_offset)
    response.headers["X-Received-Bytes"] = str(session.received)
    return response

@router.post(
    "/sessions/{session_id}/complete",
    response_model=IngestCompleteResponse,
    summary="Finalize session, verify checksum, and persist artifact",
)
async def complete_session(
    session_id: str,
    payload: IngestCompleteRequest,
    repo: IngestRepository = Depends(get_repo),
):
    session, artifact = await repo.finalize(session_id, provided_sha256=payload.sha256)
    return IngestCompleteResponse(artifact=artifact)

@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Abort ingest session (cleanup temp data)",
)
async def abort_session(
    session_id: str,
    repo: IngestRepository = Depends(get_repo),
):
    await repo.abort(session_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
