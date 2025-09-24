# oblivionvault-core/oblivionvault/requests/intake.py
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Protocol, List
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator

# ------------------------------------------------------------------------------
# Observability-safe logger (structlog if present)
# ------------------------------------------------------------------------------
try:
    import structlog  # type: ignore
    log = structlog.get_logger(__name__)
except Exception:  # pragma: no cover
    log = logging.getLogger(__name__)
    if not log.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
        handler.setFormatter(formatter)
        log.addHandler(handler)
    log.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Domain enums and constants
# ------------------------------------------------------------------------------

class RequestKind(str, Enum):
    access = "access"
    data_export = "data_export"
    policy_change = "policy_change"
    generic = "generic"


class RequestPriority(str, Enum):
    low = "low"
    normal = "normal"
    high = "high"
    urgent = "urgent"


class RequestStatus(str, Enum):
    queued = "queued"
    processing = "processing"
    completed = "completed"
    failed = "failed"
    canceled = "canceled"


DEFAULT_IDEMPOTENCY_TTL_SEC = int(os.getenv("OV_IDEMPOTENCY_TTL_SEC", "86400"))  # 24h
MAX_PAYLOAD_BYTES = int(os.getenv("OV_MAX_PAYLOAD_BYTES", "262144"))  # 256 KiB
MAX_METADATA_BYTES = int(os.getenv("OV_MAX_METADATA_BYTES", "65536"))  # 64 KiB
REDACTED = "***"

# ------------------------------------------------------------------------------
# Utility helpers
# ------------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_hash_hex(value: Any) -> str:
    data = canonical_json(value).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def derive_etag(version: int) -> str:
    return f'W/"{version}"'


def redact_secrets(obj: Any) -> Any:
    """
    Redacts likely secret fields for logging: keys containing token, secret, password, key.
    Works recursively for dicts and lists.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(s in lk for s in ("token", "secret", "password", "passwd", "api_key", "apikey", "private_key")):
                out[k] = REDACTED
            else:
                out[k] = redact_secrets(v)
        return out
    if isinstance(obj, list):
        return [redact_secrets(x) for x in obj]
    return obj


# ------------------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------------------

class RequesterRef(BaseModel):
    subject: str = Field(..., min_length=1, max_length=256, description="Requester identifier")
    org_id: Optional[str] = Field(None, max_length=128)


class IntakeRequestIn(BaseModel):
    idempotency_key: Optional[str] = Field(None, max_length=128)
    kind: RequestKind = Field(..., description="Type of the request")
    priority: RequestPriority = Field(default=RequestPriority.normal)
    requester: RequesterRef
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("payload")
    def _payload_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if len(canonical_json(v).encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload too large")
        return v

    @validator("metadata")
    def _metadata_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if len(canonical_json(v).encode("utf-8")) > MAX_METADATA_BYTES:
            raise ValueError("metadata too large")
        return v


class RequestRecord(BaseModel):
    id: UUID
    kind: RequestKind
    priority: RequestPriority
    requester: RequesterRef
    payload: Dict[str, Any]
    metadata: Dict[str, Any]
    status: RequestStatus = Field(default=RequestStatus.queued)
    version: int = Field(default=1, ge=1)
    etag: str = Field(default='W/"1"')
    idempotency_key: str
    idempotency_expires_at: datetime
    dedupe_hash: str
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ------------------------------------------------------------------------------
# Error types (domain-level, HTTP-bindings делаются на уровне API)
# ------------------------------------------------------------------------------

class ConflictError(Exception):
    pass


class NotFoundError(Exception):
    pass


class PreconditionFailedError(Exception):
    pass


# ------------------------------------------------------------------------------
# RateLimiter and Storage protocols for DI
# ------------------------------------------------------------------------------

class RateLimiter(Protocol):
    async def check(self, key: str) -> None:
        """
        Should raise Exception to refuse the request if limit is exceeded.
        """


class NoopRateLimiter:
    async def check(self, key: str) -> None:  # pragma: no cover
        # Intentionally allow everything; log once
        return


class StorageBackend(Protocol):
    async def create(self, rec: RequestRecord) -> RequestRecord:
        ...
    async def get(self, request_id: UUID) -> RequestRecord:
        ...
    async def get_by_idempotency(self, idem_key: str) -> Optional[RequestRecord]:
        ...
    async def compare_and_set(self, rec: RequestRecord, expected_version: int) -> RequestRecord:
        ...
    async def cleanup_idempotency(self, now: datetime) -> int:
        ...


# ------------------------------------------------------------------------------
# In-memory storage fallback (thread-safe for asyncio with a single lock)
# ------------------------------------------------------------------------------

class InMemoryStorage(StorageBackend):
    def __init__(self) -> None:
        self._by_id: Dict[UUID, RequestRecord] = {}
        self._by_idem: Dict[str, UUID] = {}
        self._lock = asyncio.Lock()

    async def create(self, rec: RequestRecord) -> RequestRecord:
        async with self._lock:
            if rec.id in self._by_id:
                raise ConflictError("duplicate id")
            if rec.idempotency_key in self._by_idem:
                # Protect against concurrent submits racing
                existing = self._by_id[self._by_idem[rec.idempotency_key]]
                # If payload hashes differ, it is a true conflict
                if existing.dedupe_hash != rec.dedupe_hash:
                    raise ConflictError("idempotency_key collision with different payload")
                return existing
            self._by_id[rec.id] = rec
            self._by_idem[rec.idempotency_key] = rec.id
            return rec

    async def get(self, request_id: UUID) -> RequestRecord:
        async with self._lock:
            rec = self._by_id.get(request_id)
            if not rec:
                raise NotFoundError("request not found")
            return rec

    async def get_by_idempotency(self, idem_key: str) -> Optional[RequestRecord]:
        async with self._lock:
            rid = self._by_idem.get(idem_key)
            return self._by_id.get(rid) if rid else None

    async def compare_and_set(self, rec: RequestRecord, expected_version: int) -> RequestRecord:
        async with self._lock:
            current = self._by_id.get(rec.id)
            if not current:
                raise NotFoundError("request not found")
            if current.version != expected_version:
                raise PreconditionFailedError("version mismatch")
            # update record
            rec.version = expected_version + 1
            rec.etag = derive_etag(rec.version)
            rec.updated_at = utcnow()
            self._by_id[rec.id] = rec
            # keep idem index as is
            return rec

    async def cleanup_idempotency(self, now: datetime) -> int:
        async with self._lock:
            to_delete: List[str] = []
            for idem, rid in self._by_idem.items():
                rec = self._by_id.get(rid)
                if not rec:
                    to_delete.append(idem)
                    continue
                if rec.idempotency_expires_at <= now:
                    to_delete.append(idem)
            for idem in to_delete:
                self._by_idem.pop(idem, None)
            return len(to_delete)


# ------------------------------------------------------------------------------
# Intake Service
# ------------------------------------------------------------------------------

class IntakeService:
    """
    Industrial-grade intake service with:
      - Idempotency with TTL and payload collision protection
      - Optimistic concurrency (version, ETag)
      - Deterministic dedupe hash for stable equivalence
      - Status machine: queued -> processing -> completed/failed; queued -> canceled
      - Pluggable storage and rate-limiter
      - Secret-safe logging
    """

    def __init__(
        self,
        storage: Optional[StorageBackend] = None,
        rate_limiter: Optional[RateLimiter] = None,
        idempotency_ttl_sec: int = DEFAULT_IDEMPOTENCY_TTL_SEC,
    ) -> None:
        self._storage = storage or InMemoryStorage()
        self._rate = rate_limiter or NoopRateLimiter()
        self._idem_ttl = idempotency_ttl_sec

    # ---------------------------- public API ----------------------------------

    async def submit(self, req: IntakeRequestIn) -> RequestRecord:
        """
        Submit a new request. If idempotency_key already exists and payload matches,
        returns the existing record. If payload differs, raises ConflictError.
        """
        # Rate limit by requester and kind
        await self._rate.check(f"intake:{req.requester.subject}:{req.kind.value}")

        dedupe = stable_hash_hex({"kind": req.kind.value, "requester": req.requester.dict(), "payload": req.payload})
        idem = req.idempotency_key or self._default_idem(req, dedupe)

        # Pre-existing idempotent record short-circuit
        existing = await self._storage.get_by_idempotency(idem)
        if existing:
            if existing.dedupe_hash != dedupe:
                raise ConflictError("idempotency_key collision with different payload")
            log.info(
                "intake.submit.idempotent_hit",
                idem=idem,
                request_id=str(existing.id),
                status=existing.status.value,
            )
            return existing

        now = utcnow()
        rec = RequestRecord(
            id=uuid4(),
            kind=req.kind,
            priority=req.priority,
            requester=req.requester,
            payload=req.payload,
            metadata=req.metadata,
            status=RequestStatus.queued,
            version=1,
            etag=derive_etag(1),
            idempotency_key=idem,
            idempotency_expires_at=now + timedelta(seconds=self._idem_ttl),
            dedupe_hash=dedupe,
            created_at=now,
            updated_at=now,
        )

        created = await self._storage.create(rec)
        log.info(
            "intake.submit.created",
            request_id=str(created.id),
            kind=created.kind.value,
            priority=created.priority.value,
            idem=idem,
            requester=redact_secrets(created.requester.dict()),
            payload_summary={"keys": list(created.payload.keys()), "hash": created.dedupe_hash[:12]},
        )
        return created

    async def get(self, request_id: UUID) -> RequestRecord:
        rec = await self._storage.get(request_id)
        return rec

    async def get_by_idempotency(self, idem_key: str) -> Optional[RequestRecord]:
        return await self._storage.get_by_idempotency(idem_key)

    async def cancel(self, request_id: UUID, reason: Optional[str], expected_version: Optional[int] = None) -> RequestRecord:
        rec = await self._storage.get(request_id)
        if rec.status in (RequestStatus.completed, RequestStatus.failed, RequestStatus.canceled):
            # idempotent cancel
            return rec
        rec.status = RequestStatus.canceled
        rec.error = reason or "canceled"
        updated = await self._storage.compare_and_set(rec, expected_version or rec.version)
        log.info("intake.cancel", request_id=str(request_id), reason=reason)
        return updated

    async def mark_processing(self, request_id: UUID, expected_version: Optional[int] = None) -> RequestRecord:
        rec = await self._storage.get(request_id)
        if rec.status not in (RequestStatus.queued,):
            return rec
        rec.status = RequestStatus.processing
        updated = await self._storage.compare_and_set(rec, expected_version or rec.version)
        log.info("intake.processing", request_id=str(request_id))
        return updated

    async def mark_completed(self, request_id: UUID, result_metadata: Optional[Dict[str, Any]] = None,
                             expected_version: Optional[int] = None) -> RequestRecord:
        rec = await self._storage.get(request_id)
        if rec.status in (RequestStatus.completed, RequestStatus.canceled):
            return rec
        if rec.status == RequestStatus.failed:
            # allow eventual success override only via fresh processing
            raise ConflictError("cannot complete a failed request without reprocessing")
        rec.status = RequestStatus.completed
        rec.completed_at = utcnow()
        rec.metadata = {**rec.metadata, **(result_metadata or {})}
        updated = await self._storage.compare_and_set(rec, expected_version or rec.version)
        log.info("intake.completed", request_id=str(request_id))
        return updated

    async def mark_failed(self, request_id: UUID, error: str, expected_version: Optional[int] = None) -> RequestRecord:
        rec = await self._storage.get(request_id)
        if rec.status in (RequestStatus.completed, RequestStatus.canceled):
            return rec
        rec.status = RequestStatus.failed
        rec.error = error[:2048]
        updated = await self._storage.compare_and_set(rec, expected_version or rec.version)
        log.info("intake.failed", request_id=str(request_id), error=error[:256])
        return updated

    async def maintenance_cleanup(self) -> int:
        """
        Should be called periodically by scheduler to clean expired idempotency keys.
        """
        removed = await self._storage.cleanup_idempotency(utcnow())
        if removed:
            log.info("intake.cleanup", removed=removed)
        return removed

    # ---------------------------- internals -----------------------------------

    def _default_idem(self, req: IntakeRequestIn, dedupe_hash: str) -> str:
        """
        Builds deterministic idempotency key: requester:kind:sha256(...)
        """
        subj = req.requester.subject.replace(":", "_")
        return f"{subj}:{req.kind.value}:{dedupe_hash[:24]}"
