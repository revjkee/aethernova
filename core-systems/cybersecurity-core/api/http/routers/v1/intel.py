from __future__ import annotations

import asyncio
import base64
import csv
import io
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any, Dict, Iterable, List, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field, HttpUrl, ValidationError, field_validator

# -----------------------------------------------------------------------------
# Logger (structured-friendly)
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Enums and Models
# -----------------------------------------------------------------------------

class IndicatorType(str, Enum):
    DOMAIN = "DOMAIN"
    URL = "URL"
    EMAIL = "EMAIL"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    CIDR = "CIDR"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    FILEPATH = "FILEPATH"
    YARA = "YARA"
    RULE_SNORT = "RULE_SNORT"
    RULE_SURICATA = "RULE_SURICATA"
    MIME = "MIME"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Tag(BaseModel):
    key: str = Field(..., min_length=1, max_length=128)
    value: Optional[str] = Field(default=None, max_length=2048)


class PageInfo(BaseModel):
    next_cursor: Optional[str] = Field(
        default=None, description="Opaque cursor for the next page."
    )
    total: int = Field(..., ge=0)


class IndicatorIn(BaseModel):
    type: IndicatorType
    value: str = Field(..., min_length=1, max_length=8192)
    description: Optional[str] = Field(default=None, max_length=8192)
    confidence: Confidence = Field(default=Confidence.MEDIUM)
    source: Optional[str] = Field(default=None, max_length=1024)
    ttl_hours: Optional[int] = Field(
        default=None, ge=1, le=365 * 24, description="Time-to-live in hours."
    )
    tags: List[Tag] = Field(default_factory=list)

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        return v.strip()


class IndicatorUpdate(BaseModel):
    description: Optional[str] = Field(default=None, max_length=8192)
    confidence: Optional[Confidence] = None
    source: Optional[str] = Field(default=None, max_length=1024)
    ttl_hours: Optional[int] = Field(default=None, ge=1, le=365 * 24)
    tags: Optional[List[Tag]] = None


class IndicatorOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    type: IndicatorType
    value: str
    description: Optional[str]
    confidence: Confidence
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    source: Optional[str]
    ttl_hours: Optional[int]
    tags: List[Tag]
    created_at: datetime
    updated_at: datetime


class IndicatorsListResponse(BaseModel):
    items: List[IndicatorOut]
    page: PageInfo


class IndicatorsBulkIn(BaseModel):
    items: List[IndicatorIn] = Field(..., min_length=1, max_length=10_000)


class FilterQuery(BaseModel):
    types: Optional[List[IndicatorType]] = None
    confidence: Optional[List[Confidence]] = None
    tag_keys: Optional[List[str]] = None
    value_contains: Optional[str] = Field(
        default=None, description="Substring search (case-insensitive)."
    )
    from_ts: Optional[datetime] = None
    to_ts: Optional[datetime] = None

    @field_validator("value_contains")
    @classmethod
    def norm_search(cls, v: Optional[str]) -> Optional[str]:
        return v.strip().lower() if v else v


# -----------------------------------------------------------------------------
# Multi-tenancy dependency
# -----------------------------------------------------------------------------

def parse_tenant_header(x_tenant_id: str = Header(..., alias="X-Tenant-ID")) -> uuid.UUID:
    try:
        return uuid.UUID(x_tenant_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid X-Tenant-ID header (must be UUID).",
        )


TenantIdDep = Annotated[uuid.UUID, Depends(parse_tenant_header)]


# -----------------------------------------------------------------------------
# Simple opaque cursor helpers
# -----------------------------------------------------------------------------

def encode_cursor(offset: int) -> str:
    payload = json.dumps({"o": offset}).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        data = base64.urlsafe_b64decode(cursor.encode("ascii"))
        obj = json.loads(data.decode("utf-8"))
        return int(obj.get("o", 0))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor.",
        )


# -----------------------------------------------------------------------------
# Repository (in-memory reference implementation)
# Replace with DB-backed adapter in production via DI.
# -----------------------------------------------------------------------------

@dataclass
class _Indicator:
    id: uuid.UUID
    tenant_id: uuid.UUID
    type: IndicatorType
    value: str
    description: Optional[str]
    confidence: Confidence
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    source: Optional[str]
    ttl_hours: Optional[int]
    tags: List[Tag]
    created_at: datetime
    updated_at: datetime


class IntelRepository:
    """Abstract repository (port)."""

    async def list(
        self,
        tenant_id: uuid.UUID,
        filters: FilterQuery,
        offset: int,
        limit: int,
    ) -> Tuple[List[IndicatorOut], int]:
        raise NotImplementedError

    async def get(self, tenant_id: uuid.UUID, indicator_id: uuid.UUID) -> Optional[IndicatorOut]:
        raise NotImplementedError

    async def upsert(self, tenant_id: uuid.UUID, payload: IndicatorIn) -> IndicatorOut:
        raise NotImplementedError

    async def bulk_upsert(self, tenant_id: uuid.UUID, items: List[IndicatorIn]) -> List[IndicatorOut]:
        raise NotImplementedError

    async def update(self, tenant_id: uuid.UUID, indicator_id: uuid.UUID, patch: IndicatorUpdate) -> IndicatorOut:
        raise NotImplementedError

    async def delete(self, tenant_id: uuid.UUID, indicator_id: uuid.UUID) -> None:
        raise NotImplementedError

    async def expire(self, now: datetime) -> int:
        """Delete expired by TTL; returns number of removed indicators."""
        raise NotImplementedError


class InMemoryIntelRepository(IntelRepository):
    """Thread-safe, process-local repository for development and tests."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # key: (tenant_id, type, value) for idempotency
        self._by_key: Dict[Tuple[uuid.UUID, IndicatorType, str], _Indicator] = {}
        # index by id
        self._by_id: Dict[uuid.UUID, _Indicator] = {}

    async def list(
        self,
        tenant_id: uuid.UUID,
        filters: FilterQuery,
        offset: int,
        limit: int,
    ) -> Tuple[List[IndicatorOut], int]:
        async with self._lock:
            rows = [
                it for it in self._by_id.values()
                if it.tenant_id == tenant_id
            ]
            # Apply filters
            if filters.types:
                types_set = set(filters.types)
                rows = [it for it in rows if it.type in types_set]
            if filters.confidence:
                conf_set = set(filters.confidence)
                rows = [it for it in rows if it.confidence in conf_set]
            if filters.tag_keys:
                tkeys = set(filters.tag_keys)
                rows = [
                    it for it in rows
                    if any(tag.key in tkeys for tag in it.tags)
                ]
            if filters.value_contains:
                q = filters.value_contains
                rows = [it for it in rows if q in it.value.lower()]
            if filters.from_ts:
                rows = [it for it in rows if (it.created_at >= filters.from_ts)]
            if filters.to_ts:
                rows = [it for it in rows if (it.created_at <= filters.to_ts)]

            # Stable order: updated_at desc, id desc
            rows.sort(key=lambda r: (r.updated_at, r.id), reverse=True)

            total = len(rows)
            page = rows[offset: offset + limit]
            return [self._to_out(it) for it in page], total

    async def get(self, tenant_id: uuid.UUID, indicator_id: uuid.UUID) -> Optional[IndicatorOut]:
        async with self._lock:
            it = self._by_id.get(indicator_id)
            if it and it.tenant_id == tenant_id:
                return self._to_out(it)
            return None

    async def upsert(self, tenant_id: uuid.UUID, payload: IndicatorIn) -> IndicatorOut:
        now = datetime.now(timezone.utc)
        key = (tenant_id, payload.type, payload.value)
        async with self._lock:
            existing = self._by_key.get(key)
            if existing:
                # Update path for idempotency
                existing.description = payload.description
                existing.confidence = payload.confidence
                existing.source = payload.source
                existing.ttl_hours = payload.ttl_hours
                existing.tags = payload.tags or []
                existing.last_seen = now
                existing.updated_at = now
                return self._to_out(existing)

            row = _Indicator(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                type=payload.type,
                value=payload.value,
                description=payload.description,
                confidence=payload.confidence,
                first_seen=now,
                last_seen=now,
                source=payload.source,
                ttl_hours=payload.ttl_hours,
                tags=payload.tags or [],
                created_at=now,
                updated_at=now,
            )
            self._by_key[key] = row
            self._by_id[row.id] = row
            return self._to_out(row)

    async def bulk_upsert(self, tenant_id: uuid.UUID, items: List[IndicatorIn]) -> List[IndicatorOut]:
        results: List[IndicatorOut] = []
        for it in items:
            results.append(await self.upsert(tenant_id, it))
        return results

    async def update(self, tenant_id: uuid.UUID, indicator_id: uuid.UUID, patch: IndicatorUpdate) -> IndicatorOut:
        async with self._lock:
            row = self._by_id.get(indicator_id)
            if not row or row.tenant_id != tenant_id:
                raise HTTPException(status_code=404, detail="Indicator not found.")
            if patch.description is not None:
                row.description = patch.description
            if patch.confidence is not None:
                row.confidence = patch.confidence
            if patch.source is not None:
                row.source = patch.source
            if patch.ttl_hours is not None:
                row.ttl_hours = patch.ttl_hours
            if patch.tags is not None:
                row.tags = patch.tags
            row.updated_at = datetime.now(timezone.utc)
            return self._to_out(row)

    async def delete(self, tenant_id: uuid.UUID, indicator_id: uuid.UUID) -> None:
        async with self._lock:
            row = self._by_id.get(indicator_id)
            if not row or row.tenant_id != tenant_id:
                return
            key = (row.tenant_id, row.type, row.value)
            self._by_id.pop(indicator_id, None)
            self._by_key.pop(key, None)

    async def expire(self, now: datetime) -> int:
        async with self._lock:
            to_delete: List[uuid.UUID] = []
            for row in list(self._by_id.values()):
                if row.ttl_hours:
                    deadline = row.first_seen + timedelta(hours=row.ttl_hours)
                    if deadline <= now:
                        to_delete.append(row.id)
            for rid in to_delete:
                row = self._by_id.pop(rid, None)
                if row:
                    key = (row.tenant_id, row.type, row.value)
                    self._by_key.pop(key, None)
            return len(to_delete)

    @staticmethod
    def _to_out(row: _Indicator) -> IndicatorOut:
        return IndicatorOut(
            id=row.id,
            tenant_id=row.tenant_id,
            type=row.type,
            value=row.value,
            description=row.description,
            confidence=row.confidence,
            first_seen=row.first_seen,
            last_seen=row.last_seen,
            source=row.source,
            ttl_hours=row.ttl_hours,
            tags=row.tags,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


# -----------------------------------------------------------------------------
# Dependency Injection
# -----------------------------------------------------------------------------

_repo_singleton = InMemoryIntelRepository()

async def get_repository() -> IntelRepository:
    # Hook to swap on DB-backed repo (e.g., from container / service locator)
    return _repo_singleton


# -----------------------------------------------------------------------------
# STIX 2.1 ingestion helpers (minimal mapping)
# -----------------------------------------------------------------------------

def _stix_indicator_to_items(bundle: Dict[str, Any]) -> List[IndicatorIn]:
    """
    Parse STIX 2.1 bundle and extract IndicatorIn list from "indicator" and atomic objects.
    Supported patterns:
      - [ipv4-addr:value = '1.2.3.4']
      - [domain-name:value = 'example.com']
      - [url:value = 'https://example.com']
      - [file:hashes.'SHA-256' = '...']
    """
    objects = bundle.get("objects") or []
    items: List[IndicatorIn] = []

    def add(type_: IndicatorType, value: str, description: Optional[str], source: Optional[str]) -> None:
        items.append(
            IndicatorIn(
                type=type_,
                value=value,
                description=description,
                confidence=Confidence.MEDIUM,
                source=source,
                ttl_hours=None,
                tags=[],
            )
        )

    for obj in objects:
        t = obj.get("type")
        if t == "indicator":
            pattern = obj.get("pattern") or ""
            desc = obj.get("description")
            src = obj.get("created_by_ref")
            p = pattern.strip()
            # naive extraction for common cases
            if p.startswith("[") and p.endswith("]"):
                body = p[1:-1]
                body = body.replace('"', "'")
                if "ipv4-addr:value" in body:
                    val = body.split("=")[1].strip().strip("'")
                    add(IndicatorType.IPV4, val, desc, src)
                elif "domain-name:value" in body:
                    val = body.split("=")[1].strip().strip("'")
                    add(IndicatorType.DOMAIN, val, desc, src)
                elif "url:value" in body:
                    val = body.split("=")[1].strip().strip("'")
                    add(IndicatorType.URL, val, desc, src)
                elif "file:hashes.'SHA-256'" in body or "file:hashes.'sha256'" in body.lower():
                    val = body.split("=")[1].strip().strip("'")
                    items.append(
                        IndicatorIn(
                            type=IndicatorType.HASH_SHA256,
                            value=val,
                            description=desc,
                            confidence=Confidence.MEDIUM,
                            source=src,
                            ttl_hours=None,
                            tags=[],
                        )
                    )
        elif t == "ipv4-addr" and "value" in obj:
            add(IndicatorType.IPV4, obj["value"], obj.get("description"), obj.get("created_by_ref"))
        elif t == "domain-name" and "value" in obj:
            add(IndicatorType.DOMAIN, obj["value"], obj.get("description"), obj.get("created_by_ref"))
        elif t == "url" and "value" in obj:
            add(IndicatorType.URL, obj["value"], obj.get("description"), obj.get("created_by_ref"))
        elif t == "file":
            hashes = obj.get("hashes") or {}
            sha256 = hashes.get("SHA-256") or hashes.get("sha256")
            if sha256:
                add(IndicatorType.HASH_SHA256, sha256, obj.get("description"), obj.get("created_by_ref"))

    return items


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(prefix="/v1/intel", tags=["threat-intel"])


@router.get(
    "/indicators",
    response_model=IndicatorsListResponse,
    status_code=status.HTTP_200_OK,
    summary="List indicators with filters and cursor pagination",
)
async def list_indicators(
    tenant_id: TenantIdDep,
    types: Optional[List[IndicatorType]] = Query(default=None),
    confidence: Optional[List[Confidence]] = Query(default=None),
    tag_keys: Optional[List[str]] = Query(default=None),
    value_contains: Optional[str] = Query(default=None, min_length=1, max_length=1024),
    from_ts: Optional[datetime] = Query(default=None),
    to_ts: Optional[datetime] = Query(default=None),
    after: Optional[str] = Query(default=None, description="Opaque cursor"),
    limit: int = Query(default=100, ge=1, le=1000),
    repo: IntelRepository = Depends(get_repository),
) -> IndicatorsListResponse:
    offset = decode_cursor(after)
    filters = FilterQuery(
        types=types,
        confidence=confidence,
        tag_keys=tag_keys,
        value_contains=value_contains,
        from_ts=from_ts,
        to_ts=to_ts,
    )
    items, total = await repo.list(tenant_id, filters, offset, limit)
    next_cursor = encode_cursor(offset + len(items)) if (offset + len(items)) < total else None
    logger.info(
        "intel.list",
        extra={
            "tenant_id": str(tenant_id),
            "count": len(items),
            "total": total,
            "offset": offset,
            "limit": limit,
        },
    )
    return IndicatorsListResponse(items=items, page=PageInfo(next_cursor=next_cursor, total=total))


@router.get(
    "/indicators/{indicator_id}",
    response_model=IndicatorOut,
    status_code=status.HTTP_200_OK,
    summary="Get indicator by ID",
)
async def get_indicator(
    tenant_id: TenantIdDep,
    indicator_id: uuid.UUID = Path(...),
    repo: IntelRepository = Depends(get_repository),
) -> IndicatorOut:
    out = await repo.get(tenant_id, indicator_id)
    if not out:
        raise HTTPException(status_code=404, detail="Indicator not found.")
    logger.info("intel.get", extra={"tenant_id": str(tenant_id), "indicator_id": str(indicator_id)})
    return out


@router.post(
    "/indicators",
    response_model=IndicatorOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create or idempotently upsert a single indicator",
)
async def create_indicator(
    tenant_id: TenantIdDep,
    payload: IndicatorIn,
    repo: IntelRepository = Depends(get_repository),
) -> IndicatorOut:
    out = await repo.upsert(tenant_id, payload)
    logger.info(
        "intel.create",
        extra={"tenant_id": str(tenant_id), "type": payload.type, "value": payload.value},
    )
    return out


@router.post(
    "/indicators:bulk",
    response_model=List[IndicatorOut],
    status_code=status.HTTP_201_CREATED,
    summary="Bulk upsert indicators",
)
async def bulk_upsert_indicators(
    tenant_id: TenantIdDep,
    payload: IndicatorsBulkIn,
    repo: IntelRepository = Depends(get_repository),
) -> List[IndicatorOut]:
    out = await repo.bulk_upsert(tenant_id, payload.items)
    logger.info(
        "intel.bulk",
        extra={"tenant_id": str(tenant_id), "count": len(payload.items)},
    )
    return out


@router.patch(
    "/indicators/{indicator_id}",
    response_model=IndicatorOut,
    status_code=status.HTTP_200_OK,
    summary="Update indicator metadata",
)
async def update_indicator(
    tenant_id: TenantIdDep,
    indicator_id: uuid.UUID = Path(...),
    patch: IndicatorUpdate = ...,
    repo: IntelRepository = Depends(get_repository),
) -> IndicatorOut:
    out = await repo.update(tenant_id, indicator_id, patch)
    logger.info(
        "intel.update",
        extra={"tenant_id": str(tenant_id), "indicator_id": str(indicator_id)},
    )
    return out


@router.delete(
    "/indicators/{indicator_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete indicator",
)
async def delete_indicator(
    tenant_id: TenantIdDep,
    indicator_id: uuid.UUID = Path(...),
    repo: IntelRepository = Depends(get_repository),
) -> Response:
    await repo.delete(tenant_id, indicator_id)
    logger.info("intel.delete", extra={"tenant_id": str(tenant_id), "indicator_id": str(indicator_id)})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/indicators:expire",
    status_code=status.HTTP_200_OK,
    summary="Expire indicators by TTL (maintenance)",
)
async def expire_indicators(
    repo: IntelRepository = Depends(get_repository),
) -> Dict[str, int]:
    removed = await repo.expire(datetime.now(timezone.utc))
    logger.info("intel.expire", extra={"removed": removed})
    return {"removed": removed}


# -----------------------------------------------------------------------------
# Ingestion endpoints
# -----------------------------------------------------------------------------

class IngestResult(BaseModel):
    created: int
    errors: int


@router.post(
    "/ingest/csv",
    response_model=List[IndicatorOut],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest indicators from CSV (columns: type,value,description,confidence,source,ttl_hours,tags)",
)
async def ingest_csv(
    tenant_id: TenantIdDep,
    file: UploadFile = File(...),
    repo: IntelRepository = Depends(get_repository),
) -> List[IndicatorOut]:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted.")
    content = await file.read()
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = content.decode("utf-8", errors="ignore")

    reader = csv.DictReader(io.StringIO(text))
    items: List[IndicatorIn] = []
    for i, row in enumerate(reader, start=1):
        try:
            tags_str = (row.get("tags") or "").strip()
            tags: List[Tag] = []
            if tags_str:
                # tags format: key=value;key2=value2
                for pair in tags_str.split(";"):
                    if not pair:
                        continue
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        tags.append(Tag(key=k.strip(), value=v.strip()))
                    else:
                        tags.append(Tag(key=pair.strip(), value=None))
            item = IndicatorIn(
                type=IndicatorType(row["type"].strip().upper()),
                value=row["value"].strip(),
                description=(row.get("description") or None),
                confidence=Confidence((row.get("confidence") or "MEDIUM").strip().upper()),
                source=(row.get("source") or None),
                ttl_hours=int(row["ttl_hours"]) if row.get("ttl_hours") else None,
                tags=tags,
            )
            items.append(item)
        except Exception as ex:
            logger.warning("intel.ingest.csv.skip", extra={"row": i, "error": str(ex)})
            continue

    if not items:
        raise HTTPException(status_code=400, detail="No valid rows in CSV.")

    out = await repo.bulk_upsert(tenant_id, items)
    logger.info(
        "intel.ingest.csv",
        extra={"tenant_id": str(tenant_id), "count": len(out)},
    )
    return out


@router.post(
    "/ingest/ndjson",
    response_model=List[IndicatorOut],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest indicators from NDJSON (IndicatorIn per line)",
)
async def ingest_ndjson(
    tenant_id: TenantIdDep,
    file: UploadFile = File(...),
    repo: IntelRepository = Depends(get_repository),
) -> List[IndicatorOut]:
    if not file.filename or not file.filename.lower().endswith((".ndjson", ".json")):
        raise HTTPException(status_code=400, detail="Only .ndjson or .json files are accepted.")
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    lines = [line for line in text.splitlines() if line.strip()]
    items: List[IndicatorIn] = []
    for i, line in enumerate(lines, start=1):
        try:
            obj = json.loads(line)
            items.append(IndicatorIn.model_validate(obj))
        except ValidationError as ve:
            logger.warning("intel.ingest.ndjson.validation", extra={"line": i, "error": str(ve)})
        except Exception as ex:
            logger.warning("intel.ingest.ndjson.parse", extra={"line": i, "error": str(ex)})
    if not items:
        raise HTTPException(status_code=400, detail="No valid entries in NDJSON.")
    out = await repo.bulk_upsert(tenant_id, items)
    logger.info("intel.ingest.ndjson", extra={"tenant_id": str(tenant_id), "count": len(out)})
    return out


@router.post(
    "/ingest/stix",
    response_model=List[IndicatorOut],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest indicators from STIX 2.1 bundle (application/json)",
)
async def ingest_stix_bundle(
    tenant_id: TenantIdDep,
    request: Request,
    repo: IntelRepository = Depends(get_repository),
) -> List[IndicatorOut]:
    try:
        bundle = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")
    items = _stix_indicator_to_items(bundle)
    if not items:
        raise HTTPException(status_code=400, detail="No indicators found in STIX bundle.")
    out = await repo.bulk_upsert(tenant_id, items)
    logger.info("intel.ingest.stix", extra={"tenant_id": str(tenant_id), "count": len(out)})
    return out
