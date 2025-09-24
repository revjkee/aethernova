# cybersecurity-core/api/http/routers/v1/posture.py
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Generic, List, Literal, Optional, Sequence, Tuple, TypeVar

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    Security,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, RootModel, TypeAdapter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/posture", tags=["posture"])
bearer = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Security / Auth context
# ---------------------------------------------------------------------------

class AuthContext(BaseModel):
    sub: str = Field(..., description="Subject (user/service) identifier")
    scopes: set[str] = Field(default_factory=set)


def _parse_scopes_from_token(token: str) -> set[str]:
    # Placeholder for real JWT parsing. Ensure no secrets are logged.
    # Expected to be replaced with verification against JWKS / OPA / PDP.
    try:
        # Example: "scope=posture:read,posture:write"
        parts = [p for p in token.split() if "scope=" in p]
        if not parts:
            return set()
        _, scope_str = parts[0].split("=", 1)
        return set(s.strip() for s in scope_str.split(",") if s.strip())
    except Exception:
        return set()


async def get_auth_context(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer),
) -> AuthContext:
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = credentials.credentials
    scopes = _parse_scopes_from_token(token)
    sub = "unknown"
    return AuthContext(sub=sub, scopes=scopes)


def require_scopes(required: Sequence[str]):
    async def _enforce(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        missing = [s for s in required if s not in ctx.scopes]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient scopes: missing {','.join(missing)}",
            )
        return ctx

    return _enforce


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    critical = "CRITICAL"
    high = "HIGH"
    medium = "MEDIUM"
    low = "LOW"
    info = "INFO"


class FindingStatus(str, Enum):
    open = "OPEN"
    acknowledged = "ACKNOWLEDGED"
    in_progress = "IN_PROGRESS"
    resolved = "RESOLVED"
    suppressed = "SUPPRESSED"


class FindingIngest(BaseModel):
    rule_id: str = Field(..., examples=["CIS-1.1.0-K8S-1.2.1"])
    title: str
    description: Optional[str] = None
    severity: Severity
    asset_id: str = Field(..., examples=["srv-01", "cluster-prod"])
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the issue was detected",
    )
    source: str = Field(..., examples=["edr-agent", "k8s-scanner", "iac-scanner"])
    fingerprint: Optional[str] = Field(
        default=None,
        description="Stable identifier to deduplicate findings",
        examples=["sha256:..."],
    )
    cvss: Optional[float] = Field(default=None, ge=0, le=10)
    remediation: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    evidence: Optional[Dict[str, Any]] = Field(
        default=None, description="Arbitrary structured evidence"
    )


class Finding(FindingIngest):
    id: str = Field(default_factory=lambda: str(uuid.uuid7()))
    status: FindingStatus = FindingStatus.open
    assignee: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FindingPatch(BaseModel):
    status: Optional[FindingStatus] = None
    assignee: Optional[str] = Field(default=None, description="User or team id")
    note: Optional[str] = Field(default=None, description="Short operator note")
    add_tags: List[str] = Field(default_factory=list)
    remove_tags: List[str] = Field(default_factory=list)


class Heartbeat(BaseModel):
    agent_id: str
    asset_id: str
    hostname: str
    ip: Optional[str] = None
    version: str
    capabilities: List[str] = Field(default_factory=list)
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SBOMMetadata(BaseModel):
    asset_id: str
    format: Literal["spdx", "cyclonedx"]
    sha256: str
    source: str
    component_count: int
    created_at: datetime
    storage_url: Optional[str] = Field(default=None, description="Location of SBOM blob")


class Summary(BaseModel):
    total_findings: int
    counts_by_severity: Dict[Severity, int]
    counts_by_status: Dict[FindingStatus, int]
    last_ingest_at: Optional[datetime] = None


class FrameworkScore(BaseModel):
    framework: Literal["CIS", "NIST800-53", "ISO27001", "SOC2"]
    version: Optional[str] = None
    score: float = Field(ge=0, le=100)
    passed: int
    failed: int
    not_applicable: int


# ---------------------------------------------------------------------------
# Pagination / Response envelope
# ---------------------------------------------------------------------------

class PageMeta(BaseModel):
    page: int = Field(ge=1, description="1-based page number")
    size: int = Field(ge=1, le=500, description="Page size")
    total: int = Field(ge=0, description="Total items")
    more: bool = Field(description="If true, more items can be fetched")


T = TypeVar("T")


class ResponseEnvelope(BaseModel, Generic[T]):
    correlation_id: str
    data: T
    meta: Optional[Dict[str, Any]] = None


class Paginated(BaseModel, Generic[T]):
    items: List[T]
    page: PageMeta


# ---------------------------------------------------------------------------
# Service protocol and in-memory reference implementation
# ---------------------------------------------------------------------------

class PostureService:
    async def ingest_findings(self, items: List[FindingIngest]) -> List[Finding]:
        raise NotImplementedError

    async def list_findings(
        self,
        *,
        page: int,
        size: int,
        severities: Optional[set[Severity]],
        statuses: Optional[set[FindingStatus]],
        asset_id: Optional[str],
        rule_id: Optional[str],
        tags: Optional[set[str]],
        search: Optional[str],
        since: Optional[datetime],
        until: Optional[datetime],
        sort: Optional[str],
    ) -> Tuple[List[Finding], int]:
        raise NotImplementedError

    async def get_finding(self, finding_id: str) -> Finding:
        raise NotImplementedError

    async def patch_finding(self, finding_id: str, patch: FindingPatch) -> Finding:
        raise NotImplementedError

    async def get_summary(self) -> Summary:
        raise NotImplementedError

    async def get_compliance(self) -> List[FrameworkScore]:
        raise NotImplementedError

    async def get_sbom(self, asset_id: str) -> Optional[SBOMMetadata]:
        raise NotImplementedError

    async def heartbeat(self, hb: Heartbeat) -> None:
        raise NotImplementedError

    async def start_cis_job(self, scope: str) -> str:
        raise NotImplementedError


class InMemoryPostureService(PostureService):
    def __init__(self) -> None:
        self._findings: Dict[str, Finding] = {}
        self._sboms: Dict[str, SBOMMetadata] = {}
        self._last_ingest: Optional[datetime] = None

    async def ingest_findings(self, items: List[FindingIngest]) -> List[Finding]:
        out: List[Finding] = []
        now = datetime.now(timezone.utc)
        for it in items:
            f = Finding(**it.model_dump())
            f.created_at = now
            f.updated_at = now
            if it.fingerprint:
                # Deduplicate by fingerprint+asset
                for ex in list(self._findings.values()):
                    if ex.fingerprint == it.fingerprint and ex.asset_id == it.asset_id:
                        # Update existing
                        ex.title = it.title
                        ex.description = it.description
                        ex.severity = it.severity
                        ex.detected_at = it.detected_at
                        ex.source = it.source
                        ex.cvss = it.cvss
                        ex.remediation = it.remediation
                        ex.tags = sorted(list(set(ex.tags).union(set(it.tags))))
                        ex.evidence = it.evidence
                        ex.updated_at = now
                        out.append(ex)
                        break
                else:
                    self._findings[f.id] = f
                    out.append(f)
            else:
                self._findings[f.id] = f
                out.append(f)
        self._last_ingest = now
        logger.debug("Ingested findings", extra={"count": len(out)})
        return out

    async def list_findings(
        self,
        *,
        page: int,
        size: int,
        severities: Optional[set[Severity]],
        statuses: Optional[set[FindingStatus]],
        asset_id: Optional[str],
        rule_id: Optional[str],
        tags: Optional[set[str]],
        search: Optional[str],
        since: Optional[datetime],
        until: Optional[datetime],
        sort: Optional[str],
    ) -> Tuple[List[Finding], int]:
        items = list(self._findings.values())

        def match(f: Finding) -> bool:
            if severities and f.severity not in severities:
                return False
            if statuses and f.status not in statuses:
                return False
            if asset_id and f.asset_id != asset_id:
                return False
            if rule_id and f.rule_id != rule_id:
                return False
            if tags and not tags.issubset(set(f.tags)):
                return False
            if since and f.detected_at < since:
                return False
            if until and f.detected_at > until:
                return False
            if search:
                s = search.lower()
                blob = " ".join(
                    [
                        f.title or "",
                        f.description or "",
                        f.rule_id or "",
                        f.asset_id or "",
                        " ".join(f.tags or []),
                    ]
                ).lower()
                if s not in blob:
                    return False
            return True

        items = [f for f in items if match(f)]

        reverse = True
        key = "detected_at"
        if sort:
            try:
                if sort.startswith("-"):
                    reverse = True
                    key = sort[1:]
                else:
                    reverse = False
                    key = sort
                items.sort(key=lambda x: getattr(x, key), reverse=reverse)
            except Exception:
                pass
        else:
            items.sort(key=lambda x: x.detected_at, reverse=True)

        total = len(items)
        start = (page - 1) * size
        end = start + size
        return items[start:end], total

    async def get_finding(self, finding_id: str) -> Finding:
        f = self._findings.get(finding_id)
        if not f:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
        return f

    async def patch_finding(self, finding_id: str, patch: FindingPatch) -> Finding:
        f = await self.get_finding(finding_id)
        changed = False
        if patch.status and patch.status != f.status:
            f.status = patch.status
            changed = True
        if patch.assignee is not None and patch.assignee != f.assignee:
            f.assignee = patch.assignee
            changed = True
        if patch.add_tags:
            f.tags = sorted(list(set(f.tags).union(set(patch.add_tags))))
            changed = True
        if patch.remove_tags:
            f.tags = [t for t in f.tags if t not in set(patch.remove_tags)]
            changed = True
        if changed:
            f.updated_at = datetime.now(timezone.utc)
        if patch.note:
            logger.info("Finding note", extra={"finding_id": f.id, "note": patch.note[:512]})
        return f

    async def get_summary(self) -> Summary:
        counts_by_sev: Dict[Severity, int] = {s: 0 for s in Severity}
        counts_by_status: Dict[FindingStatus, int] = {s: 0 for s in FindingStatus}
        for f in self._findings.values():
            counts_by_sev[f.severity] += 1
            counts_by_status[f.status] += 1
        return Summary(
            total_findings=len(self._findings),
            counts_by_severity=counts_by_sev,
            counts_by_status=counts_by_status,
            last_ingest_at=self._last_ingest,
        )

    async def get_compliance(self) -> List[FrameworkScore]:
        # Static demo values; in production compute from control results
        return [
            FrameworkScore(framework="CIS", version="1.24", score=86.5, passed=173, failed=27, not_applicable=14),
            FrameworkScore(framework="NIST800-53", score=78.0, passed=312, failed=88, not_applicable=45),
        ]

    async def get_sbom(self, asset_id: str) -> Optional[SBOMMetadata]:
        return self._sboms.get(asset_id)

    async def heartbeat(self, hb: Heartbeat) -> None:
        logger.debug("Agent heartbeat", extra=hb.model_dump())

    async def start_cis_job(self, scope: str) -> str:
        job_id = str(uuid.uuid7())
        logger.info("CIS job submitted", extra={"job_id": job_id, "scope": scope})
        # Simulate async job submission
        asyncio.create_task(asyncio.sleep(0.01))
        return job_id


# Dependency factory; replace with real DI in production
_service_singleton = InMemoryPostureService()


async def get_posture_service() -> PostureService:
    return _service_singleton


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


async def correlation_id_dependency(
    request: Request, x_correlation_id: Optional[str] = Header(default=None, convert_underscores=False)
) -> str:
    cid = x_correlation_id or request.headers.get("X-Request-ID") or str(uuid.uuid7())
    return cid


def wrap(data: Any, correlation_id: str, meta: Optional[Dict[str, Any]] = None) -> ResponseEnvelope[Any]:
    return ResponseEnvelope(correlation_id=correlation_id, data=data, meta=meta)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get(
    "/health",
    response_model=ResponseEnvelope[Dict[str, Any]],
    summary="Posture service health",
)
async def health(
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:read"])),
) -> ResponseEnvelope[Dict[str, Any]]:
    return wrap(
        {
            "status": "ok",
            "time": _now_utc(),
            "service": "cybersecurity-core.posture",
            "version": "1.0.0",
        },
        correlation_id=cid,
    )


@router.post(
    "/findings/ingest",
    response_model=ResponseEnvelope[List[Finding]],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest security findings",
)
async def ingest_findings(
    payload: List[FindingIngest] = Body(..., examples=[[FindingIngest.model_construct(
        rule_id="CIS-K8S-1.1.1",
        title="Ensure that the --anonymous-auth argument is set to false",
        severity=Severity.high,
        asset_id="cluster-prod",
        source="k8s-scanner",
    ).model_dump()]]),
    svc: PostureService = Depends(get_posture_service),
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:ingest"])),
) -> ResponseEnvelope[List[Finding]]:
    if not payload:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty payload")
    if len(payload) > 5000:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Too many items")
    out = await svc.ingest_findings(payload)
    return wrap(out, correlation_id=cid, meta={"ingested": len(out)})


@router.get(
    "/findings",
    response_model=ResponseEnvelope[Paginated[Finding]],
    summary="List findings with filters and pagination",
)
async def list_findings(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    severity: Optional[List[Severity]] = Query(default=None),
    status_: Optional[List[FindingStatus]] = Query(default=None, alias="status"),
    asset_id: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    tags: Optional[List[str]] = Query(default=None),
    search: Optional[str] = Query(default=None, min_length=2, max_length=200),
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
    sort: Optional[str] = Query(default=None, description="Field name, prefix with - for desc"),
    svc: PostureService = Depends(get_posture_service),
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:read"])),
) -> ResponseEnvelope[Paginated[Finding]]:
    if since and until and since > until:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid time range")

    items, total = await svc.list_findings(
        page=page,
        size=size,
        severities=set(severity) if severity else None,
        statuses=set(status_) if status_ else None,
        asset_id=asset_id,
        rule_id=rule_id,
        tags=set(tags) if tags else None,
        search=search,
        since=since,
        until=until,
        sort=sort,
    )
    meta = PageMeta(page=page, size=size, total=total, more=(page * size) < total)
    return wrap(Paginated[Finding](items=items, page=meta), correlation_id=cid)


@router.get(
    "/findings/{finding_id}",
    response_model=ResponseEnvelope[Finding],
    summary="Get finding by id",
)
async def get_finding(
    finding_id: str = Path(..., min_length=8, max_length=128),
    svc: PostureService = Depends(get_posture_service),
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:read"])),
) -> ResponseEnvelope[Finding]:
    f = await svc.get_finding(finding_id)
    return wrap(f, correlation_id=cid)


@router.patch(
    "/findings/{finding_id}",
    response_model=ResponseEnvelope[Finding],
    summary="Patch finding (status/assignee/tags)",
)
async def patch_finding(
    finding_id: str = Path(..., min_length=8, max_length=128),
    patch: FindingPatch = Body(...),
    svc: PostureService = Depends(get_posture_service),
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:write"])),
) -> ResponseEnvelope[Finding]:
    f = await svc.patch_finding(finding_id, patch)
    return wrap(f, correlation_id=cid)


@router.get(
    "/summary",
    response_model=ResponseEnvelope[Summary],
    summary="Aggregated posture summary",
)
async def summary(
    svc: PostureService = Depends(get_posture_service),
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:read"])),
) -> ResponseEnvelope[Summary]:
    s = await svc.get_summary()
    return wrap(s, correlation_id=cid)


@router.get(
    "/compliance",
    response_model=ResponseEnvelope[List[FrameworkScore]],
    summary="Compliance scores by framework",
)
async def compliance(
    svc: PostureService = Depends(get_posture_service),
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:read"])),
) -> ResponseEnvelope[List[FrameworkScore]]:
    scores = await svc.get_compliance()
    return wrap(scores, correlation_id=cid)


@router.get(
    "/sbom/{asset_id}",
    response_model=ResponseEnvelope[Optional[SBOMMetadata]],
    summary="Get SBOM metadata for asset",
)
async def get_sbom(
    asset_id: str = Path(..., min_length=1, max_length=128),
    svc: PostureService = Depends(get_posture_service),
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:read"])),
) -> ResponseEnvelope[Optional[SBOMMetadata]]:
    sb = await svc.get_sbom(asset_id)
    return wrap(sb, correlation_id=cid)


class CISJobRequest(BaseModel):
    scope: Literal["cluster", "namespace", "node", "all"] = "all"


class CISJobResponse(BaseModel):
    job_id: str
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


@router.post(
    "/benchmarks/cis/kubernetes/run",
    response_model=ResponseEnvelope[CISJobResponse],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start CIS Kubernetes benchmark job",
)
async def start_cis_job(
    req: CISJobRequest,
    svc: PostureService = Depends(get_posture_service),
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:write"])),
) -> ResponseEnvelope[CISJobResponse]:
    job_id = await svc.start_cis_job(req.scope)
    return wrap(CISJobResponse(job_id=job_id), correlation_id=cid)


@router.post(
    "/agents/heartbeat",
    response_model=ResponseEnvelope[Dict[str, str]],
    summary="Agent heartbeat",
)
async def agent_heartbeat(
    hb: Heartbeat,
    svc: PostureService = Depends(get_posture_service),
    cid: str = Depends(correlation_id_dependency),
    _: AuthContext = Depends(require_scopes(["posture:ingest"])),
) -> ResponseEnvelope[Dict[str, str]]:
    await svc.heartbeat(hb)
    return wrap({"status": "ack"}, correlation_id=cid)
