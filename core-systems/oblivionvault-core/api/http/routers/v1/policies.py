# oblivionvault-core/api/http/routers/v1/policies.py
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple, Protocol
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, Json, validator

# ------------------------------------------------------------------------------
# Observability & Logger (structlog if available, else stdlib)
# ------------------------------------------------------------------------------
try:
    import structlog  # type: ignore

    logger = structlog.get_logger(__name__)
except Exception:  # pragma: no cover
    logger = logging.getLogger(__name__)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Security dependencies (scopes/RBAC). If project provides one, we use it.
# ------------------------------------------------------------------------------
class Principal(BaseModel):
    sub: str = Field(..., description="Subject/user identifier")
    scopes: List[str] = Field(default_factory=list, description="Granted scopes")
    roles: List[str] = Field(default_factory=list, description="Assigned roles")


def _noop_require_scopes(required: Iterable[str]):
    """
    Fallback dependency: allows all but logs a warning. Replace with a real
    security dependency from your platform when available.
    """
    required_set = set(required)

    async def _dep(request: Request) -> Principal:  # pragma: no cover
        principal = Principal(sub="anonymous")
        logger.warning(
            "RBAC fallback in use; please wire real security dependency",
            required=list(required_set),
        )
        return principal

    return _dep


try:
    # Example expected import path in a real project:
    # from oblivionvault_core.platform.security import require_scopes, Principal as RealPrincipal
    # For maximal portability we'll try multiple common paths.
    from oblivionvault_core.security.dependencies import (  # type: ignore
        require_scopes as _real_require_scopes,
        Principal as _RealPrincipal,
    )

    require_scopes = _real_require_scopes  # type: ignore
    Principal = _RealPrincipal  # type: ignore
except Exception:  # pragma: no cover
    require_scopes = _noop_require_scopes

# ------------------------------------------------------------------------------
# Schemas & enums
# ------------------------------------------------------------------------------

class PolicyType(str, Enum):
    rbac = "rbac"
    abac = "abac"
    opa = "opa"  # e.g., Rego payloads stored in `rules`


class SortBy(str, Enum):
    name = "name"
    created_at = "created_at"
    updated_at = "updated_at"


class SortOrder(str, Enum):
    asc = "asc"
    desc = "desc"


class PolicyBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=128)
    description: Optional[str] = Field(None, max_length=4096)
    type: PolicyType = Field(..., description="Policy engine/type")
    tags: List[str] = Field(default_factory=list, max_items=64)
    enabled: bool = Field(default=True)
    rules: Dict[str, Any] = Field(
        ...,
        description="Policy rules payload. For ABAC, supports 'allow_all' or 'bindings'.",
    )

    @validator("tags", pre=True)
    def _tag_strip(cls, v: Iterable[str]) -> List[str]:
        return [t.strip() for t in v if str(t).strip()]


class PolicyCreate(PolicyBase):
    pass


class PolicyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=128)
    description: Optional[str] = Field(None, max_length=4096)
    type: Optional[PolicyType] = None
    tags: Optional[List[str]] = Field(None)
    enabled: Optional[bool] = None
    rules: Optional[Dict[str, Any]] = None


class PolicyOut(PolicyBase):
    id: UUID
    version: int = Field(..., ge=1)
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class PageMeta(BaseModel):
    total: int
    limit: int
    offset: int


class PolicyListOut(BaseModel):
    data: List[PolicyOut]
    meta: PageMeta


class EvaluateInput(BaseModel):
    subject: Dict[str, Any] = Field(default_factory=dict)
    action: str = Field(..., min_length=1, max_length=128)
    resource: Dict[str, Any] = Field(default_factory=dict)


class EvaluateResult(BaseModel):
    allow: bool
    explanations: List[str] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# Service protocol (domain boundary). Router depends on this interface.
# ------------------------------------------------------------------------------

class PolicyService(Protocol):
    async def list(
        self,
        q: Optional[str],
        type_: Optional[PolicyType],
        enabled: Optional[bool],
        tag: Optional[str],
        sort_by: SortBy,
        sort_order: SortOrder,
        limit: int,
        offset: int,
    ) -> Tuple[List[PolicyOut], int]:
        ...

    async def get(self, policy_id: UUID) -> PolicyOut:
        ...

    async def create(self, payload: PolicyCreate) -> PolicyOut:
        ...

    async def update(self, policy_id: UUID, payload: PolicyUpdate, if_match: Optional[int]) -> PolicyOut:
        ...

    async def soft_delete(self, policy_id: UUID, if_match: Optional[int]) -> None:
        ...

    async def set_enabled(self, policy_id: UUID, enabled: bool, if_match: Optional[int]) -> PolicyOut:
        ...

    async def export_all(self) -> List[PolicyOut]:
        ...

    async def evaluate(self, policy_id: UUID, ctx: EvaluateInput) -> EvaluateResult:
        ...


# ------------------------------------------------------------------------------
# Default In-Memory fallback implementation (for tests/dev).
# In prod, wire your DB-backed service via DI below.
# ------------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _etag_from_version(version: int) -> str:
    return f'W/"{version}"'


class _InMemoryPolicyService(PolicyService):
    """
    Industrial-grade in-memory service with optimistic concurrency (version),
    soft-delete, filtering, search, and ABAC evaluation.
    """
    def __init__(self) -> None:
        self._store: Dict[UUID, PolicyOut] = {}
        self._name_index: Dict[str, UUID] = {}

    def _ensure_unique_name(self, name: str, exclude_id: Optional[UUID] = None) -> None:
        key = name.strip().lower()
        owner = self._name_index.get(key)
        if owner and owner != exclude_id:
            raise HTTPException(status_code=409, detail="Policy with this name already exists")

    async def list(
        self,
        q: Optional[str],
        type_: Optional[PolicyType],
        enabled: Optional[bool],
        tag: Optional[str],
        sort_by: SortBy,
        sort_order: SortOrder,
        limit: int,
        offset: int,
    ) -> Tuple[List[PolicyOut], int]:
        # snapshot
        items = [p for p in self._store.values() if p.deleted_at is None]
        if q:
            q_low = q.lower()
            items = [
                p
                for p in items
                if q_low in p.name.lower()
                or (p.description or "").lower().find(q_low) >= 0
                or any(q_low in t.lower() for t in p.tags)
            ]
        if type_:
            items = [p for p in items if p.type == type_]
        if enabled is not None:
            items = [p for p in items if p.enabled == enabled]
        if tag:
            tag_low = tag.lower()
            items = [p for p in items if any(t.lower() == tag_low for t in p.tags)]

        reverse = sort_order == SortOrder.desc
        if sort_by == SortBy.name:
            items.sort(key=lambda p: p.name.lower(), reverse=reverse)
        elif sort_by == SortBy.created_at:
            items.sort(key=lambda p: p.created_at, reverse=reverse)
        else:
            items.sort(key=lambda p: p.updated_at, reverse=reverse)

        total = len(items)
        window = items[offset : offset + limit]
        return window, total

    async def get(self, policy_id: UUID) -> PolicyOut:
        p = self._store.get(policy_id)
        if not p or p.deleted_at is not None:
            raise HTTPException(status_code=404, detail="Policy not found")
        return p

    async def create(self, payload: PolicyCreate) -> PolicyOut:
        self._ensure_unique_name(payload.name)
        now = _now_utc()
        pid = uuid4()
        p = PolicyOut(
            id=pid,
            name=payload.name,
            description=payload.description,
            type=payload.type,
            tags=payload.tags,
            enabled=payload.enabled,
            rules=payload.rules,
            version=1,
            created_at=now,
            updated_at=now,
            deleted_at=None,
        )
        self._store[pid] = p
        self._name_index[payload.name.strip().lower()] = pid
        logger.info("policy.create", policy_id=str(pid), name=p.name)
        return p

    async def update(self, policy_id: UUID, payload: PolicyUpdate, if_match: Optional[int]) -> PolicyOut:
        existing = await self.get(policy_id)
        if if_match is not None and existing.version != if_match:
            raise HTTPException(status_code=412, detail="Precondition Failed: version mismatch")

        new_name = payload.name if payload.name is not None else existing.name
        if new_name != existing.name:
            self._ensure_unique_name(new_name, exclude_id=existing.id)

        updated = existing.copy(update={
            "name": new_name,
            "description": payload.description if payload.description is not None else existing.description,
            "type": payload.type if payload.type is not None else existing.type,
            "tags": payload.tags if payload.tags is not None else existing.tags,
            "enabled": payload.enabled if payload.enabled is not None else existing.enabled,
            "rules": payload.rules if payload.rules is not None else existing.rules,
            "version": existing.version + 1,
            "updated_at": _now_utc(),
        })
        self._store[policy_id] = updated
        if new_name != existing.name:
            del self._name_index[existing.name.strip().lower()]
            self._name_index[new_name.strip().lower()] = policy_id
        logger.info("policy.update", policy_id=str(policy_id), name=updated.name, version=updated.version)
        return updated

    async def soft_delete(self, policy_id: UUID, if_match: Optional[int]) -> None:
        existing = await self.get(policy_id)
        if if_match is not None and existing.version != if_match:
            raise HTTPException(status_code=412, detail="Precondition Failed: version mismatch")
        deleted = existing.copy(update={
            "deleted_at": _now_utc(),
            "version": existing.version + 1,
            "updated_at": _now_utc(),
        })
        self._store[policy_id] = deleted
        logger.info("policy.delete", policy_id=str(policy_id), name=existing.name)

    async def set_enabled(self, policy_id: UUID, enabled: bool, if_match: Optional[int]) -> PolicyOut:
        existing = await self.get(policy_id)
        if if_match is not None and existing.version != if_match:
            raise HTTPException(status_code=412, detail="Precondition Failed: version mismatch")
        updated = existing.copy(update={
            "enabled": enabled,
            "version": existing.version + 1,
            "updated_at": _now_utc(),
        })
        self._store[policy_id] = updated
        logger.info("policy.enable" if enabled else "policy.disable", policy_id=str(policy_id))
        return updated

    async def export_all(self) -> List[PolicyOut]:
        return [p for p in self._store.values() if p.deleted_at is None]

    # ------------------------------ ABAC evaluate ------------------------------
    @staticmethod
    def _match_dict(pattern: Dict[str, Any], actual: Dict[str, Any]) -> bool:
        """
        A simple exact match for dict fields with '*' wildcard support.
        pattern: {"role": "admin"} -> actual["role"] must equal "admin"
                 {"env": "*"} -> any value is accepted if key exists
        Missing keys in actual cause a mismatch unless wildcard '*'.
        """
        for k, v in pattern.items():
            if v == "*":
                if k not in actual:
                    return False
                continue
            if actual.get(k) != v:
                return False
        return True

    async def evaluate(self, policy_id: UUID, ctx: EvaluateInput) -> EvaluateResult:
        policy = await self.get(policy_id)
        rules = policy.rules or {}

        explanations: List[str] = []

        # allow_all short-circuit
        if isinstance(rules, dict) and rules.get("allow_all") is True:
            explanations.append("Rule allow_all=True matched")
            return EvaluateResult(allow=True, explanations=explanations)

        # bindings: list of {subject: {..}|'*', action: 'read'|'*', resource: {..}|'*'}
        bindings = rules.get("bindings") if isinstance(rules, dict) else None
        if not isinstance(bindings, list):
            explanations.append("No bindings found; deny by default")
            return EvaluateResult(allow=False, explanations=explanations)

        for idx, b in enumerate(bindings):
            subj_pat = b.get("subject", {})
            act_pat = b.get("action", "*")
            res_pat = b.get("resource", {})

            subj_ok = True if subj_pat == "*" else self._match_dict(subj_pat or {}, ctx.subject)
            act_ok = True if act_pat in ("*", ctx.action) else False
            res_ok = True if res_pat == "*" else self._match_dict(res_pat or {}, ctx.resource)
            if subj_ok and act_ok and res_ok:
                explanations.append(f"Binding #{idx} matched")
                return EvaluateResult(allow=True, explanations=explanations)

        explanations.append("No binding matched; deny")
        return EvaluateResult(allow=False, explanations=explanations)


# ------------------------------------------------------------------------------
# DI: obtain a service instance. Prefer project service if available.
# ------------------------------------------------------------------------------
async def get_policy_service() -> PolicyService:
    """
    Resolves a PolicyService. If your project exposes a concrete service,
    import and return it here. Otherwise, fallback to in-memory.
    """
    # Try to use a real service from the project if present.
    if os.getenv("OBLIVIONVAULT_FORCE_INMEMORY", "").lower() in ("1", "true"):
        return _InMemoryPolicyService()

    try:
        # Expected project path example:
        # from oblivionvault_core.services.policies import PolicyServiceImpl
        from oblivionvault_core.services.policies import (  # type: ignore
            PolicyServiceImpl,
        )

        return PolicyServiceImpl()  # type: ignore
    except Exception:  # pragma: no cover
        logger.warning("Using in-memory PolicyService fallback")
        return _InMemoryPolicyService()


# ------------------------------------------------------------------------------
# Router
# ------------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/policies", tags=["policies"])

# ------------------------------ Helpers ---------------------------------------
def _parse_if_match(etag_header: Optional[str]) -> Optional[int]:
    """
    Accepts If-Match header with ETag like W/"<version>" and extracts version int.
    """
    if not etag_header:
        return None
    try:
        # Accept both W/"<v>" and "<v>"
        token = etag_header.strip()
        if token.startswith('W/'):
            token = token[2:].strip()
        if token.startswith('"') and token.endswith('"'):
            token = token[1:-1]
        version = int(token)
        return version
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid If-Match header")


def _set_etag(resp: Response, version: int) -> None:
    resp.headers["ETag"] = _etag_from_version(version)


def _trace_id(x_request_id: Optional[str]) -> str:
    return x_request_id or hashlib.sha1(str(time.time()).encode()).hexdigest()[:16]


# ------------------------------ Endpoints -------------------------------------

@router.get(
    "",
    response_model=PolicyListOut,
    summary="List policies with filters, search and pagination",
)
async def list_policies(
    q: Optional[str] = Query(None, description="Full-text search by name/description/tags"),
    type_: Optional[PolicyType] = Query(None, alias="type"),
    enabled: Optional[bool] = Query(None),
    tag: Optional[str] = Query(None, description="Filter by exact tag"),
    sort_by: SortBy = Query(SortBy.updated_at),
    sort_order: SortOrder = Query(SortOrder.desc),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: Principal = Depends(require_scopes(["policies:read"])),
    svc: PolicyService = Depends(get_policy_service),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    trace = _trace_id(x_request_id)
    items, total = await svc.list(q, type_, enabled, tag, sort_by, sort_order, limit, offset)
    logger.info("policy.list", trace=trace, total=total, limit=limit, offset=offset)
    return PolicyListOut(
        data=items,
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


@router.get(
    "/{policy_id}",
    response_model=PolicyOut,
    summary="Get policy by ID",
)
async def get_policy(
    policy_id: UUID,
    _: Principal = Depends(require_scopes(["policies:read"])),
    svc: PolicyService = Depends(get_policy_service),
    response: Response = None,  # type: ignore
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    trace = _trace_id(x_request_id)
    p = await svc.get(policy_id)
    _set_etag(response, p.version)
    logger.info("policy.get", trace=trace, policy_id=str(policy_id))
    return p


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=PolicyOut,
    summary="Create a new policy",
)
async def create_policy(
    payload: PolicyCreate,
    principal: Principal = Depends(require_scopes(["policies:write"])),
    svc: PolicyService = Depends(get_policy_service),
    response: Response = None,  # type: ignore
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    trace = _trace_id(x_request_id)
    p = await svc.create(payload)
    _set_etag(response, p.version)
    logger.info("policy.created", trace=trace, policy_id=str(p.id), actor=principal.sub)
    return p


@router.patch(
    "/{policy_id}",
    response_model=PolicyOut,
    summary="Update an existing policy (optimistic concurrency with If-Match)",
)
async def update_policy(
    policy_id: UUID,
    payload: PolicyUpdate,
    principal: Principal = Depends(require_scopes(["policies:write"])),
    svc: PolicyService = Depends(get_policy_service),
    response: Response = None,  # type: ignore
    if_match: Optional[str] = Header(None, alias="If-Match"),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    trace = _trace_id(x_request_id)
    version = _parse_if_match(if_match)
    p = await svc.update(policy_id, payload, version)
    _set_etag(response, p.version)
    logger.info("policy.updated", trace=trace, policy_id=str(policy_id), actor=principal.sub)
    return p


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete a policy (optimistic concurrency with If-Match)",
)
async def delete_policy(
    policy_id: UUID,
    principal: Principal = Depends(require_scopes(["policies:admin"])),
    svc: PolicyService = Depends(get_policy_service),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    trace = _trace_id(x_request_id)
    version = _parse_if_match(if_match)
    await svc.soft_delete(policy_id, version)
    logger.info("policy.deleted", trace=trace, policy_id=str(policy_id), actor=principal.sub)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{policy_id}/enable",
    response_model=PolicyOut,
    summary="Enable a policy",
)
async def enable_policy(
    policy_id: UUID,
    principal: Principal = Depends(require_scopes(["policies:write"])),
    svc: PolicyService = Depends(get_policy_service),
    response: Response = None,  # type: ignore
    if_match: Optional[str] = Header(None, alias="If-Match"),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    trace = _trace_id(x_request_id)
    version = _parse_if_match(if_match)
    p = await svc.set_enabled(policy_id, True, version)
    _set_etag(response, p.version)
    logger.info("policy.enabled", trace=trace, policy_id=str(policy_id), actor=principal.sub)
    return p


@router.post(
    "/{policy_id}/disable",
    response_model=PolicyOut,
    summary="Disable a policy",
)
async def disable_policy(
    policy_id: UUID,
    principal: Principal = Depends(require_scopes(["policies:write"])),
    svc: PolicyService = Depends(get_policy_service),
    response: Response = None,  # type: ignore
    if_match: Optional[str] = Header(None, alias="If-Match"),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    trace = _trace_id(x_request_id)
    version = _parse_if_match(if_match)
    p = await svc.set_enabled(policy_id, False, version)
    _set_etag(response, p.version)
    logger.info("policy.disabled", trace=trace, policy_id=str(policy_id), actor=principal.sub)
    return p


@router.get(
    "/export",
    response_model=List[PolicyOut],
    summary="Export all non-deleted policies",
)
async def export_policies(
    _: Principal = Depends(require_scopes(["policies:read"])),
    svc: PolicyService = Depends(get_policy_service),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    trace = _trace_id(x_request_id)
    data = await svc.export_all()
    logger.info("policy.export", trace=trace, count=len(data))
    return data


@router.post(
    "/{policy_id}/evaluate",
    response_model=EvaluateResult,
    summary="Evaluate a policy with subject/action/resource context (ABAC)",
)
async def evaluate_policy(
    policy_id: UUID,
    body: EvaluateInput,
    _: Principal = Depends(require_scopes(["policies:evaluate", "policies:read"])),
    svc: PolicyService = Depends(get_policy_service),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
):
    trace = _trace_id(x_request_id)
    res = await svc.evaluate(policy_id, body)
    logger.info(
        "policy.evaluate",
        trace=trace,
        policy_id=str(policy_id),
        allow=res.allow,
    )
    return res
