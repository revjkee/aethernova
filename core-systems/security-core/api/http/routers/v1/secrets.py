# File: security-core/api/http/routers/v1/secrets.py
# Purpose: Industrial-grade HTTP router for Secrets management (create/get/list/rotate/version/delete/restore)
# Framework: FastAPI / Starlette
# Python: 3.10+
# Notes:
#  - Uses RFC 7807 problem+json via security_core.api.http.errors
#  - Enforces scopes/RBAC at the router boundary
#  - Value disclosure requires explicit ?reveal=true and scope "secrets:read:value"
#  - ETag/If-None-Match support for GET /{id}
#  - Soft delete with restore; hard delete requires elevated permission
#  - Safe masking of values in non-reveal responses
#  - Pagination with page_size/page_token; server-side filtering by name/type/tags/state

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field, constr, validator

# Error helpers and domain exceptions
try:
    from security_core.api.http.errors import (
        AuthenticationError,
        AuthorizationError,
        NotFoundError,
        ConflictError,
        ValidationFailed,
        RateLimited,
        ServiceUnavailable,
        raise_forbidden,
        raise_not_found,
        raise_validation_failed,
        raise_conflict,
    )
except Exception:  # Fallback if wiring not yet present
    class AuthenticationError(HTTPException):
        def __init__(self, detail: str = "Unauthorized") -> None:
            super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

    class AuthorizationError(HTTPException):
        def __init__(self, detail: str = "Forbidden") -> None:
            super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    class NotFoundError(HTTPException):
        def __init__(self, detail: str = "Not Found") -> None:
            super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)

    class ConflictError(HTTPException):
        def __init__(self, detail: str = "Conflict") -> None:
            super().__init__(status_code=status.HTTP_409_CONFLICT, detail=detail)

    class ValidationFailed(HTTPException):
        def __init__(self, detail: str = "Validation failed") -> None:
            super().__init__(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail)

    def raise_forbidden(detail: Optional[str] = None, **_: Any) -> None:
        raise AuthorizationError(detail or "Forbidden")

    def raise_not_found(detail: Optional[str] = None, **_: Any) -> None:
        raise NotFoundError(detail or "Not Found")

    def raise_validation_failed(detail: Optional[str] = None, **_: Any) -> None:
        raise ValidationFailed(detail or "Validation failed")

    def raise_conflict(detail: Optional[str] = None, **_: Any) -> None:
        raise ConflictError(detail or "Conflict")


logger = logging.getLogger("security_core.api.secrets")
router = APIRouter(prefix="/api/v1/secrets", tags=["secrets"])

# ---------------------------
# AuthN/AuthZ dependencies
# ---------------------------

class Subject(BaseModel):
    sub: str
    tenant_id: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "*" in self.scopes

    def is_admin(self) -> bool:
        return "admin" in self.roles or "security.admin" in self.roles


try:
    # Prefer project-provided dependency
    from security_core.api.http.dependencies import get_current_subject  # type: ignore
except Exception:
    async def get_current_subject(request: Request) -> Subject:
        # Default safe behavior: fail closed until auth wired
        raise AuthenticationError("Authentication is not configured")


def require_scope(subject: Subject, needed: str) -> None:
    if not subject.has_scope(needed) and not subject.is_admin():
        raise_forbidden(f"Missing scope: {needed}")


# ---------------------------
# Domain service dependency
# ---------------------------

class SecretState(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    SOFT_DELETED = "soft_deleted"


class SecretType(str, Enum):
    GENERIC = "generic"
    API_KEY = "api_key"
    CREDENTIALS = "credentials"  # username/password pair
    TOKEN = "token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY_HANDLE = "private_key_handle"  # external KMS reference


class SecretVersionInfo(BaseModel):
    version_id: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    enabled: bool = True
    checksum_sha256: Optional[str] = None


class SecretSummary(BaseModel):
    id: str
    name: str
    type: SecretType
    state: SecretState
    created_at: datetime
    updated_at: datetime
    tags: List[str] = Field(default_factory=list)
    has_value: bool = Field(False, description="Whether value exists for the current version")
    current_version_id: Optional[str] = None
    etag: Optional[str] = None


class SecretDetail(SecretSummary):
    # value is excluded by default; filled only when reveal=true and allowed
    value: Optional[str] = Field(default=None, description="Present only when reveal=true and authorized")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    versions: Optional[List[SecretVersionInfo]] = None

    @staticmethod
    def masked(detail: "SecretDetail") -> "SecretDetail":
        if detail.value is not None:
            return detail.copy(update={"value": "****"})
        return detail


# Requests

class SecretCreate(BaseModel):
    name: constr(strip_whitespace=True, min_length=3, max_length=200)
    type: SecretType = SecretType.GENERIC
    value: Optional[str] = Field(default=None, description="Optional for external handles")
    tags: List[constr(strip_whitespace=True, min_length=1, max_length=64)] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: Optional[int] = Field(default=None, ge=60, le=365 * 24 * 3600)
    rotation_period_days: Optional[int] = Field(default=None, ge=1, le=365)
    allow_read_once: bool = False

    @validator("tags")
    def unique_tags(cls, v: List[str]) -> List[str]:
        if len(set(v)) != len(v):
            raise ValueError("Tags must be unique")
        return v


class SecretRotate(BaseModel):
    new_value: Optional[str] = Field(default=None, description="If omitted, service performs managed rotation")
    version_metadata: Dict[str, Any] = Field(default_factory=dict)
    expires_at: Optional[datetime] = None
    enable_new_version: bool = True


class SecretUpdate(BaseModel):
    name: Optional[constr(strip_whitespace=True, min_length=3, max_length=200)] = None
    tags: Optional[List[constr(strip_whitespace=True, min_length=1, max_length=64)]] = None
    metadata: Optional[Dict[str, Any]] = None
    state: Optional[SecretState] = None
    rotation_period_days: Optional[int] = Field(default=None, ge=1, le=365)


class Page(BaseModel):
    items: List[SecretSummary]
    next_page_token: Optional[str] = None


# Service interface (expected to be implemented in domain layer)
class SecretService:
    async def create_secret(self, subject: Subject, payload: SecretCreate) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError

    async def list_secrets(
        self,
        subject: Subject,
        *,
        name_contains: Optional[str],
        secret_type: Optional[SecretType],
        tag: Optional[str],
        state: Optional[SecretState],
        page_size: int,
        page_token: Optional[str],
    ) -> Tuple[List[SecretSummary], Optional[str]]:  # pragma: no cover
        raise NotImplementedError

    async def get_secret(self, subject: Subject, secret_id: str, *, include_value: bool) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError

    async def get_versions(
        self, subject: Subject, secret_id: str
    ) -> List[SecretVersionInfo]:  # pragma: no cover
        raise NotImplementedError

    async def rotate(
        self, subject: Subject, secret_id: str, payload: SecretRotate
    ) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError

    async def update(
        self, subject: Subject, secret_id: str, payload: SecretUpdate
    ) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError

    async def delete(
        self, subject: Subject, secret_id: str, *, hard: bool
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    async def restore(self, subject: Subject, secret_id: str) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError


try:
    # Prefer dependency from your DI container
    from security_core.domain.secrets import get_secret_service  # type: ignore
except Exception:
    async def get_secret_service() -> SecretService:
        # Fail closed until proper service is wired
        raise ServiceUnavailable("Secret service is not configured")  # type: ignore


# ---------------------------
# Helpers
# ---------------------------

def _compute_etag(secret: SecretSummary) -> str:
    base = f"{secret.id}:{secret.updated_at.isoformat()}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def _apply_etag(resp: Response, etag: str) -> None:
    resp.headers["ETag"] = etag

def _check_conditional(if_none_match: Optional[str], etag: str) -> bool:
    if not if_none_match:
        return False
    received = [t.strip() for t in if_none_match.split(",")]
    return etag in received or "*" in received


# ---------------------------
# Routes
# ---------------------------

@router.post(
    "",
    response_model=SecretDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new secret",
)
async def create_secret(
    payload: SecretCreate,
    subject: Subject = Depends(get_current_subject),
    svc: SecretService = Depends(get_secret_service),
) -> SecretDetail:
    require_scope(subject, "secrets:write")
    created = await svc.create_secret(subject, payload)
    # Never return raw value unless explicitly retrieved with reveal
    return SecretDetail.masked(created)


@router.get(
    "",
    response_model=Page,
    status_code=status.HTTP_200_OK,
    summary="List secrets",
)
async def list_secrets(
    subject: Subject = Depends(get_current_subject),
    svc: SecretService = Depends(get_secret_service),
    name_contains: Optional[str] = Query(default=None, max_length=200),
    secret_type: Optional[SecretType] = Query(default=None),
    tag: Optional[str] = Query(default=None, max_length=64),
    state: Optional[SecretState] = Query(default=None),
    page_size: int = Query(default=50, ge=1, le=500),
    page_token: Optional[str] = Query(default=None),
) -> Page:
    require_scope(subject, "secrets:read")
    items, token = await svc.list_secrets(
        subject,
        name_contains=name_contains,
        secret_type=secret_type,
        tag=tag,
        state=state,
        page_size=page_size,
        page_token=page_token,
    )
    # Normalize ETag on summaries
    out: List[SecretSummary] = []
    for s in items:
        s.etag = s.etag or _compute_etag(s)
        out.append(s)
    return Page(items=out, next_page_token=token)


@router.get(
    "/{secret_id}",
    response_model=SecretDetail,
    status_code=status.HTTP_200_OK,
    summary="Get secret by id",
)
async def get_secret(
    secret_id: str,
    response: Response,
    subject: Subject = Depends(get_current_subject),
    svc: SecretService = Depends(get_secret_service),
    reveal: bool = Query(default=False, description="Return value if authorized"),
    if_none_match: Optional[str] = Header(default=None, convert_underscores=False),
) -> SecretDetail:
    # Read metadata requires secrets:read; revealing value requires extra scope
    require_scope(subject, "secrets:read")
    include_value = False
    if reveal:
        require_scope(subject, "secrets:read:value")
        include_value = True

    detail = await svc.get_secret(subject, secret_id, include_value=include_value)
    # Manage ETag
    summary_like = SecretSummary(
        id=detail.id,
        name=detail.name,
        type=detail.type,
        state=detail.state,
        created_at=detail.created_at,
        updated_at=detail.updated_at,
        tags=detail.tags,
        has_value=detail.has_value,
        current_version_id=detail.current_version_id,
        etag=detail.etag,
    )
    etag = summary_like.etag or _compute_etag(summary_like)
    if _check_conditional(if_none_match, etag):
        # Not Modified equivalent for conditional GET; RFC allows 304 only if cacheable,
        # however we keep 200 with empty body? Better: return 304 without body.
        response.status_code = status.HTTP_304_NOT_MODIFIED
        _apply_etag(response, etag)
        return SecretDetail(**detail.dict(exclude_unset=True))  # body will be ignored by clients

    _apply_etag(response, etag)
    return detail if include_value else SecretDetail.masked(detail)


@router.get(
    "/{secret_id}/versions",
    response_model=List[SecretVersionInfo],
    status_code=status.HTTP_200_OK,
    summary="List versions of a secret",
)
async def get_versions(
    secret_id: str,
    subject: Subject = Depends(get_current_subject),
    svc: SecretService = Depends(get_secret_service),
) -> List[SecretVersionInfo]:
    require_scope(subject, "secrets:read")
    return await svc.get_versions(subject, secret_id)


@router.post(
    "/{secret_id}/versions",
    response_model=SecretDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new version (rotate)",
)
async def rotate_secret(
    secret_id: str,
    payload: SecretRotate,
    subject: Subject = Depends(get_current_subject),
    svc: SecretService = Depends(get_secret_service),
) -> SecretDetail:
    require_scope(subject, "secrets:write")
    rotated = await svc.rotate(subject, secret_id, payload)
    # Do not leak value on rotation response unless caller also has read:value
    return rotated if subject.has_scope("secrets:read:value") or subject.is_admin() else SecretDetail.masked(rotated)


@router.patch(
    "/{secret_id}",
    response_model=SecretDetail,
    status_code=status.HTTP_200_OK,
    summary="Update secret metadata/state",
)
async def update_secret(
    secret_id: str,
    payload: SecretUpdate,
    subject: Subject = Depends(get_current_subject),
    svc: SecretService = Depends(get_secret_service),
) -> SecretDetail:
    require_scope(subject, "secrets:write")
    updated = await svc.update(subject, secret_id, payload)
    return SecretDetail.masked(updated)


@router.delete(
    "/{secret_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a secret (soft by default, hard requires admin)",
)
async def delete_secret(
    secret_id: str,
    subject: Subject = Depends(get_current_subject),
    svc: SecretService = Depends(get_secret_service),
    hard: bool = Query(default=False),
) -> Response:
    require_scope(subject, "secrets:write")
    if hard and not subject.is_admin():
        raise_forbidden("Hard delete requires admin role")
    await svc.delete(subject, secret_id, hard=hard)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{secret_id}/restore",
    response_model=SecretDetail,
    status_code=status.HTTP_200_OK,
    summary="Restore a soft-deleted secret",
)
async def restore_secret(
    secret_id: str,
    subject: Subject = Depends(get_current_subject),
    svc: SecretService = Depends(get_secret_service),
) -> SecretDetail:
    require_scope(subject, "secrets:write")
    restored = await svc.restore(subject, secret_id)
    return SecretDetail.masked(restored)
