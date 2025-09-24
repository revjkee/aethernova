# -*- coding: utf-8 -*-
"""
OblivionVault Core — HTTP Router v1: Retention Rules
Industrial-grade FastAPI router:
- JSON Schema validation (draft 2020-12), fastjsonschema -> jsonschema fallback
- RBAC guard (policy:read / policy:write)
- ETag / If-Match optimistic concurrency
- Idempotency-Key support
- X-Tenant-Id multi-tenancy
- Pagination (page_size, page_token)
- Audit logging hooks
- Preview / Enforce actions

This module depends only on FastAPI/Pydantic and a pluggable RetentionService provided via DI.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
from typing import Any, Dict, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field

# ----------------------------------------------------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------------------------------------------------

log = logging.getLogger("oblivionvault.api.retention")


# ----------------------------------------------------------------------------------------------------------------------
# Auth / Principal / RBAC (pluggable)
# ----------------------------------------------------------------------------------------------------------------------

class Principal(BaseModel):
    subject: str
    roles: List[str] = Field(default_factory=list)
    tenant_id: Optional[str] = None


async def get_principal(request: Request) -> Principal:
    """
    Replace with real auth integration (OIDC/JWT/mTLS).
    Assumes upstream middleware already verified the user and set headers.
    """
    subject = request.headers.get("X-Actor-Id") or "anonymous"
    roles = [r.strip() for r in request.headers.get("X-Actor-Roles", "").split(",") if r.strip()]
    tenant = request.headers.get("X-Tenant-Id")
    return Principal(subject=subject, roles=roles, tenant_id=tenant)


def require_privileges(principal: Principal, needed: List[str]) -> None:
    """
    Naive RBAC check: role->privileges mapping is expected to be resolved upstream.
    For this router we assume roles are privileges for simplicity (e.g., 'policy:write' in roles).
    """
    missing = [p for p in needed if p not in principal.roles]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "forbidden", "missing": missing},
        )


# ----------------------------------------------------------------------------------------------------------------------
# Retention Service Interface (to be provided via DI)
# ----------------------------------------------------------------------------------------------------------------------

class RetentionService:
    """
    Abstract retention service API. Provide your implementation via DI.
    All methods are async and must raise ValueError for 400, KeyError for 404, ConflictError for 409.
    """

    class ConflictError(Exception):
        pass

    async def create_rule(
        self,
        tenant_id: Optional[str],
        rule: Dict[str, Any],
        idempotency_key: Optional[str],
    ) -> Dict[str, Any]:
        raise NotImplementedError

    async def get_rule(self, tenant_id: Optional[str], name: str) -> Dict[str, Any]:
        raise NotImplementedError

    async def list_rules(
        self,
        tenant_id: Optional[str],
        page_size: int,
        page_token: Optional[str],
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        raise NotImplementedError

    async def replace_rule(
        self,
        tenant_id: Optional[str],
        name: str,
        rule: Dict[str, Any],
        if_match: Optional[str],
        idempotency_key: Optional[str],
    ) -> Dict[str, Any]:
        raise NotImplementedError

    async def patch_rule(
        self,
        tenant_id: Optional[str],
        name: str,
        merge_patch: Dict[str, Any],
        if_match: Optional[str],
        idempotency_key: Optional[str],
    ) -> Dict[str, Any]:
        raise NotImplementedError

    async def delete_rule(
        self,
        tenant_id: Optional[str],
        name: str,
        hard_delete: bool,
        if_match: Optional[str],
        idempotency_key: Optional[str],
    ) -> None:
        raise NotImplementedError

    async def preview_enforcement(self, tenant_id: Optional[str], name: str) -> Dict[str, Any]:
        raise NotImplementedError

    async def enforce_now(self, tenant_id: Optional[str], name: str) -> Dict[str, Any]:
        raise NotImplementedError


def get_retention_service() -> RetentionService:
    """
    Wire your implementation here (e.g., from container).
    """
    raise HTTPException(status_code=500, detail={"message": "RetentionService is not configured"})


# ----------------------------------------------------------------------------------------------------------------------
# JSON Schema validation (compile & cache)
# ----------------------------------------------------------------------------------------------------------------------

_VALIDATOR = None
_SCHEMA_ID = "https://aethernova.dev/schemas/oblivionvault/v1/retention_rule.schema.json"


def _compile_validator() -> Any:
    global _VALIDATOR
    if _VALIDATOR is not None:
        return _VALIDATOR

    schema: Dict[str, Any]
    try:
        # Load schema from installed package/resource if available
        import importlib.resources as pkg_res  # Python 3.9+
        from pathlib import Path

        # Expect schema file installed alongside code; adjust if packaging differs
        # This relative import path is illustrative — adapt to your packaging layout.
        with pkg_res.as_file(
            pkg_res.files("oblivionvault_core.schemas.jsonschema.v1").joinpath("retention_rule.schema.json")
        ) as p:
            schema = json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        # Minimal fallback: require apiVersion/kind/metadata/spec; rely on service-side deep validation.
        log.warning("Falling back to embedded minimal schema for retention rule validation")
        schema = {
            "$id": _SCHEMA_ID,
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["apiVersion", "kind", "metadata", "spec"],
            "properties": {
                "apiVersion": {"const": "oblivion.aethernova/v1"},
                "kind": {"const": "RetentionRule"},
                "metadata": {"type": "object", "required": ["name"]},
                "spec": {"type": "object", "required": ["scope", "retention", "schedule", "enforcement"]},
            },
            "additionalProperties": True,
        }

    try:
        import fastjsonschema  # type: ignore

        _VALIDATOR = fastjsonschema.compile(schema)
        log.info("fastjsonschema compiled retention_rule schema")
        return _VALIDATOR
    except Exception:  # pragma: no cover
        try:
            import jsonschema  # type: ignore

            def _validate(obj: Dict[str, Any]) -> None:
                jsonschema.validate(instance=obj, schema=schema)

            _VALIDATOR = _validate
            log.info("jsonschema fallback validator ready for retention_rule schema")
            return _VALIDATOR
        except Exception as e:  # pragma: no cover
            log.error("No JSON Schema validator available: %s", e)
            raise HTTPException(status_code=500, detail={"message": "schema validator unavailable"})


def _validate_retention_rule(doc: Dict[str, Any]) -> None:
    validator = _compile_validator()
    validator(doc)


# ----------------------------------------------------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------------------------------------------------

def _canonical_json(d: Mapping[str, Any]) -> str:
    return json.dumps(d, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def _compute_etag(doc: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json(doc).encode("utf-8")).hexdigest()
    return f"\"{digest}\""  # strong ETag


def _last_modified_iso(meta: Mapping[str, Any]) -> Optional[str]:
    ts = meta.get("updatedAt") or meta.get("createdAt")
    if isinstance(ts, str):
        return ts
    try:
        # fallback to now if absent
        return dt.datetime.now(dt.timezone.utc).isoformat()
    except Exception:
        return None


def _json_merge_patch(target: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    """
    RFC 7396 JSON Merge Patch for dicts (lists are replaced as whole).
    """
    def _merge(t: Any, p: Any) -> Any:
        if p is None:
            return None  # caller decides key removal
        if isinstance(t, dict) and isinstance(p, dict):
            out = dict(t)
            for k, v in p.items():
                if v is None:
                    out.pop(k, None)
                else:
                    out[k] = _merge(t.get(k), v)
            return out
        return p

    return _merge(target, patch)


def _audit(event: str, principal: Principal, tenant_id: Optional[str], details: Dict[str, Any]) -> None:
    log.info(
        "audit event=%s tenant=%s actor=%s details=%s",
        event,
        tenant_id or "-",
        principal.subject,
        json.dumps(details, ensure_ascii=False),
    )


def _error(status_code: int, message: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"message": message, **extra})


# ----------------------------------------------------------------------------------------------------------------------
# FastAPI Router
# ----------------------------------------------------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/retention-rules", tags=["retention"])


# ----------------------------- Create -----------------------------

@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Created"},
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        409: {"description": "Conflict"},
    },
)
async def create_rule(
    request: Request,
    response: Response,
    body: Dict[str, Any],
    principal: Principal = Depends(get_principal),
    svc: RetentionService = Depends(get_retention_service),
):
    require_privileges(principal, ["policy:write"])

    try:
        _validate_retention_rule(body)
    except HTTPException:
        raise
    except Exception as e:
        raise _error(status.HTTP_400_BAD_REQUEST, f"schema validation failed: {e}")

    idem = request.headers.get("Idempotency-Key")
    try:
        created = await svc.create_rule(principal.tenant_id, body, idem)
    except RetentionService.ConflictError as e:
        raise _error(status.HTTP_409_CONFLICT, str(e))
    except ValueError as e:
        raise _error(status.HTTP_400_BAD_REQUEST, str(e))

    etag = _compute_etag(created)
    lm = _last_modified_iso(created.get("metadata", {}))
    response.headers["ETag"] = etag
    if lm:
        response.headers["Last-Modified"] = lm
    # Location uses rule name from metadata
    name = (created.get("metadata") or {}).get("name") or ""
    response.headers["Location"] = f"{request.url.path.rstrip('/')}/{name}"

    _audit("retention.create", principal, principal.tenant_id, {"name": name})
    return created


# ----------------------------- Get -----------------------------

@router.get(
    "/{name}",
    responses={
        200: {"description": "OK"},
        304: {"description": "Not Modified"},
        404: {"description": "Not Found"},
    },
)
async def get_rule(
    name: str,
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal),
    svc: RetentionService = Depends(get_retention_service),
):
    require_privileges(principal, ["policy:read"])

    try:
        rule = await svc.get_rule(principal.tenant_id, name)
    except KeyError:
        raise _error(status.HTTP_404_NOT_FOUND, "rule not found")

    etag = _compute_etag(rule)
    if_none_match = request.headers.get("If-None-Match")
    if if_none_match and if_none_match == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    response.headers["ETag"] = etag
    lm = _last_modified_iso(rule.get("metadata", {}))
    if lm:
        response.headers["Last-Modified"] = lm
    return rule


# ----------------------------- List -----------------------------

class ListFilters(BaseModel):
    namespace: Optional[str] = None
    tag: Optional[str] = None  # match any
    page_size: int = Field(ge=1, le=1000, default=100)
    page_token: Optional[str] = None


@router.get("")
async def list_rules(
    request: Request,
    response: Response,
    namespace: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None, description="Return rules that reference this tag in scope/retention"),
    page_size: int = Query(default=100, ge=1, le=1000),
    page_token: Optional[str] = Query(default=None),
    principal: Principal = Depends(get_principal),
    svc: RetentionService = Depends(get_retention_service),
):
    require_privileges(principal, ["policy:read"])

    filters: Dict[str, Any] = {}
    if namespace:
        filters["namespace"] = namespace
    if tag:
        filters["tag"] = tag

    items, next_token = await svc.list_rules(
        tenant_id=principal.tenant_id,
        page_size=page_size,
        page_token=page_token,
        filters=filters or None,
    )
    if next_token:
        response.headers["X-Next-Page-Token"] = next_token
    return {"items": items, "next_page_token": next_token}


# ----------------------------- Replace (PUT) -----------------------------

@router.put(
    "/{name}",
    responses={
        200: {"description": "Replaced"},
        201: {"description": "Created"},
        400: {"description": "Bad Request"},
        404: {"description": "Not Found"},
        409: {"description": "Conflict (If-Match)"},
        412: {"description": "Precondition Failed (If-Match required)"},
    },
)
async def replace_rule(
    name: str,
    request: Request,
    response: Response,
    body: Dict[str, Any],
    principal: Principal = Depends(get_principal),
    svc: RetentionService = Depends(get_retention_service),
):
    require_privileges(principal, ["policy:write"])

    try:
        _validate_retention_rule(body)
    except HTTPException:
        raise
    except Exception as e:
        raise _error(status.HTTP_400_BAD_REQUEST, f"schema validation failed: {e}")

    if_match = request.headers.get("If-Match")
    # For strict concurrency, require If-Match on existing resources.
    # Service can treat missing If-Match as create-if-absent semantics.
    idem = request.headers.get("Idempotency-Key")
    try:
        doc = await svc.replace_rule(principal.tenant_id, name, body, if_match, idem)
    except KeyError:
        # create as new if service chooses to; otherwise return 404
        raise _error(status.HTTP_404_NOT_FOUND, "rule not found")
    except RetentionService.ConflictError as e:
        raise _error(status.HTTP_409_CONFLICT, str(e))
    except ValueError as e:
        raise _error(status.HTTP_400_BAD_REQUEST, str(e))

    etag = _compute_etag(doc)
    response.headers["ETag"] = etag
    lm = _last_modified_iso(doc.get("metadata", {}))
    if lm:
        response.headers["Last-Modified"] = lm
    return doc


# ----------------------------- Patch (JSON Merge Patch) -----------------------------

@router.patch(
    "/{name}",
    responses={
        200: {"description": "Patched"},
        400: {"description": "Bad Request"},
        404: {"description": "Not Found"},
        409: {"description": "Conflict (If-Match)"},
    },
)
async def patch_rule(
    name: str,
    request: Request,
    response: Response,
    merge_patch: Dict[str, Any],
    principal: Principal = Depends(get_principal),
    svc: RetentionService = Depends(get_retention_service),
):
    require_privileges(principal, ["policy:write"])

    if_match = request.headers.get("If-Match")
    idem = request.headers.get("Idempotency-Key")

    # Service is responsible for loading, merging and persisting;
    # here we only ensure the resulting document remains schema-valid.
    try:
        doc = await svc.patch_rule(principal.tenant_id, name, merge_patch, if_match, idem)
        _validate_retention_rule(doc)
    except KeyError:
        raise _error(status.HTTP_404_NOT_FOUND, "rule not found")
    except RetentionService.ConflictError as e:
        raise _error(status.HTTP_409_CONFLICT, str(e))
    except ValueError as e:
        raise _error(status.HTTP_400_BAD_REQUEST, str(e))

    etag = _compute_etag(doc)
    response.headers["ETag"] = etag
    lm = _last_modified_iso(doc.get("metadata", {}))
    if lm:
        response.headers["Last-Modified"] = lm
    return doc


# ----------------------------- Delete -----------------------------

@router.delete(
    "/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        204: {"description": "No Content"},
        404: {"description": "Not Found"},
        409: {"description": "Conflict (If-Match)"},
    },
)
async def delete_rule(
    name: str,
    request: Request,
    hard: bool = Query(default=False, description="Hard delete (irreversible)"),
    principal: Principal = Depends(get_principal),
    svc: RetentionService = Depends(get_retention_service),
):
    require_privileges(principal, ["policy:write"])

    if_match = request.headers.get("If-Match")
    idem = request.headers.get("Idempotency-Key")

    try:
        await svc.delete_rule(principal.tenant_id, name, hard_delete=hard, if_match=if_match, idempotency_key=idem)
    except KeyError:
        raise _error(status.HTTP_404_NOT_FOUND, "rule not found")
    except RetentionService.ConflictError as e:
        raise _error(status.HTTP_409_CONFLICT, str(e))
    except ValueError as e:
        raise _error(status.HTTP_400_BAD_REQUEST, str(e))

    _audit("retention.delete", principal, principal.tenant_id, {"name": name, "hard": hard})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ----------------------------- Preview / Enforce -----------------------------

@router.post(
    "/{name}:preview",
    responses={
        200: {"description": "Preview plan"},
        404: {"description": "Not Found"},
    },
)
async def preview_enforcement(
    name: str,
    principal: Principal = Depends(get_principal),
    svc: RetentionService = Depends(get_retention_service),
):
    require_privileges(principal, ["policy:read"])
    try:
        plan = await svc.preview_enforcement(principal.tenant_id, name)
    except KeyError:
        raise _error(status.HTTP_404_NOT_FOUND, "rule not found")
    return plan


@router.post(
    "/{name}:enforce",
    responses={
        202: {"description": "Enforcement started"},
        404: {"description": "Not Found"},
    },
)
async def enforce_now(
    name: str,
    response: Response,
    principal: Principal = Depends(get_principal),
    svc: RetentionService = Depends(get_retention_service),
):
    require_privileges(principal, ["policy:write"])
    try:
        result = await svc.enforce_now(principal.tenant_id, name)
    except KeyError:
        raise _error(status.HTTP_404_NOT_FOUND, "rule not found")
    # Optional: return 202 for async job, include operation id
    response.status_code = status.HTTP_202_ACCEPTED
    return result
