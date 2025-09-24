# -*- coding: utf-8 -*-
"""
Industrial-grade validation router for policy-core.

Features:
- POST /v1/policies/{policy_id}:validate
- Input shape aligned with example.policy.yaml (Policy / PolicyBundle)
- JSON Schema validation (embedded default + override via env)
- Domain checks mirroring key rules (no :latest, signatures, secContext, resources)
- RFC 7807 error responses
- Correlation (X-Request-ID), structured logging (structlog if present)
- OpenTelemetry tracing if available
- Prometheus metrics (requests, duration, failures)
- Safe timeouts and request size limit
- Pluggable ValidatorEngine: add custom checks or external engines (e.g., OPA/rego, CEL)

Environment variables:
- POLICY_DSL_SCHEMA_PATH      path to JSON Schema file to validate DSL spec (optional)
- POLICY_VALIDATE_TIMEOUT_S   per-request timeout in seconds (default 5)
- POLICY_MAX_BODY_BYTES       max request body bytes (default 2_000_000 ≈ 2 MB)

This module is self-contained and degrades gracefully if optional libs absent.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, root_validator, validator

# Optional dependencies
try:
    import jsonschema
except Exception:  # pragma: no cover
    jsonschema = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore

try:  # OpenTelemetry is optional
    from opentelemetry import trace
    from opentelemetry.trace import SpanKind
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    SpanKind = None  # type: ignore

try:
    import structlog  # structured logging, optional
except Exception:  # pragma: no cover
    structlog = None  # type: ignore

try:
    import anyio
except Exception:  # pragma: no cover
    # FastAPI already depends on anyio; define fallback
    import asyncio as anyio  # type: ignore


# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

REQUEST_TIMEOUT_S = float(os.getenv("POLICY_VALIDATE_TIMEOUT_S", "5"))
MAX_BODY_BYTES = int(os.getenv("POLICY_MAX_BODY_BYTES", "2000000"))
SCHEMA_PATH = os.getenv("POLICY_DSL_SCHEMA_PATH", "").strip() or None

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

def _get_logger():
    if structlog:
        return structlog.get_logger("policy-core.validate")
    import logging
    logging.basicConfig(level=logging.INFO)
    return logging.getLogger("policy-core.validate")


log = _get_logger()

# ------------------------------------------------------------------------------
# Telemetry (Prometheus)
# ------------------------------------------------------------------------------

if Counter and Histogram:
    REQ_TOTAL = Counter(
        "policy_validate_requests_total",
        "Total number of validation requests",
        ["method", "route", "status"],
    )
    REQ_FAIL = Counter(
        "policy_validate_failures_total",
        "Total number of failed validation requests",
        ["reason"],
    )
    REQ_LATENCY = Histogram(
        "policy_validate_duration_seconds",
        "Validation duration seconds",
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
    )
else:  # graceful no-op
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_ , **__): return None
        def observe(self, *_, **__): return None
    REQ_TOTAL = REQ_FAIL = REQ_LATENCY = _Noop()

# ------------------------------------------------------------------------------
# Models (aligned with OpenAPI and example.policy.yaml)
# ------------------------------------------------------------------------------

class Owner(BaseModel):
    team: Optional[str] = None
    contact: Optional[str] = None

class Signature(BaseModel):
    format: Optional[str] = Field(None, regex=r"^(COSIGN|X509|PGP|JWS)$")
    value: Optional[str] = None
    keyId: Optional[str] = None

class PolicyMeta(BaseModel):
    id: str = Field(..., min_length=3)
    name: Optional[str] = None
    version: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    owners: Optional[List[Owner]] = None

class Policy(BaseModel):
    apiVersion: str = Field(..., regex=r"^policy\.aethernova\.io/")
    kind: str = Field(..., regex=r"^(Policy|PolicyBundle)$")
    metadata: PolicyMeta
    spec: Dict[str, Any]
    signature: Optional[Signature] = None

class ValidationErrorItem(BaseModel):
    code: str
    message: str
    path: Optional[str] = None

class ValidationResult(BaseModel):
    ok: bool
    errors: List[ValidationErrorItem] = []
    warnings: List[str] = []
    metrics: Dict[str, float] = {}

# ------------------------------------------------------------------------------
# JSON Schema (embedded minimal, can be overridden via POLICY_DSL_SCHEMA_PATH)
# This is a pragmatic, permissive schema focusing on presence and types.
# ------------------------------------------------------------------------------

_EMBEDDED_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "internal://schemas/policy-dsl-1.2.json",
    "type": "object",
    "required": ["apiVersion", "kind", "metadata", "spec"],
    "properties": {
        "apiVersion": {"type": "string", "pattern": r"^policy\.aethernova\.io/"},
        "kind": {"type": "string", "enum": ["Policy", "PolicyBundle"]},
        "metadata": {
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": {"type": "string", "minLength": 3},
                "name": {"type": "string"},
                "version": {"type": "string"},
                "labels": {"type": "object", "additionalProperties": {"type": "string"}},
                "owners": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"team": {"type": "string"}, "contact": {"type": "string"}},
                        "additionalProperties": False,
                    },
                },
            },
            "additionalProperties": True,
        },
        "spec": {"type": "object"},
        "signature": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["COSIGN", "X509", "PGP", "JWS"]},
                "value": {"type": "string"},
                "keyId": {"type": "string"},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}

def _load_json_schema() -> Optional[Dict[str, Any]]:
    if not jsonschema:
        return None
    if SCHEMA_PATH and os.path.isfile(SCHEMA_PATH):
        try:
            with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as e:  # pragma: no cover
            log.warning("Failed to load external schema %s: %s", SCHEMA_PATH, e)
    return _EMBEDDED_SCHEMA

# ------------------------------------------------------------------------------
# Domain validators
# ------------------------------------------------------------------------------

class ValidatorEngine:
    """
    Pluggable validation engine:
      - schema_validate: JSON Schema structural validation (if jsonschema exists)
      - domain_validate: domain checks mirroring core policy rules
      - external hooks: future OPA/CEL/WASM validators
    """

    def __init__(self, schema: Optional[Dict[str, Any]]):
        self._schema = schema
        if jsonschema and schema:
            self._validator = jsonschema.Draft202012Validator(schema)  # type: ignore[attr-defined]
        else:
            self._validator = None

    def schema_validate(self, policy: Dict[str, Any]) -> List[ValidationErrorItem]:
        if not self._validator:
            return []
        errors: List[ValidationErrorItem] = []
        for err in self._validator.iter_errors(policy):  # type: ignore[union-attr]
            path = "/".join([str(p) for p in err.path])
            errors.append(ValidationErrorItem(code="SCHEMA_VALIDATION", message=err.message, path=path or "/"))
        return errors

    def domain_validate(self, policy: Dict[str, Any]) -> Tuple[List[ValidationErrorItem], List[str]]:
        """
        Implements core domain checks inspired by example.policy.yaml:
          - ban :latest tag and require signatures when images list is present
          - require securityContext hardening if containers present
          - require resources requests/limits if containers present
          - optional label for egress profile (warn)
        """
        errors: List[ValidationErrorItem] = []
        warnings: List[str] = []

        api = policy.get("apiVersion", "")
        kind = policy.get("kind", "")
        spec = policy.get("spec", {}) or {}
        metadata = policy.get("metadata", {}) or {}

        # Check enforcement profile label for egress (warn)
        labels = (metadata.get("labels") or {}) if isinstance(metadata.get("labels"), dict) else {}
        if labels.get("policy.aethernova.io/egress-profile") != "public-https":
            warnings.append("policy.aethernova.io/egress-profile is not set to public-https")

        # Try to find containers in spec if this policy embeds k8s pod template-like data
        # Accept both 'containers' at root of spec or spec.template.spec.containers
        containers = []
        def _dig_containers(obj: Any) -> List[Dict[str, Any]]:
            if not isinstance(obj, dict):
                return []
            if "containers" in obj and isinstance(obj["containers"], list):
                return obj["containers"]
            # typical k8s shape
            tmpl = obj.get("template", {})
            if isinstance(tmpl, dict):
                podspec = tmpl.get("spec", {})
                if isinstance(podspec, dict) and isinstance(podspec.get("containers"), list):
                    return podspec["containers"]
            return []
        containers = _dig_containers(spec)

        # Supply chain checks
        for idx, c in enumerate(containers or []):
            img = str(c.get("image", "")).strip()
            if img.endswith(":latest") or img == "latest":
                errors.append(
                    ValidationErrorItem(
                        code="IMG_LATEST_FORBIDDEN",
                        message="Container image tag :latest is forbidden; pin by digest or fixed tag.",
                        path=f"spec/template/spec/containers/{idx}/image",
                    )
                )
            sigs = c.get("signatures")
            if sigs is not None:
                # If signatures list provided, require at least one valid
                valid_present = False
                if isinstance(sigs, list):
                    for s in sigs:
                        if isinstance(s, dict) and s.get("valid") is True:
                            valid_present = True
                            break
                if not valid_present:
                    errors.append(
                        ValidationErrorItem(
                            code="IMG_SIGNATURE_REQUIRED",
                            message="At least one valid signature required for container image.",
                            path=f"spec/template/spec/containers/{idx}/signatures",
                        )
                    )

            # Runtime hardening
            sc = c.get("securityContext") or {}
            if not (isinstance(sc, dict) and sc.get("runAsNonRoot") is True and sc.get("readOnlyRootFilesystem") is True):
                errors.append(
                    ValidationErrorItem(
                        code="SEC_CTX_HARDENING_REQUIRED",
                        message="runAsNonRoot=true and readOnlyRootFilesystem=true are required.",
                        path=f"spec/template/spec/containers/{idx}/securityContext",
                    )
                )
            caps = ((sc or {}).get("capabilities") or {}).get("drop")
            if not (isinstance(caps, list) and "ALL" in caps):
                errors.append(
                    ValidationErrorItem(
                        code="CAPS_DROP_ALL_REQUIRED",
                        message="securityContext.capabilities.drop must include 'ALL'.",
                        path=f"spec/template/spec/containers/{idx}/securityContext/capabilities/drop",
                    )
                )

            # Resources
            res = c.get("resources") or {}
            req = res.get("requests") or {}
            lim = res.get("limits") or {}
            if not (isinstance(req, dict) and req.get("cpu") and req.get("memory") and
                    isinstance(lim, dict) and lim.get("cpu") and lim.get("memory")):
                errors.append(
                    ValidationErrorItem(
                        code="RES_LIMITS_REQUIRED",
                        message="resources.requests/limits for cpu and memory are required for all containers.",
                        path=f"spec/template/spec/containers/{idx}/resources",
                    )
                )

        # Basic metadata sanity
        version = metadata.get("version")
        if version is not None and not str(version).strip():
            errors.append(
                ValidationErrorItem(
                    code="META_VERSION_INVALID",
                    message="metadata.version if present must be non-empty string.",
                    path="metadata/version",
                )
            )

        return errors, warnings


# ------------------------------------------------------------------------------
# RFC 7807 error response
# ------------------------------------------------------------------------------

def problem(
    status_code: int,
    title: str,
    detail: Optional[str] = None,
    type_: str = "about:blank",
    instance: Optional[str] = None,
    errors: Optional[List[Dict[str, Any]]] = None,
) -> JSONResponse:
    payload: Dict[str, Any] = {
        "type": type_,
        "title": title,
        "status": status_code,
    }
    if detail:
        payload["detail"] = detail
    if instance:
        payload["instance"] = instance
    if errors:
        payload["errors"] = errors
    return JSONResponse(status_code=status_code, content=payload, media_type="application/problem+json")


# ------------------------------------------------------------------------------
# Router and endpoint
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/v1", tags=["Validation"])

def _get_tracer():
    if trace:
        return trace.get_tracer("policy-core.validate")
    return None

def _enforce_body_limit(raw: bytes) -> None:
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Request body too large")

@router.post(
    "/policies/{policy_id}:validate",
    response_model=ValidationResult,
    responses={
        400: {"model": None, "content": {"application/problem+json": {}}},
        413: {"model": None, "content": {"application/problem+json": {}}},
        422: {"model": None, "content": {"application/problem+json": {}}},
        500: {"model": None, "content": {"application/problem+json": {}}},
    },
)
async def validate_policy(
    request: Request,
    policy_id: str = Path(..., min_length=3, regex=r"^[A-Za-z0-9._\-:/]+$"),
) -> ValidationResult:
    """
    Validate policy payload against JSON Schema and domain rules.
    Returns ValidationResult with ok/errors/warnings/metrics.
    """
    t0 = time.perf_counter()
    tracer = _get_tracer()
    span = None
    if tracer and SpanKind:
        span = tracer.start_span("validate_policy", kind=SpanKind.SERVER)
        span.set_attribute("policy.id", policy_id)

    # Correlation
    req_id = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID")
    if not req_id:
        # generate simple correlation id if none provided
        req_id = f"req-{int(time.time() * 1e6)}"
    # parse body with size guard and timeout
    try:
        with anyio.move_on_after(REQUEST_TIMEOUT_S) as scope:
            raw = await request.body()
            _enforce_body_limit(raw)
            data = json.loads(raw.decode("utf-8"))
        if scope.cancel_called:
            REQ_FAIL.labels("timeout").inc()
            return ValidationResult(
                ok=False,
                errors=[ValidationErrorItem(code="TIMEOUT", message="Validation timed out", path=None)],
                warnings=[],
                metrics={"duration_s": REQUEST_TIMEOUT_S},
            )
    except HTTPException as he:
        REQ_TOTAL.labels("POST", "/v1/policies/{policy_id}:validate", str(he.status_code)).inc()
        return problem(he.status_code, "Request rejected", detail=he.detail)  # type: ignore[return-value]
    except json.JSONDecodeError as je:
        REQ_TOTAL.labels("POST", "/v1/policies/{policy_id}:validate", "400").inc()
        return problem(400, "Invalid JSON", detail=str(je))  # type: ignore[return-value]
    except Exception as e:  # pragma: no cover
        REQ_TOTAL.labels("POST", "/v1/policies/{policy_id}:validate", "500").inc()
        log.exception("Unexpected error while reading request")
        return problem(500, "Internal Server Error", detail="unexpected error")  # type: ignore[return-value]

    # Basic sanity: path id should match body metadata.id (if provided)
    body_meta_id = None
    try:
        body_meta_id = (data.get("metadata") or {}).get("id")
    except Exception:
        body_meta_id = None
    if body_meta_id and str(body_meta_id) != policy_id:
        REQ_TOTAL.labels("POST", "/v1/policies/{policy_id}:validate", "422").inc()
        return problem(
            422,
            "Policy ID mismatch",
            detail=f"Path id '{policy_id}' does not match metadata.id '{body_meta_id}'",
            type_="https://httpstatuses.com/422",
        )  # type: ignore[return-value]

    # Execute validation
    schema = _load_json_schema()
    engine = ValidatorEngine(schema=schema)

    schema_errors = engine.schema_validate(data)
    domain_errors, warnings = engine.domain_validate(data)

    ok = not schema_errors and not domain_errors
    duration = time.perf_counter() - t0

    if span:
        span.set_attribute("validation.ok", ok)
        span.set_attribute("validation.errors", len(schema_errors) + len(domain_errors))
        span.set_attribute("validation.warnings", len(warnings))
        span.end()

    REQ_TOTAL.labels("POST", "/v1/policies/{policy_id}:validate", "200" if ok else "200").inc()
    REQ_LATENCY.observe(duration)
    headers = {"X-Request-ID": req_id}

    result = ValidationResult(
        ok=ok,
        errors=[*schema_errors, *domain_errors],
        warnings=warnings,
        metrics={
            "duration_s": round(duration, 6),
            "schema_enabled": 1.0 if schema is not None and jsonschema else 0.0,
            "rules_checked": float(4),  # update when adding more domain rules
        },
    )
    return JSONResponse(status_code=200, content=json.loads(result.json()), headers=headers)
