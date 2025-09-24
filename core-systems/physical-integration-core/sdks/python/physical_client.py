# sdks/python/physical_client.py
# Industrial-grade Python SDK for physical-integration-core
# Python 3.10+
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Literal, Mapping, Optional, Tuple, Union

try:
    import httpx
except ImportError as e:
    raise ImportError("httpx is required: pip install httpx>=0.24") from e

try:
    # pydantic v2
    from pydantic import BaseModel, Field, ConfigDict, ValidationError, field_validator
    PydanticV2 = True
except Exception:
    # fallback to v1 names for runtime compatibility
    from pydantic import BaseModel, Field, ValidationError, validator as field_validator  # type: ignore
    PydanticV2 = False  # noqa: N816

__all__ = [
    "PhysicalClient",
    "AsyncPhysicalClient",
    "ClientConfig",
    "ApiError",
    "HTTPError",
    "ValidationFault",
    "CalibrationSession",
    "CalibrationProcedure",
    "CalibrationPoint",
    "Artifact",
    "CalibrationCertificate",
]

log = logging.getLogger("physical_client")
log.addHandler(logging.NullHandler())

# ------------------------------
# Configuration and constants
# ------------------------------

DEFAULT_TIMEOUT = 10.0  # seconds
DEFAULT_TOTAL_TIMEOUT = 30.0  # seconds upper bound for retries
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_BASE = 0.2  # seconds
DEFAULT_BACKOFF_FACTOR = 2.0
DEFAULT_USER_AGENT = "physical-integration-sdk/1.0 (+https://aethernova.example)"

# NOTE: Конкретные REST пути могут отличаться от вашей реализации API.
# Отредактируйте под свой gateway. I cannot verify this.
ENDPOINTS = {
    "create_session": "/v1/calibration/sessions",
    "get_session": "/v1/calibration/sessions/{session_id}",
    "list_sessions": "/v1/calibration/sessions",
    "start_session": "/v1/calibration/sessions/{session_id}:start",
    "abort_session": "/v1/calibration/sessions/{session_id}:abort",
    "finalize_session": "/v1/calibration/sessions/{session_id}:finalize",

    "create_procedure": "/v1/calibration/sessions/{session_id}/procedures",
    "update_procedure": "/v1/calibration/sessions/{session_id}/procedures/{procedure_id}",
    "start_procedure": "/v1/calibration/sessions/{session_id}/procedures/{procedure_id}:start",
    "complete_procedure": "/v1/calibration/sessions/{session_id}/procedures/{procedure_id}:complete",

    "submit_point": "/v1/calibration/sessions/{session_id}/procedures/{procedure_id}/points",
    "upload_artifact": "/v1/calibration/sessions/{session_id}/procedures/{procedure_id}/artifacts",
    "issue_certificate": "/v1/calibration/sessions/{session_id}:issueCertificate",
    "revoke_certificate": "/v1/calibration/certificates/{certificate_id}:revoke",
}

# ------------------------------
# Exceptions
# ------------------------------


class ApiError(Exception):
    """Base SDK error."""

    def __init__(self, message: str, *, context: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message)
        self.context = dict(context or {})


class HTTPError(ApiError):
    """HTTP-level error."""

    def __init__(
        self,
        status_code: int,
        message: str,
        *,
        error_code: Optional[str] = None,
        request_id: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> None:
        ctx = dict(context or {})
        ctx.update({"status_code": status_code, "error_code": error_code, "request_id": request_id})
        super().__init__(message, context=ctx)
        self.status_code = status_code
        self.error_code = error_code
        self.request_id = request_id


class ValidationFault(ApiError):
    """Raised when local model validation fails."""


# ------------------------------
# Models (align with proto semantics)
# ------------------------------


class Labels(BaseModel):
    if PydanticV2:
        model_config = ConfigDict(extra="allow")
    items: Dict[str, str] = Field(default_factory=dict)


class Quantity(BaseModel):
    value: float
    unit_ucum: str


class EnvironmentSnapshot(BaseModel):
    at: Optional[str] = None  # RFC3339 timestamp
    temperature: Optional[Quantity] = None
    humidity: Optional[Quantity] = None
    pressure: Optional[Quantity] = None
    supply_voltage: Optional[Quantity] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class CalibrationPoint(BaseModel):
    at: Optional[str] = None
    expected: Quantity
    observed: Quantity
    deviation: Optional[Quantity] = None
    within_tolerance: Optional[bool] = None
    env: Optional[EnvironmentSnapshot] = None
    note: Optional[str] = None


class Artifact(BaseModel):
    id: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    content_type: Optional[str] = None
    size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    storage_uri: Optional[str] = None
    created_at: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)


class CalibrationProcedure(BaseModel):
    id: Optional[str] = None
    type: str
    description: Optional[str] = None
    target_sensors: List[Dict[str, Any]] = Field(default_factory=list)  # {sensor_id, kind, channel}
    parameters: Dict[str, Any] = Field(default_factory=dict)
    tolerances: Dict[str, Any] = Field(default_factory=dict)
    status: Optional[str] = None
    scheduled_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    operator: Optional[str] = None
    points: List[CalibrationPoint] = Field(default_factory=list)
    artifacts: List[Artifact] = Field(default_factory=list)
    events: List[Dict[str, Any]] = Field(default_factory=list)


class CalibrationCertificate(BaseModel):
    id: Optional[str] = None
    session_id: Optional[str] = None
    serial: Optional[str] = None
    issuer: Optional[str] = None
    issued_at: Optional[str] = None
    valid_until: Optional[str] = None
    pem_cert: Optional[str] = None
    data: Dict[str, str] = Field(default_factory=dict)
    attachments: List[Artifact] = Field(default_factory=list)


class CalibrationSession(BaseModel):
    id: Optional[str] = None
    tenant_id: Optional[str] = None
    project_id: Optional[str] = None
    device: Dict[str, Any] = Field(default_factory=dict)
    sensors: List[Dict[str, Any]] = Field(default_factory=list)
    requested_by: Optional[str] = None
    goal: Optional[str] = None
    status: Optional[str] = None
    created_at: Optional[str] = None
    scheduled_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    version: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    procedures: List[CalibrationProcedure] = Field(default_factory=list)
    certificate: Optional[CalibrationCertificate] = None


# ------------------------------
# Client configuration dataclass
# ------------------------------

@dataclass(frozen=True)
class ClientConfig:
    base_url: str
    token: Optional[str] = None            # Bearer JWT/OAuth2
    api_key: Optional[str] = None          # Optional API-key auth
    timeout: float = DEFAULT_TIMEOUT
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT
    retries: int = DEFAULT_RETRIES
    backoff_base: float = DEFAULT_BACKOFF_BASE
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR
    verify_tls: Union[bool, str] = True    # CA bundle path or True/False
    user_agent: str = DEFAULT_USER_AGENT
    default_headers: Mapping[str, str] | None = None


# ------------------------------
# Base request machinery
# ------------------------------

class _BaseClient:
    def __init__(self, cfg: ClientConfig) -> None:
        self.cfg = cfg
        self._closed = False

    # --- auth & headers

    def _build_headers(
        self,
        *,
        request_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        extra: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "User-Agent": self.cfg.user_agent,
            "Accept": "application/json",
        }
        if self.cfg.default_headers:
            headers.update(self.cfg.default_headers)
        if self.cfg.token:
            headers["Authorization"] = f"Bearer {self.cfg.token}"
        if self.cfg.api_key:
            headers["X-API-Key"] = self.cfg.api_key
        headers["X-Request-ID"] = request_id or str(uuid.uuid4())
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if extra:
            headers.update(extra)
        return headers

    # --- retry/backoff

    def _sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    async def _asleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    @staticmethod
    def _calc_backoff(attempt: int, base: float, factor: float) -> float:
        return min(30.0, base * (factor ** max(0, attempt - 1)))

    # --- helpers

    @staticmethod
    def _encode_params(params: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        if not params:
            return {}
        out: Dict[str, Any] = {}
        for k, v in params.items():
            if v is None:
                continue
            out[k] = json.dumps(v) if isinstance(v, (dict, list)) else v
        return out

    @staticmethod
    def _handle_error(
        resp: httpx.Response,
        *,
        body: Optional[Dict[str, Any]] = None,
    ) -> None:
        request_id = resp.headers.get("X-Request-ID")
        status = resp.status_code
        message = f"HTTP {status}"
        error_code = None
        try:
            payload = body or resp.json()
            # common error shapes
            if isinstance(payload, dict):
                error_code = payload.get("error", {}).get("code") or payload.get("code")
                detail = payload.get("error", {}).get("message") or payload.get("message")
                if detail:
                    message = f"{message}: {detail}"
        except Exception:
            pass
        raise HTTPError(status, message, error_code=error_code, request_id=request_id, context={"url": str(resp.request.url)})

    @staticmethod
    def _validate_model(model_cls: type[BaseModel], data: Mapping[str, Any]) -> Any:
        try:
            return model_cls.model_validate(data) if PydanticV2 else model_cls.parse_obj(data)  # type: ignore[attr-defined]
        except ValidationError as ve:
            raise ValidationFault("Response validation failed", context={"errors": ve.errors()}) from ve


# ------------------------------
# Sync client
# ------------------------------

class PhysicalClient(_BaseClient):
    """
    Synchronous client for physical-integration-core.
    """

    def __init__(self, cfg: ClientConfig) -> None:
        super().__init__(cfg)
        self._client = httpx.Client(
            base_url=cfg.base_url.rstrip("/"),
            timeout=httpx.Timeout(cfg.timeout, read=cfg.timeout, write=cfg.timeout, connect=cfg.timeout),
            verify=cfg.verify_tls,
            headers=self._build_headers(),
        )

    # context manager
    def __enter__(self) -> "PhysicalClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._client.close()
            self._closed = True

    # core request method with retries
    def _request(
        self,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        files: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> httpx.Response:
        attempt = 0
        start = time.time()
        while True:
            attempt += 1
            hdrs = self._build_headers(idempotency_key=idempotency_key)
            if headers:
                hdrs.update(headers)
            try:
                resp = self._client.request(
                    method,
                    url,
                    params=self._encode_params(params),
                    json=json_body,
                    files=files,
                    headers=hdrs,
                )
                if 200 <= resp.status_code < 300:
                    return resp
                # Retry on common transient codes
                if resp.status_code in (408, 429, 500, 502, 503, 504):
                    if attempt <= self.cfg.retries and (time.time() - start) < self.cfg.total_timeout:
                        backoff = self._calc_backoff(attempt, self.cfg.backoff_base, self.cfg.backoff_factor)
                        log.warning("Retryable status %s on %s %s. Attempt %d. Sleeping %.2fs", resp.status_code, method, url, attempt, backoff)
                        self._sleep(backoff)
                        continue
                # non-retryable or retries exhausted
                self._handle_error(resp)
            except (httpx.TransportError, httpx.TimeoutException) as e:
                if attempt <= self.cfg.retries and (time.time() - start) < self.cfg.total_timeout:
                    backoff = self._calc_backoff(attempt, self.cfg.backoff_base, self.cfg.backoff_factor)
                    log.warning("Transport error on %s %s: %s. Attempt %d. Sleeping %.2fs", method, url, e, attempt, backoff)
                    self._sleep(backoff)
                    continue
                raise HTTPError(0, f"Transport error: {e}", context={"url": url}) from e

    # ------------- API methods -------------

    # Sessions
    def create_session(self, session: CalibrationSession, *, idempotency_key: Optional[str] = None) -> CalibrationSession:
        ep = ENDPOINTS["create_session"]
        payload = session.model_dump(exclude_none=True) if PydanticV2 else session.dict(exclude_none=True)  # type: ignore
        resp = self._request("POST", ep, json_body=payload, idempotency_key=idempotency_key or str(uuid.uuid4()))
        return self._validate_model(CalibrationSession, resp.json())

    def get_session(self, session_id: str) -> CalibrationSession:
        ep = ENDPOINTS["get_session"].format(session_id=session_id)
        resp = self._request("GET", ep)
        return self._validate_model(CalibrationSession, resp.json())

    def list_sessions(
        self,
        *,
        tenant_id: Optional[str] = None,
        device_id: Optional[str] = None,
        status: Optional[str] = None,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
        page_size: int = 100,
    ) -> Iterator[CalibrationSession]:
        params: Dict[str, Any] = {
            "tenant_id": tenant_id,
            "device_id": device_id,
            "status": status,
            "created_after": created_after,
            "created_before": created_before,
            "page_size": page_size,
        }
        next_token: Optional[str] = None
        while True:
            if next_token:
                params["page_token"] = next_token
            resp = self._request("GET", ENDPOINTS["list_sessions"], params=params)
            data = resp.json()
            items = data.get("items", [])
            for it in items:
                yield self._validate_model(CalibrationSession, it)
            next_token = data.get("next_page_token")
            if not next_token:
                break

    def start_session(self, session_id: str) -> CalibrationSession:
        ep = ENDPOINTS["start_session"].format(session_id=session_id)
        resp = self._request("POST", ep)
        return self._validate_model(CalibrationSession, resp.json())

    def abort_session(self, session_id: str, reason: Optional[str] = None) -> CalibrationSession:
        ep = ENDPOINTS["abort_session"].format(session_id=session_id)
        body = {"reason": reason} if reason else None
        resp = self._request("POST", ep, json_body=body)
        return self._validate_model(CalibrationSession, resp.json())

    def finalize_session(self, session_id: str) -> CalibrationSession:
        ep = ENDPOINTS["finalize_session"].format(session_id=session_id)
        resp = self._request("POST", ep)
        return self._validate_model(CalibrationSession, resp.json())

    # Procedures
    def create_procedure(self, session_id: str, proc: CalibrationProcedure, *, idempotency_key: Optional[str] = None) -> CalibrationProcedure:
        ep = ENDPOINTS["create_procedure"].format(session_id=session_id)
        payload = proc.model_dump(exclude_none=True) if PydanticV2 else proc.dict(exclude_none=True)  # type: ignore
        resp = self._request("POST", ep, json_body=payload, idempotency_key=idempotency_key or str(uuid.uuid4()))
        return self._validate_model(CalibrationProcedure, resp.json())

    def update_procedure(self, session_id: str, procedure_id: str, proc: CalibrationProcedure) -> CalibrationProcedure:
        ep = ENDPOINTS["update_procedure"].format(session_id=session_id, procedure_id=procedure_id)
        payload = proc.model_dump(exclude_none=True) if PydanticV2 else proc.dict(exclude_none=True)  # type: ignore
        resp = self._request("PUT", ep, json_body=payload)
        return self._validate_model(CalibrationProcedure, resp.json())

    def start_procedure(self, session_id: str, procedure_id: str) -> CalibrationProcedure:
        ep = ENDPOINTS["start_procedure"].format(session_id=session_id, procedure_id=procedure_id)
        resp = self._request("POST", ep)
        return self._validate_model(CalibrationProcedure, resp.json())

    def complete_procedure(self, session_id: str, procedure_id: str) -> CalibrationProcedure:
        ep = ENDPOINTS["complete_procedure"].format(session_id=session_id, procedure_id=procedure_id)
        resp = self._request("POST", ep)
        return self._validate_model(CalibrationProcedure, resp.json())

    # Points
    def submit_point(self, session_id: str, procedure_id: str, point: CalibrationPoint, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        ep = ENDPOINTS["submit_point"].format(session_id=session_id, procedure_id=procedure_id)
        payload = point.model_dump(exclude_none=True) if PydanticV2 else point.dict(exclude_none=True)  # type: ignore
        resp = self._request("POST", ep, json_body=payload, idempotency_key=idempotency_key or str(uuid.uuid4()))
        return resp.json()

    # Artifacts
    def upload_artifact(
        self,
        session_id: str,
        procedure_id: str,
        file_path: str,
        *,
        name: Optional[str] = None,
        content_type: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        sha256: Optional[str] = None,
    ) -> Artifact:
        ep = ENDPOINTS["upload_artifact"].format(session_id=session_id, procedure_id=procedure_id)
        name = name or os.path.basename(file_path)
        files = {
            "file": (name, open(file_path, "rb"), content_type or "application/octet-stream"),
            "metadata": (None, json.dumps({"labels": labels or {}, "sha256": sha256}), "application/json"),
        }
        resp = self._request("POST", ep, files=files, headers={"Accept": "application/json"})
        return self._validate_model(Artifact, resp.json())

    # Certificates
    def issue_certificate(self, session_id: str, *, template_id: Optional[str] = None, valid_for_seconds: Optional[int] = None) -> CalibrationCertificate:
        ep = ENDPOINTS["issue_certificate"].format(session_id=session_id)
        body = {
            "template_id": template_id,
            "valid_for": {"seconds": valid_for_seconds} if valid_for_seconds else None,
        }
        resp = self._request("POST", ep, json_body={k: v for k, v in body.items() if v is not None})
        return self._validate_model(CalibrationCertificate, resp.json())

    def revoke_certificate(self, certificate_id: str, *, reason: Optional[str] = None) -> CalibrationCertificate:
        ep = ENDPOINTS["revoke_certificate"].format(certificate_id=certificate_id)
        body = {"reason": reason} if reason else None
        resp = self._request("POST", ep, json_body=body)
        return self._validate_model(CalibrationCertificate, resp.json())

    # Streaming (placeholder; prefer gRPC client if stubs are available)
    def stream_live_metrics_not_implemented(self) -> None:
        raise ApiError("Live metrics streaming is not implemented for HTTP; use gRPC stubs if available.")


# ------------------------------
# Async client
# ------------------------------

class AsyncPhysicalClient(_BaseClient):
    """
    Asynchronous client for physical-integration-core.
    """

    def __init__(self, cfg: ClientConfig) -> None:
        super().__init__(cfg)
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            timeout=httpx.Timeout(cfg.timeout, read=cfg.timeout, write=cfg.timeout, connect=cfg.timeout),
            verify=cfg.verify_tls,
            headers=self._build_headers(),
        )

    async def aclose(self) -> None:
        if not self._closed:
            await self._client.aclose()
            self._closed = True

    async def __aenter__(self) -> "AsyncPhysicalClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def _request(
        self,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        files: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> httpx.Response:
        attempt = 0
        start = time.time()
        while True:
            attempt += 1
            hdrs = self._build_headers(idempotency_key=idempotency_key)
            if headers:
                hdrs.update(headers)
            try:
                resp = await self._client.request(
                    method,
                    url,
                    params=self._encode_params(params),
                    json=json_body,
                    files=files,
                    headers=hdrs,
                )
                if 200 <= resp.status_code < 300:
                    return resp
                if resp.status_code in (408, 429, 500, 502, 503, 504):
                    if attempt <= self.cfg.retries and (time.time() - start) < self.cfg.total_timeout:
                        backoff = self._calc_backoff(attempt, self.cfg.backoff_base, self.cfg.backoff_factor)
                        log.warning("Retryable status %s on %s %s. Attempt %d. Sleeping %.2fs", resp.status_code, method, url, attempt, backoff)
                        await self._asleep(backoff)
                        continue
                self._handle_error(resp)
            except (httpx.TransportError, httpx.TimeoutException) as e:
                if attempt <= self.cfg.retries and (time.time() - start) < self.cfg.total_timeout:
                    backoff = self._calc_backoff(attempt, self.cfg.backoff_base, self.cfg.backoff_factor)
                    log.warning("Transport error on %s %s: %s. Attempt %d. Sleeping %.2fs", method, url, e, attempt, backoff)
                    await self._asleep(backoff)
                    continue
                raise HTTPError(0, f"Transport error: {e}", context={"url": url}) from e

    # ---- API (async variants) ----

    async def create_session(self, session: CalibrationSession, *, idempotency_key: Optional[str] = None) -> CalibrationSession:
        ep = ENDPOINTS["create_session"]
        payload = session.model_dump(exclude_none=True) if PydanticV2 else session.dict(exclude_none=True)  # type: ignore
        resp = await self._request("POST", ep, json_body=payload, idempotency_key=idempotency_key or str(uuid.uuid4()))
        return self._validate_model(CalibrationSession, resp.json())

    async def get_session(self, session_id: str) -> CalibrationSession:
        ep = ENDPOINTS["get_session"].format(session_id=session_id)
        resp = await self._request("GET", ep)
        return self._validate_model(CalibrationSession, resp.json())

    async def list_sessions(
        self,
        *,
        tenant_id: Optional[str] = None,
        device_id: Optional[str] = None,
        status: Optional[str] = None,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
        page_size: int = 100,
    ) -> AsyncIterator[CalibrationSession]:  # type: ignore[name-defined]
        params: Dict[str, Any] = {
            "tenant_id": tenant_id,
            "device_id": device_id,
            "status": status,
            "created_after": created_after,
            "created_before": created_before,
            "page_size": page_size,
        }
        next_token: Optional[str] = None
        while True:
            if next_token:
                params["page_token"] = next_token
            resp = await self._request("GET", ENDPOINTS["list_sessions"], params=params)
            data = resp.json()
            for it in data.get("items", []):
                yield self._validate_model(CalibrationSession, it)
            next_token = data.get("next_page_token")
            if not next_token:
                break

    async def start_session(self, session_id: str) -> CalibrationSession:
        ep = ENDPOINTS["start_session"].format(session_id=session_id)
        resp = await self._request("POST", ep)
        return self._validate_model(CalibrationSession, resp.json())

    async def abort_session(self, session_id: str, reason: Optional[str] = None) -> CalibrationSession:
        ep = ENDPOINTS["abort_session"].format(session_id=session_id)
        body = {"reason": reason} if reason else None
        resp = await self._request("POST", ep, json_body=body)
        return self._validate_model(CalibrationSession, resp.json())

    async def finalize_session(self, session_id: str) -> CalibrationSession:
        ep = ENDPOINTS["finalize_session"].format(session_id=session_id)
        resp = await self._request("POST", ep)
        return self._validate_model(CalibrationSession, resp.json())

    async def create_procedure(self, session_id: str, proc: CalibrationProcedure, *, idempotency_key: Optional[str] = None) -> CalibrationProcedure:
        ep = ENDPOINTS["create_procedure"].format(session_id=session_id)
        payload = proc.model_dump(exclude_none=True) if PydanticV2 else proc.dict(exclude_none=True)  # type: ignore
        resp = await self._request("POST", ep, json_body=payload, idempotency_key=idempotency_key or str(uuid.uuid4()))
        return self._validate_model(CalibrationProcedure, resp.json())

    async def update_procedure(self, session_id: str, procedure_id: str, proc: CalibrationProcedure) -> CalibrationProcedure:
        ep = ENDPOINTS["update_procedure"].format(session_id=session_id, procedure_id=procedure_id)
        payload = proc.model_dump(exclude_none=True) if PydanticV2 else proc.dict(exclude_none=True)  # type: ignore
        resp = await self._request("PUT", ep, json_body=payload)
        return self._validate_model(CalibrationProcedure, resp.json())

    async def start_procedure(self, session_id: str, procedure_id: str) -> CalibrationProcedure:
        ep = ENDPOINTS["start_procedure"].format(session_id=session_id, procedure_id=procedure_id)
        resp = await self._request("POST", ep)
        return self._validate_model(CalibrationProcedure, resp.json())

    async def complete_procedure(self, session_id: str, procedure_id: str) -> CalibrationProcedure:
        ep = ENDPOINTS["complete_procedure"].format(session_id=session_id, procedure_id=procedure_id)
        resp = await self._request("POST", ep)
        return self._validate_model(CalibrationProcedure, resp.json())

    async def submit_point(self, session_id: str, procedure_id: str, point: CalibrationPoint, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        ep = ENDPOINTS["submit_point"].format(session_id=session_id, procedure_id=procedure_id)
        payload = point.model_dump(exclude_none=True) if PydanticV2 else point.dict(exclude_none=True)  # type: ignore
        resp = await self._request("POST", ep, json_body=payload, idempotency_key=idempotency_key or str(uuid.uuid4()))
        return resp.json()

    async def upload_artifact(
        self,
        session_id: str,
        procedure_id: str,
        file_path: str,
        *,
        name: Optional[str] = None,
        content_type: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        sha256: Optional[str] = None,
    ) -> Artifact:
        ep = ENDPOINTS["upload_artifact"].format(session_id=session_id, procedure_id=procedure_id)
        name = name or os.path.basename(file_path)
        files = {
            "file": (name, open(file_path, "rb"), content_type or "application/octet-stream"),
            "metadata": (None, json.dumps({"labels": labels or {}, "sha256": sha256}), "application/json"),
        }
        resp = await self._request("POST", ep, files=files, headers={"Accept": "application/json"})
        return self._validate_model(Artifact, resp.json())

    async def issue_certificate(self, session_id: str, *, template_id: Optional[str] = None, valid_for_seconds: Optional[int] = None) -> CalibrationCertificate:
        ep = ENDPOINTS["issue_certificate"].format(session_id=session_id)
        body = {
            "template_id": template_id,
            "valid_for": {"seconds": valid_for_seconds} if valid_for_seconds else None,
        }
        resp = await self._request("POST", ep, json_body={k: v for k, v in body.items() if v is not None})
        return self._validate_model(CalibrationCertificate, resp.json())

    async def revoke_certificate(self, certificate_id: str, *, reason: Optional[str] = None) -> CalibrationCertificate:
        ep = ENDPOINTS["revoke_certificate"].format(certificate_id=certificate_id)
        body = {"reason": reason} if reason else None
        resp = await self._request("POST", ep, json_body=body)
        return self._validate_model(CalibrationCertificate, resp.json())

    # Streaming placeholder
    async def stream_live_metrics_not_implemented(self) -> None:
        raise ApiError("Live metrics streaming is not implemented for HTTP; use gRPC stubs if available.")


# ------------------------------
# Optional gRPC helper (if stubs exist)
# ------------------------------

def grpc_available() -> bool:
    try:
        import grpc  # noqa: F401
        from aethernova.physical.v1 import calibration_pb2_grpc  # type: ignore  # noqa: F401
        return True
    except Exception:
        return False
