# -*- coding: utf-8 -*-
"""
policy-core API v1 — Pydantic schemas (industrial edition)

Назначение:
- Строгие модели запросов/ответов для HTTP API v1: /v1/decide, /v1/decide:batch, /health
- Совместимость с Pydantic v2 (с fallback для v1)
- Встроенные валидации: ISO8601-даты, перечисления, SemVer-подобные ревизии, integrity (SHA-256)
- Канонизация тела запроса при проверке integrity (исключается поле "integrity")

Примечания:
- Модули FastAPI/Starlette могут использовать эти модели напрямую.
- Поле integrity {alg:"sha256", hash:"..."} опционально; если задано, будет проверено.
- API версии и kind фиксированы: apiVersion="policy-core/v1", kind в Decision*.

Автор: Aethernova / policy-core
Лицензия: MIT
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple, Union

# ----------------------------- Pydantic bridge ------------------------------

try:
    # Pydantic v2
    from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
    PYDANTIC_V2 = True
except Exception:  # pragma: no cover - fallback for environments with v1
    from pydantic import BaseModel, Field, validator as field_validator, root_validator as model_validator  # type: ignore
    PYDANTIC_V2 = False  # type: ignore


# ----------------------------- Constants & Regex -----------------------------

API_VERSION = "policy-core/v1"
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")
ISO_DT_HINT = "YYYY-MM-DDThh:mm:ssZ"
IGNORED_INTEGRITY_KEYS = {"integrity"}  # при канонизации тела

DecisionEffect = Literal["Permit", "Deny"]
ExplainMode = Literal["off", "summary", "full"]  # "trace" допускается на входе как псевдо-режим

RequestedDecision = Literal["permit", "explain", "obligations"]


# ----------------------------- Utilities ------------------------------------

def _iso8601_or_none(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    # Допускаем Z/UTC и смещения
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value
    except Exception as e:
        raise ValueError(f"Invalid ISO8601 datetime '{value}', expected like {ISO_DT_HINT}") from e


def _canonicalize(obj: Any) -> Any:
    """
    Канонизация для стабильного хеша:
    - словари сортируются по ключам;
    - исключаем поля из IGNORED_INTEGRITY_KEYS;
    - списки канонизируются рекурсивно;
    - остальные типы возвращаются как есть.
    """
    if isinstance(obj, dict):
        items = [(k, v) for k, v in sorted(obj.items(), key=lambda kv: kv[0]) if k not in IGNORED_INTEGRITY_KEYS]
        return {k: _canonicalize(v) for k, v in items}
    if isinstance(obj, list):
        return [_canonicalize(v) for v in obj]
    return obj


def compute_integrity_sha256(payload: Dict[str, Any]) -> str:
    canon = _canonicalize(payload)
    blob = json.dumps(canon, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ----------------------------- Base model -----------------------------------

class PCBaseModel(BaseModel):
    """Общая конфигурация для всех моделей."""
    if PYDANTIC_V2:  # pydantic v2
        model_config = ConfigDict(extra="forbid", str_strip_whitespace=False, arbitrary_types_allowed=True)
    else:  # pydantic v1
        class Config:  # type: ignore
            extra = "forbid"
            anystr_strip_whitespace = False
            arbitrary_types_allowed = True


# ----------------------------- Shared types ----------------------------------

class Subject(PCBaseModel):
    id: str = Field(..., min_length=1, max_length=253)
    type: Optional[str] = Field(default=None, min_length=1, max_length=64)
    roles: Optional[List[str]] = None
    groups: Optional[List[str]] = None
    attributes: Optional[Dict[str, Any]] = None
    mfa: Optional[Dict[str, Any]] = None

class Resource(PCBaseModel):
    id: str = Field(..., min_length=1, max_length=253)
    type: str = Field(..., min_length=1, max_length=64)
    urn: Optional[str] = Field(default=None, min_length=1, max_length=512)
    ownerId: Optional[str] = Field(default=None, min_length=1, max_length=200)
    collection: Optional[str] = Field(default=None, min_length=1, max_length=100)
    path: Optional[str] = Field(default=None, min_length=1, max_length=2048)
    labels: Optional[Dict[str, str]] = None
    classification: Optional[str] = Field(default=None, min_length=1, max_length=64)
    createdAt: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None

    @field_validator("createdAt")
    def _created_at_iso(cls, v: Optional[str]) -> Optional[str]:
        return _iso8601_or_none(v)

class Action(PCBaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    operation: Optional[str] = Field(default=None, min_length=1, max_length=32)
    http: Optional[Dict[str, Any]] = None

class Location(PCBaseModel):
    country: Optional[str] = Field(default=None, min_length=2, max_length=2, description="ISO-3166-1 alpha-2, при наличии")
    city: Optional[str] = Field(default=None, min_length=1, max_length=120)
    lat: Optional[float] = None
    lon: Optional[float] = None

class Device(PCBaseModel):
    id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    os: Optional[Dict[str, Optional[str]]] = None
    managed: Optional[bool] = None
    trustedNetwork: Optional[bool] = None
    posture: Optional[Dict[str, Any]] = None

class Session(PCBaseModel):
    id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    startedAt: Optional[str] = None
    expiresAt: Optional[str] = None

    @field_validator("startedAt", "expiresAt")
    def _iso_fields(cls, v: Optional[str]) -> Optional[str]:
        return _iso8601_or_none(v)

class Risk(PCBaseModel):
    score: Optional[float] = None
    level: Optional[Literal["low", "medium", "high"]] = None
    signals: Optional[List[str]] = None

class Context(PCBaseModel):
    purposeOfUse: Optional[str] = Field(default=None, min_length=1, max_length=128)
    justification: Optional[str] = Field(default=None, min_length=1, max_length=512)
    channel: Optional[str] = Field(default=None, min_length=1, max_length=64)
    originApp: Optional[str] = Field(default=None, min_length=1, max_length=128)
    requestIp: Optional[str] = Field(default=None, min_length=1, max_length=64)
    location: Optional[Location] = None
    device: Optional[Device] = None
    session: Optional[Session] = None
    risk: Optional[Risk] = None
    jurisdiction: Optional[List[str]] = None
    dataResidency: Optional[str] = Field(default=None, min_length=1, max_length=64)
    requestTime: Optional[str] = None
    timezone: Optional[str] = Field(default=None, min_length=1, max_length=64)
    # прочие расширяемые поля допускаются вне схемы на верхнем уровне API-контракта

    @field_validator("requestTime")
    def _request_time_iso(cls, v: Optional[str]) -> Optional[str]:
        return _iso8601_or_none(v)

class MaskingRule(PCBaseModel):
    field: str = Field(..., min_length=1, max_length=200)
    method: Literal["hash", "redact", "last4", "custom"]
    params: Optional[Dict[str, Any]] = None

class RowLevel(PCBaseModel):
    # допускаем два варианта: where (устар.) или language/expr
    language: Optional[Literal["cel", "sql"]] = "cel"
    expr: Optional[str] = Field(default=None, min_length=1, max_length=2000)
    where: Optional[str] = Field(default=None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def _check_row_level(self) -> "RowLevel":
        if not (self.expr or self.where):
            raise ValueError("RowLevel requires either 'expr' or 'where'")
        return self

class DataFilter(PCBaseModel):
    allowFields: Optional[List[str]] = None
    masking: Optional[List[MaskingRule]] = None
    rowLevel: Optional[RowLevel] = None

class Obligation(PCBaseModel):
    on: Literal["Permit", "Deny", "Any"] = "Permit"
    type: str = Field(..., min_length=1, max_length=120)
    params: Optional[Dict[str, Any]] = None

class Constraints(PCBaseModel):
    dataFilter: Optional[DataFilter] = None
    obligations: Optional[List[Obligation]] = None


# ----------------------------- Decision: Request/Response --------------------

class Integrity(PCBaseModel):
    alg: Literal["sha256"] = "sha256"
    hash: str = Field(..., pattern=r"^[a-f0-9]{64}$")

class PolicyEval(PCBaseModel):
    timeoutMs: Optional[int] = Field(default=None, ge=1, le=60_000)
    explain: Optional[Literal["off", "summary", "full", "trace"]] = "off"
    trace: Optional[bool] = None
    returnObligations: Optional[bool] = None

class PolicyRef(PCBaseModel):
    set: Optional[str] = Field(default=None, min_length=1, max_length=120)
    revision: Optional[str] = None  # SemVer-подобная строка
    eval: Optional[PolicyEval] = None

    @field_validator("revision")
    def _semver_like(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not SEMVER_RE.match(v):
            raise ValueError("revision must be SemVer-like (e.g., 1.2.3 or 1.2.3-alpha.1)")
        return v

class CacheHint(PCBaseModel):
    allow: Optional[bool] = True
    ttlSeconds: Optional[int] = Field(default=None, ge=1, le=86_400)
    keyParts: Optional[List[str]] = None

class DecisionRequest(PCBaseModel):
    apiVersion: Literal[API_VERSION] = Field(API_VERSION, description="API version")
    kind: Literal["DecisionRequest"] = "DecisionRequest"
    requestId: Optional[str] = Field(default=None, min_length=8, max_length=64)
    timestamp: Optional[str] = None
    tenant: Optional[Dict[str, str]] = None
    correlationId: Optional[str] = Field(default=None, min_length=8, max_length=64)
    idempotencyKey: Optional[str] = Field(default=None, min_length=8, max_length=200)
    policy: Optional[PolicyRef] = None
    subject: Subject
    resource: Resource
    action: Action
    context: Optional[Context] = None
    constraints: Optional[Constraints] = None
    cache: Optional[CacheHint] = None
    requestedDecisions: Optional[List[RequestedDecision]] = None
    ext: Optional[Dict[str, Any]] = None
    integrity: Optional[Integrity] = None

    @field_validator("timestamp")
    def _timestamp_iso(cls, v: Optional[str]) -> Optional[str]:
        return _iso8601_or_none(v)

    @model_validator(mode="after")
    def _integrity_check(self) -> "DecisionRequest":
        if self.integrity and self.integrity.alg == "sha256":
            # Собираем словарь эквивалентный телу, исключая поле integrity
            payload = self.model_dump(mode="json") if PYDANTIC_V2 else self.dict(by_alias=False)  # type: ignore
            # Исключаем integrity
            payload.pop("integrity", None)
            actual = compute_integrity_sha256(payload)
            if actual != self.integrity.hash:
                raise ValueError("integrity hash mismatch")
        return self

class DecisionMeta(PCBaseModel):
    receivedAt: Optional[str] = None
    processedAt: Optional[str] = None
    processingTimeMs: Optional[int] = Field(default=None, ge=0)

    @field_validator("receivedAt", "processedAt")
    def _iso_dt(cls, v: Optional[str]) -> Optional[str]:
        return _iso8601_or_none(v)

class DecisionResponse(PCBaseModel):
    apiVersion: Literal[API_VERSION] = API_VERSION
    kind: Literal["DecisionResponse"] = "DecisionResponse"
    requestId: str = Field(..., min_length=8, max_length=64)
    correlationId: Optional[str] = Field(default=None, min_length=8, max_length=64)
    decision: DecisionEffect
    obligations: Optional[List[Obligation]] = None
    explain: Optional[Dict[str, Any]] = None
    cache: Optional[Dict[str, Any]] = None
    policy: Optional[Dict[str, Any]] = None
    meta: Optional[DecisionMeta] = None

class BatchDecisionItem(PCBaseModel):
    index: int = Field(..., ge=0)
    requestId: Optional[str] = Field(default=None, min_length=8, max_length=64)
    status: int = Field(..., ge=100, le=599)
    body: Optional[DecisionResponse] = None
    error: Optional["ApiError"] = None  # forward ref

class DecisionBatchResponse(PCBaseModel):
    apiVersion: Literal[API_VERSION] = API_VERSION
    kind: Literal["DecisionBatchResponse"] = "DecisionBatchResponse"
    items: List[BatchDecisionItem]


# ----------------------------- Health & Errors -------------------------------

class HealthResponse(PCBaseModel):
    status: Literal["ok", "degraded", "down"] = "ok"
    version: Optional[str] = None
    revision: Optional[str] = None
    time: Optional[str] = None

    @field_validator("time")
    def _time_iso(cls, v: Optional[str]) -> Optional[str]:
        return _iso8601_or_none(v)

class ApiError(PCBaseModel):
    error: str = Field(..., min_length=1, max_length=120)
    message: Optional[str] = Field(default=None, min_length=1, max_length=2000)
    code: Optional[str] = Field(default=None, min_length=1, max_length=64)
    requestId: Optional[str] = Field(default=None, min_length=8, max_length=64)
    details: Optional[Any] = None


# ----------------------------- Examples -------------------------------------

EXAMPLE_DECISION_REQUEST: Dict[str, Any] = {
    "apiVersion": API_VERSION,
    "kind": "DecisionRequest",
    "requestId": "6d3a0f2c-4b5e-4b1a-9b5d-1b2c3d4e5f60",
    "timestamp": "2025-08-28T13:15:00Z",
    "tenant": {"id": "acme", "environment": "prod"},
    "correlationId": "c0a8f0e2-1e2f-4f3a-9d2c-7b1a9e5f0c3d",
    "idempotencyKey": "approve-invoice-INV-000123-user-42-2025-08-28T13:15:00Z",
    "policy": {"set": "default", "revision": "1.2.3", "eval": {"timeoutMs": 1200, "explain": "full", "returnObligations": True}},
    "subject": {
        "id": "user:42",
        "type": "user",
        "roles": ["analyst", "billing-approver"],
        "groups": ["finance", "eu-staff"],
        "attributes": {"department": "finance", "country": "SE"},
        "mfa": {"presented": True, "methods": ["totp"], "lastVerifiedAt": "2025-08-28T12:50:00Z"},
    },
    "resource": {
        "id": "invoice:2025/08/INV-000123",
        "type": "invoice",
        "ownerId": "acct:customer:987",
        "collection": "invoices",
        "labels": {"region": "eu-central", "product": "prime"},
        "classification": "confidential",
        "createdAt": "2025-08-20T09:01:02Z",
        "attributes": {"amount": 1999.99, "currency": "EUR", "status": "pending", "country": "SE"},
    },
    "action": {"name": "approve", "operation": "write", "http": {"method": "POST", "path": "/v1/invoices/INV-000123/approve"}},
    "context": {
        "purposeOfUse": "billing-approval",
        "justification": "Quarterly invoice approval",
        "channel": "web",
        "originApp": "policy-console",
        "requestIp": "203.0.113.10",
        "location": {"country": "SE", "city": "Stockholm", "lat": 59.3293, "lon": 18.0686},
        "device": {"id": "dev-9a7f", "os": {"name": "macOS", "version": "14.5"}, "managed": True, "trustedNetwork": False},
        "session": {"id": "sess-abc123", "startedAt": "2025-08-28T12:00:00Z", "expiresAt": "2025-08-28T18:00:00Z"},
        "risk": {"score": 14, "level": "low", "signals": ["mfa", "managed-device"]},
        "jurisdiction": ["EU", "SE"],
        "dataResidency": "EU",
        "requestTime": "2025-08-28T13:15:00Z",
        "timezone": "Europe/Stockholm",
    },
    "constraints": {
        "dataFilter": {
            "allowFields": ["id", "amount", "currency", "status", "ownerId"],
            "masking": [{"field": "ownerId", "method": "hash", "params": {"algo": "sha256"}}],
            "rowLevel": {"expr": "attributes.country == subject.attributes.country"},
        },
        "obligations": [
            {"on": "Permit", "type": "audit.log", "params": {"category": "billing", "redact": ["ownerId"]}},
            {"on": "Permit", "type": "notify", "params": {"channel": "slack", "target": "#approvals"}},
        ],
    },
    "cache": {"allow": True, "ttlSeconds": 300, "keyParts": ["tenant.id", "subject.id", "action.name", "resource.type", "resource.id"]},
    "requestedDecisions": ["permit", "explain", "obligations"],
}

# ----------------------------- Public API -----------------------------------

__all__ = [
    # base / utils
    "PCBaseModel",
    "compute_integrity_sha256",
    # enums
    "DecisionEffect",
    "ExplainMode",
    "RequestedDecision",
    # shared
    "Subject",
    "Resource",
    "Action",
    "Context",
    "Constraints",
    "DataFilter",
    "MaskingRule",
    "RowLevel",
    "Obligation",
    # decision API
    "Integrity",
    "PolicyEval",
    "PolicyRef",
    "CacheHint",
    "DecisionRequest",
    "DecisionMeta",
    "DecisionResponse",
    "BatchDecisionItem",
    "DecisionBatchResponse",
    # health & errors
    "HealthResponse",
    "ApiError",
    # examples
    "EXAMPLE_DECISION_REQUEST",
]
