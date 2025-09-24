# cybersecurity-core/cybersecurity/iam/provisioning.py
# -*- coding: utf-8 -*-
"""
Industrial-grade IAM provisioning engine.

Key features:
- Strict Pydantic models for users, groups, roles and desired state
- Policy engine (required attrs, domain allowlist, group/name constraints)
- Plan compiler (diff current vs desired → ordered operations)
- SCIM 2.0 connector (Users, Groups, membership) over httpx with retry/backoff & rate limit
- Optional LDAP connector stub (if ldap3 installed) — no hard dep
- Idempotent apply with ETag/If-Match passthrough when доступно
- Dry-run mode, structured logging with correlation id, optional OpenTelemetry spans
- Comprehensive ProvisionReport with metrics/errors

Dependencies:
    httpx>=0.25
    pydantic>=1.10 (v2 supported)
Optional:
    opentelemetry-api
    ldap3 (for LDAP stub)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Union

# ---- Pydantic v2/v1 compat ---------------------------------------------------
try:
    from pydantic import BaseModel, Field, ValidationError  # type: ignore
    from pydantic import __version__ as _pyd_ver  # type: ignore
    PydanticV2 = _pyd_ver.startswith("2.")
except Exception:  # pragma: no cover
    from pydantic.v1 import BaseModel, Field, ValidationError  # type: ignore
    PydanticV2 = False

# ---- Optional OpenTelemetry --------------------------------------------------
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None  # type: ignore

# ---- Optional ldap3 ----------------------------------------------------------
try:
    import ldap3  # type: ignore
    _ldap_available = True
except Exception:  # pragma: no cover
    ldap3 = None  # type: ignore
    _ldap_available = False

import httpx

# ---- Logging -----------------------------------------------------------------
logger = logging.getLogger("iam_provisioning")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(_h)
    logger.setLevel(os.getenv("IAM_PROVISIONING_LOG_LEVEL", "INFO"))

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

# ---- Resilience --------------------------------------------------------------
@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay_ms: int = 200
    max_delay_ms: int = 5_000
    multiplier: float = 2.0
    jitter_ms: int = 100
    retry_on_status: Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)

    def delay_ms(self, attempt: int) -> int:
        from random import randint
        if attempt <= 1:
            backoff = self.base_delay_ms
        else:
            backoff = min(int(self.base_delay_ms * (self.multiplier ** (attempt - 1))), self.max_delay_ms)
        return backoff + randint(0, self.jitter_ms)

    def should_retry(self, attempt: int, status: Optional[int], exc: Optional[Exception]) -> bool:
        if attempt >= self.max_attempts:
            return False
        if exc is not None:
            return True
        if status is None:
            return False
        return status in self.retry_on_status

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = int(burst)
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            await self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            deficit = tokens - self._tokens
            wait_s = max(0.0, deficit / self.rate) if self.rate > 0 else 0.0
            if wait_s > 0:
                await asyncio.sleep(wait_s)
            await self._refill()
            self._tokens = max(0.0, self._tokens - tokens)

    async def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + delta * self.rate)

# ---- Errors ------------------------------------------------------------------
class ProvisioningError(Exception):
    pass

class PolicyViolation(ProvisioningError):
    def __init__(self, message: str, *, field: Optional[str] = None) -> None:
        super().__init__(message)
        self.field = field

class ConnectorError(ProvisioningError):
    pass

# ---- Models ------------------------------------------------------------------
StatusType = Union["active", "inactive", "suspended", "deprovisioned"]

class IdentityUser(BaseModel):
    external_id: Optional[str] = None        # ключ соответствия с внешней системой
    id: Optional[str] = None                 # id в целевой системе
    username: str
    email: str
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    display_name: Optional[str] = None
    phone: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    manager_external_id: Optional[str] = None
    status: StatusType = "active"
    groups: List[str] = Field(default_factory=list)          # имена групп
    attributes: Dict[str, Any] = Field(default_factory=dict) # произвольные атрибуты

class IdentityGroup(BaseModel):
    external_id: Optional[str] = None
    id: Optional[str] = None
    name: str
    description: Optional[str] = None
    members_external_ids: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

class RoleAssignment(BaseModel):
    role: str
    subject_type: str  # "user" | "group"
    subject_external_id: str
    scope: Optional[str] = None

class DesiredState(BaseModel):
    users: List[IdentityUser] = Field(default_factory=list)
    groups: List[IdentityGroup] = Field(default_factory=list)
    roles: List[RoleAssignment] = Field(default_factory=list)

class ProvisioningPolicy(BaseModel):
    allowed_email_domains: List[str] = Field(default_factory=list)
    required_user_attrs: List[str] = Field(default_factory=lambda: ["username", "email"])
    group_name_prefix_allow: Optional[str] = None           # например "nc-"
    disable_strategy: str = "suspend"                       # "suspend" | "deprovision"
    allow_delete_groups: bool = False
    max_batch_ops: int = 5000

    def validate_user(self, u: IdentityUser) -> None:
        for f in self.required_user_attrs:
            if getattr(u, f, None) in (None, "", []):
                raise PolicyViolation(f"Required attribute missing: {f}", field=f)
        if self.allowed_email_domains:
            domain = (u.email or "").split("@")[-1].lower()
            if domain not in [d.lower() for d in self.allowed_email_domains]:
                raise PolicyViolation(f"Email domain not allowed: {domain}", field="email")

    def validate_group(self, g: IdentityGroup) -> None:
        if self.group_name_prefix_allow:
            if not g.name.startswith(self.group_name_prefix_allow):
                raise PolicyViolation(f"Group name must start with '{self.group_name_prefix_allow}'", field="name")

# ---- Plan --------------------------------------------------------------------
class PlanOp(BaseModel):
    kind: str  # CREATE_USER | UPDATE_USER | DEACTIVATE_USER | CREATE_GROUP | UPDATE_GROUP | DELETE_GROUP | ADD_GROUP_MEMBER | REMOVE_GROUP_MEMBER | ASSIGN_ROLE | REVOKE_ROLE
    target: str  # external_id or composite key
    reason: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)

class Plan(BaseModel):
    items: List[PlanOp] = Field(default_factory=list)

class ApplyResult(BaseModel):
    ok: int = 0
    failed: int = 0

class ProvisionReport(BaseModel):
    correlation_id: str
    started_at: datetime
    finished_at: datetime
    duration_s: float
    plan_size: int
    results: Dict[str, ApplyResult]
    errors: List[str] = Field(default_factory=list)

# ---- Audit -------------------------------------------------------------------
class AuditEvent(BaseModel):
    ts: datetime = Field(default_factory=now_utc)
    correlation_id: str
    op: str
    target: str
    status: str  # "ok" | "error" | "skipped"
    detail: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None

class AuditSink(Protocol):
    async def write(self, event: AuditEvent) -> None: ...

class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: List[AuditEvent] = []
    async def write(self, event: AuditEvent) -> None:
        self.events.append(event)

# ---- Connector protocol ------------------------------------------------------
class IdentityConnector(Protocol):
    # Fetch current state
    async def list_users(self) -> List[IdentityUser]: ...
    async def list_groups(self) -> List[IdentityGroup]: ...
    async def get_group_members(self, group_id: str) -> List[str]: ...  # returns user external_ids

    # Mutations (idempotent where possible)
    async def upsert_user(self, user: IdentityUser) -> IdentityUser: ...
    async def deactivate_user(self, external_id: str, strategy: str = "suspend") -> None: ...
    async def upsert_group(self, group: IdentityGroup) -> IdentityGroup: ...
    async def delete_group(self, external_id: str) -> None: ...
    async def add_group_member(self, group_external_id: str, user_external_id: str) -> None: ...
    async def remove_group_member(self, group_external_id: str, user_external_id: str) -> None: ...
    async def assign_role(self, assignment: RoleAssignment) -> None: ...
    async def revoke_role(self, assignment: RoleAssignment) -> None: ...

# ---- HTTP wrapper for SCIM ---------------------------------------------------
class Http:
    def __init__(self, verify: bool, timeout_s: float, retry: RetryPolicy, rate: TokenBucket, proxies: Optional[Mapping[str, str]] = None, headers: Optional[Mapping[str, str]] = None) -> None:
        self._client = httpx.AsyncClient(verify=verify, timeout=timeout_s, proxies=proxies, headers={"User-Agent": "Aethernova-IAM/1.0", **(headers or {})})
        self.retry = retry
        self.rate = rate

    async def close(self) -> None:
        await self._client.aclose()

    async def request(self, method: str, url: str, *, headers: Optional[Mapping[str, str]] = None, params: Optional[Mapping[str, Any]] = None, json_body: Optional[Mapping[str, Any]] = None) -> httpx.Response:
        await self.rate.acquire()
        attempt = 0
        last_status = None
        last_exc: Optional[Exception] = None
        while True:
            attempt += 1
            try:
                resp = await self._client.request(method, url, headers=headers, params=params, json=json_body)
                if resp.status_code < 400:
                    return resp
                last_status = resp.status_code
                if self.retry.should_retry(attempt, last_status, None):
                    await asyncio.sleep(self.retry.delay_ms(attempt) / 1000.0)
                    continue
                return resp
            except httpx.RequestError as exc:
                last_exc = exc
                if self.retry.should_retry(attempt, None, exc):
                    await asyncio.sleep(self.retry.delay_ms(attempt) / 1000.0)
                    continue
                raise

# ---- SCIM 2.0 connector ------------------------------------------------------
class SCIMConfig(BaseModel):
    base_url: str                  # https://idp.example.com/scim/v2
    token: Optional[str] = None    # Bearer
    verify_tls: bool = True
    timeout_s: float = 20.0
    proxies: Optional[Mapping[str, str]] = None
    rate_limit_per_sec: float = 5.0
    rate_burst: int = 10

class SCIMConnector(IdentityConnector):
    def __init__(self, cfg: SCIMConfig, retry: Optional[RetryPolicy] = None) -> None:
        self.cfg = cfg
        self.retry = retry or RetryPolicy()
        headers = {"Content-Type": "application/json"}
        if cfg.token:
            headers["Authorization"] = f"Bearer {cfg.token}"
        self.http = Http(
            verify=cfg.verify_tls,
            timeout_s=cfg.timeout_s,
            retry=self.retry,
            rate=TokenBucket(cfg.rate_limit_per_sec, cfg.rate_burst),
            proxies=cfg.proxies,
            headers=headers,
        )

    async def close(self) -> None:
        await self.http.close()

    # ---- Helpers
    @property
    def users_url(self) -> str:
        return self.cfg.base_url.rstrip("/") + "/Users"

    @property
    def groups_url(self) -> str:
        return self.cfg.base_url.rstrip("/") + "/Groups"

    # ---- Fetchers
    async def _paged(self, url: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        start = 1
        count = 200
        while True:
            resp = await self.http.request("GET", url, params={"startIndex": start, "count": count})
            if resp.status_code >= 400:
                raise ConnectorError(f"SCIM fetch failed: {resp.status_code} {resp.text[:200]}")
            data = resp.json()
            resources = data.get("Resources", []) or []
            total = int(data.get("totalResults", len(resources)))
            out.extend(resources)
            start = int(data.get("startIndex", start)) + int(data.get("itemsPerPage", len(resources)))
            if len(out) >= total or not resources:
                break
        return out

    @staticmethod
    def _user_from_scim(obj: Mapping[str, Any]) -> IdentityUser:
        name = obj.get("name") or {}
        emails = obj.get("emails") or []
        primary_email = None
        for e in emails:
            if isinstance(e, dict):
                if e.get("primary"):
                    primary_email = e.get("value")
                    break
                primary_email = primary_email or e.get("value")
        return IdentityUser(
            external_id=obj.get("externalId") or obj.get("id"),
            id=obj.get("id"),
            username=obj.get("userName"),
            email=primary_email or "",
            given_name=(name.get("givenName") if isinstance(name, dict) else None),
            family_name=(name.get("familyName") if isinstance(name, dict) else None),
            display_name=obj.get("displayName"),
            phone=_first_value(obj.get("phoneNumbers")),
            status="active" if obj.get("active", True) else "inactive",
            attributes={k: v for k, v in obj.items() if k not in ("id", "userName", "name", "emails", "displayName", "phoneNumbers", "active", "externalId", "groups")},
        )

    @staticmethod
    def _group_from_scim(obj: Mapping[str, Any]) -> IdentityGroup:
        members = obj.get("members") or []
        member_ids = []
        for m in members:
            if isinstance(m, dict) and "value" in m:
                member_ids.append(m["value"])
        return IdentityGroup(
            external_id=obj.get("externalId") or obj.get("id"),
            id=obj.get("id"),
            name=obj.get("displayName") or obj.get("name") or "",
            description=obj.get("description"),
            members_external_ids=member_ids,  # note: SCIM returns member IDs, we treat as external_ids here
            attributes={k: v for k, v in obj.items() if k not in ("id", "displayName", "members", "externalId", "schemas")},
        )

    async def list_users(self) -> List[IdentityUser]:
        objs = await self._paged(self.users_url)
        return [self._user_from_scim(o) for o in objs]

    async def list_groups(self) -> List[IdentityGroup]:
        objs = await self._paged(self.groups_url)
        return [self._group_from_scim(o) for o in objs]

    async def get_group_members(self, group_id: str) -> List[str]:
        # Fetch a single group to get current members
        resp = await self.http.request("GET", f"{self.groups_url}/{group_id}")
        if resp.status_code >= 400:
            raise ConnectorError(f"SCIM group get failed: {resp.status_code}")
        obj = resp.json()
        members = obj.get("members") or []
        return [m.get("value") for m in members if isinstance(m, dict) and m.get("value")]

    # ---- Mutations
    @staticmethod
    def _scim_user_payload(u: IdentityUser) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": u.username,
            "name": {
                "givenName": u.given_name or "",
                "familyName": u.family_name or "",
            },
            "displayName": u.display_name or (u.given_name or "") + (" " + u.family_name if u.family_name else ""),
            "active": u.status in ("active",),
            "emails": [{"value": u.email, "type": "work", "primary": True}] if u.email else [],
        }
        if u.phone:
            payload["phoneNumbers"] = [{"value": u.phone, "type": "work", "primary": True}]
        if u.external_id:
            payload["externalId"] = u.external_id
        # merge custom attributes (namespaced if needed)
        for k, v in (u.attributes or {}).items():
            if k not in payload:
                payload[k] = v
        return payload

    async def upsert_user(self, user: IdentityUser) -> IdentityUser:
        # Try resolve by externalId or userName
        scim = self._scim_user_payload(user)
        # Search by userName (filter)
        filter_q = f'userName eq "{user.username}"'
        resp = await self.http.request("GET", self.users_url, params={"filter": filter_q})
        data = resp.json()
        resources = data.get("Resources") or []
        if resources:
            obj = resources[0]
            uid = obj.get("id")
            # PUT update
            r2 = await self.http.request("PUT", f"{self.users_url}/{uid}", json_body=scim)
            if r2.status_code >= 400:
                raise ConnectorError(f"SCIM user update failed: {r2.status_code} {r2.text[:200]}")
            return self._user_from_scim(r2.json())
        # POST create
        r3 = await self.http.request("POST", self.users_url, json_body=scim)
        if r3.status_code >= 400:
            raise ConnectorError(f"SCIM user create failed: {r3.status_code} {r3.text[:200]}")
        return self._user_from_scim(r3.json())

    async def deactivate_user(self, external_id: str, strategy: str = "suspend") -> None:
        # Find by id/externalId
        # SCIM spec: PATCH { "op": "Replace", "path": "active", "value": false }
        # We first try by id
        uid = await self._resolve_user_id(external_id)
        patch = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Replace", "path": "active", "value": False}],
        }
        r = await self.http.request("PATCH", f"{self.users_url}/{uid}", json_body=patch)
        if r.status_code >= 400:
            raise ConnectorError(f"SCIM user deactivate failed: {r.status_code} {r.text[:200]}")

    async def _resolve_user_id(self, key: str) -> str:
        # Try direct GET
        if key and "/" not in key and " " not in key:
            # attempt GET by id
            r = await self.http.request("GET", f"{self.users_url}/{key}")
            if r.status_code < 400:
                return key
        # else search by externalId or userName
        for f in ("externalId", "userName"):
            resp = await self.http.request("GET", self.users_url, params={"filter": f'{f} eq "{key}"'})
            data = resp.json()
            res = data.get("Resources") or []
            if res:
                return res[0].get("id")
        raise ConnectorError(f"User not found for key={key}")

    async def upsert_group(self, group: IdentityGroup) -> IdentityGroup:
        payload: Dict[str, Any] = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": group.name,
        }
        if group.external_id:
            payload["externalId"] = group.external_id

        # search by displayName
        r = await self.http.request("GET", self.groups_url, params={"filter": f'displayName eq "{group.name}"'})
        data = r.json()
        res = data.get("Resources") or []
        if res:
            gid = res[0].get("id")
            r2 = await self.http.request("PUT", f"{self.groups_url}/{gid}", json_body=payload)
            if r2.status_code >= 400:
                raise ConnectorError(f"SCIM group update failed: {r2.status_code} {r2.text[:200]}")
            return self._group_from_scim(r2.json())
        r3 = await self.http.request("POST", self.groups_url, json_body=payload)
        if r3.status_code >= 400:
            raise ConnectorError(f"SCIM group create failed: {r3.status_code} {r3.text[:200]}")
        return self._group_from_scim(r3.json())

    async def delete_group(self, external_id: str) -> None:
        gid = await self._resolve_group_id(external_id)
        r = await self.http.request("DELETE", f"{self.groups_url}/{gid}")
        if r.status_code >= 400:
            raise ConnectorError(f"SCIM group delete failed: {r.status_code} {r.text[:200]}")

    async def _resolve_group_id(self, key: str) -> str:
        if key and "/" not in key and " " not in key:
            r = await self.http.request("GET", f"{self.groups_url}/{key}")
            if r.status_code < 400:
                return key
        resp = await self.http.request("GET", self.groups_url, params={"filter": f'displayName eq "{key}"'})
        data = resp.json()
        res = data.get("Resources") or []
        if res:
            return res[0].get("id")
        raise ConnectorError(f"Group not found for key={key}")

    async def add_group_member(self, group_external_id: str, user_external_id: str) -> None:
        gid = await self._resolve_group_id(group_external_id)
        uid = await self._resolve_user_id(user_external_id)
        patch = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Add", "path": "members", "value": [{"value": uid}]}],
        }
        r = await self.http.request("PATCH", f"{self.groups_url}/{gid
