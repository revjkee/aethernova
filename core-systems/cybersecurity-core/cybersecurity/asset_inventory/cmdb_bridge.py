# cybersecurity-core/cybersecurity/asset_inventory/cmdb_bridge.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, TypedDict, Union

try:
    import httpx  # type: ignore
except Exception as _e:  # pragma: no cover - optional import check
    httpx = None  # type: ignore

from pydantic import BaseModel, Field, HttpUrl, ValidationError

logger = logging.getLogger(__name__)

__all__ = [
    "AssetType",
    "AssetStatus",
    "AssetRecord",
    "AssetDiff",
    "FieldMapping",
    "CMDBProvider",
    "AuthMode",
    "CMDBClientConfig",
    "CMDBBridgeConfig",
    "CMDBClient",
    "InMemoryCMDBClient",
    "ServiceNowCMDBClient",
    "CMDBBridge",
    "create_client",
]


# ============================================================================
# Domain models
# ============================================================================

class AssetType(str, Enum):
    server = "server"
    workstation = "workstation"
    container = "container"
    vm = "vm"
    network = "network"
    mobile = "mobile"
    application = "application"
    database = "database"
    other = "other"


class AssetStatus(str, Enum):
    active = "active"
    decommissioned = "decommissioned"
    inventory = "inventory"
    unknown = "unknown"


class AssetRecord(BaseModel):
    """Canonical asset record used internally."""
    # Natural unique keys for idempotency
    key_hostname: Optional[str] = Field(default=None, description="FQDN/hostname")
    key_serial: Optional[str] = Field(default=None, description="Hardware serial number")
    key_uuid: Optional[str] = Field(default=None, description="Hardware/VM UUID")
    # Primary attributes
    name: str
    type: AssetType = AssetType.other
    status: AssetStatus = AssetStatus.active
    owner: Optional[str] = Field(default=None, description="Owner or service owner")
    environment: Optional[str] = Field(default=None, description="prod/stage/dev/test")
    ip_addresses: List[str] = Field(default_factory=list)
    mac_addresses: List[str] = Field(default_factory=list)
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    version: Optional[str] = Field(default=None, description="App/agent version")
    location: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def idempotency_key(self) -> str:
        """Stable key for dedup/upsert across providers."""
        payload = {
            "hostname": self.key_hostname or "",
            "serial": self.key_serial or "",
            "uuid": self.key_uuid or "",
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class AssetDiff(BaseModel):
    """Field-level diff to decide if update is needed."""
    changed: Dict[str, Tuple[Any, Any]] = Field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.changed


class FieldMapping(BaseModel):
    """
    Maps canonical AssetRecord fields to provider-specific fields.
    Example (ServiceNow):
      {"name": "name", "ip_addresses": "ip_address", "os_name": "os", ...}
    """
    mapping: Dict[str, str] = Field(default_factory=dict)

    def map_outbound(self, asset: AssetRecord) -> Dict[str, Any]:
        d = {}
        src = asset.model_dump()
        for src_field, dst_field in self.mapping.items():
            if src_field not in src:
                continue
            val = src[src_field]
            # Simple normalization
            if src_field in {"ip_addresses", "mac_addresses", "tags"} and isinstance(val, list):
                val = ",".join(val)
            d[dst_field] = val
        return d


class CMDBProvider(str, Enum):
    servicenow = "servicenow"
    inmemory = "inmemory"


class AuthMode(str, Enum):
    bearer = "bearer"
    basic = "basic"
    none = "none"


class CMDBClientConfig(BaseModel):
    provider: CMDBProvider
    base_url: Optional[HttpUrl] = None
    table: Optional[str] = Field(default=None, description="Target table/class for CI (e.g. cmdb_ci_server)")
    auth_mode: AuthMode = AuthMode.bearer
    username: Optional[str] = None
    password: Optional[str] = None
    token_env: Optional[str] = Field(default=None, description="ENV var with bearer token")
    verify_ssl: bool = True
    timeout_seconds: float = 10.0
    max_retries: int = 3
    backoff_base: float = 0.2
    backoff_max: float = 2.5
    rate_limit_per_sec: float = 10.0  # tokens per second
    concurrent_requests: int = 8


class CMDBBridgeConfig(BaseModel):
    client: CMDBClientConfig
    field_mapping: FieldMapping = Field(default_factory=FieldMapping)
    dry_run: bool = False
    cache_ttl_seconds: int = 30
    namespace_prefix: str = "aethernova"


# ============================================================================
# Reliability primitives: RateLimiter, CircuitBreaker, Retry
# ============================================================================

class _TokenBucket:
    def __init__(self, rate: float, capacity: Optional[float] = None) -> None:
        self.rate = max(rate, 0.001)
        self.capacity = capacity or max(1.0, rate * 2)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last
                self.last = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                sleep_for = (tokens - self.tokens) / self.rate
                await asyncio.sleep(max(0.001, sleep_for))


class _CircuitBreakerState(Enum):
    closed = "closed"
    open = "open"
    half_open = "half_open"


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.state = _CircuitBreakerState.closed
        self.opened_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def allow(self) -> None:
        async with self._lock:
            if self.state == _CircuitBreakerState.open:
                assert self.opened_at is not None
                if (time.monotonic() - self.opened_at) >= self.reset_timeout:
                    self.state = _CircuitBreakerState.half_open
                else:
                    raise RuntimeError("circuit_open")

    async def record_success(self) -> None:
        async with self._lock:
            self.failures = 0
            self.state = _CircuitBreakerState.closed
            self.opened_at = None

    async def record_failure(self) -> None:
        async with self._lock:
            self.failures += 1
            if self.failures >= self.failure_threshold:
                self.state = _CircuitBreakerState.open
                self.opened_at = time.monotonic()


async def _retry_async(
    op,
    *,
    retries: int,
    base: float,
    max_delay: float,
    jitter: float = 0.2,
    retry_on: Tuple[type, ...] = (Exception,),
):
    attempt = 0
    while True:
        try:
            return await op()
        except retry_on as e:
            attempt += 1
            if attempt > retries:
                raise
            delay = min(max_delay, base * (2 ** (attempt - 1)))
            delay = delay * (1.0 + random.uniform(-jitter, jitter))
            await asyncio.sleep(max(0.001, delay))


# ============================================================================
# Client protocol
# ============================================================================

class CMDBClient(Protocol):
    async def health(self) -> bool: ...
    async def search_by_keys(self, asset: AssetRecord) -> Optional[Dict[str, Any]]: ...
    async def create(self, payload: Dict[str, Any]) -> Dict[str, Any]: ...
    async def update(self, record_id: str, payload: Dict[str, Any]) -> Dict[str, Any]: ...
    async def delete(self, record_id: str) -> None: ...


# ============================================================================
# InMemory client (reference & tests)
# ============================================================================

class InMemoryCMDBClient:
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}
        self._index: Dict[str, str] = {}  # idempotency_key -> record_id

    async def health(self) -> bool:  # pragma: no cover - trivial
        return True

    async def search_by_keys(self, asset: AssetRecord) -> Optional[Dict[str, Any]]:
        rid = self._index.get(asset.idempotency_key())
        return self._store.get(rid) if rid else None

    async def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        rid = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        payload = dict(payload)
        payload["id"] = rid
        self._store[rid] = payload
        # keep index by normalized idempotency key if provided
        idk = payload.get("_idempotency_key")
        if isinstance(idk, str):
            self._index[idk] = rid
        return payload

    async def update(self, record_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if record_id not in self._store:
            raise KeyError("not found")
        self._store[record_id].update(payload)
        return self._store[record_id]

    async def delete(self, record_id: str) -> None:
        self._store.pop(record_id, None)
        # clear index
        for k, v in list(self._index.items()):
            if v == record_id:
                self._index.pop(k, None)


# ============================================================================
# ServiceNow client
# ============================================================================

class ServiceNowCMDBClient:
    """
    Minimal ServiceNow CMDB client (table API). Assumes the instance exposes
    /api/now/table/{table}. Field names must match ServiceNow table columns.
    """
    def __init__(self, cfg: CMDBClientConfig) -> None:
        if httpx is None:
            raise RuntimeError("httpx is required for ServiceNow client")
        if not cfg.base_url or not cfg.table:
            raise ValueError("base_url and table are required for ServiceNow provider")
        self.cfg = cfg
        headers = {"Accept": "application/json"}
        token = os.getenv(cfg.token_env) if cfg.token_env else None
        if cfg.auth_mode == AuthMode.bearer and token:
            headers["Authorization"] = f"Bearer {token}"

        self._client = httpx.AsyncClient(
            base_url=str(cfg.base_url),
            headers=headers,
            timeout=cfg.timeout_seconds,
            verify=cfg.verify_ssl,
        )
        self._rate = _TokenBucket(rate=cfg.rate_limit_per_sec)
        self._cb = CircuitBreaker()

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        await self._rate.acquire()
        await self._cb.allow()

        async def _do():
            resp = await self._client.request(method, url, **kwargs)
            if resp.status_code >= 500:
                raise RuntimeError(f"upstream_5xx:{resp.status_code}")
            return resp

        try:
            resp = await _retry_async(
                _do,
                retries=self.cfg.max_retries,
                base=self.cfg.backoff_base,
                max_delay=self.cfg.backoff_max,
                retry_on=(httpx.TransportError, httpx.ReadTimeout, RuntimeError),
            )
            await self._cb.record_success()
            return resp
        except Exception:
            await self._cb.record_failure()
            raise

    async def health(self) -> bool:
        try:
            url = f"/api/now/table/{self.cfg.table}?sysparm_limit=1"
            r = await self._request("GET", url)
            return r.status_code == 200
        except Exception as e:  # pragma: no cover - depends on env
            logger.warning("servicenow.health_failed", extra={"error": str(e)})
            return False

    async def search_by_keys(self, asset: AssetRecord) -> Optional[Dict[str, Any]]:
        # Build a query using provided keys in priority order
        terms = []
        if asset.key_uuid:
            terms.append(f"u_uuid={asset.key_uuid}")
        if asset.key_serial:
            terms.append(f"serial_number={asset.key_serial}")
        if asset.key_hostname:
            terms.append(f"name={asset.key_hostname}")
        if not terms:
            return None

        query = "^OR".join(terms)
        url = f"/api/now/table/{self.cfg.table}?sysparm_query={httpx.QueryParams({'': query})}&sysparm_limit=1"
        r = await self._request("GET", url)
        data = r.json()
        result = (data or {}).get("result") or []
        return result[0] if result else None

    async def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"/api/now/table/{self.cfg.table}"
        r = await self._request("POST", url, json=payload)
        j = r.json()
        return (j or {}).get("result") or {}

    async def update(self, record_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"/api/now/table/{self.cfg.table}/{record_id}"
        r = await self._request("PATCH", url, json=payload)
        j = r.json()
        return (j or {}).get("result") or {}

    async def delete(self, record_id: str) -> None:
        url = f"/api/now/table/{self.cfg.table}/{record_id}"
        await self._request("DELETE", url)

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            await self._client.aclose()


# ============================================================================
# Bridge
# ============================================================================

@dataclass
class UpsertPlan:
    record_id: Optional[str]
    payload: Dict[str, Any]
    diff: AssetDiff
    is_create: bool


class CMDBBridge:
    """
    High-level orchestrator: idempotent search + diff + upsert.
    """
    def __init__(self, cfg: CMDBBridgeConfig, client: CMDBClient):
        self.cfg = cfg
        self.client = client
        self._cache: Dict[str, Tuple[float, Optional[Dict[str, Any]]]] = {}
        self._cache_ttl = cfg.cache_ttl_seconds
        self._sem = asyncio.Semaphore(cfg.client.concurrent_requests)

    # ---------- Cache helpers ----------
    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        hit = self._cache.get(key)
        if not hit:
            return None
        ts, value = hit
        if (time.time() - ts) > self._cache_ttl:
            self._cache.pop(key, None)
            return None
        return value

    def _cache_put(self, key: str, value: Optional[Dict[str, Any]]) -> None:
        self._cache[key] = (time.time(), value)

    # ---------- Public API ----------
    async def health(self) -> bool:
        return await self.client.health()

    async def upsert_asset(self, asset: AssetRecord) -> UpsertPlan:
        key = asset.idempotency_key()
        cached = self._cache_get(key)
        if cached is None:
            existing = await self.client.search_by_keys(asset)
            self._cache_put(key, existing)
        else:
            existing = cached

        plan = self._build_plan(asset, existing)
        if self.cfg.dry_run:
            logger.info("cmdb.upsert_dry_run", extra={"create": plan.is_create, "diff": list(plan.diff.changed.keys())})
            return plan

        if plan.is_create:
            result = await self.client.create(plan.payload)
            # Update cache with new record
            rid = result.get("sys_id") or result.get("id")  # ServiceNow uses sys_id
            self._cache_put(key, result | {"sys_id": rid} if rid else result)
        else:
            rid = plan.record_id or (existing.get("sys_id") if existing else None)
            if not rid:
                # Safety fallback: create if no id present
                result = await self.client.create(plan.payload)
                rid = result.get("sys_id") or result.get("id")
                self._cache_put(key, result | {"sys_id": rid} if rid else result)
            else:
                result = await self.client.update(rid, plan.payload)
                self._cache_put(key, result or existing or {})
        return plan

    async def bulk_upsert(self, assets: Sequence[AssetRecord]) -> List[UpsertPlan]:
        async def _task(a: AssetRecord) -> UpsertPlan:
            async with self._sem:
                return await self.upsert_asset(a)

        return await asyncio.gather(*[_task(a) for a in assets])

    async def delete_by_keys(self, asset: AssetRecord) -> bool:
        existing = await self.client.search_by_keys(asset)
        if not existing:
            return False
        rid = existing.get("sys_id") or existing.get("id")
        if not rid:
            return False
        if self.cfg.dry_run:
            return True
        await self.client.delete(rid)
        # Invalidate cache
        self._cache.pop(asset.idempotency_key(), None)
        return True

    # ---------- Internals ----------
    def _build_plan(self, asset: AssetRecord, existing: Optional[Dict[str, Any]]) -> UpsertPlan:
        mapped = self.cfg.field_mapping.map_outbound(asset)
        # Idempotency hint for providers that support it
        mapped["_idempotency_key"] = asset.idempotency_key()

        if not existing:
            return UpsertPlan(record_id=None, payload=mapped, diff=AssetDiff(), is_create=True)

        # detect record id
        record_id = existing.get("sys_id") or existing.get("id")

        # compute diff (naive field compare on mapped space)
        diff = AssetDiff()
        for k, v in mapped.items():
            if existing.get(k) != v:
                diff.changed[k] = (existing.get(k), v)

        if not diff.changed:
            # No changes; return a no-op plan
            return UpsertPlan(record_id=record_id, payload={}, diff=diff, is_create=False)

        return UpsertPlan(record_id=record_id, payload=mapped, diff=diff, is_create=False)


# ============================================================================
# Factory
# ============================================================================

def create_client(cfg: CMDBClientConfig) -> CMDBClient:
    if cfg.provider == CMDBProvider.inmemory:
        return InMemoryCMDBClient()
    if cfg.provider == CMDBProvider.servicenow:
        return ServiceNowCMDBClient(cfg)
    raise ValueError(f"Unsupported provider: {cfg.provider}")


# ============================================================================
# Example default mapping (can be overridden via config)
# ============================================================================

DEFAULT_MAPPING = FieldMapping(
    mapping={
        "name": "name",
        "key_hostname": "name",         # common SN field
        "ip_addresses": "ip_address",
        "os_name": "os",
        "os_version": "os_version",
        "type": "u_type",
        "status": "install_status",
        "owner": "owned_by",
        "environment": "u_environment",
        "location": "location",
        "tags": "u_tags",
        "version": "u_version",
        "last_seen": "u_last_seen",
        "key_serial": "serial_number",
        "key_uuid": "u_uuid",
    }
)

# ============================================================================
# Convenience: build a ready-to-use bridge from environment variables
# ============================================================================

def build_bridge_from_env(prefix: str = "CMDB_") -> CMDBBridge:
    """
    Reads minimal configuration from environment and returns ready-to-use bridge.
    Variables:
      CMDB_PROVIDER=servicenow|inmemory
      CMDB_BASE_URL=https://instance.service-now.com
      CMDB_TABLE=cmdb_ci_server
      CMDB_TOKEN_ENV=SERVICENOW_TOKEN
      CMDB_VERIFY_SSL=true
      CMDB_DRY_RUN=false
    """
    provider = CMDBProvider(os.getenv(f"{prefix}PROVIDER", "inmemory"))
    base_url = os.getenv(f"{prefix}BASE_URL")
    table = os.getenv(f"{prefix}TABLE")
    token_env = os.getenv(f"{prefix}TOKEN_ENV", "SERVICENOW_TOKEN")
    verify_ssl = os.getenv(f"{prefix}VERIFY_SSL", "true").lower() == "true"
    dry_run = os.getenv(f"{prefix}DRY_RUN", "false").lower() == "true"

    client_cfg = CMDBClientConfig(
        provider=provider,
        base_url=base_url if base_url else None,
        table=table if table else None,
        token_env=token_env,
        verify_ssl=verify_ssl,
    )
    bridge_cfg = CMDBBridgeConfig(client=client_cfg, field_mapping=DEFAULT_MAPPING, dry_run=dry_run)
    client = create_client(client_cfg)
    return CMDBBridge(bridge_cfg, client)


# ============================================================================
# Self-test routine (optional, non-invasive)
# ============================================================================

async def _selftest() -> None:  # pragma: no cover - utility
    bridge = build_bridge_from_env()
    ok = await bridge.health()
    logger.info("cmdb.health", extra={"ok": ok})

    ar = AssetRecord(
        key_hostname="srv-01.prod.local",
        key_serial="ABC12345",
        key_uuid=None,
        name="srv-01",
        type=AssetType.server,
        status=AssetStatus.active,
        owner="team-platform",
        environment="prod",
        ip_addresses=["10.0.0.10"],
        os_name="Ubuntu",
        os_version="22.04",
        tags=["linux", "golden"],
        location="DC1",
    )
    plan = await bridge.upsert_asset(ar)
    logger.info("cmdb.upsert", extra={"create": plan.is_create, "diff": list(plan.diff.changed.keys())})

    # No changes — should be no-op update plan
    plan2 = await bridge.upsert_asset(ar)
    logger.info("cmdb.upsert_noop", extra={"create": plan2.is_create, "diff": list(plan2.diff.changed.keys())})

    removed = await bridge.delete_by_keys(ar)
    logger.info("cmdb.delete", extra={"removed": removed})


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_selftest())
