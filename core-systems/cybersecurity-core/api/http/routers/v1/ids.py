# cybersecurity-core/api/http/routers/v1/ids.py
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple, TypeVar, Generic

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Path,
    Body,
    Header,
    Request,
    BackgroundTasks,
    status,
)
from pydantic import BaseModel, Field, IPvAnyAddress, HttpUrl, conint, constr, validator

# -----------------------------------------------------------------------------
# Logger
# -----------------------------------------------------------------------------
logger = logging.getLogger("ids.router")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s ids:%(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Security / RBAC (lightweight, pluggable)
# -----------------------------------------------------------------------------
class Role(str, Enum):
    admin = "admin"
    analyst = "analyst"
    ingest = "ingest"
    read = "read"

class AuthContext(BaseModel):
    user_id: str = "system"
    roles: List[Role] = Field(default_factory=lambda: [Role.admin])

def get_auth_context(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> AuthContext:
    # Minimal stub. Replace with JWT/OIDC validation in production.
    # Example: Bearer <token> -> parse roles; X-API-Key -> map to roles.
    roles = {Role.read}
    if api_key or authorization:
        roles |= {Role.analyst}
    if api_key == "ids-ingest" or (authorization and "ingest" in authorization.lower()):
        roles |= {Role.ingest}
    if api_key == "root" or (authorization and "admin" in authorization.lower()):
        roles |= {Role.admin}
    ctx = AuthContext(user_id="api", roles=sorted(roles, key=lambda r: r.value))
    return ctx

def require_roles(*required: Role):
    def dep(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if not set(required).issubset(set(ctx.roles)):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
        return ctx
    return dep

# -----------------------------------------------------------------------------
# Simple per-identity rate limiter (sliding window)
# -----------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self.hits: Dict[str, List[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check(self, identity: str) -> None:
        async with self._lock:
            now = time.time()
            window_start = now - self.window
            bucket = self.hits[identity]
            # drop old
            while bucket and bucket[0] < window_start:
                bucket.pop(0)
            if len(bucket) >= self.limit:
                raise HTTPException(status_code=429, detail="rate_limited")
            bucket.append(now)

rate_limiter_ingest = RateLimiter(limit=60, window_seconds=60)   # 60 req/min
rate_limiter_read   = RateLimiter(limit=120, window_seconds=60)  # 120 req/min
rate_limiter_write  = RateLimiter(limit=30, window_seconds=60)   # 30 req/min

async def limit_read(ctx: AuthContext = Depends(get_auth_context)) -> None:
    await rate_limiter_read.check("|".join([ctx.user_id, "read"]))

async def limit_ingest(ctx: AuthContext = Depends(get_auth_context)) -> None:
    await rate_limiter_ingest.check("|".join([ctx.user_id, "ingest"]))

async def limit_write(ctx: AuthContext = Depends(get_auth_context)) -> None:
    await rate_limiter_write.check("|".join([ctx.user_id, "write"]))

# -----------------------------------------------------------------------------
# Domain enums
# -----------------------------------------------------------------------------
class EventSeverity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class EventStatus(str, Enum):
    new = "new"
    under_investigation = "under_investigation"
    closed = "closed"
    false_positive = "false_positive"

class AlertStatus(str, Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"

# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

class EventBase(BaseModel):
    timestamp: datetime = Field(default_factory=_utcnow)
    src_ip: Optional[IPvAnyAddress] = None
    dst_ip: Optional[IPvAnyAddress] = None
    src_port: Optional[conint(ge=0, le=65535)] = None
    dst_port: Optional[conint(ge=0, le=65535)] = None
    protocol: Optional[constr(strip_whitespace=True, min_length=1, max_length=12)] = None
    rule_id: Optional[str] = Field(None, description="Internal rule identifier")
    signature_id: Optional[str] = Field(None, description="External IDS signature id")
    message: Optional[str] = None
    severity: EventSeverity = EventSeverity.info
    status: EventStatus = EventStatus.new
    tags: List[str] = Field(default_factory=list, max_items=64)
    extra: Dict[str, Any] = Field(default_factory=dict)

    @validator("timestamp", pre=True)
    def _ensure_tz(cls, v: Any) -> datetime:
        if isinstance(v, str):
            v = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        raise ValueError("invalid datetime")

class EventIn(EventBase):
    external_id: Optional[str] = Field(None, description="Idempotent source id")

class Event(EventBase):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)

class AlertBase(BaseModel):
    title: constr(strip_whitespace=True, min_length=1, max_length=256)
    description: Optional[str] = None
    severity: EventSeverity = EventSeverity.medium
    status: AlertStatus = AlertStatus.open
    tags: List[str] = Field(default_factory=list)

class AlertIn(AlertBase):
    event_ids: List[uuid.UUID] = Field(default_factory=list)

class Alert(AlertBase):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    created_at: datetime = Field(default_factory=_utcnow)
    event_ids: List[uuid.UUID] = Field(default_factory=list)

class Rule(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: constr(strip_whitespace=True, min_length=1, max_length=128)
    description: Optional[str] = None
    enabled: bool = True
    severity: EventSeverity = EventSeverity.low
    query: constr(strip_whitespace=True, min_length=1, max_length=2048) = Field(
        ..., description="Rule expression (KQL/Lucene/DSL)"
    )
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

class CorrelateRequest(BaseModel):
    event_ids: List[uuid.UUID] = Field(..., min_items=2, max_items=500)
    window_seconds: conint(gt=0, le=3600) = 300

class CorrelateResult(BaseModel):
    correlation_id: uuid.UUID
    alert: Alert

T = TypeVar("T")

class PageMeta(BaseModel):
    page: int
    page_size: int
    total: int

class Page(Generic[T], BaseModel):
    meta: PageMeta
    items: List[T]

# -----------------------------------------------------------------------------
# Storage interface and in-memory implementation
# -----------------------------------------------------------------------------
class IDSStorage:
    async def list_events(
        self,
        *,
        page: int,
        page_size: int,
        severity: Optional[List[EventSeverity]],
        status: Optional[List[EventStatus]],
        rule_id: Optional[str],
        signature_id: Optional[str],
        src_ip: Optional[str],
        dst_ip: Optional[str],
        ts_from: Optional[datetime],
        ts_to: Optional[datetime],
        search: Optional[str],
        sort: str,
    ) -> Tuple[int, List[Event]]:
        raise NotImplementedError

    async def get_event(self, event_id: uuid.UUID) -> Event:
        raise NotImplementedError

    async def upsert_events(self, events: List[EventIn]) -> Tuple[int, List[Event]]:
        raise NotImplementedError

    async def list_alerts(
        self, *, page: int, page_size: int, status: Optional[List[AlertStatus]]
    ) -> Tuple[int, List[Alert]]:
        raise NotImplementedError

    async def create_alert(self, alert: AlertIn) -> Alert:
        raise NotImplementedError

    async def get_alert(self, alert_id: uuid.UUID) -> Alert:
        raise NotImplementedError

    async def list_rules(self) -> List[Rule]:
        raise NotImplementedError

    async def create_rule(self, rule: Rule) -> Rule:
        raise NotImplementedError

    async def update_rule(self, rule_id: uuid.UUID, patch: Dict[str, Any]) -> Rule:
        raise NotImplementedError

    async def delete_rule(self, rule_id: uuid.UUID) -> None:
        raise NotImplementedError

    async def stats_overview(self) -> Dict[str, Any]:
        raise NotImplementedError

class InMemoryIDSStorage(IDSStorage):
    def __init__(self) -> None:
        self._events: Dict[uuid.UUID, Event] = {}
        self._events_by_external: Dict[str, uuid.UUID] = {}
        self._alerts: Dict[uuid.UUID, Alert] = {}
        self._rules: Dict[uuid.UUID, Rule] = {}
        # seed example rule
        r = Rule(name="Suspicious SSH", description="Multiple SSH failures", severity=EventSeverity.medium, query="protocol:ssh AND failed:true", tags=["ssh","bruteforce"])
        self._rules[r.id] = r

    async def list_events(
        self,
        *,
        page: int,
        page_size: int,
        severity: Optional[List[EventSeverity]],
        status: Optional[List[EventStatus]],
        rule_id: Optional[str],
        signature_id: Optional[str],
        src_ip: Optional[str],
        dst_ip: Optional[str],
        ts_from: Optional[datetime],
        ts_to: Optional[datetime],
        search: Optional[str],
        sort: str,
    ) -> Tuple[int, List[Event]]:
        items = list(self._events.values())

        def match(e: Event) -> bool:
            if severity and e.severity not in severity:
                return False
            if status and e.status not in status:
                return False
            if rule_id and e.rule_id != rule_id:
                return False
            if signature_id and e.signature_id != signature_id:
                return False
            if src_ip and (e.src_ip is None or str(e.src_ip) != src_ip):
                return False
            if dst_ip and (e.dst_ip is None or str(e.dst_ip) != dst_ip):
                return False
            if ts_from and e.timestamp < ts_from:
                return False
            if ts_to and e.timestamp > ts_to:
                return False
            if search:
                s = search.lower()
                m = (e.message or "").lower()
                if s not in m and not any(s in t.lower() for t in e.tags):
                    return False
            return True

        items = [e for e in items if match(e)]

        reverse = sort.startswith("-")
        key = sort[1:] if reverse else sort

        def sort_key(e: Event) -> Any:
            if key == "timestamp":
                return e.timestamp
            if key == "severity":
                order = ["info", "low", "medium", "high", "critical"]
                return order.index(e.severity.value)
            return e.timestamp

        items.sort(key=sort_key, reverse=reverse)
        total = len(items)
        start = (page - 1) * page_size
        end = start + page_size
        return total, items[start:end]

    async def get_event(self, event_id: uuid.UUID) -> Event:
        e = self._events.get(event_id)
        if not e:
            raise HTTPException(status_code=404, detail="event_not_found")
        return e

    async def upsert_events(self, events: List[EventIn]) -> Tuple[int, List[Event]]:
        upserted: List[Event] = []
        count = 0
        for ev in events:
            if ev.external_id and ev.external_id in self._events_by_external:
                # idempotent update (we keep original id, merge fields)
                eid = self._events_by_external[ev.external_id]
                existing = self._events[eid]
                merged = existing.copy(update=ev.dict(exclude_unset=True))
                self._events[eid] = merged
                upserted.append(merged)
                continue
            e = Event(**ev.dict())
            self._events[e.id] = e
            if ev.external_id:
                self._events_by_external[ev.external_id] = e.id
            upserted.append(e)
            count += 1
        return count, upserted

    async def list_alerts(
        self, *, page: int, page_size: int, status: Optional[List[AlertStatus]]
    ) -> Tuple[int, List[Alert]]:
        items = list(self._alerts.values())
        if status:
            items = [a for a in items if a.status in status]
        items.sort(key=lambda a: a.created_at, reverse=True)
        total = len(items)
        start = (page - 1) * page_size
        end = start + page_size
        return total, items[start:end]

    async def create_alert(self, alert: AlertIn) -> Alert:
        a = Alert(**alert.dict())
        self._alerts[a.id] = a
        return a

    async def get_alert(self, alert_id: uuid.UUID) -> Alert:
        a = self._alerts.get(alert_id)
        if not a:
            raise HTTPException(status_code=404, detail="alert_not_found")
        return a

    async def list_rules(self) -> List[Rule]:
        return sorted(self._rules.values(), key=lambda r: r.created_at, reverse=True)

    async def create_rule(self, rule: Rule) -> Rule:
        self._rules[rule.id] = rule
        return rule

    async def update_rule(self, rule_id: uuid.UUID, patch: Dict[str, Any]) -> Rule:
        r = self._rules.get(rule_id)
        if not r:
            raise HTTPException(status_code=404, detail="rule_not_found")
        data = r.dict()
        data.update(patch)
        data["updated_at"] = _utcnow()
        nr = Rule(**data)
        self._rules[rule_id] = nr
        return nr

    async def delete_rule(self, rule_id: uuid.UUID) -> None:
        if rule_id not in self._rules:
            raise HTTPException(status_code=404, detail="rule_not_found")
        del self._rules[rule_id]

    async def stats_overview(self) -> Dict[str, Any]:
        sev_count = defaultdict(int)
        status_count = defaultdict(int)
        for e in self._events.values():
            sev_count[e.severity.value] += 1
            status_count[e.status.value] += 1
        return {
            "events_total": len(self._events),
            "by_severity": dict(sev_count),
            "by_status": dict(status_count),
            "alerts_total": len(self._alerts),
            "rules_total": len(self._rules),
        }

# Default storage instance; replace with DI to a real repository if needed
_storage = InMemoryIDSStorage()

async def get_storage() -> IDSStorage:
    return _storage

# -----------------------------------------------------------------------------
# Idempotency cache (for ingest)
# -----------------------------------------------------------------------------
class _IdemCache:
    def __init__(self, ttl_seconds: int = 900) -> None:
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def get_or_set(self, key: str, value_factory) -> Dict[str, Any]:
        async with self._lock:
            now = time.time()
            # purge expired
            for k in list(self._cache.keys()):
                if now - self._cache[k][0] > self.ttl:
                    del self._cache[k]
            if key in self._cache:
                return self._cache[key][1]
            val = await value_factory()
            self._cache[key] = (now, val)
            return val

idem_cache = _IdemCache()

# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/ids", tags=["IDS"])

# Health
@router.get("/health", summary="Health check", dependencies=[Depends(limit_read)])
async def health() -> Dict[str, str]:
    return {"status": "ok", "ts": _utcnow().isoformat()}

# Events: list
@router.get(
    "/events",
    response_model=Page[Event],
    summary="List IDS events with filtering and pagination",
    dependencies=[Depends(limit_read), Depends(require_roles(Role.read))],
)
async def list_events(
    page: conint(ge=1) = Query(1),
    page_size: conint(ge=1, le=1000) = Query(50),
    severity: Optional[List[EventSeverity]] = Query(None),
    status_q: Optional[List[EventStatus]] = Query(None, alias="status"),
    rule_id: Optional[str] = Query(None),
    signature_id: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    ts_from: Optional[datetime] = Query(None),
    ts_to: Optional[datetime] = Query(None),
    search: Optional[str] = Query(None, min_length=2, max_length=128),
    sort: str = Query("-timestamp", regex=r"^-?(timestamp|severity)$"),
    storage: IDSStorage = Depends(get_storage),
):
    total, items = await storage.list_events(
        page=page,
        page_size=page_size,
        severity=severity,
        status=status_q,
        rule_id=rule_id,
        signature_id=signature_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ts_from=ts_from,
        ts_to=ts_to,
        search=search,
        sort=sort,
    )
    return Page(meta=PageMeta(page=page, page_size=page_size, total=total), items=items)

# Events: get by id
@router.get(
    "/events/{event_id}",
    response_model=Event,
    summary="Get IDS event by id",
    dependencies=[Depends(limit_read), Depends(require_roles(Role.read))],
)
async def get_event(
    event_id: uuid.UUID = Path(...),
    storage: IDSStorage = Depends(get_storage),
):
    return await storage.get_event(event_id)

# Events: ingest (bulk)
class IngestResponse(BaseModel):
    accepted: int
    total: int
    items: List[Event]

@router.post(
    "/events/ingest",
    response_model=IngestResponse,
    summary="Bulk ingest IDS events (idempotent by Idempotency-Key and external_id)",
    dependencies=[Depends(limit_ingest), Depends(require_roles(Role.ingest))],
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_events(
    payload: List[EventIn] = Body(..., min_items=1, max_items=10000),
    request: Request = None,
    storage: IDSStorage = Depends(get_storage),
    background_tasks: BackgroundTasks = None,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    async def do_ingest():
        accepted, items = await storage.upsert_events(payload)
        # Non-blocking enrichment example
        if background_tasks:
            background_tasks.add_task(_async_enrich, [e.id for e in items])
        logger.info("ingested=%s total=%s", accepted, len(payload))
        return IngestResponse(accepted=accepted, total=len(payload), items=items).dict()

    key = idempotency_key or f"payload:{hash(tuple(sorted(str(e.dict()).encode() for e in payload)))}"
    result_dict = await idem_cache.get_or_set(key, do_ingest)
    return IngestResponse(**result_dict)

async def _async_enrich(event_ids: List[uuid.UUID]) -> None:
    await asyncio.sleep(0)  # placeholder for async enrichment pipelines
    logger.info("enrichment scheduled for %d events", len(event_ids))

# Alerts: list
@router.get(
    "/alerts",
    response_model=Page[Alert],
    summary="List alerts",
    dependencies=[Depends(limit_read), Depends(require_roles(Role.read))],
)
async def list_alerts(
    page: conint(ge=1) = Query(1),
    page_size: conint(ge=1, le=1000) = Query(50),
    status_q: Optional[List[AlertStatus]] = Query(None, alias="status"),
    storage: IDSStorage = Depends(get_storage),
):
    total, items = await storage.list_alerts(page=page, page_size=page_size, status=status_q)
    return Page(meta=PageMeta(page=page, page_size=page_size, total=total), items=items)

# Alerts: create
@router.post(
    "/alerts",
    response_model=Alert,
    summary="Create alert",
    dependencies=[Depends(limit_write), Depends(require_roles(Role.analyst))],
    status_code=status.HTTP_201_CREATED,
)
async def create_alert(
    data: AlertIn = Body(...),
    storage: IDSStorage = Depends(get_storage),
):
    return await storage.create_alert(data)

# Alerts: get by id
@router.get(
    "/alerts/{alert_id}",
    response_model=Alert,
    summary="Get alert by id",
    dependencies=[Depends(limit_read), Depends(require_roles(Role.read))],
)
async def get_alert(
    alert_id: uuid.UUID = Path(...),
    storage: IDSStorage = Depends(get_storage),
):
    return await storage.get_alert(alert_id)

# Correlate: simple correlation to create an alert
@router.post(
    "/correlate",
    response_model=CorrelateResult,
    summary="Correlate events and create an alert",
    dependencies=[Depends(limit_write), Depends(require_roles(Role.analyst))],
)
async def correlate(
    data: CorrelateRequest,
    storage: IDSStorage = Depends(get_storage),
):
    # Naive correlation: group by src_ip or signature within time window
    events = [await storage.get_event(eid) for eid in data.event_ids]
    events.sort(key=lambda e: e.timestamp)
    t0, t1 = events[0].timestamp, events[-1].timestamp
    if (t1 - t0).total_seconds() > data.window_seconds:
        raise HTTPException(status_code=400, detail="window_violation")

    # Pick common attributes as context
    common_src = {str(e.src_ip) for e in events if e.src_ip}
    common_sig = {e.signature_id for e in events if e.signature_id}
    title = "Correlated activity detected"
    if common_src:
        title += f" from {', '.join(sorted(common_src))}"
    if common_sig:
        title += f" (signatures: {', '.join(sorted(s for s in common_sig if s))})"

    alert_in = AlertIn(
        title=title[:256],
        description=f"Auto-correlated {len(events)} events within {data.window_seconds}s.",
        severity=max(events, key=lambda e: ["info","low","medium","high","critical"].index(e.severity.value)).severity,
        status=AlertStatus.open,
        tags=["correlated", "auto"],
        event_ids=[e.id for e in events],
    )
    alert = await storage.create_alert(alert_in)
    corr_id = uuid.uuid4()
    return CorrelateResult(correlation_id=corr_id, alert=alert)

# Rules: list
@router.get(
    "/rules",
    response_model=List[Rule],
    summary="List detection rules",
    dependencies=[Depends(limit_read), Depends(require_roles(Role.read))],
)
async def list_rules(storage: IDSStorage = Depends(get_storage)):
    return await storage.list_rules()

# Rules: create
class RuleIn(BaseModel):
    name: constr(strip_whitespace=True, min_length=1, max_length=128)
    description: Optional[str] = None
    enabled: bool = True
    severity: EventSeverity = EventSeverity.low
    query: constr(strip_whitespace=True, min_length=1, max_length=2048)
    tags: List[str] = Field(default_factory=list)

@router.post(
    "/rules",
    response_model=Rule,
    summary="Create detection rule",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(limit_write), Depends(require_roles(Role.analyst))],
)
async def create_rule(
    payload: RuleIn,
    storage: IDSStorage = Depends(get_storage),
):
    rule = Rule(**payload.dict())
    return await storage.create_rule(rule)

# Rules: update
class RulePatch(BaseModel):
    name: Optional[constr(strip_whitespace=True, min_length=1, max_length=128)] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    severity: Optional[EventSeverity] = None
    query: Optional[constr(strip_whitespace=True, min_length=1, max_length=2048)] = None
    tags: Optional[List[str]] = None

@router.put(
    "/rules/{rule_id}",
    response_model=Rule,
    summary="Update detection rule",
    dependencies=[Depends(limit_write), Depends(require_roles(Role.analyst))],
)
async def update_rule(
    rule_id: uuid.UUID = Path(...),
    patch: RulePatch = Body(...),
    storage: IDSStorage = Depends(get_storage),
):
    return await storage.update_rule(rule_id, {k: v for k, v in patch.dict(exclude_unset=True).items()})

# Rules: delete
@router.delete(
    "/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete detection rule",
    dependencies=[Depends(limit_write), Depends(require_roles(Role.admin))],
)
async def delete_rule(
    rule_id: uuid.UUID = Path(...),
    storage: IDSStorage = Depends(get_storage),
):
    await storage.delete_rule(rule_id)
    return None

# Stats: overview
@router.get(
    "/stats/overview",
    summary="Overview statistics",
    dependencies=[Depends(limit_read), Depends(require_roles(Role.read))],
)
async def stats_overview(storage: IDSStorage = Depends(get_storage)) -> Dict[str, Any]:
    return await storage.stats_overview()
