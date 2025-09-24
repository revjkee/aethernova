# policy_core/store/repository.py
"""
Industrial-grade Policy Repository for policy-core.

Key features:
- Async-only API (awaitable methods) with strong typing.
- Multi-tenant scoping (tenant_id is mandatory in all calls).
- Optimistic Concurrency Control (version match on update/delete).
- Content hash (sha256) for integrity and ETag-like semantics.
- Full audit trail (policies_history) on create/update/delete.
- Pluggable cache (cache-aside) via AsyncCache protocol.
- Structured logging with per-request trace_id (contextvar).
- Pagination and search (by id/type/active/text/tags).
- Two backends: InMemory (for tests) and Async SQLAlchemy Core (production).

Dependencies:
- Python 3.11+
- SQLAlchemy 2.x (for AsyncSQLRepository)
"""

from __future__ import annotations

import abc
import asyncio
import contextvars
import dataclasses
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    Any,
    AsyncIterator,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

# Optional imports for SQL backend (lazy usage)
try:
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        Integer,
        JSON,
        MetaData,
        String,
        Table,
        Text,
        and_,
        func,
        literal,
        select,
        update as sa_update,
        insert as sa_insert,
        delete as sa_delete,
        text as sa_text,
        cast,
    )
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
    from sqlalchemy.engine import Result
    from sqlalchemy.exc import IntegrityError
except Exception:  # SQLAlchemy optional until SQL backend is used
    AsyncEngine = Any  # type: ignore
    AsyncSession = Any  # type: ignore
    async_sessionmaker = Any  # type: ignore
    IntegrityError = Exception  # type: ignore


# -----------------------------------------------------------------------------
# Logging / tracing
# -----------------------------------------------------------------------------

_LOG = logging.getLogger("policy_core.store.repository")
if not _LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] trace=%(trace_id)s %(message)s"))
    _LOG.addHandler(_h)
    _LOG.setLevel(logging.INFO)

_trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")

def _trace_id() -> string:
    tid = _trace_id_ctx.get()
    if not tid:
        tid = uuid.uuid4().hex
        _trace_id_ctx.set(tid)
    return tid

class _LogExtra(dict):
    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.setdefault("trace_id", _trace_id())


# -----------------------------------------------------------------------------
# Domain model & DTO
# -----------------------------------------------------------------------------

@dataclass(slots=True)
class Policy:
    id: str
    tenant_id: str
    type: str
    document: Dict[str, Any]
    description: str = ""
    tags: List[str] = field(default_factory=list)
    is_active: bool = True
    version: int = 1
    content_hash: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def compute_hash(self) -> str:
        # Stable canonical hash over doc + type + description + tags + is_active
        payload = {
            "type": self.type,
            "document": self.document,
            "description": self.description,
            "tags": self.tags,
            "is_active": self.is_active,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def touch_hash(self) -> None:
        self.content_hash = self.compute_hash()

@dataclass(slots=True, frozen=True)
class PolicyCreate:
    id: str
    tenant_id: str
    type: str
    document: Mapping[str, Any]
    description: str = ""
    tags: Sequence[str] = ()
    is_active: bool = True

@dataclass(slots=True, frozen=True)
class PolicyUpdate:
    id: str
    tenant_id: str
    expected_version: int
    document: Optional[Mapping[str, Any]] = None
    description: Optional[str] = None
    tags: Optional[Sequence[str]] = None
    is_active: Optional[bool] = None
    type: Optional[str] = None  # Optional type change if governance allows

@dataclass(slots=True, frozen=True)
class SearchQuery:
    tenant_id: str
    ids: Optional[Sequence[str]] = None
    types: Optional[Sequence[str]] = None
    is_active: Optional[bool] = None
    text: Optional[str] = None          # searches id/description
    tag_any: Optional[Sequence[str]] = None  # match any of these tags
    tag_all: Optional[Sequence[str]] = None  # must contain all these tags

@dataclass(slots=True, frozen=True)
class Page:
    limit: int = 50
    offset: int = 0
    order_by: str = "id"      # id|created_at|updated_at|type
    desc: bool = False


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------

class StoreError(RuntimeError): ...
class NotFound(StoreError): ...
class AlreadyExists(StoreError): ...
class VersionConflict(StoreError): ...
class ValidationError(StoreError): ...
class BackendNotAvailable(StoreError): ...


# -----------------------------------------------------------------------------
# Cache Protocol
# -----------------------------------------------------------------------------

class AsyncCache(Protocol):
    async def get(self, key: str) -> Optional[bytes]: ...
    async def set(self, key: str, value: bytes, ttl_seconds: int = 60) -> None: ...
    async def delete(self, key: str) -> None: ...

class NoopCache:
    async def get(self, key: str) -> Optional[bytes]:
        return None
    async def set(self, key: str, value: bytes, ttl_seconds: int = 60) -> None:
        return None
    async def delete(self, key: str) -> None:
        return None


# -----------------------------------------------------------------------------
# Repository Interface
# -----------------------------------------------------------------------------

class PolicyRepository(abc.ABC):
    """Async repository interface for Policy."""

    @abc.abstractmethod
    async def get(self, tenant_id: str, policy_id: str) -> Policy: ...

    @abc.abstractmethod
    async def batch_get(self, tenant_id: str, ids: Sequence[str]) -> Dict[str, Policy]: ...

    @abc.abstractmethod
    async def search(self, q: SearchQuery, page: Page) -> Tuple[List[Policy], int]: ...

    @abc.abstractmethod
    async def create(self, c: PolicyCreate) -> Policy: ...

    @abc.abstractmethod
    async def update(self, u: PolicyUpdate) -> Policy: ...

    @abc.abstractmethod
    async def delete(self, tenant_id: str, policy_id: str, *, expected_version: Optional[int] = None) -> None: ...

    @abc.abstractmethod
    async def history(self, tenant_id: str, policy_id: str) -> List[Policy]: ...

    @abc.abstractmethod
    async def activate(self, tenant_id: str, policy_id: str, *, expected_version: int) -> Policy: ...

    @abc.abstractmethod
    async def deactivate(self, tenant_id: str, policy_id: str, *, expected_version: int) -> Policy: ...


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)

def _dt_now() -> datetime:
    return datetime.now(timezone.utc)

def _cache_key(tenant_id: str, policy_id: str) -> str:
    return f"policy:{tenant_id}:{policy_id}"

def _to_bytes(p: Policy) -> bytes:
    return json.dumps(dataclasses.asdict(p), default=str, separators=(",", ":")).encode("utf-8")

def _from_bytes(buf: bytes) -> Policy:
    raw = json.loads(buf.decode("utf-8"))
    # restore datetimes
    for k in ("created_at", "updated_at"):
        if raw.get(k):
            raw[k] = datetime.fromisoformat(raw[k])
    return Policy(**raw)


# -----------------------------------------------------------------------------
# In-memory backend (for tests / dev)
# -----------------------------------------------------------------------------

class InMemoryPolicyRepository(PolicyRepository):
    def __init__(self, *, cache: Optional[AsyncCache] = None) -> None:
        self._data: Dict[Tuple[str, str], Policy] = {}
        self._hist: Dict[Tuple[str, str], List[Policy]] = {}
        self._lock = asyncio.Lock()
        self._cache = cache or NoopCache()

    async def get(self, tenant_id: str, policy_id: str) -> Policy:
        key = (tenant_id, policy_id)
        # cache-aside
        ck = _cache_key(tenant_id, policy_id)
        cached = await self._cache.get(ck)
        if cached:
            return _from_bytes(cached)

        async with self._lock:
            try:
                p = self._data[key]
            except KeyError:
                raise NotFound(f"policy {policy_id} not found")
            await self._cache.set(ck, _to_bytes(p), ttl_seconds=60)
            return dataclasses.replace(p)

    async def batch_get(self, tenant_id: str, ids: Sequence[str]) -> Dict[str, Policy]:
        res: Dict[str, Policy] = {}
        for pid in ids:
            try:
                res[pid] = await self.get(tenant_id, pid)
            except NotFound:
                continue
        return res

    async def search(self, q: SearchQuery, page: Page) -> Tuple[List[Policy], int]:
        async with self._lock:
            items = [p for (t, _), p in self._data.items() if t == q.tenant_id]
        def match(p: Policy) -> bool:
            if q.ids and p.id not in set(q.ids):
                return False
            if q.types and p.type not in set(q.types):
                return False
            if q.is_active is not None and p.is_active != q.is_active:
                return False
            if q.text:
                t = q.text.strip().lower()
                if t not in p.id.lower() and t not in p.description.lower():
                    return False
            if q.tag_any:
                if not any(tag in set(p.tags) for tag in q.tag_any):
                    return False
            if q.tag_all:
                if not all(tag in set(p.tags) for tag in q.tag_all):
                    return False
            return True

        filtered = [p for p in items if match(p)]
        total = len(filtered)

        key_field = page.order_by
        reverse = page.desc

        def sort_key(p: Policy):
            return getattr(p, key_field, p.id)

        filtered.sort(key=sort_key, reverse=reverse)
        sliced = filtered[page.offset: page.offset + page.limit]
        return [dataclasses.replace(p) for p in sliced], total

    async def create(self, c: PolicyCreate) -> Policy:
        async with self._lock:
            key = (c.tenant_id, c.id)
            if key in self._data:
                raise AlreadyExists(f"policy {c.id} already exists")
            p = Policy(
                id=c.id,
                tenant_id=c.tenant_id,
                type=c.type,
                document=dict(c.document),
                description=c.description,
                tags=list(c.tags),
                is_active=c.is_active,
                version=1,
            )
            p.touch_hash()
            p.created_at = _dt_now()
            p.updated_at = p.created_at
            self._data[key] = p
            self._hist.setdefault(key, []).append(dataclasses.replace(p))
            await self._cache.delete(_cache_key(c.tenant_id, c.id))
            _LOG.info("created policy id=%s tenant=%s", p.id, p.tenant_id, extra=_LogExtra())
            return dataclasses.replace(p)

    async def update(self, u: PolicyUpdate) -> Policy:
        async with self._lock:
            key = (u.tenant_id, u.id)
            if key not in self._data:
                raise NotFound(f"policy {u.id} not found")
            current = self._data[key]
            if current.version != u.expected_version:
                raise VersionConflict(f"policy {u.id} version mismatch")
            # apply changes
            if u.document is not None:
                current.document = dict(u.document)
            if u.description is not None:
                current.description = u.description
            if u.tags is not None:
                current.tags = list(u.tags)
            if u.is_active is not None:
                current.is_active = u.is_active
            if u.type is not None:
                current.type = u.type
            current.version += 1
            current.updated_at = _dt_now()
            current.touch_hash()
            self._hist.setdefault(key, []).append(dataclasses.replace(current))
            await self._cache.delete(_cache_key(u.tenant_id, u.id))
            _LOG.info("updated policy id=%s tenant=%s v=%s", current.id, current.tenant_id, current.version, extra=_LogExtra())
            return dataclasses.replace(current)

    async def delete(self, tenant_id: str, policy_id: str, *, expected_version: Optional[int] = None) -> None:
        async with self._lock:
            key = (tenant_id, policy_id)
            if key not in self._data:
                raise NotFound(f"policy {policy_id} not found")
            if expected_version is not None and self._data[key].version != expected_version:
                raise VersionConflict(f"policy {policy_id} version mismatch")
            # add tombstone to history
            tomb = dataclasses.replace(self._data[key])
            self._hist.setdefault(key, []).append(tomb)
            del self._data[key]
            await self._cache.delete(_cache_key(tenant_id, policy_id))
            _LOG.info("deleted policy id=%s tenant=%s", policy_id, tenant_id, extra=_LogExtra())

    async def history(self, tenant_id: str, policy_id: str) -> List[Policy]:
        async with self._lock:
            key = (tenant_id, policy_id)
            hist = self._hist.get(key, [])
            return [dataclasses.replace(p) for p in hist]

    async def activate(self, tenant_id: str, policy_id: str, *, expected_version: int) -> Policy:
        return await self.update(PolicyUpdate(id=policy_id, tenant_id=tenant_id, expected_version=expected_version, is_active=True))

    async def deactivate(self, tenant_id: str, policy_id: str, *, expected_version: int) -> Policy:
        return await self.update(PolicyUpdate(id=policy_id, tenant_id=tenant_id, expected_version=expected_version, is_active=False))


# -----------------------------------------------------------------------------
# SQLAlchemy Async backend (production)
# -----------------------------------------------------------------------------

class AsyncSQLPolicyRepository(PolicyRepository):
    """
    SQLAlchemy Core (async) implementation with OCC and audit history.

    Schema:
      policies(
        tenant_id TEXT NOT NULL,
        id        TEXT NOT NULL,
        type      TEXT NOT NULL,
        document  JSON NOT NULL,
        description TEXT NOT NULL,
        tags      JSON NOT NULL,      -- list[str]
        is_active BOOLEAN NOT NULL,
        version   INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY (tenant_id, id)
      )

      policies_history(
        tenant_id TEXT NOT NULL,
        id        TEXT NOT NULL,
        version   INTEGER NOT NULL,
        op        TEXT NOT NULL,      -- created|updated|deleted
        snapshot  JSON NOT NULL,      -- full Policy snapshot
        created_at TIMESTAMPTZ NOT NULL
      )

    Note: Use migrations (e.g., Alembic) in production. `ensure_schema()` provided for tests/dev.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession], *, cache: Optional[AsyncCache] = None) -> None:
        if session_factory is Any:
            raise BackendNotAvailable("SQLAlchemy is not available in this environment")
        self._sf = session_factory
        self._cache = cache or NoopCache()
        self._md = MetaData()
        self._policies = Table(
            "policies",
            self._md,
            Column("tenant_id", String, primary_key=True),
            Column("id", String, primary_key=True),
            Column("type", String, nullable=False),
            Column("document", JSON, nullable=False),
            Column("description", Text, nullable=False, default=""),
            Column("tags", JSON, nullable=False, default=list),
            Column("is_active", Boolean, nullable=False, default=True),
            Column("version", Integer, nullable=False, default=1),
            Column("content_hash", String, nullable=False),
            Column("created_at", DateTime(timezone=True), nullable=False),
            Column("updated_at", DateTime(timezone=True), nullable=False),
        )
        self._history = Table(
            "policies_history",
            self._md,
            Column("tenant_id", String, nullable=False),
            Column("id", String, nullable=False),
            Column("version", Integer, nullable=False),
            Column("op", String, nullable=False),
            Column("snapshot", JSON, nullable=False),
            Column("created_at", DateTime(timezone=True), nullable=False),
        )

    # ------------------------ helpers ------------------------

    def _row_to_policy(self, row: Mapping[str, Any]) -> Policy:
        return Policy(
            id=row["id"],
            tenant_id=row["tenant_id"],
            type=row["type"],
            document=row["document"],
            description=row["description"],
            tags=row["tags"] or [],
            is_active=row["is_active"],
            version=row["version"],
            content_hash=row["content_hash"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def _audit(self, s: AsyncSession, p: Policy, op: str) -> None:
        snap = dataclasses.asdict(p)
        # Convert datetimes to iso for JSON portability
        snap["created_at"] = p.created_at.isoformat()
        snap["updated_at"] = p.updated_at.isoformat()
        await s.execute(
            sa_insert(self._history).values(
                tenant_id=p.tenant_id,
                id=p.id,
                version=p.version,
                op=op,
                snapshot=snap,
                created_at=_dt_now(),
            )
        )

    async def ensure_schema(self, engine: AsyncEngine) -> None:
        """Dev/test helper: create tables if absent."""
        async with engine.begin() as conn:
            await conn.run_sync(self._md.create_all)

    # ------------------------- API --------------------------

    async def get(self, tenant_id: str, policy_id: str) -> Policy:
        ck = _cache_key(tenant_id, policy_id)
        cached = await self._cache.get(ck)
        if cached:
            return _from_bytes(cached)

        async with self._sf() as s:
            q = (
                select(self._policies)
                .where(and_(self._policies.c.tenant_id == tenant_id, self._policies.c.id == policy_id))
                .limit(1)
            )
            res: Result = await s.execute(q)
            row = res.mappings().first()
            if not row:
                raise NotFound(f"policy {policy_id} not found")
            p = self._row_to_policy(row)
            await self._cache.set(ck, _to_bytes(p), ttl_seconds=60)
            return p

    async def batch_get(self, tenant_id: str, ids: Sequence[str]) -> Dict[str, Policy]:
        if not ids:
            return {}
        async with self._sf() as s:
            q = (
                select(self._policies)
                .where(and_(self._policies.c.tenant_id == tenant_id, self._policies.c.id.in_(list(ids))))
            )
            res: Result = await s.execute(q)
            out: Dict[str, Policy] = {}
            for row in res.mappings():
                p = self._row_to_policy(row)
                out[p.id] = p
            return out

    async def search(self, q: SearchQuery, page: Page) -> Tuple[List[Policy], int]:
        async with self._sf() as s:
            cond = [self._policies.c.tenant_id == q.tenant_id]
            if q.ids:
                cond.append(self._policies.c.id.in_(list(q.ids)))
            if q.types:
                cond.append(self._policies.c.type.in_(list(q.types)))
            if q.is_active is not None:
                cond.append(self._policies.c.is_active == q.is_active)
            if q.text:
                t = f"%{q.text.lower()}%"
                cond.append(
                    or_(
                        func.lower(self._policies.c.id).like(t),
                        func.lower(self._policies.c.description).like(t),
                    )
                )
            # Tags filtering (generic fallback by casting JSON to TEXT)
            if q.tag_any:
                subconds = []
                for tag in q.tag_any:
                    subconds.append(cast(self._policies.c.tags, String).like(f'%"{tag}"%'))
                cond.append(or_(*subconds))
            if q.tag_all:
                for tag in q.tag_all:
                    cond.append(cast(self._policies.c.tags, String).like(f'%"{tag}"%'))

            # total
            total_q = select(func.count(literal(1))).select_from(self._policies).where(and_(*cond))
            total = int((await s.execute(total_q)).scalar_one())

            # ordering
            col = {
                "id": self._policies.c.id,
                "created_at": self._policies.c.created_at,
                "updated_at": self._policies.c.updated_at,
                "type": self._policies.c.type,
            }.get(page.order_by, self._policies.c.id)
            order_expr = col.desc() if page.desc else col.asc()

            data_q = (
                select(self._policies)
                .where(and_(*cond))
                .order_by(order_expr)
                .offset(page.offset)
                .limit(page.limit)
            )
            res: Result = await s.execute(data_q)
            items = [self._row_to_policy(r) for r in res.mappings()]
            return items, total

    async def create(self, c: PolicyCreate) -> Policy:
        now = _dt_now()
        p = Policy(
            id=c.id,
            tenant_id=c.tenant_id,
            type=c.type,
            document=dict(c.document),
            description=c.description,
            tags=list(c.tags),
            is_active=c.is_active,
            version=1,
            created_at=now,
            updated_at=now,
        )
        p.touch_hash()

        async with self._sf() as s:
            async with s.begin():
                try:
                    await s.execute(
                        sa_insert(self._policies).values(
                            tenant_id=p.tenant_id,
                            id=p.id,
                            type=p.type,
                            document=p.document,
                            description=p.description,
                            tags=p.tags,
                            is_active=p.is_active,
                            version=p.version,
                            content_hash=p.content_hash,
                            created_at=p.created_at,
                            updated_at=p.updated_at,
                        )
                    )
                except IntegrityError as e:
                    raise AlreadyExists(f"policy {p.id} already exists") from e
                await self._audit(s, p, "created")
            await self._cache.delete(_cache_key(p.tenant_id, p.id))
            _LOG.info("created policy id=%s tenant=%s", p.id, p.tenant_id, extra=_LogExtra())
            return p

    async def update(self, u: PolicyUpdate) -> Policy:
        # fetch current
        current = await self.get(u.tenant_id, u.id)
        if current.version != u.expected_version:
            raise VersionConflict(f"policy {u.id} version mismatch")

        # apply changes
        new_doc = dict(u.document) if u.document is not None else current.document
        new_desc = u.description if u.description is not None else current.description
        new_tags = list(u.tags) if u.tags is not None else current.tags
        new_active = u.is_active if u.is_active is not None else current.is_active
        new_type = u.type if u.type is not None else current.type

        updated = dataclasses.replace(
            current,
            type=new_type,
            document=new_doc,
            description=new_desc,
            tags=new_tags,
            is_active=new_active,
            version=current.version + 1,
            updated_at=_dt_now(),
        )
        updated.touch_hash()

        async with self._sf() as s:
            async with s.begin():
                q = (
                    sa_update(self._policies)
                    .where(
                        and_(
                            self._policies.c.tenant_id == u.tenant_id,
                            self._policies.c.id == u.id,
                            self._policies.c.version == u.expected_version,  # OCC
                        )
                    )
                    .values(
                        type=updated.type,
                        document=updated.document,
                        description=updated.description,
                        tags=updated.tags,
                        is_active=updated.is_active,
                        version=updated.version,
                        content_hash=updated.content_hash,
                        updated_at=updated.updated_at,
                    )
                )
                res = await s.execute(q)
                if res.rowcount != 1:
                    raise VersionConflict(f"policy {u.id} version mismatch (race)")
                await self._audit(s, updated, "updated")
            await self._cache.delete(_cache_key(updated.tenant_id, updated.id))
            _LOG.info(
                "updated policy id=%s tenant=%s v=%s",
                updated.id,
                updated.tenant_id,
                updated.version,
                extra=_LogExtra(),
            )
            return updated

    async def delete(self, tenant_id: str, policy_id: str, *, expected_version: Optional[int] = None) -> None:
        # fetch current to audit and check version
        current = await self.get(tenant_id, policy_id)
        if expected_version is not None and current.version != expected_version:
            raise VersionConflict(f"policy {policy_id} version mismatch")

        async with self._sf() as s:
            async with s.begin():
                q = sa_delete(self._policies).where(
                    and_(
                        self._policies.c.tenant_id == tenant_id,
                        self._policies.c.id == policy_id,
                        self._policies.c.version == (expected_version if expected_version is not None else current.version),
                    )
                )
                res = await s.execute(q)
                if res.rowcount != 1:
                    raise VersionConflict(f"policy {policy_id} version mismatch (race)")
                await self._audit(s, current, "deleted")
            await self._cache.delete(_cache_key(tenant_id, policy_id))
            _LOG.info("deleted policy id=%s tenant=%s", policy_id, tenant_id, extra=_LogExtra())

    async def history(self, tenant_id: str, policy_id: str) -> List[Policy]:
        async with self._sf() as s:
            q = (
                select(self._history.c.snapshot)
                .where(and_(self._history.c.tenant_id == tenant_id, self._history.c.id == policy_id))
                .order_by(self._history.c.version.asc())
            )
            res: Result = await s.execute(q)
            items: List[Policy] = []
            for r in res.mappings():
                snap = r["snapshot"]
                # normalize datetimes
                snap["created_at"] = datetime.fromisoformat(snap["created_at"])
                snap["updated_at"] = datetime.fromisoformat(snap["updated_at"])
                items.append(Policy(**snap))
            return items

    async def activate(self, tenant_id: str, policy_id: str, *, expected_version: int) -> Policy:
        return await self.update(
            PolicyUpdate(id=policy_id, tenant_id=tenant_id, expected_version=expected_version, is_active=True)
        )

    async def deactivate(self, tenant_id: str, policy_id: str, *, expected_version: int) -> Policy:
        return await self.update(
            PolicyUpdate(id=policy_id, tenant_id=tenant_id, expected_version=expected_version, is_active=False)
        )


# -----------------------------------------------------------------------------
# Factory helpers
# -----------------------------------------------------------------------------

def in_memory_repository(*, cache: Optional[AsyncCache] = None) -> PolicyRepository:
    return InMemoryPolicyRepository(cache=cache)

def sql_repository(session_factory: async_sessionmaker[AsyncSession], *, cache: Optional[AsyncCache] = None) -> PolicyRepository:
    return AsyncSQLPolicyRepository(session_factory, cache=cache)


__all__ = [
    # Entities / DTO
    "Policy",
    "PolicyCreate",
    "PolicyUpdate",
    "SearchQuery",
    "Page",
    # Errors
    "StoreError",
    "NotFound",
    "AlreadyExists",
    "VersionConflict",
    "ValidationError",
    "BackendNotAvailable",
    # Cache
    "AsyncCache",
    "NoopCache",
    # Interface and impls
    "PolicyRepository",
    "InMemoryPolicyRepository",
    "AsyncSQLPolicyRepository",
    # Factories
    "in_memory_repository",
    "sql_repository",
]
