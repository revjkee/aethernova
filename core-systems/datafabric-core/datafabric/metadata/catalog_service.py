# datafabric/metadata/catalog_service.py
# Industrial Metadata Catalog for DataFabric
# Stdlib-only. Thread-safe in-memory backend. Pluggable storage API.

from __future__ import annotations

import json
import re
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Set, Tuple, runtime_checkable

# =========================
# Logging (JSON, one-line)
# =========================

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _jlog(level: str, message: str, **kwargs) -> None:
    rec = {
        "ts": _utcnow().isoformat(),
        "level": level.upper(),
        "component": "datafabric.metadata.catalog",
        "message": message,
    }
    rec.update(kwargs or {})
    print(json.dumps(rec, ensure_ascii=False), flush=True)

def _info(m: str, **kw) -> None: _jlog("INFO", m, **kw)
def _warn(m: str, **kw) -> None: _jlog("WARN", m, **kw)
def _error(m: str, **kw) -> None: _jlog("ERROR", m, **kw)

# =========================
# Errors
# =========================

class CatalogError(Exception): ...
class NotFound(CatalogError): ...
class AlreadyExists(CatalogError): ...
class ValidationError(CatalogError): ...
class AccessDenied(CatalogError): ...
class Conflict(CatalogError): ...
class IdempotentReplay(CatalogError): ...

# =========================
# Model
# =========================

_VALID_LAYER = {"raw", "staging", "curated", "mart"}
_DTYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_() ,]*$")

@dataclass(frozen=True)
class ColumnDef:
    name: str
    dtype: str
    nullable: bool = True
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)

@dataclass(frozen=True)
class SchemaDef:
    columns: List[ColumnDef] = field(default_factory=list)

    def column_names(self) -> List[str]:
        return [c.name for c in self.columns]

@dataclass(frozen=True)
class PartitionDef:
    keys: List[str] = field(default_factory=list)

@dataclass
class SLA:
    freshness_seconds: Optional[int] = None
    max_delay_seconds: Optional[int] = None
    availability_target: Optional[float] = None  # 0..1

@dataclass
class DQMetric:
    name: str
    value: float
    ts_utc: str

@dataclass
class DQStatus:
    last_report_ts: Optional[str] = None
    metrics: List[DQMetric] = field(default_factory=list)
    status: Optional[str] = None  # green|yellow|red

@dataclass
class ACL:
    owner: str
    readers: Set[str] = field(default_factory=set)
    writers: Set[str] = field(default_factory=set)
    admins: Set[str] = field(default_factory=set)

    def can_read(self, uid: str) -> bool:
        return uid == self.owner or uid in self.readers or uid in self.writers or uid in self.admins

    def can_write(self, uid: str) -> bool:
        return uid == self.owner or uid in self.writers or uid in self.admins

    def can_admin(self, uid: str) -> bool:
        return uid == self.owner or uid in self.admins

@dataclass
class DatasetVersion:
    version: str                   # "MAJOR.MINOR.PATCH"
    schema: SchemaDef
    partitions: PartitionDef = field(default_factory=PartitionDef)
    created_at: str = field(default_factory=lambda: _utcnow().isoformat())
    description: Optional[str] = None
    changeset: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Lineage:
    upstream: Set[str] = field(default_factory=set)    # inputs
    downstream: Set[str] = field(default_factory=set)  # outputs

@dataclass
class Dataset:
    dataset_id: str               # canonical id, e.g. "curated:orders"
    name: str
    layer: str
    system: Optional[str] = None  # hive|delta|iceberg|s3|...
    path: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    owners: Set[str] = field(default_factory=set)
    acl: ACL = field(default_factory=lambda: ACL(owner="system"))
    sla: Optional[SLA] = None
    dq: DQStatus = field(default_factory=DQStatus)
    active: bool = True
    created_at: str = field(default_factory=lambda: _utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: _utcnow().isoformat())
    current_version: Optional[str] = None
    versions: List[DatasetVersion] = field(default_factory=list)
    lineage: Lineage = field(default_factory=Lineage)
    description: Optional[str] = None
    custom: Dict[str, Any] = field(default_factory=dict)

    # Optimistic concurrency token updated на каждую запись
    etag: str = field(default_factory=lambda: str(uuid.uuid4()))

    def indexable_text(self) -> str:
        cols = []
        if self.versions:
            cols = [c.name for c in self.versions[-1].schema.columns]
        blob = " ".join([self.dataset_id, self.name, self.layer, " ".join(self.tags),
                         " ".join(self.owners), " ".join(cols), self.description or ""])
        return blob.lower()

# =========================
# Utils
# =========================

def _parse_version(v: str) -> Tuple[int, int, int]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", v or "")
    if not m:
        raise ValidationError(f"Invalid semver: {v}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))

def bump_version(base: Optional[str], policy: str = "patch") -> str:
    if base is None:
        return "1.0.0"
    major, minor, patch = _parse_version(base)
    if policy == "patch":
        patch += 1
    elif policy == "minor":
        minor += 1; patch = 0
    elif policy == "major":
        major += 1; minor = 0; patch = 0
    else:
        raise ValidationError(f"Unknown bump policy: {policy}")
    return f"{major}.{minor}.{patch}"

def _validate_schema(schema: SchemaDef) -> None:
    seen = set()
    for c in schema.columns:
        if not c.name or not _DTYPE_RE.match(c.dtype):
            raise ValidationError(f"Invalid column: {c}")
        if c.name in seen:
            raise ValidationError(f"Duplicate column name: {c.name}")
        seen.add(c.name)

def _ensure_acl(acl: ACL) -> None:
    if not acl.owner:
        raise ValidationError("ACL.owner is required")

# =========================
# Event Bus (simple)
# =========================

class EventBus:
    def __init__(self) -> None:
        self._subs: Dict[str, List] = {}
        self._lock = threading.Lock()

    def subscribe(self, event: str, cb) -> None:
        with self._lock:
            self._subs.setdefault(event, []).append(cb)

    def publish(self, event: str, payload: Dict[str, Any]) -> None:
        subs = []
        with self._lock:
            subs = list(self._subs.get(event, []))
        for cb in subs:
            try:
                cb(event, payload)
            except Exception as e:
                _warn("event_handler_error", event=event, error=str(e))

# =========================
# Storage Abstraction
# =========================

@runtime_checkable
class StorageBackend(Protocol):
    @contextmanager
    def txn(self) -> Any: ...
    def get(self, dataset_id: str) -> Dataset: ...
    def put(self, ds: Dataset) -> None: ...
    def delete(self, dataset_id: str) -> None: ...
    def list_all(self) -> List[Dataset]: ...
    def append_audit(self, rec: Dict[str, Any]) -> None: ...
    def audits(self) -> List[Dict[str, Any]]: ...
    def idemp_seen(self, key: str) -> bool: ...
    def idemp_remember(self, key: str) -> None: ...
    def reindex(self, ds: Dataset) -> None: ...
    def deindex(self, dataset_id: str) -> None: ...
    def search_index(self, text: str) -> List[str]: ...  # returns dataset_ids

class _RWLock:
    """Readers-writer lock with fairness (basic)."""
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._readers = 0
        self._writer_waiting = 0
        self._cond = threading.Condition(self._lock)

    def acquire_read(self) -> None:
        with self._lock:
            while self._writer_waiting > 0:
                self._cond.wait()
            self._readers += 1

    def release_read(self) -> None:
        with self._lock:
            self._readers -= 1
            if self._readers == 0:
                self._cond.notify_all()

    def acquire_write(self) -> None:
        with self._lock:
            self._writer_waiting += 1
            while self._readers > 0:
                self._cond.wait()
            # hold RLock
        # keep ownership until release_write
    def release_write(self) -> None:
        with self._lock:
            self._writer_waiting -= 1
            self._cond.notify_all()

class InMemoryStorage(StorageBackend):
    def __init__(self) -> None:
        self._ds: Dict[str, Dataset] = {}
        self._audit: List[Dict[str, Any]] = []
        self._idemp: Set[str] = set()
        self._index: Dict[str, Set[str]] = {}  # token -> set(dataset_id)
        self._rw = _RWLock()
        self._txn_local = threading.local()

    @contextmanager
    def txn(self) -> Any:
        # In-memory "transaction": coarse-grained write lock
        self._rw.acquire_write()
        try:
            setattr(self._txn_local, "active", True)
            yield
            # nothing to commit explicitly
        except Exception:
            raise
        finally:
            setattr(self._txn_local, "active", False)
            self._rw.release_write()

    def get(self, dataset_id: str) -> Dataset:
        self._rw.acquire_read()
        try:
            ds = self._ds.get(dataset_id)
            if not ds:
                raise NotFound(f"Dataset not found: {dataset_id}")
            return ds
        finally:
            self._rw.release_read()

    def put(self, ds: Dataset) -> None:
        # writer lock guaranteed by txn
        self._ds[ds.dataset_id] = ds

    def delete(self, dataset_id: str) -> None:
        self._ds.pop(dataset_id, None)
        self.deindex(dataset_id)

    def list_all(self) -> List[Dataset]:
        self._rw.acquire_read()
        try:
            return list(self._ds.values())
        finally:
            self._rw.release_read()

    def append_audit(self, rec: Dict[str, Any]) -> None:
        self._audit.append(rec)

    def audits(self) -> List[Dict[str, Any]]:
        return list(self._audit)

    def idemp_seen(self, key: str) -> bool:
        return key in self._idemp

    def idemp_remember(self, key: str) -> None:
        self._idemp.add(key)

    # --- Index ---
    def _tokens(self, text: str) -> Set[str]:
        toks = re.findall(r"[a-z0-9_]+", text.lower())
        return set(t for t in toks if len(t) > 1)

    def reindex(self, ds: Dataset) -> None:
        self.deindex(ds.dataset_id)
        for tok in self._tokens(ds.indexable_text()):
            self._index.setdefault(tok, set()).add(ds.dataset_id)

    def deindex(self, dataset_id: str) -> None:
        for s in self._index.values():
            s.discard(dataset_id)

    def search_index(self, text: str) -> List[str]:
        tokens = self._tokens(text)
        if not tokens:
            return []
        # intersection of posting lists
        candidates: Optional[Set[str]] = None
        for t in tokens:
            ids = self._index.get(t, set())
            candidates = ids if candidates is None else candidates.intersection(ids)
            if candidates is not None and not candidates:
                break
        return list(candidates or [])

# =========================
# Catalog Service
# =========================

@dataclass
class CatalogService:
    storage: StorageBackend = field(default_factory=InMemoryStorage)
    events: EventBus = field(default_factory=EventBus)

    # ---- Internal helpers ----
    def _audit(self, actor: str, action: str, dataset_id: Optional[str], payload: Dict[str, Any]) -> None:
        rec = {
            "id": str(uuid.uuid4()),
            "ts": _utcnow().isoformat(),
            "actor": actor,
            "action": action,
            "dataset_id": dataset_id,
            "payload": payload,
        }
        self.storage.append_audit(rec)
        _info("audit", action=action, actor=actor, dataset_id=dataset_id)

    def _check_idemp(self, key: Optional[str]) -> None:
        if not key:
            return
        if self.storage.idemp_seen(key):
            raise IdempotentReplay(f"idempotent replay: {key}")
        self.storage.idemp_remember(key)

    def _require_layer(self, layer: str) -> None:
        if layer not in _VALID_LAYER:
            raise ValidationError(f"Invalid layer: {layer}")

    def _new_etag(self) -> str:
        return str(uuid.uuid4())

    # ---- Public API ----

    def register_dataset(
        self,
        actor: str,
        name: str,
        layer: str,
        system: Optional[str],
        path: Optional[str],
        schema: SchemaDef,
        description: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        owners: Optional[Iterable[str]] = None,
        acl: Optional[ACL] = None,
        sla: Optional[SLA] = None,
        dq_status: Optional[DQStatus] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dataset:
        self._require_layer(layer)
        _validate_schema(schema)
        acli = acl or ACL(owner=actor)
        _ensure_acl(acli)
        self._check_idemp(idempotency_key)

        ds_id = f"{layer}:{name}".lower()
        try:
            self.storage.get(ds_id)
            raise AlreadyExists(f"Dataset exists: {ds_id}")
        except NotFound:
            pass

        version = DatasetVersion(
            version="1.0.0",
            schema=schema,
            partitions=PartitionDef(),
            description="initial version",
            changeset={"reason": "create"},
        )

        ds = Dataset(
            dataset_id=ds_id,
            name=name,
            layer=layer,
            system=system,
            path=path,
            tags=set(tags or []),
            owners=set(owners or [actor]),
            acl=acli,
            sla=sla,
            dq=dq_status or DQStatus(),
            current_version=version.version,
            versions=[version],
            description=description,
        )

        with self.storage.txn():
            self.storage.put(ds)
            self.storage.reindex(ds)
            self._audit(actor, "register_dataset", ds_id, {"name": name, "layer": layer})
        self.events.publish("dataset.registered", {"dataset_id": ds_id, "actor": actor})
        _info("dataset_registered", dataset_id=ds_id, version=version.version)
        return ds

    def get_dataset(self, actor: str, dataset_id: str) -> Dataset:
        ds = self.storage.get(dataset_id)
        if not ds.active:
            raise NotFound(f"Dataset is deleted: {dataset_id}")
        if not ds.acl.can_read(actor):
            raise AccessDenied(f"read denied for {actor} on {dataset_id}")
        return ds

    def list_datasets(
        self,
        actor: str,
        layer: Optional[str] = None,
        tag: Optional[str] = None,
        text: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        include_deleted: bool = False,
    ) -> List[Dataset]:
        ids: Optional[List[str]] = None
        if text:
            ids = self.storage.search_index(text)
        out: List[Dataset] = []
        for ds in self.storage.list_all():
            if not include_deleted and not ds.active:
                continue
            if not ds.acl.can_read(actor):
                continue
            if layer and ds.layer != layer:
                continue
            if tag and tag not in ds.tags:
                continue
            if ids is not None and ds.dataset_id not in ids:
                continue
            out.append(ds)
        # stable ordering
        out.sort(key=lambda d: (d.layer, d.name))
        return out[offset: offset + max(0, limit)]

    def update_dataset(
        self,
        actor: str,
        dataset_id: str,
        description: Optional[str] = None,
        add_tags: Optional[Iterable[str]] = None,
        remove_tags: Optional[Iterable[str]] = None,
        owners: Optional[Iterable[str]] = None,
        acl_update: Optional[ACL] = None,
        system: Optional[str] = None,
        path: Optional[str] = None,
        bump_policy: str = "patch",
        etag: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dataset:
        self._check_idemp(idempotency_key)
        with self.storage.txn():
            ds = self.storage.get(dataset_id)
            if not ds.acl.can_write(actor):
                raise AccessDenied(f"write denied for {actor} on {dataset_id}")
            if etag and etag != ds.etag:
                raise Conflict(f"etag mismatch for {dataset_id}")
            if description is not None:
                ds.description = description
            if add_tags:
                ds.tags.update(add_tags)
            if remove_tags:
                ds.tags.difference_update(remove_tags)
            if owners:
                ds.owners = set(owners)
            if acl_update:
                _ensure_acl(acl_update)
                ds.acl = acl_update
            if system is not None:
                ds.system = system
            if path is not None:
                ds.path = path

            # bump version on metadata updates for auditability
            self._bump_and_stamp(ds, None, None, bump_policy, {"reason": "metadata_update"})
            self.storage.put(ds)
            self.storage.reindex(ds)
            self._audit(actor, "update_dataset", dataset_id, {"bump": bump_policy})
        self.events.publish("dataset.updated", {"dataset_id": dataset_id, "actor": actor})
        return self.storage.get(dataset_id)

    def set_schema(
        self,
        actor: str,
        dataset_id: str,
        schema: SchemaDef,
        partitions: Optional[PartitionDef] = None,
        bump_policy: str = "minor",
        etag: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dataset:
        self._check_idemp(idempotency_key)
        _validate_schema(schema)
        with self.storage.txn():
            ds = self.storage.get(dataset_id)
            if not ds.acl.can_write(actor):
                raise AccessDenied(f"write denied for {actor} on {dataset_id}")
            if etag and etag != ds.etag:
                raise Conflict(f"etag mismatch for {dataset_id}")

            self._bump_and_stamp(ds, schema, partitions, bump_policy, {"reason": "schema_update"})
            self.storage.put(ds)
            self.storage.reindex(ds)
            self._audit(actor, "set_schema", dataset_id, {"bump": bump_policy})
        self.events.publish("dataset.schema_updated", {"dataset_id": dataset_id, "actor": actor})
        return self.storage.get(dataset_id)

    def soft_delete(self, actor: str, dataset_id: str, etag: Optional[str] = None, idempotency_key: Optional[str] = None) -> None:
        self._check_idemp(idempotency_key)
        with self.storage.txn():
            ds = self.storage.get(dataset_id)
            if not ds.acl.can_admin(actor):
                raise AccessDenied(f"admin denied for {actor} on {dataset_id}")
            if etag and etag != ds.etag:
                raise Conflict("etag mismatch")
            ds.active = False
            ds.updated_at = _utcnow().isoformat()
            ds.etag = self._new_etag()
            self.storage.put(ds)
            self.storage.reindex(ds)
            self._audit(actor, "soft_delete", dataset_id, {})
        self.events.publish("dataset.deleted", {"dataset_id": dataset_id, "actor": actor})

    def restore(self, actor: str, dataset_id: str, etag: Optional[str] = None, idempotency_key: Optional[str] = None) -> None:
        self._check_idemp(idempotency_key)
        with self.storage.txn():
            ds = self.storage.get(dataset_id)
            if not ds.acl.can_admin(actor):
                raise AccessDenied(f"admin denied for {actor} on {dataset_id}")
            if etag and etag != ds.etag:
                raise Conflict("etag mismatch")
            ds.active = True
            ds.updated_at = _utcnow().isoformat()
            ds.etag = self._new_etag()
            self.storage.put(ds)
            self.storage.reindex(ds)
            self._audit(actor, "restore", dataset_id, {})
        self.events.publish("dataset.restored", {"dataset_id": dataset_id, "actor": actor})

    def purge(self, actor: str, dataset_id: str, idempotency_key: Optional[str] = None) -> None:
        """Полное удаление записи и индекса (необратимо)."""
        self._check_idemp(idempotency_key)
        with self.storage.txn():
            ds = self.storage.get(dataset_id)
            if not ds.acl.can_admin(actor):
                raise AccessDenied(f"admin denied for {actor} on {dataset_id}")
            # Обновляем линейность соседей
            for up in list(ds.lineage.upstream):
                try:
                    uds = self.storage.get(up); uds.lineage.downstream.discard(dataset_id)
                    uds.updated_at = _utcnow().isoformat(); uds.etag = self._new_etag()
                    self.storage.put(uds); self.storage.reindex(uds)
                except NotFound:
                    pass
            for dn in list(ds.lineage.downstream):
                try:
                    dds = self.storage.get(dn); dds.lineage.upstream.discard(dataset_id)
                    dds.updated_at = _utcnow().isoformat(); dds.etag = self._new_etag()
                    self.storage.put(dds); self.storage.reindex(dds)
                except NotFound:
                    pass
            self.storage.delete(dataset_id)
            self._audit(actor, "purge", dataset_id, {})
        self.events.publish("dataset.purged", {"dataset_id": dataset_id, "actor": actor})

    # ---- Lineage ----
    def add_lineage(self, actor: str, dataset_id: str, upstream_ids: Iterable[str], etag: Optional[str] = None, idempotency_key: Optional[str] = None) -> Dataset:
        self._check_idemp(idempotency_key)
        ups = set(upstream_ids)
        with self.storage.txn():
            ds = self.storage.get(dataset_id)
            if not ds.acl.can_write(actor):
                raise AccessDenied(f"write denied for {actor} on {dataset_id}")
            if etag and etag != ds.etag:
                raise Conflict("etag mismatch")
            for up in ups:
                upds = self.storage.get(up)
                ds.lineage.upstream.add(up)
                upds.lineage.downstream.add(dataset_id)
                upds.updated_at = _utcnow().isoformat(); upds.etag = self._new_etag()
                self.storage.put(upds); self.storage.reindex(upds)
            self._bump_and_stamp(ds, None, None, "patch", {"reason": "lineage_add", "upstream_added": list(ups)})
            self.storage.put(ds); self.storage.reindex(ds)
            self._audit(actor, "add_lineage", dataset_id, {"upstream": list(ups)})
        self.events.publish("dataset.lineage_added", {"dataset_id": dataset_id, "actor": actor, "upstream": list(ups)})
        return self.storage.get(dataset_id)

    def remove_lineage(self, actor: str, dataset_id: str, upstream_ids: Iterable[str], etag: Optional[str] = None, idempotency_key: Optional[str] = None) -> Dataset:
        self._check_idemp(idempotency_key)
        rm = set(upstream_ids)
        with self.storage.txn():
            ds = self.storage.get(dataset_id)
            if not ds.acl.can_write(actor):
                raise AccessDenied(f"write denied for {actor} on {dataset_id}")
            if etag and etag != ds.etag:
                raise Conflict("etag mismatch")
            for up in rm:
                try:
                    upds = self.storage.get(up)
                    ds.lineage.upstream.discard(up)
                    upds.lineage.downstream.discard(dataset_id)
                    upds.updated_at = _utcnow().isoformat(); upds.etag = self._new_etag()
                    self.storage.put(upds); self.storage.reindex(upds)
                except NotFound:
                    continue
            self._bump_and_stamp(ds, None, None, "patch", {"reason": "lineage_remove", "upstream_removed": list(rm)})
            self.storage.put(ds); self.storage.reindex(ds)
            self._audit(actor, "remove_lineage", dataset_id, {"upstream": list(rm)})
        self.events.publish("dataset.lineage_removed", {"dataset_id": dataset_id, "actor": actor, "upstream": list(rm)})
        return self.storage.get(dataset_id)

    def get_lineage_graph(self, actor: str, dataset_id: str, depth: int = 2) -> Dict[str, Any]:
        root = self.get_dataset(actor, dataset_id)
        visited: Set[str] = set()
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, str]] = []

        def add_node(ds: Dataset) -> None:
            nodes[ds.dataset_id] = {"id": ds.dataset_id, "name": ds.name, "layer": ds.layer}

        def dfs_up(did: str, d: int) -> None:
            if d < 0 or did in visited:
                return
            visited.add(did)
            ds = self.storage.get(did)
            add_node(ds)
            for up in ds.lineage.upstream:
                edges.append({"from": up, "to": did})
                dfs_up(up, d - 1)

        def dfs_down(did: str, d: int) -> None:
            if d < 0 or did in visited:
                return
            visited.add(did)
            ds = self.storage.get(did)
            add_node(ds)
            for dn in ds.lineage.downstream:
                edges.append({"from": did, "to": dn})
                dfs_down(dn, d - 1)

        dfs_up(root.dataset_id, depth)
        visited.clear()
        dfs_down(root.dataset_id, depth)
        return {"nodes": list(nodes.values()), "edges": edges}

    # ---- DQ / SLA ----
    def record_dq(self, actor: str, dataset_id: str, metrics: Dict[str, float], status: Optional[str] = None, etag: Optional[str] = None, idempotency_key: Optional[str] = None) -> Dataset:
        self._check_idemp(idempotency_key)
        ts = _utcnow().isoformat()
        with self.storage.txn():
            ds = self.storage.get(dataset_id)
            if not ds.acl.can_write(actor):
                raise AccessDenied(f"write denied for {actor} on {dataset_id}")
            if etag and etag != ds.etag:
                raise Conflict("etag mismatch")
            for k, v in metrics.items():
                ds.dq.metrics.append(DQMetric(name=k, value=float(v), ts_utc=ts))
            ds.dq.last_report_ts = ts
            if status:
                ds.dq.status = status
            ds.updated_at = ts
            ds.etag = self._new_etag()
            self.storage.put(ds); self.storage.reindex(ds)
            self._audit(actor, "record_dq", dataset_id, {"status": status, "metrics": list(metrics.keys())})
        self.events.publish("dataset.dq_recorded", {"dataset_id": dataset_id, "actor": actor})
        return self.storage.get(dataset_id)

    # ---- Search/Export/Import ----
    def search(self, actor: str, query: str, layer: Optional[str] = None, limit: int = 50, offset: int = 0) -> List[Dataset]:
        ids = set(self.storage.search_index(query))
        out: List[Dataset] = []
        for ds in self.storage.list_all():
            if ds.dataset_id not in ids:
                continue
            if layer and ds.layer != layer:
                continue
            if not ds.acl.can_read(actor):
                continue
            out.append(ds)
        out.sort(key=lambda d: (d.layer, d.name))
        return out[offset: offset + max(0, limit)]

    def export_json(self, actor: str, include_deleted: bool = False) -> str:
        payload = []
        for ds in self.storage.list_all():
            if not include_deleted and not ds.active:
                continue
            if ds.acl.can_admin(actor) or ds.acl.can_read(actor):
                payload.append(asdict(ds))
        blob = json.dumps({"exported_at": _utcnow().isoformat(), "datasets": payload}, ensure_ascii=False)
        _info("export_json", count=len(payload), actor=actor)
        return blob

    def import_json(self, actor: str, blob: str, overwrite: bool = False, idempotency_key: Optional[str] = None) -> int:
        self._check_idemp(idempotency_key)
        data = json.loads(blob)
        items = data.get("datasets", [])
        imported = 0
        with self.storage.txn():
            for raw in items:
                ds = self._from_dict(raw)
                try:
                    existing = self.storage.get(ds.dataset_id)
                    if not overwrite:
                        _warn("skip_existing", dataset_id=ds.dataset_id)
                        continue
                    if not existing.acl.can_admin(actor):
                        raise AccessDenied(f"admin denied for {actor} on {ds.dataset_id}")
                    self.storage.put(ds); self.storage.reindex(ds); imported += 1
                except NotFound:
                    self.storage.put(ds); self.storage.reindex(ds); imported += 1
            self._audit(actor, "import_json", None, {"count": imported})
        self.events.publish("catalog.imported", {"count": imported, "actor": actor})
        return imported

    # ---- Private helpers ----
    def _bump_and_stamp(
        self, ds: Dataset, new_schema: Optional[SchemaDef], partitions: Optional[PartitionDef],
        bump_policy: str, changeset: Dict[str, Any]
    ) -> None:
        if new_schema:
            _validate_schema(new_schema)
        new_ver = bump_version(ds.current_version, bump_policy)
        ver = DatasetVersion(
            version=new_ver,
            schema=new_schema or (ds.versions[-1].schema if ds.versions else SchemaDef()),
            partitions=partitions or (ds.versions[-1].partitions if ds.versions else PartitionDef()),
            description=changeset.get("description"),
            changeset=changeset,
        )
        ds.versions.append(ver)
        ds.current_version = new_ver
        ds.updated_at = _utcnow().isoformat()
        ds.etag = self._new_etag()

    def _from_dict(self, raw: Dict[str, Any]) -> Dataset:
        versions: List[DatasetVersion] = []
        for v in raw.get("versions", []):
            schema = SchemaDef([ColumnDef(**c) for c in v["schema"]["columns"]])
            partitions = PartitionDef(**v.get("partitions", {}))
            versions.append(DatasetVersion(
                version=v["version"],
                schema=schema,
                partitions=partitions,
                created_at=v.get("created_at", _utcnow().isoformat()),
                description=v.get("description"),
                changeset=v.get("changeset", {}),
            ))
        acl_raw = raw.get("acl", {})
        acl = ACL(
            owner=acl_raw.get("owner", "system"),
            readers=set(acl_raw.get("readers", [])),
            writers=set(acl_raw.get("writers", [])),
            admins=set(acl_raw.get("admins", [])),
        )
        ds = Dataset(
            dataset_id=raw["dataset_id"],
            name=raw["name"],
            layer=raw["layer"],
            system=raw.get("system"),
            path=raw.get("path"),
            tags=set(raw.get("tags", [])),
            owners=set(raw.get("owners", [])),
            acl=acl,
            sla=SLA(**raw["sla"]) if raw.get("sla") else None,
            dq=DQStatus(**raw.get("dq", {})),
            active=raw.get("active", True),
            created_at=raw.get("created_at", _utcnow().isoformat()),
            updated_at=raw.get("updated_at", _utcnow().isoformat()),
            current_version=raw.get("current_version"),
            versions=versions,
            lineage=Lineage(
                upstream=set(raw.get("lineage", {}).get("upstream", [])),
                downstream=set(raw.get("lineage", {}).get("downstream", [])),
            ),
            description=raw.get("description"),
            custom=raw.get("custom", {}),
            etag=raw.get("etag", str(uuid.uuid4())),
        )
        return ds

# =========================
# Reference usage (comment)
# =========================
# svc = CatalogService()
# schema = SchemaDef(columns=[
#     ColumnDef(name="order_id", dtype="long", nullable=False),
#     ColumnDef(name="amount", dtype="double", nullable=False),
#     ColumnDef(name="currency", dtype="string", nullable=False),
#     ColumnDef(name="dt", dtype="date", nullable=False),
# ])
# ds = svc.register_dataset(
#     actor="alice",
#     name="orders",
#     layer="curated",
#     system="delta",
#     path="s3a://curated/orders",
#     schema=schema,
#     description="Curated orders",
#     tags={"finance","orders"},
# )
# svc.add_lineage("alice", ds.dataset_id, upstream_ids=["raw:orders_raw"])
# svc.record_dq("alice", ds.dataset_id, {"rowcount_ok": 1.0, "null_rate": 0.0}, status="green")
# blob = svc.export_json("alice")
# print(blob)
