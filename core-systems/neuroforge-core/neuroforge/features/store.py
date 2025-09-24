# neuroforge-core/neuroforge/features/store.py
from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Sequence, Tuple

# ----------------------------- Optional deps -----------------------------
try:
    from pydantic import BaseModel, Field, ValidationError
    from pydantic import constr
    _HAVE_PYDANTIC = True
except Exception:  # pragma: no cover
    _HAVE_PYDANTIC = False
    class BaseModel:  # type: ignore
        def __init__(self, **data): self.__dict__.update(data)
        def model_dump(self, **kwargs): return self.__dict__
    def Field(*args, **kwargs): return None
    def constr(*args, **kwargs): return str
    class ValidationError(Exception): pass

try:
    import pandas as pd  # type: ignore
    _HAVE_PANDAS = True
except Exception:
    pd = None  # type: ignore
    _HAVE_PANDAS = False

try:
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore
    _HAVE_ARROW = True
except Exception:
    pa = pq = None  # type: ignore
    _HAVE_ARROW = False

try:
    import redis  # type: ignore
    _HAVE_REDIS = True
except Exception:
    redis = None  # type: ignore
    _HAVE_REDIS = False

try:
    from cachetools import TTLCache  # type: ignore
    _HAVE_CACHE = True
except Exception:
    TTLCache = None  # type: ignore
    _HAVE_CACHE = False

try:
    from prometheus_client import Counter  # type: ignore
    _HAVE_PROM = True
except Exception:
    Counter = None  # type: ignore
    _HAVE_PROM = False


# ----------------------------- Metrics (optional) -----------------------------
if _HAVE_PROM:
    MET_ONLINE_GET = Counter("nf_feat_online_get_total", "Online feature gets", ["status"])
    MET_MATERIALIZE = Counter("nf_feat_materialize_total", "Materialized records", ["view"])
else:  # pragma: no cover
    class _Dummy:
        def labels(self, *_, **__): return self
        def inc(self, *_): pass
    MET_ONLINE_GET = MET_MATERIALIZE = _Dummy()


# ----------------------------- Models / Registry -----------------------------
class ValueType(str):
    INT64 = "INT64"
    FLOAT64 = "FLOAT64"
    BOOL = "BOOL"
    STRING = "STRING"
    BYTES = "BYTES"
    VECTOR_FLOAT = "VECTOR_FLOAT"  # e.g., embeddings

class Entity(BaseModel):
    name: constr(strip_whitespace=True, min_length=1)  # type: ignore
    join_keys: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class Feature(BaseModel):
    name: constr(strip_whitespace=True, min_length=1)  # type: ignore
    dtype: Literal[
        ValueType.INT64, ValueType.FLOAT64, ValueType.BOOL, ValueType.STRING, ValueType.BYTES, ValueType.VECTOR_FLOAT
    ]
    description: Optional[str] = None
    ttl_sec: Optional[int] = Field(default=None, ge=1)

class BatchSource(BaseModel):
    kind: Literal["parquet", "table"] = "parquet"
    path_or_table: str
    timestamp_field: str = "event_timestamp"
    created_timestamp_field: Optional[str] = None  # for deduplication (latest write wins)

class StreamSource(BaseModel):
    kind: Literal["kafka", "kinesis", "pubsub"] = "kafka"
    topic: str
    timestamp_field: str = "event_timestamp"

class FeatureView(BaseModel):
    name: constr(strip_whitespace=True, min_length=1)  # type: ignore
    entities: List[str]  # names of Entity
    features: List[Feature]
    ttl_sec: Optional[int] = Field(default=None, ge=1)
    source: BatchSource  # batch source; stream optional дополняется в проде
    online: bool = True
    description: Optional[str] = None

class Registry(BaseModel):
    project: str
    entities: Dict[str, Entity] = Field(default_factory=dict)
    views: Dict[str, FeatureView] = Field(default_factory=dict)
    version: str = "1.0"

    def to_json(self) -> str:
        return json.dumps(self.model_dump(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "Registry":
        data = json.loads(s)
        # reconstruct Pydantic models
        ents = {k: Entity(**v) for k, v in data.get("entities", {}).items()}
        views = {k: FeatureView(**v) for k, v in data.get("views", {}).items()}
        return Registry(project=data["project"], entities=ents, views=views, version=data.get("version", "1.0"))


# ----------------------------- Online backend protocol -----------------------------
class OnlineBackend(Protocol):
    def mget(self, keys: List[str]) -> List[Optional[Dict[str, Any]]]: ...
    def set_many(self, kv: List[Tuple[str, Dict[str, Any]]], ttl_sec: Optional[int]) -> None: ...
    def delete_many(self, keys: List[str]) -> None: ...

class InMemoryOnlineBackend:
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[float, Optional[float], Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _expired(self, inserted_ts: float, ttl_sec: Optional[float]) -> bool:
        return ttl_sec is not None and (time.time() > inserted_ts + ttl_sec)

    def mget(self, keys: List[str]) -> List[Optional[Dict[str, Any]]]:
        out: List[Optional[Dict[str, Any]]] = []
        now = time.time()
        with self._lock:
            for k in keys:
                v = self._store.get(k)
                if not v:
                    out.append(None); continue
                inserted, ttl, payload = v
                if ttl is not None and now > inserted + ttl:
                    self._store.pop(k, None)
                    out.append(None); continue
                out.append(payload)
        return out

    def set_many(self, kv: List[Tuple[str, Dict[str, Any]]], ttl_sec: Optional[int]) -> None:
        now = time.time()
        with self._lock:
            for k, v in kv:
                self._store[k] = (now, float(ttl_sec) if ttl_sec else None, v)

    def delete_many(self, keys: List[str]) -> None:
        with self._lock:
            for k in keys:
                self._store.pop(k, None)

class RedisOnlineBackend:
    def __init__(self, url: str, namespace: str = "nf:fs"):
        if not _HAVE_REDIS:
            raise RuntimeError("redis is not installed")
        self._r = redis.Redis.from_url(url)  # type: ignore
        self.ns = namespace

    def _key(self, logical: str) -> str:
        return f"{self.ns}:{logical}"

    def mget(self, keys: List[str]) -> List[Optional[Dict[str, Any]]]:
        if not keys:
            return []
        rk = [self._key(k) for k in keys]
        vals = self._r.mget(rk)
        out = []
        for b in vals:
            if not b:
                out.append(None)
            else:
                try:
                    out.append(json.loads(b))
                except Exception:
                    out.append(None)
        return out

    def set_many(self, kv: List[Tuple[str, Dict[str, Any]]], ttl_sec: Optional[int]) -> None:
        if not kv:
            return
        pipe = self._r.pipeline(transaction=False)
        for k, v in kv:
            data = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
            if ttl_sec:
                pipe.setex(self._key(k), int(ttl_sec), data)
            else:
                pipe.set(self._key(k), data)
        pipe.execute()

    def delete_many(self, keys: List[str]) -> None:
        if not keys:
            return
        self._r.delete(*[self._key(k) for k in keys])


# ----------------------------- Offline backend protocol -----------------------------
class OfflineBackend(Protocol):
    def write(self, view: FeatureView, df: "pd.DataFrame") -> None: ...
    def read_range(self, view: FeatureView, start_ts: Optional[pd.Timestamp], end_ts: Optional[pd.Timestamp]) -> "pd.DataFrame": ...

class ParquetOfflineBackend:
    """
    Layout:
      base/
         <view.name>/
            part-YYYYMMDD.parquet  (append-only)
    """
    def __init__(self, base_path: str):
        if not (_HAVE_PANDAS and _HAVE_ARROW):
            raise RuntimeError("pandas and pyarrow are required for ParquetOfflineBackend")
        self.base = Path(base_path)
        self.base.mkdir(parents=True, exist_ok=True)

    def _view_dir(self, view: FeatureView) -> Path:
        d = self.base / view.name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write(self, view: FeatureView, df: "pd.DataFrame") -> None:
        vdir = self._view_dir(view)
        ts_col = view.source.timestamp_field
        if ts_col not in df.columns:
            raise ValueError(f"timestamp field '{ts_col}' missing")
        day = pd.to_datetime(df[ts_col]).dt.strftime("%Y%m%d").mode().iloc[0]
        fname = vdir / f"part-{day}.parquet"
        table = pa.Table.from_pandas(df)  # type: ignore
        if fname.exists():
            # append: read, concat, overwrite (simplified, robust)
            old = pq.read_table(str(fname)).to_pandas()  # type: ignore
            df2 = pd.concat([old, df], ignore_index=True)
            pq.write_table(pa.Table.from_pandas(df2), str(fname))  # type: ignore
        else:
            pq.write_table(table, str(fname))  # type: ignore

    def read_range(self, view: FeatureView, start_ts: Optional["pd.Timestamp"], end_ts: Optional["pd.Timestamp"]) -> "pd.DataFrame":
        vdir = self._view_dir(view)
        if not vdir.exists():
            return pd.DataFrame()  # type: ignore
        parts = sorted([p for p in vdir.glob("part-*.parquet")])
        if not parts:
            return pd.DataFrame()  # type: ignore
        dfs = [pq.read_table(str(p)).to_pandas() for p in parts]  # type: ignore
        df = pd.concat(dfs, ignore_index=True)
        ts_col = view.source.timestamp_field
        df[ts_col] = pd.to_datetime(df[ts_col], utc=True, errors="coerce")
        if start_ts is not None:
            df = df[df[ts_col] >= start_ts]
        if end_ts is not None:
            df = df[df[ts_col] < end_ts]
        return df


# ----------------------------- Utilities -----------------------------
def _stable_key(parts: Iterable[str]) -> str:
    s = "|".join(parts)
    h = hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]
    return f"{s}|{h}"

def _entity_key(view: FeatureView, registry: Registry, row: Dict[str, Any]) -> str:
    keys: List[str] = []
    for ent_name in view.entities:
        ent = registry.entities.get(ent_name)
        if not ent:
            raise ValueError(f"entity '{ent_name}' not in registry")
        for k in ent.join_keys:
            if k not in row:
                raise ValueError(f"missing join key '{k}' for entity '{ent_name}'")
            keys.append(f"{k}={row[k]}")
    return _stable_key([registry.project, view.name] + keys)

def _now_utc_ts() -> float:
    return time.time()

def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
        os.fsync(fd)
        os.close(fd)
    except Exception:
        pass


# ----------------------------- Feature Store -----------------------------
class FeatureStore:
    """
    Industrial Feature Store facade: registry + online/offline + materialization + retrieval.
    """
    def __init__(
        self,
        project: str,
        online: OnlineBackend,
        offline: OfflineBackend,
        registry_path: str,
        enable_cache: bool = True,
        cache_ttl_sec: int = 30,
    ):
        self.project = project
        self.online = online
        self.offline = offline
        self.registry_path = Path(registry_path)
        self._lock = threading.Lock()
        self.registry = self._load_or_init_registry(project)
        self._cache = TTLCache(maxsize=10_000, ttl=cache_ttl_sec) if (_HAVE_CACHE and enable_cache) else None

    # ---------- Registry ----------
    def _load_or_init_registry(self, project: str) -> Registry:
        if self.registry_path.exists():
            data = self.registry_path.read_text(encoding="utf-8")
            return Registry.from_json(data)
        reg = Registry(project=project)
        self._persist_registry(reg)
        return reg

    def _persist_registry(self, registry: Registry) -> None:
        tmp = self.registry_path.with_suffix(".tmp")
        tmp.write_text(registry.to_json(), encoding="utf-8")
        os.replace(tmp, self.registry_path)
        _fsync_dir(self.registry_path.parent)

    def register_entity(self, entity: Entity) -> None:
        with self._lock:
            self.registry.entities[entity.name] = entity
            self._persist_registry(self.registry)

    def register_view(self, view: FeatureView) -> None:
        # basic validation
        for ent in view.entities:
            if ent not in self.registry.entities:
                raise ValueError(f"entity '{ent}' is not registered")
        feature_names = [f.name for f in view.features]
        if len(set(feature_names)) != len(feature_names):
            raise ValueError("duplicate feature names in view")
        with self._lock:
            self.registry.views[view.name] = view
            self._persist_registry(self.registry)

    # ---------- Ingest / Materialize ----------
    def ingest_batch(self, view_name: str, df: "pd.DataFrame") -> None:
        """
        Append batch data to offline store for given view.
        df must contain entity join_keys, all feature columns, and event_timestamp column.
        """
        if not _HAVE_PANDAS:
            raise RuntimeError("pandas required for ingest")
        view = self._get_view(view_name)
        self.offline.write(view, df)

    def materialize(
        self,
        view_name: str,
        start_ts: Optional["pd.Timestamp"] = None,
        end_ts: Optional["pd.Timestamp"] = None,
        idempotency_key_col: Optional[str] = None,
    ) -> int:
        """
        Reads offline data for view within [start_ts, end_ts) and upserts into online store.
        Stores per-key payload: {"features": {...}, "event_ts": "...", "created_ts": epoch}
        TTL chosen as min(view.ttl, per-feature ttl) if specified, else None.
        """
        if not _HAVE_PANDAS:
            raise RuntimeError("pandas required for materialize")
        view = self._get_view(view_name)
        df = self.offline.read_range(view, start_ts, end_ts)
        if df.empty:
            return 0

        ts_col = view.source.timestamp_field
        df[ts_col] = pd.to_datetime(df[ts_col], utc=True, errors="coerce")  # type: ignore

        # latest by created_timestamp if provided, else by event ts
        if view.source.created_timestamp_field and view.source.created_timestamp_field in df.columns:
            df = df.sort_values(view.source.created_timestamp_field).drop_duplicates(
                subset=self._all_entity_keys(view), keep="last"  # type: ignore
            )
        else:
            df = df.sort_values(ts_col).drop_duplicates(subset=self._all_entity_keys(view), keep="last")  # type: ignore

        # TTL calculation
        ttl_candidates = [view.ttl_sec] + [f.ttl_sec for f in view.features if f.ttl_sec]
        ttl_sec = min([t for t in ttl_candidates if t]) if any(ttl_candidates) else None  # type: ignore

        # Prepare online payloads
        feature_cols = [f.name for f in view.features]
        kv: List[Tuple[str, Dict[str, Any]]] = []
        created = _now_utc_ts()
        for _, row in df.iterrows():  # type: ignore
            row_d = row.to_dict()
            key = _entity_key(view, self.registry, row_d)
            feats = {c: row_d.get(c) for c in feature_cols}
            payload = {"features": feats, "event_ts": str(row_d.get(ts_col)), "created_ts": created}
            kv.append((key, payload))

        self.online.set_many(kv, ttl_sec=ttl_sec)
        MET_MATERIALIZE.labels(view=view_name).inc(len(kv))
        return len(kv)

    # ---------- Online retrieval ----------
    def get_online_features(
        self,
        feature_refs: Sequence[str],
        entity_rows: Sequence[Dict[str, Any]],
        as_of: Optional["pd.Timestamp"] = None,
    ) -> List[Dict[str, Any]]:
        """
        feature_refs: ["view:feature", ...]
        entity_rows: [{join_key:value, ...}, ...]
        Returns list aligned to entity_rows: {"values": {...}, "stale": bool}
        """
        # group refs by view
        by_view: Dict[str, List[str]] = {}
        for ref in feature_refs:
            if ":" not in ref:
                raise ValueError("feature_refs must be 'view:feature'")
            v, f = ref.split(":", 1)
            by_view.setdefault(v, []).append(f)

        # fetch per-view to leverage shared keys
        results = [dict() for _ in entity_rows]  # type: ignore
        stale = [False for _ in entity_rows]
        for vname, feats in by_view.items():
            view = self._get_view(vname)
            keys = [_entity_key(view, self.registry, row) for row in entity_rows]
            cached: Optional[List[Optional[Dict[str, Any]]]] = None
            if self._cache is not None:
                cache_key = ("mget", vname, tuple(sorted(feats)), tuple(keys))
                cached = self._cache.get(cache_key)  # type: ignore
            vals = cached if cached is not None else self.online.mget(keys)
            if self._cache is not None and cached is None:
                self._cache[("mget", vname, tuple(sorted(feats)), tuple(keys))] = vals  # type: ignore

            for i, payload in enumerate(vals):
                if payload is None:
                    continue
                feat_map = payload.get("features", {})
                event_ts = payload.get("event_ts")
                # If as_of provided — skip newer records
                if as_of is not None and event_ts is not None:
                    try:
                        ts = pd.to_datetime(event_ts, utc=True)  # type: ignore
                        if ts > as_of:
                            continue
                    except Exception:
                        pass
                for f in feats:
                    results[i][f"{vname}:{f}"] = feat_map.get(f)

        # stale detection: if any requested feature missing
        for i in range(len(entity_rows)):
            missing = any((ref not in results[i]) for ref in feature_refs)
            stale[i] = missing

        status = "hit" if all(not s for s in stale) else "miss"
        MET_ONLINE_GET.labels(status=status).inc()
        return [{"values": results[i], "stale": stale[i]} for i in range(len(entity_rows))]

    # ---------- Historical retrieval (PIT) ----------
    def get_historical_features(
        self,
        feature_refs: Sequence[str],
        entity_df: "pd.DataFrame",
        event_timestamp_col: str,
        as_of: Optional["pd.Timestamp"] = None,
    ) -> "pd.DataFrame":
        """
        Point-in-time correct join from offline store.
        entity_df must contain join_keys + event_timestamp_col.
        """
        if not _HAVE_PANDAS:
            raise RuntimeError("pandas required for historical retrieval")
        # Normalize time
        df = entity_df.copy()
        df[event_timestamp_col] = pd.to_datetime(df[event_timestamp_col], utc=True, errors="coerce")  # type: ignore
        if as_of is not None:
            df = df[df[event_timestamp_col] <= as_of]

        # group refs by view
        by_view: Dict[str, List[str]] = {}
        for ref in feature_refs:
            v, f = ref.split(":", 1)
            by_view.setdefault(v, []).append(f)

        result = df
        for vname, feats in by_view.items():
            view = self._get_view(vname)
            src = self.offline.read_range(view, None, as_of)
            if src.empty:
                # create missing columns
                for f in feats:
                    result[f"{vname}:{f}"] = None
                continue
            ts_col = view.source.timestamp_field
            src[ts_col] = pd.to_datetime(src[ts_col], utc=True, errors="coerce")  # type: ignore

            # sort for merge_asof and merge on all join_keys
            on_keys = self._all_entity_keys(view)
            src = src.sort_values(ts_col)
            result = result.sort_values(event_timestamp_col)

            # Pandas merge_asof supports single-by; emulate multi-key with groupby trick:
            # create composite key
            def _ck(df_: "pd.DataFrame", keys: List[str]) -> "pd.Series":
                return df_[keys].astype(str).agg("|".join, axis=1)  # type: ignore

            src["_ck"] = _ck(src, on_keys)
            result["_ck"] = _ck(result, on_keys)

            joined = pd.merge_asof(
                left=result, right=src,
                by="_ck",
                left_on=event_timestamp_col, right_on=ts_col,
                direction="backward",
                suffixes=("", f"__{vname}")
            )
            # keep only requested features into namespaced columns
            for f in feats:
                if f in joined.columns:
                    joined[f"{vname}:{f}"] = joined[f]
                else:
                    joined[f"{vname}:{f}"] = None
            # drop temp cols
            result = joined.drop(columns=[c for c in joined.columns if c.endswith("__" + vname)] + ["_ck"])
        return result

    # ---------- Helpers ----------
    def _get_view(self, name: str) -> FeatureView:
        view = self.registry.views.get(name)
        if not view:
            raise ValueError(f"feature view '{name}' not found")
        return view

    def _all_entity_keys(self, view: FeatureView) -> List[str]:
        keys: List[str] = []
        for ent_name in view.entities:
            ent = self.registry.entities[ent_name]
            keys.extend(ent.join_keys)
        return keys


# ----------------------------- Convenience API -----------------------------
def create_inmemory_store(project: str, parquet_base: str, registry_path: str) -> FeatureStore:
    """
    Ready-to-use store with in-memory online backend and Parquet offline backend.
    """
    online = InMemoryOnlineBackend()
    offline = ParquetOfflineBackend(parquet_base)
    return FeatureStore(project=project, online=online, offline=offline, registry_path=registry_path)

def create_redis_store(project: str, redis_url: str, parquet_base: str, registry_path: str, namespace: str = "nf:fs") -> FeatureStore:
    online = RedisOnlineBackend(redis_url, namespace=namespace)
    offline = ParquetOfflineBackend(parquet_base)
    return FeatureStore(project=project, online=online, offline=offline, registry_path=registry_path)


# ----------------------------- Example (commented) -----------------------------
"""
# Define registry
store = create_inmemory_store(
    project="neuroforge",
    parquet_base="./data/features",
    registry_path="./data/registry.json",
)

store.register_entity(Entity(name="user", join_keys=["user_id"]))
store.register_view(FeatureView(
    name="user_stats",
    entities=["user"],
    features=[
        Feature(name="orders_30d", dtype=ValueType.INT64, ttl_sec=86400),
        Feature(name="avg_ticket_30d", dtype=ValueType.FLOAT64, ttl_sec=86400),
    ],
    ttl_sec=86400,
    source=BatchSource(kind="parquet", path_or_table="user_stats", timestamp_field="event_timestamp"),
))

# Ingest batch to offline
import pandas as pd, numpy as np
df = pd.DataFrame({
    "user_id": [1,1,2],
    "orders_30d": [3,4,1],
    "avg_ticket_30d": [12.3, 13.7, 9.0],
    "event_timestamp": pd.to_datetime(["2025-08-01","2025-08-15","2025-08-10"], utc=True),
})
store.ingest_batch("user_stats", df)

# Materialize to online
store.materialize("user_stats")

# Online retrieval
rows = [{"user_id": 1}, {"user_id": 2}]
res = store.get_online_features(["user_stats:orders_30d","user_stats:avg_ticket_30d"], rows)
# -> [{"values": {...}, "stale": False}, ...]

# Historical PIT
entity_df = pd.DataFrame({"user_id":[1,1,2], "event_timestamp": pd.to_datetime(["2025-08-05","2025-08-20","2025-08-15"], utc=True)})
hist = store.get_historical_features(["user_stats:orders_30d"], entity_df, "event_timestamp")
"""
