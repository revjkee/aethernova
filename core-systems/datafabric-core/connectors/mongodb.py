# datafabric-core/datafabric/connectors/mongodb.py
# -*- coding: utf-8 -*-
"""
Industrial-grade async MongoDB connector for DataFabric (Motor).

Features:
- Async Motor client with connection pooling, TLS/SRV, retryReads/retryWrites
- Resilient retries with exponential backoff + jitter (for transient ops)
- Transactions helper (replica set / Atlas)
- Health checks (ping), timeouts, bounded queries (projection/sort/limit)
- CRUD: insert/update/upsert/delete with safe defaults
- Bulk writes (ordered/unordered), index ensure (idempotent)
- Find with pagination (page/size, after_id), count, distinct
- Change streams (optional): watch collections or database
- ObjectId helpers and JSON-safe serialization (ISO dates, str(ObjectId))
- ENV-based config builder
- Integration with datafabric.context (log_info/log_error/trace_event)

Dependencies:
  motor>=3.4.0, pymongo>=4.x
Python: 3.10+
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import time
import typing as t
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps

# ---- Optional context integration ----
try:
    from datafabric.context import ExecutionContext, current_context, log_info, log_error, trace_event
except Exception:  # pragma: no cover
    ExecutionContext = t.Any  # type: ignore
    def current_context(): return None  # type: ignore
    def log_info(msg: str, **kw): print(f"[INFO] {msg} {kw}")  # type: ignore
    def log_error(msg: str, **kw): print(f"[ERROR] {msg} {kw}")  # type: ignore
    def trace_event(event: str, **fields): pass  # type: ignore

# ---- External dependency (motor) ----
try:
    import motor.motor_asyncio as motor_async
    from bson import ObjectId
    from pymongo import ASCENDING, DESCENDING, ReturnDocument, errors as pymongo_errors
    _MOTOR_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    raise RuntimeError("motor/pymongo are not installed. Please `pip install motor pymongo`.") from exc

# ------------------------------
# Utilities
# ------------------------------

def _utc_ms() -> int:
    return int(time.time() * 1000)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _jittered(base: float, jitter: float) -> float:
    import random
    delta = base * jitter
    return max(0.0, base + random.uniform(-delta, +delta))

def to_object_id(value: t.Union[str, ObjectId, None]) -> t.Optional[ObjectId]:
    if value is None:
        return None
    if isinstance(value, ObjectId):
        return value
    try:
        return ObjectId(str(value))
    except Exception:
        raise ValueError("Invalid ObjectId")

def to_json_safe(doc: t.Any) -> t.Any:
    """
    Convert BSON types into JSON-safe primitives.
    - ObjectId -> str
    - datetime -> ISO8601
    Works recursively for dict/list.
    """
    from bson import ObjectId
    if isinstance(doc, dict):
        return {k: to_json_safe(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [to_json_safe(x) for x in doc]
    if isinstance(doc, ObjectId):
        return str(doc)
    if isinstance(doc, datetime):
        if doc.tzinfo is None:
            doc = doc.replace(tzinfo=timezone.utc)
        return doc.isoformat()
    return doc

# ------------------------------
# Config
# ------------------------------

@dataclass
class RetryPolicy:
    initial_backoff_sec: float = 0.25
    max_backoff_sec: float = 8.0
    multiplier: float = 2.0
    jitter: float = 0.2
    max_attempts: int = 5
    # pymongo already retries some ops; this wraps transient failures around our calls.

@dataclass
class MongoConfig:
    # Connection
    uri: str = "mongodb://localhost:27017"
    db_name: str = "datafabric"
    tls: bool = False
    tls_ca_file: t.Optional[str] = None
    app_name: str = "datafabric-mongo"
    # Pool & timeouts
    max_pool_size: int = 100
    min_pool_size: int = 0
    connect_timeout_ms: int = 3000
    socket_timeout_ms: int = 15000
    server_selection_timeout_ms: int = 3000
    retry_reads: bool = True
    retry_writes: bool = True
    compressors: t.Optional[str] = "zstd"  # or "snappy,zstd" if compiled
    # Retry policy (wrapper)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    # Defaults
    default_read_concern: t.Optional[str] = None   # "local"|"majority"
    default_write_concern: t.Optional[int] = None  # w value (e.g., 1 or "majority")
    # Debug
    debug: bool = False

# ------------------------------
# Retry decorator for transient ops
# ------------------------------

_TRANSIENT_EXC = (
    pymongo_errors.AutoReconnect,
    pymongo_errors.NetworkTimeout,
    pymongo_errors.NotPrimaryError,
    pymongo_errors.ServerSelectionTimeoutError,
    pymongo_errors.ExecutionTimeout,
)

def with_retry(fn):
    @wraps(fn)
    async def _wrapped(self, *args, **kwargs):
        rp = self.cfg.retry
        delay = rp.initial_backoff_sec
        attempt = 0
        while True:
            try:
                return await fn(self, *args, **kwargs)
            except _TRANSIENT_EXC as exc:
                attempt += 1
                if attempt >= rp.max_attempts:
                    log_error("Mongo transient failure (max attempts)", op=fn.__name__, error=str(exc))
                    raise
                await asyncio.sleep(_jittered(delay, rp.jitter))
                delay = min(delay * rp.multiplier, rp.max_backoff_sec)
            except Exception:
                # Non-transient: bubble up
                raise
    return _wrapped

# ------------------------------
# Connector
# ------------------------------

class MongoConnector:
    """
    Async MongoDB connector with robust defaults and helpers.
    """

    def __init__(self, cfg: MongoConfig) -> None:
        self.cfg = cfg
        self._client: t.Optional[motor_async.AsyncIOMotorClient] = None
        self._db = None

    # ---- Lifecycle ----

    async def start(self) -> None:
        if self._client:
            return
        kwargs: dict = dict(
            maxPoolSize=self.cfg.max_pool_size,
            minPoolSize=self.cfg.min_pool_size,
            appname=self.cfg.app_name,
            serverSelectionTimeoutMS=self.cfg.server_selection_timeout_ms,
            connectTimeoutMS=self.cfg.connect_timeout_ms,
            socketTimeoutMS=self.cfg.socket_timeout_ms,
            retryReads=self.cfg.retry_reads,
            retryWrites=self.cfg.retry_writes,
        )
        if self.cfg.compressors:
            kwargs["compressors"] = self.cfg.compressors
        if self.cfg.tls:
            kwargs["tls"] = True
            if self.cfg.tls_ca_file:
                kwargs["tlsCAFile"] = self.cfg.tls_ca_file

        self._client = motor_async.AsyncIOMotorClient(self.cfg.uri, **kwargs)
        self._db = self._client[self.cfg.db_name]
        # Optional: set concerns if provided
        if self.cfg.default_read_concern:
            from pymongo.read_concern import ReadConcern
            self._db = self._db.with_options(read_concern=ReadConcern(self.cfg.default_read_concern))
        if self.cfg.default_write_concern is not None:
            from pymongo.write_concern import WriteConcern
            wc = self.cfg.default_write_concern
            wc = WriteConcern(w=wc)
            self._db = self._db.with_options(write_concern=wc)
        # Warm-up ping
        await self.ping()
        log_info("Mongo connector started", uri=self._redact_uri(self.cfg.uri), db=self.cfg.db_name)

    async def close(self) -> None:
        if self._client:
            self._client.close()  # motor close is sync
        self._client = None
        self._db = None
        log_info("Mongo connector closed")

    # ---- Introspection ----

    @property
    def db(self):
        if not self._db:
            raise RuntimeError("MongoConnector is not started")
        return self._db

    def collection(self, name: str):
        return self.db[name]

    @staticmethod
    def _redact_uri(uri: str) -> str:
        # redact credentials in logs
        if "@@" in uri:
            return uri
        try:
            if "@" in uri and "://" in uri:
                scheme, rest = uri.split("://", 1)
                creds, host = rest.split("@", 1)
                return f"{scheme}://***:***@{host}"
        except Exception:
            pass
        return uri

    # ---- Health ----

    @with_retry
    async def ping(self) -> bool:
        try:
            await self.db.command("ping")
            return True
        except Exception as exc:
            log_error("Mongo ping failed", error=str(exc))
            return False

    # ---- Indexes ----

    @with_retry
    async def ensure_indexes(self, coll: str, indexes: list[dict], *, background: bool = True) -> list[str]:
        """
        indexes: список описаний вида:
          {"keys": [("field", 1), ("other", -1)], "unique": True, "name": "idx_name", ...}
        """
        c = self.collection(coll)
        names = []
        for idx in indexes:
            keys = idx.pop("keys")
            name = await c.create_index(keys, background=background, **idx)
            names.append(name)
        trace_event("mongo_indexes_ensured", collection=coll, count=len(names))
        return names

    # ---- CRUD / Queries ----

    @with_retry
    async def find_one(
        self,
        coll: str,
        filt: dict,
        *,
        projection: t.Optional[dict] = None,
        sort: t.Optional[list[tuple[str, int]]] = None,
    ) -> t.Optional[dict]:
        c = self.collection(coll)
        doc = await c.find_one(filt, projection=projection, sort=sort)
        return doc

    @with_retry
    async def find_many(
        self,
        coll: str,
        filt: dict,
        *,
        projection: t.Optional[dict] = None,
        sort: t.Optional[list[tuple[str, int]]] = None,
        limit: int = 100,
        skip: int = 0,
    ) -> list[dict]:
        c = self.collection(coll)
        cursor = c.find(filt, projection=projection)
        if sort:
            cursor = cursor.sort(sort)
        if skip:
            cursor = cursor.skip(skip)
        if limit:
            cursor = cursor.limit(int(limit))
        docs = await cursor.to_list(length=limit or 100)
        return docs

    @with_retry
    async def find_page(
        self,
        coll: str,
        filt: dict,
        *,
        page: int = 1,
        size: int = 100,
        projection: t.Optional[dict] = None,
        sort: t.Optional[list[tuple[str, int]]] = None,
    ) -> dict:
        size = max(1, min(1000, int(size)))
        page = max(1, int(page))
        skip = (page - 1) * size
        docs = await self.find_many(coll, filt, projection=projection, sort=sort, limit=size, skip=skip)
        total = await self.count(coll, filt)
        return {"page": page, "size": size, "total": total, "items": docs}

    @with_retry
    async def count(self, coll: str, filt: dict) -> int:
        c = self.collection(coll)
        return await c.count_documents(filt)

    @with_retry
    async def distinct(self, coll: str, key: str, filt: dict) -> list:
        c = self.collection(coll)
        return await c.distinct(key, filt)

    @with_retry
    async def insert_one(self, coll: str, doc: dict) -> str:
        c = self.collection(coll)
        res = await c.insert_one(doc)
        trace_event("mongo_insert_one", collection=coll, id=str(res.inserted_id))
        return str(res.inserted_id)

    @with_retry
    async def insert_many(self, coll: str, docs: list[dict], *, ordered: bool = False) -> list[str]:
        c = self.collection(coll)
        res = await c.insert_many(docs, ordered=ordered)
        ids = [str(x) for x in res.inserted_ids]
        trace_event("mongo_insert_many", collection=coll, count=len(ids))
        return ids

    @with_retry
    async def update_one(
        self, coll: str, filt: dict, update: dict, *, upsert: bool = False, return_document: bool = False
    ) -> t.Optional[dict]:
        c = self.collection(coll)
        if return_document:
            doc = await c.find_one_and_update(
                filt, update, upsert=upsert, return_document=ReturnDocument.AFTER
            )
            return doc
        else:
            res = await c.update_one(filt, update, upsert=upsert)
            trace_event("mongo_update_one", collection=coll, matched=res.matched_count, modified=res.modified_count, upserted=str(res.upserted_id) if res.upserted_id else None)
            return None

    @with_retry
    async def update_many(self, coll: str, filt: dict, update: dict, *, upsert: bool = False) -> dict:
        c = self.collection(coll)
        res = await c.update_many(filt, update, upsert=upsert)
        trace_event("mongo_update_many", collection=coll, matched=res.matched_count, modified=res.modified_count, upserted=str(res.upserted_id) if res.upserted_id else None)
        return {"matched": res.matched_count, "modified": res.modified_count, "upserted_id": str(res.upserted_id) if res.upserted_id else None}

    @with_retry
    async def replace_one(self, coll: str, filt: dict, replacement: dict, *, upsert: bool = False) -> dict:
        c = self.collection(coll)
        res = await c.replace_one(filt, replacement, upsert=upsert)
        trace_event("mongo_replace_one", collection=coll, matched=res.matched_count, modified=res.modified_count, upserted=str(res.upserted_id) if res.upserted_id else None)
        return {"matched": res.matched_count, "modified": res.modified_count, "upserted_id": str(res.upserted_id) if res.upserted_id else None}

    @with_retry
    async def delete_one(self, coll: str, filt: dict) -> int:
        c = self.collection(coll)
        res = await c.delete_one(filt)
        trace_event("mongo_delete_one", collection=coll, deleted=res.deleted_count)
        return res.deleted_count

    @with_retry
    async def delete_many(self, coll: str, filt: dict) -> int:
        c = self.collection(coll)
        res = await c.delete_many(filt)
        trace_event("mongo_delete_many", collection=coll, deleted=res.deleted_count)
        return res.deleted_count

    # ---- Bulk ----

    @with_retry
    async def bulk_write(self, coll: str, operations: list, *, ordered: bool = False) -> dict:
        """
        operations: список pymongo операций, например:
          [InsertOne({...}), UpdateOne(filter, update, upsert=True), DeleteOne(filter)]
        """
        from pymongo import InsertOne, UpdateOne, DeleteOne, ReplaceOne
        c = self.collection(coll)
        res = await c.bulk_write(operations, ordered=ordered)
        out = {
            "inserted": res.inserted_count,
            "matched": res.matched_count,
            "modified": res.modified_count,
            "deleted": res.deleted_count,
            "upserts": [{str(k._Document__id): str(v)} for k, v in (res.upserted_ids or {}).items()] if getattr(res, "upserted_ids", None) else [],
        }
        trace_event("mongo_bulk_write", collection=coll, stats=out)
        return out

    # ---- Transactions ----

    async def with_transaction(self, coro_fn: t.Callable[..., t.Awaitable[t.Any]], *args, **kwargs) -> t.Any:
        """
        Выполнить пользовательскую корутину в транзакции.
        Требует реплика-сет/Atlas и writeConcern/readConcern/rcLevel по умолчанию.
        """
        if not self._client:
            raise RuntimeError("MongoConnector is not started")
        async with await self._client.start_session() as s:
            async def _txn_callback(session):
                return await coro_fn(session, *args, **kwargs)
            # motor предлагает session.with_transaction; используем с базовыми параметрами
            return await s.with_transaction(_txn_callback)

    # ---- Change Streams ----

    async def watch_collection(
        self,
        coll: str,
        pipeline: t.Optional[list] = None,
        *,
        full_document: str = "default",  # "default"|"updateLookup"
        stop_event: t.Optional[asyncio.Event] = None,
        handler: t.Callable[[dict], t.Awaitable[None]] = lambda ev: asyncio.sleep(0),
    ) -> None:
        """
        Асинхронное наблюдение за изменениями в коллекции.
        Внимание: требует реплика-сет/Atlas и соответствующие привилегии.
        """
        stop_event = stop_event or asyncio.Event()
        c = self.collection(coll)
        try:
            async with c.watch(pipeline or [], full_document=full_document) as stream:
                async for change in stream:
                    try:
                        await handler(to_json_safe(change))
                    except Exception as exc:
                        log_error("Change stream handler failed", error=str(exc))
                    if stop_event.is_set():
                        break
        except Exception as exc:
            log_error("Change stream error", collection=coll, error=str(exc))
            raise

# ------------------------------
# ENV builder
# ------------------------------

def build_from_env(prefix: str = "DF_MONGO_") -> MongoConfig:
    e = os.getenv
    cfg = MongoConfig(
        uri=e(f"{prefix}URI", "mongodb://localhost:27017"),
        db_name=e(f"{prefix}DB", "datafabric"),
        tls=e(f"{prefix}TLS", "false").lower() == "true",
        tls_ca_file=e(f"{prefix}TLS_CA_FILE"),
        app_name=e(f"{prefix}APP_NAME", "datafabric-mongo"),
        max_pool_size=int(e(f"{prefix}MAX_POOL", "100")),
        min_pool_size=int(e(f"{prefix}MIN_POOL", "0")),
        connect_timeout_ms=int(e(f"{prefix}CONNECT_TIMEOUT_MS", "3000")),
        socket_timeout_ms=int(e(f"{prefix}SOCKET_TIMEOUT_MS", "15000")),
        server_selection_timeout_ms=int(e(f"{prefix}SERVER_SELECTION_TIMEOUT_MS", "3000")),
        retry_reads=e(f"{prefix}RETRY_READS", "true").lower() == "true",
        retry_writes=e(f"{prefix}RETRY_WRITES", "true").lower() == "true",
        compressors=e(f"{prefix}COMPRESSORS", "zstd"),
        debug=e(f"{prefix}DEBUG", "false").lower() == "true",
    )
    # Optional concerns
    rc = e(f"{prefix}READ_CONCERN")
    wc = e(f"{prefix}WRITE_CONCERN")
    if rc:
        cfg.default_read_concern = rc
    if wc:
        try:
            cfg.default_write_concern = int(wc) if wc.isdigit() else None
            if cfg.default_write_concern is None and wc.lower() == "majority":
                cfg.default_write_concern = "majority"  # type: ignore
        except Exception:
            pass
    # Retry overrides
    try:
        cfg.retry.initial_backoff_sec = float(e(f"{prefix}RETRY_INITIAL", str(cfg.retry.initial_backoff_sec)))
        cfg.retry.max_backoff_sec = float(e(f"{prefix}RETRY_MAX", str(cfg.retry.max_backoff_sec)))
        cfg.retry.multiplier = float(e(f"{prefix}RETRY_MULT", str(cfg.retry.multiplier)))
        cfg.retry.jitter = float(e(f"{prefix}RETRY_JITTER", str(cfg.retry.jitter)))
        cfg.retry.max_attempts = int(e(f"{prefix}RETRY_ATTEMPTS", str(cfg.retry.max_attempts)))
    except Exception:
        pass
    return cfg

# ------------------------------
# Example (reference only)
# ------------------------------
# async def example():
#     cfg = build_from_env()
#     conn = MongoConnector(cfg)
#     await conn.start()
#     try:
#         await conn.ensure_indexes("users", [{"keys": [("email", 1)], "unique": True, "name": "ux_users_email"}])
#         uid = await conn.insert_one("users", {"email": "a@b.c", "created_at": datetime.utcnow()})
#         doc = await conn.find_one("users", {"_id": ObjectId(uid)}, projection={"email": 1})
#         print(to_json_safe(doc))
#     finally:
#         await conn.close()
