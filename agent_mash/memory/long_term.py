# agent_mash/memory/long_term.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import typing as t
import uuid

from agent_mash.governance.audit_log import AuditLogger

Json = dict[str, t.Any]


class MemoryError(RuntimeError):
    pass


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _safe_uuid() -> str:
    return str(uuid.uuid4())


def _stable_json(obj: t.Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ensure_tz(dt_: dt.datetime) -> dt.datetime:
    if dt_.tzinfo is None:
        raise MemoryError("datetime must be timezone-aware")
    return dt_


def _truncate_str(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _clamp_int(v: int, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _normalize_tag(tag: str) -> str:
    t_ = tag.strip().lower()
    t_ = re.sub(r"\s+", "-", t_)
    t_ = re.sub(r"[^a-z0-9._:-]+", "", t_)
    return t_


def _now_unix() -> float:
    return time.time()


@dataclasses.dataclass(frozen=True, slots=True)
class MemoryConfig:
    enabled: bool = True

    # Limits
    max_key_len: int = 256
    max_text_len: int = 16_384
    max_meta_bytes: int = 64_000
    max_tags: int = 32
    max_tag_len: int = 64

    # TTL and retention
    default_ttl_s: int = 0  # 0 = no TTL
    hard_ttl_s: int = 0     # 0 = disabled; if set, overrides/limits ttl

    # Deduplication
    enable_dedup: bool = True
    dedup_scope: str = "global"  # global|namespace

    # Search behavior
    max_search_results: int = 200

    # Audit
    audit_enabled: bool = True

    @staticmethod
    def from_env(prefix: str = "AGENT_MASH_LTM_") -> "MemoryConfig":
        def env(name: str, default: str) -> str:
            v = os.environ.get(prefix + name, default)
            v = v.strip()
            return v if v else default

        def env_bool(name: str, default: bool) -> bool:
            v = os.environ.get(prefix + name)
            if v is None:
                return default
            s = v.strip().lower()
            if s in {"1", "true", "yes", "y", "on"}:
                return True
            if s in {"0", "false", "no", "n", "off"}:
                return False
            return default

        def env_int(name: str, default: int) -> int:
            v = env(name, str(default))
            try:
                return int(v)
            except ValueError as e:
                raise MemoryError(f"Invalid int env {prefix}{name}={v}") from e

        return MemoryConfig(
            enabled=env_bool("ENABLED", True),
            max_key_len=_clamp_int(env_int("MAX_KEY_LEN", 256), 16, 4096),
            max_text_len=_clamp_int(env_int("MAX_TEXT_LEN", 16_384), 256, 1_000_000),
            max_meta_bytes=_clamp_int(env_int("MAX_META_BYTES", 64_000), 1024, 10_000_000),
            max_tags=_clamp_int(env_int("MAX_TAGS", 32), 0, 512),
            max_tag_len=_clamp_int(env_int("MAX_TAG_LEN", 64), 8, 256),
            default_ttl_s=max(0, env_int("DEFAULT_TTL_S", 0)),
            hard_ttl_s=max(0, env_int("HARD_TTL_S", 0)),
            enable_dedup=env_bool("ENABLE_DEDUP", True),
            dedup_scope=env("DEDUP_SCOPE", "global").lower(),
            max_search_results=_clamp_int(env_int("MAX_SEARCH_RESULTS", 200), 1, 10_000),
            audit_enabled=env_bool("AUDIT_ENABLED", True),
        )


@dataclasses.dataclass(frozen=True, slots=True)
class MemoryRecord:
    record_id: str
    namespace: str
    key: str
    text: str
    tags: tuple[str, ...]
    meta: Json
    created_at: dt.datetime
    updated_at: dt.datetime
    expires_at: dt.datetime | None
    content_hash: str

    def to_dict(self) -> Json:
        return {
            "record_id": self.record_id,
            "namespace": self.namespace,
            "key": self.key,
            "text": self.text,
            "tags": list(self.tags),
            "meta": self.meta,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at is not None else None,
            "content_hash": self.content_hash,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class UpsertResult:
    record: MemoryRecord
    created: bool
    deduped: bool

    def to_dict(self) -> Json:
        return {
            "created": self.created,
            "deduped": self.deduped,
            "record": self.record.to_dict(),
        }


@dataclasses.dataclass(frozen=True, slots=True)
class MemoryQuery:
    namespace: str | None = None
    text_contains: str | None = None
    key_prefix: str | None = None
    tags_all: tuple[str, ...] = ()
    tags_any: tuple[str, ...] = ()
    created_from: dt.datetime | None = None
    created_to: dt.datetime | None = None
    include_expired: bool = False
    limit: int = 50

    def normalized(self, cfg: MemoryConfig) -> "MemoryQuery":
        lim = _clamp_int(int(self.limit), 1, cfg.max_search_results)
        tags_all = tuple(_normalize_tag(x) for x in self.tags_all if x and x.strip())
        tags_any = tuple(_normalize_tag(x) for x in self.tags_any if x and x.strip())
        ns = self.namespace.strip() if isinstance(self.namespace, str) else None
        if ns == "":
            ns = None
        return MemoryQuery(
            namespace=ns,
            text_contains=_truncate_str(self.text_contains.strip(), 2048) if isinstance(self.text_contains, str) else None,
            key_prefix=_truncate_str(self.key_prefix.strip(), cfg.max_key_len) if isinstance(self.key_prefix, str) else None,
            tags_all=tags_all,
            tags_any=tags_any,
            created_from=_ensure_tz(self.created_from) if self.created_from is not None else None,
            created_to=_ensure_tz(self.created_to) if self.created_to is not None else None,
            include_expired=bool(self.include_expired),
            limit=lim,
        )


class MemoryStore(abc.ABC):
    @abc.abstractmethod
    def upsert(
        self,
        *,
        namespace: str,
        key: str,
        text: str,
        tags: tuple[str, ...],
        meta: Json,
        expires_at: dt.datetime | None,
        content_hash: str,
    ) -> tuple[MemoryRecord, bool]:
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, *, namespace: str, key: str, include_expired: bool) -> MemoryRecord | None:
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self, *, namespace: str, key: str) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def search(self, *, q: MemoryQuery) -> list[MemoryRecord]:
        raise NotImplementedError

    @abc.abstractmethod
    def prune_expired(self, *, now: dt.datetime) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def export_all(self, *, include_expired: bool) -> list[MemoryRecord]:
        raise NotImplementedError

    @abc.abstractmethod
    def close(self) -> None:
        raise NotImplementedError


class SQLiteMemoryStore(MemoryStore):
    """
    Production-friendly store with SQLite.
    Full-text search: simple LIKE on text/key/tags (no FTS to keep stdlib-only).
    """

    def __init__(self, path: str) -> None:
        self._path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ltm_records (
                    record_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    key TEXT NOT NULL,
                    text TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    meta_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NULL,
                    content_hash TEXT NOT NULL,
                    UNIQUE(namespace, key)
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ltm_ns_key ON ltm_records(namespace, key);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ltm_expires ON ltm_records(expires_at);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ltm_created ON ltm_records(created_at);"
            )

    def upsert(
        self,
        *,
        namespace: str,
        key: str,
        text: str,
        tags: tuple[str, ...],
        meta: Json,
        expires_at: dt.datetime | None,
        content_hash: str,
    ) -> tuple[MemoryRecord, bool]:
        now = _utc_now()
        record_id = _safe_uuid()

        tags_json = _stable_json(list(tags))
        meta_json = _stable_json(meta)
        expires_s = expires_at.isoformat() if expires_at is not None else None

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT record_id, created_at FROM ltm_records WHERE namespace=? AND key=?",
                (namespace, key),
            ).fetchone()

            if row is None:
                self._conn.execute(
                    """
                    INSERT INTO ltm_records
                    (record_id, namespace, key, text, tags_json, meta_json, created_at, updated_at, expires_at, content_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record_id,
                        namespace,
                        key,
                        text,
                        tags_json,
                        meta_json,
                        now.isoformat(),
                        now.isoformat(),
                        expires_s,
                        content_hash,
                    ),
                )
                created_at = now
                created = True
                rid = record_id
            else:
                rid = str(row[0])
                created_at = dt.datetime.fromisoformat(str(row[1]))
                self._conn.execute(
                    """
                    UPDATE ltm_records
                    SET text=?, tags_json=?, meta_json=?, updated_at=?, expires_at=?, content_hash=?
                    WHERE namespace=? AND key=?
                    """,
                    (
                        text,
                        tags_json,
                        meta_json,
                        now.isoformat(),
                        expires_s,
                        content_hash,
                        namespace,
                        key,
                    ),
                )
                created = False

            rec = MemoryRecord(
                record_id=rid,
                namespace=namespace,
                key=key,
                text=text,
                tags=tags,
                meta=meta,
                created_at=_ensure_tz(created_at.replace(tzinfo=created_at.tzinfo or dt.timezone.utc)),
                updated_at=now,
                expires_at=expires_at,
                content_hash=content_hash,
            )
            return rec, created

    def get(self, *, namespace: str, key: str, include_expired: bool) -> MemoryRecord | None:
        now = _utc_now()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT record_id, text, tags_json, meta_json, created_at, updated_at, expires_at, content_hash
                FROM ltm_records
                WHERE namespace=? AND key=?
                """,
                (namespace, key),
            ).fetchone()

        if row is None:
            return None

        expires_at = dt.datetime.fromisoformat(row[6]) if row[6] is not None else None
        if expires_at is not None:
            expires_at = _ensure_tz(expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=dt.timezone.utc))
        if (not include_expired) and (expires_at is not None) and (expires_at <= now):
            return None

        created_at = dt.datetime.fromisoformat(row[4])
        updated_at = dt.datetime.fromisoformat(row[5])
        created_at = _ensure_tz(created_at if created_at.tzinfo is not None else created_at.replace(tzinfo=dt.timezone.utc))
        updated_at = _ensure_tz(updated_at if updated_at.tzinfo is not None else updated_at.replace(tzinfo=dt.timezone.utc))

        tags = tuple(json.loads(row[2]))
        meta = json.loads(row[3])

        return MemoryRecord(
            record_id=str(row[0]),
            namespace=namespace,
            key=key,
            text=str(row[1]),
            tags=tags,
            meta=meta,
            created_at=created_at,
            updated_at=updated_at,
            expires_at=expires_at,
            content_hash=str(row[7]),
        )

    def delete(self, *, namespace: str, key: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM ltm_records WHERE namespace=? AND key=?",
                (namespace, key),
            )
            return int(cur.rowcount or 0) > 0

    def search(self, *, q: MemoryQuery) -> list[MemoryRecord]:
        now = _utc_now()
        qn = q  # already normalized upstream
        params: list[t.Any] = []
        where: list[str] = []

        if qn.namespace is not None:
            where.append("namespace=?")
            params.append(qn.namespace)

        if qn.key_prefix:
            where.append("key LIKE ?")
            params.append(qn.key_prefix.replace("%", "") + "%")

        if qn.text_contains:
            # match in text or key or meta_json or tags_json
            pat = "%" + qn.text_contains.replace("%", "") + "%"
            where.append("(text LIKE ? OR key LIKE ? OR meta_json LIKE ? OR tags_json LIKE ?)")
            params.extend([pat, pat, pat, pat])

        if qn.created_from is not None:
            where.append("created_at >= ?")
            params.append(qn.created_from.isoformat())

        if qn.created_to is not None:
            where.append("created_at <= ?")
            params.append(qn.created_to.isoformat())

        if not qn.include_expired:
            where.append("(expires_at IS NULL OR expires_at > ?)")
            params.append(now.isoformat())

        # tags filtering: stdlib-only approach via JSON string matching
        for tag in qn.tags_all:
            where.append("tags_json LIKE ?")
            params.append('%"' + tag.replace("%", "") + '"%')

        if qn.tags_any:
            ors: list[str] = []
            for tag in qn.tags_any:
                ors.append("tags_json LIKE ?")
                params.append('%"' + tag.replace("%", "") + '"%')
            where.append("(" + " OR ".join(ors) + ")")

        sql = """
            SELECT namespace, key, record_id, text, tags_json, meta_json, created_at, updated_at, expires_at, content_hash
            FROM ltm_records
        """
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(int(qn.limit))

        with self._lock:
            rows = self._conn.execute(sql, tuple(params)).fetchall()

        out: list[MemoryRecord] = []
        for r in rows:
            expires_at = dt.datetime.fromisoformat(r[8]) if r[8] is not None else None
            if expires_at is not None:
                expires_at = _ensure_tz(expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=dt.timezone.utc))

            created_at = dt.datetime.fromisoformat(r[6])
            updated_at = dt.datetime.fromisoformat(r[7])
            created_at = _ensure_tz(created_at if created_at.tzinfo is not None else created_at.replace(tzinfo=dt.timezone.utc))
            updated_at = _ensure_tz(updated_at if updated_at.tzinfo is not None else updated_at.replace(tzinfo=dt.timezone.utc))

            tags = tuple(json.loads(r[4]))
            meta = json.loads(r[5])

            out.append(
                MemoryRecord(
                    record_id=str(r[2]),
                    namespace=str(r[0]),
                    key=str(r[1]),
                    text=str(r[3]),
                    tags=tags,
                    meta=meta,
                    created_at=created_at,
                    updated_at=updated_at,
                    expires_at=expires_at,
                    content_hash=str(r[9]),
                )
            )
        return out

    def prune_expired(self, *, now: dt.datetime) -> int:
        now = _ensure_tz(now)
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM ltm_records WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (now.isoformat(),),
            )
            return int(cur.rowcount or 0)

    def export_all(self, *, include_expired: bool) -> list[MemoryRecord]:
        now = _utc_now()
        sql = """
            SELECT namespace, key, record_id, text, tags_json, meta_json, created_at, updated_at, expires_at, content_hash
            FROM ltm_records
        """
        params: list[t.Any] = []
        if not include_expired:
            sql += " WHERE (expires_at IS NULL OR expires_at > ?)"
            params.append(now.isoformat())
        sql += " ORDER BY created_at ASC"

        with self._lock:
            rows = self._conn.execute(sql, tuple(params)).fetchall()

        out: list[MemoryRecord] = []
        for r in rows:
            expires_at = dt.datetime.fromisoformat(r[8]) if r[8] is not None else None
            if expires_at is not None:
                expires_at = _ensure_tz(expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=dt.timezone.utc))

            created_at = dt.datetime.fromisoformat(r[6])
            updated_at = dt.datetime.fromisoformat(r[7])
            created_at = _ensure_tz(created_at if created_at.tzinfo is not None else created_at.replace(tzinfo=dt.timezone.utc))
            updated_at = _ensure_tz(updated_at if updated_at.tzinfo is not None else updated_at.replace(tzinfo=dt.timezone.utc))

            tags = tuple(json.loads(r[4]))
            meta = json.loads(r[5])

            out.append(
                MemoryRecord(
                    record_id=str(r[2]),
                    namespace=str(r[0]),
                    key=str(r[1]),
                    text=str(r[3]),
                    tags=tags,
                    meta=meta,
                    created_at=created_at,
                    updated_at=updated_at,
                    expires_at=expires_at,
                    content_hash=str(r[9]),
                )
            )
        return out

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass


class JsonlMemoryStore(MemoryStore):
    """
    Append-only JSONL store (best-effort).
    Для production рекомендуется SQLiteMemoryStore.
    Реализация хранит актуальное состояние в памяти (индекс).
    """

    def __init__(self, path: str) -> None:
        self._path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self._index: dict[tuple[str, str], MemoryRecord] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        with self._lock, open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if obj.get("_op") == "delete":
                    ns = str(obj.get("namespace", ""))
                    key = str(obj.get("key", ""))
                    self._index.pop((ns, key), None)
                    continue
                if obj.get("_op") == "upsert":
                    rec = _record_from_dict(obj.get("record"))
                    self._index[(rec.namespace, rec.key)] = rec

    def _append(self, obj: Json) -> None:
        line = _stable_json(obj)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()

    def upsert(
        self,
        *,
        namespace: str,
        key: str,
        text: str,
        tags: tuple[str, ...],
        meta: Json,
        expires_at: dt.datetime | None,
        content_hash: str,
    ) -> tuple[MemoryRecord, bool]:
        now = _utc_now()
        with self._lock:
            existing = self._index.get((namespace, key))
            created = existing is None
            record_id = existing.record_id if existing is not None else _safe_uuid()
            created_at = existing.created_at if existing is not None else now

            rec = MemoryRecord(
                record_id=record_id,
                namespace=namespace,
                key=key,
                text=text,
                tags=tags,
                meta=meta,
                created_at=created_at,
                updated_at=now,
                expires_at=expires_at,
                content_hash=content_hash,
            )
            self._index[(namespace, key)] = rec
            self._append({"_op": "upsert", "record": rec.to_dict()})
            return rec, created

    def get(self, *, namespace: str, key: str, include_expired: bool) -> MemoryRecord | None:
        now = _utc_now()
        with self._lock:
            rec = self._index.get((namespace, key))
            if rec is None:
                return None
            if (not include_expired) and (rec.expires_at is not None) and (rec.expires_at <= now):
                return None
            return rec

    def delete(self, *, namespace: str, key: str) -> bool:
        with self._lock:
            existed = (namespace, key) in self._index
            self._index.pop((namespace, key), None)
            self._append({"_op": "delete", "namespace": namespace, "key": key, "ts": _utc_now().isoformat()})
            return existed

    def search(self, *, q: MemoryQuery) -> list[MemoryRecord]:
        now = _utc_now()
        qn = q
        with self._lock:
            vals = list(self._index.values())

        out: list[MemoryRecord] = []
        for rec in vals:
            if qn.namespace is not None and rec.namespace != qn.namespace:
                continue
            if qn.key_prefix and not rec.key.startswith(qn.key_prefix):
                continue
            if (not qn.include_expired) and rec.expires_at is not None and rec.expires_at <= now:
                continue
            if qn.created_from is not None and rec.created_at < qn.created_from:
                continue
            if qn.created_to is not None and rec.created_at > qn.created_to:
                continue
            if qn.tags_all:
                if not set(qn.tags_all).issubset(set(rec.tags)):
                    continue
            if qn.tags_any:
                if set(qn.tags_any).isdisjoint(set(rec.tags)):
                    continue
            if qn.text_contains:
                needle = qn.text_contains.lower()
                hay = (rec.text + " " + rec.key + " " + _stable_json(rec.meta) + " " + " ".join(rec.tags)).lower()
                if needle not in hay:
                    continue
            out.append(rec)
            if len(out) >= int(qn.limit):
                break

        out.sort(key=lambda r: r.updated_at, reverse=True)
        return out[: int(qn.limit)]

    def prune_expired(self, *, now: dt.datetime) -> int:
        now = _ensure_tz(now)
        removed = 0
        with self._lock:
            keys = list(self._index.keys())
            for k in keys:
                rec = self._index.get(k)
                if rec is None:
                    continue
                if rec.expires_at is not None and rec.expires_at <= now:
                    self._index.pop(k, None)
                    removed += 1
        return removed

    def export_all(self, *, include_expired: bool) -> list[MemoryRecord]:
        now = _utc_now()
        with self._lock:
            vals = list(self._index.values())
        if include_expired:
            vals.sort(key=lambda r: r.created_at)
            return vals
        out = [r for r in vals if (r.expires_at is None or r.expires_at > now)]
        out.sort(key=lambda r: r.created_at)
        return out

    def close(self) -> None:
        return


def _record_from_dict(d: Json) -> MemoryRecord:
    if not isinstance(d, dict):
        raise MemoryError("Invalid record dict")
    created_at = dt.datetime.fromisoformat(d["created_at"])
    updated_at = dt.datetime.fromisoformat(d["updated_at"])
    expires_at = dt.datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None

    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=dt.timezone.utc)
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=dt.timezone.utc)
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=dt.timezone.utc)

    return MemoryRecord(
        record_id=str(d["record_id"]),
        namespace=str(d["namespace"]),
        key=str(d["key"]),
        text=str(d["text"]),
        tags=tuple(d.get("tags") or ()),
        meta=dict(d.get("meta") or {}),
        created_at=created_at,
        updated_at=updated_at,
        expires_at=expires_at,
        content_hash=str(d["content_hash"]),
    )


class LongTermMemory:
    """
    Высокоуровневый сервис долговременной памяти.
    Асинхронный API: все операции с IO выполняются через asyncio.to_thread.
    """

    def __init__(
        self,
        *,
        cfg: MemoryConfig | None = None,
        store: MemoryStore,
        audit: AuditLogger | None = None,
    ) -> None:
        self._cfg = cfg or MemoryConfig.from_env()
        self._store = store
        self._audit = audit
        self._lock = asyncio.Lock()

        if self._cfg.dedup_scope not in {"global", "namespace"}:
            raise MemoryError("dedup_scope must be global or namespace")

    @property
    def config(self) -> MemoryConfig:
        return self._cfg

    def close(self) -> None:
        self._store.close()

    async def upsert(
        self,
        *,
        namespace: str,
        key: str,
        text: str,
        tags: t.Iterable[str] = (),
        meta: Json | None = None,
        ttl_s: int | None = None,
    ) -> UpsertResult:
        if not self._cfg.enabled:
            raise MemoryError("LongTermMemory is disabled")

        ns = self._normalize_namespace(namespace)
        k = self._normalize_key(key)
        txt = self._normalize_text(text)
        tag_list = self._normalize_tags(tags)
        m = self._normalize_meta(meta or {})
        expires_at = self._compute_expires_at(ttl_s=ttl_s)

        content_hash = self._content_hash(
            namespace=ns,
            key=k,
            text=txt,
            tags=tag_list,
            meta=m,
            expires_at=expires_at,
        )

        # dedup: if same content exists for same key (or in scope), no-op update
        async with self._lock:
            existing = await asyncio.to_thread(self._store.get, namespace=ns, key=k, include_expired=True)
            if self._cfg.enable_dedup and existing is not None:
                if self._dedup_hit(existing, content_hash):
                    self._maybe_audit(
                        event_type="memory.long_term.dedup_hit",
                        severity="INFO",
                        message="Long-term memory dedup hit",
                        data={"namespace": ns, "key": k, "record_id": existing.record_id},
                    )
                    return UpsertResult(record=existing, created=False, deduped=True)

            rec, created = await asyncio.to_thread(
                self._store.upsert,
                namespace=ns,
                key=k,
                text=txt,
                tags=tag_list,
                meta=m,
                expires_at=expires_at,
                content_hash=content_hash,
            )

        self._maybe_audit(
            event_type="memory.long_term.upsert",
            severity="INFO",
            message="Long-term memory upsert",
            data={
                "namespace": ns,
                "key": k,
                "record_id": rec.record_id,
                "created": created,
                "expires_at": rec.expires_at.isoformat() if rec.expires_at else None,
                "tags_count": len(rec.tags),
            },
        )
        return UpsertResult(record=rec, created=created, deduped=False)

    async def get(self, *, namespace: str, key: str, include_expired: bool = False) -> MemoryRecord | None:
        if not self._cfg.enabled:
            raise MemoryError("LongTermMemory is disabled")
        ns = self._normalize_namespace(namespace)
        k = self._normalize_key(key)
        return await asyncio.to_thread(self._store.get, namespace=ns, key=k, include_expired=bool(include_expired))

    async def delete(self, *, namespace: str, key: str) -> bool:
        if not self._cfg.enabled:
            raise MemoryError("LongTermMemory is disabled")
        ns = self._normalize_namespace(namespace)
        k = self._normalize_key(key)
        ok = await asyncio.to_thread(self._store.delete, namespace=ns, key=k)
        self._maybe_audit(
            event_type="memory.long_term.delete",
            severity="WARN" if ok else "INFO",
            message="Long-term memory delete",
            data={"namespace": ns, "key": k, "deleted": ok},
        )
        return ok

    async def search(self, q: MemoryQuery) -> list[MemoryRecord]:
        if not self._cfg.enabled:
            raise MemoryError("LongTermMemory is disabled")
        qn = q.normalized(self._cfg)
        return await asyncio.to_thread(self._store.search, q=qn)

    async def prune_expired(self) -> int:
        if not self._cfg.enabled:
            raise MemoryError("LongTermMemory is disabled")
        now = _utc_now()
        removed = await asyncio.to_thread(self._store.prune_expired, now=now)
        if removed:
            self._maybe_audit(
                event_type="memory.long_term.prune_expired",
                severity="INFO",
                message="Long-term memory pruned expired records",
                data={"removed": removed},
            )
        return removed

    async def export_all(self, *, include_expired: bool = False) -> list[MemoryRecord]:
        if not self._cfg.enabled:
            raise MemoryError("LongTermMemory is disabled")
        return await asyncio.to_thread(self._store.export_all, include_expired=bool(include_expired))

    async def import_records(
        self,
        records: t.Iterable[MemoryRecord],
        *,
        overwrite: bool = False,
    ) -> int:
        if not self._cfg.enabled:
            raise MemoryError("LongTermMemory is disabled")
        count = 0
        async with self._lock:
            for r in records:
                ns = self._normalize_namespace(r.namespace)
                k = self._normalize_key(r.key)
                existing = await asyncio.to_thread(self._store.get, namespace=ns, key=k, include_expired=True)
                if existing is not None and not overwrite:
                    continue
                # use record content; TTL preserved by expires_at
                await asyncio.to_thread(
                    self._store.upsert,
                    namespace=ns,
                    key=k,
                    text=self._normalize_text(r.text),
                    tags=self._normalize_tags(r.tags),
                    meta=self._normalize_meta(r.meta),
                    expires_at=r.expires_at,
                    content_hash=r.content_hash,
                )
                count += 1

        if count:
            self._maybe_audit(
                event_type="memory.long_term.import",
                severity="INFO",
                message="Long-term memory imported records",
                data={"count": count, "overwrite": overwrite},
            )
        return count

    def _dedup_hit(self, existing: MemoryRecord, new_hash: str) -> bool:
        if existing.content_hash == new_hash:
            return True
        # scope option: if global, we could dedup beyond key, но без индекса по hash это не делаем.
        # промышленно: dedup beyond key требует отдельного индекса по content_hash.
        return False

    def _compute_expires_at(self, *, ttl_s: int | None) -> dt.datetime | None:
        ttl = self._cfg.default_ttl_s if ttl_s is None else max(0, int(ttl_s))
        if self._cfg.hard_ttl_s > 0:
            if ttl == 0:
                ttl = self._cfg.hard_ttl_s
            else:
                ttl = min(ttl, self._cfg.hard_ttl_s)
        if ttl <= 0:
            return None
        return _utc_now() + dt.timedelta(seconds=ttl)

    def _normalize_namespace(self, namespace: str) -> str:
        if not isinstance(namespace, str):
            raise MemoryError("namespace must be str")
        ns = namespace.strip()
        if not ns:
            raise MemoryError("namespace must be non-empty")
        ns = _truncate_str(ns, 256)
        return ns

    def _normalize_key(self, key: str) -> str:
        if not isinstance(key, str):
            raise MemoryError("key must be str")
        k = key.strip()
        if not k:
            raise MemoryError("key must be non-empty")
        if len(k) > self._cfg.max_key_len:
            raise MemoryError("key exceeds max_key_len")
        return k

    def _normalize_text(self, text: str) -> str:
        if not isinstance(text, str):
            raise MemoryError("text must be str")
        txt = text.strip()
        if not txt:
            raise MemoryError("text must be non-empty")
        if len(txt) > self._cfg.max_text_len:
            txt = _truncate_str(txt, self._cfg.max_text_len)
        return txt

    def _normalize_tags(self, tags: t.Iterable[str]) -> tuple[str, ...]:
        if self._cfg.max_tags <= 0:
            return ()
        out: list[str] = []
        for t_ in tags:
            if t_ is None:
                continue
            s = _normalize_tag(str(t_))
            if not s:
                continue
            if len(s) > self._cfg.max_tag_len:
                s = _truncate_str(s, self._cfg.max_tag_len)
            out.append(s)
            if len(out) >= self._cfg.max_tags:
                break
        # unique, stable
        uniq = []
        seen = set()
        for x in out:
            if x in seen:
                continue
            seen.add(x)
            uniq.append(x)
        return tuple(uniq)

    def _normalize_meta(self, meta: Json) -> Json:
        if not isinstance(meta, dict):
            raise MemoryError("meta must be dict")
        # size guard
        raw = _stable_json(meta).encode("utf-8")
        if len(raw) > self._cfg.max_meta_bytes:
            raise MemoryError("meta exceeds max_meta_bytes")
        return meta

    def _content_hash(
        self,
        *,
        namespace: str,
        key: str,
        text: str,
        tags: tuple[str, ...],
        meta: Json,
        expires_at: dt.datetime | None,
    ) -> str:
        payload = {
            "namespace": namespace if self._cfg.dedup_scope == "namespace" else "",
            "key": key,
            "text": text,
            "tags": list(tags),
            "meta": meta,
            "expires_at": expires_at.isoformat() if expires_at is not None else None,
        }
        return _sha256_hex(_stable_json(payload).encode("utf-8"))

    def _maybe_audit(self, *, event_type: str, severity: str, message: str, data: Json) -> None:
        if not self._cfg.audit_enabled:
            return
        if self._audit is None:
            return
        try:
            self._audit.log(
                event_type,
                severity=severity,
                message=message,
                data=data,
            )
        except Exception:
            return


__all__ = [
    "MemoryError",
    "MemoryConfig",
    "MemoryRecord",
    "UpsertResult",
    "MemoryQuery",
    "MemoryStore",
    "SQLiteMemoryStore",
    "JsonlMemoryStore",
    "LongTermMemory",
]
