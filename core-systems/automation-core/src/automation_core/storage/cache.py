# automation-core/src/automation_core/storage/cache.py
# -*- coding: utf-8 -*-
"""
Промышленный кэш с несколькими бэкендами (память/диск/Redis) и мультислойным фасадом.

Особенности:
- Единый интерфейс (get/set/delete/get_many/set_many/exists/ttl/touch/clear/close).
- Ключи нормализуются и хешируются (SHA-256) для безопасных префиксов и стабильных ключей.
- Сериализация: 'pickle' (по умолчанию) или 'json'; компрессия: 'none' | 'zlib' | 'lzma'.
- InMemoryCache: потокобезопасный LRU с TTL, ограничение по max_items и/или max_bytes.
- DiskCache (SQLite): WAL, TTL, прунинг просроченных, ограничение total_bytes, индексы, колонка last_access.
- RedisCache (опционально): если установлен пакет 'redis'; write-through, pipelining для bulk-операций.
- MultiTierCache: чтение снизу вверх (read-through) с записью попаданий наверх (write-up), запись через все уровни (write-through).
- Метрики: hits/misses/sets/deletes/evictions; контекстный менеджер для безопасного закрытия.

Замечание:
- Для RedisCache требуется библиотека 'redis' (redis-py). Если её нет, класс поднимет исключение при инициализации.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import hashlib
import json
import os
import pickle
import sqlite3
import threading
import time
import zlib
import lzma
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

try:  # опциональный Redis
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore

__all__ = [
    "CacheError",
    "CacheProtocol",
    "CacheStats",
    "Serialization",
    "Compression",
    "KeyCodec",
    "ValueCodec",
    "InMemoryCache",
    "DiskCache",
    "RedisCache",
    "MultiTierCache",
]

# =========================
#   Ошибки и метрики
# =========================

class CacheError(RuntimeError):
    pass


@dataclass(slots=True)
class CacheStats:
    hits: int = 0
    misses: int = 0
    sets: int = 0
    deletes: int = 0
    evictions: int = 0


# =========================
#   Кодеки ключей/значений
# =========================

class Serialization:
    PICKLE = "pickle"
    JSON = "json"


class Compression:
    NONE = "none"
    ZLIB = "zlib"
    LZMA = "lzma"


class KeyCodec:
    @staticmethod
    def normalize(key: Any) -> bytes:
        """
        Нормализуем ключ к байтам: строки -> utf-8; bytes -> как есть; иначе pickle.
        """
        if key is None:
            raise CacheError("Key must not be None")
        if isinstance(key, bytes):
            return key
        if isinstance(key, str):
            return key.encode("utf-8", errors="strict")
        # Для составных ключей используем pickle протокола 5
        return pickle.dumps(key, protocol=5)

    @staticmethod
    def khash(key: Any) -> str:
        """
        Стойкий хеш ключа: sha256(hex). Используется как стабильный идентификатор.
        """
        return hashlib.sha256(KeyCodec.normalize(key)).hexdigest()


class ValueCodec:
    @staticmethod
    def dumps(value: Any, *, serialization: str, compression: str) -> bytes:
        if serialization == Serialization.JSON:
            data = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        elif serialization == Serialization.PICKLE:
            data = pickle.dumps(value, protocol=5)
        else:
            raise CacheError(f"Unsupported serialization: {serialization}")

        if compression == Compression.NONE:
            return data
        if compression == Compression.ZLIB:
            return zlib.compress(data, level=6)
        if compression == Compression.LZMA:
            return lzma.compress(data, preset=6)
        raise CacheError(f"Unsupported compression: {compression}")

    @staticmethod
    def loads(blob: bytes, *, serialization: str, compression: str) -> Any:
        if compression == Compression.ZLIB:
            blob = zlib.decompress(blob)
        elif compression == Compression.LZMA:
            blob = lzma.decompress(blob)
        elif compression == Compression.NONE:
            pass
        else:
            raise CacheError(f"Unsupported compression: {compression}")

        if serialization == Serialization.JSON:
            return json.loads(blob.decode("utf-8"))
        if serialization == Serialization.PICKLE:
            return pickle.loads(blob)
        raise CacheError(f"Unsupported serialization: {serialization}")


# =========================
#   Протокол кэша
# =========================

class CacheProtocol:
    """
    Базовый интерфейс кэша. Все реализации должны соблюдать семантики TTL (секунды, None = без срока).
    """

    def get(self, key: Any, default: Any = None) -> Any: ...
    def get_many(self, keys: Sequence[Any]) -> List[Optional[Any]]: ...
    def set(self, key: Any, value: Any, ttl: Optional[float] = None) -> None: ...
    def set_many(self, kv: Mapping[Any, Any], ttl: Optional[float] = None) -> None: ...
    def delete(self, key: Any) -> bool: ...
    def clear(self) -> None: ...
    def exists(self, key: Any) -> bool: ...
    def ttl(self, key: Any) -> Optional[float]: ...
    def touch(self, key: Any, ttl: Optional[float]) -> bool: ...
    def close(self) -> None: ...
    @property
    def stats(self) -> CacheStats: ...


# =========================
#   In-Memory LRU Cache
# =========================

@dataclass(slots=True)
class _MemEntry:
    vblob: bytes
    serialization: str
    compression: str
    expires: Optional[float]
    size: int


class InMemoryCache(CacheProtocol):
    """
    Потокобезопасный LRU с TTL. Эвикция по max_items и/или max_bytes.
    """

    def __init__(
        self,
        *,
        max_items: Optional[int] = 10_000,
        max_bytes: Optional[int] = 128 * 1024 * 1024,
        serialization: str = Serialization.PICKLE,
        compression: str = Compression.NONE,
        namespace: str = "cache",
    ) -> None:
        self._lock = threading.RLock()
        self._od: "OrderedDict[str, _MemEntry]" = OrderedDict()
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._bytes = 0
        self._serialization = serialization
        self._compression = compression
        self._ns = namespace
        self._stats = CacheStats()

    @property
    def stats(self) -> CacheStats:
        return self._stats

    def _evict_if_needed(self) -> None:
        with self._lock:
            # по элементам
            if self._max_items is not None:
                while len(self._od) > self._max_items:
                    kh, e = self._od.popitem(last=False)
                    self._bytes -= e.size
                    self._stats.evictions += 1
            # по байтам
            if self._max_bytes is not None:
                while self._bytes > self._max_bytes and self._od:
                    kh, e = self._od.popitem(last=False)
                    self._bytes -= e.size
                    self._stats.evictions += 1

    def _expired(self, e: _MemEntry) -> bool:
        return e.expires is not None and e.expires <= time.time()

    def _full_key(self, kh: str) -> str:
        return f"{self._ns}:{kh}"

    def get(self, key: Any, default: Any = None) -> Any:
        kh = self._full_key(KeyCodec.khash(key))
        with self._lock:
            e = self._od.get(kh)
            if not e:
                self._stats.misses += 1
                return default
            if self._expired(e):
                # remove expired
                self._bytes -= e.size
                self._od.pop(kh, None)
                self._stats.misses += 1
                return default
            # move to MRU
            self._od.move_to_end(kh, last=True)
            self._stats.hits += 1
            return ValueCodec.loads(e.vblob, serialization=e.serialization, compression=e.compression)

    def get_many(self, keys: Sequence[Any]) -> List[Optional[Any]]:
        return [self.get(k, None) for k in keys]

    def set(self, key: Any, value: Any, ttl: Optional[float] = None) -> None:
        kh = self._full_key(KeyCodec.khash(key))
        vblob = ValueCodec.dumps(value, serialization=self._serialization, compression=self._compression)
        e = _MemEntry(
            vblob=vblob,
            serialization=self._serialization,
            compression=self._compression,
            expires=(time.time() + ttl) if ttl else None,
            size=len(vblob),
        )
        with self._lock:
            old = self._od.pop(kh, None)
            if old:
                self._bytes -= old.size
            self._od[kh] = e
            self._bytes += e.size
            self._stats.sets += 1
            self._evict_if_needed()

    def set_many(self, kv: Mapping[Any, Any], ttl: Optional[float] = None) -> None:
        for k, v in kv.items():
            self.set(k, v, ttl=ttl)

    def delete(self, key: Any) -> bool:
        kh = self._full_key(KeyCodec.khash(key))
        with self._lock:
            e = self._od.pop(kh, None)
            if e:
                self._bytes -= e.size
                self._stats.deletes += 1
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._od.clear()
            self._bytes = 0

    def exists(self, key: Any) -> bool:
        return self.get(key, object()) is not object()

    def ttl(self, key: Any) -> Optional[float]:
        kh = self._full_key(KeyCodec.khash(key))
        with self._lock:
            e = self._od.get(kh)
            if not e or self._expired(e):
                return None
            return (e.expires - time.time()) if e.expires else None

    def touch(self, key: Any, ttl: Optional[float]) -> bool:
        kh = self._full_key(KeyCodec.khash(key))
        with self._lock:
            e = self._od.get(kh)
            if not e or self._expired(e):
                return False
            e.expires = (time.time() + ttl) if ttl else None
            self._od.move_to_end(kh, last=True)
            return True

    def close(self) -> None:
        # ничего не требуется
        pass


# =========================
#   DiskCache (SQLite)
# =========================

class DiskCache(CacheProtocol):
    """
    SQLite-бэкенд с WAL, TTL, прунингом и ограничением по общему объему.
    """

    def __init__(
        self,
        path: Union[str, Path],
        *,
        total_bytes_limit: Optional[int] = 2 * 1024 * 1024 * 1024,  # 2 GiB
        serialization: str = Serialization.PICKLE,
        compression: str = Compression.ZLIB,
        namespace: str = "cache",
        busy_timeout_ms: int = 5000,
    ) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._serialization = serialization
        self._compression = compression
        self._ns = namespace
        self._lock = threading.RLock()
        self._stats = CacheStats()
        self._bytes_limit = total_bytes_limit
        # открываем соединение
        self._conn = sqlite3.connect(str(self._path), timeout=busy_timeout_ms / 1000.0, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA temp_store=MEMORY;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.execute("PRAGMA busy_timeout = ?;", (busy_timeout_ms,))
        self._init_schema()

    @property
    def stats(self) -> CacheStats:
        return self._stats

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    ns TEXT NOT NULL,
                    khash TEXT NOT NULL,
                    kblob BLOB NOT NULL,
                    vblob BLOB NOT NULL,
                    encoding TEXT NOT NULL,
                    ctype TEXT NOT NULL,
                    vsize INTEGER NOT NULL,
                    created REAL NOT NULL,
                    expires REAL,
                    last_access REAL NOT NULL,
                    PRIMARY KEY (ns, khash)
                );
                """
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON cache (expires);")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_access ON cache (last_access);")

    def _full_key(self, kh: str) -> Tuple[str, str]:
        return (self._ns, kh)

    def _prune_expired(self) -> None:
        now = time.time()
        with self._conn:
            self._conn.execute("DELETE FROM cache WHERE expires IS NOT NULL AND expires <= ?", (now,))

    def _enforce_size_limit(self) -> None:
        if self._bytes_limit is None:
            return
        cur = self._conn.cursor()
        cur.execute("SELECT COALESCE(SUM(vsize),0) FROM cache WHERE ns = ?", (self._ns,))
        total = int(cur.fetchone()[0])
        if total <= self._bytes_limit:
            return
        # удаляем наименее недавно используемые
        to_free = total - self._bytes_limit
        with self._conn:
            # выбираем кандидатов по last_access
            for row in self._conn.execute(
                "SELECT khash, vsize FROM cache WHERE ns = ? ORDER BY last_access ASC", (self._ns,)
            ):
                kh, vsize = row
                self._conn.execute("DELETE FROM cache WHERE ns = ? AND khash = ?", (self._ns, kh))
                self._stats.evictions += 1
                to_free -= int(vsize)
                if to_free <= 0:
                    break

    def get(self, key: Any, default: Any = None) -> Any:
        kh = KeyCodec.khash(key)
        self._prune_expired()
        with self._lock:
            row = self._conn.execute(
                "SELECT vblob, encoding, ctype, expires FROM cache WHERE ns = ? AND khash = ?",
                self._full_key(kh),
            ).fetchone()
            if not row:
                self._stats.misses += 1
                return default
            vblob, enc, ctype, expires = row
            if expires is not None and float(expires) <= time.time():
                with self._conn:
                    self._conn.execute("DELETE FROM cache WHERE ns = ? AND khash = ?", self._full_key(kh))
                self._stats.misses += 1
                return default
            # обновим last_access
            with self._conn:
                self._conn.execute(
                    "UPDATE cache SET last_access = ? WHERE ns = ? AND khash = ?",
                    (time.time(), self._ns, kh),
                )
            self._stats.hits += 1
            return ValueCodec.loads(vblob, serialization=enc, compression=ctype)

    def get_many(self, keys: Sequence[Any]) -> List[Optional[Any]]:
        return [self.get(k, None) for k in keys]

    def set(self, key: Any, value: Any, ttl: Optional[float] = None) -> None:
        kh = KeyCodec.khash(key)
        kblob = KeyCodec.normalize(key)
        vblob = ValueCodec.dumps(value, serialization=self._serialization, compression=self._compression)
        expires = (time.time() + ttl) if ttl else None
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO cache(ns, khash, kblob, vblob, encoding, ctype, vsize, created, expires, last_access)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ns, khash) DO UPDATE SET
                    vblob=excluded.vblob,
                    encoding=excluded.encoding,
                    ctype=excluded.ctype,
                    vsize=excluded.vsize,
                    created=excluded.created,
                    expires=excluded.expires,
                    last_access=excluded.last_access
                """,
                (self._ns, kh, kblob, vblob, self._serialization, self._compression, len(vblob), now, expires, now),
            )
            self._stats.sets += 1
            self._enforce_size_limit()

    def set_many(self, kv: Mapping[Any, Any], ttl: Optional[float] = None) -> None:
        with self._lock, self._conn:
            now = time.time()
            for k, v in kv.items():
                kh = KeyCodec.khash(k)
                kblob = KeyCodec.normalize(k)
                vblob = ValueCodec.dumps(v, serialization=self._serialization, compression=self._compression)
                expires = (now + ttl) if ttl else None
                self._conn.execute(
                    """
                    INSERT INTO cache(ns, khash, kblob, vblob, encoding, ctype, vsize, created, expires, last_access)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(ns, khash) DO UPDATE SET
                        vblob=excluded.vblob,
                        encoding=excluded.encoding,
                        ctype=excluded.ctype,
                        vsize=excluded.vsize,
                        created=excluded.created,
                        expires=excluded.expires,
                        last_access=excluded.last_access
                    """,
                    (self._ns, kh, kblob, vblob, self._serialization, self._compression, len(vblob), now, expires, now),
                )
                self._stats.sets += 1
            self._enforce_size_limit()

    def delete(self, key: Any) -> bool:
        kh = KeyCodec.khash(key)
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM cache WHERE ns = ? AND khash = ?", self._full_key(kh))
            if cur.rowcount:
                self._stats.deletes += 1
                return True
        return False

    def clear(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM cache WHERE ns = ?", (self._ns,))

    def exists(self, key: Any) -> bool:
        kh = KeyCodec.khash(key)
        row = self._conn.execute(
            "SELECT 1 FROM cache WHERE ns = ? AND khash = ? AND (expires IS NULL OR expires > ?)",
            (self._ns, kh, time.time()),
        ).fetchone()
        return bool(row)

    def ttl(self, key: Any) -> Optional[float]:
        kh = KeyCodec.khash(key)
        row = self._conn.execute("SELECT expires FROM cache WHERE ns = ? AND khash = ?", self._full_key(kh)).fetchone()
        if not row:
            return None
        expires = row[0]
        if expires is None:
            return None
        rem = float(expires) - time.time()
        return rem if rem > 0 else None

    def touch(self, key: Any, ttl: Optional[float]) -> bool:
        kh = KeyCodec.khash(key)
        if ttl is None:
            # снять срок годности
            with self._conn:
                cur = self._conn.execute(
                    "UPDATE cache SET expires = NULL WHERE ns = ? AND khash = ?", self._full_key(kh)
                )
                return cur.rowcount > 0
        new_exp = time.time() + ttl
        with self._conn:
            cur = self._conn.execute(
                "UPDATE cache SET expires = ? WHERE ns = ? AND khash = ?",
                (new_exp, self._ns, kh),
            )
            return cur.rowcount > 0

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._conn.close()


# =========================
#   RedisCache (опционально)
# =========================

class RedisCache(CacheProtocol):
    """
    Redis-бэкенд. Требует установленного 'redis' (redis-py).
    Значения сериализуются/компрессируются так же, как в других бэкендах.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        *,
        serialization: str = Serialization.PICKLE,
        compression: str = Compression.ZLIB,
        namespace: str = "cache",
        decode_responses: bool = False,
        **redis_kwargs: Any,
    ) -> None:
        if redis is None:
            raise CacheError("redis-py is not installed")
        self._serialization = serialization
        self._compression = compression
        self._ns = namespace
        self._stats = CacheStats()
        # соединимся через URL или параметры
        if url:
            self._r = redis.Redis.from_url(url, decode_responses=decode_responses, **redis_kwargs)  # type: ignore[call-arg]
        else:
            self._r = redis.Redis(decode_responses=decode_responses, **redis_kwargs)  # type: ignore[call-arg]

    @property
    def stats(self) -> CacheStats:
        return self._stats

    def _rk(self, kh: str) -> str:
        return f"{self._ns}:{kh}"

    def get(self, key: Any, default: Any = None) -> Any:
        kh = self._rk(KeyCodec.khash(key))
        blob = self._r.get(kh)
        if blob is None:
            self._stats.misses += 1
            return default
        if isinstance(blob, str):
            blob = blob.encode("utf-8")
        self._stats.hits += 1
        return ValueCodec.loads(blob, serialization=self._serialization, compression=self._compression)

    def get_many(self, keys: Sequence[Any]) -> List[Optional[Any]]:
        rks = [self._rk(KeyCodec.khash(k)) for k in keys]
        blobs = self._r.mget(rks)
        out: List[Optional[Any]] = []
        for b in blobs:
            if b is None:
                out.append(None)
                self._stats.misses += 1
            else:
                if isinstance(b, str):
                    b = b.encode("utf-8")
                out.append(ValueCodec.loads(b, serialization=self._serialization, compression=self._compression))
                self._stats.hits += 1
        return out

    def set(self, key: Any, value: Any, ttl: Optional[float] = None) -> None:
        kh = self._rk(KeyCodec.khash(key))
        blob = ValueCodec.dumps(value, serialization=self._serialization, compression=self._compression)
        if ttl is None:
            self._r.set(kh, blob)
        else:
            self._r.setex(kh, int(ttl), blob)
        self._stats.sets += 1

    def set_many(self, kv: Mapping[Any, Any], ttl: Optional[float] = None) -> None:
        pipe = self._r.pipeline()
        for k, v in kv.items():
            kh = self._rk(KeyCodec.khash(k))
            blob = ValueCodec.dumps(v, serialization=self._serialization, compression=self._compression)
            if ttl is None:
                pipe.set(kh, blob)
            else:
                pipe.setex(kh, int(ttl), blob)
        pipe.execute()
        self._stats.sets += len(kv)

    def delete(self, key: Any) -> bool:
        kh = self._rk(KeyCodec.khash(key))
        res = int(self._r.delete(kh)) > 0
        if res:
            self._stats.deletes += 1
        return res

    def clear(self) -> None:
        # Осторожно: удаляем только текущий namespace.
        cursor = 0
        pattern = f"{self._ns}:*"
        while True:
            cursor, keys = self._r.scan(cursor=cursor, match=pattern, count=1000)
            if keys:
                self._r.delete(*keys)
            if cursor == 0:
                break

    def exists(self, key: Any) -> bool:
        return bool(self._r.exists(self._rk(KeyCodec.khash(key))))

    def ttl(self, key: Any) -> Optional[float]:
        t = self._r.ttl(self._rk(KeyCodec.khash(key)))
        if t is None or t < 0:
            return None
        return float(t)

    def touch(self, key: Any, ttl: Optional[float]) -> bool:
        rk = self._rk(KeyCodec.khash(key))
        if ttl is None:
            # снять срок жизни нельзя в общих командах, делаем PERSIST
            return bool(self._r.persist(rk))
        return bool(self._r.expire(rk, int(ttl)))

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._r.close()  # type: ignore[attr-defined]


# =========================
#   Мультислойный кэш
# =========================

class MultiTierCache(CacheProtocol):
    """
    Read-through + write-through фасад над набором бэкендов (например, [InMemory, Disk, Redis]).
    Порядок бэкендов имеет значение: поиск идет сверху вниз, при попадании — запись наверх.
    """

    def __init__(self, backends: Sequence[CacheProtocol]) -> None:
        if not backends:
            raise CacheError("At least one backend required")
        self._backends = list(backends)
        self._stats = CacheStats()

    @property
    def stats(self) -> CacheStats:
        return self._stats

    def _write_up(self, key: Any, value: Any, hit_level: int) -> None:
        # Пробуем восстановить TTL (если нижний уровень умеет)
        ttl_val: Optional[float] = None
        try:
            ttl_val = self._backends[hit_level].ttl(key)
        except Exception:
            ttl_val = None
        # Пишем во все уровни выше hit_level
        for b in self._backends[:hit_level]:
            with contextlib.suppress(Exception):
                b.set(key, value, ttl=ttl_val)

    def get(self, key: Any, default: Any = None) -> Any:
        for idx, b in enumerate(self._backends):
            val = b.get(key, default=object())
            if val is not object():
                self._stats.hits += 1
                # поднять наверх
                self._write_up(key, val, hit_level=idx)
                return val
        self._stats.misses += 1
        return default

    def get_many(self, keys: Sequence[Any]) -> List[Optional[Any]]:
        return [self.get(k, None) for k in keys]

    def set(self, key: Any, value: Any, ttl: Optional[float] = None) -> None:
        for b in self._backends:
            with contextlib.suppress(Exception):
                b.set(key, value, ttl=ttl)
        self._stats.sets += 1

    def set_many(self, kv: Mapping[Any, Any], ttl: Optional[float] = None) -> None:
        for b in self._backends:
            with contextlib.suppress(Exception):
                b.set_many(kv, ttl=ttl)
        self._stats.sets += len(kv)

    def delete(self, key: Any) -> bool:
        ok = False
        for b in self._backends:
            with contextlib.suppress(Exception):
                ok = b.delete(key) or ok
        if ok:
            self._stats.deletes += 1
        return ok

    def clear(self) -> None:
        for b in self._backends:
            with contextlib.suppress(Exception):
                b.clear()

    def exists(self, key: Any) -> bool:
        return self.get(key, default=object()) is not object()

    def ttl(self, key: Any) -> Optional[float]:
        # берем минимальный положительный TTL из доступных
        ttls: List[float] = []
        for b in self._backends:
            with contextlib.suppress(Exception):
                t = b.ttl(key)
                if t is not None and t > 0:
                    ttls.append(t)
        return min(ttls) if ttls else None

    def touch(self, key: Any, ttl: Optional[float]) -> bool:
        ok = False
        for b in self._backends:
            with contextlib.suppress(Exception):
                ok = b.touch(key, ttl) or ok
        return ok

    def close(self) -> None:
        for b in self._backends:
            with contextlib.suppress(Exception):
                b.close()


# =========================
#   Пример использования
# =========================
if __name__ == "__main__":  # pragma: no cover
    mem = InMemoryCache(max_items=1000, max_bytes=10 * 1024 * 1024)
    disk = DiskCache("./.cache/automation_core.sqlite", total_bytes_limit=256 * 1024 * 1024)
    tiers = MultiTierCache([mem, disk])
    tiers.set(("user", 42), {"name": "Alice"}, ttl=30)
    print(tiers.get(("user", 42)))
    tiers.close()
