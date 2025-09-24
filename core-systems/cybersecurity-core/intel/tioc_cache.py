# cybersecurity-core/cybersecurity/intel/tioc_cache.py
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import blake2b, sha1, sha256, md5 as md5hash
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, validator

# Optional Redis (modern)
try:
    import redis.asyncio as redis  # type: ignore
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    redis = None  # type: ignore
    _HAS_REDIS = False

_LOG = logging.getLogger("tioc_cache")


# ============================== Typings & Enums ===============================

class IOCType(str):
    ip = "ip"
    domain = "domain"
    url = "url"
    sha256 = "sha256"
    sha1 = "sha1"
    md5 = "md5"
    email = "email"


class TLP(str):
    clear = "CLEAR"
    white = "WHITE"
    green = "GREEN"
    amber = "AMBER"
    amber_strict = "AMBER+STRICT"
    red = "RED"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================== Normalization =================================

_IDNA_RE = re.compile(r"[^.]+")
_URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

def _norm_domain(v: str) -> str:
    v = v.strip().strip(".").lower()
    if not v:
        raise ValueError("empty domain")
    # idna encode/normalize each label
    parts = []
    for label in v.split("."):
        if not label:
            continue
        parts.append(label.encode("idna").decode("ascii"))
    return ".".join(parts)

def _norm_ip(v: str) -> str:
    ip = ipaddress.ip_address(v.strip())
    # Return canonical form
    return ip.compressed

def _norm_hash(v: str, kind: IOCType) -> str:
    s = v.strip().lower()
    if kind == IOCType.sha256 and not re.fullmatch(r"[0-9a-f]{64}", s):
        raise ValueError("invalid sha256")
    if kind == IOCType.sha1 and not re.fullmatch(r"[0-9a-f]{40}", s):
        raise ValueError("invalid sha1")
    if kind == IOCType.md5 and not re.fullmatch(r"[0-9a-f]{32}", s):
        raise ValueError("invalid md5")
    return s

def _norm_email(v: str) -> str:
    s = v.strip().lower()
    if "@" not in s:
        raise ValueError("invalid email")
    local, domain = s.split("@", 1)
    return f"{local}@{_norm_domain(domain)}"

def _norm_url(v: str) -> str:
    # Ensure scheme
    s = v.strip()
    if not _URL_SCHEME_RE.match(s):
        s = "http://" + s
    # Basic parse without external deps
    # Lowercase scheme/host, strip fragment, remove default ports
    from urllib.parse import urlsplit, urlunsplit, quote, unquote, urlencode, parse_qsl
    sp = urlsplit(s)
    scheme = sp.scheme.lower()
    netloc = sp.netloc
    if "@" in netloc:
        # drop userinfo for normalization (we don't keep creds)
        netloc = netloc.split("@", 1)[1]
    host, sep, port = netloc.partition(":")
    host = _norm_domain(host)
    # remove default ports
    if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
        port = ""
    netloc = host + (sep + port if port else "")
    # path: percent-encode minimally; keep case
    path = quote(unquote(sp.path or "/"), safe="/._~-")
    # sort query params for determinism
    q = parse_qsl(sp.query, keep_blank_values=True)
    q.sort()
    query = urlencode(q, doseq=True)
    # drop fragment
    frag = ""
    return urlunsplit((scheme, netloc, path or "/", query, frag))

def normalize_ioc(ioc_type: str, value: str) -> str:
    t = ioc_type
    if t == IOCType.ip:
        return _norm_ip(value)
    if t == IOCType.domain:
        return _norm_domain(value)
    if t == IOCType.url:
        return _norm_url(value)
    if t in (IOCType.sha256, IOCType.sha1, IOCType.md5):
        return _norm_hash(value, t)  # type: ignore[arg-type]
    if t == IOCType.email:
        return _norm_email(value)
    raise ValueError(f"unsupported ioc type: {t}")


# ============================== Models ========================================

class IOCKey(BaseModel):
    type: str = Field(..., description="ioc type")
    value: str = Field(..., description="normalized value")

    @validator("type")
    def _vt(cls, v: str) -> str:
        if v not in {IOCType.ip, IOCType.domain, IOCType.url, IOCType.sha256, IOCType.sha1, IOCType.md5, IOCType.email}:
            raise ValueError("unsupported ioc type")
        return v

    @validator("value")
    def _vv(cls, v: str, values: Dict[str, Any]) -> str:
        t = values.get("type")
        if t:
            return normalize_ioc(t, v)
        return v

    def key(self) -> str:
        # Deterministic key for storage
        return f"{self.type}:{self.value}"


class IOCEntry(BaseModel):
    key: IOCKey
    # Intel
    tlp: str = Field(default=TLP.amber)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: int = Field(default=50, ge=0, le=100)
    source: str = Field(..., min_length=1, max_length=128)
    tags: List[str] = Field(default_factory=list)

    # Lifecycle
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    sightings: int = Field(default=1, ge=0)
    false_positive: bool = False
    revoked: bool = False

    # TTL / expiry
    ttl_sec: int = Field(..., ge=60)
    expires_at: datetime = Field(default_factory=utcnow)

    # Derived
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    note: Optional[str] = None

    @validator("tags", pre=True, always=True)
    def _tags_norm(cls, v: Any) -> List[str]:
        arr = v or []
        return sorted({str(x).strip().lower() for x in arr if str(x).strip()})

    @validator("tlp")
    def _tlp_val(cls, v: str) -> str:
        allowed = {TLP.clear, TLP.white, TLP.green, TLP.amber, TLP.amber_strict, TLP.red}
        if v not in allowed:
            raise ValueError("invalid TLP")
        return v

    @validator("expires_at", always=True)
    def _exp_val(cls, v: datetime, values: Dict[str, Any]) -> datetime:
        if v and v.tzinfo is None:
            raise ValueError("expires_at must be tz-aware UTC")
        ttl = values.get("ttl_sec") or 0
        ls = values.get("last_seen") or utcnow()
        exp = ls + timedelta(seconds=int(ttl))
        if not v or v < exp:
            return exp
        return v


class Query(BaseModel):
    types: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    source: Optional[str] = None
    active_only: bool = True
    min_confidence: Optional[int] = None
    min_severity: Optional[int] = None
    min_score: Optional[float] = None
    include_false_positive: bool = False
    include_revoked: bool = False
    limit: int = Field(default=100, ge=1, le=5000)
    offset: int = Field(default=0, ge=0)


# ============================== Scoring & TTL =================================

DEFAULT_TTLS: Dict[str, int] = {
    IOCType.ip: 3 * 24 * 3600,        # 3d
    IOCType.domain: 5 * 24 * 3600,    # 5d
    IOCType.url: 7 * 24 * 3600,       # 7d
    IOCType.sha256: 30 * 24 * 3600,   # 30d
    IOCType.sha1: 30 * 24 * 3600,
    IOCType.md5: 30 * 24 * 3600,
    IOCType.email: 14 * 24 * 3600,
}

def calc_score(confidence: int, severity: int, first_seen: datetime, last_seen: datetime, sightings: int) -> float:
    """
    Стабильная оценка важности индикатора [0..100] с учетом свежести.
    """
    now = utcnow()
    age_hours = max(1.0, (now - last_seen).total_seconds() / 3600.0)
    # эксп. распад (чем свежее, тем выше компонент)
    recency = math.exp(-age_hours / (24.0 * 7.0))  # полураспад ~ неделя
    sig = 1.0 - math.exp(-min(50, sightings) / 10.0)  # насыщение по количеству наблюдений
    base = 0.55 * (severity / 100.0) + 0.35 * (confidence / 100.0) + 0.10 * sig
    score = 100.0 * (0.7 * base + 0.3 * recency)
    return round(max(0.0, min(100.0, score)), 1)

def ttl_for(ioc_type: str, sightings: int) -> int:
    """
    Базовый TTL по типу + продление для многократных наблюдений.
    """
    base = DEFAULT_TTLS.get(ioc_type, 7 * 24 * 3600)
    # продлеваем до x2 при росте sightings (сублогарифмически)
    factor = min(2.0, 1.0 + math.log10(max(1, sightings)))
    return int(base * factor)


# ============================== Bloom Filter ==================================

class BloomFilter:
    """
    Простой неблокирующий Bloom-фильтр для маркера "видели раньше".
    m — размер битовой матрицы, k — число хэшей.
    """
    __slots__ = ("m", "k", "_bits")

    def __init__(self, capacity: int = 1_000_000, error_rate: float = 0.01) -> None:
        # формулы: m = -(n ln p) / (ln 2)^2 ; k = (m/n) ln 2
        n = max(1, capacity)
        p = min(0.3, max(0.00001, error_rate))
        m = int(-(n * math.log(p)) / (math.log(2) ** 2))
        k = max(1, int((m / n) * math.log(2)))
        self.m = m
        self.k = k
        self._bits = bytearray((m + 7) // 8)

    def _hashes(self, key: str) -> Iterable[int]:
        # два независимых хэша -> линейная комбинация
        h1 = int.from_bytes(sha256(key.encode("utf-8")).digest(), "big")
        h2 = int.from_bytes(sha1(key.encode("utf-8")).digest(), "big")
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, key: str) -> None:
        for idx in self._hashes(key):
            byte_i = idx // 8
            bit_i = idx % 8
            self._bits[byte_i] |= (1 << bit_i)

    def __contains__(self, key: str) -> bool:
        for idx in self._hashes(key):
            byte_i = idx // 8
            bit_i = idx % 8
            if not (self._bits[byte_i] & (1 << bit_i)):
                return False
        return True


# ============================== Backends ======================================

class BackendError(RuntimeError):
    pass


class AbstractBackend:
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    async def set(self, key: str, value: Dict[str, Any], ttl_sec: int) -> None:
        raise NotImplementedError

    async def delete(self, key: str) -> None:
        raise NotImplementedError

    async def keys_by_index(self, *, ioc_type: Optional[str], tag: Optional[str], source: Optional[str], offset: int, limit: int) -> List[str]:
        raise NotImplementedError

    async def update_indices(self, key: str, entry: Dict[str, Any]) -> None:
        raise NotImplementedError

    async def remove_from_indices(self, key: str, entry: Dict[str, Any]) -> None:
        raise NotImplementedError


class MemoryBackend(AbstractBackend):
    """
    Простой потокобезопасный in-memory backend с индексами.
    """
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._index_type: Dict[str, set] = {}
        self._index_tag: Dict[str, set] = {}
        self._index_source: Dict[str, set] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            row = self._data.get(key)
            if not row:
                return None
            value, exp_ts = row
            if exp_ts and exp_ts < time.time():
                # автоудаление просроченных
                await self.delete(key)
                return None
            return json.loads(json.dumps(value))

    async def set(self, key: str, value: Dict[str, Any], ttl_sec: int) -> None:
        async with self._lock:
            exp = time.time() + int(ttl_sec)
            self._data[key] = (json.loads(json.dumps(value)), exp)
            await self.update_indices(key, value)

    async def delete(self, key: str) -> None:
        async with self._lock:
            row = self._data.pop(key, None)
            if row:
                value, _ = row
                await self.remove_from_indices(key, value)

    async def keys_by_index(self, *, ioc_type: Optional[str], tag: Optional[str], source: Optional[str], offset: int, limit: int) -> List[str]:
        async with self._lock:
            sets: List[set] = []
            if ioc_type:
                sets.append(self._index_type.get(ioc_type, set()))
            if tag:
                sets.append(self._index_tag.get(tag.lower(), set()))
            if source:
                sets.append(self._index_source.get(source, set()))
            if not sets:
                keys = list(self._data.keys())
            else:
                base = sets[0].copy()
                for s in sets[1:]:
                    base &= s
                keys = list(base)
            keys.sort()
            return keys[offset: offset + limit]

    async def update_indices(self, key: str, entry: Dict[str, Any]) -> None:
        t = entry["key"]["type"]
        self._index_type.setdefault(t, set()).add(key)
        src = entry.get("source") or ""
        if src:
            self._index_source.setdefault(src, set()).add(key)
        for tag in entry.get("tags") or []:
            self._index_tag.setdefault(tag.lower(), set()).add(key)

    async def remove_from_indices(self, key: str, entry: Dict[str, Any]) -> None:
        t = entry["key"]["type"]
        self._index_type.get(t, set()).discard(key)
        src = entry.get("source") or ""
        self._index_source.get(src, set()).discard(key)
        for tag in entry.get("tags") or []:
            self._index_tag.get(tag.lower(), set()).discard(key)


class RedisBackend(AbstractBackend):
    """
    Redis backend с индексами:
      - k:<type>:<value> -> JSON (EXPIRE=ttl)
      - idx:type:<type> -> SET of keys
      - idx:tag:<tag> -> SET of keys
      - idx:src:<source> -> SET of keys
    """
    def __init__(self, client: "redis.Redis", namespace: str = "tioc") -> None:  # type: ignore[name-defined]
        if not _HAS_REDIS:
            raise BackendError("Redis backend not available")
        self.r = client
        self.ns = namespace

    def _k(self, key: str) -> str:
        return f"{self.ns}:k:{key}"

    def _i_type(self, t: str) -> str:
        return f"{self.ns}:idx:type:{t}"

    def _i_tag(self, tag: str) -> str:
        return f"{self.ns}:idx:tag:{tag}"

    def _i_src(self, src: str) -> str:
        return f"{self.ns}:idx:src:{src}"

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        raw = await self.r.get(self._k(key))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    async def set(self, key: str, value: Dict[str, Any], ttl_sec: int) -> None:
        await self.r.set(self._k(key), json.dumps(value, default=str), ex=ttl_sec)
        await self.update_indices(key, value)

    async def delete(self, key: str) -> None:
        value = await self.get(key)
        await self.r.delete(self._k(key))
        if value:
            await self.remove_from_indices(key, value)

    async def keys_by_index(self, *, ioc_type: Optional[str], tag: Optional[str], source: Optional[str], offset: int, limit: int) -> List[str]:
        # Пересечение множеств (SINTER) — если заданы несколько условий
        sets: List[str] = []
        if ioc_type:
            sets.append(self._i_type(ioc_type))
        if tag:
            sets.append(self._i_tag(tag.lower()))
        if source:
            sets.append(self._i_src(source))
        if not sets:
            # без индексов — вернем пусто (не сканируем весь Redis в «промышленном» режиме)
            return []
        if len(sets) == 1:
            members = await self.r.smembers(sets[0])
        else:
            members = await self.r.sinter(*sets)
        keys = sorted([m.decode("utf-8") if isinstance(m, (bytes, bytearray)) else str(m) for m in members])
        return keys[offset: offset + limit]

    async def update_indices(self, key: str, entry: Dict[str, Any]) -> None:
        pipe = self.r.pipeline()
        pipe.sadd(self._i_type(entry["key"]["type"]), key)
        src = entry.get("source") or ""
        if src:
            pipe.sadd(self._i_src(src), key)
        for tag in entry.get("tags") or []:
            pipe.sadd(self._i_tag(tag.lower()), key)
        await pipe.execute()

    async def remove_from_indices(self, key: str, entry: Dict[str, Any]) -> None:
        pipe = self.r.pipeline()
        pipe.srem(self._i_type(entry["key"]["type"]), key)
        src = entry.get("source") or ""
        if src:
            pipe.srem(self._i_src(src), key)
        for tag in entry.get("tags") or []:
            pipe.srem(self._i_tag(tag.lower()), key)
        await pipe.execute()


# ============================== TIOC Cache ====================================

class TIOCCache:
    """
    Асинхронный кэш Threat Intel IOC с нормализацией, TTL и индексами.
    """
    def __init__(
        self,
        backend: Optional[AbstractBackend] = None,
        *,
        bloom_capacity: int = 2_000_000,
        bloom_error_rate: float = 0.01,
    ) -> None:
        self.backend = backend or MemoryBackend()
        self._bloom = BloomFilter(capacity=bloom_capacity, error_rate=bloom_error_rate)
        self._lock = asyncio.Lock()

    # ---------- Public API ----------

    async def upsert(
        self,
        *,
        ioc_type: str,
        value: str,
        tlp: str,
        confidence: int,
        severity: int,
        source: str,
        tags: Optional[Sequence[str]] = None,
        note: Optional[str] = None,
        false_positive: Optional[bool] = None,
        revoked: Optional[bool] = None,
        seen_at: Optional[datetime] = None,
    ) -> IOCEntry:
        """
        Создать/обновить индикатор. Дедупликация по (type,value).
        """
        k = IOCKey(type=ioc_type, value=value)
        key = k.key()
        now = seen_at or utcnow()
        async with self._lock:
            existing = await self.backend.get(key)
            if existing:
                entry = IOCEntry.parse_obj(existing)
                entry.last_seen = max(entry.last_seen, now)
                entry.sightings += 1
                # обновляем поля источника разведки без понижения
                entry.tlp = tlp or entry.tlp
                entry.confidence = max(entry.confidence, confidence)
                entry.severity = max(entry.severity, severity)
                entry.tags = sorted(set(entry.tags) | set([t.strip().lower() for t in (tags or []) if t]))
                if note:
                    entry.note = (entry.note + " | " + note) if entry.note else note
                if false_positive is True:
                    entry.false_positive = True
                if revoked is True:
                    entry.revoked = True
            else:
                ttl = ttl_for(k.type, sightings=1)
                entry = IOCEntry(
                    key=k,
                    tlp=tlp or TLP.amber,
                    confidence=confidence,
                    severity=severity,
                    source=source,
                    tags=[t.strip().lower() for t in (tags or []) if t],
                    first_seen=now,
                    last_seen=now,
                    sightings=1,
                    false_positive=bool(false_positive),
                    revoked=bool(revoked),
                    ttl_sec=ttl,
                )
            # TTL и score
            entry.ttl_sec = ttl_for(entry.key.type, entry.sightings)
            entry.expires_at = entry.last_seen + timedelta(seconds=entry.ttl_sec)
            entry.score = calc_score(entry.confidence, entry.severity, entry.first_seen, entry.last_seen, entry.sightings)

            # FP/Revoked — немедленное «истечение»
            if entry.false_positive or entry.revoked:
                entry.ttl_sec = min(entry.ttl_sec, 60)  # быстрый дропаут
                entry.expires_at = now + timedelta(seconds=entry.ttl_sec)

            await self.backend.set(key, json.loads(entry.json()), ttl_sec=entry.ttl_sec)
            self._bloom.add(key)
            return entry

    async def bulk_upsert(self, items: Iterable[Dict[str, Any]]) -> List[IOCEntry]:
        out: List[IOCEntry] = []
        for it in items:
            out.append(
                await self.upsert(
                    ioc_type=it["ioc_type"],
                    value=it["value"],
                    tlp=it.get("tlp", TLP.amber),
                    confidence=int(it.get("confidence", 50)),
                    severity=int(it.get("severity", 50)),
                    source=it.get("source", "unknown"),
                    tags=it.get("tags"),
                    note=it.get("note"),
                    false_positive=it.get("false_positive"),
                    revoked=it.get("revoked"),
                    seen_at=it.get("seen_at"),
                )
            )
        return out

    async def get(self, ioc_type: str, value: str) -> Optional[IOCEntry]:
        k = IOCKey(type=ioc_type, value=value)
        row = await self.backend.get(k.key())
        return IOCEntry.parse_obj(row) if row else None

    async def delete(self, ioc_type: str, value: str) -> None:
        k = IOCKey(type=ioc_type, value=value)
        row = await self.backend.get(k.key())
        if row:
            await self.backend.delete(k.key())

    async def mark_false_positive(self, ioc_type: str, value: str, note: Optional[str] = None) -> Optional[IOCEntry]:
        entry = await self.get(ioc_type, value)
        if not entry:
            return None
        entry.false_positive = True
        entry.note = (entry.note + " | " + (note or "")) if note and entry.note else (note or entry.note)
        entry.ttl_sec = 60
        entry.expires_at = utcnow() + timedelta(seconds=entry.ttl_sec)
        await self.backend.set(entry.key.key(), json.loads(entry.json()), ttl_sec=entry.ttl_sec)
        return entry

    async def revoke_by_source(self, source: str) -> int:
        """
        Пометить revoked все IOC данного источника (без полного удаления).
        Возвращает количество обновленных записей.
        """
        updated = 0
        keys = await self.backend.keys_by_index(ioc_type=None, tag=None, source=source, offset=0, limit=10_000)
        for k in keys:
            row = await self.backend.get(k)
            if not row:
                continue
            entry = IOCEntry.parse_obj(row)
            if not entry.revoked:
                entry.revoked = True
                entry.ttl_sec = min(entry.ttl_sec, 120)
                entry.expires_at = utcnow() + timedelta(seconds=entry.ttl_sec)
                await self.backend.set(k, json.loads(entry.json()), ttl_sec=entry.ttl_sec)
                updated += 1
        return updated

    async def query(self, q: Query) -> Tuple[List[IOCEntry], Optional[int]]:
        """
        Пагинированный поиск по индексам (тип/тег/источник) с фильтрами.
        Возвращает (items, next_offset).
        """
        # Получаем кандидатов из backend индексов
        ioc_type = q.types[0] if (q.types and len(q.types) == 1) else None
        tag = q.tags[0] if (q.tags and len(q.tags) == 1) else None
        keys = await self.backend.keys_by_index(
            ioc_type=ioc_type,
            tag=tag,
            source=q.source,
            offset=q.offset,
            limit=q.limit * 3,  # чуть шире для последующей фильтрации
        )
        items: List[IOCEntry] = []
        now = utcnow()
        for k in keys:
            row = await self.backend.get(k)
            if not row:
                continue
            e = IOCEntry.parse_obj(row)
            if q.types and e.key.type not in q.types:
                continue
            if q.tags and not (set(t.lower() for t in q.tags) & set(e.tags)):
                continue
            if q.active_only and e.expires_at <= now:
                continue
            if not q.include_false_positive and e.false_positive:
                continue
            if not q.include_revoked and e.revoked:
                continue
            if q.min_confidence is not None and e.confidence < q.min_confidence:
                continue
            if q.min_severity is not None and e.severity < q.min_severity:
                continue
            if q.min_score is not None and e.score < q.min_score:
                continue
            items.append(e)
            if len(items) >= q.limit:
                break
        next_off = (q.offset + q.limit) if len(items) >= q.limit else None
        return items, next_off

    async def evict_expired(self, *, batch: int = 1000) -> int:
        """
        Удалить просроченные записи (только для in-memory backend).
        Для Redis EXPIRE выполняется сервером.
        """
        if not isinstance(self.backend, MemoryBackend):
            return 0
        removed = 0
        # Пробег по индексам типа — дешевле, чем по всем ключам
        for t in list(DEFAULT_TTLS.keys()):
            keys = await self.backend.keys_by_index(ioc_type=t, tag=None, source=None, offset=0, limit=batch)
            now_ts = time.time()
            for k in keys:
                row = self.backend._data.get(k)  # type: ignore[attr-defined]
                if not row:
                    continue
                _, exp = row
                if exp and exp < now_ts:
                    await self.backend.delete(k)
                    removed += 1
        return removed

    def probably_seen(self, ioc_type: str, value: str) -> bool:
        """
        Быстрая вероятностная проверка наличия (Bloom). Возможны ложные срабатывания.
        """
        k = IOCKey(type=ioc_type, value=value).key()
        return k in self._bloom

    # ---------- Factory helpers ----------

    @staticmethod
    def memory() -> "TIOCCache":
        return TIOCCache(MemoryBackend())

    @staticmethod
    def from_redis(url: str, *, namespace: str = "tioc") -> "TIOCCache":
        if not _HAS_REDIS:
            raise BackendError("redis is not installed")
        client = redis.from_url(url, encoding="utf-8", decode_responses=False)
        return TIOCCache(RedisBackend(client, namespace=namespace))


# ============================== Convenience ===================================

def make_entry(
    *,
    ioc_type: str,
    value: str,
    source: str,
    tlp: str = TLP.amber,
    confidence: int = 50,
    severity: int = 50,
    tags: Optional[Sequence[str]] = None,
    note: Optional[str] = None,
) -> IOCEntry:
    """
    Удобный конструктор для ручных вставок.
    """
    k = IOCKey(type=ioc_type, value=value)
    now = utcnow()
    ttl = ttl_for(k.type, sightings=1)
    entry = IOCEntry(
        key=k,
        tlp=tlp,
        confidence=confidence,
        severity=severity,
        source=source,
        tags=[t.strip().lower() for t in (tags or []) if t],
        first_seen=now,
        last_seen=now,
        sightings=1,
        ttl_sec=ttl,
        expires_at=now + timedelta(seconds=ttl),
        score=calc_score(confidence, severity, now, now, 1),
        note=note,
    )
    return entry


__all__ = [
    "IOCType",
    "TLP",
    "IOCKey",
    "IOCEntry",
    "Query",
    "TIOCCache",
    "MemoryBackend",
    "RedisBackend",
    "BackendError",
    "normalize_ioc",
    "calc_score",
    "ttl_for",
    "BloomFilter",
    "make_entry",
]
