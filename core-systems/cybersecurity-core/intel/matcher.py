# cybersecurity-core/cybersecurity/intel/matcher.py
from __future__ import annotations

import re
import ipaddress
import threading
import json
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Set
from urllib.parse import urlsplit, urlunsplit, quote, unquote, parse_qsl

# =========================
# Models / Types
# =========================

class IndicatorType(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"          # *.example.com
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    REGEX = "regex"
    TEXT = "text"                     # substring (Aho–Corasick)
    FILEPATH = "filepath"

@dataclass(slots=True)
class Indicator:
    id: str
    type: IndicatorType
    pattern: str
    confidence: int = 80                     # 0..100
    severity: str = "medium"                 # low|medium|high|critical
    source: Optional[str] = None
    actor: Optional[str] = None
    tags: Tuple[str, ...] = field(default_factory=tuple)
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    ttl: Optional[int] = None               # seconds from now if set
    metadata: Mapping[str, Any] = field(default_factory=dict)
    enabled: bool = True

@dataclass(slots=True)
class Match:
    indicator_id: str
    type: IndicatorType
    value: str
    score: float
    reason: str
    tags: Tuple[str, ...]
    source: Optional[str]
    actor: Optional[str]
    metadata: Mapping[str, Any]
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    location: Optional[str] = None          # e.g., "body", "header:X-From", "text[offset=123]"

# =========================
# Utilities
# =========================

_SEVERITY_WEIGHT = {
    "low": 0.6, "medium": 0.8, "high": 0.95, "critical": 1.0
}

_HASH_RE = {
    IndicatorType.MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
    IndicatorType.SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    IndicatorType.SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
}
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}\b")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{0,4}\b")
_DOMAIN_RE = re.compile(r"\b(?=.{1,253}\b)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*)\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@(?:[A-Z0-9\-]+\.)+[A-Z]{2,63}\b", re.IGNORECASE)
_URL_RE = re.compile(r"\b(?:h..p|https?)s?:\/\/[^\s\"'<>]+", re.IGNORECASE)  # допускаем defang hxxp

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _is_active(ind: Indicator, now: Optional[datetime] = None) -> bool:
    now = now or _utcnow()
    if not ind.enabled:
        return False
    if ind.valid_from and now < ind.valid_from:
        return False
    if ind.valid_until and now > ind.valid_until:
        return False
    if ind.ttl is not None and ind.ttl >= 0:
        # ttl интерпретируем как "живёт ind.ttl секунд с момента загрузки" — если есть loaded_at в metadata
        loaded_at_str = ind.metadata.get("loaded_at")
        if loaded_at_str:
            try:
                loaded_at = datetime.fromisoformat(loaded_at_str)
                if loaded_at.tzinfo is None:
                    loaded_at = loaded_at.replace(tzinfo=timezone.utc)
                if now > loaded_at + timedelta(seconds=ind.ttl):
                    return False
            except Exception:
                pass
    return True

def _age_decay(ind: Indicator, now: Optional[datetime] = None) -> float:
    """Коэффициент свежести: 0.7..1.0 (чем свежее, тем выше)."""
    now = now or _utcnow()
    ref = ind.valid_from or _parse_dt(ind.metadata.get("loaded_at")) or now
    days = max(0.0, (now - ref).total_seconds() / 86400.0)
    if days <= 1:
        return 1.0
    if days >= 180:
        return 0.7
    return 1.0 - (days / 180.0) * 0.3

def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def _severity_w(sev: str) -> float:
    return _SEVERITY_WEIGHT.get(sev.lower(), 0.8)

def compute_score(ind: Indicator, base: float = 0.85) -> float:
    c = max(0, min(100, ind.confidence)) / 100.0
    s = _severity_w(ind.severity)
    a = _age_decay(ind)
    return round(base * (0.5 * c + 0.3 * s + 0.2 * a), 6)

# ---- Defang/Normalization ----

@lru_cache(maxsize=4096)
def refang(s: str) -> str:
    if not s:
        return s
    t = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    t = t.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("hxxps:\\/\\/", "https://").replace("hxxp:\\/\\/", "http://")
    t = t.replace(":///", "://")
    t = t.replace("\\.", ".")
    return t

@lru_cache(maxsize=4096)
def normalize_domain(d: str) -> str:
    d = refang(d.strip().rstrip("."))
    try:
        # stdlib codec 'idna'
        d_idna = d.encode("idna").decode("ascii")
        return d_idna.lower()
    except Exception:
        return d.lower()

@lru_cache(maxsize=4096)
def normalize_email(e: str) -> str:
    e = refang(e.strip())
    try:
        local, _, host = e.rpartition("@")
        return f"{local.lower()}@{normalize_domain(host)}"
    except Exception:
        return e.lower()

@lru_cache(maxsize=4096)
def normalize_url(u: str) -> str:
    u = refang(u.strip())
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        # частый дефанг без схемы
        u = "http://" + u
    parts = urlsplit(u)
    scheme = parts.scheme.lower()
    netloc = parts.netloc
    if "@" in netloc:
        # убираем креды из нормализации
        _, _, hostport = netloc.rpartition("@")
    else:
        hostport = netloc
    host, sep, port = hostport.partition(":")
    host = normalize_domain(host)
    # убираем дефолтные порты
    if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
        port = ""
    new_netloc = f"{host}{(':'+port) if port else ''}"
    # нормализуем путь: unquote -> quote, удаляем //, оставляем /
    path = re.sub(r"/{2,}", "/", quote(unquote(parts.path)))
    # сортируем query
    if parts.query:
        q = sorted(parse_qsl(parts.query, keep_blank_values=True))
        query = "&".join(f"{quote(k)}={quote(v)}" for k, v in q)
    else:
        query = ""
    frag = ""  # фрагменты игнорируем
    return urlunsplit((scheme, new_netloc, path, query, frag))

def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

# =========================
# Aho–Corasick for TEXT
# =========================

class _ACNode:
    __slots__ = ("next", "fail", "out")
    def __init__(self) -> None:
        self.next: Dict[str, _ACNode] = {}
        self.fail: Optional[_ACNode] = None
        self.out: List[str] = []  # patterns ending here

class AhoCorasick:
    """Лёгкая AC-реализация для поиска множества подстрок (TEXT)."""
    def __init__(self, patterns: Iterable[str]) -> None:
        self._root = _ACNode()
        for p in patterns:
            self._insert(p)
        self._build()

    def _insert(self, pat: str) -> None:
        node = self._root
        for ch in pat:
            node = node.next.setdefault(ch, _ACNode())
        node.out.append(pat)

    def _build(self) -> None:
        from collections import deque
        q = deque()
        for node in self._root.next.values():
            node.fail = self._root
            q.append(node)
        while q:
            r = q.popleft()
            for a, u in r.next.items():
                q.append(u)
                f = r.fail
                while f and a not in f.next:
                    f = f.fail
                u.fail = f.next[a] if f and a in f.next else self._root
                u.out += u.fail.out if u.fail else []

    def finditer(self, s: str) -> Iterable[Tuple[int, str]]:
        node = self._root
        for i, ch in enumerate(s):
            while node and ch not in node.next:
                node = node.fail
            node = node.next.get(ch, self._root)
            for pat in node.out:
                yield i - len(pat) + 1, pat

# =========================
# Indexes
# =========================

class _DomainIndex:
    def __init__(self) -> None:
        self.exact: Set[str] = set()
        self.suffixes: Set[str] = set()  # for *.example.com store "example.com"

    def add(self, ind: Indicator) -> None:
        p = normalize_domain(ind.pattern)
        if ind.type == IndicatorType.DOMAIN:
            self.exact.add(p)
        else:
            # SUBDOMAIN: allow example.com itself and subdomains
            if p.startswith("*."):
                p = p[2:]
            self.suffixes.add(p)

    def remove(self, ind: Indicator) -> None:
        p = normalize_domain(ind.pattern)
        if ind.type == IndicatorType.DOMAIN:
            self.exact.discard(p)
        else:
            if p.startswith("*."):
                p = p[2:]
            self.suffixes.discard(p)

    def match(self, host: str) -> Tuple[bool, Optional[str], bool]:
        """return (matched, matched_suffix, is_subdomain_rule)"""
        h = normalize_domain(host)
        if h in self.exact:
            return True, h, False
        # suffix match
        parts = h.split(".")
        for i in range(len(parts) - 1):
            suffix = ".".join(parts[i:])
            if suffix in self.suffixes:
                return True, suffix, True
        return False, None, False

class _URLIndex:
    def __init__(self) -> None:
        self.exact: Set[str] = set()
        self.prefixes: List[str] = []  # startswith normalized

    def add(self, ind: Indicator) -> None:
        p = normalize_url(ind.pattern)
        if p.endswith("*"):
            self.prefixes.append(p[:-1])
        else:
            self.exact.add(p)

    def remove(self, ind: Indicator) -> None:
        p = normalize_url(ind.pattern)
        if p.endswith("*"):
            try:
                self.prefixes.remove(p[:-1])
            except ValueError:
                pass
        else:
            self.exact.discard(p)

    def match(self, url: str) -> Tuple[bool, Optional[str], bool]:
        u = normalize_url(url)
        if u in self.exact:
            return True, u, False
        for pref in self.prefixes:
            if u.startswith(pref):
                return True, pref, True
        return False, None, False

class _IPIndex:
    def __init__(self) -> None:
        self.ips: Set[str] = set()
        self.networks: List[ipaddress._BaseNetwork] = []

    def add(self, ind: Indicator) -> None:
        if ind.type == IndicatorType.IP:
            try:
                ip = ipaddress.ip_address(ind.pattern.strip())
                self.ips.add(str(ip))
            except Exception:
                pass
        else:
            try:
                net = ipaddress.ip_network(ind.pattern.strip(), strict=False)
                self.networks.append(net)
            except Exception:
                pass

    def remove(self, ind: Indicator) -> None:
        if ind.type == IndicatorType.IP:
            try:
                ip = str(ipaddress.ip_address(ind.pattern.strip()))
                self.ips.discard(ip)
            except Exception:
                pass
        else:
            try:
                net = ipaddress.ip_network(ind.pattern.strip(), strict=False)
                self.networks = [n for n in self.networks if n != net]
            except Exception:
                pass

    def match(self, ip: str) -> Tuple[bool, Optional[str], bool]:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except Exception:
            return False, None, False
        if str(addr) in self.ips:
            return True, str(addr), False
        for net in self.networks:
            if addr in net:
                return True, str(net), True
        return False, None, False

class _RegexIndex:
    def __init__(self) -> None:
        self.items: List[Tuple[re.Pattern[str], Indicator]] = []

    def add(self, ind: Indicator) -> None:
        flags = re.IGNORECASE | re.MULTILINE
        self.items.append((re.compile(ind.pattern, flags), ind))

    def remove(self, ind: Indicator) -> None:
        self.items = [(r, i) for (r, i) in self.items if i.id != ind.id]

    def match(self, value: str) -> List[Indicator]:
        hits: List[Indicator] = []
        for r, ind in self.items:
            if r.search(value):
                hits.append(ind)
        return hits

class _TextIndex:
    def __init__(self) -> None:
        self.patterns: Dict[str, Indicator] = {}
        self._ac: Optional[AhoCorasick] = None
        self._dirty = False

    def add(self, ind: Indicator) -> None:
        self.patterns[ind.pattern] = ind
        self._dirty = True

    def remove(self, ind: Indicator) -> None:
        self.patterns.pop(ind.pattern, None)
        self._dirty = True

    def _ensure(self) -> None:
        if self._dirty:
            self._ac = AhoCorasick(self.patterns.keys()) if self.patterns else None
            self._dirty = False

    def find(self, text: str) -> List[Tuple[int, Indicator, str]]:
        self._ensure()
        if not self._ac:
            return []
        out: List[Tuple[int, Indicator, str]] = []
        for pos, pat in self._ac.finditer(text):
            ind = self.patterns.get(pat)
            if ind:
                out.append((pos, ind, pat))
        return out

# =========================
# Matcher
# =========================

class IntelMatcher:
    """
    Потокобезопасный (RLock) сопоставитель индикаторов.
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()

        self._ind_by_id: Dict[str, Indicator] = {}

        self._dom = _DomainIndex()
        self._url = _URLIndex()
        self._ip = _IPIndex()
        self._regex = _RegexIndex()
        self._text = _TextIndex()

        # allowlists
        self._allow_domains: Set[str] = set()
        self._allow_ips: Set[str] = set()
        self._allow_urls: Set[str] = set()
        self._allow_hashes: Set[str] = set()
        self._allow_emails: Set[str] = set()
        self._allow_paths: Set[str] = set()

        # auxiliary indexes
        self._emails: Dict[str, List[Indicator]] = {}
        self._hashes: Dict[IndicatorType, Set[str]] = {
            IndicatorType.MD5: set(),
            IndicatorType.SHA1: set(),
            IndicatorType.SHA256: set(),
        }
        self._paths: Dict[str, List[Indicator]] = {}

    # ---------- loading / updates ----------

    def load_indicators(self, indicators: Iterable[Indicator]) -> None:
        with self._lock:
            for ind in indicators:
                self._add_ind_locked(ind)

    def add_indicator(self, ind: Indicator) -> None:
        with self._lock:
            self._add_ind_locked(ind)

    def remove_indicator(self, indicator_id: str) -> None:
        with self._lock:
            ind = self._ind_by_id.pop(indicator_id, None)
            if not ind:
                return
            self._remove_from_indexes_locked(ind)

    def _add_ind_locked(self, ind: Indicator) -> None:
        if not ind.id:
            raise ValueError("indicator.id is required")
        self._ind_by_id[ind.id] = ind
        # activation time hint
        if "loaded_at" not in ind.metadata:
            ind.metadata = {**ind.metadata, "loaded_at": _utcnow().isoformat()}

        match ind.type:
            case IndicatorType.DOMAIN | IndicatorType.SUBDOMAIN:
                self._dom.add(ind)
            case IndicatorType.URL:
                self._url.add(ind)
            case IndicatorType.IP | IndicatorType.CIDR:
                self._ip.add(ind)
            case IndicatorType.EMAIL:
                key = normalize_email(ind.pattern)
                self._emails.setdefault(key, []).append(ind)
            case IndicatorType.MD5 | IndicatorType.SHA1 | IndicatorType.SHA256:
                self._hashes[ind.type].add(ind.pattern.lower())
            case IndicatorType.FILEPATH:
                p = ind.pattern.lower()
                self._paths.setdefault(p, []).append(ind)
            case IndicatorType.REGEX:
                self._regex.add(ind)
            case IndicatorType.TEXT:
                self._text.add(ind)
            case _:
                # ignore unknown
                pass

    def _remove_from_indexes_locked(self, ind: Indicator) -> None:
        match ind.type:
            case IndicatorType.DOMAIN | IndicatorType.SUBDOMAIN:
                self._dom.remove(ind)
            case IndicatorType.URL:
                self._url.remove(ind)
            case IndicatorType.IP | IndicatorType.CIDR:
                self._ip.remove(ind)
            case IndicatorType.EMAIL:
                key = normalize_email(ind.pattern)
                lst = self._emails.get(key)
                if lst:
                    self._emails[key] = [i for i in lst if i.id != ind.id]
            case IndicatorType.MD5 | IndicatorType.SHA1 | IndicatorType.SHA256:
                self._hashes[ind.type].discard(ind.pattern.lower())
            case IndicatorType.FILEPATH:
                p = ind.pattern.lower()
                lst = self._paths.get(p)
                if lst:
                    self._paths[p] = [i for i in lst if i.id != ind.id]
            case IndicatorType.REGEX:
                self._regex.remove(ind)
            case IndicatorType.TEXT:
                self._text.remove(ind)

    # ---------- allowlists ----------

    def set_allowlist(
        self,
        *,
        domains: Iterable[str] = (),
        ips: Iterable[str] = (),
        urls: Iterable[str] = (),
        hashes: Iterable[str] = (),
        emails: Iterable[str] = (),
        paths: Iterable[str] = (),
    ) -> None:
        with self._lock:
            self._allow_domains = {normalize_domain(x) for x in domains}
            self._allow_ips = {self._norm_ip(x) for x in ips if self._norm_ip(x)}
            self._allow_urls = {normalize_url(x) for x in urls}
            self._allow_hashes = {x.lower() for x in hashes}
            self._allow_emails = {normalize_email(x) for x in emails}
            self._allow_paths = {x.lower() for x in paths}

    # ---------- matching primitives ----------

    def match_value(self, kind: IndicatorType, value: str, *, location: Optional[str] = None) -> List[Match]:
        """Точное сопоставление конкретного значения (без извлечения)."""
        with self._lock:
            return self._match_value_locked(kind, value, location=location)

    def _match_value_locked(self, kind: IndicatorType, value: str, *, location: Optional[str]) -> List[Match]:
        now = _utcnow()
        matches: List[Match] = []

        def emit(ind: Indicator, reason: str, val: str) -> None:
            if not _is_active(ind, now):
                return
            score = compute_score(ind)
            matches.append(Match(
                indicator_id=ind.id,
                type=ind.type,
                value=val,
                score=score,
                reason=reason,
                tags=ind.tags,
                source=ind.source,
                actor=ind.actor,
                metadata=ind.metadata,
                location=location,
            ))

        if kind in (IndicatorType.DOMAIN, IndicatorType.SUBDOMAIN):
            host = normalize_domain(value)
            if host in self._allow_domains:
                return []
            hit, suff, is_sub = self._dom.match(host)
            if hit:
                # выбрать все индикаторы, которым соответствует
                for ind in self._ind_by_id.values():
                    if ind.type == IndicatorType.DOMAIN and normalize_domain(ind.pattern) == host:
                        emit(ind, "domain:exact", host)
                    elif ind.type == IndicatorType.SUBDOMAIN:
                        patt = normalize_domain(ind.pattern[2:] if ind.pattern.startswith("*.") else ind.pattern)
                        if host == patt or host.endswith("." + patt):
                            emit(ind, "domain:suffix", host)
                return matches
            return matches

        if kind == IndicatorType.URL:
            url = normalize_url(value)
            if url in self._allow_urls:
                return []
            hit, sig, is_pref = self._url.match(url)
            if hit:
                for ind in self._ind_by_id.values():
                    if ind.type == IndicatorType.URL:
                        patt = normalize_url(ind.pattern)
                        if patt.endswith("*"):
                            if url.startswith(patt[:-1]):
                                emit(ind, "url:prefix", url)
                        elif url == patt:
                            emit(ind, "url:exact", url)
                return matches
            # regex url match too
            for ind in self._regex.match(url):
                emit(ind, "regex:url", url)
            return matches

        if kind in (IndicatorType.IP, IndicatorType.CIDR):
            ip = self._norm_ip(value)
            if not ip:
                return []
            if ip in self._allow_ips:
                return []
            hit, sig, is_net = self._ip.match(ip)
            if hit:
                for ind in self._ind_by_id.values():
                    if ind.type == IndicatorType.IP and self._eq_ip(ind.pattern, ip):
                        emit(ind, "ip:exact", ip)
                    elif ind.type == IndicatorType.CIDR and self._in_cidr(ip, ind.pattern):
                        emit(ind, "ip:cidr", ip)
            return matches

        if kind == IndicatorType.EMAIL:
            em = normalize_email(value)
            if em in self._allow_emails:
                return []
            lst = self._emails.get(em) or []
            for ind in lst:
                emit(ind, "email:exact", em)
            # regex fallback
            for ind in self._regex.match(em):
                emit(ind, "regex:email", em)
            return matches

        if kind in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
            val = value.lower()
            if val in self._allow_hashes:
                return []
            if val in self._hashes.get(kind, set()):
                for ind in self._ind_by_id.values():
                    if ind.type == kind and ind.pattern.lower() == val:
                        emit(ind, f"{kind.value}:exact", val)
            return matches

        if kind == IndicatorType.FILEPATH:
            key = value.lower()
            if key in self._allow_paths:
                return []
            for patt, inds in self._paths.items():
                if patt == key or key.endswith(patt):  # поддержка суффикса
                    for ind in inds:
                        emit(ind, "filepath:match", value)
            # regex fallback
            for ind in self._regex.match(value):
                emit(ind, "regex:filepath", value)
            return matches

        if kind == IndicatorType.REGEX:
            for ind in self._regex.match(value):
                emit(ind, "regex:value", value)
            return matches

        if kind == IndicatorType.TEXT:
            # text: используем AC по добавленным TEXT-индикаторам
            for pos, ind, pat in self._text.find(value):
                emit(ind, f"text:substring@{pos}", pat)
            # плюс поиск извлекаемых сущностей из текста
            matches += self.extract_and_match_text(value)
            return matches

        return matches

    # ---------- extraction + bulk matching ----------

    def extract_and_match_text(self, text: str, *, location: str = "text") -> List[Match]:
        """
        Извлекает из произвольного текста observables (URL, IP, домены, email, хэши) и сопоставляет.
        """
        out: List[Match] = []
        with self._lock:
            # URLs
            for m in _URL_RE.finditer(text):
                url_raw = m.group(0)
                for hit in self._match_value_locked(IndicatorType.URL, url_raw, location=f"{location}:url[{m.start()}]"):
                    out.append(hit)
            # IPv4/IPv6
            for m in _IP_RE.finditer(text):
                ip = m.group(0)
                out += self._match_value_locked(IndicatorType.IP, ip, location=f"{location}:ip[{m.start()}]")
            for m in _IPV6_RE.finditer(text):
                ip6 = m.group(0)
                out += self._match_value_locked(IndicatorType.IP, ip6, location=f"{location}:ip6[{m.start()}]")
            # domains
            for m in _DOMAIN_RE.finditer(text):
                dom = m.group(1)
                out += self._match_value_locked(IndicatorType.DOMAIN, dom, location=f"{location}:domain[{m.start()}]")
            # emails
            for m in _EMAIL_RE.finditer(text):
                em = m.group(0)
                out += self._match_value_locked(IndicatorType.EMAIL, em, location=f"{location}:email[{m.start()}]")
            # hashes
            for t, rx in _HASH_RE.items():
                for m in rx.finditer(text):
                    h = m.group(0)
                    out += self._match_value_locked(t, h, location=f"{location}:{t.value}[{m.start()}]")
            # text substrings via AC
            for pos, ind, pat in self._text.find(text):
                if _is_active(ind):
                    out.append(Match(
                        indicator_id=ind.id,
                        type=ind.type,
                        value=pat,
                        score=compute_score(ind),
                        reason=f"text:substring@{pos}",
                        tags=ind.tags,
                        source=ind.source,
                        actor=ind.actor,
                        metadata=ind.metadata,
                        location=f"{location}:substring[{pos}]",
                    ))
        return self._dedup(out)

    # ---------- helpers ----------

    def _dedup(self, matches: List[Match]) -> List[Match]:
        # Дедуп по (indicator_id, value, location)
        seen: Set[Tuple[str, str, Optional[str]]] = set()
        out: List[Match] = []
        for m in matches:
            k = (m.indicator_id, m.value, m.location)
            if k in seen:
                continue
            seen.add(k)
            out.append(m)
        return out

    @staticmethod
    def _norm_ip(v: str) -> Optional[str]:
        try:
            return str(ipaddress.ip_address(refang(v).strip()))
        except Exception:
            return None

    @staticmethod
    def _eq_ip(a: str, b: str) -> bool:
        try:
            return ipaddress.ip_address(a) == ipaddress.ip_address(b)
        except Exception:
            return False

    @staticmethod
    def _in_cidr(ip: str, cidr: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False

# =========================
# JSON (de)serialization helpers (optional)
# =========================

def indicator_from_dict(d: Mapping[str, Any]) -> Indicator:
    return Indicator(
        id=str(d["id"]),
        type=IndicatorType(d["type"]),
        pattern=str(d["pattern"]),
        confidence=int(d.get("confidence", 80)),
        severity=str(d.get("severity", "medium")),
        source=d.get("source"),
        actor=d.get("actor"),
        tags=tuple(d.get("tags", [])),
        valid_from=_parse_dt(d.get("valid_from")),
        valid_until=_parse_dt(d.get("valid_until")),
        ttl=int(d["ttl"]) if d.get("ttl") is not None else None,
        metadata=d.get("metadata", {}),
        enabled=bool(d.get("enabled", True)),
    )

def indicator_to_dict(ind: Indicator) -> Dict[str, Any]:
    return {
        "id": ind.id,
        "type": ind.type.value,
        "pattern": ind.pattern,
        "confidence": ind.confidence,
        "severity": ind.severity,
        "source": ind.source,
        "actor": ind.actor,
        "tags": list(ind.tags),
        "valid_from": ind.valid_from.isoformat() if ind.valid_from else None,
        "valid_until": ind.valid_until.isoformat() if ind.valid_until else None,
        "ttl": ind.ttl,
        "metadata": dict(ind.metadata),
        "enabled": ind.enabled,
    }

# =========================
# Example minimal usage (docstring)
# =========================
"""
matcher = IntelMatcher()
matcher.load_indicators([
    Indicator(id="1", type=IndicatorType.SUBDOMAIN, pattern="*.evil.com", severity="high", confidence=90),
    Indicator(id="2", type=IndicatorType.URL, pattern="https://evil.com/pay*", severity="critical", confidence=95),
    Indicator(id="3", type=IndicatorType.CIDR, pattern="10.0.0.0/8"),
    Indicator(id="4", type=IndicatorType.TEXT, pattern="BadRabbit", tags=("malware",)),
    Indicator(id="5", type=IndicatorType.REGEX, pattern=r"(?i)\btrickbot\b"),
    Indicator(id="6", type=IndicatorType.MD5, pattern="44d88612fea8a8f36de82e1278abb02f"),
])

hits = matcher.extract_and_match_text("hxxps://evil.com/pay?x=1 and 10.0.0.5 met BadRabbit")
for h in hits:
    print(h)
"""
