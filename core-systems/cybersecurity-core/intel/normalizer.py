# cybersecurity-core/cybersecurity/intel/normalizer.py
from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, ConfigDict

__all__ = [
    "IndicatorType",
    "Severity",
    "NormalizedIndicator",
    "RejectedItem",
    "NormalizationStats",
    "NormalizationBatchResult",
    "IntelNormalizer",
    "classify_indicator",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _uuid7_str() -> str:
    # Fallback to uuid4 if uuid7 is not available (Python < 3.12)
    try:
        return str(uuid.uuid7())
    except AttributeError:
        return str(uuid.uuid4())

def _safe_lower(s: Optional[str]) -> Optional[str]:
    return s.lower() if isinstance(s, str) else s

def _refang(s: str) -> str:
    """
    Reverse common defanging patterns used in threat intel (hxxp://, .[.] , h[tt]p, etc.)
    """
    if not s:
        return s
    x = s
    x = x.replace("[.]", ".").replace("(.)", ".")
    x = re.sub(r"h\[*x*\]*ttp", "http", x, flags=re.IGNORECASE)
    x = re.sub(r"h\[*x*\]*tps", "https", x, flags=re.IGNORECASE)
    x = x.replace(":///", "://")
    x = x.replace("\\.", ".")
    x = x.replace("[:]", ":")
    x = x.replace("[@]", "@")
    return x.strip()

def _idna_ascii(domain: str) -> str:
    # Convert to lowercase, strip trailing dot, encode to IDNA ASCII
    d = domain.strip().strip(".").lower()
    try:
        return d.encode("idna").decode("ascii")
    except Exception:
        return d  # if conversion fails, keep as-is

def _normalize_query(query: str) -> str:
    # sort key=value pairs to get canonical order; avoid urllib to keep dependencies minimal
    parts = [p for p in query.split("&") if p]
    kv = []
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
        else:
            k, v = p, ""
        kv.append((k, v))
    kv.sort(key=lambda t: (t[0], t[1]))
    return "&".join(f"{k}={v}" if v else k for k, v in kv)

# ---------------------------------------------------------------------------
# Regex patterns (strict, length-limited)
# ---------------------------------------------------------------------------

# IPv4 strict (0-255 segments)
_octet = r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})"
RE_IPV4 = re.compile(rf"^(?:{_octet}\.){{3}}{_octet}$")

# Simplified but safe IPv6 (use ipaddress for real validation)
RE_IPV6 = re.compile(r"^[0-9A-Fa-f:]{2,39}$")

# Domain/FQDN (labels 1-63, TLD 2-24)
RE_LABEL = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
RE_FQDN = re.compile(rf"^(?:{RE_LABEL}\.)+{RE_LABEL}$")
RE_DOMAIN = re.compile(rf"^{RE_LABEL}(?:\.{RE_LABEL})+$")

# Email
RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-']+@([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$")

# URL (scheme://host[:port]/path?query#frag) — minimal, canonicalization later
RE_URL = re.compile(
    r"^(?P<scheme>https?|ftp)://(?P<host>[A-Za-z0-9\.\-:\[\]]+)(?P<rest>/.*)?$",
    re.IGNORECASE,
)

# Hashes
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_SHA512 = re.compile(r"^[a-fA-F0-9]{128}$")

# CVE, CWE, ASN, CIDR
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
RE_CWE = re.compile(r"^CWE-\d{1,5}$", re.IGNORECASE)
RE_ASN = re.compile(r"^AS\d{1,10}$", re.IGNORECASE)
RE_CIDR = re.compile(r"^.+/\d{1,3}$")

# YARA — very loose indication (we не парсим синтаксис целиком)
RE_YARA_HINT = re.compile(r"^\s*rule\s+[A-Za-z0-9_\-]{1,64}\s*[{]", re.IGNORECASE)

# STIX pattern: [ipv4-addr:value = '1.2.3.4'] etc. (simple extraction)
RE_STIX_SIMPLE = re.compile(
    r"^\s*\[(?P<obj>[a-z0-9\-]+):(?P<field>[a-z0-9\.\-]+)\s*=\s*'(?P<val>[^']{1,4096})'\s*\]\s*$",
    re.IGNORECASE,
)

# Known special-use TLDs to down-rank or reject
SPECIAL_TLDS = {"local", "localhost", "example", "invalid", "test"}

# ---------------------------------------------------------------------------
# Domain model
# ---------------------------------------------------------------------------

class IndicatorType(str):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    FQDN = "fqdn"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    CVE = "cve"
    CWE = "cwe"
    ASN = "asn"
    FILE_PATH = "file_path"
    REGISTRY = "registry"
    MUTEX = "mutex"
    YARA = "yara"
    UNKNOWN = "unknown"

class Severity(str):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

def _severity_from_any(x: Any, default: Severity = Severity.MEDIUM) -> Severity:
    if isinstance(x, str):
        s = x.strip().upper()
        if s in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}:
            return Severity(s)
        # numeric in string?
        if s.isdigit():
            try:
                v = int(s)
                return _severity_from_any(v, default)
            except Exception:
                pass
    if isinstance(x, (int, float)):
        v = float(x)
        if v >= 9:
            return Severity.CRITICAL
        if v >= 7:
            return Severity.HIGH
        if v >= 4:
            return Severity.MEDIUM
        if v > 0:
            return Severity.LOW
        return Severity.INFO
    return default

class NormalizedIndicator(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=_uuid7_str)
    type: str = Field(..., description="IndicatorType")
    value: str = Field(..., description="Canonical value")
    raw_value: Optional[str] = Field(default=None)
    severity: Severity = Field(default=Severity.MEDIUM)
    confidence: int = Field(default=60, ge=0, le=100)
    source: Optional[str] = Field(default=None)
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)
    sightings: int = Field(default=1, ge=1)
    tags: List[str] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"

class RejectedItem(BaseModel):
    raw: Any
    reason: str

class NormalizationStats(BaseModel):
    accepted: int
    rejected: int
    by_type: Dict[str, int] = Field(default_factory=dict)

class NormalizationBatchResult(BaseModel):
    accepted: List[NormalizedIndicator]
    rejected: List[RejectedItem]
    stats: NormalizationStats

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_indicator(s: str) -> str:
    v = _refang(s.strip())
    lv = v.lower()
    if RE_IPV4.match(lv):
        return IndicatorType.IPV4
    if RE_IPV6.match(lv):
        try:
            ipaddress.IPv6Address(lv)
            return IndicatorType.IPV6
        except Exception:
            pass
    if RE_CIDR.match(lv):
        try:
            ipaddress.ip_network(lv, strict=False)
            return IndicatorType.CIDR
        except Exception:
            pass
    if RE_URL.match(v):
        return IndicatorType.URL
    if RE_EMAIL.match(v):
        return IndicatorType.EMAIL
    if RE_CVE.match(lv):
        return IndicatorType.CVE
    if RE_CWE.match(lv):
        return IndicatorType.CWE
    if RE_MD5.match(lv):
        return IndicatorType.MD5
    if RE_SHA1.match(lv):
        return IndicatorType.SHA1
    if RE_SHA256.match(lv):
        return IndicatorType.SHA256
    if RE_SHA512.match(lv):
        return IndicatorType.SHA512
    if RE_ASN.match(lv):
        return IndicatorType.ASN
    if RE_YARA_HINT.search(v):
        return IndicatorType.YARA
    # Domain/FQDN
    d = v.strip(".")
    if RE_FQDN.match(d):
        return IndicatorType.FQDN
    if RE_DOMAIN.match(d):
        return IndicatorType.DOMAIN
    # Windows registry and file path hints
    if "\\" in v or v.startswith(("/", "~")):
        if v.upper().startswith(("HKLM\\", "HKEY_LOCAL_MACHINE\\", "HKCU\\", "HKEY_CURRENT_USER\\")):
            return IndicatorType.REGISTRY
        return IndicatorType.FILE_PATH
    if "Mutex" in v or v.startswith("Global\\") or v.startswith("Local\\"):
        return IndicatorType.MUTEX
    return IndicatorType.UNKNOWN

# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------

def _canonicalize_url(u: str) -> Tuple[str, Dict[str, Any]]:
    m = RE_URL.match(_refang(u))
    if not m:
        raise ValueError("invalid_url")
    scheme = m.group("scheme").lower()
    host = m.group("host").strip()
    rest = m.group("rest") or ""
    # Extract port if present in host
    port = None
    if host.startswith("["):  # IPv6 literal
        # [::1]:443
        if "]" in host:
            h, tail = host.split("]", 1)
            host_core = h.strip("[]")
            if tail.startswith(":"):
                port = tail[1:]
            host = host_core
    elif ":" in host:
        host, port = host.rsplit(":", 1)

    # Normalize host (IDNA for names, ipaddress for IPs)
    meta: Dict[str, Any] = {}
    try:
        ip_obj = ipaddress.ip_address(host)
        host_norm = ip_obj.compressed
        meta["host_ip"] = host_norm
        meta["host_is_private"] = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        host_norm = _idna_ascii(host)
        meta["host"] = host_norm
        # detect special tlds
        tld = host_norm.split(".")[-1] if "." in host_norm else host_norm
        meta["host_tld"] = tld

    # Normalize path/query
    path = rest
    frag_idx = path.find("#")
    if frag_idx >= 0:
        path = path[:frag_idx]
    q_idx = path.find("?")
    query = ""
    if q_idx >= 0:
        query = path[q_idx + 1 :]
        path = path[:q_idx]
    # collapse multiple slashes
    path = re.sub(r"/{2,}", "/", path) or "/"
    query = _normalize_query(query)
    # remove default ports
    if port:
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            port = None

    authority = host_norm if port is None else f"{host_norm}:{port}"
    value = f"{scheme}://{authority}{path}"
    if query:
        value = f"{value}?{query}"
    meta["scheme"] = scheme
    meta["port"] = int(port) if port and port.isdigit() else None
    meta["path"] = path
    if query:
        meta["query"] = query
    return value, meta

def _canonicalize_domain(d: str) -> Tuple[str, Dict[str, Any]]:
    d = _refang(d).strip().strip(".")
    d_ascii = _idna_ascii(d)
    # Classify as FQDN or DOMAIN based on dot depth
    labels = d_ascii.split(".")
    tld = labels[-1] if labels else ""
    meta = {"tld": tld, "label_count": len(labels)}
    return d_ascii.lower(), meta

def _canonicalize_ip(ip: str) -> Tuple[str, Dict[str, Any]]:
    ip = _refang(ip).strip()
    obj = ipaddress.ip_address(ip)
    return obj.compressed, {
        "version": obj.version,
        "is_private": obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved,
        "is_multicast": obj.is_multicast,
    }

def _canonicalize_cidr(cidr: str) -> Tuple[str, Dict[str, Any]]:
    net = ipaddress.ip_network(_refang(cidr).strip(), strict=False)
    return str(net), {"version": net.version, "num_addresses": net.num_addresses}

def _canonicalize_email(e: str) -> Tuple[str, Dict[str, Any]]:
    e = _refang(e).strip()
    local, domain = e.rsplit("@", 1)
    d_ascii = _idna_ascii(domain)
    return f"{local}@{d_ascii.lower()}", {"domain": d_ascii.lower(), "local": local}

def _canonicalize_hash(h: str) -> Tuple[str, Dict[str, Any]]:
    return _safe_lower(h.strip()) or "", {}

# ---------------------------------------------------------------------------
# STIX/MISP adapters (minimal)
# ---------------------------------------------------------------------------

def _from_stix_pattern(pattern: str) -> Optional[Tuple[str, str]]:
    """
    Supports simple patterns like:
      [ipv4-addr:value = '1.2.3.4']
      [domain-name:value = 'example.com']
      [url:value = 'http://ex.com/a']
      [file:hashes.'SHA-256' = '...']
    """
    m = RE_STIX_SIMPLE.match(pattern)
    if not m:
        return None
    obj = m.group("obj").lower()
    field = m.group("field").lower()
    val = m.group("val")
    if obj == "ipv4-addr" and field == "value":
        return IndicatorType.IPV4, val
    if obj == "ipv6-addr" and field == "value":
        return IndicatorType.IPV6, val
    if obj == "domain-name" and field == "value":
        # Could be DOMAIN/FQDN; let classifier decide
        t = classify_indicator(val)
        return (t, val)
    if obj == "url" and field == "value":
        return IndicatorType.URL, val
    if obj == "file" and field.startswith("hashes"):
        vlow = val.lower()
        if RE_SHA256.match(vlow):
            return IndicatorType.SHA256, vlow
        if RE_SHA1.match(vlow):
            return IndicatorType.SHA1, vlow
        if RE_MD5.match(vlow):
            return IndicatorType.MD5, vlow
    return None

def _from_misp_attribute(attr: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """
    Minimal mapping of common MISP attribute types.
    """
    t = (attr.get("type") or "").lower()
    v = str(attr.get("value") or "").strip()
    if not v:
        return None
    mapping = {
        "ip-src": IndicatorType.IPV4,
        "ip-dst": IndicatorType.IPV4,
        "domain": IndicatorType.DOMAIN,
        "hostname": IndicatorType.FQDN,
        "url": IndicatorType.URL,
        "md5": IndicatorType.MD5,
        "sha1": IndicatorType.SHA1,
        "sha256": IndicatorType.SHA256,
        "sha512": IndicatorType.SHA512,
        "email-src": IndicatorType.EMAIL,
        "email-dst": IndicatorType.EMAIL,
        "cve": IndicatorType.CVE,
        "asn": IndicatorType.ASN,
        "mutex": IndicatorType.MUTEX,
        "yara": IndicatorType.YARA,
    }
    itype = mapping.get(t)
    if itype:
        return itype, v
    # fallback to classifier
    return classify_indicator(v), v

# ---------------------------------------------------------------------------
# Dedup TTL cache
# ---------------------------------------------------------------------------

@dataclass
class _CacheEntry:
    ind: NormalizedIndicator
    ts: float

class _TTLCache:
    def __init__(self, ttl_seconds: int = 3600) -> None:
        self.ttl = ttl_seconds
        self._store: Dict[str, _CacheEntry] = {}

    def get(self, key: str) -> Optional[NormalizedIndicator]:
        e = self._store.get(key)
        if not e:
            return None
        if (time.time() - e.ts) > self.ttl:
            self._store.pop(key, None)
            return None
        return e.ind

    def put(self, ind: NormalizedIndicator) -> None:
        self._store[ind.key] = _CacheEntry(ind=ind, ts=time.time())

    def bump(self, key: str) -> Optional[NormalizedIndicator]:
        e = self._store.get(key)
        if not e:
            return None
        e.ts = time.time()
        e.ind.last_seen = _now()
        e.ind.sightings += 1
        return e.ind

# ---------------------------------------------------------------------------
# IntelNormalizer
# ---------------------------------------------------------------------------

class IntelNormalizer:
    """
    Универсальный нормализатор TI с поддержкой строк, STIX-паттернов, MISP-атрибутов и JSON объектов.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = 3600,
        reject_private_ips: bool = True,
        reject_special_tlds: bool = True,
        default_severity: Severity = Severity.MEDIUM,
        default_confidence: int = 60,
    ) -> None:
        self.cache = _TTLCache(ttl_seconds=ttl_seconds)
        self.reject_private_ips = reject_private_ips
        self.reject_special_tlds = reject_special_tlds
        self.default_severity = default_severity
        self.default_confidence = default_confidence

    # ------------- Public API -------------

    def normalize_batch(
        self,
        items: Iterable[Any],
        *,
        source: Optional[str] = None,
        default_tags: Optional[Sequence[str]] = None,
        severity: Optional[Any] = None,
        confidence: Optional[int] = None,
    ) -> NormalizationBatchResult:
        accepted: List[NormalizedIndicator] = []
        rejected: List[RejectedItem] = []
        counts: Dict[str, int] = {}

        for item in items:
            try:
                ind = self._normalize_one(
                    item,
                    source=source,
                    tags=list(default_tags) if default_tags else [],
                    severity=severity,
                    confidence=confidence,
                )
                if ind is None:
                    rejected.append(RejectedItem(raw=item, reason="unsupported_or_empty"))
                    continue
                # Dedup/TTL
                existing = self.cache.get(ind.key)
                if existing:
                    self.cache.bump(ind.key)
                    counts[existing.type] = counts.get(existing.type, 0) + 1
                    accepted.append(existing)
                else:
                    self.cache.put(ind)
                    counts[ind.type] = counts.get(ind.type, 0) + 1
                    accepted.append(ind)
            except ValueError as ve:
                rejected.append(RejectedItem(raw=item, reason=str(ve)))
            except Exception as e:
                logger.exception("normalize_failed")
                rejected.append(RejectedItem(raw=item, reason="internal_error"))

        stats = NormalizationStats(
            accepted=len(accepted), rejected=len(rejected), by_type=counts
        )
        return NormalizationBatchResult(accepted=accepted, rejected=rejected, stats=stats)

    # ------------- Internals -------------

    def _normalize_one(
        self,
        item: Any,
        *,
        source: Optional[str],
        tags: List[str],
        severity: Optional[Any],
        confidence: Optional[int],
    ) -> Optional[NormalizedIndicator]:
        raw_val: Optional[str] = None
        itype: Optional[str] = None
        value: Optional[str] = None
        meta: Dict[str, Any] = {}

        # STIX indicator dict
        if isinstance(item, dict) and "pattern" in item and isinstance(item.get("pattern"), str):
            pr = _from_stix_pattern(item["pattern"])
            if pr:
                itype, raw_val = pr
        # MISP attribute dict
        elif isinstance(item, dict) and ("type" in item and "value" in item):
            pr = _from_misp_attribute(item)
            if pr:
                itype, raw_val = pr
        # NormalizedIndicator passthrough
        elif isinstance(item, NormalizedIndicator):
            ind = item
            ind.last_seen = _now()
            ind.sightings += 1
            return ind
        # Plain string
        elif isinstance(item, str):
            raw_val = item
            itype = classify_indicator(item)
        # JSON object with explicit type/value
        elif isinstance(item, dict) and ("indicator" in item or "value" in item):
            raw_val = str(item.get("value") or item.get("indicator") or "")
            itype = str(item.get("type") or classify_indicator(raw_val))

        if not raw_val or not itype:
            return None

        # Canonicalize by type
        value, meta2 = self._canonicalize(itype, raw_val)
        meta.update(meta2)

        # Policy filters
        if itype in (IndicatorType.IPV4, IndicatorType.IPV6):
            if self.reject_private_ips and meta.get("is_private") is True:
                raise ValueError("private_or_special_ip")
        if itype in (IndicatorType.DOMAIN, IndicatorType.FQDN, IndicatorType.URL, IndicatorType.EMAIL):
            tld = meta.get("tld") or meta.get("host_tld")
            if self.reject_special_tlds and tld and tld.lower() in SPECIAL_TLDS:
                raise ValueError("special_use_tld")

        sev = _severity_from_any(severity, self.default_severity)
        conf = int(confidence if isinstance(confidence, int) else self.default_confidence)
        conf = max(0, min(100, conf))

        ind = NormalizedIndicator(
            type=itype,
            value=value,
            raw_value=str(raw_val)[:4096],
            severity=sev,
            confidence=conf,
            source=source,
            tags=tags,
            meta=meta,
        )
        return ind

    def _canonicalize(self, itype: str, raw: str) -> Tuple[str, Dict[str, Any]]:
        if itype == IndicatorType.IPV4:
            return _canonicalize_ip(raw)
        if itype == IndicatorType.IPV6:
            return _canonicalize_ip(raw)
        if itype == IndicatorType.CIDR:
            return _canonicalize_cidr(raw)
        if itype in (IndicatorType.DOMAIN, IndicatorType.FQDN):
            return _canonicalize_domain(raw)
        if itype == IndicatorType.URL:
            return _canonicalize_url(raw)
        if itype == IndicatorType.EMAIL:
            return _canonicalize_email(raw)
        if itype in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256, IndicatorType.SHA512):
            v, meta = _canonicalize_hash(raw)
            # strict length control
            if itype == IndicatorType.MD5 and not RE_MD5.match(v):
                raise ValueError("invalid_md5")
            if itype == IndicatorType.SHA1 and not RE_SHA1.match(v):
                raise ValueError("invalid_sha1")
            if itype == IndicatorType.SHA256 and not RE_SHA256.match(v):
                raise ValueError("invalid_sha256")
            if itype == IndicatorType.SHA512 and not RE_SHA512.match(v):
                raise ValueError("invalid_sha512")
            return v, meta
        if itype == IndicatorType.CVE:
            v = raw.upper().strip()
            if not RE_CVE.match(v):
                raise ValueError("invalid_cve")
            year = int(v.split("-")[1])
            return v, {"year": year}
        if itype == IndicatorType.CWE:
            v = raw.upper().strip()
            if not RE_CWE.match(v):
                raise ValueError("invalid_cwe")
            return v, {}
        if itype == IndicatorType.ASN:
            return raw.upper().strip(), {}
        if itype in (IndicatorType.FILE_PATH, IndicatorType.REGISTRY, IndicatorType.MUTEX, IndicatorType.YARA):
            # keep as-is, trimmed
            return raw.strip(), {}
        # Unknown — keep original but mark type
        return raw.strip(), {}

    # ------------- Export -------------

    @staticmethod
    def to_stix_indicator(ind: NormalizedIndicator) -> Dict[str, Any]:
        """
        Build minimal STIX 2.1 Indicator object (dict).
        """
        created = ind.first_seen.isoformat()
        modified = ind.last_seen.isoformat()
        pattern = _stix_pattern_from_indicator(ind)
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ind.id}",
            "created": created,
            "modified": modified,
            "pattern": pattern,
            "pattern_type": "stix",
            "confidence": int(ind.confidence),
            "labels": list(set([ind.type] + (ind.tags or []))),
            "name": f"{ind.type}:{ind.value}",
            "valid_from": created,
            "extensions": {
                "x_aethernova": {
                    "source": ind.source,
                    "severity": ind.severity,
                    "sightings": ind.sightings,
                    "meta": ind.meta,
                }
            },
        }

# ---------------------------------------------------------------------------
# STIX pattern builder (inverse of simple parser)
# ---------------------------------------------------------------------------

def _stix_pattern_from_indicator(ind: NormalizedIndicator) -> str:
    t = ind.type
    v = ind.value.replace("'", "\\'")
    if t == IndicatorType.IPV4:
        return f"[ipv4-addr:value = '{v}']"
    if t == IndicatorType.IPV6:
        return f"[ipv6-addr:value = '{v}']"
    if t in (IndicatorType.DOMAIN, IndicatorType.FQDN):
        return f"[domain-name:value = '{v}']"
    if t == IndicatorType.URL:
        return f"[url:value = '{v}']"
    if t == IndicatorType.EMAIL:
        return f"[email-addr:value = '{v}']"
    if t == IndicatorType.MD5:
        return f"[file:hashes.'MD5' = '{v}']"
    if t == IndicatorType.SHA1:
        return f"[file:hashes.'SHA-1' = '{v}']"
    if t == IndicatorType.SHA256:
        return f"[file:hashes.'SHA-256' = '{v}']"
    if t == IndicatorType.SHA512:
        return f"[file:hashes.'SHA-512' = '{v}']"
    if t == IndicatorType.CVE:
        return f"[vulnerability:name = '{v}']"
    # Fallback
    return f"[x-aethernova:type = '{t}' AND x-aethernova:value = '{v}']"

# ---------------------------------------------------------------------------
# Self-test (optional)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    n = IntelNormalizer(ttl_seconds=30)
    batch = [
        "hxxp://ex[.]ample.com/a?a=1&b=2",
        "1.2.3.4",
        "10.0.0.1",
        "EXAMPLE.COM",
        {"type": "sha256", "value": "A"*64},
        {"pattern": "[ipv4-addr:value = '8.8.8.8']"},
        {"type": "cve", "value": "CVE-2021-44228"},
        {"type": "email-dst", "value": "admin@[example].com"},
        {"type": "url", "value": "https://пример.рф/path"},
    ]
    res = n.normalize_batch(batch, source="selftest", default_tags=["test"])
    print("ACCEPTED:")
    for a in res.accepted:
        print(a.type, a.value, a.meta)
    print("REJECTED:")
    for r in res.rejected:
        print(r.reason, r.raw)
    if res.accepted:
        stix = IntelNormalizer.to_stix_indicator(res.accepted[0])
        print("STIX:", json.dumps(stix, ensure_ascii=False)[:200], "...")
