# human-sovereignty-core/webui/server/auth/identity.py
from __future__ import annotations

import dataclasses
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

from starlette.requests import Request

__all__ = [
    "IdentityError",
    "IdentityValidationError",
    "IdentityNotAuthenticated",
    "IdentityNotAuthorized",
    "MtlsEvidence",
    "DeviceIdentity",
    "Principal",
    "IdentityConfig",
    "IdentityStore",
    "InMemoryIdentityStore",
    "IdentityResolver",
]


class IdentityError(Exception):
    """Base error for identity resolution."""


class IdentityValidationError(IdentityError):
    """Raised when identity evidence is malformed or violates policy."""


class IdentityNotAuthenticated(IdentityError):
    """Raised when identity cannot be established."""


class IdentityNotAuthorized(IdentityError):
    """Raised when identity is established but not allowed."""


class EvidenceSource(str, Enum):
    MTLS = "mtls"


_SPIFFE_RE = re.compile(r"^spiffe://[a-zA-Z0-9.\-]+(/[a-zA-Z0-9._\-/]+)*$")

# Common proxies:
# - Envoy/Nginx: X-Forwarded-Client-Cert (XFCC)
# - Nginx ssl vars forwarded as headers: X-SSL-Client-Verify, X-SSL-Client-S-DN, X-SSL-Client-Fingerprint
#
# Important: this module does NOT cryptographically validate the client cert itself.
# It assumes TLS termination and certificate verification are performed at a trusted proxy boundary.
# Therefore we validate:
# - request came from trusted proxy (optional allowlist)
# - proxy asserted "SUCCESS" verification
# - fingerprint is present (pinning can be enforced)
# - subject / spiffe id is present and maps to known principal
#
# If any of those checks fail, we fail closed.


@dataclass(frozen=True, slots=True)
class IdentityConfig:
    # Trust boundary
    trusted_proxy_enabled: bool = True
    trusted_proxy_ip_allowlist: Tuple[str, ...] = ("127.0.0.1", "::1")

    # Evidence headers
    header_client_verify: str = "X-SSL-Client-Verify"          # "SUCCESS"
    header_client_subject_dn: str = "X-SSL-Client-S-DN"        # "/CN=.../O=..."
    header_client_fingerprint_sha256: str = "X-SSL-Client-Fingerprint"  # "SHA256=AA:BB..." or "AA:BB..."
    header_xfcc: str = "X-Forwarded-Client-Cert"               # Envoy XFCC

    # Acceptable proof requirements
    require_verify_success: bool = True
    require_fingerprint: bool = True
    require_subject_or_spiffe: bool = True

    # Pinning / mapping policy
    enforce_fingerprint_pinning: bool = True
    allow_subject_dn_mapping: bool = True
    allow_spiffe_mapping: bool = True

    # Limits to prevent header abuse
    max_header_bytes: int = 8192
    max_subject_len: int = 2048
    max_spiffe_len: int = 512

    # Caching
    cache_ttl_seconds: int = 30
    cache_max_entries: int = 5000

    # Optional: treat any unknown principal as hard failure (recommended)
    fail_closed_unknown_principal: bool = True

    @staticmethod
    def from_env() -> "IdentityConfig":
        def b(name: str, default: bool) -> bool:
            v = os.getenv(name)
            if v is None:
                return default
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
            raise ValueError(f"Invalid bool env var {name}: {v!r}")

        def i(name: str, default: int, min_v: int, max_v: int) -> int:
            v = os.getenv(name)
            if v is None:
                return default
            n = int(v.strip())
            if n < min_v or n > max_v:
                raise ValueError(f"Env var {name} out of range: {n}")
            return n

        def csv(name: str, default: str) -> Tuple[str, ...]:
            v = os.getenv(name, default)
            items = [x.strip() for x in v.split(",") if x.strip()]
            return tuple(items)

        return IdentityConfig(
            trusted_proxy_enabled=b("HSC_WEBUI_ID_TRUSTED_PROXY_ENABLED", True),
            trusted_proxy_ip_allowlist=csv("HSC_WEBUI_ID_TRUSTED_PROXY_IPS", "127.0.0.1,::1"),
            header_client_verify=os.getenv("HSC_WEBUI_ID_HDR_VERIFY", "X-SSL-Client-Verify"),
            header_client_subject_dn=os.getenv("HSC_WEBUI_ID_HDR_SUBJECT_DN", "X-SSL-Client-S-DN"),
            header_client_fingerprint_sha256=os.getenv("HSC_WEBUI_ID_HDR_FP", "X-SSL-Client-Fingerprint"),
            header_xfcc=os.getenv("HSC_WEBUI_ID_HDR_XFCC", "X-Forwarded-Client-Cert"),
            require_verify_success=b("HSC_WEBUI_ID_REQUIRE_VERIFY_SUCCESS", True),
            require_fingerprint=b("HSC_WEBUI_ID_REQUIRE_FINGERPRINT", True),
            require_subject_or_spiffe=b("HSC_WEBUI_ID_REQUIRE_SUBJECT_OR_SPIFFE", True),
            enforce_fingerprint_pinning=b("HSC_WEBUI_ID_ENFORCE_PINNING", True),
            allow_subject_dn_mapping=b("HSC_WEBUI_ID_ALLOW_SUBJECT_DN", True),
            allow_spiffe_mapping=b("HSC_WEBUI_ID_ALLOW_SPIFFE", True),
            max_header_bytes=i("HSC_WEBUI_ID_MAX_HEADER_BYTES", 8192, 256, 1_000_000),
            max_subject_len=i("HSC_WEBUI_ID_MAX_SUBJECT_LEN", 2048, 64, 50_000),
            max_spiffe_len=i("HSC_WEBUI_ID_MAX_SPIFFE_LEN", 512, 32, 10_000),
            cache_ttl_seconds=i("HSC_WEBUI_ID_CACHE_TTL", 30, 0, 3600),
            cache_max_entries=i("HSC_WEBUI_ID_CACHE_MAX", 5000, 100, 1_000_000),
            fail_closed_unknown_principal=b("HSC_WEBUI_ID_FAIL_CLOSED_UNKNOWN", True),
        )


@dataclass(frozen=True, slots=True)
class MtlsEvidence:
    source: EvidenceSource
    verified: bool
    subject_dn: Optional[str]
    spiffe_id: Optional[str]
    fingerprint_sha256: Optional[str]
    raw: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    device_id: str
    fingerprint_sha256: str
    subject_dn: Optional[str] = None
    spiffe_id: Optional[str] = None


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    display_name: str
    tenant_id: str
    roles: Tuple[str, ...]
    device: DeviceIdentity
    evidence: MtlsEvidence

    def as_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "display_name": self.display_name,
            "tenant_id": self.tenant_id,
            "roles": list(self.roles),
            "device": dataclasses.asdict(self.device),
            "evidence": dataclasses.asdict(self.evidence),
        }


class IdentityStore(Protocol):
    async def resolve_by_fingerprint(self, fingerprint_sha256: str) -> Optional[Mapping[str, Any]]: ...
    async def resolve_by_subject_dn(self, subject_dn: str) -> Optional[Mapping[str, Any]]: ...
    async def resolve_by_spiffe_id(self, spiffe_id: str) -> Optional[Mapping[str, Any]]: ...


class InMemoryIdentityStore:
    """
    Простая реализация для dev/test.
    В prod сюда подключается storage из identity-access-core.
    """

    __slots__ = ("_by_fp", "_by_dn", "_by_spiffe")

    def __init__(self) -> None:
        self._by_fp: Dict[str, Mapping[str, Any]] = {}
        self._by_dn: Dict[str, Mapping[str, Any]] = {}
        self._by_spiffe: Dict[str, Mapping[str, Any]] = {}

    def put(
        self,
        *,
        fingerprint_sha256: str,
        principal_id: str,
        display_name: str,
        tenant_id: str,
        roles: Tuple[str, ...],
        subject_dn: Optional[str] = None,
        spiffe_id: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> None:
        rec: Dict[str, Any] = {
            "principal_id": principal_id,
            "display_name": display_name,
            "tenant_id": tenant_id,
            "roles": tuple(roles),
            "fingerprint_sha256": fingerprint_sha256,
            "subject_dn": subject_dn,
            "spiffe_id": spiffe_id,
            "device_id": device_id or fingerprint_sha256[:16],
        }
        self._by_fp[fingerprint_sha256] = rec
        if subject_dn:
            self._by_dn[subject_dn] = rec
        if spiffe_id:
            self._by_spiffe[spiffe_id] = rec

    async def resolve_by_fingerprint(self, fingerprint_sha256: str) -> Optional[Mapping[str, Any]]:
        return self._by_fp.get(fingerprint_sha256)

    async def resolve_by_subject_dn(self, subject_dn: str) -> Optional[Mapping[str, Any]]:
        return self._by_dn.get(subject_dn)

    async def resolve_by_spiffe_id(self, spiffe_id: str) -> Optional[Mapping[str, Any]]:
        return self._by_spiffe.get(spiffe_id)


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    expires_unix: int
    principal: Principal


class IdentityResolver:
    __slots__ = ("_cfg", "_store", "_cache")

    def __init__(self, *, cfg: Optional[IdentityConfig] = None, store: IdentityStore) -> None:
        self._cfg = cfg or IdentityConfig.from_env()
        self._store = store
        self._cache: Dict[str, _CacheEntry] = {}

    async def resolve(self, request: Request) -> Principal:
        self._enforce_trusted_proxy(request)

        evidence = self._extract_mtls_evidence(request)

        if self._cfg.require_verify_success and not evidence.verified:
            raise IdentityNotAuthenticated("mtls_not_verified")

        if self._cfg.require_fingerprint and not evidence.fingerprint_sha256:
            raise IdentityNotAuthenticated("missing_fingerprint")

        if self._cfg.require_subject_or_spiffe and not (evidence.subject_dn or evidence.spiffe_id):
            raise IdentityNotAuthenticated("missing_subject_or_spiffe")

        fp = evidence.fingerprint_sha256 or ""
        cache_key = fp if fp else (evidence.spiffe_id or evidence.subject_dn or "")
        cache_key = f"mtls:{cache_key}"

        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        rec = None

        # Primary: fingerprint pinning
        if fp:
            rec = await self._store.resolve_by_fingerprint(fp)

        # Secondary: spiffe mapping
        if rec is None and evidence.spiffe_id and self._cfg.allow_spiffe_mapping:
            rec = await self._store.resolve_by_spiffe_id(evidence.spiffe_id)

        # Tertiary: subject DN mapping
        if rec is None and evidence.subject_dn and self._cfg.allow_subject_dn_mapping:
            rec = await self._store.resolve_by_subject_dn(evidence.subject_dn)

        if rec is None:
            if self._cfg.fail_closed_unknown_principal:
                raise IdentityNotAuthenticated("unknown_principal")
            raise IdentityNotAuthorized("unknown_principal")

        # Enforce pinning if enabled
        if self._cfg.enforce_fingerprint_pinning:
            if not fp:
                raise IdentityNotAuthenticated("pinning_requires_fingerprint")
            stored_fp = str(rec.get("fingerprint_sha256") or "")
            if not stored_fp or stored_fp != fp:
                raise IdentityNotAuthenticated("fingerprint_pinning_mismatch")

        principal = self._build_principal(evidence, rec)
        self._cache_put(cache_key, principal)
        return principal

    def _enforce_trusted_proxy(self, request: Request) -> None:
        if not self._cfg.trusted_proxy_enabled:
            return

        client = request.client
        if client is None or not client.host:
            raise IdentityValidationError("missing_client_ip")

        if client.host not in self._cfg.trusted_proxy_ip_allowlist:
            raise IdentityNotAuthenticated("untrusted_proxy_source")

    def _extract_mtls_evidence(self, request: Request) -> MtlsEvidence:
        # Apply strict header size limits
        headers = request.headers
        raw: Dict[str, str] = {}

        def get_limited(name: str) -> Optional[str]:
            v = headers.get(name)
            if v is None:
                return None
            # hard limit by bytes
            if len(v.encode("utf-8", errors="strict")) > self._cfg.max_header_bytes:
                raise IdentityValidationError(f"header_too_large:{name}")
            raw[name] = v
            return v

        verify = get_limited(self._cfg.header_client_verify)
        subject_dn = get_limited(self._cfg.header_client_subject_dn)
        fingerprint = get_limited(self._cfg.header_client_fingerprint_sha256)
        xfcc = get_limited(self._cfg.header_xfcc)

        verified = False
        if verify is not None:
            verified = verify.strip().upper() == "SUCCESS"

        # Normalize subject DN
        norm_subject = self._normalize_subject_dn(subject_dn) if subject_dn else None

        # Extract SPIFFE from XFCC if present
        spiffe_id = self._extract_spiffe_from_xfcc(xfcc) if xfcc else None
        if spiffe_id is not None:
            spiffe_id = self._normalize_spiffe_id(spiffe_id)

        # Normalize fingerprint
        fp = self._normalize_fingerprint_sha256(fingerprint) if fingerprint else None

        return MtlsEvidence(
            source=EvidenceSource.MTLS,
            verified=verified,
            subject_dn=norm_subject,
            spiffe_id=spiffe_id,
            fingerprint_sha256=fp,
            raw=raw,
        )

    def _normalize_subject_dn(self, dn: str) -> str:
        s = dn.strip()
        if len(s) > self._cfg.max_subject_len:
            raise IdentityValidationError("subject_dn_too_long")
        # Accept two popular formats:
        # 1) OpenSSL style: "/CN=foo/O=bar/OU=baz"
        # 2) RFC 2253-ish: "CN=foo,O=bar,OU=baz"
        # Normalize to RFC2253-like with comma.
        if s.startswith("/"):
            parts = [p for p in s.split("/") if p]
            kv = []
            for p in parts:
                if "=" not in p:
                    continue
                k, v = p.split("=", 1)
                kv.append(f"{k.strip()}={v.strip()}")
            s = ",".join(kv)
        # Collapse spaces around commas
        s = re.sub(r"\s*,\s*", ",", s)
        return s

    def _normalize_spiffe_id(self, spiffe: str) -> str:
        s = spiffe.strip()
        if len(s) > self._cfg.max_spiffe_len:
            raise IdentityValidationError("spiffe_too_long")
        if not _SPIFFE_RE.match(s):
            raise IdentityValidationError("invalid_spiffe_id")
        return s

    def _normalize_fingerprint_sha256(self, fp: str) -> str:
        s = fp.strip()
        # Accept "SHA256=AA:BB:.." or "AA:BB:.." or hex without colons
        if s.upper().startswith("SHA256="):
            s = s.split("=", 1)[1].strip()
        s = s.replace(":", "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", s or ""):
            raise IdentityValidationError("invalid_fingerprint_sha256")
        return s

    def _extract_spiffe_from_xfcc(self, xfcc: str) -> Optional[str]:
        # Envoy XFCC sample segments:
        # By=spiffe://cluster/ns/default/sa/foo;Hash=...;Subject="...";URI=spiffe://trust.domain/ns/..;DNS=...
        # We prefer URI=spiffe://...
        m = re.search(r"(?:^|;)\s*URI\s*=\s*([^;]+)", xfcc)
        if m:
            v = m.group(1).strip()
            v = v.strip('"').strip()
            if v:
                return v
        return None

    def _build_principal(self, evidence: MtlsEvidence, rec: Mapping[str, Any]) -> Principal:
        fp = evidence.fingerprint_sha256
        if not fp:
            # If pinning is off and fp absent, still require device id from store
            fp = str(rec.get("fingerprint_sha256") or "")
        if not fp:
            raise IdentityNotAuthenticated("missing_fingerprint_effective")

        device_id = str(rec.get("device_id") or fp[:16])

        device = DeviceIdentity(
            device_id=device_id,
            fingerprint_sha256=fp,
            subject_dn=evidence.subject_dn,
            spiffe_id=evidence.spiffe_id,
        )

        roles_raw = rec.get("roles") or ()
        if isinstance(roles_raw, (list, tuple)):
            roles = tuple(str(x) for x in roles_raw)
        else:
            roles = (str(roles_raw),) if roles_raw else tuple()

        principal_id = str(rec.get("principal_id") or "").strip()
        display_name = str(rec.get("display_name") or principal_id).strip()
        tenant_id = str(rec.get("tenant_id") or "default").strip()

        if not principal_id:
            raise IdentityValidationError("store_record_missing_principal_id")

        return Principal(
            principal_id=principal_id,
            display_name=display_name,
            tenant_id=tenant_id,
            roles=roles,
            device=device,
            evidence=evidence,
        )

    def _cache_get(self, key: str) -> Optional[Principal]:
        if self._cfg.cache_ttl_seconds <= 0:
            return None
        e = self._cache.get(key)
        if e is None:
            return None
        if int(time.time()) >= e.expires_unix:
            self._cache.pop(key, None)
            return None
        return e.principal

    def _cache_put(self, key: str, principal: Principal) -> None:
        if self._cfg.cache_ttl_seconds <= 0:
            return
        if len(self._cache) >= self._cfg.cache_max_entries:
            # простая эвикция: удалить один произвольный элемент (детерминизм здесь не критичен)
            self._cache.pop(next(iter(self._cache.keys())), None)
        self._cache[key] = _CacheEntry(expires_unix=int(time.time()) + self._cfg.cache_ttl_seconds, principal=principal)
