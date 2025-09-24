# File: oblivionvault-core/oblivionvault/requests/scope_resolver.py
"""
Industrial-grade scope resolver for oblivionvault-core.

Goals:
- Normalize request scope (tenant, subject, roles, scopes, regions, resource selectors)
- Multiple frontends: HTTP (Starlette/FastAPI), gRPC (grpc/grpc.aio), background tasks
- Deterministic precedence across sources (explicit > headers/metadata > token claims > defaults)
- Multi-tenant & data residency enforcement; legal-hold prechecks via pluggable hooks
- Produce OPA/Rego-compatible input for policy evaluation
- Lightweight: stdlib-only (optional imports for starlette/grpc)

This module does NOT fetch external state; it exposes hooks so callers can plug their own
LegalHold checks, tenant catalogs, role-to-scope maps, etc.
"""

from __future__ import annotations

import contextvars
import ipaddress
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# Optional imports (kept soft)
try:
    from starlette.requests import Request as StarletteRequest  # type: ignore
except Exception:  # pragma: no cover
    StarletteRequest = None  # type: ignore

try:
    import grpc  # type: ignore
except Exception:  # pragma: no cover
    grpc = None  # type: ignore


# =========================
# Exceptions
# =========================

class ScopeResolutionError(Exception):
    """Base error for scope resolution problems."""

class ResidencyViolation(ScopeResolutionError):
    """Raised when requested scope violates data residency/compliance constraints."""

class LegalHoldViolation(ScopeResolutionError):
    """Raised when requested resource is blocked by a legal hold."""

class InvalidIdentity(ScopeResolutionError):
    """Raised when identity information is malformed or missing in a strict context."""


# =========================
# Data classes
# =========================

@dataclass(frozen=True)
class Principal:
    sub: str = "anonymous"
    tenant: str = "global"
    issuer: str = ""
    roles: Tuple[str, ...] = field(default_factory=tuple)
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    via: str = "none"  # jwt|apikey|mtls|internal|none
    ip: str = ""       # caller IP if known
    extra: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class ResourceSelector:
    """
    Resource naming follows AIP-style: projects/{project}/tenants/{tenant}/<kind>/{id}
    Supports literal names and simple wildcard '*' suffix on the last segment.
    """
    names: Tuple[str, ...] = field(default_factory=tuple)
    resource_types: Tuple[str, ...] = field(default_factory=tuple)
    data_tags: Tuple[str, ...] = field(default_factory=tuple)
    include_new: bool = True  # include future objects matching selector

@dataclass(frozen=True)
class Compliance:
    region: str = "EU"                       # effective region (data residency)
    allowed_regions: Tuple[str, ...] = ("EU", "US", "APAC")
    jurisdiction: str = ""                   # optional jurisdiction code
    require_tls: bool = True
    pii_allowed: bool = True

@dataclass(frozen=True)
class RequestMeta:
    request_id: str = ""
    method: str = ""             # HTTP method or gRPC full method
    path: str = ""               # HTTP path or ""
    transport: str = ""          # http|grpc|task
    user_agent: str = ""
    traceparent: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Scope:
    principal: Principal
    tenant: str
    roles: Tuple[str, ...]
    scopes: Tuple[str, ...]
    compliance: Compliance
    selector: ResourceSelector
    environment: str = "prod"
    # Arbitrary custom labels for downstream systems
    labels: Mapping[str, str] = field(default_factory=dict)
    meta: RequestMeta = field(default_factory=RequestMeta)


# =========================
# Settings & hooks
# =========================

@dataclass
class ScopeResolverSettings:
    default_tenant: str = "global"
    default_environment: str = "prod"
    default_region: str = "EU"
    allowed_regions: Tuple[str, ...] = ("EU", "US", "APAC")
    precedence: Tuple[str, ...] = ("explicit", "header", "claims", "fallback")
    # Role -> scopes map (used to extend scopes if needed)
    role_scope_map: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    # Header and metadata names
    hdr_tenant: str = "x-tenant-id"
    hdr_roles: str = "x-roles"
    hdr_scopes: str = "x-scopes"
    hdr_env: str = "x-env"
    hdr_region: str = "x-region"
    hdr_request_id: str = "x-request-id"
    hdr_traceparent: str = "traceparent"
    # Compliance defaults
    require_tls: bool = True
    pii_allowed_default: bool = True
    # Strict identity enforcement
    strict_identity: bool = False

# Hooks (pluggable)
LegalHoldHook = Callable[[Scope], Optional[str]]           # return reason string to block, or None
ResidencyPolicyHook = Callable[[Scope], Optional[str]]     # return reason string to block, or None
PostProcessHook = Callable[[Scope], Scope]                 # mutate/augment scope before returning


# =========================
# Lightweight TTL cache
# =========================

class _TTLCache:
    def __init__(self, ttl_seconds: int = 30, maxsize: int = 4096):
        self._ttl = ttl_seconds
        self._maxsize = maxsize
        self._data: Dict[str, Tuple[float, Scope]] = {}
        self._lock = threading.Lock()

    def _prune(self) -> None:
        now = time.time()
        if len(self._data) > self._maxsize:
            # simple half prune
            items = sorted(self._data.items(), key=lambda kv: kv[1][0])
            for k, _ in items[: len(items) // 2]:
                self._data.pop(k, None)
        # remove expired
        for k in list(self._data.keys()):
            exp, _ = self._data[k]
            if exp <= now:
                self._data.pop(k, None)

    def get(self, key: str) -> Optional[Scope]:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            exp, scope = item
            if exp <= time.time():
                self._data.pop(key, None)
                return None
            return scope

    def set(self, key: str, scope: Scope) -> None:
        with self._lock:
            self._prune()
            self._data[key] = (time.time() + self._ttl, scope)


# Context vars for intra-process propagation (optional)
_current_scope: contextvars.ContextVar[Optional[Scope]] = contextvars.ContextVar("ov_scope", default=None)


# =========================
# Resolver
# =========================

class ScopeResolver:
    """
    Unified resolver producing a Scope from different frontends.
    """
    def __init__(
        self,
        settings: Optional[ScopeResolverSettings] = None,
        legal_hold_hook: Optional[LegalHoldHook] = None,
        residency_hook: Optional[ResidencyPolicyHook] = None,
        post_process_hook: Optional[PostProcessHook] = None,
        cache_ttl_seconds: int = 30,
    ):
        self.settings = settings or ScopeResolverSettings()
        self.legal_hold_hook = legal_hold_hook
        self.residency_hook = residency_hook
        self.post_process_hook = post_process_hook
        self._cache = _TTLCache(ttl_seconds=cache_ttl_seconds)

    # ---------- Public: HTTP ----------

    def from_http(self, req: "StarletteRequest", explicit: Optional[Dict[str, Any]] = None) -> Scope:
        if StarletteRequest is None:
            raise RuntimeError("Starlette is not available; install starlette/fastapi")
        hdr = _lower_headers(dict(req.headers))
        meta = self._build_meta_http(req, hdr)
        principal = self._build_principal_http(req, hdr)
        raw = {
            "tenant": hdr.get(self.settings.hdr_tenant),
            "roles": _split_csv(hdr.get(self.settings.hdr_roles)),
            "scopes": _split_csv(hdr.get(self.settings.hdr_scopes)),
            "environment": hdr.get(self.settings.hdr_env),
            "region": hdr.get(self.settings.hdr_region),
            "ip": _extract_ip(hdr, getattr(req, "client", None)),
        }
        return self._resolve(principal, raw, explicit or {}, transport="http", meta=meta)

    # ---------- Public: gRPC ----------

    def from_grpc(
        self,
        method_full_name: str,
        metadata: Sequence[Tuple[str, str]],
        principal: Optional[Principal] = None,
        explicit: Optional[Dict[str, Any]] = None,
    ) -> Scope:
        md = _lower_metadata(metadata)
        meta = self._build_meta_grpc(method_full_name, md)
        # Allow callers to pass principal from their interceptor; otherwise infer minimal
        pr = principal or self._build_principal_grpc(md)
        raw = {
            "tenant": md.get(self.settings.hdr_tenant),
            "roles": _split_csv(md.get(self.settings.hdr_roles)),
            "scopes": _split_csv(md.get(self.settings.hdr_scopes)),
            "environment": md.get(self.settings.hdr_env),
            "region": md.get(self.settings.hdr_region),
            "ip": md.get("x-real-ip") or md.get("x-forwarded-for", "").split(",")[0].strip(),
        }
        return self._resolve(pr, raw, explicit or {}, transport="grpc", meta=meta)

    # ---------- Public: internal/background ----------

    def from_internal(
        self,
        principal: Optional[Principal] = None,
        *,
        tenant: Optional[str] = None,
        roles: Optional[Sequence[str]] = None,
        scopes: Optional[Sequence[str]] = None,
        environment: Optional[str] = None,
        region: Optional[str] = None,
        selector: Optional[ResourceSelector] = None,
        labels: Optional[Mapping[str, str]] = None,
        meta: Optional[RequestMeta] = None,
    ) -> Scope:
        pr = principal or Principal(sub="system", tenant=tenant or self.settings.default_tenant, via="internal")
        raw = {
            "tenant": tenant,
            "roles": tuple(roles or ()),
            "scopes": tuple(scopes or ()),
            "environment": environment,
            "region": region,
        }
        return self._resolve(pr, raw, {"selector": selector, "labels": labels}, transport="task", meta=meta or RequestMeta(transport="task"))

    # ---------- Core resolution pipeline ----------

    def _resolve(
        self,
        principal: Principal,
        raw: Dict[str, Any],
        explicit: Dict[str, Any],
        *,
        transport: str,
        meta: RequestMeta,
    ) -> Scope:
        cache_key = self._cache_key(principal, raw, explicit, transport, meta)
        cached = self._cache.get(cache_key)
        if cached:
            _current_scope.set(cached)
            return cached

        # 1) Collect candidates by precedence
        tenant = self._choose("tenant", principal.tenant, raw, explicit)
        environment = self._choose("environment", self.settings.default_environment, raw, explicit)
        region = self._choose("region", self.settings.default_region, raw, explicit)

        # 2) Merge roles/scopes
        roles = _merge_unique(principal.roles, tuple(raw.get("roles") or ()), tuple(explicit.get("roles") or ()))
        scopes = _merge_unique(principal.scopes, tuple(raw.get("scopes") or ()), tuple(explicit.get("scopes") or ()))
        # Expand scopes from roles if configured
        scopes = _expand_scopes_with_roles(scopes, roles, self.settings.role_scope_map)

        # 3) Build principal with effective tenant and IP
        ip = raw.get("ip") or principal.ip
        eff_principal = Principal(
            sub=principal.sub or "anonymous",
            tenant=tenant or self.settings.default_tenant,
            issuer=principal.issuer,
            roles=roles,
            scopes=scopes,
            via=principal.via,
            ip=ip or "",
            extra=principal.extra,
        )

        # 4) Build compliance
        compliance = Compliance(
            region=region or self.settings.default_region,
            allowed_regions=self.settings.allowed_regions,
            jurisdiction=explicit.get("jurisdiction") or "",
            require_tls=self.settings.require_tls,
            pii_allowed=self.settings.pii_allowed_default if explicit.get("pii_allowed") is None else bool(explicit["pii_allowed"]),
        )

        # 5) Resource selector
        selector: ResourceSelector = explicit.get("selector") or _selector_from_explicit(explicit) or ResourceSelector()

        # 6) Labels
        labels: Mapping[str, str] = explicit.get("labels") or {}

        scope = Scope(
            principal=eff_principal,
            tenant=eff_principal.tenant,
            roles=eff_principal.roles,
            scopes=eff_principal.scopes,
            compliance=compliance,
            selector=selector,
            environment=environment or self.settings.default_environment,
            labels=labels,
            meta=meta,
        )

        # 7) Compliance checks
        # Data residency
        if self.residency_hook:
            reason = self.residency_hook(scope)
            if reason:
                raise ResidencyViolation(reason)
        else:
            if scope.compliance.region not in scope.compliance.allowed_regions:
                raise ResidencyViolation(f"Region '{scope.compliance.region}' is not allowed for tenant '{scope.tenant}'")

        # 8) Legal hold precheck (optional)
        if self.legal_hold_hook:
            reason = self.legal_hold_hook(scope)
            if reason:
                raise LegalHoldViolation(reason)

        # 9) Post process hook
        if self.post_process_hook:
            scope = self.post_process_hook(scope)

        # 10) Cache and set context
        self._cache.set(cache_key, scope)
        _current_scope.set(scope)
        return scope

    # ---------- Helpers ----------

    def _choose(self, field: str, fallback: Any, raw: Dict[str, Any], explicit: Dict[str, Any]) -> Any:
        """
        Deterministic precedence across: explicit > header/metadata(raw) > claims(principal.*) > fallback
        """
        for p in self.settings.precedence:
            if p == "explicit" and explicit.get(field) not in (None, "", ()):
                return explicit[field]
            if p == "header" and raw.get(field) not in (None, "", ()):
                return raw[field]
            if p == "claims":
                # handled earlier by passing principal.* as default arg to this method
                pass
            if p == "fallback":
                return fallback
        return fallback

    def _build_meta_http(self, req: "StarletteRequest", hdr: Mapping[str, str]) -> RequestMeta:
        rid = hdr.get(self.settings.hdr_request_id, "")
        ua = hdr.get("user-agent", "")
        tp = hdr.get(self.settings.hdr_traceparent, "")
        path = req.url.path
        method = getattr(req, "method", "")
        return RequestMeta(
            request_id=rid,
            method=method,
            path=path,
            transport="http",
            user_agent=ua,
            traceparent=tp,
            attributes={},
        )

    def _build_principal_http(self, req: "StarletteRequest", hdr: Mapping[str, str]) -> Principal:
        # Minimal identity from headers; if your stack sets richer info, pass in via explicit/principal
        sub = hdr.get("x-user-id") or "anonymous"
        tenant = hdr.get(self.settings.hdr_tenant) or self.settings.default_tenant
        roles = tuple(_split_csv(hdr.get(self.settings.hdr_roles)))
        scopes = tuple(_split_csv(hdr.get(self.settings.hdr_scopes)))
        ip = _extract_ip(hdr, getattr(req, "client", None))
        via = "none"
        if hdr.get("authorization", "").startswith("bearer "):
            via = "jwt"
        return Principal(sub=sub, tenant=tenant, roles=roles, scopes=scopes, via=via, ip=ip)

    def _build_meta_grpc(self, method: str, md: Mapping[str, str]) -> RequestMeta:
        rid = md.get(self.settings.hdr_request_id, "")
        tp = md.get(self.settings.hdr_traceparent, "")
        ua = md.get("user-agent", "")
        return RequestMeta(
            request_id=rid,
            method=method,
            path="",
            transport="grpc",
            user_agent=ua,
            traceparent=tp,
            attributes={},
        )

    def _build_principal_grpc(self, md: Mapping[str, str]) -> Principal:
        sub = md.get("x-user-id") or "anonymous"
        tenant = md.get(self.settings.hdr_tenant) or self.settings.default_tenant
        roles = tuple(_split_csv(md.get(self.settings.hdr_roles)))
        scopes = tuple(_split_csv(md.get(self.settings.hdr_scopes)))
        via = "none"
        if (md.get("authorization") or "").lower().startswith("bearer "):
            via = "jwt"
        ip = md.get("x-real-ip") or md.get("x-forwarded-for", "").split(",")[0].strip()
        return Principal(sub=sub, tenant=tenant, roles=roles, scopes=scopes, via=via, ip=ip)

    def _cache_key(self, principal: Principal, raw: Dict[str, Any], explicit: Dict[str, Any], transport: str, meta: RequestMeta) -> str:
        key = {
            "p": {
                "sub": principal.sub,
                "t": principal.tenant,
                "r": principal.roles,
                "s": principal.scopes,
                "v": principal.via,
                "ip": principal.ip,
            },
            "raw": raw,
            "ex": _normalize_explicit(explicit),
            "tr": transport,
            "m": {
                "method": meta.method,
                "path": meta.path,
                "rid": meta.request_id,
            },
        }
        return json.dumps(key, sort_keys=True, default=str)


# =========================
# OPA/Rego input conversion
# =========================

def to_opa_input(scope: Scope, *, resource: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """
    Convert Scope to OPA/Rego input model.
    Matches the structure used in erasure_eligibility.rego and similar policies.
    """
    input_doc: Dict[str, Any] = {
        "subject": {
            "id": scope.principal.sub,
            "roles": list(scope.roles),
            "tenant": scope.tenant,
        },
        "resource": resource or {
            "type": (scope.selector.resource_types[0] if scope.selector.resource_types else ""),
            "id": "",  # fill by caller
            "dataTags": list(scope.selector.data_tags),
        },
        "request": {
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": "",  # fill by caller
            "method": scope.meta.method,
            "transport": scope.meta.transport,
        },
        "flags": {
            "gdpr": scope.compliance.region == "EU",
            "ccpa": scope.compliance.region in ("US", "US-CA"),
        },
        "legal": {
            "investigation_hold": False,  # fill by caller or via policy engine
            "retention_period_days": 0,   # fill by caller
        },
        "security": {
            "risk_level": "low",          # fill by caller
            "pending_alerts": False,
        },
        "consent": {
            "withdrawn": False,           # fill by caller
            "timestamp": "",              # fill by caller
        },
        "env": {
            "environment": scope.environment,
            "region": scope.compliance.region,
            "jurisdiction": scope.compliance.jurisdiction,
        }
    }
    return input_doc


# =========================
# Utilities
# =========================

def get_current_scope() -> Optional[Scope]:
    """Fetch scope from context var if set by resolver in the current task/thread."""
    return _current_scope.get()

def _lower_headers(h: Mapping[str, str]) -> Dict[str, str]:
    return {k.lower(): v for k, v in h.items()}

def _lower_metadata(md: Sequence[Tuple[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in md or []:
        out[k.lower()] = v
    return out

def _split_csv(s: Optional[str]) -> Tuple[str, ...]:
    if not s:
        return tuple()
    parts = [p.strip() for p in s.split(",")]
    return tuple(p for p in parts if p)

def _merge_unique(*seqs: Sequence[str]) -> Tuple[str, ...]:
    seen = set()
    out: List[str] = []
    for seq in seqs:
        for x in seq or ():
            if x not in seen:
                out.append(x)
                seen.add(x)
    return tuple(out)

def _expand_scopes_with_roles(scopes: Tuple[str, ...], roles: Tuple[str, ...], role_scope_map: Mapping[str, Tuple[str, ...]]) -> Tuple[str, ...]:
    extra: List[str] = []
    for r in roles:
        for s in role_scope_map.get(r, ()):
            if s not in scopes and s not in extra:
                extra.append(s)
    if not extra:
        return scopes
    return tuple(scopes) + tuple(extra)

def _extract_ip(hdr: Mapping[str, str], client: Any) -> str:
    xfwd = hdr.get("x-forwarded-for", "")
    ip = (xfwd.split(",")[0].strip() if xfwd else "") or hdr.get("x-real-ip") or getattr(client, "host", "") or ""
    try:
        if ip:
            ipaddress.ip_address(ip)
    except Exception:
        ip = ""
    return ip

def _selector_from_explicit(explicit: Mapping[str, Any]) -> Optional[ResourceSelector]:
    names = tuple(explicit.get("names") or ())
    rtypes = tuple(explicit.get("resource_types") or ())
    tags = tuple(explicit.get("data_tags") or ())
    include_new = explicit.get("include_new", True)
    if names or rtypes or tags:
        return ResourceSelector(names=names, resource_types=rtypes, data_tags=tags, include_new=include_new)
    return None

def _normalize_explicit(explicit: Mapping[str, Any]) -> Mapping[str, Any]:
    if not explicit:
        return {}
    norm = dict(explicit)
    if "selector" in norm and isinstance(norm["selector"], ResourceSelector):
        sel: ResourceSelector = norm["selector"]
        norm["selector"] = {
            "names": sel.names,
            "resource_types": sel.resource_types,
            "data_tags": sel.data_tags,
            "include_new": sel.include_new,
        }
    return norm


__all__ = [
    "ScopeResolverSettings",
    "ScopeResolver",
    "Scope",
    "Principal",
    "ResourceSelector",
    "Compliance",
    "RequestMeta",
    "ScopeResolutionError",
    "ResidencyViolation",
    "LegalHoldViolation",
    "InvalidIdentity",
    "to_opa_input",
    "get_current_scope",
]
