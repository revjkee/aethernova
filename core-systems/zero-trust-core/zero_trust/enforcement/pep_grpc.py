# zero-trust-core/zero_trust/enforcement/pep_grpc.py
# Industrial-grade gRPC Policy Enforcement Point (PEP) for Zero Trust.
# - Works with grpc.aio and sync grpc servers (two interceptors)
# - Extracts context (tenant/user/resource/session/network/mTLS best-effort)
# - Queries PDP (HTTP JSON or in-process callable) with timeouts
# - Caches decisions by composite key with TTL (LRU)
# - Enforces ALLOW / STEP_UP / DENY; returns PERMISSION_DENIED on step_up/deny with hints
# - For streaming RPCs: periodic re-evaluation; cancels stream if decision changes to deny
# - Failure modes: deny (default) or allow_with_alert
# - Optional OpenTelemetry span enrichment if opentelemetry available (no hard dependency)
# Stdlib only.

from __future__ import annotations

import asyncio
import base64
import json
import logging
import ssl
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple, Union
from urllib import request as _urlreq
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin

try:
    import grpc  # type: ignore
except Exception as _e:  # pragma: no cover
    raise RuntimeError("grpc package is required for PEP") from _e

# Optional OpenTelemetry (no hard dependency)
try:  # pragma: no cover
    from opentelemetry import trace as _otel_trace  # type: ignore
    _OTEL = True
except Exception:
    _OTEL = False

logger = logging.getLogger(__name__)

DecisionDict = Dict[str, Any]

# ---------------------------
# Config / Failure modes
# ---------------------------

@dataclass
class PEPConfig:
    # PDP HTTP endpoint base (JSON API). If None, use callable.
    pdp_http_base: Optional[str] = None
    # PDP callable: async def(ctx: dict) -> decision dict (same schema as HTTP response)
    pdp_callable: Optional[Callable[[Dict[str, Any]], Any]] = None
    # PDP request path for HTTP POST
    pdp_http_path: str = "/v1/evaluate"
    # PDP timeouts
    pdp_timeout_s: float = 1.5
    # Cache
    cache_max_entries: int = 50_000
    # Failure mode when PDP unavailable or malformed response: "deny" or "allow_with_alert"
    failure_mode: str = "deny"
    # Enforce mTLS presence for resources with sensitivity=high
    require_mtls_for_high: bool = True
    # Re-evaluation for streaming: seconds; if 0 -> disabled; if decision has ttl, use min(ttl, reevaluate_every_s)
    reevaluate_every_s: float = 60.0
    # Extract tenant/user/resource keys from metadata
    tenant_keys: Tuple[str, ...] = ("tenant", "x-tenant", "x-org", "x-ztc-tenant")
    user_keys: Tuple[str, ...] = ("user", "x-user", "x-sub", "x-user-id")
    resource_keys: Tuple[str, ...] = ("resource", "x-resource", "x-scope", "x-service")
    session_keys: Tuple[str, ...] = ("session", "x-session", "x-session-id")
    # Label to signal continuous verification desired
    continuous_key: str = "x-ztc-continuous"
    # Whether to include request metadata into PDP request (whitelisted)
    include_metadata_keys: Tuple[str, ...] = ("x-request-id", "x-correlation-id")
    # Whether to return MFA hints in trailers on step_up
    expose_stepup_hints: bool = True

# ---------------------------
# LRU TTL Cache
# ---------------------------

class _TTLCache:
    def __init__(self, max_entries: int = 10000):
        self.max = max_entries
        self.lock = threading.RLock()
        self.store: OrderedDict[str, Tuple[float, DecisionDict, float]] = OrderedDict()
        # key -> (expires_at, decision, cached_at)

    def _evict(self) -> None:
        while len(self.store) > self.max:
            self.store.popitem(last=False)

    def get(self, key: str) -> Optional[DecisionDict]:
        now = time.time()
        with self.lock:
            item = self.store.get(key)
            if not item:
                return None
            expires_at, decision, _ = item
            if now >= expires_at:
                try:
                    del self.store[key]
                except KeyError:
                    pass
                return None
            # move to end (recent)
            self.store.move_to_end(key, last=True)
            return decision

    def put(self, key: str, decision: DecisionDict, ttl_s: float) -> None:
        now = time.time()
        exp = now + max(1.0, ttl_s)
        with self.lock:
            self.store[key] = (exp, decision, now)
            self.store.move_to_end(key, last=True)
            self._evict()

# ---------------------------
# PDP clients
# ---------------------------

def _otel_exemplar_attrs() -> Dict[str, str]:
    if not _OTEL:
        return {}
    try:
        span = _otel_trace.get_current_span()
        sc = span.get_span_context()
        if not sc.is_valid:
            return {}
        return {"trace_id": f"{sc.trace_id:032x}"}
    except Exception:
        return {}

class _HTTPPDP:
    def __init__(self, base_url: str, path: str, timeout_s: float):
        self.base = base_url.rstrip("/")
        self.path = path
        self.timeout_s = timeout_s

    async def evaluate(self, payload: Dict[str, Any]) -> DecisionDict:
        url = urljoin(self.base + "/", self.path.lstrip("/"))
        data = json.dumps(payload).encode("utf-8")
        req = _urlreq.Request(url, data=data, method="POST",
                              headers={"content-type": "application/json"})
        loop = asyncio.get_running_loop()

        def _do():
            try:
                with _urlreq.urlopen(req, timeout=self.timeout_s) as resp:
                    code = resp.getcode()
                    body = resp.read().decode("utf-8", "replace")
                    if code >= 400:
                        raise RuntimeError(f"PDP HTTP {code}")
                    return json.loads(body)
            except HTTPError as e:
                raise RuntimeError(f"PDP HTTP {e.code}") from e
            except URLError as e:
                raise RuntimeError(f"PDP HTTP URLError: {e.reason}") from e
        return await loop.run_in_executor(None, _do)

class _CallablePDP:
    def __init__(self, func: Callable[[Dict[str, Any]], Any]):
        self.func = func

    async def evaluate(self, payload: Dict[str, Any]) -> DecisionDict:
        if asyncio.iscoroutinefunction(self.func):
            return await self.func(payload)  # type: ignore[arg-type]
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.func, payload)

# ---------------------------
# Context extraction helpers
# ---------------------------

def _md_to_dict(md: Optional[Iterable[Tuple[str, str]]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not md:
        return out
    for k, v in md:
        try:
            out[k.lower()] = v
        except Exception:
            continue
    return out

def _first(meta: Mapping[str, str], keys: Tuple[str, ...], default: str = "unknown", clamp: int = 128) -> str:
    for k in keys:
        v = meta.get(k.lower())
        if v:
            return v[:clamp]
    return default

def _extract_peer_ip(context: Union[grpc.ServicerContext, grpc.aio.ServicerContext]) -> str:
    try:
        # peer like: ipv4:1.2.3.4:56789
        peer = context.peer()
        if peer and ":" in peer:
            return peer.split(":")[1]
        return "unknown"
    except Exception:
        return "unknown"

def _extract_mtls_thumbprint(context: Union[grpc.ServicerContext, grpc.aio.ServicerContext]) -> Optional[str]:
    # Best-effort extraction of client cert hash from auth_context (requires SSL creds and client certs enforced)
    try:
        ac = context.auth_context() or {}
        # Common keys: "x509_pem_cert" (list of leaf cert), or properties like "x509_common_name"
        pem_list = ac.get("x509_pem_cert")
        if not pem_list:
            return None
        # Take first certificate (leaf), compute SHA-256 over DER
        pem = pem_list[0]
        if isinstance(pem, bytes):
            pem = pem.decode("ascii", "ignore")
        # convert PEM to DER (stdlib only)
        der_b64 = "".join(line for line in pem.splitlines() if "BEGIN" not in line and "END" not in line)
        der = base64.b64decode(der_b64.encode("ascii"), validate=False)
        import hashlib
        return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode("ascii").rstrip("=")
    except Exception:
        return None

def _build_pdp_payload(full_method: str,
                       meta: Mapping[str, str],
                       ip: str,
                       mtls_thumb: Optional[str]) -> Dict[str, Any]:
    service, method = _split_full_method(full_method)
    tenant = _first(meta, PEPConfig().tenant_keys)
    user = _first(meta, PEPConfig().user_keys)
    resource = _first(meta, PEPConfig().resource_keys, default=service)
    session = _first(meta, PEPConfig().session_keys, default="unknown", clamp=192)
    sensitivity = meta.get("x-sensitivity", "low").lower()
    # Minimal payload compatible with risk.proto semantics (using JSON form)
    payload: Dict[str, Any] = {
        "now": int(time.time()),
        "user": {"id": user, "groups": [], "roles": [], "tenant": tenant},
        "resource": {"id": resource, "sensitivity": sensitivity, "scope": [service]},
        "session": {
            "previous_failures": int(meta.get("x-prev-fails", "0") or 0),
            "logins_last_hour": int(meta.get("x-velocity-1h", "0") or 0),
            "last_mfa_epoch_seconds": int(meta.get("x-last-mfa", "0") or 0),
            "cookie_bound": meta.get("x-cookie-bound", "false").lower() == "true",
            "client_cert_bound": mtls_thumb is not None,
        },
        "network": {
            "ip": ip, "country": meta.get("x-country", ""), "asn": int(meta.get("x-asn", "0") or 0),
            "reputation": {"score": int(meta.get("x-iprep", "100") or 100), "denylist": meta.get("x-ipdeny", "false").lower() == "true"},
            "anonymous": {"tor": meta.get("x-tor", "false").lower() == "true",
                          "vpn": meta.get("x-vpn", "false").lower() == "true",
                          "proxy": meta.get("x-proxy", "false").lower() == "true"},
        },
        "device": {
            "ownership": meta.get("x-device-ownership", "corporate"),
            "platform": meta.get("x-device-platform", "linux"),
            "posture": {"hard_fail": meta.get("x-posture-hard", "false").lower() == "true",
                        "score": int(meta.get("x-posture-score", "80") or 80)},
            "mTLS": {"present": mtls_thumb is not None, "eku_clientAuth": True},
            "first_seen_age_days": int(meta.get("x-device-age-days", "90") or 90),
            "mfa": {"capabilities": meta.get("x-device-mfa", "webauthn_platform,webauthn_roaming").split(",")},
        },
        "policy": {"id": meta.get("x-policy-id", "rbmfa-prod"), "hash": meta.get("x-policy-hash", "")},
        "request_id": meta.get("x-request-id", ""),
        "tenant": tenant,
        "attributes": {k: v for k, v in meta.items() if k in PEPConfig().include_metadata_keys},
    }
    # Attach mTLS thumbprint if present
    if mtls_thumb:
        payload["device"]["mTLS"]["thumbprint"] = mtls_thumb
    return payload

def _split_full_method(full_method: str) -> Tuple[str, str]:
    # "/package.Service/Method"
    try:
        _, svc, meth = full_method.split("/", 2)
        return svc, meth
    except ValueError:
        return "unknown", "unknown"

# ---------------------------
# Enforcement core
# ---------------------------

class _Enforcer:
    def __init__(self, cfg: PEPConfig, cache: _TTLCache):
        self.cfg = cfg
        self.cache = cache
        if cfg.pdp_http_base:
            self.pdp = _HTTPPDP(cfg.pdp_http_base, cfg.pdp_http_path, cfg.pdp_timeout_s)
        elif cfg.pdp_callable:
            self.pdp = _CallablePDP(cfg.pdp_callable)
        else:
            raise ValueError("PEPConfig requires pdp_http_base or pdp_callable")

    def _cache_key(self, payload: Dict[str, Any]) -> str:
        u = payload["user"]["id"]
        t = payload["tenant"]
        r = payload["resource"]["id"]
        s = payload["session"].get("last_mfa_epoch_seconds", 0)
        sess = payload["session"]
        sid = f"{sess}"  # stable-ish; can be improved if you pass explicit session_id
        mt = payload["device"]["mTLS"].get("thumbprint") if payload.get("device") else None
        return f"{t}|{u}|{r}|{s}|{sid}|{mt}"

    async def evaluate(self, payload: Dict[str, Any]) -> DecisionDict:
        key = self._cache_key(payload)
        cached = self.cache.get(key)
        if cached:
            return cached
        try:
            decision = await self.pdp.evaluate(payload)
            ttl = float(decision.get("ttl_seconds") or
                        decision.get("decision", {}).get("ttl", 120) or 120)
            self.cache.put(key, decision, ttl)
            return decision
        except Exception as e:
            logger.warning("PDP evaluation failed: %s", e)
            if self.cfg.failure_mode == "allow_with_alert":
                # Build a minimal allow with short ttl
                decision = {
                    "action": "allow",
                    "risk": {"score": 100, "reasons": ["PDP_UNAVAILABLE"]},
                    "ttl_seconds": 15,
                }
                self.cache.put(f"fail|{key}", decision, 15)
                return decision
            raise

    @staticmethod
    def _normalize_action(decision: DecisionDict) -> str:
        # Accept either top-level "action" or nested decision.action
        action = decision.get("action")
        if not action:
            action = decision.get("decision", {}).get("action")
        if not isinstance(action, str):
            return "deny"
        return action.lower()

# ---------------------------
# Async interceptor (grpc.aio)
# ---------------------------

class AioPEPInterceptor(grpc.aio.ServerInterceptor):
    def __init__(self, cfg: Optional[PEPConfig] = None, cache: Optional[_TTLCache] = None):
        self.cfg = cfg or PEPConfig()
        self.enf = _Enforcer(self.cfg, cache or _TTLCache(self.cfg.cache_max_entries))

    async def intercept_service(self, continuation, handler_call_details: grpc.HandlerCallDetails):
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        async def _enforce_and_wrap(unary_unary=None, unary_stream=None, stream_unary=None, stream_stream=None):
            async def _precheck(context: grpc.aio.ServicerContext) -> DecisionDict:
                md = _md_to_dict(handler_call_details.invocation_metadata)
                ip = _extract_peer_ip(context)
                mt = _extract_mtls_thumbprint(context)
                payload = _build_pdp_payload(handler_call_details.method, md, ip, mt)
                # Optional: set OTEL attributes
                if _OTEL:
                    try:
                        span = _otel_trace.get_current_span()
                        span.set_attribute("ztc.tenant", payload["tenant"])
                        span.set_attribute("ztc.user", payload["user"]["id"])
                        span.set_attribute("ztc.resource", payload["resource"]["id"])
                        if mt:
                            span.set_attribute("ztc.mtls", True)
                    except Exception:
                        pass
                return await self.enf.evaluate(payload)

            async def _handle_stepup_or_deny(context: grpc.aio.ServicerContext, decision: DecisionDict) -> None:
                action = self.enf._normalize_action(decision)
                if action == "allow":
                    return
                # Prepare trailers with hints
                trailers = []
                if self.cfg.expose_stepup_hints:
                    mfa = decision.get("mfa") or decision.get("decision", {}).get("mfa", {})
                    methods = mfa.get("methods", [])
                    level = mfa.get("level", "medium")
                    trailers.append(("x-ztc-mfa-level", str(level)))
                    if methods:
                        trailers.append(("x-ztc-mfa-methods", ",".join(str(x) for x in methods)))
                    reasons = decision.get("risk", {}).get("reasons") or decision.get("decision", {}).get("reasons")
                    if reasons:
                        trailers.append(("x-ztc-reasons", ",".join(map(str, reasons))[:512]))
                await context.abort(grpc.StatusCode.PERMISSION_DENIED,
                                    "step_up_required" if action == "step_up" else "access_denied",
                                    trailers=trailers)

            # Wrappers per RPC type
            async def _unary_unary(request, context):
                decision = await _precheck(context)
                if self.enf._normalize_action(decision) != "allow":
                    await _handle_stepup_or_deny(context, decision)
                # allow
                return await unary_unary(request, context)

            async def _unary_stream(request, context):
                decision = await _precheck(context)
                if self.enf._normalize_action(decision) != "allow":
                    await _handle_stepup_or_deny(context, decision)
                ttl = float(decision.get("ttl_seconds", 120))
                reevaluate = self.cfg.reevaluate_every_s
                interval = max(1.0, min(ttl, reevaluate)) if reevaluate > 0 else 0.0

                async def _gen():
                    last_check = time.time()
                    async for item in unary_stream(request, context):
                        now = time.time()
                        if interval and (now - last_check) >= interval:
                            last_check = now
                            dec = await _precheck(context)
                            if self.enf._normalize_action(dec) != "allow":
                                await _handle_stepup_or_deny(context, dec)
                        yield item
                async for x in _gen():
                    yield x

            async def _stream_unary(request_iter, context):
                decision = await _precheck(context)
                if self.enf._normalize_action(decision) != "allow":
                    await _handle_stepup_or_deny(context, decision)

                async def _iter_guard():
                    ttl = float(decision.get("ttl_seconds", 120))
                    reevaluate = self.cfg.reevaluate_every_s
                    interval = max(1.0, min(ttl, reevaluate)) if reevaluate > 0 else 0.0
                    last_check = time.time()
                    async for req in request_iter:
                        now = time.time()
                        if interval and (now - last_check) >= interval:
                            last_check = now
                            dec = await _precheck(context)
                            if self.enf._normalize_action(dec) != "allow":
                                await _handle_stepup_or_deny(context, dec)
                        yield req
                return await stream_unary(_iter_guard(), context)

            async def _stream_stream(request_iter, context):
                decision = await _precheck(context)
                if self.enf._normalize_action(decision) != "allow":
                    await _handle_stepup_or_deny(context, decision)

                async def _iter_guard():
                    ttl = float(decision.get("ttl_seconds", 120))
                    reevaluate = self.cfg.reevaluate_every_s
                    interval = max(1.0, min(ttl, reevaluate)) if reevaluate > 0 else 0.0
                    last_check = time.time()
                    async for req in request_iter:
                        now = time.time()
                        if interval and (now - last_check) >= interval:
                            last_check = now
                            dec = await _precheck(context)
                            if self.enf._normalize_action(dec) != "allow":
                                await _handle_stepup_or_deny(context, dec)
                        yield req

                async def _resp_guard():
                    async for resp in stream_stream(_iter_guard(), context):
                        yield resp
                async for x in _resp_guard():
                    yield x

            return grpc.aio.RpcMethodHandler(
                request_streaming=handler.request_streaming,
                response_streaming=handler.response_streaming,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
                unary_unary=_unary_unary if handler.unary_unary else None,
                unary_stream=_unary_stream if handler.unary_stream else None,
                stream_unary=_stream_unary if handler.stream_unary else None,
                stream_stream=_stream_stream if handler.stream_stream else None,
            )

        return await _enforce_and_wrap(
            unary_unary=handler.unary_unary,
            unary_stream=handler.unary_stream,
            stream_unary=handler.stream_unary,
            stream_stream=handler.stream_stream,
        )

# ---------------------------
# Sync interceptor (grpc)
# ---------------------------

class SyncPEPInterceptor(grpc.ServerInterceptor):
    def __init__(self, cfg: Optional[PEPConfig] = None, cache: Optional[_TTLCache] = None):
        self.cfg = cfg or PEPConfig()
        self.enf = _Enforcer(self.cfg, cache or _TTLCache(self.cfg.cache_max_entries))

    def intercept_service(self, continuation, handler_call_details: grpc.HandlerCallDetails):
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        def _precheck(context: grpc.ServicerContext) -> DecisionDict:
            md = _md_to_dict(handler_call_details.invocation_metadata)
            ip = _extract_peer_ip(context)
            mt = _extract_mtls_thumbprint(context)
            payload = _build_pdp_payload(handler_call_details.method, md, ip, mt)
            return asyncio.run(self.enf.evaluate(payload))  # sync bridge; short, bounded by pdp_timeout

        def _handle_stepup_or_deny(context: grpc.ServicerContext, decision: DecisionDict) -> None:
            action = self.enf._normalize_action(decision)
            if action == "allow":
                return
            trailers = []
            if self.cfg.expose_stepup_hints:
                mfa = decision.get("mfa") or decision.get("decision", {}).get("mfa", {})
                methods = mfa.get("methods", [])
                level = mfa.get("level", "medium")
                trailers.append(("x-ztc-mfa-level", str(level)))
                if methods:
                    trailers.append(("x-ztc-mfa-methods", ",".join(str(x) for x in methods)))
                reasons = decision.get("risk", {}).get("reasons") or decision.get("decision", {}).get("reasons")
                if reasons:
                    trailers.append(("x-ztc-reasons", ",".join(map(str, reasons))[:512]))
            context.abort_with_status(grpc.StatusCode.PERMISSION_DENIED, "step_up_required" if action == "step_up" else "access_denied", trailers=trailers)  # type: ignore[attr-defined]

        # Type-based wrapping
        if handler.request_streaming and handler.response_streaming:
            return grpc.method_handlers_generic_handler(
                _split_full_method(handler_call_details.method)[0],
                {
                    _split_full_method(handler_call_details.method)[1]:
                        grpc.stream_stream_rpc_method_handler(
                            self._wrap_stream_stream(handler.stream_stream, _precheck, _handle_stepup_or_deny),
                            request_deserializer=handler.request_deserializer,
                            response_serializer=handler.response_serializer
                        )
                }
            )._method_handlers[_split_full_method(handler_call_details.method)[1]]  # type: ignore[attr-defined]
        if handler.request_streaming and not handler.response_streaming:
            return grpc.method_handlers_generic_handler(
                _split_full_method(handler_call_details.method)[0],
                {
                    _split_full_method(handler_call_details.method)[1]:
                        grpc.stream_unary_rpc_method_handler(
                            self._wrap_stream_unary(handler.stream_unary, _precheck, _handle_stepup_or_deny),
                            request_deserializer=handler.request_deserializer,
                            response_serializer=handler.response_serializer
                        )
                }
            )._method_handlers[_split_full_method(handler_call_details.method)[1]]  # type: ignore[attr-defined]
        if not handler.request_streaming and handler.response_streaming:
            return grpc.method_handlers_generic_handler(
                _split_full_method(handler_call_details.method)[0],
                {
                    _split_full_method(handler_call_details.method)[1]:
                        grpc.unary_stream_rpc_method_handler(
                            self._wrap_unary_stream(handler.unary_stream, _precheck, _handle_stepup_or_deny),
                            request_deserializer=handler.request_deserializer,
                            response_serializer=handler.response_serializer
                        )
                }
            )._method_handlers[_split_full_method(handler_call_details.method)[1]]  # type: ignore[attr-defined]
        # unary-unary
        return grpc.method_handlers_generic_handler(
            _split_full_method(handler_call_details.method)[0],
            {
                _split_full_method(handler_call_details.method)[1]:
                    grpc.unary_unary_rpc_method_handler(
                        self._wrap_unary_unary(handler.unary_unary, _precheck, _handle_stepup_or_deny),
                        request_deserializer=handler.request_deserializer,
                        response_serializer=handler.response_serializer
                    )
            }
        )._method_handlers[_split_full_method(handler_call_details.method)[1]]  # type: ignore[attr-defined]

    # --- wrappers (sync) ---
    def _wrap_unary_unary(self, inner, precheck, deny):
        def _h(req, ctx: grpc.ServicerContext):
            dec = precheck(ctx)
            if self.enf._normalize_action(dec) != "allow":
                deny(ctx, dec)
            return inner(req, ctx)
        return _h

    def _wrap_unary_stream(self, inner, precheck, deny):
        def _h(req, ctx: grpc.ServicerContext):
            dec = precheck(ctx)
            if self.enf._normalize_action(dec) != "allow":
                deny(ctx, dec)
            # No re-eval in sync mode to avoid thread mgmt; keep simple
            for item in inner(req, ctx):
                yield item
        return _h

    def _wrap_stream_unary(self, inner, precheck, deny):
        def _h(req_iter, ctx: grpc.ServicerContext):
            dec = precheck(ctx)
            if self.enf._normalize_action(dec) != "allow":
                deny(ctx, dec)
            return inner(req_iter, ctx)
        return _h

    def _wrap_stream_stream(self, inner, precheck, deny):
        def _h(req_iter, ctx: grpc.ServicerContext):
            dec = precheck(ctx)
            if self.enf._normalize_action(dec) != "allow":
                deny(ctx, dec)
            for item in inner(req_iter, ctx):
                yield item
        return _h

# ---------------------------
# Notes:
# - To use HTTP PDP: PEPConfig(pdp_http_base="https://pdp.example.com")
# - To use callable PDP: PEPConfig(pdp_callable=lambda payload: {"action":"allow","ttl_seconds":120})
# - Ensure your gRPC server is created with SSL creds and client auth if you rely on mTLS thumbprint extraction.
# - For continuous verification in grpc.aio, the interceptor re-evaluates decision during streaming based on TTL/interval.
# ---------------------------
