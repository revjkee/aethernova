# -*- coding: utf-8 -*-
"""
Prometheus metrics for self_inhibitor.

Python: 3.11+
Hard deps: none (prometheus_client optional). When missing, a no-op shim is used.

Features:
- Single-process and multiprocess (PROMETHEUS_MULTIPROC_DIR) registries
- Default process/platform/GC collectors (single-process)
- HTTP exporter (start_http_exporter) and ASGI /metrics app
- Pushgateway support
- Uniform label schema for decisions, rate limits, errors
- Decorators/context managers and ASGI middleware instrumentation
"""

from __future__ import annotations

import contextlib
import os
import time
import types
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple

# --------------------------------------------------------------------------------------
# Optional prometheus_client import with graceful fallback
# --------------------------------------------------------------------------------------

_PROM_AVAILABLE = True
try:
    # Core
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Summary  # type: ignore
    # Collectors vary across versions; try modern names first
    try:
        from prometheus_client import GCCollector, ProcessCollector, PlatformCollector  # type: ignore
    except Exception:  # older versions
        GCCollector = ProcessCollector = PlatformCollector = None  # type: ignore
    # Exposition
    from prometheus_client import start_http_server  # type: ignore
    try:
        from prometheus_client import make_asgi_app  # type: ignore
    except Exception:
        make_asgi_app = None  # type: ignore
    try:
        from prometheus_client import make_wsgi_app  # type: ignore
    except Exception:
        make_wsgi_app = None  # type: ignore
    # Multiprocess
    try:
        from prometheus_client import multiprocess  # type: ignore
    except Exception:
        multiprocess = None  # type: ignore
    # Pushgateway
    try:
        from prometheus_client import push_to_gateway, delete_from_gateway  # type: ignore
    except Exception:
        push_to_gateway = delete_from_gateway = None  # type: ignore
except Exception:
    _PROM_AVAILABLE = False
    CollectorRegistry = Counter = Gauge = Histogram = Summary = object  # type: ignore
    GCCollector = ProcessCollector = PlatformCollector = None  # type: ignore
    start_http_server = make_asgi_app = make_wsgi_app = multiprocess = None  # type: ignore
    push_to_gateway = delete_from_gateway = None  # type: ignore


# --------------------------------------------------------------------------------------
# No-op primitives (when prometheus_client is missing)
# --------------------------------------------------------------------------------------

class _NoopMetric:
    def __init__(self, *a, **kw) -> None: ...
    def labels(self, *a, **kw) -> "._NoopMetric": return self
    def inc(self, *a, **kw) -> None: ...
    def dec(self, *a, **kw) -> None: ...
    def set(self, *a, **kw) -> None: ...
    def observe(self, *a, **kw) -> None: ...

class _NoopRegistry:
    pass

def _noop_asgi_app(scope, receive, send):  # ASGI app placeholder
    async def _resp() -> None:
        await send({"type": "http.response.start", "status": 501, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"prometheus_client not installed"})
    if scope.get("type") == "http":
        return _resp()
    return None

# --------------------------------------------------------------------------------------
# Common label schema
# --------------------------------------------------------------------------------------

# Decision labels are broad to allow aggregation across transports (HTTP/WS/gRPC/GraphQL)
_DECISION_LABELS = (
    "tenant",       # org/project
    "endpoint",     # logical endpoint or route name
    "method",       # http/grpc/ws op kind (GET, POST, SUB, RPC, etc.)
    "decision",     # allow/deny/warn
    "policy",       # policy id/name
    "strategy",     # which strategy triggered (rate_limiter, sandbox, content_filter, etc.)
    "status",       # PASS/WARN/FAIL for strategy checks
    "http_status",  # final http status if applicable, else "na"
)

_RATE_LIMIT_LABELS = (
    "tenant",
    "key",          # rate-limit key (hashed/truncated upstream if sensitive)
    "decision",     # allow/deny
    "limiter",      # fw/sw/tb
)

_ERROR_LABELS = (
    "component",    # part of system (middleware, strategy, runtime, adapter, rules)
    "type",         # error class/kind
)

# --------------------------------------------------------------------------------------
# Public configuration dataclass
# --------------------------------------------------------------------------------------

@dataclass(slots=True)
class PromConfig:
    namespace: str = "genius_core"
    subsystem: str = "self_inhibitor"
    buckets: Tuple[float, ...] = (  # duration seconds buckets
        0.001, 0.002, 0.005, 0.01,
        0.02, 0.05, 0.1, 0.2,
        0.5, 1.0, 2.5, 5.0, 10.0
    )
    enable_default_collectors: bool = True    # process/platform/gc for single-process
    multiprocess_dir: Optional[str] = None    # if set (or env PROMETHEUS_MULTIPROC_DIR) — use multiprocess registry
    exporter_addr: str = "0.0.0.0"
    exporter_port: int = 9108                 # typical sidecar port
    # Pushgateway (optional)
    pushgateway_addr: Optional[str] = None    # host:port
    push_job: str = "self_inhibitor"
    push_grouping: Mapping[str, str] = None   # e.g., {"instance": "pod-abc", "cluster": "prod"}

# --------------------------------------------------------------------------------------
# Core metrics class
# --------------------------------------------------------------------------------------

class PrometheusMetrics:
    """
    Central metrics registry and helpers.
    """
    def __init__(self, cfg: Optional[PromConfig] = None, registry: Any = None) -> None:
        self.cfg = cfg or PromConfig()
        self._nop = not _PROM_AVAILABLE

        # Registry selection (single-process vs multiprocess)
        if self._nop:
            self.registry = _NoopRegistry()
            # No-op metrics
            self.requests_total = _NoopMetric()
            self.decisions_total = _NoopMetric()
            self.decision_latency = _NoopMetric()
            self.rate_limited_total = _NoopMetric()
            self.rate_remaining = _NoopMetric()
            self.circuit_state = _NoopMetric()
            self.quarantine_gauge = _NoopMetric()
            self.errors_total = _NoopMetric()
            return

        # Determine multiprocess mode
        mp_dir = self.cfg.multiprocess_dir or os.getenv("PROMETHEUS_MULTIPROC_DIR")
        if registry is not None:
            self.registry = registry
        elif mp_dir and multiprocess:
            os.environ["PROMETHEUS_MULTIPROC_DIR"] = mp_dir
            self.registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(self.registry)  # type: ignore
        else:
            self.registry = CollectorRegistry()
            if self.cfg.enable_default_collectors:
                # Register default collectors in single-process mode
                if ProcessCollector:
                    ProcessCollector(registry=self.registry)       # type: ignore
                if PlatformCollector:
                    PlatformCollector(registry=self.registry)      # type: ignore
                if GCCollector:
                    GCCollector(registry=self.registry)            # type: ignore

        ns, ss = self.cfg.namespace, self.cfg.subsystem

        # Core metrics
        self.requests_total = Counter(
            name="requests_total",
            documentation="Total inbound requests seen by self_inhibitor middleware",
            namespace=ns, subsystem=ss,
            labelnames=("tenant", "endpoint", "method"),
            registry=self.registry,
        )

        self.decisions_total = Counter(
            name="decisions_total",
            documentation="Total decisions emitted by self_inhibitor",
            namespace=ns, subsystem=ss,
            labelnames=_DECISION_LABELS,
            registry=self.registry,
        )

        self.decision_latency = Histogram(
            name="decision_latency_seconds",
            documentation="Decision/evaluation latency",
            namespace=ns, subsystem=ss,
            labelnames=("tenant", "endpoint", "method"),
            buckets=self.cfg.buckets,
            registry=self.registry,
        )

        self.rate_limited_total = Counter(
            name="rate_limited_total",
            documentation="Rate limiting results",
            namespace=ns, subsystem=ss,
            labelnames=_RATE_LIMIT_LABELS,
            registry=self.registry,
        )

        self.rate_remaining = Gauge(
            name="rate_limit_remaining",
            documentation="Remaining tokens/requests for the key",
            namespace=ns, subsystem=ss,
            labelnames=("tenant", "key", "limiter"),
            registry=self.registry,
        )

        self.circuit_state = Gauge(
            name="circuit_state",
            documentation="Circuit breaker state: 0=closed, 0.5=half-open, 1=open",
            namespace=ns, subsystem=ss,
            labelnames=("name",),
            registry=self.registry,
        )

        self.quarantine_gauge = Gauge(
            name="quarantine_active",
            documentation="Number of quarantined principals/resources",
            namespace=ns, subsystem=ss,
            labelnames=("scope",),  # e.g., "principal", "resource", "ip"
            registry=self.registry,
        )

        self.errors_total = Counter(
            name="errors_total",
            documentation="Unhandled errors in self_inhibitor",
            namespace=ns, subsystem=ss,
            labelnames=_ERROR_LABELS,
            registry=self.registry,
        )

    # ----------------------------------------------------------------------------------
    # Observation helpers
    # ----------------------------------------------------------------------------------

    def observe_request(self, tenant: str, endpoint: str, method: str) -> None:
        self.requests_total.labels(tenant or "na", endpoint or "na", method or "na").inc()

    def observe_decision(
        self,
        *,
        tenant: str,
        endpoint: str,
        method: str,
        decision: str,            # "allow"|"deny"|"warn"
        duration_s: float,
        policy: str = "na",
        strategy: str = "na",
        status: str = "na",       # "PASS"|"WARN"|"FAIL"|"NA"
        http_status: str | int = "na",
    ) -> None:
        self.decisions_total.labels(
            tenant or "na", endpoint or "na", method or "na",
            str(decision or "na"), str(policy or "na"), str(strategy or "na"),
            str(status or "na"), str(http_status or "na"),
        ).inc()
        self.decision_latency.labels(tenant or "na", endpoint or "na", method or "na").observe(max(0.0, float(duration_s)))

    def observe_rate_limit(
        self,
        *,
        tenant: str,
        key: str,
        limiter: str,            # "fw"|"sw"|"tb"
        decision: str,           # "allow"|"deny"
        remaining: int | float,
    ) -> None:
        self.rate_limited_total.labels(tenant or "na", key or "na", decision or "na", limiter or "na").inc()
        self.rate_remaining.labels(tenant or "na", key or "na", limiter or "na").set(max(0.0, float(remaining)))

    def inc_error(self, component: str, err_type: str) -> None:
        self.errors_total.labels(component or "na", err_type or "na").inc()

    def set_circuit_state(self, name: str, state: str) -> None:
        # normalized mapping: "closed"->0, "half_open"->0.5, "open"->1
        val = 0.0 if state == "closed" else (1.0 if state == "open" else 0.5)
        self.circuit_state.labels(name or "default").set(val)

    def set_quarantine(self, scope: str, count: int) -> None:
        self.quarantine_gauge.labels(scope or "all").set(max(0, int(count)))

    # ----------------------------------------------------------------------------------
    # Timing helpers
    # ----------------------------------------------------------------------------------

    def time_function(self, tenant: str = "na", endpoint: str = "na", method: str = "na") -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Decorator to time a function and record decision_latency with generic labels.
        You must call observe_decision separately to record the decision outcome, this only tracks latency.
        """
        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                start = time.perf_counter()
                try:
                    return fn(*args, **kwargs)
                finally:
                    dur = time.perf_counter() - start
                    self.decision_latency.labels(tenant or "na", endpoint or "na", method or "na").observe(dur)
            return wrapped
        return deco

    @contextlib.contextmanager
    def timer(self, tenant: str = "na", endpoint: str = "na", method: str = "na"):
        start = time.perf_counter()
        try:
            yield
        finally:
            dur = time.perf_counter() - start
            self.decision_latency.labels(tenant or "na", endpoint or "na", method or "na").observe(dur)

    # ----------------------------------------------------------------------------------
    # Export / Push
    # ----------------------------------------------------------------------------------

    def start_http_exporter(self, addr: Optional[str] = None, port: Optional[int] = None) -> None:
        """
        Start a background HTTP server exposing /metrics on specified addr:port.
        No-op if prometheus_client missing.
        """
        if self._nop or not start_http_server:
            return
        start_http_server(int(port or self.cfg.exporter_port), addr=addr or self.cfg.exporter_addr, registry=self.registry)  # type: ignore

    def asgi_app(self):
        """
        Return ASGI app serving /metrics (mount it in your ASGI router).
        Fallbacks to a 501 no-op app if prometheus_client not present.
        """
        if self._nop:
            return _noop_asgi_app
        if make_asgi_app:
            return make_asgi_app(registry=self.registry)  # type: ignore
        # Fallback to WSGI wrapped ASGI if available
        if make_wsgi_app:
            wsgi_app = make_wsgi_app(registry=self.registry)  # type: ignore
            async def _asgi(scope, receive, send):
                if scope["type"] != "http":
                    await send({"type": "http.response.start", "status": 500, "headers": [(b"content-type", b"text/plain")]})
                    await send({"type": "http.response.body", "body": b"WSGI metrics app only supports HTTP"})
                    return
                # Minimal ASGI->WSGI bridge for GET /metrics
                environ = {
                    "REQUEST_METHOD": "GET",
                    "PATH_INFO": "/metrics",
                    "SERVER_NAME": "metrics",
                    "SERVER_PORT": "0",
                    "wsgi.input": types.SimpleNamespace(read=lambda n=-1: b""),
                    "wsgi.errors": None,
                    "wsgi.version": (1, 0),
                    "wsgi.url_scheme": "http",
                    "wsgi.multithread": False,
                    "wsgi.multiprocess": False,
                    "wsgi.run_once": False,
                }
                status_headers: Dict[str, Any] = {}
                def _start_response(status, headers, exc_info=None):
                    code = int(status.split()[0])
                    status_headers["code"] = code
                    status_headers["headers"] = headers
                body = b"".join(wsgi_app(environ, _start_response))
                await send({"type": "http.response.start", "status": status_headers.get("code", 200),
                            "headers": [(h[0].encode(), h[1].encode()) for h in status_headers.get("headers", [])]})
                await send({"type": "http.response.body", "body": body})
            return _asgi
        return _noop_asgi_app

    def push(self, job: Optional[str] = None, grouping: Optional[Mapping[str, str]] = None, addr: Optional[str] = None) -> None:
        """
        Push current metrics snapshot to Pushgateway.
        """
        if self._nop or not push_to_gateway:
            return
        dst = addr or self.cfg.pushgateway_addr
        if not dst:
            return
        g = dict(self.cfg.push_grouping or {})
        if grouping:
            g.update(grouping)
        push_to_gateway(dst, job=job or self.cfg.push_job, registry=self.registry, grouping_key=g)  # type: ignore

    def push_delete(self, job: Optional[str] = None, grouping: Optional[Mapping[str, str]] = None, addr: Optional[str] = None) -> None:
        if self._nop or not delete_from_gateway:
            return
        dst = addr or self.cfg.pushgateway_addr
        if not dst:
            return
        g = dict(self.cfg.push_grouping or {})
        if grouping:
            g.update(grouping)
        delete_from_gateway(dst, job=job or self.cfg.push_job, grouping_key=g)  # type: ignore

    # ----------------------------------------------------------------------------------
    # ASGI middleware (transport-agnostic labels)
    # ----------------------------------------------------------------------------------

    def asgi_middleware(self, app):
        """
        Minimal ASGI middleware to instrument HTTP traffic for self_inhibitor.
        Expects scope['path'] and scope['method']; tenant must be injected upstream (scope['tenant']) or defaults to 'na'.
        """
        async def _mw(scope, receive, send):
            if scope.get("type") != "http":
                return await app(scope, receive, send)
            tenant = scope.get("tenant", "na")
            endpoint = scope.get("path", "na")
            method = scope.get("method", "na")
            self.observe_request(tenant, endpoint, method)
            start = time.perf_counter()
            status_code = "na"
            async def _send(ev):
                nonlocal status_code
                if ev["type"] == "http.response.start":
                    status_code = str(ev.get("status", "200"))
                await send(ev)
            try:
                await app(scope, receive, _send)
                dur = time.perf_counter() - start
                # Decision is app-specific; here we record latency only
                self.decision_latency.labels(tenant, endpoint, method).observe(dur)
            except Exception:
                self.inc_error("middleware", "exception")
                dur = time.perf_counter() - start
                self.decision_latency.labels(tenant, endpoint, method).observe(dur)
                raise
        return _mw


# --------------------------------------------------------------------------------------
# Convenience singleton (optional)
# --------------------------------------------------------------------------------------

_default_metrics: Optional[PrometheusMetrics] = None

def get_metrics() -> PrometheusMetrics:
    global _default_metrics
    if _default_metrics is None:
        _default_metrics = PrometheusMetrics()
    return _default_metrics


# --------------------------------------------------------------------------------------
# Example run (manual)
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    m = PrometheusMetrics(PromConfig(exporter_port=9108))
    m.start_http_exporter()
    # Simulate some signals
    m.observe_request("acme", "/v1/answer", "POST")
    m.observe_decision(tenant="acme", endpoint="/v1/answer", method="POST",
                       decision="allow", duration_s=0.012, policy="default", strategy="rate_limiter",
                       status="PASS", http_status=200)
    m.observe_rate_limit(tenant="acme", key="user:42", limiter="tb", decision="allow", remaining=3)
    m.set_circuit_state("llm-backend", "closed")
    m.set_quarantine("principal", 2)
    print("Prometheus exporter on :9108 (/metrics). Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
