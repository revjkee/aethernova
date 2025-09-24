# datafabric/datafabric/lineage/exporters/opentelemetry_exporter.py
# -*- coding: utf-8 -*-
"""
Industrial OpenTelemetry exporter for Data Lineage (datafabric-core).

Features:
- OTLP over gRPC or HTTP/protobuf (auto by OTel SDK env)
- Traces-first model: pipeline/job as Span, lineage edges as Span events
- Robust batching via BatchSpanProcessor; async-friendly facade
- Idempotent event emission (de-dup by id + TTL)
- Resilient retries with exponential backoff & jitter
- Metrics: counters for exported items / failures; latency hist
- Configurable via ENV or dict; minimal deps beyond OpenTelemetry SDK
- Safe shutdown & flush; context propagation support
- Optional logs channel for lineage audit breadcrumbs
- CLI: consume JSON lineage and export

ENV (standard OTel + custom):
- OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_PROTOCOL, OTEL_RESOURCE_ATTRIBUTES
- DF_LINEAGE_SERVICE_NAME, DF_LINEAGE_NAMESPACE, DF_OTEL_INSECURE, DF_EXPORT_TIMEOUT_MS
- DF_RETRY_MAX_ATTEMPTS, DF_RETRY_BASE_MS, DF_RETRY_MAX_MS, DF_IDEMPOTENCY_TTL_S

Copyright:
© DataFabric-Core
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

# OpenTelemetry SDK
from opentelemetry import trace, metrics
from opentelemetry.trace import Tracer, SpanKind, Link
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPSpanExporterGRPC
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPSpanExporterHTTP
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
try:
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter as OTLPMetricExporterGRPC
except Exception:
    OTLPMetricExporterGRPC = None  # optional

# Optional logs (not all distros include SDK logs stable)
try:
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter as OTLPLogExporterGRPC
    _LOGS_SUPPORTED = True
except Exception:
    _LOGS_SUPPORTED = False

LOG = logging.getLogger("datafabric.lineage.otel")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s lineage-otel:%(message)s"))
    LOG.addHandler(h)
    LOG.setLevel(logging.INFO)

# -------------------------
# Data model (lightweight)
# -------------------------

@dataclass
class DatasetRef:
    system: str
    name: str
    namespace: Optional[str] = None
    schema: Optional[Dict[str, Any]] = None
    facets: Optional[Dict[str, Any]] = None

@dataclass
class LineageEdge:
    source: DatasetRef
    target: DatasetRef
    transformation: Optional[str] = None
    run_id: Optional[str] = None
    ts_ms: Optional[int] = None
    props: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: Optional[str] = None  # for de-dup

@dataclass
class LineageGraph:
    pipeline: str
    run_id: str
    inputs: List[DatasetRef]
    outputs: List[DatasetRef]
    edges: List[LineageEdge]
    attrs: Dict[str, Any] = field(default_factory=dict)
    start_ms: Optional[int] = None
    end_ms: Optional[int] = None
    parent_context: Optional[str] = None  # W3C traceparent if any

# -------------------------
# Config
# -------------------------

@dataclass
class ExporterConfig:
    service_name: str = os.getenv("DF_LINEAGE_SERVICE_NAME", "datafabric-lineage")
    service_namespace: str = os.getenv("DF_LINEAGE_NAMESPACE", "datafabric")
    resource_attrs: Dict[str, str] = field(default_factory=dict)
    use_grpc: bool = os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc").lower() == "grpc"
    insecure: bool = os.getenv("DF_OTEL_INSECURE", "false").lower() in ("1", "true", "yes")
    endpoint: Optional[str] = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or None
    export_timeout_ms: int = int(os.getenv("DF_EXPORT_TIMEOUT_MS", "10000"))
    retry_max_attempts: int = int(os.getenv("DF_RETRY_MAX_ATTEMPTS", "5"))
    retry_base_ms: int = int(os.getenv("DF_RETRY_BASE_MS", "100"))
    retry_max_ms: int = int(os.getenv("DF_RETRY_MAX_MS", "4000"))
    idempotency_ttl_s: int = int(os.getenv("DF_IDEMPOTENCY_TTL_S", "900"))  # 15m
    enable_console_fallback: bool = False  # for local debug

# -------------------------
# Idempotency cache (in‑mem, TTL)
# -------------------------

class TTLCache:
    def __init__(self, ttl_s: int = 900, max_items: int = 100_000):
        self.ttl = ttl_s
        self.max = max_items
        self._store: Dict[str, float] = {}

    def add(self, key: str) -> bool:
        now = time.monotonic()
        self._evict(now)
        if key in self._store:
            if now - self._store[key] < self.ttl:
                return False
        if len(self._store) >= self.max:
            # simple eviction: drop oldest 1%
            cutoff = sorted(self._store.items(), key=lambda kv: kv[1])[: max(1, self.max // 100)]
            for k, _ in cutoff:
                self._store.pop(k, None)
        self._store[key] = now
        return True

    def _evict(self, now: float) -> None:
        expired = [k for k, t in self._store.items() if now - t >= self.ttl]
        for k in expired:
            self._store.pop(k, None)

# -------------------------
# Exporter
# -------------------------

class LineageOpenTelemetryExporter:
    """
    High-reliability exporter turning lineage graphs/edges into OTel spans & events.
    """

    def __init__(self, config: Optional[ExporterConfig] = None):
        self.cfg = config or ExporterConfig()
        # Resource
        res_attrs = {
            "service.name": self.cfg.service_name,
            "service.namespace": self.cfg.service_namespace,
            **self.cfg.resource_attrs,
        }
        # Allow merge with OTEL_RESOURCE_ATTRIBUTES
        env_attrs = os.getenv("OTEL_RESOURCE_ATTRIBUTES")
        if env_attrs:
            for kv in env_attrs.split(","):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    res_attrs[k.strip()] = v.strip()
        resource = Resource.create(res_attrs)

        # Traces
        provider = TracerProvider(resource=resource)
        span_exporter = self._build_span_exporter()
        provider.add_span_processor(BatchSpanProcessor(span_exporter))
        if self.cfg.enable_console_fallback:
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(provider)
        self.tracer: Tracer = trace.get_tracer("datafabric.lineage")

        # Metrics
        metric_readers = []
        metric_exporter = self._build_metric_exporter()
        if metric_exporter:
            metric_readers.append(PeriodicExportingMetricReader(metric_exporter))
        metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=metric_readers))
        self.meter = metrics.get_meter("datafabric.lineage")
        self._m_exported = self.meter.create_counter("lineage_exported_items", unit="1", description="Exported lineage items")
        self._m_failed = self.meter.create_counter("lineage_export_failures", unit="1", description="Lineage export failures")
        self._m_latency = self.meter.create_histogram("lineage_export_latency_ms", unit="ms", description="Latency of lineage export")

        # Logs (optional)
        if _LOGS_SUPPORTED:
            self._init_logs(resource)
        else:
            self.log_provider = None

        # Idempotency
        self._cache = TTLCache(ttl_s=self.cfg.idempotency_ttl_s)

    # ---------------------
    # Builders
    # ---------------------
    def _build_span_exporter(self):
        # Endpoint is auto-resolved by SDK if None
        if self.cfg.use_grpc:
            return OTLPSpanExporterGRPC(endpoint=self.cfg.endpoint, insecure=self.cfg.insecure, timeout=self.cfg.export_timeout_ms / 1000.0)
        return OTLPSpanExporterHTTP(endpoint=self.cfg.endpoint, timeout=self.cfg.export_timeout_ms / 1000.0)

    def _build_metric_exporter(self):
        if OTLPMetricExporterGRPC is None:
            return None
        try:
            return OTLPMetricExporterGRPC(endpoint=self.cfg.endpoint, insecure=self.cfg.insecure, timeout=self.cfg.export_timeout_ms / 1000.0)
        except Exception as e:
            LOG.warning("Metrics exporter not initialized: %s", e)
            return None

    def _init_logs(self, resource: Resource):
        try:
            self.log_provider = LoggerProvider(resource=resource)
            log_exporter = OTLPLogExporterGRPC(endpoint=self.cfg.endpoint, insecure=self.cfg.insecure, timeout=self.cfg.export_timeout_ms / 1000.0)
            self.log_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        except Exception as e:
            LOG.warning("Logs exporter not initialized: %s", e)
            self.log_provider = None

    # ---------------------
    # Public API
    # ---------------------
    async def export_graph(self, graph: LineageGraph) -> str:
        """
        Export a full lineage graph as a root Span (pipeline run) with events for edges/IO.
        Returns trace_id hex.
        """
        start = time.perf_counter()
        ctx = self._context_from_traceparent(graph.parent_context)
        span_name = f"lineage.run:{graph.pipeline}"
        attributes = {
            "lineage.pipeline": graph.pipeline,
            "lineage.run_id": graph.run_id,
            **self._normalize_attrs(graph.attrs),
        }
        # Span timestamps: use provided start/end if present
        start_time = (graph.start_ms or int(time.time() * 1000)) / 1000.0
        end_time = (graph.end_ms or int(time.time() * 1000)) / 1000.0

        with self.tracer.start_as_current_span(span_name, kind=SpanKind.INTERNAL, context=ctx, start_time=start_time) as span:
            # Attach inputs/outputs as attributes & events
            self._attach_datasets(span, "inputs", graph.inputs)
            self._attach_datasets(span, "outputs", graph.outputs)
            # Emit edges as events
            for edge in graph.edges:
                await self._emit_edge_event(span, edge)
            # End span at provided end time
            span.end(end_time=end_time)

            trace_id = span.get_span_context().trace_id
            hex_id = f"{trace_id:032x}"
        await self._flush_with_retry()
        self._m_exported.add(1)
        self._m_latency.record((time.perf_counter() - start) * 1000.0)
        return hex_id

    async def export_edge(self, pipeline: str, run_id: str, edge: LineageEdge, parent_trace: Optional[str] = None) -> str:
        """
        Export a single lineage edge as a child span event.
        Returns trace_id hex.
        """
        start = time.perf_counter()
        ctx = self._context_from_traceparent(parent_trace)
        span_name = f"lineage.edge:{pipeline}"
        attrs = {
            "lineage.pipeline": pipeline,
            "lineage.run_id": run_id,
        }
        with self.tracer.start_as_current_span(span_name, kind=SpanKind.INTERNAL, context=ctx) as span:
            await self._emit_edge_event(span, edge)
            trace_id = span.get_span_context().trace_id
            hex_id = f"{trace_id:032x}"
        await self._flush_with_retry()
        self._m_exported.add(1)
        self._m_latency.record((time.perf_counter() - start) * 1000.0)
        return hex_id

    async def shutdown(self) -> None:
        # Provider shutdown is handled by SDK via atexit, but we explicitly flush.
        await self._flush_with_retry(final=True)

    # ---------------------
    # Internals
    # ---------------------
    async def _emit_edge_event(self, span, edge: LineageEdge) -> None:
        # Idempotency
        key = edge.idempotency_key or self._edge_key(edge)
        if not self._cache.add(key):
            LOG.debug("Skip duplicate lineage edge: %s", key)
            return

        ev_attrs = {
            "lineage.edge.id": key,
            "lineage.edge.run_id": edge.run_id or "",
            "lineage.edge.transformation": edge.transformation or "",
            "lineage.edge.props": json.dumps(self._normalize_attrs(edge.props), ensure_ascii=False),
            **self._dataset_attrs("source", edge.source),
            **self._dataset_attrs("target", edge.target),
        }
        ts = (edge.ts_ms or int(time.time() * 1000)) / 1000.0
        span.add_event(name="lineage.edge", attributes=ev_attrs, timestamp=ts)

        # Optional audit log
        if self.log_provider:
            try:
                from opentelemetry._logs import get_logger  # type: ignore
                logger = get_logger("datafabric.lineage.audit", logger_provider=self.log_provider)
                logger.emit(
                    event="lineage.edge",
                    attributes=ev_attrs,
                    severity_text="INFO",
                )
            except Exception as e:
                LOG.debug("Log emit skipped: %s", e)

    def _attach_datasets(self, span, kind: str, datasets: List[DatasetRef]) -> None:
        arr = []
        for ds in datasets:
            arr.append({
                "system": ds.system,
                "name": ds.name,
                "namespace": ds.namespace or "",
            })
        span.set_attribute(f"lineage.{kind}.count", len(arr))
        # Keep small attribute payload; put full details as event(s)
        for ds in datasets:
            span.add_event(
                name=f"lineage.{kind[:-1]}",  # input/output
                attributes=self._dataset_attrs(kind[:-1], ds),
            )

    def _dataset_attrs(self, prefix: str, ds: DatasetRef) -> Dict[str, Any]:
        out = {
            f"{prefix}.system": ds.system,
            f"{prefix}.name": ds.name,
        }
        if ds.namespace:
            out[f"{prefix}.namespace"] = ds.namespace
        if ds.schema:
            # Avoid huge payloads; keep compact JSON
            out[f"{prefix}.schema"] = json.dumps(ds.schema, ensure_ascii=False)
        if ds.facets:
            out[f"{prefix}.facets"] = json.dumps(self._normalize_attrs(ds.facets), ensure_ascii=False)
        return out

    def _edge_key(self, edge: LineageEdge) -> str:
        seed = "|".join([
            edge.source.system, edge.source.name,
            edge.target.system, edge.target.name,
            edge.transformation or "",
            edge.run_id or "",
            str(edge.ts_ms or 0),
        ])
        # stable UUID5
        return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))

    def _normalize_attrs(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        # Flatten values to OTel-friendly primitives
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                out[k] = v
            else:
                try:
                    out[k] = json.dumps(v, ensure_ascii=False)
                except Exception:
                    out[k] = str(v)
        return out

    def _context_from_traceparent(self, traceparent: Optional[str]):
        if not traceparent:
            return None
        # Minimal traceparent parser (00 format): traceparent=version-traceid-spanid-flags
        try:
            parts = traceparent.strip().split("-")
            if len(parts) != 4:
                return None
            _ver, trace_id_hex, span_id_hex, _flags = parts
            trace_id = int(trace_id_hex, 16)
            span_id = int(span_id_hex, 16)
            from opentelemetry.trace import SpanContext, TraceFlags, INVALID_SPAN_CONTEXT
            sc = SpanContext(
                trace_id=trace_id,
                span_id=span_id,
                is_remote=True,
                trace_flags=TraceFlags(TraceFlags.SAMPLED),
                trace_state=None,
            )
            return trace.set_span_in_context(trace.NonRecordingSpan(sc))
        except Exception:
            return None

    async def _flush_with_retry(self, final: bool = False) -> None:
        attempts = 0
        base = self.cfg.retry_base_ms / 1000.0
        maxd = self.cfg.retry_max_ms / 1000.0
        provider: TracerProvider = trace.get_tracer_provider()  # type: ignore
        while True:
            try:
                provider.force_flush(timeout_millis=self.cfg.export_timeout_ms)
                return
            except Exception as e:
                attempts += 1
                self._m_failed.add(1)
                if attempts >= self.cfg.retry_max_attempts:
                    if final:
                        LOG.error("Force flush failed after %d attempts: %s", attempts, e)
                    else:
                        LOG.warning("Flush failed after %d attempts: %s", attempts, e)
                    return
                # Exponential backoff with jitter
                delay = min(maxd, base * (2 ** (attempts - 1))) + (0.001 * (uuid.uuid4().int % 1000))
                await asyncio.sleep(delay)

# -------------------------
# Convenience functions
# -------------------------

async def export_lineage_graph(graph: LineageGraph, config: Optional[ExporterConfig] = None) -> str:
    exp = LineageOpenTelemetryExporter(config)
    try:
        return await exp.export_graph(graph)
    finally:
        await exp.shutdown()

async def export_lineage_edge(edge: LineageEdge, pipeline: str, run_id: str, parent_trace: Optional[str] = None,
                              config: Optional[ExporterConfig] = None) -> str:
    exp = LineageOpenTelemetryExporter(config)
    try:
        return await exp.export_edge(pipeline=pipeline, run_id=run_id, edge=edge, parent_trace=parent_trace)
    finally:
        await exp.shutdown()

# -------------------------
# CLI
# -------------------------

def _cli():
    """
    CLI expects JSON on stdin or via --file with one of forms:
    1) Graph:
       {"type":"graph","pipeline":"p","run_id":"r","inputs":[...],"outputs":[...],"edges":[...],"attrs":{...}}
    2) Edge:
       {"type":"edge","pipeline":"p","run_id":"r","edge":{...}, "parent_trace":"00-<traceid>-<spanid>-01"}
    """
    import argparse, sys
    parser = argparse.ArgumentParser(description="DataFabric Lineage → OpenTelemetry exporter")
    parser.add_argument("--file", "-f", help="JSON file (default: stdin)")
    parser.add_argument("--console", action="store_true", help="Enable console span fallback")
    args = parser.parse_args()

    raw = None
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            raw = fh.read()
    else:
        raw = sys.stdin.read()

    payload = json.loads(raw)
    cfg = ExporterConfig()
    cfg.enable_console_fallback = bool(args.console)

    def _ds(o: Dict[str, Any]) -> DatasetRef:
        return DatasetRef(
            system=o["system"],
            name=o["name"],
            namespace=o.get("namespace"),
            schema=o.get("schema"),
            facets=o.get("facets"),
        )

    async def _run():
        if payload.get("type") == "graph":
            graph = LineageGraph(
                pipeline=payload["pipeline"],
                run_id=payload["run_id"],
                inputs=[_ds(x) for x in payload.get("inputs", [])],
                outputs=[_ds(x) for x in payload.get("outputs", [])],
                edges=[
                    LineageEdge(
                        source=_ds(e["source"]),
                        target=_ds(e["target"]),
                        transformation=e.get("transformation"),
                        run_id=e.get("run_id"),
                        ts_ms=e.get("ts_ms"),
                        props=e.get("props", {}),
                        idempotency_key=e.get("idempotency_key"),
                    )
                    for e in payload.get("edges", [])
                ],
                attrs=payload.get("attrs", {}),
                start_ms=payload.get("start_ms"),
                end_ms=payload.get("end_ms"),
                parent_context=payload.get("parent_context"),
            )
            trace_id = await export_lineage_graph(graph, cfg)
            print(trace_id)
        elif payload.get("type") == "edge":
            e = payload["edge"]
            edge = LineageEdge(
                source=_ds(e["source"]),
                target=_ds(e["target"]),
                transformation=e.get("transformation"),
                run_id=e.get("run_id"),
                ts_ms=e.get("ts_ms"),
                props=e.get("props", {}),
                idempotency_key=e.get("idempotency_key"),
            )
            trace_id = await export_lineage_edge(edge, pipeline=payload["pipeline"], run_id=payload["run_id"],
                                                 parent_trace=payload.get("parent_trace"), config=cfg)
            print(trace_id)
        else:
            raise SystemExit("Unknown type; expected 'graph' or 'edge'")

    asyncio.run(_run())

if __name__ == "__main__":
    _cli()
