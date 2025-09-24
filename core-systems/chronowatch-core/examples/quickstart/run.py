# chronowatch-core/examples/quickstart/run.py
"""
ChronoWatch Quickstart Runner (industrial-grade)

Features:
- Async service with graceful shutdown (SIGINT/SIGTERM)
- /healthz, /readyz, /metrics (Prometheus exposition)
- Structured JSON logging (service/version/correlation/request_id)
- Config via ENV and CLI (sane defaults)
- Background jobs with latency histogram, error counter, success counter
- Heartbeat gauge + up gauge
- Optional OpenTelemetry traces if opentelemetry-* installed and enabled via ENV
- Robust shutdown with timeouts and cancellation

Dependencies (minimal):
  pip install aiohttp prometheus_client
Optional:
  pip install opentelemetry-sdk opentelemetry-exporter-otlp

ENV (override CLI/defaults):
  CHRONO_SERVICE_NAME=chronowatch-quickstart
  CHRONO_VERSION=1.0.0
  CHRONO_HOST=0.0.0.0
  CHRONO_PORT=8080
  CHRONO_METRICS_PATH=/metrics
  CHRONO_HEALTH_PATH=/healthz
  CHRONO_READY_PATH=/readyz
  CHRONO_LOG_LEVEL=INFO
  CHRONO_INTERVAL_SEC=2.0
  CHRONO_JOBS=2
  CHRONO_SHUTDOWN_TIMEOUT_SEC=15
  CHRONO_STARTUP_PROBE_SEC=1.0
  CHRONO_ENABLE_OTEL=false
  OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

Run:
  python -m pip install aiohttp prometheus_client
  python chronowatch-core/examples/quickstart/run.py --port 8080 --jobs 3 --interval 1.5

Kubernetes probes:
  readinessProbe:  GET /readyz
  livenessProbe:   GET /healthz

Prometheus scrape:
  scrape: GET /metrics
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import signal
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List

from aiohttp import web
from prometheus_client import (
    CollectorRegistry,
    CONTENT_TYPE_LATEST,
    Gauge,
    Counter,
    Histogram,
    generate_latest,
)

# ----------------------------
# JSON Logging
# ----------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach extras if present
        for key in ("service", "version", "correlation_id", "request_id"):
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = val
        # Exception info
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str, service: str, version: str) -> logging.Logger:
    logger = logging.getLogger("chronowatch.quickstart")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.handlers = [handler]
    # Attach default contextual info via LoggerAdapter
    return logging.LoggerAdapter(logger, {"service": service, "version": version})  # type: ignore


# ----------------------------
# Config
# ----------------------------
@dataclass
class AppConfig:
    service_name: str = "chronowatch-quickstart"
    version: str = "1.0.0"
    host: str = "0.0.0.0"
    port: int = 8080
    metrics_path: str = "/metrics"
    health_path: str = "/healthz"
    ready_path: str = "/readyz"
    log_level: str = "INFO"
    interval_sec: float = 2.0
    jobs: int = 2
    shutdown_timeout_sec: float = 15.0
    startup_probe_sec: float = 1.0
    enable_otel: bool = False
    otlp_endpoint: Optional[str] = None

    @staticmethod
    def from_env_and_args() -> "AppConfig":
        p = argparse.ArgumentParser(description="ChronoWatch Quickstart Runner")
        p.add_argument("--service-name", default=os.getenv("CHRONO_SERVICE_NAME", "chronowatch-quickstart"))
        p.add_argument("--version", default=os.getenv("CHRONO_VERSION", "1.0.0"))
        p.add_argument("--host", default=os.getenv("CHRONO_HOST", "0.0.0.0"))
        p.add_argument("--port", type=int, default=int(os.getenv("CHRONO_PORT", "8080")))
        p.add_argument("--metrics-path", default=os.getenv("CHRONO_METRICS_PATH", "/metrics"))
        p.add_argument("--health-path", default=os.getenv("CHRONO_HEALTH_PATH", "/healthz"))
        p.add_argument("--ready-path", default=os.getenv("CHRONO_READY_PATH", "/readyz"))
        p.add_argument("--log-level", default=os.getenv("CHRONO_LOG_LEVEL", "INFO"))
        p.add_argument("--interval", type=float, default=float(os.getenv("CHRONO_INTERVAL_SEC", "2.0")))
        p.add_argument("--jobs", type=int, default=int(os.getenv("CHRONO_JOBS", "2")))
        p.add_argument("--shutdown-timeout", type=float, default=float(os.getenv("CHRONO_SHUTDOWN_TIMEOUT_SEC", "15")))
        p.add_argument("--startup-probe", type=float, default=float(os.getenv("CHRONO_STARTUP_PROBE_SEC", "1.0")))
        p.add_argument("--enable-otel", action="store_true", default=os.getenv("CHRONO_ENABLE_OTEL", "false").lower() == "true")
        p.add_argument("--otlp-endpoint", default=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))

        args = p.parse_args()

        return AppConfig(
            service_name=args.service_name,
            version=args.version,
            host=args.host,
            port=args.port,
            metrics_path=args.metrics_path,
            health_path=args.health_path,
            ready_path=args.ready_path,
            log_level=args.log_level,
            interval_sec=args.interval,
            jobs=args.jobs,
            shutdown_timeout_sec=args.shutdown_timeout,
            startup_probe_sec=args.startup_probe,
            enable_otel=bool(args.enable_otel),
            otlp_endpoint=args.otlp_endpoint,
        )


# ----------------------------
# Optional OpenTelemetry
# ----------------------------
class OptionalTracer:
    """Safe wrapper: works even if OpenTelemetry not installed or disabled."""
    def __init__(self, enabled: bool, service: str, endpoint: Optional[str], logger: logging.Logger):
        self._enabled = enabled
        self._logger = logger
        self._tracer = None
        if enabled:
            try:
                from opentelemetry import trace
                from opentelemetry.sdk.resources import Resource
                from opentelemetry.sdk.trace import TracerProvider
                from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
                exporter = None
                if endpoint:
                    # Try OTLP; fall back to console exporter if failure
                    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
                    exporter = OTLPSpanExporter(endpoint=endpoint)
                else:
                    exporter = ConsoleSpanExporter()
                provider = TracerProvider(resource=Resource.create({"service.name": service}))
                provider.add_span_processor(BatchSpanProcessor(exporter))
                trace.set_tracer_provider(provider)
                self._tracer = trace.get_tracer(service)
                self._logger.info("OpenTelemetry enabled", extra={"request_id": "otel-init"})
            except Exception as e:
                self._enabled = False
                self._logger.error(f"OpenTelemetry initialization failed: {e}")
        else:
            self._logger.info("OpenTelemetry disabled")

    def span(self, name: str):
        if not self._enabled or self._tracer is None:
            return _NullSpan()
        return _RealSpan(self._tracer, name)


class _NullSpan:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def set_attribute(self, *_args, **_kwargs): pass


class _RealSpan:
    def __init__(self, tracer, name: str):
        self._tracer = tracer
        self._name = name
        self._span = None

    def __enter__(self):
        self._span = self._tracer.start_span(self._name)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._span is not None:
            if exc:
                self._span.set_attribute("error", True)
                self._span.set_attribute("exception.type", str(exc_type))
                self._span.set_attribute("exception.message", str(exc))
            self._span.end()
        return False

    def set_attribute(self, key: str, value: Any):
        if self._span is not None:
            try:
                self._span.set_attribute(key, value)
            except Exception:
                pass


# ----------------------------
# Metrics
# ----------------------------
class Metrics:
    def __init__(self, registry: CollectorRegistry):
        self.registry = registry
        # "up" gauge for standard monitoring
        self.up = Gauge("app_up", "Application up status (1=up)", registry=registry)
        # Heartbeat
        self.heartbeat = Gauge("app_heartbeat_unixtime", "Last heartbeat timestamp (unix)", registry=registry)
        # Info (labels are constant -> value always 1)
        self.info = Gauge("app_info", "Static app info", ["service", "version"], registry=registry)
        # Jobs metrics
        self.job_latency = Histogram(
            "job_latency_seconds",
            "Latency of background job execution (seconds)",
            ["job_id"],
            registry=registry,
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0),
        )
        self.job_success = Counter("job_success_total", "Total successful job runs", ["job_id"], registry=registry)
        self.job_errors = Counter("job_errors_total", "Total job errors", ["job_id"], registry=registry)
        # Requests metrics (for HTTP handlers)
        self.http_requests = Counter("http_requests_total", "HTTP requests", ["path", "status"], registry=registry)


# ----------------------------
# HTTP App (aiohttp)
# ----------------------------
def make_app(cfg: AppConfig, metrics: Metrics, logger: logging.Logger) -> web.Application:
    app = web.Application()

    async def handle_health(_request: web.Request) -> web.Response:
        metrics.http_requests.labels(path=cfg.health_path, status="200").inc()
        return web.json_response({"status": "ok", "service": cfg.service_name, "version": cfg.version})

    async def handle_ready(_request: web.Request) -> web.Response:
        # In a real system: check DB, queues, dependencies, warmups
        metrics.http_requests.labels(path=cfg.ready_path, status="200").inc()
        return web.json_response({"ready": True})

    async def handle_metrics(_request: web.Request) -> web.Response:
        output = generate_latest(metrics.registry)
        resp = web.Response(body=output)
        resp.content_type = CONTENT_TYPE_LATEST
        metrics.http_requests.labels(path=cfg.metrics_path, status="200").inc()
        return resp

    async def handle_info(_request: web.Request) -> web.Response:
        metrics.http_requests.labels(path="/info", status="200").inc()
        return web.json_response({"config": asdict(cfg)})

    app.router.add_get(cfg.health_path, handle_health)
    app.router.add_get(cfg.ready_path, handle_ready)
    app.router.add_get(cfg.metrics_path, handle_metrics)
    app.router.add_get("/info", handle_info)

    # Access logs through our structured logger
    async def on_startup(_app: web.Application):
        logger.info("HTTP server starting", extra={"request_id": "http-start"})

    async def on_cleanup(_app: web.Application):
        logger.info("HTTP server stopping", extra={"request_id": "http-stop"})

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


# ----------------------------
# Background Jobs
# ----------------------------
class JobRunner:
    def __init__(self, job_id: str, cfg: AppConfig, metrics: Metrics, tracer: OptionalTracer, logger: logging.Logger):
        self.job_id = job_id
        self.cfg = cfg
        self.metrics = metrics
        self.tracer = tracer
        self.logger = logger
        self._stopped = asyncio.Event()

    async def run(self):
        self.logger.info(f"Job {self.job_id} started")
        try:
            while not self._stopped.is_set():
                start = time.perf_counter()
                with self.tracer.span("job.run") as span:
                    span.set_attribute("job.id", self.job_id)
                    try:
                        # Simulated work: jitter and occasional error
                        await self._do_work()
                        elapsed = time.perf_counter() - start
                        self.metrics.job_latency.labels(job_id=self.job_id).observe(elapsed)
                        self.metrics.job_success.labels(job_id=self.job_id).inc()
                        self.logger.info(
                            f"Job {self.job_id} success",
                            extra={"request_id": f"job-{self.job_id}", "correlation_id": "job-loop"},
                        )
                    except Exception as e:
                        elapsed = time.perf_counter() - start
                        self.metrics.job_latency.labels(job_id=self.job_id).observe(elapsed)
                        self.metrics.job_errors.labels(job_id=self.job_id).inc()
                        self.logger.error(
                            f"Job {self.job_id} failed: {e}",
                            extra={"request_id": f"job-{self.job_id}", "correlation_id": "job-loop"},
                            exc_info=True,
                        )
                await asyncio.sleep(self.cfg.interval_sec)
        except asyncio.CancelledError:
            self.logger.info(f"Job {self.job_id} cancelled")
            raise
        finally:
            self.logger.info(f"Job {self.job_id} stopped")

    async def _do_work(self):
        # Simulate variable latency 5–300ms and a 2% error rate
        await asyncio.sleep(random.uniform(0.005, 0.30))
        if random.random() < 0.02:
            raise RuntimeError("simulated job error")

    def stop(self):
        self._stopped.set()


async def heartbeat_task(cfg: AppConfig, metrics: Metrics, logger: logging.Logger, stop_evt: asyncio.Event):
    logger.info("Heartbeat task started")
    try:
        while not stop_evt.is_set():
            now = time.time()
            metrics.heartbeat.set(now)
            await asyncio.sleep(max(0.5, min(cfg.interval_sec, 5.0)))
    except asyncio.CancelledError:
        logger.info("Heartbeat task cancelled")
        raise
    finally:
        logger.info("Heartbeat task stopped")


# ----------------------------
# Main Application
# ----------------------------
class Application:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.logger = setup_logging(cfg.log_level, cfg.service_name, cfg.version)
        self.registry = CollectorRegistry()
        self.metrics = Metrics(self.registry)
        self.tracer = OptionalTracer(cfg.enable_otel, cfg.service_name, cfg.otlp_endpoint, self.logger)
        self.http_runner: Optional[web.AppRunner] = None
        self.http_site: Optional[web.TCPSite] = None
        self.tasks: List[asyncio.Task] = []
        self.stop_event = asyncio.Event()

    async def start(self):
        self.logger.info("Starting application", extra={"request_id": "app-start"})
        self.metrics.up.set(1)
        self.metrics.info.labels(self.cfg.service_name, self.cfg.version).set(1)

        # HTTP
        app = make_app(self.cfg, self.metrics, self.logger)
        self.http_runner = web.AppRunner(app, access_log=None)
        await self.http_runner.setup()
        self.http_site = web.TCPSite(self.http_runner, host=self.cfg.host, port=self.cfg.port)
        await self.http_site.start()
        self.logger.info(f"HTTP server listening on {self.cfg.host}:{self.cfg.port}")

        # Background tasks
        hb = asyncio.create_task(heartbeat_task(self.cfg, self.metrics, self.logger, self.stop_event), name="heartbeat")
        self.tasks.append(hb)
        for i in range(self.cfg.jobs):
            jr = JobRunner(job_id=str(i + 1), cfg=self.cfg, metrics=self.metrics, tracer=self.tracer, logger=self.logger)
            t = asyncio.create_task(jr.run(), name=f"job-{i+1}")
            self.tasks.append(t)

        # Optional startup probe delay to let readiness stabilize
        await asyncio.sleep(max(0.0, self.cfg.startup_probe_sec))
        self.logger.info("Application started", extra={"request_id": "app-started"})

    async def stop(self):
        self.logger.info("Stopping application", extra={"request_id": "app-stop"})
        self.stop_event.set()
        # Cancel background tasks gracefully
        for t in self.tasks:
            t.cancel()
        with asyncio.timeout(self.cfg.shutdown_timeout_sec):
            for t in self.tasks:
                try:
                    await t
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    self.logger.error(f"Task error during shutdown: {e}", exc_info=True)

        # Stop HTTP
        if self.http_site:
            await self.http_site.stop()
        if self.http_runner:
            await self.http_runner.cleanup()

        self.metrics.up.set(0)
        self.logger.info("Application stopped", extra={"request_id": "app-stopped"})

    async def run_forever(self):
        loop = asyncio.get_running_loop()

        def _signal_handler(sig: signal.Signals):
            self.logger.info(f"Received signal: {sig.name}")
            asyncio.create_task(self.stop())

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _signal_handler, sig)
            except NotImplementedError:
                # On Windows, signals limited; rely on KeyboardInterrupt
                pass

        await self.start()
        try:
            while self.metrics.up._value.get() == 1:  # type: ignore[attr-defined]
                await asyncio.sleep(1.0)
        finally:
            # Ensure stop if loop exits unexpectedly
            if self.metrics.up._value.get() == 1:  # type: ignore[attr-defined]
                await self.stop()


# ----------------------------
# Entrypoint
# ----------------------------
def main():
    cfg = AppConfig.from_env_and_args()
    app = Application(cfg)

    async def runner():
        await app.run_forever()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        # Extra safety on Ctrl+C paths where signal handler may not fire
        pass
    except Exception as e:
        # Fatal
        logger = setup_logging(cfg.log_level, cfg.service_name, cfg.version)
        logger.error(f"Fatal: {e}", exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
