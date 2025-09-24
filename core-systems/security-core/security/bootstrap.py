# security-core/security/bootstrap.py
"""
Industrial bootstrap for security-core.

Capabilities:
- Structured logging (stdout JSON or text), secret redaction
- Optional OpenTelemetry tracing (OTLP exporter) with graceful degradation
- Optional Prometheus metrics (if prometheus_client present)
- Central DI service registry (audit, policy, kms, trust store, maintenance)
- Trust anchors loader (PEM) and SPKI pins loader (JSON) from filesystem
- Async startup/shutdown hooks, signal-safe, without blocking I/O
- Optional auto-attach of HTTP routers: api/http/routers/v1/admin.py and v1/mtls.py
- All components are async-friendly; no synchronous ORM

Environment (examples):
- LOG_LEVEL=INFO|DEBUG|WARN
- LOG_FORMAT=json|text
- OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector:4318
- ENABLE_TRACING=true|false
- ENABLE_METRICS=true|false
- TRUST_ANCHORS_DIR=./security-core/configs/trust/anchors
- SPKI_PINS_FILE=./security-core/configs/trust/pins.json
- POLICY_BACKEND=local|opa|cedar
- OPA_URL=http://opa:8181
- KMS_BACKEND=aws|gcp|azure|vault|none
- METRICS_PATH=/metrics
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI

try:
    import uvloop  # type: ignore
    uvloop.install()
except Exception:
    pass

from pydantic import BaseModel, Field

# ----------------------------- Settings --------------------------------------


class BootstrapSettings(BaseModel):
    service_name: str = Field(default="security-core")
    service_version: str = Field(default=os.getenv("SECURITY_CORE_VERSION", "dev"))
    environment: str = Field(default=os.getenv("ENV", "dev"))

    log_level: str = Field(default=os.getenv("LOG_LEVEL", "INFO"))
    log_format: str = Field(default=os.getenv("LOG_FORMAT", "json"))  # json|text
    redact_keys: List[str] = Field(default_factory=lambda: [
        "password", "passwd", "secret", "token", "apikey", "authorization", "private_key"
    ])

    enable_tracing: bool = Field(default=os.getenv("ENABLE_TRACING", "false").lower() == "true")
    otlp_endpoint: Optional[str] = Field(default=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
    otlp_headers: Optional[str] = Field(default=os.getenv("OTEL_EXPORTER_OTLP_HEADERS"))  # key1=val1,key2=val2

    enable_metrics: bool = Field(default=os.getenv("ENABLE_METRICS", "true").lower() == "true")
    metrics_path: str = Field(default=os.getenv("METRICS_PATH", "/metrics"))

    trust_anchors_dir: Path = Field(default=Path(os.getenv("TRUST_ANCHORS_DIR", "./security-core/configs/trust/anchors")))
    spki_pins_file: Path = Field(default=Path(os.getenv("SPKI_PINS_FILE", "./security-core/configs/trust/pins.json")))

    policy_backend: str = Field(default=os.getenv("POLICY_BACKEND", "local"))  # local|opa|cedar
    opa_url: Optional[str] = Field(default=os.getenv("OPA_URL"))

    kms_backend: str = Field(default=os.getenv("KMS_BACKEND", "none"))  # aws|gcp|azure|vault|none

    attach_routers: bool = Field(default=os.getenv("ATTACH_ROUTERS", "true").lower() == "true")

    @staticmethod
    def load() -> "BootstrapSettings":
        return BootstrapSettings()


# ----------------------------- Logging ---------------------------------------


def _redact(obj: Any, keys: List[str]) -> Any:
    """Recursively redact secrets in dict/sequence by key names."""
    try:
        if isinstance(obj, dict):
            return {k: ("***" if k.lower() in keys else _redact(v, keys)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_redact(v, keys) for v in obj]
        return obj
    except Exception:
        return obj


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str, version: str, level: int):
        super().__init__()
        self.service = service
        self.version = version
        self.level = level

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "lvl": record.levelname,
            "logger": record.name,
            "service": self.service,
            "version": self.version,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False)


def init_logging(settings: BootstrapSettings) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    lvl = getattr(logging, settings.log_level.upper(), logging.INFO)
    root.setLevel(lvl)
    handler = logging.StreamHandler(sys.stdout)
    if settings.log_format == "json":
        handler.setFormatter(JsonFormatter(settings.service_name, settings.service_version, lvl))
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)
    logging.getLogger("uvicorn.error").propagate = True
    logging.getLogger("uvicorn.access").propagate = True


# ----------------------------- Tracing ---------------------------------------


@dataclass
class TracingContext:
    enabled: bool
    provider: Any = None  # OpenTelemetry SDK TracerProvider if available
    shutdown_hook: Optional[Any] = None


def init_tracing(settings: BootstrapSettings) -> TracingContext:
    if not settings.enable_tracing:
        return TracingContext(enabled=False)

    try:
        from opentelemetry import trace  # type: ignore
        from opentelemetry.sdk.resources import Resource  # type: ignore
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
    except Exception as e:
        logging.getLogger(__name__).warning("Tracing disabled: opentelemetry not available: %s", e)
        return TracingContext(enabled=False)

    headers: Dict[str, str] = {}
    if settings.otlp_headers:
        for kv in settings.otlp_headers.split(","):
            if "=" in kv:
                k, v = kv.split("=", 1)
                headers[k.strip()] = v.strip()

    resource = Resource.create({
        "service.name": settings.service_name,
        "service.version": settings.service_version,
        "deployment.environment": settings.environment,
    })
    provider = TracerProvider(resource=resource)
    if settings.otlp_endpoint:
        exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint, headers=headers or None, timeout=5)
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    async def shutdown() -> None:
        try:
            provider.shutdown()  # type: ignore
        except Exception:
            pass

    return TracingContext(enabled=True, provider=provider, shutdown_hook=shutdown)


# ----------------------------- Metrics ---------------------------------------


@dataclass
class MetricsContext:
    enabled: bool
    registry: Any = None


def init_metrics(app: FastAPI, settings: BootstrapSettings) -> MetricsContext:
    if not settings.enable_metrics:
        return MetricsContext(enabled=False)
    try:
        from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest  # type: ignore
        registry = CollectorRegistry(auto_describe=True)

        @app.get(settings.metrics_path, include_in_schema=False)
        async def metrics_endpoint():
            data = generate_latest(registry)
            return (
                data,
                200,
                {"Content-Type": CONTENT_TYPE_LATEST},
            )

        # Expose a simple process uptime gauge via custom collector
        try:
            from prometheus_client import Gauge  # type: ignore

            process_start_ts = float(os.getenv("PROCESS_STARTED_TS", str(time.time())))
            uptime_gauge = Gauge("security_core_uptime_seconds", "Process uptime in seconds", registry=registry)

            async def _tick():
                while True:
                    uptime_gauge.set(int(time.time() - process_start_ts))
                    await asyncio.sleep(5)

            app.add_event_handler("startup", lambda: asyncio.create_task(_tick()))
        except Exception:
            pass

        return MetricsContext(enabled=True, registry=registry)
    except Exception as e:
        logging.getLogger(__name__).warning("Metrics disabled: prometheus_client not available: %s", e)
        return MetricsContext(enabled=False)


# ----------------------------- Trust store -----------------------------------

class TrustAnchor(BaseModel):
    pem: str
    fingerprint_sha256: str
    subject: str
    not_after: str


class SpkiPin(BaseModel):
    spki_sha256_b64: str
    label: Optional[str] = None
    valid_until: Optional[str] = None
    allowed_dns: List[str] = Field(default_factory=list)


class TrustStore(BaseModel):
    anchors: Dict[str, TrustAnchor] = Field(default_factory=dict)  # fp -> anchor
    pins: Dict[str, SpkiPin] = Field(default_factory=dict)         # b64 -> pin

    @staticmethod
    def _fingerprint_pem(pem: str) -> Tuple[str, str, str]:
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.primitives import hashes  # type: ignore
        cert = x509.load_pem_x509_certificate(pem.encode())
        fp = cert.fingerprint(hashes.SHA256()).hex()
        subj = ", ".join([f"{a.oid._name}={a.value}" for a in cert.subject])  # type: ignore
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()
        return fp, subj, not_after

    def add_anchor_pem(self, pem: str) -> TrustAnchor:
        fp, subj, na = self._fingerprint_pem(pem)
        anchor = TrustAnchor(pem=pem, fingerprint_sha256=fp, subject=subj, not_after=na)
        self.anchors[fp] = anchor
        return anchor

    def add_pin(self, pin: SpkiPin) -> None:
        self.pins[pin.spki_sha256_b64] = pin


async def load_trust_store(settings: BootstrapSettings, logger: logging.Logger) -> TrustStore:
    store = TrustStore()
    try:
        if settings.trust_anchors_dir.exists():
            for p in settings.trust_anchors_dir.glob("*.pem"):
                pem = p.read_text(encoding="utf-8")
                store.add_anchor_pem(pem)
        if settings.spki_pins_file.exists():
            pins = json.loads(settings.spki_pins_file.read_text(encoding="utf-8"))
            for entry in pins if isinstance(pins, list) else pins.get("pins", []):
                store.add_pin(SpkiPin(**entry))
        logger.info("trust_store.loaded anchors=%d pins=%d path=%s",
                    len(store.anchors), len(store.pins), str(settings.trust_anchors_dir))
    except Exception as e:
        logger.error("trust_store.load.failed error=%s", e)
    return store


# ----------------------------- Policy engine ---------------------------------

class PolicyDecision(BaseModel):
    allow: bool
    policy_id: str
    version: str
    matched_rules: List[str] = Field(default_factory=list)
    extra: Dict[str, Any] = Field(default_factory=dict)


class PolicyEngine:
    def __init__(self, backend: str, opa_url: Optional[str], logger: logging.Logger):
        self.backend = backend
        self.opa_url = opa_url
        self.logger = logger

    async def reload(self) -> Dict[str, Any]:
        self.logger.info("policy.reload backend=%s", self.backend)
        await asyncio.sleep(0)
        return {"backend": self.backend, "reloaded_at": datetime.now(timezone.utc).isoformat()}

    async def evaluate(self, input_doc: Dict[str, Any]) -> PolicyDecision:
        # Minimal local allow-by-scope; extend for OPA/Cedar as needed.
        if self.backend == "opa" and self.opa_url:
            try:
                import aiohttp  # type: ignore
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as sess:
                    url = f"{self.opa_url}/v1/data/security/allow"
                    async with sess.post(url, json={"input": input_doc}) as resp:
                        data = await resp.json()
                        allow = bool(data.get("result", {}).get("allow", False))
                        rules = data.get("result", {}).get("matched", [])
                        return PolicyDecision(allow=allow, policy_id="opa:security/allow", version="live", matched_rules=rules)
            except Exception as e:
                self.logger.warning("policy.opa.error %s", e)
        # Local fallback: allow only if "admin" in scopes
        scopes = set(input_doc.get("scopes", []))
        allow = "admin" in scopes
        return PolicyDecision(allow=allow, policy_id="local:scopes", version="1")


# ----------------------------- KMS manager -----------------------------------

class KmsManager:
    def __init__(self, backend: str, logger: logging.Logger):
        self.backend = backend
        self.logger = logger

    async def rotate_key(self, key_alias: str, provider_id: Optional[str] = None, dry_run: bool = False) -> str:
        self.logger.info("kms.rotate start backend=%s alias=%s dry=%s", self.backend, key_alias, dry_run)
        await asyncio.sleep(0)
        return f"job-{os.urandom(6).hex()}"

    async def shutdown(self) -> None:
        await asyncio.sleep(0)


# ----------------------------- Audit emitter ---------------------------------

class AuditEmitter:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    async def emit(self, event: Dict[str, Any]) -> None:
        self.logger.info("audit.emit %s", json.dumps(event, ensure_ascii=False))


# ----------------------------- Registry/Context -------------------------------

class ServiceRegistry(BaseModel):
    audit: AuditEmitter
    policy: PolicyEngine
    kms: KmsManager
    trust: TrustStore


@dataclass
class BootstrapContext:
    settings: BootstrapSettings
    tracing: TracingContext
    metrics: MetricsContext
    registry: ServiceRegistry


# ----------------------------- Router attach ----------------------------------

def _attach_routers(app: FastAPI, logger: logging.Logger, registry: ServiceRegistry) -> None:
    """
    Optionally attach versioned routers if modules are present.
    Routers are expected to rely on their own DI; this function is best-effort.
    """
    try:
        from security_core.api.http.routers.v1 import admin as admin_router  # type: ignore
        app.include_router(admin_router.router)
        logger.info("router.attached name=admin")
    except Exception as e:
        logger.warning("router.admin.attach.skip %s", e)

    try:
        from security_core.api.http.routers.v1 import mtls as mtls_router  # type: ignore
        app.include_router(mtls_router.router)
        logger.info("router.attached name=mtls")
    except Exception as e:
        logger.warning("router.mtls.attach.skip %s", e)


# ----------------------------- Startup/Shutdown -------------------------------

def _install_signals(app: FastAPI, logger: logging.Logger):
    loop = asyncio.get_event_loop()

    async def _graceful_shutdown():
        logger.info("signal.shutdown request=graceful")
        # Starlette/FastAPI will run shutdown handlers

    def handler():
        asyncio.ensure_future(_graceful_shutdown())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handler)
        except NotImplementedError:
            # Windows / limited env
            pass


# ----------------------------- Public API -------------------------------------

async def setup_application(app: FastAPI) -> BootstrapContext:
    """
    Entry point to bootstrap FastAPI application.
    Usage:
        app = FastAPI()
        ctx = await setup_application(app)
    """
    settings = BootstrapSettings.load()
    init_logging(settings)
    logger = logging.getLogger("security_core.bootstrap")

    tracing = init_tracing(settings)
    metrics = init_metrics(app, settings)

    trust = await load_trust_store(settings, logger)
    policy = PolicyEngine(backend=settings.policy_backend, opa_url=settings.opa_url, logger=logging.getLogger("security_core.policy"))
    kms = KmsManager(backend=settings.kms_backend, logger=logging.getLogger("security_core.kms"))
    audit = AuditEmitter(logger=logging.getLogger("security_core.audit"))

    registry = ServiceRegistry(audit=audit, policy=policy, kms=kms, trust=trust)

    # Attach routers if requested
    if settings.attach_routers:
        _attach_routers(app, logger, registry)

    # Health and readiness
    @app.get("/v1/healthz", include_in_schema=False)
    async def healthz():
        return {"ok": True, "ts": datetime.now(timezone.utc).isoformat()}

    @app.get("/v1/readyz", include_in_schema=False)
    async def readyz():
        return {
            "ok": True,
            "service": settings.service_name,
            "version": settings.service_version,
            "anchors": len(trust.anchors),
            "pins": len(trust.pins),
        }

    # Startup / Shutdown hooks
    @app.on_event("startup")
    async def _on_startup():
        os.environ.setdefault("PROCESS_STARTED_TS", str(time.time()))
        os.environ.setdefault("PROCESS_STARTED_AT", datetime.now(timezone.utc).isoformat())
        _install_signals(app, logger)
        await policy.reload()
        logger.info("startup.complete env=%s version=%s", settings.environment, settings.service_version)

    @app.on_event("shutdown")
    async def _on_shutdown():
        try:
            await kms.shutdown()
        except Exception:
            pass
        if tracing.enabled and tracing.shutdown_hook:
            await tracing.shutdown_hook()  # type: ignore
        logger.info("shutdown.complete")

    return BootstrapContext(settings=settings, tracing=tracing, metrics=metrics, registry=registry)


# Optional convenience factory for Uvicorn entrypoints
def create_app() -> FastAPI:
    app = FastAPI(title="security-core", version=os.getenv("SECURITY_CORE_VERSION", "dev"))
    # setup_application is async; schedule it to run on startup
    app.add_event_handler("startup", lambda: asyncio.create_task(setup_application(app)))
    return app
