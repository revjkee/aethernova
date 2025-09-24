# SPDX-License-Identifier: MIT
"""
VeilMind Core — industrial settings loader (Pydantic v2)

Layers & precedence (highest first):
  1) Environment variables (prefix=VEILMIND_, nested delimiter="__")
  2) Env override YAML (configs/env/{ENVIRONMENT}.yaml) — optional
  3) Base YAML (configs/veilmind.yaml) — optional
  4) Built-in defaults (in-code)

Hot reload:
  - Optional watchdog observer on config files; thread-safe swap-in.

Secrets:
  - Direct providers: env, local file (YAML). Vault interface stub (sync/async ready).

Usage:
    from veilmind.settings import settings, setup_logging, hot_reload
    cfg = settings()            # singleton
    setup_logging(cfg)          # apply logging config

    # Start hot reload watcher (optional):
    stop = hot_reload()         # returns a callable to stop watcher

ENV tips:
    VEILMIND__SERVER__HTTP__PORT=8080
    VEILMIND__SECURITY__TLS__ENABLED=true
    VEILMIND__OBSERVABILITY__TRACING__OTLP__ENDPOINT=http://otel:4317
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import logging
import os
import pathlib
import re
import threading
import time
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple, Union

from pydantic import BaseModel, AnyUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Optional dependencies
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

try:
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler  # type: ignore
    _WATCHDOG = True
except Exception:  # pragma: no cover
    _WATCHDOG = False

# ------------------------------- util helpers ---------------------------------


def _deep_merge(dst: Dict[str, Any], src: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge src into dst (mutates dst). Scalars & lists are replaced, dicts merged.
    """
    for k, v in src.items():
        if isinstance(v, Mapping) and isinstance(dst.get(k), Mapping):
            _deep_merge(dst[k], v)  # type: ignore[index]
        else:
            dst[k] = copy.deepcopy(v)
    return dst


def _load_yaml(path: pathlib.Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    if yaml is None:
        raise RuntimeError(f"PyYAML is required to read {path}")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Top-level YAML in {path} must be a mapping")
        return data


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")


def _hash_public(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# --------------------------------- models -------------------------------------

# --- Metadata -----------------------------------------------------------------

class BuildInfo(BaseModel):
    git_commit: str = "unknown"
    git_branch: str = "unknown"
    build_at: str = "unknown"


class ServiceMeta(BaseModel):
    name: str = "veilmind-core"
    component: str = "api-gateway"
    owner: str = "platform@company.tld"
    team: str = "platform"
    domain: str = "veilmind"
    environment: Literal["dev", "stage", "prod"] = "dev"

    @field_validator("name", "component", "team", "domain", mode="before")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class Metadata(BaseModel):
    service: ServiceMeta = ServiceMeta()
    build: BuildInfo = BuildInfo()
    labels: Dict[str, str] = Field(default_factory=lambda: {
        "app.kubernetes.io/part-of": "veilmind",
        "app.kubernetes.io/component": "core",
        "security.tier": "critical",
        "data.classification": "confidential",
    })


# --- Server -------------------------------------------------------------------

class CORS(BaseModel):
    enabled: bool = True
    allow_origins: List[str] = Field(default_factory=lambda: ["https://app.example.com"])
    allow_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    allow_headers: List[str] = Field(default_factory=lambda: ["Authorization", "Content-Type", "X-Request-ID"])
    expose_headers: List[str] = Field(default_factory=lambda: ["X-Request-ID", "Retry-After"])
    allow_credentials: bool = False
    max_age: int = 600


class RatePolicy(BaseModel):
    id: str
    selector: str = 'route:"/api/*"'
    capacity: int = 1000
    refill_per_sec: int = 200
    burst: int = 200

    @field_validator("capacity", "refill_per_sec", "burst")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError("must be >= 0")
        return v


class RateLimit(BaseModel):
    enabled: bool = True
    policies: List[RatePolicy] = Field(default_factory=list)


class HSTS(BaseModel):
    enabled: bool = True
    max_age_seconds: int = 31536000
    include_subdomains: bool = True
    preload: bool = True


class HTTPTimeouts(BaseModel):
    read: float = 10.0
    write: float = 20.0
    idle: float = 60.0
    header: float = 5.0


class HTTP(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8080
    timeouts: HTTPTimeouts = HTTPTimeouts()
    cors: CORS = CORS()
    rate_limit: RateLimit = RateLimit()
    hsts: HSTS = HSTS()

    @field_validator("port")
    @classmethod
    def _port_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("port must be 1..65535")
        return v


class GRPCKeepAlive(BaseModel):
    time: float = 30.0
    timeout: float = 5.0
    permit_without_stream: bool = False


class GRPC(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 9090
    keepalive: GRPCKeepAlive = GRPCKeepAlive()
    max_concurrent_streams: int = 1024
    max_recv_msg_mb: int = 16
    max_send_msg_mb: int = 16


class Server(BaseModel):
    http: HTTP = HTTP()
    grpc: GRPC = GRPC()


# --- Security -----------------------------------------------------------------

class MTLSRef(BaseModel):
    provider: Literal["vault", "file", "env"] = "vault"
    crt_path: str = "pki/issue/veilmind-core"
    key_path: str = "pki/private/veilmind-core"


class MTLS(BaseModel):
    enabled: bool = True
    mode: Literal["require_and_verify_client_cert"] = "require_and_verify_client_cert"
    trust_store: Dict[str, str] = Field(default_factory=lambda: {"provider": "vault", "path": "pki/ca_bundle.pem"})
    cert_ref: MTLSRef = MTLSRef()
    rotation: Dict[str, Union[bool, int, float]] = Field(default_factory=lambda: {
        "enabled": True, "check_interval": 600.0, "renew_before": 259200.0
    })


class TLS(BaseModel):
    enabled: bool = True
    min_version: Literal["TLS1_2", "TLS1_3"] = "TLS1_3"
    curve_preferences: List[str] = Field(default_factory=lambda: ["X25519", "P-256"])
    cipher_suites: List[str] = Field(default_factory=list)
    mtls: MTLS = MTLS()


class OIDCSecretRef(BaseModel):
    provider: Literal["secretManager", "vault", "env", "file"] = "secretManager"
    key: str = "oidc/veilmind-core"


class OIDC(BaseModel):
    enabled: bool = True
    issuer: str = "https://auth.example.com/"
    client_id: str = "veilmind-core"
    client_secret_ref: OIDCSecretRef = OIDCSecretRef()
    jwks_cache_ttl: float = 600.0
    allowed_alg: List[str] = Field(default_factory=lambda: ["RS256", "ES256"])

    @field_validator("issuer")
    @classmethod
    def _issuer_https(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("OIDC issuer must be https://")
        return v


class JWT(BaseModel):
    enabled: bool = True
    audiences: List[str] = Field(default_factory=lambda: ["veilmind-core", "veilmind"])
    required_scopes: List[str] = Field(default_factory=lambda: ["api.read", "api.write"])
    leeway: float = 30.0


class ZeroTrust(BaseModel):
    intent_validation: bool = True
    strict_transport_security: bool = True
    disable_plain_http: bool = True
    jwt_audience_check: bool = True
    jwt_azp_check: bool = True
    enforce_pinned_ca: bool = True


class RBACRole(BaseModel):
    name: str
    allow: List[str] = Field(default_factory=list)


class AttributePolicy(BaseModel):
    name: str
    when: Dict[str, str] = Field(default_factory=dict)
    deny_if_missing: bool = True


class RBAC(BaseModel):
    default_role: str = "viewer"
    roles: List[RBACRole] = Field(default_factory=lambda: [
        RBACRole(name="viewer", allow=["GET:/api/*"]),
        RBACRole(name="editor", allow=["GET:/api/*", "POST:/api/*", "PUT:/api/*", "PATCH:/api/*"]),
        RBACRole(name="admin", allow=["*:*"]),
    ])
    attribute_policies: List[AttributePolicy] = Field(default_factory=lambda: [
        AttributePolicy(name="tenant_isolation", when={"match_claim": "tenant_id"}, deny_if_missing=True)
    ])


class Headers(BaseModel):
    secure: List[Dict[str, str]] = Field(default_factory=lambda: [
        {"name": "X-Content-Type-Options", "value": "nosniff"},
        {"name": "X-Frame-Options", "value": "DENY"},
        {"name": "Referrer-Policy", "value": "no-referrer"},
        {"name": "Permissions-Policy", "value": "geolocation=(), microphone=()"},
        {"name": "X-XSS-Protection", "value": "0"},
    ])


class Security(BaseModel):
    zero_trust: ZeroTrust = ZeroTrust()
    tls: TLS = TLS()
    authn: Dict[str, Any] = Field(default_factory=lambda: {"oidc": OIDC().model_dump(), "jwt": JWT().model_dump()})
    authz: RBAC = RBAC()
    headers: Headers = Headers()

    @model_validator(mode="after")
    def _prod_requires_tls(self) -> "Security":
        env = os.getenv("ENVIRONMENT", "dev").lower()
        if env == "prod" and not self.tls.enabled:
            raise ValueError("TLS must be enabled in prod")
        return self


# --- Observability -------------------------------------------------------------

class LoggingDestination(BaseModel):
    type: Literal["stdout", "loki"] = "stdout"
    url: Optional[AnyUrl] = None
    labels: Dict[str, str] = Field(default_factory=dict)


class Logging(BaseModel):
    level: Literal["TRACE", "DEBUG", "INFO", "WARN", "ERROR"] = "INFO"
    format: Literal["json", "text"] = "json"
    include_caller: bool = True
    sanitize_fields: List[str] = Field(default_factory=lambda: ["password", "token", "authorization", "set-cookie"])
    sampling: Dict[str, Union[bool, int]] = Field(default_factory=lambda: {"enabled": True, "initial": 5, "thereafter": 100})
    destinations: List[LoggingDestination] = Field(default_factory=lambda: [LoggingDestination(type="stdout")])


class OTLP(BaseModel):
    endpoint: str = "http://otel-collector:4317"
    protocol: Literal["grpc", "http/protobuf"] = "grpc"


class Tracing(BaseModel):
    enabled: bool = True
    exporter: Literal["otlp"] = "otlp"
    otlp: OTLP = OTLP()
    sampler: Dict[str, Union[str, float]] = Field(default_factory=lambda: {
        "type": "parentbased_traceidratio", "ratio": 0.10
    })
    service_name: str = "veilmind-core"
    resource: Dict[str, str] = Field(default_factory=lambda: {
        "service.version": os.getenv("SERVICE_VERSION", "0.0.0"),
        "deployment.environment": os.getenv("ENVIRONMENT", "dev"),
    })


class Metrics(BaseModel):
    enabled: bool = True
    port: int = 9102
    path: str = "/metrics"
    runtime: Dict[str, bool] = Field(default_factory=lambda: {"process": True, "go": True, "jvm": False})
    custom_labels: Dict[str, str] = Field(default_factory=lambda: {"service": "veilmind-core", "env": os.getenv("ENVIRONMENT", "dev")})


class Profiling(BaseModel):
    enabled: bool = True
    pprof: Dict[str, Union[str, int]] = Field(default_factory=lambda: {"host": "0.0.0.0", "port": 6060})


class Observability(BaseModel):
    logging: Logging = Logging()
    tracing: Tracing = Tracing()
    metrics: Metrics = Metrics()
    profiling: Profiling = Profiling()


# --- Resiliency ---------------------------------------------------------------

class Backoff(BaseModel):
    kind: Literal["exponential", "full_jitter"] = "exponential"
    base: float = 0.1
    max: float = 2.0


class Retries(BaseModel):
    attempts: int = 3
    per_try_timeout: float = 2.0
    backoff: Backoff = Backoff()
    retry_on: List[str] = Field(default_factory=lambda: ["5xx", "connect-failure", "retriable-4xx"])


class CircuitBreaker(BaseModel):
    enabled: bool = True
    failure_rate_threshold: int = 50
    slow_call_rate_threshold: int = 50
    slow_call_duration_threshold: float = 2.0
    sliding_window_size: int = 20
    sliding_window_type: Literal["count", "time"] = "count"
    permitted_calls_in_half_open: int = 5
    wait_duration_in_open_state: float = 30.0


class Bulkhead(BaseModel):
    enabled: bool = True
    max_concurrent_calls: int = 256
    max_queue_size: int = 1024


class Timeouts(BaseModel):
    connect: float = 2.0
    request: float = 3.0
    upstream: float = 5.0


class Resiliency(BaseModel):
    timeouts: Timeouts = Timeouts()
    retries: Retries = Retries()
    circuit_breaker: CircuitBreaker = CircuitBreaker()
    bulkhead: Bulkhead = Bulkhead()


# --- Data ---------------------------------------------------------------------

class Migration(BaseModel):
    enabled: bool = True
    dir: str = "/app/migrations"
    on_start: Literal["up", "none"] = "up"


class Postgres(BaseModel):
    enabled: bool = True
    dsn: str = "postgresql://veilmind:${PG_PASSWORD}@postgres:5432/veilmind?sslmode=verify-full"
    max_open_conns: int = 50
    max_idle_conns: int = 10
    conn_max_lifetime: float = 1800.0
    conn_max_idle_time: float = 600.0
    migration: Migration = Migration()


class Redis(BaseModel):
    enabled: bool = True
    addr: str = "redis:6379"
    db: int = 0
    tls: bool = True
    username: str = ""
    password_ref: Dict[str, str] = Field(default_factory=lambda: {"provider": "secretManager", "key": "redis/veilmind-core"})
    pool_size: int = 50
    min_idle_conns: int = 5
    dial_timeout: float = 1.0
    read_timeout: float = 0.5
    write_timeout: float = 0.5


class KafkaSASL(BaseModel):
    enabled: bool = False
    mechanism: Literal["SCRAM-SHA-256", "SCRAM-SHA-512", "PLAIN"] = "SCRAM-SHA-256"
    username: str = ""
    password_ref: Dict[str, str] = Field(default_factory=lambda: {"provider": "secretManager", "key": "kafka/veilmind-core"})


class KafkaTLS(BaseModel):
    enabled: bool = True
    insecure_skip_verify: bool = False


class KafkaProducer(BaseModel):
    acks: Literal["all", "leader", "none"] = "all"
    compression: Literal["none", "gzip", "snappy", "lz4", "zstd"] = "snappy"
    batch_size: int = 1_048_576
    linger_ms: int = 5


class KafkaConsumer(BaseModel):
    group_id: str = "veilmind-core"
    session_timeout_ms: int = 10000
    auto_offset_reset: Literal["earliest", "latest", "none"] = "latest"


class Kafka(BaseModel):
    enabled: bool = True
    brokers: str = "kafka-0:9092,kafka-1:9092"
    client_id: str = "veilmind-core"
    tls: KafkaTLS = KafkaTLS()
    sasl: KafkaSASL = KafkaSASL()
    topics: Dict[str, str] = Field(default_factory=lambda: {"in_events": "veilmind.events.in", "out_events": "veilmind.events.out"})
    producer: KafkaProducer = KafkaProducer()
    consumer: KafkaConsumer = KafkaConsumer()


class Data(BaseModel):
    postgres: Postgres = Postgres()
    redis: Redis = Redis()
    kafka: Kafka = Kafka()


# --- Other blocks -------------------------------------------------------------

class Cache(BaseModel):
    default_ttl: float = 300.0
    negative_ttl: float = 30.0
    max_object_size_kb: int = 256


class Pagination(BaseModel):
    default_limit: int = 50
    max_limit: int = 1000


class RequestID(BaseModel):
    header: str = "X-Request-ID"
    generate_if_missing: bool = True


class API(BaseModel):
    base_path: str = "/api"
    pagination: Pagination = Pagination()
    request_id: RequestID = RequestID()


class QuotaLimit(BaseModel):
    selector: str
    limit: int


class Quotas(BaseModel):
    enabled: bool = True
    window: float = 60.0
    limits: List[QuotaLimit] = Field(default_factory=lambda: [
        QuotaLimit(selector='tenant_id:"*"', limit=10000),
        QuotaLimit(selector='sub:"*"', limit=3000),
    ])


class PIIRedactionStrategy(BaseModel):
    json_paths: List[str]
    mode: Literal["hash", "remove"]


class PIIRedaction(BaseModel):
    enabled: bool = True
    strategies: List[PIIRedactionStrategy] = Field(default_factory=lambda: [
        PIIRedactionStrategy(json_paths=["$.email", "$.phone", "$.ssn"], mode="hash"),
        PIIRedactionStrategy(json_paths=["$.password", "$.token"], mode="remove"),
    ])


class Privacy(BaseModel):
    pii_redaction: PIIRedaction = PIIRedaction()


class Features(BaseModel):
    flags: Dict[str, Union[bool, str, int, float]] = Field(default_factory=dict)
    dynamic_reload: Dict[str, Union[bool, float]] = Field(default_factory=lambda: {"enabled": True, "watch_interval": 10.0})


class VaultProvider(BaseModel):
    address: str = "http://vault:8200"
    namespace: str = ""
    auth: Dict[str, str] = Field(default_factory=lambda: {"method": "approle", "role_id": "", "secret_id_env": "VAULT_SECRET_ID"})
    tls: Dict[str, Union[bool, str]] = Field(default_factory=lambda: {"verify": True})


class SecretManagerProvider(BaseModel):
    provider: Literal["gcp"] = "gcp"
    project_id: str = "project"
    auth: Dict[str, str] = Field(default_factory=lambda: {"method": "workload_identity"})
    cache_ttl: float = 300.0


class SecretsProviders(BaseModel):
    vault: VaultProvider = VaultProvider()
    secretManager: SecretManagerProvider = SecretManagerProvider()


class SLOs(BaseModel):
    availability: Dict[str, Union[int, float, str]] = Field(default_factory=lambda: {"target": 99.95, "window": "30d"})
    latency: Dict[str, float] = Field(default_factory=lambda: {"http_p99_seconds": 0.8, "http_p95_seconds": 0.4})
    error_budget: Dict[str, Any] = Field(default_factory=lambda: {"policy": {"fast_burn_alert_minutes": 5, "slow_burn_alert_hours": 6}})


class SchemaCtl(BaseModel):
    validate_on_start: bool = True
    fail_fast: bool = True
    allowed_environments: List[str] = Field(default_factory=lambda: ["dev", "stage", "prod"])


# --- Root settings ------------------------------------------------------------

class Settings(BaseSettings):
    # Meta
    version: int = 1
    metadata: Metadata = Metadata()

    # Blocks
    server: Server = Server()
    security: Security = Security()
    observability: Observability = Observability()
    resiliency: Resiliency = Resiliency()
    data: Data = Data()
    cache: Cache = Cache()
    api: API = API()
    quotas: Quotas = Quotas()
    privacy: Privacy = Privacy()
    features: Features = Features()
    secrets: SecretsProviders = SecretsProviders()
    slos: SLOs = SLOs()
    schema: SchemaCtl = SchemaCtl()

    # Informational
    active_profile: Literal["dev", "stage", "prod"] = Field(default_factory=lambda: os.getenv("ENVIRONMENT", "dev"))  # not used for selection here

    # Configuration for pydantic-settings
    model_config = SettingsConfigDict(
        case_sensitive=False,
        env_prefix="VEILMIND_",
        env_nested_delimiter="__",
        extra="ignore",
        validate_assignment=True,
    )

    # -------- validation & post-processing --------

    @model_validator(mode="after")
    def _validate_env(self) -> "Settings":
        env = os.getenv("ENVIRONMENT", self.metadata.service.environment).lower()
        if env not in self.schema.allowed_environments:
            raise ValueError(f"ENVIRONMENT={env} not in allowed {self.schema.allowed_environments}")
        # Prod guards
        if env == "prod":
            if not self.security.tls.enabled:
                raise ValueError("TLS must be enabled in prod")
            # CORS sanity
            if self.server.http.cors.enabled and "*" in self.server.http.cors.allow_origins:
                raise ValueError("Wildcard CORS origins are forbidden in prod")
        return self

    # Derived helpers
    def is_dev(self) -> bool:
        return self.metadata.service.environment.lower() == "dev"

    def as_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=False)

    def public_fingerprint(self) -> str:
        return _hash_public(json.dumps(self.as_dict(), sort_keys=True))


# ------------------------------ file resolution --------------------------------

_BASE_CONF_ENV = os.getenv("VEILMIND_CONFIG_PATH", "configs/veilmind.yaml")
_ENV_NAME = os.getenv("ENVIRONMENT", os.getenv("VEILMIND_ENV", "dev")).lower()
_ENV_CONF_ENV = os.getenv("VEILMIND_ENV_CONFIG_PATH", f"configs/env/{_ENV_NAME}.yaml")

_CONF_PATHS = [pathlib.Path(_BASE_CONF_ENV), pathlib.Path(_ENV_CONF_ENV)]


def _load_layers() -> Dict[str, Any]:
    """
    Load base YAML then env YAML; return merged mapping.
    """
    merged: Dict[str, Any] = {}
    for p in _CONF_PATHS:
        with contextlib.suppress(FileNotFoundError):
            data = _load_yaml(p)
            # Support 'profiles' like in veilmind.yaml: pick by ENVIRONMENT if present
            if "profiles" in data and isinstance(data["profiles"], Mapping):
                profile = _ENV_NAME
                base_defaults = data.get("_defaults") or {}
                profile_data = data["profiles"].get(profile) or {}
                staged = {}
                if isinstance(base_defaults, Mapping):
                    _deep_merge(staged, base_defaults)  # defaults
                if isinstance(profile_data, Mapping):
                    _deep_merge(staged, profile_data)   # overlay
                data = _deep_merge(copy.deepcopy(data), staged)
                # strip helpers
                data.pop("profiles", None)
                data.pop("_defaults", None)
            _deep_merge(merged, data)
    return merged


# --------------------------- settings singleton --------------------------------

_lock = threading.RLock()
_singleton: Optional[Settings] = None
_loaded_config_snapshot: Dict[str, Any] = {}
_watcher: Optional["Observer"] = None


def settings() -> Settings:
    """
    Lazy singleton. Loads YAML layers then applies ENV overrides via BaseSettings.
    """
    global _singleton, _loaded_config_snapshot
    with _lock:
        if _singleton is not None:
            return _singleton

        file_cfg = _load_layers()
        _loaded_config_snapshot = copy.deepcopy(file_cfg)
        # Feed file config as 'init_settings'; env overrides are automatic
        _singleton = Settings(**file_cfg)
        return _singleton


# ------------------------------- hot reload -----------------------------------

class _ReloadHandler(FileSystemEventHandler):  # type: ignore[misc]
    def on_any_event(self, event):  # pragma: no cover
        # debounced reload
        now = time.time()
        if not hasattr(self, "_last") or now - getattr(self, "_last") > 0.5:
            setattr(self, "_last", now)
            try:
                reload_settings()
                logging.getLogger("veilmind.settings").info("Configuration hot-reloaded")
            except Exception as e:  # do not crash watcher
                logging.getLogger("veilmind.settings").exception("Hot reload failed: %s", e)


def hot_reload(paths: Optional[List[str]] = None) -> Optional[callable]:
    """
    Start file watchers for given paths (defaults to base/env config files).
    Returns a callable to stop the watcher, or None if watchdog unavailable.
    """
    if not _WATCHDOG:  # pragma: no cover
        return None
    global _watcher
    with _lock:
        if _watcher is not None:
            return lambda: None
        watch_paths = [str(p) for p in (paths or _CONF_PATHS) if pathlib.Path(p).exists()]
        if not watch_paths:
            return None
        observer = Observer()
        handler = _ReloadHandler()
        for p in watch_paths:
            observer.schedule(handler, str(pathlib.Path(p).parent), recursive=False)
        observer.daemon = True
        observer.start()
        _watcher = observer

        def _stop():
            with contextlib.suppress(Exception):
                observer.stop()
                observer.join(timeout=2.0)
            with _lock:
                globals()["_watcher"] = None

        return _stop


def reload_settings() -> Settings:
    """
    Force re-read of YAML layers and rebuild singleton (thread-safe).
    """
    global _singleton, _loaded_config_snapshot
    with _lock:
        file_cfg = _load_layers()
        _loaded_config_snapshot = copy.deepcopy(file_cfg)
        _singleton = Settings(**file_cfg)
        return _singleton


# ------------------------------ logging config --------------------------------

def setup_logging(cfg: Optional[Settings] = None) -> None:
    """
    Apply logging configuration immediately (basic setup).
    """
    cfg = cfg or settings()
    lvl = getattr(logging, cfg.observability.logging.level, logging.INFO)
    logging.root.setLevel(lvl)
    # Console handler
    handler = logging.StreamHandler()
    if cfg.observability.logging.format == "json":
        try:
            import json_log_formatter  # type: ignore
            formatter = json_log_formatter.JSONFormatter()
        except Exception:  # pragma: no cover
            formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    else:
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(formatter)

    # Remove existing stream handlers to avoid duplicates
    for h in list(logging.root.handlers):
        if isinstance(h, logging.StreamHandler):
            logging.root.removeHandler(h)

    logging.root.addHandler(handler)

    # Add Loki notice (transport configured elsewhere)
    for dest in cfg.observability.logging.destinations:
        if dest.type == "loki" and dest.url:
            logging.getLogger("veilmind.settings").info("Loki logging enabled at %s", dest.url)


# ------------------------------ secrets facade --------------------------------

class SecretResolver:
    """
    Minimal synchronous secret resolver used by code paths that read Settings.
    Implementations for 'env' and 'file' are provided; 'vault' stub is included.
    """

    def __init__(self, cfg: Settings) -> None:
        self.cfg = cfg

    def from_ref(self, ref: Mapping[str, str]) -> Optional[str]:
        provider = ref.get("provider", "env")
        if provider == "env":
            return os.getenv(ref.get("key", ""), None) or os.getenv(ref.get("env", ""), None)
        if provider == "file":
            path = ref.get("path")
            key = ref.get("key")
            if not path:
                return None
            p = pathlib.Path(path)
            if not p.exists():
                return None
            with p.open("r", encoding="utf-8") as f:
                try:
                    data = yaml.safe_load(f) if yaml else {}
                except Exception:
                    data = {}
            if isinstance(data, Mapping) and key:
                val = data.get(key)
                return str(val) if val is not None else None
            return None
        if provider == "vault":
            # Stub: integrate hvac or custom client here
            return None
        if provider == "secretManager":
            # Stub: integrate cloud provider SDK
            return None
        return None


# ------------------------------ convenience API -------------------------------

def config_summary() -> Dict[str, Any]:
    """
    Redacted summary for diagnostics.
    """
    cfg = settings()
    d = cfg.as_dict()
    # best-effort redaction
    s = json.dumps(d)
    s = re.sub(r'("password[^"]*"\s*:\s*)"[^"]*"', r'\1"[REDACTED]"', s, flags=re.I)
    s = re.sub(r'("client_secret[^"]*"\s*:\s*)"[^"]*"', r'\1"[REDACTED]"', s, flags=re.I)
    return json.loads(s)


# ------------------------------ module init -----------------------------------

# Auto-load on import for immediate availability (safe, thread-locked)
settings()
