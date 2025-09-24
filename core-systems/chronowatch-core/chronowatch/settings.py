# -*- coding: utf-8 -*-
"""
Industrial-grade settings loader for chronowatch-core.

Features:
- Source precedence: CLI kwargs (optional) > ENV > YAML file
- YAML variable expansion: ${VAR:-default}, ${VAR}
- Deep merge of multiple sources (base + overlay)
- Secrets indirection: fields with *_env pull values from env securely
- Strong validation via Pydantic (py>=3.10)
- Cached singleton Settings.get()
- Helpful helpers: DSNs, CORS, OTEL, logging dictConfig scaffold
- Strict timeouts/rate limits defaults for safer dev/prod parity
"""

from __future__ import annotations

import os
import re
import json
import copy
import pathlib
import typing as t
from functools import lru_cache

try:
    import yaml  # PyYAML
except Exception as e:  # pragma: no cover
    raise RuntimeError("PyYAML is required: pip install pyyaml") from e

try:
    # Pydantic v2
    from pydantic import BaseModel, Field, AnyUrl, ValidationError, field_validator, model_validator
    from pydantic_settings import BaseSettings as _BaseSettings  # optional
    _PYD_VER = 2
except Exception:
    # Minimal fallback to v1 API (still using BaseModel interface)
    from pydantic import BaseModel, Field, AnyUrl, ValidationError, validator as field_validator, root_validator as model_validator  # type: ignore
    _BaseSettings = BaseModel  # type: ignore
    _PYD_VER = 1


# --------------------------
# Utility: environment
# --------------------------

_ENV_KEYS = ("APP_ENV", "ENVIRONMENT", "ENV")

def detect_env(default: str = "dev") -> str:
    for k in _ENV_KEYS:
        v = os.getenv(k)
        if v and v.strip():
            return v.strip()
    return default

def project_root() -> pathlib.Path:
    # assumes this file resides at chronowatch_core/chronowatch/settings.py
    return pathlib.Path(__file__).resolve().parents[2]

def default_config_path(env: str) -> pathlib.Path:
    return project_root() / "configs" / "env" / f"{env}.yaml"


# --------------------------
# Utility: dict operations
# --------------------------

_VAR_PATTERN = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)?(?::-(?P<default>[^}]*))?\}")

def expand_env_vars(value: t.Any) -> t.Any:
    """
    Recursively expand ${VAR:-default} in strings.
    """
    if isinstance(value, str):
        def repl(m: re.Match[str]) -> str:
            name = m.group("name")
            default = m.group("default")
            return os.getenv(name, default if default is not None else "")
        return _VAR_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: expand_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env_vars(v) for v in value]
    return value

def deep_merge(a: dict, b: dict) -> dict:
    """
    Recursively merge b into a (copy), returning new dict.
    Later keys in b override a.
    """
    out = copy.deepcopy(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out

def _read_yaml(path: pathlib.Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config root must be a mapping: {path}")
    return data


# --------------------------
# Pydantic models
# --------------------------

class BuildInfo(BaseModel):
    version: str = Field(default="dev")
    commit_sha: str = Field(default="0000000")
    branch: str = Field(default="local")

class ServerHTTP(BaseModel):
    backlog: int = 2048
    keepalive_timeout_s: int = 20
    request_timeout_s: int = 30
    read_timeout_s: int = 30
    write_timeout_s: int = 30
    max_header_size_bytes: int = 16384
    max_body_size_mb: int = 16
    workers: int = 2
    http2: bool = False

class ServerEndpoints(BaseModel):
    health: str = "/healthz"
    ready: str = "/readyz"
    metrics: str = "/metrics"
    pprof: str = "/debug/pprof"

class CORSConfig(BaseModel):
    enabled: bool = False
    allow_origins: t.List[str] = Field(default_factory=list)
    allow_methods: t.List[str] = Field(default_factory=lambda: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
    allow_headers: t.List[str] = Field(default_factory=lambda: ["*"])
    allow_credentials: bool = False
    max_age_s: int = 3600

class CSRFConfig(BaseModel):
    enabled: bool = False

class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    http: ServerHTTP = Field(default_factory=ServerHTTP)
    endpoints: ServerEndpoints = Field(default_factory=ServerEndpoints)
    cors: CORSConfig = Field(default_factory=CORSConfig)
    csrf: CSRFConfig = Field(default_factory=CSRFConfig)

class HSTSConfig(BaseModel):
    enabled: bool = False
    max_age_s: int = 15552000
    include_subdomains: bool = True
    preload: bool = False

class SecurityHeaders(BaseModel):
    frame_options: str = "DENY"
    content_type_options: str = "nosniff"
    referrer_policy: str = "no-referrer"
    xss_protection: str = "0"
    hsts: HSTSConfig = Field(default_factory=HSTSConfig)

class RateWindow(BaseModel):
    window_s: int = 60
    max_requests: int = 600

class RateLimit(BaseModel):
    enabled: bool = True
    default: RateWindow = Field(default_factory=RateWindow)
    auth_sensitive: RateWindow = Field(default_factory=lambda: RateWindow(window_s=60, max_requests=60))
    burst_multiplier: float = 2.0

class JWTConfig(BaseModel):
    issuer: str = "chronowatch-core"
    audience: str = "chronowatch-clients"
    access_ttl_s: int = 900
    refresh_ttl_s: int = 1209600
    public_key_pem_env: str = "JWT_PUBLIC_KEY_PEM"
    private_key_pem_env: str = "JWT_PRIVATE_KEY_PEM"
    alg: str = "RS256"
    clock_skew_s: int = 10

    @property
    def public_key_pem(self) -> str | None:
        v = os.getenv(self.public_key_pem_env)
        return v.strip() if v else None

    @property
    def private_key_pem(self) -> str | None:
        v = os.getenv(self.private_key_pem_env)
        return v.strip() if v else None

class MTLSConfig(BaseModel):
    enabled: bool = False
    ca_cert_env: str = "MTLS_CA_CERT_PEM"
    client_cn_allowlist: t.List[str] = Field(default_factory=list)

class AuthConfig(BaseModel):
    mode: str = Field(default="jwt")  # jwt|session|mtls
    jwt: JWTConfig = Field(default_factory=JWTConfig)
    mtls: MTLSConfig = Field(default_factory=MTLSConfig)

class SecurityConfig(BaseModel):
    secrets_source: str = Field(default="env")  # env|vault|aws-sm|gcp-sm
    headers: SecurityHeaders = Field(default_factory=SecurityHeaders)
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    ip_allowlist_enabled: bool = False
    ip_allowlist_cidrs: t.List[str] = Field(default_factory=list)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    oauth2_enabled: bool = False
    oauth2_providers: dict = Field(default_factory=dict)

class LoggingSampling(BaseModel):
    enabled: bool = True
    initial: int = 5
    thereafter: int = 100

class LoggingConfig(BaseModel):
    level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL","INFO"))
    json: bool = True
    include_caller: bool = True
    sampling: LoggingSampling = Field(default_factory=LoggingSampling)

class PrometheusConfig(BaseModel):
    enabled: bool = True
    endpoint: str = "/metrics"
    labels: dict = Field(default_factory=dict)

class OTelConfig(BaseModel):
    enabled: bool = True
    service_name: str = "chronowatch-core"
    otlp_endpoint: str = Field(default_factory=lambda: os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT","http://localhost:4317"))
    protocol: str = "grpc"  # grpc|http
    sampler: str = "parentbased_traceidratio"
    ratio: float = Field(default_factory=lambda: float(os.getenv("OTEL_SAMPLER_RATIO","0.2")))
    resource_attributes: dict = Field(default_factory=dict)

class ProfilingConfig(BaseModel):
    enabled: bool = False
    auth_required: bool = True

class ObservabilityConfig(BaseModel):
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    metrics: PrometheusConfig = Field(default_factory=PrometheusConfig)
    tracing: OTelConfig = Field(default_factory=OTelConfig)
    profiling: ProfilingConfig = Field(default_factory=ProfilingConfig)

class DBPoolConfig(BaseModel):
    min_size: int = 2
    max_size: int = 20
    max_idle_time_s: int = 60
    conn_max_lifetime_s: int = 1800

class DBMigrationConfig(BaseModel):
    enabled: bool = True
    tool: str = "alembic"
    autoupgrade_on_start: bool = True
    scripts_path: str = "ops/migrations"

class DatabaseConfig(BaseModel):
    engine: str = "postgres"
    host: str = Field(default_factory=lambda: os.getenv("DB_HOST","localhost"))
    port: int = Field(default_factory=lambda: int(os.getenv("DB_PORT","5432")))
    user: str = Field(default_factory=lambda: os.getenv("DB_USER","chronowatch"))
    password_env: str = "DB_PASSWORD"
    name: str = Field(default_factory=lambda: os.getenv("DB_NAME","chronowatch"))
    sslmode: str = "disable"
    pool: DBPoolConfig = Field(default_factory=DBPoolConfig)
    migration: DBMigrationConfig = Field(default_factory=DBMigrationConfig)

    @property
    def password(self) -> str | None:
        v = os.getenv(self.password_env)
        return v if v else None

    def dsn(self) -> str:
        pwd = self.password or ""
        auth = f"{self.user}:{pwd}" if pwd else self.user
        return f"postgresql+asyncpg://{auth}@{self.host}:{self.port}/{self.name}?sslmode={self.sslmode}"

class RedisPoolConfig(BaseModel):
    max_connections: int = 50

class RedisTimeouts(BaseModel):
    connect_ms: int = 200
    io_ms: int = 200

class CacheConfig(BaseModel):
    engine: str = "redis"
    host: str = Field(default_factory=lambda: os.getenv("REDIS_HOST","localhost"))
    port: int = Field(default_factory=lambda: int(os.getenv("REDIS_PORT","6379")))
    db: int = 0
    username: str | None = Field(default_factory=lambda: os.getenv("REDIS_USER","") or None)
    password_env: str = "REDIS_PASSWORD"
    tls: bool = False
    timeouts: RedisTimeouts = Field(default_factory=RedisTimeouts)
    pool: RedisPoolConfig = Field(default_factory=RedisPoolConfig)

    @property
    def password(self) -> str | None:
        v = os.getenv(self.password_env)
        return v if v else None

    def url(self) -> str:
        auth = ""
        if self.username or self.password:
            u = self.username or ""
            p = self.password or ""
            auth = f"{u}:{p}@"
        scheme = "rediss" if self.tls else "redis"
        return f"{scheme}://{auth}{self.host}:{self.port}/{self.db}"

class RetryConfig(BaseModel):
    max_attempts: int = 3
    backoff_initial_ms: int = 100
    backoff_max_ms: int = 2000

class RabbitMQConfig(BaseModel):
    url: str = Field(default_factory=lambda: os.getenv("RABBITMQ_URL","amqp://guest:guest@localhost:5672/"))
    prefetch: int = 64
    publishers_confirm: bool = True
    retries: RetryConfig = Field(default_factory=lambda: RetryConfig(max_attempts=5, backoff_initial_ms=100, backoff_max_ms=5000))

class QueueTopics(BaseModel):
    events: str = "chronowatch.events"
    tasks: str = "chronowatch.tasks"

class QueueConfig(BaseModel):
    engine: str = "rabbitmq"  # rabbitmq|kafka|sqs|nats
    rabbitmq: RabbitMQConfig = Field(default_factory=RabbitMQConfig)
    topics: QueueTopics = Field(default_factory=QueueTopics)

class S3Upload(BaseModel):
    multipart_threshold_mb: int = 8
    part_size_mb: int = 8
    max_concurrency: int = 4

class S3Config(BaseModel):
    endpoint: str = Field(default_factory=lambda: os.getenv("S3_ENDPOINT","http://localhost:9000"))
    region: str = Field(default_factory=lambda: os.getenv("S3_REGION","us-east-1"))
    bucket: str = Field(default_factory=lambda: os.getenv("S3_BUCKET","chronowatch-dev"))
    access_key_env: str = "S3_ACCESS_KEY"
    secret_key_env: str = "S3_SECRET_KEY"
    force_path_style: bool = True
    kms_key_id: str | None = None
    upload: S3Upload = Field(default_factory=S3Upload)

    @property
    def access_key(self) -> str | None:
        v = os.getenv(self.access_key_env)
        return v if v else None

    @property
    def secret_key(self) -> str | None:
        v = os.getenv(self.secret_key_env)
        return v if v else None

class StorageFS(BaseModel):
    base_dir: str = Field(default_factory=lambda: os.getenv("LOCAL_STORAGE_DIR","./.data"))

class StorageConfig(BaseModel):
    provider: str = "s3"  # s3|local_fs
    s3: S3Config = Field(default_factory=S3Config)
    local_fs: StorageFS = Field(default_factory=StorageFS)

class HTTPClientConfig(BaseModel):
    connect_timeout_s: int = 3
    read_timeout_s: int = 5
    retries: RetryConfig = Field(default_factory=RetryConfig)
    headers: dict = Field(default_factory=lambda: {"User-Agent": f"chronowatch-core/{os.getenv('BUILD_VERSION','dev')}"})

class FeaturesConfig(BaseModel):
    enable_async_tasks: bool = True
    enable_audit_log: bool = True
    enable_webhooks: bool = True
    strict_schema_validation: bool = True
    experimental: dict = Field(default_factory=lambda: {"new_policy_engine": False, "fast_path_caching": True})

class LimitsRequests(BaseModel):
    max_json_body_mb: int = 16
    max_multipart_body_mb: int = 64

class LimitsConcurrency(BaseModel):
    global_max: int = 512
    per_ip_max: int = 128

class LimitsQuotas(BaseModel):
    default_rps: int = 50
    burst_rps: int = 100

class LimitsConfig(BaseModel):
    requests: LimitsRequests = Field(default_factory=LimitsRequests)
    concurrency: LimitsConcurrency = Field(default_factory=LimitsConcurrency)
    quotas: LimitsQuotas = Field(default_factory=LimitsQuotas)

class SchedulerConfig(BaseModel):
    enabled: bool = True
    timezone: str = "UTC"
    max_concurrency: int = 8

class CronJob(BaseModel):
    schedule: str
    timeout_s: int = 30
    jitter_s: int = 10
    enabled: bool = True

class TasksConfig(BaseModel):
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    crons: dict[str, CronJob] = Field(default_factory=dict)

class WebhookSigning(BaseModel):
    enabled: bool = True
    alg: str = "HMAC-SHA256"
    secret_env: str = "WEBHOOK_SIGNING_SECRET"

    @property
    def secret(self) -> str | None:
        v = os.getenv(self.secret_env)
        return v if v else None

class WebhookRetry(BaseModel):
    attempts: int = 5
    backoff_initial_ms: int = 200
    backoff_max_ms: int = 8000

class WebhooksConfig(BaseModel):
    retry_policy: WebhookRetry = Field(default_factory=WebhookRetry)
    signing: WebhookSigning = Field(default_factory=WebhookSigning)

class MailSMTP(BaseModel):
    host: str = Field(default_factory=lambda: os.getenv("SMTP_HOST","localhost"))
    port: int = Field(default_factory=lambda: int(os.getenv("SMTP_PORT","1025")))
    user: str | None = Field(default_factory=lambda: os.getenv("SMTP_USER","") or None)
    password_env: str = "SMTP_PASSWORD"
    use_tls: bool = False
    from_: str = "noreply@chronowatch.dev"

    @property
    def password(self) -> str | None:
        v = os.getenv(self.password_env)
        return v if v else None

class MailConfig(BaseModel):
    provider: str = "smtp"
    smtp: MailSMTP = Field(default_factory=MailSMTP)

class IntegrationsConfig(BaseModel):
    mail: MailConfig = Field(default_factory=MailConfig)
    telemetry_dashboard: dict = Field(default_factory=lambda: {"grafana_url": os.getenv("GRAFANA_URL","http://localhost:3001")})

class MTLSBus(BaseModel):
    enabled: bool = False
    ca_env: str = "INTERNAL_CA_PEM"
    cert_env: str = "INTERNAL_CERT_PEM"
    key_env: str = "INTERNAL_KEY_PEM"

class EnvironmentInfo(BaseModel):
    name: str = Field(default_factory=lambda: detect_env())
    region: str = "eu-central-1"
    timezone: str = "UTC"
    precedence: list[str] = Field(default_factory=lambda: ["env","file"])

class DebugConfig(BaseModel):
    enabled: bool = True
    verbose_errors: bool = True

class AppConfig(BaseModel):
    name: str = "chronowatch-core"
    instance_id: str = Field(default_factory=lambda: os.getenv("HOSTNAME","local-dev"))
    build: BuildInfo = Field(default_factory=BuildInfo)

# Root settings
class Settings(BaseModel):
    schema: dict = Field(default_factory=lambda: {"version": 1, "owner": "chronowatch-core"})
    environment: EnvironmentInfo = Field(default_factory=EnvironmentInfo)
    debug: DebugConfig = Field(default_factory=DebugConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    queue: QueueConfig = Field(default_factory=QueueConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    http_clients: dict[str, HTTPClientConfig] = Field(default_factory=lambda: {"default": HTTPClientConfig()})
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    tasks: TasksConfig = Field(default_factory=TasksConfig)
    webhooks: WebhooksConfig = Field(default_factory=WebhooksConfig)
    integrations: IntegrationsConfig = Field(default_factory=IntegrationsConfig)
    mtls: MTLSBus = Field(default_factory=MTLSBus)
    env_reference: list[str] = Field(default_factory=lambda: [
        "DB_PASSWORD","REDIS_PASSWORD","S3_ACCESS_KEY","S3_SECRET_KEY",
        "JWT_PUBLIC_KEY_PEM","JWT_PRIVATE_KEY_PEM","WEBHOOK_SIGNING_SECRET",
        "SMTP_PASSWORD","OTEL_EXPORTER_OTLP_ENDPOINT"
    ])
    validation: dict = Field(default_factory=lambda: {"strict_types": True, "fail_on_unknown_keys": True, "allow_env_overrides": True})

    # ----- Validators / Normalizers -----
    @field_validator("server")
    @classmethod
    def _normalize_cors(cls, v: ServerConfig) -> ServerConfig:
        if v.cors.enabled and v.cors.allow_credentials and "*" in v.cors.allow_origins:
            # Credentials forbid wildcard; keep but will be enforced in middleware.
            pass
        return v

    @model_validator(mode="after")
    def _inject_otel_resources(self):
        # Ensure OTEL resource attrs are populated
        attrs = self.observability.tracing.resource_attributes or {}
        attrs.setdefault("deployment.environment", self.environment.name)
        attrs.setdefault("service.version", self.app.build.version)
        attrs.setdefault("git.commit", self.app.build.commit_sha)
        self.observability.tracing.resource_attributes = attrs
        return self

    # ----- Convenience helpers -----
    def postgres_dsn(self) -> str:
        return self.database.dsn()

    def redis_url(self) -> str:
        return self.cache.url()

    def s3_credentials(self) -> tuple[str | None, str | None]:
        return self.storage.s3.access_key, self.storage.s3.secret_key

    # ----- Loader API -----
    @staticmethod
    def _load_file(env: str | None = None) -> dict:
        # CHRONOWATCH_CONFIG_FILE has top priority for file source
        cfg_path = os.getenv("CHRONOWATCH_CONFIG_FILE")
        if cfg_path:
            path = pathlib.Path(cfg_path).expanduser().resolve()
            if not path.exists():
                raise FileNotFoundError(f"CHRONOWATCH_CONFIG_FILE={path} not found")
            data = _read_yaml(path)
        else:
            env_detected = env or detect_env()
            path = default_config_path(env_detected)
            if not path.exists():
                # Missing file is acceptable; we fallback to ENV-only
                return {}
            data = _read_yaml(path)

        return expand_env_vars(data)

    @staticmethod
    def _env_overlay() -> dict:
        """
        Provide a small overlay from environment for critical toggles.
        For full ENV overrides rely on ${...} in YAML and service code.
        """
        overlay: dict = {}
        # Logging level
        lvl = os.getenv("LOG_LEVEL")
        if lvl:
            overlay.setdefault("observability", {}).setdefault("logging", {})["level"] = lvl

        # Build info
        bv = os.getenv("BUILD_VERSION")
        bs = os.getenv("BUILD_SHA")
        br = os.getenv("GIT_BRANCH")
        if any([bv, bs, br]):
            overlay.setdefault("app", {}).setdefault("build", {})
            if bv: overlay["app"]["build"]["version"] = bv
            if bs: overlay["app"]["build"]["commit_sha"] = bs
            if br: overlay["app"]["build"]["branch"] = br

        # Environment name
        env_name = os.getenv("APP_ENV") or os.getenv("ENVIRONMENT")
        if env_name:
            overlay.setdefault("environment", {})["name"] = env_name

        return overlay

    @classmethod
    def from_sources(cls, *, env: str | None = None, extra_overlay: dict | None = None) -> "Settings":
        base = cls._load_file(env=env)
        env_ovr = cls._env_overlay()
        merged = deep_merge(base, env_ovr)
        if extra_overlay:
            merged = deep_merge(merged, extra_overlay)

        # Resolve secret indirections for *_env keys into runtime (kept as env for security)
        # Pydantic models will expose properties (e.g., .password) to access actual secret values.
        try:
            return cls(**merged)  # type: ignore[arg-type]
        except ValidationError as ve:
            # Helpful message with context
            msg = f"Configuration validation failed: {ve}"
            raise RuntimeError(msg) from ve

    # Cached singleton suitable for app-wide use
    @classmethod
    @lru_cache(maxsize=1)
    def get(cls) -> "Settings":
        return cls.from_sources()

# ------------- Optional: logging dictConfig scaffold -------------

def logging_dict_config(settings: Settings) -> dict:
    """
    Build a sane dictConfig based on settings.observability.logging.
    """
    json_mode = settings.observability.logging.json
    level = settings.observability.logging.level.upper()
    fmt = "%(asctime)s %(levelname)s %(name)s %(message)s" if not json_mode else "%(message)s"

    handlers = {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "json" if json_mode else "plain",
            "stream": "ext://sys.stdout",
        }
    }

    formatters = {
        "plain": {
            "format": fmt
        },
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "fmt": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    }

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters,
        "handlers": handlers,
        "root": {"level": level, "handlers": ["default"]},
    }


# ------------- CLI aid (manual debug) -------------

if __name__ == "__main__":  # pragma: no cover
    s = Settings.get()
    # Redact obvious secrets before printing
    redacted = json.loads(s.model_dump_json()) if _PYD_VER == 2 else json.loads(s.json())  # type: ignore
    # Ensure we don't accidentally print secret env contents
    # (actual secrets are not part of the model; *_env only contain env var names)
    print(json.dumps(redacted, indent=2, ensure_ascii=False))
