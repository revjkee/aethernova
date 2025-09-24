# oblivionvault/oblivionvault/settings.py
from __future__ import annotations

import os
import re
import socket
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Optional

try:
    # Pydantic v2 + settings
    from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
    from pydantic_settings import BaseSettings, SettingsConfigDict
except Exception as e:  # pragma: no cover
    raise RuntimeError("Install pydantic>=2 and pydantic-settings>=2 to use oblivionvault.settings") from e

# Optional .env auto-load if python-dotenv is present
try:  # pragma: no cover
    from dotenv import load_dotenv
    load_dotenv(override=False)
except Exception:
    pass


def _expand_file_secrets(env: dict[str, str]) -> dict[str, str]:
    """
    Support Docker/K8s secret convention: VAR or VAR_FILE.
    If VAR_FILE exists and points to a readable file, read it and set VAR.
    Does not overwrite explicit VAR already set in env.
    """
    result = dict(env)
    for key, value in list(env.items()):
        if key.endswith("_FILE"):
            base = key[:-5]
            if base in result and result[base]:
                continue
            path = Path(value)
            try:
                if path.is_file():
                    result[base] = path.read_text(encoding="utf-8").strip()
            except Exception:
                # ignore unreadable secret files
                pass
    return result


def _split_csv(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)(ms|s|m|h|d)?\s*$", re.IGNORECASE)
_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)(b|kb|k|mb|m|gb|g|tb|t|kib|mib|gib|tib)?\s*$", re.IGNORECASE)


def parse_duration(value: str | int | float) -> float:
    """
    Convert duration like '500ms', '2s', '1.5m', '2h', '1d' to seconds (float).
    Integers/floats are assumed seconds.
    """
    if isinstance(value, (int, float)):
        return float(value)
    m = _DURATION_RE.match(value)
    if not m:
        raise ValueError(f"Invalid duration: {value}")
    num = float(m.group(1))
    unit = (m.group(2) or "s").lower()
    mult = {"ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}[unit]
    return num * mult


def parse_size(value: str | int | float) -> int:
    """
    Convert sizes like '512k', '5MiB', '100MB', '1g' to bytes (int).
    Integers/floats are assumed bytes.
    """
    if isinstance(value, (int, float)):
        return int(value)
    m = _SIZE_RE.match(value)
    if not m:
        raise ValueError(f"Invalid size: {value}")
    num = float(m.group(1))
    unit = (m.group(2) or "b").lower()
    power10 = {"b": 1, "k": 10**3, "kb": 10**3, "m": 10**6, "mb": 10**6, "g": 10**9, "gb": 10**9, "t": 10**12, "tb": 10**12}
    power2 = {"kib": 2**10, "mib": 2**20, "gib": 2**30, "tib": 2**40}
    mult = power2.get(unit) or power10.get(unit)
    if not mult:
        raise ValueError(f"Invalid size unit: {unit}")
    return int(num * mult)


class LoggingSettings(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    json: bool = Field(default=True, description="Emit JSON logs")
    include_pid: bool = Field(default=True)
    include_hostname: bool = Field(default=True)

    def fmt(self) -> str:
        base = []
        if self.json:
            base.append('{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"')
            if self.include_pid:
                base.append(',"pid":"%(process)d"')
            if self.include_hostname:
                base.append(f',"host":"{socket.gethostname()}"')
            base.append('}')
            return "".join(base)
        else:
            return "%(asctime)s %(levelname)s [%(name)s] %(message)s"


class HTTPSettings(BaseModel):
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080, ge=1, le=65535)
    request_timeout_seconds: float = Field(default=30.0)
    keepalive_timeout_seconds: float = Field(default=5.0)
    max_body_bytes: int = Field(default_factory=lambda: parse_size("5MiB"))
    enable_gzip: bool = Field(default=True)
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["*"])
    allowed_hosts: list[str] = Field(default_factory=lambda: ["*"])
    request_id_header: str = Field(default="X-Request-ID")
    client_ip_header: str = Field(default="X-Forwarded-For")
    secure_csp: str = Field(default="default-src 'none'; frame-ancestors 'none'; base-uri 'none';")
    readiness_delay_ms: int = Field(default=0, ge=0)

    @field_validator("request_timeout_seconds", "keepalive_timeout_seconds", mode="before")
    @classmethod
    def _parse_durations(cls, v: Any) -> float:
        return parse_duration(v)

    @field_validator("max_body_bytes", mode="before")
    @classmethod
    def _parse_sizes(cls, v: Any) -> int:
        return parse_size(v) if isinstance(v, str) else int(v)


class StorageFSSettings(BaseModel):
    root: Path = Field(default=Path("/var/lib/oblivionvault"))


class StorageS3Settings(BaseModel):
    bucket: str
    region: Optional[str] = None
    endpoint_url: Optional[str] = None
    access_key: Optional[SecretStr] = None
    secret_key: Optional[SecretStr] = None
    path_style: bool = False


class StorageSettings(BaseModel):
    backend: Literal["memory", "filesystem", "s3"] = Field(default="memory")
    fs: StorageFSSettings = Field(default_factory=StorageFSSettings)
    s3: Optional[StorageS3Settings] = None


class DatabaseSettings(BaseModel):
    # Generic DSN; for Postgres format: postgres://user:pass@host:5432/db
    dsn: Optional[SecretStr] = None
    pool_min_size: int = 1
    pool_max_size: int = 10
    connect_timeout_seconds: float = Field(default=5.0)

    @field_validator("connect_timeout_seconds", mode="before")
    @classmethod
    def _parse_duration(cls, v: Any) -> float:
        return parse_duration(v)


class RedisSettings(BaseModel):
    url: Optional[SecretStr] = None
    socket_timeout_seconds: float = Field(default=2.0)

    @field_validator("socket_timeout_seconds", mode="before")
    @classmethod
    def _parse_duration(cls, v: Any) -> float:
        return parse_duration(v)


class BrokerSettings(BaseModel):
    # Choose one of them, leave others None
    kafka_bootstrap: Optional[str] = None
    rabbitmq_url: Optional[SecretStr] = None


class ObservabilitySettings(BaseModel):
    enable_metrics: bool = True
    prometheus_multiproc_dir: Optional[Path] = None
    enable_otel: bool = True
    otlp_endpoint: Optional[str] = None
    service_name: str = "oblivionvault-core"


class SentrySettings(BaseModel):
    dsn: Optional[SecretStr] = None
    traces_sample_rate: float = Field(default=0.0, ge=0.0, le=1.0)


class AuthSettings(BaseModel):
    jwt_public_key: Optional[SecretStr] = None
    jwt_issuer: Optional[str] = None
    audience: Optional[str] = None
    required_in_prod: bool = True


class FeatureFlags(BaseModel):
    enable_archive_module: bool = True
    enable_admin_api: bool = False


class AppSettings(BaseSettings):
    """
    Centralized settings for OblivionVault.
    Environment variables use prefixes and dotted paths, for example:
      OBLV__ENV=prod
      OBLV__HTTP__PORT=8080
      OBLV__HTTP__CORS_ALLOW_ORIGINS=https://app.example.com,https://admin.example.com
      OBLV__STORAGE__BACKEND=filesystem
      OBLV__STORAGE__FS__ROOT=/data/oblivionvault
      OBLV__OBS__ENABLE_OTEL=true
      OBLV__AUTH__JWT_PUBLIC_KEY_FILE=/var/run/secrets/jwt_pub
      OBLV__DATABASE__DSN_FILE=/var/run/secrets/pg_dsn
    We also support 1-level variables for compatibility:
      APP_ENV, APP_NAME, APP_VERSION, HTTP_HOST, HTTP_PORT, OBLIVIONVAULT_FS_ROOT
    """
    # Base meta
    app_name: str = Field(default="oblivionvault-core")
    app_version: str = Field(default="0.1.0")
    env: Literal["dev", "staging", "prod", "test"] = Field(default="dev")

    # Groups
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    http: HTTPSettings = Field(default_factory=HTTPSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    broker: BrokerSettings = Field(default_factory=BrokerSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings, alias="obs")
    sentry: SentrySettings = Field(default_factory=SentrySettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    features: FeatureFlags = Field(default_factory=FeatureFlags)

    # Derived flags
    is_prod: bool = False
    is_staging: bool = False
    is_dev: bool = False
    is_test: bool = False

    # Compatibility fallbacks for legacy envs
    model_config = SettingsConfigDict(
        env_prefix="OBLV__",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
        # Load env mapping through custom env parsing
        # We will provide env parsing via 'prepare_settings' classmethod
    )

    @classmethod
    def _legacy_overrides(cls, env: dict[str, str]) -> dict[str, str]:
        """
        Map legacy variables to new schema if present.
        """
        out = dict(env)
        # APP_ENV -> OBLV__ENV
        if "APP_ENV" in env and "OBLV__ENV" not in env:
            out["OBLV__ENV"] = env["APP_ENV"]
        if "APP_NAME" in env and "OBLV__APP_NAME" not in env:
            out["OBLV__APP_NAME"] = env["APP_NAME"]
        if "APP_VERSION" in env and "OBLV__APP_VERSION" not in env:
            out["OBLV__APP_VERSION"] = env["APP_VERSION"]
        # HTTP_*
        if "HTTP_HOST" in env:
            out["OBLV__HTTP__HOST"] = env["HTTP_HOST"]
        if "HTTP_PORT" in env:
            out["OBLV__HTTP__PORT"] = env["HTTP_PORT"]
        if "REQUEST_TIMEOUT_SECONDS" in env:
            out["OBLV__HTTP__REQUEST_TIMEOUT_SECONDS"] = env["REQUEST_TIMEOUT_SECONDS"]
        if "MAX_BODY_BYTES" in env:
            out["OBLV__HTTP__MAX_BODY_BYTES"] = env["MAX_BODY_BYTES"]
        if "CORS_ALLOW_ORIGINS" in env:
            out["OBLV__HTTP__CORS_ALLOW_ORIGINS"] = env["CORS_ALLOW_ORIGINS"]
        if "ALLOWED_HOSTS" in env:
            out["OBLV__HTTP__ALLOWED_HOSTS"] = env["ALLOWED_HOSTS"]
        if "SECURE_CSP" in env:
            out["OBLV__HTTP__SECURE_CSP"] = env["SECURE_CSP"]
        # Filesystem storage shortcut
        if "OBLIVIONVAULT_FS_ROOT" in env and "OBLV__STORAGE__BACKEND" not in env:
            out["OBLV__STORAGE__BACKEND"] = "filesystem"
            out["OBLV__STORAGE__FS__ROOT"] = env["OBLIVIONVAULT_FS_ROOT"]
        return out

    @classmethod
    def prepare_settings(cls) -> "AppSettings":
        """
        Build settings by merging:
        - os.environ (+ *_FILE expansion)
        - legacy overrides
        - parse list-like values for CORS/hosts if given as CSV
        """
        raw = _expand_file_secrets(os.environ)
        raw = cls._legacy_overrides(raw)
        # Normalize CSV lists for http.cors_allow_origins / http.allowed_hosts
        if "OBLV__HTTP__CORS_ALLOW_ORIGINS" in raw:
            raw["OBLV__HTTP__CORS_ALLOW_ORIGINS"] = _split_csv(raw["OBLV__HTTP__CORS_ALLOW_ORIGINS"])
        if "OBLV__HTTP__ALLOWED_HOSTS" in raw:
            raw["OBLV__HTTP__ALLOWED_HOSTS"] = _split_csv(raw["OBLV__HTTP__ALLOWED_HOSTS"])
        return cls.model_validate(raw)

    @model_validator(mode="after")
    def _derive_flags(self) -> "AppSettings":
        self.is_prod = self.env == "prod"
        self.is_staging = self.env == "staging"
        self.is_dev = self.env == "dev"
        self.is_test = self.env == "test"
        # Harden prod defaults
        if self.is_prod:
            if self.http.cors_allow_origins == ["*"]:
                self.http.cors_allow_origins = []
            if self.http.allowed_hosts == ["*"]:
                self.http.allowed_hosts = ["*"]  # keep wildcard only if behind a trusted proxy
        return self

    # ---- Helpers for integrations

    def as_uvicorn_kwargs(self) -> dict[str, Any]:
        """
        Convert to uvicorn.run kwargs.
        """
        return {
            "host": self.http.host,
            "port": self.http.port,
            "log_level": self.logging.level.lower(),
            "timeout_keep_alive": int(self.http.keepalive_timeout_seconds),
            "workers": int(os.getenv("UVICORN_WORKERS", "1")),
            "lifespan": "on",
            "reload": os.getenv("UVICORN_RELOAD", "false").lower() == "true",
        }

    def as_fastapi_kwargs(self) -> dict[str, Any]:
        """
        Control FastAPI docs exposure based on env.
        """
        docs = None if self.is_prod else "/docs"
        redoc = None if self.is_prod else "/redoc"
        openapi = None if self.is_prod else "/openapi.json"
        return {"title": self.app_name, "version": self.app_version, "docs_url": docs, "redoc_url": redoc, "openapi_url": openapi}

    def logging_format(self) -> str:
        return self.logging.fmt()

    def sanitized(self) -> dict[str, Any]:
        """
        Redacted dict for logging/diagnostics. SecretStr are masked.
        """
        def redact(value: Any) -> Any:
            if isinstance(value, SecretStr):
                return "***"
            if isinstance(value, BaseModel):
                return {k: redact(getattr(value, k)) for k in value.model_fields}
            if isinstance(value, (list, tuple)):
                return [redact(v) for v in value]
            if isinstance(value, dict):
                return {k: redact(v) for k, v in value.items()}
            return value

        data = {k: getattr(self, k) for k in self.model_fields}
        return redact(data)


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """
    Cached access to settings instance.
    """
    return AppSettings.prepare_settings()
