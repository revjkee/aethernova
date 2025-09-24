# ledger-core/ledger/settings.py
# -*- coding: utf-8 -*-
"""
Industrial-grade settings module for ledger-core.

Requirements:
  - pydantic>=2.5
  - pydantic-settings>=2.0
Optional:
  - python-json-logger (for richer JSON logging)
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
from functools import lru_cache
from logging.config import dictConfig
from pathlib import Path
from typing import Any, Dict, Literal, Optional

from pydantic import (
    BaseModel,
    Field,
    HttpUrl,
    PostgresDsn,
    ValidationError,
    ValidationInfo,
    computed_field,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


# -------------------------------
# Common utils
# -------------------------------

def _bool_env(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}

def _coalesce(*vals: Optional[str], default: str = "") -> str:
    for v in vals:
        if v:
            return v
    return default


# -------------------------------
# Sub-configs
# -------------------------------

class AppMeta(BaseModel):
    name: str = Field(default="ledger-core")
    part_of: str = Field(default="ledger")
    component: Literal["api", "worker", "scheduler"] = Field(default="api")
    environment: Literal["dev", "staging", "prod", "test"] = Field(default="dev")
    version: str = Field(default=os.getenv("APP_VERSION", "0.0.0"))
    instance: str = Field(default_factory=socket.gethostname)
    zone: str = Field(default=os.getenv("ZONE", ""))
    region: str = Field(default=os.getenv("REGION", ""))

class HttpConfig(BaseModel):
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080, ge=1, le=65535)
    root_path: str = Field(default="")
    request_timeout_seconds: int = Field(default=30, ge=1, le=600)
    compression: bool = Field(default=True)
    cors_enabled: bool = Field(default=True)
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["*"])

class GrpcConfig(BaseModel):
    enabled: bool = Field(default=True)
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=9090, ge=1, le=65535)
    max_concurrent_streams: int = Field(default=1024, ge=32)
    reflection: bool = Field(default=True)
    tls_enabled: bool = Field(default=False)
    tls_cert_file: Optional[Path] = None
    tls_key_file: Optional[Path] = None

    @model_validator(mode="after")
    def _validate_tls(self) -> "GrpcConfig":
        if self.tls_enabled and (not self.tls_cert_file or not self.tls_key_file):
            raise ValueError("grpc.tls_enabled is true but cert/key files are not provided")
        return self

class DatabaseConfig(BaseModel):
    # Prefer DSN; otherwise compose from parts
    dsn: Optional[PostgresDsn] = Field(default=None)
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=5432, ge=1, le=65535)
    user: str = Field(default="postgres")
    password: str = Field(default="postgres")
    database: str = Field(default="ledger")
    sslmode: Literal["disable", "require", "verify-ca", "verify-full"] = Field(default="disable")
    pool_min_size: int = Field(default=5, ge=0)
    pool_max_size: int = Field(default=20, ge=1)
    pool_max_idle: int = Field(default=10, ge=0)
    statement_timeout_ms: int = Field(default=60000, ge=1000)
    connect_timeout_sec: int = Field(default=5, ge=1, le=60)

    @computed_field  # type: ignore[misc]
    @property
    def effective_dsn(self) -> str:
        if self.dsn:
            return str(self.dsn)
        return (
            f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/"
            f"{self.database}?sslmode={self.sslmode}"
        )

    @model_validator(mode="after")
    def _validate_pool(self) -> "DatabaseConfig":
        if self.pool_min_size > self.pool_max_size:
            raise ValueError("pool_min_size cannot exceed pool_max_size")
        return self

class RedisConfig(BaseModel):
    enabled: bool = Field(default=True)
    url: str = Field(default="redis://127.0.0.1:6379/0")
    pool_max_connections: int = Field(default=100, ge=1)
    socket_timeout_ms: int = Field(default=3000, ge=100)

class TracingConfig(BaseModel):
    enabled: bool = Field(default=True)
    exporter: Literal["otlp_http", "otlp_grpc", "stdout"] = Field(default="otlp_http")
    otlp_endpoint: Optional[str] = Field(default=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
    service_name: Optional[str] = None
    sampler: Literal["always_on", "traceidratio", "parentbased_always_on", "parentbased_traceidratio", "always_off"] = Field(
        default="parentbased_traceidratio"
    )
    sampler_ratio: float = Field(default=0.1, ge=0.0, le=1.0)

class MetricsConfig(BaseModel):
    enabled: bool = Field(default=True)
    exporter: Literal["prometheus", "otlp", "stdout"] = Field(default="prometheus")
    prometheus_port: int = Field(default=9100, ge=1, le=65535)
    prefix: str = Field(default="ledger")

class SecurityConfig(BaseModel):
    # HTTP
    allow_origins: list[str] = Field(default_factory=lambda: ["*"])
    # API keys (dev only default)
    api_keys: dict[str, dict[str, Any]] = Field(default_factory=dict)
    # OAuth/OIDC
    oidc_issuer: Optional[HttpUrl] = None
    oidc_audience: Optional[str] = None
    jwks_url: Optional[HttpUrl] = None

class FeaturesConfig(BaseModel):
    source: Literal["file", "remote", "disabled"] = Field(default="file")
    file_path: Path = Field(default=Path("ops/configs/features.yaml"))
    refresh_seconds: int = Field(default=60, ge=5)
    fail_open: bool = Field(default=False)

class RateLimitConfig(BaseModel):
    source: Literal["file", "remote", "disabled"] = Field(default="file")
    file_path: Path = Field(default=Path("ops/configs/policies/rate_limits.yaml"))
    enabled: bool = Field(default=True)

class IdempotencyConfig(BaseModel):
    storage: Literal["redis", "memory"] = Field(default="redis")
    ttl_seconds: int = Field(default=86400, ge=60)
    header_name: str = Field(default="Idempotency-Key")
    body_hash_algo: Literal["sha256", "blake2b"] = Field(default="sha256")

class LoggingConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    json: bool = Field(default=True)
    service_name: str = Field(default="ledger-core")
    sampling_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    redact_headers: list[str] = Field(
        default_factory=lambda: [
            "authorization",
            "x-api-key",
            "cookie",
            "set-cookie",
            "idempotency-key",
            "proxy-authorization",
        ]
    )

    def to_dictconfig(self) -> Dict[str, Any]:
        if self.json:
            # Try python-json-logger; fallback to minimal JSON formatter
            try:
                import pythonjsonlogger  # noqa: F401
                fmt = "pythonjsonlogger.jsonlogger.JsonFormatter"
                fmt_kwargs = {"rename_fields": {"levelname": "level", "asctime": "ts"}}
            except Exception:
                fmt = "logging.Formatter"
                fmt_kwargs = {}
            return {
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {
                    "json": {"()": fmt, "fmt": "%(message)s", "validate": False, **fmt_kwargs},
                },
                "handlers": {
                    "stdout": {
                        "class": "logging.StreamHandler",
                        "stream": "ext://sys.stdout",
                        "formatter": "json",
                    }
                },
                "root": {"level": self.level, "handlers": ["stdout"]},
            }
        # Plain text
        return {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "plain": {"format": "[%(asctime)s] %(levelname)s %(name)s: %(message)s"},
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "plain",
                }
            },
            "root": {"level": self.level, "handlers": ["stdout"]},
        }


# -------------------------------
# Settings (root)
# -------------------------------

class Settings(BaseSettings):
    """
    Centralized strongly-typed settings for ledger-core.
    Loads from environment and optional .env file.
    """

    model_config = SettingsConfigDict(
        env_prefix="LEDGER_",
        env_file=_coalesce(os.getenv("LEDGER_ENV_FILE"), ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        validate_default=True,
        extra="ignore",
    )

    meta: AppMeta = Field(default_factory=AppMeta)
    http: HttpConfig = Field(default_factory=HttpConfig)
    grpc: GrpcConfig = Field(default_factory=GrpcConfig)
    db: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    tracing: TracingConfig = Field(default_factory=TracingConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    ratelimit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    idempotency: IdempotencyConfig = Field(default_factory=IdempotencyConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    # Derived flags
    debug: bool = Field(default=False)
    testing: bool = Field(default=False)
    read_only_mode: bool = Field(default=False)

    # Optional integration endpoints
    docs_url: Optional[HttpUrl] = None
    status_url: Optional[HttpUrl] = None

    # ---------------------------
    # Validators & computed
    # ---------------------------

    @field_validator("debug", mode="before")
    @classmethod
    def _debug_from_env(cls, v: Any) -> bool:
        return _bool_env(v if v is not None else os.getenv("DEBUG", "0"))

    @field_validator("testing", mode="before")
    @classmethod
    def _testing_from_env(cls, v: Any) -> bool:
        # pytest sets PYTEST_CURRENT_TEST; also respect ENV=TEST
        return _bool_env(v if v is not None else (os.getenv("PYTEST_CURRENT_TEST") or os.getenv("ENV") == "test"))

    @model_validator(mode="after")
    def _env_overrides(self) -> "Settings":
        # Normalize environment from ENV / meta.environment
        env = os.getenv("ENV") or self.meta.environment
        self.meta.environment = env if env in {"dev", "staging", "prod", "test"} else "dev"

        # Sensible defaults per environment
        if self.meta.environment == "prod":
            self.debug = False
            self.metrics.enabled = True
            self.tracing.sampler = "parentbased_traceidratio"
            if self.tracing.sampler_ratio == 1.0:
                # avoid full sampling by accident in prod unless explicitly set
                self.tracing.sampler_ratio = 0.1
            self.logging.level = "INFO" if not self.debug else self.logging.level
        elif self.meta.environment == "test":
            self.metrics.enabled = False
            self.tracing.enabled = False
            self.redis.enabled = False
            self.logging.json = False
        return self

    @computed_field  # type: ignore[misc]
    @property
    def is_prod(self) -> bool:
        return self.meta.environment == "prod"

    @computed_field  # type: ignore[misc]
    @property
    def service_labels(self) -> dict[str, str]:
        return {
            "app.kubernetes.io/name": self.meta.name,
            "app.kubernetes.io/part-of": self.meta.part_of,
            "app.kubernetes.io/component": self.meta.component,
            "app.kubernetes.io/version": self.meta.version,
            "app.kubernetes.io/instance": self.meta.instance,
            "env": self.meta.environment,
            "region": self.meta.region,
            "zone": self.meta.zone,
        }

    # ---------------------------
    # Helpers
    # ---------------------------

    def configure_logging(self) -> None:
        """Apply logging configuration via dictConfig."""
        dictConfig(self.logging.to_dictconfig())
        # Enrich root logger with service metadata
        logging.LoggerAdapter(logging.getLogger(), extra={"extra": {"service": self.meta.name}})

    def asdict(self, redacted: bool = True) -> Dict[str, Any]:
        """Export settings to dict (optionally redacting secrets)."""
        data = self.model_dump(mode="json")
        if redacted:
            # Redact commonly sensitive fields
            _redact_paths = [
                ("db", "password"),
            ]
            for path in _redact_paths:
                try:
                    d = data
                    for key in path[:-1]:
                        d = d[key]
                    if d.get(path[-1]):
                        d[path[-1]] = "***"
                except Exception:
                    pass
        return data

    def to_json(self, redacted: bool = True) -> str:
        return json.dumps(self.asdict(redacted=redacted), ensure_ascii=False, indent=2)


# -------------------------------
# Singleton accessor
# -------------------------------

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Lazy singleton. Reads from env and optional .env exactly once.
    Usage:
        from ledger.settings import get_settings
        settings = get_settings()
        settings.configure_logging()
    """
    try:
        s = Settings()
    except ValidationError as e:
        # Fail fast with clear diagnostics
        print("Invalid configuration:", file=sys.stderr)
        print(e, file=sys.stderr)
        raise
    return s


# -------------------------------
# CLI/debug helper
# -------------------------------

if __name__ == "__main__":  # pragma: no cover
    settings = get_settings()
    settings.configure_logging()
    print(settings.to_json(redacted=True))
