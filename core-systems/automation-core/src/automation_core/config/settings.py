# automation-core/src/automation_core/config/settings.py
from __future__ import annotations

import ipaddress
import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
try:
    # pydantic-settings v2
    from pydantic_settings import BaseSettings, SettingsConfigDict
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "pydantic-settings is required for configuration. "
        "Add `pydantic-settings>=2` to your dependencies."
    ) from e


# -----------------------------
# Helpers: env file discovery
# -----------------------------
_DEFAULT_ENV_FILES = (".env.test", ".env.ci", ".env")


def _project_root() -> Path:
    # .../automation-core/src/automation_core/config/settings.py
    return Path(__file__).resolve().parents[3]


def _first_existing_env_file(root: Path) -> Optional[Path]:
    for name in _DEFAULT_ENV_FILES:
        p = root / name
        if p.exists():
            return p
    return None


# -----------------------------
# Enums / Constants
# -----------------------------
class Environment(str, Enum):
    dev = "dev"
    test = "test"
    ci = "ci"
    staging = "staging"
    prod = "prod"


LogLevel = Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]


# -----------------------------
# Sub-sections
# -----------------------------
class AppSettings(BaseModel):
    name: str = Field(default="automation-core")
    env: Environment = Field(default=Environment.dev)
    debug: bool = Field(default=False)
    timezone: str = Field(default="UTC")
    version: str = Field(default="0.0.0")

    @model_validator(mode="after")
    def _normalize_debug(self) -> "AppSettings":
        # prod must not use debug
        if self.env == Environment.prod and self.debug:
            object.__setattr__(self, "debug", False)
        return self


class HTTPSettings(BaseModel):
    # Outbound HTTP timeouts and retries
    connect_timeout_s: float = Field(default=5.0, ge=0.0, le=120.0)
    read_timeout_s: float = Field(default=15.0, ge=0.0, le=600.0)
    total_timeout_s: float = Field(default=20.0, ge=0.0, le=1200.0)
    max_retries: int = Field(default=2, ge=0, le=10)
    verify_tls: bool = Field(default=True)
    user_agent: str = Field(default="automation-core/1.0")

    @field_validator("total_timeout_s")
    @classmethod
    def _total_ge_read(cls, v: float, info):
        read = info.data.get("read_timeout_s", 15.0)
        if v < read:
            raise ValueError("total_timeout_s must be >= read_timeout_s")
        return v


class DBSettings(BaseModel):
    # Unified DB layer; at least one DSN should be provided
    sqlite_path: Optional[Path] = Field(default=Path("automation.db"))
    postgres_dsn: Optional[str] = Field(default=None)  # e.g. postgresql+psycopg2://user:pass@host:5432/db
    pool_min_size: int = Field(default=1, ge=0, le=64)
    pool_max_size: int = Field(default=10, ge=1, le=256)
    echo_sql: bool = Field(default=False)
    pool_timeout_s: float = Field(default=30.0, ge=0.0, le=300.0)

    @model_validator(mode="after")
    def _validate_choice(self) -> "DBSettings":
        if not self.postgres_dsn and not self.sqlite_path:
            raise ValueError("Either postgres_dsn or sqlite_path must be set")
        if self.pool_max_size < max(self.pool_min_size, 1):
            raise ValueError("pool_max_size must be >= pool_min_size (and >=1)")
        return self


class RedisSettings(BaseModel):
    enabled: bool = Field(default=False)
    url: Optional[str] = Field(default=None)  # redis://host:6379/0
    ssl: bool = Field(default=False)
    db: int = Field(default=0, ge=0, le=15)
    max_connections: int = Field(default=128, ge=1, le=10000)

    @model_validator(mode="after")
    def _coherence(self) -> "RedisSettings":
        if self.enabled and not self.url:
            raise ValueError("Redis is enabled but no url provided")
        return self


class SecuritySettings(BaseModel):
    secret_key: SecretStr = Field(default=SecretStr("dev-secret-not-for-prod"))
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = Field(default="HS256")
    jwt_ttl_seconds: int = Field(default=3600, ge=60, le=7 * 24 * 3600)
    allowed_cors_origins: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)  # CIDR or plain

    @field_validator("allowed_ips")
    @classmethod
    def _validate_ips(cls, values: list[str]) -> list[str]:
        checked: list[str] = []
        for ip in values:
            ip = ip.strip()
            try:
                # Accept single IP or CIDR
                if "/" in ip:
                    ipaddress.ip_network(ip, strict=False)
                else:
                    ipaddress.ip_address(ip)
                checked.append(ip)
            except ValueError as e:
                raise ValueError(f"Invalid IP/CIDR entry: {ip}") from e
        return checked

    @model_validator(mode="after")
    def _prod_secret(self) -> "SecuritySettings":
        if os.getenv("ENV", "dev") == "prod" and self.secret_key.get_secret_value() == "dev-secret-not-for-prod":
            raise ValueError("Refusing to start in prod with default secret_key")
        return self


class ObservabilitySettings(BaseModel):
    log_level: LogLevel = Field(default="INFO")
    otlp_endpoint: Optional[str] = Field(default=None)   # e.g. http://otel-collector:4317
    service_name: str = Field(default="automation-core")
    tracing_enabled: bool = Field(default=True)
    metrics_enabled: bool = Field(default=True)


class BrowserSettings(BaseModel):
    # For Selenium/Playwright drivers
    headless: bool = Field(default=True)
    default_wait_s: float = Field(default=5.0, ge=0.0, le=120.0)
    downloads_dir: Path = Field(default=Path(".downloads"))


class ConcurrencySettings(BaseModel):
    # Async pools and rate limiting
    max_concurrency: int = Field(default=16, ge=1, le=2048)
    rate_limit_per_s: float = Field(default=20.0, ge=0.1, le=10000.0)
    batch_size: int = Field(default=50, ge=1, le=10000)


# -----------------------------
# Root settings
# -----------------------------
class Settings(BaseSettings):
    """
    Root settings object. Environment variables override fields using the prefix `AUTOC_`.
    Example:
        AUTOC_APP__ENV=prod
        AUTOC_DB__POSTGRES_DSN=postgresql+psycopg2://user:pass@host/db
        AUTOC_SECURITY__SECRET_KEY=...  # will be read as SecretStr
    """
    model_config = SettingsConfigDict(
        env_prefix="AUTOC_",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    app: AppSettings = Field(default_factory=AppSettings)
    http: HTTPSettings = Field(default_factory=HTTPSettings)
    db: DBSettings = Field(default_factory=DBSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    browser: BrowserSettings = Field(default_factory=BrowserSettings)
    concurrency: ConcurrencySettings = Field(default_factory=ConcurrencySettings)

    @classmethod
    def from_env(cls, env_file: Optional[Path] = None) -> "Settings":
        """
        Load settings with optional .env support. The resolution order:
        1) Explicit env_file argument (if exists)
        2) First of [.env.test, .env.ci, .env] in project root
        3) Pure environment variables only
        """
        root = _project_root()
        chosen = env_file if (env_file and env_file.exists()) else _first_existing_env_file(root)
        if chosen:
            # pydantic-settings v2 supports `.env_file` parameter via model_config param on init
            return cls(_env_file=str(chosen))
        return cls()

    @model_validator(mode="after")
    def _propagate_env(self) -> "Settings":
        # Ensure ENV consistency across sections
        os.environ.setdefault("ENV", self.app.env.value)
        return self


# -----------------------------
# Singleton accessor
# -----------------------------
@lru_cache(maxsize=1)
def get_settings(env_file: Optional[str | Path] = None) -> Settings:
    """
    Singleton accessor. Pass a path to a specific .env for tests:
        get_settings(env_file="tests/.env.test")
    """
    path: Optional[Path] = None
    if env_file:
        path = Path(env_file).resolve()
    try:
        return Settings.from_env(env_file=path)
    except ValidationError as e:
        # Re-raise with clearer message
        raise RuntimeError(f"Invalid configuration: {e}") from e


# -----------------------------
# Convenience: module-level alias
# -----------------------------
settings = get_settings()
