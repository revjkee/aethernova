# policy_core/settings.py
from __future__ import annotations

import json
import logging
import logging.config
import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    # Опционально подключаем dotenv, если установлен
    from dotenv import load_dotenv
    _HAS_DOTENV = True
except Exception:
    _HAS_DOTENV = False

from pydantic import BaseModel, Field, SecretStr, ValidationError, computed_field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ========= Enums =========

class AppEnv(str, Enum):
    dev = "dev"
    test = "test"
    staging = "staging"
    prod = "prod"


class LogFormat(str, Enum):
    text = "text"
    json = "json"


class RBACProvider(str, Enum):
    casbin = "casbin"
    oso = "oso"
    custom = "custom"


# ========= Sub-models =========

class AppConfig(BaseModel):
    name: str = Field(default="policy-core")
    version: str = Field(default="0.1.0")
    env: AppEnv = Field(default=AppEnv.dev)
    debug: bool = Field(default=True)
    timezone: str = Field(default="UTC")
    root_dir: Path = Field(default_factory=lambda: Path(os.getenv("POLICY_APP__ROOT_DIR", Path.cwd().as_posix())))
    commit_sha: Optional[str] = Field(default=None)
    instance_id: Optional[str] = Field(default=None)  # для мульти-инстансов, метка узла

    @computed_field
    @property
    def is_prod(self) -> bool:
        return self.env == AppEnv.prod

    @field_validator("debug")
    @classmethod
    def _debug_sane(cls, v: bool, info):
        # В prod debug должен быть False
        env = info.data.get("env", AppEnv.dev)
        if env == AppEnv.prod and v:
            raise ValueError("Debug must be False in production")
        return v


class SecurityConfig(BaseModel):
    secret_key: SecretStr = Field(default=SecretStr("change-me-in-prod"))
    allow_origins: List[str] = Field(default=["*"])  # CORS
    allow_credentials: bool = Field(default=True)
    allow_methods: List[str] = Field(default=["*"])
    allow_headers: List[str] = Field(default=["*"])
    allowed_hosts: List[str] = Field(default=["*"])  # хост-валидация
    csrf_secret: Optional[SecretStr] = Field(default=None)

    # JWT
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_ttl_seconds: int = Field(default=3600)
    jwt_refresh_ttl_seconds: int = Field(default=60 * 60 * 24 * 14)

    # Парольная политика
    password_min_length: int = Field(default=10)
    password_require_upper: bool = Field(default=True)
    password_require_digit: bool = Field(default=True)
    password_require_special: bool = Field(default=True)

    @field_validator("allow_origins", "allow_methods", "allow_headers", "allowed_hosts", mode="before")
    @classmethod
    def _split_csv(cls, v):
        # Поддержка CSV-строк из ENV
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    @field_validator("jwt_access_ttl_seconds", "jwt_refresh_ttl_seconds", "password_min_length")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Value must be positive")
        return v


class DatabaseConfig(BaseModel):
    # Только асинхронные драйверы (проверка валидатором)
    url: str = Field(default="postgresql+asyncpg://user:pass@localhost:5432/policy_core")
    pool_size: int = Field(default=10)
    max_overflow: int = Field(default=20)
    pool_timeout: float = Field(default=30.0)
    pool_recycle: int = Field(default=1800)
    echo: bool = Field(default=False)
    replicas: List[str] = Field(default_factory=list)  # read-only реплики (если есть)

    @field_validator("url")
    @classmethod
    def _ensure_async_driver(cls, v: str) -> str:
        if not v.startswith("postgresql+asyncpg://"):
            raise ValueError("Database URL must use async driver: postgresql+asyncpg://")
        return v

    @field_validator("replicas", mode="before")
    @classmethod
    def _replicas_csv(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    def sqlalchemy_engine_kwargs(self) -> Dict[str, Any]:
        return {
            "pool_size": self.pool_size,
            "max_overflow": self.max_overflow,
            "pool_timeout": self.pool_timeout,
            "pool_recycle": self.pool_recycle,
            "echo": self.echo,
            "future": True,
        }


class RedisConfig(BaseModel):
    url: str = Field(default="redis://localhost:6379/0")
    healthcheck_interval: int = Field(default=15)

    @field_validator("url")
    @classmethod
    def _redis_scheme(cls, v: str) -> str:
        if not (v.startswith("redis://") or v.startswith("rediss://")):
            raise ValueError("Redis URL must start with redis:// or rediss://")
        return v


class BrokerConfig(BaseModel):
    # Пример: RabbitMQ / NATS / Kafka — здесь строка подключения брокера задач/сообщений
    url: Optional[str] = Field(default=None)
    prefetch_count: int = Field(default=10)
    # Доп. параметры по необходимости


class LoggingConfig(BaseModel):
    level: str = Field(default="INFO")  # DEBUG/INFO/WARNING/ERROR
    fmt: LogFormat = Field(default=LogFormat.text)  # text/json
    enable_uvicorn_integration: bool = Field(default=True)
    propagate: bool = Field(default=False)
    service_field: str = Field(default="policy-core")  # name в логах

    def dict_config(self) -> Dict[str, Any]:
        # Базовая конфигурация logging.dictConfig
        formatters = {
            "plain": {
                "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
            },
            "uvicorn": {
                "format": "%(levelprefix)s %(client_addr)s - '%(request_line)s' %(status_code)s",
            },
            "json": {
                "()": "logging.Formatter",
                "format": json.dumps({
                    "t": "%(asctime)s",
                    "lvl": "%(levelname)s",
                    "logger": "%(name)s",
                    "msg": "%(message)s",
                    "svc": self.service_field,
                }),
            },
        }

        handler_formatter = "json" if self.fmt == LogFormat.json else "plain"

        handlers = {
            "default": {
                "class": "logging.StreamHandler",
                "level": self.level,
                "formatter": handler_formatter,
            }
        }

        loggers = {
            "": {  # root
                "handlers": ["default"],
                "level": self.level,
                "propagate": self.propagate,
            }
        }

        if self.enable_uvicorn_integration:
            loggers.update({
                "uvicorn": {"handlers": ["default"], "level": self.level, "propagate": False},
                "uvicorn.error": {"handlers": ["default"], "level": self.level, "propagate": False},
                "uvicorn.access": {
                    "handlers": ["default"],
                    "level": self.level,
                    "propagate": False,
                },
            })

        return {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": formatters,
            "handlers": handlers,
            "loggers": loggers,
        }


class TracingConfig(BaseModel):
    enabled: bool = Field(default=False)
    service_name: str = Field(default="policy-core")
    exporter: str = Field(default="otlp")  # otlp/jaeger/none
    endpoint: Optional[str] = Field(default=None)  # OTLP/Jaeger endpoint
    sample_ratio: float = Field(default=1.0)

    def init_tracer_provider(self) -> None:
        if not self.enabled:
            return
        try:
            # Lazy import, чтобы не требовать зависимость жестко
            from opentelemetry import trace
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            if self.exporter == "otlp":
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                exporter = OTLPSpanExporter(endpoint=self.endpoint) if self.endpoint else OTLPSpanExporter()
            elif self.exporter == "jaeger":
                from opentelemetry.exporter.jaeger.thrift import JaegerExporter
                exporter = JaegerExporter(agent_host_name=self.endpoint or "localhost", agent_port=6831)
            else:
                return

            resource = Resource.create({"service.name": self.service_name})
            provider = TracerProvider(resource=resource)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
        except Exception:
            # Безопасный фолбэк — не роняем приложение из-за трейсинга
            pass


class SentryConfig(BaseModel):
    dsn: Optional[str] = Field(default=None)
    traces_sample_rate: float = Field(default=0.0)
    environment: Optional[str] = Field(default=None)

    def init_sentry(self, release: Optional[str] = None) -> None:
        if not self.dsn:
            return
        try:
            import sentry_sdk
            sentry_sdk.init(
                dsn=self.dsn,
                traces_sample_rate=self.traces_sample_rate,
                environment=self.environment,
                release=release,
            )
        except Exception:
            # Безопасный фолбэк
            pass


class RBACConfig(BaseModel):
    provider: RBACProvider = Field(default=RBACProvider.casbin)
    # Casbin
    casbin_model: Optional[Path] = Field(default=None)   # путь до model.conf
    casbin_policy: Optional[Path] = Field(default=None)  # путь до policy.csv
    # OSO
    oso_policies_dir: Optional[Path] = Field(default=None)
    # кастомный провайдер - ваши параметры…

    @computed_field
    @property
    def is_casbin_ready(self) -> bool:
        return self.provider == RBACProvider.casbin and self.casbin_model and self.casbin_policy

    @computed_field
    @property
    def is_oso_ready(self) -> bool:
        return self.provider == RBACProvider.oso and self.oso_policies_dir is not None


class RateLimitConfig(BaseModel):
    default_per_minute: int = Field(default=120)
    burst: int = Field(default=60)
    per_ip: bool = Field(default=True)
    per_token: bool = Field(default=True)

    @field_validator("default_per_minute", "burst")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Value must be positive")
        return v


class FeatureFlags(BaseModel):
    enable_admin_api: bool = Field(default=True)
    enable_policy_dry_run: bool = Field(default=True)
    enable_audit_log: bool = Field(default=True)
    enable_decision_cache: bool = Field(default=True)
    enable_metrics: bool = Field(default=True)


# ========= Root Settings =========

class Settings(BaseSettings):
    """
    POLICY_* переменные окружения, вложенные поля через POLICY_<SECTION>__<FIELD>
    Пример:
      POLICY_APP__ENV=prod
      POLICY_DATABASE__URL=postgresql+asyncpg://user:pass@db:5432/policy
      POLICY_LOGGING__FMT=json
      POLICY_SECURITY__ALLOW_ORIGINS=https://app.example.com,https://admin.example.com
    """
    model_config = SettingsConfigDict(
        env_prefix="POLICY_",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    app: AppConfig = Field(default_factory=AppConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    broker: BrokerConfig = Field(default_factory=BrokerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    tracing: TracingConfig = Field(default_factory=TracingConfig)
    sentry: SentryConfig = Field(default_factory=SentryConfig)
    rbac: RBACConfig = Field(default_factory=RBACConfig)
    ratelimit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    features: FeatureFlags = Field(default_factory=FeatureFlags)

    # ======= Helpers =======

    def configure_logging(self) -> None:
        cfg = self.logging.dict_config()
        logging.config.dictConfig(cfg)
        # Доп. поля контекста сервиса
        logging.LoggerAdapter(logging.getLogger(), extra={"svc": self.logging.service_field})

    def configure_tracing(self) -> None:
        self.tracing.init_tracer_provider()

    def configure_sentry(self) -> None:
        release = None
        if self.app.commit_sha:
            release = f"{self.app.name}@{self.app.version}+{self.app.commit_sha[:7]}"
        self.sentry.init_sentry(release=release)

    def sanity_check(self) -> None:
        """
        Минимальные инварианты для prod.
        """
        if self.app.is_prod:
            if not self.security or not self.security.secret_key or self.security.secret_key.get_secret_value() == "change-me-in-prod":
                raise ValueError("In production you must set a strong SECURITY.SECRET_KEY")
            if self.security.allow_origins == ["*"]:
                raise ValueError("In production you must restrict SECURITY.ALLOW_ORIGINS")
            if self.logging.level.upper() == "DEBUG":
                raise ValueError("In production logging level must not be DEBUG")

    def export_public(self) -> Dict[str, Any]:
        """
        Безопасный экспорт без секретов.
        """
        data = self.model_dump()
        # Удаляем секреты
        try:
            data["security"]["secret_key"] = "***"
            if data["security"].get("csrf_secret"):
                data["security"]["csrf_secret"] = "***"
        except Exception:
            pass
        return data


# ========= Loader =========

def _preload_dotenv() -> None:
    """
    Пробуем мягко загрузить .env, если доступен python-dotenv.
    Порядок: .env.local, затем .env (не перезаписываем уже существующие переменные).
    """
    if not _HAS_DOTENV:
        return
    cwd = Path.cwd()
    local = cwd / ".env.local"
    common = cwd / ".env"
    # сначала локальный, затем общий (override=False)
    if local.exists():
        load_dotenv(dotenv_path=local, override=False)
    if common.exists():
        load_dotenv(dotenv_path=common, override=False)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Единая точка доступа к настройкам.
    Читает .env (если возможно), валидирует и выполняет sanity-check.
    """
    _preload_dotenv()
    try:
        s = Settings()  # pydantic-settings соберет из ENV
        s.sanity_check()
        return s
    except ValidationError as e:
        # Явная диагностика конфигурации
        msg = f"Configuration validation error: {e}"
        raise RuntimeError(msg) from e


# ========= Convenience on import =========
# Ленивая загрузка по желанию:
# settings = get_settings()
# settings.configure_logging()
# settings.configure_tracing()
# settings.configure_sentry()

__all__ = [
    "AppEnv",
    "LogFormat",
    "RBACProvider",
    "AppConfig",
    "SecurityConfig",
    "DatabaseConfig",
    "RedisConfig",
    "BrokerConfig",
    "LoggingConfig",
    "TracingConfig",
    "SentryConfig",
    "RBACConfig",
    "RateLimitConfig",
    "FeatureFlags",
    "Settings",
    "get_settings",
]
