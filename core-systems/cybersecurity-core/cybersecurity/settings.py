# cybersecurity-core/cybersecurity/settings.py
from __future__ import annotations

"""
Промышленные настройки для cybersecurity-core.

Особенности:
- Pydantic v2 Settings с env-префиксом CSC_ и вложенным разделителем '__'
- Строгая типизация/валидация (семвер, URL, пути к сертификатам)
- БД (PostgreSQL asyncpg) + sync URL для миграций
- Redis для кеша и rate-limit (или in-memory)
- Безопасность: OAuth2/JWT (iss/aud/jwks), API-Key, mTLS, CORS
- Наблюдаемость: Sentry, OpenTelemetry (OTLP http/grpc)
- Логирование: text или JSON (если доступен python-json-logger)
- Фичефлаги и билд-метаданные
- Инварианты и самопроверка конфигурации
"""

import json
import logging
import os
import re
import ssl
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

from pydantic import AnyUrl, BaseModel, Field, HttpUrl, PostgresDsn, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ===========================
# Вспомогательные перечисления
# ===========================

class Environment(str, Enum):
    dev = "dev"
    staging = "staging"
    prod = "prod"
    test = "test"


class LogFormat(str, Enum):
    text = "text"
    json = "json"


class RateLimitBackend(str, Enum):
    memory = "memory"
    redis = "redis"


class CacheBackend(str, Enum):
    memory = "memory"
    redis = "redis"


class TracingExporter(str, Enum):
    none = "none"
    otlp_http = "otlp_http"
    otlp_grpc = "otlp_grpc"


class TLSMode(str, Enum):
    disabled = "disabled"
    require = "require"       # не проверяет CA
    verify = "verify"         # строгая проверка цепочки CA


SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[A-Za-z0-9\.-]+)?$")


# ===========================
# Утилиты парсинга
# ===========================

def _split_csv(value: Union[str, List[str], None]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        # уже нормализовано
        return [v for v in value if v]
    # принимаем CSV / пробельные разделители
    parts = [p.strip() for p in re.split(r"[,\s]+", value) if p.strip()]
    return parts


# ===========================
# Блоки настроек
# ===========================

class DatabaseSettings(BaseModel):
    """
    Настройки БД. Поддержка DSN или отдельных полей.
    """
    enabled: bool = True
    dsn: Optional[PostgresDsn] = Field(None, description="Полный DSN; если задан — имеет приоритет")
    host: str = "localhost"
    port: int = 5432
    user: str = "app"
    password: SecretStr = SecretStr("app")
    database: str = "cybersec"
    schema: str = "public"
    driver: Literal["postgresql+asyncpg"] = "postgresql+asyncpg"
    options: Dict[str, Any] = Field(default_factory=dict, description="Доп. параметры подключения")

    @property
    def async_url(self) -> str:
        if self.dsn:
            # dsn уже содержит схему postgresql://; для asyncpg нужно префикс driver
            url = str(self.dsn)
            if url.startswith("postgresql://"):
                return url.replace("postgresql://", "postgresql+asyncpg://", 1)
            return url
        # Сборка URL
        pwd = self.password.get_secret_value()
        base = f"{self.driver}://{self.user}:{pwd}@{self.host}:{self.port}/{self.database}"
        if self.options:
            from urllib.parse import urlencode
            return f"{base}?{urlencode(self.options)}"
        return base

    @property
    def sync_url(self) -> str:
        """
        Для миграций Alembic (psycopg/asyncpg-async_fallback).
        """
        async_url = self.async_url
        if async_url.startswith("postgresql+asyncpg://"):
            return async_url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
        return async_url


class RedisSettings(BaseModel):
    enabled: bool = True
    url: Optional[AnyUrl] = Field(default=None, description="redis:// или rediss:// URL")
    socket_timeout: float = 1.0
    retry_on_timeout: bool = True
    client_name: str = "cybersecurity-core"

    @field_validator("url", mode="before")
    @classmethod
    def _coerce_url(cls, v: Any) -> Any:
        # принимаем пустые строки как None
        if isinstance(v, str) and not v.strip():
            return None
        return v


class RateLimitSettings(BaseModel):
    backend: RateLimitBackend = RateLimitBackend.memory
    window_seconds: int = 60
    replenish_rate: int = 50      # запросов в окно
    burst_capacity: int = 100     # пик
    redis_prefix: str = "rl:"
    enabled: bool = True


class SecuritySettings(BaseModel):
    # Общие
    api_key_header: str = "X-API-Key"

    # OAuth2/JWT
    issuer: Optional[HttpUrl] = None
    audience: List[str] = Field(default_factory=list)
    jwks_url: Optional[HttpUrl] = None
    algorithms: List[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    leeway_seconds: int = 60

    # mTLS
    mtls_mode: TLSMode = TLSMode.disabled
    tls_ca_file: Optional[Path] = None
    tls_cert_file: Optional[Path] = None
    tls_key_file: Optional[Path] = None

    # Скоупы по умолчанию
    default_read_scopes: List[str] = Field(default_factory=lambda: ["policies:read"])
    default_write_scopes: List[str] = Field(default_factory=lambda: ["policies:write"])
    evaluate_scopes: List[str] = Field(default_factory=lambda: ["policies:evaluate"])

    @field_validator("audience", "algorithms", "default_read_scopes", "default_write_scopes", "evaluate_scopes", mode="before")
    @classmethod
    def _listify(cls, v: Any) -> Any:
        return _split_csv(v)


class CORSSettings(BaseModel):
    enabled: bool = True
    allow_origins: List[str] = Field(default_factory=lambda: ["*"])
    allow_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    allow_headers: List[str] = Field(default_factory=lambda: ["*"])
    allow_credentials: bool = False
    expose_headers: List[str] = Field(default_factory=lambda: ["ETag", "X-Request-ID"])
    max_age: int = 600

    @field_validator("allow_origins", "allow_methods", "allow_headers", "expose_headers", mode="before")
    @classmethod
    def _listify(cls, v: Any) -> Any:
        return _split_csv(v)


class SentrySettings(BaseModel):
    enabled: bool = False
    dsn: Optional[SecretStr] = None
    traces_sample_rate: float = 0.05
    profiles_sample_rate: float = 0.0
    environment_tag: Optional[str] = None


class OTelSettings(BaseModel):
    enabled: bool = False
    exporter: TracingExporter = TracingExporter.none
    endpoint: Optional[HttpUrl] = None   # http(s)://host:port или grpc://host:port (логически)
    headers: Dict[str, str] = Field(default_factory=dict)
    resource: Dict[str, str] = Field(default_factory=dict)  # service.version, service.namespace и т.п.


class TLSSettings(BaseModel):
    mode: TLSMode = TLSMode.disabled
    ca_file: Optional[Path] = None
    cert_file: Optional[Path] = None
    key_file: Optional[Path] = None

    def build_ssl_context(self) -> Optional[ssl.SSLContext]:
        if self.mode == TLSMode.disabled:
            return None
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if self.ca_file:
            ctx.load_verify_locations(cafile=str(self.ca_file))
        if self.mode == TLSMode.verify:
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if self.cert_file and self.key_file:
            ctx.load_cert_chain(certfile=str(self.cert_file), keyfile=str(self.key_file))
        return ctx


class FeatureFlags(BaseModel):
    enable_openapi: bool = True
    enable_metrics: bool = True
    enable_admin_api: bool = False
    enable_health_endpoints: bool = True


class LoggingSettings(BaseModel):
    level: str = "INFO"                  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    format: LogFormat = LogFormat.text   # text | json
    uvicorn_access: bool = True
    propagate: bool = False
    json_indent: Optional[int] = None

    @property
    def level_numeric(self) -> int:
        return logging.getLevelName(self.level.upper()) if isinstance(self.level, str) else int(self.level)


# ===========================
# Основные настройки приложения
# ===========================

class AppSettings(BaseSettings):
    """
    Основной конфиг приложения.
    Переопределяется env-переменными с префиксом CSC_ и вложенным разделителем '__'.
    Примеры:
        CSC_ENV=prod
        CSC_DB__HOST=postgres
        CSC_DB__PASSWORD=supersecret
        CSC_SECURITY__AUDIENCE="api,neurocity"
        CSC_CORS__ALLOW_ORIGINS="https://app.example.com,https://admin.example.com"
    """
    model_config = SettingsConfigDict(
        env_prefix="CSC_",
        env_file=".env",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    # Метаданные приложения
    app_name: str = "cybersecurity-core"
    description: str = "NeuroCity Cybersecurity Core"
    environment: Environment = Environment.dev
    debug: bool = False

    # Билд/релиз
    version: str = "0.1.0"
    build_sha: Optional[str] = None
    build_date: Optional[str] = None  # ISO 8601

    # Сетевые параметры API
    host: str = "0.0.0.0"
    port: int = 8080
    root_path: str = ""
    openapi_url: Optional[str] = "/openapi.json"
    docs_url: Optional[str] = "/docs"
    redoc_url: Optional[str] = "/redoc"

    # Подсистемы
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    ratelimit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    cors: CORSSettings = Field(default_factory=CORSSettings)
    sentry: SentrySettings = Field(default_factory=SentrySettings)
    otel: OTelSettings = Field(default_factory=OTelSettings)
    tls: TLSSettings = Field(default_factory=TLSSettings)
    features: FeatureFlags = Field(default_factory=FeatureFlags)
    logging_: LoggingSettings = Field(default_factory=LoggingSettings, alias="logging")

    # Технические ограничения API
    default_page_limit: int = 50
    max_page_limit: int = 500
    max_payload_mb: int = 10

    # Сервисные заголовки
    request_id_header: str = "X-Request-ID"
    tenant_id_header: str = "X-Tenant-ID"

    # Валидации/нормализации
    @field_validator("version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not SEMVER_RE.match(v):
            raise ValueError("version must be semantic version (e.g., 1.2.3 or 1.2.3-rc1)")
        return v

    @field_validator("openapi_url", "docs_url", "redoc_url")
    @classmethod
    def _normalize_slash(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return v if v.startswith("/") else "/" + v

    # Сводные свойства
    @property
    def is_prod(self) -> bool:
        return self.environment == Environment.prod

    @property
    def is_debug(self) -> bool:
        return self.debug or self.environment in (Environment.dev, Environment.test)

    @cached_property
    def max_payload_bytes(self) -> int:
        return self.max_payload_mb * 1024 * 1024

    # Инварианты конфигурации
    def verify(self) -> None:
        errors: List[str] = []

        if self.ratelimit.enabled and self.ratelimit.backend == RateLimitBackend.redis:
            if not (self.redis.enabled and self.redis.url):
                errors.append("RateLimit backend 'redis' требует включенный Redis и redis.url")

        if self.security.mtls_mode != TLSMode.disabled:
            # для mTLS ожидаем CA
            if not self.security.tls_ca_file:
                errors.append("mTLS включен, но не указан security.tls_ca_file")
            else:
                if not Path(self.security.tls_ca_file).exists():
                    errors.append(f"Файл CA не найден: {self.security.tls_ca_file}")
            # Сертификат/ключ сервера — опционально (если завершается за балансером), но проверим, если указаны
            if self.security.tls_cert_file and not Path(self.security.tls_cert_file).exists():
                errors.append(f"Файл сертификата не найден: {self.security.tls_cert_file}")
            if self.security.tls_key_file and not Path(self.security.tls_key_file).exists():
                errors.append(f"Файл ключа не найден: {self.security.tls_key_file}")

        if self.tls.mode != TLSMode.disabled:
            if self.tls.cert_file and not Path(self.tls.cert_file).exists():
                errors.append(f"TLS: cert_file не найден: {self.tls.cert_file}")
            if self.tls.key_file and not Path(self.tls.key_file).exists():
                errors.append(f"TLS: key_file не найден: {self.tls.key_file}")
            if self.tls.mode == TLSMode.verify and self.tls.ca_file and not Path(self.tls.ca_file).exists():
                errors.append(f"TLS: ca_file не найден: {self.tls.ca_file}")

        if self.sentry.enabled and (not self.sentry.dsn or not self.sentry.dsn.get_secret_value().strip()):
            errors.append("Sentry включен, но dsn не задан")

        if self.otel.enabled and self.otel.exporter != TracingExporter.none and not self.otel.endpoint:
            errors.append("OpenTelemetry включен, но не задан endpoint")

        # PROD ужесточения
        if self.is_prod:
            if self.cors.enabled and "*" in self.cors.allow_origins:
                errors.append("CORS в prod не должен иметь allow_origins=['*']")
            if self.openapi_url in ("/docs", "/redoc"):
                errors.append("Недопустимые пути для OpenAPI")

        if errors:
            raise RuntimeError("Некорректная конфигурация:\n - " + "\n - ".join(errors))

    # CORS-kwargs для FastAPI
    def cors_kwargs(self) -> Dict[str, Any]:
        if not self.cors.enabled:
            return {}
        return dict(
            allow_origins=self.cors.allow_origins,
            allow_methods=self.cors.allow_methods,
            allow_headers=self.cors.allow_headers,
            allow_credentials=self.cors.allow_credentials,
            expose_headers=self.cors.expose_headers,
            max_age=self.cors.max_age,
        )

    # Логирование: dictConfig
    def logging_dict_config(self) -> Dict[str, Any]:
        fmt_text = "%(asctime)s %(levelname)s %(name)s %(message)s"
        fmt_access = '%(asctime)s %(levelname)s %(client_addr)s - "%(request_line)s" %(status_code)s'

        handlers: Dict[str, Any] = {
            "default": {
                "class": "logging.StreamHandler",
                "level": self.logging_.level,
                "stream": "ext://sys.stdout",
                "formatter": "default_json" if self.logging_.format == LogFormat.json else "default",
            },
            "access": {
                "class": "logging.StreamHandler",
                "level": self.logging_.level,
                "stream": "ext://sys.stdout",
                "formatter": "access_json" if self.logging_.format == LogFormat.json else "access",
            },
        }

        formatters: Dict[str, Any] = {
            "default": {"format": fmt_text},
            "access": {"format": fmt_access},
        }

        # Попытка JSON-форматтера если установлен python-json-logger, иначе fallback на text
        if self.logging_.format == LogFormat.json:
            try:
                import pythonjsonlogger  # noqa: F401
                json_fmt = {
                    "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
                    "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
                }
                if self.logging_.json_indent is not None:
                    json_fmt["json_indent"] = self.logging_.json_indent
                formatters["default_json"] = json_fmt
                formatters["access_json"] = {
                    "format": "%(asctime)s %(levelname)s access %(message)s",
                    "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
                }
            except Exception:
                # Fallback -> используем text, но не меняем выбранный формат глобально
                handlers["default"]["formatter"] = "default"
                handlers["access"]["formatter"] = "access"

        config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": formatters,
            "handlers": handlers,
            "root": {
                "level": self.logging_.level,
                "handlers": ["default"],
            },
            "loggers": {
                "uvicorn.error": {"level": self.logging_.level, "handlers": ["default"], "propagate": self.logging_.propagate},
                "uvicorn.access": {
                    "level": self.logging_.level,
                    "handlers": (["access"] if self.logging_.uvicorn_access else []),
                    "propagate": self.logging_.propagate,
                },
                "gunicorn.error": {"level": self.logging_.level, "handlers": ["default"], "propagate": self.logging_.propagate},
            },
        }
        return config

    # Редакция секретов для выводов/логов
    def redacted_dict(self) -> Dict[str, Any]:
        data = self.model_dump(mode="json")
        # Спрячем очевидные секреты
        try:
            if self.db.password:
                data["db"]["password"] = "***"
        except Exception:
            pass
        try:
            if self.sentry.dsn:
                data["sentry"]["dsn"] = "***"
        except Exception:
            pass
        return data


# ===========================
# Загрузка настроек (singleton)
# ===========================

def load_settings() -> AppSettings:
    """
    Загружаем настройки один раз, проверяем инварианты.
    """
    settings = AppSettings()  # читает .env и ENV
    # Авто-отключение документации в prod при фичефлаге
    if settings.is_prod and not settings.features.enable_openapi:
        settings.openapi_url = None
        settings.docs_url = None
        settings.redoc_url = None
    settings.verify()
    return settings


# Глобальный экземпляр для импорта
settings: AppSettings = load_settings()


# ===========================
# Пример интеграции логирования
# ===========================

def configure_logging() -> None:
    """
    Конфигурирует logging через dictConfig, опираясь на настройки.
    """
    import logging.config

    logging.config.dictConfig(settings.logging_dict_config())
    logging.getLogger(__name__).debug("Logging configured", extra={"env": settings.environment, "app": settings.app_name})


# Автоконфигурация логирования при импорте модуля (опционально):
if os.getenv("CSC_AUTO_CONFIGURE_LOGGING", "1") == "1":
    try:
        configure_logging()
    except Exception as e:
        # Не ломаем импорт из-за логирования
        print(f"[settings] logging configuration failed: {e}")
