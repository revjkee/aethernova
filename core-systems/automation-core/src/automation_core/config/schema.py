"""
automation_core.config.schema
-----------------------------

Промышленная схема конфигурации для сервисов automation-core.

Ключевые свойства:
- Pydantic v2 + pydantic-settings: типобезопасность, .env, переменные окружения.
- Вложенные секции с env_nested_delimiter="__": APP__NAME, DB__URL, REDIS__URL и т.д.
- Жёсткие проверки прод-политик (секреты, ALLOWED_HOSTS, порты, TLS-файлы).
- Маскировка секретов в DSN (dsn_safe).
- YAML-оверрайды с иммутабельным обновлением.
- Кэш загрузки настроек через lru_cache.

Пример переменных окружения:
  APP__NAME=automation-core
  APP__ENV=prod
  APP__DEBUG=false
  SERVER__HOST=0.0.0.0
  SERVER__PORT=8080
  DB__URL=postgresql+asyncpg://user:pass@db:5432/automation
  REDIS__URL=redis://redis:6379/0
  SECURITY__SECRET_KEY=<strong-secret>
  SECURITY__ALLOWED_HOSTS=api.example.com,internal.local
  SECURITY__CORS__ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
  OBS__OTLP_ENDPOINT=http://otel-collector:4318
  OBS__SENTRY_DSN=https://<key>@sentry.io/<project>
  TLS__ENABLED=true
  TLS__CERT_FILE=/etc/tls/tls.crt
  TLS__KEY_FILE=/etc/tls/tls.key
  FF__USE_CIRCUIT_BREAKER=true
  FF__ENABLE_METRICS=true

Зависимости (минимум):
  pydantic>=2.5
  pydantic-settings>=2.2
"""

from __future__ import annotations

import os
import re
import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Dict, List, Literal, Optional, Union

from pydantic import (
    AnyHttpUrl,
    AnyUrl,
    BaseModel,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

try:
    from importlib.metadata import PackageNotFoundError, version as pkg_version
except Exception:  # pragma: no cover
    PackageNotFoundError = Exception  # type: ignore
    def pkg_version(_: str) -> str:  # type: ignore
        raise PackageNotFoundError


# ------------------------- Вспомогательные типы/утилиты ------------------------- #

EnvName = Literal["dev", "staging", "prod", "test"]


def _coerce_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def _coerce_list(v: Any) -> List[str]:
    if v is None or v == "":
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    # Разделители: запятая / перевод строки / пробелы
    parts = re.split(r"[,\n]+", str(v))
    return [p.strip() for p in parts if p.strip()]


def _read_version_fallback() -> str:
    # 1) переменная окружения приоритетнее
    env_ver = os.getenv("APP_VERSION")
    if env_ver:
        return env_ver.strip()
    # 2) попытка прочитать pip-пакетное имя (если проект установлен)
    for name in ("automation-core", "automation_core"):
        try:
            return pkg_version(name)
        except PackageNotFoundError:
            pass
    # 3) попытка прочитать файл VERSION в корне репозитория (до 3 уровней вверх)
    here = Path(__file__).resolve()
    for up in [here.parent, here.parent.parent, here.parent.parent.parent]:
        candidate = up.parent / "VERSION"
        if candidate.exists():
            try:
                return candidate.read_text(encoding="utf-8").strip()
            except Exception:
                break
    return "0.0.0-dev"


def _mask_dsn_password(dsn: str) -> str:
    """
    Маскирует пароль в DSN: user:***@host
    Поддерживает форматы *://user:pass@host:port/db
    """
    return re.sub(r"(\/\/[^:\s\/]+:)([^@\s\/]+)(@)", r"\1***\3", dsn)


# -------------------------------- Секции схемы ---------------------------------- #

class AppConfig(BaseModel):
    name: str = Field(default="automation-core", min_length=1, max_length=128)
    env: EnvName = Field(default="dev")
    debug: bool = Field(default=False)
    version: str = Field(default_factory=_read_version_fallback)

    @model_validator(mode="after")
    def _enforce_debug_policy(self) -> "AppConfig":
        if self.env == "prod" and self.debug:
            raise ValueError("Debug нельзя включать в prod окружении")
        return self


class ServerConfig(BaseModel):
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000, ge=1, le=65535)
    workers: int = Field(default=1, ge=1, le=64)
    reload: bool = Field(default=False, description="Для dev; в prod будет принудительно отключено")

    @model_validator(mode="after")
    def _prod_hardening(self) -> "ServerConfig":
        # Ограничиваем reload в проде, даже если кто-то включил через окружение
        if os.getenv("APP__ENV", "").strip().lower() == "prod":
            object.__setattr__(self, "reload", False)
        return self


class DatabaseConfig(BaseModel):
    url: str = Field(
        default="sqlite+aiosqlite:///:memory:",
        description="Async SQLAlchemy DSN",
    )
    echo: bool = Field(default=False)
    pool_size: int = Field(default=10, ge=1, le=256)
    pool_timeout: int = Field(default=30, ge=1, le=600)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        # Разрешенные async драйверы
        allowed_prefixes = (
            "postgresql+asyncpg://",
            "sqlite+aiosqlite://",
            "mysql+aiomysql://",
            "mssql+aioodbc://",
        )
        if not v:
            raise ValueError("DB url пуст")
        if not v.startswith(allowed_prefixes):
            raise ValueError(
                "DB url должен быть async (postgresql+asyncpg, sqlite+aiosqlite, mysql+aiomysql, mssql+aioodbc)"
            )
        return v

    @property
    def dsn_safe(self) -> str:
        return _mask_dsn_password(self.url)


class RedisConfig(BaseModel):
    url: AnyUrl = Field(default="redis://localhost:6379/0")
    ssl: bool = Field(default=False)
    socket_timeout: int = Field(default=5, ge=1, le=120)

    @model_validator(mode="after")
    def _deduce_ssl(self) -> "RedisConfig":
        # rediss:// -> SSL true
        if str(self.url).startswith("rediss://"):
            object.__setattr__(self, "ssl", True)
        return self


class RabbitMQConfig(BaseModel):
    host: str = Field(default="localhost")
    port: int = Field(default=5672, ge=1, le=65535)
    username: str = Field(default="guest")
    password: SecretStr = Field(default=SecretStr("guest"))
    vhost: str = Field(default="/")
    heartbeat: int = Field(default=30, ge=0, le=600)
    ssl: bool = Field(default=False)

    @property
    def dsn_safe(self) -> str:
        pwd = "***"
        return f"amqp://{self.username}:{pwd}@{self.host}:{self.port}{self.vhost}"


class KafkaConfig(BaseModel):
    bootstrap_servers: List[str] = Field(default_factory=lambda: ["localhost:9092"])
    client_id: str = Field(default="automation-core")
    security_protocol: Literal["PLAINTEXT", "SSL", "SASL_SSL"] = Field(default="PLAINTEXT")
    sasl_mechanism: Optional[Literal["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"]] = None
    sasl_username: Optional[str] = None
    sasl_password: Optional[SecretStr] = None


BrokerType = Literal["rabbitmq", "kafka"]

class BrokerConfig(BaseModel):
    type: BrokerType = Field(default="rabbitmq")
    rabbitmq: Optional[RabbitMQConfig] = Field(default_factory=RabbitMQConfig)
    kafka: Optional[KafkaConfig] = Field(default=None)

    @model_validator(mode="after")
    def _one_of(self) -> "BrokerConfig":
        if self.type == "rabbitmq" and self.rabbitmq is None:
            raise ValueError("Для type=rabbitmq требуется секция rabbitmq")
        if self.type == "kafka" and self.kafka is None:
            raise ValueError("Для type=kafka требуется секция kafka")
        return self


class CORSConfig(BaseModel):
    allowed_origins: List[AnyHttpUrl] = Field(default_factory=list)
    allow_credentials: bool = Field(default=True)
    allow_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    allow_headers: List[str] = Field(default_factory=lambda: ["*"])


class SecurityConfig(BaseModel):
    secret_key: SecretStr = Field(default=SecretStr("change-me"))
    allowed_hosts: List[str] = Field(default_factory=list, description="Список FQDN/IP, разрешённых к обслуживанию")
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = Field(default="HS256")
    jwt_access_ttl_sec: int = Field(default=3600, ge=60, le=60 * 60 * 24)
    cors: CORSConfig = Field(default_factory=CORSConfig)

    @model_validator(mode="after")
    def _prod_requirements(self) -> "SecurityConfig":
        env_raw = os.getenv("APP__ENV", "").strip().lower()
        if env_raw == "prod":
            if self.secret_key.get_secret_value() in ("change-me", "", None):
                raise ValueError("В prod необходимо задать SECURITY__SECRET_KEY")
            if not self.allowed_hosts:
                raise ValueError("В prod необходимо задать SECURITY__ALLOWED_HOSTS")
        return self


class ObservabilityConfig(BaseModel):
    otlp_endpoint: Optional[AnyHttpUrl] = Field(default=None, description="OTLP HTTP endpoint, напр. http://otel:4318")
    sentry_dsn: Optional[AnyUrl] = Field(default=None)
    traces_enabled: bool = Field(default=True)
    metrics_enabled: bool = Field(default=True)


class TLSConfig(BaseModel):
    enabled: bool = Field(default=False)
    cert_file: Optional[Path] = None
    key_file: Optional[Path] = None

    @model_validator(mode="after")
    def _validate_tls_files(self) -> "TLSConfig":
        if self.enabled:
            if not self.cert_file or not self.cert_file.exists():
                raise ValueError("TLS включен, но TLS__CERT_FILE отсутствует или не существует")
            if not self.key_file or not self.key_file.exists():
                raise ValueError("TLS включен, но TLS__KEY_FILE отсутствует или не существует")
        return self


class FeatureFlags(BaseModel):
    use_circuit_breaker: bool = Field(default=True)
    enable_metrics: bool = Field(default=True)
    enable_request_id: bool = Field(default=True)
    enable_health_probes: bool = Field(default=True)
    hard_fail_on_migrations: bool = Field(default=False)


# ----------------------------------- Settings ----------------------------------- #

class Settings(BaseSettings):
    """
    Главная схема настроек. Все поля — вложенные, читаются из окружения .env/ENV.
    Вложенные ключи маппятся через APP__*, DB__*, SECURITY__* и т.д.
    """
    model_config = SettingsConfigDict(
        env_prefix="",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app: AppConfig = Field(default_factory=AppConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    db: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    broker: BrokerConfig = Field(default_factory=BrokerConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    obs: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    tls: TLSConfig = Field(default_factory=TLSConfig)
    ff: FeatureFlags = Field(default_factory=FeatureFlags)

    @model_validator(mode="after")
    def _cross_section_policies(self) -> "Settings":
        # Пример сквозных прод-политик
        if self.app.env == "prod":
            # Предостережение: in-memory БД в prod недопустима
            if str(self.db.url).startswith("sqlite+aiosqlite:///:memory:"):
                raise ValueError("Prod окружение не может использовать in-memory SQLite")
            if self.server.port in {80, 443} and self.tls.enabled is False:
                # Разрешено, но настоятельно рекомендуем TLS — усиливаем контроль
                raise ValueError("Сервер на 80/443 в prod требует включённый TLS")
        return self

    # Удобные computed-свойства
    @property
    def is_prod(self) -> bool:
        return self.app.env == "prod"

    @property
    def db_dsn_safe(self) -> str:
        return self.db.dsn_safe

    def dumps_masked(self) -> str:
        """
        Возвращает JSON настроек с замаскированными секретами.
        """
        def _mask(obj: Any) -> Any:
            if isinstance(obj, SecretStr):
                return "***"
            if isinstance(obj, dict):
                return {k: _mask(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_mask(x) for x in obj]
            return obj

        raw = self.model_dump(mode="json")
        masked = _mask(raw)
        return json.dumps(masked, ensure_ascii=False, indent=2)


# ------------------------------ Загрузка/оверрайды ------------------------------ #

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Загружает и кэширует настройки из .env/ENV.
    Повторные вызовы возвращают один и тот же экземпляр.
    """
    return Settings()


def load_yaml_overrides(path: Union[str, Path]) -> Settings:
    """
    Загружает YAML-оверрайды и возвращает новый экземпляр Settings с применёнными изменениями.
    Пример:
        s = get_settings()
        s2 = load_yaml_overrides("overrides.yaml")
    """
    try:
        import yaml  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Для YAML-оверрайдов требуется пакет PyYAML") from e

    base = get_settings()
    data: Dict[str, Any]
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError("YAML оверрайд должен быть объектом (mapping) верхнего уровня")

    # Иммутабельное обновление
    def deep_update(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(dst)
        for k, v in src.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = deep_update(out[k], v)  # type: ignore
            else:
                out[k] = v
        return out

    merged = deep_update(base.model_dump(mode="python"), data)
    try:
        return Settings(**merged)
    except ValidationError as ve:
        # Явная ошибка валидности, чтобы быстрый фейл в CI/CD
        raise ve


__all__ = [
    "EnvName",
    "AppConfig",
    "ServerConfig",
    "DatabaseConfig",
    "RedisConfig",
    "RabbitMQConfig",
    "KafkaConfig",
    "BrokerConfig",
    "CORSConfig",
    "SecurityConfig",
    "ObservabilityConfig",
    "TLSConfig",
    "FeatureFlags",
    "Settings",
    "get_settings",
    "load_yaml_overrides",
]
