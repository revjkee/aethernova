from __future__ import annotations

import base64
import json
import os
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

try:
    # Опционально: PyYAML для YAML-конфигов
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # YAML будет недоступен; остаётся JSON/ENV

from pydantic import BaseModel, Field, HttpUrl, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict, PydanticBaseSettingsSource, DotEnvSettingsSource


# ============ Утилиты парсинга/валидации ============

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdw]?)\s*$", re.IGNORECASE)
_TIME_MULT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration_to_seconds(value: Union[str, int, float]) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    m = _DURATION_RE.match(str(value))
    if not m:
        raise ValueError(f"Invalid duration: {value!r}")
    amount, unit = m.group(1), m.group(2).lower()
    return int(amount) * _TIME_MULT[unit]


def _split_csv_or_list(v: Union[str, Sequence[str], None]) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        if not v.strip():
            return []
        # Поддержка CSV, пробелов и новой строки
        parts = re.split(r"[\s,]+", v.strip())
        return [p for p in (x.strip() for x in parts) if p]
    return [x.strip() for x in v if x and str(x).strip()]


def _b64(s: Optional[str]) -> Optional[bytes]:
    if not s:
        return None
    return base64.b64decode(s)


def _read_version_file(maybe_path: Union[str, Path]) -> Optional[str]:
    try:
        p = Path(maybe_path)
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    return None


# ============ Кастомный источник настроек из файла ============

class FileSettingsSource(PydanticBaseSettingsSource):
    """
    Нестандартный источник настроек:
    - путь берётся из env OMNIMIND_CONFIG или параметра __config_file в AppSettings
    - поддерживаются YAML (.yml/.yaml) при наличии PyYAML, и JSON (.json)
    - структура файла должна повторять поля AppSettings (включая вложенные модели)
    """

    def __init__(self, settings_cls: type[BaseSettings], config_file: Optional[Union[str, Path]]):
        super().__init__(settings_cls)
        self.config_file = Path(config_file) if config_file else None

    def get_field_value(self, field, field_name: str) -> Tuple[Any, str, bool]:
        data = self._read_file()
        if not data:
            return None, field_name, False
        return data.get(field_name), field_name, field_name in data

    def _read_file(self) -> Dict[str, Any]:
        if not self.config_file:
            return {}
        if not self.config_file.exists():
            return {}
        suffix = self.config_file.suffix.lower()
        try:
            if suffix in (".yaml", ".yml") and yaml is not None:
                with self.config_file.open("r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
            if suffix == ".json":
                with self.config_file.open("r", encoding="utf-8") as f:
                    return json.load(f) or {}
        except Exception as e:  # pragma: no cover
            raise RuntimeError(f"Failed to read config file {self.config_file}: {e}")
        return {}


# ============ Секции конфигурации ============

class ServerConfig(BaseModel):
    host: str = Field("0.0.0.0")
    port: int = Field(8080, ge=1, le=65535)
    base_url: Optional[HttpUrl] = None
    root_path: str = Field("", description="Префикс префиксирования путей FastAPI (ingress)")
    workers: int = Field(0, ge=0, description="0 = пусть Uvicorn выберет автоматически")
    reload: bool = Field(False, description="Для локальной разработки")
    request_timeout_s: int = Field(30, ge=1)
    keepalive_s: int = Field(75, ge=1)
    cors_origins: List[str] = Field(default_factory=list)
    cors_allow_credentials: bool = False
    cors_allow_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    cors_allow_headers: List[str] = Field(default_factory=lambda: ["Authorization", "Content-Type", "X-Request-Id"])
    trust_proxy: bool = Field(True, description="Доверять заголовкам X-Forwarded-*")
    forwarded_allow_ips: List[str] = Field(default_factory=list, description="Белый список прокси, если требуется")

    @field_validator("cors_origins", "cors_allow_methods", "cors_allow_headers", mode="before")
    @classmethod
    def _split(cls, v: Any) -> Any:
        return _split_csv_or_list(v)

    def uvicorn_options(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "workers": None if self.workers == 0 else self.workers,
            "reload": self.reload,
            "timeout_keep_alive": self.keepalive_s,
        }


class DatabaseConfig(BaseModel):
    dsn: str = Field(..., description="Напр., postgresql+asyncpg://user:pass@host:5432/db")
    pool_size: int = Field(10, ge=1)
    max_overflow: int = Field(20, ge=0)
    connect_timeout_s: int = Field(5, ge=1)
    echo: bool = Field(False)
    schema: Optional[str] = Field(None, description="Напр., app")
    @field_validator("dsn")
    @classmethod
    def _validate_dsn(cls, v: str) -> str:
        if "://" not in v:
            raise ValueError("Invalid DB DSN")
        return v


class RedisConfig(BaseModel):
    url: str = Field(..., description="redis:// или rediss://")
    db: int = Field(0, ge=0)
    pool_size: int = Field(50, ge=1)
    tls: bool = Field(False)


class KafkaConfig(BaseModel):
    brokers: List[str] = Field(default_factory=list, description="host1:9092,host2:9092")
    client_id: str = Field("omnimind-core")
    acks: Literal["all", "leader", "none"] = "all"
    sasl_username: Optional[str] = None
    sasl_password_b64: Optional[str] = None
    sasl_mechanism: Optional[Literal["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"]] = None
    security_protocol: Literal["PLAINTEXT", "SASL_PLAINTEXT", "SSL", "SASL_SSL"] = "PLAINTEXT"

    @field_validator("brokers", mode="before")
    @classmethod
    def _split(cls, v: Any) -> Any:
        return _split_csv_or_list(v)


class JWKSConfigModel(BaseModel):
    url: str
    issuer: str
    audience: Union[str, List[str]]
    algorithms: List[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    cache_ttl_seconds: int = 600
    http_timeout_seconds: float = 3.0
    leeway_seconds: int = 60
    require_exp: bool = True
    require_iat: bool = False
    require_nbf: bool = False


class APIKeyConfigModel(BaseModel):
    enabled: bool = True
    header_name: str = "X-API-Key"
    query_name: str = "api_key"
    allowed_keys: List[str] = Field(default_factory=list)
    hmac_header: Optional[str] = None
    hmac_secret_b64: Optional[str] = None
    hmac_required: bool = False


class MTLSProxyConfigModel(BaseModel):
    enabled: bool = False
    verify_header: str = "X-SSL-Client-Verify"
    subject_header: str = "X-SSL-Client-S-DN"
    san_header: str = "X-SSL-Client-SAN"
    require_verify_success: bool = True
    trusted_proxy_cidrs: List[str] = Field(default_factory=list)


class AuthConfig(BaseModel):
    jwks: Optional[JWKSConfigModel] = None
    apikey: APIKeyConfigModel = Field(default_factory=APIKeyConfigModel)
    mtls: MTLSProxyConfigModel = Field(default_factory=MTLSProxyConfigModel)
    leeway_seconds: int = 60
    default_scopes: List[str] = Field(default_factory=list)
    default_roles: List[str] = Field(default_factory=list)
    jti_revocation_ttl_seconds: int = 3600

    def to_middleware_settings(self):
        """
        Ленивая конвертация в объекты middleware (избегаем циклических импортов).
        """
        try:
            from ops.api.http.middleware.auth import (
                AuthSettings as _AuthSettings,
                JWKSConfig as _JWKSConfig,
                APIKeyConfig as _APIKeyConfig,
                MTLSProxyConfig as _MTLSProxyConfig,
            )
        except Exception as e:  # pragma: no cover
            raise RuntimeError("auth middleware not available") from e

        jwks = None
        if self.jwks:
            jwks = _JWKSConfig(
                url=self.jwks.url,
                issuer=self.jwks.issuer,
                audience=tuple(self.jwks.audience) if isinstance(self.jwks.audience, list) else self.jwks.audience,
                algorithms=tuple(self.jwks.algorithms),
                cache_ttl_seconds=self.jwks.cache_ttl_seconds,
                http_timeout_seconds=self.jwks.http_timeout_seconds,
                leeway_seconds=self.jwks.leeway_seconds,
                require_exp=self.jwks.require_exp,
                require_iat=self.jwks.require_iat,
                require_nbf=self.jwks.require_nbf,
            )

        return _AuthSettings(
            jwks=jwks,
            apikey=_APIKeyConfig(
                enabled=self.apikey.enabled,
                header_name=self.apikey.header_name,
                query_name=self.apikey.query_name,
                allowed_keys=tuple(self.apikey.allowed_keys),
                hmac_header=self.apikey.hmac_header,
                hmac_secret_b64=self.apikey.hmac_secret_b64,
                hmac_required=self.apikey.hmac_required,
            ),
            mtls=_MTLSProxyConfig(
                enabled=self.mtls.enabled,
                verify_header=self.mtls.verify_header,
                subject_header=self.mtls.subject_header,
                san_header=self.mtls.san_header,
                require_verify_success=self.mtls.require_verify_success,
                trusted_proxy_cidrs=tuple(self.mtls.trusted_proxy_cidrs),
            ),
            leeway_seconds=self.leeway_seconds,
            default_scopes=tuple(self.default_scopes),
            default_roles=tuple(self.default_roles),
            jti_revocation_ttl_seconds=self.jti_revocation_ttl_seconds,
        )


class SecurityConfig(BaseModel):
    allowed_hosts: List[str] = Field(default_factory=list)
    cors_enabled: bool = True
    csrf_enabled: bool = False
    cookies_secure: bool = True
    session_secret_b64: Optional[str] = None

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def _split(cls, v: Any) -> Any:
        return _split_csv_or_list(v)


class TelemetryConfig(BaseModel):
    prometheus_enabled: bool = True
    prometheus_path: str = "/metrics"


class TracingConfig(BaseModel):
    enabled: bool = False
    otlp_endpoint: Optional[str] = None
    sample_ratio: float = Field(0.05, ge=0.0, le=1.0)
    service_name: str = "omnimind-core"
    service_version: Optional[str] = None


class MetricsConfig(BaseModel):
    enabled: bool = True
    runtime_metrics: bool = True  # gc, mem, etc.


class StorageS3Config(BaseModel):
    enabled: bool = False
    endpoint: Optional[str] = None  # кастомный endpoint, если минуем AWS
    bucket: Optional[str] = None
    region: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key_b64: Optional[str] = None
    use_path_style: bool = False
    tls: bool = True


class RateLimitConfig(BaseModel):
    enabled: bool = False
    capacity: int = Field(100, ge=1)
    refill_rate_per_s: int = Field(50, ge=1)
    burst: int = Field(50, ge=0)
    key_strategy: Literal["ip", "user", "api_key"] = "ip"


class FeaturesConfig(BaseModel):
    flags: Dict[str, bool] = Field(default_factory=dict)


# ============ Главный объект настроек ============

class AppSettings(BaseSettings):
    """
    Единая типобезопасная конфигурация приложения.
    Источники (приоритет у более левых):
      1) Параметры инициализации (init)
      2) Переменные окружения (OMNIMIND___)
      3) .env (если присутствует)
      4) Внешний конфиг (OMNIMIND_CONFIG=path.{yaml,json})
      5) Секреты из директории (например, Docker secrets)
    """
    model_config = SettingsConfigDict(
        env_prefix="OMNIMIND_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
        secrets_dir=os.environ.get("OMNIMIND_SECRETS_DIR", None),
    )

    # — Базовые параметры
    app_name: str = "omnimind-core"
    environment: Literal["dev", "staging", "prod", "test"] = "dev"
    version: Optional[str] = Field(default_factory=lambda: _read_version_file(Path(__file__).resolve().parents[2] / "VERSION"))
    debug: bool = False

    # — Секции
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig
    redis: Optional[RedisConfig] = None
    kafka: Optional[KafkaConfig] = None
    auth: AuthConfig = Field(default_factory=AuthConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    tracing: TracingConfig = Field(default_factory=TracingConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    storage_s3: StorageS3Config = Field(default_factory=StorageS3Config)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)

    # — Вспомогательные поля (не из ENV): путь к внешнему конфигу
    __config_file: Optional[Union[str, Path]] = Field(default=os.environ.get("OMNIMIND_CONFIG"))

    @classmethod
    def settings_customise_sources(
        cls,
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: DotEnvSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        # Порядок: init → ENV → .env → файл → секреты-директория
        file_src = FileSettingsSource(cls, os.environ.get("OMNIMIND_CONFIG"))
        return (init_settings, env_settings, dotenv_settings, file_src, file_secret_settings)

    @model_validator(mode="after")
    def _post(self) -> "AppSettings":
        # Безопасные дефолты/нормализация
        if self.tracing.enabled and not self.tracing.service_version and self.version:
            self.tracing.service_version = self.version
        return self

    # Удобные геттеры

    def uvicorn_options(self) -> Dict[str, Any]:
        return self.server.uvicorn_options()

    def auth_middleware_settings(self):
        return self.auth.to_middleware_settings()


# ============ Глобальные функции доступа ============

@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    try:
        return AppSettings()  # все источники подтянутся автоматически
    except ValidationError as e:
        # Явно печатаем в stderr, чтобы быстрее ловить ошибки конфигурации на старте
        print("Configuration error:", file=sys.stderr)
        print(e, file=sys.stderr)
        raise


def reload_settings() -> None:
    get_settings.cache_clear()


# ============ Пример (не исполняется при импорте) ============

if __name__ == "__main__":  # pragma: no cover
    # Быстрый вывод настроек для отладки локально
    s = get_settings()
    print(s.model_dump(mode="json", exclude={"__config_file"}))
