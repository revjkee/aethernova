# physical_integration/settings.py
# Промышленный модуль конфигурации:
# - Типобезопасные секции (HTTP/GRPC/Security/Storage/Bus/Observability/Resilience/Features)
# - Совместимость pydantic v1/v2
# - ENV-префикс: PIC_
# - Профили окружений: dev|staging|prod
# - Безопасные SecretStr, валидации и derived-поля
# - Настройка логирования через dictConfig
from __future__ import annotations

import json
import logging
import os
import re
import socket
import sys
from dataclasses import asdict as _dc_asdict
from functools import lru_cache
from typing import Any, Dict, List, Literal, Optional

try:
    # pydantic v2
    from pydantic_settings import BaseSettings
    from pydantic import BaseModel, Field, SecretStr, AnyUrl, ValidationError, field_validator, model_validator
    _PYDANTIC_V2 = True
except Exception:  # pragma: no cover
    # pydantic v1 fallback
    from pydantic import BaseSettings, BaseModel, Field, SecretStr, AnyUrl, ValidationError, validator as field_validator, root_validator as model_validator
    _PYDANTIC_V2 = False

from logging.config import dictConfig as _dictConfig


# ----------------------------- Утилиты -----------------------------
_DURATION_RE = re.compile(r"^\s*(\d+)(ms|s|m|h|d)\s*$", re.IGNORECASE)
_SIZE_RE = re.compile(r"^\s*(\d+)\s*(B|KB|MB|GB)\s*$", re.IGNORECASE)

def parse_duration(s: str) -> float:
    """
    Преобразует '250ms'|'2s'|'5m'|'1h'|'1d' -> секунды (float).
    """
    m = _DURATION_RE.match(str(s))
    if not m:
        raise ValueError(f"Invalid duration: {s!r}")
    val, unit = int(m.group(1)), m.group(2).lower()
    mult = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return val * mult

def parse_size(s: str) -> int:
    """
    Преобразует '128MB'|'4GB'|'512KB' -> байты (int).
    """
    m = _SIZE_RE.match(str(s))
    if not m:
        raise ValueError(f"Invalid size: {s!r}")
    val, unit = int(m.group(1)), m.group(2).upper()
    mult = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}[unit]
    return val * mult

def _bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


# ----------------------------- Секции -----------------------------
class App(BaseModel):
    name: str = Field("physical-integration-core")
    env: Literal["dev", "staging", "prod"] = Field(default="prod")
    region: Optional[str] = Field(default=None)
    zone: Optional[str] = Field(default=None)
    version: str = Field(default=os.getenv("APP_VERSION", "0.0.0"))
    git_commit: str = Field(default=os.getenv("GIT_COMMIT", "unknown"))
    build_date: str = Field(default=os.getenv("BUILD_DATE", "unknown"))
    hostname: str = Field(default_factory=lambda: socket.gethostname())

class HTTP(BaseModel):
    host: str = Field("0.0.0.0")
    port: int = Field(8080, ge=1, le=65535)
    metrics_port: int = Field(9090, ge=1, le=65535)
    read_timeout: str = Field("10s")
    write_timeout: str = Field("10s")
    idle_timeout: str = Field("60s")
    cors_enabled: bool = Field(False)
    allowed_origins: List[str] = Field(default_factory=lambda: ["*"])
    @field_validator("read_timeout", "write_timeout", "idle_timeout")
    def _durations(cls, v: str) -> str:
        parse_duration(v)  # валидация
        return v

class GRPC(BaseModel):
    host: str = Field("0.0.0.0")
    port: int = Field(9091, ge=1, le=65535)
    max_recv: str = Field("64MB")
    max_send: str = Field("64MB")
    keepalive_time: str = Field("20s")
    keepalive_timeout: str = Field("20s")
    max_concurrent_streams: int = Field(1024, ge=1)
    @field_validator("max_recv", "max_send")
    def _sizes(cls, v: str) -> str:
        parse_size(v)
        return v
    @field_validator("keepalive_time", "keepalive_timeout")
    def _durations(cls, v: str) -> str:
        parse_duration(v)
        return v

class TLS(BaseModel):
    enabled: bool = Field(False)
    mtls: bool = Field(False)
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None

    @model_validator(mode="after")
    def _validate_tls(self):
        if self.enabled:
            if not self.cert_file or not self.key_file:
                raise ValueError("TLS enabled but cert_file/key_file not provided")
            if self.mtls and not self.ca_file:
                raise ValueError("mTLS enabled but ca_file not provided")
        return self

class Auth(BaseModel):
    provider: Literal["none", "jwt", "oauth2"] = Field("jwt")
    bearer_header: str = Field("authorization")
    issuer: Optional[str] = None
    audience: Optional[str] = None
    jwks_url: Optional[str] = None
    introspection_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[SecretStr] = None

    @model_validator(mode="after")
    def _validate_auth(self):
        if self.provider == "jwt":
            if not (self.issuer and self.audience and self.jwks_url):
                raise ValueError("JWT provider requires issuer, audience, jwks_url")
        if self.provider == "oauth2":
            if not (self.introspection_url and self.client_id and self.client_secret):
                raise ValueError("OAuth2 provider requires introspection_url, client_id, client_secret")
        return self

class Observability(BaseModel):
    log_level: Literal["debug", "info", "warn", "error"] = Field("info")
    log_json: bool = Field(True)
    otel_enabled: bool = Field(True)
    otel_endpoint: str = Field("http://otel-collector.observability:4317")
    otel_insecure: bool = Field(True)
    traces_ratio: float = Field(0.1, ge=0.0, le=1.0)
    metrics_prefix: str = Field("pic_")

class Resilience(BaseModel):
    timeout_default: str = Field("2s")
    retry_initial: str = Field("200ms")
    retry_max: str = Field("3s")
    retry_max_elapsed: str = Field("10s")
    circuit_failure_rate: int = Field(50, ge=0, le=100)
    backpressure_queue: int = Field(10000, ge=1)
    @field_validator("timeout_default", "retry_initial", "retry_max", "retry_max_elapsed")
    def _durations(cls, v: str) -> str:
        parse_duration(v); return v

class RateLimits(BaseModel):
    global_rps: int = Field(2000, ge=0)
    per_client_rps: int = Field(200, ge=0)
    grpc_qps: int = Field(0, ge=0)
    grpc_burst: int = Field(0, ge=0)

class Postgres(BaseModel):
    enabled: bool = Field(True)
    host: str = Field("postgres.physical")
    port: int = Field(5432, ge=1, le=65535)
    user: str = Field("user")
    password: SecretStr = Field(default=SecretStr("pass"))
    db: str = Field("pic")
    ssl_mode: Literal["disable", "require", "verify-ca", "verify-full"] = Field("prefer".replace("prefer","disable"))
    max_open: int = Field(50, ge=1)
    max_idle: int = Field(10, ge=0)
    conn_max_lifetime: str = Field("30m")

    @field_validator("conn_max_lifetime")
    def _durations(cls, v: str) -> str:
        parse_duration(v); return v

    def dsn(self) -> str:
        pwd = self.password.get_secret_value()
        return f"postgresql://{self.user}:{pwd}@{self.host}:{self.port}/{self.db}?sslmode={self.ssl_mode}"

class Redis(BaseModel):
    enabled: bool = Field(True)
    addr: str = Field("redis.observability:6379")
    db: int = Field(0, ge=0)
    tls: bool = Field(False)
    pool_size: int = Field(50, ge=1)

    def url(self) -> str:
        scheme = "rediss" if self.tls else "redis"
        return f"{scheme}://{self.addr}/{self.db}"

class S3(BaseModel):
    enabled: bool = Field(True)
    endpoint: str = Field("https://s3.amazonaws.com")
    bucket_raw: str = Field("pic-raw")
    bucket_norm: str = Field("pic-norm")
    kms_key_arn: Optional[str] = None

class Kafka(BaseModel):
    enabled: bool = Field(True)
    brokers: str = Field("kafka-0:9092,kafka-1:9092")
    sasl_enabled: bool = Field(False)
    sasl_mechanism: Literal["SCRAM-SHA-256", "SCRAM-SHA-512", "PLAIN"] = Field("SCRAM-SHA-256")
    sasl_username: Optional[str] = None
    sasl_password: Optional[SecretStr] = None
    tls_enabled: bool = Field(False)
    ca_file: Optional[str] = None
    client_cert_file: Optional[str] = None
    client_key_file: Optional[str] = None
    client_id: str = Field("physical-integration-core")
    topic_raw: str = Field("pic.ingress.raw")
    topic_norm: str = Field("pic.ingress.norm")
    topic_events: str = Field("pic.events")
    topic_audit: str = Field("pic.audit")
    topic_dlq: str = Field("pic.dlq")

    @model_validator(mode="after")
    def _validate_sasl(self):
        if self.sasl_enabled:
            if not (self.sasl_username and self.sasl_password):
                raise ValueError("Kafka SASL enabled but username/password not provided")
        if self.tls_enabled and not self.ca_file:
            # клиентская TLS без CA теоретически возможна (insecure), но запрещаем по умолчанию
            raise ValueError("Kafka TLS enabled but ca_file not provided")
        return self

class MQTT(BaseModel):
    enabled: bool = Field(False)
    broker_url: str = Field("mqtt://emqx.mqtt:1883")
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    client_id: str = Field("pic")
    tls_enabled: bool = Field(False)
    ca_file: Optional[str] = None
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    keepalive_sec: int = Field(30, ge=1)

class Idempotency(BaseModel):
    enabled: bool = Field(True)
    store: Literal["redis", "memory"] = Field("redis")
    ttl: str = Field("10m")
    @field_validator("ttl")
    def _durations(cls, v: str) -> str:
        parse_duration(v); return v

class Features(BaseModel):
    ingestion: bool = Field(True)
    device_bridge: bool = Field(True)
    opentelemetry: bool = Field(True)
    pii_redaction: bool = Field(True)

# ----------------------------- Корневая модель -----------------------------
class Settings(BaseSettings):
    # Префикс окружения
    model_config = dict(env_prefix="PIC_", case_sensitive=False) if _PYDANTIC_V2 else type("Cfg",(object,),{"env_prefix":"PIC_","case_sensitive":False})

    app: App = Field(default_factory=App)
    http: HTTP = Field(default_factory=HTTP)
    grpc: GRPC = Field(default_factory=GRPC)
    tls: TLS = Field(default_factory=TLS)
    auth: Auth = Field(default_factory=Auth)
    observability: Observability = Field(default_factory=Observability)
    resilience: Resilience = Field(default_factory=Resilience)
    ratelimits: RateLimits = Field(default_factory=RateLimits)

    postgres: Postgres = Field(default_factory=Postgres)
    redis: Redis = Field(default_factory=Redis)
    s3: S3 = Field(default_factory=S3)
    kafka: Kafka = Field(default_factory=Kafka)
    mqtt: MQTT = Field(default_factory=MQTT)
    idempotency: Idempotency = Field(default_factory=Idempotency)
    features: Features = Field(default_factory=Features)

    # Производные/служебные
    env_file: Optional[str] = Field(default=os.getenv("PIC_ENV_FILE"))  # путь к .env (опционально)

    # ----- Валидаторы профиля окружения -----
    @model_validator(mode="after")
    def _apply_profile_overrides(self):
        env = self.app.env
        # Базовые безопасные различия профилей
        if env == "dev":
            self.observability.log_level = "debug"
            self.observability.traces_ratio = 1.0
            self.auth.provider = "jwt" if self.auth.provider == "none" else self.auth.provider
        elif env == "staging":
            self.observability.traces_ratio = min(self.observability.traces_ratio, 0.2)
        elif env == "prod":
            self.observability.traces_ratio = min(self.observability.traces_ratio, 0.1)
            # Требуем TLS в проде, если gRPC/HTTP внешний:
            # (логика может быть специфичной для вашего деплоя; оставлено как пример)
        return self

    # ----- Удобные derived-поля/хелперы -----
    @property
    def http_read_timeout_sec(self) -> float:
        return parse_duration(self.http.read_timeout)

    @property
    def grpc_max_recv_bytes(self) -> int:
        return parse_size(self.grpc.max_recv)

    def to_dict(self, redact_secrets: bool = True) -> Dict[str, Any]:
        def _model_to_dict(m: BaseModel) -> Dict[str, Any]:
            data = m.model_dump() if _PYDANTIC_V2 else m.dict()
            for k, v in list(data.items()):
                if isinstance(v, SecretStr):
                    data[k] = v.get_secret_value() if not redact_secrets else "***"
            return data

        top = {}
        for k, v in self.__dict__.items():
            if isinstance(v, BaseModel):
                top[k] = _model_to_dict(v)
            else:
                top[k] = v
        return top

    # ----- Настройка логирования -----
    def configure_logging(self) -> None:
        json_enabled = self.observability.log_json
        level_name = self.observability.log_level.upper()
        # Стандартная схема dictConfig
        fmt_text = "%(asctime)s %(levelname)s %(name)s %(message)s"
        handlers: Dict[str, Any] = {
            "default": {
                "class": "logging.StreamHandler",
                "level": level_name,
                "stream": "ext://sys.stdout",
                "formatter": "json" if json_enabled else "plain",
            }
        }
        formatters = {
            "plain": {"format": fmt_text},
            "json": {
                "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                "format": "%(asctime)s %(levelname)s %(name)s %(message)s %(process)d %(thread)d",
            },
        }
        loggers = {
            "uvicorn": {"level": level_name, "handlers": ["default"], "propagate": False},
            "grpc-server": {"level": level_name, "handlers": ["default"], "propagate": False},
            "physical-integration": {"level": level_name, "handlers": ["default"], "propagate": False},
            "": {"level": level_name, "handlers": ["default"]},  # root
        }
        _dictConfig({"version": 1, "disable_existing_loggers": False, "formatters": formatters, "handlers": handlers, "loggers": loggers})

    # ----- Простейшая проверка «готовности конфигурации» -----
    def validate_required(self) -> None:
        # Пример: prod требует TLS включённый при внешнем доступе
        if self.app.env == "prod" and self.tls.enabled is False:
            logging.getLogger(__name__).warning("TLS is disabled in prod profile")

        if self.kafka.enabled and not self.kafka.brokers:
            raise ValueError("Kafka enabled but no brokers specified")

        if self.postgres.enabled and not self.postgres.host:
            raise ValueError("Postgres enabled but host is empty")


# ----------------------------- Загрузка/синглтон -----------------------------
def _env_files() -> List[str]:
    # Приоритет: PIC_ENV_FILE > .env.production/.env.staging/.env.development > .env
    files = []
    explicit = os.getenv("PIC_ENV_FILE")
    if explicit and os.path.isfile(explicit):
        files.append(explicit)
        return files
    profile = os.getenv("PIC_APP__ENV") or os.getenv("PIC_APP_ENV") or os.getenv("ENV", "prod")
    mapping = {"prod": ".env.production", "staging": ".env.staging", "dev": ".env.development"}
    if os.path.isfile(mapping.get(profile, "")):
        files.append(mapping[profile])
    if os.path.isfile(".env"):
        files.append(".env")
    return files

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    env_files = _env_files()
    # pydantic v2 BaseSettings принимает _env_file; v1 — тоже, но имя параметра env_file.
    kwargs = {"_env_file": env_files} if _PYDANTIC_V2 else {"env_file": env_files}
    try:
        s = Settings(**kwargs)  # type: ignore
    except ValidationError as e:
        # Выводим в STDERR, чтобы не потерять причину ошибки при старте контейнера
        sys.stderr.write(f"Settings validation error: {e}\n")
        raise
    s.validate_required()
    return s


# ----------------------------- Пример использования -----------------------------
# from physical_integration.settings import get_settings
# settings = get_settings()
# settings.configure_logging()
# logger = logging.getLogger(__name__)
# logger.info("Service %s v%s env=%s", settings.app.name, settings.app.version, settings.app.env)
# pg_dsn = settings.postgres.dsn()
