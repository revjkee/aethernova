# datafabric-core/datafabric/settings.py
from __future__ import annotations

import ipaddress
import json
import logging
import logging.config
import os
import pathlib
import sys
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Literal, Optional

from pydantic import AnyHttpUrl, BaseSettings, Field, PostgresDsn, RedisDsn, SecretStr, validator

# -----------------------------------------------------------------------------
# Константы и базовые утилиты
# -----------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parents[2]  # корень репозитория
ENV_DOTFILE = BASE_DIR / ".env"

class RuntimeEnv(str, Enum):
    local = "local"        # локальная разработка
    dev = "dev"            # дев‑стенд
    staging = "staging"    # предпрод
    prod = "prod"          # продакшен
    test = "test"          # pytest/CI

def _bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}

def _split_csv(value: Any) -> List[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [chunk.strip() for chunk in str(value).split(",") if chunk.strip()]

def _coalesce(*values: Any) -> Any:
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return None

# -----------------------------------------------------------------------------
# Settings
# -----------------------------------------------------------------------------

class AppSettings(BaseSettings):
    # --- Базовое приложение ---
    APP_NAME: str = "datafabric-core"
    APP_VERSION: str = Field("1.0.0", description="Версия сервиса")
    RUNTIME_ENV: RuntimeEnv = Field(RuntimeEnv.local, env="ENV")
    DEBUG: bool = Field(False, description="Расширенные логи/трассировка")

    # --- HTTP / API ---
    HTTP_HOST: str = "0.0.0.0"
    HTTP_PORT: int = 8080
    CORS_ALLOW_ORIGINS: List[AnyHttpUrl | str] = Field(default_factory=lambda: ["*"])
    CORS_ALLOW_METHODS: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    CORS_ALLOW_HEADERS: List[str] = Field(default_factory=lambda: ["*"])
    CORS_ALLOW_CREDENTIALS: bool = True
    GZIP_MIN_SIZE: int = 1024
    RATE_LIMIT_RPS: float = 5.0
    RATE_LIMIT_BURST: int = 20

    # --- Безопасность / Auth ---
    SECRET_KEY: SecretStr = Field(SecretStr("dev-secret-change-me"), description="Ключ подписи (JWT/crypto)")
    ACCESS_TOKEN_EXPIRE_MIN: int = 30
    REFRESH_TOKEN_EXPIRE_MIN: int = 60 * 24 * 30
    JWT_ALG: Literal["HS256", "HS384", "HS512"] = "HS256"
    ALLOWED_IPS: List[str] = Field(default_factory=list, description="Белый список IP/CIDR, опционально")

    # --- База данных (PostgreSQL, asyncpg) ---
    PG_HOST: str = "localhost"
    PG_PORT: int = 5432
    PG_USER: str = "postgres"
    PG_PASSWORD: SecretStr = Field(SecretStr("postgres"))
    PG_DB: str = "datafabric"
    PG_SSLMODE: Literal["disable", "prefer", "require", "verify-ca", "verify-full"] = "prefer"
    SQLA_ECHO: bool = False
    SQLA_POOL_SIZE: int = 10
    SQLA_MAX_OVERFLOW: int = 20
    SQLA_POOL_TIMEOUT: int = 30
    SQLA_POOL_RECYCLE: int = 1800  # seconds

    # --- Redis ---
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[SecretStr] = None
    REDIS_SSL: bool = False

    # --- Kafka (опционально) ---
    KAFKA_BROKERS: List[str] = Field(default_factory=list)  # host1:9092,host2:9092
    KAFKA_CLIENT_ID: str = "datafabric"
    KAFKA_SSL: bool = False
    KAFKA_SASL_MECH: Optional[Literal["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"]] = None
    KAFKA_SASL_USER: Optional[str] = None
    KAFKA_SASL_PASSWORD: Optional[SecretStr] = None

    # --- Объектное хранилище (S3/MinIO) ---
    S3_ENDPOINT: Optional[AnyHttpUrl] = None
    S3_REGION: str = "us-east-1"
    S3_ACCESS_KEY: Optional[str] = None
    S3_SECRET_KEY: Optional[SecretStr] = None
    S3_BUCKET_DEFAULT: Optional[str] = None
    S3_SECURE: bool = True  # https

    # --- Наблюдаемость / Алёртинг ---
    SENTRY_DSN: Optional[AnyHttpUrl] = None
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[AnyHttpUrl] = None
    OTEL_SERVICE_NAME: Optional[str] = None
    OTEL_ENABLE: bool = False
    TRACING_SAMPLER_RATIO: float = 0.01

    # --- Feature flags ---
    FEATURE_EXPERIMENTAL_API: bool = False
    FEATURE_APQ: bool = True
    FEATURE_DEPTH_VALIDATION: bool = True

    # --- Конфигурация из внешнего YAML (опционально) ---
    CONFIG_YAML_PATH: Optional[str] = Field(None, description="Путь к YAML с переопределениями полей")

    # --- Прочее ---
    REQUEST_ID_HEADER: str = "x-request-id"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    STRUCTURED_LOGS: bool = True

    class Config:
        env_file = str(ENV_DOTFILE) if ENV_DOTFILE.exists() else None
        env_prefix = "DATAFABRIC_"
        case_sensitive = False

    # ----------------------- ВАЛИДАТОРЫ -----------------------

    @validator("HTTP_PORT")
    def _port_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("HTTP_PORT must be between 1 and 65535")
        return v

    @validator("PG_PORT", "REDIS_PORT")
    def _svc_port_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v

    @validator("ALLOWED_IPS", pre=True)
    def _validate_ips(cls, v: Any) -> List[str]:
        ips = _split_csv(v)
        for ip in ips:
            # поддержка одиночных IP и CIDR
            try:
                if "/" in ip:
                    ipaddress.ip_network(ip, strict=False)
                else:
                    ipaddress.ip_address(ip)
            except Exception as e:
                raise ValueError(f"Invalid IP/CIDR: {ip} ({e})")
        return ips

    @validator("KAFKA_BROKERS", pre=True)
    def _parse_brokers(cls, v: Any) -> List[str]:
        return _split_csv(v)

    @validator("TRACING_SAMPLER_RATIO")
    def _sampler_ratio(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("TRACING_SAMPLER_RATIO must be in [0.0, 1.0]")
        return v

    # ----------------------- ВЫЧИСЛЯЕМЫЕ СВОЙСТВА -----------------------

    @property
    def is_prod(self) -> bool:
        return self.RUNTIME_ENV == RuntimeEnv.prod

    @property
    def is_local(self) -> bool:
        return self.RUNTIME_ENV == RuntimeEnv.local

    # DSN для asyncpg/SQLAlchemy
    @property
    def pg_async_dsn(self) -> str:
        # Пример: postgresql+asyncpg://user:pass@host:port/db?sslmode=require
        pw = self.PG_PASSWORD.get_secret_value()
        return str(
            PostgresDsn.build(
                scheme="postgresql+asyncpg",
                user=self.PG_USER,
                password=pw,
                host=self.PG_HOST,
                port=str(self.PG_PORT),
                path=f"/{self.PG_DB}",
                query=f"sslmode={self.PG_SSLMODE}",
            )
        )

    # Redis DSN
    @property
    def redis_dsn(self) -> str:
        pw = self.REDIS_PASSWORD.get_secret_value() if self.REDIS_PASSWORD else None
        scheme = "rediss" if self.REDIS_SSL else "redis"
        auth = f":{pw}@" if pw else ""
        return str(
            RedisDsn.build(
                scheme=scheme,
                host=self.REDIS_HOST,
                port=str(self.REDIS_PORT),
                path=f"/{self.REDIS_DB}",
                password=pw,
            )
        )

    # Kafka dict (для aiokafka/confluent-kafka)
    @property
    def kafka_config(self) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {
            "bootstrap.servers": ",".join(self.KAFKA_BROKERS) if self.KAFKA_BROKERS else "",
            "client.id": self.KAFKA_CLIENT_ID,
        }
        if self.KAFKA_SSL:
            cfg.update({"security.protocol": "SSL"})
        if self.KAFKA_SASL_MECH:
            cfg.update(
                {
                    "security.protocol": "SASL_SSL" if self.KAFKA_SSL else "SASL_PLAINTEXT",
                    "sasl.mechanism": self.KAFKA_SASL_MECH,
                    "sasl.username": self.KAFKA_SASL_USER or "",
                    "sasl.password": (self.KAFKA_SASL_PASSWORD.get_secret_value() if self.KAFKA_SASL_PASSWORD else ""),
                }
            )
        return cfg

    # OpenTelemetry env
    @property
    def otel_env(self) -> Dict[str, str]:
        if not self.OTEL_ENABLE:
            return {}
        env = {
            "OTEL_SERVICE_NAME": self.OTEL_SERVICE_NAME or self.APP_NAME,
            "OTEL_TRACES_SAMPLER_ARG": str(self.TRACING_SAMPLER_RATIO),
        }
        if self.OTEL_EXPORTER_OTLP_ENDPOINT:
            env["OTEL_EXPORTER_OTLP_ENDPOINT"] = str(self.OTEL_EXPORTER_OTLP_ENDPOINT)
        return env

    # ----------------------- ЗАГРУЗКА ИЗ YAML -----------------------

    def _apply_yaml_overrides(self, data: Dict[str, Any]) -> "AppSettings":
        """
        Переопределяет поля экземпляра значениями из словаря, где ключи соответствуют полям Pydantic.
        Любые отсутствующие ключи игнорируются. Возвращает self для чейнинга.
        """
        for key, val in data.items():
            if not hasattr(self, key):
                continue
            # простое поверхностное присваивание; вложенные структуры можно расширить по необходимости
            object.__setattr__(self, key, val)
        return self

    def load_overrides_from_yaml(self) -> "AppSettings":
        """
        Если указан CONFIG_YAML_PATH и файл существует, применяет переопределения.
        Поддерживает JSON как подмножество (если расширение .json).
        """
        path = self.CONFIG_YAML_PATH
        if not path:
            return self

        file = pathlib.Path(path)
        if not file.exists():
            raise FileNotFoundError(f"CONFIG_YAML_PATH does not exist: {file}")

        text = file.read_text(encoding="utf-8")
        try:
            if file.suffix.lower() == ".json":
                payload = json.loads(text)
            else:
                # безопасный YAML‑парсер без внешних референсов
                import yaml  # type: ignore
                payload = yaml.safe_load(text) or {}
        except Exception as e:
            raise ValueError(f"Failed to parse config {file}: {e}")

        if not isinstance(payload, dict):
            raise ValueError(f"Top-level structure must be a dict in {file}")

        return self._apply_yaml_overrides(payload)

    # ----------------------- ЛОГИРОВАНИЕ -----------------------

    def configure_logging(self) -> None:
        """
        Структурное логирование (JSON) + лаконичные логи для локалки.
        """
        if self.STRUCTURED_LOGS and not self.is_local:
            logging.config.dictConfig(
                {
                    "version": 1,
                    "disable_existing_loggers": False,
                    "formatters": {
                        "json": {
                            "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
                            "format": "%(asctime)s %(levelname)s %(name)s %(message)s %(process)d %(thread)d",
                        }
                    },
                    "handlers": {
                        "stdout": {
                            "class": "logging.StreamHandler",
                            "stream": "ext://sys.stdout",
                            "formatter": "json",
                        }
                    },
                    "root": {"level": self.LOG_LEVEL, "handlers": ["stdout"]},
                }
            )
        else:
            logging.config.dictConfig(
                {
                    "version": 1,
                    "disable_existing_loggers": False,
                    "formatters": {
                        "plain": {
                            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
                        }
                    },
                    "handlers": {
                        "stdout": {
                            "class": "logging.StreamHandler",
                            "stream": "ext://sys.stdout",
                            "formatter": "plain",
                        }
                    },
                    "root": {"level": self.LOG_LEVEL, "handlers": ["stdout"]},
                }
            )

    # ----------------------- ПОЛЕЗНЫЕ МЕТОДЫ -----------------------

    def summarize(self) -> Dict[str, Any]:
        """
        Краткий безопасный дайджест настроек (без секретов).
        """
        return {
            "app": {"name": self.APP_NAME, "version": self.APP_VERSION, "env": self.RUNTIME_ENV.value, "debug": self.DEBUG},
            "http": {"host": self.HTTP_HOST, "port": self.HTTP_PORT},
            "db": {"host": self.PG_HOST, "port": self.PG_PORT, "db": self.PG_DB, "sslmode": self.PG_SSLMODE},
            "redis": {"host": self.REDIS_HOST, "port": self.REDIS_PORT, "db": self.REDIS_DB, "ssl": self.REDIS_SSL},
            "kafka": {"brokers": self.KAFKA_BROKERS, "ssl": self.KAFKA_SSL, "sasl": bool(self.KAFKA_SASL_MECH)},
            "s3": {
                "endpoint": str(self.S3_ENDPOINT) if self.S3_ENDPOINT else None,
                "region": self.S3_REGION,
                "bucket": self.S3_BUCKET_DEFAULT,
                "secure": self.S3_SECURE,
            },
            "telemetry": {
                "sentry": bool(self.SENTRY_DSN),
                "otel": self.OTEL_ENABLE,
                "otel_endpoint": str(self.OTEL_EXPORTER_OTLP_ENDPOINT) if self.OTEL_EXPORTER_OTLP_ENDPOINT else None,
                "sampler": self.TRACING_SAMPLER_RATIO,
            },
            "features": {
                "apq": self.FEATURE_APQ,
                "depth_validation": self.FEATURE_DEPTH_VALIDATION,
                "experimental_api": self.FEATURE_EXPERIMENTAL_API,
            },
        }

# -----------------------------------------------------------------------------
# Фабрика настроек с LRU‑кэшем
# -----------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """
    Создаёт и кэширует настройки.
    Порядок источников:
      1) Значения по умолчанию
      2) .env (если присутствует)
      3) ENV/процесс
      4) YAML переопределения (если указан DATAFABRIC_CONFIG_YAML_PATH)
    """
    # Шаг 1–3: Pydantic загрузка
    settings = AppSettings()

    # Шаг 4: YAML overrides
    settings = settings.load_overrides_from_yaml()

    # Логирование
    settings.configure_logging()

    # Применим переменные OTEL в процесс (по необходимости)
    for k, v in settings.otel_env.items():
        os.environ.setdefault(k, v)

    # Диагностика (информационный лог)
    logging.getLogger(settings.APP_NAME).info(
        "settings.loaded",
        extra={"summary": settings.summarize()},
    )
    return settings

# -----------------------------------------------------------------------------
# CLI‑запуск для диагностики: python -m datafabric.settings
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    s = get_settings()
    print(json.dumps(s.summarize(), indent=2, ensure_ascii=False))
    print("PG:", s.pg_async_dsn)
    print("REDIS:", s.redis_dsn)
    print("KAFKA:", s.kafka_config)
