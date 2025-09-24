# neuroforge/settings.py
# SPDX-License-Identifier: Apache-2.0
"""
Промышленная конфигурация NeuroForge Core.

Приоритет источников (от низшего к высшему):
  1) Встроенные дефолты (значения датаклассов ниже)
  2) Файл конфигурации, если указан NF_CONFIG_FILE (JSON|YAML|YML|TOML)
  3) Переменные окружения (с префиксом NF_ для большинства полей; см. map ниже)
  4) *_FILE переменные для секретов (побеждают соответствующие ENV-переменные)

Опционально:
  - .env подхватывается при наличии python-dotenv (автоматически)
  - YAML доступен при наличии PyYAML; иначе используйте JSON или TOML (3.11+: stdlib tomllib)

Использование:
  from neuroforge.settings import get_settings
  cfg = get_settings()
  print(cfg.http.host, cfg.database.sqlalchemy_url())

Переменные окружения (частично):
  HTTP:           HTTP_HOST, HTTP_PORT, HTTP_ROOT_PATH, CORS_ORIGINS, CORS_ALLOW_CREDENTIALS
  GRPC:           GRPC_HOST, GRPC_PORT, GRPC_TLS_ENABLED, GRPC_TLS_CERT[_FILE], GRPC_TLS_KEY[_FILE], GRPC_TLS_CLIENT_CA[_FILE]
  LOGGING:        LOG_LEVEL, LOG_JSON
  DB(Postgres):   DB_HOST, DB_PORT, DB_NAME, DB_USER[_FILE], DB_PASSWORD[_FILE], DB_SSLMODE
  REDIS:          REDIS_URL
  KAFKA:          KAFKA_BROKERS, KAFKA_SSL_CA[_FILE], KAFKA_SASL_USERNAME[_FILE], KAFKA_SASL_PASSWORD[_FILE]
  S3:             S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY[_FILE], S3_SECRET_KEY[_FILE], S3_SECURE
  OTEL:           OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_SERVICE_NAME, OTEL_TRACES_SAMPLER_RATIO
  MISC:           APP_NAME, APP_VERSION, GIT_REVISION, RELEASE_CHANNEL, ENV

Префикс NF_ можно использовать для явного неймспейса: NF_DB_HOST и т. п.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

# -----------------------------
# Опциональные улучшайзеры
# -----------------------------
# .env загрузим, если установлен python-dotenv
try:  # pragma: no cover
    import dotenv  # type: ignore
    dotenv.load_dotenv()  # загрузка .env из cwd автоматически
except Exception:
    pass

# YAML — опционально (PyYAML)
_try_yaml = None  # type: ignore
try:  # pragma: no cover
    import yaml  # type: ignore
    _try_yaml = yaml
except Exception:
    _try_yaml = None

# TOML: с Python 3.11 есть tomllib
_try_toml_load = None
if sys.version_info >= (3, 11):  # pragma: no cover
    import tomllib  # type: ignore

    def _toml_load(b: bytes) -> Dict[str, Any]:
        return tomllib.loads(b.decode())
    _try_toml_load = _toml_load
else:  # pragma: no cover
    try:
        import tomli  # type: ignore

        def _toml_load(b: bytes) -> Dict[str, Any]:
            return tomli.loads(b.decode())
        _try_toml_load = _toml_load
    except Exception:
        _try_toml_load = None


# -----------------------------
# Утилиты
# -----------------------------

def _getenv(key: str, default: Optional[str] = None) -> Optional[str]:
    """Берет из окружения: сначала точный ключ, затем с префиксом NF_."""
    return os.getenv(key, os.getenv(f"NF_{key}", default))

def _read_secret(var: str) -> Optional[str]:
    """
    Безопасная загрузка секрета.
    Приоритет: VAR_FILE (путь к файлу) > VAR (значение).
    """
    file_key = f"{var}_FILE"
    file_key_nf = f"NF_{file_key}"
    path = os.getenv(file_key) or os.getenv(file_key_nf)
    if path:
        p = Path(path)
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    val = _getenv(var, None)
    return val.strip() if isinstance(val, str) else val

def _parse_bool(v: Union[str, bool, None], default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}

def _parse_int(v: Union[str, int, None], default: int) -> int:
    if isinstance(v, int):
        return v
    if v is None or str(v).strip() == "":
        return default
    try:
        return int(str(v).strip())
    except Exception:
        return default

def _split_csv(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [x.strip() for x in re.split(r"[,\s]+", s) if x.strip()]

def _is_url(s: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s))

def _ensure_dir(path: Union[str, Path]) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)

def _coalesce(*values: Optional[str]) -> Optional[str]:
    for v in values:
        if v is not None and str(v).strip() != "":
            return str(v)
    return None


# -----------------------------
# Секции конфигурации
# -----------------------------

@dataclass
class AppInfo:
    name: str = _getenv("APP_NAME", "neuroforge-core") or "neuroforge-core"
    version: str = _getenv("APP_VERSION", "0.1.0") or "0.1.0"
    revision: str = _getenv("GIT_REVISION", "") or ""
    release_channel: str = _getenv("RELEASE_CHANNEL", "dev") or "dev"
    environment: str = _getenv("ENV", "dev") or "dev"

@dataclass
class LoggingSettings:
    level: str = _getenv("LOG_LEVEL", "INFO") or "INFO"
    json: bool = _parse_bool(_getenv("LOG_JSON", None), default=False)
    file: Optional[str] = _getenv("LOG_FILE", None)

@dataclass
class HTTPSettings:
    host: str = _getenv("HTTP_HOST", "0.0.0.0") or "0.0.0.0"
    port: int = _parse_int(_getenv("HTTP_PORT", None), 8080)
    root_path: str = _getenv("HTTP_ROOT_PATH", "") or ""
    request_body_limit_mb: int = _parse_int(_getenv("REQ_LIMIT_MB", None), 8)
    # CORS
    cors_origins: List[str] = field(default_factory=lambda: _split_csv(_getenv("CORS_ORIGINS", "")))
    cors_allow_credentials: bool = _parse_bool(_getenv("CORS_ALLOW_CREDENTIALS", None), default=False)
    cors_allow_methods: List[str] = field(default_factory=lambda: _split_csv(_getenv("CORS_ALLOW_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")))
    cors_allow_headers: List[str] = field(default_factory=lambda: _split_csv(_getenv("CORS_ALLOW_HEADERS", "authorization,content-type,x-request-id")))
    cors_expose_headers: List[str] = field(default_factory=lambda: _split_csv(_getenv("CORS_EXPOSE_HEADERS", "x-request-id")))
    cors_max_age_sec: int = _parse_int(_getenv("CORS_MAX_AGE", None), 600)

@dataclass
class GRPCSettings:
    host: str = _getenv("GRPC_HOST", "0.0.0.0") or "0.0.0.0"
    port: int = _parse_int(_getenv("GRPC_PORT", None), 50051)
    tls_enabled: bool = _parse_bool(_getenv("GRPC_TLS_ENABLED", None), default=False)
    tls_cert: Optional[str] = _read_secret("GRPC_TLS_CERT")
    tls_key: Optional[str] = _read_secret("GRPC_TLS_KEY")
    tls_client_ca: Optional[str] = _read_secret("GRPC_TLS_CLIENT_CA")
    auth_enabled: bool = _parse_bool(_getenv("GRPC_AUTH_ENABLED", None), default=False)
    auth_keys: List[str] = field(default_factory=lambda: _split_csv(_getenv("GRPC_AUTH_KEYS", "")))
    prometheus_enabled: bool = _parse_bool(_getenv("PROMETHEUS_ENABLED", None), default=True)
    prometheus_port: int = _parse_int(_getenv("PROMETHEUS_PORT", None), 9095)

@dataclass
class PostgresSettings:
    host: str = _getenv("DB_HOST", "localhost") or "localhost"
    port: int = _parse_int(_getenv("DB_PORT", None), 5432)
    name: str = _getenv("DB_NAME", "neuroforge") or "neuroforge"
    user: str = _read_secret("DB_USER") or "postgres"
    password: str = _read_secret("DB_PASSWORD") or ""
    sslmode: str = _getenv("DB_SSLMODE", "prefer") or "prefer"
    options: str = _getenv("DB_OPTIONS", "") or ""  # доп. параметры в строке подключения

    def sqlalchemy_url(self, driver: str = "psycopg") -> str:
        # Поддержка psycopg3/asyncpg: driver="psycopg"|"asyncpg"
        auth = f"{self.user}:{self.password}" if self.password else self.user
        opts = f"?sslmode={self.sslmode}"
        if self.options:
            sep = "&" if "?" in opts else "?"
            opts = f"{opts}{sep}{self.options.lstrip('?&')}"
        return f"postgresql+{driver}://{auth}@{self.host}:{self.port}/{self.name}{opts}"

@dataclass
class RedisSettings:
    url: str = _getenv("REDIS_URL", "redis://localhost:6379/0") or "redis://localhost:6379/0"

@dataclass
class KafkaSettings:
    brokers: List[str] = field(default_factory=lambda: _split_csv(_getenv("KAFKA_BROKERS", "")))
    ssl_ca: Optional[str] = _read_secret("KAFKA_SSL_CA")
    sasl_username: Optional[str] = _read_secret("KAFKA_SASL_USERNAME")
    sasl_password: Optional[str] = _read_secret("KAFKA_SASL_PASSWORD")
    sasl_mechanism: Optional[str] = _getenv("KAFKA_SASL_MECHANISM", None)

@dataclass
class S3Settings:
    endpoint: Optional[str] = _getenv("S3_ENDPOINT", None)
    region: Optional[str] = _getenv("S3_REGION", None)
    bucket: Optional[str] = _getenv("S3_BUCKET", None)
    access_key: Optional[str] = _read_secret("S3_ACCESS_KEY")
    secret_key: Optional[str] = _read_secret("S3_SECRET_KEY")
    secure: bool = _parse_bool(_getenv("S3_SECURE", None), default=True)

@dataclass
class OTELSettings:
    endpoint: Optional[str] = _getenv("OTEL_EXPORTER_OTLP_ENDPOINT", None)
    service_name: Optional[str] = _getenv("OTEL_SERVICE_NAME", None)
    traces_ratio: float = float(_getenv("OTEL_TRACES_SAMPLER_RATIO", "0.05") or "0.05")

@dataclass
class RateLimitSettings:
    enabled: bool = _parse_bool(_getenv("RATE_LIMIT_ENABLED", None), default=True)
    rps_limit: int = _parse_int(_getenv("RPS_LIMIT", None), 50)
    rps_burst: int = _parse_int(_getenv("RPS_BURST", None), 100)
    window_sec: int = _parse_int(_getenv("RATE_LIMIT_WINDOW_SEC", None), 1)

@dataclass
class PathsSettings:
    data_dir: str = _getenv("DATA_DIR", "./data") or "./data"
    artifacts_dir: str = _getenv("ARTIFACTS_DIR", "./artifacts") or "./artifacts"
    logs_dir: str = _getenv("LOGS_DIR", "./logs") or "./logs"

@dataclass
class Features:
    experimental: bool = _parse_bool(_getenv("FEATURE_EXPERIMENTAL", None), default=False)
    enable_grpc_server: bool = _parse_bool(_getenv("FEATURE_GRPC", None), default=True)
    enable_http_server: bool = _parse_bool(_getenv("FEATURE_HTTP", None), default=True)

# -----------------------------
# Корневой конфиг
# -----------------------------

@dataclass
class Settings:
    app: AppInfo = field(default_factory=AppInfo)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    http: HTTPSettings = field(default_factory=HTTPSettings)
    grpc: GRPCSettings = field(default_factory=GRPCSettings)
    database: PostgresSettings = field(default_factory=PostgresSettings)
    redis: RedisSettings = field(default_factory=RedisSettings)
    kafka: KafkaSettings = field(default_factory=KafkaSettings)
    s3: S3Settings = field(default_factory=S3Settings)
    otel: OTELSettings = field(default_factory=OTELSettings)
    ratelimit: RateLimitSettings = field(default_factory=RateLimitSettings)
    paths: PathsSettings = field(default_factory=PathsSettings)
    features: Features = field(default_factory=Features)

    # --------- Валидация и производные значения ---------

    def validate(self) -> None:
        # HTTP
        assert 1 <= self.http.port <= 65535, "HTTP.port вне диапазона"
        # gRPC TLS
        if self.grpc.tls_enabled:
            assert self.grpc.tls_cert and self.grpc.tls_key, "Включен gRPC TLS, но не заданы GRPC_TLS_CERT/KEY"
        # DB
        assert self.database.user, "DB_USER пуст"
        # Kafka
        if self.kafka.brokers:
            for b in self.kafka.brokers:
                assert ":" in b, f"Kafka broker '{b}' должен быть в формате host:port"
        # S3
        if self.s3.endpoint:
            assert _is_url(self.s3.endpoint), "S3_ENDPOINT должен быть URL (scheme://host[:port])"
        # OTEL
        if self.otel.endpoint:
            assert _is_url(self.otel.endpoint), "OTEL_EXPORTER_OTLP_ENDPOINT должен быть URL"
        # Пути
        for d in (self.paths.data_dir, self.paths.artifacts_dir, self.paths.logs_dir):
            _ensure_dir(d)

    @property
    def service_fqdn(self) -> str:
        try:
            hn = socket.gethostname()
            return f"{self.app.name}.{hn}"
        except Exception:
            return self.app.name

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

# -----------------------------
# Загрузка из файла
# -----------------------------

def _load_from_file(path: Union[str, Path]) -> Dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Config file not found: {p}")
    data = p.read_bytes()
    suffix = p.suffix.lower()
    if suffix in (".json",):
        return json.loads(data.decode())
    if suffix in (".yaml", ".yml"):
        if not _try_yaml:
            raise RuntimeError("PyYAML не установлен, используйте JSON/TOML или установите pyyaml")
        return _try_yaml.safe_load(data.decode()) or {}
    if suffix in (".toml",):
        if not _try_toml_load:
            raise RuntimeError("tomllib/tomli недоступен; используйте JSON/YAML или Python 3.11+")
        return _try_toml_load(data)
    raise ValueError(f"Неизвестный формат конфигурации: {suffix}")

def _deep_merge(dst: Dict[str, Any], src: Mapping[str, Any]) -> Dict[str, Any]:
    for k, v in src.items():
        if isinstance(v, Mapping) and isinstance(dst.get(k), Mapping):
            dst[k] = _deep_merge(dict(dst[k]), v)  # type: ignore
        else:
            dst[k] = v  # type: ignore
    return dst

def _apply_mapping_from_env(base: Dict[str, Any]) -> Dict[str, Any]:
    """
    Применяет ENV к словарю конфигурации.
    Карта ключей: секция.поле -> ENV ключ (без NF_).
    """
    map_keys = {
        # logging
        "logging.level": "LOG_LEVEL",
        "logging.json": "LOG_JSON",
        "logging.file": "LOG_FILE",
        # http
        "http.host": "HTTP_HOST",
        "http.port": "HTTP_PORT",
        "http.root_path": "HTTP_ROOT_PATH",
        "http.request_body_limit_mb": "REQ_LIMIT_MB",
        "http.cors_allow_credentials": "CORS_ALLOW_CREDENTIALS",
        "http.cors_max_age_sec": "CORS_MAX_AGE",
        "http.cors_origins": "CORS_ORIGINS",
        "http.cors_allow_methods": "CORS_ALLOW_METHODS",
        "http.cors_allow_headers": "CORS_ALLOW_HEADERS",
        "http.cors_expose_headers": "CORS_EXPOSE_HEADERS",
        # grpc
        "grpc.host": "GRPC_HOST",
        "grpc.port": "GRPC_PORT",
        "grpc.tls_enabled": "GRPC_TLS_ENABLED",
        "grpc.prometheus_enabled": "PROMETHEUS_ENABLED",
        "grpc.prometheus_port": "PROMETHEUS_PORT",
        "grpc.auth_enabled": "GRPC_AUTH_ENABLED",
        "grpc.auth_keys": "GRPC_AUTH_KEYS",
        # db
        "database.host": "DB_HOST",
        "database.port": "DB_PORT",
        "database.name": "DB_NAME",
        "database.user": "DB_USER",
        "database.password": "DB_PASSWORD",
        "database.sslmode": "DB_SSLMODE",
        "database.options": "DB_OPTIONS",
        # redis
        "redis.url": "REDIS_URL",
        # kafka
        "kafka.brokers": "KAFKA_BROKERS",
        "kafka.sasl_mechanism": "KAFKA_SASL_MECHANISM",
        "kafka.sasl_username": "KAFKA_SASL_USERNAME",
        "kafka.sasl_password": "KAFKA_SASL_PASSWORD",
        # s3
        "s3.endpoint": "S3_ENDPOINT",
        "s3.region": "S3_REGION",
        "s3.bucket": "S3_BUCKET",
        "s3.access_key": "S3_ACCESS_KEY",
        "s3.secret_key": "S3_SECRET_KEY",
        "s3.secure": "S3_SECURE",
        # otel
        "otel.endpoint": "OTEL_EXPORTER_OTLP_ENDPOINT",
        "otel.service_name": "OTEL_SERVICE_NAME",
        "otel.traces_ratio": "OTEL_TRACES_SAMPLER_RATIO",
        # ratelimit
        "ratelimit.enabled": "RATE_LIMIT_ENABLED",
        "ratelimit.rps_limit": "RPS_LIMIT",
        "ratelimit.rps_burst": "RPS_BURST",
        "ratelimit.window_sec": "RATE_LIMIT_WINDOW_SEC",
        # paths
        "paths.data_dir": "DATA_DIR",
        "paths.artifacts_dir": "ARTIFACTS_DIR",
        "paths.logs_dir": "LOGS_DIR",
        # features
        "features.experimental": "FEATURE_EXPERIMENTAL",
        "features.enable_grpc_server": "FEATURE_GRPC",
        "features.enable_http_server": "FEATURE_HTTP",
        # app
        "app.name": "APP_NAME",
        "app.version": "APP_VERSION",
        "app.revision": "GIT_REVISION",
        "app.release_channel": "RELEASE_CHANNEL",
        "app.environment": "ENV",
    }

    def set_in(d: Dict[str, Any], dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        cur = d
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value

    def convert(key: str, raw: str) -> Any:
        # простая типизация по ключам
        if key.endswith(("port", "limit_mb", "rps_limit", "rps_burst", "window_sec")):
            return _parse_int(raw, int(raw) if raw.isdigit() else 0)
        if key.endswith(("enabled", "json", "allow_credentials", "secure")):
            return _parse_bool(raw, False)
        if key.endswith(("origins", "allow_methods", "allow_headers", "expose_headers", "auth_keys", "brokers")):
            return _split_csv(raw)
        if key.endswith(("traces_ratio",)):
            try:
                return float(raw)
            except Exception:
                return 0.05
        return raw

    for dotted, env_key in map_keys.items():
        val = _getenv(env_key, None)
        if val is not None:
            set_in(base, dotted, convert(dotted.split(".")[-1], val))

    # *_FILE секреты (имеют приоритет)
    file_secrets = {
        "database.user": "DB_USER",
        "database.password": "DB_PASSWORD",
        "grpc.tls_cert": "GRPC_TLS_CERT",
        "grpc.tls_key": "GRPC_TLS_KEY",
        "grpc.tls_client_ca": "GRPC_TLS_CLIENT_CA",
        "kafka.ssl_ca": "KAFKA_SSL_CA",
        "kafka.sasl_username": "KAFKA_SASL_USERNAME",
        "kafka.sasl_password": "KAFKA_SASL_PASSWORD",
        "s3.access_key": "S3_ACCESS_KEY",
        "s3.secret_key": "S3_SECRET_KEY",
    }
    for dotted, env_base in file_secrets.items():
        sec = _read_secret(env_base)
        if sec is not None:
            set_in(base, dotted, sec)

    return base


# -----------------------------
# Публичное API загрузки
# -----------------------------

_cached: Optional[Settings] = None

def load_settings() -> Settings:
    """
    Загружает конфигурацию из дефолтов, файла (если указан) и окружения.
    """
    # 1) дефолты
    base: Dict[str, Any] = dataclasses.asdict(Settings())

    # 2) файл
    cfg_file = _coalesce(_getenv("CONFIG_FILE", None), os.getenv("NF_CONFIG_FILE", None))
    if cfg_file:
        file_data = _load_from_file(cfg_file)
        base = _deep_merge(base, file_data or {})

    # 3) окружение
    base = _apply_mapping_from_env(base)

    # 4) материализация в dataclass
    def dc_from(cls, data: Dict[str, Any]):
        # рекурсивно собираем вложенные датаклассы
        fields = {f.name: f for f in dataclasses.fields(cls)}
        kwargs = {}
        for k, fmeta in fields.items():
            if dataclasses.is_dataclass(fmeta.type):
                kwargs[k] = dc_from(fmeta.type, data.get(k, {}))
            else:
                kwargs[k] = data.get(k, getattr(cls, k, None))
        return cls(**kwargs)  # type: ignore

    settings = dc_from(Settings, base)
    settings.validate()
    return settings  # type: ignore

def get_settings() -> Settings:
    """
    Возвращает кэшированную конфигурацию (singleton).
    """
    global _cached
    if _cached is None:
        _cached = load_settings()
    return _cached

def reload_settings() -> Settings:
    """
    Перезагружает конфигурацию, сбрасывая кэш.
    """
    global _cached
    _cached = load_settings()
    return _cached


__all__ = [
    "Settings",
    "get_settings",
    "reload_settings",
]
