# veilmind/bootstr ap.py
# -*- coding: utf-8 -*-
"""
VeilMind Core — Bootstrap
Единая точка инициализации инфраструктуры приложения: конфиг, логи, секреты,
подключения к Postgres/Redis/Kafka, телеметрия (OTLP), PEP‑кэш и корректный shutdown.

Все внешние зависимости необязательны. Если их нет, компонент отключается безопасно.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# ----------------------------
# Опциональные зависимости
# ----------------------------
try:
    import asyncpg  # type: ignore
except Exception:  # pragma: no cover
    asyncpg = None  # type: ignore

try:
    import redis.asyncio as redis_async  # type: ignore
except Exception:  # pragma: no cover
    redis_async = None  # type: ignore

try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer  # type: ignore
except Exception:  # pragma: no cover
    AIOKafkaProducer = AIOKafkaConsumer = None  # type: ignore

try:
    import hvac  # HashiCorp Vault (опционально)
except Exception:  # pragma: no cover
    hvac = None  # type: ignore

try:
    import boto3  # AWS KMS (опционально)
    from botocore.config import Config as BotoConfig  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore
    BotoConfig = None  # type: ignore

try:
    # OpenTelemetry (опционально)
    from opentelemetry import trace, metrics  # type: ignore
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # type: ignore
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter  # type: ignore
    from opentelemetry.sdk.resources import Resource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
    from opentelemetry.sdk.metrics import MeterProvider  # type: ignore
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader  # type: ignore
except Exception:  # pragma: no cover
    trace = metrics = None  # type: ignore
    OTLPSpanExporter = OTLPMetricExporter = None  # type: ignore
    Resource = TracerProvider = BatchSpanProcessor = None  # type: ignore
    MeterProvider = PeriodicExportingMetricReader = None  # type: ignore

# Опциональный PEP‑кэш
PepDecisionCache = None
try:  # pragma: no cover
    from zero_trust.pep.cache import PepDecisionCache as _PepCache  # type: ignore

    PepDecisionCache = _PepCache
except Exception:
    pass


# ----------------------------
# Конфигурация
# ----------------------------

@dataclass(frozen=True)
class AppConfig:
    # Core
    app_name: str = os.getenv("APP_NAME", "veilmind-core")
    app_env: str = os.getenv("APP_ENV", "dev")
    app_version: str = os.getenv("APP_VERSION", "0.1.0")
    tz: str = os.getenv("TZ", "UTC")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_json: bool = os.getenv("LOG_JSON", "true").lower() == "true"

    # Database (PostgreSQL)
    db_driver: str = os.getenv("DB_DRIVER", "postgres")
    db_host: str = os.getenv("DB_HOST", "127.0.0.1")
    db_port: int = int(os.getenv("DB_PORT", "5432"))
    db_name: str = os.getenv("DB_NAME", "veilmind")
    db_user: str = os.getenv("DB_USER", "veilmind_rw")
    db_password: str = os.getenv("DB_PASSWORD", "")
    db_ssl_mode: str = os.getenv("DB_SSL_MODE", "require")  # disable|require|verify-ca|verify-full
    db_pool_min: int = int(os.getenv("DB_POOL_MIN", "1"))
    db_pool_max: int = int(os.getenv("DB_POOL_MAX", "10"))
    db_statement_timeout_ms: int = int(os.getenv("DB_STATEMENT_TIMEOUT_MS", "30000"))

    # Redis
    redis_url: str = os.getenv("REDIS_URL", "")
    redis_password: str = os.getenv("REDIS_PASSWORD", "")

    # Kafka
    kafka_bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "")
    kafka_security_protocol: str = os.getenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    kafka_sasl_mechanism: str = os.getenv("KAFKA_SASL_MECHANISM", "PLAIN")
    kafka_username: str = os.getenv("KAFKA_SASL_USERNAME", "")
    kafka_password: str = os.getenv("KAFKA_SASL_PASSWORD", "")
    kafka_client_id: str = os.getenv("KAFKA_CLIENT_ID", "veilmind-core")

    # OTEL
    otel_service_name: str = os.getenv("OTEL_SERVICE_NAME", "veilmind-core")
    otel_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    otel_protocol: str = os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
    otel_traces_sampler: str = os.getenv("OTEL_TRACES_SAMPLER", "parentbased_traceidratio")
    otel_traces_sampler_arg: float = float(os.getenv("OTEL_TRACES_SAMPLER_ARG", "0.10"))
    otel_resource_attributes: str = os.getenv("OTEL_RESOURCE_ATTRIBUTES", "")

    # Vault
    vault_addr: str = os.getenv("VAULT_ADDR", "")
    vault_namespace: str = os.getenv("VAULT_NAMESPACE", "")
    vault_auth: str = os.getenv("VAULT_AUTH", "approle")  # token|approle|kubernetes
    vault_token: str = os.getenv("VAULT_TOKEN", "")
    vault_role_id: str = os.getenv("VAULT_ROLE_ID", "")
    vault_secret_id: str = os.getenv("VAULT_SECRET_ID", "")
    vault_mount: str = os.getenv("VAULT_MOUNT", "kv")
    vault_path_app: str = os.getenv("VAULT_PATH_APP", "veilmind-core/")

    # Misc / PEP cache
    pep_cache_ttl_sec: int = int(os.getenv("ZT_PEP_CACHE_TTL_SEC", "300"))
    pep_cache_capacity: int = int(os.getenv("ZT_PEP_CACHE_CAPACITY", "50000"))
    pep_negative_cache: bool = os.getenv("ZT_NEGATIVE_CACHE", "true").lower() == "true"

    def dsn(self) -> str:
        """
        Формирует DSN для asyncpg. Если задан DB_PASSWORD пустым — используется анонимное подключение.
        """
        user = self.db_user
        pw = self.db_password
        host = self.db_host
        port = self.db_port
        db = self.db_name
        sslmode = self.db_ssl_mode
        # asyncpg DSN совместим с libpq форматом
        auth = f"{user}:{pw}@" if pw else f"{user}@"
        return f"postgresql://{auth}{host}:{port}/{db}?sslmode={sslmode}"

    def validate(self) -> None:
        # Минимальная валидация окружения
        assert self.db_pool_min >= 0 and self.db_pool_max >= 1 and self.db_pool_max >= self.db_pool_min
        assert self.otel_protocol in ("grpc", "http", "http/protobuf", "http/json")
        if self.kafka_bootstrap_servers and not self.kafka_client_id:
            raise ValueError("KAFKA_CLIENT_ID must be set when KAFKA_BOOTSTRAP_SERVERS is provided")


# ----------------------------
# Логирование
# ----------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Дополнительные поля, если были проставлены через extra
        for k in ("request_id", "component", "subsystem", "event", "actor_id", "db_conn_state"):
            v = getattr(record, k, None)
            if v is not None:
                payload[k] = v
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(cfg: AppConfig) -> logging.Logger:
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if cfg.log_json else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    logger = logging.getLogger("veilmind.bootstrap")
    logger.info("logging configured", extra={"component": "bootstrap"})
    return logger


# ----------------------------
# Резолвер секретов
# ----------------------------

class SecretResolver:
    """
    Простая фабрика секретов:
      - env: просто вернуть значение переменной
      - vault://<path>#<field>
      - awskms://<base64-ciphertext> (дешифр через AWS KMS)
    """

    def __init__(self, cfg: AppConfig, logger: logging.Logger):
        self.cfg = cfg
        self.log = logger
        self._vault_client = None
        self._kms = None

    def _get_vault(self):
        if not hvac or not self.cfg.vault_addr:
            raise RuntimeError("Vault is not configured or hvac is missing")
        if self._vault_client:
            return self._vault_client
        client = hvac.Client(url=self.cfg.vault_addr, namespace=self.cfg.vault_namespace or None)
        if self.cfg.vault_auth == "token":
            client.token = self.cfg.vault_token
        elif self.cfg.vault_auth == "approle":
            client.auth_approle(self.cfg.vault_role_id, self.cfg.vault_secret_id)
        else:
            # Kubernetes или другие — оставить пользователю
            raise RuntimeError("Unsupported VAULT_AUTH mode for bootstrap")
        if not client.is_authenticated():
            raise RuntimeError("Vault authentication failed")
        self._vault_client = client
        return client

    def _get_kms(self):
        if not boto3:
            raise RuntimeError("boto3 missing for KMS decryption")
        if self._kms:
            return self._kms
        self._kms = boto3.client("kms", config=BotoConfig(retries={"max_attempts": 3}))  # type: ignore
        return self._kms

    async def resolve(self, spec: str) -> str:
        if not spec:
            return ""
        if spec.startswith("vault://"):
            # vault://kv/path#field
            path_field = spec[len("vault://") :]
            if "#" not in path_field:
                raise ValueError("vault spec must be vault://<path>#<field>")
            path, field = path_field.split("#", 1)
            path = path.strip().lstrip("/")
            client = self._get_vault()
            # поддежка KVv2: mount/path_app уже учтен в конфиге
            mount = self.cfg.vault_mount.strip("/")
            if not path.startswith(self.cfg.vault_path_app):
                full = f"{self.cfg.vault_path_app}{path}"
            else:
                full = path
            data = client.secrets.kv.v2.read_secret_version(path=full, mount_point=mount)  # type: ignore
            val = data["data"]["data"].get(field)
            if val is None:
                raise KeyError(f"vault field not found: {field}")
            return str(val)
        if spec.startswith("awskms://"):
            cipher_b64 = spec[len("awskms://") :]
            kms = self._get_kms()
            import base64

            blob = base64.b64decode(cipher_b64)
            out = kms.decrypt(CiphertextBlob=blob)
            return out["Plaintext"].decode("utf-8")
        # otherwise treat as plain env var name
        return os.getenv(spec, "")


# ----------------------------
# Контекст приложения и bootstrap
# ----------------------------

@dataclass
class AppContext:
    cfg: AppConfig
    log: logging.Logger
    db: Optional["asyncpg.pool.Pool"] = None  # type: ignore
    redis: Optional["redis_async.Redis"] = None  # type: ignore
    kafka_producer: Optional["AIOKafkaProducer"] = None  # type: ignore
    kafka_consumer: Optional["AIOKafkaConsumer"] = None  # type: ignore
    tracer_provider: Optional["TracerProvider"] = None  # type: ignore
    meter_provider: Optional["MeterProvider"] = None  # type: ignore
    pep_cache: Any = None

    async def close(self) -> None:
        # Закрываем в обратном порядке
        if self.kafka_producer:
            try:
                await self.kafka_producer.stop()
                self.log.info("kafka producer stopped", extra={"component": "bootstrap"})
            except Exception:
                pass
        if self.kafka_consumer:
            try:
                await self.kafka_consumer.stop()
                self.log.info("kafka consumer stopped", extra={"component": "bootstrap"})
            except Exception:
                pass
        if self.redis:
            try:
                await self.redis.close()
                self.log.info("redis closed", extra={"component": "bootstrap"})
            except Exception:
                pass
        if self.db:
            try:
                await self.db.close()
                self.log.info("db pool closed", extra={"component": "bootstrap"})
            except Exception:
                pass

    # Контекстный менеджер
    async def __aenter__(self) -> "AppContext":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()


async def _init_db(cfg: AppConfig, log: logging.Logger):
    if not asyncpg:
        log.warning("asyncpg not installed, database disabled", extra={"component": "db"})
        return None
    try:
        pool = await asyncpg.create_pool(
            dsn=cfg.dsn(),
            min_size=cfg.db_pool_min,
            max_size=cfg.db_pool_max,
            statement_cache_size=0,  # чтобы избежать проблем при частых миграциях
            command_timeout=cfg.db_statement_timeout_ms / 1000.0,
        )
        async with pool.acquire() as con:
            await con.execute("/* bootstrap ping */ SELECT 1;")
        log.info("db pool ready", extra={"component": "db"})
        return pool
    except Exception as e:
        log.error("db init failed: %s", str(e), extra={"component": "db"})
        return None


async def _init_redis(cfg: AppConfig, log: logging.Logger):
    if not cfg.redis_url:
        return None
    if not redis_async:
        log.warning("redis.asyncio not installed, redis disabled", extra={"component": "redis"})
        return None
    try:
        r = redis_async.from_url(cfg.redis_url, decode_responses=True, password=cfg.redis_password or None)
        await r.ping()
        log.info("redis ready", extra={"component": "redis"})
        return r
    except Exception as e:
        log.error("redis init failed: %s", str(e), extra={"component": "redis"})
        return None


async def _init_kafka(cfg: AppConfig, log: logging.Logger):
    if not cfg.kafka_bootstrap_servers:
        return None, None
    if not AIOKafkaProducer:
        log.warning("aiokafka not installed, kafka disabled", extra={"component": "kafka"})
        return None, None
    try:
        # Конфигурация безопасности (упрощенная)
        sasl_mech = cfg.kafka_sasl_mechanism
        sec_proto = cfg.kafka_security_protocol
        common_kwargs: Dict[str, Any] = {
            "bootstrap_servers": cfg.kafka_bootstrap_servers,
            "client_id": cfg.kafka_client_id,
            "request_timeout_ms": 10000,
        }
        if sec_proto != "PLAINTEXT":
            common_kwargs.update(
                security_protocol=sec_proto,
                sasl_mechanism=sasl_mech,
                sasl_plain_username=(cfg.kafka_username or None),
                sasl_plain_password=(cfg.kafka_password or None),
            )
        prod = AIOKafkaProducer(**common_kwargs)  # type: ignore
        await prod.start()
        log.info("kafka producer ready", extra={"component": "kafka"})
        return prod, None
    except Exception as e:
        log.error("kafka init failed: %s", str(e), extra={"component": "kafka"})
        return None, None


def _init_otel(cfg: AppConfig, log: logging.Logger):
    if not trace or not metrics or not Resource:
        log.warning("opentelemetry sdk not installed, telemetry disabled", extra={"component": "otel"})
        return None, None
    if not cfg.otel_endpoint:
        log.info("otel endpoint not configured, telemetry disabled", extra={"component": "otel"})
        return None, None
    try:
        attrs: Dict[str, Any] = {
            "service.name": cfg.otel_service_name,
            "service.version": cfg.app_version,
            "deployment.environment": cfg.app_env,
            "host.name": socket.gethostname(),
        }
        # ручное добавление атрибутов из OTEL_RESOURCE_ATTRIBUTES
        if cfg.otel_resource_attributes:
            for kv in cfg.otel_resource_attributes.split(","):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    attrs[k.strip()] = v.strip()

        res = Resource.create(attrs)
        tp = TracerProvider(resource=res)  # type: ignore
        mp = MeterProvider(resource=res)  # type: ignore

        # Экспортеры
        span_exp = OTLPSpanExporter(endpoint=cfg.otel_endpoint)  # type: ignore
        tp.add_span_processor(BatchSpanProcessor(span_exp))  # type: ignore

        metric_exp = OTLPMetricExporter(endpoint=cfg.otel_endpoint)  # type: ignore
        reader = PeriodicExportingMetricReader(metric_exp)  # type: ignore
        mp.add_metric_reader(reader)

        trace.set_tracer_provider(tp)  # type: ignore
        metrics.set_meter_provider(mp)  # type: ignore

        log.info("otel configured", extra={"component": "otel"})
        return tp, mp
    except Exception as e:
        log.error("otel init failed: %s", str(e), extra={"component": "otel"})
        return None, None


def _init_pep_cache(cfg: AppConfig, log: logging.Logger):
    if not PepDecisionCache:
        return None
    try:
        cache = PepDecisionCache(
            capacity=cfg.pep_cache_capacity,
            default_ttl=float(cfg.pep_cache_ttl_sec),
            allow_negative=cfg.pep_negative_cache,
        )
        log.info("pep cache ready", extra={"component": "pep"})
        return cache
    except Exception as e:
        log.error("pep cache init failed: %s", str(e), extra={"component": "pep"})
        return None


async def _load_sensitive_from_vault(cfg: AppConfig, log: logging.Logger) -> Dict[str, str]:
    """
    Пример: можно объявить переменные вида:
      DB_PASSWORD=vault://<path>#db_password
      REDIS_PASSWORD=vault://<path>#redis_password
    и мы подтянем их значения в рантайме (если hvac доступен).
    """
    mapping = {}
    resolver = SecretResolver(cfg, log)
    # Список известных «секретных» ключей, допускающих vault/kms‑ссылки
    candidates = {
        "DB_PASSWORD": cfg.db_password,
        "REDIS_PASSWORD": cfg.redis_password,
        "KAFKA_SASL_PASSWORD": cfg.kafka_password,
    }
    for key, val in candidates.items():
        if isinstance(val, str) and (val.startswith("vault://") or val.startswith("awskms://")):
            try:
                real = await resolver.resolve(val)
                mapping[key] = real
            except Exception as e:
                log.error("secret resolve failed: %s for %s", str(e), key, extra={"component": "secrets"})
    return mapping


async def bootstrap() -> AppContext:
    """
    Главная функция инициализации. Возвращает AppContext с подключениями и телеметрией.
    """
    cfg = AppConfig()
    cfg.validate()
    log = configure_logging(cfg)

    # Подтягиваем секреты (если указаны через vault:// или awskms://)
    secrets = await _load_sensitive_from_vault(cfg, log)
    if secrets.get("DB_PASSWORD"):
        object.__setattr__(cfg, "db_password", secrets["DB_PASSWORD"])
    if secrets.get("REDIS_PASSWORD"):
        object.__setattr__(cfg, "redis_password", secrets["REDIS_PASSWORD"])
    if secrets.get("KAFKA_SASL_PASSWORD"):
        object.__setattr__(cfg, "kafka_password", secrets["KAFKA_SASL_PASSWORD"])

    # Подключения
    db_pool = await _init_db(cfg, log)
    redis_cli = await _init_redis(cfg, log)
    kafka_prod, kafka_cons = await _init_kafka(cfg, log)
    tracer_provider, meter_provider = _init_otel(cfg, log)
    pep_cache = _init_pep_cache(cfg, log)

    log.info(
        "bootstrap completed",
        extra={
            "component": "bootstrap",
            "subsystem": "core",
            "event": "ready",
        },
    )
    return AppContext(
        cfg=cfg,
        log=log,
        db=db_pool,
        redis=redis_cli,
        kafka_producer=kafka_prod,
        kafka_consumer=kafka_cons,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        pep_cache=pep_cache,
    )


# Удобный контекст‑менеджер для жизненного цикла
@asynccontextmanager
async def app_lifecycle() -> AppContext:
    ctx = await bootstrap()
    try:
        yield ctx
    finally:
        await ctx.close()


# Тестовый запуск (локально)
if __name__ == "__main__":  # pragma: no cover
    async def _main():
        async with app_lifecycle() as ctx:
            print(f"[bootstrap] {ctx.cfg.app_name} {ctx.cfg.app_version} env={ctx.cfg.app_env}")
            # имитация работы
            await asyncio.sleep(0.1)

    asyncio.run(_main())
