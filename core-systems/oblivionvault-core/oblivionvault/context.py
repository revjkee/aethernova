# oblivionvault-core/oblivionvault/context.py
# Центральный контекст приложения: конфиги, секреты, логгер, наблюдаемость, клиенты и ресурсы.
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import functools
import json
import logging
import os
import signal
import sys
import time
import types
import typing as t
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

# Опциональные зависимости (graceful degradation)
try:
    import yaml  # pyyaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
except Exception:  # pragma: no cover
    AsyncEngine = AsyncSession = async_sessionmaker = create_async_engine = None  # type: ignore

try:
    import redis.asyncio as aioredis
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

try:
    import aioboto3
except Exception:  # pragma: no cover
    aioboto3 = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = CollectorRegistry = None  # type: ignore

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
except Exception:  # pragma: no cover
    trace = TracerProvider = BatchSpanProcessor = OTLPSpanExporter = Resource = None  # type: ignore

# JSON Schema (валидация артефактов, по необходимости)
try:
    from jsonschema import Draft202012Validator
except Exception:  # pragma: no cover
    Draft202012Validator = None  # type: ignore

# ------------------------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------------------------

ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

def make_ulid_like() -> str:
    ts = int(time.time() * 1000)
    tpart = ""
    n = ts
    while n > 0:
        tpart = ULID_ALPHABET[n % 32] + tpart
        n //= 32
    import secrets
    rpart = "".join(ULID_ALPHABET[secrets.randbelow(32)] for _ in range(16))
    return (tpart + rpart)[:26]

def deep_merge(a: t.Mapping, b: t.Mapping) -> dict:
    out = dict(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ------------------------------------------------------------------------------
# Резолвер секретов: secretref://env/VAR, secretref://file/path, secretref://aws-secretsmanager/...
# ------------------------------------------------------------------------------

class SecretError(RuntimeError):
    pass

class SecretResolver:
    def __init__(self, cache_ttl: int = 300):
        self._cache: dict[str, tuple[float, t.Any]] = {}
        self._ttl = cache_ttl

    async def resolve(self, ref: str) -> t.Any:
        if not isinstance(ref, str) or not ref.startswith("secretref://"):
            return ref
        now = time.time()
        cached = self._cache.get(ref)
        if cached and now - cached[0] < self._ttl:
            return cached[1]

        scheme_path = ref[len("secretref://"):]  # env/VAR, file/..., aws-secretsmanager/...
        if scheme_path.startswith("env/"):
            key = scheme_path[4:]
            val = os.getenv(key)
            if val is None:
                raise SecretError(f"ENV secret {key} is not set")
            self._cache[ref] = (now, val)
            return val

        if scheme_path.startswith("file/"):
            file_path = scheme_path[5:]
            p = Path(file_path)
            if not p.exists():
                raise SecretError(f"Secret file not found: {p}")
            val = p.read_text(encoding="utf-8").strip()
            self._cache[ref] = (now, val)
            return val

        if scheme_path.startswith("aws-secretsmanager/"):
            if aioboto3 is None:
                raise SecretError("aioboto3 is not available for AWS Secrets Manager")
            secret_id = scheme_path[len("aws-secretsmanager/"):]
            async with aioboto3.client("secretsmanager") as client:
                resp = await client.get_secret_value(SecretId=secret_id)
                if "SecretString" in resp:
                    val = resp["SecretString"]
                else:
                    import base64
                    val = base64.b64decode(resp["SecretBinary"]).decode("utf-8")
            self._cache[ref] = (now, val)
            return val

        raise SecretError(f"Unsupported secretref: {ref}")

    async def resolve_in_mapping(self, data: t.Any) -> t.Any:
        # Рекурсивное развёртывание secretref для dict/list/str
        if isinstance(data, str):
            return await self.resolve(data)
        if isinstance(data, list):
            return [await self.resolve_in_mapping(x) for x in data]
        if isinstance(data, dict):
            out = {}
            for k, v in data.items():
                out[k] = await self.resolve_in_mapping(v)
            return out
        return data

# ------------------------------------------------------------------------------
# Конфиг-лоадер: YAML + ENV overrides
# ------------------------------------------------------------------------------

class ConfigError(RuntimeError):
    pass

class ConfigLoader:
    def __init__(self, env: str, base_dir: str | Path | None = None):
        self.env = env
        self.base_dir = Path(base_dir or Path(__file__).resolve().parents[2])
        # ожидаем: configs/env/{env}.yaml
        self.env_file = self.base_dir / "configs" / "env" / f"{env}.yaml"

    def load(self) -> dict:
        if yaml is None:
            raise ConfigError("PyYAML is not installed")
        if not self.env_file.exists():
            raise ConfigError(f"Config file not found: {self.env_file}")
        d = yaml.safe_load(self.env_file.read_text(encoding="utf-8")) or {}
        # ENV overrides: OVAULT__a__b=value => config["a"]["b"]=value (простая схема)
        for key, val in os.environ.items():
            if not key.startswith("OVAULT__"):
                continue
            path = key[len("OVAULT__") :].split("__")
            cur = d
            for segment in path[:-1]:
                cur = cur.setdefault(segment, {})
            # Автоматическая типизация true/false/int/float/json
            cur[path[-1]] = self._coerce(val)
        return d

    @staticmethod
    def _coerce(v: str) -> t.Any:
        low = v.lower()
        if low in {"true", "false"}:
            return low == "true"
        try:
            if "." in v:
                return float(v)
            return int(v)
        except ValueError:
            pass
        # попробуем JSON
        try:
            return json.loads(v)
        except Exception:
            return v

# ------------------------------------------------------------------------------
# Логирование (JSON), безопасная редакция полей
# ------------------------------------------------------------------------------

REDACT_KEYS = {"password", "token", "authorization", "cookie", "set-cookie", "x-api-key", "secret", "client_secret"}

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        # контекст, если задан
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(self._redact(record.extra))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _redact(d: dict) -> dict:
        out = {}
        for k, v in d.items():
            lk = str(k).lower()
            if lk in REDACT_KEYS:
                out[k] = "***"
            else:
                out[k] = v
        return out

def setup_logger(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("oblivionvault")
    logger.setLevel(level.upper())
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.handlers = [handler]
    logger.propagate = False
    return logger

# ------------------------------------------------------------------------------
# Метрики Prometheus (опционально)
# ------------------------------------------------------------------------------

@dataclasses.dataclass
class Metrics:
    registry: t.Any | None
    http_requests_total: t.Any | None
    http_latency_seconds: t.Any | None
    db_queries_total: t.Any | None

def setup_metrics() -> Metrics:
    if CollectorRegistry is None:
        return Metrics(None, None, None, None)
    reg = CollectorRegistry()
    http_total = Counter("http_requests_total", "HTTP requests", ["method", "route", "status"], registry=reg)
    http_latency = Histogram("http_request_latency_seconds", "HTTP latency", ["method", "route"], registry=reg)
    db_total = Counter("db_queries_total", "DB queries", ["op"], registry=reg)
    return Metrics(reg, http_total, http_latency, db_total)

# ------------------------------------------------------------------------------
# Трейсинг OpenTelemetry (опционально)
# ------------------------------------------------------------------------------

@dataclasses.dataclass
class Tracing:
    tracer_provider: t.Any | None

def setup_tracing(service_name: str, endpoint: str | None) -> Tracing:
    if not endpoint or TracerProvider is None:
        return Tracing(None)
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=endpoint)
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)  # type: ignore
    return Tracing(provider)

# ------------------------------------------------------------------------------
# HTTP-клиент с ретраями и таймаутами (httpx)
# ------------------------------------------------------------------------------

class HttpClientFactory:
    def __init__(self, timeout: float = 15.0, retries: int = 2, backoff_ms: int = 150):
        self.timeout = timeout
        self.retries = retries
        self.backoff_ms = backoff_ms

    def _transport(self) -> httpx.AsyncBaseTransport:
        return httpx.AsyncHTTPTransport(retries=self.retries)

    def make(self, headers: dict[str, str] | None = None) -> httpx.AsyncClient:
        if httpx is None:
            raise RuntimeError("httpx is not installed")
        return httpx.AsyncClient(
            timeout=self.timeout,
            headers=headers or {},
            transport=self._transport(),
        )

# ------------------------------------------------------------------------------
# Главный контекст приложения
# ------------------------------------------------------------------------------

@dataclasses.dataclass
class AppContext:
    env: str
    config: dict
    logger: logging.Logger
    metrics: Metrics
    tracing: Tracing
    secret_resolver: SecretResolver

    http: httpx.AsyncClient | None = None
    db_engine: AsyncEngine | None = None
    db_sessionmaker: async_sessionmaker[AsyncSession] | None = None  # type: ignore[type-arg]
    redis: t.Any | None = None
    s3: t.Any | None = None
    json_validators: dict[str, Draft202012Validator] | None = None

    _shutdown_callbacks: list[t.Callable[[], t.Awaitable[None]]] = dataclasses.field(default_factory=list)

    # ----------------------------
    # Фабрика контекста
    # ----------------------------
    @classmethod
    async def from_env(cls, env: str = None) -> "AppContext":
        env = env or os.getenv("OVAULT_ENV", "prod")
        loader = ConfigLoader(env=env)
        config = loader.load()

        logger = setup_logger(level=str(((config.get("observability") or {}).get("logging") or {}).get("level", "INFO")))
        metrics = setup_metrics()
        tracing = setup_tracing(
            service_name=config.get("app", {}).get("name", "oblivionvault-core"),
            endpoint=((config.get("observability") or {}).get("tracing") or {}).get("endpoint"),
        )
        secrets = SecretResolver(cache_ttl=int(((config.get("security") or {}).get("secrets") or {}).get("cache_ttl", 300)))

        ctx = cls(
            env=env,
            config=config,
            logger=logger,
            metrics=metrics,
            tracing=tracing,
            secret_resolver=secrets,
        )
        await ctx._startup()
        return ctx

    # ----------------------------
    # Жизненный цикл
    # ----------------------------
    async def _startup(self) -> None:
        self.logger.info("context.start", extra={"env": self.env, "ts": now_iso()})

        # HTTP client
        if httpx is not None:
            headers = {
                "User-Agent": f"oblivionvault-core/{self.config.get('revision','unknown')}",
                "X-Request-ID": make_ulid_like(),
            }
            self.http = HttpClientFactory(
                timeout=float(self.config.get("networking", {}).get("http", {}).get("client_timeout", 15)),
                retries=int(self.config.get("networking", {}).get("http", {}).get("retries", 2)),
            ).make(headers=headers)
            self._shutdown_callbacks.append(self.http.aclose)  # type: ignore[arg-type]

        # DB
        db_cfg = (self.config.get("services") or {}).get("database") or {}
        if db_cfg and create_async_engine is not None:
            # DSN может содержать secretref
            user = os.getenv("DB_USER") or db_cfg.get("user")
            password = await self.secret_resolver.resolve(db_cfg.get("password"))
            host = os.getenv("DB_HOST") or db_cfg.get("host")
            port = db_cfg.get("port", 5432)
            dbname = db_cfg.get("dbname", "oblivionvault")
            sslmode = db_cfg.get("sslmode", "verify-full")
            dsn = f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}"
            self.db_engine = create_async_engine(
                dsn,
                pool_pre_ping=True,
                pool_size=int((db_cfg.get("pool") or {}).get("min_conns", 5)),
                max_overflow=int((db_cfg.get("pool") or {}).get("max_conns", 20)),
            )
            self.db_sessionmaker = async_sessionmaker(self.db_engine, expire_on_commit=False)  # type: ignore[call-arg]

            async def _close_db():
                await self.db_engine.dispose()  # type: ignore[union-attr]

            self._shutdown_callbacks.append(_close_db)

        # Redis
        cache_cfg = (self.config.get("services") or {}).get("cache") or {}
        if cache_cfg and aioredis is not None:
            endpoints = cache_cfg.get("endpoints") or []
            password = await self.secret_resolver.resolve(cache_cfg.get("password")) if cache_cfg.get("password") else None
            # Для кластера (если указан mode: cluster)
            if cache_cfg.get("mode") == "cluster" and hasattr(aioredis, "RedisCluster"):
                self.redis = aioredis.RedisCluster.from_url(
                    f"redis://{endpoints[0]}",
                    username=cache_cfg.get("username"),
                    password=password,
                    decode_responses=False,
                )
            else:
                self.redis = aioredis.Redis.from_url(
                    f"redis://{endpoints[0]}" if endpoints else "redis://localhost:6379",
                    username=cache_cfg.get("username"),
                    password=password,
                    decode_responses=False,
                )

            async def _close_redis():
                try:
                    await self.redis.close()  # type: ignore[union-attr]
                except Exception:
                    pass

            self._shutdown_callbacks.append(_close_redis)

        # S3
        s3_cfg = (self.config.get("services") or {}).get("object_storage") or {}
        if s3_cfg and aioboto3 is not None and s3_cfg.get("provider") == "s3":
            sess = aioboto3.Session()
            # креды могут быть secretref
            access_key = await self.secret_resolver.resolve(((s3_cfg.get("credentials") or {}).get("access_key_id")))
            secret_key = await self.secret_resolver.resolve(((s3_cfg.get("credentials") or {}).get("secret_access_key")))
            region = (self.config.get("app") or {}).get("region") or os.getenv("AWS_REGION", "eu-north-1")
            self.s3 = sess.client(
                "s3",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
                endpoint_url=s3_cfg.get("endpoint"),
            )

            async def _close_s3():
                try:
                    await self.s3.close()  # type: ignore[union-attr]
                except Exception:
                    pass

            self._shutdown_callbacks.append(_close_s3)

        # JSON Schema кэш
        self.json_validators = {}

        # Перехват SIGTERM/SIGINT для мягкого завершения
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.shutdown(reason=f"signal:{s.name}")))

        self.logger.info("context.ready", extra={"ts": now_iso()})

    async def shutdown(self, reason: str = "normal") -> None:
        self.logger.info("context.shutdown.start", extra={"reason": reason})
        # Запускаем коллбеки в обратном порядке
        while self._shutdown_callbacks:
            cb = self._shutdown_callbacks.pop()
            with contextlib.suppress(Exception):
                await cb()
        self.logger.info("context.shutdown.done")

    # ----------------------------
    # Утилиты
    # ----------------------------
    @asynccontextmanager
    async def db_session(self) -> t.AsyncIterator[AsyncSession]:
        if self.db_sessionmaker is None:
            raise RuntimeError("Database is not configured")
        session = self.db_sessionmaker()  # type: ignore[operator]
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    def validator_for(self, schema_path: str) -> Draft202012Validator:
        if Draft202012Validator is None:
            raise RuntimeError("jsonschema is not installed")
        schema_path = str(schema_path)
        if schema_path in self.json_validators:
            return self.json_validators[schema_path]  # type: ignore[index]
        p = Path(schema_path)
        if not p.is_absolute():
            # относительно корня repo
            base = Path(__file__).resolve().parents[2]
            p = (base / schema_path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Schema file not found: {p}")
        schema = json.loads(p.read_text(encoding="utf-8"))
        v = Draft202012Validator(schema)
        self.json_validators[schema_path] = v  # type: ignore[index]
        return v

    async def secret(self, val: t.Any) -> t.Any:
        return await self.secret_resolver.resolve_in_mapping(val)

    def log(self, level: int, msg: str, **extra):
        self.logger.log(level, msg, extra={"extra": extra})

# ------------------------------------------------------------------------------
# FastAPI lifespan/Depends интеграция
# ------------------------------------------------------------------------------

_GLOBAL_CTX: AppContext | None = None

@asynccontextmanager
async def lifespan(_: t.Any):  # FastAPI(app).lifespan
    global _GLOBAL_CTX
    ctx = await AppContext.from_env()
    _GLOBAL_CTX = ctx
    try:
        yield
    finally:
        await ctx.shutdown("app_lifespan")

def get_context() -> AppContext:
    if _GLOBAL_CTX is None:
        raise RuntimeError("AppContext is not initialized. Attach lifespan to FastAPI app.")
    return _GLOBAL_CTX

# ------------------------------------------------------------------------------
# Примеры вспомогательных хелперов (S3/HTTP/Redis)
# ------------------------------------------------------------------------------

async def s3_upload(ctx: AppContext, bucket: str, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
    if ctx.s3 is None:
        raise RuntimeError("S3 client is not configured")
    await ctx.s3.put_object(Bucket=bucket, Key=key, Body=data, ContentType=content_type)
    return f"s3://{bucket}/{key}"

async def http_get_json(ctx: AppContext, url: str, headers: dict[str, str] | None = None, timeout: float | None = None) -> dict:
    if ctx.http is None:
        raise RuntimeError("HTTP client is not configured")
    r = await ctx.http.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()

async def redis_setex(ctx: AppContext, key: str, ttl: int, value: bytes) -> None:
    if ctx.redis is None:
        raise RuntimeError("Redis is not configured")
    await ctx.redis.setex(key, ttl, value)

# ------------------------------------------------------------------------------
# Точка входа для локального запуска/проверки (необязательно)
# ------------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def _main():
        ctx = await AppContext.from_env(os.getenv("OVAULT_ENV", "dev"))
        ctx.log(logging.INFO, "context.selftest", env=ctx.env)
        await ctx.shutdown("selftest")
    asyncio.run(_main())
