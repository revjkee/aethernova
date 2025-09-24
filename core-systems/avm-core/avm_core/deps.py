"""
avm_core.deps — промышленный DI/ресурсный контейнер для ядра AVM.

Ключевые свойства:
- Lazy инициализация провайдеров, безопасные заглушки (NOOP) при отсутствии внешних пакетов.
- Чёткий жизненный цикл: init -> use -> shutdown, с идемпотентными завершениями.
- Контекстная изоляция (contextvars) для совместимости с async‑стеком и тестами.
- Перекрытия зависимостей в тестах/садбоксах через overrides() без monkey‑patching.
- Единообразное логирование (structlog если доступен, иначе logging), транспорт метрик/трейсинга (OTel, если доступен).
- Интеграция с httpx (ретраи, таймауты), Redis (aioredis), SQLAlchemy async engine — по возможности, иначе NOOP.

Зависимости (опциональные):
- httpx>=0.24  — HTTP‑клиент
- redis>=5     — Redis (async)
- sqlalchemy>=2, asyncpg — БД (опционально)
- structlog    — структурное логирование
- opentelemetry-sdk, opentelemetry-exporter-otlp — трейсинг (опционально)
- pyjwt|python-jose[cryptography] — JWT/подписи (опционально)

Автор: NeuroCity Engineering
Лицензия: Proprietary
"""
from __future__ import annotations

import asyncio
import atexit
import contextlib
import contextvars
import dataclasses
import functools
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, MutableMapping, Optional, Tuple, TypeVar

# -------------------------------
# Внутренние типы и утилиты
# -------------------------------
T = TypeVar("T")

class DependencyError(RuntimeError):
    """Ошибка предоставления зависимости."""

class LazyImportError(DependencyError):
    """Уточнение: требуемый пакет не установлен."""

def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None and v != "" else default

def _to_bool(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")

# -------------------------------
# Настройки (без жёсткой зависимости от pydantic)
# -------------------------------
@dataclass(frozen=True)
class Settings:
    # Общие
    env: str = field(default_factory=lambda: _env("AVM_ENV", "prod"))
    service_name: str = field(default_factory=lambda: _env("AVM_SERVICE", "avm-core"))
    log_level: str = field(default_factory=lambda: _env("AVM_LOG_LEVEL", "INFO"))
    log_json: bool = field(default_factory=lambda: _to_bool(_env("AVM_LOG_JSON", "1"), True))

    # HTTP
    http_timeout_sec: float = field(default_factory=lambda: float(_env("AVM_HTTP_TIMEOUT", "10")))
    http_retries: int = field(default_factory=lambda: int(_env("AVM_HTTP_RETRIES", "2")))
    http_backoff_base: float = field(default_factory=lambda: float(_env("AVM_HTTP_BACKOFF_BASE", "0.2")))
    http_keepalive: bool = field(default_factory=lambda: _to_bool(_env("AVM_HTTP_KEEPALIVE", "1"), True))

    # Redis
    redis_url: Optional[str] = field(default_factory=lambda: _env("AVM_REDIS_URL"))
    redis_namespace: str = field(default_factory=lambda: _env("AVM_REDIS_NS", "avm:core"))
    redis_tls: bool = field(default_factory=lambda: _to_bool(_env("AVM_REDIS_TLS", "0"), False))

    # DB (SQLAlchemy async)
    db_url: Optional[str] = field(default_factory=lambda: _env("AVM_DB_URL"))
    db_pool_min: int = field(default_factory=lambda: int(_env("AVM_DB_POOL_MIN", "1")))
    db_pool_max: int = field(default_factory=lambda: int(_env("AVM_DB_POOL_MAX", "10")))
    db_echo: bool = field(default_factory=lambda: _to_bool(_env("AVM_DB_ECHO", "0"), False))

    # Telemetry (OTel)
    otel_enabled: bool = field(default_factory=lambda: _to_bool(_env("AVM_OTEL_ENABLED", "0"), False))
    otel_endpoint: Optional[str] = field(default_factory=lambda: _env("OTEL_EXPORTER_OTLP_ENDPOINT"))
    otel_service_version: str = field(default_factory=lambda: _env("AVM_VERSION", "0.0.0"))

    # Crypto / JWT
    jwt_algorithm: str = field(default_factory=lambda: _env("AVM_JWT_ALG", "RS256"))
    jwt_issuer: Optional[str] = field(default_factory=lambda: _env("AVM_JWT_ISS"))
    jwt_audience: Optional[str] = field(default_factory=lambda: _env("AVM_JWT_AUD"))
    jwt_key_env: Optional[str] = field(default_factory=lambda: _env("AVM_JWT_KEY_ENV", "AVM_JWT_SIGNING_KEY_PEM"))

# -------------------------------
# Логирование
# -------------------------------
def _setup_logger(settings: Settings) -> logging.Logger:
    logger = logging.getLogger(settings.service_name)
    if logger.handlers:
        return logger
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    if settings.log_json:
        class JsonFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                payload = {
                    "ts": int(time.time() * 1000),
                    "level": record.levelname,
                    "msg": record.getMessage(),
                    "logger": record.name,
                    "module": record.module,
                    "func": record.funcName,
                }
                if record.exc_info:
                    payload["exc_info"] = self.formatException(record.exc_info)
                return json.dumps(payload, ensure_ascii=False)
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger

def _maybe_structlog(logger: logging.Logger):
    try:
        import structlog  # type: ignore
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.add_log_level,
                structlog.processors.EventRenamer("msg"),
                structlog.processors.JSONRenderer(ensure_ascii=False),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(logger.level),
            cache_logger_on_first_use=True,
        )
        return structlog.get_logger(logger.name)
    except Exception:
        return logger

# -------------------------------
# NOOP заглушки
# -------------------------------
class _NoopAsyncCloser:
    async def aclose(self) -> None:
        return

class NoopCache:
    async def get(self, key: str) -> Optional[str]:
        return None
    async def set(self, key: str, value: str, ttl: int = 60) -> None:
        return
    async def delete(self, key: str) -> None:
        return
    async def aclose(self) -> None:
        return

class NoopDB:
    async def acquire(self) -> contextlib.AbstractAsyncContextManager:
        @contextlib.asynccontextmanager
        async def _cm():
            yield None
        return _cm()
    async def aclose(self) -> None:
        return

class NoopTracer:
    def start_span(self, name: str):
        @contextlib.contextmanager
        def _cm():
            yield
        return _cm()

class NoopCrypto:
    def sign_jwt(self, claims: Mapping[str, Any]) -> str:
        raise LazyImportError("JWT signing not available: install `pyjwt` or `python-jose[cryptography]`")
    def verify_jwt(self, token: str) -> Mapping[str, Any]:
        raise LazyImportError("JWT verification not available: install `pyjwt` or `python-jose[cryptography]`")

# -------------------------------
# HTTP клиент (httpx) с ретраями
# -------------------------------
class HttpClient(_NoopAsyncCloser):
    def __init__(self, settings: Settings, logger: Any):
        self._settings = settings
        self._logger = logger
        self._client = None  # lazy

    async def ensure(self):
        if self._client is not None:
            return
        try:
            import httpx  # type: ignore
        except Exception as e:
            raise LazyImportError("httpx is required for HttpClient") from e

        limits = httpx.Limits(max_keepalive_connections=64, max_connections=128) if self._settings.http_keepalive else None
        self._client = httpx.AsyncClient(
            timeout=self._settings.http_timeout_sec,
            limits=limits,
            follow_redirects=False,
        )

    async def request(self, method: str, url: str, **kw) -> Any:
        await self.ensure()
        # Простейший экспоненциальный retry по сетевым ошибкам/5xx
        retries = max(0, int(self._settings.http_retries))
        backoff = max(0.0, float(self._settings.http_backoff_base))
        last_exc = None
        for attempt in range(retries + 1):
            try:
                resp = await self._client.request(method.upper(), url, **kw)
                if resp.status_code >= 500 and attempt < retries:
                    raise RuntimeError(f"server {resp.status_code}")
                return resp
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt >= retries:
                    self._logger.error("http_request_failed", extra={"url": url, "attempt": attempt, "err": str(exc)})
                    raise
                await asyncio.sleep(backoff * (2 ** attempt))
        if last_exc:
            raise last_exc

    async def get(self, url: str, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw):
        return await self.request("POST", url, **kw)

    async def aclose(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            finally:
                self._client = None

# -------------------------------
# Redis кэш (опционально)
# -------------------------------
class RedisCache(NoopCache):
    def __init__(self, settings: Settings, logger: Any):
        self._settings = settings
        self._logger = logger
        self._redis = None  # lazy

    async def ensure(self):
        if self._redis is not None:
            return
        if not self._settings.redis_url:
            self._logger.info("redis_disabled_no_url")
            raise LazyImportError("AVM_REDIS_URL not set")
        try:
            import redis.asyncio as redis  # type: ignore
            ssl = self._settings.redis_tls
            self._redis = redis.from_url(self._settings.redis_url, encoding="utf-8", decode_responses=True, ssl=ssl)
        except Exception as e:
            raise LazyImportError("redis>=5 required for RedisCache") from e

    async def get(self, key: str) -> Optional[str]:
        await self.ensure()
        return await self._redis.get(f"{self._settings.redis_namespace}:{key}")

    async def set(self, key: str, value: str, ttl: int = 60) -> None:
        await self.ensure()
        await self._redis.set(f"{self._settings.redis_namespace}:{key}", value, ex=ttl)

    async def delete(self, key: str) -> None:
        await self.ensure()
        await self._redis.delete(f"{self._settings.redis_namespace}:{key}")

    async def aclose(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.close()
            finally:
                self._redis = None

# -------------------------------
# БД провайдер (SQLAlchemy async)
# -------------------------------
class Database(NoopDB):
    def __init__(self, settings: Settings, logger: Any):
        self._settings = settings
        self._logger = logger
        self._engine = None

    async def ensure(self):
        if self._engine is not None:
            return
        if not self._settings.db_url:
            self._logger.info("db_disabled_no_url")
            raise LazyImportError("AVM_DB_URL not set")
        try:
            from sqlalchemy.ext.asyncio import create_async_engine  # type: ignore
        except Exception as e:
            raise LazyImportError("sqlalchemy>=2 async required (and asyncpg if Postgres)") from e
        self._engine = create_async_engine(
            self._settings.db_url,
            echo=self._settings.db_echo,
            pool_pre_ping=True,
            pool_size=self._settings.db_pool_max,
            max_overflow=max(0, self._settings.db_pool_max - self._settings.db_pool_min),
        )

    async def acquire(self):
        await self.ensure()
        from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
        from sqlalchemy.orm import sessionmaker  # type: ignore
        maker = sessionmaker(self._engine, expire_on_commit=False, class_=AsyncSession)
        @contextlib.asynccontextmanager
        async def _cm():
            async with maker() as session:
                yield session
        return _cm()

    async def aclose(self) -> None:
        if self._engine is not None:
            try:
                await self._engine.dispose()
            finally:
                self._engine = None

# -------------------------------
# Криптопровайдер (JWT)
# -------------------------------
class CryptoProvider(NoopCrypto):
    def __init__(self, settings: Settings):
        self._settings = settings
        self._priv_key_pem = None

    def _load_key(self) -> str:
        if self._priv_key_pem:
            return self._priv_key_pem
        key_env = self._settings.jwt_key_env or "AVM_JWT_SIGNING_KEY_PEM"
        pem = os.getenv(key_env)
        if not pem:
            raise DependencyError(f"JWT signing key not found in env: {key_env}")
        self._priv_key_pem = pem
        return pem

    def sign_jwt(self, claims: Mapping[str, Any]) -> str:
        # jose -> pyjwt fallback
        alg = self._settings.jwt_algorithm
        iss = self._settings.jwt_issuer
        aud = self._settings.jwt_audience
        payload = dict(claims)
        if iss and "iss" not in payload:
            payload["iss"] = iss
        if aud and "aud" not in payload:
            payload["aud"] = aud
        key = self._load_key()
        try:
            from jose import jwt  # type: ignore
            return jwt.encode(payload, key, algorithm=alg)
        except Exception:
            try:
                import jwt as pyjwt  # type: ignore
                return pyjwt.encode(payload, key, algorithm=alg)
            except Exception as e:
                raise LazyImportError("Install `python-jose[cryptography]` or `PyJWT`") from e

    def verify_jwt(self, token: str) -> Mapping[str, Any]:
        alg = self._settings.jwt_algorithm
        key = self._load_key()
        try:
            from jose import jwt  # type: ignore
            return jwt.decode(token, key, algorithms=[alg], options={"verify_aud": False})
        except Exception:
            try:
                import jwt as pyjwt  # type: ignore
                return pyjwt.decode(token, key, algorithms=[alg], options={"verify_aud": False})
            except Exception as e:
                raise LazyImportError("Install `python-jose[cryptography]` or `PyJWT`") from e

# -------------------------------
# Телеметрия (OTel, опционально)
# -------------------------------
class Tracer(NoopTracer):
    def __init__(self, settings: Settings, logger: Any):
        self._settings = settings
        self._logger = logger
        self._tracer = None

    def ensure(self):
        if self._tracer is not None:
            return
        if not self._settings.otel_enabled:
            self._logger.info("otel_disabled")
            raise LazyImportError("OTel disabled")
        try:
            from opentelemetry import trace  # type: ignore
            from opentelemetry.sdk.resources import Resource  # type: ignore
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore
            from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # type: ignore
            resource = Resource.create({
                "service.name": self._settings.service_name,
                "service.version": self._settings.otel_service_version,
                "service.namespace": "core-systems",
            })
            provider = TracerProvider(resource=resource)
            endpoint = self._settings.otel_endpoint or "http://localhost:4317"
            processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
            provider.add_span_processor(processor)
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(self._settings.service_name)
        except Exception as e:
            raise LazyImportError("opentelemetry SDK/exporter missing") from e

    def start_span(self, name: str):
        try:
            self.ensure()
        except LazyImportError:
            return super().start_span(name)
        span_cm = self._tracer.start_as_current_span(name)
        return span_cm

# -------------------------------
# DI‑контейнер и управление жизненным циклом
# -------------------------------
@dataclass
class DependencyContainer:
    settings: Settings
    logger: Any
    http: HttpClient
    cache: NoopCache | RedisCache
    db: NoopDB | Database
    crypto: NoopCrypto | CryptoProvider
    tracer: NoopTracer | Tracer
    _closed: bool = field(default=False, init=False)

    async def aclose(self):
        if self._closed:
            return
        # Закрываем по мере наличия интерфейсов закрытия
        for obj in (self.http, self.cache, self.db):
            with contextlib.suppress(Exception):
                close = getattr(obj, "aclose", None)
                if asyncio.iscoroutinefunction(close):
                    await close()  # type: ignore[misc]
                elif callable(close):
                    close()
        self._closed = True

# Текущий контейнер в contextvar (без глобальных одиночек)
_current_container: contextvars.ContextVar[Optional[DependencyContainer]] = contextvars.ContextVar(
    "avm_core_current_container", default=None
)

# Временные overrides (например, для тестов)
_overrides: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("avm_core_overrides", default={})

def _get_override(name: str) -> Optional[Any]:
    ov = _overrides.get()
    return ov.get(name)

@contextlib.contextmanager
def overrides(**mapping: Any):
    """
    Пример:
        with overrides(http=FakeHttp(), cache=InMemoryCache()):
            ...
    """
    old = _overrides.get()
    new = dict(old)
    new.update(mapping)
    token = _overrides.set(new)
    try:
        yield
    finally:
        _overrides.reset(token)

# Фабрики провайдеров (с учётом overrides)
def _make_http(settings: Settings, logger: Any) -> HttpClient:
    o = _get_override("http")
    if o is not None:
        return o
    return HttpClient(settings, logger)

def _make_cache(settings: Settings, logger: Any) -> NoopCache | RedisCache:
    o = _get_override("cache")
    if o is not None:
        return o
    if settings.redis_url:
        return RedisCache(settings, logger)
    return NoopCache()

def _make_db(settings: Settings, logger: Any) -> NoopDB | Database:
    o = _get_override("db")
    if o is not None:
        return o
    if settings.db_url:
        return Database(settings, logger)
    return NoopDB()

def _make_crypto(settings: Settings) -> NoopCrypto | CryptoProvider:
    o = _get_override("crypto")
    if o is not None:
        return o
    return CryptoProvider(settings)

def _make_tracer(settings: Settings, logger: Any) -> NoopTracer | Tracer:
    o = _get_override("tracer")
    if o is not None:
        return o
    if settings.otel_enabled:
        return Tracer(settings, logger)
    return NoopTracer()

# Публичные API
def get_container() -> DependencyContainer:
    c = _current_container.get()
    if c is None:
        raise DependencyError("Dependency container is not initialized. Call init_container() first.")
    return c

def get_settings() -> Settings:
    return get_container().settings

def get_logger() -> Any:
    return get_container().logger

def get_http() -> HttpClient:
    return get_container().http

def get_cache() -> NoopCache | RedisCache:
    return get_container().cache

def get_db() -> NoopDB | Database:
    return get_container().db

def get_crypto() -> NoopCrypto | CryptoProvider:
    return get_container().crypto

def get_tracer() -> NoopTracer | Tracer:
    return get_container().tracer

# Инициализация/завершение контейнера
def init_container(settings: Optional[Settings] = None) -> DependencyContainer:
    if _current_container.get() is not None:
        return _current_container.get()  # идемпотентность

    settings = settings or Settings()
    base_logger = _setup_logger(settings)
    logger = _maybe_structlog(base_logger)

    container = DependencyContainer(
        settings=settings,
        logger=logger,
        http=_make_http(settings, logger),
        cache=_make_cache(settings, logger),
        db=_make_db(settings, logger),
        crypto=_make_crypto(settings),
        tracer=_make_tracer(settings, logger),
    )
    _current_container.set(container)

    # Грейсфул‑shutdown на SIGTERM/SIGINT и при выходе процесса
    def _install_signals():
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        async def _async_shutdown():
            try:
                await container.aclose()
            except Exception as e:  # noqa: BLE001
                base_logger.error("container_shutdown_error", extra={"err": str(e)})

        def _sync_handler(signum, _frame):
            base_logger.info("signal_received", extra={"signal": signum})
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(_async_shutdown(), loop)
            else:
                asyncio.run(_async_shutdown())

        with contextlib.suppress(Exception):
            signal.signal(signal.SIGTERM, _sync_handler)
        with contextlib.suppress(Exception):
            signal.signal(signal.SIGINT, _sync_handler)

    _install_signals()
    atexit.register(lambda: asyncio.run(container.aclose()))
    logger.info("container_initialized", extra={"env": settings.env, "service": settings.service_name})
    return container

async def shutdown_container() -> None:
    c = _current_container.get()
    if c is None:
        return
    await c.aclose()
    _current_container.set(None)

# -------------------------------
# Lifespan‑контекст (например, FastAPI lifespan=deps.lifespan)
# -------------------------------
@contextlib.asynccontextmanager
async def lifespan(_: Any = None):
    """
    Пример использования с FastAPI:
        app = FastAPI(lifespan=deps.lifespan)
    """
    init_container()
    try:
        yield
    finally:
        await shutdown_container()

# -------------------------------
# Утилиты для часто используемых операций
# -------------------------------
async def http_json(method: str, url: str, *, expect_status: int = 200, **kw) -> Tuple[int, Dict[str, Any]]:
    http = get_http()
    resp = await http.request(method, url, **kw)
    status = resp.status_code
    body: Dict[str, Any] = {}
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = {"raw": await resp.aread()} if hasattr(resp, "aread") else {"raw": resp.text}
    if status != expect_status:
        get_logger().error("http_unexpected_status", extra={"status": status, "url": url, "body": body})
    return status, body

async def cache_json_get(key: str) -> Optional[Dict[str, Any]]:
    v = await get_cache().get(key)
    if v is None:
        return None
    try:
        return json.loads(v)
    except Exception:  # noqa: BLE001
        return None

async def cache_json_set(key: str, value: Mapping[str, Any], ttl: int = 60) -> None:
    await get_cache().set(key, json.dumps(value, ensure_ascii=False), ttl=ttl)

# -------------------------------
# __all__
# -------------------------------
__all__ = [
    "Settings",
    "DependencyContainer",
    "init_container",
    "shutdown_container",
    "lifespan",
    "overrides",
    "get_container",
    "get_settings",
    "get_logger",
    "get_http",
    "get_cache",
    "get_db",
    "get_crypto",
    "get_tracer",
    "http_json",
    "cache_json_get",
    "cache_json_set",
    "DependencyError",
    "LazyImportError",
]
