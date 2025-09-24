# physical-integration-core/api/http/routers/v1/health.py
# Промышленный роутер здоровья: /v1/healthz, /v1/ready, /v1/startup
# Зависимости: fastapi, pydantic (в составе проекта). aiohttp не обязателен.

from __future__ import annotations

import asyncio
import os
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import aiohttp  # для HTTP-проверок, опционально
    _HAS_AIOHTTP = True
except Exception:  # pragma: no cover
    _HAS_AIOHTTP = False

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, BaseSettings, Field, validator

router = APIRouter(prefix="/v1", tags=["health"])

# ---------------------------------------------------------------------
# Конфигурация через переменные окружения
# ---------------------------------------------------------------------
class HealthSettings(BaseSettings):
    # Общие
    service_name: str = Field("physical-integration-core", env="APP_NAME")
    version: str = Field(os.getenv("APP_VERSION", "0.0.0"))
    git_commit: str = Field(os.getenv("GIT_COMMIT", "unknown"))
    build_date: str = Field(os.getenv("BUILD_DATE", "unknown"))
    environment: str = Field(os.getenv("ENV", "prod"))
    region: Optional[str] = Field(default=os.getenv("REGION"))
    # Тайминги
    default_timeout_sec: float = Field(1.5, env="HEALTH_TIMEOUT_SEC")
    http_timeout_sec: float = Field(2.0, env="HEALTH_HTTP_TIMEOUT_SEC")
    cache_ttl_sec: float = Field(2.0, env="HEALTH_CACHE_TTL_SEC")
    startup_grace_sec: float = Field(10.0, env="HEALTH_STARTUP_GRACE_SEC")

    # Проверки readiness (всё опционально)
    postgres_addr: Optional[str] = Field(default=os.getenv("PG_ADDR"))   # host:port
    redis_addr: Optional[str] = Field(default=os.getenv("REDIS_ADDR"))   # host:port
    kafka_brokers: Optional[str] = Field(default=os.getenv("KAFKA_BROKERS"))  # host1:port1,host2:port2
    s3_http_endpoint: Optional[str] = Field(default=os.getenv("S3_HEALTH_ENDPOINT"))  # https://s3.amazonaws.com or minio endpoint
    # Проверка диска (свободное место)
    disk_path: str = Field("/tmp", env="HEALTH_DISK_PATH")
    disk_min_free_mb: int = Field(128, env="HEALTH_DISK_MIN_FREE_MB")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    @validator("kafka_brokers")
    def normalize_brokers(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return v
        return ",".join([b.strip() for b in v.split(",") if b.strip()])


SETTINGS = HealthSettings()

# ---------------------------------------------------------------------
# Модели ответа
# ---------------------------------------------------------------------
class ComponentStatus(str):
    UP = "UP"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


class ComponentReport(BaseModel):
    name: str
    status: ComponentStatus
    details: Optional[Dict[str, Any]] = None
    latency_ms: Optional[int] = None


class HealthReport(BaseModel):
    status: ComponentStatus
    service: str
    version: str
    gitCommit: str
    buildDate: str
    environment: str
    region: Optional[str] = None
    uptimeSec: int
    components: List[ComponentReport] = Field(default_factory=list)


# ---------------------------------------------------------------------
# Вспомогательные утилиты
# ---------------------------------------------------------------------
_START_TS = time.monotonic()
_CACHE: Dict[str, Tuple[float, HealthReport]] = {}  # key -> (expire_ts, report)


def _uptime_sec() -> int:
    return int(time.monotonic() - _START_TS)


async def _check_tcp(host: str, port: int, timeout: float) -> Tuple[ComponentStatus, Dict[str, Any], float]:
    start = time.perf_counter()
    try:
        fut = asyncio.open_connection(host=host, port=port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        latency = (time.perf_counter() - start) * 1000
        return ComponentStatus.UP, {"endpoint": f"{host}:{port}"}, latency
    except (asyncio.TimeoutError, OSError, socket.gaierror) as e:
        latency = (time.perf_counter() - start) * 1000
        return ComponentStatus.DOWN, {"endpoint": f"{host}:{port}", "error": str(e)}, latency


async def _check_http(url: str, timeout: float) -> Tuple[ComponentStatus, Dict[str, Any], float]:
    start = time.perf_counter()
    if not _HAS_AIOHTTP:
        # Если aiohttp нет, возвращаем UNKNOWN, но не ломаем readiness
        latency = (time.perf_counter() - start) * 1000
        return ComponentStatus.UNKNOWN, {"endpoint": url, "warning": "aiohttp not installed"}, latency
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout) as resp:
                ok = 200 <= resp.status < 300
                latency = (time.perf_counter() - start) * 1000
                if ok:
                    return ComponentStatus.UP, {"endpoint": url, "code": resp.status}, latency
                # 5xx — DOWN, остальное — DEGRADED
                status_cat = ComponentStatus.DOWN if resp.status >= 500 else ComponentStatus.DEGRADED
                return status_cat, {"endpoint": url, "code": resp.status}, latency
    except (asyncio.TimeoutError, Exception) as e:
        latency = (time.perf_counter() - start) * 1000
        return ComponentStatus.DOWN, {"endpoint": url, "error": str(e)}, latency


def _check_disk(path: str, min_free_mb: int) -> Tuple[ComponentStatus, Dict[str, Any], float]:
    start = time.perf_counter()
    try:
        st = os.statvfs(path)
        free_mb = int(st.f_bavail * st.f_frsize / 1024 / 1024)
        latency = (time.perf_counter() - start) * 1000
        if free_mb < min_free_mb:
            return ComponentStatus.DEGRADED, {"path": path, "freeMB": free_mb, "minFreeMB": min_free_mb}, latency
        return ComponentStatus.UP, {"path": path, "freeMB": free_mb}, latency
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return ComponentStatus.DOWN, {"path": path, "error": str(e)}, latency


def _aggregate_status(components: List[ComponentReport]) -> ComponentStatus:
    # Приоритет: DOWN > DEGRADED > UP; UNKNOWN игнорируем, если есть другие
    has_down = any(c.status == ComponentStatus.DOWN for c in components)
    if has_down:
        return ComponentStatus.DOWN
    has_degraded = any(c.status == ComponentStatus.DEGRADED for c in components)
    if has_degraded:
        return ComponentStatus.DEGRADED
    has_up = any(c.status == ComponentStatus.UP for c in components)
    return ComponentStatus.UP if has_up else ComponentStatus.UNKNOWN


def _build_report(components: List[ComponentReport]) -> HealthReport:
    return HealthReport(
        status=_aggregate_status(components),
        service=SETTINGS.service_name,
        version=SETTINGS.version,
        gitCommit=SETTINGS.git_commit,
        buildDate=SETTINGS.build_date,
        environment=SETTINGS.environment,
        region=SETTINGS.region,
        uptimeSec=_uptime_sec(),
        components=components,
    )


def _cache_get(key: str) -> Optional[HealthReport]:
    now = time.monotonic()
    data = _CACHE.get(key)
    if not data:
        return None
    exp, report = data
    if now > exp:
        _CACHE.pop(key, None)
        return None
    return report


def _cache_put(key: str, report: HealthReport) -> None:
    _CACHE[key] = (time.monotonic() + SETTINGS.cache_ttl_sec, report)


# ---------------------------------------------------------------------
# Конкретные наборы проверок
# ---------------------------------------------------------------------
async def _liveness_checks() -> List[ComponentReport]:
    # Минимальные внутренние проверки: время аптайма и доступность диска
    disk_status, disk_details, disk_latency = _check_disk(SETTINGS.disk_path, SETTINGS.disk_min_free_mb)
    return [
        ComponentReport(name="process", status=ComponentStatus.UP, details={"uptimeSec": _uptime_sec()}),
        ComponentReport(name="disk", status=disk_status, details=disk_details, latency_ms=int(disk_latency)),
    ]


async def _readiness_checks() -> List[ComponentReport]:
    checks: List[ComponentReport] = []

    # Диск — обязательный для нормальной работы
    disk_status, disk_details, disk_latency = _check_disk(SETTINGS.disk_path, SETTINGS.disk_min_free_mb)
    checks.append(ComponentReport(name="disk", status=disk_status, details=disk_details, latency_ms=int(disk_latency)))

    timeout_tcp = SETTINGS.default_timeout_sec
    tasks: List[asyncio.Task] = []
    mapping: List[Tuple[str, str, Tuple[Any, ...]]] = []

    # PostgreSQL
    if SETTINGS.postgres_addr:
        host, port = _split_host_port(SETTINGS.postgres_addr)
        mapping.append(("postgres", "tcp", (host, port, timeout_tcp)))

    # Redis
    if SETTINGS.redis_addr:
        host, port = _split_host_port(SETTINGS.redis_addr)
        mapping.append(("redis", "tcp", (host, port, timeout_tcp)))

    # Kafka (несколько брокеров)
    if SETTINGS.kafka_brokers:
        for idx, broker in enumerate(SETTINGS.kafka_brokers.split(",")):
            host, port = _split_host_port(broker)
            mapping.append((f"kafka-{idx}", "tcp", (host, port, timeout_tcp)))

    # S3/MinIO HTTP health (HEAD/GET /)
    if SETTINGS.s3_http_endpoint:
        mapping.append(("object-storage", "http", (SETTINGS.s3_http_endpoint, SETTINGS.http_timeout_sec)))

    # Асинхронно запускаем проверки
    for name, kind, params in mapping:
        if kind == "tcp":
            host, port, tmo = params  # type: ignore
            tasks.append(asyncio.create_task(_check_tcp(host, port, tmo)))
        elif kind == "http":
            url, tmo = params  # type: ignore
            tasks.append(asyncio.create_task(_check_http(url, tmo)))

    # Собираем результаты
    for i, task in enumerate(tasks):
        name, kind, _ = mapping[i]
        status_, details, latency = await task
        checks.append(ComponentReport(name=name, status=status_, details=details, latency_ms=int(latency)))

    return checks


def _split_host_port(addr: str) -> Tuple[str, int]:
    if ":" not in addr:
        raise ValueError(f"Invalid host:port '{addr}'")
    host, port_s = addr.rsplit(":", 1)
    return host.strip(), int(port_s.strip())


# ---------------------------------------------------------------------
# Эндпоинты
# ---------------------------------------------------------------------
@router.get("/healthz", response_model=HealthReport, summary="Liveness probe")
async def healthz(response: Response) -> HealthReport:
    """
    Liveness: проверка жизнеспособности процесса.
    Возвращает 200 при статусе UP/DEGRADED, 500 при DOWN.
    """
    cache_key = "healthz"
    cached = _cache_get(cache_key)
    if cached:
        response.status_code = status.HTTP_200_OK if cached.status != ComponentStatus.DOWN else status.HTTP_500_INTERNAL_SERVER_ERROR
        return cached

    comps = await _liveness_checks()
    report = _build_report(comps)
    _cache_put(cache_key, report)
    response.status_code = status.HTTP_200_OK if report.status != ComponentStatus.DOWN else status.HTTP_500_INTERNAL_SERVER_ERROR
    return report


@router.get("/ready", response_model=HealthReport, summary="Readiness probe")
async def ready(response: Response) -> HealthReport:
    """
    Readiness: готовность принимать трафик.
    Возвращает 200 при статусе UP, 503 при DEGRADED/DOWN (консервативно).
    """
    cache_key = "ready"
    cached = _cache_get(cache_key)
    if cached:
        response.status_code = status.HTTP_200_OK if cached.status == ComponentStatus.UP else status.HTTP_503_SERVICE_UNAVAILABLE
        return cached

    comps = await _readiness_checks()
    report = _build_report(comps)
    _cache_put(cache_key, report)
    response.status_code = status.HTTP_200_OK if report.status == ComponentStatus.UP else status.HTTP_503_SERVICE_UNAVAILABLE
    return report


@router.get("/startup", response_model=HealthReport, summary="Startup probe")
async def startup(response: Response) -> HealthReport:
    """
    Startup: успешно ли сервис стартовал и прошёл первичную проверку.
    До истечения grace-периода возвращает 503, чтобы дать время прогреться.
    """
    # Грейс-период
    if (_uptime_sec() < SETTINGS.startup_grace_sec):
        comps = [ComponentReport(name="startup", status=ComponentStatus.DEGRADED, details={"graceSec": SETTINGS.startup_grace_sec})]
        report = _build_report(comps)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return report

    cache_key = "startup"
    cached = _cache_get(cache_key)
    if cached:
        response.status_code = status.HTTP_200_OK if cached.status == ComponentStatus.UP else status.HTTP_503_SERVICE_UNAVAILABLE
        return cached

    # Для startup используем тот же набор, что и readiness
    comps = await _readiness_checks()
    report = _build_report(comps)
    _cache_put(cache_key, report)
    response.status_code = status.HTTP_200_OK if report.status == ComponentStatus.UP else status.HTTP_503_SERVICE_UNAVAILABLE
    return report
