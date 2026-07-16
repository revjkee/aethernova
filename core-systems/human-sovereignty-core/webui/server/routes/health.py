# human-sovereignty-core/webui/server/routes/health.py
from __future__ import annotations

import asyncio
import os
import platform
import shutil
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return v.strip() if isinstance(v, str) and v.strip() else default


class CheckStatus(str):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


class HealthStatus(str):
    OK = "ok"
    DEGRADED = "degraded"
    FAIL = "fail"


class HealthCheckResult(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    status: str = Field(..., min_length=1, max_length=16)
    latency_ms: int = Field(..., ge=0)
    message: str = Field(default="", max_length=1024)
    details: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str = Field(..., min_length=1, max_length=16)
    time_utc: str = Field(..., min_length=1, max_length=64)
    service: str = Field(..., min_length=1, max_length=128)
    version: str = Field(..., min_length=1, max_length=64)
    build: Dict[str, Any] = Field(default_factory=dict)
    checks: List[HealthCheckResult] = Field(default_factory=list)
    latency_ms: int = Field(..., ge=0)


CheckFn = Callable[[], Awaitable[HealthCheckResult]]


@dataclass(frozen=True)
class BuildInfo:
    service: str
    version: str
    commit: str
    build_time_utc: str
    environment: str
    instance_id: str

    @staticmethod
    def from_env() -> "BuildInfo":
        return BuildInfo(
            service=_env("SERVICE_NAME", "human-sovereignty-webui"),
            version=_env("SERVICE_VERSION", _env("APP_VERSION", "0.0.0")),
            commit=_env("GIT_COMMIT", _env("COMMIT_SHA", "")),
            build_time_utc=_env("BUILD_TIME_UTC", ""),
            environment=_env("ENVIRONMENT", _env("APP_ENV", "unknown")),
            instance_id=_env("INSTANCE_ID", _env("HOSTNAME", "unknown")),
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "commit": self.commit,
            "build_time_utc": self.build_time_utc,
            "environment": self.environment,
            "instance_id": self.instance_id,
            "runtime": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
        }


class HealthRegistry:
    """
    Реестр проверок готовности.
    - Liveness: минимальные проверки (процесс жив, event loop работает)
    - Readiness: зависимости и критичные ресурсы
    """

    def __init__(
        self,
        *,
        build: Optional[BuildInfo] = None,
        readiness_timeout_seconds: float = 2.5,
        liveness_timeout_seconds: float = 1.0,
    ) -> None:
        self.build = build or BuildInfo.from_env()
        self.readiness_timeout_seconds = float(readiness_timeout_seconds)
        self.liveness_timeout_seconds = float(liveness_timeout_seconds)

        self._liveness_checks: List[CheckFn] = []
        self._readiness_checks: List[CheckFn] = []

        # Канонический минимум
        self.add_liveness_check(self._check_event_loop)
        self.add_readiness_check(self._check_disk_free_minimum)

    def add_liveness_check(self, fn: CheckFn) -> None:
        self._liveness_checks.append(fn)

    def add_readiness_check(self, fn: CheckFn) -> None:
        self._readiness_checks.append(fn)

    async def run_liveness(self) -> HealthResponse:
        return await self._run(
            checks=self._liveness_checks,
            timeout_seconds=self.liveness_timeout_seconds,
            mode="liveness",
        )

    async def run_readiness(self) -> HealthResponse:
        return await self._run(
            checks=self._readiness_checks,
            timeout_seconds=self.readiness_timeout_seconds,
            mode="readiness",
        )

    async def _run(self, *, checks: Sequence[CheckFn], timeout_seconds: float, mode: str) -> HealthResponse:
        started = time.time()
        results: List[HealthCheckResult] = []

        # Запускаем проверки последовательно, чтобы:
        # - не создавать лавину подключений
        # - сохранить детерминированность
        overall = HealthStatus.OK

        for fn in checks:
            try:
                r = await asyncio.wait_for(fn(), timeout=timeout_seconds)
            except asyncio.TimeoutError:
                r = HealthCheckResult(
                    name=getattr(fn, "__name__", "check"),
                    status=CheckStatus.FAIL,
                    latency_ms=int(timeout_seconds * 1000),
                    message=f"{mode}_check_timeout",
                    details={},
                )
            except Exception as e:
                r = HealthCheckResult(
                    name=getattr(fn, "__name__", "check"),
                    status=CheckStatus.FAIL,
                    latency_ms=0,
                    message="check_exception",
                    details={"error": str(e)[:512]},
                )

            results.append(r)

            if r.status == CheckStatus.FAIL:
                overall = HealthStatus.FAIL
            elif r.status == CheckStatus.WARN and overall != HealthStatus.FAIL:
                overall = HealthStatus.DEGRADED

        total_ms = int((time.time() - started) * 1000)

        return HealthResponse(
            status=overall,
            time_utc=_utcnow_iso(),
            service=self.build.service,
            version=self.build.version,
            build=self.build.as_dict(),
            checks=results,
            latency_ms=total_ms,
        )

    async def _check_event_loop(self) -> HealthCheckResult:
        started = time.time()
        await asyncio.sleep(0)
        return HealthCheckResult(
            name="event_loop",
            status=CheckStatus.PASS,
            latency_ms=int((time.time() - started) * 1000),
            message="",
            details={},
        )

    async def _check_disk_free_minimum(self) -> HealthCheckResult:
        """
        Минимальная проверка ресурса без внешних зависимостей.
        Порог задаётся env: HS_DISK_MIN_FREE_MB (default 256MB).
        Путь env: HS_DISK_PATH (default current working dir).
        """
        started = time.time()
        path = _env("HS_DISK_PATH", os.getcwd())
        min_free_mb_str = _env("HS_DISK_MIN_FREE_MB", "256")

        try:
            min_free_mb = int(min_free_mb_str)
        except Exception:
            min_free_mb = 256

        try:
            usage = shutil.disk_usage(path)
            free_mb = int(usage.free / (1024 * 1024))
        except Exception as e:
            return HealthCheckResult(
                name="disk_free",
                status=CheckStatus.FAIL,
                latency_ms=int((time.time() - started) * 1000),
                message="disk_usage_failed",
                details={"path": path, "error": str(e)[:256]},
            )

        if free_mb < min_free_mb:
            return HealthCheckResult(
                name="disk_free",
                status=CheckStatus.WARN,
                latency_ms=int((time.time() - started) * 1000),
                message="disk_free_low",
                details={"path": path, "free_mb": free_mb, "min_free_mb": min_free_mb},
            )

        return HealthCheckResult(
            name="disk_free",
            status=CheckStatus.PASS,
            latency_ms=int((time.time() - started) * 1000),
            message="",
            details={"path": path, "free_mb": free_mb, "min_free_mb": min_free_mb},
        )


async def tcp_check(
    *,
    name: str,
    host: str,
    port: int,
    timeout_seconds: float = 1.0,
    warn_only: bool = False,
) -> HealthCheckResult:
    started = time.time()
    status_ok = CheckStatus.PASS
    status_bad = CheckStatus.WARN if warn_only else CheckStatus.FAIL

    try:
        loop = asyncio.get_running_loop()
        fut = loop.run_in_executor(None, _tcp_connect_blocking, host, port, timeout_seconds)
        await asyncio.wait_for(fut, timeout=timeout_seconds + 0.25)
        return HealthCheckResult(
            name=name,
            status=status_ok,
            latency_ms=int((time.time() - started) * 1000),
            message="",
            details={"host": host, "port": port},
        )
    except Exception as e:
        return HealthCheckResult(
            name=name,
            status=status_bad,
            latency_ms=int((time.time() - started) * 1000),
            message="tcp_unreachable",
            details={"host": host, "port": port, "error": str(e)[:256]},
        )


def _tcp_connect_blocking(host: str, port: int, timeout_seconds: float) -> None:
    with socket.create_connection((host, port), timeout=timeout_seconds):
        return


async def dns_check(
    *,
    name: str,
    hostname: str,
    timeout_seconds: float = 1.0,
    warn_only: bool = True,
) -> HealthCheckResult:
    started = time.time()
    status_ok = CheckStatus.PASS
    status_bad = CheckStatus.WARN if warn_only else CheckStatus.FAIL

    try:
        loop = asyncio.get_running_loop()
        fut = loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
        await asyncio.wait_for(fut, timeout=timeout_seconds)
        return HealthCheckResult(
            name=name,
            status=status_ok,
            latency_ms=int((time.time() - started) * 1000),
            message="",
            details={"hostname": hostname},
        )
    except Exception as e:
        return HealthCheckResult(
            name=name,
            status=status_bad,
            latency_ms=int((time.time() - started) * 1000),
            message="dns_failed",
            details={"hostname": hostname, "error": str(e)[:256]},
        )


def make_registry() -> HealthRegistry:
    """
    Фабрика, чтобы приложение могло централизованно регистрировать проверки.
    Опциональные зависимости подключаются только при наличии env.
    """
    reg = HealthRegistry(
        build=BuildInfo.from_env(),
        readiness_timeout_seconds=float(_env("HS_READINESS_TIMEOUT", "2.5")),
        liveness_timeout_seconds=float(_env("HS_LIVENESS_TIMEOUT", "1.0")),
    )

    # Опционально: внешний DNS (для диагностик среды)
    dns_host = _env("HS_DNS_CHECK_HOST", "")
    if dns_host:
        reg.add_readiness_check(lambda: dns_check(name="dns", hostname=dns_host))

    # Опционально: TCP dependency checks (без библиотек)
    # Формат: HS_TCP_CHECKS="redis:127.0.0.1:6379,db:127.0.0.1:5432"
    tcp_checks = _env("HS_TCP_CHECKS", "")
    if tcp_checks:
        for item in [x.strip() for x in tcp_checks.split(",") if x.strip()]:
            try:
                n, h, p = item.split(":")
                port = int(p)
            except Exception:
                continue

            reg.add_readiness_check(lambda n=n, h=h, port=port: tcp_check(name=n, host=h, port=port))

    return reg


router = APIRouter(tags=["health"])
_registry = make_registry()


def _http_code_from_status(s: str) -> int:
    if s == HealthStatus.OK:
        return status.HTTP_200_OK
    if s == HealthStatus.DEGRADED:
        return status.HTTP_200_OK
    return status.HTTP_503_SERVICE_UNAVAILABLE


@router.get("/health", response_model=HealthResponse)
@router.get("/healthz", response_model=HealthResponse)
async def health() -> HealthResponse:
    """
    Совмещённый endpoint: readiness семантика.
    """
    resp = await _registry.run_readiness()
    return resp


@router.get("/livez", response_model=HealthResponse)
async def livez(response: Response) -> HealthResponse:
    resp = await _registry.run_liveness()
    response.status_code = _http_code_from_status(resp.status)
    return resp


@router.get("/readyz", response_model=HealthResponse)
async def readyz(response: Response) -> HealthResponse:
    resp = await _registry.run_readiness()
    response.status_code = _http_code_from_status(resp.status)
    return resp


@router.get("/version", response_model=Dict[str, Any])
async def version() -> Dict[str, Any]:
    """
    Отдельный endpoint для build info без тяжёлых checks.
    """
    b = _registry.build
    return {
        "service": b.service,
        "version": b.version,
        "build": b.as_dict(),
        "time_utc": _utcnow_iso(),
    }
