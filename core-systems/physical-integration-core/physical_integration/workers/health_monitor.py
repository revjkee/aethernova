# physical_integration/workers/health_monitor.py
from __future__ import annotations

import asyncio
import enum
import logging
import random
import shutil
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Dict,
    List,
    Optional,
    Protocol,
    Tuple,
    Union,
    Iterable,
    Callable,
)

__all__ = [
    "HealthStatus",
    "Severity",
    "HealthResult",
    "HealthCheck",
    "HealthMonitorConfig",
    "HealthMonitor",
    # Built-in checks
    "TCPPortCheck",
    "HTTPCheck",
    "DiskSpaceCheck",
    "FileExistsCheck",
    "KafkaCheck",
]

# -------------------------
# Protocols (metrics, kafka)
# -------------------------

class MetricsSink(Protocol):
    def incr(self, name: str, value: int = 1, **tags: Any) -> None: ...
    def gauge(self, name: str, value: float, **tags: Any) -> None: ...
    def timing(self, name: str, value_ms: float, **tags: Any) -> None: ...

class KafkaProducerLike(Protocol):
    async def send(
        self,
        topic: str,
        value: Union[bytes, str, Dict[str, Any], List[Any], None],
        *,
        key: Optional[Union[bytes, str]] = None,
        headers: Optional[Dict[str, Union[str, bytes]]] = None,
        partition: Optional[int] = None,
        timestamp_ms: Optional[int] = None,
        ensure_started: bool = True,
    ) -> None: ...

# -------------------------
# Model
# -------------------------

class HealthStatus(str, enum.Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

class Severity(str, enum.Enum):
    INFO = "info"
    MINOR = "minor"
    MAJOR = "major"
    CRITICAL = "critical"

@dataclass(frozen=True)
class HealthResult:
    name: str
    status: HealthStatus
    severity: Severity
    latency_ms: float
    ts_unix: float
    error: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

# -------------------------
# HealthCheck interface
# -------------------------

class HealthCheck(Protocol):
    name: str
    severity: Severity
    interval_s: float
    timeout_s: float

    async def probe(self) -> HealthResult: ...

# -------------------------
# Config
# -------------------------

@dataclass
class HealthMonitorConfig:
    interval_jitter_s: float = 0.2
    max_concurrency: int = 16
    backoff_base_s: float = 0.5
    backoff_max_s: float = 30.0
    publish_every_n_cycles: int = 10  # принудительная публикация даже без изменений
    overall_degraded_if_any_major_fail: bool = True
    overall_unhealthy_if_any_critical_fail: bool = True
    history_window: int = 50  # глубина истории на чек
    kafka_topic: Optional[str] = None  # если задано — публикуем события
    log_level: int = logging.INFO

# -------------------------
# Util
# -------------------------

def _now() -> float:
    return time.time()

def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

def _json_safe(v: Any) -> Any:
    try:
        import json  # stdlib
        json.dumps(v)
        return v
    except Exception:
        return str(v)

# -------------------------
# HealthMonitor
# -------------------------

class HealthMonitor:
    """
    Асинхронный промышленный монитор здоровья компонентов.
    Особенности:
    - Плагинные проверки с независимым расписанием и таймаутами.
    - Экспоненциальный backoff при сбоях каждой проверки.
    - Параллелизм с ограничением по семафору.
    - Агрегация статуса: healthy/degraded/unhealthy согласно политике.
    - История результатов и снимок текущего состояния.
    - Метрики (необязательные) и опциональная публикация событий в Kafka.
    - Корректный graceful-shutdown.
    """

    def __init__(
        self,
        checks: Iterable[HealthCheck],
        *,
        config: Optional[HealthMonitorConfig] = None,
        metrics: Optional[MetricsSink] = None,
        kafka_producer: Optional[KafkaProducerLike] = None,
        logger: Optional[logging.Logger] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.cfg = config or HealthMonitorConfig()
        self.loop = loop or asyncio.get_event_loop()
        self.log = logger or logging.getLogger(__name__)
        self.log.setLevel(self.cfg.log_level)
        self.metrics = metrics
        self.kafka = kafka_producer

        self._checks: List[HealthCheck] = list(checks)
        self._stop = asyncio.Event()
        self._sema = asyncio.Semaphore(self.cfg.max_concurrency)
        self._tasks: List[asyncio.Task] = []
        self._history: Dict[str, List[HealthResult]] = {}
        self._next_run_at: Dict[str, float] = {}
        self._fail_streak: Dict[str, int] = {}
        self._snapshot: Dict[str, HealthResult] = {}
        self._overall: HealthStatus = HealthStatus.UNKNOWN
        self._cycle: int = 0
        self._last_published_overall: Optional[HealthStatus] = None

        # init schedules
        now = _now()
        for chk in self._checks:
            self._next_run_at[chk.name] = now + random.uniform(0.0, self.cfg.interval_jitter_s)
            self._history[chk.name] = []

    # ---- Public API

    def get_overall_status(self) -> HealthStatus:
        return self._overall

    def get_snapshot(self) -> Dict[str, HealthResult]:
        return dict(self._snapshot)

    def get_history(self, name: str) -> List[HealthResult]:
        return list(self._history.get(name, []))

    async def start(self) -> None:
        self.log.info("HealthMonitor starting with %d checks", len(self._checks))
        self._stop.clear()
        self._tasks.append(self.loop.create_task(self._scheduler_loop()))
        self._tasks.append(self.loop.create_task(self._aggregation_loop()))

    async def stop(self) -> None:
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self.log.info("HealthMonitor stopped")

    # ---- Internal loops

    async def _scheduler_loop(self) -> None:
        try:
            while not self._stop.is_set():
                now = _now()
                due_checks = [c for c in self._checks if self._next_run_at.get(c.name, 0) <= now]
                if not due_checks:
                    await asyncio.sleep(0.05)
                    continue

                # запускаем просроченные чеки, не превосходя семафор
                run_tasks: List[Awaitable[Any]] = []
                for chk in due_checks:
                    run_tasks.append(self._run_check(chk))

                await asyncio.gather(*run_tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._metric_incr("health.scheduler.error")
            self.log.exception("Scheduler loop error: %s", e)
        finally:
            self.log.debug("Scheduler loop exited")

    async def _aggregation_loop(self) -> None:
        try:
            while not self._stop.is_set():
                await asyncio.sleep(0.5)
                self._cycle += 1
                self._recompute_overall()
                await self._maybe_publish()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._metric_incr("health.aggregation.error")
            self.log.exception("Aggregation loop error: %s", e)
        finally:
            await self._maybe_publish(force=True)
            self.log.debug("Aggregation loop exited")

    # ---- Execution

    async def _run_check(self, chk: HealthCheck) -> None:
        async with self._sema:
            start = time.perf_counter()
            name = chk.name
            try:
                res: HealthResult = await asyncio.wait_for(chk.probe(), timeout=chk.timeout_s)
                self._record_result(res)
                self._schedule_next(name, success=True)
                self._metric_incr("health.check.ok", tags={"check": name, "status": res.status.value})
                self._metric_timing("health.check.latency_ms", (time.perf_counter() - start) * 1000.0, tags={"check": name})
            except asyncio.TimeoutError:
                res = HealthResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    severity=chk.severity,
                    latency_ms=(time.perf_counter() - start) * 1000.0,
                    ts_unix=_now(),
                    error=f"timeout>{chk.timeout_s}s",
                    meta={},
                )
                self._record_result(res)
                self._schedule_next(name, success=False)
                self._metric_incr("health.check.timeout", tags={"check": name})
            except Exception as e:
                res = HealthResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    severity=chk.severity,
                    latency_ms=(time.perf_counter() - start) * 1000.0,
                    ts_unix=_now(),
                    error=repr(e),
                    meta={},
                )
                self._record_result(res)
                self._schedule_next(name, success=False)
                self._metric_incr("health.check.error", tags={"check": name})
                self.log.warning("Check '%s' failed: %s", name, res.error)

    def _record_result(self, res: HealthResult) -> None:
        # обновить снапшот
        self._snapshot[res.name] = res
        # история с ограничением окна
        hist = self._history.get(res.name)
        if hist is None:
            hist = []
            self._history[res.name] = hist
        hist.append(res)
        if len(hist) > self.cfg.history_window:
            del hist[: len(hist) - self.cfg.history_window]

    def _schedule_next(self, name: str, *, success: bool) -> None:
        fail_n = self._fail_streak.get(name, 0)
        if success:
            self._fail_streak[name] = 0
            delay = self._base_interval(name)
        else:
            fail_n += 1
            self._fail_streak[name] = fail_n
            backoff = self.cfg.backoff_base_s * (2 ** (fail_n - 1))
            delay = _clamp(backoff, self.cfg.backoff_base_s, self.cfg.backoff_max_s)
        # добавить джиттер
        delay += random.uniform(0.0, self.cfg.interval_jitter_s)
        self._next_run_at[name] = _now() + delay

    def _base_interval(self, name: str) -> float:
        chk = next((c for c in self._checks if c.name == name), None)
        return getattr(chk, "interval_s", 5.0) if chk else 5.0

    # ---- Aggregation & publishing

    def _recompute_overall(self) -> None:
        # политика: если хоть один CRITICAL = UNHEALTHY -> overall UNHEALTHY
        # если есть MAJOR = UNHEALTHY -> overall DEGRADED (или UNHEALTHY, если включено)
        # иначе если есть MINOR=UNHEALTHY -> DEGRADED, при INFO сбоях — DEGRADED, но не UNHEALTHY
        status = HealthStatus.HEALTHY
        for res in self._snapshot.values():
            if res.status == HealthStatus.UNHEALTHY:
                if res.severity == Severity.CRITICAL and self.cfg.overall_unhealthy_if_any_critical_fail:
                    status = HealthStatus.UNHEALTHY
                    break
                elif res.severity == Severity.MAJOR and self.cfg.overall_degraded_if_any_major_fail:
                    status = HealthStatus.DEGRADED
                elif res.severity in (Severity.MINOR, Severity.INFO) and status != HealthStatus.DEGRADED:
                    status = HealthStatus.DEGRADED

        if not self._snapshot:
            status = HealthStatus.UNKNOWN

        self._overall = status
        self._metric_gauge("health.overall.code", {HealthStatus.HEALTHY: 0, HealthStatus.DEGRADED: 1,
                                                   HealthStatus.UNHEALTHY: 2, HealthStatus.UNKNOWN: -1}[status])

    async def _maybe_publish(self, *, force: bool = False) -> None:
        # Публикуем в Kafka при изменении overall или каждые N циклов
        if not self.kafka or not self.cfg.kafka_topic:
            return
        changed = self._last_published_overall != self._overall
        periodic = (self._cycle % max(1, self.cfg.publish_every_n_cycles) == 0)
        if not (changed or periodic or force):
            return

        payload = {
            "ts_unix": _now(),
            "overall": self._overall.value,
            "checks": {
                name: {
                    "status": res.status.value,
                    "severity": res.severity.value,
                    "latency_ms": round(res.latency_ms, 3),
                    "ts_unix": res.ts_unix,
                    "error": res.error,
                    "meta": {k: _json_safe(v) for k, v in (res.meta or {}).items()},
                }
                for name, res in self._snapshot.items()
            },
        }
        try:
            await self.kafka.send(self.cfg.kafka_topic, payload, key="health.monitor")
            self._last_published_overall = self._overall
            self._metric_incr("health.publish.ok")
        except Exception as e:
            self._metric_incr("health.publish.error")
            self.log.warning("Failed to publish health to Kafka: %r", e)

    # ---- Metrics helpers

    def _metric_incr(self, name: str, value: int = 1, tags: Optional[Dict[str, Any]] = None) -> None:
        if not self.metrics:
            return
        try:
            self.metrics.incr(name, value, **(tags or {}))
        except Exception:
            pass

    def _metric_gauge(self, name: str, value: float, tags: Optional[Dict[str, Any]] = None) -> None:
        if not self.metrics:
            return
        try:
            self.metrics.gauge(name, value, **(tags or {}))
        except Exception:
            pass

    def _metric_timing(self, name: str, value_ms: float, tags: Optional[Dict[str, Any]] = None) -> None:
        if not self.metrics:
            return
        try:
            self.metrics.timing(name, value_ms, **(tags or {}))
        except Exception:
            pass

# -------------------------
# Built-in checks
# -------------------------

@dataclass
class _BaseCheck:
    name: str
    severity: Severity = Severity.MAJOR
    interval_s: float = 5.0
    timeout_s: float = 2.0

    async def probe(self) -> HealthResult:  # type: ignore[override]
        start = time.perf_counter()
        try:
            status, meta = await self._do()
            return HealthResult(
                name=self.name,
                status=status,
                severity=self.severity,
                latency_ms=(time.perf_counter() - start) * 1000.0,
                ts_unix=_now(),
                error=None if status == HealthStatus.HEALTHY else meta.get("error"),
                meta=meta,
            )
        except Exception as e:
            return HealthResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                severity=self.severity,
                latency_ms=(time.perf_counter() - start) * 1000.0,
                ts_unix=_now(),
                error=repr(e),
                meta={},
            )

    async def _do(self) -> Tuple[HealthStatus, Dict[str, Any]]:
        raise NotImplementedError

class TCPPortCheck(_BaseCheck):
    host: str = ""
    port: int = 0
    use_ssl: bool = False

    def __init__(
        self,
        name: str,
        host: str,
        port: int,
        *,
        severity: Severity = Severity.MAJOR,
        interval_s: float = 5.0,
        timeout_s: float = 1.0,
        use_ssl: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        super().__init__(name=name, severity=severity, interval_s=interval_s, timeout_s=timeout_s)
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self._ssl_context = ssl_context

    async def _do(self) -> Tuple[HealthStatus, Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        start = time.perf_counter()
        try:
            if self.use_ssl:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port, ssl=self._ssl_context),
                    timeout=self.timeout_s,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port),
                    timeout=self.timeout_s,
                )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return HealthStatus.HEALTHY, {
                "host": self.host,
                "port": self.port,
                "rtt_ms": round((time.perf_counter() - start) * 1000.0, 3),
            }
        except Exception as e:
            return HealthStatus.UNHEALTHY, {"host": self.host, "port": self.port, "error": repr(e)}

class HTTPCheck(_BaseCheck):
    host: str = ""
    port: int = 80
    path: str = "/"
    use_ssl: bool = False
    expected_codes: Tuple[int, ...] = (200, 204, 301, 302)

    def __init__(
        self,
        name: str,
        host: str,
        *,
        port: int = 80,
        path: str = "/",
        use_ssl: bool = False,
        expected_codes: Tuple[int, ...] = (200, 204, 301, 302),
        severity: Severity = Severity.MAJOR,
        interval_s: float = 5.0,
        timeout_s: float = 2.0,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        super().__init__(name=name, severity=severity, interval_s=interval_s, timeout_s=timeout_s)
        self.host = host
        self.port = port
        self.path = path
        self.use_ssl = use_ssl
        self.expected_codes = expected_codes
        self._ssl_context = ssl_context

    async def _do(self) -> Tuple[HealthStatus, Dict[str, Any]]:
        # Минимальный HTTP/1.1 HEAD через сокет, без внешних зависимостей
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=self._ssl_context if self.use_ssl else None),
                timeout=self.timeout_s,
            )
            req = (
                f"HEAD {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Connection: close\r\n"
                f"User-Agent: physical-integration/health-monitor\r\n\r\n"
            )
            writer.write(req.encode("ascii"))
            await writer.drain()
            # читаем статус‑строку
            status_line = await asyncio.wait_for(reader.readline(), timeout=self.timeout_s)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            parts = status_line.decode("ascii", "replace").strip().split()
            code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            ok = code in self.expected_codes
            return (HealthStatus.HEALTHY if ok else HealthStatus.UNHEALTHY), {
                "code": code,
                "rtt_ms": round((time.perf_counter() - start) * 1000.0, 3),
            }
        except Exception as e:
            return HealthStatus.UNHEALTHY, {"error": repr(e)}

class DiskSpaceCheck(_BaseCheck):
    path: str = "/"
    min_free_bytes: int = 1_000_000_000  # 1GB по умолчанию

    def __init__(
        self,
        name: str,
        path: str = "/",
        *,
        min_free_bytes: int = 1_000_000_000,
        severity: Severity = Severity.MAJOR,
        interval_s: float = 15.0,
        timeout_s: float = 1.0,
    ) -> None:
        super().__init__(name=name, severity=severity, interval_s=interval_s, timeout_s=timeout_s)
        self.path = path
        self.min_free_bytes = int(min_free_bytes)

    async def _do(self) -> Tuple[HealthStatus, Dict[str, Any]]:
        usage = shutil.disk_usage(self.path)
        free_ok = usage.free >= self.min_free_bytes
        status = HealthStatus.HEALTHY if free_ok else HealthStatus.UNHEALTHY
        return status, {
            "total": int(usage.total),
            "used": int(usage.used),
            "free": int(usage.free),
            "min_free_required": self.min_free_bytes,
        }

class FileExistsCheck(_BaseCheck):
    filename: str = ""

    def __init__(
        self,
        name: str,
        filename: str,
        *,
        severity: Severity = Severity.MINOR,
        interval_s: float = 10.0,
        timeout_s: float = 0.5,
    ) -> None:
        super().__init__(name=name, severity=severity, interval_s=interval_s, timeout_s=timeout_s)
        self.filename = filename

    async def _do(self) -> Tuple[HealthStatus, Dict[str, Any]]:
        import os
        ok = os.path.exists(self.filename)
        return (HealthStatus.HEALTHY if ok else HealthStatus.UNHEALTHY), {"path": self.filename}

class KafkaCheck(_BaseCheck):
    """
    Обертка над Kafka‑адаптером проекта. Ожидается объект с методом:
        async def health_check(self, timeout_s: float = 5.0) -> Dict[str, Any]
    """
    def __init__(
        self,
        name: str,
        kafka_adapter: Any,
        *,
        severity: Severity = Severity.CRITICAL,
        interval_s: float = 5.0,
        timeout_s: float = 2.5,
    ) -> None:
        super().__init__(name=name, severity=severity, interval_s=interval_s, timeout_s=timeout_s)
        self._kafka = kafka_adapter

    async def _do(self) -> Tuple[HealthStatus, Dict[str, Any]]:
        status = await self._kafka.health_check(timeout_s=self.timeout_s)
        ok = bool(status.get("brokers_ok", False))
        # Дополнительно проверяем наличие producer/consumer, если используются
        producer_ok = bool(status.get("producer", False))
        consumer_ok = bool(status.get("consumer", True))  # consumer может быть необязателен
        overall_ok = ok and producer_ok
        meta = {
            "brokers_ok": ok,
            "producer": producer_ok,
            "consumer": consumer_ok,
        }
        return (HealthStatus.HEALTHY if overall_ok else HealthStatus.UNHEALTHY), meta

# -------------------------
# Пример инициализации (для справки внутри проекта)
# -------------------------
# Пример использования (не исполняется при импорте):
# async def main():
#     from physical_integration.adapters.kafka_adapter import KafkaAdapter, KafkaConfig
#
#     kafka = KafkaAdapter(KafkaConfig(bootstrap_servers="localhost:9092"))
#     await kafka.start_producer()
#
#     checks = [
#         KafkaCheck("kafka", kafka_adapter=kafka, severity=Severity.CRITICAL, interval_s=5.0, timeout_s=2.0),
#         TCPPortCheck("rtsp-gateway", host="127.0.0.1", port=8554, severity=Severity.MAJOR, interval_s=5.0),
#         HTTPCheck("ingress-http", host="example.com", port=80, path="/healthz", interval_s=5.0, timeout_s=1.0),
#         DiskSpaceCheck("disk-root", path="/", min_free_bytes=5_000_000_000, interval_s=30.0),
#     ]
#
#     monitor = HealthMonitor(
#         checks,
#         config=HealthMonitorConfig(kafka_topic="health.events", publish_every_n_cycles=20),
#         metrics=None,
#         kafka_producer=kafka,  # тот же адаптер умеет send
#     )
#     await monitor.start()
#     try:
#         await asyncio.sleep(3600)
#     finally:
#         await monitor.stop()
#         await kafka.close()
#
# if __name__ == "__main__":
#     asyncio.run(main())
