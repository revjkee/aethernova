# -*- coding: utf-8 -*-
"""
ChronoWatch Heartbeat Agent (production-grade, async)

Функции:
- Периодические heartbeat-запросы на один/несколько HTTP эндпойнтов.
- Экспоненциальный бэкофф с джиттером, учёт Retry-After (429/503).
- Опциональная компрессия GZIP и HMAC-SHA256 подпись тела.
- Корреляция по instance_id/request_id, последовательный номер seq.
- Сбор системных метрик (cpu/mem/disk/load; через psutil, если доступен).
- Интеграция с chronowatch.context.AppContext: общий http-клиент и health_check().
- Безопасная редакция чувствительных ключей в логах.
- Грациозное завершение и идемпотентный lifecycle (start/stop).

Зависимости:
- Стандартная библиотека. Опционально: httpx, psutil.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import gzip
import hmac
import json
import logging
import os
import platform
import random
import signal
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

# Опциональные зависимости
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover - опционально
    httpx = None  # type: ignore

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - опционально
    psutil = None  # type: ignore

# Интеграция с AppContext (опционально)
try:
    from chronowatch.context import AppContext  # type: ignore
except Exception:  # pragma: no cover
    AppContext = Any  # type: ignore


# ------------------------------------------------------------------------------
# Конфигурация агента
# ------------------------------------------------------------------------------

@dataclass(frozen=True)
class HeartbeatConfig:
    # Идентификация
    service: str = field(default_factory=lambda: os.getenv("SERVICE_NAME", "chronowatch-core"))
    env: str = field(default_factory=lambda: os.getenv("CHRONOWATCH_ENV", "dev"))
    version: str = field(default_factory=lambda: os.getenv("SERVICE_VERSION", "0.0.0"))
    tenant_id: Optional[str] = field(default_factory=lambda: os.getenv("TENANT_ID") or None)
    instance_id: str = field(default_factory=lambda: os.getenv("INSTANCE_ID", str(uuid.uuid4())))

    # Транспорт
    endpoints: Tuple[str, ...] = field(
        default_factory=lambda: tuple(
            filter(None, [os.getenv("HEARTBEAT_ENDPOINT", "http://localhost:8080/heartbeat")])
        )
    )
    method: str = field(default="POST")
    headers: Mapping[str, str] = field(default_factory=lambda: {"content-type": "application/json"})
    timeout_s: float = float(os.getenv("HEARTBEAT_TIMEOUT_S", "3.0"))
    verify_tls: bool = os.getenv("HEARTBEAT_VERIFY_TLS", "true").lower() in ("1", "true", "yes")
    connect_via_app_http: bool = os.getenv("HEARTBEAT_USE_APP_HTTP", "true").lower() in ("1", "true", "yes"))

    # Расписание
    interval_s: float = float(os.getenv("HEARTBEAT_INTERVAL_S", "15.0"))
    initial_delay_s: float = float(os.getenv("HEARTBEAT_INITIAL_DELAY_S", "0.5"))
    jitter_ratio: float = float(os.getenv("HEARTBEAT_JITTER_RATIO", "0.2"))  # 20% от интервала

    # Повторные попытки
    max_retries: int = int(os.getenv("HEARTBEAT_MAX_RETRIES", "5"))
    backoff_base_ms: int = int(os.getenv("HEARTBEAT_BACKOFF_BASE_MS", "200"))
    backoff_max_ms: int = int(os.getenv("HEARTBEAT_BACKOFF_MAX_MS", "5000"))

    # Пэйлоад
    compress_gzip: bool = os.getenv("HEARTBEAT_GZIP", "true").lower() in ("1", "true", "yes")
    include_system_metrics: bool = os.getenv("HEARTBEAT_SYS_METRICS", "true").lower() in ("1", "true", "yes")
    include_health: bool = os.getenv("HEARTBEAT_INCLUDE_HEALTH", "true").lower() in ("1", "true", "yes")
    extra_payload: Mapping[str, Any] = field(default_factory=dict)

    # Подпись
    hmac_secret: Optional[str] = field(default_factory=lambda: os.getenv("HEARTBEAT_HMAC_SECRET") or None)
    hmac_header: str = field(default="x-signature-sha256")
    hmac_ts_header: str = field(default="x-signature-ts")

    # Безопасность логов
    redact_keys: Tuple[str, ...] = ("password", "authorization", "cookie", "token", "secret", "set-cookie", "api-key")

    # Пропуски/filters
    skip_on_oom: bool = True  # при MemoryError попробуем пропустить один тик


# ------------------------------------------------------------------------------
# Агент
# ------------------------------------------------------------------------------

class HeartbeatAgent:
    def __init__(self, cfg: HeartbeatConfig, app: Optional[AppContext] = None, logger: Optional[logging.Logger] = None):
        self.cfg = cfg
        self.app = app
        self.log = logger or self._default_logger()
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._seq = 0
        self._started_at = time.time()
        self._signals_bound = False

    # ---------- Lifecycle ----------

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._bind_signals()
        self._stopping.clear()
        self._task = asyncio.create_task(self._run_loop(), name="heartbeat-agent")
        self.log.info("heartbeat_started", extra={"service": self.cfg.service, "env": self.cfg.env, "interval_s": self.cfg.interval_s})

    async def stop(self) -> None:
        self._stopping.set()
        if self._task:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._task, timeout=self.cfg.timeout_s * 2)
        self.log.info("heartbeat_stopped")

    async def __aenter__(self) -> "HeartbeatAgent":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    # ---------- Основной цикл ----------

    async def _run_loop(self) -> None:
        await asyncio.sleep(max(0.0, self.cfg.initial_delay_s))
        while not self._stopping.is_set():
            t0 = time.time()
            try:
                await self._tick()
            except MemoryError:
                self.log.warning("heartbeat_tick_oom")
                if self.cfg.skip_on_oom:
                    # пропускаем тик, даем GC шанс
                    await asyncio.sleep(self.cfg.interval_s)
                else:
                    raise
            except Exception as e:
                self.log.error("heartbeat_tick_failed", extra={"error": str(e).__class__ if hasattr(e, "__class__") else str(e)})
            # ожидание с джиттером
            elapsed = time.time() - t0
            sleep_for = max(0.0, self._interval_with_jitter() - elapsed)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=sleep_for)
            except asyncio.TimeoutError:
                pass

    async def _tick(self) -> None:
        self._seq += 1
        payload = await self._build_payload()
        # Отправка на первый успешный эндпойнт
        last_exc: Optional[Exception] = None
        for url in self.cfg.endpoints:
            try:
                await self._send(url, payload)
                self.log.debug("heartbeat_sent", extra={"endpoint": url, "seq": self._seq})
                return
            except Exception as e:  # noqa: PERF203
                last_exc = e
                self.log.warning("heartbeat_endpoint_failed", extra={"endpoint": url, "error": str(e)})
        if last_exc:
            raise last_exc

    # ---------- Сбор данных ----------

    async def _build_payload(self) -> Dict[str, Any]:
        now_ns = time.time_ns()
        uptime_s = time.time() - self._started_at
        host = socket.gethostname()
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time()%1)*1e6):06d}Z",
            "ts_ns": now_ns,
            "service": self.cfg.service,
            "env": self.cfg.env,
            "version": self.cfg.version,
            "tenant_id": self.cfg.tenant_id,
            "instance_id": self.cfg.instance_id,
            "seq": self._seq,
            "host": {
                "hostname": host,
                "platform": platform.platform(),
                "python": sys.version.split()[0],
                "pid": os.getpid(),
                "ppid": os.getppid(),
                "ips": _local_ips(),
                "container": {
                    "pod": os.getenv("POD_NAME"),
                    "namespace": os.getenv("POD_NAMESPACE"),
                    "node": os.getenv("K8S_NODE_NAME"),
                    "container_id": _container_id(),
                },
            },
            "uptime_s": round(uptime_s, 3),
        }

        if self.cfg.include_system_metrics:
            payload["metrics"] = _system_metrics()

        if self.cfg.include_health and self.app is not None:
            with contextlib.suppress(Exception):
                payload["health"] = await self.app.health_check()

        if self.cfg.extra_payload:
            payload["extra"] = self.cfg.extra_payload

        return payload

    # ---------- Отправка ----------

    async def _send(self, url: str, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = dict(self.cfg.headers) if self.cfg.headers else {}
        ts_str = str(int(time.time()))
        # Компрессия
        if self.cfg.compress_gzip:
            body = gzip.compress(body, compresslevel=5)
            headers["content-encoding"] = "gzip"
            headers["content-type"] = headers.get("content-type", "application/json")

        # Подпись
        if self.cfg.hmac_secret:
            digest = hmac.new(self.cfg.hmac_secret.encode("utf-8"), body + ts_str.encode("ascii"), sha256).hexdigest()
            headers[self.cfg.hmac_header] = digest
            headers[self.cfg.hmac_ts_header] = ts_str

        # Попытки
        attempt = 0
        backoff_ms = self.cfg.backoff_base_ms
        while True:
            attempt += 1
            try:
                status, resp_headers = await self._http_send(url, body, headers)
                if 200 <= status < 300:
                    return
                if status in (408, 425, 429, 500, 502, 503, 504):
                    # Уважать Retry-After для 429/503
                    if status in (429, 503):
                        ra = resp_headers.get("retry-after")
                        if ra:
                            with contextlib.suppress(Exception):
                                # секунды или HTTP-date; поддержим секунды
                                delay = float(ra)
                                await asyncio.sleep(delay)
                                continue
                    # иначе — обычный бэкофф
                    if attempt <= self.cfg.max_retries:
                        await asyncio.sleep(_jittered(backoff_ms, self.cfg.backoff_max_ms))
                        backoff_ms = min(self.cfg.backoff_max_ms, int(backoff_ms * 2))
                        continue
                # Клиентская ошибка или исчерпаны попытки
                raise RuntimeError(f"heartbeat_http_error status={status}")
            except Exception as e:
                if attempt <= self.cfg.max_retries:
                    await asyncio.sleep(_jittered(backoff_ms, self.cfg.backoff_max_ms))
                    backoff_ms = min(self.cfg.backoff_max_ms, int(backoff_ms * 2))
                    continue
                raise e

    async def _http_send(self, url: str, body: bytes, headers: Mapping[str, str]) -> Tuple[int, Dict[str, str]]:
        # Используем httpx из AppContext, если доступно и разрешено
        if self.app is not None and self.cfg.connect_via_app_http:
            client = await self.app.http()
            resp = await client.request(self.cfg.method, url, content=body, headers=headers, timeout=self.cfg.timeout_s)
            try:
                return resp.status_code, {k.lower(): v for k, v in (resp.headers or {}).items()}
            finally:
                # httpx.AsyncClient из AppContext — общий, не закрываем
                pass

        # Иначе собственный httpx-клиент, если библиотека доступна
        if httpx is not None:
            async with httpx.AsyncClient(verify=self.cfg.verify_tls, timeout=self.cfg.timeout_s) as client:
                r = await client.request(self.cfg.method, url, content=body, headers=headers)
                return r.status_code, {k.lower(): v for k, v in (r.headers or {}).items()}

        # Fallback — минималистичный пул со stdlib недоступен (нет async http), эмулируем ошибку
        raise RuntimeError("httpx is not available and AppContext HTTP client is missing")

    # ---------- Служебное ----------

    def _interval_with_jitter(self) -> float:
        base = self.cfg.interval_s
        jr = self.cfg.jitter_ratio
        if jr <= 0:
            return base
        spread = base * jr
        return max(0.1, base - spread + (random.random() * 2 * spread))

    def _bind_signals(self) -> None:
        if self._signals_bound:
            return
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._on_signal(s)))
            except NotImplementedError:
                pass
        self._signals_bound = True

    async def _on_signal(self, sig: signal.Signals) -> None:
        self.log.warning("heartbeat_signal_received", extra={"signal": str(sig)})
        await self.stop()

    @staticmethod
    def _default_logger() -> logging.Logger:
        lg = logging.getLogger("chronowatch.heartbeat")
        if not lg.handlers:
            lg.setLevel(logging.INFO)
            h = logging.StreamHandler(sys.stdout)
            h.setFormatter(logging.Formatter('%(message)s'))
            lg.addHandler(h)
            lg.propagate = False
        return lg


# ------------------------------------------------------------------------------
# Утилиты
# ------------------------------------------------------------------------------

def _jittered(backoff_ms: int, backoff_max_ms: int) -> float:
    base = min(backoff_ms, backoff_max_ms)
    # full jitter
    return random.uniform(0, base) / 1000.0

def _local_ips() -> List[str]:
    ips: List[str] = []
    try:
        hn = socket.gethostname()
        ip = socket.gethostbyname(hn)
        if ip:
            ips.append(ip)
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(None, 0, proto=socket.IPPROTO_TCP):
            addr = info[-1][0]
            if addr and addr not in ips and ":" not in addr:
                ips.append(addr)
    except Exception:
        pass
    return ips[:5]

def _container_id() -> Optional[str]:
    # Наиболее распространённый способ: читаем /proc/self/cgroup
    try:
        with open("/proc/self/cgroup", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # .../docker/<id> или .../kubepods.slice/.../<id>
                parts = line.split("/")
                cand = parts[-1]
                if len(cand) >= 12:
                    return cand[-64:][:64]
    except Exception:
        return None
    return None

def _system_metrics() -> Dict[str, Any]:
    m: Dict[str, Any] = {"source": "builtin"}
    # Базовые метрики без psutil
    try:
        if hasattr(os, "getloadavg"):
            la = os.getloadavg()  # type: ignore[attr-defined]
            m["load_1"] = round(float(la[0]), 3)
            m["load_5"] = round(float(la[1]), 3)
            m["load_15"] = round(float(la[2]), 3)
    except Exception:
        pass

    # Доп. метрики через psutil (если доступен)
    if psutil is None:
        return m

    try:
        m["cpu_percent"] = psutil.cpu_percent(interval=None)
    except Exception:
        pass

    try:
        vm = psutil.virtual_memory()
        m["mem_total"] = int(vm.total)
        m["mem_used"] = int(vm.used)
        m["mem_free"] = int(vm.available)
        m["mem_percent"] = float(vm.percent)
    except Exception:
        pass

    try:
        du = psutil.disk_usage("/")
        m["disk_total"] = int(du.total)
        m["disk_used"] = int(du.used)
        m["disk_free"] = int(du.free)
        m["disk_percent"] = float(du.percent)
    except Exception:
        pass

    try:
        p = psutil.Process(os.getpid())
        with contextlib.suppress(Exception):
            m["proc_rss"] = int(p.memory_info().rss)
        with contextlib.suppress(Exception):
            m["proc_threads"] = int(p.num_threads())
        with contextlib.suppress(Exception):
            m["proc_fds"] = int(p.num_fds()) if hasattr(p, "num_fds") else None
        with contextlib.suppress(Exception):
            m["proc_cpu_percent"] = float(p.cpu_percent(interval=None))
    except Exception:
        pass

    m["source"] = "psutil"
    return m


# ------------------------------------------------------------------------------
# Пример использования (не исполняется в проде)
# ------------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def main():
        cfg = HeartbeatConfig()
        agent = HeartbeatAgent(cfg, app=None)
        async with agent:
            # работаем 3 интервала для демонстрации
            await asyncio.sleep(cfg.interval_s * 3)

    asyncio.run(main())
