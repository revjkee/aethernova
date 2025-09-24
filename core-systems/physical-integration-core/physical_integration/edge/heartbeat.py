from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import json
import os
import platform
import random
import socket
import subprocess
import sys
import time
import typing as t
import uuid
from dataclasses import dataclass

# HTTP/2 клиент с пулом соединений
try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("heartbeat requires httpx>=0.23") from e

# Системные метрики
try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

# Метрики (no-op fallback)
try:
    from prometheus_client import Counter, Gauge, Histogram  # type: ignore
except Exception:  # pragma: no cover
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_): return
        def set(self, *_): return
        def observe(self, *_): return
    Counter = Gauge = Histogram = _Noop  # type: ignore


# ================================
# Конфигурация
# ================================

@dataclass(frozen=True)
class TLSConfig:
    verify: t.Union[bool, str] = True            # True|False|path_to_ca_bundle
    cert: t.Optional[str] = None                 # путь к клиентскому сертификату (PEM) для mTLS
    key: t.Optional[str] = None                  # путь к приватному ключу (PEM) для mTLS


@dataclass(frozen=True)
class HeartbeatConfig:
    endpoints: tuple[str, ...]                   # список HTTPS эндпоинтов (приоритет по порядку)
    interval_seconds: float = 15.0               # базовый интервал heartbeat
    jitter_fraction: float = 0.2                 # +/-20% джиттер
    timeout_seconds: float = 4.0                 # таймаут запроса
    connect_timeout_seconds: float = 2.0         # таймаут установки соединения
    concurrency_limit: int = 1                   # не более 1 одновременного heartbeat
    max_payload_kb: int = 64                     # ограничение размера полезной нагрузки
    backoff_base_seconds: float = 1.0            # начальный бэкофф
    backoff_max_seconds: float = 30.0            # максимум бэкоффа
    backoff_multiplier: float = 2.0              # экспонента бэкоффа
    backoff_jitter_fraction: float = 0.2         # джиттер бэкоффа
    hmac_secret: t.Optional[str] = None          # общий секрет (base64 или raw) для подписи нагрузки
    hmac_header: str = "X-Signature"             # заголовок подписи
    hmac_key_id: t.Optional[str] = None          # идентификатор ключа (для ротации), попадёт в X-Signature-Key-Id
    bearer_token: t.Optional[str] = None         # альтернатива HMAC: статический токен аутентификации
    api_key: t.Optional[str] = None              # альтернатива: X-API-Key
    idempotency_header: str = "Idempotency-Key"  # для безопасных повторов
    node_id: t.Optional[str] = None              # фиксированный идентификатор узла
    site: str = os.getenv("SITE", "default-site")
    environment: str = os.getenv("ENVIRONMENT", "prod")
    region: str = os.getenv("REGION", "eu-north-1")
    tls: TLSConfig = TLSConfig()
    log_json: bool = True                        # структурированное логирование
    include_process_metrics: bool = True         # проц/память текущего процесса
    include_time_sync: bool = True               # попытка прочитать chrony/ptp
    include_disks: bool = True
    include_net: bool = True
    include_gpu: bool = True                     # попытаемся считать краткую статистику NVIDIA (nvidia-smi)
    headers: tuple[tuple[str, str], ...] = tuple()  # дополнительные заголовки (k, v) пары

    def __post_init__(self):
        if not self.endpoints:
            raise ValueError("At least one endpoint is required")
        for url in self.endpoints:
            if not (url.startswith("https://") or url.startswith("http://")):
                raise ValueError(f"endpoint must be http(s) URL: {url}")
        if self.interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        if not (0.0 <= self.jitter_fraction <= 1.0):
            raise ValueError("jitter_fraction must be in [0,1]")


# ================================
# Вспомогательные утилиты
# ================================

def _now_ms() -> int:
    return int(time.time() * 1000)


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _get_node_id(explicit: t.Optional[str]) -> str:
    if explicit:
        return explicit
    # детерминированный ID на основе hostname + MAC (если доступен)
    seed = _hostname()
    try:
        mac = hex(uuid.getnode())[2:]
        seed += f"-{mac}"
    except Exception:
        pass
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def _hmac_sign(secret: str, payload: bytes) -> str:
    # secret может быть base64; если декодирование не удалось — используем raw
    try:
        key = base64.b64decode(secret, validate=True)
    except Exception:
        key = secret.encode()
    mac = hashlib.sha256(key + payload).digest()
    return base64.b64encode(mac).decode()


def _canonical_json(obj: t.Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _log(json_mode: bool, level: str, msg: str, **extra: t.Any) -> None:  # pragma: no cover
    if json_mode:
        print(json.dumps({"level": level, "msg": msg, **extra}, ensure_ascii=False))
    else:
        print(f"[{level}] {msg} {extra}")


# ================================
# Сбор метрик узла
# ================================

def _collect_time_sync() -> dict:
    """Безопасная попытка получить смещение/страты из chrony/ptp; ошибки игнорируются."""
    result: dict[str, t.Any] = {}
    try:
        out = subprocess.check_output(["chronyc", "tracking"], timeout=1.0, text=True)  # type: ignore
        for line in out.splitlines():
            if "Leap status" in line: result["leap"] = line.split(":", 1)[1].strip()
            if "Stratum" in line: result["stratum"] = int(line.split(":", 1)[1].strip())
            if "Last offset" in line: result["last_offset_ms"] = float(line.split()[-2]) * 1000.0
            if "RMS offset" in line: result["rms_offset_ms"] = float(line.split()[-2]) * 1000.0
    except Exception:
        pass
    # ptp4l/phc2sys статус (очень кратко)
    try:
        out = subprocess.check_output(["pmc", "-u", "-b", "0", "GET", "TIME_STATUS_NP"], timeout=1.0, text=True)  # type: ignore
        if "master_offset" in out:
            # грубый парсинг master_offset X
            for tok in out.split():
                if tok.startswith("master_offset"):
                    try:
                        result["ptp_master_offset_ns"] = int(tok.split(" ")[-1])
                    except Exception:
                        pass
    except Exception:
        pass
    return result


def _collect_gpu_short() -> dict:
    """Короткая сводка GPU через nvidia-smi (если доступно)."""
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=utilization.gpu,memory.total,memory.used", "--format=csv,noheader,nounits"],
            timeout=1.0, text=True
        )
        util, mem_total, mem_used = out.strip().splitlines()[0].split(", ")
        return {
            "vendor": "nvidia",
            "util_percent": float(util),
            "mem_total_mb": float(mem_total),
            "mem_used_mb": float(mem_used),
        }
    except Exception:
        return {}


def _collect_system_metrics(cfg: HeartbeatConfig) -> dict:
    info = {
        "os": {
            "platform": sys.platform,
            "release": platform.release(),
            "kernel": platform.version(),
            "python": platform.python_version(),
        },
        "node": {
            "hostname": _hostname(),
            "site": cfg.site,
            "environment": cfg.environment,
            "region": cfg.region,
        },
        "proc": {},
        "cpu": {},
        "mem": {},
        "disks": {},
        "net": {},
    }

    if psutil:
        try:
            info["cpu"] = {
                "cores_logical": psutil.cpu_count(),
                "load_avg": getattr(os, "getloadavg", lambda: (0.0, 0.0, 0.0))(),
                "util_percent": psutil.cpu_percent(interval=None),
            }
            vm = psutil.virtual_memory()
            info["mem"] = {
                "total_mb": vm.total / (1024 * 1024),
                "used_mb": vm.used / (1024 * 1024),
                "util_percent": vm.percent,
            }
            if cfg.include_disks:
                try:
                    du = psutil.disk_usage("/")
                    info["disks"] = {
                        "root_total_gb": du.total / (1024**3),
                        "root_used_gb": du.used / (1024**3),
                        "root_util_percent": du.percent,
                    }
                except Exception:
                    pass
            if cfg.include_net:
                try:
                    ni = psutil.net_io_counters()
                    info["net"] = {"bytes_sent": ni.bytes_sent, "bytes_recv": ni.bytes_recv}
                except Exception:
                    pass
            if cfg.include_process_metrics:
                p = psutil.Process(os.getpid())
                with p.oneshot():
                    info["proc"] = {
                        "pid": p.pid,
                        "cpu_percent": p.cpu_percent(interval=None),
                        "rss_mb": p.memory_info().rss / (1024 * 1024),
                        "num_threads": p.num_threads(),
                        "open_files": len(p.open_files()),
                    }
        except Exception:
            pass

    if cfg.include_time_sync:
        info["time_sync"] = _collect_time_sync()

    if cfg.include_gpu:
        g = _collect_gpu_short()
        if g:
            info["gpu"] = g

    return info


# ================================
# Метрики Prometheus
# ================================

M_SENT = Counter("heartbeat_sent_total", "Heartbeats successfully sent", ["endpoint", "code"])
M_FAIL = Counter("heartbeat_fail_total", "Heartbeat send failures", ["endpoint", "reason"])
H_LAT = Histogram("heartbeat_latency_seconds", "Heartbeat request latency seconds", ["endpoint"])
G_UP = Gauge("heartbeat_up", "Heartbeat loop up (1) / down (0)", ["endpoint"])
G_LAST_OK_MS = Gauge("heartbeat_last_ok_ms", "Timestamp ms of last successful heartbeat", ["endpoint"])


# ================================
# Основной клиент
# ================================

class HeartbeatClient:
    """
    Асинхронный отправитель heartbeat сообщений на пул эндпоинтов с:
      - HTTP/2, пулами соединений и таймаутами
      - HMAC-подписью полезной нагрузки или Bearer/API-Key
      - экспоненциальным бэкоффом и джиттером
      - идемпотентностью (Idempotency-Key)
      - безопасным сбором системных метрик
    """

    def __init__(self, cfg: HeartbeatConfig) -> None:
        self.cfg = cfg
        self.node_id = _get_node_id(cfg.node_id)
        limits = httpx.Limits(
            max_keepalive_connections=10,
            max_connections=10,
            keepalive_expiry=30.0,
        )
        verify = cfg.tls.verify
        cert = (cfg.tls.cert, cfg.tls.key) if cfg.tls.cert and cfg.tls.key else None
        self._client = httpx.AsyncClient(
            http2=True,
            limits=limits,
            timeout=httpx.Timeout(cfg.timeout_seconds, connect=cfg.connect_timeout_seconds),
            verify=verify,
            cert=cert,
        )
        self._lock = asyncio.Semaphore(cfg.concurrency_limit)
        self._task: t.Optional[asyncio.Task] = None
        self._running = False

    # --------------- Публичное API ---------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="heartbeat-loop")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._client.aclose()

    async def once(self) -> tuple[bool, int, str]:
        """Единичная отправка heartbeat. Возвращает (ok, status_code, endpoint)."""
        async with self._lock:
            return await self._send_one()

    # --------------- Внутреннее ---------------

    async def _loop(self) -> None:
        backoff = self.cfg.backoff_base_seconds
        while self._running:
            ok, _, _ = await self.once()
            if ok:
                backoff = self.cfg.backoff_base_seconds
                # интервальный джиттер
                base = self.cfg.interval_seconds
                jitter = base * self.cfg.jitter_fraction
                await asyncio.sleep(max(0.1, base + random.uniform(-jitter, jitter)))
            else:
                # экспоненциальный бэкофф с джиттером
                sleep_s = min(self.cfg.backoff_max_seconds, backoff)
                jitter = sleep_s * self.cfg.backoff_jitter_fraction
                await asyncio.sleep(max(0.2, sleep_s + random.uniform(-jitter, jitter)))
                backoff *= self.cfg.backoff_multiplier

    async def _send_one(self) -> tuple[bool, int, str]:
        payload, idempotency_key = self._build_payload()
        data_bytes = _canonical_json(payload)
        # огран. размера
        if len(data_bytes) > self.cfg.max_payload_kb * 1024:
            # урежем неважные разделы
            payload.pop("proc", None)
            payload.pop("gpu", None)
            data_bytes = _canonical_json(payload)

        hdrs = {
            "Content-Type": "application/json",
            "X-Node-Id": self.node_id,
            self.cfg.idempotency_header: idempotency_key,
        }
        for k, v in self.cfg.headers:
            hdrs[k] = v

        if self.cfg.bearer_token:
            hdrs["Authorization"] = f"Bearer {self.cfg.bearer_token}"
        if self.cfg.api_key:
            hdrs["X-API-Key"] = self.cfg.api_key
        if self.cfg.hmac_secret:
            sig = _hmac_sign(self.cfg.hmac_secret, data_bytes)
            hdrs[self.cfg.hmac_header] = sig
            if self.cfg.hmac_key_id:
                hdrs[f"{self.cfg.hmac_header}-Key-Id"] = self.cfg.hmac_key_id

        # failover по списку эндпоинтов
        last_exc: t.Optional[Exception] = None
        for url in self.cfg.endpoints:
            t0 = time.time()
            try:
                resp = await self._client.post(url, content=data_bytes, headers=hdrs)
                H_LAT.labels(url).observe(time.time() - t0)
                if 200 <= resp.status_code < 300:
                    M_SENT.labels(url, str(resp.status_code)).inc()
                    G_UP.labels(url).set(1)
                    G_LAST_OK_MS.labels(url).set(_now_ms())
                    return True, resp.status_code, url
                else:
                    # 409/429/5xx считаем ошибкой; сервер может использовать идемпотентность и вернуть 200/204 на повторы
                    M_FAIL.labels(url, f"http_{resp.status_code}").inc()
                    G_UP.labels(url).set(0)
                    last_exc = RuntimeError(f"http {resp.status_code}")
            except Exception as e:
                M_FAIL.labels(url, "exception").inc()
                G_UP.labels(url).set(0)
                last_exc = e
                continue  # пробуем следующий URL

        # все попытки неуспешны
        reason = str(last_exc) if last_exc else "unknown"
        _log(self.cfg.log_json, "warn", "heartbeat_failed", reason=reason)
        return False, 0, self.cfg.endpoints[0]

    # Формирование полезной нагрузки
    def _build_payload(self) -> tuple[dict, str]:
        event_id = str(uuid.uuid4())
        ts = _now_ms()
        sysinfo = _collect_system_metrics(self.cfg)
        payload = {
            "schema_version": "1.0.0",
            "event_id": event_id,
            "event_time_ms": ts,
            "node": {
                "id": self.node_id,
                "hostname": sysinfo["node"]["hostname"],
                "site": self.cfg.site,
                "environment": self.cfg.environment,
                "region": self.cfg.region,
            },
            "system": sysinfo,
            "app": {
                "name": os.getenv("APP_NAME", "physical-integration-core"),
                "version": os.getenv("APP_VERSION", "0.0.0"),
                "commit": os.getenv("APP_COMMIT", ""),
            },
        }
        # Идемпотентность: ключ привязываем к event_id и минутному окну (сервер может дубли игнорировать)
        window = int(ts // (60 * 1000))
        idemp = hashlib.sha256(f"{event_id}:{self.node_id}:{window}".encode()).hexdigest()
        return payload, idemp


# ================================
# Пример интеграции (не запускается в проде автоматически)
# ================================

async def _demo() -> None:  # pragma: no cover
    cfg = HeartbeatConfig(
        endpoints=(os.getenv("HEARTBEAT_URL", "https://localhost:8443/edge/heartbeat"),),
        interval_seconds=float(os.getenv("HEARTBEAT_INTERVAL", "10")),
        bearer_token=os.getenv("HEARTBEARER", None),
        api_key=os.getenv("HEARTAPIKEY", None),
        hmac_secret=os.getenv("HEARTHMAC", None),
        tls=TLSConfig(
            verify=os.getenv("TLS_VERIFY", "true").lower() != "false",
            cert=os.getenv("TLS_CERT"),
            key=os.getenv("TLS_KEY"),
        ),
        headers=(("X-Client", "edge"),),
    )
    hb = HeartbeatClient(cfg)
    await hb.start()
    try:
        # Работает пока не прервут
        while True:
            await asyncio.sleep(60)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await hb.stop()


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_demo())
