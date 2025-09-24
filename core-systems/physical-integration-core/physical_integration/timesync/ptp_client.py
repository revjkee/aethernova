# physical_integration/timesync/ptp_client.py
from __future__ import annotations

import asyncio
import os
import time
import math
import socket
import signal
from dataclasses import dataclass, field
from typing import Callable, Optional, Deque, Tuple, List, Dict
from collections import deque

# -----------------------------
# Конфигурация и типы
# -----------------------------

@dataclass
class PTPThresholds:
    # Пороги в наносекундах
    lock_max_offset_ns: int = 500_000        # 0.5 ms
    holdover_max_offset_ns: int = 2_000_000  # 2 ms
    unlock_max_offset_ns: int = 10_000_000   # 10 ms
    # Порог джиттера (СКО, ns)
    jitter_ns: int = 1_000_000               # 1 ms
    # Порог скорости дрейфа (|d offset/dt|, ns/s) для holdover
    drift_ns_per_s: int = 5_000              # 5 μs/s

@dataclass
class PTPMonitorConfig:
    device: str = "/dev/ptp0"
    samples_per_measure: int = 15
    measure_interval_s: float = 5.0
    min_inter_measure_s: float = 0.5
    ewma_alpha: float = 0.2  # сглаживание оффсета
    thresholds: PTPThresholds = field(default_factory=PTPThresholds)
    prometheus_bind: Optional[str] = None     # "0.0.0.0:9109" или None
    prometheus_path: str = "/metrics"
    rate_limit_qps: float = 20.0
    rate_limit_burst: int = 40
    name: str = "ptp"
    # Безопасные таймауты
    measure_timeout_s: float = 1.0

@dataclass
class PTPSample:
    offset_ns: int     # оценка смещения (PHC - System)
    delay_ns: int      # (t3 - t1)
    t1_ns: int
    t2_ns: int
    t3_ns: int

@dataclass
class PTPStats:
    last_offset_ns: int = 0
    ewma_offset_ns: float = 0.0
    stddev_ns: float = 0.0
    drift_ns_per_s: float = 0.0
    samples: int = 0

# -----------------------------
# Утилиты
# -----------------------------

def _fd_to_clockid(fd: int) -> int:
    # FD_TO_CLOCKID(fd) = (((~fd) << 3) | 3)
    return ((~fd) << 3) | 3

def _clock_gettime_ns(clock_id: int) -> int:
    """
    Получение времени в ns для произвольного clock_id, включая fd-clock.
    Пытаемся через time.clock_gettime_ns (CPython пробрасывает clockid_t),
    иначе — через ctypes на clock_gettime.
    """
    try:
        return time.clock_gettime_ns(clock_id)  # type: ignore[arg-type]
    except Exception:
        # Fallback через ctypes
        import ctypes
        import ctypes.util
        librt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
        class timespec(ctypes.Structure):
            _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]
        ts = timespec()
        if librt.clock_gettime(ctypes.c_int(clock_id), ctypes.byref(ts)) != 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e))
        return int(ts.tv_sec) * 1_000_000_000 + int(ts.tv_nsec)

def _now_ns() -> int:
    # Монотонный таймер для внутренних интервалов
    return time.monotonic_ns()

class _TokenBucket:
    def __init__(self, qps: float, burst: int):
        self.rate = float(qps)
        self.burst = float(burst)
        self.tokens = float(burst)
        self.last = time.monotonic()

    async def take(self, n: float = 1.0):
        while True:
            now = time.monotonic()
            delta = now - self.last
            self.last = now
            self.tokens = min(self.burst, self.tokens + delta * self.rate)
            if self.tokens >= n:
                self.tokens -= n
                return
            await asyncio.sleep(max((n - self.tokens) / self.rate, 0.005))

# -----------------------------
# Prometheus (минималистичный)
# -----------------------------

class PrometheusServer:
    def __init__(self, bind: str, path: str = "/metrics"):
        self.host, self.port = bind.split(":")
        self.port = int(self.port)
        self.path = path
        self._metrics: Dict[str, Tuple[str, Dict[str, float]]] = {}  # name -> (help, {label_line: value})

    def set_gauge(self, name: str, value: float, help_text: str, labels: Dict[str, str] | None = None):
        labels = labels or {}
        key = self._label_line(labels)
        if name not in self._metrics:
            self._metrics[name] = (help_text, {})
        self._metrics[name][1][key] = value

    def inc_counter(self, name: str, inc: float, help_text: str, labels: Dict[str, str] | None = None):
        labels = labels or {}
        key = self._label_line(labels)
        if name not in self._metrics:
            self._metrics[name] = (help_text, {})
        cur = self._metrics[name][1].get(key, 0.0)
        self._metrics[name][1][key] = cur + inc

    def _label_line(self, labels: Dict[str, str]) -> str:
        if not labels:
            return ""
        parts = [f'{k}="{v}"' for k, v in sorted(labels.items())]
        return "{" + ",".join(parts) + "}"

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            req = await reader.read(1024)
            # Простейший парсер: проверим только строку запроса
            line = req.split(b"\r\n", 1)[0].decode("latin1", errors="ignore")
            if not line.startswith("GET "):
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            path = line.split(" ")[1]
            if path != self.path:
                writer.write(b"HTTP/1.1 404 Not Found\r\n\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            body = self._render().encode("utf-8")
            headers = [
                "HTTP/1.1 200 OK",
                "Content-Type: text/plain; version=0.0.4; charset=utf-8",
                f"Content-Length: {len(body)}",
                "Connection: close",
                "\r\n",
            ]
            writer.write("\r\n".join(headers).encode("ascii") + body)
            await writer.drain()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _render(self) -> str:
        out: List[str] = []
        for name, (help_text, series) in sorted(self._metrics.items()):
            out.append(f"# HELP {name} {help_text}")
            out.append(f"# TYPE {name} gauge")
            for label_line, value in series.items():
                out.append(f"{name}{label_line} {value}")
        return "\n".join(out) + "\n"

    async def start(self):
        self._server = await asyncio.start_server(self._serve, host=self.host, port=self.port)

    async def stop(self):
        try:
            self._server.close()
            await self._server.wait_closed()
        except Exception:
            pass

# -----------------------------
# Основной клиент
# -----------------------------

class PTPClient:
    """
    Монитор точности PTP: измеряет смещение PHC↔System многократно, выбирает лучший сэмпл,
    считает джиттер/дрейф и публикует метрики/события.
    """

    def __init__(
        self,
        cfg: PTPMonitorConfig = PTPMonitorConfig(),
        on_status_change: Optional[Callable[[str, PTPStats], None]] = None,
        on_sample: Optional[Callable[[PTPSample], None]] = None,
    ):
        self.cfg = cfg
        self.on_status_change = on_status_change
        self.on_sample = on_sample
        self._fd: Optional[int] = None
        self._clockid: Optional[int] = None
        self._limiter = _TokenBucket(cfg.rate_limit_qps, cfg.rate_limit_burst)
        self._prom: Optional[PrometheusServer] = None
        self._status = "unknown"
        self._stats = PTPStats()
        self._hist: Deque[Tuple[int,int]] = deque(maxlen=120)  # (time_ns, offset_ns)

    # ---------- Жизненный цикл ----------

    async def open(self):
        if not os.path.exists(self.cfg.device):
            raise FileNotFoundError(self.cfg.device)
        self._fd = os.open(self.cfg.device, os.O_RDONLY | os.O_CLOEXEC)
        self._clockid = _fd_to_clockid(self._fd)
        if self.cfg.prometheus_bind:
            self._prom = PrometheusServer(self.cfg.prometheus_bind, self.cfg.prometheus_path)
            await self._prom.start()

    async def close(self):
        if self._prom:
            await self._prom.stop()
            self._prom = None
        try:
            if self._fd is not None:
                os.close(self._fd)
        finally:
            self._fd = None
            self._clockid = None

    # ---------- Измерение ----------

    async def measure_once(self, n_samples: Optional[int] = None) -> PTPSample:
        """
        Делает серию из N замеров (t1, t2, t3) и возвращает лучший (минимальная задержка).
        t1,t3 — CLOCK_REALTIME; t2 — PHC clockid(/dev/ptpX).
        offset ≈ t2 - (t1+t3)/2
        """
        await self._limiter.take(1.0)
        if self._clockid is None:
            raise RuntimeError("PTPClient not opened")
        N = max(3, n_samples or self.cfg.samples_per_measure)

        best: Optional[PTPSample] = None
        deadline = time.monotonic() + self.cfg.measure_timeout_s

        for _ in range(N):
            if time.monotonic() > deadline:
                break
            t1 = time.clock_gettime_ns(time.CLOCK_REALTIME)
            t2 = _clock_gettime_ns(self._clockid)
            t3 = time.clock_gettime_ns(time.CLOCK_REALTIME)
            delay = t3 - t1
            # оценка смещения (PHC - середина окна системных замеров)
            offset = t2 - ((t1 + t3) // 2)
            sample = PTPSample(offset_ns=offset, delay_ns=delay, t1_ns=t1, t2_ns=t2, t3_ns=t3)
            if self.on_sample:
                try: self.on_sample(sample)
                except Exception: pass
            if best is None or sample.delay_ns < best.delay_ns:
                best = sample
            # небольшая пауза между сэмплами, чтобы не грузить ядро
            await asyncio.sleep(self.cfg.min_inter_measure_s)

        if best is None:
            # fallback: один замер
            t1 = time.clock_gettime_ns(time.CLOCK_REALTIME)
            t2 = _clock_gettime_ns(self._clockid)
            t3 = time.clock_gettime_ns(time.CLOCK_REALTIME)
            best = PTPSample(offset_ns=t2 - ((t1 + t3) // 2), delay_ns=t3 - t1, t1_ns=t1, t2_ns=t2, t3_ns=t3)
        return best

    # ---------- Мониторинг ----------

    async def run_monitor(self, stop_event: Optional[asyncio.Event] = None):
        """
        Основной цикл мониторинга. Обновляет статистику, статус и метрики Prometheus.
        """
        if self._clockid is None:
            await self.open()

        try:
            while True:
                start = _now_ns()
                sample = await self.measure_once()
                self._update_stats(sample)
                self._update_status()
                self._export_metrics(sample)

                # Ожидание до следующего цикла
                elapsed_s = ( _now_ns() - start ) / 1e9
                delay = max(0.0, self.cfg.measure_interval_s - elapsed_s)
                if stop_event:
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=delay)
                        return
                    except asyncio.TimeoutError:
                        pass
                else:
                    await asyncio.sleep(delay)
        finally:
            await self.close()

    # ---------- Обработка статистики/статуса ----------

    def _update_stats(self, sample: PTPSample):
        # EWMA оффсета
        if self._stats.samples == 0:
            self._stats.ewma_offset_ns = float(sample.offset_ns)
        else:
            a = self.cfg.ewma_alpha
            self._stats.ewma_offset_ns = a * float(sample.offset_ns) + (1 - a) * self._stats.ewma_offset_ns

        # История для stddev и дрейфа
        self._hist.append((time.time_ns(), sample.offset_ns))
        self._stats.samples += 1
        self._stats.last_offset_ns = sample.offset_ns

        # stddev по истории (до 120 точек)
        if len(self._hist) >= 5:
            mean = sum(o for _, o in self._hist) / len(self._hist)
            var = sum((o - mean) ** 2 for _, o in self._hist) / (len(self._hist) - 1)
            self._stats.stddev_ns = math.sqrt(var)
            # дрейф: линейная аппроксимация по последним точкам (dy/dt)
            t0, o0 = self._hist[0]
            t1, o1 = self._hist[-1]
            dt_s = max(1e-6, (t1 - t0) / 1e9)
            self._stats.drift_ns_per_s = (o1 - o0) / dt_s
        else:
            self._stats.stddev_ns = 0.0
            self._stats.drift_ns_per_s = 0.0

    def _update_status(self):
        th = self.cfg.thresholds
        off = abs(self._stats.last_offset_ns)
        jitter = self._stats.stddev_ns
        drift = abs(self._stats.drift_ns_per_s)

        prev = self._status
        new = prev

        # Грубая логика с гистерезисом
        if off <= th.lock_max_offset_ns and jitter <= th.jitter_ns:
            new = "locked"
        elif off <= th.holdover_max_offset_ns and drift <= th.drift_ns_per_s:
            new = "holdover"
        elif off > th.unlock_max_offset_ns or jitter > 5 * th.jitter_ns:
            new = "unlocked"
        else:
            # между порогами — сохраняем предыдущее
            new = prev

        if new != prev:
            self._status = new
            if self.on_status_change:
                try: self.on_status_change(new, self._stats)
                except Exception: pass

    def _export_metrics(self, sample: PTPSample):
        if not self._prom:
            return
        labels = {"name": self.cfg.name, "device": self.cfg.device}
        self._prom.set_gauge("ptp_offset_ns", float(self._stats.last_offset_ns),
                             "PTP offset estimate (PHC - System) in ns", labels)
        self._prom.set_gauge("ptp_offset_ewma_ns", float(self._stats.ewma_offset_ns),
                             "PTP offset EWMA in ns", labels)
        self._prom.set_gauge("ptp_delay_ns", float(sample.delay_ns),
                             "One-shot measurement delay window (t3 - t1) in ns", labels)
        self._prom.set_gauge("ptp_jitter_stddev_ns", float(self._stats.stddev_ns),
                             "PTP offset stddev over recent window in ns", labels)
        self._prom.set_gauge("ptp_drift_ns_per_s", float(self._stats.drift_ns_per_s),
                             "PTP offset drift absolute value in ns/s", labels)
        status_num = {"locked": 2, "holdover": 1, "unlocked": 0, "unknown": -1}[self._status]
        self._prom.set_gauge("ptp_lock_status", float(status_num),
                             "PTP lock status: 2=locked,1=holdover,0=unlocked,-1=unknown", labels)

    # ---------- Вспомогательное ----------

    @property
    def status(self) -> str:
        return self._status

    @property
    def stats(self) -> PTPStats:
        return self._stats


# -----------------------------
# Пример запуска демона
# -----------------------------

async def _main():
    cfg = PTPMonitorConfig(
        device=os.environ.get("PIC_PTP_DEVICE", "/dev/ptp0"),
        samples_per_measure=int(os.environ.get("PIC_PTP_SAMPLES", "15")),
        measure_interval_s=float(os.environ.get("PIC_PTP_INTERVAL", "5.0")),
        prometheus_bind=os.environ.get("PIC_PTP_PROM", "0.0.0.0:9109"),
        name=os.environ.get("PIC_PTP_NAME", "ptp0"),
    )

    def on_status_change(new_status: str, st: PTPStats):
        print(f"[PTP] status={new_status} offset={st.last_offset_ns}ns jitter={int(st.stddev_ns)}ns drift={int(st.drift_ns_per_s)}ns/s")

    def on_sample(s: PTPSample):
        # Можно логировать редкие аномалии по delay
        pass

    client = PTPClient(cfg, on_status_change=on_status_change, on_sample=on_sample)
    stop = asyncio.Event()

    def _sig(*_):
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try: loop.add_signal_handler(sig, _sig)
        except NotImplementedError: pass  # Windows

    await client.open()
    try:
        await client.run_monitor(stop_event=stop)
    finally:
        await client.close()

if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
