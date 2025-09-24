# chronowatch-core/chronowatch/timebase/drift_monitor.py
from __future__ import annotations

import asyncio
import dataclasses
import enum
import logging
import random
import socket
import statistics
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Awaitable, Callable, Deque, Dict, Iterable, List, Optional, Tuple, Protocol
from collections import deque

__all__ = [
    "DriftConfig",
    "DriftLevel",
    "DriftSample",
    "DriftSnapshot",
    "DriftEvent",
    "TimeSource",
    "SystemTimeSource",
    "NtpTimeSource",
    "DriftMonitor",
]

# ---------------------------
# Constants & helpers
# ---------------------------

NTP_DELTA = 2208988800  # seconds between NTP epoch (1900) and Unix epoch (1970)

def _unix_now() -> float:
    return time.time()

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _to_ntp(ts_unix: float) -> Tuple[int, int]:
    """Convert unix seconds to NTP 64-bit seconds.fraction."""
    ntp = ts_unix + NTP_DELTA
    sec = int(ntp)
    frac = int((ntp - sec) * (1 << 32))
    return sec, frac

def _from_ntp(sec: int, frac: int) -> float:
    """Convert NTP seconds.fraction to unix seconds."""
    return (sec + frac / (1 << 32)) - NTP_DELTA


# ---------------------------
# Data model
# ---------------------------

class DriftLevel(enum.IntEnum):
    OK = 0
    WARN = 1
    ERROR = 2
    DEGRADED = 3  # источники недоступны/недостаточны для оценки

@dataclass(slots=True)
class DriftSample:
    source: str
    offset_ms: float      # смещение источника относительно локального системного времени (ms)
    rtt_ms: float         # оценка Round-Trip Time (ms); для SystemTimeSource = 0
    at: datetime          # момент измерения (UTC)

@dataclass(slots=True)
class DriftSnapshot:
    level: DriftLevel
    offset_ms_p50: Optional[float]
    offset_ms_p95: Optional[float]
    rtt_ms_p50: Optional[float]
    sources_ok: int
    sources_total: int
    samples_window_size: int
    last_event: Optional["DriftEvent"] = None
    at: datetime = field(default_factory=_utc_now)

@dataclass(slots=True)
class DriftEvent:
    level: DriftLevel
    reason: str
    offset_ms: Optional[float]
    details: Dict[str, Any]
    at: datetime = field(default_factory=_utc_now)

# ---------------------------
# Interfaces
# ---------------------------

class TimeSource(Protocol):
    """Абстракция источника точного времени (UTC)."""

    name: str

    async def get_time(self) -> Tuple[datetime, Dict[str, Any]]:
        """
        Возвращает (UTC datetime, diagnostics).
        Должна выбрасывать исключение при ошибке.
        """
        ...

# ---------------------------
# Time sources
# ---------------------------

class SystemTimeSource:
    """Тривиальный источник: локальная системная UTC-время."""

    def __init__(self, name: str = "system"):
        self.name = name

    async def get_time(self) -> Tuple[datetime, Dict[str, Any]]:
        now = _utc_now()
        return now, {"rtt_ms": 0.0, "kind": "system"}

class NtpTimeSource:
    """
    SNTP v4 клиент без внешних зависимостей.
    Выполняет блокирующий UDP-запрос в thread-пуле через asyncio.to_thread.
    Фильтрует ответы по LI/stratum/RTT.
    """

    def __init__(
        self,
        server: str,
        port: int = 123,
        timeout: float = 1.0,          # сек на запрос
        min_stratum: int = 1,          # допустимый минимум (1..)
        max_stratum: int = 15,         # допустимый максимум (16 = unsynchronized)
        max_rtt_ms: float = 250.0,     # отсекать слишком «долгие» ответы
        name: Optional[str] = None,
        family: int = socket.AF_UNSPEC # авто-выбор A/AAAA
    ):
        self.server = server
        self.port = port
        self.timeout = timeout
        self.min_stratum = min_stratum
        self.max_stratum = max_stratum
        self.max_rtt_ms = max_rtt_ms
        self.family = family
        self.name = name or f"ntp:{server}"

    async def get_time(self) -> Tuple[datetime, Dict[str, Any]]:
        # Выполняем блокирующую операцию в пуле
        return await asyncio.to_thread(self._query_once)

    def _query_once(self) -> Tuple[datetime, Dict[str, Any]]:
        # Подготовка пакета SNTP (48 байт)
        LI = 0
        VN = 4
        MODE = 3  # client
        first_byte = (LI << 6) | (VN << 3) | MODE
        packet = bytearray(48)
        packet[0] = first_byte

        # t1 (client transmit) в NTP формате
        t1_unix = _unix_now()
        t1_sec, t1_frac = _to_ntp(t1_unix)
        struct.pack_into("!I", packet, 40, t1_sec)
        struct.pack_into("!I", packet, 44, t1_frac)

        # Отправка/приём
        addrinfos = socket.getaddrinfo(self.server, self.port, self.family, socket.SOCK_DGRAM)
        exc: Optional[Exception] = None

        for family, socktype, proto, _, sa in addrinfos:
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(self.timeout)
                sock.connect(sa)
                sock.send(packet)
                data = sock.recv(48)
                t4_unix = _unix_now()
                if len(data) < 48:
                    raise IOError("Short NTP packet")

                # Парсинг ответа (SNTP)
                (
                    li_vn_mode,
                    stratum,
                    _poll,
                    _precision,
                    _root_delay,
                    _root_dispersion,
                    _ref_id,
                    ref_ts_sec, ref_ts_frac,
                    t2_sec, t2_frac,
                    t3_sec, t3_frac,
                    _orig_sec, _orig_frac,
                ) = struct.unpack("!BBBbIII4I", data[:40] + data[40:56])

                li = (li_vn_mode >> 6) & 0b11
                mode = li_vn_mode & 0b111
                if mode not in (4, 5):  # server(4) or broadcast(5) accepted; client(3) невозможен
                    raise IOError(f"Unexpected NTP mode: {mode}")

                if li == 3:
                    raise IOError("NTP server not synchronized (LI=3)")

                if not (self.min_stratum <= stratum <= self.max_stratum):
                    raise IOError(f"Invalid stratum: {stratum}")

                # Времена сервера -> Unix
                t2_unix = _from_ntp(t2_sec, t2_frac)   # server receive
                t3_unix = _from_ntp(t3_sec, t3_frac)   # server transmit

                # offset/delay по SNTP
                delay = (t4_unix - t1_unix) - (t3_unix - t2_unix)
                offset = ((t2_unix - t1_unix) + (t3_unix - t4_unix)) / 2.0
                rtt_ms = max(0.0, delay * 1000.0)
                if rtt_ms > self.max_rtt_ms:
                    raise IOError(f"RTT too high: {rtt_ms:.1f}ms")

                ts = datetime.fromtimestamp(t3_unix, tz=timezone.utc)
                return ts, {
                    "rtt_ms": rtt_ms,
                    "stratum": int(stratum),
                    "leap": int(li),
                    "server": self.server,
                }
            except Exception as e:
                exc = e
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        # Если сюда дошли — все адреса не сработали
        raise exc or IOError("NTP query failed")


# ---------------------------
# Config
# ---------------------------

@dataclass(slots=True)
class DriftConfig:
    # Опрос
    interval_sec: float = 10.0
    jitter_ratio: float = 0.2               # 0..1 случайный джиттер к интервалу
    per_source_timeout_sec: float = 1.0
    min_sources_ok: int = 1                 # минимум успешных источников для расчёта

    # Фильтрация и окно
    window_size: int = 120                  # кол-во последних агрегированных оценок
    warmup_samples: int = 3
    max_source_rtt_ms: float = 250.0
    aggregate: str = "median"               # median|mean|trimmed_mean

    # Пороги и гистерезис
    warn_threshold_ms: float = 20.0
    error_threshold_ms: float = 100.0
    clear_hysteresis_ms: float = 5.0

    # Деградация по отказам
    max_consecutive_failures: int = 5

    # Логирование
    log_level: int = logging.INFO


# ---------------------------
# Monitor
# ---------------------------

class DriftMonitor:
    """
    Асинхронный монитор дрейфа системного времени.
    Использует несколько TimeSource, агрегирует смещение и публикует события.
    """

    def __init__(
        self,
        sources: Iterable[TimeSource],
        config: DriftConfig | None = None,
        *,
        logger: Optional[logging.Logger] = None,
        on_event: Optional[Callable[[DriftEvent], None]] = None,
        now_provider: Callable[[], datetime] = _utc_now,
        time_provider: Callable[[], float] = _unix_now,
    ):
        self._sources: List[TimeSource] = list(sources)
        if not self._sources:
            raise ValueError("At least one TimeSource required")

        self.cfg = config or DriftConfig()
        self.log = logger or logging.getLogger("chronowatch.drift")
        self.log.setLevel(self.cfg.log_level)

        self._on_event = on_event
        self._now = now_provider
        self._time = time_provider

        self._loop_task: Optional[asyncio.Task] = None
        self._stop_evt = asyncio.Event()
        self._window: Deque[DriftSample] = deque(maxlen=self.cfg.window_size)
        self._agg_window: Deque[Tuple[datetime, float]] = deque(maxlen=self.cfg.window_size)
        self._consec_fail = 0
        self._level: DriftLevel = DriftLevel.DEGRADED
        self._last_event: Optional[DriftEvent] = None

    # ---------- lifecycle ----------

    async def start(self) -> None:
        if self._loop_task is not None:
            return
        self._stop_evt.clear()
        self._loop_task = asyncio.create_task(self._run_loop(), name="drift-monitor")
        self.log.info("DriftMonitor started with %d sources", len(self._sources))

    async def stop(self) -> None:
        if self._loop_task is None:
            return
        self._stop_evt.set()
        self._loop_task.cancel()
        try:
            await self._loop_task
        except asyncio.CancelledError:
            pass
        finally:
            self._loop_task = None
        self.log.info("DriftMonitor stopped")

    # ---------- public API ----------

    def snapshot(self) -> DriftSnapshot:
        offsets = [off for _, off in list(self._agg_window)]
        rtts = [s.rtt_ms for s in list(self._window)]
        p50 = statistics.median(offsets) if offsets else None
        p95 = (statistics.quantiles(offsets, n=20)[18] if len(offsets) >= 20 else max(offsets) if offsets else None)
        rtt50 = statistics.median(rtts) if rtts else None
        return DriftSnapshot(
            level=self._level,
            offset_ms_p50=p50,
            offset_ms_p95=p95,
            rtt_ms_p50=rtt50,
            sources_ok=self._sources_ok_last,
            sources_total=len(self._sources),
            samples_window_size=len(self._agg_window),
            last_event=self._last_event,
        )

    def last_event(self) -> Optional[DriftEvent]:
        return self._last_event

    # ---------- internals ----------

    async def _run_loop(self) -> None:
        self._sources_ok_last = 0
        try:
            while not self._stop_evt.is_set():
                start = self._now()
                try:
                    await self._poll_once()
                except Exception as e:
                    self.log.exception("Drift poll failed: %s", e)

                # Ждём следующий цикл с джиттером
                base = self.cfg.interval_sec
                jitter = base * self.cfg.jitter_ratio
                delay = max(0.2, base + random.uniform(-jitter, jitter))
                # Корректируем, чтобы не накапливать дрейф интервала
                elapsed = (self._now() - start).total_seconds()
                await asyncio.sleep(max(0.0, delay - elapsed))
        except asyncio.CancelledError:
            return

    async def _poll_once(self) -> None:
        """
        Опрос всех источников, расчёт смещения и генерация событий.
        """
        sys_unix_before = self._time()
        tasks = [self._poll_source(src) for src in self._sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        sys_unix_after = self._time()

        samples: List[DriftSample] = []
        ok = 0
        for src, res in zip(self._sources, results):
            if isinstance(res, Exception):
                self.log.debug("Source %s error: %s", src.name, res)
                continue
            sample = res  # type: ignore[assignment]
            # Фильтрация по RTT
            if sample.rtt_ms > self.cfg.max_source_rtt_ms:
                self.log.debug("Source %s rejected due to RTT %.1fms", src.name, sample.rtt_ms)
                continue
            samples.append(sample)
            ok += 1

        self._sources_ok_last = ok

        if ok < self.cfg.min_sources_ok:
            self._consec_fail += 1
            self._maybe_emit(DriftLevel.DEGRADED, "insufficient_sources", None, {
                "ok": ok, "required": self.cfg.min_sources_ok
            })
            return
        else:
            self._consec_fail = 0

        # Агрегация смещения по источникам
        offsets = [s.offset_ms for s in samples]
        aggregated = self._aggregate(offsets)

        # Сохраняем в окна
        now = self._now()
        for s in samples:
            self._window.append(s)
        self._agg_window.append((now, aggregated))

        # Warmup
        if len(self._agg_window) < self.cfg.warmup_samples:
            self._maybe_emit(DriftLevel.OK, "warmup", aggregated, {"window": len(self._agg_window)})
            return

        # Оценка уровня с гистерезисом
        level = self._evaluate_level(aggregated)
        self._maybe_emit(level, "drift_update", aggregated, {
            "offset_ms": aggregated,
            "ok_sources": ok,
            "rtt_ms_p50": statistics.median([s.rtt_ms for s in samples]) if samples else None,
        })

    async def _poll_source(self, src: TimeSource) -> DriftSample:
        """
        Получение времени от источника и расчёт offset = (t_source - t_local) * 1000.
        """
        # Пер-источник таймаут
        async def _run() -> DriftSample:
            t_req = self._time()
            dt, diag = await src.get_time()
            t_resp = self._time()

            # Оценка локального времени и RTT
            # Для «обычных» источников используем t=(t_req+t_resp)/2 как лучшую оценку середины запроса
            t_mid = (t_req + t_resp) / 2.0
            offset_ms = (dt.timestamp() - t_mid) * 1000.0
            rtt_ms = float(diag.get("rtt_ms", (t_resp - t_req) * 1000.0))
            sample = DriftSample(source=src.name, offset_ms=offset_ms, rtt_ms=rtt_ms, at=self._now())
            return sample

        try:
            return await asyncio.wait_for(_run(), timeout=self.cfg.per_source_timeout_sec)
        except Exception as e:
            raise e

    def _aggregate(self, offsets: List[float]) -> float:
        if not offsets:
            raise ValueError("no offsets to aggregate")
        method = self.cfg.aggregate
        if method == "median":
            return float(statistics.median(offsets))
        if method == "mean":
            return float(statistics.fmean(offsets))
        if method == "trimmed_mean":
            if len(offsets) <= 2:
                return float(statistics.fmean(offsets))
            trimmed = sorted(offsets)[1:-1]
            return float(statistics.fmean(trimmed))
        # fallback
        return float(statistics.median(offsets))

    def _evaluate_level(self, offset_ms: float) -> DriftLevel:
        # Гистерезис: понижаем уровень лишь при возврате в «порог − hysteresis»
        warn = self.cfg.warn_threshold_ms
        err = self.cfg.error_threshold_ms
        hys = self.cfg.clear_hysteresis_ms

        current = self._level

        # Вверх по уровням без гистерезиса
        if abs(offset_ms) >= err:
            return DriftLevel.ERROR
        if abs(offset_ms) >= warn:
            return DriftLevel.WARN

        # Вниз по уровням с гистерезисом
        if current == DriftLevel.ERROR and abs(offset_ms) < (err - hys):
            return DriftLevel.WARN if abs(offset_ms) >= (warn - hys) else DriftLevel.OK
        if current == DriftLevel.WARN and abs(offset_ms) < (warn - hys):
            return DriftLevel.OK

        # Если текущий уже лучше — оставляем лучшее
        if current in (DriftLevel.DEGRADED, DriftLevel.ERROR, DriftLevel.WARN):
            # Ничего не меняем, если «почти» вернулись, но не пересекли гистерезис
            pass
        return DriftLevel.OK

    def _maybe_emit(self, level: DriftLevel, reason: str, offset_ms: Optional[float], details: Dict[str, Any]) -> None:
        # Деградация по连续 отказам
        if self._consec_fail >= self.cfg.max_consecutive_failures:
            level = DriftLevel.DEGRADED
            reason = "consecutive_failures"

        changed = (level != self._level) or (reason != (self._last_event.reason if self._last_event else None))
        evt = DriftEvent(level=level, reason=reason, offset_ms=offset_ms, details=details)
        self._last_event = evt
        self._level = level

        # Логирование (умеренное)
        if changed:
            self.log.log(
                logging.WARNING if level in (DriftLevel.WARN, DriftLevel.ERROR, DriftLevel.DEGRADED) else logging.INFO,
                "DriftEvent level=%s reason=%s offset_ms=%s details=%s",
                level.name, reason, f"{offset_ms:.2f}" if offset_ms is not None else "n/a", details
            )

        # Коллбек метрик/событий
        if self._on_event:
            try:
                self._on_event(evt)
            except Exception:  # не ломаем монитор из-за пользовательского кода
                self.log.exception("on_event callback failed")

# ---------------------------
# Example: building a monitor
# ---------------------------

def build_default_monitor(logger: Optional[logging.Logger] = None) -> DriftMonitor:
    """
    Удобный фабричный метод: система + несколько публичных NTP.
    В проде укажите собственные NTP (например, внутри VPC) вместо публичных.
    """
    sources: List[TimeSource] = [
        SystemTimeSource(),
        NtpTimeSource("time.google.com"),
        NtpTimeSource("time.cloudflare.com"),
        NtpTimeSource("pool.ntp.org"),
    ]
    cfg = DriftConfig(
        interval_sec=15.0,
        jitter_ratio=0.15,
        per_source_timeout_sec=1.0,
        min_sources_ok=1,
        window_size=120,
        warmup_samples=3,
        max_source_rtt_ms=250.0,
        aggregate="median",
        warn_threshold_ms=20.0,
        error_threshold_ms=100.0,
        clear_hysteresis_ms=5.0,
        max_consecutive_failures=5,
        log_level=logging.INFO,
    )
    return DriftMonitor(sources, cfg, logger=logger)

# ---------------------------
# Minimal self-test (optional)
# ---------------------------

async def _demo() -> None:  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    mon = build_default_monitor()

    def printer(evt: DriftEvent) -> None:
        snap = mon.snapshot()
        print(f"[{evt.at.isoformat()}] level={evt.level.name} offset={evt.offset_ms}ms ok={snap.sources_ok}/{snap.sources_total}")

    mon._on_event = printer
    await mon.start()
    try:
        await asyncio.sleep(60)
    finally:
        await mon.stop()

if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass
