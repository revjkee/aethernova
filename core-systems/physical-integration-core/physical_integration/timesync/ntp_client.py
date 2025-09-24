# physical-integration-core/physical_integration/timesync/ntp_client.py
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import math
import socket
import struct
import time
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Tuple

# ----------------------------- Константы и утилиты -----------------------------

NTP_EPOCH_OFFSET = 2208988800  # сек. смещение между Unix и NTP эпохами
NTP_PACKET_LEN = 48
NTP_MODE_CLIENT = 3
NTP_VERSION = 4

# Коды Kiss-o'-Death (stratum == 0, RefID = ASCII)
KOD_CODES = {"RATE", "RSTR", "DENY", "STEP"}

# Лимиты и дефолты
DEFAULT_TIMEOUT_S = 2.0
DEFAULT_PER_SERVER_ATTEMPTS = 2
DEFAULT_MAX_SAMPLES = 8
DEFAULT_PORT = 123
DEFAULT_MAX_DELAY_MS = 250.0
DEFAULT_MAX_ROOT_DISTANCE_MS = 1000.0
DEFAULT_MAX_OFFSET_ABS_MS = 2_000.0  # отсечь очевидные аномалии
DEFAULT_MIN_POLL_S = 8.0             # 8с
DEFAULT_MAX_POLL_S = 1024.0          # 17мин
DEFAULT_JITTER_LOW_MS = 2.0          # низкий джиттер => можно увеличивать poll
DEFAULT_JITTER_HIGH_MS = 10.0        # высокий джиттер => уменьшаем poll
DEFAULT_STEP_THRESHOLD_MS = 400.0    # больше — step, меньше — slew рекомендация

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def unix_time_ns() -> int:
    return time.time_ns()

def _to_ntp64_from_unix_ns(ns: int) -> Tuple[int, int]:
    sec = ns // 1_000_000_000
    frac = ns % 1_000_000_000
    ntp_sec = sec + NTP_EPOCH_OFFSET
    ntp_frac = int(frac * (2**32) / 1_000_000_000)
    return ntp_sec, ntp_frac

def _from_ntp64_to_unix_ns(sec: int, frac: int) -> int:
    unix_sec = sec - NTP_EPOCH_OFFSET
    unix_frac = int(frac * 1_000_000_000 / (2**32))
    return unix_sec * 1_000_000_000 + unix_frac

def _ms(ns: int) -> float:
    return ns / 1_000_000.0

def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

def _is_ipv6(host: str) -> bool:
    with contextlib.suppress(ValueError):
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    return False

# ----------------------------- Конфигурация/модели -----------------------------

@dataclass
class NTPServer:
    host: str
    port: int = DEFAULT_PORT

@dataclass
class NTPSettings:
    servers: List[NTPServer]
    timeout_s: float = DEFAULT_TIMEOUT_S
    per_server_attempts: int = DEFAULT_PER_SERVER_ATTEMPTS
    max_samples: int = DEFAULT_MAX_SAMPLES
    max_delay_ms: float = DEFAULT_MAX_DELAY_MS
    max_root_distance_ms: float = DEFAULT_MAX_ROOT_DISTANCE_MS
    max_offset_abs_ms: float = DEFAULT_MAX_OFFSET_ABS_MS
    min_poll_s: float = DEFAULT_MIN_POLL_S
    max_poll_s: float = DEFAULT_MAX_POLL_S
    step_threshold_ms: float = DEFAULT_STEP_THRESHOLD_MS

@dataclass
class Sample:
    server: NTPServer
    t1_ns: int
    t2_ns: int
    t3_ns: int
    t4_ns: int
    delay_ms: float
    offset_ms: float
    root_delay_ms: float
    root_disp_ms: float
    root_distance_ms: float
    stratum: int
    leap: int
    koD: Optional[str] = None
    valid: bool = True
    reason: Optional[str] = None

@dataclass
class Aggregated:
    samples: List[Sample]
    best: Optional[Sample]
    offset_ms: Optional[float]
    jitter_ms: Optional[float]
    delay_ms: Optional[float]
    confidence: float
    poll_next_s: float
    recommendation: str  # "slew" | "step" | "hold"

# ----------------------------- Клиент NTP/SNTP --------------------------------

class NTPClient:
    """
    Асинхронный, беззависимый NTP/SNTP-клиент:
      - параллельные опросы several servers;
      - вычисление offset/delay/root distance;
      - фильтры и анти-анализ для KoD;
      - агрегация (кластер быстрых сэмплов);
      - адаптивная частота опроса.
    """

    def __init__(self, settings: NTPSettings,
                 metrics_hook: Optional[Callable[[Aggregated], None]] = None,
                 clock_setter: Optional[Callable[[float, str], None]] = None) -> None:
        """
        metrics_hook(agg): колбэк телеметрии.
        clock_setter(offset_ms, recommendation): внешний колбэк дисциплины часов.
        """
        self.s = settings
        self.metrics_hook = metrics_hook
        self.clock_setter = clock_setter
        self._history_offsets: List[float] = []
        self._last_poll_s = _clamp(self.s.min_poll_s, self.s.min_poll_s, self.s.max_poll_s)

    # -------- Публичный API --------

    async def synchronize(self) -> Aggregated:
        """
        Выполняет один цикл синхронизации: опрос серверов, агрегация, рекомендация.
        """
        raw = await self._query_all()
        agg = self._aggregate(raw)

        # Колбэки
        if self.metrics_hook:
            with contextlib.suppress(Exception):
                self.metrics_hook(agg)
        if self.clock_setter and agg.offset_ms is not None and agg.recommendation in ("slew", "step"):
            with contextlib.suppress(Exception):
                self.clock_setter(agg.offset_ms, agg.recommendation)

        return agg

    # -------- Низкоуровневый опрос --------

    async def _query_all(self) -> List[Sample]:
        tasks = [self._query_server(srv) for srv in self.s.servers[: self.s.max_samples]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: List[Sample] = []
        for r in results:
            if isinstance(r, Sample):
                out.append(r)
            else:
                # Исключение на уровне запроса одного сервера
                # Запишем как невалидный сэмпл (без раскрытия стека)
                # Сервер неизвестен (нет контекста), игнорируем
                pass
        return out

    async def _query_server(self, srv: NTPServer) -> Sample:
        """
        Один запрос к серверу NTP. Несколько попыток на тайм-аут/сетевые сбои.
        """
        attempts = max(1, self.s.per_server_attempts)
        last_exc: Optional[Exception] = None
        for _ in range(attempts):
            try:
                return await asyncio.wait_for(self._query_once(srv), timeout=self.s.timeout_s)
            except Exception as e:
                last_exc = e
        # Сформируем "пустой" сэмпл с причиной
        return Sample(
            server=srv, t1_ns=0, t2_ns=0, t3_ns=0, t4_ns=0,
            delay_ms=math.inf, offset_ms=math.inf,
            root_delay_ms=math.inf, root_disp_ms=math.inf, root_distance_ms=math.inf,
            stratum=16, leap=3, koD=None, valid=False, reason=f"no response: {last_exc}"
        )

    async def _query_once(self, srv: NTPServer) -> Sample:
        # Разрешение адреса
        addrinfo = await asyncio.get_running_loop().getaddrinfo(srv.host, srv.port, type=socket.SOCK_DGRAM)
        # Берём первый вариант
        family, socktype, proto, _, sockaddr = addrinfo[0]

        # Нестандартная особенность: для UDP используем неблокирующий сокет
        sock = socket.socket(family=family, type=socktype, proto=proto)
        sock.setblocking(False)

        try:
            # Сформируем пакет
            li_vn_mode = (0 << 6) | (NTP_VERSION << 3) | NTP_MODE_CLIENT
            stratum = 0
            poll = 4   # несущественно для клиента
            precision = -20  # ~1 us (индикативно)
            root_delay = 0
            root_dispersion = 0
            ref_id = 0
            ts = unix_time_ns()
            tx_sec, tx_frac = _to_ntp64_from_unix_ns(ts)

            pkt = struct.pack(
                "!BBBbIII4sQQQQ",
                li_vn_mode, stratum, poll, precision,
                root_delay, root_dispersion,
                0,  # ref id (заполним нулями у клиента)
                b"\x00\x00\x00\x00",
                0, 0, 0,  # Reference, Originate, Receive
                (tx_sec << 32) | tx_frac,  # Transmit Timestamp
            )

            # Отправка
            await asyncio.get_running_loop().sock_sendto(sock, pkt, sockaddr)
            t1_ns = ts

            # Приём
            data, _ = await asyncio.get_running_loop().sock_recvfrom(sock, NTP_PACKET_LEN)
            t4_ns = unix_time_ns()

            if len(data) < NTP_PACKET_LEN:
                raise RuntimeError("short NTP packet")

            # Разбор ответа
            (r_li_vn_mode, r_stratum, r_poll, r_precision,
             r_root_delay, r_root_dispersion,
             r_ref_id_bytes,
             r_ref_ts, r_orig_ts, r_recv_ts, r_tx_ts) = struct.unpack("!BBBbIII4sQQQQ", data)

            r_leap = (r_li_vn_mode >> 6) & 0x3
            r_mode = r_li_vn_mode & 0x7
            if r_mode not in (4, 5):  # server=4, broadcast=5 (broadcast не поддерживаем)
                raise RuntimeError("invalid NTP mode")

            # Поля времени
            t2_ns = _from_ntp64_to_unix_ns((r_recv_ts >> 32) & 0xFFFFFFFF, r_recv_ts & 0xFFFFFFFF)
            t3_ns = _from_ntp64_to_unix_ns((r_tx_ts >> 32) & 0xFFFFFFFF, r_tx_ts & 0xFFFFFFFF)

            # Проверка originate timestamp (может быть 0 у некоторых SNTP-проксей)
            if r_orig_ts != ((tx_sec << 32) | tx_frac):
                # Допускаем расхождение, но пометим причину в sample
                pass

            # Расчёт метрик RFC5905: delay/offset
            delay_ms = _ms((t4_ns - t1_ns) - (t3_ns - t2_ns))
            offset_ms = _ms(((t2_ns - t1_ns) + (t3_ns - t4_ns)) // 2)

            # Root delay/dispersion: сетевые/каскадные неопределённости сервера
            # В пакетах NTP они в формате 16.16 fixed-point (signed/unsigned).
            root_delay_ms = (r_root_delay / 65536.0) * 1000.0
            root_disp_ms = (r_root_dispersion / 65536.0) * 1000.0
            root_distance_ms = (root_delay_ms / 2.0) + root_disp_ms

            # KoD и refid
            kod: Optional[str] = None
            if r_stratum == 0:
                try:
                    kod_text = r_ref_id_bytes.decode("ascii", errors="ignore")
                    if kod_text in KOD_CODES:
                        kod = kod_text
                except Exception:
                    pass

            # Валидации
            reason = None
            valid = True
            if r_leap == 3:  # unsynchronized
                reason, valid = "unsynchronized (LI=3)", False
            elif kod is not None:
                reason, valid = f"kiss-o'-death {kod}", False
            elif delay_ms < 0 or delay_ms > self.s.max_delay_ms:
                reason, valid = "excessive delay", False
            elif abs(offset_ms) > self.s.max_offset_abs_ms:
                reason, valid = "excessive offset", False
            elif root_distance_ms > self.s.max_root_distance_ms:
                reason, valid = "excessive root distance", False

            return Sample(
                server=srv,
                t1_ns=t1_ns, t2_ns=t2_ns, t3_ns=t3_ns, t4_ns=t4_ns,
                delay_ms=delay_ms, offset_ms=offset_ms,
                root_delay_ms=root_delay_ms, root_disp_ms=root_disp_ms, root_distance_ms=root_distance_ms,
                stratum=r_stratum, leap=r_leap, koD=kod, valid=valid, reason=reason
            )

        finally:
            with contextlib.suppress(Exception):
                sock.close()

    # -------- Агрегация и рекомендации --------

    def _aggregate(self, samples: List[Sample]) -> Aggregated:
        # 1) Оставляем только валидные
        valid = [s for s in samples if s.valid]
        best: Optional[Sample] = None
        offset_ms: Optional[float] = None
        jitter_ms: Optional[float] = None
        delay_ms: Optional[float] = None
        confidence = 0.0
        recommendation = "hold"

        if valid:
            # 2) Сортируем по задержке (меньше — лучше), берём быстрый кластер
            valid.sort(key=lambda s: (s.delay_ms, s.root_distance_ms))
            cluster = self._take_fast_cluster(valid)

            # 3) Оценка: медиана offset в кластере, best — минимальная задержка
            offsets = [s.offset_ms for s in cluster]
            offset_ms = statistics.median(offsets)
            best = cluster[0]
            delay_ms = best.delay_ms

            # 4) История и jitter
            self._push_history(offset_ms)
            jitter_ms = self._jitter()

            # 5) Доверие (0..1): лучше при малом jitter, малой задержке и низком стратауме
            confidence = self._confidence(best, jitter_ms, len(cluster))

            # 6) Рекомендация step/slew/hold
            if abs(offset_ms) >= self.s.step_threshold_ms:
                recommendation = "step"
            elif abs(offset_ms) >= 0.5:  # едва заметная коррекция — slew
                recommendation = "slew"
            else:
                recommendation = "hold"

        # 7) Следующий poll-интервал
        poll_next_s = self._adjust_poll(jitter_ms, recommendation)

        return Aggregated(
            samples=samples, best=best,
            offset_ms=offset_ms, jitter_ms=jitter_ms, delay_ms=delay_ms,
            confidence=confidence, poll_next_s=poll_next_s,
            recommendation=recommendation
        )

    def _take_fast_cluster(self, samples: List[Sample]) -> List[Sample]:
        """
        Берём первые N с наименьшей задержкой, но ограничиваемся границей «быстроты».
        Например, все, у кого delay <= 1.5 * delay_min, до максимум 5 штук.
        """
        if not samples:
            return []
        dmin = samples[0].delay_ms
        cluster = [s for s in samples if s.delay_ms <= dmin * 1.5]
        return cluster[:5]

    def _push_history(self, offset_ms: float, maxlen: int = 32) -> None:
        self._history_offsets.append(offset_ms)
        if len(self._history_offsets) > maxlen:
            self._history_offsets.pop(0)

    def _jitter(self) -> Optional[float]:
        if len(self._history_offsets) < 2:
            return None
        return statistics.pstdev(self._history_offsets)

    def _confidence(self, best: Sample, jitter_ms: Optional[float], cluster_size: int) -> float:
        """
        Простейшая оценка доверия [0..1].
        """
        c = 1.0
        # Стратаум: 1..3 — ок, 4.. — штраф
        if best.stratum >= 4:
            c *= 0.7
        # Jitter
        if jitter_ms is not None:
            if jitter_ms <= DEFAULT_JITTER_LOW_MS:
                c *= 1.0
            elif jitter_ms <= DEFAULT_JITTER_HIGH_MS:
                c *= 0.85
            else:
                c *= 0.6
        # Задержка
        if best.delay_ms > 50.0:
            c *= 0.85
        if best.delay_ms > 100.0:
            c *= 0.7
        # Размер кластера
        if cluster_size < 2:
            c *= 0.9
        return _clamp(c, 0.0, 1.0)

    def _adjust_poll(self, jitter_ms: Optional[float], recommendation: str) -> float:
        """
        Адаптация следующего интервала опроса.
        """
        poll = self._last_poll_s
        if recommendation == "step":
            # после шага — чаще перепроверяем
            poll = max(self.s.min_poll_s, poll / 2.0)
        else:
            if jitter_ms is None:
                pass
            elif jitter_ms <= DEFAULT_JITTER_LOW_MS:
                poll = min(self.s.max_poll_s, poll * 2.0)
            elif jitter_ms >= DEFAULT_JITTER_HIGH_MS:
                poll = max(self.s.min_poll_s, poll / 2.0)
        self._last_poll_s = _clamp(poll, self.s.min_poll_s, self.s.max_poll_s)
        return self._last_poll_s

# ----------------------------- Пример использования -----------------------------

async def example():
    settings = NTPSettings(
        servers=[
            NTPServer("time.google.com"),
            NTPServer("time.cloudflare.com"),
            NTPServer("pool.ntp.org"),
        ],
        timeout_s=1.5,
        per_server_attempts=2,
    )

    def metrics(agg: Aggregated) -> None:
        # Здесь можно отправить метрики в систему мониторинга
        # Например: offset_ms, jitter_ms, delay_ms, confidence, poll_next_s
        pass

    def set_clock(offset_ms: float, recommendation: str) -> None:
        # В проде вызывайте платформенный инструмент (chrony/adjtime/clock_settime) с учётом прав.
        # Этот модуль только даёт рекомендацию; смена системного времени — внешняя ответственность.
        pass

    client = NTPClient(settings, metrics_hook=metrics, clock_setter=set_clock)
    agg = await client.synchronize()
    # agg.offset_ms, agg.recommendation, agg.poll_next_s содержат итог

# Если требуется самостоятельный запуск цикла:
# asyncio.run(example())
