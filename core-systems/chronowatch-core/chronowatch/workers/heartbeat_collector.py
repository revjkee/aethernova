"""
chronowatch.workers.heartbeat_collector

Промышленный сборщик пульсов (heartbeats) для ChronoWatch.

Возможности:
- Синхронный и асинхронный прием пульсов от множества сущностей (series_key).
- Пер-сущностное состояние: last_seen, inter-arrival, EWMA джиттер, EWMA сетевой задержки,
  последовательность (seq) и защита от дубликатов/рассинхронизации.
- Детекция состояний: healthy/late/unhealthy/expired с антидребезгом (cooldown) и
  флаппинг-защитой.
- Периодический скан таймаутов, TTL-эвикция неактивных серий.
- Публикация событий статуса в sink (синхронный/асинхронный интерфейсы).
- Экспорт агрегированных метрик и снимка состояния.
- Автоматическое использование MonotonicClock (если доступен) для стабильного времени.

Зависимости: только стандартная библиотека Python 3.11+.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Protocol, Tuple

log = logging.getLogger("chronowatch.workers.heartbeat_collector")

# ----------------------- Время (локальная абстракция) ------------------------

def _wall_now_ms() -> int:
    return int(time.time() * 1000)

try:
    # Опциональная интеграция с ChronoWatch timebase (если модуль доступен)
    from chronowatch.timebase.monotonic import MonotonicClock  # type: ignore

    _CLOCK = MonotonicClock()
    def _now_ms() -> int:
        # Стабильная к скачкам проекция UNIX-времени
        return int(_CLOCK.unix_now_ns() / 1e6)
except Exception:
    _CLOCK = None
    _now_ms = _wall_now_ms


# ---------------------------- Конфигурация -----------------------------------

@dataclass(frozen=True)
class HeartbeatConfig:
    """
    Конфигурация детекции пропусков/флаппинга.

    expected_interval_ms: ожидаемый интервал пульсов для сущности (по умолчанию).
    late_multiplier: пульс считается "late", если задержка > late_multiplier * expected_interval_ms.
    miss_multiplier: отсутствие пульса дольше этого множителя => unhealthy.
    expire_multiplier: отсутствие пульса дольше этого множителя => expired (state удаляется).
    cooldown_seconds: минимальный интервал между событиями статуса (антидребезг).
    min_recovery_pulses: минимальное число подряд полученных пульсов для выхода из unhealthy.
    series_idle_ttl_seconds: время бездействия для TTL-эвикции серии.
    max_series: верхняя граница числа серий (LRU-эвикция при превышении).
    scan_period_ms: период фона для сканирования таймаутов.
    queue_maxsize: размер очереди асинхронного ingestion.
    """
    expected_interval_ms: int = 5000
    late_multiplier: float = 1.2
    miss_multiplier: float = 2.0
    expire_multiplier: float = 100.0
    cooldown_seconds: int = 30
    min_recovery_pulses: int = 2
    series_idle_ttl_seconds: int = 3600
    max_series: int = 50_000
    scan_period_ms: int = 1000
    queue_maxsize: int = 65536


# ------------------------------- Модели --------------------------------------

class HBStatus(str, Enum):
    healthy = "healthy"
    late = "late"
    unhealthy = "unhealthy"
    expired = "expired"  # логическое состояние, не публикуется как «в эфир» (серия удаляется)


@dataclass(frozen=True)
class Heartbeat:
    """
    Входной пульс.
    - series_key: идентификатор источника (узел/воркер/джоб/шард и т.д.)
    - emit_ts_ms: время на стороне эмиттера (может отсутствовать — тогда ставьте None)
    - recv_ts_ms: время приема на стороне коллектора (заполняется автоматически при ingest=None)
    - seq: необязательная монотонно растущая последовательность для защиты от дубликатов/реордеринга
    - payload: произвольный словарь тегов/атрибутов
    """
    series_key: str
    emit_ts_ms: Optional[int] = None
    recv_ts_ms: Optional[int] = None
    seq: Optional[int] = None
    payload: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class StatusEvent:
    """Событие изменения статуса для серии."""
    series_key: str
    prev: Optional[HBStatus]
    curr: HBStatus
    reason: str
    at_ms: int
    late_by_ms: int = 0
    stats: Dict[str, Any] = field(default_factory=dict)


class EventSink(Protocol):
    """Интерфейс публикации событий статуса."""
    def publish_status(self, event: StatusEvent) -> None: ...
    async def publish_status_async(self, event: StatusEvent) -> None: ...


class NullSink:
    def publish_status(self, event: StatusEvent) -> None:
        log.info("HB status change: series=%s %s->%s reason=%s late=%dms",
                 event.series_key, event.prev, event.curr, event.reason, event.late_by_ms)

    async def publish_status_async(self, event: StatusEvent) -> None:
        self.publish_status(event)


# --------------------------- EWMA / статистика --------------------------------

@dataclass(slots=True)
class _EWMA:
    alpha: float = 0.2
    value: float = 0.0
    initialized: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, sample: float) -> None:
        with self._lock:
            if not self.initialized:
                self.value = float(sample)
                self.initialized = True
            else:
                self.value = self.alpha * float(sample) + (1.0 - self.alpha) * self.value

    def get(self) -> float:
        with self._lock:
            return self.value if self.initialized else 0.0


# ---------------------------- Состояние серии ---------------------------------

@dataclass
class _SeriesState:
    key: str
    expected_interval_ms: int
    last_seen_ms: int
    last_seq: Optional[int] = None
    status: HBStatus = HBStatus.healthy
    status_since_ms: int = field(default_factory=_now_ms)
    cooldown_until_ms: int = 0
    misses: int = 0
    recovery_streak: int = 0
    arrival_ewma_ms: _EWMA = field(default_factory=lambda: _EWMA(alpha=0.2))
    jitter_ewma_ms: _EWMA = field(default_factory=lambda: _EWMA(alpha=0.2))
    net_delay_ewma_ms: _EWMA = field(default_factory=lambda: _EWMA(alpha=0.2))
    last_arrival_ms: Optional[int] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "expected_interval_ms": self.expected_interval_ms,
            "last_seen_ms": self.last_seen_ms,
            "status": self.status.value,
            "status_since_ms": self.status_since_ms,
            "misses": self.misses,
            "recovery_streak": self.recovery_streak,
            "arrival_ewma_ms": self.arrival_ewma_ms.get(),
            "jitter_ewma_ms": self.jitter_ewma_ms.get(),
            "net_delay_ewma_ms": self.net_delay_ewma_ms.get(),
            "last_arrival_ms": self.last_arrival_ms,
            "attributes": self.attributes,
        }


# ------------------------------ Коллектор ------------------------------------

class HeartbeatCollector:
    """
    Сборщик и детектор состояний для heartbeats.

    Быстрый путь (синхронный):
        hb = Heartbeat(series_key="node-1", emit_ts_ms=..., seq=123)
        collector.record(hb)

    Асинхронный ingestion:
        await collector.start()
        await collector.ingest(hb)
        ...
        await collector.stop()
    """

    def __init__(
        self,
        config: HeartbeatConfig | None = None,
        sink: EventSink | None = None,
        *,
        now_ms = _now_ms,
    ) -> None:
        self._cfg = config or HeartbeatConfig()
        self._sink = sink or NullSink()
        self._now = now_ms

        self._lock = threading.RLock()
        self._series: Dict[str, _SeriesState] = {}
        self._total_received = 0
        self._duplicates = 0
        self._late_count = 0
        self._unhealthy_count = 0
        self._evictions = 0

        # async machinery
        self._queue: asyncio.Queue[Heartbeat] = asyncio.Queue(maxsize=self._cfg.queue_maxsize)
        self._worker: Optional[asyncio.Task] = None
        self._scanner: Optional[asyncio.Task] = None
        self._stop_evt = asyncio.Event()

    # ------------------------ Публичные методы --------------------------------

    def record(self, hb: Heartbeat, *, expected_interval_ms: Optional[int] = None) -> HBStatus:
        """
        Синхронный прием пульса.
        Возвращает текущий статус серии после обработки.
        """
        recv_ms = hb.recv_ts_ms if hb.recv_ts_ms is not None else self._now()
        key = hb.series_key
        exp = int(expected_interval_ms or self._cfg.expected_interval_ms)

        with self._lock:
            st = self._series.get(key)
            if st is None:
                st = self._create_series(key, exp, recv_ms, attributes=hb.payload or {})
            # Защита от реордеринга/дубликатов (при наличии seq)
            if hb.seq is not None and st.last_seq is not None and hb.seq <= st.last_seq:
                self._duplicates += 1
                return st.status

            self._total_received += 1
            self._update_stats_on_heartbeat(st, hb, recv_ms)
            self._maybe_transition_on_arrival(st, recv_ms)

            # LRU/TTL эвикция по превышению max_series
            if len(self._series) > self._cfg.max_series:
                self._evict_lru()

            return st.status

    async def ingest(self, hb: Heartbeat, *, expected_interval_ms: Optional[int] = None) -> None:
        """
        Асинхронная постановка пульса в очередь. Параметр expected_interval_ms
        влияет только на новую серию (при первом пульсе).
        """
        # Кодируем ожидаемый интервал в payload атрибут для использования при create
        if expected_interval_ms is not None:
            payload = dict(hb.payload or {})
            payload["_expected_interval_ms"] = int(expected_interval_ms)
            hb = Heartbeat(**{**hb.__dict__, "payload": payload})
        await self._queue.put(hb)

    async def start(self) -> None:
        if self._worker or self._scanner:
            return
        self._stop_evt.clear()
        self._worker = asyncio.create_task(self._run_worker())
        self._scanner = asyncio.create_task(self._run_scanner())

    async def stop(self) -> None:
        if not (self._worker or self._scanner):
            return
        self._stop_evt.set()
        tasks = [t for t in (self._worker, self._scanner) if t]
        await asyncio.gather(*tasks, return_exceptions=True)
        self._worker = None
        self._scanner = None

    def export_metrics(self) -> Dict[str, Any]:
        """
        Возвращает снимок агрегированных метрик и состояния серий.
        Внимание: формат предназначен для внутреннего экспорта/диагностики.
        """
        with self._lock:
            now = self._now()
            states = {k: v.to_dict() for k, v in self._series.items()}
            status_counts: Dict[str, int] = {"healthy": 0, "late": 0, "unhealthy": 0}
            for v in self._series.values():
                if v.status in (HBStatus.healthy, HBStatus.late, HBStatus.unhealthy):
                    status_counts[v.status.value] += 1
            return {
                "now_ms": now,
                "series_total": len(self._series),
                "received_total": self._total_received,
                "duplicates_total": self._duplicates,
                "late_total": self._late_count,
                "unhealthy_total": self._unhealthy_count,
                "evictions_total": self._evictions,
                "status_counts": status_counts,
                "series": states,
            }

    # ------------------------ Внутренняя логика --------------------------------

    def _create_series(self, key: str, expected_interval_ms: int, recv_ms: int, *, attributes: Dict[str, Any]) -> _SeriesState:
        st = _SeriesState(
            key=key,
            expected_interval_ms=expected_interval_ms if expected_interval_ms > 0 else self._cfg.expected_interval_ms,
            last_seen_ms=recv_ms,
            status=HBStatus.healthy,
            status_since_ms=recv_ms,
            attributes={k: v for k, v in (attributes or {}).items() if not k.startswith("_")},
        )
        # возможно задан override в первом пульсе
        if attributes and "_expected_interval_ms" in attributes:
            try:
                st.expected_interval_ms = max(1, int(attributes["_expected_interval_ms"]))
            except Exception:
                pass
        self._series[key] = st
        return st

    def _update_stats_on_heartbeat(self, st: _SeriesState, hb: Heartbeat, recv_ms: int) -> None:
        # Последовательность
        if hb.seq is not None:
            st.last_seq = hb.seq

        # Inter-arrival и джиттер
        if st.last_arrival_ms is not None:
            inter = max(0, recv_ms - st.last_arrival_ms)
            prev_avg = st.arrival_ewma_ms.get()
            st.arrival_ewma_ms.add(inter)
            # |inter - avg| как оценка джиттера
            st.jitter_ewma_ms.add(abs(inter - (prev_avg if prev_avg > 0 else inter)))
        st.last_arrival_ms = recv_ms

        # Сетевая задержка (если эмиттер передал emit_ts_ms)
        if hb.emit_ts_ms is not None:
            net_delay = max(0, recv_ms - hb.emit_ts_ms)
            st.net_delay_ewma_ms.add(net_delay)

        # Обновление атрибутов (последний пульс может содержать runtime-теги)
        if hb.payload:
            for k, v in hb.payload.items():
                if not str(k).startswith("_"):
                    st.attributes[k] = v

        st.last_seen_ms = recv_ms
        st.recovery_streak += 1  # на каждый пульс увеличиваем; при пропусках обнуляется

    def _maybe_transition_on_arrival(self, st: _SeriesState, recv_ms: int) -> None:
        # Пришедший пульс — это шанс восстановиться из late/unhealthy
        if st.status in (HBStatus.unhealthy, HBStatus.late):
            if st.recovery_streak >= self._cfg.min_recovery_pulses:
                self._set_status(st, HBStatus.healthy, recv_ms, reason="recovered_on_heartbeat")
        else:
            # healthy: проверим, не был ли он «опоздавшим» (интервал > late_threshold)
            if st.arrival_ewma_ms.initialized:
                avg = st.arrival_ewma_ms.get()
                inter = max(0, recv_ms - (st.last_arrival_ms or recv_ms))
                # фактический интервал уже учтен выше; дополнительно сравним с ожидаемым порогом
                threshold = int(self._cfg.late_multiplier * st.expected_interval_ms)
                if inter > threshold and self._cooldown_passed(st, recv_ms):
                    self._late_count += 1
                    self._set_status(st, HBStatus.late, recv_ms, reason="late_arrival", late_by_ms=inter - threshold)

    def _cooldown_passed(self, st: _SeriesState, now_ms: int) -> bool:
        return now_ms >= st.cooldown_until_ms

    def _set_status(self, st: _SeriesState, new_status: HBStatus, now_ms: int, *, reason: str, late_by_ms: int = 0) -> None:
        if st.status == new_status and reason != "force":
            return
        prev = st.status
        st.status = new_status
        st.status_since_ms = now_ms
        st.cooldown_until_ms = now_ms + self._cfg.cooldown_seconds * 1000
        if new_status in (HBStatus.healthy, HBStatus.late):
            st.misses = 0
        if new_status == HBStatus.healthy:
            st.recovery_streak = 0  # начнем заново считать для следующего восстановления
        if new_status == HBStatus.unhealthy:
            self._unhealthy_count += 1
            st.recovery_streak = 0

        evt = StatusEvent(
            series_key=st.key,
            prev=prev,
            curr=new_status,
            reason=reason,
            at_ms=now_ms,
            late_by_ms=late_by_ms,
            stats={
                "arrival_ewma_ms": st.arrival_ewma_ms.get(),
                "jitter_ewma_ms": st.jitter_ewma_ms.get(),
                "net_delay_ewma_ms": st.net_delay_ewma_ms.get(),
                "expected_interval_ms": st.expected_interval_ms,
                "misses": st.misses,
            },
        )
        try:
            self._sink.publish_status(evt)
        except Exception as e:
            log.exception("sink.publish_status failed: %s", e)

    def _evict_lru(self) -> None:
        # Найдем самую старую по last_seen_ms серию и удалим
        oldest_key = None
        oldest_ts = 2**63 - 1
        for k, v in self._series.items():
            if v.last_seen_ms < oldest_ts:
                oldest_key, oldest_ts = k, v.last_seen_ms
        if oldest_key is not None:
            self._series.pop(oldest_key, None)
            self._evictions += 1
            log.debug("HeartbeatCollector LRU evicted series '%s'", oldest_key)

    # ----------------------------- Сканы/таймауты ------------------------------

    def _scan_timeouts_once(self, now_ms: Optional[int] = None) -> None:
        now = now_ms if now_ms is not None else self._now()
        expire_after = int(self._cfg.expire_multiplier * self._cfg.expected_interval_ms)
        idle_ttl_ms = max(60_000, self._cfg.series_idle_ttl_seconds * 1000)

        to_delete = []
        for st in list(self._series.values()):
            # Индивидуальные пороги для серии
            exp = max(1, st.expected_interval_ms)
            late_thr = int(self._cfg.late_multiplier * exp)
            miss_thr = int(self._cfg.miss_multiplier * exp)
            expire_thr = int(self._cfg.expire_multiplier * exp)

            silence = now - st.last_seen_ms

            # TTL-эвикция по длительному простою (независимо от expire_thr)
            if now - st.last_seen_ms > idle_ttl_ms:
                to_delete.append(st.key)
                continue

            # Переходы статуса по таймерам
            if silence >= expire_thr:
                to_delete.append(st.key)
                continue  # не генерируем отдельного события, серия исчезает

            if silence >= miss_thr and st.status != HBStatus.unhealthy and self._cooldown_passed(st, now):
                st.misses += 1
                self._set_status(st, HBStatus.unhealthy, now, reason="miss_threshold", late_by_ms=silence - miss_thr)
                continue

            if silence >= late_thr and st.status == HBStatus.healthy and self._cooldown_passed(st, now):
                self._late_count += 1
                self._set_status(st, HBStatus.late, now, reason="late_threshold", late_by_ms=silence - late_thr)
                continue

        for k in to_delete:
            self._series.pop(k, None)
            self._evictions += 1
            log.debug("HeartbeatCollector expired/TTL evicted series '%s'", k)

    # ------------------------------ Async loops --------------------------------

    async def _run_worker(self) -> None:
        log.info("HeartbeatCollector worker started")
        while not self._stop_evt.is_set():
            try:
                hb = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            try:
                recv_ms = hb.recv_ts_ms if hb.recv_ts_ms is not None else self._now()
                key = hb.series_key
                with self._lock:
                    st = self._series.get(key)
                    if st is None:
                        exp = int((hb.payload or {}).get("_expected_interval_ms", self._cfg.expected_interval_ms))
                        st = self._create_series(key, exp, recv_ms, attributes=hb.payload or {})
                    # защита от реордеринга
                    if hb.seq is not None and st.last_seq is not None and hb.seq <= st.last_seq:
                        self._duplicates += 1
                        continue
                    self._total_received += 1
                    self._update_stats_on_heartbeat(st, hb, recv_ms)
                    self._maybe_transition_on_arrival(st, recv_ms)
                    if len(self._series) > self._cfg.max_series:
                        self._evict_lru()
            except Exception as e:
                log.exception("processing heartbeat failed: %s", e)
        log.info("HeartbeatCollector worker stopped")

    async def _run_scanner(self) -> None:
        log.info("HeartbeatCollector scanner started")
        period = max(50, self._cfg.scan_period_ms) / 1000.0
        while not self._stop_evt.is_set():
            try:
                await asyncio.sleep(period)
                with self._lock:
                    self._scan_timeouts_once()
            except Exception as e:
                log.exception("scanner iteration failed: %s", e)
        log.info("HeartbeatCollector scanner stopped")
