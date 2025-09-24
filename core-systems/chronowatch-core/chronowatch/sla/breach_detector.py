"""
chronowatch.sla.breach_detector

Промышленная детекция нарушений SLA/SLO для ChronoWatch:

- Модель событий доставки: planned_ms (ожидалось), delivered_ms (фактическое),
  latency_ms = delivered_ms - planned_ms; breach := latency_ms > sla_ms.
- Скользящие окна на основе минутных бакетов: суммирование good/bad по окнам
  с длиной N минут. Поддержка нескольких окон (multi-window).
- Поддержка SLO target ∈ (0,1], error budget = 1 - target; burn rate
  = error_rate / error_budget. Сравнение с порогами burn_threshold для окна.
- Гистограммы латентности (экспоненциальные границы).
- Высокая кардинальность: агрегаторы на ключ (series_key) с TTL-эвикцией.
- Асинхронный ingestion (asyncio.Queue) + синхронный API для hot-path.
- Интеграционные хуки через EventSink (например, публикация в Kafka/NATS/лог).
- Потокобезопасность: GIL + asyncio; доступ к общим структурам через lock.
- Никаких внешних зависимостей, только stdlib.

Единицы времени: миллисекунды (ms) для совместимости с остальными компонентами.
"""

from __future__ import annotations

import asyncio
import bisect
import dataclasses
import logging
import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Deque, Dict, Iterable, List, Optional, Protocol, Tuple

log = logging.getLogger("chronowatch.sla.breach_detector")


# =========================
# Конфигурация и модели
# =========================

@dataclass(frozen=True)
class WindowPolicy:
    """Параметры окна для burn-rate алертов."""
    name: str                 # например: "5m", "30m", "6h"
    length_minutes: int       # длина окна в минутах
    min_events: int           # минимальное кол-во событий для срабатывания
    burn_threshold: float     # порог burn rate, например 14.4, 6.0, 3.0
    cooldown_seconds: int = 300  # антидребезг: не чаще одного алерта в N секунд


@dataclass(frozen=True)
class SLAConfig:
    """SLA/SLO конфигурация."""
    name: str
    sla_ms: int               # SLA на доставку/завершение
    target_slo: float         # доля успешных, например 0.99, 0.999
    windows: Tuple[WindowPolicy, ...]
    histo_bounds_ms: Tuple[int, ...] = (
        1, 2, 5, 10, 20, 50,
        100, 200, 500, 1000, 2000, 5000,
        10_000, 20_000, 50_000, 100_000
    )  # экспоненциальные границы для гистограммы


@dataclass(frozen=True)
class DeliveryEvent:
    """Событие доставки триггера/работы."""
    series_key: str          # ключ серии (например schedule_id или owner)
    planned_ms: int          # ожидаемое время
    delivered_ms: int        # фактическое время
    sla_ms: Optional[int] = None  # локальный override SLA (если не задан, берем из SLAConfig)


@dataclass(frozen=True)
class BreachEvent:
    """Событие нарушения SLO по окну."""
    series_key: str
    config_name: str
    window_name: str
    window_minutes: int
    burn_rate: float
    error_rate: float
    good: int
    bad: int
    total: int
    threshold: float
    first_ts_ms: int
    last_ts_ms: int
    fired_at_ms: int


class EventSink(Protocol):
    """Интерфейс публикации алертов и метрик."""
    def publish_breach(self, event: BreachEvent) -> None: ...
    async def publish_breach_async(self, event: BreachEvent) -> None: ...


class NullSink:
    def publish_breach(self, event: BreachEvent) -> None:
        log.warning(
            "BREACH %s[%s] burn=%.3f thr=%.3f err=%.5f total=%d bad=%d",
            event.series_key, event.window_name, event.burn_rate,
            event.threshold, event.error_rate, event.total, event.bad
        )
    async def publish_breach_async(self, event: BreachEvent) -> None:
        self.publish_breach(event)


# =========================
# Вспомогательные структуры
# =========================

@dataclass
class Bucket:
    start_minute_ms: int
    good: int = 0
    bad: int = 0
    counts: List[int] = field(default_factory=list)  # гистограмма по границам


class RollingCounters:
    """
    Массив минутных бакетов в пределах максимального окна.
    Обновляется на каждое событие; предоставляет суммарные good/bad по окнам.
    """
    __slots__ = ("bucket_ms", "max_buckets", "buckets", "bounds", "_index")

    def __init__(self, *, bucket_ms: int, max_window_minutes: int, histo_bounds_ms: Iterable[int]) -> None:
        self.bucket_ms = bucket_ms
        self.max_buckets = max(1, (max_window_minutes * 60_000) // bucket_ms + 2)
        self.bounds = tuple(sorted(histo_bounds_ms))
        self.buckets: Deque[Bucket] = deque(maxlen=self.max_buckets)
        self._index: Dict[int, Bucket] = {}

    def _align_minute(self, ts_ms: int) -> int:
        return (ts_ms // 60_000) * 60_000

    def _get_or_create(self, minute_ms: int) -> Bucket:
        b = self._index.get(minute_ms)
        if b is not None:
            return b
        b = Bucket(start_minute_ms=minute_ms, counts=[0] * (len(self.bounds) + 1))
        self.buckets.append(b)
        self._index[minute_ms] = b
        # Эвикция вышедших из окна
        while len(self.buckets) > self.max_buckets:
            old = self.buckets.popleft()
            self._index.pop(old.start_minute_ms, None)
        return b

    def add(self, ts_ms: int, latency_ms: int, breached: bool) -> None:
        minute = self._align_minute(ts_ms)
        b = self._get_or_create(minute)
        if breached:
            b.bad += 1
        else:
            b.good += 1
        # histogram bucket
        idx = bisect.bisect_right(self.bounds, latency_ms)
        b.counts[idx] += 1

    def summarize(self, now_ms: int, length_minutes: int) -> Tuple[int, int, int, int, int]:
        """
        Возвращает (good, bad, total, first_ts_ms, last_ts_ms) за окно length_minutes до now_ms.
        """
        if not self.buckets:
            return (0, 0, 0, now_ms, now_ms)
        window_start = self._align_minute(now_ms) - (length_minutes * 60_000)
        good = bad = 0
        first = None
        last = None
        for b in self.buckets:
            if b.start_minute_ms > window_start:
                good += b.good
                bad += b.bad
                first = b.start_minute_ms if first is None else min(first, b.start_minute_ms)
                last = b.start_minute_ms
        total = good + bad
        if first is None:
            first = window_start
            last = self._align_minute(now_ms)
        return good, bad, total, first, last

    def snapshot_histogram(self) -> List[Tuple[int, int]]:
        """
        Сумма гистограмм по всем бакетам текущего окна хранения.
        Возвращает список (upper_bound_ms_or_inf, count).
        """
        if not self.buckets:
            return [(b, 0) for b in self.bounds] + [(math.inf, 0)]
        sum_counts = [0] * (len(self.bounds) + 1)
        for b in self.buckets:
            for i, v in enumerate(b.counts):
                sum_counts[i] += v
        res: List[Tuple[int, int]] = []
        for i, ub in enumerate(self.bounds):
            res.append((ub, sum_counts[i]))
        res.append((math.inf, sum_counts[-1]))
        return res


@dataclass
class SeriesAggregator:
    """
    Агрегатор для одной серии (series_key).
    Хранит скользящие счетчики и состояние cooldown по окнам.
    """
    config: SLAConfig
    rolling: RollingCounters
    last_seen_ms: int
    cooldown_until: Dict[str, int] = field(default_factory=dict)  # window_name -> ts_ms


# =========================
# Основной детектор
# =========================

class SLABreachDetector:
    """
    Детектор SLA/SLO нарушений для событий доставки.

    Использование (синхронный путь):
        detector = SLABreachDetector(default_config=cfg)
        detector.record_delivery(DeliveryEvent(...))

    Использование (асинхронный ingestion):
        await detector.start()
        await detector.ingest(event)
        ...
        await detector.stop()
    """

    def __init__(
        self,
        *,
        default_config: SLAConfig,
        sink: Optional[EventSink] = None,
        max_series: int = 10000,
        series_idle_ttl_seconds: int = 3600,
        bucket_ms: int = 60_000,
        clock: Optional[callable] = None,  # функция now_ms()
    ) -> None:
        self._default_config = default_config
        self._sink: EventSink = sink or NullSink()
        self._max_series = max(100, max_series)
        self._idle_ttl = max(60, series_idle_ttl_seconds) * 1000
        self._bucket_ms = bucket_ms
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._series: Dict[str, SeriesAggregator] = {}
        self._lock = threading.RLock()

        # async ingestion
        self._queue: asyncio.Queue[DeliveryEvent] = asyncio.Queue(maxsize=65536)
        self._worker: Optional[asyncio.Task] = None
        self._stop_evt = asyncio.Event()

        # Метрики уровня детектора
        self._total_events = 0
        self._total_breaches = 0
        self._evictions = 0

        # Подготовка max длины окна для хранения
        self._max_window_minutes = max(w.length_minutes for w in default_config.windows)

    # ---------- Публичный API ----------

    def record_delivery(self, ev: DeliveryEvent, *, config: Optional[SLAConfig] = None) -> Tuple[bool, int]:
        """
        Синхронная обработка события доставки.
        Возвращает (breached, latency_ms).
        """
        cfg = config or self._default_config
        now_ms = self._clock()
        latency_ms = max(0, ev.delivered_ms - ev.planned_ms)
        sla_ms = cfg.sla_ms if ev.sla_ms is None else int(ev.sla_ms)
        breached = latency_ms > sla_ms

        with self._lock:
            self._total_events += 1
            if breached:
                self._total_breaches += 1

            agg = self._get_or_create_series(ev.series_key, cfg, now_ms)
            agg.last_seen_ms = now_ms
            agg.rolling.add(ts_ms=ev.delivered_ms, latency_ms=latency_ms, breached=breached)

            # Оценка окон и потенциальная генерация алертов
            self._evaluate_windows(ev.series_key, agg, now_ms)

            # Периодическая эвикция по TTL/лимиту
            self._maybe_evict(now_ms)

        return breached, latency_ms

    async def ingest(self, ev: DeliveryEvent, *, config: Optional[SLAConfig] = None) -> None:
        """
        Асинхронная постановка события в очередь обработки.
        Конфигурация на событие не сериализуется, используйте global default или
        заранее настройте пер-сериес конфигурации через map (не реализовано здесь).
        """
        await self._queue.put(ev)

    async def start(self) -> None:
        if self._worker is not None:
            return
        self._stop_evt.clear()
        self._worker = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._worker is None:
            return
        self._stop_evt.set()
        await self._worker
        self._worker = None

    # ---------- Вспомогательные методы ----------

    def _get_or_create_series(self, key: str, cfg: SLAConfig, now_ms: int) -> SeriesAggregator:
        agg = self._series.get(key)
        if agg is not None:
            return agg
        rolling = RollingCounters(
            bucket_ms=self._bucket_ms,
            max_window_minutes=self._max_window_minutes,
            histo_bounds_ms=cfg.histo_bounds_ms,
        )
        agg = SeriesAggregator(config=cfg, rolling=rolling, last_seen_ms=now_ms)
        self._series[key] = agg
        # Если превысили лимит серий, эвиктнем самые старые
        if len(self._series) > self._max_series:
            self._evict_lru()
        return agg

    def _evict_lru(self) -> None:
        # Эвикция одного самого старого агрегатора
        oldest_key = None
        oldest_ts = 2**63 - 1
        for k, v in self._series.items():
            if v.last_seen_ms < oldest_ts:
                oldest_key = k
                oldest_ts = v.last_seen_ms
        if oldest_key is not None:
            self._series.pop(oldest_key, None)
            self._evictions += 1
            log.debug("Evicted series '%s' (LRU)", oldest_key)

    def _maybe_evict(self, now_ms: int) -> None:
        # TTL-эвикция всех серий, не виденных более idle_ttl
        to_delete: List[str] = []
        for k, v in self._series.items():
            if now_ms - v.last_seen_ms > self._idle_ttl:
                to_delete.append(k)
        for k in to_delete:
            self._series.pop(k, None)
            self._evictions += 1
            log.debug("Evicted series '%s' (idle TTL)", k)

    def _evaluate_windows(self, series_key: str, agg: SeriesAggregator, now_ms: int) -> None:
        cfg = agg.config
        error_budget = max(1e-9, 1.0 - float(cfg.target_slo))
        for w in cfg.windows:
            good, bad, total, first_ts, last_ts = agg.rolling.summarize(now_ms, w.length_minutes)
            if total < max(1, w.min_events):
                continue
            error_rate = bad / total
            burn_rate = error_rate / error_budget
            if burn_rate >= w.burn_threshold:
                # cooldown check
                until = agg.cooldown_until.get(w.name, 0)
                if now_ms >= until:
                    agg.cooldown_until[w.name] = now_ms + w.cooldown_seconds * 1000
                    evt = BreachEvent(
                        series_key=series_key,
                        config_name=cfg.name,
                        window_name=w.name,
                        window_minutes=w.length_minutes,
                        burn_rate=burn_rate,
                        error_rate=error_rate,
                        good=good,
                        bad=bad,
                        total=total,
                        threshold=w.burn_threshold,
                        first_ts_ms=first_ts,
                        last_ts_ms=last_ts,
                        fired_at_ms=now_ms,
                    )
                    # синхронная публикация (без await) для минимальной задержки
                    try:
                        self._sink.publish_breach(evt)
                    except Exception as e:
                        log.exception("sink.publish_breach failed: %s", e)

    async def _run(self) -> None:
        """
        Асинхронный воркер: извлекает события из очереди и обрабатывает их.
        """
        log.info("SLABreachDetector worker started")
        while not self._stop_evt.is_set():
            try:
                ev: DeliveryEvent = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            try:
                breached, latency = self.record_delivery(ev)
                # Дополнительно, если sink поддерживает async-публикацию и хотим симметрии — нет оповещения здесь.
            except Exception as e:
                log.exception("record_delivery failed: %s", e)
        log.info("SLABreachDetector worker stopped")

    # ---------- Метрики / снимки состояния ----------

    def export_metrics(self) -> Dict[str, Any]:
        """
        Снимок агрегированных метрик детектора и гистограмм по сериям.
        Не постоянный формат — под Prometheus адаптируйте экспортер.
        """
        with self._lock:
            out: Dict[str, Any] = {
                "total_events": self._total_events,
                "total_breaches": self._total_breaches,
                "series_count": len(self._series),
                "evictions": self._evictions,
                "series": {},
            }
            now_ms = self._clock()
            for k, agg in self._series.items():
                series_item = {
                    "last_seen_ms": agg.last_seen_ms,
                    "histogram": agg.rolling.snapshot_histogram(),
                    "windows": {},
                }
                for w in agg.config.windows:
                    g, b, t, first, last = agg.rolling.summarize(now_ms, w.length_minutes)
                    series_item["windows"][w.name] = {
                        "good": g, "bad": b, "total": t, "first_ms": first, "last_ms": last
                    }
                out["series"][k] = series_item
            return out


# =========================
# Пример конфигурации и локальный запуск
# =========================

DEFAULT_WINDOWS = (
    # Классическая multi-window стратегия (пример):
    # - быстрое обнаружение сильного прогорания бюджета
    WindowPolicy(name="5m", length_minutes=5, min_events=50, burn_threshold=14.4, cooldown_seconds=120),
    # - среднесрочное
    WindowPolicy(name="30m", length_minutes=30, min_events=300, burn_threshold=6.0, cooldown_seconds=300),
    # - долгосрочное
    WindowPolicy(name="6h", length_minutes=360, min_events=3600, burn_threshold=3.0, cooldown_seconds=900),
)

DEFAULT_CONFIG = SLAConfig(
    name="delivery-latency",
    sla_ms=1000,          # SLA на доставку триггера 1s
    target_slo=0.999,     # 99.9% должны укладываться в SLA
    windows=DEFAULT_WINDOWS,
)


# =========================
# Мини-демо
# =========================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    det = SLABreachDetector(default_config=DEFAULT_CONFIG)

    now = int(time.time() * 1000)
    key = "schedule:demo"

    # Сгенерируем 1000 событий за ~5 минут с 2% нарушений
    import random
    random.seed(7)

    for i in range(1000):
        planned = now + i * 300  # каждые 300ms
        # 98% — 100..800ms, 2% — 1500..5000ms
        if random.random() < 0.98:
            lat = random.randint(100, 800)
        else:
            lat = random.randint(1500, 5000)
        ev = DeliveryEvent(series_key=key, planned_ms=planned, delivered_ms=planned + lat)
        det.record_delivery(ev)

    snap = det.export_metrics()
    log.info("snapshot: series=%d total=%d bad=%d",
             len(snap["series"]), snap["total_events"], snap["total_breaches"])
