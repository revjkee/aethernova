# security-core/security/threat_detection/anomaly.py
from __future__ import annotations

import bisect
import collections
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union

try:
    # Опционально для многомерной детекции
    import numpy as _np  # type: ignore
    _HAVE_NUMPY = True
except Exception:  # pragma: no cover
    _HAVE_NUMPY = False  # type: ignore


# ============================ Типы домена ============================

Timestamp = int


@dataclass(frozen=True)
class Event:
    """
    Универсальное событие для детекции.
    """
    ts: Timestamp
    tenant: str
    metric: str              # имя метрики: "auth.latency_ms", "http.rps", "kms.sign.fail_ratio" и т.п.
    value: Optional[float] = None   # числовая величина (для univariate/частотных детекторов)
    vector: Optional[Sequence[float]] = None  # многомерный признак (для Mahalanobis), d>=2
    category: Optional[str] = None  # для редких категорий/последовательностей
    entity_key: Optional[str] = None  # ключ сущности: ip, subject, client_id, route и т.д.
    attrs: Mapping[str, Any] = field(default_factory=dict)  # доп. атрибуты (для лога/метрик)


@dataclass(frozen=True)
class Alert:
    """
    Стандартизированный алерт от детектора.
    """
    ts: Timestamp
    tenant: str
    metric: str
    entity_key: Optional[str]
    detector: str
    score: float
    threshold: float
    severity: str  # low | medium | high | critical
    reason: str
    details: Mapping[str, Any] = field(default_factory=dict)


# ============================ Базовые утилиты ============================

class _TTLCache:
    def __init__(self, ttl_s: int, max_entries: int = 10000) -> None:
        self.ttl = ttl_s
        self.max = max_entries
        self._lock = threading.RLock()
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, k: str) -> Optional[Any]:
        with self._lock:
            it = self._store.get(k)
            if not it:
                return None
            ts, v = it
            if time.time() - ts > self.ttl:
                self._store.pop(k, None)
                return None
            return v

    def set(self, k: str, v: Any) -> None:
        with self._lock:
            if len(self._store) >= self.max:
                items = sorted(self._store.items(), key=lambda kv: kv[1][0])
                for kk, _ in items[: max(1, len(items) // 10)]:
                    self._store.pop(kk, None)
            self._store[k] = (time.time(), v)


def _now_s() -> int:
    return int(time.time())


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _severity_from_score(z: float) -> str:
    # Простейшая шкала важности по z-оценке/дистанции
    if z >= 6.0:
        return "critical"
    if z >= 4.0:
        return "high"
    if z >= 3.0:
        return "medium"
    return "low"


# ============================ Интерфейс детектора ============================

class Detector(Protocol):
    name: str

    def update(self, evt: Event) -> Optional[Alert]:
        """
        Обновляет внутреннее состояние детектора событием и, при необходимости,
        возвращает алерт. Возвращает None, если аномалии нет.
        """
        ...


# ============================ EWMA Z-score (онлайн, эксп. затухание) ============================

class _DecayedWelford:
    """
    Онлайн-оценка среднего и дисперсии с экспоненциальным затуханием.
    При alpha в (0,1]: чем больше alpha, тем быстрее забываем прошлое.
    """
    __slots__ = ("alpha", "w", "mean", "s", "n")

    def __init__(self, alpha: float) -> None:
        self.alpha = float(alpha)
        self.w = 0.0
        self.mean = 0.0
        self.s = 0.0   # 'S' для дисперсии
        self.n = 0

    def add(self, x: float) -> None:
        self.n += 1
        if self.w <= 0.0:
            self.w = 1.0
            self.mean = x
            self.s = 0.0
            return
        # Эффективный вес с распадом
        lam = 1.0 - self.alpha
        self.w = lam * self.w + 1.0
        delta = x - self.mean
        self.mean += delta / self.w
        self.s = lam * self.s + delta * (x - self.mean)

    @property
    def var(self) -> float:
        return self.s / max(self.w, 1.0)

    @property
    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))


@dataclass
class EWMAZScoreConfig:
    alpha: float = 0.1            # скорость забывания
    threshold: float = 4.0        # порог по |z|
    min_samples: int = 20         # минимум наблюдений перед сигналом
    min_std: float = 1e-6         # защита от деления на ноль


class EWMAZScore(Detector):
    """
    Унивариантный детектор: |z| = |x-μ|/σ с экспоненциально затухающей оценкой μ,σ.
    Ключевание по (tenant, metric, entity_key).
    """
    name = "ewma_zscore"

    def __init__(self, cfg: Optional[EWMAZScoreConfig] = None) -> None:
        self.cfg = cfg or EWMAZScoreConfig()
        self._stats: Dict[Tuple[str, str, Optional[str]], _DecayedWelford] = {}

    def update(self, evt: Event) -> Optional[Alert]:
        if evt.value is None:
            return None
        key = (evt.tenant, evt.metric, evt.entity_key)
        st = self._stats.get(key)
        if st is None:
            st = _DecayedWelford(self.cfg.alpha)
            self._stats[key] = st

        st.add(float(evt.value))
        if st.n < self.cfg.min_samples:
            return None

        std = max(st.std, self.cfg.min_std)
        z = (evt.value - st.mean) / std
        if abs(z) >= self.cfg.threshold:
            return Alert(
                ts=evt.ts,
                tenant=evt.tenant,
                metric=evt.metric,
                entity_key=evt.entity_key,
                detector=self.name,
                score=float(abs(z)),
                threshold=self.cfg.threshold,
                severity=_severity_from_score(abs(z)),
                reason="ewma_zscore_threshold_exceeded",
                details={"value": evt.value, "mean": st.mean, "std": std, "z": z},
            )
        return None


# ============================ Rolling MAD (робастный) ============================

class _RollingOrderStats:
    """
    Окно фиксированного размера с поддержкой rolling медианы и MAD через отсортированный список.
    Операции O(log n) на вставку/удаление, O(1) на медиану.
    """
    def __init__(self, window: int) -> None:
        self.win = int(window)
        self._data: Deque[float] = collections.deque()
        self._sorted: List[float] = []

    def push(self, x: float) -> None:
        self._data.append(x)
        bisect.insort(self._sorted, x)
        if len(self._data) > self.win:
            old = self._data.popleft()
            idx = bisect.bisect_left(self._sorted, old)
            if 0 <= idx < len(self._sorted) and self._sorted[idx] == old:
                self._sorted.pop(idx)

    def median(self) -> float:
        n = len(self._sorted)
        if n == 0:
            return 0.0
        if n % 2 == 1:
            return self._sorted[n // 2]
        return 0.5 * (self._sorted[n // 2 - 1] + self._sorted[n // 2])

    def mad(self, med: Optional[float] = None) -> float:
        """
        Median Absolute Deviation. Вычисляем на копии окна (O(n)).
        Нормировка 1.4826 для аппроксимации σ при нормальном распределении.
        """
        if not self._sorted:
            return 0.0
        m = self.median() if med is None else med
        abs_dev = [abs(x - m) for x in self._sorted]
        n = len(abs_dev)
        abs_dev.sort()
        if n % 2 == 1:
            mad = abs_dev[n // 2]
        else:
            mad = 0.5 * (abs_dev[n // 2 - 1] + abs_dev[n // 2])
        return 1.4826 * mad  # прибл. σ


@dataclass
class RollingMADConfig:
    window: int = 512
    threshold: float = 6.0    # |(x - median)| / MAD
    min_warmup: int = 64
    min_mad: float = 1e-6


class RollingMAD(Detector):
    """
    Робастный унивариантный детектор по медиане и MAD в скользящем окне.
    Устойчив к выбросам и дрейфу.
    """
    name = "rolling_mad"

    def __init__(self, cfg: Optional[RollingMADConfig] = None) -> None:
        self.cfg = cfg or RollingMADConfig()
        self._store: Dict[Tuple[str, str, Optional[str]], _RollingOrderStats] = {}

    def update(self, evt: Event) -> Optional[Alert]:
        if evt.value is None:
            return None
        key = (evt.tenant, evt.metric, evt.entity_key)
        st = self._store.get(key)
        if st is None:
            st = _RollingOrderStats(self.cfg.window)
            self._store[key] = st
        st.push(float(evt.value))

        # warmup
        if len(st._sorted) < self.cfg.min_warmup:
            return None

        med = st.median()
        mad = max(st.mad(med), self.cfg.min_mad)
        score = abs(float(evt.value) - med) / mad
        if score >= self.cfg.threshold:
            return Alert(
                ts=evt.ts,
                tenant=evt.tenant,
                metric=evt.metric,
                entity_key=evt.entity_key,
                detector=self.name,
                score=score,
                threshold=self.cfg.threshold,
                severity=_severity_from_score(score),
                reason="rolling_mad_threshold_exceeded",
                details={"value": evt.value, "median": med, "mad": mad},
            )
        return None


# ============================ Многомерный Mahalanobis (опц. numpy) ============================

@dataclass
class MahalanobisConfig:
    alpha: float = 0.05          # скорость забывания
    threshold: float = 25.0      # порог по квадрату расстояния (хи-квадрат ~d.f.=d)
    min_samples: int = 50
    ridge: float = 1e-3          # регуляризация на диагонали


class Mahalanobis(Detector):
    """
    Экспоненциально затухающие оценки μ и ковариации; расстояние Махаланобиса.
    Требует numpy. Если numpy отсутствует, детектор неактивен.
    """
    name = "mahalanobis"

    def __init__(self, cfg: Optional[MahalanobisConfig] = None) -> None:
        self.cfg = cfg or MahalanobisConfig()
        self._mu: Dict[Tuple[str, str, Optional[str]], Any] = {}
        self._cov: Dict[Tuple[str, str, Optional[str]], Any] = {}
        self._n: Dict[Tuple[str, str, Optional[str]], int] = {}
        self._inv: Dict[Tuple[str, str, Optional[str]], Any] = {}

    def update(self, evt: Event) -> Optional[Alert]:
        if not _HAVE_NUMPY or evt.vector is None:
            return None
        key = (evt.tenant, evt.metric, evt.entity_key)
        x = _np.asarray(evt.vector, dtype=float).reshape(-1, 1)  # d x 1
        d = x.shape[0]

        mu = self._mu.get(key)
        cov = self._cov.get(key)
        n = self._n.get(key, 0)
        alpha = float(self.cfg.alpha)

        if mu is None:
            mu = x
            cov = _np.eye(d)
            self._mu[key] = mu
            self._cov[key] = cov
            self._n[key] = 1
            return None

        # Экспоненциально затухающая оценка
        prev_mu = mu
        mu = (1 - alpha) * mu + alpha * x
        xc = x - prev_mu
        cov = (1 - alpha) * cov + alpha * (xc @ xc.T)

        self._mu[key] = mu
        self._cov[key] = cov
        self._n[key] = n + 1

        if self._n[key] < self.cfg.min_samples:
            return None

        # Инверсия ковариации с регуляризацией
        cov_r = cov + self.cfg.ridge * _np.eye(d)
        try:
            inv = _np.linalg.inv(cov_r)
        except Exception:
            inv = _np.linalg.pinv(cov_r)
        self._inv[key] = inv

        delta = (x - mu).T  # 1 x d
        dist2 = float(delta @ inv @ delta.T)  # скаляр
        if dist2 >= self.cfg.threshold:
            # В качестве "score" используем sqrt(dist2) для сопоставимости с z
            score = math.sqrt(dist2)
            return Alert(
                ts=evt.ts,
                tenant=evt.tenant,
                metric=evt.metric,
                entity_key=evt.entity_key,
                detector=self.name,
                score=score,
                threshold=math.sqrt(self.cfg.threshold),
                severity=_severity_from_score(score),
                reason="mahalanobis_threshold_exceeded",
                details={"dist2": dist2, "dim": d},
            )
        return None


# ============================ Частотные всплески (Rate Spike) ============================

@dataclass
class RateSpikeConfig:
    bucket_s: int = 1           # ширина временного бакета
    baseline_alpha: float = 0.2 # EWMA для baseline
    threshold: float = 5.0      # порог по z-скор для счетчика
    min_count: int = 10         # минимальное число событий в бакете для сигнала
    window_buckets: int = 300   # хранить не более N бакетов в памяти


class RateSpike(Detector):
    """
    Детектор всплесков частоты (события без value, считаем штуки/бакет).
    Ключевание по (tenant, metric, entity_key).
    """
    name = "rate_spike"

    def __init__(self, cfg: Optional[RateSpikeConfig] = None) -> None:
        self.cfg = cfg or RateSpikeConfig()
        self._counts: Dict[Tuple[str, str, Optional[str]], Dict[int, int]] = {}
        self._stat: Dict[Tuple[str, str, Optional[str]], _DecayedWelford] = {}

    def update(self, evt: Event) -> Optional[Alert]:
        key = (evt.tenant, evt.metric, evt.entity_key)
        bucket = (evt.ts // self.cfg.bucket_s) * self.cfg.bucket_s
        cdict = self._counts.setdefault(key, {})
        cdict[bucket] = cdict.get(bucket, 0) + 1

        # Прореживание истории
        if len(cdict) > self.cfg.window_buckets:
            oldest = sorted(cdict.keys())[: max(1, len(cdict) - self.cfg.window_buckets)]
            for k in oldest:
                cdict.pop(k, None)

        # Обновляем baseline только на закрытых бакетах (предыдущий)
        prev_b = bucket - self.cfg.bucket_s
        if prev_b in cdict:
            cnt = cdict[prev_b]
            st = self._stat.get(key)
            if st is None:
                st = _DecayedWelford(self.cfg.baseline_alpha)
                self._stat[key] = st
            st.add(float(cnt))
            if cnt >= self.cfg.min_count and st.n >= 10:
                std = max(st.std, 1e-6)
                z = (cnt - st.mean) / std
                if z >= self.cfg.threshold:
                    return Alert(
                        ts=evt.ts,
                        tenant=evt.tenant,
                        metric=evt.metric,
                        entity_key=evt.entity_key,
                        detector=self.name,
                        score=float(z),
                        threshold=self.cfg.threshold,
                        severity=_severity_from_score(z),
                        reason="rate_spike_threshold_exceeded",
                        details={"bucket_start": prev_b, "count": cnt, "baseline_mean": st.mean, "baseline_std": std},
                    )
        return None


# ============================ Роутер алертов: дедуп и cooldown ============================

@dataclass
class RouterConfig:
    cooldown_s: int = 60
    dedup_ttl_s: int = 300
    max_alerts_per_minute: int = 2000  # защитный лимит вывода


class AlertRouter:
    """
    На вход получает алерты от детекторов, выполняет suppression:
    - cooldown per (tenant, metric, entity_key, detector, reason)
    - дедупликация (TTL)
    """
    def __init__(
        self,
        cfg: Optional[RouterConfig] = None,
        sink: Optional[Callable[[Alert], None]] = None,
        metrics_hook: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
    ) -> None:
        self.cfg = cfg or RouterConfig()
        self.sink = sink
        self.metrics = metrics_hook
        self._cooldown = _TTLCache(self.cfg.cooldown_s, 20000)
        self._dedup = _TTLCache(self.cfg.dedup_ttl_s, 50000)
        self._lock = threading.RLock()
        self._counter_minute = 0
        self._window_start = _now_s()

    def _metric(self, name: str, tags: Mapping[str, Any]) -> None:
        try:
            if self.metrics:
                self.metrics(name, tags)
        except Exception:
            pass

    def _rate_limit_ok(self) -> bool:
        now = _now_s()
        if now - self._window_start >= 60:
            self._window_start = now
            self._counter_minute = 0
        if self._counter_minute >= self.cfg.max_alerts_per_minute:
            return False
        self._counter_minute += 1
        return True

    def emit(self, alert: Alert) -> Optional[Alert]:
        key = f"{alert.tenant}|{alert.metric}|{alert.entity_key}|{alert.detector}|{alert.reason}"
        if self._cooldown.get(key) is not None:
            # в cooldown
            return None
        if self._dedup.get(key) is not None:
            # дубликат за TTL
            return None

        if not self._rate_limit_ok():
            self._metric("anomaly_alert_dropped_ratelimit", {"tenant": alert.tenant, "metric": alert.metric})
            return None

        self._cooldown.set(key, True)
        self._dedup.set(key, True)
        try:
            if self.sink:
                self.sink(alert)
        finally:
            self._metric("anomaly_alert_emitted", {"tenant": alert.tenant, "metric": alert.metric, "detector": alert.detector, "severity": alert.severity})
        return alert


# ============================ Движок: оркестрация детекторов ============================

@dataclass
class EngineConfig:
    detectors: Sequence[Detector] = field(default_factory=lambda: (EWMAZScore(), RollingMAD(), Mahalanobis() if _HAVE_NUMPY else EWMAZScore(EWMAZScoreConfig(alpha=0.2, threshold=5.0)), RateSpike()))
    router: Optional[AlertRouter] = None


class AnomalyEngine:
    """
    Высокоуровневый движок:
      engine = AnomalyEngine()
      engine.process(event) -> Optional[Alert]
    """
    def __init__(self, cfg: Optional[EngineConfig] = None) -> None:
        self.cfg = cfg or EngineConfig()
        self.router = cfg.router or AlertRouter()

    def process(self, evt: Event) -> List[Alert]:
        alerts: List[Alert] = []
        for det in self.cfg.detectors:
            try:
                a = det.update(evt)
                if a:
                    out = self.router.emit(a)
                    if out:
                        alerts.append(out)
            except Exception as e:  # защита от падений конкретного детектора
                # Молча игнорируем, в проде можно добавить логгер/метрики
                self.router._metric("anomaly_detector_error", {"detector": getattr(det, "name", "unknown"), "metric": evt.metric, "tenant": evt.tenant, "err": type(e).__name__})
        return alerts


# ============================ Пример использования (док) ============================

"""
Пример (псевдокод):
    router = AlertRouter(sink=lambda a: print("ALERT:", a))
    engine = AnomalyEngine(EngineConfig(router=router))

    # Унивариантные значения
    engine.process(Event(ts=int(time.time()), tenant="t1", metric="auth.latency_ms", value=123.0, entity_key="route:/login"))
    ...
    # Частотные события (счетчик)
    engine.process(Event(ts=int(time.time()), tenant="t1", metric="http.requests", entity_key="ip:10.0.0.5"))
    ...
    # Многомерные признаки (если установлен numpy)
    engine.process(Event(ts=int(time.time()), tenant="t1", metric="auth.multi", vector=[latency_ms, response_size, sql_ms], entity_key="user:alice"))
"""
