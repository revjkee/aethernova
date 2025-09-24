# physical_integration/telemetry/aggregators.py
# Python 3.10+
from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

# =============================================================================
# Public data structures
# =============================================================================

@dataclass(frozen=True)
class SeriesPoint:
    """
    Единичная точка временного ряда.
    values: произвольный набор метрических полей (только float).
    """
    ts: datetime
    values: Mapping[str, float]

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            raise ValueError("SeriesPoint.ts must be timezone-aware")
        for k, v in self.values.items():
            if not isinstance(v, (int, float)) or isinstance(v, bool) or math.isnan(float(v)):
                raise ValueError(f"Invalid numeric value for field '{k}'")

@dataclass(frozen=True)
class AggregatedPoint:
    """
    Агрегированная точка на границе бакета.
    """
    ts: datetime
    values: Mapping[str, float]

@dataclass(frozen=True)
class AggregationSpec:
    """
    Спецификация агрегации для набора полей.
    funcs: список имен агрегаторов (sum, avg, min, max, count, stddev, p50, p90, p95, p99, ewma, rate)
    fields: список имён полей или ['*'] для всех.
    name_pattern: шаблон имён выходных полей, где {field} и {func} подставляются в имя.
    """
    funcs: Sequence[str]
    fields: Sequence[str] = field(default_factory=lambda: ["*"])
    name_pattern: str = "{field}_{func}"

# =============================================================================
# Interval utilities
# =============================================================================

_INTERVAL_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)
_UNIT_TO_SEC = {"s": 1, "m": 60, "h": 3600, "d": 86400}

def parse_interval(interval: str) -> int:
    """
    Парсит '10s','1m','5m','1h','1d' в количество секунд.
    """
    m = _INTERVAL_RE.match(interval or "")
    if not m:
        raise ValueError(f"Invalid interval: {interval!r}")
    qty, unit = int(m.group(1)), m.group(2).lower()
    return qty * _UNIT_TO_SEC[unit]

def floor_to_bucket(ts: datetime, interval_s: int, *, origin: Optional[datetime] = None) -> int:
    """
    Возвращает UNIX-секунду начала бакета для данного ts.
    origin: начало сетки бакетов (UTC). По умолчанию — эпоха.
    """
    if ts.tzinfo is None:
        raise ValueError("ts must be timezone-aware")
    epoch = origin or datetime(1970, 1, 1, tzinfo=timezone.utc)
    off = int((ts - epoch).total_seconds())
    return (off // interval_s) * interval_s

# =============================================================================
# Online aggregators (per-field, per-bucket)
# =============================================================================

class AggBase:
    """Базовый интерфейс агрегатора по одному полю внутри бакета."""
    def add(self, x: float, ts: Optional[datetime] = None) -> None:  # noqa: ARG002
        raise NotImplementedError
    def result(self) -> Optional[float]:
        raise NotImplementedError
    def merge(self, other: "AggBase") -> "AggBase":
        raise NotImplementedError

class SumAgg(AggBase):
    __slots__ = ("s",)
    def __init__(self) -> None:
        self.s = 0.0
    def add(self, x: float, ts: Optional[datetime] = None) -> None:
        self.s += float(x)
    def result(self) -> Optional[float]:
        return self.s
    def merge(self, other: "SumAgg") -> "SumAgg":
        self.s += other.s
        return self

class CountAgg(AggBase):
    __slots__ = ("n",)
    def __init__(self) -> None:
        self.n = 0
    def add(self, x: float, ts: Optional[datetime] = None) -> None:
        self.n += 1
    def result(self) -> Optional[float]:
        return float(self.n)
    def merge(self, other: "CountAgg") -> "CountAgg":
        self.n += other.n
        return self

class MinAgg(AggBase):
    __slots__ = ("m",)
    def __init__(self) -> None:
        self.m: Optional[float] = None
    def add(self, x: float, ts: Optional[datetime] = None) -> None:
        self.m = float(x) if self.m is None else min(self.m, float(x))
    def result(self) -> Optional[float]:
        return self.m
    def merge(self, other: "MinAgg") -> "MinAgg":
        if other.m is not None:
            self.add(other.m)
        return self

class MaxAgg(AggBase):
    __slots__ = ("m",)
    def __init__(self) -> None:
        self.m: Optional[float] = None
    def add(self, x: float, ts: Optional[datetime] = None) -> None:
        self.m = float(x) if self.m is None else max(self.m, float(x))
    def result(self) -> Optional[float]:
        return self.m
    def merge(self, other: "MaxAgg") -> "MaxAgg":
        if other.m is not None:
            self.add(other.m)
        return self

class MeanAgg(AggBase):
    """
    Онлайн-среднее по Welford.
    """
    __slots__ = ("n", "mean")
    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
    def add(self, x: float, ts: Optional[datetime] = None) -> None:
        self.n += 1
        dx = float(x) - self.mean
        self.mean += dx / self.n
    def result(self) -> Optional[float]:
        return self.mean if self.n > 0 else None
    def merge(self, other: "MeanAgg") -> "MeanAgg":
        if other.n == 0:
            return self
        if self.n == 0:
            self.n, self.mean = other.n, other.mean
            return self
        # merge two running means
        total = self.n + other.n
        self.mean = (self.mean * self.n + other.mean * other.n) / total
        self.n = total
        return self

class StddevAgg(AggBase):
    """
    Онлайн-вариация/стдев по Welford (несмещенная, sample stddev).
    """
    __slots__ = ("n", "mean", "m2")
    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
    def add(self, x: float, ts: Optional[datetime] = None) -> None:
        self.n += 1
        dx = float(x) - self.mean
        self.mean += dx / self.n
        self.m2 += dx * (float(x) - self.mean)
    def result(self) -> Optional[float]:
        if self.n < 2:
            return 0.0 if self.n == 1 else None
        var = self.m2 / (self.n - 1)
        return math.sqrt(var)
    def merge(self, other: "StddevAgg") -> "StddevAgg":
        if other.n == 0:
            return self
        if self.n == 0:
            self.n, self.mean, self.m2 = other.n, other.mean, other.m2
            return self
        # parallel variance merge
        n = self.n + other.n
        delta = other.mean - self.mean
        m2 = self.m2 + other.m2 + delta * delta * (self.n * other.n) / n
        mean = (self.mean * self.n + other.mean * other.n) / n
        self.n, self.mean, self.m2 = n, mean, m2
        return self

class EwmaAgg(AggBase):
    """
    EWMA по времени добавления значений. Если timestamps не передаются, считается по порядку (равный шаг).
    alpha: 0..1, чем больше — тем меньше сглаживание.
    """
    __slots__ = ("alpha", "value", "initialized")
    def __init__(self, alpha: float = 0.3) -> None:
        if not (0.0 < alpha <= 1.0):
            raise ValueError("alpha must be in (0,1]")
        self.alpha = float(alpha)
        self.value: float = 0.0
        self.initialized = False
    def add(self, x: float, ts: Optional[datetime] = None) -> None:
        xv = float(x)
        if not self.initialized:
            self.value = xv
            self.initialized = True
        else:
            self.value = self.alpha * xv + (1.0 - self.alpha) * self.value
    def result(self) -> Optional[float]:
        return self.value if self.initialized else None
    def merge(self, other: "EwmaAgg") -> "EwmaAgg":
        # EWMA нелинейна для merge; выбираем значение последнего (консервативно).
        if other.initialized:
            self.value = other.value
            self.initialized = True
        return self

# ---- P² quantile (Jain & Chlamtac) ------------------------------------------

class P2QuantileAgg(AggBase):
    """
    Онлайн-оценка квантиля q с O(1) памятью.
    Подходит для p50/p90/p95/p99. Для нескольких квантилей используйте несколько инстансов.
    """
    __slots__ = ("q", "n", "x", "m", "qpos", "np")
    def __init__(self, q: float) -> None:
        if not (0.0 < q < 1.0):
            raise ValueError("q must be in (0,1)")
        self.q = float(q)
        self.n = 0  # число наблюдений
        # маркеры: позиции m[0..4], высоты x[0..4], желаемые позиции qpos[0..4], инкременты np[0..4]
        self.x: List[float] = []
        self.m: List[int] = []
        self.qpos: List[float] = []
        self.np: List[float] = []

    def add(self, x: float, ts: Optional[datetime] = None) -> None:
        v = float(x)
        self.n += 1
        if self.n <= 5:
            # буфер до 5 значений
            self.x.append(v)
            if self.n == 5:
                self.x.sort()
                self.m = [1, 2, 3, 4, 5]
                self.qpos = [1, 1 + 2 * self.q, 1 + 4 * self.q, 3 + 2 * self.q, 5]
                self.np = [0, self.q / 2, self.q, (1 + self.q) / 2, 1]
            return

        # locate cell
        k = 0
        if v < self.x[0]:
            self.x[0] = v
            k = 0
        elif v >= self.x[4]:
            self.x[4] = v
            k = 3
        else:
            for i in range(0, 4):
                if self.x[i] <= v < self.x[i + 1]:
                    k = i
                    break

        # increment positions
        for i in range(k + 1, 5):
            self.m[i] += 1
        for i in range(5):
            self.qpos[i] += self.np[i]

        # adjust heights
        for i in range(1, 4):
            d = self.qpos[i] - self.m[i]
            if (d >= 1 and self.m[i + 1] - self.m[i] > 1) or (d <= -1 and self.m[i - 1] - self.m[i] < -1):
                dsign = 1 if d >= 0 else -1
                # параболическая интерполяция
                xip = self._p2_parabolic(i, dsign)
                if self.x[i - 1] < xip < self.x[i + 1]:
                    self.x[i] = xip
                else:
                    # линейная интерполяция
                    self.x[i] = self._p2_linear(i, dsign)
                self.m[i] += dsign

    def _p2_parabolic(self, i: int, d: int) -> float:
        return self.x[i] + d * (
            (self.m[i] - self.m[i - 1] + d) * (self.x[i + 1] - self.x[i]) / (self.m[i + 1] - self.m[i])
            + (self.m[i + 1] - self.m[i] - d) * (self.x[i] - self.x[i - 1]) / (self.m[i] - self.m[i - 1])
        )

    def _p2_linear(self, i: int, d: int) -> float:
        return self.x[i] + d * (self.x[i + d] - self.x[i]) / (self.m[i + d] - self.m[i])

    def result(self) -> Optional[float]:
        if self.n == 0:
            return None
        if self.n <= 5:
            arr = sorted(self.x)
            pos = int(round((self.n - 1) * self.q))
            return float(arr[pos])
        return float(self.x[2])

    def merge(self, other: "P2QuantileAgg") -> "P2QuantileAgg":
        # Нелинейно; безопасный вариант — повторно «скормить» семплы недоступен. Возвращаем собственное состояние.
        return self

# ---- Rate agg ---------------------------------------------------------------

class RateAgg(AggBase):
    """
    Оценка средней скорости изменения монотонного счётчика в бакете.
    Алгоритм: усредняет мгновенные скорости между последовательными точками, чей правый конец попадает в бакет.
    Для межбакетной непрерывности требуется внешний контекст последней точки (см. BucketEngine).
    """
    __slots__ = ("sum_rate", "n")
    def __init__(self) -> None:
        self.sum_rate = 0.0
        self.n = 0
    def add(self, x: float, ts: Optional[datetime] = None) -> None:
        # сюда должны передаваться уже рассчитанные мгновенные скорости
        self.sum_rate += float(x)
        self.n += 1
    def result(self) -> Optional[float]:
        return (self.sum_rate / self.n) if self.n > 0 else 0.0
    def merge(self, other: "RateAgg") -> "RateAgg":
        self.sum_rate += other.sum_rate
        self.n += other.n
        return self

# =============================================================================
# Aggregator registry & factory
# =============================================================================

class AggFactory:
    """
    Регистр доступных агрегаторов и фабрика их инстансов по имени.
    """
    _registry = {
        "sum": lambda: SumAgg(),
        "count": lambda: CountAgg(),
        "avg": lambda: MeanAgg(),
        "min": lambda: MinAgg(),
        "max": lambda: MaxAgg(),
        "stddev": lambda: StddevAgg(),
        "ewma": lambda: EwmaAgg(0.3),
        "p50": lambda: P2QuantileAgg(0.50),
        "p90": lambda: P2QuantileAgg(0.90),
        "p95": lambda: P2QuantileAgg(0.95),
        "p99": lambda: P2QuantileAgg(0.99),
        "rate": lambda: RateAgg(),  # требует подготовленного instant rate
    }

    @classmethod
    def create(cls, name: str) -> AggBase:
        fn = cls._registry.get(name)
        if not fn:
            raise KeyError(f"Unknown aggregator: {name}")
        return fn()

# =============================================================================
# Bucket engine
# =============================================================================

@dataclass
class _FieldAggSet:
    """
    Набор агрегаторов по одному полю внутри бакета.
    """
    aggs: Dict[str, AggBase] = field(default_factory=dict)

    def add(self, func: str, x: float, ts: Optional[datetime] = None) -> None:
        if func not in self.aggs:
            self.aggs[func] = AggFactory.create(func)
        if func == "rate":
            # rate.add ожидает уже «скорость», см. BucketEngine
            self.aggs[func].add(x, ts)
        else:
            self.aggs[func].add(x, ts)

    def finalize(self) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for name, agg in self.aggs.items():
            r = agg.result()
            if r is not None and not (isinstance(r, float) and (math.isnan(r) or math.isinf(r))):
                out[name] = float(r)
        return out

class BucketEngine:
    """
    Потоковый движок агрегации по бакетам фиксированного интервала.

    Особенности:
      - сортирует вход по времени;
      - поддерживает любые наборы полей и функций через AggregationSpec;
      - корректно считает 'rate' для монотонных счётчиков, используя предыдущую точку (межбакетный контекст);
      - ограничение на число бакетов для защиты памяти.

    Важно: входные точки должны относиться к одной метрике/стриму (одинаковый семантический набор полей).
    """

    def __init__(
        self,
        interval: str | int,
        spec: AggregationSpec,
        *,
        utc_origin: Optional[datetime] = None,
        max_buckets: int = 1_000_000,
    ) -> None:
        self.interval_s = parse_interval(interval) if isinstance(interval, str) else int(interval)
        if self.interval_s <= 0:
            raise ValueError("interval must be > 0")
        self.spec = spec
        self.origin = utc_origin or datetime(1970, 1, 1, tzinfo=timezone.utc)
        self.max_buckets = max_buckets

        # внутреннее состояние
        self._buckets: Dict[int, Dict[str, _FieldAggSet]] = {}
        self._last_sample_per_field: Dict[str, Tuple[datetime, float]] = {}  # для rate

    def _ensure_bucket(self, key: int) -> Dict[str, _FieldAggSet]:
        if key not in self._buckets:
            if len(self._buckets) >= self.max_buckets:
                raise MemoryError("too many buckets")
            self._buckets[key] = {}
        return self._buckets[key]

    def _match_fields(self, fields: Iterable[str]) -> Iterable[str]:
        if self.spec.fields == ["*"]:
            return fields
        return [f for f in fields if f in self.spec.fields]

    def _update_rate(self, field: str, ts: datetime, value: float) -> Optional[float]:
        """
        Рассчитывает мгновенную скорость изменения счётчика между последней точкой и текущей.
        Отрицательная дельта трактуется как reset и игнорируется.
        """
        last = self._last_sample_per_field.get(field)
        self._last_sample_per_field[field] = (ts, value)
        if not last:
            return None
        last_ts, last_val = last
        dt = (ts - last_ts).total_seconds()
        if dt <= 0:
            return None
        dv = value - last_val
        if dv < 0:
            # reset — начало нового счётчика
            return None
        return dv / dt

    def add_points(self, points: Sequence[SeriesPoint]) -> None:
        """
        Добавляет батч точек. Точки сортируются по времени.
        """
        if not points:
            return
        pts = sorted(points, key=lambda p: p.ts)
        for p in pts:
            key = floor_to_bucket(p.ts, self.interval_s, origin=self.origin)
            bucket = self._ensure_bucket(key)
            for field in self._match_fields(p.values.keys()):
                val = float(p.values[field])
                # подготовка rate, если он запрошен
                if "rate" in self.spec.funcs:
                    inst_rate = self._update_rate(field, p.ts, val)
                    if inst_rate is not None:
                        fas = bucket.setdefault(field, _FieldAggSet())
                        fas.add("rate", inst_rate, p.ts)
                # обновление остальных аггрегатов
                for func in self.spec.funcs:
                    if func == "rate":
                        continue
                    fas = bucket.setdefault(field, _FieldAggSet())
                    fas.add(func, val, p.ts)

    def finalize(self) -> List[AggregatedPoint]:
        """
        Возвращает агрегированные точки на границах бакетов [t_bucket_start].
        """
        out: List[AggregatedPoint] = []
        for key in sorted(self._buckets.keys()):
            fieldsets = self._buckets[key]
            values: Dict[str, float] = {}
            for field, fas in fieldsets.items():
                res = fas.finalize()
                for func_name, v in res.items():
                    out_name = self.spec.name_pattern.format(field=field, func=func_name)
                    values[out_name] = v
            ts = datetime.fromtimestamp(key, tz=self.origin.tzinfo)
            out.append(AggregatedPoint(ts=ts, values=values))
        return out

# =============================================================================
# Convenience API
# =============================================================================

def aggregate_timeseries(
    points: Sequence[SeriesPoint],
    interval: str,
    spec: AggregationSpec,
    *,
    utc_origin: Optional[datetime] = None,
) -> List[AggregatedPoint]:
    """
    Упрощённая функция: агрегирует список точек по заданной спецификации и интервалу.
    """
    engine = BucketEngine(interval=interval, spec=spec, utc_origin=utc_origin)
    engine.add_points(points)
    return engine.finalize()

# =============================================================================
# Fills / interpolation (optional helpers)
# =============================================================================

def fill_missing_buckets(
    aggs: List[AggregatedPoint],
    interval: str | int,
    *,
    strategy: str = "none",  # none|zero|ffill
) -> List[AggregatedPoint]:
    """
    Заполняет пропуски между бакетами по выбранной стратегии.
    'none'  — не заполнять,
    'zero'  — нули по всем полям,
    'ffill' — тянуть последнее значение вперёд.
    """
    if not aggs:
        return aggs
    interval_s = parse_interval(interval) if isinstance(interval, str) else int(interval)
    result: List[AggregatedPoint] = []
    last_vals: Mapping[str, float] = {}
    for i, ap in enumerate(aggs):
        result.append(ap)
        last_vals = ap.values
        if i == len(aggs) - 1:
            break
        next_ts = aggs[i + 1].ts
        expected = ap.ts + timedelta(seconds=interval_s)
        while expected < next_ts:
            if strategy == "none":
                break
            if strategy == "zero":
                vals = {k: 0.0 for k in last_vals.keys()}
            elif strategy == "ffill":
                vals = dict(last_vals)
            else:
                raise ValueError("unknown fill strategy")
            result.append(AggregatedPoint(ts=expected, values=vals))
            expected += timedelta(seconds=interval_s)
    return result

# =============================================================================
# Example usage (commented)
# =============================================================================
# if __name__ == "__main__":
#     pts = [
#         SeriesPoint(ts=datetime.now(timezone.utc) + timedelta(seconds=i*10), values={"temp": 20 + i*0.2, "counter": i})
#         for i in range(12)
#     ]
#     spec = AggregationSpec(funcs=["avg","min","max","p95","rate"], fields=["temp","counter"])
#     out = aggregate_timeseries(pts, "1m", spec)
#     for ap in out:
#         print(ap.ts.isoformat(), ap.values)

