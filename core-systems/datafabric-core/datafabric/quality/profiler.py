# -*- coding: utf-8 -*-
"""
DataFabric | quality.profiler
Промышленный модуль профилирования данных.

Возможности:
- Потоковое профилирование из разных источников: iterable of dict/tuple, CSV-файл, pandas.DataFrame (опционально)
- Автоопределение колонок и типов (numeric, boolean, datetime-подобные строки, string)
- Онлайн-статистики: count, nulls, Welford mean/var, min/max
- Приблизительная кардинальность: HyperLogLog (конфигурируемая точность)
- Резервоарная выборка для квантилей и гистограмм, top-k (Misra-Gries)
- Корреляции Пирсона по числовым колонкам (на основе онлайн-аккумуляторов)
- Паттерны строк: email, url, ipv4, uuid, numeric-like, datetime-like
- Энтропия (Шеннон) по выборке
- Асинхронный интерфейс и таймауты, ограничители по числу строк/времени
- Структурированный лог и аккуратные ошибки

Зависимости:
- numpy >= 1.20  (обязательно)
- pandas (опционально) — если передан DataFrame

Оговорки:
- Приближённые структуры (HLL, top-k, квантили) дают погрешности, приемлемые для профилирования.
- Для крайне перекошенных распределений увеличивайте размер резервоара/бинов.

(c) Aethernova / DataFabric Core
"""
from __future__ import annotations

import asyncio
import csv
import dataclasses
import io
import logging
import math
import os
import re
import time
import typing as t
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import blake2b

import numpy as np

try:
    import pandas as pd  # type: ignore
    _HAS_PANDAS = True
except Exception:
    _HAS_PANDAS = False

_LOG = logging.getLogger("datafabric.quality.profiler")
if not _LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s trace=%(trace_id)s %(message)s"))
    _LOG.addHandler(_h)
    _LOG.setLevel(logging.INFO)

# =========================================
# Конфиги и типы
# =========================================

Number = t.Union[int, float, np.number]

@dataclass(frozen=True)
class ProfilerConfig:
    max_rows: int | None = None                 # жёстный лимит строк
    timeout_sec: float | None = None            # глобальный таймаут
    reservoir_size: int = 50_000                # размер выборки для квантилей/гистограмм/энтропии
    histogram_bins: int = 50                    # число бинов для гистограмм
    quantiles: t.Tuple[float, ...] = (0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99)
    hll_precision_p: int = 14                   # 2^p регистров (p in [4..18])
    topk_k: int = 20                            # отслеживать топ-k значений
    detect_correlations: bool = True
    datetime_formats: t.Tuple[str, ...] = ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d.%m.%Y")
    null_like: t.Tuple[t.Any, ...] = (None, "", "NULL", "NaN", "N/A")
    trace_id: str = field(default_factory=lambda: f"{int(time.time()*1000):x}")

@dataclass
class ColumnType:
    base: t.Literal["numeric", "boolean", "datetime", "string"] = "string"
    # detail: e.g., "int", "float", "bool", "datetime-str-<fmt>", "string"

@dataclass
class ColumnStats:
    name: str
    col_type: ColumnType = field(default_factory=ColumnType)
    count: int = 0
    nulls: int = 0
    empties: int = 0
    min: Number | str | None = None
    max: Number | str | None = None
    mean: float | None = None
    stddev: float | None = None
    p01: float | None = None
    p05: float | None = None
    p25: float | None = None
    p50: float | None = None
    p75: float | None = None
    p95: float | None = None
    p99: float | None = None
    histogram: dict[str, t.Any] | None = None
    topk: list[tuple[t.Any, int]] = field(default_factory=list)
    distinct_estimate: int | None = None
    entropy: float | None = None
    patterns: dict[str, float] = field(default_factory=dict)  # доля вхождений по паттернам

@dataclass
class DatasetProfile:
    n_rows_scanned: int
    n_cols: int
    columns: list[ColumnStats]
    correlations: dict[tuple[str, str], float] = field(default_factory=dict)
    elapsed_sec: float = 0.0
    truncated: bool = False
    timed_out: bool = False
    meta: dict[str, t.Any] = field(default_factory=dict)

# =========================================
# Вспомогательные структуры
# =========================================

class Welford:
    """Онлайн-оценка среднего и дисперсии."""
    __slots__ = ("n", "mean", "M2")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2

    def finalize(self) -> tuple[float | None, float | None]:
        if self.n == 0:
            return None, None
        if self.n < 2:
            return float(self.mean), 0.0
        var = self.M2 / (self.n - 1)
        return float(self.mean), float(math.sqrt(max(var, 0.0)))

class HyperLogLog:
    """
    Простая реализация HLL для оценки количества уникальных.
    Погрешность ~ 1.04 / sqrt(m), m = 2^p.
    """
    __slots__ = ("p", "m", "registers")

    def __init__(self, p: int = 14) -> None:
        if not (4 <= p <= 18):
            raise ValueError("HLL p must be in [4..18]")
        self.p = p
        self.m = 1 << p
        self.registers = np.zeros(self.m, dtype=np.uint8)

    @staticmethod
    def _hash(x: t.Any) -> int:
        b = repr(x).encode("utf-8", errors="ignore")
        return int.from_bytes(blake2b(b, digest_size=8).digest(), "big")

    def add(self, x: t.Any) -> None:
        h = self._hash(x)
        idx = h >> (64 - self.p)
        w = (h << self.p) & ((1 << 64) - 1)
        rho = (w.bit_length() ^ 64) + 1  # позиция первого 1
        self.registers[idx] = max(self.registers[idx], rho)

    def estimate(self) -> int:
        m = float(self.m)
        alpha_m = 0.7213 / (1 + 1.079 / m)
        E = alpha_m * m * m / float(np.sum(2.0 ** (-self.registers)))
        # малые коррекции
        if E <= (5.0 / 2.0) * m:
            V = np.count_nonzero(self.registers == 0)
            if V > 0:
                E = m * math.log(m / V)
        return int(E)

class MisraGriesTopK:
    """Приближённый топ-k частот."""
    def __init__(self, k: int) -> None:
        self.k = max(1, k)
        self.counters: dict[t.Any, int] = {}

    def offer(self, x: t.Any) -> None:
        if x in self.counters:
            self.counters[x] += 1
            return
        if len(self.counters) < self.k:
            self.counters[x] = 1
            return
        # уменьшение
        to_del = []
        for key in list(self.counters.keys()):
            self.counters[key] -= 1
            if self.counters[key] <= 0:
                to_del.append(key)
        for key in to_del:
            del self.counters[key]

    def snapshot(self) -> list[tuple[t.Any, int]]:
        # это верхняя оценка; для точных частот нужен второй проход.
        return sorted(self.counters.items(), key=lambda kv: kv[1], reverse=True)

class ReservoirSampler:
    """Резервоарная выборка фиксированного размера."""
    def __init__(self, capacity: int) -> None:
        self.capacity = max(0, int(capacity))
        self.buf: list[t.Any] = []
        self.seen = 0

    def offer(self, x: t.Any) -> None:
        if self.capacity == 0:
            return
        self.seen += 1
        if len(self.buf) < self.capacity:
            self.buf.append(x)
            return
        # Алгоритм Vitter
        j = np.random.randint(0, self.seen)
        if j < self.capacity:
            self.buf[j] = x

    def array(self) -> np.ndarray:
        if not self.buf:
            return np.array([], dtype=float)
        # попытка привести к числу
        try:
            return np.array(self.buf, dtype=float)
        except Exception:
            return np.array(self.buf, dtype=object)

# =========================================
# Детектор паттернов строк
# =========================================

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_URL = re.compile(r"^https?://")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[1-5][0-9a-fA-F]{3}\-[89abAB][0-9a-fA-F]{3}\-[0-9a-fA-F]{12}$")
_NUMERIC_LIKE = re.compile(r"^[\+\-]?\d+(\.\d+)?$")
_DT_LIKE = re.compile(r"^\d{4}\-\d{2}\-\d{2}")

def detect_patterns(s: str) -> dict[str, bool]:
    return {
        "email": bool(_EMAIL.match(s)),
        "url": bool(_URL.match(s)),
        "ipv4": bool(_IPV4.match(s)),
        "uuid": bool(_UUID.match(s)),
        "numeric_like": bool(_NUMERIC_LIKE.match(s)),
        "datetime_like": bool(_DT_LIKE.match(s)),
    }

# =========================================
# Адаптация источников
# =========================================

class RowAdapter:
    """
    Единый интерфейс: выдаёт строки как dict[str, Any] или tuple по колонкам.
    Также возвращает список имён колонок.
    """
    def __init__(self, data: t.Any) -> None:
        self.data = data
        self.columns: list[str] | None = None
        self._iter: t.Iterator[t.Any] | None = None

    def _init(self) -> None:
        if self._iter is not None:
            return
        if _HAS_PANDAS and isinstance(self.data, pd.DataFrame):
            self.columns = [str(c) for c in self.data.columns]
            self._iter = (row for _, row in self.data.iterrows())
            return
        if isinstance(self.data, str) and os.path.isfile(self.data) and self.data.lower().endswith(".csv"):
            f = open(self.data, "r", encoding="utf-8", newline="")
            reader = csv.DictReader(f)
            self.columns = list(reader.fieldnames or [])
            self._iter = iter(reader)
            return
        # iterable of dict or tuple/list
        it = iter(self.data)
        first = next(it, None)
        if first is None:
            self.columns = []
            self._iter = iter(())
            return
        if isinstance(first, dict):
            self.columns = list(first.keys())
            self._iter = iter([first, *it])
            return
        if isinstance(first, (list, tuple)):
            # имена колонок неизвестны — создаём по индексу
            self.columns = [f"c{i}" for i in range(len(first))]
            self._iter = iter([first, *it])
            return
        # одиночные объекты — одна колонка "value"
        self.columns = ["value"]
        self._iter = iter([first, *it])

    def columns_or_empty(self) -> list[str]:
        self._init()
        return self.columns or []

    def rows(self) -> t.Iterator[dict[str, t.Any]]:
        self._init()
        cols = self.columns or []
        it = self._iter or iter(())
        for item in it:
            if _HAS_PANDAS and isinstance(item, pd.Series):
                yield {str(k): item[k] for k in cols}
                continue
            if isinstance(item, dict):
                yield item
                continue
            if isinstance(item, (list, tuple)):
                yield {cols[i]: item[i] if i < len(item) else None for i in range(len(cols))}
                continue
            yield {"value": item}

# =========================================
# Типизация колонок
# =========================================

def infer_type(value: t.Any, cfg: ProfilerConfig) -> ColumnType:
    if value is None:
        return ColumnType("string")
    if isinstance(value, (int, float, np.integer, np.floating)) and not (isinstance(value, float) and (math.isnan(value))):
        return ColumnType("numeric")
    if isinstance(value, (bool, np.bool_)):
        return ColumnType("boolean")
    # datetime объектов
    if isinstance(value, (datetime, )):
        return ColumnType("datetime")
    # строки
    if isinstance(value, str):
        s = value.strip()
        if s.upper() in cfg.null_like:
            return ColumnType("string")
        # boolean-like
        if s.lower() in ("true", "false", "t", "f", "yes", "no", "y", "n"):
            return ColumnType("boolean")
        # numeric-like
        if _NUMERIC_LIKE.match(s):
            return ColumnType("numeric")
        # datetime-like
        if _DT_LIKE.match(s):
            # формат уточним позже
            return ColumnType("datetime")
        return ColumnType("string")
    # прочее → строка
    return ColumnType("string")

# =========================================
# Профайлер колонки
# =========================================

class ColumnProfiler:
    def __init__(self, name: str, cfg: ProfilerConfig) -> None:
        self.name = name
        self.cfg = cfg
        self.type = ColumnType("string")
        self.count = 0
        self.nulls = 0
        self.empties = 0
        self.min_val: t.Any = None
        self.max_val: t.Any = None
        self.welford = Welford()
        self.hll = HyperLogLog(p=cfg.hll_precision_p)
        self.topk = MisraGriesTopK(cfg.topk_k)
        self.sample = ReservoirSampler(cfg.reservoir_size)
        self.pattern_counts: dict[str, int] = {"email": 0, "url": 0, "ipv4": 0, "uuid": 0, "numeric_like": 0, "datetime_like": 0}

    def _normalize_null(self, v: t.Any) -> bool:
        if v is None:
            return True
        if isinstance(v, float) and math.isnan(v):
            return True
        if isinstance(v, str) and v.strip() in self.cfg.null_like:
            return True
        return False

    def observe(self, v: t.Any) -> None:
        self.count += 1
        if self._normalize_null(v):
            self.nulls += 1
            return

        # пустые строки
        if isinstance(v, str) and v == "":
            self.empties += 1

        # тип
        if self.count == 1 or self.type.base == "string":
            self.type = infer_type(v, self.cfg)

        # HLL + topk
        self.hll.add(v)
        self.topk.offer(v)

        # числовая статистика (пробуем привести)
        num: float | None = None
        if self.type.base == "numeric":
            try:
                num = float(v)
            except Exception:
                # возможно строка numeric-like
                try:
                    num = float(str(v).strip())
                except Exception:
                    num = None

        if num is not None and not math.isnan(num):
            self.welford.update(num)
            # min/max как числа
            if self.min_val is None or num < t.cast(float, self.min_val):
                self.min_val = num
            if self.max_val is None or num > t.cast(float, self.max_val):
                self.max_val = num
            self.sample.offer(num)
        else:
            # min/max как строки для строковых колонок
            if isinstance(v, str):
                self.sample.offer(v)
                if self.min_val is None or v < t.cast(str, self.min_val):
                    self.min_val = v
                if self.max_val is None or v > t.cast(str, self.max_val):
                    self.max_val = v
                # паттерны
                p = detect_patterns(v)
                for k, ok in p.items():
                    if ok:
                        self.pattern_counts[k] += 1
            else:
                # нумеризация прочих типов по repr для min/max
                rv = repr(v)
                self.sample.offer(rv)
                if self.min_val is None or rv < t.cast(str, self.min_val):
                    self.min_val = rv
                if self.max_val is None or rv > t.cast(str, self.max_val):
                    self.max_val = rv

    def finalize(self) -> ColumnStats:
        mean, std = self.welford.finalize()
        distinct_est = self.hll.estimate()

        # гистограмма и квантили
        qmap: dict[float, float] = {}
        histogram: dict[str, t.Any] | None = None
        entropy_val: float | None = None

        arr = self.sample.array()
        if arr.size > 0:
            if arr.dtype != object:
                # numeric
                qs = np.quantile(arr, q=list(self.cfg.quantiles))
                for i, q in enumerate(self.cfg.quantiles):
                    qmap[float(q)] = float(qs[i])
                # histogram
                hist, edges = np.histogram(arr, bins=self.cfg.histogram_bins)
                histogram = {"bins": [float(x) for x in edges.tolist()], "counts": [int(x) for x in hist.tolist()]}
            else:
                # строковая выборка: энтропия и топ частоты в выборке
                # энтропия
                _, counts = np.unique(np.array(arr, dtype=object), return_counts=True)
                p = counts / counts.sum()
                entropy_val = float(-(p * np.log2(p + 1e-12)).sum())

        # доли паттернов
        patt_total = max(1, self.count - self.nulls)
        patt_share = {k: round(v / patt_total, 6) for k, v in self.pattern_counts.items()} if patt_total > 0 else {}

        # top-k
        topk_list = self.topk.snapshot()

        # сборка
        st = ColumnStats(
            name=self.name,
            col_type=self.type,
            count=self.count,
            nulls=self.nulls,
            empties=self.empties,
            min=self.min_val,
            max=self.max_val,
            mean=mean,
            stddev=std,
            p01=qmap.get(0.01),
            p05=qmap.get(0.05),
            p25=qmap.get(0.25),
            p50=qmap.get(0.5),
            p75=qmap.get(0.75),
            p95=qmap.get(0.95),
            p99=qmap.get(0.99),
            histogram=histogram,
            topk=topk_list,
            distinct_estimate=int(distinct_est) if distinct_est is not None else None,
            entropy=entropy_val,
            patterns=patt_share,
        )
        return st

# =========================================
# Корреляции по числовым колонкам (онлайн)
# =========================================

class CorrAccumulator:
    """
    Онлайн-аккумуляция для корреляции Пирсона между несколькими числовыми колонками.
    Сохраняем суммы: n, sum(x), sum(y), sum(x^2), sum(y^2), sum(x*y)
    """
    def __init__(self, col_names: list[str]) -> None:
        self.cols = col_names
        n = len(col_names)
        self.n = 0
        self.sum = np.zeros(n, dtype=np.float64)
        self.sumsq = np.zeros(n, dtype=np.float64)
        self.cross = np.zeros((n, n), dtype=np.float64)

    def update(self, row_vals: list[float]) -> None:
        v = np.array(row_vals, dtype=np.float64)
        if np.any(np.isnan(v)):
            return
        self.n += 1
        self.sum += v
        self.sumsq += v * v
        self.cross += np.outer(v, v)

    def finalize(self) -> dict[tuple[str, str], float]:
        res: dict[tuple[str, str], float] = {}
        if self.n < 2:
            return res
        n = float(self.n)
        mean = self.sum / n
        var = (self.sumsq / n) - (mean * mean)
        std = np.sqrt(np.maximum(var, 0.0))
        denom = np.outer(std, std)
        cov = (self.cross / n) - np.outer(mean, mean)
        with np.errstate(invalid="ignore", divide="ignore"):
            corr = cov / denom
        for i, ci in enumerate(self.cols):
            for j in range(i + 1, len(self.cols)):
                cj = self.cols[j]
                val = corr[i, j]
                if np.isfinite(val):
                    res[(ci, cj)] = float(val)
        return res

# =========================================
# Основной профайлер
# =========================================

class DataProfiler:
    def __init__(self, cfg: ProfilerConfig | None = None) -> None:
        self.cfg = cfg or ProfilerConfig()

    def profile(self, data: t.Any) -> DatasetProfile:
        """
        Синхронное профилирование.
        """
        trace = self.cfg.trace_id
        t0 = time.time()
        adapter = RowAdapter(data)
        cols = adapter.columns_or_empty()
        profs = {c: ColumnProfiler(c, self.cfg) for c in cols}
        numeric_cols: list[str] = []
        corr_acc: CorrAccumulator | None = None

        rows_scanned = 0
        timed_out = False
        truncated = False

        for row in adapter.rows():
            rows_scanned += 1
            if self.cfg.max_rows is not None and rows_scanned > self.cfg.max_rows:
                truncated = True
                break
            if self.cfg.timeout_sec is not None and (time.time() - t0) > self.cfg.timeout_sec:
                timed_out = True
                break

            # ленивое создание профилировщиков для новых ключей (если dict может менять состав)
            for k in row.keys():
                if k not in profs:
                    profs[k] = ColumnProfiler(k, self.cfg)

            # наблюдение
            for c, p in profs.items():
                v = row.get(c, None)
                p.observe(v)

        # определить числовые колонки для корреляций
        if self.cfg.detect_correlations:
            numeric_cols = [c for c, p in profs.items() if p.type.base == "numeric"]
            if len(numeric_cols) >= 2:
                corr_acc = CorrAccumulator(numeric_cols)
                # второй легкий проход по резервоарам для оценочной корреляции:
                # здесь мы принимаем приближение — используем резервоар каждой колонки и синхронизируем по индексу.
                # Более точный расчёт потребует второго полного прохода по данным.
                min_len = min((len(profs[c].sample.buf) for c in numeric_cols), default=0)
                if min_len > 0:
                    # нормализуем длины через первые min_len элементов (случайные за счёт резервоара)
                    for i in range(min_len):
                        vals = []
                        ok = True
                        for c in numeric_cols:
                            xi = profs[c].sample.buf[i]
                            try:
                                xv = float(xi)
                                if math.isnan(xv):
                                    ok = False
                                    break
                                vals.append(xv)
                            except Exception:
                                ok = False
                                break
                        if ok:
                            corr_acc.update(vals)

        columns_stats = [profs[c].finalize() for c in sorted(profs.keys())]
        correlations = corr_acc.finalize() if corr_acc is not None else {}

        elapsed = time.time() - t0
        _LOG.info(
            "profile.done rows=%d cols=%d elapsed=%.3f truncated=%s timeout=%s",
            rows_scanned,
            len(columns_stats),
            elapsed,
            truncated,
            timed_out,
            extra={"trace_id": trace},
        )
        return DatasetProfile(
            n_rows_scanned=rows_scanned,
            n_cols=len(columns_stats),
            columns=columns_stats,
            correlations=correlations,
            elapsed_sec=elapsed,
            truncated=truncated,
            timed_out=timed_out,
            meta={"trace_id": trace},
        )

    async def profile_async(self, data: t.Any) -> DatasetProfile:
        """
        Асинхронное профилирование с уважением таймаута.
        """
        loop = asyncio.get_event_loop()
        # если задан timeout_sec — оборачиваем в asyncio.wait_for
        if self.cfg.timeout_sec is not None:
            try:
                return await asyncio.wait_for(loop.run_in_executor(None, self.profile, data), timeout=self.cfg.timeout_sec)
            except asyncio.TimeoutError:
                # возвращаем частичный отчёт (пустой), указываем timed_out
                return DatasetProfile(
                    n_rows_scanned=0,
                    n_cols=0,
                    columns=[],
                    correlations={},
                    elapsed_sec=self.cfg.timeout_sec,
                    truncated=False,
                    timed_out=True,
                    meta={"trace_id": self.cfg.trace_id, "reason": "timeout_async"},
                )
        # без таймаута — просто offload
        return await loop.run_in_executor(None, self.profile, data)

# =========================================
# Публичная API
# =========================================

__all__ = [
    "ProfilerConfig",
    "ColumnType",
    "ColumnStats",
    "DatasetProfile",
    "DataProfiler",
]
