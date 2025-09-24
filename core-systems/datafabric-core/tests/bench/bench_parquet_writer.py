# -*- coding: utf-8 -*-
"""
Бенчмарк записи Parquet для DataFabric.

Возможности:
- Benchmark встроенного datafabric.storage.writers.ParquetWriter (если доступен).
- Benchmark эталона: прямая запись через pyarrow.parquet (если доступен).
- Настройка: --rows, --batch, --row-group-size, --compression, --partitions, --target {df,pyarrow,both}.
- Метрики: rows/s, MB/s, p50/p95/p99 латентности батчей, total size, файлов, peak RSS (если psutil).
- Вывод: табличный и JSON (для CI).

Запуск как CLI:
    python bench_parquet_writer.py --rows 200000 --batch 20000 --compression zstd --row-group-size 8192 --target both

Запуск через pytest (если есть pytest-benchmark):
    pytest -q tests/bench/bench_parquet_writer.py::test_bench_parquet_writer --benchmark-min-time=1.0

Зависимости:
- Обязательно для pyarrow-бенчмарка: pyarrow>=9
- Опционально: psutil (для peak RSS)
- Для бенчмарка DataFabric writer: datafabric.storage.writers.ParquetWriter

Совместимо с Python 3.10+.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
import random
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# -------- Опциональные зависимости --------
_HAS_PA = False
try:
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore
    _HAS_PA = True
except Exception:
    _HAS_PA = False

_HAS_PSUTIL = False
try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:
    _HAS_PSUTIL = False

_HAS_DF_WRITER = False
ParquetWriter = None
try:
    from datafabric.storage.writers import ParquetWriter as _DFParquetWriter  # type: ignore
    ParquetWriter = _DFParquetWriter
    _HAS_DF_WRITER = True
except Exception:
    _HAS_DF_WRITER = False


# -------- Генерация синтетики --------

EVENT_TYPES = ("order.created", "order.updated", "order.paid", "order.cancelled")

def _rand_id(prefix: str, width: int = 8) -> str:
    return f"{prefix}-{random.randint(0, 10**width - 1):0{width}d}"

def make_record(i: int) -> Dict[str, Any]:
    order_id = _rand_id("O")
    cust_id = _rand_id("C")
    et = EVENT_TYPES[i % len(EVENT_TYPES)]
    return {
        "msg_id": f"m-{i:016d}",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(1_725_000_000 + i)),
        "dataset": "sales",
        "event_type": et,
        "key": {"order_id": order_id, "customer_id": cust_id},
        "payload": {
            "amount_cents": (i * 5 + 123) % 100_000,
            "currency": "USD",
            "items": [{"sku": f"SKU-{i%9999:04d}", "qty": (i % 5) + 1} for _ in range((i % 3) + 1)],
        },
        "_meta": {"schema": "demo.order.v1"},
    }

def make_batch(start: int, size: int) -> List[Dict[str, Any]]:
    return [make_record(start + i) for i in range(size)]


# -------- Конфигурация --------

@dataclass
class Config:
    out_dir: Path
    rows: int
    batch: int
    row_group_size: int
    compression: Optional[str]
    partitions: Optional[str]
    target: str  # df | pyarrow | both
    seed: int

    @staticmethod
    def from_args() -> "Config":
        p = argparse.ArgumentParser(description="Parquet writer benchmark")
        p.add_argument("--out", type=Path, default=None, help="Каталог для вывода (по умолчанию tmp)")
        p.add_argument("--rows", type=int, default=int(os.getenv("DF_BENCH_ROWS", "200000")))
        p.add_argument("--batch", type=int, default=int(os.getenv("DF_BENCH_BATCH", "20000")))
        p.add_argument("--row-group-size", type=int, default=int(os.getenv("DF_ROW_GROUP", "8192")))
        p.add_argument("--compression", choices=["none", "snappy", "gzip", "zstd"], default=os.getenv("DF_COMPRESSION", "zstd"))
        p.add_argument("--partitions", default=os.getenv("DF_PARTITIONS", "event_type"), help="Поле партиционирования или пусто")
        p.add_argument("--target", choices=["df", "pyarrow", "both"], default=os.getenv("DF_TARGET", "both"))
        p.add_argument("--seed", type=int, default=int(os.getenv("DF_SEED", "1")))
        args = p.parse_args()

        out_dir = args.out or Path(tempfile.mkdtemp(prefix="df_parquet_bench_"))
        compression = None if args.compression in (None, "none") else args.compression
        partitions = (args.partitions or "").strip() or None
        return Config(
            out_dir=out_dir,
            rows=args.rows,
            batch=args.batch,
            row_group_size=args.row_group_size,
            compression=compression,
            partitions=partitions,
            target=args.target,
            seed=args.seed,
        )


# -------- Метрики/отчет --------

@dataclass
class BenchResult:
    name: str
    rows: int
    bytes_total: int
    files: int
    wall_s: float
    rows_per_s: float
    mb_per_s: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    peak_rss_mb: Optional[float]

def _percentiles(values_ms: List[float]) -> Tuple[float, float, float]:
    if not values_ms:
        return 0.0, 0.0, 0.0
    vals = sorted(values_ms)
    def pct(p: float) -> float:
        k = (len(vals)-1) * p
        f = math.floor(k); c = math.ceil(k)
        if f == c: return vals[int(k)]
        d0 = vals[f] * (c - k)
        d1 = vals[c] * (k - f)
        return d0 + d1
    return pct(0.5), pct(0.95), pct(0.99)

def _dir_size_and_count(path: Path) -> Tuple[int, int]:
    total = 0
    files = 0
    for p in path.rglob("*"):
        if p.is_file():
            files += 1
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total, files


# -------- Бенчмарки --------

async def bench_df_writer(cfg: Config) -> BenchResult:
    if not _HAS_DF_WRITER:
        raise RuntimeError("ParquetWriter из DataFabric недоступен")
    out = cfg.out_dir / "df"
    out.mkdir(parents=True, exist_ok=True)

    kw = {}
    # Партиционирование
    if cfg.partitions:
        # поддержка разных имен параметров
        kw["partition_by"] = cfg.partitions
    # row group / компрессия: зависят от реализации, но часто есть параметры конструктора
    for k in ("row_group_size", "compression"):
        kw[k] = getattr(cfg, k)
    # базовые пути
    kw["base_path"] = str(out)

    writer = ParquetWriter(**{k: v for k, v in kw.items() if k in __import__("inspect").signature(ParquetWriter).parameters})  # type: ignore

    await writer.start()  # type: ignore[attr-defined]

    lat_ms: List[float] = []
    t0 = time.perf_counter()
    if _HAS_PSUTIL:
        proc = psutil.Process(os.getpid())
    peak_rss_mb = None

    remaining = cfg.rows
    i = 0
    while remaining > 0:
        n = min(cfg.batch, remaining)
        batch = make_batch(i, n)
        b0 = time.perf_counter()
        if hasattr(writer, "write_batch"):
            await writer.write_batch(batch)  # type: ignore[attr-defined]
        else:
            for r in batch:
                await writer.write(r)  # type: ignore[attr-defined]
        lat_ms.append((time.perf_counter() - b0) * 1000.0)
        remaining -= n
        i += n
        if _HAS_PSUTIL:
            try:
                peak_rss_mb = max((peak_rss_mb or 0.0), proc.memory_info().rss / (1024 * 1024))
            except Exception:
                pass

    if hasattr(writer, "flush"):
        await writer.flush()  # type: ignore[attr-defined]
    if hasattr(writer, "close"):
        await writer.close()  # type: ignore[attr-defined]
    wall = time.perf_counter() - t0

    bytes_total, files = _dir_size_and_count(out)
    rps = cfg.rows / wall if wall > 0 else 0.0
    mbps = (bytes_total / (1024 * 1024)) / wall if wall > 0 else 0.0
    p50, p95, p99 = _percentiles(lat_ms)

    return BenchResult(
        name="datafabric.parquet_writer",
        rows=cfg.rows,
        bytes_total=bytes_total,
        files=files,
        wall_s=wall,
        rows_per_s=rps,
        mb_per_s=mbps,
        p50_ms=p50,
        p95_ms=p95,
        p99_ms=p99,
        peak_rss_mb=peak_rss_mb,
    )

async def bench_pyarrow(cfg: Config) -> BenchResult:
    if not _HAS_PA:
        raise RuntimeError("pyarrow недоступен")

    out = cfg.out_dir / "pyarrow"
    out.mkdir(parents=True, exist_ok=True)

    lat_ms: List[float] = []
    t0 = time.perf_counter()
    peak_rss_mb = None
    if _HAS_PSUTIL:
        proc = psutil.Process(os.getpid())

    # Схема, раскладывающая вложенные поля
    schema = pa.schema([
        ("msg_id", pa.string()),
        ("ts", pa.string()),
        ("dataset", pa.string()),
        ("event_type", pa.string()),
        ("key", pa.struct([("order_id", pa.string()), ("customer_id", pa.string())])),
        ("payload", pa.struct([
            ("amount_cents", pa.int64()),
            ("currency", pa.string()),
            ("items", pa.list_(pa.struct([("sku", pa.string()), ("qty", pa.int32())])))
        ])),
        ("_meta", pa.struct([("schema", pa.string())])),
    ])

    write_opts = dict(
        compression=cfg.compression or "NONE",
        use_dictionary=True,
        write_statistics=True,
    )

    # Эмулируем партиционирование: создаем подкаталоги по значению поля
    remaining = cfg.rows
    i = 0
    while remaining > 0:
        n = min(cfg.batch, remaining)
        batch = make_batch(i, n)

        # Преобразуем в таблицу
        table = pa.Table.from_pylist(batch, schema=schema)
        # Разбивка по партициям (на лету)
        if cfg.partitions:
            col = table.column(cfg.partitions)
            # Получим уникальные значения партиции в батче
            vals = set(map(lambda x: x.as_py(), col.to_pylist()))
            for v in vals:
                mask = pa.compute.equal(col, pa.scalar(v))  # type: ignore
                subt = table.filter(mask)  # type: ignore
                part_dir = out / f"{cfg.partitions}={v}"
                part_dir.mkdir(parents=True, exist_ok=True)
                path = part_dir / f"part-{i:012d}.parquet"
                b0 = time.perf_counter()
                pq.write_table(subt, where=str(path),
                               compression=write_opts["compression"],
                               use_dictionary=write_opts["use_dictionary"],
                               write_statistics=write_opts["write_statistics"],
                               row_group_size=cfg.row_group_size)
                lat_ms.append((time.perf_counter() - b0) * 1000.0)
        else:
            path = out / f"part-{i:012d}.parquet"
            b0 = time.perf_counter()
            pq.write_table(table, where=str(path),
                           compression=write_opts["compression"],
                           use_dictionary=write_opts["use_dictionary"],
                           write_statistics=write_opts["write_statistics"],
                           row_group_size=cfg.row_group_size)
            lat_ms.append((time.perf_counter() - b0) * 1000.0)

        remaining -= n
        i += n
        if _HAS_PSUTIL:
            try:
                peak_rss_mb = max((peak_rss_mb or 0.0), proc.memory_info().rss / (1024 * 1024))
            except Exception:
                pass

    wall = time.perf_counter() - t0
    bytes_total, files = _dir_size_and_count(out)
    rps = cfg.rows / wall if wall > 0 else 0.0
    mbps = (bytes_total / (1024 * 1024)) / wall if wall > 0 else 0.0
    p50, p95, p99 = _percentiles(lat_ms)

    return BenchResult(
        name="pyarrow.write_table",
        rows=cfg.rows,
        bytes_total=bytes_total,
        files=files,
        wall_s=wall,
        rows_per_s=rps,
        mb_per_s=mbps,
        p50_ms=p50,
        p95_ms=p95,
        p99_ms=p99,
        peak_rss_mb=peak_rss_mb,
    )


# -------- Отчет --------

def print_report(results: List[BenchResult]) -> None:
    def fmt_mb(x: float) -> str:
        return f"{x:,.2f}"
    def fmt_i(x: int) -> str:
        return f"{x:,}"

    # Табличный вывод
    cols = ["name", "rows", "bytes_total", "files", "wall_s", "rows_per_s", "mb_per_s", "p50_ms", "p95_ms", "p99_ms", "peak_rss_mb"]
    widths = {c: max(len(c), 12) for c in cols}
    rows = []
    for r in results:
        row = {
            "name": r.name,
            "rows": fmt_i(r.rows),
            "bytes_total": fmt_i(r.bytes_total),
            "files": fmt_i(r.files),
            "wall_s": f"{r.wall_s:,.3f}",
            "rows_per_s": fmt_i(int(r.rows_per_s)),
            "mb_per_s": fmt_mb(r.mb_per_s),
            "p50_ms": fmt_mb(r.p50_ms),
            "p95_ms": fmt_mb(r.p95_ms),
            "p99_ms": fmt_mb(r.p99_ms),
            "peak_rss_mb": "-" if r.peak_rss_mb is None else fmt_mb(r.peak_rss_mb),
        }
        rows.append(row)
        for k, v in row.items():
            widths[k] = max(widths[k], len(str(v)))

    header = " | ".join(k.ljust(widths[k]) for k in cols)
    sep = "-+-".join("-" * widths[k] for k in cols)
    print(header)
    print(sep)
    for row in rows:
        print(" | ".join(str(row[k]).ljust(widths[k]) for k in cols))

    # JSON для CI
    out_json = [dataclasses.asdict(r) for r in results]
    print("\nJSON:", json.dumps(out_json, ensure_ascii=False, separators=(",", ":")))


# -------- CLI entrypoint --------

def _warn(msg: str) -> None:
    print(f"[warn] {msg}", file=sys.stderr)

def main() -> None:
    cfg = Config.from_args()
    random.seed(cfg.seed)

    results: List[BenchResult] = []

    # Выбор целей
    targets = []
    if cfg.target in ("df", "both"):
        if _HAS_DF_WRITER:
            targets.append(("df", bench_df_writer))
        else:
            _warn("DataFabric ParquetWriter недоступен — пропускаю цель 'df'")
    if cfg.target in ("pyarrow", "both"):
        if _HAS_PA:
            targets.append(("pyarrow", bench_pyarrow))
        else:
            _warn("pyarrow недоступен — пропускаю цель 'pyarrow'")

    if not targets:
        _warn("Нет доступных целей для бенчмарка. Завершение.")
        # Для соответствия требованиям валидации окружения:
        print('[]')
        return

    # Запуск в простом event loop
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        for name, fn in targets:
            res = loop.run_until_complete(fn(cfg))
            results.append(res)
    finally:
        loop.run_until_complete(asyncio.sleep(0))
        loop.close()

    print_report(results)


# -------- PyTest benchmark (опционально) --------
# Будет автоматически использовано, если установлен pytest-benchmark.
def _run_pytest_bench(cfg: Config, benchmark):
    # benchmark() синхронный, оборачиваем асинхронные функции
    import asyncio
    async def run_all():
        outs = []
        if _HAS_DF_WRITER:
            outs.append(await bench_df_writer(cfg))
        if _HAS_PA:
            outs.append(await bench_pyarrow(cfg))
        return outs
    def _sync():
        return asyncio.run(run_all())
    results = benchmark(_sync)
    # Вывести компактный отчет в лог теста
    if results:
        print_report(results)

# Тестовая точка входа для pytest
def test_bench_parquet_writer(pytestconfig=None, benchmark=None):
    # Минимальные параметры, чтобы тест проходил быстро в CI
    cfg = Config(
        out_dir=Path(tempfile.mkdtemp(prefix="df_parquet_bench_pytest_")),
        rows=int(os.getenv("DF_BENCH_ROWS", "40000")),
        batch=int(os.getenv("DF_BENCH_BATCH", "10000")),
        row_group_size=int(os.getenv("DF_ROW_GROUP", "8192")),
        compression=(None if os.getenv("DF_COMPRESSION", "zstd") in ("none", "None") else os.getenv("DF_COMPRESSION", "zstd")),
        partitions=(os.getenv("DF_PARTITIONS", "event_type") or None),
        target=os.getenv("DF_TARGET", "both"),
        seed=int(os.getenv("DF_SEED", "1")),
    )
    if benchmark is None:
        # pytest-benchmark отсутствует — запуск как обычный тест без строгих проверок
        main()
        return
    _run_pytest_bench(cfg, benchmark)


if __name__ == "__main__":
    main()
