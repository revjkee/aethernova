#!/usr/bin/env python3
# tests/bench/bench_serializer.py
# Industrial serializer benchmark (stdlib-only).
# Measures: serialize/deserialize time, peak memory, artifact sizes, gzip effect.
# Backends: json(compact/indent), pickle(protocol=4/5)
# Usage:
#   python -m tests.bench.bench_serializer --help
#   python -m tests.bench.bench_serializer --payload catalog --size 10000 --iters 5 --backends json,pickle --gzip none,1,6 --out results.csv

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import pickle
import random
import statistics
import sys
import time
import tracemalloc
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# -----------------------
# Payload generators
# -----------------------

def _seeded_random(seed: int) -> random.Random:
    r = random.Random(seed)
    return r

def _rand_word(r: random.Random, n: int = 8) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    return "".join(r.choice(alphabet) for _ in range(n))

def _make_catalog(n: int, seed: int = 42) -> List[Dict[str, Any]]:
    """
    Имитация записей каталога с версиями/тегами/ACL: список dict'ов.
    Детеминированно по seed.
    """
    r = _seeded_random(seed)
    out = []
    for i in range(n):
        name = f"{_rand_word(r, 5)}_{i}"
        layer = r.choice(["raw", "staging", "curated", "mart"])
        cols = [{"name": f"c{j}", "dtype": r.choice(["string", "long", "double", "date"]), "nullable": r.choice([True, False])} for j in range(r.randint(3, 12))]
        versions = []
        for v in range(r.randint(1, 5)):
            versions.append({
                "version": f"1.{v}.{r.randint(0,9)}",
                "schema": {"columns": cols},
                "partitions": {"keys": ["dt"] if any(c["name"] == "dt" for c in cols) else []},
                "changeset": {"reason": r.choice(["create", "schema_update", "metadata_update"])},
            })
        item = {
            "dataset_id": f"{layer}:{name}",
            "name": name,
            "layer": layer,
            "tags": list({r.choice(["pii", "finance", "orders", "core", "tmp"]) for _ in range(r.randint(0, 4))}),
            "owners": [r.choice(["alice", "bob", "carol", "dave"])],
            "acl": {"owner": r.choice(["alice", "bob", "carol"]), "readers": [], "writers": [], "admins": []},
            "versions": versions,
            "active": True,
            "description": "demo",
            "custom": {"sla": {"freshness_seconds": r.randint(60, 86400)}},
        }
        out.append(item)
    return out

def _make_bus_envelopes(n: int, seed: int = 43) -> List[Dict[str, Any]]:
    r = _seeded_random(seed)
    out = []
    for i in range(n):
        payload = {
            "id": i,
            "amount": round(r.random() * 1000, 4),
            "currency": r.choice(["USD", "EUR", "SEK"]),
            "ts": f"2025-01-{r.randint(1,28):02d}T12:{r.randint(0,59):02d}:{r.randint(0,59):02d}Z",
            "tags": [_rand_word(r, 4) for _ in range(r.randint(0, 6))],
        }
        env = {
            "message_id": f"m-{seed}-{i}",
            "topic": r.choice(["dq.events", "catalog.audit", "etl.progress"]),
            "headers": {"type": r.choice(["report", "audit", "metric"]), "corr": f"t-{r.randint(100,999)}"},
            "payload": payload,
        }
        out.append(env)
    return out

def _make_dq_report(n: int, seed: int = 44) -> Dict[str, Any]:
    """
    Один отчёт с большим количеством метрик, массивов и вложенностей для имитации тяжёлого JSON.
    n масштабирует размер массивов.
    """
    r = _seeded_random(seed)
    null_counts = {f"c{j}": r.randint(0, 10) for j in range(20)}
    distinct_counts = {f"c{j}": r.randint(1, 1000) for j in range(20)}
    expectations = []
    for i in range(10):
        expectations.append({
            "name": r.choice(["expect_schema", "expect_not_null", "expect_unique"]),
            "success": r.choice([True, False]),
            "details": {"rows_checked": n * 10 + i, "cols": [f"c{k}" for k in range(r.randint(1, 8))]},
        })
    rows = []
    for i in range(max(1, n // 10)):
        rows.append({"id": i, "name": _rand_word(r, 7), "amount": r.random() * 100, "dt": f"2025-02-{r.randint(1,28):02d}"})
    return {
        "success": r.choice([True, False]),
        "row_count": n,
        "metrics": {"null_counts": null_counts, "distinct_counts": distinct_counts},
        "expectations": expectations,
        "sample_rows": rows,
    }

def make_payload(kind: str, size: int) -> Any:
    if kind == "catalog":
        return _make_catalog(size)
    if kind == "bus":
        return _make_bus_envelopes(size)
    if kind == "dq":
        return _make_dq_report(size)
    raise ValueError(f"unknown payload: {kind}")

# -----------------------
# Serializers
# -----------------------

@dataclass
class Serializer:
    name: str
    variant: str
    serialize: Any   # fn(obj)->bytes
    deserialize: Any # fn(bytes)->obj

def _json_compact() -> Serializer:
    def dumps(obj: Any) -> bytes:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    def loads(b: bytes) -> Any:
        return json.loads(b.decode("utf-8"))
    return Serializer("json", "compact", dumps, loads)

def _json_indent() -> Serializer:
    def dumps(obj: Any) -> bytes:
        return json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
    def loads(b: bytes) -> Any:
        return json.loads(b.decode("utf-8"))
    return Serializer("json", "indent2", dumps, loads)

def _pickle(protocol: int) -> Serializer:
    def dumps(obj: Any) -> bytes:
        return pickle.dumps(obj, protocol=protocol)
    def loads(b: bytes) -> Any:
        return pickle.loads(b)
    return Serializer("pickle", f"p{protocol}", dumps, loads)

def get_serializers(names: Iterable[str]) -> List[Serializer]:
    out: List[Serializer] = []
    for n in names:
        if n == "json":
            out.append(_json_compact())
            out.append(_json_indent())
        elif n == "pickle":
            out.append(_pickle(4))
            out.append(_pickle(5))
        else:
            raise ValueError(f"unknown backend: {n}")
    return out

# -----------------------
# Benchmark core
# -----------------------

@dataclass
class BenchConfig:
    payload: str = "catalog"            # catalog|bus|dq
    size: int = 1000
    iters: int = 5
    warmup: int = 1
    gzip_levels: Tuple[str, ...] = ("none", "1", "6")
    backends: Tuple[str, ...] = ("json", "pickle")
    out: Optional[Path] = None
    jsonl: Optional[Path] = None

@dataclass
class BenchResult:
    payload: str
    size: int
    backend: str
    variant: str
    gzip: str
    ser_ns_p50: int
    ser_ns_p95: int
    de_ns_p50: int
    de_ns_p95: int
    bytes_raw: int
    bytes_comp: int
    peak_kib_ser: int
    peak_kib_de: int

def _time_call(fn, *a, **kw) -> Tuple[int, int]:
    """
    Возвращает (elapsed_ns, peak_kib) c tracemalloc.
    """
    tracemalloc.start()
    t0 = time.perf_counter_ns()
    fn(*a, **kw)
    elapsed = time.perf_counter_ns() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return elapsed, peak // 1024

def _gzip(data: bytes, level: int) -> bytes:
    if level == 0:
        return data
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=level, mtime=0) as f:
        f.write(data)
    return buf.getvalue()

def _stats(ns: List[int]) -> Tuple[int, int]:
    if not ns:
        return 0, 0
    p50 = int(statistics.median(ns))
    # простой p95 по отсортированному массиву
    ns_sorted = sorted(ns)
    idx = min(len(ns_sorted) - 1, int(round(0.95 * (len(ns_sorted) - 1))))
    return p50, int(ns_sorted[idx])

def run_one(payload_obj: Any, ser: Serializer, gzip_level: int, iters: int, warmup: int) -> BenchResult:
    # Прогрев
    for _ in range(max(0, warmup)):
        _ = ser.deserialize(ser.serialize(payload_obj))

    ser_times: List[int] = []
    de_times: List[int] = []
    peak_ser: List[int] = []
    peak_de: List[int] = []

    data_raw = b""
    data_comp = b""

    for _ in range(max(1, iters)):
        # serialize
        t_ns, peak_kib = _time_call(ser.serialize, payload_obj)
        blob = ser.serialize(payload_obj)
        ser_times.append(t_ns)
        peak_ser.append(peak_kib)

        # size / gzip
        data_raw = blob
        data_comp = _gzip(blob, gzip_level)

        # deserialize
        t_ns, peak_kib = _time_call(ser.deserialize, blob)
        _ = ser.deserialize(blob)
        de_times.append(t_ns)
        peak_de.append(peak_kib)

    s50, s95 = _stats(ser_times)
    d50, d95 = _stats(de_times)

    return BenchResult(
        payload="",
        size=0,
        backend=ser.name,
        variant=ser.variant,
        gzip=str(gzip_level if gzip_level > 0 else "none"),
        ser_ns_p50=s50,
        ser_ns_p95=s95,
        de_ns_p50=d50,
        de_ns_p95=d95,
        bytes_raw=len(data_raw),
        bytes_comp=len(data_comp),
        peak_kib_ser=max(peak_ser) if peak_ser else 0,
        peak_kib_de=max(peak_de) if peak_de else 0,
    )

def run_bench(cfg: BenchConfig) -> List[BenchResult]:
    payload_obj = make_payload(cfg.payload, cfg.size)
    serializers = get_serializers(cfg.backends)

    results: List[BenchResult] = []
    for ser in serializers:
        for gz in cfg.gzip_levels:
            gz_level = 0 if gz == "none" else int(gz)
            res = run_one(payload_obj, ser, gz_level, cfg.iters, cfg.warmup)
            res.payload = cfg.payload
            res.size = cfg.size
            results.append(res)
    return results

# -----------------------
# Output helpers
# -----------------------

def _write_csv(path: Path, rows: List[BenchResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "payload","size","backend","variant","gzip",
            "ser_ns_p50","ser_ns_p95","de_ns_p50","de_ns_p95",
            "bytes_raw","bytes_comp","peak_kib_ser","peak_kib_de"
        ])
        for r in rows:
            w.writerow([
                r.payload, r.size, r.backend, r.variant, r.gzip,
                r.ser_ns_p50, r.ser_ns_p95, r.de_ns_p50, r.de_ns_p95,
                r.bytes_raw, r.bytes_comp, r.peak_kib_ser, r.peak_kib_de
            ])

def _write_jsonl(path: Path, rows: List[BenchResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")

def _print_table(rows: List[BenchResult]) -> None:
    # Лаконичный табличный вывод без зависимостей
    headers = ["payload","size","backend/variant","gzip","ser p50/p95 ns","de p50/p95 ns","bytes raw/comp","peak KiB s/d"]
    print("\t".join(headers))
    for r in rows:
        print("\t".join([
            r.payload,
            str(r.size),
            f"{r.backend}/{r.variant}",
            r.gzip,
            f"{r.ser_ns_p50}/{r.ser_ns_p95}",
            f"{r.de_ns_p50}/{r.de_ns_p95}",
            f"{r.bytes_raw}/{r.bytes_comp}",
            f"{r.peak_kib_ser}/{r.peak_kib_de}",
        ]))

# -----------------------
# CLI
# -----------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bench-serializer",
        description="DataFabric serializer benchmark (stdlib-only)"
    )
    p.add_argument("--payload", default="catalog", choices=["catalog","bus","dq"], help="Payload type")
    p.add_argument("--size", type=int, default=1000, help="Payload scale (items or rows)")
    p.add_argument("--iters", type=int, default=5, help="Iterations per case")
    p.add_argument("--warmup", type=int, default=1, help="Warmup iterations")
    p.add_argument("--backends", default="json,pickle", help="Comma-separated backends: json,pickle")
    p.add_argument("--gzip", dest="gzip_levels", default="none,1,6", help="Comma-separated gzip levels: none,0-9")
    p.add_argument("--out", default=None, help="CSV output path")
    p.add_argument("--jsonl", default=None, help="JSONL output path")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = BenchConfig(
        payload=args.payload,
        size=max(1, int(args.size)),
        iters=max(1, int(args.iters)),
        warmup=max(0, int(args.warmup)),
        gzip_levels=tuple(s.strip() for s in str(args.gzip_levels).split(",")),
        backends=tuple(s.strip() for s in str(args.backends).split(",")),
        out=Path(args.out) if args.out else None,
        jsonl=Path(args.jsonl) if args.jsonl else None,
    )

    rows = run_bench(cfg)
    _print_table(rows)
    if cfg.out:
        _write_csv(cfg.out, rows)
    if cfg.jsonl:
        _write_jsonl(cfg.jsonl, rows)
    return 0

if __name__ == "__main__":
    sys.exit(main())
