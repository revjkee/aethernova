# -*- coding: utf-8 -*-
"""
DataFabric | examples.quickstart_local.batch_demo.etl_job

Локальный batch-ETL:
- Источник: директория с *.csv и/или *.jsonl
- Схема: JSON Schema (опционально). Валидация строк (best-effort).
- Трансформации: выбор/переименование/касты/добавление вычисляемых полей.
- Качество: профиль набора через DataProfiler.
- Вывод: атомарная запись в out_dir (gzip CSV), манифест JSON + подпись (опционально).
- Идемпотентность: чекпоинт по (имя файла, mtime, размер, sha256), повторно не перерабатывает.
- Логи: структурированные (в JSON при --json-logs).
- Безопасные дефолты, коды выхода (0=OK, 2=есть брак, 3=фатальная ошибка).

Зависимости (жёстких нет):
- datafabric.io.streams
- datafabric.quality.profiler (опционально)
- datafabric.security.signature (опционально)
- jsonschema/pandas/pyarrow (опционально)
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import logging
import os
import random
import shutil
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# ---------- Опциональные зависимости ----------
try:
    import pandas as pd  # type: ignore
    _HAS_PD = True
except Exception:
    _HAS_PD = False

try:
    import pyarrow as pa  # type: ignore
    import pyarrow.csv as pa_csv  # type: ignore
    _HAS_ARROW = True
except Exception:
    _HAS_ARROW = False

try:
    import jsonschema  # type: ignore
    _HAS_JSONSCHEMA = True
except Exception:
    _HAS_JSONSCHEMA = False

# ---------- DataFabric внутренние модули (опционально) ----------
try:
    from datafabric.io.streams import StreamConfig, open_writer, Manifest, copy_bytes_to_file  # type: ignore
    _HAS_STREAMS = True
except Exception:
    _HAS_STREAMS = False
    StreamConfig = None  # type: ignore
    open_writer = None  # type: ignore
    Manifest = None  # type: ignore
    copy_bytes_to_file = None  # type: ignore

try:
    from datafabric.quality.profiler import DataProfiler, ProfilerConfig  # type: ignore
    _HAS_PROFILER = True
except Exception:
    _HAS_PROFILER = False
    DataProfiler = None  # type: ignore
    ProfilerConfig = None  # type: ignore

try:
    from datafabric.security.signature import (  # type: ignore
        create_detached_signature, KeyRef, SigAlg, DigestAlg
    )
    _HAS_SIGN = True
except Exception:
    _HAS_SIGN = False
    create_detached_signature = None  # type: ignore
    KeyRef = None  # type: ignore
    SigAlg = None  # type: ignore
    DigestAlg = None  # type: ignore

LOG = logging.getLogger("datafabric.examples.etl")

# ---------- Конфиг ----------

@dataclass
class TransformRule:
    select: List[str] = field(default_factory=list)         # какие колонки оставить (в порядке)
    rename: Dict[str, str] = field(default_factory=dict)    # старое->новое имя
    casts: Dict[str, str] = field(default_factory=dict)     # имя->тип ('int','float','str','date:%Y-%m-%d')
    add_fields: Dict[str, str] = field(default_factory=dict)  # имя->expr (выражение на Python eval over 'row')
    drop_if_missing: List[str] = field(default_factory=list)  # если нет значения — строка отбраковывается

@dataclass
class JobConfig:
    in_dir: str
    out_dir: str
    schema_path: Optional[str] = None
    rule: TransformRule = field(default_factory=TransformRule)
    output_basename: str = "dataset"
    output_format: str = "csv-gz"  # csv-gz | csv
    partition_by_day: bool = True
    profile: bool = True
    # Чекпоинты и ретраи
    checkpoint_path: Optional[str] = None
    retries: int = 2
    backoff_base: float = 0.25
    backoff_factor: float = 2.0
    # Подпись манифеста
    sign_manifest: bool = False
    hmac_secret: Optional[str] = None  # если задан — HMAC_SHA256
    # Потоковое I/O
    chunk_size: int = 1024 * 1024
    checksum: bool = True

# ---------- Утилиты ----------

def setup_logging(json_logs: bool, verbose: int) -> None:
    level = logging.INFO if verbose == 0 else (logging.DEBUG if verbose > 1 else logging.WARNING)
    h = logging.StreamHandler(sys.stderr)
    fmt = '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}' if json_logs else "%(asctime)s %(levelname)s %(name)s %(message)s"
    h.setFormatter(logging.Formatter(fmt))
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(level)

def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_config(path: str) -> JobConfig:
    obj = read_json(path)
    # грубое связывание в dataclass
    rule = TransformRule(**obj.get("rule", {}))
    cfg = JobConfig(
        in_dir=obj["in_dir"],
        out_dir=obj["out_dir"],
        schema_path=obj.get("schema_path"),
        rule=rule,
        output_basename=obj.get("output_basename", "dataset"),
        output_format=obj.get("output_format", "csv-gz"),
        partition_by_day=bool(obj.get("partition_by_day", True)),
        profile=bool(obj.get("profile", True)),
        checkpoint_path=obj.get("checkpoint_path"),
        retries=int(obj.get("retries", 2)),
        backoff_base=float(obj.get("backoff_base", 0.25)),
        backoff_factor=float(obj.get("backoff_factor", 2.0)),
        sign_manifest=bool(obj.get("sign_manifest", False)),
        hmac_secret=obj.get("hmac_secret"),
        chunk_size=int(obj.get("chunk_size", 1024 * 1024)),
        checksum=bool(obj.get("checksum", True)),
    )
    return cfg

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def backoff_sleep(attempt: int, base: float, factor: float) -> None:
    delay = min(5.0, base * (factor ** max(0, attempt - 1))) + random.uniform(0, 0.05)
    time.sleep(delay)

def list_inputs(in_dir: str) -> List[Path]:
    p = Path(in_dir)
    items = sorted([*p.glob("*.csv"), *p.glob("*.jsonl")])
    return items

def load_checkpoint(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_checkpoint(path: Optional[str], ckpt: Dict[str, Any]) -> None:
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(ckpt, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(p)

# ---------- Схема и валидация ----------

def load_schema(schema_path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not schema_path:
        return None
    try:
        schema = read_json(schema_path)
        if _HAS_JSONSCHEMA:
            # лёгкая проверка валидности мета-схемы
            jsonschema.Draft7Validator.check_schema(schema)
        return schema
    except Exception as e:
        LOG.error("schema load failed: %s", e)
        return None

def validate_row(row: Dict[str, Any], schema: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    if not schema:
        return True, None
    if _HAS_JSONSCHEMA:
        try:
            jsonschema.validate(row, schema)  # type: ignore
            return True, None
        except Exception as e:
            return False, str(e)
    # минимальная проверка типов по "type" в properties
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    for k, p in props.items():
        if k not in row:
            continue
        t = p.get("type")
        v = row[k]
        if t == "integer" and isinstance(v, str):
            if not v.strip("-").isdigit():
                return False, f"{k} not integer-like"
        if t == "number":
            try:
                float(v)
            except Exception:
                return False, f"{k} not number-like"
    return True, None

# ---------- Трансформации ----------

def cast_value(val: Any, spec: str) -> Any:
    if val is None or val == "":
        return None
    if spec == "int":
        return int(float(val))
    if spec == "float":
        return float(val)
    if spec == "str":
        return str(val)
    if spec.startswith("date:"):
        fmt = spec.split(":", 1)[1]
        # Приводим к ISO дате
        return datetime.strptime(str(val), fmt).date().isoformat()
    return val

def apply_transform(row: Dict[str, Any], rule: TransformRule) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    r = dict(row)
    # rename
    for old, new in rule.rename.items():
        if old in r:
            r[new] = r.pop(old)
    # select
    if rule.select:
        r = {k: r.get(k) for k in rule.select}
    # casts
    for k, typ in rule.casts.items():
        if k in r:
            try:
                r[k] = cast_value(r[k], typ)
            except Exception as e:
                return None, f"cast failed for {k}: {e}"
    # add fields (eval с минимальным окружением)
    for k, expr in rule.add_fields.items():
        try:
            r[k] = eval(expr, {"__builtins__": {}}, {"row": r})
        except Exception as e:
            return None, f"expr failed for {k}: {e}"
    # drop if missing
    for k in rule.drop_if_missing:
        if r.get(k) in (None, "", []):
            return None, f"missing required {k}"
    return r, None

# ---------- Чтение источника ----------

def read_csv_rows(path: Path) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield dict(row)

def read_jsonl_rows(path: Path) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            yield json.loads(line)

def iter_rows(path: Path) -> Iterator[Dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        yield from read_csv_rows(path)
    else:
        yield from read_jsonl_rows(path)

# ---------- Запись результата ----------

def write_csv_gz_atomic(rows: Iterable[Dict[str, Any]], out_path: Path, chunk_size: int = 1024 * 1024) -> Dict[str, Any]:
    """
    Пишет gzip CSV атомарно без сторонних модулей.
    Возвращает метаданные (байты, строки).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    count = 0
    bytes_written = 0
    # Определяем заголовок по первой строке
    rows_iter = iter(rows)
    try:
        first = next(rows_iter)
    except StopIteration:
        # пустой файл — создаём пустой gzip с заголовком без строк
        with gzip.open(tmp, "wt", encoding="utf-8", newline="") as gz:
            pass
        tmp.replace(out_path)
        return {"rows": 0, "bytes": out_path.stat().st_size}
    fieldnames = list(first.keys())
    with gzip.open(tmp, "wt", encoding="utf-8", newline="") as gz:
        w = csv.DictWriter(gz, fieldnames=fieldnames)
        w.writeheader()
        w.writerow(first); count += 1
        for row in rows_iter:
            w.writerow(row); count += 1
    bytes_written = tmp.stat().st_size
    tmp.replace(out_path)
    return {"rows": count, "bytes": bytes_written, "columns": fieldnames}

# ---------- Профилирование ----------

def profile_dataset(rows_path: Path, columns_hint: Optional[List[str]], cfg: JobConfig) -> Optional[Dict[str, Any]]:
    if not _HAS_PROFILER:
        return None
    # Профилируем напрямую CSV
    pcfg = ProfilerConfig(max_rows=None, timeout_sec=30.0, reservoir_size=50_000, histogram_bins=50, hll_precision_p=14, topk_k=20)  # type: ignore
    prof = DataProfiler(pcfg).profile(str(rows_path))  # type: ignore
    return {
        "rows": prof.n_rows_scanned,
        "cols": prof.n_cols,
        "elapsed_sec": round(prof.elapsed_sec, 3),
        "columns": [
            {
                "name": c.name,
                "type": c.col_type.base,
                "count": c.count,
                "nulls": c.nulls,
                "p50": c.p50,
                "distinct_estimate": c.distinct_estimate,
            } for c in prof.columns
        ],
    }

# ---------- Манифест и подпись ----------

def build_manifest(input_files: List[Dict[str, Any]], output_path: Path, write_meta: Dict[str, Any], rejected_rows: int, cfg: JobConfig) -> Dict[str, Any]:
    m = {
        "created_at": int(time.time()),
        "output": str(output_path),
        "output_bytes": write_meta.get("bytes"),
        "output_rows": write_meta.get("rows"),
        "columns": write_meta.get("columns"),
        "input": input_files,
        "rejected_rows": rejected_rows,
        "config": asdict(cfg),
        "tool": {"name": "datafabric-etl-job", "version": "1.0.0"},
    }
    return m

def sign_manifest_if_needed(manifest: Dict[str, Any], cfg: JobConfig) -> Optional[Dict[str, Any]]:
    if not cfg.sign_manifest or not _HAS_SIGN or not cfg.hmac_secret:
        return None
    key = KeyRef(kid="local-demo", secret=cfg.hmac_secret.encode("utf-8"))  # type: ignore
    sig = create_detached_signature(manifest, key=key, alg=SigAlg.HMAC_SHA256, digest_alg=DigestAlg.SHA256)  # type: ignore
    return sig

# ---------- Основной конвейер ----------

def process_file(path: Path, schema: Optional[Dict[str, Any]], cfg: JobConfig) -> Tuple[List[Dict[str, Any]], int]:
    """Возвращает (строки трансформированные, число отбракованных) — только для небольших файлов.
    Для больших файлов используйте потоковую запись ниже.
    """
    out_rows: List[Dict[str, Any]] = []
    rejected = 0
    for row in iter_rows(path):
        ok, reason = validate_row(row, schema)
        if not ok:
            rejected += 1
            continue
        row2, err = apply_transform(row, cfg.rule)
        if row2 is None:
            rejected += 1
            continue
        out_rows.append(row2)
    return out_rows, rejected

def run_job(cfg: JobConfig) -> int:
    LOG.info("job.start in_dir=%s out_dir=%s", cfg.in_dir, cfg.out_dir)
    inputs = list_inputs(cfg.in_dir)
    if not inputs:
        LOG.info("no input files, exiting")
        return 0

    ckpt = load_checkpoint(cfg.checkpoint_path)
    schema = load_schema(cfg.schema_path)

    processed_meta: List[Dict[str, Any]] = []
    all_rows: List[Dict[str, Any]] = []
    total_rejected = 0

    for p in inputs:
        try:
            st = p.stat()
            sha = sha256_file(p)
            key = f"{p.name}:{int(st.st_mtime)}:{st.st_size}:{sha}"
            if ckpt.get(key):
                LOG.info("skip already processed: %s", p.name)
                continue
            LOG.info("process file: %s", p.name)
            rows, rejected = process_file(p, schema, cfg)
            total_rejected += rejected
            LOG.info("file done: rows_ok=%d rejected=%d", len(rows), rejected)
            processed_meta.append({"path": str(p), "size": st.st_size, "mtime": int(st.st_mtime), "sha256": sha, "rows_ok": len(rows), "rows_rejected": rejected})
            all_rows.extend(rows)
            ckpt[key] = {"at": int(time.time())}
        except Exception as e:
            LOG.error("process failed for %s: %s", p, e)
            # не фейлим весь джоб: продолжаем
            continue

    if not all_rows:
        LOG.warning("no rows to write; exiting")
        save_checkpoint(cfg.checkpoint_path, ckpt)
        return 2 if total_rejected > 0 else 0

    # Вычисляем путь результата
    out_dir = Path(cfg.out_dir)
    part = datetime.utcnow().strftime("%Y-%m-%d") if cfg.partition_by_day else "nopart"
    out_dir = out_dir / f"dt={part}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{cfg.output_basename}.csv.gz" if cfg.output_format == "csv-gz" else out_dir / f"{cfg.output_basename}.csv"

    # Запись результата
    attempt = 0
    write_meta: Dict[str, Any] = {}
    while True:
        try:
            if cfg.output_format == "csv-gz":
                write_meta = write_csv_gz_atomic(all_rows, out_path, chunk_size=cfg.chunk_size)
            else:
                # без gzip
                tmp = out_path.with_suffix(out_path.suffix + ".tmp")
                tmp.parent.mkdir(parents=True, exist_ok=True)
                with open(tmp, "w", encoding="utf-8", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
                    w.writeheader()
                    for r in all_rows:
                        w.writerow(r)
                tmp.replace(out_path)
                write_meta = {"rows": len(all_rows), "bytes": out_path.stat().st_size, "columns": list(all_rows[0].keys())}
            break
        except Exception as e:
            attempt += 1
            if attempt > cfg.retries:
                LOG.error("write failed: %s", e)
                return 3
            backoff_sleep(attempt, cfg.backoff_base, cfg.backoff_factor)

    # Профиль качества (опционально)
    quality: Optional[Dict[str, Any]] = None
    if cfg.profile:
        try:
            # для gzip передаем путь напрямую — профилировщик умеет CSV‑файл
            quality = profile_dataset(out_path if cfg.output_format != "csv-gz" else out_path, write_meta.get("columns"), cfg)
        except Exception as e:
            LOG.warning("quality profiling failed: %s", e)

    # Манифест и подпись
    manifest = build_manifest(processed_meta, out_path, write_meta, total_rejected, cfg)
    if quality:
        manifest["quality"] = quality
    signature = sign_manifest_if_needed(manifest, cfg)
    if signature:
        manifest["signature"] = signature

    # Сохраняем манифест рядом
    manifest_path = out_dir / f"{cfg.output_basename}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")

    # Чекпоинт
    save_checkpoint(cfg.checkpoint_path, ckpt)

    LOG.info("job.done output=%s rows=%s rejected=%s bytes=%s", out_path, write_meta.get("rows"), total_rejected, write_meta.get("bytes"))
    return 0 if total_rejected == 0 else 2

# ---------- CLI ----------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="etl_job", description="DataFabric Quickstart Local Batch ETL")
    p.add_argument("--config", required=True, help="path to job config JSON")
    p.add_argument("--json-logs", action="store_true", help="structured logs as JSON")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p

def main(argv: Optional[List[str]] = None) -> None:
    args = build_arg_parser().parse_args(argv)
    setup_logging(args.json_logs, args.verbose)
    try:
        cfg = load_config(args.config)
    except Exception as e:
        LOG.error("config load failed: %s", e)
        sys.exit(3)
    code = run_job(cfg)
    sys.exit(code)

if __name__ == "__main__":
    main()
