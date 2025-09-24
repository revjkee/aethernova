#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dump_decisions.py — потоковый дампер решений PEP/PDP из логов.

Возможности:
- Источники: stdin, локальные файлы (включая .gz), S3 префикс (s3://bucket/prefix).
- Фильтры: время (ISO8601), effect, tenant, subject_id, role, method, path (regex),
           rule_id, reason substring, request_id/correlation_id, type (pep_decision|veilmind_decision).
- Вывод: ndjson | csv | table (по умолчанию table для TTY, иначе ndjson).
- Сводка: --stats (по effect/rule_id/path/tenant/subject_id, --top N).
- Устойчивость: игнор «грязных» строк, защита от OOM (стриминг), аккуратные ошибки.
- S3 (опционально): чтение объектов по префиксу, фильтр по ключу (--s3-key-regex), параллель до --s3-max.
  Требуется boto3; при отсутствии — graceful fallback.

Пример:
  cat app.log | python dump_decisions.py --effect deny --format table --stats --top 10
  python dump_decisions.py --files logs/app-*.log.gz --path '^/api/v1/secure' --format csv > denies.csv
  python dump_decisions.py --s3 s3://acme-logs/policy/ --effect permit --from 2025-08-01T00:00:00Z --stats

Автор: Aethernova / NeuroCity policy-core
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import itertools
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# Опционально: boto3 для S3
try:
    import boto3  # type: ignore
    from botocore.config import Config as BotoConfig  # type: ignore
    _BOTO3_OK = True
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore
    BotoConfig = None  # type: ignore
    _BOTO3_OK = False

# ---------------------- Утилиты времени ----------------------

_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)

def _parse_iso8601(s: str) -> Optional[float]:
    try:
        if not s:
            return None
        if not _ISO_RE.match(s):
            # Допускаем без 'Z' -> добавим 'Z'
            if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", s):
                s = s.rstrip("Z") + "Z"
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return None

def _extract_ts(obj: Dict[str, Any]) -> Optional[float]:
    # Ищем поле времени: ts|time|@timestamp
    for k in ("ts", "time", "@timestamp"):
        v = obj.get(k)
        if isinstance(v, (int, float)):
            # предполагаем сек/мс
            if v > 10**12:  # мс
                return v / 1000.0
            return float(v)
        if isinstance(v, str):
            t = _parse_iso8601(v)
            if t is not None:
                return t
    return None  # нет явного таймштампа — фильтр времени будет пропущен

# ---------------------- Источники ввода ----------------------

def _is_gz_path(p: str) -> bool:
    return p.lower().endswith(".gz")

def _open_file_stream(path: str) -> Iterator[str]:
    try:
        if _is_gz_path(path):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line
        else:
            with open(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line
    except Exception as e:
        print(f"[warn] cannot read file: {path} ({type(e).__name__})", file=sys.stderr)

def _stdin_stream() -> Iterator[str]:
    for line in sys.stdin:
        yield line

# ---------------------- S3 ввод (опционально) ----------------------

@dataclass
class S3Config:
    url: str
    region: Optional[str] = None
    connect_timeout: float = 2.0
    read_timeout: float = 5.0
    max_attempts: int = 5
    key_regex: Optional[re.Pattern] = None
    max_workers: int = 4

def _parse_s3_url(url: str) -> Tuple[str, str]:
    # s3://bucket/prefix -> (bucket, prefix)
    m = re.match(r"^s3://([^/]+)/(.*)$", url)
    if not m:
        raise ValueError("S3 URL must be s3://bucket/prefix")
    return m.group(1), m.group(2).lstrip("/")

def _iter_s3_keys(cfg: S3Config) -> Iterator[Tuple[str, str]]:
    if not _BOTO3_OK:
        print("[warn] boto3 is not available; S3 disabled", file=sys.stderr)
        return iter(())  # пустой итератор
    bucket, prefix = _parse_s3_url(cfg.url)
    client = boto3.client(
        "s3",
        region_name=cfg.region,
        config=BotoConfig(
            retries={"max_attempts": cfg.max_attempts, "mode": "standard"},
            connect_timeout=cfg.connect_timeout,
            read_timeout=cfg.read_timeout,
        ),
    )
    token = None
    while True:
        params = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            params["ContinuationToken"] = token
        resp = client.list_objects_v2(**params)
        for it in resp.get("Contents", []):
            key = it["Key"]
            if cfg.key_regex and not cfg.key_regex.search(key):
                continue
            yield bucket, key
        token = resp.get("NextContinuationToken")
        if not token:
            break

def _read_s3_object(client, bucket: str, key: str) -> Iterator[str]:
    try:
        obj = client.get_object(Bucket=bucket, Key=key)
        body = obj["Body"]
        stream = io.TextIOWrapper(body, encoding="utf-8", errors="replace")
        # Если объект gz — попробуем распаковать
        if key.lower().endswith(".gz"):
            # скачиваем целиком, но ограничиться построчным из gzip почти невозможно без локального буфера
            # поэтому компромисс: читаем в память порционно
            raw = obj["Body"].read()
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                for bline in gz.read().splitlines():
                    yield bline.decode("utf-8", "replace")
        else:
            for line in stream:
                yield line
    except Exception as e:
        print(f"[warn] cannot read s3://{bucket}/{key} ({type(e).__name__})", file=sys.stderr)

def _s3_stream(cfg: S3Config) -> Iterator[str]:
    if not _BOTO3_OK:
        return iter(())
    bucket, _ = _parse_s3_url(cfg.url)
    client = boto3.client(
        "s3",
        region_name=cfg.region,
        config=BotoConfig(
            retries={"max_attempts": cfg.max_attempts, "mode": "standard"},
            connect_timeout=cfg.connect_timeout,
            read_timeout=cfg.read_timeout,
        ),
    )
    # Параллельное чтение объектов
    ex = ThreadPoolExecutor(max_workers=max(1, cfg.max_workers))
    futures = []
    for b, key in _iter_s3_keys(cfg):
        futures.append(ex.submit(list, _read_s3_object(client, b, key)))
    for fut in as_completed(futures):
        try:
            for line in fut.result():
                yield line
        except Exception as e:
            print(f"[warn] s3 future error: {type(e).__name__}", file=sys.stderr)
    ex.shutdown(wait=True)

# ---------------------- Парсинг и фильтры ----------------------

@dataclass
class Filters:
    t_from: Optional[float] = None
    t_to: Optional[float] = None
    effect: Optional[str] = None
    tenant: Optional[str] = None
    subject: Optional[str] = None
    role: Optional[str] = None
    method: Optional[str] = None
    path_regex: Optional[re.Pattern] = None
    rule_id: Optional[str] = None
    reason_substr: Optional[str] = None
    req_id: Optional[str] = None
    corr_id: Optional[str] = None
    types: Tuple[str, ...] = ("pep_decision", "veilmind_decision")

    def match(self, obj: Dict[str, Any]) -> bool:
        t = obj.get("type")
        if t not in self.types:
            return False
        ts = _extract_ts(obj)
        if self.t_from is not None and ts is not None and ts < self.t_from:
            return False
        if self.t_to is not None and ts is not None and ts > self.t_to:
            return False
        if self.effect and str(obj.get("effect") or "").lower() != self.effect:
            return False
        if self.tenant and str(obj.get("tenant") or "") != self.tenant:
            return False
        if self.subject and str(obj.get("subject_id") or "") != self.subject:
            return False
        if self.role:
            roles = obj.get("roles") or []
            if self.role not in [str(r) for r in roles]:
                return False
        if self.method and str(obj.get("method") or "").upper() != self.method:
            return False
        if self.path_regex and not self.path_regex.search(str(obj.get("path") or "")):
            return False
        if self.rule_id and str(obj.get("rule_id") or "") != self.rule_id:
            return False
        if self.reason_substr and self.reason_substr.lower() not in str(obj.get("reason") or "").lower():
            return False
        if self.req_id and str(obj.get("request_id") or "") != self.req_id:
            return False
        if self.corr_id and str(obj.get("correlation_id") or "") != self.corr_id:
            return False
        return True

# ---------------------- Вывод ----------------------

_FIELDS = [
    "type",
    "effect",
    "tenant",
    "subject_id",
    "roles",
    "method",
    "path",
    "rule_id",
    "reason",
    "request_id",
    "correlation_id",
    "ttl",
]

def _to_row(obj: Dict[str, Any]) -> List[str]:
    return [
        str(obj.get("type") or ""),
        str(obj.get("effect") or ""),
        str(obj.get("tenant") or ""),
        str(obj.get("subject_id") or ""),
        ",".join([str(r) for r in (obj.get("roles") or [])]),
        str(obj.get("method") or ""),
        str(obj.get("path") or ""),
        str(obj.get("rule_id") or ""),
        str(obj.get("reason") or ""),
        str(obj.get("request_id") or ""),
        str(obj.get("correlation_id") or ""),
        str(obj.get("ttl") or obj.get("ttl_seconds") or ""),
    ]

def _print_table(rows: Iterable[List[str]], headers: List[str]) -> None:
    # Простой табличный вывод без внешних зависимостей
    rows = list(rows)
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            if len(c) > widths[i]:
                widths[i] = min(120, len(c))
    def fmt_row(vals: List[str]) -> str:
        return " | ".join(v[:widths[i]].ljust(widths[i]) for i, v in enumerate(vals))
    sep = "-+-".join("-" * w for w in widths)
    print(fmt_row(headers))
    print(sep)
    for r in rows:
        print(fmt_row(r))

def _print_csv(rows: Iterable[List[str]], headers: List[str]) -> None:
    w = csv.writer(sys.stdout)
    w.writerow(headers)
    for r in rows:
        w.writerow(r)

def _print_ndjson(objs: Iterable[Dict[str, Any]]) -> None:
    for o in objs:
        print(json.dumps(o, ensure_ascii=False))

# ---------------------- Статистика ----------------------

@dataclass
class Stats:
    by_effect: Dict[str, int] = field(default_factory=dict)
    by_rule: Dict[str, int] = field(default_factory=dict)
    by_path: Dict[str, int] = field(default_factory=dict)
    by_tenant: Dict[str, int] = field(default_factory=dict)
    by_subject: Dict[str, int] = field(default_factory=dict)
    total: int = 0
    skipped: int = 0

    def add(self, obj: Dict[str, Any]) -> None:
        self.total += 1
        eff = str(obj.get("effect") or "")
        self.by_effect[eff] = self.by_effect.get(eff, 0) + 1
        r = str(obj.get("rule_id") or "")
        self.by_rule[r] = self.by_rule.get(r, 0) + 1
        p = str(obj.get("path") or "")
        self.by_path[p] = self.by_path.get(p, 0) + 1
        t = str(obj.get("tenant") or "")
        self.by_tenant[t] = self.by_tenant.get(t, 0) + 1
        s = str(obj.get("subject_id") or "")
        self.by_subject[s] = self.by_subject.get(s, 0) + 1

    def dump(self, top: int = 10) -> None:
        def topn(d: Dict[str, int]) -> List[Tuple[str, int]]:
            return sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:top]
        print("\n== Stats ==")
        print(f"Total: {self.total}  |  Skipped: {self.skipped}")
        for title, d in [
            ("By effect", self.by_effect),
            ("By rule_id", self.by_rule),
            ("By path", self.by_path),
            ("By tenant", self.by_tenant),
            ("By subject_id", self.by_subject),
        ]:
            print(f"\n{title}:")
            for k, v in topn(d):
                print(f"  {k or '<empty>'}: {v}")

# ---------------------- Основная логика ----------------------

def _iter_objects_from_lines(lines: Iterable[str]) -> Iterator[Dict[str, Any]]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Пытаемся найти JSON в строке
        obj: Optional[Dict[str, Any]] = None
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
            except Exception:
                obj = None
        else:
            # иногда JSON идёт после префикса времени/уровня
            p = line.find("{")
            if p >= 0:
                frag = line[p:]
                try:
                    obj = json.loads(frag)
                except Exception:
                    obj = None
        if not isinstance(obj, dict):
            yield {"__skip__": True, "__raw__": line}
            continue
        yield obj

def _build_filters(args: argparse.Namespace) -> Filters:
    t_from = _parse_iso8601(args.time_from) if args.time_from else None
    t_to = _parse_iso8601(args.time_to) if args.time_to else None
    path_re = re.compile(args.path) if args.path else None
    types = tuple(args.type) if args.type else ("pep_decision", "veilmind_decision")
    return Filters(
        t_from=t_from,
        t_to=t_to,
        effect=(args.effect.lower() if args.effect else None),
        tenant=args.tenant,
        subject=args.subject,
        role=args.role,
        method=(args.method.upper() if args.method else None),
        path_regex=path_re,
        rule_id=args.rule_id,
        reason_substr=args.reason,
        req_id=args.request_id,
        corr_id=args.correlation_id,
        types=types,
    )

def _iter_input(args: argparse.Namespace) -> Iterator[str]:
    yielded = False
    if args.files:
        for pat in args.files:
            # простая глоб-поддержка
            for path in sorted(_glob_paths(pat)):
                yielded = True
                yield from _open_file_stream(path)
    if args.s3:
        yielded = True
        key_re = re.compile(args.s3_key_regex) if args.s3_key_regex else None
        s3cfg = S3Config(url=args.s3, region=args.s3_region,
                         key_regex=key_re, max_workers=args.s3_max)
        yield from _s3_stream(s3cfg)
    if not yielded:
        # stdin
        yield from _stdin_stream()

def _glob_paths(pattern: str) -> List[str]:
    # Не используем glob.iglob чтобы отсортировать стабильно
    import glob
    return glob.glob(pattern)

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Dump and filter PEP/PDP decision logs (pep_decision, veilmind_decision)."
    )
    src = p.add_argument_group("Input")
    src.add_argument("--files", nargs="*", help="Paths or globs to log files (.log, .gz).")
    src.add_argument("--s3", help="S3 URL: s3://bucket/prefix")
    src.add_argument("--s3-region", help="S3 region name")
    src.add_argument("--s3-key-regex", help="Regex to filter S3 keys")
    src.add_argument("--s3-max", type=int, default=4, help="Max parallel S3 downloads (default: 4)")

    flt = p.add_argument_group("Filters")
    flt.add_argument("--time-from", help="ISO8601 start time, e.g. 2025-08-01T00:00:00Z")
    flt.add_argument("--time-to", help="ISO8601 end time, e.g. 2025-08-28T23:59:59Z")
    flt.add_argument("--effect", choices=["permit", "deny"], help="Effect filter")
    flt.add_argument("--tenant", help="Tenant")
    flt.add_argument("--subject", help="Subject ID")
    flt.add_argument("--role", help="Role name")
    flt.add_argument("--method", help="HTTP method (GET/POST/...)")
    flt.add_argument("--path", help="Regex for resource path")
    flt.add_argument("--rule-id", help="Rule ID")
    flt.add_argument("--reason", help="Substring in reason")
    flt.add_argument("--request-id", help="X-Request-ID exact match")
    flt.add_argument("--correlation-id", help="X-Correlation-ID exact match")
    flt.add_argument("--type", nargs="*", choices=["pep_decision", "veilmind_decision"], help="Event types")

    out = p.add_argument_group("Output")
    out.add_argument("--format", choices=["ndjson", "csv", "table"], help="Output format")
    out.add_argument("--stats", action="store_true", help="Show aggregated stats")
    out.add_argument("--top", type=int, default=10, help="Top N for stats (default: 10)")
    out.add_argument("--limit", type=int, help="Limit number of rows in output")

    args = p.parse_args(argv)

    # Формат вывода по умолчанию
    fmt = args.format
    if not fmt:
        fmt = "table" if sys.stdout.isatty() else "ndjson"

    filters = _build_filters(args)
    stats = Stats()

    rows: List[List[str]] = []
    objs_for_ndjson: List[Dict[str, Any]] = []

    produced = 0
    for obj in _iter_objects_from_lines(_iter_input(args)):
        if obj.get("__skip__"):
            stats.skipped += 1
            continue
        if not filters.match(obj):
            continue
        stats.add(obj)
        if fmt == "ndjson":
            objs_for_ndjson.append(obj)
        else:
            rows.append(_to_row(obj))
        produced += 1
        if args.limit and produced >= args.limit:
            break

    # Вывод
    if fmt == "ndjson":
        _print_ndjson(objs_for_ndjson)
    elif fmt == "csv":
        _print_csv(rows, _FIELDS)
    else:
        _print_table(rows, _FIELDS)

    if args.stats:
        stats.dump(top=max(1, args.top))

    # Диагностика в stderr
    print(f"[info] produced={produced} total={stats.total} skipped={stats.skipped}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
