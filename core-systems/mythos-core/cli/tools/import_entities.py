#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mythos Core — CLI импортёр графовых сущностей.

Форматы входа:
  - NDJSON: одна запись на строку (Node/Edge/BatchChunk)
  - JSON:   массив записей или объект BatchChunk
  - CSV:    строки, транслируемые в Node/Edge по mapping-файлу (JSON/YAML)

Режимы доставки:
  - stream: NDJSON-стрим в /v1/graph/import (максимальная производительность)
  - batch:  POST чанков в /v1/graph/batch с контролем чекпойнта

Требования:
  pip install requests  (PyYAML опционально для .yaml mapping)
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import sys
import time
import typing as t
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from threading import Event, Thread

import requests

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

# --------------------------------- Константы/утилиты ----------------------------------

ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

def new_ulid() -> str:
    ts_ms = int(time.time() * 1000)
    rnd = int.from_bytes(os.urandom(10), "big")
    val = (ts_ms << 80) | rnd
    out = []
    for _ in range(26):
        out.append(ULID_ALPHABET[val & 31])
        val >>= 5
    return "".join(reversed(out))

def eprint(*args: t.Any, **kwargs: t.Any) -> None:
    print(*args, file=sys.stderr, **kwargs)

def sha256_of_bytes(b: bytes) -> str:
    import hashlib
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

# --------------------------------- Типы данных ----------------------------------------

@dataclass
class Stats:
    lines_in: int = 0
    nodes_out: int = 0
    edges_out: int = 0
    batches_sent: int = 0
    bytes_sent: int = 0
    http_tries: int = 0
    http_failures: int = 0
    started_at: float = time.time()
    def as_dict(self) -> dict:
        return {
            "lines_in": self.lines_in,
            "nodes_out": self.nodes_out,
            "edges_out": self.edges_out,
            "batches_sent": self.batches_sent,
            "bytes_sent": self.bytes_sent,
            "http_tries": self.http_tries,
            "http_failures": self.http_failures,
            "duration_sec": round(time.time() - self.started_at, 3),
        }

# Канонические структуры Node/Edge для HTTP-API (совместимы с routers/v1/graph.py)
def canon_node(record: dict) -> dict:
    # допускаем уже каноничную форму
    if "resource" in record and "kind" in record:
        return record
    # допускаем укороченную: {"id": "...", "kind": "user", "props": {...}, "labels": {...}}
    rid = record.get("id") or record.get("resource", {}).get("id")
    if not rid:
        rid = new_ulid()
    props = record.get("props") or {}
    if "entries" not in props:
        props = {"entries": {k: _wrap_value(v) for k, v in props.items()}}
    labels = record.get("labels") or {}
    if "entries" not in labels:
        labels = {"entries": labels}
    return {
        "resource": {"id": rid},
        "kind": record["kind"],
        "props": props,
        "labels": labels,
    }

def canon_edge(record: dict) -> dict:
    if "resource" in record and "src" in record and "dst" in record:
        return record
    rid = record.get("id") or record.get("resource", {}).get("id") or new_ulid()
    src = record.get("src") or record.get("from") or record.get("source")
    dst = record.get("dst") or record.get("to") or record.get("target")
    if isinstance(src, dict):
        src_id = src.get("id")
    else:
        src_id = src
    if isinstance(dst, dict):
        dst_id = dst.get("id")
    else:
        dst_id = dst
    if not src_id or not dst_id:
        raise ValueError("edge requires src/dst identifiers")
    props = record.get("props") or {}
    if "entries" not in props:
        props = {"entries": {k: _wrap_value(v) for k, v in props.items()}}
    labels = record.get("labels") or {}
    if "entries" not in labels:
        labels = {"entries": labels}
    directed = bool(record.get("directed", True))
    return {
        "resource": {"id": rid},
        "src": {"id": src_id},
        "dst": {"id": dst_id},
        "type": record["type"],
        "props": props,
        "labels": labels,
        "directed": directed,
    }

def _wrap_value(v: t.Any) -> dict:
    if isinstance(v, bool):
        return {"b": v}
    if isinstance(v, int):
        return {"i": v}
    if isinstance(v, float):
        return {"d": v}
    if isinstance(v, (bytes, bytearray)):
        return {"by": bytes(v)}
    return {"s": str(v)}

# --------------------------------- Маппинг CSV ----------------------------------------

class MappingError(Exception):
    pass

def load_mapping(path: Path) -> dict:
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise MappingError("PyYAML is not installed, cannot read YAML mapping")
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def render_template(tpl: t.Any, row: dict) -> t.Any:
    """
    Поддерживает строки со вставками {field[:type]} и словари/списки (обрабатываются рекурсивно).
    Типы: int, float, bool, json.
    """
    if isinstance(tpl, dict):
        return {k: render_template(v, row) for k, v in tpl.items()}
    if isinstance(tpl, list):
        return [render_template(x, row) for x in tpl]
    if not isinstance(tpl, str):
        return tpl
    out = tpl
    # простой парсер плейсхолдеров
    import re
    def repl(m: "re.Match[str]") -> str:
        spec = m.group(1)
        if ":" in spec:
            fld, typ = spec.split(":", 1)
        else:
            fld, typ = spec, "str"
        raw = row.get(fld, "")
        if typ == "int":
            return str(int(raw)) if raw != "" else "0"
        if typ == "float":
            return str(float(raw)) if raw != "" else "0.0"
        if typ == "bool":
            return "true" if str(raw).lower() in ("1", "true", "yes", "y") else "false"
        if typ == "json":
            try:
                return json.dumps(json.loads(raw))
            except Exception:
                return json.dumps(raw)
        return str(raw)
    return re.sub(r"\{([A-Za-z_][A-Za-z0-9_:\-]*)\}", repl, out)

def csv_row_to_entity(row: dict, mapping: dict, mode: str) -> dict:
    """
    Преобразует CSV строку в Node/Edge согласно mapping.
    Пример mapping (nodes):
      mode: nodes
      kind: user
      id: "{user_id}"
      props:
        name: "{name}"
        age: "{age:int}"
      labels:
        env: "prod"
    Пример mapping (edges):
      mode: edges
      type: follows
      id: "{edge_id}"
      src: "{src_id}"
      dst: "{dst_id}"
      props:
        weight: "{weight:float}"
    """
    if mode == "nodes":
        item = {
            "id": render_template(mapping.get("id") or "", row) or None,
            "kind": mapping["kind"],
            "props": {k: _coerce(render_template(v, row)) for k, v in (mapping.get("props") or {}).items()},
            "labels": {k: render_template(v, row) for k, v in (mapping.get("labels") or {}).items()},
        }
        return canon_node(item)
    elif mode == "edges":
        item = {
            "id": render_template(mapping.get("id") or "", row) or None,
            "type": mapping["type"],
            "src": render_template(mapping["src"], row),
            "dst": render_template(mapping["dst"], row),
            "props": {k: _coerce(render_template(v, row)) for k, v in (mapping.get("props") or {}).items()},
            "labels": {k: render_template(v, row) for k, v in (mapping.get("labels") or {}).items()},
            "directed": bool(mapping.get("directed", True)),
        }
        return canon_edge(item)
    else:
        raise MappingError("mapping.mode must be 'nodes' or 'edges'")

def _coerce(s: t.Any) -> t.Any:
    # Приходит строка из render_template; попытка привести к числу/булю, иначе строка.
    if isinstance(s, (int, float, bool, dict, list)):
        return s
    if not isinstance(s, str):
        return s
    sl = s.lower()
    if sl in ("true", "false"):
        return sl == "true"
    try:
        if "." in s:
            return float(s)
        return int(s)
    except Exception:
        return s

# ----------------------------- Парсеры входных файлов ---------------------------------

def iter_ndjson(fh: t.Iterable[str]) -> t.Iterator[dict]:
    for line in fh:
        if not line.strip():
            continue
        yield json.loads(line)

def iter_json(fh: io.TextIOBase) -> t.Iterator[dict]:
    data = json.load(fh)
    if isinstance(data, list):
        for x in data:
            yield x
    elif isinstance(data, dict):
        # либо BatchChunk, либо одиночная запись
        if "nodes" in data or "edges" in data:
            for n in data.get("nodes", []):
                yield {"node": n}
            for e in data.get("edges", []):
                yield {"edge": e}
        else:
            yield data
    else:
        raise ValueError("Unsupported JSON root")

def iter_csv(fh: io.TextIOBase, mapping: dict) -> t.Iterator[dict]:
    rdr = csv.DictReader(fh)
    mode = (mapping.get("mode") or "").strip().lower()
    if mode not in ("nodes", "edges"):
        raise MappingError("mapping.mode must be 'nodes' or 'edges'")
    for row in rdr:
        yield csv_row_to_entity(row, mapping, mode)

# --------------------------------- Буферизация чанков ---------------------------------

def chunkify_entities(
    records: t.Iterator[dict],
    chunk_size: int = 1000,
) -> t.Iterator[dict]:
    """
    Принимает записи в виде:
      - каноничный Node/Edge
      - {"node": <Node>}
      - {"edge": <Edge>}
    Выдаёт BatchChunk: {"nodes":[...], "edges":[...]} размером до chunk_size.
    """
    nodes: list = []
    edges: list = []
    for rec in records:
        if "node" in rec:
            nodes.append(canon_node(rec["node"]))
        elif "edge" in rec:
            edges.append(canon_edge(rec["edge"]))
        else:
            # попытка автоопределения
            if "kind" in rec:
                nodes.append(canon_node(rec))
            elif "type" in rec and ("src" in rec or "dst" in rec):
                edges.append(canon_edge(rec))
            else:
                raise ValueError("Unknown record shape")
        if (len(nodes) + len(edges)) >= chunk_size:
            yield {"nodes": nodes, "edges": edges}
            nodes, edges = [], []
    if nodes or edges:
        yield {"nodes": nodes, "edges": edges}

# --------------------------------- HTTP отправка --------------------------------------

class HttpError(Exception):
    pass

def post_stream_import(
    session: requests.Session,
    api_base: str,
    chunks: t.Iterator[dict],
    idempotency_key: str,
    token: t.Optional[str],
    timeout: int,
    stats: Stats,
) -> dict:
    """
    Отправляет NDJSON-стримом чанки в /v1/graph/import.
    """
    url = api_base.rstrip("/") + "/import"
    headers = {
        "Content-Type": "application/x-ndjson; charset=utf-8",
        "Idempotency-Key": idempotency_key,
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def gen() -> t.Iterator[bytes]:
        for ch in chunks:
            line = json.dumps(ch, ensure_ascii=False, separators=(",", ":")) + "\n"
            b = line.encode("utf-8")
            stats.bytes_sent += len(b)
            yield b

    # ретраи при 5xx/сетевых ошибках
    backoff = 0.2
    for attempt in range(1, 8):
        stats.http_tries += 1
        try:
            resp = session.post(url, data=gen(), headers=headers, timeout=timeout)
            if 200 <= resp.status_code < 300:
                return resp.json() if resp.content else {"ok": True}
            if resp.status_code in (408, 425, 429, 500, 502, 503, 504):
                stats.http_failures += 1
                time.sleep(backoff)
                backoff = min(2.0, backoff * 2.0)
                continue
            raise HttpError(f"HTTP {resp.status_code}: {resp.text[:500]}")
        except (requests.Timeout, requests.ConnectionError) as e:
            stats.http_failures += 1
            time.sleep(backoff)
            backoff = min(2.0, backoff * 2.0)
            if attempt == 7:
                raise HttpError(str(e))
    raise HttpError("exhausted retries")

def post_batch(
    session: requests.Session,
    api_base: str,
    chunk: dict,
    idempotency_key: str,
    token: t.Optional[str],
    timeout: int,
    stats: Stats,
) -> dict:
    """
    Отправляет один BatchChunk через /v1/graph/batch, оборачивая в контракт API.
    """
    url = api_base.rstrip("/") + "/batch"
    headers = {"Content-Type": "application/json", "Idempotency-Key": idempotency_key, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    upsert_nodes = [{"node": n, "allow_create": True} for n in chunk.get("nodes", [])]
    upsert_edges = [{"edge": e, "allow_create": True} for e in chunk.get("edges", [])]
    body = {
        "upsert_nodes": upsert_nodes,
        "upsert_edges": upsert_edges,
        "delete_nodes": [],
        "delete_edges": [],
        "transactional": False,
    }

    stats.http_tries += 1
    resp = session.post(url, json=body, headers=headers, timeout=timeout)
    if 200 <= resp.status_code < 300:
        return resp.json() if resp.content else {"ok": True}
    if resp.status_code in (408, 425, 429, 500, 502, 503, 504):
        raise HttpError(f"retryable {resp.status_code}")
    raise HttpError(f"HTTP {resp.status_code}: {resp.text[:500]}")

# --------------------------------- CLI реализация -------------------------------------

def parse_args(argv: t.List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="mythos-import", description="Import Mythos Graph entities")
    p.add_argument("--api-base", default="http://localhost:8080/v1/graph", help="Base URL for Graph API")
    p.add_argument("--input", "-i", default="-", help="Path to input file or '-' for stdin")
    p.add_argument("--format", choices=["auto", "ndjson", "json", "csv"], default="auto", help="Input format")
    p.add_argument("--mode", choices=["stream", "batch"], default="stream", help="Delivery mode")
    p.add_argument("--chunk-size", type=int, default=1000, help="Entities per chunk")
    p.add_argument("--mapping", help="CSV mapping file (json/yaml) for --format=csv")
    p.add_argument("--type", choices=["auto", "nodes", "edges"], default="auto", help="Force entity type for JSON/NDJSON")
    p.add_argument("--token", help="Bearer token")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    p.add_argument("--idempotency-key", help="Idempotency key (ULID). Auto-generated if omitted.")
    p.add_argument("--verify-ssl", action="store_true", default=False, help="Verify TLS certificates")
    p.add_argument("--dry-run", action="store_true", help="Parse and validate only, do not send")
    p.add_argument("--stats-every", type=int, default=2000, help="Print progress every N input lines")
    return p.parse_args(argv)

def open_input(path: str) -> io.TextIOBase:
    if path == "-" or not path:
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")
    return open(path, "r", encoding="utf-8")

def detect_format(path: str, forced: str) -> str:
    if forced != "auto":
        return forced
    if path == "-" or not path:
        return "ndjson"  # безопасное предположение для пайпов
    ext = Path(path).suffix.lower()
    if ext in (".ndjson", ".jsonl", ".log"):
        return "ndjson"
    if ext == ".json":
        return "json"
    if ext == ".csv":
        return "csv"
    return "ndjson"

def main(argv: t.List[str]) -> int:
    args = parse_args(argv)
    stats = Stats()
    idem = args.idempotency_key or new_ulid()

    # Парсинг входа -> итератор записей
    try:
        fh = open_input(args.input)
        fmt = detect_format(args.input, args.format)

        if fmt == "ndjson":
            raw_iter = iter_ndjson(fh)
        elif fmt == "json":
            raw_iter = iter_json(fh)
        elif fmt == "csv":
            if not args.mapping:
                raise MappingError("--mapping is required for CSV")
            mapping = load_mapping(Path(args.mapping))
            raw_iter = iter_csv(fh, mapping)
        else:
            raise ValueError("unknown format")

        # Принудительный тип для JSON/NDJSON (оборачиваем)
        if args.type != "auto" and fmt in ("json", "ndjson"):
            def wrap_type(it: t.Iterator[dict]) -> t.Iterator[dict]:
                tpe = args.type
                for rec in it:
                    if tpe == "nodes":
                        if "node" in rec:
                            yield rec
                        else:
                            if "kind" in rec:
                                yield {"node": canon_node(rec)}
                            else:
                                raise ValueError("record is not a node")
                    else:
                        if "edge" in rec:
                            yield rec
                        else:
                            if "type" in rec:
                                yield {"edge": canon_edge(rec)}
                            else:
                                raise ValueError("record is not an edge")
            raw_iter = wrap_type(raw_iter)

        # На выход — чанки {"nodes":[...], "edges":[...]}
        chunks_iter = chunkify_entities(_counting_iter(raw_iter, stats), chunk_size=args.chunk_size)

        if args.dry_run:
            # Просто посчитаем
            for ch in chunks_iter:
                stats.nodes_out += len(ch.get("nodes", []))
                stats.edges_out += len(ch.get("edges", []))
                stats.batches_sent += 1
                if stats.batches_sent % max(1, args.stats_every // max(1, args.chunk_size)) == 0:
                    eprint(f"[dry-run] progress: {stats.as_dict()}")
            print(json.dumps({"dry_run": True, **stats.as_dict()}, ensure_ascii=False))
            return 0

        session = requests.Session()
        session.verify = args.verify_ssl

        if args.mode == "stream":
            # stream: один длинный запрос POST /import с NDJSON
            # Для печати прогресса — оборачиваем генератор ещё раз
            chunks_iter = _progress_chunks(chunks_iter, stats, args)
            summary = post_stream_import(
                session=session,
                api_base=args.api_base,
                chunks=chunks_iter,
                idempotency_key=idem,
                token=args.token,
                timeout=args.timeout,
                stats=stats,
            )
            print(json.dumps({"mode": "stream", "idempotency_key": idem, "summary": summary, **stats.as_dict()}, ensure_ascii=False))
            return 0

        # batch: несколько POST /batch
        sent = 0
        for ch in _progress_chunks(chunks_iter, stats, args):
            backoff = 0.2
            for attempt in range(1, 8):
                try:
                    _ = post_batch(
                        session=session,
                        api_base=args.api_base,
                        chunk=ch,
                        idempotency_key=f"{idem}-{sent}",
                        token=args.token,
                        timeout=args.timeout,
                        stats=stats,
                    )
                    break
                except HttpError as e:
                    if "retryable" in str(e) and attempt < 7:
                        time.sleep(backoff)
                        backoff = min(2.0, backoff * 2.0)
                        continue
                    raise
            sent += 1
            stats.batches_sent = sent

        print(json.dumps({"mode": "batch", "idempotency_key": idem, **stats.as_dict()}, ensure_ascii=False))
        return 0

    except MappingError as me:
        eprint(f"Mapping error: {me}")
        return 2
    except (ValueError, HttpError) as e:
        eprint(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        eprint("Interrupted")
        return 130
    finally:
        try:
            if fh and fh is not sys.stdin:
                fh.close()
        except Exception:
            pass

def _counting_iter(it: t.Iterator[dict], stats: Stats) -> t.Iterator[dict]:
    for rec in it:
        stats.lines_in += 1
        yield rec

def _progress_chunks(chunks: t.Iterator[dict], stats: Stats, args: argparse.Namespace) -> t.Iterator[dict]:
    for ch in chunks:
        n_nodes = len(ch.get("nodes", []))
        n_edges = len(ch.get("edges", []))
        stats.nodes_out += n_nodes
        stats.edges_out += n_edges
        stats.batches_sent += 1
        if stats.lines_in and stats.lines_in % args.stats_every == 0:
            eprint(f"progress: {stats.as_dict()}")
        yield ch

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
