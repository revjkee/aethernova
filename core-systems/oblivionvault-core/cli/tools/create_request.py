# oblivionvault-core/cli/tools/create_request.py
#!/usr/bin/env python3
"""
OblivionVault CLI — create_request
Формирует каноническое событие AnchorRequest для последующего якорения в Ledger.

Функции:
- Вычисление content_id и merkle_root (stream, без загрузки всего в память).
- Каноническое событие: {schema, content_id, merkle_root, size, metadata, created_at, tenant}.
- Детерминированный txid = hash(canonical_event) (тем же "best" алгоритмом).
- Режим вывода: envelope (event + служебные поля) или только event.
- Мульти-вход: список файлов или stdin.
- Метаданные: JSON-файл + пары k=v (слияние, пары перекрывают JSON).
- Управление алгоритмом (auto/blake3/blake2b/sha256), размером чанка (с KiB/MiB/GiB).

Коды возврата:
  0 — успех, все элементы созданы;
  2 — часть элементов обработана, были ошибки;
  1 — фатальная ошибка (неверные параметры/невозможно начать работу).

Пример:
  create_request.py --algo auto --chunk-size 4MiB \\
      --metadata-json meta.json --meta project=NeuroCity env=prod \\
      --tenant main --ndjson inputs/*.bin > requests.ndjson

Зависимости:
- Внутренние модули: oblivionvault.utils.hashing
- Стандартная библиотека. При отсутствии blake3 — безопасная деградация (blake2b/sha256).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Iterable

# --- Локальный импорт пакета (dev-режим): добавим корень репозитория в sys.path при необходимости
try:
    from oblivionvault.utils import hashing as hv
except Exception:
    # Попытка добавить .. / ../.. относительно этого файла
    _here = Path(__file__).resolve()
    for up in (_here.parents[2], _here.parents[3] if len(_here.parents) >= 4 else None):
        if up and (up / "oblivionvault" / "utils" / "hashing.py").exists():
            sys.path.insert(0, str(up))
            break
    from oblivionvault.utils import hashing as hv  # type: ignore


__version__ = "1.0.0"

LOG = logging.getLogger("create_request")


# ---------- Парсинг размеров ----------

_SIZE_RE = re.compile(r"^\s*(\d+)\s*([KMG]i?B?)?\s*$", re.IGNORECASE)
_SIZE_MULT = {
    None: 1,
    "K": 10**3, "KB": 10**3, "KI": 2**10, "KIB": 2**10,
    "M": 10**6, "MB": 10**6, "MI": 2**20, "MIB": 2**20,
    "G": 10**9, "GB": 10**9, "GI": 2**30, "GIB": 2**30,
}

def parse_size(s: str) -> int:
    m = _SIZE_RE.match(s)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid size '{s}'")
    n = int(m.group(1))
    suf = m.group(2)
    if suf:
        suf = suf.upper().replace("B", "")
    mult = _SIZE_MULT.get(suf, None if suf else 1)
    if mult is None:
        raise argparse.ArgumentTypeError(f"invalid size suffix in '{s}'")
    return n * mult


# ---------- Метаданные ----------

def load_metadata(json_path: Optional[Path]) -> Dict[str, Any]:
    if not json_path:
        return {}
    p = Path(json_path)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("metadata JSON root must be an object")
    return data


def merge_kv(meta: Dict[str, Any], items: Iterable[str]) -> Dict[str, Any]:
    out = dict(meta)
    for kv in items or []:
        if "=" not in kv:
            raise ValueError(f"invalid --meta entry '{kv}', expected key=value")
        k, v = kv.split("=", 1)
        k = k.strip()
        v = v.strip()
        # Пытаемся привести тип: int/float/bool/null/json
        try:
            v_json = json.loads(v)
            out[k] = v_json
        except Exception:
            # Не JSON — оставляем строкой
            out[k] = v
    return out


# ---------- Основная логика ----------

def make_canonical_event(
    *,
    content_id: str,
    merkle_root: str,
    size: int,
    metadata: Dict[str, Any],
    tenant: Optional[str],
    created_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    ts = created_at or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    # Ровно те поля и формат, что используются в LedgerAdapter.AnchorRequest.canonical_event
    event = {
        "content_id": content_id,
        "merkle_root": merkle_root,
        "size": int(size),
        "metadata": metadata or {},
        "created_at": ts.isoformat(),
        "tenant": tenant or "",
        "schema": 1,
    }
    return event


def compute_hashes_for_path(path: Optional[Path], *, algo: Optional[hv.HashAlgo], chunk_size: int) -> Tuple[str, str, int]:
    """
    Возвращает (content_hex, merkle_hex, total_size).
    Если path=None — читаем stdin в потоковом режиме.
    """
    if path is None:
        # stdin
        stream = sys.stdin.buffer
        content_hex, merkle_hex, total_size = hv.hash_stream_with_merkle(stream, algo=algo, digest_size=hv.DEFAULT_DIGEST_SIZE, chunk_size=chunk_size)
        return content_hex, merkle_hex, total_size

    with path.open("rb") as f:
        content_hex, merkle_hex, total_size = hv.hash_stream_with_merkle(f, algo=algo, digest_size=hv.DEFAULT_DIGEST_SIZE, chunk_size=chunk_size)
    return content_hex, merkle_hex, total_size


def compute_txid_for_event(event: Dict[str, Any]) -> str:
    # Точно как в Ledger: txid = hash(canonical_event_bytes), auto_best алгоритм
    payload = hv.canonical_json_dumps(event)
    return hv.hash_bytes(payload, algo=hv.HashAlgo.auto_best())


def build_envelope(
    *,
    event: Dict[str, Any],
    txid: str,
    algo_used: hv.HashAlgo,
    chunk_size: int,
    source_path: Optional[str],
) -> Dict[str, Any]:
    env = {
        "event": event,
        "txid": txid,
        "algo": algo_used.value,
        "chunk_size": chunk_size,
    }
    if source_path is not None:
        env["source_path"] = source_path
    return env


# ---------- Аргументы ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="create_request", description="Create canonical AnchorRequest event(s) for OblivionVault.")
    p.add_argument("inputs", nargs="*", help="Input files. If omitted and --stdin is set, reads from stdin.")
    gsrc = p.add_mutually_exclusive_group()
    gsrc.add_argument("--stdin", action="store_true", help="Read single request from stdin.")
    p.add_argument("--algo", choices=["auto", "blake3", "blake2b", "sha256"], default="auto", help="Hash algorithm for content_id/Merkle. Default: auto.")
    p.add_argument("--chunk-size", type=parse_size, default="4MiB", help="Chunk size for hashing (supports KiB/MiB/GiB). Default: 4MiB.")
    p.add_argument("--metadata-json", type=Path, help="Path to JSON with metadata (object).")
    p.add_argument("--meta", action="append", default=[], help="Inline metadata key=value. May be repeated. Values parsed as JSON if possible.")
    p.add_argument("--tenant", type=str, help="Tenant label to include into event.")
    p.add_argument("--include-source-path", action="store_true", help="Include file path into envelope.source_path and metadata.source_path.")
    p.add_argument("--emit", choices=["envelope", "event"], default="envelope", help="Output envelope (event+txid) or event only. Default: envelope.")
    p.add_argument("--ndjson", action="store_true", help="Emit newline-delimited JSON (one per line).")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON (ignored for --ndjson).")
    p.add_argument("--output", type=Path, help="Write output to file instead of stdout.")
    p.add_argument("--continue-on-error", action="store_true", help="Continue processing next inputs on error and exit with code 2 if any failed.")
    p.add_argument("--log-level", default="INFO", choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"], help="Log level for stderr.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


# ---------- Основной сценарий ----------

def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    # Источники
    if args.stdin:
        if args.inputs:
            LOG.error("When --stdin is set, no positional inputs are allowed.")
            return 1
        inputs: List[Optional[Path]] = [None]
    else:
        if not args.inputs:
            LOG.error("No inputs provided. Specify files or use --stdin.")
            return 1
        inputs = [Path(x) for x in args.inputs]

    # Алгоритм
    algo_map = {
        "auto": None,  # hv.ensure_algo(None) => auto_best
        "blake3": hv.HashAlgo.BLAKE3,
        "blake2b": hv.HashAlgo.BLAKE2B,
        "sha256": hv.HashAlgo.SHA256,
    }
    algo_selected = algo_map[args.algo]
    algo_effective = hv.ensure_algo(algo_selected)

    # Метаданные
    try:
        meta = load_metadata(args.metadata_json)
        meta = merge_kv(meta, args.meta)
    except Exception as e:
        LOG.error("Failed to load/merge metadata: %s", e)
        return 1

    # Обработка
    results: List[Dict[str, Any]] = []
    failures = 0

    for path in inputs:
        try:
            if path is not None and (not path.exists() or not path.is_file()):
                raise FileNotFoundError(f"{path} not found or not a regular file")

            content_hex, merkle_hex, total_size = compute_hashes_for_path(path, algo=algo_effective, chunk_size=args.chunk_size)

            # Сформируем per-file metadata (копия базовой)
            md = dict(meta)
            source_path_str: Optional[str] = None
            if args.include_source_path:
                source_path_str = "<stdin>" if path is None else str(path)
                md.setdefault("source_path", source_path_str)

            event = make_canonical_event(
                content_id=content_hex,
                merkle_root=merkle_hex,
                size=total_size,
                metadata=md,
                tenant=args.tenant,
            )
            txid = compute_txid_for_event(event)

            if args.emit == "event":
                out_obj = event
            else:
                out_obj = build_envelope(
                    event=event,
                    txid=txid,
                    algo_used=algo_effective,
                    chunk_size=args.chunk_size,
                    source_path=source_path_str if args.include_source_path else None,
                )
            results.append(out_obj)

            LOG.info("Prepared request: content_id=%s size=%d txid=%s", content_hex[:16], total_size, txid[:16])

        except Exception as e:
            failures += 1
            LOG.error("Failed to process %s: %s", "<stdin>" if path is None else path, e)
            if not args.continue_on_error:
                return 1

    # Вывод
    try:
        if args.output:
            out_stream = args.output.open("w", encoding="utf-8")
        else:
            out_stream = sys.stdout

        if args.ndjson:
            for obj in results:
                out_stream.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
        else:
            if len(results) == 1:
                out_stream.write(json.dumps(results[0], ensure_ascii=False, sort_keys=True, indent=(2 if args.pretty else None)) + ("\n" if args.pretty else ""))
            else:
                out_stream.write(json.dumps(results, ensure_ascii=False, sort_keys=True, indent=(2 if args.pretty else None)) + ("\n" if args.pretty else ""))
        if out_stream is not sys.stdout:
            out_stream.close()
    except Exception as e:
        LOG.error("Failed to write output: %s", e)
        return 1

    if failures:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
