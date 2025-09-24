# oblivionvault-core/examples/quickstart/run.py
#!/usr/bin/env python3
"""
OblivionVault Quickstart (industrial-grade)

Демонстрирует end-to-end:
  1) Инициализацию WORMStore и Ledger (file-ledger).
  2) Запись объекта в WORM (атомарно, CAS), stat/verify.
  3) Установку retention/legal hold (опционально).
  4) Формирование канонического AnchorRequest и якорение.
  5) Верификацию записи в Ledger и получение пруфа из WORM.

Запуск (примеры):
  python run.py --base-dir ./.ov_demo --input ./data.bin --algo auto --chunk-size 4MiB --tenant main --pretty
  echo "hello" | python run.py --base-dir ./.ov_demo --stdin --include-source-path --pretty
  python run.py --base-dir ./.ov_demo --input ./data.bin --retention-days 7 --legal-hold --pretty

Коды возврата:
  0 — успех; 1 — неверные параметры/фатальная ошибка.
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
from typing import Any, Dict, List, Optional, Tuple

import asyncio

# --- Локальные импорты пакета (dev-режим): аккуратно добавим корень репозитория в sys.path
def _ensure_pkg_on_path():
    here = Path(__file__).resolve()
    for up in (here.parents[2], here.parents[3] if len(here.parents) >= 4 else None):
        if up and (up / "oblivionvault" / "utils" / "hashing.py").exists():
            sys.path.insert(0, str(up))
            return
_ensure_pkg_on_path()

from oblivionvault.utils import hashing as hv
from oblivionvault.archive.worm_store import WORMStore, WORMStoreConfig
from oblivionvault.adapters.ledger_core_adapter import (
    build_ledger_adapter,
    LedgerConfig,
    LedgerBackendType,
    make_anchor_request,
)

LOG = logging.getLogger("ov.quickstart")
__version__ = "1.0.0"

# ---------- Утилиты парсинга размеров ----------

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

# ---------- Аргументы CLI ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ov-quickstart", description="OblivionVault quickstart demo.")
    p.add_argument("--base-dir", type=Path, required=True, help="Рабочая база (будут созданы ./vault и ./ledger).")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--input", type=Path, help="Входной файл для записи в WORM.")
    src.add_argument("--stdin", action="store_true", help="Читать данные из stdin (один объект).")
    p.add_argument("--algo", choices=["auto", "blake3", "blake2b", "sha256"], default="auto", help="Алгоритм хэширования для CAS/Merkle.")
    p.add_argument("--chunk-size", type=parse_size, default="4MiB", help="Размер чанка для потокового хэширования. По умолчанию 4MiB.")
    p.add_argument("--tenant", type=str, default="demo", help="Метка tenant для событий AnchorRequest.")
    p.add_argument("--retention-days", type=int, default=0, help="Политика удержания (дни). 0 — без удержания.")
    p.add_argument("--legal-hold", action="store_true", help="Включить legal hold после записи.")
    p.add_argument("--include-source-path", action="store_true", help="Добавить путь источника в метаданные.")
    p.add_argument("--ledger-backend", choices=["file", "null"], default="file", help="Тип Ledger backend для примера.")
    p.add_argument("--pretty", action="store_true", help="Красивый вывод JSON.")
    p.add_argument("--log-level", default="INFO", choices=["CRITICAL","ERROR","WARNING","INFO","DEBUG"], help="Уровень логирования.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p

# ---------- Основной сценарий ----------

async def run(args: argparse.Namespace) -> Dict[str, Any]:
    # Внутри активного event loop создаём хранилище (важно для его внутренних executors)
    base_dir = args.base_dir.resolve()
    vault_dir = base_dir / "vault"
    ledger_dir = base_dir / "ledger"
    vault_dir.mkdir(parents=True, exist_ok=True)
    ledger_dir.mkdir(parents=True, exist_ok=True)

    algo_map = {
        "auto": None,
        "blake3": hv.HashAlgo.BLAKE3,
        "blake2b": hv.HashAlgo.BLAKE2B,
        "sha256": hv.HashAlgo.SHA256,
    }
    algo_selected = algo_map[args.algo]
    algo_effective = hv.ensure_algo(algo_selected)

    # Инициализация WORMStore (без обязательного шифрования; immutable best-effort)
    store_cfg = WORMStoreConfig(
        base_dir=vault_dir,
        algo=algo_effective,
        chunk_size=args.chunk_size,
        compression=hv.HashAlgo.auto_best() and None,  # не меняем полезную нагрузку в quickstart
        require_encryption=False,
        default_retention_days=args.retention_days,
        immutable_best_effort=True,
        parallelism=min(4, os.cpu_count() or 2),
    )
    # Параметр compression в WORMStoreConfig был Enum в архивном модуле;
    # если используются дефолты, он будет интерпретирован корректно. Для простоты — оставляем по умолчанию.

    store = WORMStore(store_cfg)

    # Подготовим данные к записи
    metadata: Dict[str, Any] = {"example": "quickstart"}
    source_path_str: Optional[str] = None

    if args.stdin:
        data_source = sys.stdin.buffer  # будет прочитан потоково внутри WORMStore
        source_path_str = "<stdin>"
    elif args.input:
        if not args.input.exists() or not args.input.is_file():
            raise FileNotFoundError(f"input file not found: {args.input}")
        data_source = args.input.open("rb")
        source_path_str = str(args.input.resolve())
    else:
        # Демонстрационный полезный груз
        sample = (
            b"OblivionVault quickstart payload\n"
            b"Timestamp: " + datetime.now(timezone.utc).isoformat().encode("utf-8") + b"\n"
        )
        data_source = sample

    if args.include_source_path and source_path_str:
        metadata["source_path"] = source_path_str

    LOG.info("Writing object into WORM (algo=%s chunk=%d)...", algo_effective.value, args.chunk_size)
    info = await store.write(data_source, metadata=metadata, actor="quickstart", retention_days=args.retention_days)
    LOG.info("WORM write ok: content_id=%s size=%d", info.content_id, info.size)

    # Политики (опционально)
    if args.legal_hold:
        await store.set_legal_hold(info.content_id, True, actor="quickstart")
        LOG.info("Legal hold set")

    # Verify WORM object fully
    verified = await store.verify(info.content_id)
    if not verified:
        raise RuntimeError("WORM verification failed")
    LOG.info("WORM verify ok")

    # Инициализируем Ledger backend
    backend = LedgerBackendType.FILE if args.ledger_backend == "file" else LedgerBackendType.NULL
    ledger_cfg = LedgerConfig(
        base_dir=ledger_dir,
        backend=backend,
        db_filename="ledger.sqlite",
        synchronous_full=True,
        tenant=args.tenant,
    )
    ledger = build_ledger_adapter(ledger_cfg)

    # Сформируем канонический AnchorRequest из данных WORM
    event_ts = info.created_at  # фиксируем время артефакта
    req = make_anchor_request(
        content_id=info.content_id,
        merkle_root=info.merkle_root,
        size=info.size,
        metadata=info.metadata,
        tenant=args.tenant,
        created_at=event_ts,
    )

    LOG.info("Anchoring into ledger backend=%s ...", args.ledger_backend)
    receipt = await ledger.anchor(req)
    LOG.info("Ledger anchor status=%s txid=%s", receipt.status.value, receipt.txid)

    # Верифицируем запись в Ledger (для file/null)
    ok = await ledger.verify(info.content_id)
    LOG.info("Ledger verify: %s", "ok" if ok else "failed")
    if not ok and args.ledger_backend == "file":
        raise RuntimeError("Ledger verification failed")

    # Получим пруф WORM и подготовим итоговый JSON
    proof = await store.proof(info.content_id)

    result = {
        "worm": {
            "object": info.to_dict(),
            "verified": True,
            "proof_tail": proof.get("audit_tail", []),
        },
        "ledger": {
            "backend": args.ledger_backend,
            "receipt": {
                "status": receipt.status.value,
                "txid": receipt.txid,
                "chain_id": receipt.chain_id,
                "block_number": receipt.block_number,
                "timestamp": receipt.timestamp.isoformat(),
                "content_id": receipt.content_id,
                "merkle_root": receipt.merkle_root,
                "size": receipt.size,
                "metadata": receipt.metadata,
                "confirmations": receipt.confirmations,
                "hmac_prev": receipt.hmac_prev,
                "hmac_curr": receipt.hmac_curr,
            },
            "verified": ok,
        },
    }

    await ledger.close()
    await store.close()
    return result

def configure_logging(level: str):
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    # Базовая валидация источника
    if not args.stdin and not args.input:
        LOG.warning("No --input provided; using in-memory sample payload.")
    if args.stdin and args.input:
        LOG.error("Choose either --stdin or --input, not both.")
        return 1

    try:
        result = asyncio.run(run(args))
        if args.pretty:
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
        return 0
    except KeyboardInterrupt:
        LOG.error("Interrupted")
        return 1
    except Exception as e:
        LOG.exception("Quickstart failed: %s", e)
        return 1

if __name__ == "__main__":
    sys.exit(main())
