# neuroforge-core/cli/main.py
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import concurrent.futures as _fut
from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Внутренние утилиты идентификаторов
from neuroforge.utils.idgen import (
    IDGenerator,
    SnowflakeConfig,
    crockford_base32_decode,
    base62_decode,
    is_ulid as _is_ulid,
    is_uuid as _is_uuid,
    is_uuid_v7 as _is_uuid_v7,
    is_ksuid as _is_ksuid,
    is_nanoid as _is_nanoid,
)

EXIT_OK = 0
EXIT_INVALID_ARGS = 2
EXIT_RUNTIME_ERR = 3


# ========= Общие утилиты =========

def _iso_from_ms(ms: int) -> str:
    # Без зависимостей: используем UTC-вывод через стандартный способ
    # datetime в stdlib требует import, но чтобы не тянуть — простой ISO-псевдо-вывод.
    # Для аналитики ms достаточно; более точное форматирование не критично.
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()

def _print(obj: Any, as_json: bool, ndjson: bool) -> None:
    if ndjson:
        if isinstance(obj, list):
            for item in obj:
                sys.stdout.write(json.dumps(item, ensure_ascii=False) + "\n")
        else:
            sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        return
    if as_json:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
        return
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                sys.stdout.write(json.dumps(item, ensure_ascii=False) + "\n")
            else:
                sys.stdout.write(str(item) + "\n")
    else:
        sys.stdout.write(str(obj) + "\n")


def _read_ids_from_stdin() -> List[str]:
    data = sys.stdin.read().splitlines()
    return [line.strip() for line in data if line.strip()]


# ========= Детекция и парсинг форматов =========

def _detect_type(s: str) -> str:
    # Порядок: UUID -> UUIDv7 -> ULID -> KSUID -> NanoID -> unknown
    if _is_uuid(s):
        return "uuid7" if _is_uuid_v7(s) else "uuid"
    if _is_ulid(s):
        return "ulid"
    if _is_ksuid(s):
        return "ksuid"
    # NanoID не имеет фикс длины или алфавита, проверим как «возможный»
    if _is_nanoid(s):
        return "nanoid"
    # Snowflake — обычно десятичный int/base62; детекция рискованна без контекста.
    # Не считаем автоматом snowflake, чтобы не ошибаться на произвольных числах.
    return "unknown"


def _ulid_timestamp_ms(s: str) -> Optional[int]:
    # ULID: первые 48 бит — ms. 26 символов Crockford Base32 -> 128 бит.
    try:
        # Декодируем все 26 символов в 130 бит, но ULID — 128 бит: старшие 2 бита нули.
        b = crockford_base32_decode(s)
        n = int.from_bytes(b, "big")
        # b может иметь длину не ровно 16, нормализуем:
        if len(b) * 8 < 128:
            n = n << (128 - len(b) * 8)
        n &= (1 << 128) - 1
        ts = (n >> 80) & ((1 << 48) - 1)
        return int(ts)
    except Exception:
        return None


def _uuid7_timestamp_ms(uuid_str: str) -> Optional[int]:
    # UUIDv7: 60 бит ms в старших 64 битах
    import uuid as _uuid
    try:
        u = _uuid.UUID(uuid_str)
        if u.version != 7:
            return None
        b = u.bytes
        hi = int.from_bytes(b[:8], "big")
        # Старшие 60 бит — timestamp
        ts = hi >> 16
        return int(ts)
    except Exception:
        return None


def _ksuid_timestamp_ms(ksuid_str: str) -> Optional[int]:
    # KSUID: первые 4 байта — seconds since 2014-05-13 epoch (1400000000)
    try:
        n = base62_decode(ksuid_str)
        b = n.to_bytes(20, "big")
        ts_rel = int.from_bytes(b[:4], "big")
        epoch = 1400000000
        return int((epoch + ts_rel) * 1000)
    except Exception:
        return None


def _parse_snowflake(sf: int, gen: IDGenerator) -> Dict[str, Any]:
    parts = gen.parse_snowflake(sf)
    return {
        "type": "snowflake",
        "timestamp_ms": parts["timestamp_ms"],
        "timestamp_iso": _iso_from_ms(parts["timestamp_ms"]),
        "datacenter_id": parts["datacenter_id"],
        "worker_id": parts["worker_id"],
        "sequence": parts["sequence"],
        "raw": sf,
    }


# ========= Команды =========

def cmd_id_new(args: argparse.Namespace, gen: IDGenerator) -> int:
    t = args.type
    count = args.count
    concurrency = max(1, args.concurrency)
    out_json = args.json
    ndjson = args.ndjson
    prefix = args.prefix or ""
    suffix = args.suffix or ""

    def _one() -> Any:
        if t == "ulid":
            val = gen.new_ulid() if args.monotonic else gen.new_ulid_non_monotonic()
        elif t == "uuid4":
            val = str(gen.new_uuid4())
        elif t == "uuid7":
            val = str(gen.new_uuid7())
        elif t == "snowflake":
            if args.sf_encoding == "base62":
                val = gen.snowflake_str(encoding="base62")
            else:
                val = gen.snowflake_str(encoding="dec")
        elif t == "ksuid":
            val = gen.new_ksuid()
        elif t == "nanoid":
            val = gen.new_nanoid(size=args.size, alphabet=args.alphabet)
        else:
            raise ValueError(f"Unsupported type: {t}")
        return f"{prefix}{val}{suffix}"

    if count == 1 and concurrency == 1 and not (out_json or ndjson):
        _print(_one(), as_json=False, ndjson=False)
        return EXIT_OK

    results: List[str] = []

    if concurrency == 1:
        for _ in range(count):
            results.append(_one())
    else:
        # Потокобезопасность обеспечена внутри генераторов
        with _fut.ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="idgen") as ex:
            futs = [ex.submit(_one) for _ in range(count)]
            for f in _fut.as_completed(futs):
                results.append(f.result())

    if out_json or ndjson:
        payload = [{"id": r, "type": t} for r in results]
        _print(payload, as_json=out_json, ndjson=ndjson)
    else:
        _print(results, as_json=False, ndjson=False)
    return EXIT_OK


def cmd_id_validate(args: argparse.Namespace, gen: IDGenerator) -> int:
    ids: List[str] = args.ids or []
    if args.stdin or (not ids and not sys.stdin.isatty()):
        ids.extend(_read_ids_from_stdin())

    if not ids:
        sys.stderr.write("No IDs provided. Use arguments or pipe via stdin.\n")
        return EXIT_INVALID_ARGS

    out_json = args.json
    ndjson = args.ndjson

    out: List[Dict[str, Any]] = []
    for s in ids:
        t = _detect_type(s)
        info: Dict[str, Any] = {"input": s, "type": t, "valid": False}

        if t == "uuid" or t == "uuid7":
            info["valid"] = True
            if t == "uuid7":
                ts = _uuid7_timestamp_ms(s)
                info["timestamp_ms"] = ts
                info["timestamp_iso"] = _iso_from_ms(ts) if ts is not None else None
        elif t == "ulid":
            info["valid"] = True
            ts = _ulid_timestamp_ms(s)
            info["timestamp_ms"] = ts
            info["timestamp_iso"] = _iso_from_ms(ts) if ts is not None else None
        elif t == "ksuid":
            info["valid"] = True
            ts = _ksuid_timestamp_ms(s)
            info["timestamp_ms"] = ts
            info["timestamp_iso"] = _iso_from_ms(ts) if ts is not None else None
        elif t == "nanoid":
            info["valid"] = True
        else:
            info["valid"] = False

        out.append(info)

    _print(out, as_json=out_json, ndjson=ndjson)
    return EXIT_OK


def cmd_id_parse(args: argparse.Namespace, gen: IDGenerator) -> int:
    # Специфичный разбор: snowflake|ulid|uuid7|ksuid
    s = args.value
    out_json = args.json
    ndjson = args.ndjson

    try:
        if args.kind == "snowflake":
            val = int(s) if s.isdigit() else base62_decode(s)
            data = _parse_snowflake(val, gen)
            _print(data, as_json=out_json, ndjson=ndjson)
            return EXIT_OK

        if args.kind == "ulid":
            if not _is_ulid(s):
                sys.stderr.write("Not a valid ULID string.\n")
                return EXIT_INVALID_ARGS
            ts = _ulid_timestamp_ms(s)
            data = {
                "type": "ulid",
                "timestamp_ms": ts,
                "timestamp_iso": _iso_from_ms(ts) if ts is not None else None,
                "value": s,
            }
            _print(data, as_json=out_json, ndjson=ndjson)
            return EXIT_OK

        if args.kind == "uuid7":
            if not _is_uuid_v7(s):
                sys.stderr.write("Not a valid UUIDv7 string.\n")
                return EXIT_INVALID_ARGS
            ts = _uuid7_timestamp_ms(s)
            data = {
                "type": "uuid7",
                "timestamp_ms": ts,
                "timestamp_iso": _iso_from_ms(ts) if ts is not None else None,
                "value": s,
            }
            _print(data, as_json=out_json, ndjson=ndjson)
            return EXIT_OK

        if args.kind == "ksuid":
            if not _is_ksuid(s):
                sys.stderr.write("Not a valid KSUID string.\n")
                return EXIT_INVALID_ARGS
            ts = _ksuid_timestamp_ms(s)
            data = {
                "type": "ksuid",
                "timestamp_ms": ts,
                "timestamp_iso": _iso_from_ms(ts) if ts is not None else None,
                "value": s,
            }
            _print(data, as_json=out_json, ndjson=ndjson)
            return EXIT_OK

        sys.stderr.write("Unknown kind. Use one of: snowflake, ulid, uuid7, ksuid.\n")
        return EXIT_INVALID_ARGS
    except Exception as e:
        sys.stderr.write(f"Parse error: {e}\n")
        return EXIT_RUNTIME_ERR


def cmd_sys_node_ids(args: argparse.Namespace, gen: IDGenerator) -> int:
    # Достаём поля через генерацию snowflake и обратный разбор
    sf = gen.new_snowflake()
    data = gen.parse_snowflake(sf)
    out = {
        "datacenter_id": data["datacenter_id"],
        "worker_id": data["worker_id"],
        "env": {
            "NEUROFORGE_DC_ID": os.getenv("NEUROFORGE_DC_ID"),
            "NEUROFORGE_NODE_ID": os.getenv("NEUROFORGE_NODE_ID"),
        },
    }
    _print(out, as_json=args.json, ndjson=args.ndjson)
    return EXIT_OK


def cmd_sys_time(args: argparse.Namespace, gen: IDGenerator) -> int:
    # Берём ms через ULID timestamp для консистентности
    ulid = gen.new_ulid_non_monotonic()
    ts = _ulid_timestamp_ms(ulid)
    out = {"now_ms": ts, "now_iso": _iso_from_ms(ts) if ts is not None else None}
    _print(out, as_json=args.json, ndjson=args.ndjson)
    return EXIT_OK


def cmd_codec_encode(args: argparse.Namespace) -> int:
    data = args.data
    fmt = args.format
    if args.hex:
        try:
            raw = bytes.fromhex(data)
        except ValueError:
            sys.stderr.write("Invalid hex input for --hex.\n")
            return EXIT_INVALID_ARGS
    else:
        raw = data.encode("utf-8")

    if fmt == "base32":
        from neuroforge.utils.idgen import crockford_base32_encode
        out = crockford_base32_encode(raw)
    elif fmt == "base62":
        from neuroforge.utils.idgen import base62_encode
        out = base62_encode(raw)
    else:
        sys.stderr.write("Unsupported format. Use base32 or base62.\n")
        return EXIT_INVALID_ARGS

    _print(out, as_json=False, ndjson=False)
    return EXIT_OK


def cmd_codec_decode(args: argparse.Namespace) -> int:
    data = args.data
    fmt = args.format
    try:
        if fmt == "base32":
            raw = crockford_base32_decode(data)
        elif fmt == "base62":
            n = base62_decode(data)
            # Выводим в hex для однозначности
            raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        else:
            sys.stderr.write("Unsupported format. Use base32 or base62.\n")
            return EXIT_INVALID_ARGS
    except Exception as e:
        sys.stderr.write(f"Decode error: {e}\n")
        return EXIT_RUNTIME_ERR

    if args.out == "hex":
        _print(raw.hex(), as_json=False, ndjson=False)
    else:
        # utf-8 может не подойти; бережно декодируем
        try:
            _print(raw.decode("utf-8"), as_json=False, ndjson=False)
        except UnicodeDecodeError:
            _print(raw.hex(), as_json=False, ndjson=False)
    return EXIT_OK


# ========= Парсер аргументов =========

def _add_common_output_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="Вывод в JSON.")
    p.add_argument("--ndjson", action="store_true", help="Построчный NDJSON-вывод.")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="neuroforge",
        description="NeuroForge Core CLI: генерация, валидация и парсинг идентификаторов",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # id new
    p_id = sub.add_parser("id", help="Операции с идентификаторами")
    sub_id = p_id.add_subparsers(dest="id_cmd", required=True)

    p_id_new = sub_id.add_parser("new", help="Сгенерировать ID")
    p_id_new.add_argument("--type", choices=["ulid", "uuid4", "uuid7", "snowflake", "ksuid", "nanoid"], required=True)
    p_id_new.add_argument("--count", type=int, default=1, help="Количество идентификаторов.")
    p_id_new.add_argument("--concurrency", type=int, default=1, help="Параллельная генерация, число потоков.")
    p_id_new.add_argument("--prefix", type=str, default="", help="Префикс для каждой строки.")
    p_id_new.add_argument("--suffix", type=str, default="", help="Суффикс для каждой строки.")
    p_id_new.add_argument("--monotonic", action="store_true", help="ULID: монотоничная выдача.")
    p_id_new.add_argument("--size", type=int, default=21, help="NanoID: длина.")
    p_id_new.add_argument("--alphabet", type=str, default="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-", help="NanoID: алфавит.")
    p_id_new.add_argument("--sf-encoding", choices=["dec", "base62"], default="dec", help="Snowflake: вывод как десятичный int или base62.")
    _add_common_output_flags(p_id_new)

    # id validate
    p_id_val = sub_id.add_parser("validate", help="Проверить и детектировать тип ID")
    p_id_val.add_argument("ids", nargs="*", help="Список идентификаторов.")
    p_id_val.add_argument("--stdin", action="store_true", help="Читать идентификаторы из stdin построчно.")
    _add_common_output_flags(p_id_val)

    # id parse
    p_id_parse = sub_id.add_parser("parse", help="Разобрать поля ID")
    p_id_parse.add_argument("kind", choices=["snowflake", "ulid", "uuid7", "ksuid"], help="Тип для парсинга.")
    p_id_parse.add_argument("value", help="Значение ID.")
    _add_common_output_flags(p_id_parse)

    # sys
    p_sys = sub.add_parser("sys", help="Системные сведения")
    sys_sub = p_sys.add_subparsers(dest="sys_cmd", required=True)

    p_sys_node = sys_sub.add_parser("node-ids", help="Показать datacenter/worker идентичности узла.")
    _add_common_output_flags(p_sys_node)

    p_sys_time = sys_sub.add_parser("time", help="Текущее время (ms, ISO).")
    _add_common_output_flags(p_sys_time)

    # codec
    p_codec = sub.add_parser("codec", help="Кодеки Base32/Base62")
    csub = p_codec.add_subparsers(dest="codec_cmd", required=True)

    p_enc = csub.add_parser("encode", help="Закодировать данные")
    p_enc.add_argument("--format", choices=["base32", "base62"], required=True)
    p_enc.add_argument("data", help="Данные: строка или hex при --hex.")
    p_enc.add_argument("--hex", action="store_true", help="Интерпретировать вход как hex.")
    _add_common_output_flags(p_enc)

    p_dec = csub.add_parser("decode", help="Декодировать строку")
    p_dec.add_argument("--format", choices=["base32", "base62"], required=True)
    p_dec.add_argument("data", help="Строка для декодирования.")
    p_dec.add_argument("--out", choices=["utf8", "hex"], default="utf8", help="Формат вывода.")
    _add_common_output_flags(p_dec)

    return parser


# ========= Точка входа =========

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Конфигурация Snowflake через ENV
    cfg = SnowflakeConfig(
        epoch_ms=int(os.getenv("NEUROFORGE_SF_EPOCH_MS", SnowflakeConfig.epoch_ms)),
        datacenter_id_bits=int(os.getenv("NEUROFORGE_SF_DC_BITS", SnowflakeConfig.datacenter_id_bits)),
        worker_id_bits=int(os.getenv("NEUROFORGE_SF_WORKER_BITS", SnowflakeConfig.worker_id_bits)),
        sequence_bits=int(os.getenv("NEUROFORGE_SF_SEQ_BITS", SnowflakeConfig.sequence_bits)),
    )
    gen = IDGenerator(snowflake_config=cfg)

    try:
        if args.command == "id":
            if args.id_cmd == "new":
                return cmd_id_new(args, gen)
            if args.id_cmd == "validate":
                return cmd_id_validate(args, gen)
            if args.id_cmd == "parse":
                return cmd_id_parse(args, gen)
            parser.error("Unknown id subcommand")
            return EXIT_INVALID_ARGS

        if args.command == "sys":
            if args.sys_cmd == "node-ids":
                return cmd_sys_node_ids(args, gen)
            if args.sys_cmd == "time":
                return cmd_sys_time(args, gen)
            parser.error("Unknown sys subcommand")
            return EXIT_INVALID_ARGS

        if args.command == "codec":
            if args.codec_cmd == "encode":
                return cmd_codec_encode(args)
            if args.codec_cmd == "decode":
                return cmd_codec_decode(args)
            parser.error("Unknown codec subcommand")
            return EXIT_INVALID_ARGS

        parser.error("Unknown command")
        return EXIT_INVALID_ARGS

    except KeyboardInterrupt:
        sys.stderr.write("Interrupted by user.\n")
        return EXIT_RUNTIME_ERR
    except BrokenPipeError:
        # Корректно завершаем при пайпинге в head | tail
        try:
            sys.stdout.close()
        except Exception:
            pass
        return EXIT_OK
    except Exception as e:
        sys.stderr.write(f"Runtime error: {e}\n")
        return EXIT_RUNTIME_ERR


if __name__ == "__main__":
    sys.exit(main())
