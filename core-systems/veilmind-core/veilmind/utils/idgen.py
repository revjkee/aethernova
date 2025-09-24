# veilmind-core/veilmind/utils/idgen.py
# -*- coding: utf-8 -*-
"""
VeilMind — ID generation utilities.

Функциональность:
- ULID (Crockford Base32, 26 символов, верхний регистр) — ulid(), is_ulid(), ulid_timestamp(), ulid_to_uuid().
- Монотонный ULID без коллизий в пределах 1 мс — ulid_monotonic().
- UUID: uuid4_str(), uuid7_str() (использует stdlib, при отсутствии — корректная ручная реализация v7).
- Короткие URL‑безопасные идентификаторы — short_id().
- Проверка/нормализация/парсинг — is_uuid(), normalize_ulid().
- CLI для DevOps (python -m veilmind.utils.idgen ...).

Зависимости: только стандартная библиотека (secrets, uuid, os, time).
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Crockford Base32 (без I, L, O, U)
# ---------------------------------------------------------------------------

_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_IDX = {c: i for i, c in enumerate(_CROCKFORD_ALPHABET)}
_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")

def _b128_to_base32_crockford(b128: int) -> str:
    # 128 бит → 26 символов Base32 (Crockford). Старшие биты слева.
    out = []
    for _ in range(26):
        out.append(_CROCKFORD_ALPHABET[b128 & 0b11111])
        b128 >>= 5
    return "".join(reversed(out))

def _base32_crockford_to_b128(s: str) -> int:
    n = 0
    for ch in s:
        try:
            n = (n << 5) | _CROCKFORD_IDX[ch]
        except KeyError:
            raise ValueError("invalid Crockford Base32 character")
    return n

def _normalize_crockford(s: str) -> str:
    """
    Нормализует визуально похожие символы:
      i, l, I, L -> 1
      o, O -> 0
    И приводит к верхнему регистру.
    """
    tbl = str.maketrans({"i": "1", "l": "1", "I": "1", "L": "1", "o": "0", "O": "0"})
    return s.translate(tbl).upper()

# ---------------------------------------------------------------------------
# ULID (RFC draft de-facto)
# Структура: 48 бит времени (мс от Unix epoch, big-endian) + 80 бит случайных
# ---------------------------------------------------------------------------

class _MonotonicULIDState:
    __slots__ = ("lock", "last_ms", "last_rand")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last_ms = -1
        self.last_rand = 0

_MONO = _MonotonicULIDState()

def _ulid_from(ts_ms: int, rand80: int) -> str:
    # Сборка 128 бит: (48бит ts << 80) | rand80
    if not (0 <= ts_ms < (1 << 48)):
        raise ValueError("timestamp out of 48-bit range")
    if not (0 <= rand80 < (1 << 80)):
        raise ValueError("random part out of 80-bit range")
    b128 = (ts_ms << 80) | rand80
    return _b128_to_base32_crockford(b128)

def _time_ms(now: Optional[float] = None) -> int:
    # Миллисекунды UTC. Используем time.time_ns для большей точности.
    if now is None:
        return time.time_ns() // 1_000_000
    return int(now * 1000)

def ulid(now: Optional[float] = None) -> str:
    """
    Генерирует стандартный ULID (26 символов, верхний регистр, Base32 Crockford).
    Случайная часть — криптографически стойкая (80 бит).
    """
    ts_ms = _time_ms(now)
    rand80 = int.from_bytes(secrets.token_bytes(10), "big")
    return _ulid_from(ts_ms, rand80)

def ulid_monotonic(now: Optional[float] = None) -> str:
    """
    Генерирует монотонный ULID: при нескольких вызовах в одну и ту же миллисекунду
    80‑битовый хвост инкрементируется, исключая коллизии.
    Потокобезопасно.
    """
    ts_ms = _time_ms(now)
    with _MONO.lock:
        if ts_ms == _MONO.last_ms:
            _MONO.last_rand = (_MONO.last_rand + 1) & ((1 << 80) - 1)
        else:
            _MONO.last_ms = ts_ms
            _MONO.last_rand = int.from_bytes(secrets.token_bytes(10), "big")
        rand80 = _MONO.last_rand
    return _ulid_from(ts_ms, rand80)

def is_ulid(s: str) -> bool:
    """Быстрая проверка формата ULID (26 символов Crockford Base32, верхний регистр)."""
    if not s or len(s) != 26:
        return False
    return bool(_ULID_RE.match(s))

def normalize_ulid(s: str) -> str:
    """
    Нормализует строку в валидный Crockford‑совместимый ULID (верхний регистр).
    Бросает ValueError, если строка после нормализации некорректна.
    """
    if not s:
        raise ValueError("empty string")
    n = _normalize_crockford(s)
    if not is_ulid(n):
        raise ValueError("invalid ULID")
    return n

def ulid_timestamp(s: str) -> datetime:
    """
    Возвращает datetime (UTC) из 48‑битового времени ULID.
    """
    s = normalize_ulid(s)
    b128 = _base32_crockford_to_b128(s)
    ts_ms = b128 >> 80
    return datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)

def ulid_to_uuid(s: str) -> uuid.UUID:
    """
    Преобразует ULID в UUID (с сохранением 128 бит), что удобно для БД/ORM.
    """
    s = normalize_ulid(s)
    b128 = _base32_crockford_to_b128(s)
    return uuid.UUID(int=b128)

# ---------------------------------------------------------------------------
# UUIDv4 / UUIDv7
# ---------------------------------------------------------------------------

def uuid4_str() -> str:
    """UUIDv4 в каноническом виде."""
    return str(uuid.uuid4())

def _uuid7_manual() -> uuid.UUID:
    """
    Корректная ручная реализация UUIDv7 (RFC 9562):
      - 60 бит мс‑времени (Unix epoch milliseconds)
      - версия 7 (0b0111)
      - 62 бита случайности (var + rand)
    """
    ts_ms = _time_ms()
    if not (0 <= ts_ms < (1 << 60)):
        raise ValueError("timestamp out of 60-bit range for UUIDv7")

    # Формируем 128 бит по полям UUID:
    # time_hi_and_version: старшие 12 бит времени + версия 7
    time_low = ts_ms & 0xFFFFFFFF
    time_mid = (ts_ms >> 32) & 0xFFFF
    time_hi_and_version = ((ts_ms >> 48) & 0x0FFF) | (0x7 << 12)  # версия 7

    # clock_seq: 14 бит случайности + variant (RFC 4122) '10'
    rnd = int.from_bytes(secrets.token_bytes(10), "big")  # 80 случайных бит, используем нужные
    clock_seq = (rnd >> 66) & 0x3FFF  # 14 бит
    clock_seq |= 0x8000  # variant '10xx xxxx xxxx xxxx'

    node = rnd & 0xFFFFFFFFFFFF  # 48 бит

    return uuid.UUID(fields=(time_low, time_mid, time_hi_and_version, (clock_seq >> 8) & 0xFF, clock_seq & 0xFF, node))

def uuid7_str() -> str:
    """
    UUIDv7 в каноническом виде.
    Если стандартная реализация доступна (Python 3.11+), используется она; иначе корректная ручная.
    """
    if hasattr(uuid, "uuid7"):
        try:
            return str(uuid.uuid7())  # type: ignore[attr-defined]
        except Exception:
            pass
    return str(_uuid7_manual())

# ---------------------------------------------------------------------------
# Короткие URL‑безопасные ID
# ---------------------------------------------------------------------------

_URL_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-"
# По умолчанию 21 символов (~126 бит энтропии при 62..64‑символ. алфавите)

def short_id(length: int = 21, alphabet: str = _URL_ALPHABET) -> str:
    """
    Генерирует короткий URL‑безопасный идентификатор.
    Алфавит по умолчанию соответствует URL‑safe символам без спецсимволов.
    """
    if length <= 0:
        raise ValueError("length must be positive")
    if not alphabet or len(set(alphabet)) < 16:
        raise ValueError("alphabet too small")
    # secrets.choice использует системный CSPRNG
    return "".join(secrets.choice(alphabet) for _ in range(length))

# ---------------------------------------------------------------------------
# Унифицированная фабрика
# ---------------------------------------------------------------------------

def new_id(kind: str = "ulid", *, monotonic: bool = False) -> str:
    """
    Универсальный генератор:
      - kind = 'ulid' | 'uuid4' | 'uuid7' | 'short'
      - monotonic=True применяется только к ULID
    """
    k = kind.lower()
    if k == "ulid":
        return ulid_monotonic() if monotonic else ulid()
    if k == "uuid4":
        return uuid4_str()
    if k == "uuid7":
        return uuid7_str()
    if k == "short":
        return short_id()
    raise ValueError("unknown kind")

# ---------------------------------------------------------------------------
# Проверки
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

def is_uuid(s: str) -> bool:
    """Быстрая проверка формата UUID (каноническая строка с дефисами)."""
    if not s:
        return False
    return bool(_UUID_RE.match(s))

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_ulid(args: argparse.Namespace) -> None:
    gen = ulid_monotonic if args.monotonic else ulid
    for _ in range(args.n):
        print(gen())

def _cmd_uuid(args: argparse.Namespace) -> None:
    gen = uuid7_str if args.v == "7" else uuid4_str
    for _ in range(args.n):
        print(gen())

def _cmd_short(args: argparse.Namespace) -> None:
    for _ in range(args.n):
        print(short_id(length=args.length))

def _cmd_info(args: argparse.Namespace) -> None:
    s = args.id.strip()
    info = {"input": s}
    if is_ulid(s):
        dt = ulid_timestamp(s)
        info.update({"type": "ULID", "timestamp_utc": dt.isoformat()})
    elif is_uuid(s):
        u = uuid.UUID(s)
        # Определим версию
        info.update({"type": f"UUIDv{u.version}", "hex": u.hex})
    else:
        info.update({"type": "unknown"})
    print(info)

def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(prog="veilmind-idgen", description="VeilMind ID generator")
    sub = parser.add_subparsers(required=True)

    p_ulid = argparse.ArgumentParser(add_help=False)
    sp1 = sub.add_parser("ulid", parents=[p_ulid], help="Generate ULID")
    sp1.add_argument("-n", type=int, default=1, dest="n")
    sp1.add_argument("--monotonic", action="store_true", help="use monotonic sequence")
    sp1.set_defaults(func=_cmd_ulid)

    sp2 = sub.add_parser("uuid", help="Generate UUIDv4/UUIDv7")
    sp2.add_argument("-n", type=int, default=1, dest="n")
    sp2.add_argument("-v", choices=["4", "7"], default="7")
    sp2.set_defaults(func=_cmd_uuid)

    sp3 = sub.add_parser("short", help="Generate short URL-safe IDs")
    sp3.add_argument("-n", type=int, default=1, dest="n")
    sp3.add_argument("--length", type=int, default=21)
    sp3.set_defaults(func=_cmd_short)

    sp4 = sub.add_parser("info", help="Inspect ID (type, timestamp for ULID)")
    sp4.add_argument("id")
    sp4.set_defaults(func=_cmd_info)

    args = parser.parse_args(list(argv) if argv is not None else None)
    args.func(args)

if __name__ == "__main__":  # pragma: no cover
    main()
