# -*- coding: utf-8 -*-
"""
engine-core / engine / state / replay.py

Deterministic Replay System.

Формат файла (версия 1), little-endian, все числа без знака если не указано обратное:
Header:
  - magic:   4 bytes = b"RPL1"
  - flags:   u32     (бит 0 = hash_chain_on, бит 1 = crc_on)
  - created_us: u64  (UTC epoch in microseconds)
  - tick_hz: u32     (0 если неизвестно)
  - session_id_len: u16, session_id utf8
  - meta_len: u32, meta utf8 JSON (компактный)
  - reserve: 8 bytes = zero

Далее последовательность записей:
Record:
  - kind: u8    (0=EVENT,1=BOOKMARK,2=ROTATE,3=END)
  - dt_us_varint (delta от предыдущей absolute_ts_us; для первой записи delta = absolute_ts_us - created_us)
  - type_len varint, type utf8    (для BOOKMARK используется фикс. type="bookmark")
  - payload_len varint, payload raw bytes (обычно JSON utf8)
  - hash32/u32? см. ниже
  - crc32_last4 u32   (CRC32 всей записи без этого поля)
  - Если флаг hash_chain_on = 1: перед crc32 записывается 32 bytes SHA-256(chain), где chain = SHA256(prev_hash || record_without_chain_and_crc)

Индексные «checkpoints» в самом файле не требуются — индекс строится на лету при записи и при чтении может быть реконструирован. Для ускорения seek мы периодически эмитим BOOKMARK с key="ix:n" (каждые K записей) — Replayer использует их как sparse index.

Цели:
- Надёжность: CRC на запись, цепочка SHA-256 исключает незаметную правку.
- Детерминизм: упорядоченный монотонный ts_us, неизменяемый append-only.
- Удобство: API записи/чтения, seek по времени/индексу, скорость воспроизведения.

Без внешних зависимостей.

Author: Aethernova / engine-core
"""

from __future__ import annotations

import io
import json
import os
import struct
import threading
import time
import hashlib
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# ============================================================
# Low-level utils
# ============================================================

def _now_us() -> int:
    return int(time.time() * 1_000_000)

def _varint_encode(x: int) -> bytes:
    if x < 0:
        raise ValueError("varint expects non-negative")
    out = bytearray()
    while True:
        b = x & 0x7F
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def _varint_decode(buf: memoryview, pos: int) -> Tuple[int, int]:
    x = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise EOFError("varint underflow")
        b = buf[pos]
        pos += 1
        x |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return x, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too large")

def _crc32(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF

def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

# ============================================================
# Constants / enums
# ============================================================

MAGIC = b"RPL1"
FLAG_HASH = 1 << 0
FLAG_CRC = 1 << 1

REC_EVENT = 0
REC_BOOKMARK = 1
REC_ROTATE = 2
REC_END = 3

BOOKMARK_IX_PREFIX = "ix:"       # автоматическая «слабая» закладка через N записей
DEFAULT_AUTO_BOOKMARK_EVERY = 512

# ============================================================
# Data structures
# ============================================================

@dataclass
class ReplayHeader:
    flags: int
    created_us: int
    tick_hz: int
    session_id: str
    meta: Dict[str, Any]

@dataclass
class Event:
    ts_us: int                   # absolute time
    etype: str                   # тип события
    payload: bytes               # произвольные байты (обычно JSON)
    idx: int                     # порядковый индекс события внутри файла (считая только EVENT)

@dataclass
class Bookmark:
    ts_us: int
    name: str
    file_offset: int             # смещение записи (для seek без полного парсинга)
    idx_hint: int                # порядковый индекс события на момент закладки

# ============================================================
# Recorder
# ============================================================

class Recorder:
    """
    Append-only writer with integrity checks and sparse index bookmarks.
    Thread-safe: запись защищена RLock.
    """

    def __init__(
        self,
        path: str,
        *,
        tick_hz: int = 0,
        session_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        enable_hash_chain: bool = True,
        enable_crc: bool = True,
        auto_bookmark_every: int = DEFAULT_AUTO_BOOKMARK_EVERY,
    ) -> None:
        self._lock = threading.RLock()
        self.path = path
        self._f = open(path, "wb", buffering=0)
        self._flags = (FLAG_HASH if enable_hash_chain else 0) | (FLAG_CRC if enable_crc else 0)
        self._hdr = ReplayHeader(
            flags=self._flags,
            created_us=_now_us(),
            tick_hz=int(tick_hz),
            session_id=session_id or _gen_session_id(),
            meta=dict(meta or {}),
        )
        self._last_abs_us = self._hdr.created_us
        self._hash_prev = b"\x00" * 32
        self._events = 0
        self._records = 0
        self._auto_every = max(0, int(auto_bookmark_every))
        self._write_header()

    # --------------- public API ---------------

    def write_event(self, etype: str, payload_obj: Any, *, ts_us: Optional[int] = None) -> Event:
        """
        Записать событие. payload_obj сериализуется в компактный JSON (utf-8).
        Возвращает метаданные события (absolute ts и индекс).
        """
        pay = _ensure_bytes(payload_obj)
        t = self._choose_ts(ts_us)
        with self._lock:
            self._append_record(REC_EVENT, t, etype, pay)
            self._events += 1
            self._records += 1
            if self._auto_every and (self._records % self._auto_every == 0):
                # слабая закладка — для ускорения seek
                self.bookmark(f"{BOOKMARK_IX_PREFIX}{self._records}")
            return Event(ts_us=t, etype=etype, payload=pay, idx=self._events - 1)

    def bookmark(self, name: str, *, ts_us: Optional[int] = None) -> Bookmark:
        """
        Пишет BOOKMARK с произвольным именем (короткая строка). Возвращает Bookmark.
        """
        t = self._choose_ts(ts_us)
        with self._lock:
            offs_before = self._f.tell()
            self._append_record(REC_BOOKMARK, t, "bookmark", name.encode("utf-8"))
            self._records += 1
            return Bookmark(ts_us=t, name=name, file_offset=offs_before, idx_hint=self._events)

    def close(self) -> None:
        with self._lock:
            if self._f.closed:
                return
            try:
                self._append_record(REC_END, self._last_abs_us, "end", b"")
            finally:
                self._f.flush()
                self._f.close()

    # --------------- internals ---------------

    def _choose_ts(self, ts_us: Optional[int]) -> int:
        t = self._last_abs_us if ts_us is None else int(ts_us)
        # монотонность
        if t < self._last_abs_us:
            t = self._last_abs_us
        return t

    def _write_header(self) -> None:
        sid = self._hdr.session_id.encode("utf-8")
        meta = json.dumps(self._hdr.meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        buf = io.BytesIO()
        buf.write(MAGIC)
        buf.write(struct.pack("<I", self._hdr.flags))
        buf.write(struct.pack("<Q", self._hdr.created_us))
        buf.write(struct.pack("<I", self._hdr.tick_hz))
        buf.write(struct.pack("<H", len(sid))); buf.write(sid)
        buf.write(struct.pack("<I", len(meta))); buf.write(meta)
        buf.write(b"\x00" * 8)
        self._f.write(buf.getvalue())

    def _append_record(self, kind: int, abs_us: int, etype: str, payload: bytes) -> None:
        # delta time
        dt = abs_us - self._last_abs_us
        self._last_abs_us = abs_us
        # build record without hash/crc
        typ = etype.encode("utf-8")
        body = bytearray()
        body.append(kind & 0xFF)
        body += _varint_encode(dt if dt >= 0 else 0)
        body += _varint_encode(len(typ)); body += typ
        body += _varint_encode(len(payload)); body += payload

        # hash chain (optional)
        if self._flags & FLAG_HASH:
            # chain input = prev_hash || body
            h = _sha256(self._hash_prev + bytes(body))
            self._hash_prev = h
            body += h  # 32 bytes

        # crc32 (optional)
        if self._flags & FLAG_CRC:
            crc = _crc32(bytes(body))
            body += struct.pack("<I", crc)

        self._f.write(body)

# ============================================================
# Replayer
# ============================================================

class Replayer:
    """
    Читатель/проигрыватель с валидацией. Поддерживает:
      - iterate(): последовательный разбор всех записей
      - play(): воспроизведение с контролем скорости
      - seek_ts()/seek_index(): быстрые перемотки по закладкам и dT
      - integrity_scan(): поиск последней валидной записи (watermark) с проверкой CRC/hash
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._f = open(path, "rb")
        self.header = self._read_header()
        self._flags = self.header.flags
        self._index: List[Bookmark] = []       # собранные закладки
        self._watermark_off = None             # последний валидный байт оффсет
        self._build_index()

    # --------------- public API ---------------

    def iterate(self, *, verify: bool = True):
        """
        Итератор по событиям (Event) и закладкам (Bookmark) в порядке файла.
        """
        f = self._f
        f.seek(self._data_start())
        prev_abs = self.header.created_us
        prev_hash = b"\x00" * 32
        while True:
            off = f.tell()
            chunk = self._read_record_bytes(f)
            if chunk is None:
                break
            rec_buf = memoryview(chunk)
            try:
                kind, dt, pos = rec_buf[0], * _read_dt_pos(rec_buf, 1)
                abs_us = prev_abs + dt
                # type
                typ_len, pos = _varint_decode(rec_buf, pos)
                typ = rec_buf[pos:pos+typ_len].tobytes().decode("utf-8"); pos += typ_len
                # payload
                pay_len, pos = _varint_decode(rec_buf, pos)
                payload = rec_buf[pos:pos+pay_len].tobytes(); pos += pay_len
                # hash chain
                if self._flags & FLAG_HASH:
                    h = rec_buf[pos:pos+32].tobytes(); pos += 32
                    calc = _sha256(prev_hash + rec_buf[:pos-32].tobytes())
                    if h != calc:
                        raise ValueError("hash_chain_mismatch")
                    prev_hash = h
                # crc32
                if self._flags & FLAG_CRC:
                    crc_expected = struct.unpack("<I", rec_buf[pos:pos+4])[0]
                    crc_calc = _crc32(rec_buf[:pos].tobytes())
                    if crc_calc != crc_expected:
                        raise ValueError("crc_mismatch")

                if kind == REC_EVENT:
                    yield Event(ts_us=abs_us, etype=typ, payload=payload, idx=-1)
                elif kind == REC_BOOKMARK:
                    name = payload.decode("utf-8") if payload else ""
                    bm = Bookmark(ts_us=abs_us, name=name, file_offset=off, idx_hint=-1)
                    yield bm
                elif kind == REC_END:
                    break
                prev_abs = abs_us
            except Exception:
                if verify:
                    # при verify любые ошибки останавливают
                    raise
                else:
                    # без verify — помечаем watermark и выходим
                    self._watermark_off = off
                    break

    def play(
        self,
        on_event: Callable[[Event], None],
        *,
        speed: float = 1.0,
        start_ts_us: Optional[int] = None,
        verify: bool = True,
        stop_ts_us: Optional[int] = None,
    ) -> None:
        """
        Проигрывание событий с контролем скорости (реального времени).
        speed=1.0 — реальная скорость; 0 — как можно быстрее.
        """
        # первичный скан без разборки всего
        it = self.iterate(verify=verify)
        t0_wall = time.perf_counter()
        first_abs: Optional[int] = None
        for item in it:
            if isinstance(item, Bookmark):
                continue
            ev: Event = item  # type: ignore[assignment]
            if first_abs is None:
                first_abs = ev.ts_us
            if start_ts_us is not None and ev.ts_us < start_ts_us:
                continue
            if stop_ts_us is not None and ev.ts_us > stop_ts_us:
                break
            if speed > 0:
                # рассчитать задержку
                base = start_ts_us if start_ts_us is not None else first_abs
                elapsed_sim = (ev.ts_us - base) / 1_000_000.0
                elapsed_wall = time.perf_counter() - t0_wall
                target = elapsed_sim / max(1e-9, speed)
                if target > elapsed_wall:
                    time.sleep(target - elapsed_wall)
            on_event(Event(ts_us=ev.ts_us, etype=ev.etype, payload=ev.payload, idx=-1))

    def seek_ts(self, ts_us: int) -> int:
        """
        Быстрый seek по времени. Возвращает файловый оффсет первой записи с abs_ts >= ts_us.
        """
        # двоичный поиск по закладкам, затем линейная догонка
        if not self._index:
            self._build_index()
        lo, hi = 0, len(self._index) - 1
        pos_off = self._data_start()
        while lo <= hi:
            mid = (lo + hi) // 2
            if self._index[mid].ts_us < ts_us:
                lo = mid + 1
            else:
                hi = mid - 1
        # точка входа
        if 0 <= hi < len(self._index):
            pos_off = self._index[hi].file_offset
        self._f.seek(pos_off)
        prev_abs = self.header.created_us
        while True:
            off = self._f.tell()
            rec = self._read_record_bytes(self._f)
            if rec is None:
                return off
            kind, dt, new_abs, _ = _peek_kind_dt_abs(rec, prev_abs)
            if new_abs >= ts_us:
                self._f.seek(off)
                return off
            prev_abs = new_abs

    def seek_index(self, event_idx: int) -> int:
        """
        Seek к событию с заданным индексом (0-based). Возвращает файловый оффсет.
        """
        if event_idx < 0:
            return self._data_start()
        # используем ix: закладки для оценки диапазона
        approx_off = self._data_start()
        for bm in self._index:
            if bm.idx_hint <= event_idx and bm.name.startswith(BOOKMARK_IX_PREFIX):
                approx_off = bm.file_offset
        self._f.seek(approx_off)
        prev_abs = self.header.created_us
        cur_idx = 0
        while True:
            off = self._f.tell()
            rec = self._read_record_bytes(self._f)
            if rec is None:
                return off
            kind, dt, new_abs, _ = _peek_kind_dt_abs(rec, prev_abs)
            if kind == REC_EVENT:
                if cur_idx == event_idx:
                    self._f.seek(off)
                    return off
                cur_idx += 1
            prev_abs = new_abs

    def integrity_scan(self) -> Tuple[int, Optional[int]]:
        """
        Полная проверка целостности файла.
        Возвращает (valid_bytes_up_to, last_abs_ts_us or None).
        """
        f = self._f
        f.seek(self._data_start())
        prev_abs = self.header.created_us
        prev_hash = b"\x00" * 32
        last_good_off = f.tell()
        last_ts = None
        while True:
            off = f.tell()
            chunk = self._read_record_bytes(f)
            if chunk is None:
                break
            mv = memoryview(chunk)
            try:
                kind, dt, pos = mv[0], * _read_dt_pos(mv, 1)
                abs_us = prev_abs + dt
                typ_len, pos = _varint_decode(mv, pos)
                pos += typ_len
                pay_len, pos = _varint_decode(mv, pos)
                pos += pay_len
                if self._flags & FLAG_HASH:
                    h = mv[pos:pos+32].tobytes(); pos += 32
                    calc = _sha256(prev_hash + mv[:pos-32].tobytes())
                    if h != calc:
                        break
                    prev_hash = h
                if self._flags & FLAG_CRC:
                    crc_expected = struct.unpack("<I", mv[pos:pos+4])[0]
                    crc_calc = _crc32(mv[:pos].tobytes())
                    if crc_calc != crc_expected:
                        break
                last_good_off = f.tell()
                last_ts = abs_us
                prev_abs = abs_us
                if kind == REC_END:
                    break
            except Exception:
                break
        self._watermark_off = last_good_off
        return last_good_off, last_ts

    # --------------- internals ---------------

    def _read_header(self) -> ReplayHeader:
        f = self._f
        mg = f.read(4)
        if mg != MAGIC:
            raise ValueError("bad magic")
        flags = struct.unpack("<I", f.read(4))[0]
        created_us = struct.unpack("<Q", f.read(8))[0]
        tick_hz = struct.unpack("<I", f.read(4))[0]
        sid_len = struct.unpack("<H", f.read(2))[0]
        sid = f.read(sid_len).decode("utf-8")
        meta_len = struct.unpack("<I", f.read(4))[0]
        meta = json.loads(f.read(meta_len).decode("utf-8")) if meta_len > 0 else {}
        f.read(8)  # reserve
        return ReplayHeader(flags=flags, created_us=created_us, tick_hz=tick_hz, session_id=sid, meta=meta)

    def _data_start(self) -> int:
        # позиция после заголовка
        self._f.seek(0)
        _ = self._read_header()
        return self._f.tell()

    def _build_index(self) -> None:
        self._index.clear()
        f = self._f
        f.seek(self._data_start())
        prev_abs = self.header.created_us
        events = 0
        while True:
            off = f.tell()
            rec = self._read_record_bytes(f)
            if rec is None:
                break
            kind, dt, abs_us, payload_slice = _peek_kind_dt_abs(rec, prev_abs)
            if kind == REC_EVENT:
                events += 1
            elif kind == REC_BOOKMARK:
                name = payload_slice.tobytes().decode("utf-8") if payload_slice else ""
                self._index.append(Bookmark(ts_us=abs_us, name=name, file_offset=off, idx_hint=events))
            elif kind == REC_END:
                break
            prev_abs = abs_us

    def _read_record_bytes(self, f) -> Optional[bytes]:
        # Читаем минимум 1 байт (kind). Если EOF — None.
        pos0 = f.tell()
        k = f.read(1)
        if not k:
            return None
        # для безопасного чтения прочитываем прогрессивно, используя varint-поля
        buf = bytearray(k)
        mv = memoryview(buf)
        # dt
        while True:
            # пытаемся декодировать dt
            try:
                dt, _ = _varint_decode(mv, 1)
                break
            except (EOFError, ValueError):
                b = f.read(1)
                if not b:
                    raise EOFError("truncated dt varint")
                buf += b
                mv = memoryview(buf)
        # type_len
        pos = 1
        dt, pos = _varint_decode(mv, pos)
        # читаем пока не сможем декодировать type_len
        while True:
            try:
                typ_len, _ = _varint_decode(mv, pos)
                break
            except (EOFError, ValueError):
                b = f.read(1)
                if not b:
                    raise EOFError("truncated type varint")
                buf += b; mv = memoryview(buf)
        typ_len, pos = _varint_decode(mv, pos)
        need = pos + typ_len
        while len(buf) < need:
            b = f.read(need - len(buf))
            if not b:
                raise EOFError("truncated type bytes")
            buf += b; mv = memoryview(buf)
        pos = need
        # payload_len
        while True:
            try:
                pay_len, _ = _varint_decode(mv, pos)
                break
            except (EOFError, ValueError):
                b = f.read(1)
                if not b:
                    raise EOFError("truncated payload varint")
                buf += b; mv = memoryview(buf)
        pay_len, pos = _varint_decode(mv, pos)
        need = pos + pay_len
        while len(buf) < need:
            b = f.read(need - len(buf))
            if not b:
                raise EOFError("truncated payload bytes")
            buf += b; mv = memoryview(buf)
        pos = need
        # hash+crc (optional)
        extra = (32 if (self._flags & FLAG_HASH) else 0) + (4 if (self._flags & FLAG_CRC) else 0)
        if extra:
            b = f.read(extra)
            if len(b) != extra:
                raise EOFError("truncated integrity trailer")
            buf += b
        return bytes(buf)

# ============================================================
# Helpers
# ============================================================

def _read_dt_pos(mv: memoryview, pos: int) -> Tuple[int, int]:
    dt, pos2 = _varint_decode(mv, pos)
    return dt, pos2

def _peek_kind_dt_abs(rec: bytes, prev_abs: int) -> Tuple[int, int, int, memoryview]:
    mv = memoryview(rec)
    kind = mv[0]
    dt, pos = _varint_decode(mv, 1)
    typ_len, pos = _varint_decode(mv, pos)
    pos_typ_end = pos + typ_len
    pay_len, pos2 = _varint_decode(mv, pos_typ_end)
    pos_pay = pos2
    payload = mv[pos_pay:pos_pay+pay_len]
    abs_us = prev_abs + dt
    return kind, dt, abs_us, payload

def _gen_session_id() -> str:
    return hashlib.sha256(f"{os.getpid()}-{time.time_ns()}".encode("utf-8")).hexdigest()[:16]

def _ensure_bytes(obj: Any) -> bytes:
    if obj is None:
        return b"null"
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, (dict, list, int, float, bool, str)):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") if not isinstance(obj, bytes) else obj
    return str(obj).encode("utf-8")

# ============================================================
# Example usage / self-check
# ============================================================

if __name__ == "__main__":
    # Запись
    rec = Recorder("test.replay", tick_hz=60, meta={"build":"dev"}, enable_hash_chain=True, enable_crc=True)
    rec.bookmark("start")
    for i in range(3):
        rec.write_event("tick", {"i": i})
        time.sleep(0.01)
    rec.bookmark("mid")
    rec.write_event("custom", {"payload":"ok"})
    rec.close()

    # Чтение
    rep = Replayer("test.replay")
    print("Header:", rep.header)
    print("Integrity:", rep.integrity_scan())
    print("Iterate:")
    for itm in rep.iterate():
        if isinstance(itm, Event):
            print("E", itm.etype, itm.ts_us)
        else:
            print("B", itm.name, itm.ts_us)

    print("Seek ts to middle:")
    off = rep.seek_ts(rep.header.created_us + 15_000)
    print("off=", off)
