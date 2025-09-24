# physical_integration/protocols/modbus_tcp.py
from __future__ import annotations

import asyncio
import math
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

__all__ = [
    "ModbusError",
    "ModbusProtocolError",
    "ModbusIOError",
    "Metrics",
    "NullMetrics",
    "BackoffPolicy",
    "RateLimit",
    "CircuitBreakerConfig",
    "BatchMapItem",
    "BatchReadResult",
    "ModbusTcpClient",
]

# =========================
# Ошибки
# =========================

class ModbusError(Exception):
    pass

class ModbusProtocolError(ModbusError):
    pass

class ModbusIOError(ModbusError):
    pass

# =========================
# Наблюдаемость / Метрики
# =========================

class Metrics:
    def inc(self, name: str, **labels: Any) -> None: ...
    def observe(self, name: str, value: float, **labels: Any) -> None: ...
    def gauge(self, name: str, value: float, **labels: Any) -> None: ...

class NullMetrics(Metrics):
    def inc(self, name: str, **labels: Any) -> None: pass
    def observe(self, name: str, value: float, **labels: Any) -> None: pass
    def gauge(self, name: str, value: float, **labels: Any) -> None: pass

# =========================
# Вспомогательные структуры
# =========================

@dataclass
class BackoffPolicy:
    max_attempts: int = 6
    base_ms: int = 200
    max_ms: int = 20_000
    multiplier: float = 2.0
    jitter: float = 0.2  # 0..1

@dataclass
class RateLimit:
    tokens_per_sec: float = 50.0
    burst: int = 100

class _TokenBucket:
    def __init__(self, cfg: RateLimit):
        self.rate = cfg.tokens_per_sec
        self.burst = float(cfg.burst)
        self.tokens = float(cfg.burst)
        self.last = time.monotonic()

    async def take(self, n: float = 1.0):
        while True:
            now = time.monotonic()
            delta = now - self.last
            self.last = now
            self.tokens = min(self.burst, self.tokens + delta * self.rate)
            if self.tokens >= n:
                self.tokens -= n
                return
            wait = max((n - self.tokens) / self.rate, 0.005)
            await asyncio.sleep(wait)

@dataclass
class CircuitBreakerConfig:
    failure_threshold_pct: float = 50.0
    min_samples: int = 20
    open_ms: int = 30_000
    half_open_max_calls: int = 5

class _CircuitBreaker:
    def __init__(self, cfg: CircuitBreakerConfig, on_state: Optional[Callable[[str], None]] = None):
        self.cfg = cfg
        self.state: Literal["closed","open","half-open"] = "closed"
        self.failures = 0
        self.successes = 0
        self.opened_at = 0.0
        self.half_calls = 0
        self.on_state = on_state

    def _emit(self, s: str):
        if self.on_state:
            try: self.on_state(s)
            except Exception: pass

    def can_pass(self) -> bool:
        if self.state == "open":
            if (time.monotonic() - self.opened_at) * 1000 >= self.cfg.open_ms:
                self.state = "half-open"; self.half_calls = 0; self._emit(self.state); return True
            return False
        if self.state == "half-open":
            if self.half_calls < self.cfg.half_open_max_calls:
                self.half_calls += 1; return True
            return False
        return True

    def record_success(self):
        if self.state == "half-open":
            self.state = "closed"; self.failures = 0; self.successes = 1; self.half_calls = 0; self._emit(self.state)
            return
        self.successes += 1

    def record_failure(self):
        if self.state == "half-open":
            self.state = "open"; self.opened_at = time.monotonic(); self._emit(self.state); return
        self.failures += 1
        total = self.failures + self.successes
        if total >= self.cfg.min_samples:
            rate = self.failures / total * 100.0
            if rate >= self.cfg.failure_threshold_pct:
                self.state = "open"; self.opened_at = time.monotonic(); self._emit(self.state)

# =========================
# Типы и преобразования
# =========================

Endian = Literal["big","little"]
WordOrder = Literal["AB","BA"]  # AB=network order, BA=word swap

@dataclass
class BatchMapItem:
    name: str
    at: int                           # смещение внутри блока (в регистрах/катушках)
    type: Literal[
        "bool",
        "uint16","int16",
        "uint32","int32","float32",
        "uint64","int64","float64",
    ] = "uint16"
    scale: float = 1.0
    offset: float = 0.0
    word_order: WordOrder = "AB"
    endian: Endian = "big"           # порядок байтов внутри 16-битного слова (обычно big)
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BatchReadResult:
    ok: bool
    ts_ms: int
    registers: Optional[List[int]] = None
    coils: Optional[List[bool]] = None
    values: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

# =========================
# Утилиты преобразований
# =========================

def _words_to_bytes(words: Sequence[int], endian: Endian) -> bytes:
    fmt = ">" if endian == "big" else "<"
    return b"".join(struct.pack(fmt + "H", w & 0xFFFF) for w in words)

def _bytes_to_words(data: bytes, endian: Endian) -> List[int]:
    if len(data) % 2 != 0:
        raise ModbusProtocolError("odd byte length for words")
    fmt = ">" if endian == "big" else "<"
    return list(struct.unpack(fmt + f"{len(data)//2}H", data))

def _swap_words(words: Sequence[int]) -> List[int]:
    out = list(words)
    out.reverse()
    return out

def _decode_value(words: Sequence[int], typ: str, endian: Endian, word_order: WordOrder) -> Union[int,float,bool]:
    if typ == "bool":
        return bool(words[0] & 0x0001)
    if typ in ("uint16","int16"):
        b = _words_to_bytes(words[:1], endian)
        fmt = (">" if endian=="big" else "<") + ("H" if typ=="uint16" else "h")
        return struct.unpack(fmt, b)[0]
    size_words = {"uint32":2,"int32":2,"float32":2,"uint64":4,"int64":4,"float64":4}[typ]
    w = list(words[:size_words])
    if word_order == "BA":
        # swap 16-битные слова (например, 0x1122 0x3344 -> 0x3344 0x1122)
        w = _swap_words(w)
    b = _words_to_bytes(w, endian)
    fmt_map = {
        "uint32":"I", "int32":"i", "float32":"f",
        "uint64":"Q", "int64":"q", "float64":"d",
    }
    fmt = (">" if endian == "big" else "<") + fmt_map[typ]
    return struct.unpack(fmt, b)[0]

def _encode_value(val: Union[int,float,bool], typ: str, endian: Endian, word_order: WordOrder) -> List[int]:
    if typ == "bool":
        return [1 if bool(val) else 0]
    if typ in ("uint16","int16"):
        fmt = (">" if endian=="big" else "<") + ("H" if typ=="uint16" else "h")
        b = struct.pack(fmt, int(val))
        return _bytes_to_words(b, endian)
    fmt_map = {
        "uint32":"I", "int32":"i", "float32":"f",
        "uint64":"Q", "int64":"q", "float64":"d",
    }
    fmt = (">" if endian=="big" else "<") + fmt_map[typ]
    b = struct.pack(fmt, val)
    words = _bytes_to_words(b, endian)
    if word_order == "BA":
        words = _swap_words(words)
    return words

# =========================
# Клиент Modbus-TCP
# =========================

class ModbusTcpClient:
    """
    Асинхронный Modbus-TCP клиент без внешних зависимостей.

    Особенности:
      - Автоподключение/переподключение
      - Ретраи (экспоненциальные, джиттер)
      - Circuit-breaker
      - Rate-limit (токен-бакет)
      - Таймаут на запрос
      - Потокобезопасность запросов (lock)
      - Поддержка FC: 0x01,0x03,0x04,0x05,0x06,0x0F,0x10
    """

    EXC_CODES = {
        1: "Illegal Function",
        2: "Illegal Data Address",
        3: "Illegal Data Value",
        4: "Slave Device Failure",
        5: "Acknowledge",
        6: "Slave Device Busy",
        8: "Memory Parity Error",
        10: "Gateway Path Unavailable",
        11: "Gateway Target Device Failed to Respond",
    }

    def __init__(
        self,
        host: str,
        port: int = 502,
        unit_id: int = 1,
        *,
        connect_timeout: float = 5.0,
        request_timeout: float = 2.0,
        backoff: Optional[BackoffPolicy] = None,
        rate_limit: Optional[RateLimit] = None,
        breaker: Optional[CircuitBreakerConfig] = None,
        metrics: Optional[Metrics] = None,
        tcp_keepalive: bool = True,
        name: str = "modbus",
    ):
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self.backoff = backoff or BackoffPolicy()
        self.rate = _TokenBucket(rate_limit or RateLimit())
        self.metrics = metrics or NullMetrics()
        self.breaker = _CircuitBreaker(breaker or CircuitBreakerConfig(), on_state=lambda s: self.metrics.inc("modbus_breaker_state", state=s, name=name))
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._lock = asyncio.Lock()
        self._tx_id = 0
        self._name = name
        self._closed = False
        self._tcp_keepalive = tcp_keepalive

    # ---------- Жизненный цикл ----------

    async def connect(self):
        await self._ensure_conn()

    async def close(self):
        self._closed = True
        try:
            if self._writer:
                self._writer.close()
                try:
                    await self._writer.wait_closed()
                except Exception:
                    pass
        finally:
            self._reader = None
            self._writer = None

    # ---------- Публичные операции ----------

    async def read_coils(self, address: int, count: int) -> List[bool]:
        pdu = struct.pack(">BHH", 0x01, address, count)
        data = await self._xfer(pdu)
        byte_count = data[0]
        bits = data[1:1+byte_count]
        out: List[bool] = []
        for i in range(count):
            byte = bits[i // 8]
            out.append(bool((byte >> (i % 8)) & 0x01))
        return out

    async def read_discrete_inputs(self, address: int, count: int) -> List[bool]:
        pdu = struct.pack(">BHH", 0x02, address, count)
        data = await self._xfer(pdu)
        byte_count = data[0]
        bits = data[1:1+byte_count]
        out: List[bool] = []
        for i in range(count):
            byte = bits[i // 8]
            out.append(bool((byte >> (i % 8)) & 0x01))
        return out

    async def read_holding_registers(self, address: int, count: int) -> List[int]:
        pdu = struct.pack(">BHH", 0x03, address, count)
        data = await self._xfer(pdu)
        byte_count = data[0]
        payload = data[1:1+byte_count]
        regs = list(struct.unpack(">" + "H" * (byte_count // 2), payload))
        return regs

    async def read_input_registers(self, address: int, count: int) -> List[int]:
        pdu = struct.pack(">BHH", 0x04, address, count)
        data = await self._xfer(pdu)
        byte_count = data[0]
        payload = data[1:1+byte_count]
        regs = list(struct.unpack(">" + "H" * (byte_count // 2), payload))
        return regs

    async def write_single_coil(self, address: int, value: bool) -> None:
        v = 0xFF00 if value else 0x0000
        pdu = struct.pack(">BHH", 0x05, address, v)
        _ = await self._xfer(pdu)  # echo

    async def write_single_register(self, address: int, value: int) -> None:
        pdu = struct.pack(">BHH", 0x06, address, value & 0xFFFF)
        _ = await self._xfer(pdu)  # echo

    async def write_multiple_coils(self, address: int, values: Sequence[bool], *, max_multi_write: int = 1968) -> None:
        if len(values) > max_multi_write:
            raise ModbusError(f"mass write exceeds limit {max_multi_write}")
        qty = len(values)
        bytc = (qty + 7) // 8
        buf = bytearray(bytc)
        for i, bit in enumerate(values):
            if bit:
                buf[i // 8] |= (1 << (i % 8))
        pdu = struct.pack(">BHHB", 0x0F, address, qty, bytc) + bytes(buf)
        _ = await self._xfer(pdu)

    async def write_multiple_registers(self, address: int, values: Sequence[int], *, max_multi_write: int = 123) -> None:
        if len(values) > max_multi_write:
            raise ModbusError(f"mass write exceeds limit {max_multi_write}")
        qty = len(values)
        payload = struct.pack(">" + "H"*qty, *[v & 0xFFFF for v in values])
        pdu = struct.pack(">BHHB", 0x10, address, qty, qty*2) + payload
        _ = await self._xfer(pdu)

    # ---------- Высокоуровневые утилиты ----------

    async def read_batch(
        self,
        address: int,
        count: int,
        *,
        kind: Literal["holding","input"] = "holding",
        mapping: Optional[List[BatchMapItem]] = None,
        endian: Endian = "big"
    ) -> BatchReadResult:
        ts = int(time.time() * 1000)
        try:
            regs = await (self.read_holding_registers(address, count) if kind=="holding" else self.read_input_registers(address, count))
        except Exception as e:
            return BatchReadResult(ok=False, ts_ms=ts, error=str(e))

        res = BatchReadResult(ok=True, ts_ms=ts, registers=regs, values={})
        if mapping:
            for m in mapping:
                try:
                    window = regs[m.at : m.at + _words_span(m.type)]
                    raw = _decode_value(window, m.type, m.endian, m.word_order)
                    val = float(raw) * m.scale + m.offset if isinstance(raw, (int,float)) else raw
                    res.values[m.name] = val
                except Exception as ex:
                    res.values[m.name] = None
        return res

    async def write_typed(
        self,
        address: int,
        value: Union[int,float,bool],
        *,
        typ: BatchMapItem["type"] = "uint16",
        endian: Endian = "big",
        word_order: WordOrder = "AB",
        scale: float = 1.0,
        offset: float = 0.0,
        idempotency_key: Optional[str] = None,
        max_multi_write: int = 123
    ) -> None:
        # идемпотентность по ключу — примитивная локальная: не повторяем ту же комбинацию в пределах процесса
        # (в реале используйте внешнее хранилище)
        if idempotency_key:
            if not hasattr(self, "_idem"): self._idem = set()
            key = (address, typ, idempotency_key)
            if key in self._idem:
                return
            self._idem.add(key)

        val = value
        if isinstance(val, (int, float)):
            val = (val - offset) / (scale if scale != 0 else 1.0)
        words = _encode_value(val, typ, endian, word_order)

        if len(words) == 1:
            if typ == "bool":
                await self.write_single_coil(address, bool(value))
            else:
                await self.write_single_register(address, words[0])
        else:
            await self.write_multiple_registers(address, words, max_multi_write=max_multi_write)

    # ---------- Внутренний транспорт и retry ----------

    async def _xfer(self, pdu: bytes) -> bytes:
        # Rate limit
        await self.rate.take(1.0)

        # Circuit breaker
        if not self.breaker.can_pass():
            raise ModbusIOError("circuit breaker open")

        # Retries
        attempt = 1
        last_exc: Optional[Exception] = None
        while attempt <= self.backoff.max_attempts:
            try:
                return await self._xfer_once(pdu)
            except (ModbusIOError, ModbusProtocolError) as e:
                last_exc = e
                self.breaker.record_failure()
                if attempt >= self.backoff.max_attempts:
                    break
                await asyncio.sleep(self._delay_for(attempt))
                attempt += 1
                continue
        assert last_exc is not None
        raise last_exc

    def _delay_for(self, attempt: int) -> float:
        expo = self.backoff.base_ms * (self.backoff.multiplier ** (attempt - 1))
        capped = min(expo, self.backoff.max_ms)
        jitter = capped * self.backoff.jitter * (random.random()*2 - 1)
        return max(0.0, (capped + jitter) / 1000.0)

    async def _ensure_conn(self):
        if self._reader and self._writer:
            return
        await self._connect()

    async def _connect(self):
        if self._closed:
            raise ModbusIOError("client is closed")
        try:
            self.metrics.inc("modbus_connect_attempt")
            coro = asyncio.open_connection(self.host, self.port)
            self._reader, self._writer = await asyncio.wait_for(coro, timeout=self.connect_timeout)
            # TCP keepalive
            if self._tcp_keepalive:
                sock: Optional[socket.socket] = self._writer.get_extra_info("socket")
                if sock is not None:
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                        if hasattr(socket, "TCP_KEEPIDLE"):
                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                        if hasattr(socket, "TCP_KEEPINTVL"):
                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                        if hasattr(socket, "TCP_KEEPCNT"):
                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                    except Exception:
                        pass
            self.metrics.inc("modbus_connect_success")
        except Exception as e:
            self._reader = None; self._writer = None
            self.metrics.inc("modbus_connect_fail")
            raise ModbusIOError(f"connect failed: {e}")

    async def _xfer_once(self, pdu: bytes) -> bytes:
        async with self._lock:
            await self._ensure_conn()
            assert self._writer and self._reader
            tx_id = (self._tx_id + 1) & 0xFFFF
            self._tx_id = tx_id

            # MBAP: tx(2), proto=0(2), len=1+len(pdu)(2), unit(1)
            mbap = struct.pack(">HHHB", tx_id, 0, 1 + len(pdu), self.unit_id)
            req = mbap + pdu

            self.metrics.inc("modbus_request", fn=pdu[0])
            t0 = time.perf_counter()
            try:
                self._writer.write(req)
                await self._writer.drain()
            except Exception as e:
                await self._on_broken_conn()
                raise ModbusIOError(f"write failed: {e}")

            # Read MBAP
            try:
                hdr = await asyncio.wait_for(self._reader.readexactly(7), timeout=self.request_timeout)
            except Exception as e:
                await self._on_broken_conn()
                raise ModbusIOError(f"timeout or read header failed: {e}")

            (rx_tx, rx_proto, rx_len) = struct.unpack(">HHH", hdr[:6])
            rx_unit = hdr[6]

            if rx_tx != tx_id or rx_proto != 0 or rx_unit != self.unit_id:
                await self._on_broken_conn()
                raise ModbusProtocolError("mbap mismatch")

            # Read PDU
            # rx_len includes 1 byte of unit already accounted; remaining bytes in PDU:
            to_read = rx_len - 1
            try:
                pdu_resp = await asyncio.wait_for(self._reader.readexactly(to_read), timeout=self.request_timeout)
            except Exception as e:
                await self._on_broken_conn()
                raise ModbusIOError(f"timeout or read pdu failed: {e}")

            dur = (time.perf_counter() - t0) * 1000.0
            self.metrics.observe("modbus_request_ms", dur, fn=pdu[0])

            # Check exception
            fn = pdu_resp[0]
            if fn & 0x80:
                code = pdu_resp[1] if len(pdu_resp) > 1 else -1
                reason = self.EXC_CODES.get(code, f"exception {code}")
                # 5/6 (ACK/BUSY) считаем временными для ретрая
                if code in (5,6,11):
                    raise ModbusIOError(f"device busy/ack: {reason}")
                raise ModbusProtocolError(reason)

            self.breaker.record_success()
            return pdu_resp

    async def _on_broken_conn(self):
        try:
            if self._writer:
                self._writer.close()
                try:
                    await self._writer.wait_closed()
                except Exception:
                    pass
        finally:
            self._reader = None
            self._writer = None

# =========================
# Вспомогательное
# =========================

def _words_span(typ: str) -> int:
    return {
        "bool": 1,
        "uint16": 1, "int16": 1,
        "uint32": 2, "int32": 2, "float32": 2,
        "uint64": 4, "int64": 4, "float64": 4,
    }[typ]

# =========================
# Пример использования (док-строка)
# =========================

"""
Пример:

import asyncio
from physical_integration.protocols.modbus_tcp import (
    ModbusTcpClient, BatchMapItem
)

async def main():
    client = ModbusTcpClient("10.0.0.10", unit_id=1)
    await client.connect()

    # Чтение 16 регистров начиная с адреса 0
    res = await client.read_batch(
        0, 16, kind="holding",
        mapping=[
            BatchMapItem(name="voltage_v", at=0,  type="uint16",  scale=0.1),
            BatchMapItem(name="current_a", at=1,  type="uint16",  scale=0.01),
            BatchMapItem(name="energy_kwh",at=2,  type="uint32",  endian="big", word_order="AB", scale=0.001),
            BatchMapItem(name="temp_c",    at=4,  type="float32", endian="big", word_order="BA"),
        ]
    )
    print(res.values)

    # Безопасная запись setpoint (float32, порядок слов BA)
    await client.write_typed(
        address=100,
        value=42.5,
        typ="float32",
        endian="big",
        word_order="BA",
        scale=1.0, offset=0.0,
        idempotency_key="op-123"
    )

    await client.close()

asyncio.run(main())
"""
