# -*- coding: utf-8 -*-
"""
Aethernova / NeuroCity
core-systems/avm_core/phantommesh/mesh_client.py

PhantomMeshClient — промышленный асинхронный клиент оверлей-сети c:
- Zero Trust фреймингом: подпись каждого кадра HMAC‑SHA256 с ротацией ключей (Keyring)
- Heartbeat/PING‑PONG, контроль таймаутов, backpressure, max frame size
- Экспоненциальный бэкофф + jitter, Circuit Breaker
- Поддержка прямого TLS (с верификацией/пиннингом) и проксирования через SOCKS5 (Tor)
- Лимитирование скорости (token bucket), метрики и наблюдаемость через hooks
- Без внешних зависимостей (только стандартная библиотека)

Примечание по криптографии:
Шифрование канала обеспечивается TLS (для прямого подключения).
Для режима через SOCKS5 (Tor) применяется целостность/аутентичность сообщений на уровне приложения
через HMAC‑SHA256 (PSK keyring). При необходимости end‑to‑end шифрования добавьте поверх
дополнительный слой (например, NaCl), интегрировав его в FrameCodec.

Автор: PhantomMesh Team (Aethernova / NeuroCity)
Лицензия: Apache-2.0
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import enum
import functools
import hmac
import ipaddress
import json
import logging
import os
import random
import secrets
import signal
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

# ------------------------------------------------------------
# Логирование (структурное)
# ------------------------------------------------------------

def _build_logger(name: str = "phantommesh") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


log = _build_logger()


# ------------------------------------------------------------
# Константы и протокол
# ------------------------------------------------------------

FRAME_VERSION = 1

class FrameType(enum.IntEnum):
    AUTH = 1
    AUTH_OK = 2
    PING = 3
    PONG = 4
    DATA = 5
    ERROR = 6
    CLOSE = 7
    PRESENCE = 8

# Заголовок: | ver:1 | type:1 | flags:1 | key_id:4 | seq:4 | len:4 | hmac:32 |
_HEADER_STRUCT = struct.Struct("!BBB I I I 32s")
_HEADER_SIZE = _HEADER_STRUCT.size  # 1+1+1+4+4+4+32 = 47 байт
MAX_FRAME_BYTES_DEFAULT = 1_048_576  # 1 MiB

# Флаги
FLAG_COMPRESS = 0x01  # зарезервировано на будущее
FLAG_RESERVED = 0x80


# ------------------------------------------------------------
# Ключевое хранилище (PSK) для HMAC
# ------------------------------------------------------------

@dataclass
class Keyring:
    """
    Простое keyring‑хранилище для HMAC‑подписей кадров.
    key_id -> key_bytes
    """
    keys: Dict[int, bytes] = field(default_factory=dict)
    current_key_id: int = 1

    def add_key(self, key_id: int, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise ValueError("key must be bytes with length >= 16")
        self.keys[int(key_id)] = bytes(key)

    def get(self, key_id: int) -> bytes:
        key = self.keys.get(int(key_id))
        if not key:
            raise KeyError(f"key id {key_id} not found in keyring")
        return key

    def active(self) -> Tuple[int, bytes]:
        return self.current_key_id, self.get(self.current_key_id)

    def rotate(self, new_key_id: int, new_key: bytes) -> None:
        self.add_key(new_key_id, new_key)
        self.current_key_id = new_key_id


# ------------------------------------------------------------
# Транспортные уровни
# ------------------------------------------------------------

class AbstractTransport:
    async def connect(self) -> None: ...
    async def read_exactly(self, n: int) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    async def drain(self) -> None: ...
    async def close(self) -> None: ...
    @property
    def connected(self) -> bool: ...


@dataclass
class TLSSettings:
    verify: bool = True
    sni: Optional[str] = None
    ca_file: Optional[str] = None
    ca_path: Optional[str] = None
    cert_fingerprint_sha256: Optional[str] = None  # HEX без двоеточий


def _fingerprint_sha256(cert_der: bytes) -> str:
    return sha256(cert_der).hexdigest()


class TLSTransport(AbstractTransport):
    def __init__(self, host: str, port: int, timeout: float, tls: TLSSettings):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.tls = tls
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    async def connect(self) -> None:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if self.tls.ca_file or self.tls.ca_path:
            ctx.load_verify_locations(cafile=self.tls.ca_file, capath=self.tls.ca_path)
        ctx.check_hostname = self.tls.verify
        ctx.verify_mode = ssl.CERT_REQUIRED if self.tls.verify else ssl.CERT_NONE
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ctx, server_hostname=self.tls.sni or self.host),
                timeout=self.timeout,
            )
        except Exception as e:
            raise ConnectionError(f"TLS connect failed: {e}") from e

        if self.tls.cert_fingerprint_sha256:
            # Проверка пиннинга
            sslobj: ssl.SSLObject = self._writer.get_extra_info("ssl_object")  # type: ignore
            if not sslobj:
                await self.close()
                raise ConnectionError("No SSL object for fingerprint check")
            cert = sslobj.getpeercert(binary_form=True)
            fp = _fingerprint_sha256(cert)
            if fp.lower() != self.tls.cert_fingerprint_sha256.lower():
                await self.close()
                raise ConnectionError("Certificate fingerprint mismatch")

    async def read_exactly(self, n: int) -> bytes:
        assert self._reader
        return await self._reader.readexactly(n)

    def write(self, data: bytes) -> None:
        assert self._writer
        self._writer.write(data)

    async def drain(self) -> None:
        assert self._writer
        await self._writer.drain()

    async def close(self) -> None:
        if self._writer:
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
        self._reader = None
        self._writer = None

    @property
    def connected(self) -> bool:
        return self._writer is not None and not self._writer.is_closing()


@dataclass
class SOCKS5Proxy:
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None


class SOCKS5Transport(AbstractTransport):
    """
    Минимальный SOCKS5 клиент (CONNECT), без TLS поверх (для использования через Tor).
    Для end‑to‑end целостности/аутентичности используется кадровый HMAC.
    """

    def __init__(self, proxy: SOCKS5Proxy, dest_host: str, dest_port: int, timeout: float):
        self.proxy = proxy
        self.dest_host = dest_host
        self.dest_port = int(dest_port)
        self.timeout = float(timeout)
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    async def connect(self) -> None:
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.proxy.host, self.proxy.port),
                timeout=self.timeout,
            )
        except Exception as e:
            raise ConnectionError(f"SOCKS5 connect to proxy failed: {e}") from e

        # Greeting
        methods = [0x00]  # no auth
        if self.proxy.username and self.proxy.password:
            methods = [0x02]
        self.write(bytes([0x05, len(methods), *methods]))
        await self.drain()
        resp = await self.read_exactly(2)
        if resp[0] != 0x05:
            raise ConnectionError("Invalid SOCKS5 version in response")
        if resp[1] == 0xFF:
            raise ConnectionError("SOCKS5: no acceptable auth methods")
        if resp[1] == 0x02:
            # Username/Password auth (RFC 1929)
            u = self.proxy.username or ""
            p = self.proxy.password or ""
            if len(u) > 255 or len(p) > 255:
                raise ValueError("SOCKS5 credentials too long")
            auth_req = bytes([0x01, len(u)]) + u.encode("utf-8") + bytes([len(p)]) + p.encode("utf-8")
            self.write(auth_req)
            await self.drain()
            auth_resp = await self.read_exactly(2)
            if auth_resp != b"\x01\x00":
                raise ConnectionError("SOCKS5 auth failed")

        # CONNECT
        dst = self.dest_host
        atype = 0x03
        addr_bytes: bytes
        try:
            ip_obj = ipaddress.ip_address(dst)
            if ip_obj.version == 4:
                atype = 0x01
                addr_bytes = ip_obj.packed
            else:
                atype = 0x04
                addr_bytes = ip_obj.packed
        except ValueError:
            d = dst.encode("idna")
            if len(d) > 255:
                raise ValueError("SOCKS5 domain too long")
            addr_bytes = bytes([len(d)]) + d

        port_bytes = struct.pack("!H", self.dest_port)
        req = bytes([0x05, 0x01, 0x00, atype]) + addr_bytes + port_bytes
        self.write(req)
        await self.drain()
        # Response: VER REP RSV ATYP BND.ADDR BND.PORT
        head = await self.read_exactly(4)
        if head[0] != 0x05 or head[1] != 0x00:
            raise ConnectionError(f"SOCKS5 connect failed, REP={head[1]}")
        atyp = head[3]
        if atyp == 0x01:
            await self.read_exactly(4 + 2)
        elif atyp == 0x03:
            ln = (await self.read_exactly(1))[0]
            await self.read_exactly(ln + 2)
        elif atyp == 0x04:
            await self.read_exactly(16 + 2)
        else:
            raise ConnectionError("SOCKS5 invalid ATYP")

    async def read_exactly(self, n: int) -> bytes:
        assert self._reader
        return await self._reader.readexactly(n)

    def write(self, data: bytes) -> None:
        assert self._writer
        self._writer.write(data)

    async def drain(self) -> None:
        assert self._writer
        await self._writer.drain()

    async def close(self) -> None:
        if self._writer:
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
        self._reader = None
        self._writer = None

    @property
    def connected(self) -> bool:
        return self._writer is not None and not self._writer.is_closing()


# ------------------------------------------------------------
# Фреймер, подпись, кодек
# ------------------------------------------------------------

class FrameCodec:
    def __init__(self, keyring: Keyring, app_id: str, max_frame_bytes: int = MAX_FRAME_BYTES_DEFAULT):
        self.keyring = keyring
        self.app_id = app_id.encode("utf-8")
        self.max_frame = int(max_frame_bytes)
        self._seq = 0

    def _sign(self, key_id: int, ftype: int, flags: int, seq: int, payload: bytes) -> bytes:
        key = self.keyring.get(key_id)
        # Контекст включаем в подпись (app_id)
        hm = hmac.new(key, digestmod=sha256)
        hm.update(bytes([FRAME_VERSION, ftype, flags]))
        hm.update(struct.pack("!I", key_id))
        hm.update(struct.pack("!I", seq))
        hm.update(struct.pack("!I", len(payload)))
        hm.update(self.app_id)
        hm.update(payload)
        return hm.digest()

    def encode(self, ftype: FrameType, payload: Union[bytes, Dict[str, Any]], flags: int = 0, key_id: Optional[int] = None) -> bytes:
        if isinstance(payload, dict):
            payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        else:
            payload_bytes = payload
        if len(payload_bytes) > self.max_frame:
            raise ValueError("payload too large")
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        seq = self._seq
        kid = key_id if key_id is not None else self.keyring.current_key_id
        mac = self._sign(kid, int(ftype), flags, seq, payload_bytes)
        header = _HEADER_STRUCT.pack(FRAME_VERSION, int(ftype), flags, kid, seq, len(payload_bytes), mac)
        return header + payload_bytes

    def decode(self, frame: bytes) -> Tuple[FrameType, int, int, int, bytes]:
        if len(frame) < _HEADER_SIZE:
            raise ValueError("frame too short")
        ver, ftype, flags, kid, seq, plen, mac = _HEADER_STRUCT.unpack(frame[:_HEADER_SIZE])
        if ver != FRAME_VERSION:
            raise ValueError("invalid frame version")
        if plen > self.max_frame:
            raise ValueError("declared payload too large")
        payload = frame[_HEADER_SIZE:]
        if len(payload) != plen:
            raise ValueError("invalid frame length")
        # Проверяем подпись
        expected = self._sign(kid, ftype, flags, seq, payload)
        if not hmac.compare_digest(expected, mac):
            raise ValueError("invalid HMAC")
        return FrameType(ftype), flags, kid, seq, payload


# ------------------------------------------------------------
# Конфигурация клиента, лимитер, бэкофф
# ------------------------------------------------------------

@dataclass
class MeshEndpoint:
    host: str
    port: int
    use_tls: bool = True
    tls: TLSSettings = field(default_factory=TLSSettings)
    proxy: Optional[SOCKS5Proxy] = None


@dataclass
class MeshClientConfig:
    app_id: str
    client_id: str
    keyring: Keyring
    bootstrap: List[MeshEndpoint]
    connect_timeout: float = 7.5
    read_timeout: float = 30.0
    write_timeout: float = 10.0
    heartbeat_interval: float = 20.0
    max_frame_bytes: int = MAX_FRAME_BYTES_DEFAULT
    max_retry_backoff: float = 60.0
    initial_backoff: float = 0.5
    backoff_factor: float = 2.0
    jitter: float = 0.25  # добавочный процент
    bucket_rate_per_sec: int = 2048 * 10  # байт/с
    bucket_capacity: int = 2048 * 100     # максимум всплеска


class TokenBucket:
    def __init__(self, rate: int, capacity: int):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self._tokens = float(capacity)
        self._last = time.monotonic()

    def consume(self, amount: int) -> float:
        """
        Пытается списать amount токенов.
        Возвращает 0 если удалось сразу, иначе секунды ожидания до доступности.
        """
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        if self._tokens >= amount:
            self._tokens -= amount
            return 0.0
        deficit = amount - self._tokens
        return deficit / self.rate


# ------------------------------------------------------------
# Наблюдаемость и события
# ------------------------------------------------------------

class Events(enum.Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    AUTH_OK = "auth_ok"
    RX = "rx"
    TX = "tx"
    ERROR = "error"
    PING = "ping"
    PONG = "pong"
    PRESENCE = "presence"


ObserverHook = Callable[[Events, Dict[str, Any]], None]


# ------------------------------------------------------------
# Основной клиент
# ------------------------------------------------------------

class PhantomMeshClient:
    def __init__(self, cfg: MeshClientConfig, observer: Optional[ObserverHook] = None):
        self.cfg = cfg
        self.codec = FrameCodec(cfg.keyring, cfg.app_id, cfg.max_frame_bytes)
        self._transport: Optional[AbstractTransport] = None
        self._stop = asyncio.Event()
        self._rx_task: Optional[asyncio.Task] = None
        self._hb_task: Optional[asyncio.Task] = None
        self._bucket = TokenBucket(cfg.bucket_rate_per_sec, cfg.bucket_capacity)
        self._observer = observer
        self._circuit_open_until = 0.0
        self._on_message: Optional[Callable[[bytes, Dict[str, Any]], Awaitable[None]]] = None

    # ---------------------------
    # Hooks
    # ---------------------------

    def _emit(self, event: Events, **kwargs: Any) -> None:
        if self._observer:
            try:
                self._observer(event, kwargs)
            except Exception as e:
                log.debug("observer hook error: %s", e)

    def on_message(self, handler: Callable[[bytes, Dict[str, Any]], Awaitable[None]]) -> None:
        self._on_message = handler

    # ---------------------------
    # Подключение/цикл
    # ---------------------------

    async def start(self) -> None:
        self._stop.clear()
        self._rx_task = asyncio.create_task(self._run())
        self._hb_task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._hb_task:
            self._hb_task.cancel()
            with contextlib.suppress(Exception):
                await self._hb_task
        if self._rx_task:
            self._rx_task.cancel()
            with contextlib.suppress(Exception):
                await self._rx_task
        await self._close_transport()

    async def _run(self) -> None:
        backoff = self.cfg.initial_backoff
        while not self._stop.is_set():
            now = time.time()
            if now < self._circuit_open_until:
                await asyncio.sleep(min(self._circuit_open_until - now, 1.0))
                continue
            try:
                await self._connect_any()
                await self._auth()
                self._emit(Events.CONNECTED, endpoint=self._current_ep_meta())
                backoff = self.cfg.initial_backoff  # reset on success
                await self._recv_loop()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning("connection error: %s", e)
                self._emit(Events.ERROR, error=str(e))
                await self._close_transport()
                # Circuit breaker (простое открытие на max_retry_backoff при множественных сбоях)
                backoff = min(backoff * self.cfg.backoff_factor, self.cfg.max_retry_backoff)
                jitter = 1.0 + (random.random() - 0.5) * 2.0 * self.cfg.jitter
                delay = backoff * jitter
                self._circuit_open_until = time.time() + delay
                self._emit(Events.DISCONNECTED, retry_in=round(delay, 2))
            await asyncio.sleep(0.1)

    async def _connect_any(self) -> None:
        last_err: Optional[Exception] = None
        for ep in self.cfg.bootstrap:
            try:
                self._transport = await self._connect_endpoint(ep)
                return
            except Exception as e:
                last_err = e
                log.info("endpoint %s:%s failed: %s", ep.host, ep.port, e)
        if last_err:
            raise last_err
        raise ConnectionError("no endpoints configured")

    async def _connect_endpoint(self, ep: MeshEndpoint) -> AbstractTransport:
        t: AbstractTransport
        if ep.proxy:
            t = SOCKS5Transport(ep.proxy, ep.host, ep.port, timeout=self.cfg.connect_timeout)
        else:
            if not ep.use_tls:
                raise ValueError("direct non-TLS is not permitted; use TLS or SOCKS5 proxy")
            t = TLSTransport(ep.host, ep.port, timeout=self.cfg.connect_timeout, tls=ep.tls)
        await t.connect()
        return t

    def _current_ep_meta(self) -> Dict[str, Any]:
        if not self._transport:
            return {}
        # Не раскрываем детали транспорта наружу, только тип
        return {"transport": self._transport.__class__.__name__}

    async def _auth(self) -> None:
        assert self._transport
        nonce = secrets.token_bytes(16)
        ts = int(time.time())
        kid, _ = self.cfg.keyring.active()
        auth_payload = {
            "client_id": self.cfg.client_id,
            "ts": ts,
            "nonce": nonce.hex(),
            "cap": {"ver": 1, "hb": self.cfg.heartbeat_interval, "max": self.cfg.max_frame_bytes},
        }
        frame = self.codec.encode(FrameType.AUTH, auth_payload, flags=0, key_id=kid)
        self._transport.write(frame)
        await self._transport.drain()

        # Ждём AUTH_OK
        hdr = await asyncio.wait_for(self._transport.read_exactly(_HEADER_SIZE), timeout=self.cfg.read_timeout)
        # прочитаем payload длину из заголовка, затем проверим подпись декодером
        ver, ftype, flags, kid2, seq, plen, mac = _HEADER_STRUCT.unpack(hdr)
        payload = await asyncio.wait_for(self._transport.read_exactly(plen), timeout=self.cfg.read_timeout)
        ftype_e, _, _, _, body = self.codec.decode(hdr + payload)
        if ftype_e != FrameType.AUTH_OK:
            raise ConnectionError("auth failed: no AUTH_OK")
        data = json.loads(body.decode("utf-8"))
        if "ok" not in data or not data["ok"]:
            raise ConnectionError("auth failed: server did not accept")
        self._emit(Events.AUTH_OK, server=data.get("server", "unknown"))

    async def _recv_loop(self) -> None:
        assert self._transport
        while not self._stop.is_set() and self._transport.connected:
            try:
                hdr = await asyncio.wait_for(self._transport.read_exactly(_HEADER_SIZE), timeout=self.cfg.read_timeout)
                ver, ftype, flags, kid, seq, plen, mac = _HEADER_STRUCT.unpack(hdr)
                if plen > self.cfg.max_frame_bytes:
                    raise ValueError("incoming frame too large")
                payload = await asyncio.wait_for(self._transport.read_exactly(plen), timeout=self.cfg.read_timeout)
                ftype_e, flags_e, kid_e, seq_e, body = self.codec.decode(hdr + payload)
                await self._handle_frame(ftype_e, flags_e, kid_e, seq_e, body)
            except asyncio.TimeoutError:
                # Таймаут чтения — пингуем
                await self._send_ping()
            except asyncio.IncompleteReadError:
                raise ConnectionError("connection closed by peer")
            except Exception as e:
                raise

    # ---------------------------
    # Обработка кадров
    # ---------------------------

    async def _handle_frame(self, ftype: FrameType, flags: int, kid: int, seq: int, body: bytes) -> None:
        if ftype == FrameType.PING:
            await self._send_pong()
            self._emit(Events.PING, seq=seq)
            return
        if ftype == FrameType.PONG:
            self._emit(Events.PONG, seq=seq)
            return
        if ftype == FrameType.PRESENCE:
            try:
                meta = json.loads(body.decode("utf-8"))
            except Exception:
                meta = {}
            self._emit(Events.PRESENCE, **meta)
            return
        if ftype == FrameType.DATA:
            meta = {"seq": seq, "flags": flags, "kid": kid}
            self._emit(Events.RX, size=len(body), **meta)
            if self._on_message:
                await self._on_message(body, meta)
            return
        if ftype == FrameType.ERROR:
            try:
                err = json.loads(body.decode("utf-8"))
            except Exception:
                err = {"error": body[:200].decode("utf-8", "ignore")}
            self._emit(Events.ERROR, **err)
            return
        if ftype == FrameType.CLOSE:
            raise ConnectionError("peer requested close")

    # ---------------------------
    # Публичные операции
    # ---------------------------

    async def publish_presence(self, tags: Dict[str, Any]) -> None:
        await self._send_control(FrameType.PRESENCE, tags)

    async def send_data(self, payload: Union[bytes, Dict[str, Any]], flags: int = 0) -> None:
        data = payload if isinstance(payload, (bytes, bytearray)) else json.dumps(payload).encode("utf-8")
        await self._send_frame(FrameType.DATA, data, flags=flags)

    async def _send_control(self, ftype: FrameType, payload: Dict[str, Any]) -> None:
        await self._send_frame(ftype, json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

    async def _send_frame(self, ftype: FrameType, payload: bytes, flags: int = 0) -> None:
        if not self._transport or not self._transport.connected:
            raise ConnectionError("transport not connected")
        to_wait = self._bucket.consume(len(payload) + _HEADER_SIZE)
        if to_wait > 0:
            await asyncio.sleep(to_wait)
        frame = self.codec.encode(ftype, payload, flags=flags)
        self._transport.write(frame)
        await asyncio.wait_for(self._transport.drain(), timeout=self.cfg.write_timeout)
        self._emit(Events.TX, type=int(ftype), size=len(payload))

    async def _send_ping(self) -> None:
        if not self._transport or not self._transport.connected:
            return
        try:
            frame = self.codec.encode(FrameType.PING, b"")
            self._transport.write(frame)
            await asyncio.wait_for(self._transport.drain(), timeout=self.cfg.write_timeout)
            self._emit(Events.PING, seq="out")
        except Exception as e:
            raise ConnectionError(f"ping failed: {e}")

    async def _send_pong(self) -> None:
        if not self._transport or not self._transport.connected:
            return
        frame = self.codec.encode(FrameType.PONG, b"")
        self._transport.write(frame)
        await asyncio.wait_for(self._transport.drain(), timeout=self.cfg.write_timeout)

    async def _heartbeat_loop(self) -> None:
        try:
            while not self._stop.is_set():
                await asyncio.sleep(self.cfg.heartbeat_interval)
                with contextlib.suppress(Exception):
                    await self._send_ping()
        except asyncio.CancelledError:
            return

    async def _close_transport(self) -> None:
        if self._transport:
            await self._transport.close()
            self._transport = None

    # ---------------------------
    # Health snapshot
    # ---------------------------

    def get_health_snapshot(self) -> Dict[str, Any]:
        return {
            "connected": bool(self._transport and self._transport.connected),
            "transport": self._transport.__class__.__name__ if self._transport else None,
            "bucket_tokens": round(self._bucket._tokens, 2),
            "circuit_open_until": max(0.0, self._circuit_open_until - time.time()),
        }


# ------------------------------------------------------------
# Утилита: создание клиента из примитивных параметров
# ------------------------------------------------------------

def make_client(
    app_id: str,
    client_id: str,
    psk: bytes,
    endpoints: List[Tuple[str, int]],
    tls_verify: bool = True,
    tls_fingerprint: Optional[str] = None,
    via_socks5: Optional[Tuple[str, int, Optional[str], Optional[str]]] = None,
) -> PhantomMeshClient:
    """
    Упрощенный конструктор клиента.
    """
    kr = Keyring({1: psk}, current_key_id=1)
    eps: List<MeshEndpoint] = []
    proxy = None
    if via_socks5:
        proxy = SOCKS5Proxy(via_socks5[0], via_socks5[1], via_socks5[2], via_socks5[3])
    for host, port in endpoints:
        eps.append(
            MeshEndpoint(
                host=host,
                port=port,
                use_tls=(proxy is None),
                tls=TLSSettings(verify=tls_verify, sni=host, cert_fingerprint_sha256=tls_fingerprint),
                proxy=proxy,
            )
        )
    cfg = MeshClientConfig(app_id=app_id, client_id=client_id, keyring=kr, bootstrap=eps)
    return PhantomMeshClient(cfg)


# ------------------------------------------------------------
# Пример локального запуска (можно удалить в проде)
# ------------------------------------------------------------

async def _example() -> None:
    """
    Пример использования:
    - Для прямого TLS соединения укажите endpoints и psk (pre-shared key для HMAC).
    - Для Tor используйте via_socks5=("127.0.0.1", 9050, None, None) и включите endpoint на .onion.

    Внимание: это демо. В продакшн-коде управление конфигами делайте извне.
    """
    psk = sha256(b"change-me-strong-psk").digest()
    client = make_client(
        app_id="phantommesh.avm",
        client_id="node-12345",
        psk=psk,
        endpoints=[("example.org", 443)],
        tls_verify=True,
        tls_fingerprint=None,
        via_socks5=None,
    )

    async def on_msg(data: bytes, meta: Dict[str, Any]) -> None:
        log.info("RX message len=%s meta=%s", len(data), meta)

    client.on_message(on_msg)
    await client.start()
    await asyncio.sleep(1.0)
    await client.publish_presence({"tags": ["edge", "v1"], "time": int(time.time())})
    await client.send_data({"hello": "world"})
    await asyncio.sleep(5.0)
    snap = client.get_health_snapshot()
    log.info("health: %s", snap)
    await client.stop()


if __name__ == "__main__":
    # Грациозное завершение по Ctrl+C
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stop_event = asyncio.Event()

    def _handle_sig():
        if not stop_event.is_set():
            stop_event.set()

    for s in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(Exception):
            loop.add_signal_handler(s, _handle_sig)

    async def _main():
        # Для демонстрации: отменяем пример при сигнале
        task = asyncio.create_task(_example())
        await stop_event.wait()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    try:
        loop.run_until_complete(_main())
    finally:
        loop.stop()
        loop.close()
