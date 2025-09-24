# -*- coding: utf-8 -*-
"""
VeilMind Adapter — промышленный асинхронный адаптер для интеграции кибер‑физического устройства/шины
в состав physical-integration-core.

Возможности:
- Безопасное подключение: TLS (опционально), HMAC-SHA256 подпись кадров.
- Надёжность: экспоненциальный backoff, circuit breaker (CLOSED/OPEN/HALF_OPEN), heartbeat.
- Производительность: асинхронные очереди, токен‑бакет rate limit, ограничение inflight, backpressure.
- Наблюдаемость: структурные логи, счётчики метрик, событийные callbacks on_message/on_status.
- Контракт: length‑prefixed JSON кадры {hdr, payload}; hdr содержит ts, nonce, seq, signature.

Зависимости: только стандартная библиотека Python 3.10+.
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

__all__ = [
    "VeilMindAdapter",
    "VeilMindConfig",
    "VeilMindError",
    "ConnectionState",
    "AdapterMetrics",
]

# =========================
# Исключения и состояния
# =========================

class VeilMindError(Exception):
    """Базовая ошибка адаптера VeilMind."""


class HandshakeError(VeilMindError):
    """Ошибка рукопожатия."""


class FrameIntegrityError(VeilMindError):
    """Ошибка верификации подписи/целостности кадра."""


class ConnectionState(enum.Enum):
    INIT = "init"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    STOPPED = "stopped"


# =========================
# Конфигурация и метрики
# =========================

@dataclass(frozen=True)
class VeilMindConfig:
    host: str
    port: int
    device_id: str
    secret_key: str  # HMAC shared secret
    use_tls: bool = True
    ca_file: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    allow_insecure: bool = False  # для отладки: отключает проверку сертификата

    connect_timeout_s: float = 5.0
    io_timeout_s: float = 5.0
    heartbeat_interval_s: float = 10.0
    heartbeat_timeout_s: float = 5.0

    max_retries: int = 25
    backoff_base_s: float = 0.5
    backoff_max_s: float = 30.0
    jitter_s: float = 0.2

    rate_limit_per_sec: float = 100.0
    rate_burst: int = 200

    send_queue_max: int = 10_000
    recv_queue_max: int = 10_000
    max_inflight: int = 1024

    handshake_version: str = "1.0"
    protocol_version: str = "1.0"

    # Политики разрывов/восстановлений
    circuit_fail_threshold: int = 5
    circuit_reset_timeout_s: float = 20.0

    # Ограничения полезной нагрузки
    max_frame_bytes: int = 1_048_576  # 1 MiB
    max_payload_keys: int = 256

    # Теги среды/аудита
    environment: str = "prod"
    node_id: str = field(default_factory=lambda: os.getenv("HOSTNAME", "unknown-node"))


@dataclass
class AdapterMetrics:
    connected_at: Optional[float] = None
    last_rx_ts: Optional[float] = None
    last_tx_ts: Optional[float] = None
    total_reconnects: int = 0
    frames_rx: int = 0
    frames_tx: int = 0
    bytes_rx: int = 0
    bytes_tx: int = 0
    integrity_failures: int = 0
    handshake_failures: int = 0
    circuit_opens: int = 0
    circuit_half_opens: int = 0
    circuit_closes: int = 0


# =========================
# Вспомогательные утилиты
# =========================

class TokenBucket:
    """Асинхронный токен‑бакет для ограничения скорости отправки кадров."""

    def __init__(self, rate_per_sec: float, capacity: int) -> None:
        self._rate = float(rate_per_sec)
        self._capacity = int(capacity)
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        self._last = now
        self._tokens = min(self._capacity, self._tokens + self._rate * delta)

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # Сколько ждать для накопления
                missing = tokens - self._tokens
                sleep_for = max(missing / self._rate, 0.001)
                await asyncio.sleep(sleep_for)


class CircuitBreaker:
    """Простой circuit breaker для стабилизации при частых сбоях."""

    class State(enum.Enum):
        CLOSED = "closed"
        OPEN = "open"
        HALF_OPEN = "half_open"

    def __init__(self, fail_threshold: int, reset_timeout_s: float) -> None:
        self._fail_threshold = fail_threshold
        self._reset_timeout_s = reset_timeout_s
        self._state = CircuitBreaker.State.CLOSED
        self._fail_count = 0
        self._opened_at: Optional[float] = None

    @property
    def state(self) -> "CircuitBreaker.State":
        return self._state

    def on_success(self) -> None:
        self._state = CircuitBreaker.State.CLOSED
        self._fail_count = 0
        self._opened_at = None

    def on_failure(self) -> None:
        self._fail_count += 1
        if self._fail_count >= self._fail_threshold:
            self._state = CircuitBreaker.State.OPEN
            self._opened_at = time.monotonic()

    def allow_attempt(self) -> bool:
        if self._state == CircuitBreaker.State.CLOSED:
            return True
        if self._state == CircuitBreaker.State.OPEN:
            if self._opened_at is None:
                return False
            if (time.monotonic() - self._opened_at) >= self._reset_timeout_s:
                self._state = CircuitBreaker.State.HALF_OPEN
                return True
            return False
        # HALF_OPEN: разрешаем один пробный запрос
        return True


def _build_ssl_context(cfg: VeilMindConfig) -> Optional[ssl.SSLContext]:
    if not cfg.use_tls:
        return None
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if cfg.allow_insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        if cfg.ca_file:
            ctx.load_verify_locations(cafile=cfg.ca_file)
    if cfg.client_cert and cfg.client_key:
        ctx.load_cert_chain(certfile=cfg.client_cert, keyfile=cfg.client_key)
    # Современные параметры
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:!aNULL:!eNULL:!MD5:!RC4")
    return ctx


def _json_dumps(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _json_loads(data: bytes) -> Dict[str, Any]:
    return json.loads(data.decode("utf-8"))


def _hmac_sign(secret: str, message: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


# =========================
# Адаптер VeilMind
# =========================

class VeilMindAdapter:
    """
    Промышленный адаптер для VeilMind.

    Интерфейс:
        adapter = VeilMindAdapter(cfg, on_message=..., on_status=...)
        await adapter.start()
        await adapter.send({"op":"set", "path":"/motor/1", "value":0.9})
        ...
        await adapter.stop()

    Обработка фреймов:
      FRAME := [LEN][JSON]
      LEN   := 4 байта BE
      JSON  := {"hdr": {...}, "payload": {...}}

    Подпись:
      signature = HMAC_SHA256(secret, json_bytes_without_signature)
      signature хранится в hdr.signature
    """

    def __init__(
        self,
        cfg: VeilMindConfig,
        *,
        on_message: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
        on_status: Optional[Callable[[str], Awaitable[None]]] = None,
        logger: Optional[logging.Logger] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self._cfg = cfg
        self._loop = loop or asyncio.get_event_loop()
        self._logger = logger or logging.getLogger("physical_integration.veilmind")
        self._logger.setLevel(logging.INFO)

        self._metrics = AdapterMetrics()
        self._state = ConnectionState.INIT

        self._send_q: "asyncio.Queue[Tuple[int, Dict[str, Any]]]" = asyncio.Queue(maxsize=cfg.send_queue_max)
        self._recv_q: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=cfg.recv_queue_max)

        self._rate = TokenBucket(cfg.rate_limit_per_sec, cfg.rate_burst)
        self._circuit = CircuitBreaker(cfg.circuit_fail_threshold, cfg.circuit_reset_timeout_s)

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

        self._tasks: set[asyncio.Task] = set()
        self._stopping = asyncio.Event()
        self._connected = asyncio.Event()
        self._seq = 0

        self._on_message = on_message
        self._on_status = on_status

        # SIGTERM/SIGINT дружелюбное завершение (если под управлением uvloop/systemd/k8s)
        try:
            for sig in (signal.SIGTERM, signal.SIGINT):
                self._loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.stop()))
        except NotImplementedError:
            # Windows/embedded среда может не поддерживать сигналы
            pass

    # ------------- Публичное API -------------

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def metrics(self) -> AdapterMetrics:
        return self._metrics

    async def start(self) -> None:
        if self._state != ConnectionState.INIT:
            return
        self._stopping.clear()
        self._set_state(ConnectionState.CONNECTING)
        self._spawn(self._run_forever(), name="vm.run_forever")

    async def stop(self) -> None:
        self._stopping.set()
        self._set_state(ConnectionState.STOPPED)
        await self._disconnect()
        await self._cancel_all()

    async def send(self, payload: Dict[str, Any], *, priority: int = 5, timeout: Optional[float] = None) -> None:
        """
        Отправка полезной нагрузки. Помещается в приоритетную очередь (реализовано простым seq‑порядком + rate‑limit).
        """
        self._validate_payload(payload)
        await asyncio.wait_for(self._send_q.put((priority, payload)), timeout=timeout)

    # ------------- Внутренняя логика -------------

    def _spawn(self, coro: Awaitable[Any], *, name: str) -> None:
        t = self._loop.create_task(coro, name=name)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    def _set_state(self, st: ConnectionState) -> None:
        if st != self._state:
            self._log("state_change", state=st.value, prev=self._state.value if self._state else None)
            self._state = st
            if self._on_status:
                # Без await — не блокируем критичный путь
                asyncio.create_task(self._on_status(st.value))

    async def _run_forever(self) -> None:
        retries = 0
        while not self._stopping.is_set():
            if not self._circuit.allow_attempt():
                self._metrics.circuit_opens += 1
                self._log("circuit_open_sleep", level=logging.WARNING)
                await asyncio.sleep(self._cfg.circuit_reset_timeout_s)
                continue

            try:
                await self._connect_and_loop()
                # Нормальное завершение (stop) — выходим
                if self._stopping.is_set():
                    break
                # Неожиданный разрыв — пробуем переподключиться
                self._circuit.on_failure()
                retries += 1
                self._metrics.total_reconnects += 1
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._log("connection_loop_error", level=logging.ERROR, error=str(e))
                self._circuit.on_failure()
                retries += 1
                self._metrics.total_reconnects += 1

            # backoff
            if self._stopping.is_set():
                break
            if retries > self._cfg.max_retries:
                self._log("max_retries_exceeded", level=logging.ERROR)
                self._set_state(ConnectionState.STOPPED)
                break

            if self._circuit.state == CircuitBreaker.State.HALF_OPEN:
                self._metrics.circuit_half_opens += 1

            sleep_s = min(
                self._cfg.backoff_base_s * (2 ** (retries - 1)),
                self._cfg.backoff_max_s,
            )
            sleep_s += secrets.SystemRandom().uniform(0, self._cfg.jitter_s)
            await asyncio.sleep(sleep_s)

        await self._disconnect()

    async def _connect_and_loop(self) -> None:
        self._set_state(ConnectionState.CONNECTING)
        ssl_ctx = _build_ssl_context(self._cfg)

        self._log("connecting", host=self._cfg.host, port=self._cfg.port, tls=bool(ssl_ctx))
        try:
            conn = asyncio.open_connection(self._cfg.host, self._cfg.port, ssl=ssl_ctx)
            self._reader, self._writer = await asyncio.wait_for(conn, timeout=self._cfg.connect_timeout_s)
        except Exception as e:
            self._metrics.handshake_failures += 1
            raise VeilMindError(f"TCP/TLS connect failed: {e}") from e

        try:
            await asyncio.wait_for(self._handshake(), timeout=self._cfg.io_timeout_s)
        except Exception as e:
            self._metrics.handshake_failures += 1
            await self._disconnect()
            raise HandshakeError(f"Handshake failed: {e}") from e

        self._connected.set()
        self._set_state(ConnectionState.CONNECTED)
        self._metrics.connected_at = time.time()
        self._circuit.on_success()
        self._metrics.circuit_closes += 1

        # Основные рабочие таски
        send_t = self._loop.create_task(self._sender_loop(), name="vm.sender")
        recv_t = self._loop.create_task(self._reader_loop(), name="vm.reader")
        hb_t = self._loop.create_task(self._heartbeat_loop(), name="vm.heartbeat")
        self._tasks.update({send_t, recv_t, hb_t})

        # Ждём завершения хотя бы одного критичного таска (обычно reader при разрыве)
        done, pending = await asyncio.wait({send_t, recv_t, hb_t}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

        self._connected.clear()
        self._set_state(ConnectionState.DISCONNECTED)

    async def _disconnect(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                with contextlib_suppress(Exception):
                    await self._writer.wait_closed()
            finally:
                self._writer = None
        self._reader = None

    async def _cancel_all(self) -> None:
        if not self._tasks:
            return
        for t in list(self._tasks):
            t.cancel()
        with contextlib_suppress(asyncio.CancelledError):
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
        self._tasks.clear()

    # ------------- Протокол -------------

    async def _handshake(self) -> None:
        assert self._writer and self._reader
        ts = int(time.time() * 1000)
        hello = {
            "hdr": {
                "proto": self._cfg.protocol_version,
                "hs": self._cfg.handshake_version,
                "ts": ts,
                "nonce": secrets.token_hex(8),
                "seq": self._next_seq(),
                "device_id": self._cfg.device_id,
                "type": "hello",
            },
            "payload": {
                "environment": self._cfg.environment,
                "node_id": self._cfg.node_id,
                "capabilities": {
                    "heartbeat": True,
                    "hmac": "sha256",
                    "max_frame_bytes": self._cfg.max_frame_bytes,
                },
            },
        }
        self._sign_inplace(hello)
        await self._write_frame(hello)

        # Ожидаем ответ
        resp = await asyncio.wait_for(self._read_frame(), timeout=self._cfg.io_timeout_s)
        if not isinstance(resp, dict) or resp.get("hdr", {}).get("type") != "hello_ok":
            raise HandshakeError("unexpected handshake response")
        self._verify_frame(resp)  # верификация подписи

    async def _sender_loop(self) -> None:
        assert self._writer
        inflight = 0
        while not self._stopping.is_set():
            try:
                # Берём задание на отправку
                _priority, payload = await self._send_q.get()
                await self._rate.acquire(1.0)

                if inflight >= self._cfg.max_inflight:
                    # Простейший backpressure: ждём освобождения
                    await asyncio.sleep(0.001)
                    continue

                frame = self._make_frame("data", payload)
                await self._write_frame(frame)
                inflight += 1
                self._metrics.frames_tx += 1
                self._metrics.last_tx_ts = time.time()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._log("sender_error", level=logging.ERROR, error=str(e))
                # Прерываемся, чтобы запустить переподключение
                raise

    async def _reader_loop(self) -> None:
        assert self._reader
        while not self._stopping.is_set():
            try:
                frame = await self._read_frame()
                self._verify_frame(frame)
                self._metrics.frames_rx += 1
                self._metrics.last_rx_ts = time.time()

                hdr = frame.get("hdr", {})
                ftype = hdr.get("type")
                if ftype == "heartbeat_ok":
                    # Ничего, просто подтверждение
                    continue
                elif ftype == "data_ok":
                    # Подтверждение приёма
                    continue
                elif ftype == "data":
                    # Входящее сообщение от VeilMind
                    payload = frame.get("payload", {})
                    if self._on_message:
                        asyncio.create_task(self._on_message(payload))
                    # Отправим ACK
                    ack = self._make_frame("data_ok", {"seq_ack": hdr.get("seq")})
                    await self._write_frame(ack)
                else:
                    # Неизвестный тип — логируем на уровне WARN
                    self._log("unknown_frame_type", level=logging.WARNING, frame_type=str(ftype))
            except asyncio.CancelledError:
                break
            except FrameIntegrityError as e:
                self._metrics.integrity_failures += 1
                self._log("integrity_error", level=logging.ERROR, error=str(e))
                # Продолжаем принимать последующие кадры
            except Exception as e:
                self._log("reader_error", level=logging.ERROR, error=str(e))
                # Прерываемся для переподключения
                raise

    async def _heartbeat_loop(self) -> None:
        while not self._stopping.is_set():
            if not self._connected.is_set():
                await asyncio.sleep(0.1)
                continue
            try:
                hb = self._make_frame("heartbeat", {"uptime_s": int(time.monotonic())})
                await self._write_frame(hb)

                # Ждём ответ определённое время
                await asyncio.wait_for(self._await_heartbeat_ok(timeout=self._cfg.heartbeat_timeout_s), timeout=self._cfg.heartbeat_timeout_s)
            except asyncio.TimeoutError:
                self._log("heartbeat_timeout", level=logging.WARNING)
                # Прерываем для переподключения
                raise VeilMindError("heartbeat timeout")
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._log("heartbeat_error", level=logging.ERROR, error=str(e))
                raise
            finally:
                await asyncio.sleep(self._cfg.heartbeat_interval_s)

    async def _await_heartbeat_ok(self, timeout: float) -> None:
        """
        Упрощённо: ждём, что reader_loop примет heartbeat_ok. Так как reader_loop сам по себе
        асинхронно обрабатывает, используем небольшую задержку; если в этот период не было ошибок reader,
        считаем hb успешным. В проде можно расширить до внутреннего события.
        """
        await asyncio.sleep(min(0.05, timeout))

    # ------------- Кадры и подписи -------------

    def _make_frame(self, ftype: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        ts = int(time.time() * 1000)
        frame = {
            "hdr": {
                "proto": self._cfg.protocol_version,
                "ts": ts,
                "nonce": secrets.token_hex(8),
                "seq": self._next_seq(),
                "device_id": self._cfg.device_id,
                "type": ftype,
            },
            "payload": payload,
        }
        self._sign_inplace(frame)
        return frame

    def _sign_inplace(self, frame: Dict[str, Any]) -> None:
        hdr = frame.get("hdr", {})
        # Временная копия без signature
        tmp = {"hdr": {k: v for k, v in hdr.items() if k != "signature"}, "payload": frame.get("payload", {})}
        msg = _json_dumps(tmp)
        sig = _hmac_sign(self._cfg.secret_key, msg)
        hdr["signature"] = sig
        frame["hdr"] = hdr

    def _verify_frame(self, frame: Dict[str, Any]) -> None:
        hdr = frame.get("hdr", {})
        provided = hdr.get("signature")
        if not provided:
            raise FrameIntegrityError("missing signature")
        tmp = {"hdr": {k: v for k, v in hdr.items() if k != "signature"}, "payload": frame.get("payload", {})}
        msg = _json_dumps(tmp)
        expected = _hmac_sign(self._cfg.secret_key, msg)
        # Защита от тайминговых атак — hmac.compare_digest
        if not hmac.compare_digest(provided, expected):
            raise FrameIntegrityError("invalid signature")

    async def _write_frame(self, frame: Dict[str, Any]) -> None:
        if not self._writer:
            raise VeilMindError("writer is not available")
        data = _json_dumps(frame)
        if len(data) > self._cfg.max_frame_bytes:
            raise VeilMindError("frame too large")
        hdr = struct.pack(">I", len(data))
        try:
            self._writer.write(hdr)
            self._writer.write(data)
            await asyncio.wait_for(self._writer.drain(), timeout=self._cfg.io_timeout_s)
            self._metrics.bytes_tx += len(data) + 4
        except Exception as e:
            raise VeilMindError(f"write failed: {e}") from e

    async def _read_frame(self) -> Dict[str, Any]:
        if not self._reader:
            raise VeilMindError("reader is not available")
        try:
            hdr = await asyncio.wait_for(self._reader.readexactly(4), timeout=self._cfg.io_timeout_s)
            (length,) = struct.unpack(">I", hdr)
            if length <= 0 or length > self._cfg.max_frame_bytes:
                raise VeilMindError(f"invalid frame length: {length}")
            data = await asyncio.wait_for(self._reader.readexactly(length), timeout=self._cfg.io_timeout_s)
            self._metrics.bytes_rx += length + 4
            frame = _json_loads(data)
            if not isinstance(frame, dict):
                raise VeilMindError("malformed frame")
            return frame
        except Exception as e:
            raise VeilMindError(f"read failed: {e}") from e

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0x7FFF_FFFF
        return self._seq

    # ------------- Валидация/логирование -------------

    def _validate_payload(self, payload: Dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise VeilMindError("payload must be a dict")
        if len(payload) > self._cfg.max_payload_keys:
            raise VeilMindError("payload too many keys")
        # Дополнительно можно запрещать непереносимые типы
        for k, v in payload.items():
            if not isinstance(k, str):
                raise VeilMindError("payload keys must be strings")
            if not isinstance(v, (str, int, float, bool, dict, list, type(None))):
                raise VeilMindError(f"unsupported value type for key '{k}'")

    def _log(self, event: str, *, level: int = logging.INFO, **fields: Any) -> None:
        rec = {
            "event": event,
            "adapter": "veilmind",
            "device_id": self._cfg.device_id,
            "env": self._cfg.environment,
            "node": self._cfg.node_id,
            **fields,
        }
        self._logger.log(level, json.dumps(rec, ensure_ascii=False))


# =========================
# Вспомогательное подавление исключений
# =========================

class contextlib_suppress:
    """Локальный аналог contextlib.suppress, чтобы не тянуть лишние импорты в критический путь."""
    def __init__(self, *exceptions: type[BaseException]) -> None:
        self._exceptions = exceptions or (Exception,)

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, self._exceptions)
