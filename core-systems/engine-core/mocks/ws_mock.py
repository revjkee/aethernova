# engine/mocks/ws_mock.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import random
import time
from asyncio import Queue, QueueFull, TimeoutError
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple, Union

LOG = logging.getLogger(__name__)
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(_h)
    LOG.setLevel(logging.INFO)

# Опциональная интеграция с телеметрией
with contextlib.suppress(Exception):
    from engine.telemetry.profiling import profile_block  # type: ignore
    _HAS_PROF = True
if not locals().get("_HAS_PROF"):
    def profile_block(name: Optional[str] = None, config: Optional[Any] = None):
        @contextlib.contextmanager
        def _noop():
            yield
        return _noop()

# Опциональная валидация (Pydantic v1/v2)
try:
    from pydantic import BaseModel as _PModel, ValidationError as _PValErr  # type: ignore
    _HAS_PYD = True
except Exception:
    _HAS_PYD = False
    class _PModel: ...      # type: ignore
    class _PValErr(Exception): ...  # type: ignore


# =========================
# Конфигурации и типы
# =========================

@dataclass(frozen=True)
class NetworkProfile:
    base_latency_ms: int = 2
    jitter_ms: int = 2
    loss_prob: float = 0.0
    bandwidth_bytes_per_sec: Optional[int] = None  # лимит скорости (tx), None — без лимита
    max_queue: int = 1000  # глубина буфера на соединение

@dataclass(frozen=True)
class AuthConfig:
    required: bool = False
    token_header: str = "Authorization"
    valid_tokens: Tuple[str, ...] = tuple()

@dataclass(frozen=True)
class ServerConfig:
    name: str = "ws-mock"
    network: NetworkProfile = field(default_factory=NetworkProfile)
    auth: AuthConfig = field(default_factory=AuthConfig)
    strict_json: bool = True          # требовать JSON в send() по умолчанию
    allow_text_frames: bool = True
    idle_timeout_sec: Optional[float] = 180.0
    max_message_bytes: int = 1_000_000
    enable_topics: bool = True
    record_traffic: bool = False
    record_payloads: bool = True

@dataclass
class Frame:
    ts: float
    direction: str          # "in" (к серверу) | "out" (к клиенту)
    topic: Optional[str]
    payload: Any

@dataclass
class Metrics:
    connected: int = 0
    sent: int = 0
    received: int = 0
    dropped: int = 0
    auth_fail: int = 0
    closed: int = 0

# Типы обработчиков
Message = Any
Validator = Optional[Callable[[Message], None]]
AsyncHandler = Callable[['MockWsConnection', Message], Awaitable[None]]
SyncOrAsync = Union[Callable[..., Any], Callable[..., Awaitable[Any]]]


# =========================
# Ядро: брокер
# =========================

class MockWsBroker:
    """
    In‑memory брокер для соединений и топиков.
    """
    def __init__(self, name: str = "ws-broker"):
        self.name = name
        self._topics: Dict[str, List['MockWsConnection']] = {}
        self._conns: Dict[str, 'MockWsConnection'] = {}
        self.metrics = Metrics()
        self._lock = asyncio.Lock()
        self._rec: List[Frame] = []

    async def register(self, conn: 'MockWsConnection') -> None:
        async with self._lock:
            self._conns[conn.id] = conn
            self.metrics.connected += 1

    async def unregister(self, conn: 'MockWsConnection') -> None:
        async with self._lock:
            self._conns.pop(conn.id, None)
            for lst in self._topics.values():
                with contextlib.suppress(ValueError):
                    lst.remove(conn)
            self.metrics.closed += 1

    async def subscribe(self, topic: str, conn: 'MockWsConnection') -> None:
        async with self._lock:
            self._topics.setdefault(topic, [])
            if conn not in self._topics[topic]:
                self._topics[topic].append(conn)

    async def unsubscribe(self, topic: str, conn: 'MockWsConnection') -> None:
        async with self._lock:
            lst = self._topics.get(topic)
            if lst and conn in lst:
                lst.remove(conn)

    async def broadcast(self, topic: str, payload: Message) -> int:
        async with self._lock:
            lst = list(self._topics.get(topic, []))
        delivered = 0
        for c in lst:
            with profile_block("ws.broker.broadcast"):
                ok = await c._deliver(payload, topic=topic)
                delivered += 1 if ok else 0
        return delivered

    def record(self, frame: Frame) -> None:
        self._rec.append(frame)

    def dump_recording(self) -> List[Frame]:
        return list(self._rec)

    def connections(self) -> List['MockWsConnection']:
        return list(self._conns.values())


# =========================
# Соединение
# =========================

class MockWsConnection:
    """
    Двунаправленное «WS‑соединение»:
      - send/recv JSON или текст
      - регулируемые задержки/потери/скорость
      - ограничение буфера и backpressure
      - обработчики сообщений (behavior)
    """
    _id_seq = 0

    def __init__(
        self,
        server: 'MockWsServer',
        broker: MockWsBroker,
        network: NetworkProfile,
        validator: Validator = None,
        client_headers: Optional[Dict[str, str]] = None,
        topics: Optional[List[str]] = None,
    ):
        MockWsConnection._id_seq += 1
        self.id = f"conn-{MockWsConnection._id_seq}"
        self.server = server
        self.broker = broker
        self.network = network
        self.validator = validator
        self.client_headers = client_headers or {}
        self._in: Queue = Queue(maxsize=network.max_queue)    # к приложению (recv)
        self._out: Queue = Queue(maxsize=network.max_queue)   # к клиенту (получит через recv_client)
        self._closed = False
        self._topics = set(topics or [])
        self._bandwidth_bucket: float = 0.0
        self._last_bw_ts: float = time.monotonic()

    # --- сетевые эффекты ---
    def _bw_allow(self, size: int) -> float:
        if not self.network.bandwidth_bytes_per_sec:
            return 0.0
        now = time.monotonic()
        elapsed = now - self._last_bw_ts
        self._last_bw_ts = now
        # токен‑бакет 1:1
        self._bandwidth_bucket = min(
            self.network.bandwidth_bytes_per_sec,
            self._bandwidth_bucket + elapsed * self.network.bandwidth_bytes_per_sec
        )
        if self._bandwidth_bucket >= size:
            self._bandwidth_bucket -= size
            return 0.0
        deficit = size - self._bandwidth_bucket
        wait = deficit / float(self.network.bandwidth_bytes_per_sec)
        self._bandwidth_bucket = 0.0
        return max(0.0, wait)

    async def _net_delay(self) -> None:
        base = self.network.base_latency_ms / 1000.0
        jitter = random.uniform(-self.network.jitter_ms, self.network.jitter_ms) / 1000.0
        d = max(0.0, base + jitter)
        if d:
            await asyncio.sleep(d)

    def _maybe_drop(self) -> bool:
        return random.random() < self.network.loss_prob

    # --- API клиента (то, что «видит» приложение) ---

    async def recv(self, timeout: Optional[float] = None) -> Message:
        if self.server.cfg.idle_timeout_sec and timeout is None:
            timeout = self.server.cfg.idle_timeout_sec
        try:
            with profile_block("ws.recv"):
                return await asyncio.wait_for(self._in.get(), timeout=timeout)
        except TimeoutError as e:
            raise TimeoutError("WS recv timeout") from e

    async def send(self, message: Message, topic: Optional[str] = None) -> None:
        if self.server.cfg.strict_json:
            if isinstance(message, (bytes, bytearray)):
                raise TypeError("Binary frames not supported in strict_json mode")
        if not self.server.cfg.allow_text_frames and isinstance(message, str):
            raise TypeError("Text frames disabled")
        payload = message
        data_size = len(json.dumps(payload, ensure_ascii=False).encode()) if not isinstance(payload, (bytes, bytearray)) else len(payload)
        if data_size > self.server.cfg.max_message_bytes:
            raise ValueError("Message too large")

        with profile_block("ws.send"):
            await self._net_delay()
            if self._maybe_drop():
                self.broker.metrics.dropped += 1
                return
            extra_wait = self._bw_allow(data_size)
            if extra_wait > 0:
                await asyncio.sleep(extra_wait)

            # Передаём в behavior сервера
            await self.server._handle_incoming(self, payload, topic)
            self.broker.metrics.received += 1
            if self.server.cfg.record_traffic:
                self.broker.record(Frame(ts=time.time(), direction="in", topic=topic, payload=payload))

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.broker.unregister(self)

    # --- API клиента‑потребителя (что «видит» удалённая сторона/тест) ---

    async def recv_client(self, timeout: Optional[float] = None) -> Message:
        if self.server.cfg.idle_timeout_sec and timeout is None:
            timeout = self.server.cfg.idle_timeout_sec
        try:
            with profile_block("ws.client.recv"):
                return await asyncio.wait_for(self._out.get(), timeout=timeout)
        except TimeoutError as e:
            raise TimeoutError("Client recv timeout") from e

    async def _deliver(self, payload: Message, topic: Optional[str]) -> bool:
        if self._closed:
            return False
        # фильтр по топику
        if topic and self.server.cfg.enable_topics and topic not in self._topics:
            return True  # «доставлено», но игнор по подписке
        await self._net_delay()
        if self._maybe_drop():
            self.broker.metrics.dropped += 1
            return False
        size = len(json.dumps(payload, ensure_ascii=False).encode())
        extra = self._bw_allow(size)
        if extra > 0:
            await asyncio.sleep(extra)

        try:
            self._out.put_nowait(payload)
            self.broker.metrics.sent += 1
            if self.server.cfg.record_traffic:
                self.broker.record(Frame(ts=time.time(), direction="out", topic=topic, payload=payload if self.server.cfg.record_payloads else None))
            return True
        except QueueFull:
            self.broker.metrics.dropped += 1
            return False

    # --- подписки ---
    async def subscribe(self, topic: str) -> None:
        if not self.server.cfg.enable_topics:
            return
        self._topics.add(topic)
        await self.broker.subscribe(topic, self)

    async def unsubscribe(self, topic: str) -> None:
        if topic in self._topics:
            self._topics.remove(topic)
        await self.broker.unsubscribe(topic, self)


# =========================
# Сервер и поведения
# =========================

class MockWsServer:
    """
    Лёгкий in‑memory «сервер» с настраиваемым поведением.
    """
    def __init__(
        self,
        cfg: Optional[ServerConfig] = None,
        broker: Optional[MockWsBroker] = None,
        behavior: Optional[AsyncHandler] = None,
        validator: Validator = None,
        on_connect: Optional[Callable[[MockWsConnection], Awaitable[None]]] = None,
        on_close: Optional[Callable[[MockWsConnection], Awaitable[None]]] = None,
    ):
        self.cfg = cfg or ServerConfig()
        self.broker = broker or MockWsBroker(self.cfg.name + "-broker")
        self.behavior: AsyncHandler = behavior or EchoBehavior()
        self.validator = validator
        self.on_connect = on_connect
        self.on_close = on_close
        self._closed = False

    async def accept(self, headers: Optional[Dict[str, str]] = None, topics: Optional[List[str]] = None) -> MockWsConnection:
        # Авторизация
        if self.cfg.auth.required:
            token = (headers or {}).get(self.cfg.auth.token_header, "")
            if token not in self.cfg.auth.valid_tokens:
                self.broker.metrics.auth_fail += 1
                raise PermissionError("Unauthorized")

        conn = MockWsConnection(
            server=self,
            broker=self.broker,
            network=self.cfg.network,
            validator=self.validator,
            client_headers=headers,
            topics=topics,
        )
        await self.broker.register(conn)
        if topics:
            for t in topics:
                await conn.subscribe(t)
        if self.on_connect:
            with profile_block("ws.on_connect"):
                await self.on_connect(conn)
        return conn

    async def _handle_incoming(self, conn: MockWsConnection, payload: Message, topic: Optional[str]) -> None:
        # Валидация
        if self.validator:
            with profile_block("ws.validate"):
                self.validator(payload)  # может кинуть исключение
        # Делегирование поведению
        await self.behavior(conn, payload)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Закрываем всех
        for c in list(self.broker.connections()):
            with contextlib.suppress(Exception):
                await c.close()


# --------- Поведения ---------

class EchoBehavior:
    async def __call__(self, conn: MockWsConnection, msg: Message) -> None:
        await conn._deliver({"echo": msg, "ts": time.time()}, topic=None)

class BroadcastBehavior:
    def __init__(self, topic: str):
        self.topic = topic
    async def __call__(self, conn: MockWsConnection, msg: Message) -> None:
        await conn.broker.broadcast(self.topic, {"broadcast": msg, "topic": self.topic, "ts": time.time()})

class ScriptBehavior:
    """
    Реплей заранее заданных ответов: список шагов, где каждый шаг — callable(conn, msg)->payload или сам payload.
    """
    def __init__(self, steps: Iterable[Union[Message, Callable[[MockWsConnection, Message], Awaitable[Message]]]]):
        self.steps: List[Union[Message, Callable[[MockWsConnection, Message], Awaitable[Message]]]] = list(steps)
        self._i = 0

    async def __call__(self, conn: MockWsConnection, msg: Message) -> None:
        if self._i >= len(self.steps):
            # по умолчанию — echo
            await conn._deliver({"echo": msg, "ts": time.time()}, topic=None)
            return
        step = self.steps[self._i]
        self._i += 1
        if callable(step):
            out = await step(conn, msg)  # type: ignore
        else:
            out = step
        await conn._deliver(out, topic=None)

class CustomBehavior:
    """
    Произвольный handler (sync/async).
    """
    def __init__(self, handler: SyncOrAsync):
        self.handler = handler

    async def __call__(self, conn: MockWsConnection, msg: Message) -> None:
        res = self.handler(conn, msg)
        if asyncio.iscoroutine(res):
            res = await res  # type: ignore
        if res is not None:
            await conn._deliver(res, topic=None)

# ===== Валидатор через Pydantic (опционально) =====

def pydantic_validator(model: type[_PModel]) -> Validator:
    if not _HAS_PYD:
        raise RuntimeError("Pydantic is not installed")
    def _v(msg: Any) -> None:
        try:
            if isinstance(msg, dict):
                model(**msg)  # type: ignore
            else:
                model.parse_raw(msg)  # type: ignore
        except _PValErr as e:
            raise ValueError(f"Validation failed: {e}") from e
    return _v


# =========================
# Запись/воспроизведение
# =========================

def export_recording(frames: List[Frame]) -> str:
    return json.dumps([dataclasses.asdict(f) for f in frames], ensure_ascii=False, indent=2)

def import_recording(s: str) -> List[Frame]:
    raw = json.loads(s)
    out: List[Frame] = []
    for item in raw:
        out.append(Frame(**item))
    return out


# =========================
# Контекстные хелперы для тестов
# =========================

class run_broker:
    def __init__(self, name: str = "ws-broker"):
        self.broker = MockWsBroker(name)

    async def __aenter__(self) -> MockWsBroker:
        return self.broker

    async def __aexit__(self, exc_type, exc, tb) -> None:
        # ничего спец не требуется
        return None

class run_server:
    def __init__(self, cfg: Optional[ServerConfig] = None, behavior: Optional[AsyncHandler] = None, validator: Validator = None):
        self.server = MockWsServer(cfg=cfg, behavior=behavior, validator=validator)

    async def __aenter__(self) -> MockWsServer:
        return self.server

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.server.close()

# =========================
# Примеры мини‑использования в тестах
# =========================

async def _example_echo_usage() -> None:
    async with run_server(ServerConfig(name="test-echo", record_traffic=True)) as srv:
        conn = await srv.accept(headers={"Authorization": "token123"})
        await conn.send({"op": "ping"})
        got = await conn.recv_client()
        assert got["echo"]["op"] == "ping"
        # записанный трафик
        frames = srv.broker.dump_recording()
        _ = export_recording(frames)

async def _example_broadcast_usage() -> None:
    cfg = ServerConfig(name="test-bc", enable_topics=True)
    async with run_server(cfg=cfg, behavior=BroadcastBehavior(topic="updates")) as srv:
        c1 = await srv.accept(topics=["updates"])
        c2 = await srv.accept(topics=["updates"])
        c3 = await srv.accept(topics=["other"])

        await c1.send({"n": 1})
        a = await c1.recv_client()
        b = await c2.recv_client()
        # c3 ничего не получит

# =========================
# Sync‑обёртки (для простых юнит‑тестов)
# =========================

def run_sync(coro: Awaitable[Any]) -> Any:
    return asyncio.get_event_loop().run_until_complete(coro)

def example_sync() -> None:
    async def _run():
        async with run_server(ServerConfig(name="sync-echo"), behavior=EchoBehavior()) as srv:
            c = await srv.accept()
            await c.send({"x": 1})
            got = await c.recv_client()
            assert got["echo"]["x"] == 1
    run_sync(_run())

# =========================
# Экспорт «публичного» API
# =========================

__all__ = [
    "NetworkProfile",
    "AuthConfig",
    "ServerConfig",
    "MockWsBroker",
    "MockWsServer",
    "MockWsConnection",
    "EchoBehavior",
    "BroadcastBehavior",
    "ScriptBehavior",
    "CustomBehavior",
    "pydantic_validator",
    "export_recording",
    "import_recording",
    "run_broker",
    "run_server",
    "run_sync",
    "example_sync",
]
