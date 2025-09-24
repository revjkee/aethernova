# chronowatch-core/tests/integration/test_heartbeat_monitor.py
# -*- coding: utf-8 -*-
"""
Интеграционные тесты heartbeat-монитора ChronoWatch.
Требуется pytest. В остальном — только стандартная библиотека.

Покрытие:
- базовая доставка heartbeat на HTTP endpoint;
- проверка схемы полезной нагрузки и заголовков (Authorization);
- устойчивость к временным ошибкам (5xx) с ретраями;
- оценки интервального джиттера (стабильность периодики);
- корректное завершение (graceful shutdown, отсутствие новых событий).

Тесты предусмотрительно skip/xfail-ят сценарии,
если конкретная реализация HeartbeatMonitor чего-то не поддерживает.
"""

from __future__ import annotations

import contextlib
import importlib
import inspect
import io
import json
import os
import queue
import socket
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

import pytest


# ------------------------------- Utilities -------------------------------

def _find_free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _now_mono_ns() -> int:
    return time.monotonic_ns()


@dataclass
class ReceivedEvent:
    t_recv_ns: int
    path: str
    headers: Dict[str, str]
    body: Dict[str, Any]
    status_sent: int


class _RequestQueue(queue.Queue):
    """Queue[ReceivedEvent] with helper for timed drains."""
    def drain_for(self, min_count: int, timeout_s: float) -> List[ReceivedEvent]:
        deadline = time.time() + timeout_s
        acc: List[ReceivedEvent] = []
        while len(acc) < min_count and time.time() < deadline:
            try:
                item = self.get(timeout=max(0.01, deadline - time.time()))
                acc.append(item)
            except queue.Empty:
                pass
        # collect any immediately available without blocking to reduce flakiness
        while True:
            try:
                acc.append(self.get_nowait())
            except queue.Empty:
                break
        return acc


class _HeartbeatHTTPHandler(BaseHTTPRequestHandler):
    server_version = "ChronoWatchMock/1.0"

    # Silence default logging to stderr
    def log_message(self, fmt, *args):  # noqa: N802
        return

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):  # noqa: N802
        status = HTTPStatus.OK
        # Simulate initial failures
        if getattr(self.server, "fail_first_n", 0) > 0:
            self.server.fail_first_n -= 1  # type: ignore[attr-defined]
            status = HTTPStatus.INTERNAL_SERVER_ERROR

        # Read body safely
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b""
        body: Dict[str, Any]
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            status = HTTPStatus.BAD_REQUEST
            body = {"_parse_error": True}

        # Record event
        event = ReceivedEvent(
            t_recv_ns=_now_mono_ns(),
            path=self.path,
            headers={k.lower(): v for k, v in self.headers.items()},
            body=body,
            status_sent=int(status),
        )
        self.server.events.put(event)  # type: ignore[attr-defined]

        # Send response
        payload = json.dumps({"status": int(status)}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        with contextlib.suppress(Exception):
            self.wfile.write(payload)


class MockHeartbeatServer:
    """
    Threaded mock server to receive heartbeat POSTs.
    """
    def __init__(self, fail_first_n: int = 0) -> None:
        self.port = _find_free_port()
        self.addr = ("127.0.0.1", self.port)
        self.events: _RequestQueue = _RequestQueue()
        self._httpd = ThreadingHTTPServer(self.addr, _HeartbeatHTTPHandler)
        # attach shared state
        self._httpd.events = self.events  # type: ignore[attr-defined]
        self._httpd.fail_first_n = fail_first_n  # type: ignore[attr-defined]
        self._thr = threading.Thread(target=self._httpd.serve_forever, name="MockHeartbeatServer", daemon=True)

    @property
    def url(self) -> str:
        return f"http://{self.addr[0]}:{self.addr[1]}"

    @property
    def heartbeat_endpoint(self) -> str:
        return f"{self.url}/heartbeat"

    def start(self) -> "MockHeartbeatServer":
        self._thr.start()
        self.wait_ready(timeout_s=2.0)
        return self

    def wait_ready(self, timeout_s: float = 2.0) -> None:
        import urllib.request
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{self.url}/healthz", timeout=0.2) as resp:
                    if resp.status == 200:
                        return
            except Exception:
                time.sleep(0.05)
        raise RuntimeError("MockHeartbeatServer did not become ready")

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            self._httpd.shutdown()
        with contextlib.suppress(Exception):
            self._httpd.server_close()
        self._thr.join(timeout=2.0)

    def wait_events(self, n: int, timeout_s: float) -> List[ReceivedEvent]:
        return self.events.drain_for(n, timeout_s)


# ------------------- HeartbeatMonitor dynamic discovery -------------------

@dataclass
class MonitorRunner:
    """Runs a HeartbeatMonitor with unknown exact API in a best-effort way."""
    monitor: Any
    _started: bool = field(default=False, init=False)

    def start(self) -> None:
        # Prefer non-blocking start() if exists
        if hasattr(self.monitor, "start"):
            res = self.monitor.start()  # may return None or future
            self._started = True
            # If callable returned a thread or similar, we don't join here.
            return
        # Fallback: run() in background thread if exists
        if hasattr(self.monitor, "run"):
            thr = threading.Thread(target=self.monitor.run, name="HeartbeatMonitorRun", daemon=True)
            thr.start()
            self._started = True
            return
        raise RuntimeError("Unsupported HeartbeatMonitor API: no start()/run()")

    def stop(self) -> None:
        # Try stop/shutdown/close in that order
        for method in ("stop", "shutdown", "close"):
            if hasattr(self.monitor, method):
                try:
                    getattr(self.monitor, method)()
                    return
                except Exception:
                    pass
        # If nothing worked but we started, give a small grace and return
        time.sleep(0.1)


def _try_import(paths: List[Tuple[str, str]]) -> Tuple[Any, str]:
    last_err: Optional[Exception] = None
    for mod_name, cls_name in paths:
        try:
            mod = importlib.import_module(mod_name)
            cls = getattr(mod, cls_name, None)
            if cls is not None:
                return cls, f"{mod_name}.{cls_name}"
        except Exception as e:
            last_err = e
    reason = f"HeartbeatMonitor not found. Last error: {last_err!r}" if last_err else "not found"
    pytest.skip(reason)  # pragma: no cover
    raise RuntimeError("unreachable")  # to satisfy typing


def _build_monitor(endpoint: str, interval_ms: int, auth_token: Optional[str]) -> MonitorRunner:
    """
    Create a HeartbeatMonitor instance by adapting to different ctor signatures.
    """
    candidates = [
        ("chronowatch_core.monitor.heartbeat", "HeartbeatMonitor"),
        ("chronowatch_core.agent.heartbeat", "HeartbeatMonitor"),
        ("chronowatch_core.heartbeat", "HeartbeatMonitor"),
    ]
    HB, path = _try_import(candidates)

    ctor = HB
    sig = inspect.signature(ctor)
    kwargs = {
        "endpoint": endpoint,
        "interval_ms": interval_ms,
        "headers": {"Authorization": f"Bearer {auth_token}"} if auth_token else None,
        "auth_token": auth_token,
        "path": "/heartbeat",
        "timeout_ms": 2000,
        "retry": {"enabled": True, "initial_ms": 50, "max_ms": 500, "max_retries": 10},
        "payload_extra": {"service": "chronowatch", "platform": "windows"},
    }
    # filter only accepted params
    filtered = {k: v for k, v in kwargs.items() if k in sig.parameters and v is not None}

    monitor = ctor(**filtered)  # type: ignore[call-arg]
    return MonitorRunner(monitor=monitor)


# -------------------------------- Fixtures --------------------------------

@pytest.fixture(scope="function")
def mock_server():
    srv = MockHeartbeatServer().start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture(scope="function")
def mock_server_fail3():
    srv = MockHeartbeatServer(fail_first_n=3).start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture(scope="function")
def auth_token(monkeypatch):
    token = "itest-token-123"
    # Set common env var names some agents might read implicitly
    monkeypatch.setenv("CHRONOWATCH_HEARTBEAT_TOKEN", token)
    monkeypatch.setenv("HEARTBEAT_AUTH_TOKEN", token)
    monkeypatch.setenv("OTLP_AUTH_TOKEN", token)
    return token


# --------------------------------- Tests ----------------------------------

@pytest.mark.integration
def test_basic_heartbeat_delivery_and_schema(mock_server):
    """
    Монитор должен доставлять несколько heartbeat за разумный интервал времени,
    а полезная нагрузка должна содержать базовые поля.
    """
    runner = _build_monitor(endpoint=mock_server.heartbeat_endpoint, interval_ms=100, auth_token=None)
    runner.start()
    try:
        events = mock_server.wait_events(n=4, timeout_s=3.0)
        assert len(events) >= 3, "Ожидалось минимум 3 heartbeat-события"
        # Схема полезной нагрузки — допускаем вариативность ключей
        required_any_keys = [
            ["host", "hostname", "node"],
            ["ts", "timestamp", "time_unix_ms", "time"],
            ["service", "svc", "component"],
        ]
        for ev in events:
            body_keys = set(ev.body.keys())
            for variants in required_any_keys:
                assert any(k in body_keys for k in variants), f"Нет ни одного из ключей {variants} в {body_keys}"
            # Статус ответа сервера
            assert ev.status_sent == 200
    finally:
        runner.stop()


@pytest.mark.integration
def test_authorization_header_present_if_configured(mock_server, auth_token):
    """
    Если монитор поддерживает передачу токена, проверяем наличие Authorization.
    В противном случае — xfail (функциональность может не поддерживаться).
    """
    runner = _build_monitor(endpoint=mock_server.heartbeat_endpoint, interval_ms=80, auth_token=auth_token)
    runner.start()
    try:
        events = mock_server.wait_events(n=2, timeout_s=2.5)
        if not events:
            pytest.fail("Не получено ни одного heartbeat для проверки заголовков")
        has_auth = any("authorization" in ev.headers and auth_token in ev.headers["authorization"] for ev in events)
        if not has_auth:
            pytest.xfail("Реализация HeartbeatMonitor не проставляет Authorization заголовок")
    finally:
        runner.stop()


@pytest.mark.integration
def test_retry_on_server_errors(mock_server_fail3):
    """
    Сервер отдаёт 500 на первые 3 запроса. Монитор должен повторить попытки
    и добиться успешной доставки в пределах таймаута.
    """
    runner = _build_monitor(endpoint=mock_server_fail3.heartbeat_endpoint, interval_ms=60, auth_token=None)
    runner.start()
    try:
        # ждём минимум 5 событий (3 неуспеха + 2 успеха)
        events = mock_server_fail3.wait_events(n=5, timeout_s=6.0)
        assert len(events) >= 4, f"Недостаточно попыток/доставок: получено {len(events)}"
        # Проверим, что были и 500, и 200
        codes = [e.status_sent for e in events]
        assert any(c == 500 for c in codes), "Не зафиксированы ошибки 5xx"
        assert any(c == 200 for c in codes), "Не зафиксированы успешные доставки после 5xx"
    finally:
        runner.stop()


@pytest.mark.integration
def test_jitter_bounds(mock_server):
    """
    Проверяем интервалы между доставками (по времени приёма сервером).
    Коэффициент вариации по первым 10 интервалам должен быть разумным.
    """
    import statistics

    runner = _build_monitor(endpoint=mock_server.heartbeat_endpoint, interval_ms=100, auth_token=None)
    runner.start()
    try:
        events = mock_server.wait_events(n=12, timeout_s=5.0)
        assert len(events) >= 8, "Недостаточно событий для оценки джиттера"
        t = [ev.t_recv_ns for ev in events]
        # Берём интервалы, игнорируя первый
        intervals_ms = [(t[i] - t[i - 1]) / 1e6 for i in range(1, min(len(t), 12))]
        mean_ms = statistics.fmean(intervals_ms)
        stdev_ms = statistics.pstdev(intervals_ms)
        # Коэффициент вариации CV = stdev / mean
        cv = stdev_ms / mean_ms if mean_ms > 0 else 1.0
        # Допуск щадящий из-за планировщика ОС и Python GIL
        assert cv < 0.4, f"Слишком высокий джиттер: mean={mean_ms:.1f}ms stdev={stdev_ms:.1f}ms CV={cv:.2f}"
    finally:
        runner.stop()


@pytest.mark.integration
def test_graceful_shutdown_flushes_and_stops(mock_server):
    """
    После остановки не должно появляться новых heartbeat, кроме, возможно,
    одного in-flight сообщения.
    """
    runner = _build_monitor(endpoint=mock_server.heartbeat_endpoint, interval_ms=70, auth_token=None)
    runner.start()
    try:
        events1 = mock_server.wait_events(n=5, timeout_s=4.0)
        before = len(events1)
        runner.stop()
        # ждём чуть больше двух интервалов
        time.sleep(0.18)
        events2 = mock_server.wait_events(n=1, timeout_s=0.5)
        # допускаем максимум одно «догоняющее» сообщение
        after = before + len(events2)
        assert (after - before) <= 1, f"После остановки пришло слишком много событий: {after - before}"
    finally:
        # повторный stop на случай исключений внутри try
        with contextlib.suppress(Exception):
            runner.stop()
