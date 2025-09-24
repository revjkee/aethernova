# automation-core/tests/fixtures/http.py
# -*- coding: utf-8 -*-
"""
Локальный тестовый HTTP/1.1 сервер для pytest без внешних зависимостей.

Фактическая основа:
- HTTP Semantics — IETF RFC 9110 (семантика методов/кодов/заголовков). См. RFC Editor.  # noqa: E501
- HTTP/1.1 — IETF RFC 9112 (синтаксис сообщений, управление соединением, chunked).     # noqa: E501
- Python stdlib http.server: BaseHTTPRequestHandler / ThreadingHTTPServer.              # noqa: E501
Источники: RFC 9110, RFC 9112, docs.python.org. См. ссылки в тестовом ответе.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs, urlparse


@dataclass
class RequestRecord:
    """Запись о запросе для ассертов в тестах."""
    method: str
    path: str
    query: Mapping[str, List[str]]
    headers: Mapping[str, str]
    body_b64: Optional[str] = None
    json: Optional[object] = None
    request_id: str = ""


@dataclass
class ServerInfo:
    """Объект, возвращаемый фикстурой: адрес, лог и хелперы."""
    host: str
    port: int
    scheme: str = "http"
    request_log: List[RequestRecord] = field(default_factory=list)

    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url()}{path}"

    def clear_log(self) -> None:
        self.request_log.clear()


# ------------------------- HTTP Handler & Server -----------------------------

class _TestHandler(BaseHTTPRequestHandler):
    # Используем HTTP/1.1 (RFC 9112); подавляем стандартный консольный лог.
    protocol_version = "HTTP/1.1"
    server_version = "AutomationCoreTestServer/1.0"
    sys_version = ""

    # Регистр пользовательских обработчиков: path -> callable(handler) -> (status, headers, body_bytes)
    ROUTES: Dict[str, Callable[["_TestHandler"], Tuple[int, List[Tuple[str, str]], bytes]]] = {}

    def log_message(self, fmt: str, *args) -> None:  # noqa: D401
        # Тихий сервер: вывод подавлен; лог ведётся в request_log.
        return

    # ---------------------- Вспомогательные методы ----------------------

    def _now_httpdate(self) -> str:
        # Формат даты: RFC 9110 §5.6.7 (HTTP-date). Стандартная библиотека шлёт GMT автоматически,
        # здесь достаточно time.strftime c gmtime.
        return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _capture_request(self, body: bytes, request_id: str) -> None:
        parsed = urlparse(self.path)
        headers = {k: v for k, v in self.headers.items()}
        rec = RequestRecord(
            method=self.command,
            path=parsed.path,
            query=parse_qs(parsed.query, keep_blank_values=True),
            headers=headers,
            body_b64=base64.b64encode(body).decode("ascii") if body else None,
            json=None,
            request_id=request_id,
        )
        ctype = self.headers.get("Content-Type", "")
        if ctype.startswith("application/json") and body:
            try:
                rec.json = json.loads(body.decode("utf-8"))
            except Exception:
                rec.json = None
        self.server.request_log.append(rec)  # type: ignore[attr-defined]

    def _apply_common_headers(self, extra: Optional[List[Tuple[str, str]]] = None) -> None:
        # Базовые заголовки ответа согласно семантике HTTP (RFC 9110).
        self.send_header("Date", self._now_httpdate())
        self.send_header("Server", self.server_version)
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-Id", getattr(self, "_request_id", ""))
        if extra:
            for k, v in extra:
                self.send_header(k, v)

    # ---------------------- Обработчики методов -------------------------

    def do_HEAD(self) -> None:  # noqa: N802
        # Семантика HEAD: те же заголовки, что и для GET, но без тела (RFC 9110 §9.3.2).
        self._dispatch(head_only=True)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    # ---------------------- Диспетчер маршрутов -------------------------

    def _dispatch(self, head_only: bool = False) -> None:
        body = self._read_body()
        self._request_id = str(uuid.uuid4())
        self._capture_request(body, self._request_id)

        status, headers, payload = self._route(body)

        # HEAD: те же заголовки, нулевое тело
        if head_only:
            payload = b""

        self.send_response(status)
        self._apply_common_headers(headers + [("Content-Length", str(len(payload)))])
        self.end_headers()
        if payload and not head_only:
            self.wfile.write(payload)

    # ---------------------- Реализация маршрутов ------------------------

    def _route(self, body: bytes) -> Tuple[int, List[Tuple[str, str]], bytes]:
        parsed = urlparse(self.path)
        path = parsed.path

        # Пользовательский роутер имеет приоритет
        if path in self.ROUTES:
            return self.ROUTES[path](self)

        if path == "/json":
            data = {"ok": True, "message": "hello", "request_id": self._request_id}
            payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
            return (HTTPStatus.OK, [("Content-Type", "application/json; charset=utf-8")], payload)

        if path == "/echo":
            ctype = self.headers.get("Content-Type", "")
            parsed_q = parse_qs(parsed.query, keep_blank_values=True)
            resp = {
                "method": self.command,
                "path": path,
                "query": parsed_q,
                "headers": {k: v for k, v in self.headers.items()},
                "body_b64": base64.b64encode(body).decode("ascii") if body else None,
                "json": None,
                "request_id": self._request_id,
            }
            if ctype.startswith("application/json") and body:
                try:
                    resp["json"] = json.loads(body.decode("utf-8"))
                except Exception:
                    resp["json"] = None
            payload = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            return (HTTPStatus.OK, [("Content-Type", "application/json; charset=utf-8")], payload)

        if path.startswith("/status/"):
            try:
                code = int(path.split("/", 2)[-1])
                status = HTTPStatus(code)
            except Exception:
                status = HTTPStatus.BAD_REQUEST
            payload = json.dumps({"status": int(status), "request_id": self._request_id}).encode("utf-8")
            return (int(status), [("Content-Type", "application/json; charset=utf-8")], payload)

        if path.startswith("/delay/"):
            try:
                ms = int(path.split("/", 2)[-1])
                time.sleep(max(ms, 0) / 1000.0)
            except Exception:
                return (HTTPStatus.BAD_REQUEST, [], b"")
            return (HTTPStatus.OK, [("Content-Type", "text/plain; charset=utf-8")], b"delayed")

        if path.startswith("/redirect/"):
            try:
                n = int(path.split("/", 2)[-1])
            except Exception:
                n = 1
            location = "/echo" if n <= 1 else f"/redirect/{n-1}"
            headers = [("Location", location)]
            return (HTTPStatus.FOUND, headers, b"")

        if path == "/chunked":
            # Демонстрация chunked-ответа (RFC 9112 §7.1); отправим вручную.
            # Для chunked нельзя ставить Content-Length; отправим заголовок и тело сами.
            self.send_response(HTTPStatus.OK)
            self._apply_common_headers([("Content-Type", "text/plain; charset=utf-8"),
                                        ("Transfer-Encoding", "chunked")])
            self.end_headers()
            for chunk in [b"hello ", b"from ", b"chunked ", b"response"]:
                self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii"))
                self.wfile.write(chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return (HTTPStatus.OK, [], b"")

        # Неизвестный маршрут
        return (HTTPStatus.NOT_FOUND, [("Content-Type", "text/plain; charset=utf-8")], b"not found")


class _ThreadedHTTPServer(ThreadingHTTPServer):
    # Контейнер для лога запросов (доступ через ServerInfo)
    request_log: List[RequestRecord]

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.request_log = []


# ------------------------------ Фикстуры -------------------------------------

def start_test_server(host: str = "127.0.0.1", port: int = 0) -> Tuple[_ThreadedHTTPServer, ServerInfo, threading.Thread]:
    """
    Запускает потоковый HTTP/1.1 сервер и возвращает (server, info, thread).
    Корректное завершение: server.shutdown(); thread.join(); server.server_close().

    Соответствие HTTP/1.1 обеспечивается стандартной реализацией Python (см. docs.python.org).
    """
    httpd = _ThreadedHTTPServer((host, port), _TestHandler)
    real_host, real_port = httpd.server_address  # type: ignore[assignment]
    info = ServerInfo(host=real_host, port=real_port, request_log=httpd.request_log)

    thread = threading.Thread(target=httpd.serve_forever, name="TestHTTPServer", daemon=True)
    thread.start()
    return httpd, info, thread


# ------------------------------ Pytest glue ----------------------------------

try:
    import pytest  # type: ignore

    @pytest.fixture(scope="function")
    def http_server():
        """
        Pytest-фикстура: поднимает сервер на время теста и корректно останавливает его.

        Пример использования:
            def test_echo(http_server):
                import urllib.request, json
                url = http_server.url("/echo")
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                assert data["method"] == "GET"
        """
        server, info, thread = start_test_server()
        try:
            yield info
        finally:
            server.shutdown()
            thread.join(timeout=5.0)
            server.server_close()

    @pytest.fixture(scope="function")
    def http_routes():
        """
        Доступ к пользовательским маршрутам:
            def my_handler(h):
                return 200, [("Content-Type","text/plain")], b"ok"
            http_routes["/custom"] = my_handler
        """
        # Очистим и вернём ссылку на общий реестр
        _TestHandler.ROUTES.clear()
        try:
            yield _TestHandler.ROUTES
        finally:
            _TestHandler.ROUTES.clear()

except Exception:
    # Pytest необязателен: модуль можно использовать как вспомогательную библиотеку.
    pass
