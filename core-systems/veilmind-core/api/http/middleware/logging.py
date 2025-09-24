"""
VeilMind — Access Logging ASGI middleware (industrial grade)

Особенности:
- Структурированное логирование access-событий с минимальными накладными.
- Корреляция: request_id, trace_id, span_id (OTEL/W3C), user_id (если есть).
- Корректное вычисление client_ip за прокси (trusted proxies / RFC1918).
- Редактирование PII (Authorization, password, token, email, api_key).
- Пропуск /healthz, /readyz, /livez и настраиваемых путей.
- Ограничение логируемых тел запросов/ответов по размеру и типу.
- Надёжный подсчёт response_bytes без разрушения стриминга.

Зависимости:
- Стандартная библиотека + любой ASGI-фреймворк (FastAPI/Starlette/Quart и т.д.).
- Опционально: opentelemetry-api (если установлен) для извлечения trace/span.

Совместимость:
- Логгер "veilmind.access" (см. configs/logging.yaml) с JSON-форматтером и каналом access.log.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Опциональная интеграция с OTEL
try:
    from opentelemetry.trace import get_current_span  # type: ignore
except Exception:  # pragma: no cover
    get_current_span = None  # type: ignore

# -----------------------------------------------------------------------------
# Контекстные переменные для лог-фильтров (если используются в logging.yaml)
# -----------------------------------------------------------------------------
cv_request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
cv_trace_id: ContextVar[Optional[str]] = ContextVar("trace_id", default=None)
cv_span_id: ContextVar[Optional[str]] = ContextVar("span_id", default=None)


# -----------------------------------------------------------------------------
# Конфигурация middleware
# -----------------------------------------------------------------------------
@dataclass
class AccessLogConfig:
    enabled: bool = field(default=bool(int(os.getenv("ACCESS_LOG_ENABLED", "1"))))
    # Пропуск путей (regex, через |). По умолчанию — health-пробы.
    exclude_path_pattern: str = field(
        default=os.getenv("ACCESS_LOG_EXCLUDE_RE", r"^/(healthz|readyz|livez)(/.*)?$")
    )
    # Доверенные прокси — CIDR списка, по которым мы шагаем справа-налево из XFF
    trusted_proxies: Tuple[str, ...] = field(
        default_factory=lambda: tuple(
            os.getenv(
                "ACCESS_LOG_TRUSTED_PROXIES",
                "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32,::1/128",
            ).split(",")
        )
    )
    # Лимиты на логирование тела запроса/ответа
    max_body_log_bytes: int = int(os.getenv("ACCESS_LOG_MAX_BODY_BYTES", "2048"))
    # Жёсткий лимит на чтение тела запроса в middleware (для вычисления сэмпла)
    request_body_hard_limit: int = int(os.getenv("ACCESS_LOG_REQUEST_HARD_LIMIT", "1048576"))  # 1 MiB
    # Логировать тела только для ошибок (>=400)
    body_on_errors_only: bool = bool(int(os.getenv("ACCESS_LOG_BODY_ERRORS_ONLY", "1")))
    # Логировать тела запросов целиком (иначе — только сэмпл)
    log_request_body: bool = bool(int(os.getenv("ACCESS_LOG_REQUEST_BODY", "0")))
    log_response_body: bool = bool(int(os.getenv("ACCESS_LOG_RESPONSE_BODY", "0")))
    # Разрешённые content-types для логирования тел
    allow_body_content_types: Tuple[str, ...] = field(
        default_factory=lambda: tuple(
            os.getenv(
                "ACCESS_LOG_ALLOWED_CT",
                "application/json,application/problem+json,text/plain",
            ).split(",")
        )
    )
    # Имя логгера
    logger_name: str = os.getenv("ACCESS_LOG_LOGGER", "veilmind.access")
    # Добавлять X-Request-ID в ответ
    set_request_id_header: bool = bool(int(os.getenv("ACCESS_LOG_SET_REQ_ID_HDR", "1")))
    # Имя заголовка с request id
    request_id_header: str = os.getenv("ACCESS_LOG_REQ_ID_HDR", "X-Request-ID")


# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------
_PII_PATTERNS = [
    re.compile(r"(?i)authorization\s*:\s*Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*"),
    re.compile(r"(?i)(api[_-]?key)\s*[=:]\s*([A-Za-z0-9\-]{16,})"),
    re.compile(r"(?i)(password)\s*[=:]\s*([^\s]+)"),
    re.compile(r"(?i)(secret)\s*[=:]\s*([^\s]+)"),
    re.compile(r"(?i)(token)\s*[=:]\s*([A-Za-z0-9\._\-]{8,})"),
    re.compile(r"(?i)(email)\s*[:=]\s*([^\s]+@[^\s]+)"),
]

_REPLACEMENT = "[REDACTED]"


def _redact_text(value: str) -> str:
    out = value
    for pat in _PII_PATTERNS:
        out = pat.sub(lambda m: f"{m.group(1) if m.lastindex else ''}: {_REPLACEMENT}", out)
    return out


def _redact_headers(headers: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
    h: Dict[str, str] = {}
    for k_b, v_b in headers:
        k = k_b.decode("latin-1")
        v = v_b.decode("latin-1")
        if k.lower() in ("authorization", "cookie", "set-cookie"):
            h[k] = _REPLACEMENT
        else:
            h[k] = _redact_text(v)
    return h


def _maybe_json(obj: bytes) -> Optional[Any]:
    try:
        return json.loads(obj.decode("utf-8"))
    except Exception:
        return None


def _redact_json(obj: Any) -> Any:
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in {"authorization", "password", "token", "secret", "api_key", "apikey", "email"}:
                redacted[k] = _REPLACEMENT
            else:
                redacted[k] = _redact_json(v)
        return redacted
    if isinstance(obj, list):
        return [_redact_json(v) for v in obj]
    if isinstance(obj, str):
        return _redact_text(obj)
    return obj


def _content_type(headers: List[Tuple[bytes, bytes]]) -> str:
    for k, v in headers:
        if k.lower() == b"content-type":
            return v.decode("latin-1").split(";")[0].strip()
    return ""


def _starts_with_any(s: str, prefixes: Iterable[str]) -> bool:
    s = s.lower()
    return any(s.startswith(p.strip().lower()) for p in prefixes if p.strip())


def _parse_traceparent(headers: List[Tuple[bytes, bytes]]) -> Tuple[Optional[str], Optional[str]]:
    # W3C traceparent: "00-<trace-id>-<span-id>-<flags>"
    for k, v in headers:
        if k.lower() == b"traceparent":
            parts = v.decode("latin-1").split("-")
            if len(parts) >= 4 and len(parts[1]) == 32 and len(parts[2]) == 16:
                return parts[1], parts[2]
    return None, None


def _otel_ids() -> Tuple[Optional[str], Optional[str]]:
    if get_current_span is None:  # opentelemetry не установлен
        return None, None
    try:
        span = get_current_span()
        ctx = span.get_span_context()  # type: ignore[attr-defined]
        if getattr(ctx, "is_valid", False):
            trace_id = f"{ctx.trace_id:032x}"  # type: ignore[attr-defined]
            span_id = f"{ctx.span_id:016x}"  # type: ignore[attr-defined]
            return trace_id, span_id
    except Exception:
        return None, None
    return None, None


def _ip_from_xff_or_remote(
    headers: List[Tuple[bytes, bytes]], remote_addr: Optional[str], trusted_cidrs: Tuple[str, ...]
) -> str:
    """
    Возвращает наиболее вероятный client IP.
    Алгоритм: берём X-Forwarded-For как список, шагаем справа налево, отбрасывая доверенные прокси,
    следующая слева — клиент. Если ничего не нашли — remote_addr.
    """
    nets = []
    for c in trusted_cidrs:
        try:
            nets.append(ipaddress.ip_network(c.strip()))
        except Exception:
            continue

    def is_trusted(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return any(ip in n for n in nets)
        except Exception:
            return False

    xff = None
    for k, v in headers:
        if k.lower() == b"x-forwarded-for":
            xff = v.decode("latin-1")
            break

    if xff:
        chain = [p.strip() for p in xff.split(",") if p.strip()]
        # идём справа налево
        for i in range(len(chain) - 1, -1, -1):
            candidate = chain[i]
            if not is_trusted(candidate):
                return candidate

        # все в цепочке доверенные -> берём левый (клиентский)
        if chain:
            return chain[0]

    return remote_addr or "0.0.0.0"


def _should_log_body(ct: str, cfg: AccessLogConfig, status: int) -> bool:
    if cfg.body_on_errors_only and status < 400:
        return False
    if not ct:
        return False
    return _starts_with_any(ct, cfg.allow_body_content_types)


# -----------------------------------------------------------------------------
# Middleware
# -----------------------------------------------------------------------------
class AccessLoggingMiddleware:
    """
    ASGI-middleware для структурного access-логирования.
    """

    def __init__(self, app: ASGIApp, config: Optional[AccessLogConfig] = None) -> None:
        self.app = app
        self.cfg = config or AccessLogConfig()
        self.logger = logging.getLogger(self.cfg.logger_name)
        self._exclude_re = re.compile(self.cfg.exclude_path_pattern)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.cfg.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "") or "/"
        if self._exclude_re.search(path):
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        http_version = scope.get("http_version", "1.1")
        raw_headers: List[Tuple[bytes, bytes]] = list(scope.get("headers", []))
        remote_addr = None
        client = scope.get("client")
        if client and isinstance(client, (list, tuple)) and client:
            remote_addr = str(client[0])

        # Корреляция
        req_id = self._request_id_from_headers(raw_headers) or str(uuid.uuid4())
        trace_id, span_id = _otel_ids()
        if trace_id is None or span_id is None:
            w3c_trace, w3c_span = _parse_traceparent(raw_headers)
            trace_id = trace_id or w3c_trace
            span_id = span_id or w3c_span

        # Устанавливаем контекстные переменные для лог-фильтров
        token_rid = cv_request_id.set(req_id)
        token_tid = cv_trace_id.set(trace_id)
        token_sid = cv_span_id.set(span_id)

        # Определяем client IP
        client_ip = _ip_from_xff_or_remote(raw_headers, remote_addr, self.cfg.trusted_proxies)

        # Собираем request-метаданные
        query_string = scope.get("query_string", b"").decode("latin-1")
        user_agent = self._header(raw_headers, b"user-agent")
        host = self._header(raw_headers, b"host")
        content_type = _content_type(raw_headers)

        # Подготовка к чтению тела запроса (сэмпл для логов)
        request_body_sample = None
        full_request_body: Optional[bytes] = None
        need_body = self.cfg.log_request_body and _starts_with_any(content_type, self.cfg.allow_body_content_types)

        # Если хотим логировать тело запроса — буферизуем полностью (с ограничением) и переигрываем вниз по стеку
        if need_body:
            full_request_body = await self._drain_body(receive, self.cfg.request_body_hard_limit)
            request_body_sample = self._prepare_body_sample(full_request_body, content_type, self.cfg.max_body_log_bytes)
            # Переигрываем тело приложению
            receive = self._replay_body(full_request_body)

        start_ns = time.perf_counter_ns()
        status_code: int = 500
        resp_headers: List[Tuple[bytes, bytes]] = []
        response_bytes = 0
        response_body_sample = None

        # Обёртка над send для подсчёта байтов/статуса и инъекции X-Request-ID
        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, resp_headers, response_bytes, response_body_sample

            if message["type"] == "http.response.start":
                status_code = int(message.get("status", 200))
                headers_list: List[Tuple[bytes, bytes]] = list(message.get("headers", []))
                if self.cfg.set_request_id_header:
                    headers_list.append((self.cfg.request_id_header.encode("latin-1"), req_id.encode("latin-1")))
                message["headers"] = headers_list
                resp_headers = headers_list

            elif message["type"] == "http.response.body":
                body = message.get("body", b"") or b""
                response_bytes += len(body)

                # Сэмплим тело ответа только если нужно и только для разрешённых типов
                resp_ct = _content_type(resp_headers)
                if (
                    response_body_sample is None
                    and self.cfg.log_response_body
                    and _should_log_body(resp_ct, self.cfg, status_code)
                    and len(body) > 0
                ):
                    response_body_sample = self._prepare_body_sample(body, resp_ct, self.cfg.max_body_log_bytes)

            await send(message)

        # Вызов приложения
        exc: Optional[BaseException] = None
        try:
            await self.app(scope, receive, send_wrapper)
        except BaseException as e:  # фиксируем исключение, чтобы залогировать и пробросить
            exc = e
            raise
        finally:
            duration_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

            # Заголовки запроса/ответа с редакцией
            safe_req_headers = _redact_headers(raw_headers)
            safe_resp_headers = _redact_headers(resp_headers)

            level = logging.INFO
            if status_code >= 500:
                level = logging.ERROR
            elif status_code >= 400:
                level = logging.WARNING

            # Сэмплим тела только при ошибках, если включён флаг body_on_errors_only
            if self.cfg.body_on_errors_only and status_code < 400:
                request_body_sample = None
                response_body_sample = None

            # Готовим payload
            log_payload: Dict[str, Any] = {
                "http_method": method,
                "http_path": path,
                "http_query": _redact_text(query_string),
                "http_protocol": f"HTTP/{http_version}",
                "http_status": status_code,
                "host": host,
                "user_agent": user_agent,
                "client_ip": client_ip,
                "request_id": req_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "duration_ms": round(duration_ms, 3),
                "response_bytes": response_bytes,
                "request_headers": safe_req_headers,
                "response_headers": safe_resp_headers,
            }

            if request_body_sample is not None:
                log_payload["request_body_sample"] = request_body_sample
            if response_body_sample is not None:
                log_payload["response_body_sample"] = response_body_sample

            # user_id (если установлен где-то ранее в пайплайне)
            user_id = scope.get("state", {}).get("user_id") if isinstance(scope.get("state"), dict) else None
            if user_id is not None:
                log_payload["user_id"] = str(user_id)

            # Логируем
            try:
                self.logger.log(level, "access", extra=log_payload)
            except Exception:  # защита от падения логирования
                # Последний шанс: минимальный лог
                self.logger.log(level, "access", extra={"http_method": method, "http_path": path, "http_status": status_code})

            # Возвращаем контекстные переменные в прежнее состояние
            cv_request_id.reset(token_rid)
            cv_trace_id.reset(token_tid)
            cv_span_id.reset(token_sid)

    # -------------------------- helpers --------------------------

    @staticmethod
    def _header(headers: List[Tuple[bytes, bytes]], name: bytes) -> str:
        lname = name.lower()
        for k, v in headers:
            if k.lower() == lname:
                return v.decode("latin-1")
        return ""

    @staticmethod
    def _request_id_from_headers(headers: List[Tuple[bytes, bytes]]) -> Optional[str]:
        for k, v in headers:
            if k.lower() == b"x-request-id":
                rid = v.decode("latin-1").strip()
                if rid:
                    return rid
        return None

    async def _drain_body(self, receive: Receive, hard_limit: int) -> bytes:
        """
        Считывает ВСЁ тело запроса (до hard_limit) в память, чтобы затем проиграть его приложению.
        Если размер превысил hard_limit — прекращаем логирование тела и пропускаем поток дальше без буферизации.
        """
        body_chunks: List[bytes] = []
        total = 0

        while True:
            message = await receive()
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"") or b""
            if chunk:
                total += len(chunk)
                if total <= hard_limit:
                    body_chunks.append(chunk)
            if not message.get("more_body", False):
                break

            # Не блокируем цикл событий
            if total > hard_limit:
                # Дочитываем остаток, но больше не накапливаем
                continue

        return b"".join(body_chunks)

    @staticmethod
    def _replay_body(body: bytes) -> Receive:
        """
        Возвращает новый receive, который отдает ранее считанное тело (1-2 фрейма).
        """
        sent = False

        async def _receive() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        return _receive

    def _prepare_body_sample(self, body: bytes, ct: str, limit: int) -> Any:
        """
        Возвращает отредактированный и ограниченный сэмпл тела: JSON (dict/list) или строка.
        """
        if not body:
            return None
        sample = body[:limit]
        if _starts_with_any(ct, ("application/json", "application/problem+json")):
            parsed = _maybe_json(sample)
            if parsed is None:
                return _redact_text(sample.decode("utf-8", errors="ignore"))
            return _redact_json(parsed)
        # Текстовые типы
        if _starts_with_any(ct, ("text/plain", "text/")):
            return _redact_text(sample.decode("utf-8", errors="ignore"))
        # Бинарные/иные — только длина и сигнатура
        return {"bytes_sampled": len(sample), "hex_prefix": sample[:32].hex()}


# -----------------------------------------------------------------------------
# Установщик (удобный хелпер)
# -----------------------------------------------------------------------------
def setup_access_logging_middleware(app: ASGIApp, config: Optional[AccessLogConfig] = None) -> ASGIApp:
    """
    Оборачивает ASGI-приложение middleware-ом access-логирования.
    Пример (FastAPI):
        app = FastAPI()
        app.add_middleware(  # type: ignore[attr-defined]
            AccessLoggingMiddleware,
            config=AccessLogConfig(),
        )
    Или:
        app = setup_access_logging_middleware(app, AccessLogConfig())
    """
    return AccessLoggingMiddleware(app, config=config or AccessLogConfig())


# -----------------------------------------------------------------------------
# Экспортируемое имя для add_middleware(FastAPI)
# -----------------------------------------------------------------------------
__all__ = [
    "AccessLoggingMiddleware",
    "AccessLogConfig",
    "setup_access_logging_middleware",
    "cv_request_id",
    "cv_trace_id",
    "cv_span_id",
]
