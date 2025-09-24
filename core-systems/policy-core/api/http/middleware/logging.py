# policy-core/api/http/middleware/logging.py
# Структурированное access-логирование для FastAPI/Starlette.
# Особенности:
# - Корреляция: X-Request-Id (принимаем/генерируем), traceparent (если есть)
# - Семплинг логов тела: по вероятности и при ошибках (>=500)
# - Безопасность: редактирование PII (email/phone/card/IBAN/SSN/SE-personnummer/ETH/TON) в теле и query
# - Ограничения: типы контента и лимиты размера; не ломает streaming
# - Метрики: время выполнения, байты запроса/ответа, статус
# - Интеграция с OpenTelemetry (если установлен) — без обязательств
# I cannot verify this.

from __future__ import annotations

import contextvars
import os
import re
import time
import typing as t
import uuid
import random

try:
    import structlog  # type: ignore
except Exception:  # pragma: no cover
    # Минимальный шим, если structlog не сконфигурирован.
    import logging as _logging

    class _ShimLogger:
        def __init__(self, name: str = "policy_core.http"):
            self._l = _logging.getLogger(name)

        def bind(self, **kw):
            return self

        def info(self, msg: str, **kw):
            self._l.info("%s | %s", msg, kw)

        def warning(self, msg: str, **kw):
            self._l.warning("%s | %s", msg, kw)

        def error(self, msg: str, **kw):
            self._l.error("%s | %s", msg, kw, exc_info=kw.pop("exc_info", None))

    class structlog:  # type: ignore
        @staticmethod
        def get_logger(name: str = "policy_core.http"):
            return _ShimLogger(name)

from starlette.types import ASGIApp, Scope, Receive, Send, Message

try:
    from opentelemetry import trace as _otel_trace  # type: ignore
except Exception:  # pragma: no cover
    _otel_trace = None  # type: ignore

# -------------------------- Публичный API --------------------------

__all__ = [
    "LoggingMiddleware",
    "get_request_id",
    "set_request_id",
]

_request_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    """Текущий request-id из контекста (или None)."""
    return _request_id_ctx.get()


def set_request_id(value: str | None) -> None:
    """Явно установить request-id в контексте."""
    _request_id_ctx.set(value)


# -------------------------- Утилиты --------------------------

_PII_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PII_PHONE = re.compile(r"\+?[0-9][0-9()\-\s]{6,}[0-9]")
_PII_CARD = re.compile(r"\b(?:\d[ -]*?){12,19}\b")
_PII_IBAN = re.compile(r"(?i)\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")
_PII_SSN_US = re.compile(r"\b(?!000|666)[0-8]\d{2}-?(?!00)\d{2}-?(?!0000)\d{4}\b")
_PII_SE_PNR = re.compile(r"\b\d{6,8}[-+]\d{4}\b")
_PII_ETH = re.compile(r"(?i)\b0x[0-9a-f]{40}\b")
_PII_TON = re.compile(r"\b(?:ton:[A-Za-z0-9_-]{48,}|[EQ0Q][A-Za-z0-9_-]{47,})\b")

_DEFAULT_PII_PATTERNS = [
    _PII_EMAIL,
    _PII_PHONE,
    _PII_CARD,
    _PII_IBAN,
    _PII_SSN_US,
    _PII_SE_PNR,
    _PII_ETH,
    _PII_TON,
]


def _redact(text: str, mask: str = "*", patterns: list[re.Pattern[str]] | None = None) -> str:
    patterns = patterns or _DEFAULT_PII_PATTERNS
    out = text
    for p in patterns:
        out = p.sub(lambda m: _mask(m.group(0), mask), out)
    return out


def _mask(s: str, mask: str = "*", keep: int = 3) -> str:
    keep = min(keep, len(s))
    return s[:keep] + mask * (len(s) - keep)


def _hdr(headers: list[tuple[bytes, bytes]], key: str) -> str | None:
    k = key.lower().encode("latin-1")
    for hk, hv in headers:
        if hk.lower() == k:
            try:
                return hv.decode("latin-1")
            except Exception:
                return None
    return None


def _parse_ct(headers: list[tuple[bytes, bytes]]) -> tuple[str, str]:
    """Возвращает (mime, charset); mime пустой при отсутствии."""
    ct = _hdr(headers, "content-type") or ""
    parts = [p.strip() for p in ct.split(";") if p.strip()]
    mime = parts[0].lower() if parts else ""
    charset = "utf-8"
    for p in parts[1:]:
        if p.lower().startswith("charset="):
            charset = p.split("=", 1)[1].strip()
            break
    return mime, charset


def _client_ip(scope: Scope, headers: list[tuple[bytes, bytes]]) -> str | None:
    xff = _hdr(headers, "x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    xri = _hdr(headers, "x-real-ip")
    if xri:
        return xri.strip()
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and client:
        return str(client[0])
    return None


def _bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "").strip() or default)
    except Exception:
        return default


# -------------------------- Middleware --------------------------

class LoggingMiddleware:
    """
    ASGI middleware для безопасного структурированного логирования.

    Параметры:
      app: ASGI-приложение
      logger_name: имя логгера structlog
      sample_rate: доля запросов для полноценного логирования тела (0..1)
      body_max_bytes: максимум байт тела для логирования (запрос/ответ)
      redact_pii: включить редактирование PII в query/body
      redact_mask: символ маски для редактирования
      log_request_headers: логировать заголовки запросов (безопасные)
      log_response_headers: логировать заголовки ответов (безопасные)
      include_content_types: список MIME, для которых допускается лог тела
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        logger_name: str = "policy_core.http",
        sample_rate: float | None = None,
        body_max_bytes: int = 64 * 1024,
        redact_pii: bool = True,
        redact_mask: str = "*",
        log_request_headers: bool = False,
        log_response_headers: bool = False,
        include_content_types: tuple[str, ...] = (
            "application/json",
            "application/*+json",
            "text/plain",
            "text/*",
        ),
    ) -> None:
        self.app = app
        self.logger = structlog.get_logger(logger_name)
        self.sample_rate = (
            sample_rate if sample_rate is not None else _float_env("LOG_SAMPLE_RATE", 0.05)
        )
        self.body_max_bytes = int(os.getenv("LOG_BODY_MAX_BYTES", str(body_max_bytes)))
        self.redact_pii = _bool_env("LOG_REDACT_PII", redact_pii)
        self.redact_mask = os.getenv("LOG_REDACT_MASK", redact_mask)
        self.log_request_headers = _bool_env("LOG_REQUEST_HEADERS", log_request_headers)
        self.log_response_headers = _bool_env("LOG_RESPONSE_HEADERS", log_response_headers)
        self.include_content_types = include_content_types

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_ns = time.perf_counter_ns()
        headers: list[tuple[bytes, bytes]] = list(scope.get("headers") or [])
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        query_str = (scope.get("query_string") or b"").decode("latin-1")
        ua = _hdr(headers, "user-agent") or ""
        client_ip = _client_ip(scope, headers)

        # Корреляция
        req_id = (_hdr(headers, "x-request-id") or "").strip() or str(uuid.uuid4())
        set_request_id(req_id)

        # Контент-тайп запроса
        req_mime, req_charset = _parse_ct(headers)

        # Захват тела запроса (через обертку receive)
        req_bytes_collected = bytearray()
        req_bytes_total = 0
        req_body_captured = self._is_body_loggable(req_mime)

        async def _recv() -> Message:
            nonlocal req_bytes_total
            message = await receive()
            if message["type"] == "http.request":
                body: bytes = message.get("body", b"")
                req_bytes_total += len(body)
                if req_body_captured and len(req_bytes_collected) < self.body_max_bytes:
                    space = self.body_max_bytes - len(req_bytes_collected)
                    req_bytes_collected.extend(body[:space])
            return message

        # Захват ответа (status/body/headers)
        resp_status: int | None = None
        resp_headers: list[tuple[bytes, bytes]] = []
        resp_bytes_collected = bytearray()
        resp_bytes_total = 0
        resp_mime: str = ""
        resp_charset: str = "utf-8"
        resp_body_captured: bool = False

        async def _send(message: Message) -> None:
            nonlocal resp_status, resp_headers, resp_bytes_total, resp_mime, resp_charset, resp_body_captured
            if message["type"] == "http.response.start":
                resp_status = message["status"]
                resp_headers = list(message.get("headers") or [])
                # Установить/пробросить X-Request-Id
                self._ensure_request_id(resp_headers, req_id)
                # Контент-тайп ответа
                resp_mime, resp_charset = _parse_ct(resp_headers)
                resp_body_captured = self._is_body_loggable(resp_mime)
                # Пропихнуть модифицированные заголовки дальше
                message = {**message, "headers": resp_headers}
            elif message["type"] == "http.response.body":
                body: bytes = message.get("body", b"")
                resp_bytes_total += len(body)
                if resp_body_captured and len(resp_bytes_collected) < self.body_max_bytes:
                    space = self.body_max_bytes - len(resp_bytes_collected)
                    resp_bytes_collected.extend(body[:space])
            await send(message)

        # Логгер с привязкой общих полей
        log = self.logger.bind(
            request_id=req_id,
            method=method,
            path=path,
            client_ip=client_ip,
            user_agent=ua,
        )

        # OTel: добавим атрибуты в текущий спан, если он есть
        if _otel_trace is not None:  # pragma: no cover
            try:
                span = _otel_trace.get_current_span()
                if span and span.get_span_context().is_valid:
                    span.set_attribute("http.method", method)
                    span.set_attribute("http.target", path)
                    if client_ip:
                        span.set_attribute("client.address", client_ip)
                    span.set_attribute("http.request_id", req_id)
            except Exception:
                pass

        # Лог входа (метаданные + query с редактированием)
        safe_query = query_str
        if self.redact_pii and safe_query:
            safe_query = _redact(safe_query, self.redact_mask)

        if self.log_request_headers:
            log.info(
                "http.request.start",
                query=safe_query,
                headers=self._safe_headers(headers),
                content_type=req_mime or None,
            )
        else:
            log.info("http.request.start", query=safe_query, content_type=req_mime or None)

        error: Exception | None = None
        try:
            await self.app(scope, _recv, _send)
        except Exception as exc:  # noqa: BLE001
            error = exc
            resp_status = resp_status or 500
            # Пропускаем исключение после логирования
        finally:
            # Решаем, логировать ли тела полностью
            took_ns = time.perf_counter_ns() - start_ns
            took_ms = round(took_ns / 1_000_000, 2)
            status = int(resp_status or 500)

            # Политика семплинга: всегда при 5xx, иначе по вероятности
            sampled = status >= 500 or (random.random() < max(0.0, min(1.0, self.sample_rate)))

            req_body_text: str | None = None
            resp_body_text: str | None = None

            if sampled:
                if req_body_captured and req_bytes_collected:
                    try:
                        req_body_text = req_bytes_collected.decode(req_charset, errors="replace")
                        if self.redact_pii:
                            req_body_text = _redact(req_body_text, self.redact_mask)
                    except Exception:
                        req_body_text = "<decode-error>"
                if resp_body_captured and resp_bytes_collected:
                    try:
                        resp_body_text = resp_bytes_collected.decode(resp_charset, errors="replace")
                        if self.redact_pii:
                            resp_body_text = _redact(resp_body_text, self.redact_mask)
                    except Exception:
                        resp_body_text = "<decode-error>"

            log_fields: dict[str, t.Any] = dict(
                status=status,
                duration_ms=took_ms,
                bytes_in=req_bytes_total,
                bytes_out=resp_bytes_total,
                sampled=sampled,
                request_content_type=req_mime or None,
                response_content_type=resp_mime or None,
            )

            if self.log_response_headers:
                log_fields["response_headers"] = self._safe_headers(resp_headers)

            if sampled:
                if req_body_text is not None:
                    log_fields["request_body"] = self._bounded_text(req_body_text)
                if resp_body_text is not None:
                    log_fields["response_body"] = self._bounded_text(resp_body_text)

            if error is not None:
                log.error("http.request.end", exc_info=error, **log_fields)
            else:
                log.info("http.request.end", **log_fields)

            # Поднять исключение после логирования
            if error is not None:
                raise error

    # ----------------------- Вспомогательные методы -----------------------

    def _is_body_loggable(self, mime: str) -> bool:
        if not mime:
            return False
        # отклоняем мультимедиа/мультипарт/архивы
        if mime.startswith(("multipart/", "image/", "audio/", "video/")):
            return False
        return any(self._mime_match(mime, allowed) for allowed in self.include_content_types)

    @staticmethod
    def _mime_match(mime: str, pattern: str) -> bool:
        if pattern.endswith("/*"):
            return mime.startswith(pattern[:-1])
        return mime == pattern

    def _ensure_request_id(self, headers: list[tuple[bytes, bytes]], req_id: string := "") -> None:  # type: ignore[valid-type]
        """Добавить X-Request-Id в ответ при его отсутствии."""
        # NOTE: mypy не любит alias 'string'; используем стандартную str
        present = any(hk.lower() == b"x-request-id" for hk, _ in headers)
        if not present and req_id:
            headers.append((b"x-request-id", req_id.encode("latin-1", errors="ignore")))

    def _safe_headers(self, headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
        # Скрываем потенциально опасные заголовки
        deny = {b"authorization", b"cookie", b"set-cookie", b"proxy-authorization"}
        out: dict[str, str] = {}
        for k, v in headers:
            lk = k.lower()
            if lk in deny:
                out[lk.decode()] = "<redacted>"
            else:
                try:
                    out[lk.decode()] = v.decode("latin-1")
                except Exception:
                    out[lk.decode()] = "<decode-error>"
        return out

    def _bounded_text(self, text: str) -> str:
        # Режем текст до self.body_max_bytes с заметкой о тримминге
        b = text.encode("utf-8", errors="ignore")
        if len(b) <= self.body_max_bytes:
            return text
        cut = b[: self.body_max_bytes]
        try:
            s = cut.decode("utf-8", errors="ignore")
        except Exception:
            s = "<decode-error>"
        return f"{s}… [truncated {len(b) - self.body_max_bytes} bytes]"

