# ledger-core/api/http/middleware/logging.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import traceback
import types
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Optional structlog support (falls back to stdlib logging)
try:
    import structlog  # type: ignore
except Exception:  # pragma: no cover
    structlog = None  # type: ignore


# ---------------------------
# Config
# ---------------------------

DEFAULT_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "idempotency-key",
}

DEFAULT_SENSITIVE_JSON_FIELDS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "card",
    "card_number",
    "iban",
    "pan",
    "ssn",
    "cvv",
    "email",
    "phone",
}

HEALTH_PATH_RE = re.compile(r"^/(health|healthz|ready|readiness|live|liveness|metrics)$", re.IGNORECASE)


@dataclass
class AccessLogConfig:
    enabled: bool = True
    redact_headers: Iterable[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_HEADERS)
    redact_json_fields: Iterable[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_JSON_FIELDS)
    request_body_max_bytes: int = 2048
    response_body_max_bytes: int = 2048
    include_request_body: bool = True
    include_response_body: bool = False  # включайте с осторожностью в проде
    # Сэмплирование: 1.0 = логировать всё
    sample_rate: float = 1.0
    # Логи всегда для статусов >= этого порога
    always_log_status_gte: int = 500
    # Подавление шумных путей
    suppress_health_and_metrics: bool = True
    # Таймаут обработки (для метрики и логического ката)
    slow_request_ms_warn: int = 1000
    # Дополнительные маскируемые заголовки (регэкспы)
    header_redact_patterns: Iterable[re.Pattern] = field(default_factory=list)
    # Доп. фильтрация путей (регэкспы), которые логируем пониженно (только итог)
    low_verbosity_paths: Iterable[re.Pattern] = field(default_factory=list)

    @staticmethod
    def from_env(prefix: str = "LEDGER_LOG_") -> "AccessLogConfig":
        def _bool(name: str, default: bool) -> bool:
            return os.getenv(prefix + name, str(default)).lower() in {"1", "true", "yes", "on"}

        def _int(name: str, default: int) -> int:
            try:
                return int(os.getenv(prefix + name, default))
            except Exception:
                return default

        def _float(name: str, default: float) -> float:
            try:
                return float(os.getenv(prefix + name, default))
            except Exception:
                return default

        return AccessLogConfig(
            enabled=_bool("ENABLED", True),
            request_body_max_bytes=_int("REQ_MAX", 2048),
            response_body_max_bytes=_int("RESP_MAX", 2048),
            include_request_body=_bool("INCLUDE_REQUEST_BODY", True),
            include_response_body=_bool("INCLUDE_RESPONSE_BODY", False),
            sample_rate=_float("SAMPLE_RATE", 1.0),
            always_log_status_gte=_int("ALWAYS_STATUS_GTE", 500),
            suppress_health_and_metrics=_bool("SUPPRESS_HEALTH", True),
            slow_request_ms_warn=_int("SLOW_MS_WARN", 1000),
        )


# ---------------------------
# Logger factory
# ---------------------------

def _get_logger() -> Any:
    if structlog:
        return structlog.get_logger("access")
    return logging.getLogger("ledger.access")


def setup_json_logging(level: int = logging.INFO) -> None:
    """
    Минимальная настройка JSON‑логов для stdlib logging.
    Если используется structlog — конфигурируйте отдельно в боевом коде.
    """
    if structlog:
        return  # у structlog обычно есть отдельный конфиг в приложении
    logger = logging.getLogger()
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonLogFormatter())
        logger.addHandler(handler)
    logger.setLevel(level)


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # pragma: no cover - форматирование
        payload = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Подмешиваем extra, если это dict
        if isinstance(getattr(record, "extra", None), dict):
            payload.update(record.extra)  # type: ignore
        # traceback
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


# ---------------------------
# Utils
# ---------------------------

def _gen_request_id() -> str:
    return str(uuid.uuid4())

def _parse_traceparent(value: Optional[str]) -> Tuple[str, str]:
    """
    Возвращает (trace_id, span_id) в hex без префиксов.
    Если нет/битый — сгенерируем.
    """
    try:
        if not value:
            raise ValueError()
        # traceparent: version-traceid-spanid-flags
        parts = value.strip().split("-")
        if len(parts) >= 4 and len(parts[1]) == 32 and len(parts[2]) == 16:
            return parts[1], parts[2]
        raise ValueError()
    except Exception:
        # Сгенерируем валидные 16/8 байт hex
        return uuid.uuid4().hex + uuid.uuid4().hex[:16], uuid.uuid4().hex[:16]

def _redact_headers(headers: Headers, sensitive: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    lower_sensitive = {h.lower() for h in sensitive}
    for k, v in headers.multi_items():
        lk = k.lower()
        if lk in lower_sensitive:
            out[k] = "***"
        else:
            out[k] = v
    return out

def _redact_json(obj: Any, sensitive_fields: Iterable[str], depth: int = 0) -> Any:
    try:
        sens = {s.lower() for s in sensitive_fields}
        if isinstance(obj, dict):
            return {k: ("***" if k.lower() in sens else _redact_json(v, sens, depth + 1)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_redact_json(it, sens, depth + 1) for it in obj]
        return obj
    except Exception:
        return obj


# ---------------------------
# ASGI Middleware
# ---------------------------

class AccessLogMiddleware:
    """
    Структурированное логирование HTTP для ASGI (Starlette/FastAPI).

    Возможности:
      - Корреляция: заголовки X-Request-ID (создание при отсутствии), W3C traceparent
      - Редакция чувствительных заголовков и JSON‑полей
      - Лимитированный захват тела запроса/ответа (байт) без поломки пайплайна
      - Сэмплирование и подавление шумных endpoint'ов (health/metrics)
      - Метрики: latency_ms, bytes_in, bytes_out, status, method, path, client_ip, ua
      - Устойчивость к исключениям (лог + повторное пробрасывание)

    Добавляет X-Request-ID в ответ.
    """

    def __init__(self, app: ASGIApp, config: Optional[AccessLogConfig] = None) -> None:
        self.app = app
        self.cfg = config or AccessLogConfig.from_env()
        self.logger = _get_logger()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.cfg.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_ns = time.perf_counter_ns()
        req_headers = Headers(scope=scope)
        method: str = scope.get("method", "-")
        path: str = scope.get("path", "-")
        client = scope.get("client")
        client_ip = client[0] if isinstance(client, (list, tuple)) and client else "-"
        ua = req_headers.get("user-agent", "-")

        # корреляция
        request_id = req_headers.get("x-request-id") or _gen_request_id()
        trace_id, span_id = _parse_traceparent(req_headers.get("traceparent"))
        # подменим заголовок в запросе (для downstream)
        scoped_headers = MutableHeaders(raw=list(req_headers.raw))
        scoped_headers["x-request-id"] = request_id
        scoped_headers["traceparent"] = f"00-{trace_id}-{span_id}-01"
        scope["headers"] = scoped_headers.raw

        # захват тела запроса (до лимита)
        body_chunks: List[bytes] = []
        bytes_in = 0

        async def _recv() -> Message:
            nonlocal bytes_in
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                if chunk:
                    bytes_in += len(chunk)
                    if self.cfg.include_request_body and sum(len(c) for c in body_chunks) < self.cfg.request_body_max_bytes:
                        body_chunks.append(chunk)
                if not message.get("more_body", False):
                    # завершение
                    pass
            return message

        # перехват ответа для измерения и (опц.) тела
        resp_headers: MutableHeaders = MutableHeaders()
        status_code: int = 500
        bytes_out = 0
        response_body_buf: List[bytes] = []

        async def _send(message: Message) -> None:
            nonlocal status_code, bytes_out, resp_headers
            if message["type"] == "http.response.start":
                status_code = message["status"]
                resp_headers = MutableHeaders(scope=message)
                resp_headers["X-Request-ID"] = request_id
                # Встраиваем traceparent дальше (с новым span_id могли бы создать)
                resp_headers.setdefault("traceparent", f"00-{trace_id}-{span_id}-01")
                await send(message)
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                if body:
                    bytes_out += len(body)
                    if self.cfg.include_response_body and sum(len(b) for b in response_body_buf) < self.cfg.response_body_max_bytes:
                        response_body_buf.append(body)
                await send(message)
            else:
                await send(message)

        # быстрый bail‑out для health/metrics
        if self.cfg.suppress_health_and_metrics and HEALTH_PATH_RE.match(path):
            try:
                await self.app(scope, _recv, _send)
            finally:
                # минимальный лог на debug
                self._log(
                    level="DEBUG",
                    msg="health_access",
                    base={
                        "http.method": method,
                        "http.path": path,
                        "http.status": status_code,
                        "net.peer_ip": client_ip,
                        "http.user_agent": ua,
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "duration_ms": (time.perf_counter_ns() - start_ns) / 1e6,
                    },
                )
            return

        # основной обработчик с защитой от исключений
        exc_info: Optional[Tuple[type, BaseException, Any]] = None
        try:
            await self.app(scope, _recv, _send)
        except BaseException as e:
            exc_info = (type(e), e, e.__traceback__)
            # гарантируем старт ответа, если апп не сделал этого
            if status_code == 500:
                # попытаемся отправить 500, если ещё не отправляли заголовки
                try:
                    await _send({"type": "http.response.start", "status": 500, "headers": []})  # type: ignore
                    await _send({"type": "http.response.body", "body": b"", "more_body": False})  # type: ignore
                except Exception:
                    pass  # уже отправлено
            raise
        finally:
            end_ns = time.perf_counter_ns()
            duration_ms = (end_ns - start_ns) / 1e6
            level = "INFO"
            if status_code >= self.cfg.always_log_status_gte or exc_info:
                level = "ERROR"
            elif duration_ms >= self.cfg.slow_request_ms_warn:
                level = "WARNING"

            # sampling
            if not _should_log(self.cfg.sample_rate) and level == "INFO":
                return

            # заголовки (редактируем)
            redacted_req_headers = _redact_headers(Headers(scope=scope), self.cfg.redact_headers)
            redacted_resp_headers = _redact_headers(Headers(raw=resp_headers.raw), self.cfg.redact_headers)

            # тело запроса (попытка распарсить JSON для редактирования)
            req_body_snippet = None
            if self.cfg.include_request_body and body_chunks:
                req_body_bytes = b"".join(body_chunks)[: self.cfg.request_body_max_bytes]
                req_body_snippet = _best_effort_redacted_body(req_body_bytes, self.cfg.redact_json_fields)

            resp_body_snippet = None
            if self.cfg.include_response_body and response_body_buf:
                resp_body_bytes = b"".join(response_body_buf)[: self.cfg.response_body_max_bytes]
                resp_body_snippet = _best_effort_redacted_body(resp_body_bytes, self.cfg.redact_json_fields)

            base = {
                "http.method": method,
                "http.path": path,
                "http.status": status_code,
                "http.request.headers": redacted_req_headers,
                "http.response.headers": redacted_resp_headers,
                "http.request.body": req_body_snippet,
                "http.response.body": resp_body_snippet,
                "net.peer_ip": client_ip,
                "http.user_agent": ua,
                "http.bytes_in": bytes_in,
                "http.bytes_out": bytes_out,
                "duration_ms": round(duration_ms, 3),
                "request_id": request_id,
                "trace_id": trace_id,
                "span_id": span_id,
            }

            if exc_info:
                self._log(level="ERROR", msg="http_request_error", base=base, exc_info=exc_info)
            else:
                self._log(level=level, msg="http_request", base=base)

    # -----------------------
    # Logging sink (structlog or stdlib)
    # -----------------------
    def _log(
        self,
        *,
        level: str,
        msg: str,
        base: Mapping[str, Any],
        exc_info: Optional[Tuple[type, BaseException, Any]] = None,
    ) -> None:
        if structlog:
            logger = self.logger.bind(**base)  # type: ignore
            if exc_info:
                logger = logger.bind(exc="".join(traceback.format_exception(*exc_info)))
            getattr(logger, level.lower())(msg)
        else:
            log = logging.getLogger("ledger.access")
            fn = getattr(log, level.lower())
            # stdlib JSON форматер из setup_json_logging возьмёт record.extra
            fn(msg, extra={"extra": dict(base)})


def _best_effort_redacted_body(raw: bytes, sensitive_fields: Iterable[str]) -> Any:
    # Пытаемся распарсить JSON, иначе возвращаем текстовый сниппет
    try:
        txt = raw.decode("utf-8", errors="replace")
        obj = json.loads(txt)
        return _redact_json(obj, sensitive_fields)
    except Exception:
        # Вернём первые 2 KiB безопасно
        return raw[:2048].decode("utf-8", errors="replace")


def _should_log(rate: float) -> bool:
    if rate >= 1.0:
        return True
    # простое детерминированное сэмплирование по времени
    return (time.time_ns() % 1000) / 1000.0 < max(0.0, rate)


# ---------------------------
# Public helpers
# ---------------------------

def install_access_log_middleware(app, config: Optional[AccessLogConfig] = None) -> None:
    """
    Удобный хелпер для FastAPI/Starlette:
        from ledger_core.api.http.middleware.logging import install_access_log_middleware, setup_json_logging
        setup_json_logging()
        install_access_log_middleware(app)
    """
    app.add_middleware(AccessLogMiddleware, config=config)


# ---------------------------
# Example (manual run)
# ---------------------------

if __name__ == "__main__":  # pragma: no cover
    # Мини‑пример интеграции с FastAPI
    try:
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        setup_json_logging()
        app = FastAPI()
        install_access_log_middleware(app)

        @app.get("/healthz")
        async def healthz():
            return {"status": "ok"}

        @app.post("/echo")
        async def echo(data: Dict[str, Any]):
            return JSONResponse({"ok": True, "data": data})

        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=8080)
    except Exception:
        print("Run inside an environment with FastAPI/uvicorn to try demo.")
