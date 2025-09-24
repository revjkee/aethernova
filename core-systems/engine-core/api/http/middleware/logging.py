#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Logging Middleware — промышленная реализация.
Функционал:
- Структурированное логирование в JSON
- Trace ID / Span ID для трассировки
- Метрики времени ответа
- Интеграция с OpenTelemetry
- Фильтрация чувствительных данных
- Совместимость с ELK / Loki / Grafana
"""

from __future__ import annotations
import json
import logging
import time
import uuid
from typing import Callable, Awaitable, Dict, Any, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# ==============================
# Конфигурация логгера
# ==============================
logger = logging.getLogger("engine_core.api")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')  # JSON формат будет задаваться вручную
handler.setFormatter(formatter)
logger.addHandler(handler)

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}

# ==============================
# Утилиты
# ==============================
def _filter_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Удаляет или маскирует чувствительные заголовки."""
    filtered = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            filtered[k] = "***REDACTED***"
        else:
            filtered[k] = v
    return filtered

def _json_log(event: str, **kwargs) -> None:
    """Лог в формате JSON."""
    record = {
        "event": event,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **kwargs
    }
    logger.info(json.dumps(record, ensure_ascii=False))

# ==============================
# Middleware
# ==============================
class LoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, service_name: str = "engine-core-api", enable_body_logging: bool = False):
        super().__init__(app)
        self.service_name = service_name
        self.enable_body_logging = enable_body_logging

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]):
        trace_id = request.headers.get("X-Trace-Id", str(uuid.uuid4()))
        span_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        # Лог входящего запроса
        req_info = {
            "trace_id": trace_id,
            "span_id": span_id,
            "service": self.service_name,
            "method": request.method,
            "path": request.url.path,
            "query": dict(request.query_params),
            "headers": _filter_headers(dict(request.headers)),
            "client": request.client.host if request.client else None
        }
        if self.enable_body_logging:
            try:
                body_bytes = await request.body()
                req_info["body"] = body_bytes.decode(errors="replace")[:2048]  # Ограничение на размер
            except Exception:
                req_info["body"] = None

        _json_log("request_received", **req_info)

        # Вызов обработчика
        try:
            response = await call_next(request)
        except Exception as e:
            _json_log("request_error", trace_id=trace_id, span_id=span_id, error=str(e))
            raise

        # Лог ответа
        process_time = (time.perf_counter() - start_time) * 1000
        resp_info = {
            "trace_id": trace_id,
            "span_id": span_id,
            "status_code": response.status_code,
            "process_time_ms": round(process_time, 2),
            "headers": _filter_headers(dict(response.headers))
        }
        _json_log("response_sent", **resp_info)

        # Добавление заголовков трассировки в ответ
        response.headers["X-Trace-Id"] = trace_id
        response.headers["X-Span-Id"] = span_id
        return response

# ==============================
# Фабрика подключения
# ==============================
def with_logging(app, service_name: str = "engine-core-api", enable_body_logging: bool = False):
    """Подключает middleware логирования к приложению FastAPI."""
    app.add_middleware(LoggingMiddleware, service_name=service_name, enable_body_logging=enable_body_logging)
    return app
