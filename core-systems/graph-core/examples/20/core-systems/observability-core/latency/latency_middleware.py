import time
import uuid
import logging
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp
from .latency_event import LatencyEvent

logger = logging.getLogger("latency.middleware")

class LatencyMiddleware(BaseHTTPMiddleware):
    """
    Middleware для измерения и логгирования latency каждого HTTP-запроса.
    Создаёт LatencyEvent с trace_id, route, временем и дополнительными метками.
    """

    def __init__(self, app: ASGIApp, log_level: int = logging.DEBUG):
        super().__init__(app)
        self.log_level = log_level

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        route = request.url.path
        method = request.method
        trace_id = str(uuid.uuid4())

        event = LatencyEvent(
            name=f"{method} {route}",
            metadata={
                "method": method,
                "path": route,
                "client": request.client.host if request.client else None,
                "trace_id": trace_id,
                "headers": {
                    "user-agent": request.headers.get("user-agent"),
                    "content-type": request.headers.get("content-type")
                }
            }
        )

        try:
            response = await call_next(request)
            return response
        finally:
            event.stop()
            logger.log(self.log_level, f"[LATENCY] {event.to_json()}")

            # Пример расширения:
            # send_to_prometheus(event)
            # send_to_otlp(event)
            # append_to_buffer(event)
