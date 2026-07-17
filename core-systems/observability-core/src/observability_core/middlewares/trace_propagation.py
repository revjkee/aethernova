# observability/dashboards/middlewares/trace_propagation.py

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .context_injector import clear_context, set_context


class TracePropagationMiddleware(BaseHTTPMiddleware):
    """
    Middleware для генерации и передачи trace_id и span_id.
    Совместим с OpenTelemetry, X-Trace-ID, Cloud headers.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        trace_id = request.headers.get("x-trace-id") or uuid.uuid4().hex
        span_id = uuid.uuid4().hex[:16]

        set_context(trace_id=trace_id, span_id=span_id)

        try:
            response = await call_next(request)
            response.headers["x-trace-id"] = trace_id
            response.headers["x-span-id"] = span_id
            return response
        finally:
            clear_context()
