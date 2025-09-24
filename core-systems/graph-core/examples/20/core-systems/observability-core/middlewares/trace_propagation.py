# observability/dashboards/middlewares/trace_propagation.py

import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from observability.dashboards.middlewares.context_injector import set_context


class TracePropagationMiddleware(BaseHTTPMiddleware):
    """
    Middleware для генерации и передачи trace_id и span_id.
    Совместим с OpenTelemetry, X-Trace-ID, Cloud headers.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        trace_id = request.headers.get("x-trace-id") or str(uuid.uuid4())
        span_id = str(uuid.uuid4())

        set_context(trace_id=trace_id, span_id=span_id)

        response = await call_next(request)
        response.headers["x-trace-id"] = trace_id
        response.headers["x-span-id"] = span_id
        return response
