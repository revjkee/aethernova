# observability/dashboards/middlewares/exception_middleware.py

import logging
import traceback
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from observability.dashboards.middlewares.context_injector import set_context, clear_context
from observability.clients.sentry_client import capture_exception as capture_sentry
from observability.clients.prometheus_exporter import increment_error_metric


logger = logging.getLogger("exception")


class ExceptionMiddleware(BaseHTTPMiddleware):
    """
    Middleware для глобального перехвата исключений в FastAPI.
    Обогащает лог контекстом и отправляет в observability-систему.
    """

    async def dispatch(self, request: Request, call_next):
        try:
            # Пример передачи trace_id из заголовков (можно адаптировать)
            trace_id = request.headers.get("x-trace-id")
            user_id = request.headers.get("x-user-id")
            set_context(trace_id=trace_id, user_id=user_id)

            response = await call_next(request)
            return response

        except Exception as exc:
            # Обогащённое логирование
            logger.error("Unhandled Exception", exc_info=True, extra={
                "trace_id": trace_id,
                "user_id": user_id,
                "path": request.url.path,
                "method": request.method
            })

            # SIEM + APM
            capture_sentry(exc)
            increment_error_metric("unhandled_exception")

            return JSONResponse(
                status_code=500,
                content={"detail": "Internal Server Error"}
            )

        finally:
            clear_context()
