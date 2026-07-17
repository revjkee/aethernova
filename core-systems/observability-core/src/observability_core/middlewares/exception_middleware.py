# observability/dashboards/middlewares/exception_middleware.py

import logging

from prometheus_client import Counter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .context_injector import clear_context, set_context

logger = logging.getLogger("exception")
UNHANDLED_ERRORS = Counter(
    "aethernova_observability_unhandled_errors_total",
    "Unhandled exceptions captured by Observability Core middleware",
    ["exception_type"],
)


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
            logger.error(
                "Unhandled Exception",
                exc_info=True,
                extra={
                    "trace_id": trace_id,
                    "user_id": user_id,
                    "path": request.url.path,
                    "method": request.method,
                },
            )

            UNHANDLED_ERRORS.labels(type(exc).__name__).inc()

            return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})

        finally:
            clear_context()
