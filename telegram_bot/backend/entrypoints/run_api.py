import uvicorn
import logging

from backend.core.settings import settings
from api.v1.bookings import router as bookings_router
from api.v1.masters import router as masters_router
from api.v1.timeslots import router as timeslots_router
from fastapi import FastAPI
from backend.core.logging_config import setup_logging

setup_logging()
logger = logging.getLogger("bot")  # или "api", "worker"

logger = logging.getLogger("run_api")


def create_app() -> FastAPI:
    """
    Создает и конфигурирует FastAPI приложение с роутерами API v1.
    """
    app = FastAPI(
        title="Client Booking API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Регистрируем роутеры API
    app.include_router(bookings_router, prefix="/api/v1/bookings", tags=["bookings"])
    app.include_router(masters_router, prefix="/api/v1/masters", tags=["masters"])
    app.include_router(timeslots_router, prefix="/api/v1/timeslots", tags=["timeslots"])

    return app


def main():
    """
    Запускает FastAPI приложение через uvicorn.
    """
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting FastAPI server on %s:%d", settings.api_host, settings.api_port)

    app = create_app()

    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
        reload=settings.debug,
        workers=1,  # для дебага, на продакшене можно поднять
    )


if __name__ == "__main__":
    main()
