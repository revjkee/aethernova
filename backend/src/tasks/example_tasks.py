from src.tasks.celery_app import app
import logging
import asyncio

logger = logging.getLogger(__name__)

@app.task(bind=True, max_retries=3, default_retry_delay=60)
def sample_task(self, data):
    """
    Пример синхронной задачи Celery.
    Выполняет простую обработку данных.
    """
    try:
        # Имитация обработки
        result = f"Обработаны данные: {data}"
        logger.info(result)
        return result
    except Exception as exc:
        logger.error(f"Ошибка в sample_task: {exc}")
        raise self.retry(exc=exc)

@app.task(bind=True)
async def async_task(self, param):
    """
    Пример асинхронной задачи, если используется Celery с поддержкой async.
    """
    try:
        await asyncio.sleep(1)  # Имитация async операции
        return f"Async обработка параметра: {param}"
    except Exception as exc:
        logger.error(f"Ошибка в async_task: {exc}")
        raise self.retry(exc=exc)
