# autopwn-framework/logging/ueba/decorators/retry_logger.py

import logging
import time
import functools
import traceback
from datetime import datetime
from uuid import uuid4

from config.settings import LOGGING_RETRY_COUNT, LOGGING_RETRY_BACKOFF
from core.kafka.kafka_producer import KafkaLogProducer
from core.ueba.threat_labels import classify_log_event

kafka_producer = KafkaLogProducer()
logger = logging.getLogger("autopwn.retry_logger")

def retry_logger(module: str = "generic", severity: str = "info", kafka_topic: str = "logging.events"):
    """
    Декоратор с автоматическим повтором логирования в случае сбоев.
    Также классифицирует событие UEBA и отправляет в Kafka.
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            retries = 0
            while retries <= LOGGING_RETRY_COUNT:
                try:
                    result = await func(*args, **kwargs)

                    log_event = {
                        "id": str(uuid4()),
                        "timestamp": datetime.utcnow().isoformat(),
                        "module": module,
                        "severity": severity,
                        "function": func.__name__,
                        "args": str(args),
                        "kwargs": str(kwargs),
                        "result": str(result),
                        "ueba_tag": classify_log_event(module, severity, str(result)),
                        "retry_count": retries,
                        "status": "success"
                    }

                    kafka_producer.send(topic=kafka_topic, value=log_event)
                    return result

                except Exception as e:
                    retries += 1
                    backoff_time = LOGGING_RETRY_BACKOFF * retries
                    error_trace = traceback.format_exc()

                    log_event = {
                        "id": str(uuid4()),
                        "timestamp": datetime.utcnow().isoformat(),
                        "module": module,
                        "severity": "error",
                        "function": func.__name__,
                        "args": str(args),
                        "kwargs": str(kwargs),
                        "error": str(e),
                        "traceback": error_trace,
                        "ueba_tag": classify_log_event(module, "error", str(e)),
                        "retry_count": retries,
                        "status": "retrying" if retries <= LOGGING_RETRY_COUNT else "failed"
                    }

                    kafka_producer.send(topic=kafka_topic, value=log_event)
                    logger.warning(f"[{module}] Retry {retries}/{LOGGING_RETRY_COUNT} after exception: {e}")

                    if retries > LOGGING_RETRY_COUNT:
                        logger.error(f"[{module}] Failed after {retries} retries: {e}")
                        raise e
                    time.sleep(backoff_time)

        return wrapper

    return decorator
