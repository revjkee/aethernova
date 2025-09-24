import os
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Optional

import redis
import pika
import requests

# Конфигурация логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [fallback-alert]: %(message)s'
)

# ENV-переменные
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
ALERTMANAGER_ENDPOINT = os.getenv("ALERTMANAGER_ENDPOINT", "http://alertmanager:9093/api/v2/alerts")
QUEUE_NAME = os.getenv("FALLBACK_QUEUE", "alert-fallback-queue")
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "5"))
RETRY_DELAY = int(os.getenv("RETRY_DELAY_SECONDS", "10"))

# Инициализация клиентов
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def publish_to_rabbitmq(message: dict):
    connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    channel.basic_publish(
        exchange='',
        routing_key=QUEUE_NAME,
        body=json.dumps(message),
        properties=pika.BasicProperties(
            delivery_mode=2  # persistent
        )
    )
    connection.close()
    logging.info("Сообщение отправлено в резервную очередь RabbitMQ.")

def persist_to_redis(alert: dict):
    key = f"alert:{uuid.uuid4()}"
    redis_client.setex(key, 3600, json.dumps(alert))  # TTL: 1 час
    logging.info(f"Алерт сохранён в Redis под ключом: {key}")

def send_to_alertmanager(alert: dict) -> bool:
    try:
        response = requests.post(ALERTMANAGER_ENDPOINT, json=[alert], timeout=5)
        if response.status_code == 200:
            logging.info("Алерт успешно доставлен в Alertmanager.")
            return True
        logging.warning(f"Alertmanager вернул статус: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка при отправке в Alertmanager: {e}")
    return False

def route_alert(alert: dict):
    success = False
    for attempt in range(1, MAX_RETRIES + 1):
        logging.info(f"Попытка {attempt} отправить алерт...")
        success = send_to_alertmanager(alert)
        if success:
            return
        time.sleep(RETRY_DELAY)

    logging.warning("Все попытки отправки неудачны. Сохраняем в резерв.")
    persist_to_redis(alert)
    publish_to_rabbitmq(alert)

def create_alert(summary: str, description: str, severity: str = "critical", source: Optional[str] = None) -> dict:
    return {
        "labels": {
            "alertname": "FallbackAlerter",
            "severity": severity,
            "source": source or "undefined",
        },
        "annotations": {
            "summary": summary,
            "description": description,
        },
        "startsAt": datetime.utcnow().isoformat() + "Z"
    }

if __name__ == "__main__":
    test_alert = create_alert(
        summary="Тестовый алерт отказоустойчивости",
        description="Этот алерт сгенерирован fallback-механизмом.",
        severity="warning",
        source="fallback-test"
    )
    route_alert(test_alert)
