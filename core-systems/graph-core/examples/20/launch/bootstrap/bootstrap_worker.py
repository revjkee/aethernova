#!/usr/bin/env python3

import os, sys, logging
from core.worker.queue_initializer import init_queues
from core.worker.task_registry import register_all_tasks
from core.telemetry.launch_log import log_event
from ai_core.orchestrator import start_worker_pool
from infrastructure.health.rabbitmq_checker import check_rabbitmq
from infrastructure.health.redis_checker import check_redis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [WORKER] %(message)s")
logger = logging.getLogger("bootstrap_worker")

REQUIRED_ENV_VARS = ["QUEUE_BACKEND", "REDIS_URL", "RABBITMQ_URL"]

def check_env():
    logger.info("Проверка переменных окружения...")
    missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
    if missing:
        logger.critical(f"Отсутствуют переменные: {missing}")
        sys.exit(1)

def check_dependencies():
    backend = os.getenv("QUEUE_BACKEND")
    logger.info(f"Выбран QUEUE_BACKEND: {backend}")
    if backend == "rabbitmq":
        check_rabbitmq(os.getenv("RABBITMQ_URL"))
    elif backend == "redis":
        check_redis(os.getenv("REDIS_URL"))
    else:
        logger.critical(f"Неизвестный QUEUE_BACKEND: {backend}")
        sys.exit(1)

def bootstrap():
    logger.info("Инициализация очередей и задач...")
    init_queues()
    register_all_tasks()
    logger.info("Запуск пула воркеров...")
    start_worker_pool(max_workers=4)
    log_event("worker_bootstrap_success")
    logger.info("Воркеры успешно активированы.")

def main():
    logger.info("==> ЗАПУСК TESLAAI WORKER SYSTEM <==")
    check_env()
    check_dependencies()
    bootstrap()

if __name__ == "__main__":
    main()
