#!/usr/bin/env python3

import os, sys, logging
from graph_core.bootstrap.schema_loader import load_base_schemas
from graph_core.bootstrap.node_initializer import create_initial_nodes
from graph_core.bootstrap.edge_mapper import load_edge_mappings
from graph_core.engine.runtime import start_graph_runtime
from ai_core.telemetry.logger import log_boot_event
from infrastructure.health.neo4j_checker import check_neo4j_connection

logging.basicConfig(level=logging.INFO, format="%(asctime)s [GRAPH-CORE] %(message)s")
logger = logging.getLogger("bootstrap_graph_core")

REQUIRED_ENV = ["GRAPH_DB_URL", "GRAPH_RUNTIME_MODE"]

def check_env():
    logger.info("Проверка переменных окружения...")
    missing = [v for v in REQUIRED_ENV if not os.getenv(v)]
    if missing:
        logger.critical(f"Отсутствуют переменные: {missing}")
        sys.exit(1)

def check_dependencies():
    logger.info("Проверка подключения к базе графа...")
    check_neo4j_connection(os.getenv("GRAPH_DB_URL"))

def bootstrap_graph():
    logger.info("Инициализация базовых схем...")
    load_base_schemas()
    logger.info("Создание корневых узлов...")
    create_initial_nodes()
    logger.info("Загрузка связей и мапперов...")
    load_edge_mappings()
    logger.info("Графовая модель успешно загружена")

def start_runtime():
    mode = os.getenv("GRAPH_RUNTIME_MODE", "local")
    logger.info(f"Запуск runtime в режиме: {mode}")
    start_graph_runtime(mode=mode)

def main():
    logger.info("==> ЗАПУСК GRAPH CORE TESLAAI <==")
    check_env()
    check_dependencies()
    bootstrap_graph()
    start_runtime()
    log_boot_event("graph_core_bootstrap_success")

if __name__ == "__main__":
    main()
