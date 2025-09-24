#!/usr/bin/env python3

import os
import sys
import json
import logging
from subprocess import run, CalledProcessError
from pathlib import Path

from core.ai_kernel import AICoreEngine
from core.security.integrity import verify_integrity_hash
from core.telemetry.launch_log import log_event
from core.config_loader import load_runtime_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [AI-CORE] %(message)s")
logger = logging.getLogger(__name__)

LAUNCH_STATE_PATH = "/var/lib/teslaai/ai_core_launch_state.json"
REQUIRED_ENV_VARS = ["OPENAI_API_KEY", "GENESIS_MODE", "RBAC_ENABLED", "JAILKEEPER_ON"]

def check_env():
    logger.info("Проверка переменных окружения...")
    missing = [v for v in REQUIRED_ENV_VARS if not os.getenv(v)]
    if missing:
        logger.error(f"Отсутствуют переменные окружения: {missing}")
        sys.exit(1)

def validate_integrity():
    logger.info("Проверка целостности ядра...")
    if not verify_integrity_hash("ai-core"):
        logger.critical("Целостность AI ядра нарушена. Прерывание запуска.")
        sys.exit(1)

def launch_ai_kernel():
    logger.info("Запуск ядра TeslaAI...")
    config = load_runtime_config(profile="production")
    engine = AICoreEngine(config=config)
    engine.initialize()
    engine.warmup()
    logger.info("Ядро успешно активировано.")

def update_launch_state():
    logger.info("Обновление статуса запуска...")
    Path(os.path.dirname(LAUNCH_STATE_PATH)).mkdir(parents=True, exist_ok=True)
    with open(LAUNCH_STATE_PATH, "w") as f:
        json.dump({
            "status": "launched",
            "timestamp": log_event("ai_core_boot"),
            "ethics_lock": os.getenv("ETHICS_LOCK", "false"),
            "rbac": os.getenv("RBAC_ENABLED"),
            "jailkeeper": os.getenv("JAILKEEPER_ON")
        }, f, indent=2)

def run_self_diagnostics():
    try:
        logger.info("Запуск самодиагностики...")
        run(["python3", "-m", "diagnostics.ai_healthcheck"], check=True)
    except CalledProcessError:
        logger.warning("Диагностика завершилась с ошибками, проверьте логи.")

def main():
    logger.info("==> ИНИЦИАЛИЗАЦИЯ ЗАПУСКА AI CORE <==")
    check_env()
    validate_integrity()
    launch_ai_kernel()
    update_launch_state()
    run_self_diagnostics()
    logger.info("==> AI CORE ГОТОВО К РАБОТЕ <==")

if __name__ == "__main__":
    main()
