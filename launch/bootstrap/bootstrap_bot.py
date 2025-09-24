#!/usr/bin/env python3

import os
import sys
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.utils import executor
from core.security.integrity import verify_integrity_hash
from core.config_loader import load_runtime_config
from core.telemetry.launch_log import log_event
from core.bot.handlers import register_all_handlers

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TG-BOT] %(message)s")
logger = logging.getLogger(__name__)

REQUIRED_ENV_VARS = ["BOT_TOKEN", "AI_CORE_ENDPOINT", "BOT_MODE"]
LAUNCH_STATE_PATH = "/var/lib/teslaai/bot_launch_state.json"

def check_env():
    logger.info("Проверка переменных окружения...")
    missing = [v for v in REQUIRED_ENV_VARS if not os.getenv(v)]
    if missing:
        logger.critical(f"Отсутствуют переменные окружения: {missing}")
        sys.exit(1)

def verify_integrity():
    logger.info("Проверка целостности Telegram-модуля...")
    if not verify_integrity_hash("telegram-bot"):
        logger.critical("Нарушена целостность кода бота. Прерывание.")
        sys.exit(1)

def bootstrap():
    logger.info("Инициализация Telegram-бота TeslaAI Genesis...")

    config = load_runtime_config(profile="production")
    bot_token = os.getenv("BOT_TOKEN")
    bot_mode = os.getenv("BOT_MODE", "polling")  # polling или webhook

    bot = Bot(token=bot_token, parse_mode=types.ParseMode.HTML)
    dp = Dispatcher(bot)

    register_all_handlers(dp, config)

    if bot_mode == "polling":
        logger.info("Бот запускается в режиме polling")
        executor.start_polling(dp, skip_updates=True)
    elif bot_mode == "webhook":
        webhook_url = config["webhook"]["url"]
        logger.info(f"Установка webhook: {webhook_url}")
        executor.start_webhook(
            dispatcher=dp,
            webhook_path="/webhook",
            on_startup=lambda _: bot.set_webhook(webhook_url),
            on_shutdown=lambda _: bot.delete_webhook(),
            skip_updates=True,
        )
    else:
        logger.error(f"Неверный BOT_MODE: {bot_mode}")
        sys.exit(1)

def main():
    logger.info("==> ЗАПУСК TELEGRAM-БОТА TESLAAI <==")
    check_env()
    verify_integrity()
    bootstrap()
    log_event("telegram_bot_boot")
    logger.info("Telegram-бот успешно активирован.")

if __name__ == "__main__":
    main()
