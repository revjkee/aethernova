# Интеграция с Telegram
# telegram.py
# Интеграция системы оповещений с Telegram

import asyncio
import logging
from typing import Dict, Any

import aiohttp

from c2.config import settings  # Убедись, что token и chat_id заданы в конфиге
from c2.covenant.modules.core.alerts.alert_templates import AlertTemplates, AlertLevel

logger = logging.getLogger(__name__)

class TelegramNotifier:
    TELEGRAM_API_URL = "https://api.telegram.org"

    def __init__(self, token: str = None, chat_id: str = None):
        self.token = token or settings.TELEGRAM_BOT_TOKEN
        self.chat_id = chat_id or settings.TELEGRAM_ALERT_CHAT_ID
        self.api_url = f"{self.TELEGRAM_API_URL}/bot{self.token}/sendMessage"

        if not self.token or not self.chat_id:
            raise ValueError("TELEGRAM_BOT_TOKEN и TELEGRAM_ALERT_CHAT_ID обязательны")

    async def send_alert(
        self,
        level: AlertLevel,
        message: str,
        context: Dict[str, Any] = None,
        parse_mode: str = "HTML"
    ) -> bool:
        formatted_message = AlertTemplates.telegram_template(level, message, context or {})

        payload = {
            "chat_id": self.chat_id,
            "text": formatted_message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.api_url, json=payload, timeout=10) as resp:
                    if resp.status == 200:
                        logger.info("Telegram alert sent successfully.")
                        return True
                    else:
                        text = await resp.text()
                        logger.error(f"Failed to send alert to Telegram: {resp.status} {text}")
                        return False
        except Exception as e:
            logger.exception(f"Exception while sending Telegram alert: {e}")
            return False

