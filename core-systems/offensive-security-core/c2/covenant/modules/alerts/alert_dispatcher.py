# Рассылка оповещений
# alert_dispatcher.py
# Рассылка оповещений и маршрутизация в каналы реагирования

import asyncio
import logging
from enum import Enum
from typing import Optional, Callable
import smtplib
import httpx

logger = logging.getLogger("alert_dispatcher")
logger.setLevel(logging.INFO)


class AlertLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertDispatcher:
    def __init__(
        self,
        enable_email: bool = False,
        enable_telegram: bool = False,
        enable_webhook: bool = False,
        enable_internal_callback: bool = False,
    ):
        self.enable_email = enable_email
        self.enable_telegram = enable_telegram
        self.enable_webhook = enable_webhook
        self.enable_internal_callback = enable_internal_callback

        self.internal_callback: Optional[Callable[[dict], None]] = None
        self.telegram_token = None
        self.telegram_chat_id = None
        self.webhook_url = None
        self.smtp_config = {}

    def set_email_config(self, smtp_host: str, smtp_port: int, user: str, password: str, from_email: str, to_email: str):
        self.smtp_config = {
            "host": smtp_host,
            "port": smtp_port,
            "user": user,
            "password": password,
            "from": from_email,
            "to": to_email,
        }

    def set_telegram_config(self, token: str, chat_id: str):
        self.telegram_token = token
        self.telegram_chat_id = chat_id

    def set_webhook_url(self, url: str):
        self.webhook_url = url

    def set_internal_callback(self, callback: Callable[[dict], None]):
        self.internal_callback = callback

    async def dispatch(self, message: str, level: AlertLevel = AlertLevel.INFO, context: Optional[dict] = None):
        """
        Отправляет оповещение во все активные каналы.
        """
        alert_data = {
            "level": level,
            "message": message,
            "context": context or {},
        }

        tasks = []
        logger.info(f"Оповещение уровня {level.upper()}: {message}")

        if self.enable_email:
            tasks.append(self._send_email(alert_data))
        if self.enable_telegram:
            tasks.append(self._send_telegram(alert_data))
        if self.enable_webhook:
            tasks.append(self._send_webhook(alert_data))
        if self.enable_internal_callback and self.internal_callback:
            tasks.append(self._trigger_internal_callback(alert_data))

        await asyncio.gather(*tasks)

    async def _send_email(self, alert: dict):
        try:
            smtp = smtplib.SMTP(self.smtp_config["host"], self.smtp_config["port"])
            smtp.starttls()
            smtp.login(self.smtp_config["user"], self.smtp_config["password"])
            body = f"Subject: Alert [{alert['level'].upper()}]\n\n{alert['message']}\n\nContext:\n{alert['context']}"
            smtp.sendmail(self.smtp_config["from"], self.smtp_config["to"], body)
            smtp.quit()
            logger.info("Оповещение отправлено по Email")
        except Exception as e:
            logger.error(f"Ошибка отправки Email: {e}")

    async def _send_telegram(self, alert: dict):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": f"🚨 [{alert['level'].upper()}] {alert['message']}\n\nContext:\n{alert['context']}",
                "parse_mode": "HTML",
            }
            async with httpx.AsyncClient() as client:
                await client.post(url, json=payload)
            logger.info("Оповещение отправлено в Telegram")
        except Exception as e:
            logger.error(f"Ошибка отправки Telegram: {e}")

    async def _send_webhook(self, alert: dict):
        try:
            async with httpx.AsyncClient() as client:
                await client.post(self.webhook_url, json=alert)
            logger.info("Оповещение отправлено на Webhook")
        except Exception as e:
            logger.error(f"Ошибка Webhook: {e}")

    async def _trigger_internal_callback(self, alert: dict):
        try:
            self.internal_callback(alert)
            logger.info("Внутренний callback вызван")
        except Exception as e:
            logger.error(f"Ошибка внутреннего callback: {e}")
