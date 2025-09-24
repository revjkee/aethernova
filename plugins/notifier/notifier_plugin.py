import smtplib
import json
import time
from typing import Dict, Any, List, Optional
from email.message import EmailMessage
from plugins.core.base_plugin import BasePlugin
from plugins.utils.plugin_logger import plugin_logger as logger
from utils.retry import retry_on_exception
from utils.encoder import safe_json_dumps
from utils.config import get_env

class NotifierPlugin(BasePlugin):
    plugin_name = "UniversalNotifier"
    plugin_version = "3.0.2"
    plugin_author = "TeslaAI Notification Core"
    plugin_description = "Многоформатный плагин для безопасных оповещений через email, Telegram, Discord, Webhook."
    plugin_dependencies = {
        "requests": ">=2.30.0"
    }

    def __init__(self):
        super().__init__()
        import requests
        self.requests = requests

        # Получение конфигурации из окружения
        self.telegram_token = get_env("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = get_env("TELEGRAM_CHAT_ID")
        self.webhook_url = get_env("GENERIC_WEBHOOK_URL")
        self.smtp_config = {
            "host": get_env("SMTP_HOST"),
            "port": int(get_env("SMTP_PORT", "587")),
            "user": get_env("SMTP_USER"),
            "password": get_env("SMTP_PASSWORD"),
            "from": get_env("SMTP_FROM"),
            "to": get_env("SMTP_TO")
        }

    @retry_on_exception(max_retries=3, delay=5)
    def notify_email(self, subject: str, body: str) -> bool:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.smtp_config["from"]
        msg["To"] = self.smtp_config["to"]
        msg.set_content(body)

        with smtplib.SMTP(self.smtp_config["host"], self.smtp_config["port"]) as server:
            server.starttls()
            server.login(self.smtp_config["user"], self.smtp_config["password"])
            server.send_message(msg)
        logger.info("[Notifier] Email sent.")
        return True

    @retry_on_exception(max_retries=3, delay=2)
    def notify_telegram(self, message: str) -> bool:
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        data = {"chat_id": self.telegram_chat_id, "text": message}
        response = self.requests.post(url, json=data)
        if response.ok:
            logger.info("[Notifier] Telegram message sent.")
        else:
            logger.warning(f"[Notifier] Telegram failed: {response.text}")
        return response.ok

    @retry_on_exception(max_retries=3, delay=2)
    def notify_webhook(self, payload: Dict[str, Any]) -> bool:
        headers = {"Content-Type": "application/json"}
        response = self.requests.post(self.webhook_url, data=safe_json_dumps(payload), headers=headers)
        if response.ok:
            logger.info("[Notifier] Webhook delivered.")
        else:
            logger.warning(f"[Notifier] Webhook error: {response.text}")
        return response.ok

    def run(self, input_data: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Универсальная точка входа. В зависимости от параметров отправляет оповещение через нужный канал.
        """
        message = input_data.get("message", "Empty message")
        subject = input_data.get("subject", "TeslaAI Notification")
        channels = input_data.get("channels", ["telegram", "webhook"])
        payload = input_data.get("payload", {})

        results = {}

        if "email" in channels:
            try:
                results["email"] = self.notify_email(subject, message)
            except Exception as e:
                logger.error(f"[Notifier] Email error: {e}")
                results["email"] = False

        if "telegram" in channels:
            results["telegram"] = self.notify_telegram(message)

        if "webhook" in channels:
            results["webhook"] = self.notify_webhook(payload or {"message": message})

        return {
            "plugin": self.plugin_name,
            "results": results,
            "timestamp": time.time()
        }
