# Slack-подключение
# slack.py
# Интеграция с Slack для оповещений в рамках Covenant Alert System

import logging
from typing import Dict, Any

import httpx

from c2.config import settings
from c2.covenant.modules.core.alerts.alert_templates import AlertTemplates, AlertLevel

logger = logging.getLogger(__name__)

class SlackNotifier:
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or settings.SLACK_WEBHOOK_URL
        if not self.webhook_url:
            raise ValueError("Slack Webhook URL не указан.")

    async def send_alert(
        self,
        level: AlertLevel,
        title: str,
        message: str,
        context: Dict[str, Any] = None
    ) -> bool:
        try:
            formatted_message = AlertTemplates.slack_template(level, message, context or {})

            payload = {
                "text": f"*[{level.name}] {title}*\n{formatted_message}"
            }

            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self.webhook_url, json=payload)

            if response.status_code == 200:
                logger.info("Slack alert sent successfully.")
                return True
            else:
                logger.error(f"Ошибка отправки Slack-оповещения: HTTP {response.status_code}")
                return False

        except Exception as e:
            logger.exception(f"Исключение при Slack-оповещении: {e}")
            return False
