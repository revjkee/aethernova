# llmops/integrations/slack_bot.py

import os
import json
import logging
import requests
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class SlackBot:
    """
    SlackBot для отправки алертов, уведомлений и отчётов о состоянии LLM-систем в Slack.

    Поддерживает форматированные сообщения, вложения, реакции и кнопки.
    """

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        if not self.webhook_url:
            raise ValueError("SLACK_WEBHOOK_URL is not set")
        logger.debug(f"[SlackBot] Инициализирован с URL: {self.webhook_url}")

    def send_message(
        self,
        text: str,
        blocks: Optional[list] = None,
        attachments: Optional[list] = None,
        username: Optional[str] = "LLMOps Notifier",
        icon_emoji: Optional[str] = ":robot_face:",
        channel: Optional[str] = None,
        retries: int = 3
    ) -> bool:
        """
        Отправка сообщения в Slack с поддержкой retries и вложений.

        :param text: Основной текст сообщения
        :param blocks: Опциональные блоки (для форматирования)
        :param attachments: Вложения Slack (для кнопок, цвета и т.д.)
        :param username: Отображаемое имя бота
        :param icon_emoji: Иконка
        :param channel: Канал (если отличается от настроек вебхука)
        :param retries: Количество попыток при неудаче
        :return: Успешность отправки
        """
        payload: Dict[str, Any] = {
            "text": text,
            "username": username,
            "icon_emoji": icon_emoji
        }

        if blocks:
            payload["blocks"] = blocks
        if attachments:
            payload["attachments"] = attachments
        if channel:
            payload["channel"] = channel

        headers = {"Content-Type": "application/json"}

        for attempt in range(retries):
            try:
                response = requests.post(
                    self.webhook_url, data=json.dumps(payload), headers=headers, timeout=5
                )
                if response.status_code == 200:
                    logger.info("[SlackBot] Сообщение отправлено успешно.")
                    return True
                else:
                    logger.warning(
                        f"[SlackBot] Ошибка при отправке: {response.status_code} — {response.text}"
                    )
            except requests.RequestException as e:
                logger.error(f"[SlackBot] Ошибка запроса: {e}")
        return False

    def send_alert(self, title: str, message: str, color: str = "#FF0000") -> bool:
        """
        Быстрая отправка алерта с цветной подсветкой (например, при падении сервиса)

        :param title: Заголовок алерта
        :param message: Описание или тело сообщения
        :param color: Цвет полоски (например, красный — #FF0000)
        """
        attachment = {
            "fallback": title,
            "color": color,
            "title": title,
            "text": message,
            "mrkdwn_in": ["text", "title"]
        }
        return self.send_message(
            text=f"*{title}*\n{message}",
            attachments=[attachment],
            username="LLMOps Alert"
        )

    def send_blocks(self, blocks: list) -> bool:
        """
        Отправка структурированных блоков Slack (например, таблицы или кнопки)

        :param blocks: Массив блоков в Slack JSON-формате
        """
        return self.send_message(text=" ", blocks=blocks)

    def health_check(self) -> bool:
        """
        Простая проверка: работает ли бот
        """
        return self.send_message("✅ SlackBot активен и готов к работе.")

