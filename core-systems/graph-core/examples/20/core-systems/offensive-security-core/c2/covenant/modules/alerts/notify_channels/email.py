# Email-оповещения
# email.py
# Модуль интеграции с email-оповещениями

import logging
from typing import Dict, Any

import aiosmtplib
from email.message import EmailMessage

from c2.config import settings
from c2.covenant.modules.core.alerts.alert_templates import AlertTemplates, AlertLevel

logger = logging.getLogger(__name__)

class EmailNotifier:
    def __init__(
        self,
        smtp_host: str = None,
        smtp_port: int = None,
        username: str = None,
        password: str = None,
        sender_email: str = None,
        recipient_email: str = None,
        use_tls: bool = True
    ):
        self.smtp_host = smtp_host or settings.SMTP_HOST
        self.smtp_port = smtp_port or settings.SMTP_PORT
        self.username = username or settings.SMTP_USERNAME
        self.password = password or settings.SMTP_PASSWORD
        self.sender_email = sender_email or settings.SMTP_SENDER
        self.recipient_email = recipient_email or settings.SMTP_RECIPIENT
        self.use_tls = use_tls

        if not all([self.smtp_host, self.smtp_port, self.username, self.password, self.sender_email, self.recipient_email]):
            raise ValueError("SMTP-параметры не заданы полностью.")

    async def send_alert(
        self,
        level: AlertLevel,
        subject: str,
        message: str,
        context: Dict[str, Any] = None
    ) -> bool:
        try:
            html_content = AlertTemplates.email_template(level, message, context or {})
            text_fallback = AlertTemplates.text_template(level, message, context or {})

            msg = EmailMessage()
            msg["From"] = self.sender_email
            msg["To"] = self.recipient_email
            msg["Subject"] = f"[{level.name}] {subject}"
            msg.set_content(text_fallback)
            msg.add_alternative(html_content, subtype="html")

            await aiosmtplib.send(
                message=msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.username,
                password=self.password,
                start_tls=self.use_tls,
                timeout=10
            )
            logger.info("Email alert sent successfully.")
            return True

        except Exception as e:
            logger.exception(f"Ошибка при отправке email-оповещения: {e}")
            return False
