# autopwn-framework/services/notification_service.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import asyncio

class NotificationService:
    """
    Сервис для отправки уведомлений через Email, Slack и Telegram.
    Поддерживает асинхронную отправку сообщений.
    """

    def __init__(self, email_config: dict, slack_config: dict, telegram_config: dict):
        self.email_config = email_config
        self.slack_config = slack_config
        self.telegram_config = telegram_config

    async def send_email(self, subject: str, body: str, to_addresses: list):
        msg = MIMEMultipart()
        msg['From'] = self.email_config['sender']
        msg['To'] = ', '.join(to_addresses)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port']) as server:
                server.starttls()
                server.login(self.email_config['username'], self.email_config['password'])
                server.sendmail(self.email_config['sender'], to_addresses, msg.as_string())
        except Exception as e:
            print(f"Ошибка при отправке Email: {e}")

    async def send_slack(self, message: str, channel: str = None):
        url = self.slack_config['webhook_url']
        payload = {"text": message}
        if channel:
            payload["channel"] = channel
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
        except Exception as e:
            print(f"Ошибка при отправке Slack сообщения: {e}")

    async def send_telegram(self, message: str, chat_id: str = None):
        token = self.telegram_config['bot_token']
        chat = chat_id or self.telegram_config['default_chat_id']
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        params = {"chat_id": chat, "text": message}
        try:
            response = requests.post(url, params=params)
            response.raise_for_status()
        except Exception as e:
            print(f"Ошибка при отправке Telegram сообщения: {e}")

    async def notify_all(self, subject: str, message: str, email_recipients: list, slack_channel: str = None, telegram_chat_id: str = None):
        await asyncio.gather(
            self.send_email(subject, message, email_recipients),
            self.send_slack(message, slack_channel),
            self.send_telegram(message, telegram_chat_id)
        )
