import asyncio
import aiohttp
import smtplib
from typing import Dict, List, Any, Optional
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from dataclasses import dataclass
import json
import logging
from abc import ABC, abstractmethod

from .monitor import Alert

@dataclass
class NotificationChannel:
    """Канал уведомлений"""
    channel_id: str
    name: str
    type: str  # email, slack, webhook, telegram
    config: Dict[str, Any]
    enabled: bool
    severity_filter: List[str]  # critical, warning, info

class NotificationProvider(ABC):
    """Абстрактный провайдер уведомлений"""
    
    @abstractmethod
    async def send_notification(self, alert: Alert, channel: NotificationChannel) -> bool:
        """Отправка уведомления"""
        pass
    
    @abstractmethod
    async def test_connection(self, channel: NotificationChannel) -> bool:
        """Тестирование подключения"""
        pass

class EmailNotificationProvider(NotificationProvider):
    """Провайдер уведомлений по Email"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def send_notification(self, alert: Alert, channel: NotificationChannel) -> bool:
        """Отправка email уведомления"""
        try:
            config = channel.config
            smtp_server = config.get("smtp_server", "smtp.gmail.com")
            smtp_port = config.get("smtp_port", 587)
            username = config.get("username")
            password = config.get("password")
            to_emails = config.get("to_emails", [])
            
            if not username or not password or not to_emails:
                self.logger.error("Invalid email configuration")
                return False
            
            # Создание сообщения
            subject = f"🚨 AI Agent Alert [{alert.severity.upper()}] - {alert.agent_id}"
            body = await self._format_email_body(alert)
            
            msg = MimeMultipart()
            msg['From'] = username
            msg['To'] = ", ".join(to_emails)
            msg['Subject'] = subject
            msg.attach(MimeText(body, 'html'))
            
            # Отправка через SMTP
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent for {alert.alert_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            return False
    
    async def test_connection(self, channel: NotificationChannel) -> bool:
        """Тестирование SMTP подключения"""
        try:
            config = channel.config
            smtp_server = config.get("smtp_server", "smtp.gmail.com")
            smtp_port = config.get("smtp_port", 587)
            username = config.get("username")
            password = config.get("password")
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.quit()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Email connection test failed: {e}")
            return False
    
    async def _format_email_body(self, alert: Alert) -> str:
        """Форматирование тела email"""
        severity_colors = {
            "critical": "#dc3545",
            "warning": "#ffc107",
            "info": "#17a2b8"
        }
        
        color = severity_colors.get(alert.severity, "#6c757d")
        
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: {color}; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
                <h2 style="margin: 0;">🤖 AI Agent Alert</h2>
                <p style="margin: 5px 0 0 0;">Severity: {alert.severity.upper()}</p>
            </div>
            
            <div style="background: #f8f9fa; padding: 20px; border: 1px solid #dee2e6; border-top: none;">
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px; font-weight: bold; width: 30%;">Agent ID:</td>
                        <td style="padding: 8px;">{alert.agent_id}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold;">Message:</td>
                        <td style="padding: 8px;">{alert.message}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold;">Triggered At:</td>
                        <td style="padding: 8px;">{alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold;">Alert ID:</td>
                        <td style="padding: 8px;">{alert.alert_id}</td>
                    </tr>
                </table>
            </div>
            
            <div style="background: #ffffff; padding: 15px; border: 1px solid #dee2e6; border-top: none; border-radius: 0 0 8px 8px;">
                <p style="margin: 0; font-size: 12px; color: #6c757d;">
                    This is an automated alert from AetherNova AI Agent System.
                    Please check the dashboard for more details.
                </p>
            </div>
        </body>
        </html>
        """

class SlackNotificationProvider(NotificationProvider):
    """Провайдер уведомлений в Slack"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def send_notification(self, alert: Alert, channel: NotificationChannel) -> bool:
        """Отправка уведомления в Slack"""
        try:
            config = channel.config
            webhook_url = config.get("webhook_url")
            channel_name = config.get("channel", "#alerts")
            
            if not webhook_url:
                self.logger.error("Slack webhook URL not configured")
                return False
            
            # Форматирование сообщения
            color = self._get_severity_color(alert.severity)
            message = await self._format_slack_message(alert, channel_name, color)
            
            # Отправка через webhook
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=message) as response:
                    if response.status == 200:
                        self.logger.info(f"Slack alert sent for {alert.alert_id}")
                        return True
                    else:
                        self.logger.error(f"Slack webhook failed with status {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
            return False
    
    async def test_connection(self, channel: NotificationChannel) -> bool:
        """Тестирование Slack webhook"""
        try:
            config = channel.config
            webhook_url = config.get("webhook_url")
            
            test_message = {
                "text": "🧪 Test notification from AetherNova AI Agent System",
                "username": "AI-Agent-Monitor"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=test_message) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"Slack connection test failed: {e}")
            return False
    
    def _get_severity_color(self, severity: str) -> str:
        """Получение цвета для уровня важности"""
        colors = {
            "critical": "danger",
            "warning": "warning", 
            "info": "good"
        }
        return colors.get(severity, "warning")
    
    async def _format_slack_message(self, alert: Alert, channel: str, color: str) -> Dict[str, Any]:
        """Форматирование сообщения для Slack"""
        severity_icons = {
            "critical": "🚨",
            "warning": "⚠️",
            "info": "ℹ️"
        }
        
        icon = severity_icons.get(alert.severity, "🔔")
        
        return {
            "channel": channel,
            "username": "AI-Agent-Monitor",
            "icon_emoji": ":robot_face:",
            "attachments": [
                {
                    "color": color,
                    "title": f"{icon} AI Agent Alert - {alert.severity.upper()}",
                    "fields": [
                        {
                            "title": "Agent ID",
                            "value": alert.agent_id,
                            "short": True
                        },
                        {
                            "title": "Message",
                            "value": alert.message,
                            "short": False
                        },
                        {
                            "title": "Time",
                            "value": alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S'),
                            "short": True
                        },
                        {
                            "title": "Alert ID",
                            "value": alert.alert_id,
                            "short": True
                        }
                    ],
                    "footer": "AetherNova AI Agent System",
                    "ts": int(alert.triggered_at.timestamp())
                }
            ]
        }

class WebhookNotificationProvider(NotificationProvider):
    """Провайдер уведомлений через webhook"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def send_notification(self, alert: Alert, channel: NotificationChannel) -> bool:
        """Отправка webhook уведомления"""
        try:
            config = channel.config
            webhook_url = config.get("url")
            headers = config.get("headers", {})
            
            if not webhook_url:
                self.logger.error("Webhook URL not configured")
                return False
            
            # Подготовка payload
            payload = {
                "alert_id": alert.alert_id,
                "agent_id": alert.agent_id,
                "severity": alert.severity,
                "message": alert.message,
                "triggered_at": alert.triggered_at.isoformat(),
                "rule_id": alert.rule_id,
                "system": "aethernova-ai-agents"
            }
            
            # Отправка
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, headers=headers) as response:
                    if 200 <= response.status < 300:
                        self.logger.info(f"Webhook alert sent for {alert.alert_id}")
                        return True
                    else:
                        self.logger.error(f"Webhook failed with status {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")
            return False
    
    async def test_connection(self, channel: NotificationChannel) -> bool:
        """Тестирование webhook"""
        try:
            config = channel.config
            webhook_url = config.get("url")
            headers = config.get("headers", {})
            
            test_payload = {
                "test": True,
                "message": "Test notification from AetherNova AI Agent System",
                "timestamp": "2025-10-08T10:00:00Z"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=test_payload, headers=headers) as response:
                    return 200 <= response.status < 300
                    
        except Exception as e:
            self.logger.error(f"Webhook connection test failed: {e}")
            return False

class NotificationManager:
    """Менеджер системы уведомлений"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.channels: Dict[str, NotificationChannel] = {}
        self.providers: Dict[str, NotificationProvider] = {
            "email": EmailNotificationProvider(),
            "slack": SlackNotificationProvider(), 
            "webhook": WebhookNotificationProvider()
        }
        
    async def initialize(self) -> None:
        """Инициализация менеджера уведомлений"""
        await self._load_notification_channels()
        self.logger.info("Notification Manager initialized")
        
    async def _load_notification_channels(self) -> None:
        """Загрузка каналов уведомлений из конфигурации"""
        # В реальной реализации это будет загружаться из конфигурации/базы данных
        
        # Пример каналов
        example_channels = [
            NotificationChannel(
                channel_id="email_admins",
                name="Admin Email Notifications",
                type="email",
                config={
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "username": "alerts@aethernova.ai",
                    "password": "your-app-password",
                    "to_emails": ["admin@aethernova.ai", "devops@aethernova.ai"]
                },
                enabled=False,  # Отключено по умолчанию
                severity_filter=["critical", "warning"]
            ),
            NotificationChannel(
                channel_id="slack_alerts",
                name="Slack Alerts Channel",
                type="slack",
                config={
                    "webhook_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
                    "channel": "#ai-agents-alerts"
                },
                enabled=False,  # Отключено по умолчанию  
                severity_filter=["critical", "warning"]
            )
        ]
        
        for channel in example_channels:
            self.channels[channel.channel_id] = channel
            
    async def send_alert(self, alert: Alert) -> None:
        """Отправка алерта через все подходящие каналы"""
        try:
            for channel in self.channels.values():
                if not channel.enabled:
                    continue
                    
                if alert.severity not in channel.severity_filter:
                    continue
                    
                provider = self.providers.get(channel.type)
                if not provider:
                    self.logger.warning(f"No provider for channel type: {channel.type}")
                    continue
                    
                # Отправка в фоне
                asyncio.create_task(self._send_to_channel(alert, channel, provider))
                
        except Exception as e:
            self.logger.error(f"Error sending alert notifications: {e}")
            
    async def _send_to_channel(self, alert: Alert, channel: NotificationChannel, 
                             provider: NotificationProvider) -> None:
        """Отправка алерта в конкретный канал"""
        try:
            success = await provider.send_notification(alert, channel)
            if success:
                self.logger.info(f"Alert {alert.alert_id} sent to channel {channel.channel_id}")
            else:
                self.logger.error(f"Failed to send alert {alert.alert_id} to channel {channel.channel_id}")
                
        except Exception as e:
            self.logger.error(f"Error sending to channel {channel.channel_id}: {e}")
            
    async def test_channel(self, channel_id: str) -> bool:
        """Тестирование канала уведомлений"""
        try:
            channel = self.channels.get(channel_id)
            if not channel:
                return False
                
            provider = self.providers.get(channel.type)
            if not provider:
                return False
                
            return await provider.test_connection(channel)
            
        except Exception as e:
            self.logger.error(f"Error testing channel {channel_id}: {e}")
            return False
            
    async def add_channel(self, channel: NotificationChannel) -> None:
        """Добавление нового канала"""
        self.channels[channel.channel_id] = channel
        self.logger.info(f"Added notification channel: {channel.channel_id}")
        
    async def remove_channel(self, channel_id: str) -> None:
        """Удаление канала"""
        if channel_id in self.channels:
            del self.channels[channel_id]
            self.logger.info(f"Removed notification channel: {channel_id}")
            
    async def get_channels(self) -> List[NotificationChannel]:
        """Получение списка каналов"""
        return list(self.channels.values())
        
    async def update_channel(self, channel_id: str, updates: Dict[str, Any]) -> bool:
        """Обновление канала"""
        if channel_id not in self.channels:
            return False
            
        channel = self.channels[channel_id]
        
        if "enabled" in updates:
            channel.enabled = updates["enabled"]
        if "severity_filter" in updates:
            channel.severity_filter = updates["severity_filter"]
        if "config" in updates:
            channel.config.update(updates["config"])
            
        return True

# Глобальный экземпляр менеджера уведомлений
notification_manager = NotificationManager()