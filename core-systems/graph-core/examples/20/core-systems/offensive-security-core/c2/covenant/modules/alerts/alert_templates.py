# Форматирование сообщений
# alert_templates.py
# Форматирование сообщений для разных каналов доставки оповещений

from datetime import datetime
from enum import Enum
from typing import Dict, Any


class AlertLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertTemplates:
    @staticmethod
    def _base_context(level: AlertLevel, message: str, context: Dict[str, Any]) -> Dict[str, str]:
        return {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "level": level.upper(),
            "message": message,
            "context": AlertTemplates._format_context(context),
        }

    @staticmethod
    def _format_context(context: Dict[str, Any]) -> str:
        if not context:
            return "No additional context provided."
        return "\n".join(f"{k}: {v}" for k, v in context.items())

    @staticmethod
    def email_template(level: AlertLevel, message: str, context: Dict[str, Any]) -> str:
        base = AlertTemplates._base_context(level, message, context)
        return (
            f"Subject: [ALERT - {base['level']}] Notification\n\n"
            f"Time: {base['timestamp']}\n"
            f"Level: {base['level']}\n"
            f"Message: {base['message']}\n\n"
            f"Context:\n{base['context']}"
        )

    @staticmethod
    def telegram_template(level: AlertLevel, message: str, context: Dict[str, Any]) -> str:
        base = AlertTemplates._base_context(level, message, context)
        return (
            f"🚨 <b>[{base['level']}]</b> <code>{base['timestamp']}</code>\n"
            f"<b>Message:</b> {base['message']}\n\n"
            f"<b>Context:</b>\n<pre>{base['context']}</pre>"
        )

    @staticmethod
    def webhook_template(level: AlertLevel, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "context": context,
        }

    @staticmethod
    def log_template(level: AlertLevel, message: str, context: Dict[str, Any]) -> str:
        base = AlertTemplates._base_context(level, message, context)
        return (
            f"[{base['timestamp']}] [{base['level']}] {base['message']} | Context: {base['context']}"
        )
