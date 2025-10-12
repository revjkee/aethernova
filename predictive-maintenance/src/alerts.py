"""
Alert System Module
Интеллектуальная система алертов с приоритизацией и эскалацией
"""

import logging
import asyncio
import json
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict

logger = logging.getLogger("predictive-maintenance.alerts")


class AlertSeverity(str, Enum):
    """Уровни серьезности алертов"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Статусы алертов"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    SUPPRESSED = "suppressed"


class AlertChannel(str, Enum):
    """Каналы доставки алертов"""
    EMAIL = "email"
    SLACK = "slack"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"
    SMS = "sms"
    CONSOLE = "console"


@dataclass
class Alert:
    """Представление алерта"""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    source: str  # Источник (система/компонент)
    timestamp: datetime
    status: AlertStatus = AlertStatus.NEW
    
    # Метаданные
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Обработка
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resolution_note: Optional[str] = None
    
    # Эскалация
    escalation_level: int = 0
    escalated_at: Optional[datetime] = None
    
    # История
    history: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "tags": self.tags,
            "metadata": self.metadata,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": (
                self.acknowledged_at.isoformat() 
                if self.acknowledged_at else None
            ),
            "resolved_at": (
                self.resolved_at.isoformat() 
                if self.resolved_at else None
            ),
            "resolution_note": self.resolution_note,
            "escalation_level": self.escalation_level,
            "escalated_at": (
                self.escalated_at.isoformat() 
                if self.escalated_at else None
            ),
            "history": self.history
        }


@dataclass
class AlertRule:
    """Правило для создания алертов"""
    name: str
    condition: Callable  # Функция проверки условия
    severity: AlertSeverity
    title_template: str
    description_template: str
    tags: List[str] = field(default_factory=list)
    cooldown: timedelta = timedelta(minutes=5)  # Минимальный интервал между алертами
    last_triggered: Optional[datetime] = None
    
    def should_trigger(self) -> bool:
        """Проверка, можно ли триггерить (учитывая cooldown)"""
        if not self.last_triggered:
            return True
        return datetime.now() - self.last_triggered >= self.cooldown


@dataclass
class NotificationChannel:
    """Конфигурация канала уведомлений"""
    channel_type: AlertChannel
    config: Dict[str, Any]
    enabled: bool = True
    min_severity: AlertSeverity = AlertSeverity.WARNING
    
    # Rate limiting
    max_alerts_per_hour: int = 100
    alerts_sent_hour: int = 0
    hour_start: datetime = field(default_factory=datetime.now)


class AlertManager:
    """
    Менеджер алертов с интеллектуальной обработкой
    
    Возможности:
    - Создание и управление алертами
    - Приоритизация по серьезности
    - Автоматическая эскалация
    - Группировка похожих алертов
    - Подавление дублирующихся алертов
    - Мульти-канальная доставка
    """
    
    def __init__(
        self,
        escalation_timeout: timedelta = timedelta(minutes=30),
        max_escalation_level: int = 3,
        enable_auto_resolution: bool = True
    ):
        self.escalation_timeout = escalation_timeout
        self.max_escalation_level = max_escalation_level
        self.enable_auto_resolution = enable_auto_resolution
        
        # Хранилище алертов
        self.alerts: Dict[str, Alert] = {}
        self.alert_counter = 0
        
        # Правила создания алертов
        self.rules: Dict[str, AlertRule] = {}
        
        # Каналы уведомлений
        self.channels: Dict[AlertChannel, NotificationChannel] = {}
        
        # Группы алертов
        self.alert_groups: Dict[str, List[str]] = defaultdict(list)
        
        # Подавленные алерты
        self.suppressed_alerts: Dict[str, datetime] = {}
        
        # Коллбэки
        self.alert_callbacks: Dict[str, List[Callable]] = defaultdict(list)
        
        # Статус эскалации
        self.is_escalating = False
        self._escalation_task: Optional[asyncio.Task] = None
        
        logger.info(
            f"AlertManager initialized: "
            f"escalation_timeout={escalation_timeout}, "
            f"max_level={max_escalation_level}"
        )
    
    async def start(self) -> None:
        """Запуск менеджера алертов"""
        if self.is_escalating:
            return
        
        self.is_escalating = True
        self._escalation_task = asyncio.create_task(self._escalation_loop())
        logger.info("Alert manager started")
    
    async def stop(self) -> None:
        """Остановка менеджера"""
        self.is_escalating = False
        if self._escalation_task:
            self._escalation_task.cancel()
            try:
                await self._escalation_task
            except asyncio.CancelledError:
                pass
        logger.info("Alert manager stopped")
    
    async def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        source: str,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Alert:
        """
        Создание нового алерта
        
        Args:
            title: Заголовок
            description: Описание
            severity: Уровень серьезности
            source: Источник
            tags: Теги для категоризации
            metadata: Дополнительные данные
        """
        # Генерация ID
        self.alert_counter += 1
        alert_id = f"ALERT-{self.alert_counter:06d}"
        
        # Проверка на дубликаты
        if self._is_duplicate(title, source):
            logger.debug(f"Suppressed duplicate alert: {title}")
            return None
        
        # Создание алерта
        alert = Alert(
            id=alert_id,
            title=title,
            description=description,
            severity=severity,
            source=source,
            timestamp=datetime.now(),
            tags=tags or [],
            metadata=metadata or {}
        )
        
        # Сохранение
        self.alerts[alert_id] = alert
        
        # Группировка
        group_key = self._get_group_key(alert)
        self.alert_groups[group_key].append(alert_id)
        
        # История
        alert.history.append({
            "action": "created",
            "timestamp": datetime.now().isoformat(),
            "status": AlertStatus.NEW.value
        })
        
        logger.info(
            f"Created alert {alert_id}: {title} "
            f"[{severity.value}] from {source}"
        )
        
        # Отправка уведомлений
        await self._send_notifications(alert)
        
        # Коллбэки
        await self._trigger_callbacks("alert_created", alert)
        
        return alert
    
    async def acknowledge_alert(
        self,
        alert_id: str,
        user: str,
        note: Optional[str] = None
    ) -> bool:
        """Подтверждение получения алерта"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = user
        alert.acknowledged_at = datetime.now()
        
        alert.history.append({
            "action": "acknowledged",
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "note": note
        })
        
        logger.info(f"Alert {alert_id} acknowledged by {user}")
        await self._trigger_callbacks("alert_acknowledged", alert)
        
        return True
    
    async def resolve_alert(
        self,
        alert_id: str,
        resolution_note: str,
        user: Optional[str] = None
    ) -> bool:
        """Разрешение алерта"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.now()
        alert.resolution_note = resolution_note
        
        alert.history.append({
            "action": "resolved",
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "note": resolution_note
        })
        
        logger.info(f"Alert {alert_id} resolved: {resolution_note}")
        await self._trigger_callbacks("alert_resolved", alert)
        
        return True
    
    async def escalate_alert(
        self,
        alert_id: str,
        reason: Optional[str] = None
    ) -> bool:
        """Эскалация алерта"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        
        if alert.escalation_level >= self.max_escalation_level:
            logger.warning(
                f"Alert {alert_id} already at max escalation level"
            )
            return False
        
        alert.escalation_level += 1
        alert.escalated_at = datetime.now()
        alert.status = AlertStatus.ESCALATED
        
        alert.history.append({
            "action": "escalated",
            "timestamp": datetime.now().isoformat(),
            "level": alert.escalation_level,
            "reason": reason
        })
        
        logger.warning(
            f"Alert {alert_id} escalated to level {alert.escalation_level}"
        )
        
        # Уведомления для эскалированного алерта
        await self._send_notifications(alert, escalated=True)
        await self._trigger_callbacks("alert_escalated", alert)
        
        return True
    
    async def suppress_alert(
        self,
        alert_id: str,
        duration: timedelta = timedelta(hours=1)
    ) -> bool:
        """Подавление алерта на определенное время"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        
        alert.status = AlertStatus.SUPPRESSED
        until = datetime.now() + duration
        self.suppressed_alerts[alert_id] = until
        
        alert.history.append({
            "action": "suppressed",
            "timestamp": datetime.now().isoformat(),
            "until": until.isoformat()
        })
        
        logger.info(f"Alert {alert_id} suppressed until {until}")
        return True
    
    def register_rule(
        self,
        name: str,
        condition: Callable,
        severity: AlertSeverity,
        title_template: str,
        description_template: str,
        tags: Optional[List[str]] = None,
        cooldown: timedelta = timedelta(minutes=5)
    ) -> None:
        """Регистрация правила для автоматического создания алертов"""
        rule = AlertRule(
            name=name,
            condition=condition,
            severity=severity,
            title_template=title_template,
            description_template=description_template,
            tags=tags or [],
            cooldown=cooldown
        )
        
        self.rules[name] = rule
        logger.info(f"Registered alert rule: {name}")
    
    async def evaluate_rules(
        self,
        context: Dict[str, Any]
    ) -> List[Alert]:
        """Оценка всех правил и создание алертов"""
        created_alerts = []
        
        for name, rule in self.rules.items():
            try:
                if not rule.should_trigger():
                    continue
                
                # Проверка условия
                should_alert = False
                if asyncio.iscoroutinefunction(rule.condition):
                    should_alert = await rule.condition(context)
                else:
                    should_alert = rule.condition(context)
                
                if should_alert:
                    # Создание алерта из шаблона
                    title = rule.title_template.format(**context)
                    description = rule.description_template.format(**context)
                    
                    alert = await self.create_alert(
                        title=title,
                        description=description,
                        severity=rule.severity,
                        source=context.get("source", "system"),
                        tags=rule.tags,
                        metadata={"rule": name, **context}
                    )
                    
                    if alert:
                        created_alerts.append(alert)
                        rule.last_triggered = datetime.now()
            
            except Exception as e:
                logger.error(f"Error evaluating rule {name}: {e}", exc_info=True)
        
        return created_alerts
    
    def register_channel(
        self,
        channel_type: AlertChannel,
        config: Dict[str, Any],
        min_severity: AlertSeverity = AlertSeverity.WARNING
    ) -> None:
        """Регистрация канала уведомлений"""
        channel = NotificationChannel(
            channel_type=channel_type,
            config=config,
            min_severity=min_severity
        )
        
        self.channels[channel_type] = channel
        logger.info(f"Registered notification channel: {channel_type.value}")
    
    async def _send_notifications(
        self,
        alert: Alert,
        escalated: bool = False
    ) -> None:
        """Отправка уведомлений через все каналы"""
        for channel_type, channel in self.channels.items():
            if not channel.enabled:
                continue
            
            # Проверка минимальной серьезности
            severity_order = [
                AlertSeverity.INFO,
                AlertSeverity.WARNING,
                AlertSeverity.ERROR,
                AlertSeverity.CRITICAL
            ]
            
            if severity_order.index(alert.severity) < severity_order.index(channel.min_severity):
                continue
            
            # Rate limiting
            if not self._check_rate_limit(channel):
                logger.warning(
                    f"Rate limit exceeded for channel {channel_type.value}"
                )
                continue
            
            # Отправка
            try:
                await self._send_to_channel(channel_type, alert, escalated)
            except Exception as e:
                logger.error(
                    f"Error sending to {channel_type.value}: {e}",
                    exc_info=True
                )
    
    async def _send_to_channel(
        self,
        channel_type: AlertChannel,
        alert: Alert,
        escalated: bool
    ) -> None:
        """Отправка в конкретный канал"""
        channel = self.channels[channel_type]
        
        if channel_type == AlertChannel.CONSOLE:
            # Консольный вывод
            emoji = {
                AlertSeverity.INFO: "ℹ️",
                AlertSeverity.WARNING: "⚠️",
                AlertSeverity.ERROR: "❌",
                AlertSeverity.CRITICAL: "🚨"
            }.get(alert.severity, "")
            
            escalation = f" [ESCALATED L{alert.escalation_level}]" if escalated else ""
            
            print(
                f"\n{emoji} {alert.severity.value.upper()}{escalation}\n"
                f"  {alert.title}\n"
                f"  Source: {alert.source}\n"
                f"  {alert.description}\n"
                f"  ID: {alert.id} | Time: {alert.timestamp.strftime('%H:%M:%S')}\n"
            )
        
        elif channel_type == AlertChannel.WEBHOOK:
            # Webhook (имитация)
            webhook_url = channel.config.get("url")
            logger.info(
                f"[Webhook] Would send alert {alert.id} to {webhook_url}"
            )
            # В production: await self._http_client.post(webhook_url, json=alert.to_dict())
        
        elif channel_type == AlertChannel.EMAIL:
            # Email (имитация)
            recipients = channel.config.get("recipients", [])
            logger.info(
                f"[Email] Would send alert {alert.id} to {', '.join(recipients)}"
            )
        
        elif channel_type == AlertChannel.SLACK:
            # Slack (имитация)
            slack_channel = channel.config.get("channel", "#alerts")
            logger.info(
                f"[Slack] Would post alert {alert.id} to {slack_channel}"
            )
    
    def _check_rate_limit(self, channel: NotificationChannel) -> bool:
        """Проверка rate limit для канала"""
        now = datetime.now()
        
        # Сброс счетчика если прошел час
        if (now - channel.hour_start).total_seconds() >= 3600:
            channel.alerts_sent_hour = 0
            channel.hour_start = now
        
        if channel.alerts_sent_hour >= channel.max_alerts_per_hour:
            return False
        
        channel.alerts_sent_hour += 1
        return True
    
    def _is_duplicate(self, title: str, source: str) -> bool:
        """Проверка на дублирующийся алерт"""
        # Проверка последних алертов (за последние 5 минут)
        cutoff = datetime.now() - timedelta(minutes=5)
        
        for alert in self.alerts.values():
            if (alert.timestamp >= cutoff and
                alert.title == title and
                alert.source == source and
                alert.status != AlertStatus.RESOLVED):
                return True
        
        return False
    
    def _get_group_key(self, alert: Alert) -> str:
        """Получение ключа для группировки алертов"""
        return f"{alert.source}:{alert.severity.value}"
    
    async def _escalation_loop(self) -> None:
        """Автоматическая эскалация неподтвержденных алертов"""
        while self.is_escalating:
            try:
                await self._check_escalations()
                await asyncio.sleep(60)  # Проверка каждую минуту
            except Exception as e:
                logger.error(f"Error in escalation loop: {e}", exc_info=True)
                await asyncio.sleep(5)
    
    async def _check_escalations(self) -> None:
        """Проверка алертов для эскалации"""
        now = datetime.now()
        
        for alert in self.alerts.values():
            # Пропуск разрешенных и подавленных
            if alert.status in [AlertStatus.RESOLVED, AlertStatus.SUPPRESSED]:
                continue
            
            # Эскалация неподтвержденных критичных алертов
            if (alert.severity == AlertSeverity.CRITICAL and
                alert.status == AlertStatus.NEW and
                now - alert.timestamp >= self.escalation_timeout):
                
                await self.escalate_alert(
                    alert.id,
                    reason="No acknowledgment within timeout"
                )
    
    def register_callback(
        self,
        event: str,
        callback: Callable
    ) -> None:
        """Регистрация коллбэка для событий алертов"""
        self.alert_callbacks[event].append(callback)
        logger.info(f"Registered callback for event: {event}")
    
    async def _trigger_callbacks(
        self,
        event: str,
        alert: Alert
    ) -> None:
        """Вызов коллбэков для события"""
        for callback in self.alert_callbacks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                logger.error(f"Error in callback for {event}: {e}")
    
    def get_alerts(
        self,
        status: Optional[AlertStatus] = None,
        severity: Optional[AlertSeverity] = None,
        source: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Alert]:
        """Получение алертов с фильтрацией"""
        alerts = list(self.alerts.values())
        
        if status:
            alerts = [a for a in alerts if a.status == status]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if source:
            alerts = [a for a in alerts if a.source == source]
        
        # Сортировка по timestamp (новые первые)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        
        if limit:
            alerts = alerts[:limit]
        
        return alerts
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики алертов"""
        total = len(self.alerts)
        
        by_status = defaultdict(int)
        by_severity = defaultdict(int)
        
        for alert in self.alerts.values():
            by_status[alert.status.value] += 1
            by_severity[alert.severity.value] += 1
        
        return {
            "total_alerts": total,
            "by_status": dict(by_status),
            "by_severity": dict(by_severity),
            "active_rules": len(self.rules),
            "active_channels": len([c for c in self.channels.values() if c.enabled]),
            "is_escalating": self.is_escalating
        }
