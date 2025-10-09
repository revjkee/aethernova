import asyncio
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import json
import logging

from ..base import BaseAgent, AgentState, AgentMetrics
from ..registry import agent_registry

@dataclass
class PerformanceMetrics:
    """Метрики производительности агента"""
    agent_id: str
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    response_time: float
    tasks_per_minute: float
    error_rate: float
    success_rate: float
    queue_length: int
    active_connections: int

@dataclass
class HealthStatus:
    """Статус здоровья агента"""
    agent_id: str
    is_healthy: bool
    status: str  # healthy, warning, critical, down
    last_heartbeat: datetime
    uptime: timedelta
    issues: List[str]
    recommendations: List[str]

@dataclass
class AlertRule:
    """Правило для алертов"""
    rule_id: str
    name: str
    condition: str  # python expression
    severity: str  # info, warning, critical
    threshold: float
    duration: int  # seconds
    enabled: bool
    
@dataclass
class Alert:
    """Алерт о проблеме"""
    alert_id: str
    rule_id: str
    agent_id: str
    severity: str
    message: str
    triggered_at: datetime
    resolved_at: Optional[datetime]
    is_resolved: bool

class AgentMonitor:
    """Система мониторинга агентов"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.health_status: Dict[str, HealthStatus] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.monitoring_enabled = True
        self.collection_interval = 30  # seconds
        self.retention_hours = 24
        
    async def initialize(self) -> None:
        """Инициализация системы мониторинга"""
        await self._load_alert_rules()
        
        # Запуск циклов мониторинга
        asyncio.create_task(self._metrics_collection_loop())
        asyncio.create_task(self._health_check_loop())
        asyncio.create_task(self._alert_processing_loop())
        
        self.logger.info("Agent Monitor initialized")
        
    async def _load_alert_rules(self) -> None:
        """Загрузка правил алертов"""
        default_rules = [
            AlertRule(
                rule_id="high_cpu",
                name="High CPU Usage",
                condition="cpu_usage > threshold",
                severity="warning",
                threshold=80.0,
                duration=300,  # 5 minutes
                enabled=True
            ),
            AlertRule(
                rule_id="high_memory",
                name="High Memory Usage", 
                condition="memory_usage > threshold",
                severity="warning",
                threshold=85.0,
                duration=300,
                enabled=True
            ),
            AlertRule(
                rule_id="high_error_rate",
                name="High Error Rate",
                condition="error_rate > threshold",
                severity="critical",
                threshold=0.1,  # 10%
                duration=60,
                enabled=True
            ),
            AlertRule(
                rule_id="slow_response",
                name="Slow Response Time",
                condition="response_time > threshold",
                severity="warning",
                threshold=2000.0,  # 2 seconds
                duration=180,
                enabled=True
            ),
            AlertRule(
                rule_id="agent_down",
                name="Agent Down",
                condition="status == 'down'",
                severity="critical",
                threshold=0,
                duration=30,
                enabled=True
            )
        ]
        
        for rule in default_rules:
            self.alert_rules[rule.rule_id] = rule
            
    async def _metrics_collection_loop(self) -> None:
        """Цикл сбора метрик"""
        while self.monitoring_enabled:
            try:
                await self._collect_metrics()
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in metrics collection: {e}")
                await asyncio.sleep(60)
                
    async def _health_check_loop(self) -> None:
        """Цикл проверки здоровья"""
        while self.monitoring_enabled:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in health check: {e}")
                await asyncio.sleep(60)
                
    async def _alert_processing_loop(self) -> None:
        """Цикл обработки алертов"""
        while self.monitoring_enabled:
            try:
                await self._process_alerts()
                await asyncio.sleep(10)  # Check alerts more frequently
                
            except Exception as e:
                self.logger.error(f"Error in alert processing: {e}")
                await asyncio.sleep(30)
                
    async def _collect_metrics(self) -> None:
        """Сбор метрик со всех агентов"""
        for agent_id, agent_info in agent_registry.agents.items():
            try:
                agent = agent_info["agent"]
                metrics = await self._get_agent_metrics(agent)
                
                if metrics:
                    self.metrics_history[agent_id].append(metrics)
                    
            except Exception as e:
                self.logger.error(f"Error collecting metrics for agent {agent_id}: {e}")
                
    async def _get_agent_metrics(self, agent: BaseAgent) -> Optional[PerformanceMetrics]:
        """Получение метрик от конкретного агента"""
        try:
            # Симуляция сбора метрик - в реальной реализации это будет
            # получение реальных данных о производительности
            
            # Базовые метрики
            cpu_usage = 45.0 + (agent.current_load * 30)  # 45-75%
            memory_usage = 60.0 + (agent.current_load * 25)  # 60-85%
            
            # Метрики производительности
            recent_tasks = len(getattr(agent, 'recent_tasks', []))
            tasks_per_minute = recent_tasks / max(1, self.collection_interval / 60)
            
            # Время отклика (симуляция)
            response_time = 100.0 + (agent.current_load * 500)  # 100-600ms
            
            # Показатели успешности
            agent_metrics = agent_registry.agents[agent.agent_id]["metrics"]
            total_tasks = agent_metrics.total_tasks
            success_rate = (agent_metrics.successful_tasks / max(1, total_tasks)) * 100
            error_rate = (agent_metrics.failed_tasks / max(1, total_tasks)) * 100
            
            return PerformanceMetrics(
                agent_id=agent.agent_id,
                timestamp=datetime.now(),
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                response_time=response_time,
                tasks_per_minute=tasks_per_minute,
                error_rate=error_rate / 100,  # as decimal
                success_rate=success_rate / 100,  # as decimal
                queue_length=getattr(agent, 'queue_size', 0),
                active_connections=1 if agent.state == AgentState.RUNNING else 0
            )
            
        except Exception as e:
            self.logger.error(f"Error getting metrics for agent {agent.agent_id}: {e}")
            return None
            
    async def _perform_health_checks(self) -> None:
        """Выполнение проверки здоровья агентов"""
        for agent_id, agent_info in agent_registry.agents.items():
            try:
                agent = agent_info["agent"]
                health = await self._check_agent_health(agent)
                
                if health:
                    self.health_status[agent_id] = health
                    
            except Exception as e:
                self.logger.error(f"Error checking health for agent {agent_id}: {e}")
                
    async def _check_agent_health(self, agent: BaseAgent) -> Optional[HealthStatus]:
        """Проверка здоровья конкретного агента"""
        try:
            issues = []
            recommendations = []
            
            # Проверка состояния агента
            if agent.state == AgentState.ERROR:
                issues.append("Agent is in error state")
                recommendations.append("Restart agent")
                status = "critical"
                is_healthy = False
            elif agent.state == AgentState.STOPPED:
                issues.append("Agent is stopped")
                recommendations.append("Start agent")
                status = "down"
                is_healthy = False
            elif agent.current_load > 0.9:
                issues.append("Agent is overloaded")
                recommendations.append("Redistribute tasks or scale up")
                status = "warning"
                is_healthy = False
            else:
                status = "healthy"
                is_healthy = True
                
            # Проверка активности
            agent_metrics = agent_registry.agents[agent.agent_id]["metrics"]
            if agent_metrics.last_activity:
                time_since_activity = datetime.now() - agent_metrics.last_activity
                if time_since_activity > timedelta(minutes=10):
                    issues.append("No activity for 10+ minutes")
                    recommendations.append("Check agent connectivity")
                    if status == "healthy":
                        status = "warning"
                        is_healthy = False
                        
            # Вычисление uptime
            uptime = datetime.now() - getattr(agent, 'start_time', datetime.now())
            
            return HealthStatus(
                agent_id=agent.agent_id,
                is_healthy=is_healthy,
                status=status,
                last_heartbeat=datetime.now(),
                uptime=uptime,
                issues=issues,
                recommendations=recommendations
            )
            
        except Exception as e:
            self.logger.error(f"Error checking health for agent {agent.agent_id}: {e}")
            return None
            
    async def _process_alerts(self) -> None:
        """Обработка алертов на основе метрик и правил"""
        for agent_id in agent_registry.agents.keys():
            try:
                await self._check_agent_alerts(agent_id)
                
            except Exception as e:
                self.logger.error(f"Error processing alerts for agent {agent_id}: {e}")
                
    async def _check_agent_alerts(self, agent_id: str) -> None:
        """Проверка алертов для конкретного агента"""
        if agent_id not in self.metrics_history or not self.metrics_history[agent_id]:
            return
            
        latest_metrics = self.metrics_history[agent_id][-1]
        health_status = self.health_status.get(agent_id)
        
        for rule_id, rule in self.alert_rules.items():
            if not rule.enabled:
                continue
                
            try:
                # Проверка условия алерта
                triggered = await self._evaluate_alert_condition(rule, latest_metrics, health_status)
                
                alert_key = f"{agent_id}_{rule_id}"
                
                if triggered and alert_key not in self.active_alerts:
                    # Создание нового алерта
                    alert = Alert(
                        alert_id=f"alert_{len(self.active_alerts) + 1}",
                        rule_id=rule_id,
                        agent_id=agent_id,
                        severity=rule.severity,
                        message=await self._generate_alert_message(rule, latest_metrics, health_status),
                        triggered_at=datetime.now(),
                        resolved_at=None,
                        is_resolved=False
                    )
                    
                    self.active_alerts[alert_key] = alert
                    await self._send_alert(alert)
                    
                elif not triggered and alert_key in self.active_alerts:
                    # Разрешение алерта
                    alert = self.active_alerts[alert_key]
                    alert.resolved_at = datetime.now()
                    alert.is_resolved = True
                    await self._resolve_alert(alert)
                    del self.active_alerts[alert_key]
                    
            except Exception as e:
                self.logger.error(f"Error evaluating alert rule {rule_id}: {e}")
                
    async def _evaluate_alert_condition(self, rule: AlertRule, metrics: PerformanceMetrics, 
                                      health: Optional[HealthStatus]) -> bool:
        """Оценка условия алерта"""
        try:
            # Подготовка переменных для условия
            context = {
                'cpu_usage': metrics.cpu_usage,
                'memory_usage': metrics.memory_usage,
                'response_time': metrics.response_time,
                'error_rate': metrics.error_rate,
                'success_rate': metrics.success_rate,
                'tasks_per_minute': metrics.tasks_per_minute,
                'threshold': rule.threshold,
                'status': health.status if health else 'unknown'
            }
            
            # Выполнение условия
            return eval(rule.condition, {"__builtins__": {}}, context)
            
        except Exception as e:
            self.logger.error(f"Error evaluating condition '{rule.condition}': {e}")
            return False
            
    async def _generate_alert_message(self, rule: AlertRule, metrics: PerformanceMetrics,
                                    health: Optional[HealthStatus]) -> str:
        """Генерация сообщения алерта"""
        if rule.rule_id == "high_cpu":
            return f"High CPU usage: {metrics.cpu_usage:.1f}% (threshold: {rule.threshold}%)"
        elif rule.rule_id == "high_memory":
            return f"High memory usage: {metrics.memory_usage:.1f}% (threshold: {rule.threshold}%)"
        elif rule.rule_id == "high_error_rate":
            return f"High error rate: {metrics.error_rate*100:.1f}% (threshold: {rule.threshold*100}%)"
        elif rule.rule_id == "slow_response":
            return f"Slow response time: {metrics.response_time:.1f}ms (threshold: {rule.threshold}ms)"
        elif rule.rule_id == "agent_down":
            return f"Agent is down or not responding"
        else:
            return f"Alert triggered: {rule.name}"
            
    async def _send_alert(self, alert: Alert) -> None:
        """Отправка алерта"""
        self.logger.warning(f"ALERT [{alert.severity.upper()}] Agent {alert.agent_id}: {alert.message}")
        
        # Здесь можно добавить отправку в внешние системы:
        # - Email
        # - Slack
        # - Webhook
        # - SMS
        
    async def _resolve_alert(self, alert: Alert) -> None:
        """Разрешение алерта"""
        self.logger.info(f"RESOLVED Alert {alert.alert_id} for agent {alert.agent_id}")
        
    # Public API методы
    
    async def get_agent_metrics(self, agent_id: str, hours: int = 1) -> List[PerformanceMetrics]:
        """Получение метрик агента за указанный период"""
        if agent_id not in self.metrics_history:
            return []
            
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [m for m in self.metrics_history[agent_id] 
                if m.timestamp >= cutoff_time]
        
    async def get_agent_health(self, agent_id: str) -> Optional[HealthStatus]:
        """Получение статуса здоровья агента"""
        return self.health_status.get(agent_id)
        
    async def get_all_agents_health(self) -> Dict[str, HealthStatus]:
        """Получение статуса здоровья всех агентов"""
        return dict(self.health_status)
        
    async def get_active_alerts(self, agent_id: Optional[str] = None) -> List[Alert]:
        """Получение активных алертов"""
        alerts = list(self.active_alerts.values())
        
        if agent_id:
            alerts = [a for a in alerts if a.agent_id == agent_id]
            
        return alerts
        
    async def get_system_overview(self) -> Dict[str, Any]:
        """Получение общего обзора системы"""
        total_agents = len(agent_registry.agents)
        healthy_agents = len([h for h in self.health_status.values() if h.is_healthy])
        critical_alerts = len([a for a in self.active_alerts.values() if a.severity == "critical"])
        warning_alerts = len([a for a in self.active_alerts.values() if a.severity == "warning"])
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_agents": total_agents,
            "healthy_agents": healthy_agents,
            "unhealthy_agents": total_agents - healthy_agents,
            "active_alerts": len(self.active_alerts),
            "critical_alerts": critical_alerts,
            "warning_alerts": warning_alerts,
            "system_status": "healthy" if critical_alerts == 0 and warning_alerts < 3 else "warning" if critical_alerts == 0 else "critical"
        }
        
    async def shutdown(self) -> None:
        """Завершение работы мониторинга"""
        self.monitoring_enabled = False
        self.logger.info("Agent Monitor shutting down")

# Глобальный экземпляр монитора
agent_monitor = AgentMonitor()