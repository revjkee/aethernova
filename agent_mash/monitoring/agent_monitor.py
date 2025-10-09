# agent_mash/monitoring/agent_monitor.py

import asyncio
import time
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
import psutil
import threading
from agent_mash.core.base_agent import BaseAgent, AgentStatus
from agent_mash.strategy_router import StrategyRouter

logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    """Системные метрики производительности"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_available_mb: float
    disk_usage_percent: float
    network_io_bytes_sent: int
    network_io_bytes_recv: int
    active_processes: int
    load_average: List[float]  # 1, 5, 15 минут

@dataclass
class AgentHealthCheck:
    """Результат проверки здоровья агента"""
    agent_id: str
    timestamp: float
    status: str
    response_time_ms: float
    cpu_usage: float
    memory_usage: float
    message_queue_size: int
    last_activity: Optional[float]
    error_count: int
    health_score: float  # от 0 до 100

class AgentMonitor:
    """
    Система мониторинга агентов AetherNova
    
    Функции:
    - Сбор метрик производительности агентов
    - Мониторинг системных ресурсов
    - Анализ здоровья агентов
    - Генерация алертов
    - Хранение исторических данных
    """

    def __init__(self, router: StrategyRouter, check_interval: float = 5.0):
        self.router = router
        self.check_interval = check_interval
        self.agents: Dict[str, BaseAgent] = {}
        
        # История метрик
        self.agent_metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.system_metrics_history: deque = deque(maxlen=100)
        
        # Алерты и уведомления
        self.active_alerts: Dict[str, Dict[str, Any]] = {}
        self.alert_thresholds = {
            "cpu_high": 80.0,
            "memory_high": 85.0,
            "response_time_high": 5000.0,  # мс
            "error_rate_high": 0.1,  # 10%
            "health_score_low": 30.0
        }
        
        # Статус мониторинга
        self.monitoring_active = False
        self.start_time = time.time()
        
        # Фоновые задачи
        self._monitoring_task = None
        self._cleanup_task = None

    def register_agent(self, agent: BaseAgent):
        """Зарегистрировать агента для мониторинга"""
        self.agents[agent.agent_id] = agent
        logger.info(f"Agent {agent.agent_id} registered for monitoring")

    def unregister_agent(self, agent_id: str):
        """Отменить регистрацию агента"""
        if agent_id in self.agents:
            del self.agents[agent_id]
            # Очистка истории метрик
            if agent_id in self.agent_metrics_history:
                del self.agent_metrics_history[agent_id]
            logger.info(f"Agent {agent_id} unregistered from monitoring")

    async def start_monitoring(self):
        """Запуск системы мониторинга"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        logger.info("Starting agent monitoring system")
        
        # Запуск фоновых задач
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_monitoring(self):
        """Остановка системы мониторинга"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        logger.info("Stopping agent monitoring system")
        
        # Отмена фоновых задач
        if self._monitoring_task:
            self._monitoring_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()

    async def _monitoring_loop(self):
        """Основной цикл мониторинга"""
        while self.monitoring_active:
            try:
                # Сбор системных метрик
                await self._collect_system_metrics()
                
                # Проверка здоровья агентов
                await self._check_agents_health()
                
                # Обновление метрик в роутере
                self._update_router_metrics()
                
                # Анализ и генерация алертов
                await self._analyze_and_alert()
                
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                logger.info("Monitoring loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(self.check_interval)

    async def _collect_system_metrics(self):
        """Сбор системных метрик"""
        try:
            # CPU и память
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Сетевые интерфейсы
            network = psutil.net_io_counters()
            
            # Загрузка системы (только для Unix-систем)
            try:
                load_avg = list(psutil.getloadavg())
            except AttributeError:
                load_avg = [0.0, 0.0, 0.0]  # Windows не поддерживает getloadavg
            
            metrics = SystemMetrics(
                timestamp=time.time(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_available_mb=memory.available / (1024 * 1024),
                disk_usage_percent=disk.percent,
                network_io_bytes_sent=network.bytes_sent,
                network_io_bytes_recv=network.bytes_recv,
                active_processes=len(psutil.pids()),
                load_average=load_avg
            )
            
            self.system_metrics_history.append(metrics)
            logger.debug(f"Collected system metrics: CPU={cpu_percent}%, Memory={memory.percent}%")
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")

    async def _check_agents_health(self):
        """Проверка здоровья всех зарегистрированных агентов"""
        for agent_id, agent in self.agents.items():
            try:
                health_check = await self._check_agent_health(agent)
                self.agent_metrics_history[agent_id].append(health_check)
                
            except Exception as e:
                logger.error(f"Error checking health of agent {agent_id}: {e}")

    async def _check_agent_health(self, agent: BaseAgent) -> AgentHealthCheck:
        """Проверка здоровья конкретного агента"""
        start_time = time.time()
        
        # Получение статуса агента
        try:
            status_info = agent.get_status()
            response_time = (time.time() - start_time) * 1000
        except Exception as e:
            logger.warning(f"Failed to get status for agent {agent.agent_id}: {e}")
            response_time = -1
            status_info = {"status": "error"}
        
        # Вычисление health score
        health_score = self._calculate_health_score(agent, response_time)
        
        return AgentHealthCheck(
            agent_id=agent.agent_id,
            timestamp=time.time(),
            status=status_info.get("status", "unknown"),
            response_time_ms=response_time,
            cpu_usage=status_info.get("metrics", {}).get("cpu_usage", 0.0),
            memory_usage=status_info.get("metrics", {}).get("memory_usage", 0.0),
            message_queue_size=len(agent._running_tasks) if hasattr(agent, '_running_tasks') else 0,
            last_activity=agent.metrics.last_activity.timestamp() if agent.metrics.last_activity else None,
            error_count=agent.metrics.failed_messages,
            health_score=health_score
        )

    def _calculate_health_score(self, agent: BaseAgent, response_time: float) -> float:
        """Вычисление общего показателя здоровья агента (0-100)"""
        score = 100.0
        
        # Штраф за статус
        if agent.status == AgentStatus.ERROR:
            score -= 30
        elif agent.status == AgentStatus.STOPPING:
            score -= 20
        elif agent.status != AgentStatus.RUNNING and agent.status != AgentStatus.IDLE:
            score -= 10
        
        # Штраф за медленный отклик
        if response_time > 0:
            if response_time > 5000:  # > 5 секунд
                score -= 20
            elif response_time > 2000:  # > 2 секунд
                score -= 10
            elif response_time > 1000:  # > 1 секунды
                score -= 5
        
        # Бонус/штраф за успешность
        if agent.metrics.total_messages > 0:
            success_rate = agent.metrics.success_messages / agent.metrics.total_messages
            if success_rate < 0.5:
                score -= 25
            elif success_rate < 0.7:
                score -= 15
            elif success_rate < 0.9:
                score -= 5
            else:
                score += 5  # бонус за высокую успешность
        
        # Штраф за неактивность
        if agent.metrics.last_activity:
            inactive_time = time.time() - agent.metrics.last_activity.timestamp()
            if inactive_time > 3600:  # > 1 часа
                score -= 15
            elif inactive_time > 1800:  # > 30 минут
                score -= 10
        
        return max(0.0, min(100.0, score))

    def _update_router_metrics(self):
        """Обновление метрик в роутере для балансировки нагрузки"""
        for agent_id, agent in self.agents.items():
            # Получение последней проверки здоровья
            if agent_id in self.agent_metrics_history and self.agent_metrics_history[agent_id]:
                latest_check = self.agent_metrics_history[agent_id][-1]
                
                # Обновление метрик в роутере
                self.router.update_agent_metrics(
                    agent_id=agent_id,
                    current_load=len(agent._running_tasks) if hasattr(agent, '_running_tasks') else 0,
                    max_capacity=agent.config.get('max_concurrent_tasks', 5),
                    avg_response_time=latest_check.response_time_ms,
                    success_rate=agent.metrics.success_messages / max(1, agent.metrics.total_messages)
                )

    async def _analyze_and_alert(self):
        """Анализ метрик и генерация алертов"""
        current_time = time.time()
        
        # Проверка системных алертов
        if self.system_metrics_history:
            latest_system = self.system_metrics_history[-1]
            
            # CPU алерт
            if latest_system.cpu_percent > self.alert_thresholds["cpu_high"]:
                await self._create_alert("system_cpu_high", 
                                       f"High CPU usage: {latest_system.cpu_percent:.1f}%")
            
            # Memory алерт
            if latest_system.memory_percent > self.alert_thresholds["memory_high"]:
                await self._create_alert("system_memory_high",
                                       f"High memory usage: {latest_system.memory_percent:.1f}%")
        
        # Проверка алертов по агентам
        for agent_id, history in self.agent_metrics_history.items():
            if not history:
                continue
                
            latest_check = history[-1]
            
            # Response time алерт
            if latest_check.response_time_ms > self.alert_thresholds["response_time_high"]:
                await self._create_alert(f"agent_{agent_id}_slow_response",
                                       f"Slow response: {latest_check.response_time_ms:.1f}ms")
            
            # Health score алерт
            if latest_check.health_score < self.alert_thresholds["health_score_low"]:
                await self._create_alert(f"agent_{agent_id}_poor_health",
                                       f"Poor health score: {latest_check.health_score:.1f}/100")

    async def _create_alert(self, alert_id: str, message: str, severity: str = "warning"):
        """Создание нового алерта"""
        if alert_id in self.active_alerts:
            # Обновление существующего алерта
            self.active_alerts[alert_id]["count"] += 1
            self.active_alerts[alert_id]["last_seen"] = time.time()
        else:
            # Новый алерт
            self.active_alerts[alert_id] = {
                "message": message,
                "severity": severity,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "count": 1
            }
            logger.warning(f"New alert [{severity}]: {message}")

    async def _cleanup_loop(self):
        """Очистка старых алертов и данных"""
        while self.monitoring_active:
            try:
                await asyncio.sleep(300)  # каждые 5 минут
                
                current_time = time.time()
                
                # Удаление старых алертов (старше 1 часа)
                expired_alerts = [
                    alert_id for alert_id, alert in self.active_alerts.items()
                    if current_time - alert["last_seen"] > 3600
                ]
                
                for alert_id in expired_alerts:
                    del self.active_alerts[alert_id]
                    logger.debug(f"Removed expired alert: {alert_id}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Получение данных для дашборда мониторинга"""
        current_time = time.time()
        uptime = current_time - self.start_time
        
        # Системные метрики
        system_status = "unknown"
        latest_system = None
        if self.system_metrics_history:
            latest_system = self.system_metrics_history[-1]
            system_status = "healthy"
            if (latest_system.cpu_percent > 80 or 
                latest_system.memory_percent > 85):
                system_status = "warning"
            if (latest_system.cpu_percent > 95 or 
                latest_system.memory_percent > 95):
                system_status = "critical"
        
        # Статус агентов
        agent_statuses = {}
        for agent_id, agent in self.agents.items():
            latest_check = None
            if agent_id in self.agent_metrics_history and self.agent_metrics_history[agent_id]:
                latest_check = self.agent_metrics_history[agent_id][-1]
            
            agent_statuses[agent_id] = {
                "status": agent.status.value,
                "health_score": latest_check.health_score if latest_check else 0,
                "response_time": latest_check.response_time_ms if latest_check else -1,
                "success_rate": (agent.metrics.success_messages / max(1, agent.metrics.total_messages) * 100),
                "total_messages": agent.metrics.total_messages,
                "active_tasks": len(agent._running_tasks) if hasattr(agent, '_running_tasks') else 0
            }
        
        return {
            "timestamp": current_time,
            "uptime_seconds": uptime,
            "monitoring_active": self.monitoring_active,
            "system": {
                "status": system_status,
                "cpu_percent": latest_system.cpu_percent if latest_system else 0,
                "memory_percent": latest_system.memory_percent if latest_system else 0,
                "disk_percent": latest_system.disk_usage_percent if latest_system else 0,
                "load_average": latest_system.load_average if latest_system else [0, 0, 0]
            },
            "agents": {
                "total": len(self.agents),
                "running": sum(1 for a in self.agents.values() if a.status == AgentStatus.RUNNING),
                "idle": sum(1 for a in self.agents.values() if a.status == AgentStatus.IDLE),
                "error": sum(1 for a in self.agents.values() if a.status == AgentStatus.ERROR),
                "statuses": agent_statuses
            },
            "alerts": {
                "total": len(self.active_alerts),
                "critical": sum(1 for a in self.active_alerts.values() if a["severity"] == "critical"),
                "warning": sum(1 for a in self.active_alerts.values() if a["severity"] == "warning"),
                "active": self.active_alerts
            },
            "router_stats": self.router.get_routing_stats() if self.router else {}
        }

    def export_metrics_prometheus(self) -> str:
        """Экспорт метрик в формате Prometheus"""
        lines = []
        current_time = int(time.time() * 1000)
        
        # Системные метрики
        if self.system_metrics_history:
            latest_system = self.system_metrics_history[-1]
            lines.append(f"aethernova_system_cpu_percent {latest_system.cpu_percent} {current_time}")
            lines.append(f"aethernova_system_memory_percent {latest_system.memory_percent} {current_time}")
            lines.append(f"aethernova_system_disk_percent {latest_system.disk_usage_percent} {current_time}")
        
        # Метрики агентов
        for agent_id, agent in self.agents.items():
            if agent_id in self.agent_metrics_history and self.agent_metrics_history[agent_id]:
                latest_check = self.agent_metrics_history[agent_id][-1]
                lines.append(f'aethernova_agent_health_score{{agent_id="{agent_id}"}} {latest_check.health_score} {current_time}')
                lines.append(f'aethernova_agent_response_time{{agent_id="{agent_id}"}} {latest_check.response_time_ms} {current_time}')
                lines.append(f'aethernova_agent_total_messages{{agent_id="{agent_id}"}} {agent.metrics.total_messages} {current_time}')
                lines.append(f'aethernova_agent_success_messages{{agent_id="{agent_id}"}} {agent.metrics.success_messages} {current_time}')
        
        return "\n".join(lines)