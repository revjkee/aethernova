# agent_mash/monitoring/monitoring_dashboard.py

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import json
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
import time

# Импорты для веб-интерфейса (опционально)
try:
    from flask import Flask, render_template_string, jsonify, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class MetricSnapshot:
    """Снимок метрик в определенный момент времени"""
    timestamp: datetime
    agent_id: str
    metric_name: str
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SystemHealth:
    """Общее состояние системы"""
    timestamp: datetime
    total_agents: int
    active_agents: int
    total_tasks_processed: int
    avg_response_time: float
    success_rate: float
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    error_rate: float = 0.0

class MetricsCollector:
    """Сборщик метрик для агентов"""
    
    def __init__(self, max_history_size: int = 1000):
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history_size))
        self.system_health_history: deque = deque(maxlen=max_history_size)
        self.alert_thresholds = {
            'max_response_time': 30.0,
            'min_success_rate': 0.85,
            'max_error_rate': 0.15,
            'max_cpu_usage': 80.0,
            'max_memory_usage': 90.0
        }
        self.active_alerts: Dict[str, Dict[str, Any]] = {}
        
    async def collect_agent_metrics(self, agent) -> List[MetricSnapshot]:
        """Сбор метрик от агента"""
        try:
            status = await agent.get_enhanced_status()
            timestamp = datetime.utcnow()
            metrics = []
            
            # Базовые метрики производительности
            perf_metrics = status.get('performance_metrics', {})
            
            metrics.extend([
                MetricSnapshot(
                    timestamp=timestamp,
                    agent_id=agent.agent_id,
                    metric_name='decisions_made',
                    value=perf_metrics.get('decisions_made', 0)
                ),
                MetricSnapshot(
                    timestamp=timestamp,
                    agent_id=agent.agent_id,
                    metric_name='successful_decisions',
                    value=perf_metrics.get('successful_decisions', 0)
                ),
                MetricSnapshot(
                    timestamp=timestamp,
                    agent_id=agent.agent_id,
                    metric_name='avg_processing_time',
                    value=perf_metrics.get('avg_processing_time', 0.0)
                ),
                MetricSnapshot(
                    timestamp=timestamp,
                    agent_id=agent.agent_id,
                    metric_name='api_calls_made',
                    value=perf_metrics.get('api_calls_made', 0)
                )
            ])
            
            # Вычисляемые метрики
            total_decisions = perf_metrics.get('decisions_made', 0)
            if total_decisions > 0:
                success_rate = perf_metrics.get('successful_decisions', 0) / total_decisions
                metrics.append(MetricSnapshot(
                    timestamp=timestamp,
                    agent_id=agent.agent_id,
                    metric_name='success_rate',
                    value=success_rate
                ))
                
            # Метрики памяти
            memory_stats = status.get('memory', {})
            metrics.extend([
                MetricSnapshot(
                    timestamp=timestamp,
                    agent_id=agent.agent_id,
                    metric_name='short_term_memory_items',
                    value=memory_stats.get('short_term_items', 0)
                ),
                MetricSnapshot(
                    timestamp=timestamp,
                    agent_id=agent.agent_id,
                    metric_name='episodic_memories',
                    value=memory_stats.get('episodic_memories', 0)
                )
            ])
            
            # Сохранение метрик
            for metric in metrics:
                self.metrics_history[f"{metric.agent_id}.{metric.metric_name}"].append(metric)
                
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting metrics for agent {agent.agent_id}: {e}")
            return []
            
    async def collect_system_health(self, orchestra) -> SystemHealth:
        """Сбор общих метрик системы"""
        try:
            status = await orchestra.get_orchestra_status()
            timestamp = datetime.utcnow()
            
            stats = status.get('orchestra_stats', {})
            agents = status.get('agents', {})
            
            # Подсчет активных агентов
            active_agents = sum(1 for agent_info in agents.values() 
                              if agent_info.get('status') in ['running', 'idle'])
            
            # Расчет средней успешности
            total_success = 0
            total_decisions = 0
            total_response_time = 0.0
            agent_count = 0
            
            for agent_info in agents.values():
                metrics = agent_info.get('metrics', {})
                if metrics:
                    agent_count += 1
                    total_decisions += metrics.get('tasks_completed', 0) + metrics.get('tasks_failed', 0)
                    total_success += metrics.get('tasks_completed', 0)
                    total_response_time += metrics.get('avg_execution_time', 0.0)
                    
            success_rate = total_success / max(total_decisions, 1)
            avg_response_time = total_response_time / max(agent_count, 1)
            
            # Получение системных метрик (упрощенная версия)
            try:
                import psutil
                cpu_usage = psutil.cpu_percent(interval=1)
                memory_usage = psutil.virtual_memory().percent
            except ImportError:
                cpu_usage = 0.0
                memory_usage = 0.0
                
            health = SystemHealth(
                timestamp=timestamp,
                total_agents=len(agents),
                active_agents=active_agents,
                total_tasks_processed=stats.get('total_tasks_processed', 0),
                avg_response_time=avg_response_time,
                success_rate=success_rate,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                error_rate=1.0 - success_rate
            )
            
            self.system_health_history.append(health)
            
            # Проверка алертов
            await self._check_alerts(health)
            
            return health
            
        except Exception as e:
            logger.error(f"Error collecting system health: {e}")
            return SystemHealth(
                timestamp=datetime.utcnow(),
                total_agents=0,
                active_agents=0,
                total_tasks_processed=0,
                avg_response_time=0.0,
                success_rate=0.0
            )
            
    async def _check_alerts(self, health: SystemHealth):
        """Проверка условий для алертов"""
        alerts_to_trigger = []
        alerts_to_clear = []
        
        # Проверка времени отклика
        if health.avg_response_time > self.alert_thresholds['max_response_time']:
            if 'high_response_time' not in self.active_alerts:
                alerts_to_trigger.append({
                    'id': 'high_response_time',
                    'severity': 'warning',
                    'message': f'High response time: {health.avg_response_time:.2f}s',
                    'timestamp': health.timestamp
                })
        else:
            if 'high_response_time' in self.active_alerts:
                alerts_to_clear.append('high_response_time')
                
        # Проверка успешности
        if health.success_rate < self.alert_thresholds['min_success_rate']:
            if 'low_success_rate' not in self.active_alerts:
                alerts_to_trigger.append({
                    'id': 'low_success_rate',
                    'severity': 'critical',
                    'message': f'Low success rate: {health.success_rate:.1%}',
                    'timestamp': health.timestamp
                })
        else:
            if 'low_success_rate' in self.active_alerts:
                alerts_to_clear.append('low_success_rate')
                
        # Проверка использования CPU
        if health.cpu_usage > self.alert_thresholds['max_cpu_usage']:
            if 'high_cpu_usage' not in self.active_alerts:
                alerts_to_trigger.append({
                    'id': 'high_cpu_usage',
                    'severity': 'warning',
                    'message': f'High CPU usage: {health.cpu_usage:.1f}%',
                    'timestamp': health.timestamp
                })
        else:
            if 'high_cpu_usage' in self.active_alerts:
                alerts_to_clear.append('high_cpu_usage')
                
        # Активация новых алертов
        for alert in alerts_to_trigger:
            self.active_alerts[alert['id']] = alert
            logger.warning(f"ALERT: {alert['message']}")
            
        # Очистка разрешенных алертов
        for alert_id in alerts_to_clear:
            if alert_id in self.active_alerts:
                logger.info(f"ALERT CLEARED: {alert_id}")
                del self.active_alerts[alert_id]
                
    def get_metrics_summary(self, agent_id: Optional[str] = None, 
                          time_range: Optional[timedelta] = None) -> Dict[str, Any]:
        """Получение сводки метрик"""
        if time_range is None:
            time_range = timedelta(hours=1)
            
        cutoff_time = datetime.utcnow() - time_range
        
        summary = {
            'agents': {},
            'system': {},
            'alerts': list(self.active_alerts.values())
        }
        
        # Метрики агентов
        for metric_key, history in self.metrics_history.items():
            if '.' not in metric_key:
                continue
                
            agent_id_part, metric_name = metric_key.split('.', 1)
            
            if agent_id and agent_id != agent_id_part:
                continue
                
            # Фильтрация по времени
            recent_metrics = [m for m in history if m.timestamp >= cutoff_time]
            
            if not recent_metrics:
                continue
                
            if agent_id_part not in summary['agents']:
                summary['agents'][agent_id_part] = {}
                
            if recent_metrics:
                values = [m.value for m in recent_metrics]
                summary['agents'][agent_id_part][metric_name] = {
                    'current': values[-1] if values else 0,
                    'min': min(values),
                    'max': max(values),
                    'avg': sum(values) / len(values),
                    'count': len(values)
                }
                
        # Системные метрики
        recent_health = [h for h in self.system_health_history if h.timestamp >= cutoff_time]
        
        if recent_health:
            summary['system'] = {
                'current_agents': recent_health[-1].total_agents,
                'active_agents': recent_health[-1].active_agents,
                'tasks_processed': recent_health[-1].total_tasks_processed,
                'avg_response_time': sum(h.avg_response_time for h in recent_health) / len(recent_health),
                'success_rate': sum(h.success_rate for h in recent_health) / len(recent_health),
                'cpu_usage': recent_health[-1].cpu_usage,
                'memory_usage': recent_health[-1].memory_usage
            }
            
        return summary

class MonitoringDashboard:
    """Dashboard для мониторинга агентов"""
    
    def __init__(self, orchestra, metrics_collector: MetricsCollector):
        self.orchestra = orchestra
        self.metrics_collector = metrics_collector
        self.monitoring_enabled = True
        self.monitoring_interval = 30  # секунды
        self.monitoring_task = None
        
        # Flask приложение если доступно
        self.flask_app = None
        if FLASK_AVAILABLE:
            self._setup_flask_app()
            
    def _setup_flask_app(self):
        """Настройка Flask веб-интерфейса"""
        self.flask_app = Flask(__name__)
        
        @self.flask_app.route('/')
        def dashboard():
            return render_template_string(DASHBOARD_TEMPLATE)
            
        @self.flask_app.route('/api/metrics')
        def get_metrics():
            time_range_hours = request.args.get('hours', 1, type=int)
            time_range = timedelta(hours=time_range_hours)
            
            summary = self.metrics_collector.get_metrics_summary(time_range=time_range)
            return jsonify(summary)
            
        @self.flask_app.route('/api/agents')
        def get_agents():
            try:
                status = asyncio.run(self.orchestra.get_orchestra_status())
                return jsonify(status.get('agents', {}))
            except Exception as e:
                return jsonify({'error': str(e)}), 500
                
        @self.flask_app.route('/api/health')
        def get_health():
            if self.metrics_collector.system_health_history:
                health = self.metrics_collector.system_health_history[-1]
                return jsonify(asdict(health))
            return jsonify({'error': 'No health data available'}), 404
            
    async def start_monitoring(self):
        """Запуск мониторинга"""
        if self.monitoring_task is None:
            self.monitoring_enabled = True
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            logger.info("Monitoring started")
            
    async def stop_monitoring(self):
        """Остановка мониторинга"""
        self.monitoring_enabled = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
            self.monitoring_task = None
        logger.info("Monitoring stopped")
        
    async def _monitoring_loop(self):
        """Основной цикл мониторинга"""
        while self.monitoring_enabled:
            try:
                # Сбор метрик от всех агентов
                for agent in self.orchestra.agents.values():
                    await self.metrics_collector.collect_agent_metrics(agent)
                    
                # Сбор системных метрик
                await self.metrics_collector.collect_system_health(self.orchestra)
                
                # Вывод сводной информации
                await self._log_summary()
                
                await asyncio.sleep(self.monitoring_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(self.monitoring_interval)
                
    async def _log_summary(self):
        """Логирование сводной информации"""
        if not self.metrics_collector.system_health_history:
            return
            
        health = self.metrics_collector.system_health_history[-1]
        
        logger.info("=" * 50)
        logger.info("МОНИТОРИНГ СИСТЕМЫ АГЕНТОВ")
        logger.info("=" * 50)
        logger.info(f"Время: {health.timestamp.strftime('%H:%M:%S')}")
        logger.info(f"Агентов всего: {health.total_agents}")
        logger.info(f"Агентов активных: {health.active_agents}")
        logger.info(f"Обработано задач: {health.total_tasks_processed}")
        logger.info(f"Среднее время отклика: {health.avg_response_time:.2f}с")
        logger.info(f"Успешность: {health.success_rate:.1%}")
        
        if health.cpu_usage > 0:
            logger.info(f"CPU: {health.cpu_usage:.1f}%")
            logger.info(f"Память: {health.memory_usage:.1f}%")
            
        # Активные алерты
        if self.metrics_collector.active_alerts:
            logger.warning(f"Активных алертов: {len(self.metrics_collector.active_alerts)}")
            for alert in self.metrics_collector.active_alerts.values():
                logger.warning(f"  - {alert['severity'].upper()}: {alert['message']}")
        else:
            logger.info("Алерты отсутствуют ✅")
            
    def run_web_dashboard(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
        """Запуск веб-dashboard"""
        if not FLASK_AVAILABLE:
            logger.error("Flask не установлен. Установите: pip install flask")
            return
            
        if not self.flask_app:
            logger.error("Flask приложение не настроено")
            return
            
        logger.info(f"Запуск веб-dashboard на http://{host}:{port}")
        self.flask_app.run(host=host, port=port, debug=debug, use_reloader=False)
        
    def generate_report(self, time_range: timedelta = None) -> Dict[str, Any]:
        """Генерация отчета о производительности"""
        if time_range is None:
            time_range = timedelta(hours=24)
            
        summary = self.metrics_collector.get_metrics_summary(time_range=time_range)
        
        report = {
            'report_generated': datetime.utcnow().isoformat(),
            'time_range_hours': time_range.total_seconds() / 3600,
            'summary': summary,
            'recommendations': []
        }
        
        # Анализ и рекомендации
        system_metrics = summary.get('system', {})
        
        if system_metrics.get('avg_response_time', 0) > 10:
            report['recommendations'].append({
                'type': 'performance',
                'message': 'Высокое время отклика. Рассмотрите масштабирование системы.',
                'priority': 'high'
            })
            
        if system_metrics.get('success_rate', 1) < 0.9:
            report['recommendations'].append({
                'type': 'reliability',
                'message': 'Низкая успешность выполнения задач. Проверьте логи на ошибки.',
                'priority': 'critical'
            })
            
        if system_metrics.get('cpu_usage', 0) > 80:
            report['recommendations'].append({
                'type': 'resources',
                'message': 'Высокая загрузка CPU. Требуется оптимизация или увеличение ресурсов.',
                'priority': 'high'
            })
            
        return report

# HTML шаблон для веб-dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Agents Monitoring Dashboard</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 20px; 
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .card { 
            background: white; 
            padding: 20px; 
            margin: 10px 0; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metrics { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
        }
        .metric { 
            text-align: center; 
            padding: 15px;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            border-radius: 8px;
        }
        .metric-value { 
            font-size: 2em; 
            font-weight: bold; 
        }
        .metric-label { 
            font-size: 0.9em; 
            opacity: 0.9; 
        }
        .alert { 
            background: #f8d7da; 
            color: #721c24; 
            padding: 10px; 
            border-radius: 4px; 
            margin: 5px 0; 
        }
        .refresh-btn {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px;
        }
        .refresh-btn:hover { 
            background: #0056b3; 
        }
        .status-running { color: #28a745; }
        .status-idle { color: #ffc107; }
        .status-error { color: #dc3545; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🤖 AI Agents Monitoring Dashboard</h1>
        <p>Мониторинг системы улучшенных AI агентов в реальном времени</p>
    </div>

    <button class="refresh-btn" onclick="refreshData()">🔄 Обновить данные</button>
    <button class="refresh-btn" onclick="toggleAutoRefresh()">⏱️ Авто-обновление</button>

    <div class="card">
        <h2>📊 Системные метрики</h2>
        <div class="metrics" id="systemMetrics">
            <div class="metric">
                <div class="metric-value" id="totalAgents">-</div>
                <div class="metric-label">Всего агентов</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="activeAgents">-</div>
                <div class="metric-label">Активных агентов</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="tasksProcessed">-</div>
                <div class="metric-label">Задач обработано</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="successRate">-</div>
                <div class="metric-label">Успешность</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="responseTime">-</div>
                <div class="metric-label">Время отклика (сек)</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="cpuUsage">-</div>
                <div class="metric-label">CPU %</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>⚠️ Активные алерты</h2>
        <div id="alerts">Загрузка...</div>
    </div>

    <div class="card">
        <h2>🤖 Состояние агентов</h2>
        <div id="agentsList">Загрузка...</div>
    </div>

    <div class="card">
        <h2>📈 Детальные метрики агентов</h2>
        <div id="agentMetrics">Загрузка...</div>
    </div>

    <script>
        let autoRefresh = false;
        let refreshInterval;

        async function fetchData(url) {
            try {
                const response = await fetch(url);
                return await response.json();
            } catch (error) {
                console.error('Ошибка загрузки данных:', error);
                return null;
            }
        }

        async function refreshData() {
            // Системные метрики
            const health = await fetchData('/api/health');
            if (health) {
                document.getElementById('totalAgents').textContent = health.total_agents || 0;
                document.getElementById('activeAgents').textContent = health.active_agents || 0;
                document.getElementById('tasksProcessed').textContent = health.total_tasks_processed || 0;
                document.getElementById('successRate').textContent = 
                    ((health.success_rate || 0) * 100).toFixed(1) + '%';
                document.getElementById('responseTime').textContent = 
                    (health.avg_response_time || 0).toFixed(2);
                document.getElementById('cpuUsage').textContent = 
                    (health.cpu_usage || 0).toFixed(1);
            }

            // Метрики и алерты
            const metrics = await fetchData('/api/metrics');
            if (metrics) {
                // Алерты
                const alertsDiv = document.getElementById('alerts');
                if (metrics.alerts && metrics.alerts.length > 0) {
                    alertsDiv.innerHTML = metrics.alerts.map(alert => 
                        `<div class="alert">${alert.severity.toUpperCase()}: ${alert.message}</div>`
                    ).join('');
                } else {
                    alertsDiv.innerHTML = '<p style="color: green;">✅ Алерты отсутствуют</p>';
                }

                // Детальные метрики агентов
                const agentMetricsDiv = document.getElementById('agentMetrics');
                if (metrics.agents) {
                    let html = '<div class="metrics">';
                    Object.entries(metrics.agents).forEach(([agentId, agentMetrics]) => {
                        html += `<div class="card">
                            <h3>${agentId}</h3>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">`;
                        
                        Object.entries(agentMetrics).forEach(([metricName, metricData]) => {
                            html += `<div style="text-align: center; padding: 10px; background: #f8f9fa; border-radius: 4px;">
                                <div style="font-weight: bold;">${metricData.current || 0}</div>
                                <div style="font-size: 0.8em; color: #666;">${metricName}</div>
                            </div>`;
                        });
                        
                        html += '</div></div>';
                    });
                    html += '</div>';
                    agentMetricsDiv.innerHTML = html;
                } else {
                    agentMetricsDiv.innerHTML = '<p>Нет данных о метриках агентов</p>';
                }
            }

            // Список агентов
            const agents = await fetchData('/api/agents');
            if (agents) {
                const agentsList = document.getElementById('agentsList');
                let html = '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px;">';
                
                Object.entries(agents).forEach(([agentId, agentInfo]) => {
                    const statusClass = `status-${agentInfo.status}`;
                    html += `<div style="border: 1px solid #ddd; padding: 15px; border-radius: 8px;">
                        <h4>${agentId}</h4>
                        <p><strong>Статус:</strong> <span class="${statusClass}">${agentInfo.status}</span></p>
                        <p><strong>Тип:</strong> ${agentInfo.type}</p>
                        <p><strong>Возможности:</strong> ${agentInfo.capabilities.length}</p>
                    </div>`;
                });
                
                html += '</div>';
                agentsList.innerHTML = html;
            }

            document.title = `AI Agents Dashboard - Обновлено ${new Date().toLocaleTimeString()}`;
        }

        function toggleAutoRefresh() {
            autoRefresh = !autoRefresh;
            const btn = event.target;
            
            if (autoRefresh) {
                btn.textContent = '⏸️ Остановить авто-обновление';
                refreshInterval = setInterval(refreshData, 10000); // каждые 10 секунд
            } else {
                btn.textContent = '▶️ Запустить авто-обновление';
                clearInterval(refreshInterval);
            }
        }

        // Первоначальная загрузка данных
        refreshData();
    </script>
</body>
</html>
"""

# Утилитарные функции для быстрого создания мониторинга
async def create_simple_monitoring(orchestra) -> MonitoringDashboard:
    """Создание простой системы мониторинга"""
    collector = MetricsCollector()
    dashboard = MonitoringDashboard(orchestra, collector)
    await dashboard.start_monitoring()
    return dashboard

async def run_monitoring_demo(orchestra):
    """Демонстрация мониторинга"""
    logger.info("🚀 Запуск демонстрации мониторинга")
    
    dashboard = await create_simple_monitoring(orchestra)
    
    try:
        # Запуск мониторинга на 60 секунд
        await asyncio.sleep(60)
        
        # Генерация отчета
        report = dashboard.generate_report(timedelta(minutes=5))
        
        logger.info("📊 Отчет о производительности:")
        logger.info(f"Сгенерирован: {report['report_generated']}")
        logger.info(f"Временной диапазон: {report['time_range_hours']} часов")
        
        if report['recommendations']:
            logger.info("💡 Рекомендации:")
            for rec in report['recommendations']:
                logger.info(f"  - {rec['type']}: {rec['message']} (приоритет: {rec['priority']})")
        else:
            logger.info("✅ Система работает оптимально, рекомендаций нет")
            
        return report
        
    finally:
        await dashboard.stop_monitoring()

if __name__ == "__main__":
    
    async def main():
        """Запуск веб-dashboard отдельно"""
        # Заглушка для демонстрации
        class MockOrchestra:
            def __init__(self):
                self.agents = {}
                
            async def get_orchestra_status(self):
                return {
                    'orchestra_stats': {'total_tasks_processed': 42},
                    'agents': {
                        'demo-agent-1': {
                            'status': 'running',
                            'type': 'chatbot',
                            'capabilities': ['text_processing'],
                            'metrics': {'tasks_completed': 10, 'tasks_failed': 1}
                        }
                    }
                }
        
        mock_orchestra = MockOrchestra()
        collector = MetricsCollector()
        dashboard = MonitoringDashboard(mock_orchestra, collector)
        
        print("Запуск веб-dashboard на http://localhost:5000")
        print("Для остановки нажмите Ctrl+C")
        
        dashboard.run_web_dashboard(host='0.0.0.0', port=5000, debug=True)

    if FLASK_AVAILABLE:
        asyncio.run(main())
    else:
        print("Для запуска веб-dashboard установите Flask: pip install flask")
        print("Для системного мониторинга установите psutil: pip install psutil")