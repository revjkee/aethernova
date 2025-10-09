from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json

from .monitor import agent_monitor
from ..registry import agent_registry

# Создание роутера для дашборда
dashboard_router = APIRouter(prefix="/dashboard", tags=["Monitoring Dashboard"])

# Настройка шаблонов (в реальной реализации нужно создать папку templates)
templates = Jinja2Templates(directory="templates")

@dashboard_router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Главная страница дашборда"""
    return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Agents Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        .charts-section {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .agents-table {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        .status-healthy { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-critical { color: #dc3545; }
        .status-down { color: #6c757d; }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .refresh-btn {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin-left: 10px;
        }
        .alerts-section {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-top: 20px;
        }
        .alert-item {
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }
        .alert-critical {
            background-color: #f8d7da;
            border-left-color: #dc3545;
        }
        .alert-warning {
            background-color: #fff3cd;
            border-left-color: #ffc107;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🤖 AI Agents Monitoring Dashboard</h1>
        <p>Мониторинг производительности и здоровья системы агентов</p>
        <button class="refresh-btn" onclick="refreshData()">🔄 Обновить</button>
    </div>

    <div class="stats-grid" id="statsGrid">
        <!-- Stats cards will be populated here -->
    </div>

    <div class="charts-section">
        <div class="chart-container">
            <h3>Загрузка системы</h3>
            <canvas id="systemLoadChart"></canvas>
        </div>
        <div class="chart-container">
            <h3>Производительность агентов</h3>
            <canvas id="performanceChart"></canvas>
        </div>
    </div>

    <div class="agents-table">
        <h3>Статус агентов</h3>
        <table id="agentsTable">
            <thead>
                <tr>
                    <th>Agent ID</th>
                    <th>Тип</th>
                    <th>Статус</th>
                    <th>CPU %</th>
                    <th>Memory %</th>
                    <th>Задач/мин</th>
                    <th>Успешность %</th>
                    <th>Время отклика</th>
                </tr>
            </thead>
            <tbody>
                <!-- Agent data will be populated here -->
            </tbody>
        </table>
    </div>

    <div class="alerts-section">
        <h3>🚨 Активные алерты</h3>
        <div id="alertsContainer">
            <!-- Alerts will be populated here -->
        </div>
    </div>

    <script>
        let systemLoadChart, performanceChart;
        
        async function fetchData(endpoint) {
            try {
                const response = await fetch(`/dashboard/api${endpoint}`);
                return await response.json();
            } catch (error) {
                console.error('Error fetching data:', error);
                return null;
            }
        }
        
        async function refreshData() {
            await Promise.all([
                updateStats(),
                updateCharts(), 
                updateAgentsTable(),
                updateAlerts()
            ]);
        }
        
        async function updateStats() {
            const overview = await fetchData('/overview');
            if (!overview) return;
            
            const statsGrid = document.getElementById('statsGrid');
            statsGrid.innerHTML = `
                <div class="stat-card">
                    <div class="stat-value">${overview.total_agents}</div>
                    <div class="stat-label">Всего агентов</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value status-healthy">${overview.healthy_agents}</div>
                    <div class="stat-label">Здоровых</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value status-warning">${overview.unhealthy_agents}</div>
                    <div class="stat-label">Проблемных</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value status-critical">${overview.active_alerts}</div>
                    <div class="stat-label">Активных алертов</div>
                </div>
            `;
        }
        
        async function updateCharts() {
            const metrics = await fetchData('/metrics/system');
            if (!metrics) return;
            
            // Update system load chart
            if (systemLoadChart) {
                systemLoadChart.destroy();
            }
            
            const ctx1 = document.getElementById('systemLoadChart').getContext('2d');
            systemLoadChart = new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: metrics.timestamps,
                    datasets: [{
                        label: 'CPU Usage %',
                        data: metrics.cpu_usage,
                        borderColor: 'rgb(255, 99, 132)',
                        tension: 0.1
                    }, {
                        label: 'Memory Usage %',
                        data: metrics.memory_usage,
                        borderColor: 'rgb(54, 162, 235)',
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100
                        }
                    }
                }
            });
            
            // Update performance chart
            if (performanceChart) {
                performanceChart.destroy();
            }
            
            const ctx2 = document.getElementById('performanceChart').getContext('2d');
            performanceChart = new Chart(ctx2, {
                type: 'bar',
                data: {
                    labels: metrics.agent_names,
                    datasets: [{
                        label: 'Задач в минуту',
                        data: metrics.tasks_per_minute,
                        backgroundColor: 'rgba(75, 192, 192, 0.6)'
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        
        async function updateAgentsTable() {
            const agents = await fetchData('/agents');
            if (!agents) return;
            
            const tbody = document.querySelector('#agentsTable tbody');
            tbody.innerHTML = agents.map(agent => `
                <tr>
                    <td>${agent.agent_id}</td>
                    <td>${agent.type}</td>
                    <td><span class="status-${agent.status}">${agent.status}</span></td>
                    <td>${agent.cpu_usage?.toFixed(1) || 'N/A'}</td>
                    <td>${agent.memory_usage?.toFixed(1) || 'N/A'}</td>
                    <td>${agent.tasks_per_minute?.toFixed(1) || 'N/A'}</td>
                    <td>${agent.success_rate?.toFixed(1) || 'N/A'}</td>
                    <td>${agent.response_time?.toFixed(0) || 'N/A'}ms</td>
                </tr>
            `).join('');
        }
        
        async function updateAlerts() {
            const alerts = await fetchData('/alerts');
            if (!alerts) return;
            
            const container = document.getElementById('alertsContainer');
            
            if (alerts.length === 0) {
                container.innerHTML = '<p>✅ Нет активных алертов</p>';
                return;
            }
            
            container.innerHTML = alerts.map(alert => `
                <div class="alert-item alert-${alert.severity}">
                    <strong>${alert.severity.toUpperCase()}</strong> - Agent ${alert.agent_id}
                    <br>${alert.message}
                    <br><small>Время: ${new Date(alert.triggered_at).toLocaleString()}</small>
                </div>
            `).join('');
        }
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            refreshData();
            // Auto-refresh every 30 seconds
            setInterval(refreshData, 30000);
        });
    </script>
</body>
</html>
    """)

# API endpoints для данных дашборда

@dashboard_router.get("/api/overview")
async def get_system_overview():
    """Получение общего обзора системы"""
    try:
        overview = await agent_monitor.get_system_overview()
        return overview
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@dashboard_router.get("/api/agents")
async def get_agents_status():
    """Получение статуса всех агентов"""
    try:
        agents_data = []
        
        for agent_id, agent_info in agent_registry.agents.items():
            agent = agent_info["agent"]
            
            # Получение метрик
            metrics_list = await agent_monitor.get_agent_metrics(agent_id, hours=1)
            latest_metrics = metrics_list[-1] if metrics_list else None
            
            # Получение здоровья
            health = await agent_monitor.get_agent_health(agent_id)
            
            agent_data = {
                "agent_id": agent_id,
                "type": agent.__class__.__name__,
                "status": health.status if health else "unknown",
                "cpu_usage": latest_metrics.cpu_usage if latest_metrics else None,
                "memory_usage": latest_metrics.memory_usage if latest_metrics else None,
                "tasks_per_minute": latest_metrics.tasks_per_minute if latest_metrics else None,
                "success_rate": latest_metrics.success_rate * 100 if latest_metrics else None,
                "response_time": latest_metrics.response_time if latest_metrics else None
            }
            
            agents_data.append(agent_data)
            
        return agents_data
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@dashboard_router.get("/api/metrics/system")
async def get_system_metrics():
    """Получение системных метрик для графиков"""
    try:
        # Агрегированные метрики за последний час
        all_metrics = {}
        
        for agent_id in agent_registry.agents.keys():
            metrics_list = await agent_monitor.get_agent_metrics(agent_id, hours=1)
            if metrics_list:
                all_metrics[agent_id] = metrics_list
                
        # Подготовка данных для графиков
        timestamps = []
        cpu_usage = []
        memory_usage = []
        agent_names = []
        tasks_per_minute = []
        
        # Временные метки (последние 10 точек)
        if all_metrics:
            sample_metrics = next(iter(all_metrics.values()))
            timestamps = [m.timestamp.strftime("%H:%M") for m in sample_metrics[-10:]]
            
            # Средние значения CPU и памяти по времени
            for i in range(len(timestamps)):
                cpu_values = []
                memory_values = []
                
                for agent_metrics in all_metrics.values():
                    if i < len(agent_metrics):
                        cpu_values.append(agent_metrics[i].cpu_usage)
                        memory_values.append(agent_metrics[i].memory_usage)
                        
                cpu_usage.append(sum(cpu_values) / len(cpu_values) if cpu_values else 0)
                memory_usage.append(sum(memory_values) / len(memory_values) if memory_values else 0)
                
        # Производительность по агентам
        for agent_id, metrics_list in all_metrics.items():
            agent_names.append(agent_id)
            if metrics_list:
                avg_tpm = sum(m.tasks_per_minute for m in metrics_list[-5:]) / min(5, len(metrics_list))
                tasks_per_minute.append(avg_tpm)
            else:
                tasks_per_minute.append(0)
                
        return {
            "timestamps": timestamps,
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
            "agent_names": agent_names,
            "tasks_per_minute": tasks_per_minute
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@dashboard_router.get("/api/alerts")
async def get_active_alerts():
    """Получение активных алертов"""
    try:
        alerts = await agent_monitor.get_active_alerts()
        
        return [
            {
                "alert_id": alert.alert_id,
                "agent_id": alert.agent_id,
                "severity": alert.severity,
                "message": alert.message,
                "triggered_at": alert.triggered_at.isoformat()
            }
            for alert in alerts
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@dashboard_router.get("/api/agent/{agent_id}/metrics")
async def get_agent_detailed_metrics(agent_id: str, hours: int = 1):
    """Получение детальных метрик агента"""
    try:
        if agent_id not in agent_registry.agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
            
        metrics = await agent_monitor.get_agent_metrics(agent_id, hours=hours)
        health = await agent_monitor.get_agent_health(agent_id)
        alerts = await agent_monitor.get_active_alerts(agent_id)
        
        return {
            "agent_id": agent_id,
            "metrics": [
                {
                    "timestamp": m.timestamp.isoformat(),
                    "cpu_usage": m.cpu_usage,
                    "memory_usage": m.memory_usage,
                    "response_time": m.response_time,
                    "tasks_per_minute": m.tasks_per_minute,
                    "error_rate": m.error_rate,
                    "success_rate": m.success_rate
                }
                for m in metrics
            ],
            "health": {
                "status": health.status,
                "is_healthy": health.is_healthy,
                "issues": health.issues,
                "recommendations": health.recommendations,
                "uptime": str(health.uptime)
            } if health else None,
            "active_alerts": len(alerts)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))