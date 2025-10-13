#!/usr/bin/env python3
"""
AETHERNOVA MEGA INTELLIGENCE SYSTEM
=====================================

Интегрированная система объединяющая:
B. Умная аналитика (genius-core агенты)
C. Граф-анализ (graph-core агенты) 
D. Веб-дашборд (realtime monitoring)
E. Реальные задачи (filesystem, logs, git automation)

Архитектура:
- IntelligenceEngine: Управление AI агентами из genius-core
- GraphAnalyticsEngine: Анализ связей и данных graph-core
- RealTimeWebDashboard: Веб-интерфейс с WebSocket
- RealWorldTaskProcessor: Обработка реальных задач
- MegaOrchestrator: Координирует все компоненты
"""

import asyncio
import logging
import json
import time
import psutil
import websockets
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import subprocess
import os
import git
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Импорты для веб-сервера
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socketserver

# Добавляем наши модули
import sys
sys.path.insert(0, str(Path(__file__).parent))
from core_agents_integrated_launch import ExtendedCoreSystemsOrchestra, CoreSystemsAdapter

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

class TaskPriority(Enum):
    LOW = 1
    MEDIUM = 2 
    HIGH = 3
    CRITICAL = 4

@dataclass
class RealWorldTask:
    """Реальная задача для обработки"""
    id: str
    name: str
    type: str  # 'filesystem', 'git', 'log_analysis', 'system_monitor'
    priority: TaskPriority
    data: Dict[str, Any]
    created_at: datetime
    assigned_agent: Optional[str] = None
    status: str = 'pending'
    result: Optional[Dict] = None

@dataclass
class AgentMetrics:
    """Метрики агента"""
    agent_id: str
    agent_type: str
    core_system: str
    tasks_completed: int = 0
    tasks_failed: int = 0
    avg_processing_time: float = 0.0
    last_activity: Optional[datetime] = None
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    status: str = 'active'

class IntelligenceEngine:
    """Движок умной аналитики с genius-core агентами"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.ai_agents: Dict[str, Any] = {}
        self.analysis_results: List[Dict] = []
        
    async def initialize_genius_agents(self):
        """Инициализация AI агентов из genius-core"""
        self.logger.info("🧠 Инициализация genius-core агентов для умной аналитики")
        
        # Симуляция инициализации различных AI агентов
        genius_agents = [
            {'id': 'goal_evaluator', 'type': 'motivation', 'capabilities': ['goal_analysis', 'priority_evaluation']},
            {'id': 'code_analyzer', 'type': 'code_intelligence', 'capabilities': ['code_summary', 'refactor_suggestions']},
            {'id': 'learning_agent', 'type': 'ml_trainer', 'capabilities': ['model_training', 'performance_evaluation']},
            {'id': 'intent_resolver', 'type': 'decision_maker', 'capabilities': ['intent_analysis', 'action_planning']},
        ]
        
        for agent_config in genius_agents:
            self.ai_agents[agent_config['id']] = agent_config
            self.logger.info(f"✅ AI агент {agent_config['id']} готов: {agent_config['capabilities']}")
    
    async def analyze_system_intelligence(self, system_data: Dict) -> Dict:
        """Интеллектуальный анализ системы"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'system_health': self._calculate_system_health(system_data),
            'performance_insights': self._generate_performance_insights(system_data),
            'optimization_suggestions': self._suggest_optimizations(system_data),
            'anomaly_detection': self._detect_anomalies(system_data)
        }
        
        self.analysis_results.append(analysis)
        return analysis
    
    def _calculate_system_health(self, data: Dict) -> Dict:
        """Расчет здоровья системы"""
        agents_active = data.get('active_agents', 0)
        total_agents = data.get('total_agents', 1)
        
        health_score = min(100, (agents_active / total_agents) * 100)
        
        return {
            'score': health_score,
            'status': 'excellent' if health_score > 90 else 'good' if health_score > 70 else 'needs_attention',
            'active_ratio': f"{agents_active}/{total_agents}"
        }
    
    def _generate_performance_insights(self, data: Dict) -> List[str]:
        """Генерация инсайтов производительности"""
        insights = []
        
        if data.get('avg_task_time', 0) > 5:
            insights.append("Среднее время обработки задач превышает оптимальное")
        
        if data.get('failed_tasks', 0) > 0:
            insights.append(f"Обнаружено {data['failed_tasks']} неудачных задач")
        
        if data.get('cpu_usage', 0) > 80:
            insights.append("Высокая загрузка CPU требует оптимизации")
        
        return insights
    
    def _suggest_optimizations(self, data: Dict) -> List[str]:
        """Предложения по оптимизации"""
        suggestions = []
        
        if data.get('active_agents', 0) < data.get('total_agents', 0) * 0.8:
            suggestions.append("Рекомендуется активировать больше агентов")
        
        if data.get('memory_usage', 0) > 70:
            suggestions.append("Рассмотрите увеличение памяти или оптимизацию алгоритмов")
        
        return suggestions
    
    def _detect_anomalies(self, data: Dict) -> List[str]:
        """Обнаружение аномалий"""
        anomalies = []
        
        if data.get('task_completion_rate', 100) < 95:
            anomalies.append("Низкий процент успешного выполнения задач")
        
        return anomalies

class GraphAnalyticsEngine:
    """Движок граф-аналитики с graph-core агентами"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.graph_agents: Dict[str, Any] = {}
        self.graph_data: Dict = {'nodes': [], 'edges': []}
        
    async def initialize_graph_agents(self):
        """Инициализация граф-агентов"""
        self.logger.info("🌐 Инициализация graph-core агентов для анализа связей")
        
        graph_agents = [
            {'id': 'network_analyzer', 'type': 'topology', 'focus': 'agent_connections'},
            {'id': 'data_flow_tracer', 'type': 'pipeline', 'focus': 'data_movement'},
            {'id': 'dependency_mapper', 'type': 'relations', 'focus': 'system_dependencies'},
            {'id': 'performance_grapher', 'type': 'metrics', 'focus': 'performance_visualization'},
        ]
        
        for agent_config in graph_agents:
            self.graph_agents[agent_config['id']] = agent_config
            self.logger.info(f"✅ Граф-агент {agent_config['id']} готов: {agent_config['focus']}")
    
    async def analyze_agent_network(self, agents_data: List[Dict]) -> Dict:
        """Анализ сети агентов"""
        # Создание графа связей между агентами
        nodes = []
        edges = []
        
        for agent in agents_data:
            nodes.append({
                'id': agent.get('agent_id', 'unknown'),
                'type': agent.get('agent_type', 'generic'),
                'core_system': agent.get('core_system', 'none'),
                'status': agent.get('status', 'unknown'),
                'metrics': {
                    'tasks_completed': agent.get('tasks_completed', 0),
                    'avg_time': agent.get('avg_processing_time', 0)
                }
            })
        
        # Создание связей на основе core-систем
        core_groups = {}
        for node in nodes:
            core = node['core_system']
            if core not in core_groups:
                core_groups[core] = []
            core_groups[core].append(node['id'])
        
        # Связи внутри core-систем
        for core, agent_ids in core_groups.items():
            for i, agent1 in enumerate(agent_ids):
                for agent2 in agent_ids[i+1:]:
                    edges.append({
                        'source': agent1,
                        'target': agent2,
                        'type': 'core_system_relation',
                        'weight': 1.0
                    })
        
        self.graph_data = {'nodes': nodes, 'edges': edges}
        
        return {
            'total_nodes': len(nodes),
            'total_edges': len(edges),
            'core_systems': list(core_groups.keys()),
            'network_density': len(edges) / (len(nodes) * (len(nodes) - 1) / 2) if len(nodes) > 1 else 0,
            'graph_data': self.graph_data
        }

class RealTimeWebDashboard:
    """Веб-дашборд в реальном времени"""
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.logger = logging.getLogger(self.__class__.__name__)
        self.connected_clients: Set = set()
        self.dashboard_data: Dict = {}
        
    async def start_web_server(self):
        """Запуск веб-сервера"""
        self.logger.info(f"🌐 Запуск веб-дашборда на порту {self.port}")
        
        # Создаем HTML файл дашборда
        await self._create_dashboard_html()
        
        # Запуск WebSocket сервера в отдельном потоке
        websocket_thread = threading.Thread(
            target=self._start_websocket_server,
            daemon=True
        )
        websocket_thread.start()
        
        # Запуск HTTP сервера в отдельном потоке  
        http_thread = threading.Thread(
            target=self._start_http_server,
            daemon=True
        )
        http_thread.start()
        
        self.logger.info(f"✅ Дашборд доступен по адресу: http://localhost:{self.port}")
    
    def _start_websocket_server(self):
        """Запуск WebSocket сервера"""
        asyncio.new_event_loop().run_until_complete(
            websockets.serve(self._websocket_handler, "localhost", self.port + 1)
        )
    
    def _start_http_server(self):
        """Запуск HTTP сервера"""
        class CustomHandler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(Path(__file__).parent), **kwargs)
        
        with socketserver.TCPServer(("", self.port), CustomHandler) as httpd:
            httpd.serve_forever()
    
    async def _websocket_handler(self, websocket, path):
        """Обработчик WebSocket соединений"""
        self.connected_clients.add(websocket)
        self.logger.info(f"Новое WebSocket соединение: {len(self.connected_clients)} клиентов")
        
        try:
            await websocket.wait_closed()
        finally:
            self.connected_clients.remove(websocket)
    
    async def broadcast_update(self, data: Dict):
        """Отправка обновлений всем подключенным клиентам"""
        if self.connected_clients:
            message = json.dumps(data)
            disconnected_clients = set()
            
            for client in self.connected_clients:
                try:
                    await client.send(message)
                except:
                    disconnected_clients.add(client)
            
            # Удаляем отключенных клиентов
            self.connected_clients -= disconnected_clients
    
    async def _create_dashboard_html(self):
        """Создание HTML файла дашборда"""
        html_content = '''
<!DOCTYPE html>
<html>
<head>
    <title>AetherNova Mega Intelligence Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: white; }
        .dashboard { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .panel { background: #2d2d2d; padding: 20px; border-radius: 10px; border: 1px solid #404040; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 2em; font-weight: bold; color: #4CAF50; }
        .metric-label { font-size: 0.9em; color: #888; }
        .status-good { color: #4CAF50; }
        .status-warning { color: #FF9800; }
        .status-error { color: #F44336; }
        #agentsList { max-height: 300px; overflow-y: auto; }
        .agent-item { padding: 5px; margin: 2px 0; background: #333; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🚀 AetherNova Mega Intelligence Dashboard</h1>
    
    <div class="dashboard">
        <div class="panel">
            <h2>📊 System Overview</h2>
            <div class="metric">
                <div class="metric-value" id="totalAgents">0</div>
                <div class="metric-label">Total Agents</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="activeAgents">0</div>
                <div class="metric-label">Active Agents</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="completedTasks">0</div>
                <div class="metric-label">Completed Tasks</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="systemHealth">0%</div>
                <div class="metric-label">System Health</div>
            </div>
        </div>
        
        <div class="panel">
            <h2>🧠 Intelligence Analysis</h2>
            <div id="intelligenceInsights">
                <p>Инициализация анализа...</p>
            </div>
        </div>
        
        <div class="panel">
            <h2>🌐 Graph Analytics</h2>
            <canvas id="networkChart" width="400" height="200"></canvas>
        </div>
        
        <div class="panel">
            <h2>🔄 Real-time Agents</h2>
            <div id="agentsList">
                <p>Загрузка агентов...</p>
            </div>
        </div>
    </div>
    
    <script>
        const ws = new WebSocket('ws://localhost:8081');
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            updateDashboard(data);
        };
        
        function updateDashboard(data) {
            // Обновление метрик
            document.getElementById('totalAgents').textContent = data.total_agents || 0;
            document.getElementById('activeAgents').textContent = data.active_agents || 0;
            document.getElementById('completedTasks').textContent = data.completed_tasks || 0;
            document.getElementById('systemHealth').textContent = (data.system_health || 0) + '%';
            
            // Обновление инсайтов
            if (data.intelligence_analysis) {
                const insights = data.intelligence_analysis.performance_insights || [];
                document.getElementById('intelligenceInsights').innerHTML = 
                    insights.map(insight => `<p>💡 ${insight}</p>`).join('');
            }
            
            // Обновление списка агентов
            if (data.agents) {
                const agentsList = data.agents.map(agent => 
                    `<div class="agent-item">
                        <strong>${agent.agent_id}</strong> (${agent.core_system})
                        <span class="status-${agent.status === 'active' ? 'good' : 'warning'}">${agent.status}</span>
                    </div>`
                ).join('');
                document.getElementById('agentsList').innerHTML = agentsList;
            }
        }
        
        // Инициализация графика
        const ctx = document.getElementById('networkChart').getContext('2d');
        const networkChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Active', 'Idle', 'Processing'],
                datasets: [{
                    data: [10, 5, 3],
                    backgroundColor: ['#4CAF50', '#FF9800', '#2196F3']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { labels: { color: 'white' } }
                }
            }
        });
    </script>
</body>
</html>
        '''
        
        dashboard_path = Path(__file__).parent / "dashboard.html"
        with open(dashboard_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

class RealWorldTaskProcessor:
    """Процессор реальных задач"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.task_queue: List[RealWorldTask] = []
        self.completed_tasks: List[RealWorldTask] = []
        self.file_observer: Optional[Observer] = None
        
    async def initialize_real_tasks(self):
        """Инициализация реальных задач"""
        self.logger.info("💼 Инициализация обработки реальных задач")
        
        # Мониторинг файловой системы
        await self._setup_filesystem_monitoring()
        
        # Создание базовых задач
        await self._create_initial_tasks()
    
    async def _setup_filesystem_monitoring(self):
        """Настройка мониторинга файловой системы"""
        class FileChangeHandler(FileSystemEventHandler):
            def __init__(self, processor):
                self.processor = processor
            
            def on_modified(self, event):
                if not event.is_directory:
                    asyncio.create_task(self.processor._handle_file_change(event.src_path))
        
        self.file_observer = Observer()
        handler = FileChangeHandler(self)
        
        # Мониторим текущую директорию проекта
        watch_path = Path(__file__).parent.parent
        self.file_observer.schedule(handler, str(watch_path), recursive=True)
        self.file_observer.start()
        
        self.logger.info(f"📁 Мониторинг файловой системы: {watch_path}")
    
    async def _handle_file_change(self, file_path: str):
        """Обработка изменения файла"""
        task = RealWorldTask(
            id=f"file_change_{int(time.time())}",
            name=f"File Changed: {Path(file_path).name}",
            type="filesystem",
            priority=TaskPriority.LOW,
            data={"file_path": file_path, "change_time": datetime.now()},
            created_at=datetime.now()
        )
        
        self.task_queue.append(task)
        self.logger.info(f"📝 Новая задача: {task.name}")
    
    async def _create_initial_tasks(self):
        """Создание начальных задач"""
        initial_tasks = [
            RealWorldTask(
                id="git_status_check",
                name="Git Repository Status Check",
                type="git",
                priority=TaskPriority.MEDIUM,
                data={"repo_path": str(Path(__file__).parent.parent)},
                created_at=datetime.now()
            ),
            RealWorldTask(
                id="system_metrics",
                name="System Metrics Collection",
                type="system_monitor",
                priority=TaskPriority.HIGH,
                data={"collect_interval": 30},
                created_at=datetime.now()
            ),
            RealWorldTask(
                id="log_analysis",
                name="Application Log Analysis",
                type="log_analysis",
                priority=TaskPriority.MEDIUM,
                data={"log_pattern": "*.log"},
                created_at=datetime.now()
            )
        ]
        
        self.task_queue.extend(initial_tasks)
        self.logger.info(f"✅ Создано {len(initial_tasks)} начальных задач")
    
    async def process_next_task(self) -> Optional[RealWorldTask]:
        """Обработка следующей задачи"""
        if not self.task_queue:
            return None
        
        # Сортируем по приоритету
        self.task_queue.sort(key=lambda t: t.priority.value, reverse=True)
        task = self.task_queue.pop(0)
        
        task.status = 'processing'
        
        try:
            result = await self._execute_task(task)
            task.result = result
            task.status = 'completed'
            self.completed_tasks.append(task)
            
            self.logger.info(f"✅ Задача выполнена: {task.name}")
            return task
            
        except Exception as e:
            task.status = 'failed'
            task.result = {'error': str(e)}
            self.logger.error(f"❌ Ошибка выполнения задачи {task.name}: {e}")
            return task
    
    async def _execute_task(self, task: RealWorldTask) -> Dict:
        """Выполнение конкретной задачи"""
        if task.type == "git":
            return await self._execute_git_task(task)
        elif task.type == "system_monitor":
            return await self._execute_system_monitor_task(task)
        elif task.type == "log_analysis":
            return await self._execute_log_analysis_task(task)
        elif task.type == "filesystem":
            return await self._execute_filesystem_task(task)
        else:
            return {"result": "unknown_task_type"}
    
    async def _execute_git_task(self, task: RealWorldTask) -> Dict:
        """Выполнение Git задачи"""
        repo_path = task.data.get("repo_path", ".")
        
        try:
            repo = git.Repo(repo_path)
            status = {
                "branch": repo.active_branch.name,
                "uncommitted_changes": repo.is_dirty(),
                "untracked_files": len(repo.untracked_files),
                "commits_ahead": 0,  # Упрощенно
                "last_commit": repo.head.commit.hexsha[:8]
            }
            return status
        except Exception as e:
            return {"error": f"Git operation failed: {e}"}
    
    async def _execute_system_monitor_task(self, task: RealWorldTask) -> Dict:
        """Выполнение задачи мониторинга системы"""
        return {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "processes": len(psutil.pids()),
            "timestamp": datetime.now().isoformat()
        }
    
    async def _execute_log_analysis_task(self, task: RealWorldTask) -> Dict:
        """Выполнение анализа логов"""
        log_pattern = task.data.get("log_pattern", "*.log")
        log_files = list(Path(__file__).parent.parent.glob(f"**/{log_pattern}"))
        
        analysis = {
            "log_files_found": len(log_files),
            "total_size": sum(f.stat().st_size for f in log_files if f.exists()),
            "recent_files": [str(f) for f in log_files[-5:]]  # Последние 5 файлов
        }
        
        return analysis
    
    async def _execute_filesystem_task(self, task: RealWorldTask) -> Dict:
        """Выполнение файловой задачи"""
        file_path = task.data.get("file_path", "")
        
        if Path(file_path).exists():
            stat = Path(file_path).stat()
            return {
                "file_exists": True,
                "size": stat.st_size,
                "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "file_type": Path(file_path).suffix
            }
        else:
            return {"file_exists": False}

class MegaOrchestrator:
    """Главный оркестратор мега-системы"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Компоненты системы
        self.core_orchestra: Optional[ExtendedCoreSystemsOrchestra] = None
        self.intelligence_engine = IntelligenceEngine()
        self.graph_analytics = GraphAnalyticsEngine()
        self.web_dashboard = RealTimeWebDashboard()
        self.task_processor = RealWorldTaskProcessor()
        
        # Метрики
        self.agent_metrics: Dict[str, AgentMetrics] = {}
        self.system_metrics: Dict = {}
        
    async def initialize_mega_system(self):
        """Инициализация всей мега-системы"""
        self.logger.info("🚀 ЗАПУСК AETHERNOVA MEGA INTELLIGENCE SYSTEM")
        self.logger.info("=" * 80)
        
        # 1. Инициализация core-системы агентов
        await self._initialize_core_agents()
        
        # 2. Инициализация intelligence engine
        await self.intelligence_engine.initialize_genius_agents()
        
        # 3. Инициализация graph analytics
        await self.graph_analytics.initialize_graph_agents()
        
        # 4. Запуск веб-дашборда
        await self.web_dashboard.start_web_server()
        
        # 5. Инициализация обработки реальных задач
        await self.task_processor.initialize_real_tasks()
        
        self.logger.info("✅ Все компоненты мега-системы инициализированы")
    
    async def _initialize_core_agents(self):
        """Инициализация основных агентов"""
        core_adapter = CoreSystemsAdapter()
        self.core_orchestra = ExtendedCoreSystemsOrchestra(core_adapter)
        await self.core_orchestra.load_all_agents()
        
        self.logger.info(f"🤖 Загружено агентов: {len(self.core_orchestra.regular_agents) + len(self.core_orchestra.core_agents)}")
    
    async def run_mega_loop(self):
        """Главный цикл мега-системы"""
        self.logger.info("🔄 Запуск главного цикла мега-системы")
        
        while True:
            try:
                # 1. Обработка реальных задач
                await self._process_real_tasks()
                
                # 2. Сбор метрик
                await self._collect_system_metrics()
                
                # 3. Интеллектуальный анализ
                await self._perform_intelligence_analysis()
                
                # 4. Граф-анализ
                await self._perform_graph_analysis()
                
                # 5. Обновление дашборда
                await self._update_dashboard()
                
                # Пауза между циклами
                await asyncio.sleep(10)
                
            except Exception as e:
                self.logger.error(f"Ошибка в главном цикле: {e}")
                await asyncio.sleep(5)
    
    async def _process_real_tasks(self):
        """Обработка реальных задач"""
        for _ in range(3):  # Обрабатываем до 3 задач за цикл
            task = await self.task_processor.process_next_task()
            if not task:
                break
    
    async def _collect_system_metrics(self):
        """Сбор системных метрик"""
        total_agents = len(self.core_orchestra.regular_agents) + len(self.core_orchestra.core_agents) if self.core_orchestra else 0
        
        self.system_metrics = {
            'timestamp': datetime.now().isoformat(),
            'total_agents': total_agents,
            'active_agents': total_agents,  # Упрощенно - все активны
            'completed_tasks': len(self.task_processor.completed_tasks),
            'pending_tasks': len(self.task_processor.task_queue),
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'avg_task_time': 2.5,  # Симуляция
            'failed_tasks': sum(1 for t in self.task_processor.completed_tasks if t.status == 'failed'),
            'task_completion_rate': 98.5  # Симуляция
        }
    
    async def _perform_intelligence_analysis(self):
        """Выполнение интеллектуального анализа"""
        analysis = await self.intelligence_engine.analyze_system_intelligence(self.system_metrics)
        self.system_metrics['intelligence_analysis'] = analysis
    
    async def _perform_graph_analysis(self):
        """Выполнение граф-анализа"""
        agents_data = []
        
        if self.core_orchestra:
            for i, agent in enumerate(self.core_orchestra.regular_agents + self.core_orchestra.core_agents):
                agents_data.append({
                    'agent_id': f"agent_{i}",
                    'agent_type': getattr(agent, 'agent_type', 'unknown'),
                    'core_system': getattr(agent.base_agent, 'core_system', 'none') if hasattr(agent, 'base_agent') else 'none',
                    'status': 'active',
                    'tasks_completed': 10,  # Симуляция
                    'avg_processing_time': 2.5
                })
        
        graph_analysis = await self.graph_analytics.analyze_agent_network(agents_data)
        self.system_metrics['graph_analysis'] = graph_analysis
        self.system_metrics['agents'] = agents_data
    
    async def _update_dashboard(self):
        """Обновление веб-дашборда"""
        dashboard_data = {
            **self.system_metrics,
            'system_health': self.system_metrics.get('intelligence_analysis', {}).get('system_health', {}).get('score', 0)
        }
        
        await self.web_dashboard.broadcast_update(dashboard_data)

async def main():
    """Главная функция запуска мега-системы"""
    mega_orchestrator = MegaOrchestrator()
    
    try:
        # Инициализация
        await mega_orchestrator.initialize_mega_system()
        
        # Запуск главного цикла
        await mega_orchestrator.run_mega_loop()
        
    except KeyboardInterrupt:
        mega_orchestrator.logger.info("🛑 Завершение работы мега-системы")
    except Exception as e:
        mega_orchestrator.logger.error(f"❌ Критическая ошибка: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())