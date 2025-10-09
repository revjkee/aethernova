# AI Agents Integration System

Комплексная система интеграции для AI-агентов, предоставляющая планирование задач, управление рабочими процессами и API для внешних интеграций.

## 🏗️ Архитектура

Система интеграции включает три основных компонента:

### 1. Task Scheduler (Планировщик задач)
- **TaskScheduler** - абстрактный интерфейс планировщика
- **OmnimindCorePlanner** - интеграция с omnimind-core системой
- Поддержка задач, батчей и пайплайнов
- Fallback механизм для автономной работы

### 2. Workflow Engine (Движок рабочих процессов)
- Определение и выполнение сложных рабочих процессов
- Поддержка различных типов узлов (задачи, условия, циклы)
- Мониторинг выполнения и обработка ошибок
- Система повторов и таймаутов

### 3. API Management (Управление API)
- REST API для управления агентами и задачами
- WebSocket API для real-time уведомлений
- Система аутентификации через API ключи
- Rate limiting и мониторинг использования

## 🚀 Быстрый старт

### Инициализация системы

```python
from backend.ai_core.agents import agent_system

# Инициализация всех систем
await agent_system.initialize()

# Проверка статуса
status = await agent_system.get_system_status()
print(f"Система: {status['status']}")
print(f"Интеграция: {status.get('integration', {})}")
```

### Планировщик задач

```python
from backend.ai_core.agents.integration import OmnimindCorePlanner, ScheduledTask

# Создание планировщика
scheduler = OmnimindCorePlanner("http://localhost:8080/api/v1")

# Планирование задачи
task = ScheduledTask(
    task_id="task_1",
    type="code_generation",
    data={"language": "python"},
    agent_requirements=["DeveloperAgent"]
)

result = await scheduler.schedule_task(task)
```

### Рабочие процессы

```python
from backend.ai_core.agents.integration import (
    workflow_engine, 
    WorkflowDefinition, 
    WorkflowNode, 
    NodeType
)

# Создание workflow
workflow = WorkflowDefinition(
    workflow_id="dev_pipeline",
    name="Development Pipeline",
    description="Полный цикл разработки",
    version="1.0",
    nodes=[
        WorkflowNode(
            node_id="analyze",
            name="Анализ требований",
            node_type=NodeType.TASK,
            task=create_analysis_task()
        ),
        WorkflowNode(
            node_id="develop",
            name="Разработка",
            node_type=NodeType.TASK,
            dependencies=["analyze"],
            task=create_development_task()
        )
    ]
)

# Регистрация и запуск
await workflow_engine.register_workflow(workflow)
execution = await workflow_engine.start_workflow("dev_pipeline", {"project": "my_app"})
```

### API Management

```python
from backend.ai_core.agents.api import create_api_management_system

# Создание API системы
api_system = create_api_management_system(
    agent_registry=agent_registry,
    agent_monitor=agent_monitor, 
    workflow_engine=workflow_engine
)

await api_system.initialize()

# Получение FastAPI приложения
app = api_system.get_app()

# Трансляция событий
await api_system.broadcast_event("task_completed", {
    "task_id": "123",
    "status": "success"
})
```

## 🔧 Конфигурация

### Основной конфигурационный файл

```yaml
# config/integration.yaml

scheduler:
  omnimind_core:
    enabled: true
    base_url: "http://localhost:8080/api/v1"
    timeout: 30
    retry_attempts: 3

integration:
  mode: "hybrid"  # pull, push, hybrid
  assignment:
    timeout: 300
    max_concurrent_per_agent: 10

workflows:
  engine:
    max_concurrent_workflows: 50
    monitoring_interval: 10.0

api_management:
  server:
    host: "0.0.0.0"
    port: 8000
  rate_limiting:
    enabled: true
    default_rules:
      - type: "per_minute"
        limit: 60
```

### Переменные окружения

```bash
# Omnimind Core
OMNIMIND_CORE_URL=http://localhost:8080/api/v1
OMNIMIND_CORE_API_KEY=your-api-key

# Redis для API Management
REDIS_URL=redis://localhost:6379

# API Management
API_SECRET_KEY=your-secret-key
API_ADMIN_TOKEN=admin-token

# Безопасность
ENCRYPT_SECRET_KEY=encryption-key
```

## 📡 REST API Endpoints

### Агенты

```http
GET /api/v1/agents
POST /api/v1/agents
GET /api/v1/agents/{agent_id}
PUT /api/v1/agents/{agent_id}
DELETE /api/v1/agents/{agent_id}
```

### Задачи

```http
GET /api/v1/tasks
POST /api/v1/tasks
GET /api/v1/tasks/{task_id}
PUT /api/v1/tasks/{task_id}
DELETE /api/v1/tasks/{task_id}
```

### Рабочие процессы

```http
GET /api/v1/workflows
POST /api/v1/workflows
GET /api/v1/workflows/{workflow_id}
GET /api/v1/workflows/executions/{execution_id}
POST /api/v1/workflows/{workflow_id}/start
POST /api/v1/workflows/executions/{execution_id}/pause
POST /api/v1/workflows/executions/{execution_id}/resume
POST /api/v1/workflows/executions/{execution_id}/cancel
```

### Мониторинг

```http
GET /api/v1/monitoring/metrics
GET /api/v1/monitoring/health
GET /api/v1/monitoring/agents/{agent_id}/metrics
```

### Администрирование

```http
POST /api/v1/admin/api-keys
GET /api/v1/admin/api-keys
DELETE /api/v1/admin/api-keys/{key_id}
```

## 🔌 WebSocket API

### Подключение

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/my_connection_id');

ws.onopen = function() {
    // Подписка на события
    ws.send(JSON.stringify({
        command: 'subscribe',
        topic: 'agent_status'
    }));
};

ws.onmessage = function(event) {
    const message = JSON.parse(event.data);
    console.log('Event:', message);
};
```

### Доступные топики

- `agent_status` - изменения статуса агентов
- `task_events` - события задач
- `workflow_events` - события рабочих процессов
- `system_alerts` - системные уведомления
- `performance_metrics` - метрики производительности

## 🔐 Аутентификация

### Создание API ключа

```bash
curl -X POST http://localhost:8000/api/v1/admin/api-keys \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My API Key",
    "permissions": ["agents:read", "tasks:create"],
    "expires_in_days": 365
  }'
```

### Использование API ключа

```bash
curl -X GET http://localhost:8000/api/v1/agents \
  -H "Authorization: Bearer ak_your_api_key_here"
```

### Группы разрешений

- **readonly** - только чтение данных
- **standard** - чтение + создание агентов/задач
- **advanced** - полный доступ к агентам/задачам/workflows
- **admin** - административные функции

## 📊 Мониторинг

### Метрики системы

```python
# Получение общих метрик
metrics = await agent_monitor.get_system_metrics()

# Метрики конкретного агента  
agent_metrics = await agent_monitor.get_agent_performance_metrics("agent_1")

# Статус здоровья системы
health = await agent_monitor.get_system_health()
```

### Dashboard

Веб-интерфейс мониторинга доступен по адресу:
- http://localhost:8000/monitoring/dashboard

### Уведомления

Поддерживаются каналы уведомлений:
- Email (SMTP)
- Slack (webhooks) 
- Webhooks (HTTP POST)

## 🔄 Интеграция с внешними системами

### GitHub

```yaml
external_integrations:
  github:
    enabled: true
    token: ${GITHUB_TOKEN}
    webhook_secret: ${GITHUB_WEBHOOK_SECRET}
```

### Slack

```yaml
external_integrations:
  slack:
    enabled: true
    webhook_url: ${SLACK_WEBHOOK_URL}
    bot_token: ${SLACK_BOT_TOKEN}
```

### Jira

```yaml
external_integrations:
  jira:
    enabled: true
    server_url: ${JIRA_SERVER_URL}
    username: ${JIRA_USERNAME}
    api_token: ${JIRA_API_TOKEN}
```

## 📈 Масштабирование

### Горизонтальное масштабирование

```python
# Несколько экземпляров с Redis координацией
api_config = {
    "redis_url": "redis://redis-cluster:6379",
    "server": {"workers": 4}
}

api_system = create_api_management_system(
    agent_registry, agent_monitor, workflow_engine, api_config
)
```

### Вертикальное масштабирование

```yaml
workflows:
  engine:
    max_concurrent_workflows: 200  # Увеличение лимитов
    
api_management:
  rate_limiting:
    default_rules:
      - type: "per_minute"
        limit: 200  # Более высокие лимиты
```

## 🚨 Обработка ошибок

### Retry политики

```yaml
workflows:
  retry_policies:
    default_max_retries: 3
    default_retry_delay: 5.0
    exponential_backoff: true
```

### Fallback механизмы

```python
# Автоматический fallback на локальный планировщик
scheduler = OmnimindCorePlanner(
    base_url="http://omnimind:8080/api/v1",
    fallback_enabled=True
)
```

## 🧪 Тестирование

### Запуск тестов

```bash
# Все тесты интеграции
python -m pytest backend/ai_core/agents/tests/integration/

# Тесты API
python -m pytest backend/ai_core/agents/tests/api/

# Тесты workflows
python -m pytest backend/ai_core/agents/tests/workflows/
```

### Демонстрация системы

```bash
# Полная демонстрация всех возможностей
python backend/ai_core/agents/examples/full_system_demo.py
```

## 📚 Дополнительные ресурсы

- [Архитектура системы](../docs/architecture.md)
- [API Reference](../docs/api_reference.md)
- [Примеры интеграции](../examples/)
- [Troubleshooting](../docs/troubleshooting.md)

## 🤝 Поддержка

Для получения поддержки:
1. Проверьте [FAQ](../docs/faq.md)
2. Создайте issue в репозитории
3. Свяжитесь с командой разработки