# GitHub Actions CI/CD для AI Agents

Комплексная система непрерывной интеграции и доставки для проекта AI Agents с автоматическим тестированием, мониторингом, и деплоем.

## 🏗️ Архитектура CI/CD

### Workflow Files Overview

```
.github/
├── workflows/
│   ├── ci-cd.yml           # Основной CI/CD pipeline
│   ├── automated-testing.yml    # Автоматическое тестирование
│   ├── monitoring.yml      # Мониторинг и health checks
│   ├── release-deploy.yml  # Релизы и деплой
│   └── documentation.yml   # Генерация документации
├── dependabot.yml         # Автоматические обновления зависимостей
├── ISSUE_TEMPLATE/        # Шаблоны для issues
└── pull_request_template.md # Шаблон для PR
```

## 🚀 Основные Workflows

### 1. CI/CD Pipeline (`ci-cd.yml`)

**Триггеры:**
- Push в `main`/`develop`
- Pull requests
- Manual dispatch

**Этапы:**
1. **Changes Detection** - анализ изменений для оптимизации
2. **Code Quality** - проверка стиля кода, линтинг, типизация
3. **Unit Tests** - тесты по компонентам и версиям Python
4. **Integration Tests** - с Redis, PostgreSQL, RabbitMQ
5. **Performance Tests** - benchmark тесты
6. **Docker Build** - сборка и push образов
7. **Security Scan** - сканирование уязвимостей
8. **Deploy** - автоматический деплой в staging/production

**Пример использования:**
```bash
# Запуск полного pipeline
git push origin main

# Ручной запуск с параметрами
gh workflow run ci-cd.yml \
  --field deploy_environment=staging \
  --field run_integration_tests=true
```

### 2. Automated Testing (`automated-testing.yml`)

**Расписание:** Ежедневно в 2:00 UTC

**Матричное тестирование:**
- Python 3.10, 3.11, 3.12
- Ubuntu, Windows, macOS  
- Minimal, Standard, Full конфигурации

**Типы тестов:**
- **Unit Tests** - базовые функциональные тесты
- **Load Tests** - тесты нагрузки с Locust
- **Security Tests** - Bandit, Safety, Semgrep
- **Extended Integration** - длительные интеграционные тесты

**Пример запуска:**
```bash
# Запуск всех тестов
gh workflow run automated-testing.yml

# Запуск только тестов производительности
gh workflow run automated-testing.yml \
  --field test_type=performance
```

### 3. Health Monitoring (`monitoring.yml`)

**Расписание:** Каждые 15 минут

**Проверки:**
- API здоровье
- Статус агентов
- Система workflows
- Подключения к БД и Redis
- Метрики производительности
- Анализ логов

**Алерты:**
- Slack уведомления
- GitHub Issues для критических проблем
- Webhook в систему мониторинга

**Пример мануального запуска:**
```bash
# Проверка production
gh workflow run monitoring.yml \
  --field environment=production \
  --field alert_level=warning
```

### 4. Release & Deploy (`release-deploy.yml`)

**Триггеры:**
- Git tags `v*.*.*`
- GitHub Releases
- Manual dispatch

**Процесс релиза:**
1. **Validation** - проверка версии и changelog
2. **Release Tests** - быстрые критические тесты
3. **Build** - сборка релизных образов
4. **Security Scan** - проверка безопасности
5. **Staging Deploy** - деплой в staging с smoke tests
6. **Production Deploy** - с manual approval и blue-green деплой
7. **Rollback** - автоматический откат при проблемах

**Пример релиза:**
```bash
# Создание тега для релиза
git tag v1.2.3
git push origin v1.2.3

# Ручной деплой в production
gh workflow run release-deploy.yml \
  --field version=v1.2.3 \
  --field environment=production
```

### 5. Documentation (`documentation.yml`)

**Автоматическая генерация:**
- API документация с pdoc3
- OpenAPI схема
- MkDocs сайт документации
- Changelog generation

**Проверки качества:**
- Broken links detection
- Spell checking
- Documentation coverage
- Code examples validation

## 🔧 Конфигурация

### Переменные окружения

```yaml
# Repository Secrets (Settings > Secrets)
SLACK_WEBHOOK: https://hooks.slack.com/...
PRODUCTION_KUBECONFIG: base64_encoded_kubeconfig
STAGING_KUBECONFIG: base64_encoded_kubeconfig
MONITORING_API_KEY: monitoring_system_api_key
PRODUCTION_APPROVERS: user1,user2,user3
VERCEL_TOKEN: vercel_deployment_token
GITHUB_TOKEN: # автоматически доступен
```

### Dependabot настройки

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    reviewers: ["ai-agents-team"]
    labels: ["dependencies", "python"]
```

## 📊 Мониторинг и Метрики

### CI/CD Метрики

Автоматический сбор метрик:
- Время выполнения тестов
- Покрытие кода
- Частота деплоев
- MTTR (Mean Time To Recovery)
- Success rate

### Health Monitoring

Continuous monitoring:
- API response times
- System resource usage
- Error rates
- Agent performance
- Workflow execution status

## 🚨 Алерты и Уведомления

### Slack Integration

```yaml
- name: Notify on failure
  uses: 8398a7/action-slack@v3
  if: failure()
  with:
    status: failure
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
    text: |
      🚨 CI/CD Pipeline Failed
      
      Workflow: ${{ github.workflow }}
      Branch: ${{ github.ref }}
      Commit: ${{ github.sha }}
      
      Please check the logs and fix the issues.
```

### GitHub Issues

Автоматическое создание issues для:
- Критических ошибок мониторинга
- Security vulnerabilities
- Performance regressions

## 🔒 Безопасность

### Security Scanning

Интегрированные инструменты:
- **Bandit** - Python security scanner
- **Safety** - dependency vulnerability scanner  
- **Semgrep** - SAST tool
- **Trivy** - container vulnerability scanner

### Секреты и конфиденциальность

- Все секреты в GitHub Secrets
- Rotation policy для API ключей
- Audit logging для доступа

## 🎯 Best Practices

### Workflow Optimization

```yaml
# Условное выполнение для экономии ресурсов
- name: Run expensive tests
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  run: pytest expensive_tests/

# Параллельное выполнение
strategy:
  matrix:
    python-version: [3.10, 3.11, 3.12]
  fail-fast: false  # Продолжить даже если один job failed
```

### Caching Strategies

```yaml
# Кеширование pip dependencies
- uses: actions/setup-python@v4
  with:
    python-version: ${{ env.PYTHON_VERSION }}
    cache: 'pip'

# Docker layer caching
- name: Build Docker image
  uses: docker/build-push-action@v5
  with:
    cache-from: type=gha
    cache-to: type=gha,mode=max
```

### Error Handling

```yaml
# Retry mechanism для нестабильных тестов
- name: Run flaky tests
  run: |
    for i in {1..3}; do
      if pytest flaky_tests/; then
        break
      else
        echo "Attempt $i failed, retrying..."
        sleep 10
      fi
    done
```

## 📈 Continuous Improvement

### Metrics Dashboard

Рекомендуется настроить dashboard для отслеживания:
- Build success rate
- Test execution time trends
- Deployment frequency
- Lead time for changes
- Mean time to recovery

### Feedback Loop

Регулярная оптимизация на основе:
- Build times analysis
- Test failure patterns
- Resource utilization
- Developer feedback

## 🛠️ Локальная разработка

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.1.0
    hooks:
      - id: black
  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
```

### Local Testing

```bash
# Запуск тестов локально перед push
make test-all

# Проверка стиля кода
make lint

# Проверка безопасности
make security-scan
```

## 🎛️ Управление Workflows

### Manual Triggers

```bash
# Список доступных workflows
gh workflow list

# Запуск с параметрами
gh workflow run "CI/CD Pipeline" \
  --field environment=staging \
  --field skip_tests=false

# Мониторинг выполнения
gh run watch
```

### Управление через API

```python
import requests

# Trigger workflow via GitHub API
url = "https://api.github.com/repos/owner/repo/actions/workflows/ci-cd.yml/dispatches"
headers = {"Authorization": "Bearer YOUR_TOKEN"}
data = {
    "ref": "main",
    "inputs": {
        "environment": "staging",
        "run_tests": "true"
    }
}

response = requests.post(url, headers=headers, json=data)
```

## 🔍 Troubleshooting

### Частые проблемы и решения

1. **Timeout в тестах**
   ```yaml
   - name: Run tests with timeout
     run: timeout 600 pytest tests/
   ```

2. **Нехватка ресурсов**
   ```yaml
   # Использование более мощных runners
   runs-on: ubuntu-latest-4-cores
   ```

3. **Flaky tests**
   ```yaml
   # Retry механизм
   - uses: nick-invision/retry@v2
     with:
       timeout_minutes: 10
       max_attempts: 3
       command: pytest tests/integration/
   ```

Эта система CI/CD обеспечивает надежную автоматизацию всего жизненного цикла разработки AI Agents с акцентом на качество, безопасность и производительность. 🚀