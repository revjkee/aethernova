# Automation Core

**Automation Core** — это промышленный фреймворк для надёжной и безопасной автоматизации с поддержкой:
- Асинхронных и синхронных HTTP-клиентов
- Интеграции с браузерами (Selenium, Playwright)
- Унифицированной работы с БД (SQLite, PostgreSQL, ORM)
- Пайплайнов данных (Excel, API, парсинг новостей, курсы валют)
- Очередей, кэшей и concurrency-примитивов
- Метрик, трейсинга и логирования (OpenTelemetry)
- Политик безопасности (Zero Trust, криптография, секреты)
- Поддержки Kubernetes, Docker, CI/CD и SLSA provenance

Проект следует стандартам: [PEP 8](https://peps.python.org/pep-0008/), [OpenSSF Scorecards](https://github.com/ossf/scorecard), [SLSA](https://slsa.dev).

---

## Возможности

- **HTTP-клиент**: поддержка `httpx` (async), `requests` (sync), circuit-breaker
- **Парсеры**: `lxml`, `BeautifulSoup4`, утилиты для `pandas`
- **Браузерная автоматизация**: Selenium и Playwright, управление cookies и сценариями
- **Базы данных**: SQLite и PostgreSQL, Alembic-миграции, ORM-слой
- **Concurrency**: пул задач, rate limiting, batching, async/thread pool
- **Хранилища**: кэширование (in-memory, Redis), очередь заданий
- **Наблюдаемость**: метрики, трейсинг, централизованное логирование
- **Комплаенс**: robots.txt, политика запросов
- **Безопасность**: шифрование, управление секретами, безопасное хранение
- **Плагины**: регистрация и расширяемая архитектура
- **Инфраструктура**: Helm, Kustomize, Docker, GitHub Actions, ArgoCD

---

## Установка

```bash
# Клонирование репозитория
git clone https://github.com/your-org/automation-core.git
cd automation-core

# Установка через poetry
poetry install

# Альтернативно через pip
pip install -e .
