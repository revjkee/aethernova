
---

## 🔍 Компоненты

### Форматтеры

- `ecs_formatter.py` — Elastic Common Schema совместимость
- `json_formatter.py` — расширенное логирование JSON с контекстом
- `red_team_formatter.py` — для RedTeam и PurpleTeam сценариев

### Обработчики логов

- `stdout_handler.py`, `syslog_handler.py` — базовый вывод
- `loki_handler.py` — интеграция с Grafana Loki
- `kafka_handler.py` — асинхронная отправка событий в Kafka
- `sentry_handler.py` — отправка ошибок в Sentry
- `siem_router.py` — роутинг логов по SIEM-правилам (YAML)

### OpenTelemetry

- `jaeger_tracing.py` — распределённый трейсинг
- `latency_tracker.py` — отслеживание задержек API
- `error_logger.py`, `lerror_logger.py` — логирование исключений
- `token_usage_tracker.py` — мониторинг токенов (LLM и др.)

### UEBA (User & Entity Behavior Analytics)

- `user_behavior_model.py` — поведенческий профиль пользователя
- `anomaly_detector.py` — обнаружение отклонений
- `threat_score.py` — скоринг на основе поведения

---

## 📊 SIEM-правила

Файлы YAML с правилами обнаружения угроз:

- `brute_force.yaml`
- `dns_tunneling.yaml`
- `exfiltration.yaml`
- `lateral_movement.yaml`
- `privilege_escalation.yaml`

Используются в `siem_router.py`.

---

## ✅ Валидация

- `validation_rules.yaml` — схема валидации входящих маршрутов и параметров
- `routing_policy.yaml` — правила маршрутизации потоков логов

---

## 🧪 Тесты

Каждый компонент покрыт PyTest-тестами с моками и проверкой логики:

- `test_context_injector.py`
- `test_siem_router.py`
- `test_stdout_handler.py`
- и т.д.

---

## 🛠 Инструменты

- `formatter_tester.py` — локальный запуск форматтеров
- `log_compressor.py` — компрессия логов
- `log_redactor.py` — защита чувствительных данных
- `log_validator.py` — проверка на соответствие схемам

---

## 🧠 Цели

- **Полная совместимость** с системами мониторинга уровня SOC (Grafana, Loki, Prometheus, Jaeger)
- **AI-обогащение логов** и моделей поведения для автономного анализа
- **Модульность и масштабируемость** для DevSecOps-платформ

---

## ⚙️ Требования

- Python 3.10+
- FastAPI
- opentelemetry, sentry-sdk, uvicorn
- pyyaml, numpy, pytest
- Kafka (опционально), Loki (опционально), Jaeger (опционально)

---

## 🚀 Запуск

```bash
# Установка зависимостей
pip install -r requirements.txt

# Пример запуска трассировки
python dashboards/otel/jaeger_tracing.py

# Тестирование
pytest dashboards/tests/
