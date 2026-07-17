# Этап 1.6 — Backend Prometheus metrics

## Этап

Устранение `OBS-001`: корневой Prometheus был настроен на
`backend:8000/metrics`, но backend не публиковал такой endpoint.

## Обнаружено

| ID | Критичность | Компонент | Проблема | Причина | Последствие |
| --- | --- | --- | --- | --- | --- |
| OBS-001 | HIGH | Backend / Prometheus | Prometheus scrape target указывал на отсутствующий `/metrics` | В backend была заявлена instrumentator dependency, но instrumentation не подключалась к FastAPI app | Основной backend target постоянно возвращал 404 и создавал ложную картину observability |
| OBS-002 | MEDIUM | Backend telemetry | Не было regression test на реальный Prometheus payload и route label | Проверялось только наличие health routes | Повторное удаление или неверное подключение middleware не обнаруживалось локально |
| OBS-003 | MEDIUM | Backend code quality | Изменяемый runtime module не проходил Black/Flake8 | Накопились неиспользуемые imports, длинные строки и неиспользуемая exception variable | Локальная проверка observability-изменения давала шум и не могла служить строгим gate |

## Решение

- существующая dependency `prometheus-fastapi-instrumentator~=6.1` подключена
  к FastAPI application factory;
- endpoint `/metrics` исключён из собственной instrumentation;
- нетемплейтированные URL игнорируются, чтобы случайные path values не
  создавали unbounded label cardinality;
- HTTP status codes группируются стандартным instrumentator contract;
- `/metrics` скрыт из OpenAPI как внутренний operational endpoint;
- regression test проверяет:
  - регистрацию `/metrics`;
  - успешный запрос к разрешённому host;
  - Prometheus text content type;
  - наличие `http_requests_total`;
  - templated label `handler="/health"`;
- изменённый backend module приведён к Black/Flake8 contract, удалены только
  доказанно неиспользуемые imports и exception binding;
- Prometheus target не менялся: его существующий контракт
  `backend:8000/metrics` теперь выполняется.

Новые package dependencies и environment variables не добавлялись.

## Изменённые файлы

- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\backend\src\main.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\backend\tests\unit\test_main.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\docs\reports\stage-1-6-backend-prometheus-metrics-2026-07-17.md`

## Проверки

### Backend route and payload contract

```text
Команда:
<isolated-python> -m pytest backend/tests/unit/test_main.py -q

Результат:
PASS

Код завершения:
0

Вывод:
....                                                                     [100%]
4 passed, 19 warnings in 1.03s
```

Предупреждения раскрыты отдельным запуском без `--disable-warnings`. Они
исходят из FastAPI, Starlette и pytest-asyncio на локальном Python 3.14:
использование удаляемых в Python 3.16 asyncio APIs и pending deprecation
старого import path `python-multipart`. Project runtime matrix этим запуском
не подменялась.

### Prometheus configuration contract

```text
Команда:
<isolated-python> -c "<parse monitoring/prometheus/prometheus.yml and assert backend target>"

Результат:
PASS

Код завершения:
0

Вывод:
prometheus config: backend:8000/metrics contract present
```

### Root Compose syntax

```text
Команда:
docker compose config --quiet

Результат:
PASS с предупреждениями окружения

Код завершения:
0

Вывод:
WARNING: Error loading config file: open C:\Users\revav\.docker\config.json: Access is denied.
The "ZABBIX_DB_PASSWORD" variable is not set. Defaulting to a blank string.
```

Для известных interpolation values использованы только синтетические test
values. Незаданный Zabbix password оставлен видимым как отдельный deployment
configuration risk.

### Repository contract audit

```text
Команда:
<isolated-python> tools/repository_audit.py

Результат:
PASS с прежним предупреждением о LICENSE

Код завершения:
0

Вывод:
WARNING: LICENSE is empty; choose a license before publishing releases or packages
repository audit: 13246 tracked files, 0 error(s), 1 warning(s)
```

### Formatter и lint

```text
Команды:
<isolated-python> -m black --check backend/src/main.py backend/tests/unit/test_main.py
<isolated-python> -m flake8 backend/src/main.py backend/tests/unit/test_main.py

Результат:
PASS

Код завершения:
0
```

## Десять независимых проверок

| Позиция | Результат |
| --- | --- |
| Системный архитектор | Prometheus consumer и backend provider теперь имеют один реальный contract |
| Domain-архитектор | Domain routes и business payloads не изменялись |
| Senior Python Engineer | Instrumentation подключена в application factory и покрыта payload test |
| Database Engineer | DB engine, session factory, migrations и readiness semantics не менялись |
| Security Engineer | `/metrics` не добавлен в OpenAPI; секреты и auth middleware не затронуты |
| DevOps Engineer | Compose config проходит, service name и port совпадают с scrape target |
| SRE Engineer | Scrape endpoint существует, self-scrape исключён, status labels сгруппированы |
| QA Engineer | Проверяется не только route table, но и реальный Prometheus exposition payload |
| Performance Engineer | Untemplated paths игнорируются для ограничения label cardinality |
| Reviewer | Использована уже заявленная dependency; конфигурационный target не переписывался |

## Риски

- Полный container-to-container scrape не подтверждён, пока Docker Desktop
  daemon выключен.
- При нескольких Gunicorn workers Python Prometheus registry остаётся
  process-local; корректная агрегация требует отдельного multiprocess design
  или одного worker.
- `/metrics` пока не защищён network policy или отдельным management port.
- Backend readiness по-прежнему относится только к DB, а observability-core
  health содержит синтетические проверки pipeline.
- Alertmanager направляет уведомления в `local-null`, поэтому end-to-end alert
  delivery не подтверждена.
- Compose допускает пустой `ZABBIX_DB_PASSWORD`; production deployment должен
  требовать secret явно.

## Следующий шаг

Проверить canonical `observability-core` как сервис: убрать синтетическую
pipeline readiness, подтвердить конфигурацию exporters/receivers и отделить
liveness от dependency readiness. Параллельно зафиксировать production
secret contract для Zabbix без добавления реальных секретов в репозиторий.
