# DataFabric Core

DataFabric Core — это ядро платформы для потоковой и пакетной обработки данных, с акцентом на низкую задержку, наблюдаемость и простоту интеграции. Поддерживаются коннекторы к OLTP/OLAP, шинам событий, объектным хранилищам и движкам вычислений.

## Содержимое репозитория

- `datafabric-core/`
  - `README.md` — этот документ
  - `engine-core/` — код ядра и инструментов (см. соответствующий README)
  - `deploy/` — конфигурации Docker/Kubernetes/Helm
  - `examples/` — примеры конвейеров, демо‑скрипты
  - `scripts/` — утилиты CI/CD, миграции
  - `telemetry/` — профили, дампы метрик, примеры дашбордов

## Ключевые возможности

- Потоковая и пакетная обработка с гарантиями доставки (at‑least‑once/at‑most‑once).
- Схемы, версионирование контрактов и контроль совместимости.
- Интеграция с кэшем (горячие данные, LFU/LRU), бэкенды: Redis/локальный.
- Наблюдаемость: метрики, трассировка, профилирование CPU/Wall/Alloc.
- Конфигурация через ENV/файлы, безопасные секреты, политики ACL/RBAC.
- Инварианты целостности, якорение контрольных сумм (ledger anchoring).
- Инструменты нагруженного тестирования и хаос‑инженерии.

## Архитектура (обзор)

lua
Копировать
Редактировать
            +----------------------+
Sources -----> | Ingest (Connectors) | ----+
+----------------------+ |
v
+----------------------+ +-------------------+
| Stream Bus / MQ | | Batch Runner |
+----------------------+ +-------------------+
| |
v v
+-----------+ +----------------+
| Cache |<--------->| Transformation |
+-----------+ +----------------+
| |
v v
+-----------------------------------------------+
| Storage Targets |
| OLTP/OLAP, Object Store, Search, DLQ |
+-----------------------------------------------+
|
v
+-------------------+ +----------------------+
| Observability | | Control Plane/CLI |
| (metrics, traces) | | health, profile |
+-------------------+ +----------------------+

bash
Копировать
Редактировать

## Быстрый старт

Требования:
- Linux/macOS, Docker 20+, Python 3.10+
- Опционально: Redis 7+, Kubernetes 1.26+, Helm 3

### Запуск локально (Docker Compose)

```bash
git clone <repo-url> datafabric-core
cd datafabric-core

# Запуск минимального стека (шина, кэш, ядро)
docker compose -f deploy/compose/docker-compose.yml up -d

# Проверка здоровья
docker compose -f deploy/compose/docker-compose.yml exec core python -m engine.cli.main health --deep
Запуск без Docker (venv)
bash
Копировать
Редактировать
python3 -m venv .venv && source .venv/bin/activate
pip install -e .               # локальная установка
python -m engine.cli.main health
Конфигурация
Все параметры могут задаваться через переменные окружения или файл конфигурации (YAML/JSON).

Базовые ENV
Переменная	Значение по умолчанию	Назначение
ENGINE_LOG_LEVEL	INFO	Уровень логирования
ENGINE_LOG_FORMAT	text	text или json
ENGINE_VERSION	0.1.0	Версия сборки
CACHE_REDIS_URL	redis://127.0.0.1:6379/0	Подключение к Redis
DF_SQL_ENDPOINT	—	Точка доступа DataFabric SQL
DF_AUTH_TOKEN	—	Токен доступа
LEDGER_ENDPOINT	—	Бэкенд якорения контрольных сумм
LEDGER_API_KEY	—	Ключ API для якорения
LOADGEN_*	—	Генератор нагрузки (см. engine/cli/tools)
ENGINE_PROFILE_DIR	telemetry/profiles	Каталог профилей

Пример config.yaml
yaml
Копировать
Редактировать
log_level: INFO
log_format: json
cache:
  backend: redis
  url: ${CACHE_REDIS_URL}
datafabric:
  sql_endpoint: ${DF_SQL_ENDPOINT}
  auth_token: ${DF_AUTH_TOKEN}
ledger:
  endpoint: ${LEDGER_ENDPOINT}
  api_key: ${LEDGER_API_KEY}
observability:
  metrics: true
  traces: true
Запуск CLI с конфигом:

bash
Копировать
Редактировать
python -m engine.cli.main --config config.yaml health --deep
Безопасность
Секреты только через ENV/Secret Manager/Sealed Secrets, не коммитить в Git.

Минимизировать поверхности доступа: ограничить исходящий трафик и сетевые политики.

ACL/RBAC для административных команд; политики валидации схем входящих событий.

Идемпотентность публикаций через ключи, дедупликация на шине.

Подпись и якорение контрольных сумм для аудита неизменности.

Наблюдаемость и профилирование
Метрики (Prometheus‑совместимо), логи (JSON), трассировка (Chrome trace).

bash
Копировать
Редактировать
# Снять профиль горячего блока
python -m engine.cli.main profile --block "ingest_loop" --duration 3.0 --out-dir telemetry/profiles

# Диагностика адаптеров
python -m engine.cli.main adapters datafabric --sql "SELECT 1" --page 1 --page-size 5
Генерация трафика для измерений:

bash
Копировать
Редактировать
python -m engine.cli.tools.loadgen --rps 200 --duration 30 --model open \
  --sink memory --export telemetry/reports/load.json --tag smoke
Тестирование и соответствие
Юнит‑тесты ACL, конформанс AOI, интеграционные тесты якорения, хаос‑тесты шины.

Запуск локально:

bash
Копировать
Редактировать
pytest -q engine/tests/unit
pytest -q engine/tests/integration -m "not requires_backend"
pytest -q engine/tests/chaos -m "chaos"   # при наличии фич инжекции
Переменные для интеграций:

ini
Копировать
Редактировать
LEDGER_ENDPOINT=... LEDGER_API_KEY=... pytest -q engine/tests/integration/test_ledger_anchor.py
Производительность
Микробенчмарки ECS‑итераций:

bash
Копировать
Редактировать
python -m engine.tests.bench.bench_ecs_iter --entities 200000 --iters 200 --repeats 5 \
  --backends naive,packed --out-json telemetry/reports/ecs.json --out-csv telemetry/reports/ecs.csv
Отчет формируется в JSON/CSV; PNG создается при наличии matplotlib.

Развертывание в Kubernetes
Helm‑чарт в deploy/helm/datafabric-core/.

Пример values:

yaml
Копировать
Редактировать
image:
  repository: your-registry/datafabric-core
  tag: "0.1.0"
env:
  - name: ENGINE_LOG_LEVEL
    value: INFO
  - name: CACHE_REDIS_URL
    valueFrom:
      secretKeyRef:
        name: datafabric-secrets
        key: CACHE_REDIS_URL
resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "2"
    memory: "2Gi"
service:
  type: ClusterIP
  port: 8080
livenessProbe:
  httpGet:
    path: /health
    port: 8080
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
Установка:

bash
Копировать
Редактировать
helm upgrade --install datafabric-core deploy/helm/datafabric-core -n datafabric --create-namespace -f values.yaml
Модель данных и контракты
События описываются JSON‑схемами; версии схем хранятся в registry.

Совместимость: semver на уровне контрактов; строгая валидация при ingest.

Политики эволюции: только расширения полей и обратная совместимость; breaking‑изменения проходят через двойную публикацию и миграции.

SLA, эксплуатация и SRE
Цели по задержкам: p99 ingest‑to‑sink ≤ 250 ms (внутри одной зоны).

DLQ и ретраи: экспоненциальная стратегия, ограничение максимального TTL в очередях.

Квоты и rate‑limits: на продюсеров и потребителей, по ключам и по API‑token.

Плейбуки инцидентов: деградация кэш‑бэкенда, потеря связности шины, отставание консьюмеров.

Миграции и обновления
Модель Blue/Green: совместимый релиз с включенными обоими форматами событий.

Фича‑флаги: включение новых конвертеров на проценте трафика.

Контрольная точка: снепшоты схем, якорение контрольных сумм для аудита миграций.

Лицензия
Укажите подходящую лицензию в LICENSE и продублируйте here. Если лицензия не выбрана, по умолчанию код распространяется на условиях, согласованных в контракте поставки. I cannot verify this.

История изменений
См. CHANGELOG.md для фиксирования изменений между версиями. I cannot verify this.

Контакты команды
Ответственная команда: Data Platform

Канал инцидентов: внутренний on‑call

Домашняя страница проекта: внутренний портал. I cannot verify this.