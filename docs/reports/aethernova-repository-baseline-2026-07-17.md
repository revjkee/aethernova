# Aethernova Repository Baseline

Дата инвентаризации: 2026-07-17.

Этот документ фиксирует фактическое состояние репозитория до рефакторинга. Он
не объявляет целевую архитектуру уже реализованной и не считает пустые каталоги
или документацию доказательством работающего компонента.

## Этап

Этап 0 — инвентаризация репозитория и построение исходной архитектурной карты.

## Исходное Git-состояние

| Параметр | Фактическое значение |
| --- | --- |
| Рабочая копия аудита | `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization` |
| Ветка | `refactor/aethernova-architecture-stabilization` |
| Upstream | `origin/main` |
| HEAD | `bcc189675741a59a7c468cdae7fd1514ef8fa0a6` |
| `origin/main` | `bcc189675741a59a7c468cdae7fd1514ef8fa0a6` |
| Состояние до создания baseline | чистое |
| Tracked-файлы | 13 237 |
| Условия checkout | на Windows потребовался `git -c core.longpaths=true` |

Исходная рабочая копия пользователя и ранее созданный изолированный WIP не
изменялись и не смешивались с этой веткой.

## Фактическая структура

### Верхний уровень

Репозиторий является неоднородным monorepo. В нём одновременно присутствуют:

- запускаемые приложения: `backend`, `frontend`, `aethernova-web`,
  `telegram_bot`, `reva-studio`, `mobile_app`;
- платформенные/агентные приложения: `agent_mash`, `agents`, `llmops`,
  `nlp-supermodule`, `lab-os`, `predictive-maintenance`, `hr_ai`;
- продуктовые контексты: `csmarket`, `marketplace`, `airdrop_manager`, `game`;
- 43 каталога верхнего уровня в `core-systems`, рассматриваемых текущей
  документацией как канонические ядра;
- 28 каталогов в `core-systems/2roadmap`;
- 20 каталогов в `core-systems/1csmarket`;
- архивные и overlay-материалы в `archive` и `core-systems/3archive`;
- общие deployment/configuration assets в `.github`, `.devcontainer`,
  `monitoring`, `workflows`, `tools`, `docs`.

Из 13 237 tracked-файлов 2 765 активных файлов имеют размер 0 байт. Это не
доказывает, что каждый файл ошибочен, но не позволяет считать дерево каталогов
реализованной архитектурой.

### Основные приложения

| Приложение | Файлов | Пустых | Подтверждённый путь запуска/сборки | Состояние |
| --- | ---: | ---: | --- | --- |
| `backend` | 457 | 360 | `gunicorn src.main:app`, `python -m uvicorn backend.src.main:app` | Запускаемый shell API, доменные роуты не зарегистрированы |
| `frontend` | 678 | 57 | Vite build, Nginx image | Основной web frontend |
| `aethernova-web` | 29 | 8 | отдельный Node/Docker контур | Неполный контур |
| `telegram_bot` | 247 | 74 | `backend.main:app`, `entrypoints/run_bot.py`, `entrypoints/run_worker.py` | Несогласованные Docker и runtime paths |
| `agent_mash` | 394 | 56 | несколько CLI/agent entrypoints | Отдельная агентная подсистема |
| `reva-studio` | 71 | 2 | отдельные API/deploy assets | Прикладной продукт |
| `observability-core` | 190 | 2 | `uvicorn observability_core.api:app` | Наиболее оформленное устанавливаемое ядро |

### Канонические ядра

Фактически присутствуют 43 каталога:

`aethernova-chain-core`, `ai_core`, `ai-ethics-engine`, `ai-platform-core`,
`automation-core`, `avm-core`, `blackvault-core`, `chronowatch-core`,
`compliance-core`, `cybersecurity-core`, `datafabric-core`, `engine-core`,
`evolution-core`, `forgemind-core`, `genesisops-core`, `genius-core`,
`graph-core`, `human-sovereignty-core`, `identity-access-core`, `intel_core`,
`ledger-core`, `mythos-core`, `neuroforge-core`, `oblivionvault-core`,
`observability-core`, `offensive-security-core`, `omnimind-core`,
`onchain-core`, `phantommesh-core`, `physical-integration-core`,
`platform_ops-core`, `platform-security-core`, `policy-core`, `quantum-core`,
`quantumpulse-core`, `resilience-core`, `sageai-core`, `security-core`,
`sentinelwatch-core`, `silentlink-core`, `veilmind-core`, `zero-trust-core`,
`zk-core`.

Именование не унифицировано: `ai_core`, `intel_core` и `platform_ops-core`
используют underscore, остальные в основном kebab-case. Наличие суффикса
`-core` также непоследовательно. Массовое переименование до построения полного
графа импортов, Docker, CI и контрактов запрещено.

Наиболее заметная неполнота:

| Компонент | Файлов | Пустых | Непустых |
| --- | ---: | ---: | ---: |
| `identity-access-core` | 208 | 184 | 24 |
| `resilience-core` | 270 | 264 | 6 |
| `onchain-core` | 223 | 125 | 98 |
| `engine-core` | 292 | 89 | 203 |
| `omnimind-core` | 298 | 78 | 220 |

## Технологический стек

Версии ниже получены из текущих manifests, Docker, Compose, CI и devcontainer,
а не выбраны заново.

| Область | Фактическое состояние |
| --- | --- |
| Python | root `>=3.11`; CI и root Docker используют 3.12; tox/pre-commit/devcontainer ориентированы на 3.11; отдельные компоненты задают диапазоны от 3.10 до 3.13/3.14 |
| Backend | FastAPI, Uvicorn/Gunicorn, Pydantic 2, SQLAlchemy 2 async, asyncpg, Alembic |
| Background work | Celery в root backend; отдельные in-process queues; Redis Streams в Telegram; Redis/Kafka transports в `agent_mash` |
| Frontend | Node/Vite/TypeScript; root CI использует Node 22; devcontainer Node 20; package manifests требуют версии от 18 до 24 |
| Databases | PostgreSQL 15 в root Compose; отдельная PostgreSQL 15 в Telegram Compose; SQLAlchemy async; несколько независимых migration trees |
| Cache/messaging | Redis 7; RabbitMQ объявлен в Telegram Compose, но активный Telegram queue client использует Redis Streams; Kafka используется отдельными компонентами |
| Observability | Prometheus 2.44, Alertmanager 0.27, Grafana 9.5.2, Zabbix, Elasticsearch/Kibana 8.12.1, OpenTelemetry-зависимости |
| Deployment | 55 активных Dockerfile, 31 Compose-файл, 26 Helm Chart, 186 активных Terraform-файлов |
| CI | один исполняемый root workflow; 88 активных nested workflows находятся вне поддерживаемого GitHub пути |

Инвентарь manifests:

| Тип | Активных |
| --- | ---: |
| `pyproject.toml` | 77 |
| `requirements*.txt` | 54 |
| `package.json` | 33 |
| Python/Node/Rust lock-файлы, найденные общим сканированием | 21 |
| Dockerfile | 55 |
| Compose | 31 |
| Helm Chart | 26 |
| Terraform `.tf` | 186 |

Три активных `pyproject.toml` пусты:
`predictive-maintenance/pyproject.toml`,
`core-systems/identity-access-core/pyproject.toml`,
`core-systems/resilience-core/pyproject.toml`.

## Точки входа и пути запуска

### Root backend

- container: `gunicorn src.main:app` из `/app`;
- local Makefile: `python -m uvicorn backend.src.main:app`;
- direct mode в `backend/src/main.py`: `uvicorn main:app`;
- API: `/`, `/health`, `/ready`;
- `register_routes()` пуст, поэтому доменные API в root runtime не подключены;
- settings и logging создаются при импорте;
- database engine хранится в module-level mutable globals;
- production startup падает при недоступной БД, development startup продолжает
  работу, но readiness остаётся 503.

### Frontend

- `npm ci`;
- `npm run typecheck`;
- `npm run build`;
- CI не запускает заявленные `lint` и `test`.

### Observability Core

- package: `core-systems/observability-core/src/observability_core`;
- runtime: `uvicorn observability_core.api:app --port 8080`;
- API: `/health`, `/ready`, `/status`, `/metrics`;
- dashboard: отдельный Vite package;
- верхнеуровневые `exporters`, `ai_monitors`, `incident-replay` и другие
  прототипы не входят в устанавливаемый runtime package.

### Telegram

- API: `uvicorn backend.main:app`;
- bot: `python entrypoints/run_bot.py`;
- worker: `python entrypoints/run_worker.py`;
- текущий Dockerfile пытается копировать отсутствующие в build context
  `.env` и `entrypoints`;
- settings создаются при импорте и печатают полную конфигурацию;
- объявленный RabbitMQ не используется активным queue client;
- Redis Streams client не использует consumer groups, acknowledgements,
  deduplication или DLQ;
- `run_worker.py` импортирует `MessageQueue`, но фактически запускает только
  process-local notification queue.

### Миграции

- root Makefile вызывает Alembic для backend;
- `backend/alembic.ini` задаёт `script_location = backend/migrations`;
- `backend/migrations/env.py` имеет размер 0, `backend/migrations/versions`
  отсутствует;
- реальные migration scripts находятся в `backend/alembic`, где есть
  непустой `env.py` и revisions `0001`, `0002`;
- реальный `env.py` не находит текущие `backend/src/db.py:Base.metadata` и
  `backend/src/models.py:metadata` своим списком candidates;
- runtime `backend/src/main.py` использует `DATABASE_URL`, альтернативный
  `backend/src/db.py` использует `DB_PRIMARY_URL`;
- `backend/src/models.py` описывает сокращённые таблицы, не соответствующие
  фактическим миграциям.

## Инфраструктура и observability

Root Compose синтаксически валиден и содержит:

- backend, frontend, observability-core;
- PostgreSQL 15 и Redis 7;
- Prometheus, Alertmanager, Grafana;
- отдельные Zabbix server/database/web;
- Elasticsearch и Kibana.

Ограничения текущего контура:

- `.dockerignore` отсутствует при root build context `.`; в Docker context
  попадают архивы, документация, незадействованные ядра и потенциально
  чувствительные материалы;
- Prometheus scrapes `backend:8000/metrics`, но root backend не регистрирует
  `/metrics`;
- Alertmanager направляет все уведомления в `local-null`;
- Observability Core подтверждает здоровье локальных synthetic components, а
  не состояние реальных metrics/logs/traces pipelines;
- `OBSERVABILITY_CORE_INTEGRATION_ENABLED=false` в root Compose отключает
  discovery интеграций;
- Grafana assets внутри ядра используют прежнее имя TeslaAI и не
  provisioned root Grafana;
- Elasticsearch запускается с `xpack.security.enabled=false` и публикует порт,
  что допустимо только как явно локальный профиль;
- Compose не задаёт healthcheck для backend, frontend и большинства
  monitoring services и не отделяет production profile.

## Первоначальная карта зависимостей

Высокоуверенный статический AST/import scan публичных package names обнаружил
следующие межкомпонентные зависимости:

```text
agent_mash          -> automation-core
veilmind-core       -> zero-trust-core
omnimind-core       -> observability-core
genius-core         -> omnimind-core
genius-core         -> observability-core
platform_ops-core   -> security-core
zero-trust-core     -> security-core
```

В этом высокоуверенном подграфе цикл не найден. Это не доказательство
отсутствия циклов во всём репозитории:

- найдено 116 активных Python-файлов, изменяющих `sys.path` или `PYTHONPATH`;
- имена `engine`, `security`, `observability`, `eval` принадлежат нескольким
  компонентам;
- `ai_core` одновременно встречается как top-level core и backend package;
- динамические импорты и запускаемые как файлы scripts обходят package graph.

Текущий порядок зависимостей нельзя считать Clean Architecture: в репозитории
сосуществуют package imports, прямые path mutations, HTTP clients, shared
Redis/Kafka transports и process-local queues без единого contract registry.

## Основные команды

### Заявленные команды запуска

```text
make run
docker compose up
python -m uvicorn backend.src.main:app --reload --host 0.0.0.0 --port 8000
uvicorn observability_core.api:app --host 0.0.0.0 --port 8080
npm --prefix frontend run build
```

### Заявленные команды тестирования и качества

```text
python -m pytest tests backend/tests
python -m pytest backend/tests/unit -q
python -m pytest -q
flake8 backend/src backend/tests
mypy backend/src --ignore-missing-imports
black --check backend/src backend/tests tools tests
python tools/repository_audit.py
docker compose config --quiet
```

Root devcontainer и tox используют `requirements-dev.txt`, которое в текущем
виде неразрешимо из-за конфликтующих exact pins.

## Обнаружено

| ID | Критичность | Компонент | Проблема | Причина | Последствие |
| --- | --- | --- | --- | --- | --- |
| BASE-001 | BLOCKER | Root dependencies | `requirements-dev.txt` содержит 10 exact-pin конфликтов с включаемым `requirements.txt` | Два независимых набора версий объединены через `-r requirements.txt` | Devcontainer post-create и tox не могут воспроизводимо установить окружение |
| BASE-002 | BLOCKER | Backend migrations | `backend/alembic.ini` направлен в пустое migration tree | Реальные revisions находятся в другом каталоге | Штатный migrate path не может применить или проверить схему |
| BASE-003 | BLOCKER | Telegram container | Dockerfile копирует отсутствующие `.env` и `entrypoints` | Docker paths не соответствуют дереву `backend/entrypoints` | Telegram image не собирается |
| BASE-004 | CRITICAL | Telegram settings | Полный `settings.model_dump()` печатается при импорте | Debug side effect оставлен в production import path | Telegram token, database URL и парольные поля попадают в stdout/log aggregation |
| BASE-005 | CRITICAL | Identity Access | При инициализации всегда создаётся `emergency_admin` с `*`, известным default password и без MFA | Emergency recovery code и документация объявлены production-ready | При достижимом запуске возникает предсказуемая privileged identity; fail-open security |
| BASE-006 | HIGH | Identity Access | Документированный `python main.py` использует относительные импорты, package manifest и Dockerfile пусты, 184/208 файлов пусты | Recovery skeleton принят за реализованное ядро | Критическое ядро нельзя корректно установить, собрать и запустить заявленным способом |
| BASE-007 | HIGH | Backend API | Root container обслуживает только system endpoints | `register_routes()` является пустым placeholder | Container может быть healthy, не предоставляя заявленной бизнес-функциональности |
| BASE-008 | HIGH | Database model | Runtime, альтернативный DB layer, Alembic metadata и table models расходятся | Несколько несогласованных источников истины | Autogenerate ненадёжен, schema drift не обнаруживается, возможны ошибки данных |
| BASE-009 | HIGH | CI | 88 активных workflow вложены в component `.github/workflows` | GitHub исполняет workflows только из root `.github/workflows` | Большинство компонентов создаёт ложное впечатление CI coverage |
| BASE-010 | HIGH | Repository completeness | 2 765 активных файлов имеют размер 0 | Скелеты и восстановленные деревья смешаны с runtime | Наличие файла/ядра не означает наличие реализации; imports и builds непредсказуемы |
| BASE-011 | HIGH | Dependency management | 77 pyproject и 54 requirements-файла используют Poetry, setuptools, Hatchling и разные version policies | Нет единого ownership и lock policy | Чистая установка всего monorepo невоспроизводима |
| BASE-012 | HIGH | Module boundaries | 116 path mutations и collisions публичных package names | Scripts и компоненты обходят установку packages | Import graph зависит от CWD/PYTHONPATH; полный cycle analysis пока недостоверен |
| BASE-013 | HIGH | Docker build | Root `.dockerignore` отсутствует | Docker build context равен repository root | Медленные/нестабильные builds и риск попадания лишних/чувствительных файлов в context |
| BASE-014 | HIGH | Observability | Prometheus scrapes отсутствующий backend `/metrics`; core health является synthetic | Runtime wiring не соответствует monitoring config | Backend target постоянно down, readiness не подтверждает telemetry pipeline |
| BASE-015 | HIGH | Messaging | Redis Streams, in-memory queues, Celery, Redis Pub/Sub и Kafka не имеют общего envelope/ownership | Messaging развивался локально по компонентам | Нет сквозной идемпотентности, correlation/causation, retry/DLQ policy |
| BASE-016 | MEDIUM | Runtime versions | Python/Node версии различаются между CI, Docker, tox, devcontainer и components | Нет compatibility matrix | Локальный результат может отличаться от CI/container |
| BASE-017 | MEDIUM | Documentation | `docs/system_overview.md` описывает TeslaAI и несуществующие пути | Документ не обновлялся вместе со структурой | Архитектурные решения принимаются по устаревшей карте |
| BASE-018 | MEDIUM | Compose security | Несколько сервисов публикуют management/data ports; Elasticsearch security отключена | Root Compose смешивает local и production-like services | Опасная конфигурация при использовании вне изолированной dev-сети |
| BASE-019 | MEDIUM | Windows checkout | Обычный checkout падает на длинных путях | Глубокие архивные/infra trees превышают Windows path limit | Новые contributors не могут клонировать/checkout без специальной настройки |
| BASE-020 | LOW | Distribution metadata | Root `LICENSE` пуст | Лицензия не выбрана/не добавлена | Нельзя корректно публиковать packages/releases |

Конфликтующие root dev pins:

| Package | Root | Dev |
| --- | --- | --- |
| `argon2-cffi` | 23.1.0 | 21.3.0 |
| `docker` | 7.1.0 | 6.1.3 |
| `jaeger-client` | 4.9.0 | 4.8.0 |
| `kubernetes` | 29.0.0 | 26.1.0 |
| `onnxruntime` | 1.17.3 | 1.22.0 |
| `opentelemetry-sdk` | 1.26.0 | 1.25.0 |
| `ray` | 2.21.0 | 2.47.1 |
| `scikit-learn` | 1.5.0 | 1.3.0 |
| `sphinx` | 7.3.7 | 7.1.1 |
| `tox` | 4.15.0 | 4.9.0 |

## Решение

На этапе baseline код, зависимости, инфраструктура и публичные контракты не
изменялись. Создана отдельная ветка и изолированная рабочая копия, собран
проверяемый реестр компонентов, manifests, entrypoints, инфраструктуры,
первоначальных dependency edges и блокеров.

Первым исправлением после baseline выбран `BASE-004`: удалить импортный вывод
секретов из Telegram settings и добавить regression test, подтверждающий, что
импорт конфигурации не пишет значения секретов в stdout/stderr. Это минимальное
обратно совместимое изменение, устраняющее достижимую утечку без перестройки
архитектуры.

`BASE-005` требует отдельного fail-closed решения и тестов до включения
identity-access-core в какой-либо production runtime. Старый emergency WIP не
будет переноситься автоматически.

## Изменённые файлы

- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\docs\reports\aethernova-repository-baseline-2026-07-17.md`

## Проверки

### Git state

```text
Команда:
git -c core.longpaths=true status --short --branch
git -c core.longpaths=true rev-parse HEAD
git -c core.longpaths=true rev-parse origin/main

Результат:
PASS

Код завершения:
0

Вывод:
## refactor/aethernova-architecture-stabilization...origin/main
bcc189675741a59a7c468cdae7fd1514ef8fa0a6
bcc189675741a59a7c468cdae7fd1514ef8fa0a6
```

### Repository contract audit

```text
Команда:
python tools/repository_audit.py

Результат:
PASS с предупреждением

Код завершения:
0

Вывод:
WARNING: LICENSE is empty; choose a license before publishing releases or packages
repository audit: 13237 tracked files, 0 error(s), 1 warning(s)
```

### Compose syntax

```text
Команда:
docker compose config --quiet

Результат:
PASS; Compose синтаксически валиден

Код завершения:
0

Вывод:
WARNING: Error loading config file: open C:\Users\revav\.docker\config.json: Access is denied.
WARNING: Error loading config file: open C:\Users\revav\.docker\config.json: Access is denied.
```

### Root requirements consistency

```text
Команда:
PowerShell exact-pin comparison of requirements.txt and requirements-dev.txt

Результат:
FAIL; найдено 10 несовместимых exact pins

Код завершения:
0 (диагностический скрипт)

Вывод:
CONFLICT_COUNT=10
```

### Backend migration path

```text
Команда:
PowerShell path/size validation for backend/alembic.ini script_location

Результат:
FAIL

Код завершения:
0 (диагностический скрипт)

Вывод:
ConfiguredEnvExists=True
ConfiguredEnvBytes=0
ConfiguredVersionsExists=False
ActualEnvExists=True
ActualEnvBytes=6985
ActualVersionsExists=True
ActualRevisionCount=2
```

### Alembic executable check

```text
Команда:
python -m alembic -c backend/alembic.ini heads

Результат:
BLOCKED локальным окружением до проверки неверного script_location

Код завершения:
1

Вывод:
C:\Users\revav\AppData\Local\Programs\Python\Python314\python.exe: No module named alembic
```

### Local toolchain

```text
Команда:
python -m pytest --version
node --version
npm --version
docker --version
docker compose version
git --version

Результат:
Python tests BLOCKED до создания совместимого окружения; остальные CLI доступны

Код завершения:
составная диагностическая команда завершилась 0 по последнему вызову

Вывод:
Python 3.14: No module named pytest
Node v24.13.0
npm 11.6.2
Docker 29.2.0
Docker Compose v5.0.2
git 2.54.0.windows.1
```

## Десять независимых проверок baseline

| Роль | Фактический результат |
| --- | --- |
| Системный архитектор | Core-based дерево присутствует, но package ownership и исполняемые границы не совпадают с каталогами |
| Domain-архитектор | Bounded contexts документированы неравномерно; root backend не подключает domain routes |
| Senior Python Engineer | Async runtime существует, но settings side effects, globals, path mutations и несколько package layouts мешают воспроизводимости |
| Database Engineer | Migration tree, metadata, модели и runtime database config не имеют единого источника истины |
| Security Engineer | Подтверждены import-time утечка Telegram secrets и unsafe emergency privileged identity |
| DevOps Engineer | Compose syntax валиден; dev dependencies, Telegram image и migration command заблокированы |
| SRE Engineer | Health endpoints не равны telemetry health; backend Prometheus target отсутствует |
| QA Engineer | Root CI тестирует малую часть monorepo; nested workflows не исполняются |
| Performance Engineer | Root Docker context не ограничен; тяжёлые ML/infra dependencies сведены в общий requirements |
| Reviewer | Массовые перемещения и удаления не обоснованы; первый безопасный шаг должен быть узким security fix |

## Риски

- Полный граф импортов ещё нельзя считать доказанным из-за path mutations,
  dynamic imports и namespace collisions.
- Содержимое 43 ядер не проверено построчно; baseline классифицирует структуру
  и подтверждённые blockers, но не заменяет последующие component audits.
- Docker images не собирались, сервисы и внешние БД/брокеры не запускались на
  этапе read-only inventory.
- Dependency vulnerability audit не запускался: сначала нужен разрешимый и
  воспроизводимый dependency set.
- В репозитории есть файлы, имитирующие credentials/private keys для security
  tests и deception; автоматический secret scan требует allowlist и ручной
  review, чтобы не смешать fixtures с реальными утечками.
- Root Compose является допустимым только как локальная исходная конфигурация,
  пока deployment profiles и network exposure не формализованы.

## Следующий шаг

Этап 1.1 — устранить `BASE-004`: import-time утечку Telegram secrets, добавить
regression test, затем выполнить узкие tests/static checks и повторный
repository audit.
