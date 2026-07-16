# Deployment Runbook

## Документ

- Название: `deployment.md`
- Контур: `reva-studio/docs/runbooks/`
- Назначение: единый production-grade runbook для безопасного, повторяемого и аудируемого деплоя Reva Studio
- Аудитория:
  - platform engineers
  - backend engineers
  - DevOps / SRE
  - on-call engineers
  - release managers
- Статус: Active
- Критичность: High
- Последнее обновление: 2026-03-22
- Владение:
  - Platform Team
  - Backend Team
  - Security Review

---

# 1. Цель

Этот runbook описывает стандартный процесс деплоя Reva Studio в окружения `dev`, `staging`, `production`.

Документ нужен для того, чтобы:

- деплой был повторяемым
- деплой был безопасным
- деплой был проверяемым
- деплой можно было откатить
- инциденты при релизе можно было быстро локализовать
- изменения были привязаны к release-процессу, миграциям, health-check и post-deploy verification

---

# 2. Область действия

Runbook покрывает:

- подготовку к релизу
- проверку артефактов
- деплой backend
- деплой worker / scheduler
- деплой миграций БД
- деплой frontend
- post-deploy verification
- rollback
- failure handling
- минимальные требования к observability и audit

Runbook не покрывает в деталях:

- разработку инфраструктуры Terraform
- проектирование CI/CD pipelines
- написание Helm charts
- внутреннюю реализацию Dockerfiles
- бизнес-изменения доменов

---

# 3. Базовые принципы

## 3.1 Общие правила

1. Никакой ручной деплой в production без runbook-совместимого процесса.
2. Никаких неподтверждённых hotfix-релизов без явной фиксации change reason.
3. Никаких миграций БД без проверки backward/forward compatibility.
4. Никаких релизов без smoke-check после выката.
5. Никаких изменений secrets через ad hoc-редактирование контейнеров или runtime-окружения.
6. Никаких ручных правок данных в БД как части штатного деплоя.
7. Любой production deploy должен быть аудируемым: кто, когда, что выкатывал, какой commit, какой образ, какой rollout result.
8. При сомнении приоритет: безопасность и консистентность выше скорости релиза.

## 3.2 Подход к деплою

Предпочтительный подход:

- immutable artifacts
- versioned docker images
- environment-specific configuration
- automated migrations
- health-based rollout
- explicit rollback path
- post-deploy verification
- structured logging and metrics

## 3.3 Требования к артефактам

Каждый релиз должен иметь:

- git commit SHA
- release tag или version label
- docker image tag
- changelog / release notes
- миграции, если есть schema changes
- подтверждённый deployment target
- запись о результате выката

---

# 4. Компоненты, входящие в деплой

Типовой deployment scope Reva Studio включает:

- `api`
- `worker`
- `scheduler` или `beat`
- `frontend`
- `nginx` или ingress configuration
- `database migrations`
- `redis` integration checks
- `observability hooks`

Опционально:

- background consumers
- webhook processors
- admin panel
- async integration workers

---

# 5. Роли и ответственность

## 5.1 Release Initiator

Отвечает за:

- запуск процесса релиза
- проверку релизной готовности
- подтверждение target environment
- фиксацию версии и changelog

## 5.2 Deployment Operator

Отвечает за:

- выполнение команд деплоя
- контроль статуса rollout
- верификацию миграций
- запуск smoke-check
- эскалацию при сбое

## 5.3 Reviewer / Approver

Отвечает за:

- проверку release-risk
- approval production rollout
- проверку rollback readiness

## 5.4 On-call Engineer

Отвечает за:

- реакцию на деградацию после релиза
- оценку rollback vs fix-forward
- контроль инцидентного окна

---

# 6. Предварительные условия

Перед деплоем должны быть выполнены все пункты ниже.

## 6.1 Код и артефакты

- все изменения в main / release branch замержены
- CI завершился успешно
- тесты прошли
- image build завершён
- image опубликован в registry
- tag / SHA известен и зафиксирован
- release notes подготовлены

## 6.2 Инфраструктура

- целевое окружение доступно
- registry доступен
- secrets доступны через approved mechanism
- БД доступна
- Redis доступен
- ingress / LB в нормальном состоянии
- monitoring доступен
- alerting работает

## 6.3 Безопасность

- нет незапланированных секретов в diff
- нет hardcoded credentials в релизе
- нет отладочных флагов для production
- нет отключённых security middleware без approved exception

## 6.4 Миграции

Если релиз содержит миграции:

- миграции просмотрены
- миграции протестированы в staging
- оценено время выполнения
- оценён риск блокировок
- есть план rollback / forward-fix
- изменение схемы совместимо с текущим rollout strategy

---

# 7. Политика версионирования релиза

Каждый деплой должен ссылаться минимум на:

- `release version`
- `git sha`
- `container image tag`
- `migration revision`, если применимо

Пример release identity:

```text
release_version=2026.03.22-01
git_sha=abc123def456
api_image=registry.example.com/reva-studio/api:2026.03.22-01
worker_image=registry.example.com/reva-studio/worker:2026.03.22-01
frontend_image=registry.example.com/reva-studio/frontend:2026.03.22-01
alembic_revision=20260322_0007