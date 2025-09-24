---
kb_id: "kb.omnimind.core.demo.001"
title: "OmniMind Core: руководство по развертыванию и операционке (Demo)"
version: "1.0.0"
status: "stable"               # stable | draft | deprecated
domain: "platform-engineering"
subdomain: "omnimind-core"
owner_team: "platform"
owner_contact: "platform@omni.example"
last_reviewed_at: "2025-08-01"
next_review_due: "2026-02-01"
confidentiality: "internal"    # public | internal | restricted
tags:
  - ansible
  - deployment
  - healthcheck
  - k8s
  - docker
  - terraform
  - postgresql
  - redis
language: "ru"
format: "kb-card.v1"
checksum: "sha256:{{ вычисляется CI на артефакте }}"
sources:                        # реальные ссылки на внутренние репо/процедуры
  - type: "repo"
    name: "omnimind-core"
    path: "ops/ansible"
    ref: "main"
  - type: "repo"
    name: "omnimind-core"
    path: "ops/k8s"
    ref: "main"
compliance:
  pii: false
  sox_relevant: false
retrieval:
  bm25_boost_terms: ["omnimind-core", "ansible", "healthcheck", "deploy", "k8s", "helm", "pdb", "terraform"]
  synonyms: ["развертывание=deployment", "проверка здоровья=healthcheck", "контейнеризация=docker"]
---

# Обзор

Цель документа: дать инженерной команде воспроизводимую последовательность действий для окружений dev и prod, включая подготовку хоста Ansible, проверку здоровья сервиса, контейнеризацию, Helm-часть и минимально достаточную инфраструктуру в облаке. Документ согласован с промышленными файлами, предложенными для `omnimind-core` (роль prereq, healthcheck, devcontainer, Dockerfile, Helm PDB, Terraform dev).

> Политика проверки: при каждом изменении CI обновляет `checksum` и валидирует поля front matter. Если источник фактов отсутствует или спорен, отметка в тексте делается как I cannot verify this.

---

## 1. Быстрый старт по развертыванию

### 1.1 Подготовка хоста Ansible

Предпосылки: Ansible >= 2.14, Python >= 3.8 на целевом хосте.

Команды:
1) Выполнить роль prereq для подготовки ОС, пользователя, лимитов и опционального Docker.  
2) Применить конфиг окружения `configs/env/dev.yaml`.

Контрольные пункты:
- Созданы директории `/opt/omnimind`, `/etc/omnimind`, `/var/log/omnimind`, `/var/run/omnimind` с правами 0750.  
- Пользователь и группа приложения существуют и ненаделены интерактивной оболочкой.

См. роль: `ops/ansible/roles/omnimind-core/tasks/prereq.yml`.

### 1.2 Проверка здоровья

Выполнить playbook или тег `health` роли. Ожидаемый артефакт: `/var/log/omnimind/health_report.json`. Любые найденные нарушения должны быть устранены до запуска в прод.

См. роль: `ops/ansible/roles/omnimind-core/tasks/healthcheck.yml`.

---

## 2. Контейнеризация и запуск

- Базовый образ: `python:3.11-slim`, многостадийный билд, non-root пользователь, включен HEALTHCHECK.  
- Запуск в прод: Gunicorn с UvicornWorker, `umask 027`, переменные окружения через Secret.  
- Секреты рекомендуется доставлять через External Secrets Operator, чтобы значения не попадали в Git.

См. файл: `ops/docker/Dockerfile`.  
См. манифест: `ops/k8s/base/secret.yaml` (ExternalSecret).

---

## 3. Kubernetes и устойчивость

- `PodDisruptionBudget` задается через Helm-шаблон, запрещено одновременное использование `minAvailable` и `maxUnavailable`.  
- Для кластеров Kubernetes версии 1.26+ возможно задать `unhealthyPodEvictionPolicy`.

См. файл: `ops/helm/templates/pdb.yaml`.

---

## 4. Terraform окружение dev

Компоненты:
- VPC с public/private подсетями в двух зонах доступности.  
- EC2 для запуска контейнера, доступ через SSM без SSH.  
- S3 для артефактов, ECR для образов.  
- Опционально RDS PostgreSQL, в dev допускается публичная доступность, но ограниченная по IP.

См. файл: `ops/ansible/playbooks/envs/dev/main.tf`.

---

## 5. Переменные окружения Ansible

Использовать `ops/ansible/configs/env/dev.yaml`. Ключевые поля:
- `identity.*` для пользователя и группы.  
- `app.http.*` для портов и эндпойнтов здоровья.  
- `integrations.*` для Postgres/Redis.  
- `tuning.*` для лимитов и sysctl.  
- `healthcheck.*` для порогов мониторинга.

---

## 6. Карточки знаний (Q&A)

### 6.1 Как проверить, что сервис готов принимать трафик

Проблема: нестабильность после деплоя.  
Решение: вызвать `/ready` до начала трафика, `/healthz` для периодического мониторинга.

Псевдокод проверки:
- GET `http://127.0.0.1:8000/ready` ожидает 200.  
- Если 5 последовательных попыток вернули не 200, деплой считается неуспешным.

Источники: роль `healthcheck.yml`.

### 6.2 Как интерпретировать отчет здоровья

`health_report.json` включает ключ `failures`. Если список пуст, хост в норме. Иначе проверьте префикс проблемы:
- `service:*` ошибки systemd.  
- `http:*` проблемы эндпойнтов.  
- `disk:*`, `cpu:*`, `mem:*` ресурсы.  
- `db:*`, `cache:*` интеграции.

Источники: роль `healthcheck.yml`.

### 6.3 Как безопасно доставить секреты в кластер

Использовать External Secrets Operator и `ClusterSecretStore`. В Git хранится только `ExternalSecret` с именами ключей. Значения хранятся во внешнем Secret Store.

Источники: `ops/k8s/base/secret.yaml`.

---

## 7. Операционные процедуры

### 7.1 Обновление приложения в Kubernetes

1) Обновить контейнерный образ в Helm values или в GitOps-репозитории.  
2) Применить релиз с включенным PDB.  
3) Убедиться, что PDB допускает только допустимые voluntary-эвикции.  
4) Проверить `/ready` и `/healthz`.

### 7.2 Восстановление после сбоев

- Проверить журнал systemd и фильтры ошибок за последние 10 минут.  
- Проверить лимиты `ulimit -n` и `fs.file-max`.  
- Для RDS проверить доступность и метрики CPU/IOPS.

---

## 8. Схема метаданных карточки знаний

Каждая карточка в этом файле (разделы 6.x) соответствует схеме:

