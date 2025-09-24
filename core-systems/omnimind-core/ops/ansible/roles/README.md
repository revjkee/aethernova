omnimind-core/ops/ansible/roles/omnimind-core/README.md

# Ansible Role: omnimind-core

Производственная роль для установки, обновления и управления сервисом **omnimind-core** на хостах Linux. Поддерживает режимы: бинарная установка, установка контейнером (Docker/Podman), интеграция с systemd, управление конфигурацией и безопасным перезапуском.

## Поддерживаемые платформы

- Ubuntu 20.04 LTS, 22.04 LTS
- Debian 11, 12
- RHEL 8, 9 / Rocky Linux 8, 9
- Amazon Linux 2
- (опционально) Docker/Podman host с systemd

## Предпосылки и требования

- Ansible >= 2.14
- Python >= 3.8 на управляющей машине и на таргет-хосте
- Привилегии `become: true` для задач, модифицирующих системные ресурсы
- Доступ к артефактам: OCI-реестр (для контейнерного режима) или бинарный релиз/тарболл
- Настроенные репозитории и брандмауэр согласно вашей политике безопасности

## Переменные роли (defaults)

Файл: `defaults/main.yml` (фактические значения переопределяйте в inventory/vars или group_vars)

```yaml
# Режим установки: binary | container
omnimind_mode: "binary"

# Версия приложения (SemVer). Может читаться из отдельного файла VERSION в CI.
omnimind_version: "0.1.0"

# Пользователь/группа системы для сервиса
omnimind_user: "omnimind"
omnimind_group: "omnimind"

# Директории
omnimind_root_dir: "/opt/omnimind-core"
omnimind_config_dir: "/etc/omnimind"
omnimind_data_dir: "/var/lib/omnimind"
omnimind_log_dir: "/var/log/omnimind"

# Бинарная установка
omnimind_binary_url: ""
omnimind_binary_checksum: ""   # sha256:<hex>; если пусто — проверка отключена
omnimind_binary_name: "omnimind-core"

# Контейнерный режим
omnimind_container_runtime: "docker"    # docker | podman
omnimind_image_repository: "ghcr.io/aethernova/omnimind-core"
omnimind_image_tag: "{{ omnimind_version }}"
omnimind_image_pull: true
omnimind_container_name: "omnimind-core"
omnimind_container_env: {}
omnimind_container_ports: []  # пример: ["127.0.0.1:8080:8080/tcp"]
omnimind_container_extra_args: []

# Конфигурация приложения
omnimind_config_template: "omnimind.yml.j2"
omnimind_config:
  log_level: "info"
  http:
    listen: "0.0.0.0"
    port: 8080
  telemetry:
    enable_prometheus: true
    path: /metrics

# Systemd
omnimind_systemd_unit: "omnimind-core.service"
omnimind_systemd_restart: "on-failure"
omnimind_systemd_restart_sec: 5
omnimind_systemd_limit_nofile: 65536
omnimind_systemd_environment: {}  # K=V для Environment=

# Healthcheck
omnimind_healthcheck_enabled: true
omnimind_healthcheck_url: "http://127.0.0.1:8080/healthz"
omnimind_healthcheck_timeout: 15

# SELinux (RHEL-семейство)
omnimind_selinux_manage: true
omnimind_selinux_booleans: []   # пример: ["container_manage_cgroup"]

# Безопасность
omnimind_manage_user: true
omnimind_umask: "0027"
omnimind_extra_sysctl: {}       # пример: {"net.core.somaxconn": 1024}

# Откат
omnimind_keep_previous_binary: true
omnimind_prev_binary_path: "{{ omnimind_root_dir }}/{{ omnimind_binary_name }}.previous"

Переменные (важные для контейнерного режима)
omnimind_container_volumes:
  - "{{ omnimind_config_dir }}:/app/config:ro"
  - "{{ omnimind_data_dir }}:/app/data:rw"
  - "{{ omnimind_log_dir }}:/app/logs:rw"

Теги роли

user — создание пользователя/группы, директории, права

sysctl — системные параметры

install — установка бинаря или контейнера

config — генерация конфигураций и юнитов

service — управление сервисом (systemd)

healthcheck — проверка живости/готовности

rollback — откат на предыдущую версию (binary-mode)

Что делает роль (высокоуровнево)

Создаёт системного пользователя/группу и необходимые директории с безопасными правами.

Применяет системные настройки (sysctl), при необходимости SELinux booleans.

Выполняет установку:

binary: скачивает артефакт, проверяет checksum, кладёт в omnimind_root_dir, выставляет владельца/права, сохраняет предыдущую версию для отката.

container: тянет образ {{ omnimind_image_repository }}:{{ omnimind_image_tag }}, создаёт/обновляет контейнер.

Генерирует конфиг приложения из шаблона omnimind.yml.j2 и unit-файлы systemd.

Делает безопасный рестарт сервиса, ожидает readiness, выполняет health-чек.

При неудаче умеет откатиться на предыдущую версию (в binary-mode).

Пример использования
Inventory

inventory/hosts.yml

all:
  children:
    omnimind_nodes:
      hosts:
        app-01.example.com:
        app-02.example.com:


group_vars/omnimind_nodes.yml

omnimind_mode: "binary"
omnimind_version: "0.1.0"
omnimind_binary_url: "https://artifacts.example.com/omnimind-core/0.1.0/omnimind-core_linux_amd64.tar.gz"
omnimind_binary_checksum: "sha256:DEADBEEF..."
omnimind_config:
  log_level: "info"
  http:
    listen: "0.0.0.0"
    port: 8080

Playbook

site.yml

- name: Deploy omnimind-core
  hosts: omnimind_nodes
  become: true
  roles:
    - role: omnimind-core
      tags: ["user","sysctl","install","config","service","healthcheck"]

Контейнерный режим (пример)
omnimind_mode: "container"
omnimind_image_repository: "ghcr.io/aethernova/omnimind-core"
omnimind_image_tag: "0.1.0"
omnimind_container_ports:
  - "127.0.0.1:8080:8080/tcp"
omnimind_container_env:
  OMNIMIND_LOG_LEVEL: "info"

Хендлеры

restart omnimind-core — перезапускает systemd-юнит.

reload systemd — перезагружает конфигурацию systemd при изменении unit-файлов.

Файлы и шаблоны

templates/omnimind.yml.j2 — конфигурация приложения.

templates/omnimind-core.service.j2 — unit для systemd (binary-mode).

templates/omnimind-core.container.service.j2 — unit для systemd (container-mode, при необходимости).

Идемпотентность и безопасность

Все операции идемпотентны: повторный запуск не меняет состояние без изменения входных данных.

Права на директории и файлы — строгие (umask 0027 по умолчанию).

Проверка checksum бинаря отключаема, но рекомендуется к использованию.

SELinux и sysctl — опциональны и управляются через переменные.

Откат (binary-mode)

При обновлении предыдущий бинарь сохраняется в {{ omnimind_prev_binary_path }}.

Для ручного отката установите omnimind_version на предыдущую версию или выполните задачу с тегом rollback.

Проверка здоровья

Если omnimind_healthcheck_enabled: true, роль выполнит HTTP-проверку {{ omnimind_healthcheck_url }} с таймаутом {{ omnimind_healthcheck_timeout }} секунд.

Ненулевой ответ или таймаут приведут к ошибке деплоя.

Тестирование (Molecule)

Рекомендуемая структура:

molecule/
  default/
    converge.yml
    verify.yml
    molecule.yml


Минимальный molecule/default/molecule.yml:

driver:
  name: docker
platforms:
  - name: omnimind-ubuntu
    image: geerlingguy/docker-ubuntu2204-ansible:latest
provisioner:
  name: ansible
verifier:
  name: ansible


molecule/default/converge.yml:

- name: Converge
  hosts: all
  become: true
  roles:
    - role: omnimind-core

Интеграция с CI

Запускайте ansible-lint для роли.

Выполняйте Molecule-сценарии на матрице платформ.

Публикуйте артефакты (бинарь или контейнер) до запуска роли.

Храните omnimind_version синхронно с манифестами Helm/ Kubernetes.

Переменные для продакшна (рекомендации)

Установите лимиты и requests для системных сервисов контейнерного рантайма.

Включите лог-ротацию (logrotate/journald) для {{ omnimind_log_dir }}.

Секреты (пароли, токены) передавайте через Ansible Vault или через manager секретов.

Теги запуска (примеры)

Только конфиг и рестарт:

ansible-playbook site.yml -t config,service


Только установка:

ansible-playbook site.yml -t install

Лицензия

Apache-2.0

Авторы

Omnimind Release Engineering Team

ChatGPT может допускать ошибки. Рекомендуе