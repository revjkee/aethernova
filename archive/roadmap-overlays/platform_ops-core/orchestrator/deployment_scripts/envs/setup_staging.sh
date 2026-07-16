#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

# setup_staging.sh — автоматизация настройки стейджинг окружения
# Обеспечивает установку зависимостей, настройку переменных, деплой сервисов и проверку статуса

log() {
    echo "[setup_staging] $(date +'%Y-%m-%d %H:%M:%S') - $*"
}

ensure_command() {
    local cmd=$1
    local install_hint=$2
    if ! command -v "$cmd" &>/dev/null; then
        log "Команда '$cmd' не найдена. Необходима установка."
        echo "$install_hint"
        exit 1
    else
        log "Команда '$cmd' присутствует."
    fi
}

load_env() {
    if [ -f ".env.staging" ]; then
        export $(grep -v '^#' .env.staging | xargs)
        log "Переменные окружения загружены из .env.staging"
    else
        log "Файл .env.staging отсутствует! Настройте его вручную."
        exit 1
    fi
}

deploy_services() {
    if command -v docker-compose &>/dev/null; then
        log "Запуск docker-compose для стейджинг окружения..."
        docker-compose -f docker-compose.staging.yml pull
        docker-compose -f docker-compose.staging.yml up -d --remove-orphans
        log "Сервисы стейджинга запущены."
    else
        log "docker-compose не найден. Не могу запустить сервисы."
        exit 1
    fi
}

run_health_checks() {
    log "Выполнение проверки состояния сервисов..."
    # Пример простой проверки доступности основного API
    local retries=5
    local url="http://localhost:8080/health"
    while [ $retries -gt 0 ]; do
        if curl --silent --fail "$url" >/dev/null; then
            log "Сервис доступен по $url"
            return 0
        else
            log "Сервис недоступен, пробуем еще раз через 5 секунд..."
            sleep 5
            ((retries--))
        fi
    done
    log "Сервис не запустился корректно после нескольких попыток."
    exit 1
}

main() {
    log "Начинаем настройку стейджинг окружения..."

    ensure_command "docker" "Установите Docker: https://docs.docker.com/get-docker/"
    ensure_command "docker-compose" "Установите docker-compose: https://docs.docker.com/compose/install/"

    load_env
    deploy_services
    run_health_checks

    log "Стейджинг окружение настроено успешно."
}

main "$@"
