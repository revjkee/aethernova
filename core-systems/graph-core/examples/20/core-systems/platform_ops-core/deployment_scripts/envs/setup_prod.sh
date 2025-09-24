#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

# setup_prod.sh — автоматизация настройки продакшен окружения
# Включает проверку зависимостей, загрузку конфигураций, деплой сервисов и post-deploy проверки

log() {
    echo "[setup_prod] $(date +'%Y-%m-%d %H:%M:%S') - $*"
}

ensure_command() {
    local cmd=$1
    local install_hint=$2
    if ! command -v "$cmd" &>/dev/null; then
        log "Команда '$cmd' не найдена. Требуется установка."
        echo "$install_hint"
        exit 1
    else
        log "Команда '$cmd' присутствует."
    fi
}

load_env() {
    if [ -f ".env.prod" ]; then
        set -o allexport
        source .env.prod
        set +o allexport
        log "Переменные окружения загружены из .env.prod"
    else
        log "Файл .env.prod отсутствует! Настройте его перед запуском."
        exit 1
    fi
}

deploy_services() {
    if command -v docker-compose &>/dev/null; then
        log "Запуск docker-compose для продакшен окружения..."
        docker-compose -f docker-compose.prod.yml pull --quiet
        docker-compose -f docker-compose.prod.yml up -d --remove-orphans
        log "Сервисы продакшена запущены."
    else
        log "docker-compose не найден. Прервать выполнение."
        exit 1
    fi
}

run_health_checks() {
    log "Запуск проверки здоровья сервисов..."

    local retries=10
    local url="https://your-production-domain.com/health"
    while [ $retries -gt 0 ]; do
        if curl --silent --fail --insecure "$url" >/dev/null; then
            log "Сервис доступен по $url"
            return 0
        else
            log "Сервис не доступен, повтор через 10 секунд..."
            sleep 10
            ((retries--))
        fi
    done

    log "Сервисы не запустились корректно после нескольких попыток."
    exit 1
}

security_checks() {
    log "Запуск базовых проверок безопасности..."

    # Проверка, что docker-compose.prod.yml не содержит небезопасных настроек
    if grep -E '(privileged: true|cap_add: \[SYS_ADMIN\])' docker-compose.prod.yml &>/dev/null; then
        log "Внимание! Найдены потенциально опасные права в docker-compose.prod.yml"
        exit 1
    fi

    # Проверка доступа к файлам конфигурации
    if [ "$(stat -c '%a' .env.prod)" -gt 640 ]; then
        log "Предупреждение: слишком открытые права на .env.prod"
        chmod 640 .env.prod
        log "Права доступа к .env.prod исправлены на 640."
    fi

    log "Базовые проверки безопасности пройдены."
}

main() {
    log "Начинаем настройку продакшен окружения..."

    ensure_command "docker" "Установите Docker: https://docs.docker.com/get-docker/"
    ensure_command "docker-compose" "Установите docker-compose: https://docs.docker.com/compose/install/"

    load_env
    security_checks
    deploy_services
    run_health_checks

    log "Продакшен окружение настроено успешно."
}

main "$@"
