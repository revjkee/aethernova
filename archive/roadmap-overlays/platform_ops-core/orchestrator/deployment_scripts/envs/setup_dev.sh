#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

# setup_dev.sh — автоматизация настройки локального дев окружения
# Обеспечивает установку зависимостей, настройку переменных окружения и старт сервисов

# Логирование с отметками времени
log() {
    echo "[setup_dev] $(date +'%Y-%m-%d %H:%M:%S') - $*"
}

# Проверка наличия команды, иначе установка
ensure_command() {
    local cmd=$1
    local install_instructions=$2
    if ! command -v "$cmd" &>/dev/null; then
        log "Команда '$cmd' не найдена. Запускаем установку."
        eval "$install_instructions"
    else
        log "Команда '$cmd' найдена."
    fi
}

# Установка Python виртуального окружения и зависимостей
setup_python_env() {
    log "Настройка Python виртуального окружения..."
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        log "Виртуальное окружение создано."
    else
        log "Виртуальное окружение уже существует."
    fi
    source .venv/bin/activate
    pip install --upgrade pip setuptools wheel
    pip install -r requirements.txt
    log "Python зависимости установлены."
}

# Настройка переменных окружения из шаблона
setup_env_file() {
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
            log "Файл .env создан на основе .env.example"
        else
            log "Файл .env.example не найден, пропускаем создание .env"
        fi
    else
        log "Файл .env уже существует."
    fi
}

# Запуск локальных сервисов через docker-compose
start_services() {
    if command -v docker-compose &>/dev/null; then
        log "Запуск docker-compose сервисов..."
        docker-compose up -d
        log "Сервисы запущены."
    else
        log "docker-compose не установлен. Пропускаем запуск сервисов."
    fi
}

# Проверка наличия git и установка git hooks
setup_git_hooks() {
    if command -v git &>/dev/null; then
        log "Настройка git hooks..."
        if [ -d ".git" ]; then
            cp ./scripts/git-hooks/pre-commit .git/hooks/pre-commit
            chmod +x .git/hooks/pre-commit
            log "Git hooks установлены."
        else
            log "Это не git репозиторий, пропускаем настройку git hooks."
        fi
    else
        log "Git не найден, пропускаем настройку git hooks."
    fi
}

# Основной сценарий
main() {
    log "Запуск скрипта настройки дев окружения."

    ensure_command "python3" "echo 'Установите Python 3 вручную и запустите скрипт снова.' && exit 1"
    ensure_command "pip" "echo 'pip не найден, установка невозможна, проверьте Python' && exit 1"
    ensure_command "docker-compose" "echo 'docker-compose не найден, пропускаем запуск сервисов.'"

    setup_python_env
    setup_env_file
    start_services
    setup_git_hooks

    log "Настройка дев окружения завершена успешно."
}

main "$@"
