#!/bin/bash
# Скрипт для нагрузочного тестирования основных сервисов и компонентов инфраструктуры
# Использует ab (ApacheBench) и встроенные системные средства для базовой оценки производительности
# Логирование результатов с детальным анализом

set -euo pipefail

LOG_DIR="/var/log/test_load"
LOG_FILE="$LOG_DIR/load_test_$(date +'%Y%m%d_%H%M%S').log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# Проверка наличия ab (ApacheBench)
check_tools() {
    if ! command -v ab &> /dev/null; then
        log "Ошибка: ApacheBench (ab) не установлен"
        exit 1
    fi
}

# Запуск нагрузочного теста HTTP(S) сервиса
run_http_load_test() {
    local url=$1
    local concurrency=$2
    local requests=$3

    log "Запуск нагрузочного теста: URL=$url, concurrency=$concurrency, requests=$requests"
    ab -n "$requests" -c "$concurrency" "$url" >> "$LOG_FILE" 2>&1

    if [ $? -eq 0 ]; then
        log "Нагрузочный тест для $url завершен успешно"
    else
        log "Ошибка при выполнении нагрузочного теста $url"
        return 1
    fi
}

# Проверка загрузки CPU и памяти в реальном времени
monitor_resources() {
    log "Снятие текущей нагрузки CPU и памяти"
    top -b -n 1 | head -20 >> "$LOG_FILE"
}

main() {
    log "Начало нагрузочного тестирования инфраструктуры"

    check_tools

    # Пример нагрузочного теста API endpoint
    run_http_load_test "https://api.example.com/health" 50 1000

    monitor_resources

    log "Нагрузочное тестирование завершено"
}

main "$@"
