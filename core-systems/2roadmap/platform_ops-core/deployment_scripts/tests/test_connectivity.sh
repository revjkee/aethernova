#!/bin/bash
# Скрипт для тестирования сетевой и сервисной доступности критичных компонентов инфраструктуры
# Включает проверку DNS, ping, TCP портов, и основных API эндпоинтов
# Логирование и контроль ошибок обязательны для безопасности и оперативного реагирования

set -euo pipefail

LOG_FILE="/var/log/test_connectivity.log"

# Функция логирования с отметкой времени
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# Проверка доступности DNS сервера
check_dns() {
    local domain=$1
    log "Проверка DNS для домена $domain"
    if nslookup "$domain" > /dev/null 2>&1; then
        log "DNS работает корректно для $domain"
    else
        log "Ошибка DNS для $domain"
        return 1
    fi
}

# Проверка пинга до хоста
check_ping() {
    local host=$1
    log "Проверка пинга до $host"
    if ping -c 3 "$host" > /dev/null 2>&1; then
        log "Хост $host доступен по ping"
    else
        log "Нет ответа на ping от $host"
        return 1
    fi
}

# Проверка TCP порта
check_tcp_port() {
    local host=$1
    local port=$2
    log "Проверка TCP порта $port на хосте $host"
    if timeout 5 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; th
