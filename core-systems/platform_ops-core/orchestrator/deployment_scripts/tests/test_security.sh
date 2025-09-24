#!/bin/bash
# Скрипт комплексного тестирования безопасности инфраструктуры
# Включает проверку firewall, уязвимостей, базовых атак и целостности системных файлов
# Логирование результатов с отчетом для анализа

set -euo pipefail

LOG_DIR="/var/log/test_security"
LOG_FILE="$LOG_DIR/security_test_$(date +'%Y%m%d_%H%M%S').log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

check_tools() {
    for tool in nmap lynis chkrootkit fail2ban; do
        if ! command -v $tool &> /dev/null; then
            log "Ошибка: $tool не установлен"
            exit 1
        fi
    done
}

run_firewall_check() {
    log "Проверка статуса и правил firewall (iptables)"
    sudo iptables -L -v -n | tee -a "$LOG_FILE"
}

run_nmap_scan() {
    local target=$1
    log "Запуск сканирования открытых портов и сервисов nmap по адресу $target"
    sudo nmap -sS -sV -O "$target" | tee -a "$LOG_FILE"
}

run_rootkit_check() {
    log "Запуск проверки наличия руткитов chkrootkit"
    sudo chkrootkit | tee -a "$LOG_FILE"
}

run_audit() {
    log "Запуск комплексного аудита безопасности Lynis"
    sudo lynis audit system | tee -a "$LOG_FILE"
}

main() {
    log "Начало тестирования безопасности инфраструктуры"

    check_tools

    run_firewall_check

    # Пример IP или хоста для сканирования
    run_nmap_scan "127.0.0.1"

    run_rootkit_check

    run_audit

    log "Тестирование безопасности завершено"
}

main "$@"
