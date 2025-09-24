#!/bin/bash

# === TeslaAI Leak Detector v2.0 ===
# Назначение: обнаружение DNS, IP и WebRTC утечек при активной VPN (WireGuard) или TOR.
# Совместимость: Linux (bash, dig, curl, ip, resolvectl)

set -euo pipefail

LOG_FILE="/tmp/leak_check_$(date +%Y%m%d_%H%M%S).log"
VPN_INTERFACE="wg0"
TOR_CHECK_URL="https://check.torproject.org/"
IP_API="https://api.ipify.org"
DNS_TEST_DOMAIN="leak.test.teslaai.io"  # Специальный поддомен с логированием на сервере
SAFE_DNS=("1.1.1.1" "9.9.9.9" "8.8.8.8")

function log() {
    echo "[*] $1" | tee -a "$LOG_FILE"
}

function check_external_ip() {
    log "Проверка внешнего IP..."
    EXT_IP=$(curl -s "$IP_API")
    log "Внешний IP: $EXT_IP"
}

function check_dns_servers() {
    log "Анализ DNS резолверов..."

    if command -v resolvectl &> /dev/null; then
        resolvectl dns | tee -a "$LOG_FILE"
    elif [[ -f /etc/resolv.conf ]]; then
        cat /etc/resolv.conf | grep -E '^nameserver' | tee -a "$LOG_FILE"
    else
        log "DNS не удалось определить"
    fi
}

function test_dns_leak() {
    log "Отправка запроса на тестовый домен ($DNS_TEST_DOMAIN) для пассивного логирования..."
    dig +short $DNS_TEST_DOMAIN > /dev/null 2>&1 || log "dig не сработал — возможно, DNS блокирует выход"
    log "Если DNS-запрос зафиксирован на контролирующем сервере — утечка подтверждена."
}

function check_interface_routes() {
    log "Проверка активных маршрутов через VPN-интерфейс ($VPN_INTERFACE)..."
    ip route show | grep "$VPN_INTERFACE" | tee -a "$LOG_FILE" || log "ВНИМАНИЕ: трафик может идти в обход VPN!"
}

function check_ipv6_status() {
    log "Проверка активности IPv6..."
    if [[ $(cat /proc/net/if_inet6 | wc -l) -gt 0 ]]; then
        log "IPv6 АКТИВЕН — потенциальная утечка!"
    else
        log "IPv6 отключён — хорошо."
    fi
}

function check_tor_presence() {
    log "Проверка присутствия TOR..."
    if curl -s "$TOR_CHECK_URL" | grep -q "Congratulations. This browser is configured to use Tor."; then
        log "TOR успешно активен."
    else
        log "TOR не используется или фильтруется."
    fi
}

function check_webrtc_leak() {
    log "Для WebRTC утечек требуется ручная проверка: https://browserleaks.com/webrtc или запуск headless-браузера через selenium."
}

# === MAIN ===

log "======== НАЧАЛО АНАЛИЗА УТЕЧЕК ========"

check_external_ip
check_dns_servers
test_dns_leak
check_interface_routes
check_ipv6_status
check_tor_presence
check_webrtc_leak

log "======== АНАЛИЗ ЗАВЕРШЁН. Лог: $LOG_FILE ========"
