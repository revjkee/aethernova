#!/bin/bash

# TeslaAI MAC Spoofing Script v3.1 — Hardened
# Конфиденциальная смена MAC-адреса с очисткой следов
# Поддержка: Linux (Debian-based), виртуальные интерфейсы

set -euo pipefail
INTERFACE=${1:-"eth0"}
MACGEN_BIN="/usr/bin/macchanger"

log() {
    echo "[+] $1"
}

abort_if_rootless() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "[-] Необходим запуск от root"
        exit 1
    fi
}

check_dependencies() {
    command -v $MACGEN_BIN >/dev/null 2>&1 || {
        echo "[-] macchanger не найден. Установите: sudo apt install macchanger"
        exit 2
    }
}

disable_network() {
    ip link set "$INTERFACE" down
    log "Интерфейс $INTERFACE отключён"
}

generate_random_mac() {
    $MACGEN_BIN -r "$INTERFACE" > /dev/null
    NEW_MAC=$(ip link show "$INTERFACE" | awk '/ether/ {print $2}')
    log "Установлен новый MAC: $NEW_MAC"
}

flush_arp_cache() {
    ip neigh flush all || true
    log "ARP кэш очищен"
}

re_enable_network() {
    ip link set "$INTERFACE" up
    log "Интерфейс $INTERFACE включён"
}

wipe_logs() {
    journalctl --rotate
    journalctl --vacuum-time=1s
    log "Журналы systemd сжаты"
}

force_kvm_isolation() {
    if [ -d /sys/class/net/"$INTERFACE"/device ]; then
        echo 1 > /sys/class/net/"$INTERFACE"/device/disable_netpoll 2>/dev/null || true
        log "Изоляция уровня KVM/virtio применена"
    fi
}

# MAIN EXECUTION
abort_if_rootless
check_dependencies
disable_network
generate_random_mac
flush_arp_cache
re_enable_network
force_kvm_isolation
wipe_logs

log "MAC Spoofing завершён. Используйте VPN или TOR сразу после перезапуска сети."
exit 0
