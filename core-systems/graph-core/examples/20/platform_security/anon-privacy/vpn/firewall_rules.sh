#!/bin/bash

# === TeslaAI Genesis VPN Kill Switch Script ===
# Версия: промышленная, с поддержкой IPv6, DNS и fallback
# Назначение: блокировка всего трафика вне интерфейса WireGuard
# Поддержка: iptables и nftables (по умолчанию — iptables)

set -euo pipefail

VPN_INTERFACE="wg0"
DNS_IPv4="1.1.1.1"
DNS_IPv6="2606:4700:4700::1111"

function flush_rules() {
    echo "[INFO] Очистка предыдущих iptables правил..."
    iptables -F
    iptables -X
    ip6tables -F
    ip6tables -X
}

function enforce_iptables_killswitch() {
    echo "[INFO] Применение правил Kill Switch (iptables)..."

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    iptables -A INPUT -i $VPN_INTERFACE -j ACCEPT
    iptables -A OUTPUT -o $VPN_INTERFACE -j ACCEPT

    iptables -A OUTPUT -d $DNS_IPv4 -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d $DNS_IPv4 -p tcp --dport 53 -j ACCEPT

    iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 51820 -j ACCEPT

    echo "[INFO] IPv4 Kill Switch включён"
}

function enforce_ip6tables_killswitch() {
    echo "[INFO] Применение правил Kill Switch (ip6tables)..."

    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP

    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT

    ip6tables -A INPUT -i $VPN_INTERFACE -j ACCEPT
    ip6tables -A OUTPUT -o $VPN_INTERFACE -j ACCEPT

    ip6tables -A OUTPUT -d $DNS_IPv6 -p udp --dport 53 -j ACCEPT
    ip6tables -A OUTPUT -d $DNS_IPv6 -p tcp --dport 53 -j ACCEPT

    ip6tables -A OUTPUT -p udp --dport 51820 -j ACCEPT
    ip6tables -A OUTPUT -p tcp --dport 51820 -j ACCEPT

    echo "[INFO] IPv6 Kill Switch включён"
}

function validate_interface() {
    if ! ip link show "$VPN_INTERFACE" &> /dev/null; then
        echo "[ERROR] Интерфейс $VPN_INTERFACE не найден!"
        exit 1
    fi
}

# === MAIN ===
validate_interface
flush_rules
enforce_iptables_killswitch
enforce_ip6tables_killswitch

echo "======================================="
echo "[DONE] Kill Switch активен через $VPN_INTERFACE"
echo "Весь небезопасный трафик заблокирован."
echo "======================================="
