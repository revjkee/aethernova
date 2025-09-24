#!/bin/bash

# ========================================================================
# startup_guard.sh — агент запуска для проверки окружения и угроз
# Проверка на виртуализацию, подмену сетевых параметров, DNS-утечек,
# открытые порты, нестандартные ядра и следы отладки.
# ========================================================================

set -euo pipefail
IFS=$'\n\t'

LOG="/var/log/startup_guard.log"
mkdir -p "$(dirname "$LOG")"

log() {
  echo "[$(date +'%F %T')] $1" | tee -a "$LOG"
}

log "=== Запуск Startup Guard ==="

# === Проверка на виртуализацию ===
check_vm() {
  if grep -qa 'hypervisor' /proc/cpuinfo; then
    log "[ALERT] Обнаружен гипервизор через cpuinfo"
  fi

  if systemd-detect-virt --vm &>/dev/null; then
    log "[ALERT] Обнаружено окружение виртуальной машины: $(systemd-detect-virt)"
  fi
}

# === Проверка на отладку ядра ===
check_kernel_debug() {
  if [[ -f /sys/kernel/debug ]]; then
    log "[ALERT] Доступно ядро в режиме debug: /sys/kernel/debug"
  fi

  if [[ "$(uname -r)" == *"debug"* ]]; then
    log "[ALERT] Ядро собрано с флагами debug: $(uname -r)"
  fi
}

# === Проверка открытых портов ===
check_ports() {
  OPEN_PORTS=$(ss -tunlp | grep -v "127.0.0.1" || true)
  if [[ -n "$OPEN_PORTS" ]]; then
    log "[WARNING] Обнаружены открытые внешние порты:"
    echo "$OPEN_PORTS" | tee -a "$LOG"
  else
    log "[OK] Внешние порты не обнаружены"
  fi
}

# === Проверка утечек DNS/IP ===
check_dns_leak() {
  TEST_DNS=$(dig +short myip.opendns.com @resolver1.opendns.com || echo "FAIL")
  MY_IP=$(curl -s ifconfig.me || echo "FAIL")

  if [[ "$TEST_DNS" != "$MY_IP" ]]; then
    log "[ALERT] Обнаружена потенциальная DNS-утечка. dig=$TEST_DNS curl=$MY_IP"
  else
    log "[OK] DNS и IP совпадают"
  fi
}

# === Проверка MAC-адреса и интерфейсов ===
check_mac() {
  for iface in $(ls /sys/class/net/ | grep -v lo); do
    mac=$(cat /sys/class/net/$iface/address)
    if [[ "$mac" =~ ^00:05:69|^00:0C:29|^00:50:56 ]]; then
      log "[ALERT] MAC-адрес $mac указывает на VMware-интерфейс ($iface)"
    fi
  done
}

# === Запуск всех проверок ===
check_vm
check_kernel_debug
check_ports
check_dns_leak
check_mac

log "=== Startup Guard завершён ==="
exit 0
