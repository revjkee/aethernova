#!/bin/bash

# === WireGuard VPN Setup Script ===
# Генерация ключей, настройка интерфейса, защита от утечек
# Промышленная версия: безопасный и автономный запуск
# Автор: TeslaAI Genesis, Security Core

set -euo pipefail

WG_DIR="/etc/wireguard"
WG_INTERFACE="wg0"
WG_PORT=51820
WG_CONF="${WG_DIR}/${WG_INTERFACE}.conf"
PRIVATE_KEY_FILE="${WG_DIR}/privatekey"
PUBLIC_KEY_FILE="${WG_DIR}/publickey"
DNS_SERVER="1.1.1.1"

function check_requirements() {
  echo "[INFO] Проверка наличия необходимых утилит..."
  for bin in wg wg-quick iptables resolvectl systemctl; do
    command -v "$bin" >/dev/null || { echo "[ERROR] Утилита $bin не найдена"; exit 1; }
  done
}

function create_keys() {
  echo "[INFO] Генерация ключей WireGuard..."
  umask 077
  wg genkey | tee "$PRIVATE_KEY_FILE" | wg pubkey > "$PUBLIC_KEY_FILE"
}

function create_config() {
  echo "[INFO] Создание конфигурационного файла ${WG_CONF}..."
  PRIVATE_KEY=$(cat "$PRIVATE_KEY_FILE")

  cat > "$WG_CONF" <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = $WG_PORT
DNS = ${DNS_SERVER}
SaveConfig = true

# Добавляйте пиров вручную в секцию ниже
#[Peer]
#PublicKey = <peer_public_key>
#AllowedIPs = 10.0.0.2/32
#Endpoint = <peer_ip>:<port>
EOF
  chmod 600 "$WG_CONF"
}

function enable_firewall_protection() {
  echo "[INFO] Настройка защиты от утечек через iptables..."
  iptables -A OUTPUT ! -o $WG_INTERFACE -m mark ! --mark 0x1 -j REJECT
  ip rule add not fwmark 0x1 table main
  ip route add default dev $WG_INTERFACE table 51820
  ip rule add fwmark 0x1 table 51820
}

function start_wireguard() {
  echo "[INFO] Активация WireGuard-интерфейса..."
  systemctl enable wg-quick@$WG_INTERFACE
  systemctl start wg-quick@$WG_INTERFACE
  systemctl status wg-quick@$WG_INTERFACE --no-pager
}

function show_summary() {
  echo "========================================"
  echo "[DONE] WireGuard установлен и активен!"
  echo "Публичный ключ: $(cat "$PUBLIC_KEY_FILE")"
  echo "Конфигурация: $WG_CONF"
  echo "========================================"
}

# === MAIN EXECUTION ===
check_requirements
mkdir -p "$WG_DIR"
create_keys
create_config
enable_firewall_protection
start_wireguard
show_summary
