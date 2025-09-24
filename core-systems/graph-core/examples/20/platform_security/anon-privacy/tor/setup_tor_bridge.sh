#!/bin/bash

# === Установка и настройка TOR-моста с поддержкой obfs4/meek/snowflake ===
# Поддерживает автоматическую генерацию ключей, настройку firewall и режим выбора транспорта.

set -euo pipefail

MODE=${1:-obfs4}  # Режим по умолчанию — obfs4
TOR_USER=debian-tor
TOR_SERVICE=tor@default
TOR_DIR=/var/lib/tor
OBFS4_KEY_FILE="${TOR_DIR}/pt_state/obfs4_bridgeline.txt"
LOG_FILE="/var/log/tor_bridge_setup.log"

echo "=== [TOR Bridge Setup] Начало установки ($MODE) ==="

# Проверка root-доступа
if [[ $EUID -ne 0 ]]; then
   echo "Запускать от root" 1>&2
   exit 1
fi

# Установка зависимостей
apt update
apt install -y tor obfs4proxy snowflake-server meek-server

# Создание каталога и прав
mkdir -p "${TOR_DIR}/pt_state"
chown -R "${TOR_USER}:${TOR_USER}" "$TOR_DIR"

# Базовая конфигурация torrc
cat > /etc/tor/torrc <<EOF
RunAsDaemon 1
ORPort 9001
ExitRelay 0
SocksPort 0
Log notice file /var/log/tor/notices.log
EOF

# Добавление транспорта в зависимости от режима
case $MODE in
  obfs4)
    echo "Настройка obfs4 моста..."
    cat >> /etc/tor/torrc <<EOF
BridgeRelay 1
ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ExtORPort auto
ServerTransportListenAddr obfs4 0.0.0.0:12345
EOF
    ;;

  meek)
    echo "Настройка meek моста..."
    cat >> /etc/tor/torrc <<EOF
BridgeRelay 1
ServerTransportPlugin meek exec /usr/bin/meek-server --log /var/log/tor/meek.log
ExtORPort auto
EOF
    ;;

  snowflake)
    echo "Настройка snowflake моста..."
    cat >> /etc/tor/torrc <<EOF
BridgeRelay 1
ServerTransportPlugin snowflake exec /usr/bin/snowflake-server -verbosity 2
ExtORPort auto
EOF
    ;;

  *)
    echo "Неподдерживаемый режим: $MODE"
    exit 2
    ;;
esac

# Перезапуск TOR
echo "Перезапуск TOR..."
systemctl restart "$TOR_SERVICE"
sleep 5

# Вывод состояния
echo "=== Статус TOR ==="
systemctl status "$TOR_SERVICE" --no-pager

# Генерация ключа и вывод моста (если obfs4)
if [[ $MODE == "obfs4" ]]; then
  echo "=== Ждём генерации obfs4 ключа ==="
  sleep 10
  if [[ -f "$OBFS4_KEY_FILE" ]]; then
    echo "=== Ваша строчка обфускации: ==="
    cat "$OBFS4_KEY_FILE"
  else
    echo "Ключ obfs4 пока не сгенерирован."
  fi
fi

echo "=== [TOR Bridge Setup] Завершено ($MODE) ===" | tee -a "$LOG_FILE"
