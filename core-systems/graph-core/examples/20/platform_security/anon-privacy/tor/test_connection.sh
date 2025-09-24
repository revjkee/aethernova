#!/bin/bash

# === TOR Connection Test Script ===
# Проверка: текущий IP, DNS-утечки, прокси-доступ через curl через TOR
# Совместим с режимами obfs4, meek, snowflake
# Обеспечивает быстрый аудит анонимности

set -euo pipefail

TOR_PROXY="socks5h://127.0.0.1:9050"
DNS_TEST_HOST="whoami.akamai.net"
TEST_URL="https://check.torproject.org"
TMP_DNS_OUTPUT="/tmp/dns_leak_test.txt"

echo "=========================="
echo "[INFO] Проверка TOR-соединения"
echo "=========================="

# Проверка IP через TOR
echo -n "[STEP 1] Внешний IP через TOR: "
curl --silent --socks5-hostname $TOR_PROXY https://api.ipify.org || echo "[Ошибка запроса IP]"

# Проверка доступности ресурса через TOR
echo -n "[STEP 2] Доступность check.torproject.org: "
if curl --silent --socks5-hostname $TOR_PROXY --max-time 5 "$TEST_URL" | grep -q "Congratulations. This browser is configured to use Tor"; then
  echo "[OK] TOR доступен"
else
  echo "[FAIL] Нет ответа или вы не через TOR"
fi

# DNS Leak Test
echo "[STEP 3] Тест на DNS-утечки (через dig)"
if command -v dig &>/dev/null; then
  dig @$DNS_TEST_HOST google.com > "$TMP_DNS_OUTPUT" 2>/dev/null || true
  if grep -q "SERVER:" "$TMP_DNS_OUTPUT"; then
    echo "[FAIL] DNS утечка! Проверь настройки resolver"
  else
    echo "[OK] Нет DNS-утечки обнаружено"
  fi
else
  echo "[SKIP] dig не установлен"
fi

# Проверка через curl и прокси
echo "[STEP 4] Проверка доступа к Google через прокси TOR: "
curl --socks5-hostname $TOR_PROXY -s -o /dev/null -w "%{http_code}\n" https://www.google.com || echo "[Ошибка доступа]"

# Проверка порта
echo "[STEP 5] Проверка прослушивания 9050 (SOCKS5): "
if netstat -an | grep -q ':9050.*LISTEN'; then
  echo "[OK] Порт 9050 слушает (SOCKS5 активен)"
else
  echo "[FAIL] Порт 9050 не слушает — проверь torrc"
fi

# Завершение
echo "=========================="
echo "[INFO] Проверка завершена"
echo "=========================="
