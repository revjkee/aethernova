#!/usr/bin/env bash
# omnimind-core/ops/ansible/roles/omnimind-core/files/scripts/healthcheck.sh
# Универсальная проверка здоровья сервиса OmniMind Core.
# Поддерживает HTTP/TCP/systemd/PID и опционально PostgreSQL/Redis/Kafka.
# Использование:
#   healthcheck.sh --url http://127.0.0.1:8080/healthz --expect-code 200 --timeout 2 --retries 3
#   healthcheck.sh --tcp 127.0.0.1:8080
#   healthcheck.sh --systemd omnimind-core.service
#   healthcheck.sh --pidfile /run/omnimind/omnimind.pid
#   Дополнительно: --json-key status --json-expect ok  (для JSON-ответа)
# Переменные окружения (могут переопределять аргументы):
#   HC_URL, HC_EXPECT_CODE, HC_TIMEOUT, HC_RETRIES, HC_TCP, HC_SYSTEMD, HC_PIDFILE,
#   HC_JSON_KEY, HC_JSON_EXPECT, HC_SLO_MS, HC_DB_URL, HC_REDIS_URL, HC_KAFKA_BROKERS
#
# Коды выхода:
#   0 - здоров
#   1 - нездоров (функциональный сбой)
#   2 - ошибка выполнения (некорректные параметры/внутренняя ошибка)
set -Eeuo pipefail

# --------- Логирование ----------
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf "%s [%s] %s\n" "$(ts)" "$1" "$2"; }
info() { log "INFO" "$*"; }
warn() { log "WARN" "$*"; }
err() { log "ERROR" "$*" >&2; }

# --------- Параметры по умолчанию ----------
URL="${HC_URL:-}"
EXPECT_CODE="${HC_EXPECT_CODE:-200}"
TIMEOUT="${HC_TIMEOUT:-2}"
RETRIES="${HC_RETRIES:-3}"
TCP="${HC_TCP:-}"
SYSTEMD_UNIT="${HC_SYSTEMD:-}"
PIDFILE="${HC_PIDFILE:-}"
JSON_KEY="${HC_JSON_KEY:-}"
JSON_EXPECT="${HC_JSON_EXPECT:-}"
SLO_MS="${HC_SLO_MS:-0}" # 0 = не проверять SLO
DB_URL="${HC_DB_URL:-}"
REDIS_URL="${HC_REDIS_URL:-}"
KAFKA_BROKERS="${HC_KAFKA_BROKERS:-}"

CURL_BIN="${CURL_BIN:-curl}"
JQ_BIN="${JQ_BIN:-jq}"
TIME_BIN="${TIME_BIN:-/usr/bin/time}"

# --------- Парсер аргументов ----------
print_help() {
  cat <<EOF
Usage: $0 [options]
  --url <http(s)://host:port/path>   HTTP(S) эндпоинт для проверки
  --expect-code <int>                Ожидаемый HTTP-код (по умолчанию ${EXPECT_CODE})
  --timeout <sec>                    Таймаут одной попытки (по умолчанию ${TIMEOUT})
  --retries <n>                      Количество попыток (по умолчанию ${RETRIES})
  --tcp <host:port>                  TCP-проверка сокета
  --systemd <unit.service>           Проверка активного systemd-юнита
  --pidfile <path>                   Проверка существования живого PID
  --json-key <key.path>              Ключ в JSON (поддержка пути вида a.b.c)
  --json-expect <value>              Ожидаемое значение JSON-ключа
  --slo-ms <ms>                      SLO по latency (P99 одной проверки)
  --db-url <postgres://...>          Проверка подключения к PostgreSQL
  --redis-url <redis://...>          Проверка подключения к Redis
  --kafka-brokers <host:port,...>    Проверка доступности Kafka брокеров (tcp)
  -h|--help                          Печать справки
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2;;
    --expect-code) EXPECT_CODE="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    --retries) RETRIES="$2"; shift 2;;
    --tcp) TCP="$2"; shift 2;;
    --systemd) SYSTEMD_UNIT="$2"; shift 2;;
    --pidfile) PIDFILE="$2"; shift 2;;
    --json-key) JSON_KEY="$2"; shift 2;;
    --json-expect) JSON_EXPECT="$2"; shift 2;;
    --slo-ms) SLO_MS="$2"; shift 2;;
    --db-url) DB_URL="$2"; shift 2;;
    --redis-url) REDIS_URL="$2"; shift 2;;
    --kafka-brokers) KAFKA_BROKERS="$2"; shift 2;;
    -h|--help) print_help; exit 0;;
    *) err "Неизвестный аргумент: $1"; print_help; exit 2;;
  esac
done

# --------- Утилиты/проверки наличия ----------
need_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Требуется команда: $1"; exit 2; }; }
# curl нужен только для HTTP; jq — только для JSON-проверок
[[ -n "$URL" ]] && need_cmd "$CURL_BIN"
if [[ -n "$JSON_KEY" || -n "$JSON_EXPECT" ]]; then need_cmd "$JQ_BIN"; fi

# --------- Вспомогательные функции ----------
to_ms() { awk "BEGIN {printf \"%.0f\", $1 * 1000}"; }

probe_tcp() {
  local hostport="$1"
  local host="${hostport%:*}"
  local port="${hostport#*:}"
  local start end diff
  start=$(date +%s.%3N)
  # Используем bash /dev/tcp
  if (exec 3<>"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
    end=$(date +%s.%3N)
    diff=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", (e-s)}')
    echo "$diff"
    exec 3>&- 3<&- || true
    return 0
  else
    echo "FAIL"
    return 1
  fi
}

probe_http() {
  local url="$1" expect="$2" timeout="$3"
  local body_file status_file
  body_file="$(mktemp)"; status_file="$(mktemp)"
  local start end diff rc=0
  start=$(date +%s.%3N)
  if ! "$CURL_BIN" -fsS -m "$timeout" -w "%{http_code}" -o "$body_file" "$url" >"$status_file" 2>/dev/null; then
    rc=1
  fi
  end=$(date +%s.%3N)
  diff=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", (e-s)}')
  local code="000"
  if [[ -s "$status_file" ]]; then
    code="$(cat "$status_file")"
  fi
  local body="" ; body="$(cat "$body_file" 2>/dev/null || true)"
  rm -f "$body_file" "$status_file"
  echo "$rc|$code|$diff|$body"
}

json_expect_matches() {
  local body="$1" key="$2" expect="$3"
  # Поддержка пути a.b.c
  local jq_path
  jq_path=".$(echo "$key" | sed 's/\./\]\.\[/g' | sed 's/^/[/;s/$/]/' | sed 's/\[\.\]/./g;s/\[\]/./g' | sed 's/^\.\././')"
  # Если ключ простой без точек
  if [[ "$key" != *"."* ]]; then jq_path=".$key"; fi
  # Сравнение с приведением к строке
  local val
  if ! val=$(printf '%s' "$body" | "$JQ_BIN" -er "$jq_path | tostring"); then
    return 1
  fi
  [[ "$val" == "$expect" ]]
}

probe_systemd() {
  local unit="$1"
  if systemctl is-active --quiet "$unit"; then
    echo "active"; return 0
  else
    echo "inactive"; return 1
  fi
}

probe_pidfile() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  local pid; pid="$(cat "$file" 2>/dev/null || echo "")"
  [[ -n "$pid" ]] || return 1
  if kill -0 "$pid" 2>/dev/null; then
    echo "$pid"; return 0
  fi
  return 1
}

probe_postgres() {
  local url="$1"
  command -v psql >/dev/null 2>&1 || { warn "psql не найден; пропускаю PostgreSQL-проверку"; return 0; }
  PGCONNECT_TIMEOUT="${TIMEOUT}" PSQLRC=/dev/null PGPASSWORD="" psql "$url" -Atqc "SELECT 1" >/dev/null 2>&1
}

probe_redis() {
  local url="$1"
  command -v redis-cli >/dev/null 2>&1 || { warn "redis-cli не найден; пропускаю Redis-проверку"; return 0; }
  local host port db
  host="$(python3 - <<'PY' "$url"
import sys,urllib.parse as u
p=u.urlparse(sys.argv[1]); print(p.hostname or '127.0.0.1')
PY
)"
  port="$(python3 - <<'PY' "$url"
import sys,urllib.parse as u
p=u.urlparse(sys.argv[1]); print(p.port or 6379)
PY
)"
  redis-cli -h "$host" -p "$port" PING >/dev/null 2>&1
}

probe_kafka() {
  local brokers_csv="$1" any_ok=1
  IFS=',' read -r -a brokers <<<"$brokers_csv"
  for b in "${brokers[@]}"; do
    if [[ -z "$b" ]]; then continue; fi
    if [[ "$(probe_tcp "$b")" != "FAIL" ]]; then any_ok=0; fi
  done
  return $any_ok
}

# --------- Основная логика с ретраями ----------
overall_rc=0
lat_ms=()
attempt=1
while (( attempt <= RETRIES )); do
  info "Попытка ${attempt}/${RETRIES}"

  # TCP
  if [[ -n "$TCP" ]]; then
    tcp_res="$(probe_tcp "$TCP")" || { warn "TCP ${TCP} недоступен"; overall_rc=1; }
    if [[ "$tcp_res" != "FAIL" ]]; then
      ms=$(to_ms "$tcp_res"); lat_ms+=("$ms"); info "TCP ${TCP} ok ${ms}ms"
    fi
  fi

  # HTTP
  if [[ -n "$URL" ]]; then
    res="$(probe_http "$URL" "$EXPECT_CODE" "$TIMEOUT")"
    rc="${res%%|*}"; rest="${res#*|}"
    code="${rest%%|*}"; rest="${rest#*|}"
    diff="${rest%%|*}"; body="${rest#*|}"
    ms=$(to_ms "$diff"); lat_ms+=("$ms")
    if [[ "$rc" -eq 0 && "$code" == "$EXPECT_CODE" ]]; then
      info "HTTP ${URL} code=${code} latency=${ms}ms"
      # JSON ожидание (если задано)
      if [[ -n "$JSON_KEY" || -n "$JSON_EXPECT" ]]; then
        if json_expect_matches "$body" "$JSON_KEY" "$JSON_EXPECT"; then
          info "JSON ${JSON_KEY} == ${JSON_EXPECT}"
        else
          warn "JSON ожидание не выполнено: ${JSON_KEY} != ${JSON_EXPECT}"
          overall_rc=1
        fi
      fi
    else
      warn "HTTP сбой: code=${code} rc=${rc} latency=${ms}ms"
      overall_rc=1
    fi
  fi

  # systemd
  if [[ -n "$SYSTEMD_UNIT" ]]; then
    if [[ "$(probe_systemd "$SYSTEMD_UNIT")" == "active" ]]; then
      info "systemd ${SYSTEMD_UNIT} active"
    else
      warn "systemd ${SYSTEMD_UNIT} inactive"
      overall_rc=1
    fi
  fi

  # PID
  if [[ -n "$PIDFILE" ]]; then
    if pid="$(probe_pidfile "$PIDFILE")"; then
      info "PID ${pid} жив"
    else
      warn "PID-файл отсутствует или процесс мертв"
      overall_rc=1
    fi
  fi

  # PostgreSQL
  if [[ -n "$DB_URL" ]]; then
    if probe_postgres "$DB_URL"; then
      info "PostgreSQL доступен"
    else
      warn "PostgreSQL недоступен"
      overall_rc=1
    fi
  fi

  # Redis
  if [[ -n "$REDIS_URL" ]]; then
    if probe_redis "$REDIS_URL"; then
      info "Redis доступен"
    else
      warn "Redis недоступен"
      overall_rc=1
    fi
  fi

  # Kafka
  if [[ -n "$KAFKA_BROKERS" ]]; then
    if probe_kafka "$KAFKA_BROKERS"; then
      info "Kafka брокеры доступны"
    else
      warn "Kafka брокеры недоступны"
      overall_rc=1
    fi
  fi

  # Если все проверки прошли — выходим досрочно
  if [[ $overall_rc -eq 0 ]]; then break; fi

  # Иначе пробуем снова
  attempt=$((attempt+1))
  sleep 1
  # Сброс статуса между попытками
  overall_rc=0
done

# --------- Проверка SLO по latency (если задано) ----------
if (( SLO_MS > 0 )) && (( ${#lat_ms[@]} > 0 )); then
  # Берем худшее наблюдение в попытках как приближение P~max
  worst=0
  for v in "${lat_ms[@]}"; do
    (( v > worst )) && worst="$v"
  done
  if (( worst > SLO_MS )); then
    warn "Нарушен SLO latency: ${worst}ms > ${SLO_MS}ms"
    overall_rc=1
  else
    info "SLO latency соблюден: Pworst=${worst}ms <= ${SLO_MS}ms"
  fi
fi

# --------- Итоговый JSON-отчет на stdout (одной строкой) ----------
status_str=$([ $overall_rc -eq 0 ] && echo "healthy" || echo "unhealthy")
lat_join="$(printf "%s," "${lat_ms[@]}" | sed 's/,$//')"
printf '{"timestamp":"%s","status":"%s","url":"%s","tcp":"%s","systemd":"%s","pidfile":"%s","retries":%s,"timeout_sec":%s,"latency_ms":[%s]}\n' \
  "$(ts)" "$status_str" "${URL:-}" "${TCP:-}" "${SYSTEMD_UNIT:-}" "${PIDFILE:-}" "$RETRIES" "$TIMEOUT" "${lat_join}"

# --------- Выход ---------
if [[ "$status_str" == "healthy" ]]; then
  exit 0
else
  exit 1
fi
