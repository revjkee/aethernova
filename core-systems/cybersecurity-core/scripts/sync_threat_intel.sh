#!/usr/bin/env bash
# sync_threat_intel.sh — промышленный конвейер синхронизации Threat Intelligence
# Особенности:
#  - Безопасные опции: set -Eeuo pipefail, строгий IFS, trap
#  - Один экземпляр: файловая блокировка (flock)
#  - Конфигурация: YAML (yq) или JSON (jq)
#  - Надёжная загрузка: timeout, retries, proxy, TLS verify/insecure
#  - Опциональная проверка подписи: gpg/cosign (keyless)
#  - Нормализация IOC: IP, Domain, URL, Hash (MD5/SHA1/SHA256)
#  - Дедупликация и дельты; ротация артефактов; JSON-сводка
# Зависимости: bash (4+), curl, jq, awk, sed, grep, sort, uniq, sha256sum, flock
# Опционально: yq (для YAML-конфига), gpg/gpgv (gpg-verify), cosign (keyless)

set -Eeuo pipefail
IFS=$'\n\t'

# --------- Константы по умолчанию ---------
SCRIPT_NAME="$(basename "$0")"
WORKSPACE="${WORKSPACE:-$(pwd)}"
OUT_DIR="${OUT_DIR:-${WORKSPACE}/out/ti}"
STATE_DIR="${STATE_DIR:-${WORKSPACE}/state/ti}"
LOG_DIR="${LOG_DIR:-${WORKSPACE}/logs}"
CONFIG_PATH="${CONFIG_PATH:-${WORKSPACE}/config/threat_feeds.yaml}"   # YAML по умолчанию
TIMEOUT="${TIMEOUT:-30}"
RETRIES="${RETRIES:-3}"
RETRY_DELAY="${RETRY_DELAY:-2}"
CONCURRENCY="${CONCURRENCY:-4}"
PROXY="${PROXY:-}"              # пример: http://user:pass@proxy:8080
INSECURE_TLS="${INSECURE_TLS:-false}"
ROTATE_KEEP="${ROTATE_KEEP:-5}"
SIG_VERIFY="${SIG_VERIFY:-none}"  # none|gpg|cosign
GPG_KEYRING="${GPG_KEYRING:-}"    # путь к keyring при SIG_VERIFY=gpg
LOG_FORMAT="${LOG_FORMAT:-text}"  # text|json
LOCK_DIR="${STATE_DIR}/locks"
LOCK_FILE="${LOCK_DIR}/sync_threat_intel.lock"
TMP_ROOT="$(mktemp -d -t ti_sync.XXXXXXXX)"
DATE_TAG="$(date -u +"%Y%m%dT%H%M%SZ")"

# --------- Утилиты логирования ---------
log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  mkdir -p "${LOG_DIR}"
  if [[ "${LOG_FORMAT}" == "json" ]]; then
    printf '{"ts":"%s","level":"%s","msg":"%s"}\n' "$ts" "$level" "$(echo "$msg" | sed 's/"/\\"/g')" | tee -a "${LOG_DIR}/${SCRIPT_NAME%.sh}.log" 1>&2
  else
    printf "%s [%s] %s\n" "$ts" "$level" "$msg" | tee -a "${LOG_DIR}/${SCRIPT_NAME%.sh}.log" 1>&2
  fi
}
info() { log "INFO" "$*"; }
warn() { log "WARN" "$*"; }
err()  { log "ERROR" "$*"; }

cleanup() {
  local ec=$?
  rm -rf "${TMP_ROOT}" || true
  exit "${ec}"
}
trap cleanup EXIT INT TERM

# --------- Проверки окружения ---------
need() {
  command -v "$1" >/dev/null 2>&1 || { err "Не найдена зависимость: $1"; exit 127; }
}

need curl
need jq
need awk
need sed
need grep
need sort
need uniq
need sha256sum
need flock

# yq опционально (для YAML)
has_yq=true
if ! command -v yq >/dev/null 2>&1; then
  has_yq=false
fi

# gpg/cosign опционально
if [[ "${SIG_VERIFY}" == "gpg" ]]; then
  need gpg
  need gpgv
fi
if [[ "${SIG_VERIFY}" == "cosign" ]]; then
  command -v cosign >/dev/null 2>&1 || warn "cosign не найден; подпись будет пропущена"
fi

# --------- Парсер аргументов ---------
usage() {
  cat <<EOF
${SCRIPT_NAME} — синхронизация Threat Intel

Параметры (env или флаги):
  --config PATH            Путь к конфигу (YAML/JSON). [${CONFIG_PATH}]
  --out-dir PATH           Каталог артефактов.        [${OUT_DIR}]
  --state-dir PATH         Каталог состояния.         [${STATE_DIR}]
  --timeout SEC            Таймаут curl.              [${TIMEOUT}]
  --retries N              Повторы curl.              [${RETRIES}]
  --retry-delay SEC        Задержка между повторами.  [${RETRY_DELAY}]
  --concurrency N          Параллелизм загрузок.      [${CONCURRENCY}]
  --proxy URL              Прокси (http/https/socks).
  --insecure               Не проверять TLS сертификат.
  --rotate KEEP            Кол-во версий для ротации. [${ROTATE_KEEP}]
  --sig-verify MODE        Подпись: none|gpg|cosign.  [${SIG_VERIFY}]
  --gpg-keyring PATH       Keyring для GPG.
  --json-logs              Формат логов JSON.
  -h|--help                Справка.

Выходы:
  - ${OUT_DIR}/indicators/{ips,domains,urls,hashes}.txt
  - ${OUT_DIR}/feeds/<name>/{raw,normalized}.txt
  - ${OUT_DIR}/summary-${DATE_TAG}.json
  - ${STATE_DIR}/deltas/<type>-{added,removed}.txt

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_PATH="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    --state-dir) STATE_DIR="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    --retries) RETRIES="$2"; shift 2;;
    --retry-delay) RETRY_DELAY="$2"; shift 2;;
    --concurrency) CONCURRENCY="$2"; shift 2;;
    --proxy) PROXY="$2"; shift 2;;
    --insecure) INSECURE_TLS="true"; shift 1;;
    --rotate) ROTATE_KEEP="$2"; shift 2;;
    --sig-verify) SIG_VERIFY="$2"; shift 2;;
    --gpg-keyring) GPG_KEYRING="$2"; shift 2;;
    --json-logs) LOG_FORMAT="json"; shift 1;;
    -h|--help) usage; exit 0;;
    *) err "Неизвестный аргумент: $1"; usage; exit 2;;
  esac
done

mkdir -p "${OUT_DIR}/feeds" "${OUT_DIR}/indicators" "${STATE_DIR}/deltas" "${LOCK_DIR}"

# --------- Блокировка одиночного запуска ---------
exec {LOCK_FD}>"${LOCK_FILE}"
if ! flock -n "${LOCK_FD}"; then
  err "Уже выполняется другой экземпляр (${LOCK_FILE})."
  exit 1
fi

# --------- Загрузка конфигурации фидов ---------
# Схема (YAML/JSON):
# feeds:
#   - name: myfeed
#     url: "https://example.com/feeds/list.txt"
#     type: "txt|csv|json|stix2|auto"
#     json_jq: ".indicators[]"
#     csv_column: 1
#     signature_url: "https://example.com/feeds/list.txt.sig"   # опционально
#     auth:
#       header: "Authorization: Bearer \$TOKEN"
#     tags: ["ip","domain","url","hash"]  # опционально, подсказка
#
# Примечание: если YAML — нужен yq; если JSON — jq.

FEEDS_TSV="${TMP_ROOT}/feeds.tsv"
touch "${FEEDS_TSV}"

load_config_yaml() {
  yq -r '.feeds[] | [.name, .url, (.type // "auto"), (.json_jq // ""), ( .csv_column // "" ), (.signature_url // ""), (.auth.header // ""), ((.tags // []) | join(","))] | @tsv' \
    "${CONFIG_PATH}" >> "${FEEDS_TSV}"
}

load_config_json() {
  jq -r '.feeds[] | [ .name, .url, (.type // "auto"), (.json_jq // ""), (.csv_column // ""), (.signature_url // ""), (.auth.header // ""), ((.tags // []) | join(",")) ] | @tsv' \
    "${CONFIG_PATH}" >> "${FEEDS_TSV}"
}

if [[ -f "${CONFIG_PATH}" ]]; then
  case "${CONFIG_PATH}" in
    *.yaml|*.yml)
      if [[ "${has_yq}" == "true" ]]; then
        info "Загрузка конфигурации (YAML): ${CONFIG_PATH}"
        load_config_yaml
      else
        err "yq отсутствует, а конфиг в YAML: ${CONFIG_PATH}"
        exit 2
      fi
      ;;
    *.json)
      info "Загрузка конфигурации (JSON): ${CONFIG_PATH}"
      load_config_json
      ;;
    *)
      # Попытка auto: сначала yq, затем jq
      if [[ "${has_yq}" == "true" ]]; then
        info "Попытка прочитать как YAML: ${CONFIG_PATH}"
        if load_config_yaml 2>/dev/null; then :; else err "Не удалось распарсить YAML"; exit 2; fi
      else
        info "Попытка прочитать как JSON: ${CONFIG_PATH}"
        if load_config_json 2>/dev/null; then :; else err "Не удалось распарсить JSON"; exit 2; fi
      fi
      ;;
  esac
else
  warn "Конфиг не найден: ${CONFIG_PATH}. Будет сгенерирован шаблон."
  mkdir -p "$(dirname "${CONFIG_PATH}")"
  cat > "${CONFIG_PATH}" <<'YAML'
feeds:
  - name: example_txt
    url: "https://example.invalid/ti/indicators.txt"
    type: "txt"
    tags: ["ip","domain","url","hash"]
  - name: example_json
    url: "https://example.invalid/ti/indicators.json"
    type: "json"
    json_jq: ".indicators[].value"
YAML
  if [[ "${has_yq}" == "true" ]]; then load_config_yaml; else load_config_json; fi || true
fi

if [[ ! -s "${FEEDS_TSV}" ]]; then
  err "Нет валидных фидов в конфигурации."
  exit 3
fi

# --------- Утилиты извлечения индикаторов ---------
# Классификация IOC по шаблонам
is_ipv4()   { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_domain() { [[ "$1" =~ ^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$ ]]; }
is_url()    { [[ "$1" =~ ^https?://[[:graph:]]+$ ]]; }
is_md5()    { [[ "$1" =~ ^[A-Fa-f0-9]{32}$ ]]; }
is_sha1()   { [[ "$1" =~ ^[A-Fa-f0-9]{40}$ ]]; }
is_sha256() { [[ "$1" =~ ^[A-Fa-f0-9]{64}$ ]]; }

normalize_line() {
  # Удаление комментариев и пробелов, перевод в нижний регистр
  sed -E 's/[[:space:]]+#.*$//; s/^#.*$//; s/\r$//' | awk 'length>0' | tr '[:upper:]' '[:lower:]'
}

extract_from_txt() {
  cat "$1" | normalize_line
}

extract_from_csv() {
  local file="$1" col="$2"
  awk -F',' -v c="${col}" 'NR>1 {print $c}' "$file" | normalize_line
}

extract_from_json() {
  local file="$1" jqpath="$2"
  if [[ -z "${jqpath}" ]]; then
    warn "json_jq не задан; пропуск JSON-фида"
    return 0
  fi
  jq -r "${jqpath}" "$file" | normalize_line
}

extract_from_stix2() {
  # Наивный парсер STIX2 индикаторов (pattern), извлекает значения из выражений вида:
  # [domain-name:value = 'example.com'] OR [ipv4-addr:value = '1.2.3.4']
  local file="$1"
  jq -r '.objects[]? | select(.type=="indicator") | .pattern' "$file" 2>/dev/null \
    | sed -E "s/\\[/?/g; s/\\]/?/g" \
    | grep -Eo "'[^']+'" \
    | sed "s/'//g" \
    | normalize_line
}

classify_and_append() {
  local in_file="$1"
  local ips="${TMP_ROOT}/ips.txt"
  local domains="${TMP_ROOT}/domains.txt"
  local urls="${TMP_ROOT}/urls.txt"
  local hashes="${TMP_ROOT}/hashes.txt"
  touch "${ips}" "${domains}" "${urls}" "${hashes}"

  while IFS= read -r ioc; do
    [[ -z "${ioc}" ]] && continue
    if is_ipv4 "${ioc}"; then
      echo "${ioc}" >> "${ips}"
    elif is_url "${ioc}"; then
      echo "${ioc}" >> "${urls}"
    elif is_domain "${ioc}"; then
      echo "${ioc}" >> "${domains}"
    elif is_md5 "${ioc}" || is_sha1 "${ioc}" || is_sha256 "${ioc}"; then
      echo "${ioc}" >> "${hashes}"
    fi
  done < "${in_file}"
}

dedup_sort() {
  local src="$1" dst="$2"
  if [[ -s "${src}" ]]; then
    sort -u "${src}" > "${dst}"
  else
    : > "${dst}"
  fi
}

rotate_keep() {
  local file="$1"
  local keep="${2:-$ROTATE_KEEP}"
  local base="$(basename "${file}")"
  local dir="$(dirname "${file}")"
  mkdir -p "${dir}/.archive"
  if [[ -f "${file}" ]]; then
    cp -f "${file}" "${dir}/.archive/${base}.${DATE_TAG}" || true
  fi
  # удалить старые
  ls -1t "${dir}/.archive/${base}."* 2>/dev/null | awk "NR>${keep}" | xargs -r rm -f
}

write_delta() {
  local new_file="$1" state_name="$2"
  local prev="${STATE_DIR}/snapshots/${state_name}.txt"
  mkdir -p "${STATE_DIR}/snapshots" "${STATE_DIR}/deltas"

  : > "${STATE_DIR}/deltas/${state_name}-added.txt"
  : > "${STATE_DIR}/deltas/${state_name}-removed.txt"

  if [[ -f "${prev}" ]]; then
    comm -13 <(sort -u "${prev}") <(sort -u "${new_file}") > "${STATE_DIR}/deltas/${state_name}-added.txt"
    comm -23 <(sort -u "${prev}") <(sort -u "${new_file}") > "${STATE_DIR}/deltas/${state_name}-removed.txt"
  else
    sort -u "${new_file}" > "${STATE_DIR}/deltas/${state_name}-added.txt"
    : > "${STATE_DIR}/deltas/${state_name}-removed.txt"
  fi
  cp -f "${new_file}" "${prev}"
}

# --------- Загрузка и проверка подписи ---------
curl_common_args=(
  --fail-with-body
  --location
  --connect-timeout "${TIMEOUT}"
  --max-time "$(( TIMEOUT * (RETRIES + 1) ))"
  --retry "${RETRIES}"
  --retry-all-errors
  --retry-delay "${RETRY_DELAY}"
  --no-buffer
  --silent
  --show-error
)

if [[ -n "${PROXY}" ]]; then
  curl_common_args+=( --proxy "${PROXY}" )
fi
if [[ "${INSECURE_TLS}" == "true" ]]; then
  curl_common_args+=( -k )
fi

fetch_feed() {
  local name="$1" url="$2" ftype="$3" json_jq="$4" csv_col="$5" sig_url="$6" auth_header="$7"
  local feed_dir="${OUT_DIR}/feeds/${name}"
  mkdir -p "${feed_dir}"
  local raw="${feed_dir}/raw-${DATE_TAG}.txt"
  local normalized="${feed_dir}/normalized-${DATE_TAG}.txt"
  local tmp_raw="${TMP_ROOT}/${name}.raw"
  local tmp_norm="${TMP_ROOT}/${name}.norm"
  local curl_args=("${curl_common_args[@]}")
  if [[ -n "${auth_header}" && "${auth_header}" != "null" ]]; then
    curl_args+=( -H "${auth_header}" )
  fi

  info "Загрузка фида: ${name} (${url})"
  if ! curl "${curl_args[@]}" -o "${tmp_raw}" "${url}"; then
    err "Ошибка загрузки: ${name}"
    return 1
  fi

  # Подпись (опционально)
  if [[ -n "${sig_url}" && "${sig_url}" != "null" ]]; then
    info "Загрузка подписи для ${name}: ${sig_url}"
    local sig_file="${TMP_ROOT}/${name}.sig"
    if curl "${curl_args[@]}" -o "${sig_file}" "${sig_url}"; then
      case "${SIG_VERIFY}" in
        gpg)
          if [[ -n "${GPG_KEYRING}" ]]; then
            gpgv --keyring "${GPG_KEYRING}" "${sig_file}" "${tmp_raw}" && info "GPG проверка успешна: ${name}" || warn "GPG проверка не прошла: ${name}"
          else
            warn "GPG keyring не задан; пропуск проверки для ${name}"
          fi
          ;;
        cosign)
          if command -v cosign >/dev/null 2>&1; then
            # Ожидаем sig-файл как detached sig PEM или DSSE — это сильно зависит от поставщика.
            # В промышленности стоит согласовать формат. Здесь только уведомление.
            warn "Проверка cosign для произвольного .sig требует согласования формата; пропуск для ${name}"
          else
            warn "cosign отсутствует; пропуск проверки для ${name}"
          fi
          ;;
        none|*)
          ;;
      esac
    else
      warn "Не удалось загрузить подпись для ${name}; продолжаем без проверки"
    fi
  fi

  # Преобразование → нормализация
  case "${ftype}" in
    txt|auto)
      extract_from_txt "${tmp_raw}" > "${tmp_norm}" || true
      ;;
    csv)
      local col="${csv_col:-1}"
      extract_from_csv "${tmp_raw}" "${col}" > "${tmp_norm}" || true
      ;;
    json)
      extract_from_json "${tmp_raw}" "${json_jq}" > "${tmp_norm}" || true
      ;;
    stix2)
      extract_from_stix2 "${tmp_raw}" > "${tmp_norm}" || true
      ;;
    *)
      warn "Неизвестный тип фида '${ftype}' для ${name}; будет попытка auto (txt)"
      extract_from_txt "${tmp_raw}" > "${tmp_norm}" || true
      ;;
  esac

  # Сохранить сырой и нормализованный
  rotate_keep "${raw}"
  rotate_keep "${normalized}"
  cp -f "${tmp_raw}" "${raw}"
  cp -f "${tmp_norm}" "${normalized}"

  # Добавить в общий пуул для классификации
  classify_and_append "${tmp_norm}"
  info "Готово: ${name}"
}

# --------- Параллельная обработка фидов ---------
export -f fetch_feed log info warn err normalize_line extract_from_txt extract_from_csv extract_from_json extract_from_stix2 classify_and_append rotate_keep
export TMP_ROOT OUT_DIR DATE_TAG SIG_VERIFY GPG_KEYRING
export -f is_ipv4 is_domain is_url is_md5 is_sha1 is_sha256
export -f dedup_sort write_delta
export curl_common_args PROXY INSECURE_TLS

# xargs параллелит по строкам TSV
# Колонки: 1=name 2=url 3=type 4=json_jq 5=csv_column 6=sig_url 7=auth_header 8=tags
cat "${FEEDS_TSV}" | awk 'NF>=2' | xargs -0 -I{} -0 bash -c 'true' 2>/dev/null || true # no-op для совместимости с -0
# Безопасный разбор TSV в bash:
while IFS=$'\t' read -r name url ftype json_jq csv_col sig_url auth_header tags; do
  # Запуск с ограничением по параллелизму через семафор
  while (( $(jobs -rp | wc -l) >= CONCURRENCY )); do sleep 0.2; done
  fetch_feed "${name}" "${url}" "${ftype:-auto}" "${json_jq:-}" "${csv_col:-1}" "${sig_url:-}" "${auth_header:-}" &
done < "${FEEDS_TSV}"

wait || true

# --------- Сборка агрегированных индикаторов ---------
TMP_IPS="${TMP_ROOT}/ips.txt"
TMP_DOMAINS="${TMP_ROOT}/domains.txt"
TMP_URLS="${TMP_ROOT}/urls.txt"
TMP_HASHES="${TMP_ROOT}/hashes.txt"

AGG_IPS="${OUT_DIR}/indicators/ips.txt"
AGG_DOMAINS="${OUT_DIR}/indicators/domains.txt"
AGG_URLS="${OUT_DIR}/indicators/urls.txt"
AGG_HASHES="${OUT_DIR}/indicators/hashes.txt"

mkdir -p "${OUT_DIR}/indicators"
rotate_keep "${AGG_IPS}"
rotate_keep "${AGG_DOMAINS}"
rotate_keep "${AGG_URLS}"
rotate_keep "${AGG_HASHES}"

dedup_sort "${TMP_IPS}"     "${AGG_IPS}"
dedup_sort "${TMP_DOMAINS}" "${AGG_DOMAINS}"
dedup_sort "${TMP_URLS}"    "${AGG_URLS}"
dedup_sort "${TMP_HASHES}"  "${AGG_HASHES}"

# --------- Дельты и сводка ---------
write_delta "${AGG_IPS}"     "ips"
write_delta "${AGG_DOMAINS}" "domains"
write_delta "${AGG_URLS}"    "urls"
write_delta "${AGG_HASHES}"  "hashes"

SUMMARY="${OUT_DIR}/summary-${DATE_TAG}.json"
jq -n --arg ts "${DATE_TAG}" \
  --arg ips_count "$(wc -l < "${AGG_IPS}"     2>/dev/null | tr -d ' ')" \
  --arg dom_count "$(wc -l < "${AGG_DOMAINS}" 2>/dev/null | tr -d ' ')" \
  --arg url_count "$(wc -l < "${AGG_URLS}"    2>/dev/null | tr -d ' ')" \
  --arg hsh_count "$(wc -l < "${AGG_HASHES}"  2>/dev/null | tr -d ' ')" \
  --arg added_ips "$(wc -l < "${STATE_DIR}/deltas/ips-added.txt"       2>/dev/null | tr -d ' ')" \
  --arg rm_ips    "$(wc -l < "${STATE_DIR}/deltas/ips-removed.txt"     2>/dev/null | tr -d ' ')" \
  --arg added_dom "$(wc -l < "${STATE_DIR}/deltas/domains-added.txt"   2>/dev/null | tr -d ' ')" \
  --arg rm_dom    "$(wc -l < "${STATE_DIR}/deltas/domains-removed.txt" 2>/dev/null | tr -d ' ')" \
  --arg added_url "$(wc -l < "${STATE_DIR}/deltas/urls-added.txt"      2>/dev/null | tr -d ' ')" \
  --arg rm_url    "$(wc -l < "${STATE_DIR}/deltas/urls-removed.txt"    2>/dev/null | tr -d ' ')" \
  --arg added_hsh "$(wc -l < "${STATE_DIR}/deltas/hashes-added.txt"    2>/dev/null | tr -d ' ')" \
  --arg rm_hsh    "$(wc -l < "${STATE_DIR}/deltas/hashes-removed.txt"  2>/dev/null | tr -d ' ')" \
  '{
     timestamp: $ts,
     totals: { ips: ($ips_count|tonumber), domains: ($dom_count|tonumber), urls: ($url_count|tonumber), hashes: ($hsh_count|tonumber) },
     deltas: {
       ips:     { added: ($added_ips|tonumber), removed: ($rm_ips|tonumber) },
       domains: { added: ($added_dom|tonumber), removed: ($rm_dom|tonumber) },
       urls:    { added: ($added_url|tonumber), removed: ($rm_url|tonumber) },
       hashes:  { added: ($added_hsh|tonumber), removed: ($rm_hsh|tonumber) }
     },
     artifacts: {
       indicators: {
         ips:     "'"${AGG_IPS}"'",
         domains: "'"${AGG_DOMAINS}"'",
         urls:    "'"${AGG_URLS}"'",
         hashes:  "'"${AGG_HASHES}"'"
       }
     }
   }' > "${SUMMARY}"

# Контрольные суммы агрегатов и summary
(
  cd "${OUT_DIR}"
  sha256sum "indicators/ips.txt" \
            "indicators/domains.txt" \
            "indicators/urls.txt" \
            "indicators/hashes.txt" \
            "$(basename "${SUMMARY}")" \
            > "sha256sum-${DATE_TAG}.txt"
)

info "Синхронизация завершена. Сводка: ${SUMMARY}"
