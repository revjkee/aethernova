#!/usr/bin/env bash
# datafabric-core / scripts / sbom.sh
# Генерация SBOM (SPDX & CycloneDX) для исходников или Docker-образа.
# Особенности:
#  - Скан system-пакетов и файлов: Syft;
#  - Python deps: CycloneDX-Python (fallback: pip freeze);
#  - Node deps: CycloneDX-Node (fallback: package-lock.json через Syft);
#  - Итоговая агрегация: сохраняем отдельные SBOM-артефакты, checksum.txt, сводку summary.txt;
#  - Опциональная подпись cosign и базовый аудит grype.
#
# Требования (хотя бы часть):
#  - syft (обязательно для системного/образного слоя)
#  - grype (опционально, --audit)
#  - cosign (опционально, --sign)
#  - python3 + cyclonedx-bom (pip install cyclonedx-bom) (опционально)
#  - node + @cyclonedx/cyclonedx-npm (npm i -g @cyclonedx/cyclonedx-npm) (опционально)

set -Eeuo pipefail
IFS=$'\n\t'

# ------------------------------
# Цвета/логирование
# ------------------------------
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_RESET='\033[0m'

log()  { printf "${COLOR_BLUE}[sbom]${COLOR_RESET} %s\n" "$*"; }
ok()   { printf "${COLOR_GREEN}[ ok ]${COLOR_RESET} %s\n" "$*"; }
warn() { printf "${COLOR_YELLOW}[warn]${COLOR_RESET} %s\n" "$*"; }
err()  { printf "${COLOR_RED}[fail]${COLOR_RESET} %s\n" "$*" 1>&2; }
die()  { err "$*"; exit 1; }

trap 'err "Ошибка на строке $LINENO"; exit 2' ERR

# ------------------------------
# Утилиты
# ------------------------------
need() { command -v "$1" >/dev/null 2>&1 || die "Требуется инструмент: $1"; }

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
sha256() { command -v shasum >/dev/null 2>&1 && shasum -a 256 "$@" | awk '{print $1}' || sha256sum "$@" | awk '{print $1}'; }

json_pretty() {
  if command -v jq >/dev/null 2>&1; then jq -S .; else cat; fi
}

# ------------------------------
# Параметры CLI
# ------------------------------
SOURCE_TYPE="dir"         # dir|image
SOURCE_PATH="."
OUT_DIR="sbom-out"
PROJ_NAME="${PROJ_NAME:-datafabric-core}"
PROJ_VERSION="${PROJ_VERSION:-0.0.0-dev}"
DO_AUDIT=0
DO_SIGN=0
TIMEOUT="${TIMEOUT:-600}" # сек

usage() {
cat <<EOF
Usage: $0 [--dir PATH | --image NAME[:TAG]] [--out DIR] [--name NAME] [--version VER]
          [--audit] [--sign] [--timeout SEC] [--help]

  --dir PATH         Источник — директория (по умолчанию: .)
  --image NAME[:TAG] Источник — Docker/OCI образ (локально доступен)
  --out DIR          Каталог вывода (по умолчанию: sbom-out)
  --name NAME        Имя проекта / субъекта SBOM (default: ${PROJ_NAME})
  --version VER      Версия проекта / субъекта SBOM (default: ${PROJ_VERSION})
  --audit            Запуск grype для базового аудита уязвимостей
  --sign             Подписать все артефакты cosign-ом (OIDC, keyless)
  --timeout SEC      Таймаут операций (default: ${TIMEOUT})
  --help             Показать справку
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)   SOURCE_TYPE="dir"; SOURCE_PATH="${2:?}"; shift 2 ;;
    --image) SOURCE_TYPE="image"; SOURCE_PATH="${2:?}"; shift 2 ;;
    --out)   OUT_DIR="${2:?}"; shift 2 ;;
    --name)  PROJ_NAME="${2:?}"; shift 2 ;;
    --version) PROJ_VERSION="${2:?}"; shift 2 ;;
    --audit) DO_AUDIT=1; shift ;;
    --sign)  DO_SIGN=1; shift ;;
    --timeout) TIMEOUT="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Неизвестный аргумент: $1" ;;
  esac
done

# ------------------------------
# Проверки инструментов
# ------------------------------
need syft
if (( DO_AUDIT == 1 )); then
  if ! command -v grype >/dev/null 2>&1; then
    warn "grype не найден — аудит будет пропущен"
    DO_AUDIT=0
  fi
fi
if (( DO_SIGN == 1 )); then
  need cosign
fi

# Доп. инструменты (опциональные)
HAVE_PY=0; HAVE_CDXPY=0
if command -v python3 >/dev/null 2>&1; then
  HAVE_PY=1
  if python3 -c "import cyclonedx_bom" 2>/dev/null; then HAVE_CDXPY=1; fi
fi

HAVE_NODE=0; HAVE_CDXNPM=0
if command -v node >/dev/null 2>&1; then
  HAVE_NODE=1
  if command -v cyclonedx-npm >/dev/null 2>&1; then HAVE_CDXNPM=1; fi
fi

# ------------------------------
# Каталоги/маркеры
# ------------------------------
mkdir -p "${OUT_DIR}"
RUN_ID="$(timestamp)"
SUMMARY="${OUT_DIR}/summary.txt"
CHECKSUMS="${OUT_DIR}/checksums.sha256"

# Очистка прошлых сумм (идемпотентно)
: > "${CHECKSUMS}"
: > "${SUMMARY}"

# ------------------------------
# Помощники генерации
# ------------------------------
gen_syft_dir() {
  local path="$1"
  local out_spdx="$2"
  local out_cdx="$3"
  log "Syft scan directory: ${path}"
  # SPDX
  syft dir:"${path}" --output spdx-json > "${out_spdx}"
  # CycloneDX
  syft dir:"${path}" --output cyclonedx-json > "${out_cdx}"
}

gen_syft_image() {
  local image="$1"
  local out_spdx="$2"
  local out_cdx="$3"
  log "Syft scan image: ${image}"
  syft "registry:${image}" --output spdx-json > "${out_spdx}" || syft "image:${image}" --output spdx-json > "${out_spdx}"
  syft "registry:${image}" --output cyclonedx-json > "${out_cdx}" || syft "image:${image}"  --output cyclonedx-json > "${out_cdx}"
}

gen_cyclonedx_python() {
  local root="$1"
  local out_cdx="$2"
  if (( HAVE_PY == 1 && HAVE_CDXPY == 1 )); then
    log "CycloneDX-Python (poetry/pip/req) по корню: ${root}"
    ( cd "${root}" && python3 -m cyclonedx_bom -o "${out_cdx}" ) || warn "CycloneDX-Python: не удалось сгенерировать SBOM"
  else
    warn "CycloneDX-Python недоступен — пропуск детального Python SBOM"
  fi
}

gen_cyclonedx_npm() {
  local root="$1"
  local out_cdx="$2"
  if (( HAVE_NODE == 1 && HAVE_CDXNPM == 1 )); then
    log "CycloneDX-Node (npm/yarn/pnpm) по корню: ${root}"
    ( cd "${root}" && cyclonedx-npm --output-format json --output-file "${out_cdx}" ) || warn "CycloneDX-NPM: не удалось сгенерировать SBOM"
  else
    warn "CycloneDX-NPM недоступен — пропуск детального Node SBOM"
  fi
}

add_checksum() {
  local f="$1"
  if [[ -f "$f" ]]; then
    sha256 "$f" >> "${CHECKSUMS}"
  fi
}

sign_artifacts() {
  if (( DO_SIGN == 1 )); then
    log "Подпись артефактов cosign (keyless OIDC)"
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      cosign sign-blob --yes --output-signature "${f}.sig" --output-certificate "${f}.crt" "$f" >/dev/null
      ok "signed: $(basename "$f")"
    done < <(find "${OUT_DIR}" -maxdepth 1 -type f \( -name "*.json" -o -name "*.spdx.json" -o -name "*.cdx.json" \))
  fi
}

audit_with_grype() {
  local target="$1"
  local report="${OUT_DIR}/grype-${SOURCE_TYPE}.txt"
  if (( DO_AUDIT == 1 )); then
    log "Аудит уязвимостей grype: ${target}"
    if [[ "${SOURCE_TYPE}" == "image" ]]; then
      grype "${target}" --by-cve --only-fixed=false --fail-on medium --add-cpes-if-none > "${report}" || true
    else
      # Для директорий grype поддерживает sbom ввод
      local sbom_cdx="${OUT_DIR}/sbom-syft.cdx.json"
      if [[ -f "${sbom_cdx}" ]]; then
        grype sbom:"${sbom_cdx}" --by-cve --only-fixed=false --fail-on medium --add-cpes-if-none > "${report}" || true
      else
        warn "Не найден CycloneDX из Syft — пропуск grype для директории"
      fi
    fi
    add_checksum "${report}"
  fi
}

# ------------------------------
# Основной сценарий
# ------------------------------
log "Старт SBOM | subject=${PROJ_NAME}@${PROJ_VERSION} | source=${SOURCE_TYPE}:${SOURCE_PATH} | out=${OUT_DIR}"

# Базовые имена файлов
SPDX_SYFT="${OUT_DIR}/sbom-syft.spdx.json"
CDX_SYFT="${OUT_DIR}/sbom-syft.cdx.json"
CDX_PY="${OUT_DIR}/sbom-python.cdx.json"
CDX_NPM="${OUT_DIR}/sbom-node.cdx.json"

# 1) Скан источника (Syft)
case "${SOURCE_TYPE}" in
  dir)
    [[ -d "${SOURCE_PATH}" ]] || die "Нет директории: ${SOURCE_PATH}"
    gen_syft_dir "${SOURCE_PATH}" "${SPDX_SYFT}" "${CDX_SYFT}"
    ;;
  image)
    gen_syft_image "${SOURCE_PATH}" "${SPDX_SYFT}" "${CDX_SYFT}"
    ;;
  *) die "Неподдерживаемый SOURCE_TYPE: ${SOURCE_TYPE}" ;;
esac

# 2) Языковые SBOM (опционально)
if [[ "${SOURCE_TYPE}" == "dir" ]]; then
  # Python
  if [[ -f "${SOURCE_PATH}/pyproject.toml" || -f "${SOURCE_PATH}/requirements.txt" || -d "${SOURCE_PATH}/src" ]]; then
    gen_cyclonedx_python "${SOURCE_PATH}" "${CDX_PY}"
  fi
  # Node
  if [[ -f "${SOURCE_PATH}/package.json" ]]; then
    gen_cyclonedx_npm "${SOURCE_PATH}" "${CDX_NPM}"
  fi
fi

# 3) Нормализация/проверка JSON (при наличии jq)
for f in "${SPDX_SYFT}" "${CDX_SYFT}" "${CDX_PY}" "${CDX_NPM}"; do
  if [[ -f "$f" ]]; then
    tmp="${f}.tmp"
    cat "$f" | json_pretty > "${tmp}" && mv "${tmp}" "$f"
  fi
done

# 4) Сводка и контрольные суммы
{
  echo "subject: ${PROJ_NAME}"
  echo "version: ${PROJ_VERSION}"
  echo "source:  ${SOURCE_TYPE}:${SOURCE_PATH}"
  echo "time:    ${RUN_ID}"
  echo
  echo "artifacts:"
  for f in "${SPDX_SYFT}" "${CDX_SYFT}" "${CDX_PY}" "${CDX_NPM}"; do
    [[ -f "$f" ]] && printf "  - %s (%s bytes)\n" "$(basename "$f")" "$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")"
  done
} >> "${SUMMARY}"

for f in "${SPDX_SYFT}" "${CDX_SYFT}" "${CDX_PY}" "${CDX_NPM}"; do
  [[ -f "$f" ]] && add_checksum "$f"
done

# 5) Базовый аудит (по запросу)
audit_with_grype "${SOURCE_PATH}"

# 6) Подпись (по запросу)
sign_artifacts

# 7) Финал
ok "SBOM готов. Каталог: ${OUT_DIR}"
log "Сводка:    ${SUMMARY}"
log "Чек-суммы: ${CHECKSUMS}"

# Быстрый вывод сводки
echo
cat "${SUMMARY}"

exit 0
