#!/usr/bin/env bash
# policy-core/scripts/sbom.sh
# Индустриальный генератор SBOM c поддержкой CycloneDX/SPDX, контейнерных образов и директорий.
# Зависимости (минимум один бэкенд): syft >= 1.x, trivy >= 0.50, jq, cosign (опц.), grype (опц.)
# Безопасность: строгий режим, предсказуемые таймстемпы, игнор нежелательных путей.

set -Eeuo pipefail

# ----------------------------
# Логирование и общие утилиты
# ----------------------------
SCRIPT_NAME="$(basename "$0")"
COLOR=${COLOR:-1}
if [[ -t 1 && "${COLOR}" -eq 1 ]]; then
  RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; NC='\033[0m'
else
  RED=''; YEL=''; GRN=''; BLU=''; NC=''
fi

info()    { printf "${BLU}[INFO]${NC} %s\n" "$*"; }
warn()    { printf "${YEL}[WARN]${NC} %s\n" "$*"; }
error()   { printf "${RED}[ERROR]${NC} %s\n" "$*" 1>&2; }
success() { printf "${GRN}[OK]${NC} %s\n" "$*"; }

die() { error "$*"; exit 1; }

trap 'error "Произошла ошибка на строке $LINENO"; exit 1' ERR

# ----------------------------
# Значения по умолчанию
# ----------------------------
BACKEND="auto"                # syft|trivy|auto
FORMATS=("cyclonedx-json")    # cyclonedx-json|cyclonedx-xml|spdx-json
OUT_DIR="./artifacts/sbom"
STRICT=0
VALIDATE=1
VULN=0
SIGN=0
ATTEST=0
SIGN_KEY="${SIGN_KEY:-}"       # путь к ключу для cosign (опционально)
COSIGN_IDENTITY="${COSIGN_IDENTITY:-}" # identity/email для keyless
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  TIMESTAMP="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y%m%dT%H%M%SZ 2>/dev/null || date -u +%Y%m%dT%H%M%SZ)"
fi

TARGET_DIRS=()
TARGET_IMAGES=()
EXTRA_ARGS=()

# ----------------------------
# Справка
# ----------------------------
usage() {
  cat <<EOF
${SCRIPT_NAME} — генерация SBOM (CycloneDX/SPDX) для директорий и контейнерных образов.

Использование:
  ${SCRIPT_NAME} [опции] [--dir PATH ...] [--image REF ...]
Опции:
  --backend {auto|syft|trivy}     Бэкенд для SBOM (по умолчанию auto)
  --format  f1,f2                  Форматы: cyclonedx-json, cyclonedx-xml, spdx-json (деф. cyclonedx-json)
  --dir PATH                       Каталог для анализа (можно несколько раз)
  --image REF                      Образ (docker/podman) имя:тег или @digest (можно несколько раз)
  --out DIR                        Директория для артефактов (деф. ./artifacts/sbom)
  --no-validate                    Отключить простую валидацию результата
  --strict                         Ненулевой exit при ошибках/пустых результатах
  --vuln                           Дополнительно сгенерировать отчет уязвимостей (Trivy/Grype)
  --sign                           Подписать SBOM cosign (файлы)
  --attest                         Создать OCI-инттестации (cosign attest) для --image целей
  --extra ARG                      Проброс дополнительных аргументов в бэкенд (можно повторять)
  -h|--help                        Справка

Переменные окружения:
  SOURCE_DATE_EPOCH   Фиксированный timestamp для репродьюсибилити
  SIGN_KEY            Путь к приватному ключу cosign (если не задан — возможно keyless)
  COSIGN_IDENTITY     Identity (email/issuer) для keyless-подписи cosign

Примеры:
  ${SCRIPT_NAME} --dir . --format cyclonedx-json,spdx-json --vuln --strict
  ${SCRIPT_NAME} --image nginx:1.27 --attest --sign
EOF
}

# ----------------------------
# Парсинг аргументов
# ----------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend) BACKEND="${2:-}"; shift 2 ;;
    --format)  IFS=',' read -r -a FORMATS <<< "${2:-}"; shift 2 ;;
    --dir)     TARGET_DIRS+=("${2:-}"); shift 2 ;;
    --image)   TARGET_IMAGES+=("${2:-}"); shift 2 ;;
    --out)     OUT_DIR="${2:-}"; shift 2 ;;
    --no-validate) VALIDATE=0; shift ;;
    --strict)  STRICT=1; shift ;;
    --vuln)    VULN=1; shift ;;
    --sign)    SIGN=1; shift ;;
    --attest)  ATTEST=1; shift ;;
    --extra)   EXTRA_ARGS+=("${2:-}"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)         die "Неизвестный аргумент: $1. Запустите с --help." ;;
  esac
done

# ----------------------------
# Проверка окружения/зависимостей
# ----------------------------
has() { command -v "$1" >/dev/null 2>&1; }

pick_backend() {
  local choice="${BACKEND}"
  if [[ "${choice}" == "auto" ]]; then
    if has syft; then choice="syft"; elif has trivy; then choice="trivy"; else choice=""; fi
  fi
  [[ -n "${choice}" ]] || die "Не найден ни syft, ни trivy. Установите один из бэкендов."
  echo "${choice}"
}

ensure_outdir() { mkdir -p "${OUT_DIR}" || die "Не удалось создать ${OUT_DIR}"; }

# ----------------------------
# Игнор-лист
# ----------------------------
# По умолчанию игнорируем тяжелые каталоги; можно добавить .sbomignore в корне цели
DEFAULT_IGNORES=(
  ".git" "node_modules" "dist" "build" "target" ".venv" "venv" "__pycache__" ".tox" ".mypy_cache" ".pytest_cache"
  ".idea" ".vscode" ".gradle" ".cargo" "bin" "obj" "vendor"
)
should_ignore() {
  local path="$1" root="$2"
  local ignore_file="${root}/.sbomignore"
  for pat in "${DEFAULT_IGNORES[@]}"; do
    [[ "${path}" == *"/${pat}"* ]] && return 0 || true
  done
  if [[ -f "${ignore_file}" ]]; then
    # простая проверка подстрокой; при необходимости заменить на .gitignore-совместимый парсер
    while IFS= read -r pat; do
      [[ -z "${pat}" || "${pat}" =~ ^# ]] && continue
      [[ "${path}" == *"${pat}"* ]] && return 0 || true
    done < "${ignore_file}"
  fi
  return 1
}

# ----------------------------
# Детекция экосистем (информативно)
# ----------------------------
detect_stack() {
  local root="$1"
  local features=()
  [[ -f "${root}/package-lock.json" || -f "${root}/pnpm-lock.yaml" || -f "${root}/yarn.lock" ]] && features+=("node")
  [[ -f "${root}/requirements.txt" || -f "${root}/poetry.lock" || -f "${root}/Pipfile.lock" ]] && features+=("python")
  [[ -f "${root}/go.mod" ]] && features+=("go")
  [[ -f "${root}/Cargo.lock" ]] && features+=("rust")
  [[ -f "${root}/pom.xml" || -f "${root}/build.gradle" || -f "${root}/build.gradle.kts" ]] && features+=("java")
  ((${#features[@]})) && printf "%s\n" "${features[@]}" || true
}

# ----------------------------
# Генерация SBOM: SYFT
# ----------------------------
syft_formats_arg() {
  local args=()
  for f in "${FORMATS[@]}"; do
    case "$f" in
      cyclonedx-json) args+=("-o" "cyclonedx-json");;
      cyclonedx-xml)  args+=("-o" "cyclonedx-xml");;
      spdx-json)      args+=("-o" "spdx-json");;
      *) warn "Формат $f не поддерживается syft напрямую; будет пропущен."; ;
    esac
  done
  printf "%s " "${args[@]}"
}

syft_dir() {
  local dir="$1" base out
  base="$(basename "$(realpath "${dir}")")"
  local stack="$(detect_stack "${dir}" | tr '\n' ',' || true)"
  info "SYFT каталог: ${dir} (stack: ${stack:-unknown})"
  local fmt
  for fmt in "${FORMATS[@]}"; do
    case "$fmt" in
      cyclonedx-json) out="${OUT_DIR}/${base}-${TIMESTAMP}-cyclonedx.json" ;;
      cyclonedx-xml)  out="${OUT_DIR}/${base}-${TIMESTAMP}-cyclonedx.xml" ;;
      spdx-json)      out="${OUT_DIR}/${base}-${TIMESTAMP}-spdx.json" ;;
      *) warn "Пропуск неизвестного формата: $fmt"; continue ;;
    esac
    info "→ ${out}"
    # shellcheck disable=SC2046
    syft packages "dir:${dir}" $(syft_formats_arg) --file "${out}" --exclude "$(printf "%s," "${DEFAULT_IGNORES[@]}")" "${EXTRA_ARGS[@]}" || die "syft не смог собрать SBOM для ${dir}"
    [[ -s "${out}" ]] || die "Пустой файл SBOM: ${out}"
  done
}

syft_image() {
  local ref="$1" out
  info "SYFT образ: ${ref}"
  local fmt
  for fmt in "${FORMATS[@]}"; do
    case "$fmt" in
      cyclonedx-json) out="${OUT_DIR}/image-$(echo "${ref}" | tr '/:@' '___')-${TIMESTAMP}-cyclonedx.json" ;;
      cyclonedx-xml)  out="${OUT_DIR}/image-$(echo "${ref}" | tr '/:@' '___')-${TIMESTAMP}-cyclonedx.xml" ;;
      spdx-json)      out="${OUT_DIR}/image-$(echo "${ref}" | tr '/:@' '___')-${TIMESTAMP}-spdx.json" ;;
      *) warn "Пропуск неизвестного формата: $fmt"; continue ;;
    esac
    info "→ ${out}"
    # shellcheck disable=SC2046
    syft "${ref}" $(syft_formats_arg) --file "${out}" "${EXTRA_ARGS[@]}" || die "syft не смог собрать SBOM для образа ${ref}"
    [[ -s "${out}" ]] || die "Пустой файл SBOM: ${out}"
  done
}

# ----------------------------
# Генерация SBOM: TRIVY
# ----------------------------
trivy_format_arg() {
  # Trivy поддерживает --format cyclonedx, spdx-json (едиственный)
  local f="$1"
  case "$f" in
    cyclonedx-json|cyclonedx-xml) echo "cyclonedx" ;;
    spdx-json) echo "spdx-json" ;;
    *) echo ""; return 1 ;;
  esac
}

trivy_dir() {
  local dir="$1" out fmt f
  info "TRIVY каталог: ${dir}"
  for fmt in "${FORMATS[@]}"; do
    f="$(trivy_format_arg "${fmt}" || true)"
    [[ -n "${f}" ]] || { warn "Формат ${fmt} не поддерживается Trivy; пропуск."; continue; }
    case "$fmt" in
      cyclonedx-json|cyclonedx-xml) out="${OUT_DIR}/$(basename "$(realpath "${dir}")")-${TIMESTAMP}-cyclonedx.json" ;;
      spdx-json)                    out="${OUT_DIR}/$(basename "$(realpath "${dir}")")-${TIMESTAMP}-spdx.json" ;;
    esac
    info "→ ${out}"
    trivy sbom --format "${f}" --output "${out}" "dir:${dir}" "${EXTRA_ARGS[@]}" || die "trivy не смог собрать SBOM для ${dir}"
    [[ -s "${out}" ]] || die "Пустой файл SBOM: ${out}"
  done
}

trivy_image() {
  local ref="$1" out fmt f
  info "TRIVY образ: ${ref}"
  for fmt in "${FORMATS[@]}"; do
    f="$(trivy_format_arg "${fmt}" || true)"
    [[ -n "${f}" ]] || { warn "Формат ${fmt} не поддерживается Trivy; пропуск."; continue; }
    case "$fmt" in
      cyclonedx-json|cyclonedx-xml) out="${OUT_DIR}/image-$(echo "${ref}" | tr '/:@' '___')-${TIMESTAMP}-cyclonedx.json" ;;
      spdx-json)                    out="${OUT_DIR}/image-$(echo "${ref}" | tr '/:@' '___')-${TIMESTAMP}-spdx.json" ;;
    esac
    info "→ ${out}"
    trivy sbom --format "${f}" --output "${out}" "image:${ref}" "${EXTRA_ARGS[@]}" || die "trivy не смог собрать SBOM для ${ref}"
    [[ -s "${out}" ]] || die "Пустой файл SBOM: ${out}"
  done
}

# ----------------------------
# Валидация SBOM (простая)
# ----------------------------
validate_sbom_file() {
  [[ "${VALIDATE}" -eq 1 ]] || return 0
  local file="$1"
  [[ -s "${file}" ]] || die "SBOM пуст: ${file}"
  case "${file}" in
    *.json)
      has jq || { warn "jq не найден, пропуск валидации JSON"; return 0; }
      jq -e 'type=="object" and ( .bomFormat=="CycloneDX" or .spdxVersion? )' "${file}" >/dev/null \
        || die "Файл не похож на валидный CycloneDX/SPDX JSON: ${file}"
      ;;
    *.xml)
      # Легкая проверка: наличие корневых элементов CycloneDX
      grep -q "<bom" "${file}" || die "XML SBOM без корневого <bom>: ${file}"
      ;;
    *)
      warn "Неизвестное расширение для валидации: ${file}"
      ;;
  esac
}

# ----------------------------
# Уязвимости (опционально)
# ----------------------------
scan_vuln_dir() {
  local dir="$1" out="${OUT_DIR}/$(basename "$(realpath "${dir}")")-${TIMESTAMP}-vuln.json"
  if has trivy; then
    info "TRIVY уязвимости: dir:${dir}"
    trivy fs --format json --output "${out}" --severity HIGH,CRITICAL "${dir}" || warn "Trivy вернул ошибку (fs) для ${dir}"
  elif has grype; then
    info "GRYPE уязвимости: dir:${dir}"
    grype "dir:${dir}" -o json > "${out}" || warn "Grype вернул ошибку (fs) для ${dir}"
  else
    warn "Нет trivy/grype — пропуск отчета уязвимостей для ${dir}"
    return 0
  fi
  [[ -s "${out}" ]] && success "Уязвимости сохранены: ${out}" || warn "Пустой отчет уязвимостей: ${out}"
}

scan_vuln_image() {
  local ref="$1" out="${OUT_DIR}/image-$(echo "${ref}" | tr '/:@' '___')-${TIMESTAMP}-vuln.json"
  if has trivy; then
    info "TRIVY уязвимости: image:${ref}"
    trivy image --format json --output "${out}" --severity HIGH,CRITICAL "${ref}" || warn "Trivy вернул ошибку (image) для ${ref}"
  elif has grype; then
    info "GRYPE уязвимости: image:${ref}"
    grype "${ref}" -o json > "${out}" || warn "Grype вернул ошибку (image) для ${ref}"
  else
    warn "Нет trivy/grype — пропуск отчета уязвимостей для ${ref}"
    return 0
  fi
  [[ -s "${out}" ]] && success "Уязвимости сохранены: ${out}" || warn "Пустой отчет уязвимостей: ${out}"
}

# ----------------------------
# Подпись SBOM (опционально)
# ----------------------------
cosign_sign_file() {
  local file="$1"
  has cosign || { warn "cosign не найден — пропуск подписи ${file}"; return 0; }
  local sig="${file}.sig"
  if [[ -n "${SIGN_KEY}" ]]; then
    info "COSIGN подпись (key): ${file}"
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --key "${SIGN_KEY}" --output-signature "${sig}" "${file}" \
      || warn "Не удалось подписать ${file}"
  else
    info "COSIGN подпись (keyless): ${file}"
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --output-signature "${sig}" "${file}" \
      ${COSIGN_IDENTITY:+--identity "${COSIGN_IDENTITY}"} \
      || warn "Не удалось подписать ${file}"
  fi
  [[ -s "${sig}" ]] && success "Подпись создана: ${sig}" || warn "Подпись пуста: ${sig}"
}

cosign_attest_image() {
  local ref="$1" sbom_json="$2"
  has cosign || { warn "cosign не найден — пропуск аттестации ${ref}"; return 0; }
  [[ -f "${sbom_json}" ]] || { warn "SBOM не найден для аттестации: ${sbom_json}"; return 0; }
  info "COSIGN attest (CycloneDX): ${ref}"
  COSIGN_EXPERIMENTAL=1 cosign attest --type cyclonedx --predicate "${sbom_json}" "${ref}" \
    || warn "Не удалось создать аттестацию для ${ref}"
}

# ----------------------------
# Основная логика
# ----------------------------
main() {
  ensure_outdir
  local backend; backend="$(pick_backend)"; info "Выбран бэкенд: ${backend}"

  local produced=()

  # Директории
  for d in "${TARGET_DIRS[@]:-}"; do
    [[ -d "${d}" ]] || { [[ "${STRICT}" -eq 1 ]] && die "Каталог не существует: ${d}" || { warn "Нет каталога: ${d}"; continue; }; }
    case "${backend}" in
      syft)  syft_dir "${d}";;
      trivy) trivy_dir "${d}";;
      *) die "Неподдерживаемый бэкенд: ${backend}";;
    esac
    # собираем список созданных файлов для валидации и подписи
    for fmt in "${FORMATS[@]}"; do
      case "$fmt" in
        cyclonedx-json) produced+=("${OUT_DIR}/$(basename "$(realpath "${d}")")-${TIMESTAMP}-cyclonedx.json");;
        cyclonedx-xml)  produced+=("${OUT_DIR}/$(basename "$(realpath "${d}")")-${TIMESTAMP}-cyclonedx.xml");;
        spdx-json)      produced+=("${OUT_DIR}/$(basename "$(realpath "${d}")")-${TIMESTAMP}-spdx.json");;
      esac
    done
    [[ "${VULN}" -eq 1 ]] && scan_vuln_dir "${d}"
  done

  # Образы
  for img in "${TARGET_IMAGES[@]:-}"; do
    case "${backend}" in
      syft)  syft_image "${img}";;
      trivy) trivy_image "${img}";;
      *) die "Неподдерживаемый бэкенд: ${backend}";;
    esac
    for fmt in "${FORMATS[@]}"; do
      case "$fmt" in
        cyclonedx-json) produced+=("${OUT_DIR}/image-$(echo "${img}" | tr '/:@' '___')-${TIMESTAMP}-cyclonedx.json");;
        cyclonedx-xml)  produced+=("${OUT_DIR}/image-$(echo "${img}" | tr '/:@' '___')-${TIMESTAMP}-cyclonedx.xml");;
        spdx-json)      produced+=("${OUT_DIR}/image-$(echo "${img}" | tr '/:@' '___')-${TIMESTAMP}-spdx.json");;
      esac
    done
    [[ "${VULN}" -eq 1 ]] && scan_vuln_image "${img}"
  done

  # Валидация/подпись
  local count_ok=0
  for f in "${produced[@]:-}"; do
    [[ -f "${f}" ]] || { warn "Ожидался файл, но не найден: ${f}"; continue; }
    validate_sbom_file "${f}" || true
    if [[ "${SIGN}" -eq 1 ]]; then cosign_sign_file "${f}"; fi
    ((count_ok++))
  done

  # Аттестации OCI для образов (только CycloneDX JSON)
  if [[ "${ATTEST}" -eq 1 && "${#TARGET_IMAGES[@]:-}" -gt 0 ]]; then
    for img in "${TARGET_IMAGES[@]}"; do
      local pred="${OUT_DIR}/image-$(echo "${img}" | tr '/:@' '___')-${TIMESTAMP}-cyclonedx.json"
      [[ -f "${pred}" ]] && cosign_attest_image "${img}" "${pred}""
    done
  fi

  if [[ "${STRICT}" -eq 1 && ${count_ok} -eq 0 ]]; then
    die "SBOM не были сгенерированы."
  fi

  success "Готово. Артефакты: ${OUT_DIR}"
}

main "$@"
