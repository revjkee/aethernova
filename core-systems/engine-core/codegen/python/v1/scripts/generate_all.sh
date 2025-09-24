#!/usr/bin/env bash
# Aethernova Engine | Codegen v1
# Основной генератор Python protobuf + gRPC stubs
# Профили: dev|ci|release
# Требования: bash, python3, grpcio-tools (PyPI), protobuf (PyPI)
# Опционально: buf (lint), protoc (для версии), yq (YAML), sha256sum/shasum

set -Eeuo pipefail

# ---------------------------
# Константы и оформление лога
# ---------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_GUESS="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
PROJECT="engine-core"
PRODUCT="Aethernova Engine Codegen"
DEFAULT_PROFILE="dev"
PARALLELISM="${PARALLELISM:-4}"
COLOR="${COLOR:-auto}"

if [[ -t 1 && "${COLOR}" != "never" ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLU=$'\e[34m'; DIM=$'\e[2m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YLW=""; BLU=""; DIM=""; RST=""
fi

log()   { echo -e "${DIM}[$(date -u +%H:%M:%S)]${RST} $*"; }
info()  { echo -e "${GRN}INFO${RST}  $*"; }
warn()  { echo -e "${YLW}WARN${RST}  $*"; }
err()   { echo -e "${RED}ERROR${RST} $*" 1>&2; }
die()   { err "$*"; exit 1; }

# ---------------------------
# Аргументы
# ---------------------------
PROFILE="${DEFAULT_PROFILE}"
VERBOSE="0"
DRYRUN="0"
CLEAN="0"

usage() {
  cat <<USAGE
${PRODUCT} — генерация Python protobuf/gRPC
Usage: $(basename "$0") [--profile dev|ci|release] [--parallel N] [--clean] [--verbose] [--dry-run]

Options:
  --profile P     Профиль сборки (default: ${DEFAULT_PROFILE})
  --parallel N    Параллелизм генерации (default: ${PARALLELISM})
  --clean         Очистить каталог вывода перед сборкой
  --verbose       Подробный лог
  --dry-run       Показать команды, не исполняя
  -h, --help      Помощь
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --parallel) PARALLELISM="${2:-}"; shift 2 ;;
    --clean) CLEAN="1"; shift ;;
    --verbose) VERBOSE="1"; shift ;;
    --dry-run) DRYRUN="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Неизвестный аргумент: $1" ;;
  esac
done

[[ "${PROFILE}" =~ ^(dev|ci|release)$ ]] || die "Некорректный профиль: ${PROFILE}"

# ---------------------------
# Поиск корня репозитория
# ---------------------------
detect_repo_root() {
  local dir="${1:-$REPO_GUESS}"
  while [[ "$dir" != "/" ]]; do
    if [[ -e "$dir/.git" || -e "$dir/pyproject.toml" || -d "$dir/engine-core" ]]; then
      echo "$dir"; return 0
    fi
    dir="$(dirname "$dir")"
  done
  echo "$REPO_GUESS"
}
REPO_ROOT="$(detect_repo_root)"
cd "$REPO_ROOT"

# ---------------------------
# Переменные окружения/пути
# ---------------------------
SCHEMAS_ROOT="${SCHEMAS_ROOT:-${REPO_ROOT}/engine-core/schemas/proto}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/engine-core/codegen/python/v1/generated}"
AUTOGEN_DIR="${AUTOGEN_DIR:-_autogen}"
OUT_AUTOGEN="${OUT_ROOT}/${AUTOGEN_DIR}"
STAMP_FILE="${OUT_AUTOGEN}/__genstamp__.json"
SBOM_FILE="${OUT_AUTOGEN}/SBOM.CODEGEN.txt"

[[ -d "$SCHEMAS_ROOT" ]] || die "Не найден каталог схем: $SCHEMAS_ROOT"

# Воспроизводимость
export LC_ALL=C
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1715107200}" # 2024-05-07 00:00:00Z

# ---------------------------
# Проверки окружения
# ---------------------------
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Требуется команда: $1"; }

PYTHON="${PYTHON:-python3}"
require_cmd "$PYTHON"

# Проверка Python-пакетов
py_check() {
  "$PYTHON" - <<'PY' || exit 1
import sys
missing=[]
try:
  import google.protobuf  # noqa
except Exception:
  missing.append('protobuf')
try:
  import grpc_tools.protoc  # noqa
except Exception:
  missing.append('grpcio-tools')
if missing:
  sys.stderr.write("Отсутствуют Python-пакеты: %s\n" % ", ".join(missing))
  sys.exit(2)
PY
}
if ! py_check; then
  die "Установите зависимости: ${PYTHON} -m pip install --upgrade protobuf grpcio grpcio-tools"
fi

# Необязательные инструменты
if command -v protoc >/dev/null 2>&1; then
  PROTOC_VER="$(protoc --version || true)"
  info "protoc: ${PROTOC_VER}"
else
  warn "protoc не найден (не критично, используем python -m grpc_tools.protoc)"
fi

if command -v buf >/dev/null 2>&1; then
  BUF_VER="$(buf --version || true)"
  info "buf: ${BUF_VER}"
fi

# ---------------------------
# Lint (если доступен buf)
# ---------------------------
if command -v buf >/dev/null 2>&1; then
  if [[ -f "${REPO_ROOT}/buf.yaml" || -f "${REPO_ROOT}/buf.gen.yaml" ]]; then
    log "Запуск buf lint..."
    if ! buf lint; then
      if [[ "${PROFILE}" == "ci" || "${PROFILE}" == "release" ]]; then
        die "buf lint: ошибки линтинга (профиль ${PROFILE})"
      else
        warn "buf lint: предупреждения/ошибки (профиль ${PROFILE}), продолжаем"
      fi
    fi
  else
    warn "buf не сконфигурирован (buf.yaml не найден), пропуск линта"
  fi
else
  warn "buf не установлен, пропуск линта"
fi

# ---------------------------
# Очистка, инициализация
# ---------------------------
if [[ "$CLEAN" == "1" ]]; then
  log "Очистка каталога вывода: ${OUT_AUTOGEN}"
  rm -rf -- "${OUT_AUTOGEN}"
fi

mkdir -p "${OUT_AUTOGEN}"
# Пакеты для Python
init_pkg() {
  local d="$1"
  [[ -d "$d" ]] || mkdir -p "$d"
  [[ -f "$d/__init__.py" ]] || echo "# auto-generated package init" > "$d/__init__.py"
}
init_pkg "${OUT_AUTOGEN}"
init_pkg "${OUT_AUTOGEN}/engine"
init_pkg "${OUT_AUTOGEN}/common"
init_pkg "${OUT_AUTOGEN}/common/error"
init_pkg "${OUT_AUTOGEN}/economy" || true

# ---------------------------
# Сканирование источников
# ---------------------------
shopt -s globstar nullglob
ENGINE_PROTOS=("${SCHEMAS_ROOT}/v1/engine/"**/*.proto)
COMMON_PROTOS=("${SCHEMAS_ROOT}/v1/common/"**/*.proto)
ECONOMY_PROTOS=("${SCHEMAS_ROOT}/v1/economy/"**/*.proto)

# Исключения
filter_excludes() {
  local out=()
  for f in "$@"; do
    [[ "$f" == *"_internal.proto" ]] && continue
    out+=("$f")
  done
  printf '%s\n' "${out[@]}"
}
ENGINE_PROTOS=($(filter_excludes "${ENGINE_PROTOS[@]}"))
COMMON_PROTOS=($(filter_excludes "${COMMON_PROTOS[@]}"))
ECONOMY_PROTOS=($(filter_excludes "${ECONOMY_PROTOS[@]}"))

TOTAL=$(( ${#ENGINE_PROTOS[@]} + ${#COMMON_PROTOS[@]} + ${#ECONOMY_PROTOS[@]} ))
[[ $TOTAL -gt 0 ]] || die "Не найдено ни одного .proto файла в ${SCHEMAS_ROOT}/v1"

info "Найдено .proto файлов: $TOTAL (engine=${#ENGINE_PROTOS[@]}, common=${#COMMON_PROTOS[@]}, economy=${#ECONOMY_PROTOS[@]})"

# ---------------------------
# Команда генерации
# ---------------------------
PROTO_INCLUDES=(-I "${SCHEMAS_ROOT}" -I "${REPO_ROOT}")

PROTO_CMD_BASE=(
  "$PYTHON" -m grpc_tools.protoc
  "${PROTO_INCLUDES[@]}"
  --python_out "${OUT_AUTOGEN}"
  --grpc_python_out "${OUT_AUTOGEN}"
)

[[ "${VERBOSE}" == "1" ]] && info "Команда (база): ${PROTO_CMD_BASE[*]}"

run_protoc_for() {
  local proto="$1"
  local cmd=( "${PROTO_CMD_BASE[@]}" "${proto}" )
  if [[ "${DRYRUN}" == "1" ]]; then
    echo "[dry-run] ${cmd[*]}"
    return 0
  fi
  if [[ "${VERBOSE}" == "1" ]]; then
    log "protoc: ${proto}"
  fi
  "${cmd[@]}"
}

# ---------------------------
# Параллельная генерация
# ---------------------------
generate_all() {
  local list=("$@")
  if [[ ${#list[@]} -eq 0 ]]; then
    return 0
  fi
  printf '%s\0' "${list[@]}" | xargs -0 -I{} -P "${PARALLELISM}" bash -c '
    set -Eeuo pipefail
    proto="$1"
    "'"${BASH_SOURCE[0]}"'" --internal-protoc "$proto"
  ' _ {}
}

# Внутренний режим single file (для xargs fork)
if [[ "${1:-}" == "--internal-protoc" ]]; then
  shift
  run_protoc_for "$1"
  exit 0
fi

# ---------------------------
# Генерация по профилям
# ---------------------------
case "${PROFILE}" in
  dev)
    TO_GEN=( "${ENGINE_PROTOS[@]}" "${COMMON_PROTOS[@]}" "${ECONOMY_PROTOS[@]}" )
    ;;
  ci|release)
    TO_GEN=( "${ENGINE_PROTOS[@]}" "${COMMON_PROTOS[@]}" "${ECONOMY_PROTOS[@]}" )
    ;;
  *) die "Неизвестный профиль: ${PROFILE}" ;;
esac

log "Старт генерации (profile=${PROFILE}, parallel=${PARALLELISM})..."
generate_all "${TO_GEN[@]}"

info "Генерация завершена"

# ---------------------------
# Нормализация импортов и SBOM
# ---------------------------
# Простая нормализация: ensure relative imports в автогене совместимы с пакетом
fix_imports() {
  local root="${OUT_AUTOGEN}"
  # Приведение 'import engine_pb2 as engine__pb2' и подобных — оставляем как есть (сгенерировано grpc_tools)
  # Гарантируем пакетную структуру
  :
}
fix_imports

# SBOM/штамп целостности
hash_all_py() {
  local root="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    find "$root" -type f -name '*.py' -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
  else
    # macOS fallback
    find "$root" -type f -name '*.py' -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}'
  fi
}

if [[ "${DRYRUN}" != "1" ]]; then
  mkdir -p "$(dirname "$SBOM_FILE")"
  SBOM_HASH="$(hash_all_py "${OUT_AUTOGEN}")"
  echo "${SBOM_HASH}" > "${SBOM_FILE}"
  log "SBOM: ${SBOM_FILE}"
fi

# ---------------------------
# Политики профилей (fail_on_warn и т.д.)
# ---------------------------
if [[ "${PROFILE}" == "release" ]]; then
  # Заморозка импортов/внешних инклюдов могла бы быть реализована здесь (при наличии allowlist).
  :
fi

info "Готово: артефакты → ${OUT_AUTOGEN}"
