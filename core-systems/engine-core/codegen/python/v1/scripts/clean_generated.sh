#!/usr/bin/env bash
# Aethernova Engine | Codegen v1
# Очистка артефактов генерации в engine-core/codegen/python/v1/generated
# Безопасно удаляет _autogen/, кэш и вспомогательные файлы, с защитой путей.
# Платформы: Linux/macOS. Требуется bash.

set -Eeuo pipefail

PRODUCT="Aethernova Engine Codegen Cleaner"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_GUESS="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

COLOR="${COLOR:-auto}"
if [[ -t 1 && "${COLOR}" != "never" ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLU=$'\e[34m'; DIM=$'\e[2m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YLW=""; BLU=""; DIM=""; RST=""
fi

log()  { echo -e "${DIM}[$(date -u +%H:%M:%S)]${RST} $*"; }
info() { echo -e "${GRN}INFO${RST}  $*"; }
warn() { echo -e "${YLW}WARN${RST}  $*"; }
err()  { echo -e "${RED}ERROR${RST} $*" 1>&2; }
die()  { err "$*"; exit 1; }

# ---------------------------
# Опции
# ---------------------------
DRYRUN=0
YES=0
ALL=0
ONLY_AUTOGEN=0
CLEAN_STAMPS=0
CLEAN_CACHES=0
CLEAN_ORPHANED=0
VERBOSE=0

usage() {
  cat <<USAGE
${PRODUCT}
Usage: $(basename "$0") [options]

Options:
  --all              Полная очистка (эквивалентно: --autogen --stamps --caches --orphaned)
  --autogen          Удалить каталог _autogen/ целиком
  --stamps           Удалить штампы/отчеты (например, __genstamp__.json, SBOM.CODEGEN.txt)
  --caches           Удалить локальный кэш (.cache/proto, __pycache__, *.pyc)
  --orphaned         Удалить осиротевшие сгенерированные файлы вне _autogen (если есть)
  --dry-run          Показать, что будет удалено, без фактического удаления
  -y, --yes          Не спрашивать подтверждение
  --verbose          Подробный лог
  -h, --help         Помощь

По умолчанию без флагов ничего не делает.
Безопасность:
  - Проверяется, что путь вывода действительно указывает на .../engine-core/codegen/python/v1/generated
  - Межпроцессная блокировка на время операции.
Коды возврата:
  0 — успех; 2 — неверное использование; 3 — небезопасный путь; 4 — ошибка блокировки/IO.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) ALL=1; shift ;;
    --autogen) ONLY_AUTOGEN=1; shift ;;
    --stamps) CLEAN_STAMPS=1; shift ;;
    --caches) CLEAN_CACHES=1; shift ;;
    --orphaned) CLEAN_ORPHANED=1; shift ;;
    --dry-run) DRYRUN=1; shift ;;
    -y|--yes) YES=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Неизвестный аргумент: $1"; usage; exit 2 ;;
  esac
done

if (( ALL == 1 )); then
  ONLY_AUTOGEN=1
  CLEAN_STAMPS=1
  CLEAN_CACHES=1
  CLEAN_ORPHANED=1
fi

if (( ONLY_AUTOGEN == 0 && CLEAN_STAMPS == 0 && CLEAN_CACHES == 0 && CLEAN_ORPHANED == 0 )); then
  warn "Не указаны области очистки. Нечего делать."
  exit 0
fi

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

# Пути
SCHEMAS_ROOT="${SCHEMAS_ROOT:-${REPO_ROOT}/engine-core/schemas/proto}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/engine-core/codegen/python/v1/generated}"
AUTOGEN_DIR="${AUTOGEN_DIR:-_autogen}"
OUT_AUTOGEN="${OUT_ROOT}/${AUTOGEN_DIR}"
CACHE_DIR_DEFAULT="${REPO_ROOT}/.cache/proto"

# ---------------------------
# Защита путей
# ---------------------------
case "$OUT_ROOT" in
  *"engine-core/codegen/python/v1/generated") : ;;
  *) err "Небезопасный OUT_ROOT: $OUT_ROOT"; exit 3 ;;
esac
[[ -d "$OUT_ROOT" ]] || warn "Каталог вывода отсутствует: $OUT_ROOT"

# ---------------------------
# Блокировка
# ---------------------------
LOCK_DIR="${OUT_ROOT}/.clean.lock"
acquire_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>"${LOCK_DIR}.flock" || { err "Не могу открыть lock-файл"; exit 4; }
    flock -n 9 || { err "Другой процесс уже выполняет очистку"; exit 4; }
    echo $$ 1>&9 || true
  else
    if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
      err "Другой процесс уже выполняет очистку (lockdir)"; exit 4
    fi
  fi
}
release_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>&-
    rm -f "${LOCK_DIR}.flock" || true
  else
    rmdir "${LOCK_DIR}" 2>/dev/null || true
  fi
}
trap 'release_lock' EXIT
acquire_lock

# ---------------------------
# Удаление (с Dry‑run)
# ---------------------------
rm_path() {
  local path="$1"
  if (( DRYRUN == 1 )); then
    echo "[dry-run] rm -rf -- $path"
  else
    rm -rf -- "$path"
  fi
}

rm_glob() {
  # безопасное удаление по шаблону внутри OUT_ROOT
  local pattern="$1"
  shopt -s nullglob
  local matches=("$OUT_ROOT"/$pattern)
  shopt -u nullglob
  if (( ${#matches[@]} )); then
    for p in "${matches[@]}"; do
      rm_path "$p"
    done
  fi
}

confirm() {
  (( YES == 1 )) && return 0
  echo -n "Подтвердить очистку в ${OUT_ROOT}? [y/N]: "
  read -r ans
  [[ "${ans}" == "y" || "${ans}" == "Y" ]]
}

if ! confirm; then
  info "Отменено пользователем."
  exit 0
fi

# Сводка намерений
log "Репозиторий: ${REPO_ROOT}"
log "OUT_ROOT:    ${OUT_ROOT}"
log "AUTOGEN_DIR: ${AUTOGEN_DIR}"
(( VERBOSE == 1 )) && log "SCHEMAS_ROOT: ${SCHEMAS_ROOT}"

# 1) _autogen/
if (( ONLY_AUTOGEN == 1 )); then
  if [[ -d "$OUT_AUTOGEN" ]]; then
    info "Удаление каталога _autogen/: ${OUT_AUTOGEN}"
    rm_path "${OUT_AUTOGEN}"
  else
    warn "Нет каталога _autogen/: ${OUT_AUTOGEN}"
  fi
fi

# 2) stamps/reports в generated/
if (( CLEAN_STAMPS == 1 )); then
  info "Удаление штампов/отчетов"
  rm_glob "__genstamp__.json"
  rm_glob "SBOM.CODEGEN.txt"
  rm_glob "*.stamp"
fi

# 3) caches: .cache/proto, __pycache__, *.pyc внутри generated
if (( CLEAN_CACHES == 1 )); then
  info "Удаление кэшей"
  # локальный кэш в репозитории
  if [[ -d "$CACHE_DIR_DEFAULT" ]]; then
    if (( DRYRUN == 1 )); then
      echo "[dry-run] rm -rf -- ${CACHE_DIR_DEFAULT}"
    else
      rm -rf -- "${CACHE_DIR_DEFAULT}"
    fi
  fi
  # python байткод внутри generated
  if [[ -d "$OUT_ROOT" ]]; then
    if (( DRYRUN == 1 )); then
      echo "[dry-run] find \"$OUT_ROOT\" -name '__pycache__' -type d -prune -exec rm -rf -- {} +"
      echo "[dry-run] find \"$OUT_ROOT\" -name '*.py[co]' -type f -delete"
    else
      find "$OUT_ROOT" -name '__pycache__' -type d -prune -exec rm -rf -- {} + || true
      find "$OUT_ROOT" -name '*.py[co]' -type f -delete || true
    fi
  fi
fi

# 4) orphaned: любые *.py, оставшиеся вне _autogen, которые выглядят как автоген
#    эвристика: файлы с содержимым "Generated by the protocol buffer compiler" или префиксами grpc_tools
if (( CLEAN_ORPHANED == 1 )); then
  info "Поиск и удаление осиротевших автоген-файлов вне _autogen"
  if [[ -d "$OUT_ROOT" ]]; then
    shopt -s globstar nullglob
    for f in "$OUT_ROOT"/**/*.py; do
      [[ "$f" == "$OUT_AUTOGEN"* ]] && continue
      # быстрое чтение первых 5КБ
      head_content="$(head -c 5120 "$f" 2>/dev/null || true)"
      if grep -qE "Generated by the protocol buffer compiler|grpc_tools|_pb2(_grpc)?\.py" <<<"$head_content"; then
        rm_path "$f"
        # удаляем опустевшие каталоги
        d="$(dirname "$f")"
        find "$d" -type d -empty -delete 2>/dev/null || true
      fi
    done
    shopt -u globstar nullglob
  fi
fi

info "Очистка завершена"
exit 0
