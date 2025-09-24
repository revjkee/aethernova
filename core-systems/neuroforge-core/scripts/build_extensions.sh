#!/usr/bin/env bash
# neuroforge-core/scripts/build_extensions.sh
# Надёжная сборка нативных расширений/колёс Python для разных бэкендов.
# Поддерживаемые бэкенды: maturin, scikit-build-core, meson-python, setuptools/hatchling.
# Зависимости подтягиваются автоматически (можно отключить флагом --no-install).

set -Eeuo pipefail
IFS=$'\n\t'

# ---------- Константы и значения по умолчанию ----------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

MODE="release"                 # release|debug
BACKEND="auto"                 # auto|maturin|scikit-build|meson|setuptools|hatch
PY_BIN="auto"                  # auto|/path/to/python
VENV_PATH="${REPO_ROOT}/.venv" # путь к venv (исп. при --python=auto)
DIST_DIR="${REPO_ROOT}/dist"
REPAIR="false"                 # auditwheel/delocate
CLEAN="false"
INSTALL_TOOLS="true"
JOBS="auto"
QUIET="false"

# Цвета (если TTY)
if [[ -t 1 ]]; then
  C_BOLD=$'\033[1m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_CYAN=$'\033[36m'; C_RST=$'\033[0m'
else
  C_BOLD=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYAN=""; C_RST=""
fi

log()  { echo "${C_CYAN}[build]${C_RST} $*"; }
ok()   { echo "${C_GRN}[ok]${C_RST} $*"; }
warn() { echo "${C_YEL}[warn]${C_RST} $*" >&2; }
err()  { echo "${C_RED}[err]${C_RST} $*" >&2; }
die()  { err "$*"; exit 1; }

on_exit() { local ec=$?; if [[ $ec -ne 0 ]]; then err "сборка завершилась с кодом $ec"; fi; }
trap on_exit EXIT

usage() {
  cat <<EOF
${C_BOLD}Сборка нативных расширений Python${C_RST}

Использование:
  $(basename "$0") [опции]

Опции:
  --release | --debug          Режим сборки (по умолчанию: --release)
  --backend <auto|maturin|scikit-build|meson|setuptools|hatch>
                               Принудительный выбор бэкенда (по умолчанию: auto)
  --python <auto|/path/to/python>
                               Интерпретатор Python (auto: .venv/bin/python или python3)
  --venv <path>                Путь к виртуальному окружению (по умолчанию: ${VENV_PATH})
  --dist <dir>                 Директория для артефактов (по умолчанию: ${DIST_DIR})
  --jobs <N|auto>              Число потоков для сборки (по умолчанию: auto)
  --repair                     Починка колёс (auditwheel/delocate)
  --clean                      Очистка build/ dist/ wheelhouse/ *.egg-info
  --no-install                 Не устанавливать инструменты автоматически
  --quiet                      Меньше логов
  -h | --help                  Справка

Примеры:
  $ $(basename "$0") --release --repair
  $ $(basename "$0") --backend maturin --python /opt/py311/bin/python --jobs 8
EOF
}

# ---------- Парсинг аргументов ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --release) MODE="release"; shift;;
    --debug)   MODE="debug"; shift;;
    --backend) BACKEND="${2:-}"; shift 2;;
    --python)  PY_BIN="${2:-}"; shift 2;;
    --venv)    VENV_PATH="$(cd -P -- "$2" && pwd)"; shift 2;;
    --dist)    DIST_DIR="$(mkdir -p -- "$2" && cd -P -- "$2" && pwd)"; shift 2;;
    --jobs)    JOBS="${2:-}"; shift 2;;
    --repair)  REPAIR="true"; shift;;
    --clean)   CLEAN="true"; shift;;
    --no-install) INSTALL_TOOLS="false"; shift;;
    --quiet)   QUIET="true"; shift;;
    -h|--help) usage; exit 0;;
    *) die "неизвестный аргумент: $1";;
  esac
done

# ---------- Утилиты ----------
run() { [[ "${QUIET}" == "true" ]] && "$@" >/dev/null 2>&1 || "$@"; }

cpu_jobs() {
  if [[ "${JOBS}" != "auto" ]]; then echo "${JOBS}"; return; fi
  case "$(uname -s)" in
    Linux) nproc || echo 1;;
    Darwin) sysctl -n hw.logicalcpu || echo 1;;
    *) echo 1;;
  esac
}

ensure_dir() { mkdir -p -- "$1"; }

# ---------- Очистка ----------
if [[ "${CLEAN}" == "true" ]]; then
  log "очистка артефактов..."
  rm -rf -- "${REPO_ROOT}/build" "${REPO_ROOT}/wheelhouse" "${REPO_ROOT}"/*.egg-info "${DIST_DIR}"
  ok "очистка выполнена"
fi

# ---------- Определение Python ----------
detect_python() {
  if [[ "${PY_BIN}" != "auto" ]]; then
    command -v -- "${PY_BIN}" >/dev/null || die "python не найден: ${PY_BIN}"
    echo "${PY_BIN}"; return
  fi
  if [[ -x "${VENV_PATH}/bin/python" ]]; then
    echo "${VENV_PATH}/bin/python"; return
  fi
  if command -v python3 >/dev/null; then echo "python3"; return; fi
  if command -v python >/dev/null; then echo "python"; return; fi
  die "python не найден в PATH"
}

PY="$(detect_python)"
log "python: ${PY}"

# ---------- Создание venv при необходимости ----------
if [[ "${PY_BIN}" == "auto" && ! -x "${VENV_PATH}/bin/python" ]]; then
  log "виртуальное окружение не найдено, создаю: ${VENV_PATH}"
  run "${PY}" -m venv "${VENV_PATH}"
  PY="${VENV_PATH}/bin/python"
fi

# ---------- Версия Python и pip ----------
PY_VER="$(${PY} -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
log "версия Python: ${PY_VER}"
run "${PY}" -m pip install --upgrade pip wheel setuptools >/dev/null

# ---------- Автообнаружение бэкенда ----------
detect_backend() {
  local pyproject="${REPO_ROOT}/pyproject.toml"
  [[ -f "${pyproject}" ]] || { warn "pyproject.toml не найден — переключаюсь на setuptools (fallback)"; echo "setuptools"; return; }

  # Ищем указания build-system.requires / backend
  if grep -Eiq 'maturin' "${pyproject}"; then echo "maturin"; return; fi
  if grep -Eiq 'scikit-build-core' "${pyproject}"; then echo "scikit-build"; return; fi
  if grep -Eiq 'meson-python' "${pyproject}"; then echo "meson"; return; fi
  # hatchling и setuptools: оба возможны; hatch -> hatch
  if grep -Eiq 'hatchling' "${pyproject}"; then echo "hatch"; return; fi
  echo "setuptools"
}

if [[ "${BACKEND}" == "auto" ]]; then
  BACKEND="$(detect_backend)"
fi
log "бэкенд: ${BACKEND}"

# ---------- Подготовка окружения ----------
JOBS_N="$(cpu_jobs)"
export CMAKE_BUILD_PARALLEL_LEVEL="${JOBS_N}"
export MAKEFLAGS="-j${JOBS_N}"

# ccache (если установлен)
if command -v ccache >/dev/null; then
  export CCACHE_DIR="${REPO_ROOT}/.ccache"
  ensure_dir "${CCACHE_DIR}"
  export CC="${CC:-ccache gcc}"
  export CXX="${CXX:-ccache g++}"
  log "активирован ccache в ${CCACHE_DIR}"
fi

# Настройки платформы
UNAME_S="$(uname -s)"
if [[ "${UNAME_S}" == "Darwin" && -z "${MACOSX_DEPLOYMENT_TARGET:-}" ]]; then
  export MACOSX_DEPLOYMENT_TARGET="11.0"
  log "MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET}"
fi

ensure_dir "${DIST_DIR}"

# Установка инструментов (если разрешено)
maybe_install() {
  local pkgs=("$@")
  if [[ "${INSTALL_TOOLS}" == "true" ]]; then
    log "установка инструментов: ${pkgs[*]}"
    run "${PY}" -m pip install -U "${pkgs[@]}"
  else
    log "пропуск установки инструментов (--no-install)"
  fi
}

# ---------- Сборка по бэкендам ----------
build_setuptools() {
  maybe_install build
  log "сборка (setuptools/hatchling через PEP 517 build)..."
  run "${PY}" -m build --wheel --outdir "${DIST_DIR}"
}

build_hatch() {
  maybe_install hatch hatchling
  log "сборка (hatch)..."
  run "${PY}" -m hatch build -t wheel -t sdist
  # Переместим артефакты, если hatch положил их не в dist/
  ensure_dir "${DIST_DIR}"
}

build_scikit() {
  maybe_install "scikit-build-core[pyproject]" cmake ninja build
  log "сборка (scikit-build-core)..."
  # Параллель задаётся CMAKE_BUILD_PARALLEL_LEVEL
  run "${PY}" -m build --wheel --outdir "${DIST_DIR}"
}

build_meson() {
  maybe_install meson-python ninja build
  log "сборка (meson-python)..."
  run "${PY}" -m build --wheel --outdir "${DIST_DIR}"
}

build_maturin() {
  local prof="--release"; [[ "${MODE}" == "debug" ]] && prof="--debug"
  maybe_install maturin
  log "сборка (maturin) ${prof}, потоков: ${JOBS_N}"
  # Если есть Cargo.lock — используем --locked
  local locked=""; [[ -f "${REPO_ROOT}/Cargo.lock" ]] && locked="--locked"
  run "${PY}" -m maturin build ${prof} ${locked} -j "${JOBS_N}" --interpreter "${PY}" --out "${DIST_DIR}" --strip
}

case "${BACKEND}" in
  setuptools) build_setuptools;;
  hatch)      build_hatch;;
  scikit-build) build_scikit;;
  meson)      build_meson;;
  maturin)    build_maturin;;
  *) die "неподдерживаемый бэкенд: ${BACKEND}";;
esac

ok "сборка завершена. Артефакты в: ${DIST_DIR}"

# ---------- Починка колёс (опционально) ----------
repair_linux() {
  maybe_install auditwheel
  local wh
  shopt -s nullglob
  for wh in "${DIST_DIR}"/*.whl; do
    log "auditwheel repair ${wh}"
    run "${PY}" -m auditwheel repair "${wh}" -w "${REPO_ROOT}/wheelhouse"
  done
  shopt -u nullglob
}

repair_macos() {
  # delocate лучше ставить в системный python (подойдёт и текущий)
  maybe_install delocate
  local wh
  shopt -s nullglob
  for wh in "${DIST_DIR}"/*.whl; do
    log "delocate-wheel ${wh}"
    run delocate-wheel -w "${REPO_ROOT}/wheelhouse" "${wh}"
  done
  shopt -u nullglob
}

if [[ "${REPAIR}" == "true" ]]; then
  case "${UNAME_S}" in
    Linux)  repair_linux;;
    Darwin) repair_macos;;
    *) warn "постобработка колёс не поддержана на платформе: ${UNAME_S}";;
  esac
  ok "починка выполнена. Колёса в: ${REPO_ROOT}/wheelhouse"
fi

# ---------- Сводка ----------
summary() {
  echo
  echo "${C_BOLD}Сводка:${C_RST}"
  echo "  Бэкенд:      ${BACKEND}"
  echo "  Режим:       ${MODE}"
  echo "  Python:      ${PY} (${PY_VER})"
  echo "  Потоки:      ${JOBS_N}"
  echo "  Артефакты:   ${DIST_DIR}"
  [[ "${REPAIR}" == "true" ]] && echo "  Wheelhouse:  ${REPO_ROOT}/wheelhouse"
}
summary
