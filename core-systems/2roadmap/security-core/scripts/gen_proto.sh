#!/usr/bin/env bash
# ==============================================================================
# security-core :: gen_proto.sh
# Промышленная генерация Protobuf/gRPC артефактов с приоритетом на Buf.
# Поддержка: Buf/protoc, Python/Go/TypeScript, инкрементальная сборка,
# параллелизм, Docker fallback, строгий режим, безопасные пути.
# SPDX-License-Identifier: Apache-2.0
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

# ------------------------------- Defaults -------------------------------------

# Автоматически определяем директории
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_CORE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
PROJECT_ROOT="$(cd -- "${SECURITY_CORE_DIR}/.." && pwd)"

# Источники .proto
PROTO_SRC="${PROTO_SRC:-${SECURITY_CORE_DIR}/proto}"
THIRD_PARTY_PROTO="${THIRD_PARTY_PROTO:-${PROJECT_ROOT}/third_party/proto}"

# Директория для артефактов
OUT_DIR="${OUT_DIR:-${SECURITY_CORE_DIR}/generated}"

# Языки для генерации: python,go,ts (через ts-proto)
LANGS="${LANGS:-python,go,ts}"

# Инкрементальная сборка на основе checksum
CACHE_DIR="${CACHE_DIR:-${SECURITY_CORE_DIR}/.cache}"
HASH_FILE="${HASH_FILE:-${CACHE_DIR}/proto.sha256}"
FORCE="${FORCE:-0}"

# Параллелизм
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

# Приоритет Buf, если найден buf.yaml или buf.gen.yaml
PREFER_BUF="${PREFER_BUF:-1}"

# Fallback в Docker при отсутствии локальных инструментов
DOCKER_FALLBACK="${DOCKER_FALLBACK:-1}"

# Закреплённые версии инструментов (для Docker по умолчанию)
BUF_IMAGE="${BUF_IMAGE:-ghcr.io/bufbuild/buf:1.45.0}"
PROTOC_IMAGE="${PROTOC_IMAGE:-ghcr.io/namely/docker-protoc:4.28.2-1}"

# Плагины и версии (ожидаются локально при protoc-режиме)
GO_PB_VER="${GO_PB_VER:-v1.33.0}"
GO_GRPC_VER="${GO_GRPC_VER:-v1.4.0}"
TS_PLUGIN_MODE="${TS_PLUGIN_MODE:-ts-proto}"   # ts-proto | grpc-web
# Путь до node_modules/.bin (для ts-proto/grpc-web)
NPM_BIN="${NPM_BIN:-$(command -v npm >/dev/null 2>&1 && npm bin 2>/dev/null || echo "${PROJECT_ROOT}/node_modules/.bin")}"

# Лог-уровень: INFO|DEBUG
LOG_LEVEL="${LOG_LEVEL:-INFO}"

# ------------------------------- Logging --------------------------------------

log() {
  local level="$1"; shift
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "[${ts}] [${level}] $*" >&2
}

debug() { [[ "${LOG_LEVEL}" == "DEBUG" ]] && log "DEBUG" "$@" || true; }
info()  { log "INFO"  "$@"; }
warn()  { log "WARN"  "$@"; }
err()   { log "ERROR" "$@"; }

die() { err "$@"; exit 1; }

# ------------------------------ Helpers ---------------------------------------

join_by() { local IFS="$1"; shift; echo "$*"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_dir() { mkdir -p "$1"; }

cleanup() { :; } # hook
trap cleanup EXIT

usage() {
  cat <<'USAGE'
Usage: scripts/gen_proto.sh [options]

Options:
  LANGS=python,go,ts         Кома-разделенный список языков (python|go|ts)
  PROTO_SRC=...              Каталог с .proto (по умолчанию security-core/proto)
  THIRD_PARTY_PROTO=...      Каталог с внешними .proto (по умолчанию project/third_party/proto)
  OUT_DIR=...                Каталог для артефактов (по умолчанию security-core/generated)
  PREFER_BUF=1               1 — использовать Buf при наличии конфигурации
  DOCKER_FALLBACK=1          1 — fallback в Docker при отсутствии инструментов
  JOBS=N                     Количество параллельных задач (по умолчанию CPU count)
  FORCE=1                    Игнорировать кеш и пересобрать всё
  LOG_LEVEL=DEBUG            Включить подробный лог
USAGE
}

# ------------------------------ Discovery -------------------------------------

detect_buf_mode() {
  local cfg1="${PROTO_SRC}/buf.yaml"
  local cfg2="${PROTO_SRC}/buf.gen.yaml"
  local cfg3="${PROJECT_ROOT}/buf.yaml"
  local cfg4="${PROJECT_ROOT}/buf.gen.yaml"
  if [[ "${PREFER_BUF}" == "1" ]] && { [[ -f "${cfg1}" || -f "${cfg3}" ]] || [[ -f "${cfg2}" || -f "${cfg4}" ]]; }; then
    echo "1"
  else
    echo "0"
  fi
}

list_proto_files() {
  find "${PROTO_SRC}" -type f -name '*.proto' | LC_ALL=C sort
}

compute_hash() {
  # Хэшируем содержимое всех .proto + конфигурации buf (если есть)
  local tmp
  tmp="$(mktemp)"
  list_proto_files | xargs -I{} sh -c 'sha256sum "{}" || shasum -a256 "{}"' 2>/dev/null | awk '{print $1}' >> "${tmp}" || true
  if [[ -f "${PROTO_SRC}/buf.yaml" ]]; then cat "${PROTO_SRC}/buf.yaml" | sha256sum | awk '{print $1}' >> "${tmp}"; fi 2>/dev/null || true
  if [[ -f "${PROTO_SRC}/buf.gen.yaml" ]]; then cat "${PROTO_SRC}/buf.gen.yaml" | sha256sum | awk '{print $1}' >> "${tmp}"; fi 2>/dev/null || true
  if [[ -f "${PROJECT_ROOT}/buf.yaml" ]]; then cat "${PROJECT_ROOT}/buf.yaml" | sha256sum | awk '{print $1}' >> "${tmp}"; fi 2>/dev/null || true
  if [[ -f "${PROJECT_ROOT}/buf.gen.yaml" ]]; then cat "${PROJECT_ROOT}/buf.gen.yaml" | sha256sum | awk '{print $1}' >> "${tmp}"; fi 2>/dev/null || true
  sha256sum "${tmp}" 2>/dev/null | awk '{print $1}'
  rm -f "${tmp}"
}

cache_ok() {
  [[ "${FORCE}" == "1" ]] && return 1
  [[ -f "${HASH_FILE}" ]] || return 1
  local cur
  cur="$(compute_hash)"
  local prev
  prev="$(cat "${HASH_FILE}" 2>/dev/null || echo '')"
  [[ "${cur}" == "${prev}" ]]
}

cache_store() {
  ensure_dir "$(dirname "${HASH_FILE}")"
  compute_hash > "${HASH_FILE}"
}

# ------------------------------ Tool checks -----------------------------------

check_protoc_stack() {
  has_cmd protoc || return 1
  info "Found protoc: $(protoc --version | awk '{print $2}')"
  return 0
}

check_buf_stack() {
  has_cmd buf || return 1
  info "Found buf: $(buf --version | awk '{print $1}')"
  return 0
}

check_go_plugins() {
  has_cmd protoc-gen-go && has_cmd protoc-gen-go-grpc
}

check_python_plugin() {
  # Для Python достаточно protoc + стандартные параметры
  return 0
}

check_ts_plugin() {
  case "${TS_PLUGIN_MODE}" in
    ts-proto)
      [[ -x "${NPM_BIN}/protoc-gen-ts_proto" ]] && return 0
      ;;
    grpc-web)
      [[ -x "${NPM_BIN}/protoc-gen-grpc-web" ]] && return 0
      ;;
    *)
      return 1
      ;;
  esac
  return 1
}

# ------------------------------ Docker wrappers -------------------------------

docker_run_buf() {
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -v "${PROJECT_ROOT}:${PROJECT_ROOT}" \
    -w "${PROTO_SRC}" \
    "${BUF_IMAGE}" "$@"
}

docker_run_protoc() {
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -v "${PROJECT_ROOT}:${PROJECT_ROOT}" \
    -w "${PROJECT_ROOT}" \
    "${PROTOC_IMAGE}" "$@"
}

# ------------------------------ Generators ------------------------------------

generate_with_buf() {
  info "Using Buf pipeline"
  # buf format + lint для стабильности
  docker_flag=0
  if check_buf_stack; then
    buf format -w "${PROTO_SRC}"
    buf lint "${PROTO_SRC}"
    buf generate "${PROTO_SRC}"
  else
    [[ "${DOCKER_FALLBACK}" == "1" ]] || die "buf is not installed and DOCKER_FALLBACK=0"
    info "buf not found, using Docker image ${BUF_IMAGE}"
    docker_flag=1
    docker_run_buf format -w .
    docker_run_buf lint .
    docker_run_buf generate .
  fi
  info "Buf generation completed"
}

# protoc path flags
protoc_include_flags() {
  local flags=()
  flags+=("-I" "${PROTO_SRC}")
  [[ -d "${THIRD_PARTY_PROTO}" ]] && flags+=("-I" "${THIRD_PARTY_PROTO}")
  echo "$(join_by ' ' "${flags[@]}")"
}

generate_python() {
  info "Generating Python"
  local out="${OUT_DIR}/python"
  ensure_dir "${out}"
  local inc; inc="$(protoc_include_flags)"

  if check_protoc_stack; then
    list_proto_files | xargs -P "${JOBS}" -I{} \
      bash -c "protoc ${inc} --python_out='${out}' --grpc_python_out='${out}' '{}'"
  else
    [[ "${DOCKER_FALLBACK}" == "1" ]] || die "protoc not found and DOCKER_FALLBACK=0"
    info "protoc not found, using Docker image ${PROTOC_IMAGE} for Python"
    list_proto_files | xargs -P "${JOBS}" -I{} \
      bash -c "docker run --rm -u $(id -u):$(id -g) -v ${PROJECT_ROOT}:${PROJECT_ROOT} -w ${PROJECT_ROOT} ${PROTOC_IMAGE} \
        -I ${PROTO_SRC} $( [[ -d ${THIRD_PARTY_PROTO} ]] && echo -I ${THIRD_PARTY_PROTO} ) \
        --python_out=${out} --grpc_out=${out} --plugin=protoc-gen-grpc=/usr/bin/grpc_python_plugin {}"
  fi
}

generate_go() {
  info "Generating Go"
  local out="${OUT_DIR}/go"
  ensure_dir "${out}"
  local inc; inc="$(protoc_include_flags)"

  if check_protoc_stack && check_go_plugins; then
    list_proto_files | xargs -P "${JOBS}" -I{} \
      bash -c "protoc ${inc} --go_out='${out}' --go-grpc_out='${out}' '{}'"
  else
    [[ "${DOCKER_FALLBACK}" == "1" ]] || die "protoc/go-plugins not found and DOCKER_FALLBACK=0"
    info "protoc or go plugins not found, using Docker image ${PROTOC_IMAGE} for Go"
    list_proto_files | xargs -P "${JOBS}" -I{} \
      bash -c "docker run --rm -u $(id -u):$(id -g) -v ${PROJECT_ROOT}:${PROJECT_ROOT} -w ${PROJECT_ROOT} ${PROTOC_IMAGE} \
        -I ${PROTO_SRC} $( [[ -d ${THIRD_PARTY_PROTO} ]] && echo -I ${THIRD_PARTY_PROTO} ) \
        --go_out=${out} --go-grpc_out=${out} {}"
  fi
}

generate_ts() {
  info "Generating TypeScript (${TS_PLUGIN_MODE})"
  local out="${OUT_DIR}/ts"
  ensure_dir "${out}"
  local inc; inc="$(protoc_include_flags)"

  case "${TS_PLUGIN_MODE}" in
    ts-proto)
      local plugin="${NPM_BIN}/protoc-gen-ts_proto"
      [[ -x "${plugin}" ]] || {
        [[ "${DOCKER_FALLBACK}" == "1" ]] || die "ts-proto plugin not found and DOCKER_FALLBACK=0"
        info "ts-proto not found. Using Docker image ${PROTOC_IMAGE} with mounted node_modules is not supported out-of-the-box."
        die "Install ts-proto locally (npm i -D ts-proto) or set TS_PLUGIN_MODE=grpc-web"
      }
      if check_protoc_stack; then
        list_proto_files | xargs -P "${JOBS}" -I{} \
          bash -c "protoc ${inc} --plugin=protoc-gen-ts_proto='${plugin}' --ts_proto_out='${out}' --ts_proto_opt=esModuleInterop=true,useExactTypes=false '{}'"
      else
        [[ "${DOCKER_FALLBACK}" == "1" ]] || die "protoc not found and DOCKER_FALLBACK=0"
        info "protoc not found; Docker mode cannot access host ts-proto plugin path reliably."
        die 'Install protoc locally or use TS_PLUGIN_MODE=grpc-web with Docker-capable plugin.'
      fi
      ;;
    grpc-web)
      local plugin="${NPM_BIN}/protoc-gen-grpc-web"
      [[ -x "${plugin}" ]] || {
        [[ "${DOCKER_FALLBACK}" == "1" ]] || die "grpc-web plugin not found and DOCKER_FALLBACK=0"
        info "grpc-web not found; Docker mode for grpc-web is not configured in this script."
        die 'Install protoc-gen-grpc-web locally (npm i -D protoc-gen-grpc-web).'
      }
      if check_protoc_stack; then
        list_proto_files | xargs -P "${JOBS}" -I{} \
          bash -c "protoc ${inc} --js_out=import_style=commonjs,binary:'${out}' --grpc-web_out=import_style=typescript,mode=grpcwebtext:'${out}' --plugin=protoc-gen-grpc-web='${plugin}' '{}'"
      else
        [[ "${DOCKER_FALLBACK}" == "1" ]] || die "protoc not found and DOCKER_FALLBACK=0"
        die 'Docker path for grpc-web is not configured. Install local protoc or switch to ts-proto.'
      fi
      ;;
    *)
      die "Unknown TS_PLUGIN_MODE: ${TS_PLUGIN_MODE}"
      ;;
  esac
}

# ------------------------------ Main flow -------------------------------------

main() {
  # Подгружаем .env при наличии (без ошибок)
  if [[ -f "${SECURITY_CORE_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${SECURITY_CORE_DIR}/.env"
    set +a
  fi

  [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }

  [[ -d "${PROTO_SRC}" ]] || die "PROTO_SRC not found: ${PROTO_SRC}"
  ensure_dir "${OUT_DIR}"

  info "Project root: ${PROJECT_ROOT}"
  info "Module root:  ${SECURITY_CORE_DIR}"
  info "Proto src:    ${PROTO_SRC}"
  [[ -d "${THIRD_PARTY_PROTO}" ]] && info "3rd-party:     ${THIRD_PARTY_PROTO}" || true
  info "Out dir:      ${OUT_DIR}"
  info "Langs:        ${LANGS}"
  info "Jobs:         ${JOBS}"
  info "Prefer Buf:   ${PREFER_BUF}"
  info "Docker FB:    ${DOCKER_FALLBACK}"

  if cache_ok; then
    info "No changes in proto sources. Skipping generation."
    exit 0
  fi

  local use_buf
  use_buf="$(detect_buf_mode)"

  if [[ "${use_buf}" == "1" ]]; then
    generate_with_buf
    cache_store
    info "Done (buf)."
    exit 0
  fi

  info "Buf config not found or PREFER_BUF=0. Falling back to protoc."

  # Проверяем наличие protoc или Docker fallback
  if ! check_protoc_stack; then
    [[ "${DOCKER_FALLBACK}" == "1" ]] || die "protoc not found and DOCKER_FALLBACK=0"
    warn "protoc not found; Docker image ${PROTOC_IMAGE} will be used where possible."
  fi

  # Генерация по языкам
  IFS=',' read -r -a langs <<< "${LANGS}"
  for lang in "${langs[@]}"; do
    case "${lang}" in
      python) generate_python ;;
      go)     generate_go ;;
      ts)     generate_ts ;;
      *)      die "Unsupported language: ${lang}" ;;
    esac
  done

  cache_store
  info "Done (protoc)."
}

main "$@"
