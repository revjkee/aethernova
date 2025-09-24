#!/usr/bin/env bash
# veilmind-core — промышленная генерация кода из Protobuf/gRPC
# Поддержка: Python, Go, TypeScript (grpc-web|ts-proto), Java. Lint/breaking: buf (если доступен).
# Fallback: Docker-образ protoc при отсутствии локальных плагинов.

set -euo pipefail

# ---------------------------
# Конфигурация по умолчанию
# ---------------------------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="${PROTO_DIR:-${ROOT_DIR}/proto}"
GEN_DIR="${GEN_DIR:-${ROOT_DIR}/generated}"
DESC_DIR="${DESC_DIR:-${GEN_DIR}/descriptors}"
CACHE_DIR="${CACHE_DIR:-${ROOT_DIR}/.cache/proto}"
BUF_CONFIG="${BUF_CONFIG:-${ROOT_DIR}/buf.yaml}" # опционально

# Языковые флаги (все выключены => включить все)
WITH_PY=false
WITH_GO=false
WITH_TS=false
WITH_JAVA=false

# Режимы
CLEAN=false
DOCKER_FALLBACK=true
TS_IMPL="${TS_IMPL:-grpc-web}"   # grpc-web|ts-proto
TS_OUT_SUBDIR="${TS_OUT_SUBDIR:-ts}"
PY_OUT_SUBDIR="${PY_OUT_SUBDIR:-python}"
GO_OUT_SUBDIR="${GO_OUT_SUBDIR:-go}"
JAVA_OUT_SUBDIR="${JAVA_OUT_SUBDIR:-java}"
DESC_FILE="${DESC_DIR}/bundle.pb"

# Версии для Docker fallback (пинованные)
DOCKER_PROTOC_IMAGE="${DOCKER_PROTOC_IMAGE:-ghcr.io/namely/docker-protoc:3.21-1}" # включает плагины go/java/python/grpc-web
DOCKER_USER="$(id -u):$(id -g)"

# ---------------------------
# Помощь
# ---------------------------
usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --py                 Сгенерировать Python (protoc + grpc_python)
  --go                 Сгенерировать Go (protoc-gen-go, protoc-gen-go-grpc)
  --ts                 Сгенерировать TypeScript (grpc-web или ts-proto, см. TS_IMPL)
  --java               Сгенерировать Java
  --all                Сгенерировать для всех поддерживаемых языков
  --clean              Очистить каталог generated перед сборкой
  --no-docker          Отключить Docker fallback (требуются локальные плагины)
  --proto-dir DIR      Каталог с .proto (default: ${PROTO_DIR})
  --gen-dir DIR        Каталог для вывода (default: ${GEN_DIR})
  --buf                Принудительно запускать buf lint/breaking (если установлен)
  --no-buf             Пропустить buf даже если установлен
  -h, --help           Печать этой справки

Env:
  TS_IMPL=grpc-web|ts-proto      Выбор генератора TS (default: grpc-web)
  DOCKER_PROTOC_IMAGE=<image>    Образ для fallback (default: ${DOCKER_PROTOC_IMAGE})

Examples:
  $0 --all
  $0 --py --go --clean
  PROTO_DIR=./apis PROTO_INCLUDE=./third_party $0 --ts
EOF
}

# ---------------------------
# Парсинг аргументов
# ---------------------------
USE_BUF="auto"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --py) WITH_PY=true ;;
    --go) WITH_GO=true ;;
    --ts) WITH_TS=true ;;
    --java) WITH_JAVA=true ;;
    --all) WITH_PY=true; WITH_GO=true; WITH_TS=true; WITH_JAVA=true ;;
    --clean) CLEAN=true ;;
    --no-docker) DOCKER_FALLBACK=false ;;
    --proto-dir) PROTO_DIR="$(realpath "$2")"; shift ;;
    --gen-dir) GEN_DIR="$(realpath "$2")"; shift ;;
    --buf) USE_BUF="on" ;;
    --no-buf) USE_BUF="off" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

if ! $WITH_PY && ! $WITH_GO && ! $WITH_TS && ! $WITH_JAVA; then
  # если ничего не выбрано — генерируем всё
  WITH_PY=true; WITH_GO=true; WITH_TS=true; WITH_JAVA=true
fi

# ---------------------------
# Проверки окружения
# ---------------------------
err() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[gen_proto] $*"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

[[ -d "$PROTO_DIR" ]] || err "Каталог с .proto не найден: ${PROTO_DIR}"

# Список .proto
mapfile -t PROTO_FILES < <(find "$PROTO_DIR" -type f -name '*.proto' ! -path '*/\.*' | sort)
[[ ${#PROTO_FILES[@]} -gt 0 ]] || err "В ${PROTO_DIR} не найдено .proto файлов"

mkdir -p "$GEN_DIR" "$DESC_DIR" "$CACHE_DIR"

if $CLEAN; then
  info "Очистка каталога ${GEN_DIR}"
  rm -rf "${GEN_DIR:?}/"*
  mkdir -p "$DESC_DIR"
fi

# ---------------------------
# Lint и breaking через buf (если доступен/нужен)
# ---------------------------
run_buf=false
if [[ "$USE_BUF" == "on" ]]; then
  run_buf=true
elif [[ "$USE_BUF" == "auto" && -f "$BUF_CONFIG" && $(command_exists buf && echo yes || echo no) == "yes" ]]; then
  run_buf=true
fi

if $run_buf; then
  info "buf lint…"
  buf lint || err "buf lint обнаружил проблемы"
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    # сравниваем с основной веткой, если задана
    BASE_REF="${BASE_REF:-origin/master}"
    if git rev-parse "$BASE_REF" >/dev/null 2>&1; then
      info "buf breaking (сравнение с ${BASE_REF})…"
      buf breaking --against ".git#branch=$(basename "$BASE_REF")" || err "buf breaking обнаружил несовместимые изменения"
    fi
  fi
fi

# ---------------------------
# Подготовка include-путей
# ---------------------------
INCLUDES=(-I "$PROTO_DIR")
# Дополнительные include каталоги можно передать через PROTO_INCLUDE (через пробел)
if [[ -n "${PROTO_INCLUDE:-}" ]]; then
  for p in $PROTO_INCLUDE; do
    INCLUDES+=(-I "$(realpath "$p")")
  done
fi

# ---------------------------
# Функции генерации
# ---------------------------
PROTOC_BIN="protoc"
USE_DOCKER=false
if ! command_exists "$PROTOC_BIN"; then
  if $DOCKER_FALLBACK; then
    USE_DOCKER=true
    info "protoc не найден — будет использован Docker fallback (${DOCKER_PROTOC_IMAGE})"
  else
    err "protoc не найден и Docker fallback отключён (--no-docker)"
  fi
fi

docker_protoc() {
  # $@: дополнительные аргументы к protoc
  docker run --rm -u "${DOCKER_USER}" \
    -v "${PROTO_DIR}:/defs:ro" \
    -v "${GEN_DIR}:/out" \
    -v "${CACHE_DIR}:/cache" \
    "${DOCKER_PROTOC_IMAGE}" \
      -I /defs "$@" || return $?
}

local_protoc() {
  # shellcheck disable=SC2068
  "$PROTOC_BIN" ${INCLUDES[@]} "$@" || return $?
}

run_protoc() {
  if $USE_DOCKER; then
    docker_protoc "$@"
  else
    # shellcheck disable=SC2068
    local_protoc $@
  fi
}

# Дескрипторный набор (детерминированная сборка)
info "Генерация descriptor set: ${DESC_FILE}"
run_protoc --include_imports --include_source_info \
  "${INCLUDES[@]}" \
  -o "${DESC_FILE}" \
  "${PROTO_FILES[@]}"

# ---------------------------
# Python
# ---------------------------
if $WITH_PY; then
  OUT_PY="${GEN_DIR}/${PY_OUT_SUBDIR}"
  mkdir -p "$OUT_PY"
  info "Python: генерация в ${OUT_PY}"

  PY_ARGS=(--python_out="${OUT_PY}" --grpc_python_out="${OUT_PY}")
  # Дополнительные опции для детерминированного импорта можно задать через env: PY_PROTOC_OPTS
  if [[ -n "${PY_PROTOC_OPTS:-}" ]]; then
    IFS=' ' read -r -a extra <<< "${PY_PROTOC_OPTS}"; PY_ARGS+=("${extra[@]}")
  fi

  run_protoc "${INCLUDES[@]}" "${PY_ARGS[@]}" "${PROTO_FILES[@]}"

  # Поддержка pkg (инициализация модулей)
  find "${OUT_PY}" -type d -exec sh -c '[ -f "$1/__init__.py" ] || : > "$1/__init__.py"' _ {} \;
fi

# ---------------------------
# Go
# ---------------------------
if $WITH_GO; then
  OUT_GO="${GEN_DIR}/${GO_OUT_SUBDIR}"
  mkdir -p "$OUT_GO"
  info "Go: генерация в ${OUT_GO}"

  if ! $USE_DOCKER; then
    command_exists protoc-gen-go || err "protoc-gen-go не найден"
    command_exists protoc-gen-go-grpc || err "protoc-gen-go-grpc не найден"
  fi

  # go_package учитывается из option go_package в .proto
  GO_ARGS=(--go_out="${OUT_GO}" --go-grpc_out="${OUT_GO}")
  if [[ -n "${GO_PROTOC_OPTS:-}" ]]; then
    IFS=' ' read -r -a extra <<< "${GO_PROTOC_OPTS}"; GO_ARGS+=("${extra[@]}")
  fi
  run_protoc "${INCLUDES[@]}" "${GO_ARGS[@]}" "${PROTO_FILES[@]}"

  # go mod tidy подсказка (не выполняем автоматически)
fi

# ---------------------------
# TypeScript
# ---------------------------
if $WITH_TS; then
  OUT_TS="${GEN_DIR}/${TS_OUT_SUBDIR}"
  mkdir -p "$OUT_TS"
  info "TypeScript (${TS_IMPL}): генерация в ${OUT_TS}"

  case "${TS_IMPL}" in
    grpc-web)
      # Нужен плагин protoc-gen-grpc-web (локально или в docker-образе)
      if ! $USE_DOCKER; then
        command_exists protoc-gen-grpc-web || err "protoc-gen-grpc-web не найден"
      fi
      run_protoc "${INCLUDES[@]}" \
        --js_out="import_style=commonjs,binary:${OUT_TS}" \
        --grpc-web_out="import_style=typescript,mode=grpcweb:${OUT_TS}" \
        "${PROTO_FILES[@]}"
      ;;
    ts-proto)
      # Нужен protoc-gen-ts_proto (npm i -g ts-proto, либо node_modules/.bin в PATH)
      if ! $USE_DOCKER; then
        command_exists protoc-gen-ts_proto || err "protoc-gen-ts_proto не найден"
      fi
      # Пример опций ts-proto можно расширить через TS_PROTO_OPTS
      TS_PROTO_ARGS="esModuleInterop=true,outputServices=grpc-js,env=node"
      if [[ -n "${TS_PROTO_OPTS:-}" ]]; then
        TS_PROTO_ARGS="${TS_PROTO_ARGS},${TS_PROTO_OPTS}"
      fi
      run_protoc "${INCLUDES[@]}" \
        --ts_proto_out="${OUT_TS}" \
        --ts_proto_opt="${TS_PROTO_ARGS}" \
        "${PROTO_FILES[@]}"
      ;;
    *)
      err "Неизвестный TS_IMPL: ${TS_IMPL} (поддерживается grpc-web|ts-proto)"
      ;;
  esac
fi

# ---------------------------
# Java
# ---------------------------
if $WITH_JAVA; then
  OUT_JAVA="${GEN_DIR}/${JAVA_OUT_SUBDIR}"
  mkdir -p "$OUT_JAVA"
  info "Java: генерация в ${OUT_JAVA}"

  if ! $USE_DOCKER; then
    # локально требуется protoc-gen-grpc-java
    command_exists protoc-gen-grpc-java || err "protoc-gen-grpc-java не найден"
  fi

  run_protoc "${INCLUDES[@]}" \
    --java_out="${OUT_JAVA}" \
    --grpc-java_out="${OUT_JAVA}" \
    "${PROTO_FILES[@]}"
fi

# ---------------------------
# Результаты
# ---------------------------
info "Готово. Артефакты:"
echo " - descriptors: ${DESC_FILE}"
$WITH_PY && echo " - python:     ${GEN_DIR}/${PY_OUT_SUBDIR}"
$WITH_GO && echo " - go:         ${GEN_DIR}/${GO_OUT_SUBDIR}"
$WITH_TS && echo " - ts:         ${GEN_DIR}/${TS_OUT_SUBDIR}"
$WITH_JAVA && echo " - java:       ${GEN_DIR}/${JAVA_OUT_SUBDIR}"
