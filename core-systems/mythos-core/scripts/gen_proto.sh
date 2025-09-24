#!/usr/bin/env bash
# Mythos Core — Protobuf/gRPC codegen
# Industrial-grade generator with lint/breaking checks, multi-lang targets, and Docker fallback.

set -Eeuo pipefail

# -----------------------------
# Defaults (override via ENV)
# -----------------------------
: "${PROTO_SRC:=./proto}"                    # Корень .proto
: "${GEN_ROOT:=./generated}"                 # Корень артефактов
: "${OUT_PY:=${GEN_ROOT}/python}"            # Python out
: "${OUT_GO:=${GEN_ROOT}/go}"                # Go out
: "${OUT_TS:=${GEN_ROOT}/ts}"                # TypeScript out (ts-proto)
: "${OUT_DOCS:=${GEN_ROOT}/docs}"            # Документация (опц.)
: "${INCLUDE_PATHS:=./proto:./third_party}"  # Доп. инклюды через ':'
: "${BUF_CONFIG:=./buf.yaml}"                # buf конфиг
: "${BUF_LOCK:=./buf.lock}"                  # buf lock
: "${BREAKING_BASE:=main}"                   # ветка/реф для breaking-check
: "${DOCKER_IMAGE_PROTOC:=bufbuild/buf:latest}" # Docker-образ для fallback
: "${GO_PKG_PREFIX:=github.com/org/mythos-core/gen/go}" # go_package prefix
: "${TS_PROTOC_PLUGIN:=protoc-gen-ts}"       # Имя плагина для TS (ts-proto)
: "${TS_TARGET:=es6}"                        # Цель TS
: "${LOG_LEVEL:=info}"                       # debug|info|warn

# -----------------------------
# UI helpers
# -----------------------------
log() { printf ":: %s :: %s\n" "${1^^}" "${2:-}"; }
die() { log "error" "$1"; exit 1; }

# Отладочный вывод команд при LOG_LEVEL=debug
if [[ "${LOG_LEVEL}" == "debug" ]]; then
  set -x
fi

# -----------------------------
# Tooling detection
# -----------------------------
has() { command -v "$1" >/dev/null 2>&1; }

need() {
  local bin="$1"
  has "$bin" || die "Требуется '${bin}', но он не найден в PATH"
}

# Проверяем protoc и плагины по мере необходимости
check_toolchain_base() {
  need protoc
  log info "protoc: $(protoc --version)"
}

check_buf() {
  if has buf; then
    log info "buf: $(buf --version)"
    [[ -f "${BUF_CONFIG}" ]] || die "Не найден ${BUF_CONFIG}"
    [[ -f "${BUF_LOCK}" ]] || log warn "buf.lock не найден — рекомендовано зафиксировать зависимости"
  else
    log warn "buf не найден — lint/breaking-check будут недоступны локально"
  fi
}

# -----------------------------
# Paths & sanity
# -----------------------------
normalize_paths() {
  mkdir -p "${GEN_ROOT}" "${OUT_PY}" "${OUT_GO}" "${OUT_TS}" "${OUT_DOCS}"
  [[ -d "${PROTO_SRC}" ]] || die "Каталог с .proto не найден: ${PROTO_SRC}"
}

includes_args() {
  local args=()
  IFS=':' read -r -a arr <<< "${INCLUDE_PATHS}"
  for p in "${arr[@]}"; do
    [[ -d "${p}" ]] && args+=( -I "${p}" )
  done
  # Всегда добавляем корень исходников
  args+=( -I "${PROTO_SRC}" )
  printf "%s " "${args[@]}"
}

list_protos() {
  # Находим все .proto в PROTO_SRC
  find "${PROTO_SRC}" -type f -name "*.proto" -print0 | sort -z | xargs -0 -I{} echo "{}"
}

# -----------------------------
# Language-specific generators
# -----------------------------
gen_python() {
  log info "Генерация Python (grpc + messages) -> ${OUT_PY}"
  need python3
  python3 - <<'PY'
import sys, pkgutil
want = ("grpc_tools",)
missing = [m for m in want if pkgutil.find_loader(m) is None]
if missing:
    sys.stderr.write("Missing Python modules: %r (pip install grpcio-tools)\n" % (missing,))
    sys.exit(2)
PY
  local inc; inc=$(includes_args)
  local files; files=$(list_protos)
  # Опции детерминированной сборки
  protoc ${inc} \
    --python_out="${OUT_PY}" \
    --grpc_python_out="${OUT_PY}" \
    ${files}
  # Патчим импорты (relative) для пакетов, если нужно
  fix_py_imports "${OUT_PY}"
}

fix_py_imports() {
  local root="$1"
  # Делает каталоги пакетами
  find "${root}" -type d -exec sh -c '[ -f "$0/__init__.py" ] || : > "$0/__init__.py"' {} \;
}

gen_go() {
  log info "Генерация Go (google.golang.org/protobuf + grpc) -> ${OUT_GO}"
  need protoc-gen-go
  need protoc-gen-go-grpc
  local inc; inc=$(includes_args)
  local files; files=$(list_protos)
  # go_package должен быть прописан в .proto; при необходимости задаём M-мэппинги
  protoc ${inc} \
    --go_out="module=${GO_PKG_PREFIX}:${OUT_GO}" \
    --go-grpc_out="module=${GO_PKG_PREFIX}:${OUT_GO}" \
    ${files}
}

gen_ts() {
  log info "Генерация TypeScript (ts-proto) -> ${OUT_TS}"
  need "${TS_PROTOC_PLUGIN}"
  local inc; inc=$(includes_args)
  local files; files=$(list_protos)
  # ts-proto через стандартный protoc плагин
  protoc ${inc} \
    --plugin="protoc-gen-ts=$(command -v ${TS_PROTOC_PLUGIN})" \
    --ts_out="${OUT_TS}" \
    --ts_opt=esModuleInterop=true,outputServices=grpc-js,env=node,target="${TS_TARGET}",useExactTypes=false \
    ${files}
}

gen_docs() {
  # Опционально: сгенерировать markdown из proto (если есть плагин protoc-gen-doc)
  if has protoc-gen-doc; then
    log info "Генерация документации -> ${OUT_DOCS}"
    local inc; inc=$(includes_args)
    local files; files=$(list_protos)
    protoc ${inc} \
      --doc_out="${OUT_DOCS}" \
      --doc_opt=markdown,API.md \
      ${files}
  else
    log warn "protoc-gen-doc не найден — пропускаю генерацию документации"
  fi
}

# -----------------------------
# Buf-based flows
# -----------------------------
lint() {
  if has buf; then
    log info "buf lint"
    buf lint
  else
    die "buf не установлен — lint недоступен. Установите: https://buf.build"
  fi
}

breaking_check() {
  if has buf; then
    log info "buf breaking (against ${BREAKING_BASE})"
    # Требует доступ к git и предыдущему состоянию API (ветка/тег)
    buf breaking --against ".git#ref=${BREAKING_BASE}"
  else
    die "buf не установлен — breaking-check недоступен."
  fi
}

# -----------------------------
# Deterministic manifest
# -----------------------------
manifest() {
  log info "Формирую manifest SHA256 для ${GEN_ROOT}"
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum не найден"
  (
    cd "${GEN_ROOT}"
    # Создаем стабильный список файлов (без manifest самого себя)
    find . -type f ! -name "MANIFEST.sha256" -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256
  )
}

# -----------------------------
# Cleaning
# -----------------------------
clean() {
  log warn "Очистка ${GEN_ROOT}"
  rm -rf "${GEN_ROOT}"
  mkdir -p "${GEN_ROOT}"
}

# -----------------------------
# Docker fallback
# -----------------------------
docker_run() {
  need docker
  log info "Docker fallback: ${DOCKER_IMAGE_PROTOC}"
  docker run --rm -it \
    -v "$(pwd)":/work \
    -w /work \
    "${DOCKER_IMAGE_PROTOC}" \
    bash -lc "BUF_CACHE_DIR=/work/.bufcache ./scripts/gen_proto.sh ${*:-all}"
}

# -----------------------------
# Orchestrators
# -----------------------------
generate_all() {
  check_toolchain_base
  normalize_paths
  # Линт перед генерацией, если доступен buf
  has buf && lint || log warn "lint пропущен"
  gen_python
  gen_go
  gen_ts
  gen_docs
  manifest
  log info "Готово. Артефакты: ${GEN_ROOT}"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

Commands:
  all           — сгенерировать всё (python, go, ts, docs) + manifest
  python        — только Python
  go            — только Go
  ts            — только TypeScript (ts-proto)
  docs          — только документация (protoc-gen-doc)
  lint          — buf lint
  breaking      — buf breaking (against \$BREAKING_BASE, default: ${BREAKING_BASE})
  clean         — удалить ${GEN_ROOT}
  docker [cmd]  — запустить внутри Docker образа (${DOCKER_IMAGE_PROTOC}), cmd по умолчанию 'all'

ENV override:
  PROTO_SRC, GEN_ROOT, OUT_PY, OUT_GO, OUT_TS, OUT_DOCS, INCLUDE_PATHS,
  BUF_CONFIG, BUF_LOCK, BREAKING_BASE, DOCKER_IMAGE_PROTOC, GO_PKG_PREFIX,
  TS_PROTOC_PLUGIN, TS_TARGET, LOG_LEVEL

Examples:
  PROTO_SRC=./proto INCLUDE_PATHS="./proto:./third_party" ./scripts/gen_proto.sh all
  ./scripts/gen_proto.sh lint
  ./scripts/gen_proto.sh breaking
  ./scripts/gen_proto.sh docker all
EOF
}

# -----------------------------
# Main
# -----------------------------
main() {
  check_buf || true
  local cmd="${1:-all}"
  case "${cmd}" in
    all)        generate_all ;;
    python)     check_toolchain_base; normalize_paths; gen_python; manifest ;;
    go)         check_toolchain_base; normalize_paths; gen_go; manifest ;;
    ts)         check_toolchain_base; normalize_paths; gen_ts; manifest ;;
    docs)       check_toolchain_base; normalize_paths; gen_docs; manifest ;;
    lint)       lint ;;
    breaking)   breaking_check ;;
    clean)      clean ;;
    docker)     shift || true; docker_run "$@" ;;
    -h|--help|help) usage ;;
    *)
      usage; die "Неизвестная команда: ${cmd}"
      ;;
  esac
}

main "$@"
