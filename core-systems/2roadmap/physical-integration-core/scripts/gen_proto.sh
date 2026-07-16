#!/usr/bin/env bash
# physical-integration-core/scripts/gen_proto.sh
# Industrial-grade protobuf/gRPC codegen with caching, plugin validation, and Docker fallback.
# Supported: Go, Python, JS, TS (ts-proto), gRPC-Web
# Dependencies (native path): protoc >= 3.21, optional: buf >= 1.30, Docker
# Plugins (if language enabled):
#   Go:       protoc-gen-go, protoc-gen-go-grpc
#   Python:   grpc_python_plugin (usually bundled with grpcio-tools) or python_out+grpc_python_out via plugin
#   JS:       protoc-gen-js
#   TS:       protoc-gen-ts (ts-proto)  OR grpc-web via protoc-gen-grpc-web
#   gRPC-Web: protoc-gen-grpc-web
set -Eeuo pipefail

# -----------------------------
# Defaults (overridable via env)
# -----------------------------
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROTO_SRC_DIR="${PROTO_SRC_DIR:-${PROJECT_ROOT}/proto}"
OUT_BASE_DIR="${OUT_BASE_DIR:-${PROJECT_ROOT}/generated}"
INCLUDE_DIRS_DEFAULT="${INCLUDE_DIRS_DEFAULT:-${PROTO_SRC_DIR}}"
INCLUDE_DIRS="${INCLUDE_DIRS:-${INCLUDE_DIRS_DEFAULT}}"

# Languages: comma-separated list among: go,python,js,ts,grpc-web
LANGS="${LANGS:-go,python,ts,grpc-web}"

# Options
CLEAN="${CLEAN:-0}"                # 1 — очистить выходные директории перед генерацией
USE_DOCKER="${USE_DOCKER:-0}"      # 1 — использовать Docker+buf независимо от наличия локального protoc
BUF_IMAGE="${BUF_IMAGE:-ghcr.io/bufbuild/buf:1.45.0}"  # pinned version
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
CACHE_DIR="${CACHE_DIR:-${OUT_BASE_DIR}/._cache}"
LOG_DIR="${LOG_DIR:-${OUT_BASE_DIR}/_logs}"
HASH_FILE="${CACHE_DIR}/inputs.hash"

# Per-language out directories
GO_OUT="${GO_OUT:-${OUT_BASE_DIR}/go}"
PY_OUT="${PY_OUT:-${OUT_BASE_DIR}/python}"
JS_OUT="${JS_OUT:-${OUT_BASE_DIR}/js}"
TS_OUT="${TS_OUT:-${OUT_BASE_DIR}/ts}"
WEB_OUT="${WEB_OUT:-${OUT_BASE_DIR}/web}"

# Additional Options
GO_MODULE="${GO_MODULE:-github.com/example/physical-integration-core/generated/go}"
TS_FLAVOR="${TS_FLAVOR:-ts-proto}"  # ts-proto | grpc-web-ts
GRPC_WEB_MODE="${GRPC_WEB_MODE:-import_style=typescript,mode=grpcwebtext}" # for protoc-gen-grpc-web
PROTOC_MIN_VERSION="${PROTOC_MIN_VERSION:-3.21.0}"

# -----------------------------
# Helpers
# -----------------------------
log() { printf '[gen-proto] %s\n' "$*" | tee -a "${LOG_DIR}/gen_proto.log" >&2; }
die() { printf '[gen-proto][ERROR] %s\n' "$*" | tee -a "${LOG_DIR}/gen_proto.log" >&2; exit 1; }

verlte() { [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }
verify_protoc_version() {
  local v
  v="$(protoc --version 2>/dev/null | awk '{print $2}')" || return 1
  verlte "${PROTOC_MIN_VERSION}" "${v}"
}

print_usage() {
  cat <<EOF
Usage: $(basename "$0") [--langs go,python,js,ts,grpc-web] [--clean] [--docker] [--jobs N] [--proto-dir DIR] [--include DIR[,DIR2...]]
Env overrides are supported. Current:
  LANGS=${LANGS}
  CLEAN=${CLEAN}
  USE_DOCKER=${USE_DOCKER}
  JOBS=${JOBS}
  PROTO_SRC_DIR=${PROTO_SRC_DIR}
  INCLUDE_DIRS=${INCLUDE_DIRS}
  OUT_BASE_DIR=${OUT_BASE_DIR}
EOF
}

# -----------------------------
# Parse CLI
# -----------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) print_usage; exit 0 ;;
    --clean) CLEAN=1; shift ;;
    --docker) USE_DOCKER=1; shift ;;
    --langs) LANGS="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --proto-dir) PROTO_SRC_DIR="$2"; shift 2 ;;
    --include) INCLUDE_DIRS="$2"; shift 2 ;;
    --out) OUT_BASE_DIR="$2"; shift 2 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

mkdir -p "${OUT_BASE_DIR}" "${CACHE_DIR}" "${LOG_DIR}"

# -----------------------------
# Discovery
# -----------------------------
IFS=$'\n' read -r -d '' -a PROTO_FILES < <(find "${PROTO_SRC_DIR}" -type f -name '*.proto' ! -path '*/vendor/*' ! -path '*/generated/*' -print0 | xargs -0 -I{} echo {} && printf '\0')
[[ "${#PROTO_FILES[@]}" -gt 0 ]] || die "No .proto files found in ${PROTO_SRC_DIR}"

# -----------------------------
# Compute Inputs Hash (cache key)
# -----------------------------
hash_inputs() {
  local tmp="${CACHE_DIR}/inputs.tmp"
  : > "${tmp}"
  printf 'protoc_min=%s\n' "${PROTOC_MIN_VERSION}" >> "${tmp}"
  printf 'langs=%s\n' "${LANGS}" >> "${tmp}"
  printf 'ts_flavor=%s\n' "${TS_FLAVOR}" >> "${tmp}"
  printf 'grpc_web_mode=%s\n' "${GRPC_WEB_MODE}" >> "${tmp}"
  printf 'includes=%s\n' "${INCLUDE_DIRS}" >> "${tmp}"

  # plugin versions (best-effort)
  { command -v protoc-gen-go >/dev/null && printf 'pg_go=%s\n' "$(protoc-gen-go --version 2>/dev/null || echo 'na')"; } || true
  { command -v protoc-gen-go-grpc >/dev/null && printf 'pg_go_grpc=%s\n' "$(protoc-gen-go-grpc --version 2>/dev/null || echo 'na')"; } || true
  { command -v protoc-gen-grpc-web >/dev/null && printf 'pg_web=%s\n' "$(protoc-gen-grpc-web --version 2>/dev/null || echo 'na')"; } || true
  { command -v protoc-gen-ts >/dev/null && printf 'pg_ts=%s\n' "$(protoc-gen-ts --version 2>/dev/null || echo 'na')"; } || true
  { command -v protoc-gen-js >/dev/null && printf 'pg_js=%s\n' "$(protoc-gen-js --version 2>/dev/null || echo 'na')"; } || true
  { command -v buf >/dev/null && printf 'buf=%s\n' "$(buf --version 2>/dev/null || echo 'na')"; } || true

  # proto contents hash
  for f in "${PROTO_FILES[@]}"; do
    printf '%s %s\n' "$(sha256sum "$f" | awk '{print $1}')" "$f" >> "${tmp}"
  done

  sha256sum "${tmp}" | awk '{print $1}'
}

CURRENT_HASH="$(hash_inputs)"
LAST_HASH="$(cat "${HASH_FILE}" 2>/dev/null || true)"

if [[ "${CLEAN}" -eq 1 ]]; then
  log "Cleaning output dirs…"
  rm -rf "${GO_OUT}" "${PY_OUT}" "${JS_OUT}" "${TS_OUT}" "${WEB_OUT}"
fi

if [[ "${CURRENT_HASH}" = "${LAST_HASH}" && "${CLEAN}" -eq 0 ]]; then
  log "Cache unchanged. Skipping codegen."
  exit 0
fi

# -----------------------------
# Validate toolchain or Docker
# -----------------------------
NEED_DOCKER=0
if [[ "${USE_DOCKER}" -eq 1 ]]; then
  NEED_DOCKER=1
else
  if ! command -v protoc >/dev/null || ! verify_protoc_version; then
    log "protoc not found or version < ${PROTOC_MIN_VERSION}. Will use Docker fallback."
    NEED_DOCKER=1
  fi
fi

if [[ "${NEED_DOCKER}" -eq 1 ]]; then
  command -v docker >/dev/null || die "Docker is required for Docker fallback but not found."
fi

# Validate plugins when using native pipeline
plugin_required() {
  local bin="$1"
  command -v "${bin}" >/dev/null || die "Required plugin missing: ${bin}"
}

contains_lang() { [[ ",${LANGS}," == *",$1,"* ]]; }

if [[ "${NEED_DOCKER}" -eq 0 ]]; then
  # Go
  if contains_lang "go"; then
    plugin_required protoc-gen-go
    plugin_required protoc-gen-go-grpc
  fi
  # Python: grpc plugin is commonly in PATH as `grpc_python_plugin` or provided by grpcio-tools via python -m grpc_tools.protoc
  # We'll prefer native protoc plugin path; Docker fallback covers the rest via buf.
  # JS
  if contains_lang "js"; then
    plugin_required protoc-gen-js
  fi
  # TS (ts-proto) OR grpc-web-ts
  if contains_lang "ts" && [[ "${TS_FLAVOR}" == "ts-proto" ]]; then
    plugin_required protoc-gen-ts
  fi
  # gRPC-Web
  if contains_lang "grpc-web"; then
    plugin_required protoc-gen-grpc-web
  fi
fi

# -----------------------------
# Prepare output dirs
# -----------------------------
mkdir -p "${GO_OUT}" "${PY_OUT}" "${JS_OUT}" "${TS_OUT}" "${WEB_OUT}"

# -----------------------------
# INCLUDES
# -----------------------------
PROTOC_INCLUDE_ARGS=()
IFS=',' read -r -a _inc <<< "${INCLUDE_DIRS}"
for d in "${_inc[@]}"; do
  [[ -d "${d}" ]] || die "Include dir not found: ${d}"
  PROTOC_INCLUDE_ARGS+=("-I" "${d}")
done

# -----------------------------
# Execution helpers
# -----------------------------
run_native_protoc() {
  local args=("$@")
  protoc "${PROTOC_INCLUDE_ARGS[@]}" "${args[@]}"
}

run_buf_docker() {
  # We mount project root as /work and execute buf generate if buf config exists,
  # else run protoc inside the container.
  local work="/work"
  local run=(docker run --rm -u "$(id -u):$(id -g)" -v "${PROJECT_ROOT}:${work}" -w "${work}" "${BUF_IMAGE}")
  "${run[@]}" "$@"
}

# -----------------------------
# Codegen per language (native)
# -----------------------------
gen_go_native() {
  log "Generating Go…"
  run_native_protoc \
    --go_out="${GO_OUT}" --go_opt=paths=source_relative,module="${GO_MODULE}" \
    --go-grpc_out="${GO_OUT}" --go-grpc_opt=paths=source_relative,module="${GO_MODULE}" \
    "${PROTO_FILES[@]}" | tee -a "${LOG_DIR}/go.log"
}

gen_python_native() {
  log "Generating Python…"
  # python_out generates dataclasses; grpc generation via plugin if available.
  if command -v grpc_python_plugin >/dev/null; then
    run_native_protoc \
      --python_out="${PY_OUT}" \
      --grpc_python_out="${PY_OUT}" \
      --plugin=protoc-gen-grpc_python="$(command -v grpc_python_plugin)" \
      "${PROTO_FILES[@]}" | tee -a "${LOG_DIR}/python.log"
  else
    # fallback to python stubs only; (grpc stubs can be built via Docker or separate tool)
    run_native_protoc \
      --python_out="${PY_OUT}" \
      "${PROTO_FILES[@]}" | tee -a "${LOG_DIR}/python.log"
  fi
}

gen_js_native() {
  log "Generating JS…"
  run_native_protoc \
    --js_out="import_style=commonjs,binary:${JS_OUT}" \
    "${PROTO_FILES[@]}" | tee -a "${LOG_DIR}/js.log"
}

gen_ts_native() {
  if [[ "${TS_FLAVOR}" == "ts-proto" ]]; then
    log "Generating TS via ts-proto…"
    run_native_protoc \
      --ts_out "${TS_OUT}" \
      --ts_opt esModuleInterop=true,outputServices=grpc-js,outputJsonMethods=false \
      "${PROTO_FILES[@]}" | tee -a "${LOG_DIR}/ts.log"
  else
    log "Generating TS via grpc-web-ts…"
    # This branch is usually covered by grpc-web plugin producing .ts:
    run_native_protoc \
      --grpc-web_out="${GRPC_WEB_MODE}:${TS_OUT}" \
      "${PROTO_FILES[@]}" | tee -a "${LOG_DIR}/ts.log"
  fi
}

gen_grpc_web_native() {
  log "Generating gRPC-Web…"
  run_native_protoc \
    --grpc-web_out="${GRPC_WEB_MODE}:${WEB_OUT}" \
    --js_out="import_style=commonjs,binary:${WEB_OUT}" \
    "${PROTO_FILES[@]}" | tee -a "${LOG_DIR}/web.log"
}

# -----------------------------
# Docker (buf) pipeline
# -----------------------------
gen_with_buf_docker() {
  log "Using Docker with buf image: ${BUF_IMAGE}"
  # If buf config is present, prefer buf generate (requires buf.gen.yaml or buf.gen.yaml + buf.yaml)
  if [[ -f "${PROJECT_ROOT}/buf.yaml" || -f "${PROJECT_ROOT}/buf.gen.yaml" || -f "${PROJECT_ROOT}/buf.gen.yml" ]]; then
    log "Detected buf config. Running buf generate…"
    run_buf_docker buf generate | tee -a "${LOG_DIR}/buf.log"
    return
  fi

  # Otherwise, emulate protoc calls inside container.
  # Construct include args for inside container (mirror paths).
  local inside_includes=()
  for d in "${_inc[@]}"; do
    # Map host ${PROJECT_ROOT} -> /work; ensure include path is inside root
    local rel="${d#${PROJECT_ROOT}}"
    [[ "${d}" == "${PROJECT_ROOT}"* ]] || die "Include path must be within project root for Docker fallback: ${d}"
    inside_includes+=("-I" "/work${rel}")
  done

  # Build file list relative to /work
  local rel_files=()
  for f in "${PROTO_FILES[@]}"; do
    [[ "${f}" == "${PROJECT_ROOT}"* ]] || die "Proto file outside project root: ${f}"
    rel_files+=("/work${f#${PROJECT_ROOT}}")
  done

  # Go
  if contains_lang "go"; then
    log "Docker: Go…"
    run_buf_docker protoc "${inside_includes[@]}" \
      --go_out="/work${GO_OUT#${PROJECT_ROOT}}" --go_opt=paths=source_relative,module="${GO_MODULE}" \
      --go-grpc_out="/work${GO_OUT#${PROJECT_ROOT}}" --go-grpc_opt=paths=source_relative,module="${GO_MODULE}" \
      "${rel_files[@]}" | tee -a "${LOG_DIR}/go.log"
  fi
  # Python
  if contains_lang "python"; then
    log "Docker: Python…"
    run_buf_docker protoc "${inside_includes[@]}" \
      --python_out="/work${PY_OUT#${PROJECT_ROOT}}" \
      --grpc_python_out="/work${PY_OUT#${PROJECT_ROOT}}" \
      "${rel_files[@]}" | tee -a "${LOG_DIR}/python.log"
  fi
  # JS
  if contains_lang "js"; then
    log "Docker: JS…"
    run_buf_docker protoc "${inside_includes[@]}" \
      --js_out="import_style=commonjs,binary:/work${JS_OUT#${PROJECT_ROOT}}" \
      "${rel_files[@]}" | tee -a "${LOG_DIR}/js.log"
  fi
  # TS via grpc-web
  if contains_lang "ts"; then
    if [[ "${TS_FLAVOR}" == "ts-proto" ]]; then
      log "Docker: TS via ts-proto not supported by buf image by default. Skipping TS (use native protoc-gen-ts) or set TS_FLAVOR=grpc-web-ts."
    else
      log "Docker: TS via grpc-web-ts…"
      run_buf_docker protoc "${inside_includes[@]}" \
        --grpc-web_out="${GRPC_WEB_MODE}:/work${TS_OUT#${PROJECT_ROOT}}" \
        "${rel_files[@]}" | tee -a "${LOG_DIR}/ts.log"
    fi
  fi
  # gRPC-Web
  if contains_lang "grpc-web"; then
    log "Docker: gRPC-Web…"
    run_buf_docker protoc "${inside_includes[@]}" \
      --grpc-web_out="${GRPC_WEB_MODE}:/work${WEB_OUT#${PROJECT_ROOT}}" \
      --js_out="import_style=commonjs,binary:/work${WEB_OUT#${PROJECT_ROOT}}" \
      "${rel_files[@]}" | tee -a "${LOG_DIR}/web.log"
  fi
}

# -----------------------------
# Run generation
# -----------------------------
log "Starting protobuf codegen"
log "Languages: ${LANGS}"
log "Proto dir: ${PROTO_SRC_DIR}"
log "Includes: ${INCLUDE_DIRS}"
log "Output: ${OUT_BASE_DIR}"
log "Jobs: ${JOBS}"

if [[ "${NEED_DOCKER}" -eq 1 ]]; then
  gen_with_buf_docker
else
  # Native path (run per-language)
  contains_lang "go"        && gen_go_native
  contains_lang "python"    && gen_python_native
  contains_lang "js"        && gen_js_native
  contains_lang "ts"        && gen_ts_native
  contains_lang "grpc-web"  && gen_grpc_web_native
fi

# -----------------------------
# Post-processing
# -----------------------------
# Normalize permissions for CI artifacts
find "${OUT_BASE_DIR}" -type d -exec chmod 755 {} \; || true
find "${OUT_BASE_DIR}" -type f -exec chmod 644 {} \; || true

# Save hash to cache
echo "${CURRENT_HASH}" > "${HASH_FILE}"
log "Codegen completed. Cache updated."

# Summary
log "Generated trees:"
for d in "${GO_OUT}" "${PY_OUT}" "${JS_OUT}" "${TS_OUT}" "${WEB_OUT}"; do
  [[ -d "${d}" ]] && log " - ${d}"
done
