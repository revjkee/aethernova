#!/usr/bin/env bash
# Industrial-grade Protobuf/gRPC generator for policy-core
# Supports: protoc / buf / Docker fallback
# Languages: python, go, ts (ts-proto or grpc-web), java
# Copyright: Aethernova

set -Eeuo pipefail

########################################
# Globals & Defaults
########################################
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# Defaults (can be overridden by env)
SRC_DIR="${PROTO_SRC_DIR:-${REPO_ROOT}/proto}"
INCLUDE_DIRS_DEFAULT="${PROTO_INCLUDE_DIRS:-${SRC_DIR}:${REPO_ROOT}/third_party}"
OUT_DIR="${PROTO_OUT_DIR:-${REPO_ROOT}/generated}"
LANGS="${PROTO_LANGS:-python,go,ts,java}"
BUF_MODE="${PROTO_USE_BUF:-false}"           # true/false or --buf flag
DOCKER_FALLBACK="${PROTO_DOCKER_FALLBACK:-true}"
CLEAN="${PROTO_CLEAN:-false}"
CACHE_DIR="${PROTO_CACHE_DIR:-${REPO_ROOT}/.cache}"
HASH_FILE="${CACHE_DIR}/proto.sha256"
PARALLEL_JOBS="${PROTO_JOBS:-0}"             # 0 = auto (no xargs parallelization here)
GRPC_WEB_MODE="${PROTO_TS_WEB_MODE:-auto}"   # auto|ts-proto|grpc-web
TS_OUT_STYLE="${PROTO_TS_OUT_STYLE:-esm}"    # esm|commonjs (for grpc-web)
GO_SOURCE_REL="${PROTO_GO_SOURCE_REL:-true}" # true-> paths=source_relative
JAVA_PKG_OPT="${PROTO_JAVA_PKG_OPT:-}"       # e.g. "multiple_files=true"
VERBOSE="${VERBOSE:-false}"

########################################
# Colors
########################################
if [ -t 1 ]; then
  tput setaf 2 >/dev/null && GREEN=$(tput setaf 2) || GREEN=""
  tput setaf 3 >/dev/null && YELLOW=$(tput setaf 3) || YELLOW=""
  tput setaf 1 >/dev/null && RED=$(tput setaf 1) || RED=""
  tput sgr0    >/dev/null && RESET=$(tput sgr0)    || RESET=""
else
  GREEN=""; YELLOW=""; RED=""; RESET=""
fi

log()  { echo -e "${GREEN}[gen-proto]${RESET} $*"; }
warn() { echo -e "${YELLOW}[gen-proto] WARN:${RESET} $*" >&2; }
err()  { echo -e "${RED}[gen-proto] ERROR:${RESET} $*" >&2; }

die() {
  err "$*"
  exit 1
}

trap 'err "unexpected error on line $LINENO"; exit 1' ERR

########################################
# Usage
########################################
usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --src <dir>             Path to proto sources (default: ${SRC_DIR})
  --out <dir>             Output directory for generated code (default: ${OUT_DIR})
  --langs <csv>           Languages to generate: python,go,ts,java (default: ${LANGS})
  --includes <csv>        Additional include dirs (colon- or comma-separated). Default: ${INCLUDE_DIRS_DEFAULT}
  --buf                   Use buf toolchain (lint + generate). Requires buf.{yaml,gen.yaml}
  --no-buf                Disable buf mode explicitly
  --docker-fallback       Use Docker fallback if protoc/plugins missing (default: ${DOCKER_FALLBACK})
  --no-docker             Disable docker fallback (fail fast if missing)
  --clean                 Clean output dir before generation (default: ${CLEAN})
  --jobs <N>              Parallel jobs (reserved, not used in plain protoc flow) default: ${PARALLEL_JOBS}
  --ts-web-mode <m>       TS mode: auto|ts-proto|grpc-web (default: ${GRPC_WEB_MODE})
  --ts-out-style <m>      TS grpc-web module style: esm|commonjs (default: ${TS_OUT_STYLE})
  --go-source-rel <bool>  go_out paths=source_relative (default: ${GO_SOURCE_REL})
  --java-pkg-opt <str>    Java generator options, e.g. "multiple_files=true" (default: empty)
  --verbose               Verbose logging
  -h|--help               This help

Env overrides:
  PROTO_SRC_DIR, PROTO_OUT_DIR, PROTO_INCLUDE_DIRS, PROTO_LANGS, PROTO_USE_BUF,
  PROTO_DOCKER_FALLBACK, PROTO_CLEAN, PROTO_CACHE_DIR, PROTO_TS_WEB_MODE,
  PROTO_TS_OUT_STYLE, PROTO_GO_SOURCE_REL, PROTO_JOBS, PROTO_JAVA_PKG_OPT, VERBOSE

Examples:
  $0 --langs python,go --clean
  PROTO_USE_BUF=true $0
  PROTO_TS_WEB_MODE=grpc-web PROTO_TS_OUT_STYLE=esm $0 --langs ts
EOF
}

########################################
# Parse args
########################################
INCLUDE_DIRS="${INCLUDE_DIRS_DEFAULT}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --src) SRC_DIR="$2"; shift 2;;
    --out) OUT_DIR="$2"; shift 2;;
    --langs) LANGS="$2"; shift 2;;
    --includes) INCLUDE_DIRS="$2"; shift 2;;
    --buf) BUF_MODE="true"; shift;;
    --no-buf) BUF_MODE="false"; shift;;
    --docker-fallback) DOCKER_FALLBACK="true"; shift;;
    --no-docker) DOCKER_FALLBACK="false"; shift;;
    --clean) CLEAN="true"; shift;;
    --jobs) PARALLEL_JOBS="$2"; shift 2;;
    --ts-web-mode) GRPC_WEB_MODE="$2"; shift 2;;
    --ts-out-style) TS_OUT_STYLE="$2"; shift 2;;
    --go-source-rel) GO_SOURCE_REL="$2"; shift 2;;
    --java-pkg-opt) JAVA_PKG_OPT="$2"; shift 2;;
    --verbose) VERBOSE="true"; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown option: $1";;
  esac
done

########################################
# Helpers
########################################
split_csv() {
  local IFS=,
  read -ra ARR <<<"$1"
  for i in "${ARR[@]}"; do
    echo "$i"
  done
}

canon_includes() {
  # allow comma or colon separators
  local s="$1"
  s="${s//,/ }"
  s="${s//:/ }"
  echo "$s"
}

ensure_dirs() {
  mkdir -p "${OUT_DIR}" "${CACHE_DIR}"
}

proto_files() {
  find "${SRC_DIR}" -type f -name '*.proto' | LC_ALL=C sort
}

hash_protos() {
  # Hash includes content & toolchain markers
  (
    proto_files | xargs -r cat
    echo "INCLUDES=$(canon_includes "${INCLUDE_DIRS}")"
    echo "LANGS=${LANGS}"
    echo "BUF_MODE=${BUF_MODE}"
    echo "GRPC_WEB_MODE=${GRPC_WEB_MODE}"
    echo "GO_SOURCE_REL=${GO_SOURCE_REL}"
    echo "JAVA_PKG_OPT=${JAVA_PKG_OPT}"
    if command -v protoc >/dev/null 2>&1; then protoc --version || true; fi
    if command -v buf >/dev/null 2>&1; then buf --version || true; fi
  ) | sha256sum | awk '{print $1}'
}

print_versions() {
  log "Environment:"
  command -v protoc >/dev/null 2>&1 && log "  protoc: $(protoc --version)" || warn "  protoc: not found"
  command -v buf >/dev/null 2>&1    && log "  buf:    $(buf --version)"     || log  "  buf: not used"
  command -v docker >/dev/null 2>&1 && log "  docker: available"            || warn "  docker: not found"
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

########################################
# Clean if requested
########################################
ensure_dirs
if [[ "${CLEAN}" == "true" ]]; then
  log "Cleaning output dir: ${OUT_DIR}"
  rm -rf "${OUT_DIR:?}/"*
fi

########################################
# Fast skip via hash
########################################
NEW_HASH="$(hash_protos)"
if [[ -f "${HASH_FILE}" ]]; then
  OLD_HASH="$(cat "${HASH_FILE}")"
else
  OLD_HASH=""
fi

########################################
# No proto files -> exit
########################################
if ! proto_files >/dev/null; then
  die "No .proto files found in ${SRC_DIR}"
fi

########################################
# Print versions
########################################
print_versions
[[ "${VERBOSE}" == "true" ]] && set -x

########################################
# buf path
########################################
run_with_buf() {
  # Requires buf.yaml and buf.gen.yaml at repo or SRC_DIR root
  local root
  if [[ -f "${REPO_ROOT}/buf.yaml" ]]; then
    root="${REPO_ROOT}"
  elif [[ -f "${SRC_DIR}/buf.yaml" ]]; then
    root="${SRC_DIR}"
  else
    die "--buf requested but buf.yaml not found in ${REPO_ROOT} or ${SRC_DIR}"
  fi

  log "Running buf lint..."
  (cd "${root}" && buf lint)

  log "Running buf generate..."
  (cd "${root}" && buf generate)
}

########################################
# protoc local or docker
########################################
PROTOC_BIN=""
protoc_detect() {
  if has_cmd protoc; then
    PROTOC_BIN="protoc"
    return 0
  fi
  if [[ "${DOCKER_FALLBACK}" == "true" ]] && has_cmd docker; then
    # Use bufbuild/protoc image (tiny & current)
    PROTOC_BIN="docker run --rm -u $(id -u):$(id -g) -v ${REPO_ROOT}:${REPO_ROOT} -w ${REPO_ROOT} ghcr.io/bufbuild/protoc:latest protoc"
    return 0
  fi
  return 1
}

protoc_includes() {
  local incs=()
  for p in $(canon_includes "${INCLUDE_DIRS}"); do
    incs+=("-I" "${p}")
  done
  printf '%q ' "${incs[@]}"
}

########################################
# Language generators
########################################

gen_python() {
  local out="${OUT_DIR}/python"
  mkdir -p "${out}"
  # Validate plugins presence if local (docker image includes basic python)
  if ! ${PROTOC_BIN} --help >/dev/null 2>&1; then
    die "protoc not available"
  fi

  # Some distributions require explicit plugin, but protoc detects python by --python_out
  ${PROTOC_BIN} $(protoc_includes) --python_out="${out}" --grpc_python_out="${out}" $(proto_files)
  # Optional: mypy stubs if plugin exists
  if has_cmd protoc-gen-mypy || [[ "${PROTOC_BIN}" == docker* ]]; then
    ${PROTOC_BIN} $(protoc_includes) --mypy_out="${out}" $(proto_files) || true
  fi
  log "Python stubs -> ${out}"
}

gen_go() {
  local out="${OUT_DIR}/go"
  mkdir -p "${out}"
  local go_opts="paths=source_relative"
  [[ "${GO_SOURCE_REL}" == "false" ]] && go_opts=""

  # Need protoc-gen-go and protoc-gen-go-grpc on PATH (except in docker image that has them preinstalled)
  if [[ "${PROTOC_BIN}" != docker* ]]; then
    has_cmd protoc-gen-go || die "protoc-gen-go not found; install: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
    has_cmd protoc-gen-go-grpc || die "protoc-gen-go-grpc not found; install: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
  fi

  ${PROTOC_BIN} $(protoc_includes) --go_out="${out}" --go_opt="${go_opts}" \
    --go-grpc_out="${out}" --go-grpc_opt="${go_opts}" $(proto_files)
  log "Go stubs -> ${out}"
}

ts_mode_detect() {
  local mode="${GRPC_WEB_MODE}"
  if [[ "${mode}" == "auto" ]]; then
    if has_cmd protoc-gen-ts_proto; then
      mode="ts-proto"
    elif has_cmd protoc-gen-grpc-web; then
      mode="grpc-web"
    else
      # In docker image we don't know; prefer grpc-web
      mode="grpc-web"
    fi
  fi
  echo "${mode}"
}

gen_ts() {
  local out="${OUT_DIR}/ts"
  mkdir -p "${out}"
  local mode
  mode="$(ts_mode_detect)"
  case "${mode}" in
    ts-proto)
      # ts-proto plugin name can be protoc-gen-ts_proto
      if [[ "${PROTOC_BIN}" != docker* ]]; then
        has_cmd protoc-gen-ts_proto || die "protoc-gen-ts_proto not found (ts-proto). Install: npm i -g ts-proto"
      fi
      ${PROTOC_BIN} $(protoc_includes) \
        --ts_proto_out="${out}" \
        --ts_proto_opt=esModuleInterop=true,env=node,outputServices=grpc-js,outputJsonMethods=false \
        $(proto_files)
      log "TS (ts-proto) stubs -> ${out}"
      ;;
    grpc-web)
      # protoc-gen-grpc-web required locally
      if [[ "${PROTOC_BIN}" != docker* ]]; then
        has_cmd protoc-gen-grpc-web || die "protoc-gen-grpc-web not found. Install: npm i -g protoc-gen-grpc-web"
      fi
      local mstyle="${TS_OUT_STYLE}"
      ${PROTOC_BIN} $(protoc_includes) \
        --js_out="import_style=${mstyle},binary:${out}" \
        --grpc-web_out="import_style=${mstyle},mode=grpcwebtext:${out}" \
        $(proto_files)
      log "TS (grpc-web) stubs -> ${out}"
      ;;
    *)
      die "Unknown TS mode: ${mode}"
      ;;
  esac
}

gen_java() {
  local out="${OUT_DIR}/java"
  mkdir -p "${out}"
  local jopt=()
  [[ -n "${JAVA_PKG_OPT}" ]] && jopt=(--java_opt="${JAVA_PKG_OPT}")

  # grpc-java plugin name: protoc-gen-grpc-java
  if [[ "${PROTOC_BIN}" != docker* ]]; then
    has_cmd protoc-gen-grpc-java || warn "protoc-gen-grpc-java not found; generating Java POJOs only"
  fi

  ${PROTOC_BIN} $(protoc_includes) --java_out="${out}" "${jopt[@]}" $(proto_files)

  if has_cmd protoc-gen-grpc-java || [[ "${PROTOC_BIN}" == docker* ]]; then
    ${PROTOC_BIN} $(protoc_includes) --grpc-java_out="${out}" $(proto_files) || true
  fi
  log "Java stubs -> ${out}"
}

########################################
# Main flow
########################################

# If buf requested, run and store hash if changed
if [[ "${BUF_MODE}" == "true" ]]; then
  has_cmd buf || die "buf requested but not found on PATH"
  run_with_buf
  echo "${NEW_HASH}" > "${HASH_FILE}"
  log "Done via buf."
  exit 0
fi

# protoc path
protoc_detect || die "protoc not found and docker fallback disabled"

# Skip if hash unchanged
if [[ "${NEW_HASH}" == "${OLD_HASH}" ]]; then
  log "No changes in proto sources; skipping generation."
  exit 0
fi

# Build include flags
INCLUDE_FLAGS=()
for inc in $(canon_includes "${INCLUDE_DIRS}"); do
  [[ -d "${inc}" ]] || warn "Include dir not found: ${inc}"
done

# Generate per language
for lang in $(split_csv "${LANGS}"); do
  case "${lang}" in
    python) gen_python ;;
    go)     gen_go ;;
    ts)     gen_ts ;;
    java)   gen_java ;;
    *) warn "Unknown language '${lang}', skipping" ;;
  esac
done

echo "${NEW_HASH}" > "${HASH_FILE}"
log "Generation finished. Output: ${OUT_DIR}"
