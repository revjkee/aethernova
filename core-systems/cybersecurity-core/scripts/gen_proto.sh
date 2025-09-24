#!/usr/bin/env bash
# cybersecurity-core/scripts/gen_proto.sh
# Industrial-grade Protobuf/gRPC code generator for Python, Go, TypeScript, Java.

set -Eeuo pipefail

# --------------------------- Config & Defaults --------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

SRC_DIRS=("proto")                 # default proto sources relative to repo root
OUT_BASE="generated"               # base out dir relative to repo root
LANGS=("python" "go" "ts" "java")  # default languages
WITH_GRPC="true"
CLEAN="false"
BOOTSTRAP="false"
VERBOSE="false"
FORCE="false"

CACHE_DIR="${REPO_ROOT}/.cache/proto"
HASH_FILE="${CACHE_DIR}/last.hash"

# Optional third-party include path (e.g., google/api, openapiv3, etc.)
THIRD_PARTY_DIR="${REPO_ROOT}/third_party/proto"

# --------------------------- Colorful Logging ---------------------------------
: "${NO_COLOR:=}"
if [[ -t 1 && -z "${NO_COLOR}" ]]; then
  c_reset=$'\033[0m'; c_dim=$'\033[2m'; c_red=$'\033[31m'; c_green=$'\033[32m'; c_yellow=$'\033[33m'; c_blue=$'\033[34m'
else
  c_reset=""; c_dim=""; c_red=""; c_green=""; c_yellow=""; c_blue=""
fi

log()  { echo "${c_dim}[$(date +'%H:%M:%S')]${c_reset} $*"; }
info() { echo "${c_blue}[INFO]${c_reset} $*"; }
ok()   { echo "${c_green}[OK]${c_reset} $*"; }
warn() { echo "${c_yellow}[WARN]${c_reset} $*"; }
err()  { echo "${c_red}[ERROR]${c_reset} $*" >&2; }

trap 'err "Generation failed on line $LINENO"; exit 1' ERR

# --------------------------- Helpers ------------------------------------------
usage() {
  cat <<'USAGE'
gen_proto.sh — Industrial Protobuf/gRPC generator

Usage:
  scripts/gen_proto.sh [options]

Options:
  --src DIR            Add proto source directory (can be repeated). Default: proto
  --out DIR            Base output directory (relative to repo). Default: generated
  --langs LIST         Comma-separated languages: python,go,ts,java,all. Default: python,go,ts,java
  --no-grpc            Disable gRPC service stubs (messages only where applicable)
  --clean              Remove generated outputs and exit
  --bootstrap          Attempt to install missing generator plugins (pip/go/npm)
  --force              Ignore cache and regenerate
  --verbose            Verbose logging
  -h, --help           Show this help

Examples:
  scripts/gen_proto.sh --langs python,go
  scripts/gen_proto.sh --src proto --src vendor/proto --out generated --bootstrap
USAGE
}

contains_lang() {
  local x="$1"; shift
  for l in "$@"; do [[ "$l" == "$x" ]] && return 0; done
  return 1
}

join_by() { local IFS="$1"; shift; echo "$*"; }

ensure_dir() { mkdir -p "$1"; }

check_cmd() {
  command -v "$1" >/dev/null 2>&1 || return 1
}

bootstrap_python_tools() {
  if ! python3 -c 'import grpc_tools' >/dev/null 2>&1; then
    [[ "${BOOTSTRAP}" == "true" ]] || { err "Missing python package grpcio-tools. Use --bootstrap to install."; return 1; }
    info "Installing python package grpcio-tools..."
    python3 -m pip install --user --upgrade pip >/dev/null
    python3 -m pip install --user grpcio-tools >/dev/null
  fi
}

bootstrap_go_tools() {
  local need=false
  check_cmd protoc-gen-go || need=true
  check_cmd protoc-gen-go-grpc || need=true
  if $need; then
    [[ "${BOOTSTRAP}" == "true" ]] || { err "Missing Go plugins (protoc-gen-go, protoc-gen-go-grpc). Use --bootstrap."; return 1; }
    info "Installing Go protoc plugins..."
    GO111MODULE=on GOBIN="${GOBIN:-$(go env GOPATH 2>/dev/null)/bin}" \
      go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2 >/dev/null
    GO111MODULE=on GOBIN="${GOBIN:-$(go env GOPATH 2>/dev/null)/bin}" \
      go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1 >/dev/null
  fi
}

bootstrap_ts_tools() {
  # Prefer ts-proto
  if ! check_cmd protoc-gen-ts_proto; then
    if [[ "${BOOTSTRAP}" == "true" ]]; then
      info "Installing ts-proto (protoc-gen-ts_proto)..."
      if check_cmd npm; then
        npm install -g ts-proto >/dev/null 2>&1 || true
        npm install -g protoc-gen-ts >/dev/null 2>&1 || true
      else
        warn "npm is not available; TypeScript generation may fail."
      fi
    fi
  fi
}

bootstrap_java_tools() {
  if ! check_cmd protoc-gen-grpc-java && [[ "${WITH_GRPC}" == "true" ]]; then
    [[ "${BOOTSTRAP}" == "true" ]] || { warn "Missing protoc-gen-grpc-java; Java gRPC stubs will be skipped."; return 0; }
    err "Automatic installation of protoc-gen-grpc-java is not implemented; install it and ensure it is on PATH."
  fi
}

compute_hash() {
  local tmp="${CACHE_DIR}/_calc.$$"
  ensure_dir "${CACHE_DIR}"
  {
    echo "WITH_GRPC=${WITH_GRPC}"
    echo "LANGS=$(join_by , "${LANGS[@]}")"
    echo "SRC_DIRS=$(join_by , "${SRC_DIRS[@]}")"
    echo "protoc=$(protoc --version 2>/dev/null || echo 'none')"
    echo "grpc_tools=$(python3 -c 'import grpc_tools, pkgutil; import grpc_tools.protoc as p; print(\"ok\")' 2>/dev/null || echo 'none')"
    echo "protoc-gen-go=$(command -v protoc-gen-go || echo 'none')"
    echo "protoc-gen-go-grpc=$(command -v protoc-gen-go-grpc || echo 'none')"
    echo "protoc-gen-ts_proto=$(command -v protoc-gen-ts_proto || echo 'none')"
    echo "protoc-gen-ts=$(command -v protoc-gen-ts || echo 'none')"
    find "${SRC_DIRS[@]/#/${REPO_ROOT}/}" -type f -name '*.proto' -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null || true
  } > "${tmp}"
  sha256sum "${tmp}" | awk '{print $1}'
  rm -f "${tmp}"
}

# --------------------------- Args Parsing -------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --src)         SRC_DIRS+=("$2"); shift 2 ;;
    --out)         OUT_BASE="$2"; shift 2 ;;
    --langs)       IFS=',' read -r -a LANGS <<< "$2"; shift 2 ;;
    --no-grpc)     WITH_GRPC="false"; shift ;;
    --clean)       CLEAN="true"; shift ;;
    --bootstrap)   BOOTSTRAP="true"; shift ;;
    --force)       FORCE="true"; shift ;;
    --verbose)     VERBOSE="true"; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             err "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# Normalize "all"
if contains_lang "all" "${LANGS[@]}"; then
  LANGS=("python" "go" "ts" "java")
fi

# Resolve absolute paths
ABS_SRC_DIRS=()
for d in "${SRC_DIRS[@]}"; do
  if [[ -d "${REPO_ROOT}/${d}" ]]; then
    ABS_SRC_DIRS+=("${REPO_ROOT}/${d}")
  elif [[ -d "$]()]()
