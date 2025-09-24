#!/usr/bin/env bash
# automation-core/scripts/gen_proto.sh
# Industrial-grade protobuf code generation script.
# Modes: auto (default), buf, protoc.
# Languages: go, python, ts (TypeScript via ts-proto).
# Safe, deterministic, reproducible where possible.

set -Eeuo pipefail

# ------------------------------ config ---------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "$(cd "${SCRIPT_DIR}/.." && pwd)")"

# Defaults (override via CLI/ENV)
MODE="${MODE:-auto}"              # auto|buf|protoc
LANGS="${LANGS:-go,python,ts}"    # comma-separated: go|python|ts|all
IN_DIRS_DEFAULT="proto,protos"    # search roots
IN_DIRS="${IN_DIRS:-${IN_DIRS_DEFAULT}}"
OUT_BASE="${OUT_BASE:-${REPO_ROOT}/generated}"
BUF_TEMPLATE="${BUF_TEMPLATE:-}"   # optional custom buf.gen.yaml
CLEAN="${CLEAN:-0}"               # 1 to wipe OUT_BASE before generate
VERBOSE="${VERBOSE:-0}"

# ------------------------------ utils ----------------------------------
log() { echo "[$(date -u +%H:%M:%S)] $*"; }
vlog() { [[ "${VERBOSE}" == "1" ]] && log "$@"; true; }
fail() { echo "Error: $*" >&2; exit 1; }

on_err() {
  local exit_code=$?
  echo "Generation failed (code ${exit_code}) at line ${BASH_LINENO[0]} (cmd: ${BASH_COMMAND})" >&2
  exit "${exit_code}"
}
trap on_err ERR

have() { command -v "$1" >/dev/null 2>&1; }

split_csv() {
  local IFS=","
  read -ra __arr__ <<<"$1"
  printf "%s\n" "${__arr__[@]}"
}

ensure_dir() { mkdir -p "$1"; }

realpath_f() { python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"; }

# ------------------------------ inputs ---------------------------------
usage() {
  cat <<EOF
Usage: $(basename "$0") [--mode auto|buf|protoc] [--langs go,python,ts|all]
                        [--in-dirs proto,protos] [--out-base DIR]
                        [--buf-template PATH] [--clean] [--verbose]

Examples:
  $0 --mode auto --langs go,python --in-dirs proto --out-base ./generated
  $0 --mode protoc --langs ts --in-dirs schema --clean

Notes:
  - Buf mode uses buf.gen.yaml (from --buf-template or repo root). If not provided, a minimal template is generated on-the-fly.
  - Protoc mode requires appropriate plugins in PATH:
      Go:   protoc-gen-go, protoc-gen-go-grpc
      Py:   python -m grpc_tools.protoc
      TS:   protoc-gen-ts_proto (ts-proto)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --langs) LANGS="$2"; shift 2;;
    --in-dirs) IN_DIRS="$2"; shift 2;;
    --out-base) OUT_BASE="$2"; shift 2;;
    --buf-template) BUF_TEMPLATE="$2"; shift 2;;
    --clean) CLEAN=1; shift;;
    --verbose|-v) VERBOSE=1; shift;;
    -h|--help) usage; exit 0;;
    *) fail "Unknown argument: $1";;
  esac
done

# normalize langs
if [[ "${LANGS}" == "all" ]]; then
  LANGS="go,python,ts"
fi

declare -A WANT
for l in $(split_csv "${LANGS}"); do WANT["$l"]=1; done

# ------------------------------ discover inputs ------------------------
mapfile -t SRC_ROOTS < <(for d in $(split_csv "${IN_DIRS}"); do
  test -d "${REPO_ROOT}/${d}" && echo "${REPO_ROOT}/${d}";
done)

[[ "${#SRC_ROOTS[@]}" -eq 0 ]] && fail "No input directories found under: ${IN_DIRS}"

# Collect .proto files and include paths
declare -a PROTO_FILES=()
declare -a INCLUDE_PATHS=()
for root in "${SRC_ROOTS[@]}"; do
  mapfile -t pf < <(find "${root}" -type f -name '*.proto' | sort)
  PROTO_FILES+=("${pf[@]}")
  INCLUDE_PATHS+=("-I" "${root}")
done

[[ "${#PROTO_FILES[@]}" -eq 0 ]] && fail "No .proto files found under: ${IN_DIRS}"

log "Found ${#PROTO_FILES[@]} proto files under: ${IN_DIRS}"

# ------------------------------ outputs --------------------------------
OUT_GO="${OUT_BASE}/go"
OUT_PY="${OUT_BASE}/python"
OUT_TS="${OUT_BASE}/ts"

if [[ "${CLEAN}" == "1" ]]; then
  log "Cleaning output base: ${OUT_BASE}"
  rm -rf "${OUT_BASE}"
fi
ensure_dir "${OUT_GO}"; ensure_dir "${OUT_PY}"; ensure_dir "${OUT_TS}"

# ------------------------------ mode select ----------------------------
detect_mode() {
  if [[ "${MODE}" != "auto" ]]; then
    echo "${MODE}"; return
  fi
  if have buf; then echo "buf"; else echo "protoc"; fi
}
MODE_EFF="$(detect_mode)"
log "Effective mode: ${MODE_EFF}"

# ------------------------------ BUF mode --------------------------------
write_temp_buf_gen() {
  local tmpfile="$1"
  # Minimal v2 template with remote plugins for the selected languages.
  # Uses paths=source_relative for Go to keep file layout stable.
  # Python and TS plugins use default options; ts-proto is local via protoc mode (Buf remote TS example uses bufbuild/es).
  {
    echo "version: v2"
    echo "plugins:"
    if [[ -n "${WANT[go]:-}" ]]; then
      echo "  - remote: buf.build/protocolbuffers/go"
      echo "    out: ${OUT_GO}"
      echo "    opt: paths=source_relative"
      echo "  - remote: buf.build/grpc/go"
      echo "    out: ${OUT_GO}"
      echo "    opt: paths=source_relative"
    fi
    if [[ -n "${WANT[python]:-}" ]]; then
      echo "  - remote: buf.build/protocolbuffers/python"
      echo "    out: ${OUT_PY}"
      echo "  - remote: buf.build/grpc/python"
      echo "    out: ${OUT_PY}"
    fi
    # For TS via Buf, the common remote plugin is bufbuild/es (connect). We keep TS generation in protoc-mode for ts-proto specifics.
  } > "${tmpfile}"
}

run_buf_generate() {
  have buf || fail "buf not found in PATH"
  local tmpl=""
  if [[ -n "${BUF_TEMPLATE}" ]]; then
    tmpl="$(realpath_f "${BUF_TEMPLATE}")"
    [[ -f "${tmpl}" ]] || fail "buf template not found: ${tmpl}"
  else
    tmpl="${OUT_BASE}/.buf.gen.yaml"
    write_temp_buf_gen "${tmpl}"
  fi

  # Buf generates from repo root if buf.yaml is there, else uses directory input.
  local input="${REPO_ROOT}"
  if [[ ! -f "${REPO_ROOT}/buf.yaml" && ! -f "${REPO_ROOT}/buf.work.yaml" ]]; then
    # Generate from explicit proto roots
    input="${SRC_ROOTS[0]}"
  fi

  log "Running: buf generate --template ${tmpl}"
  (cd "${input}" && buf generate --template "${tmpl}")
}

# ------------------------------ protoc mode -----------------------------
require_protoc() { have protoc || fail "protoc not found in PATH"; }

gen_go() {
  have protoc-gen-go || fail "protoc-gen-go not found in PATH (install per docs)"
  have protoc-gen-go-grpc || fail "protoc-gen-go-grpc not found in PATH (install per docs)"
  vlog "Generating Go into: ${OUT_GO}"
  protoc "${INCLUDE_PATHS[@]}" \
    --go_out="paths=source_relative:${OUT_GO}" \
    --go-grpc_out="paths=source_relative:${OUT_GO}" \
    "${PROTO_FILES[@]}"
}

gen_python() {
  # Prefer grpc_tools.protoc as recommended by gRPC Python docs
  python3 - <<'PY' || fail "grpcio-tools not installed; run: python -m pip install grpcio-tools"
import sys, pkgutil
m = pkgutil.find_loader("grpc_tools")
sys.exit(0 if m else 1)
PY
  vlog "Generating Python into: ${OUT_PY}"
  python3 -m grpc_tools.protoc \
    "${INCLUDE_PATHS[@]}" \
    --python_out="${OUT_PY}" \
    --grpc_python_out="${OUT_PY}" \
    "${PROTO_FILES[@]}"
}

gen_ts() {
  # ts-proto expects protoc-gen-ts_proto in PATH
  have protoc-gen-ts_proto || fail "protoc-gen-ts_proto not found in PATH (npm i -g ts-proto)"
  vlog "Generating TypeScript (ts-proto) into: ${OUT_TS}"
  protoc "${INCLUDE_PATHS[@]}" \
    --ts_proto_out="${OUT_TS}" \
    --ts_proto_opt="esModuleInterop=true,outputServices=grpc-js,env=node" \
    "${PROTO_FILES[@]}"
}

run_protoc_generate() {
  require_protoc
  [[ -n "${WANT[go]:-}" ]] && gen_go
  [[ -n "${WANT[python]:-}" ]] && gen_python
  [[ -n "${WANT[ts]:-}" ]] && gen_ts
}

# ------------------------------ run -------------------------------------
case "${MODE_EFF}" in
  buf)    run_buf_generate ;;
  protoc) run_protoc_generate ;;
  *)      fail "Unsupported mode: ${MODE_EFF}" ;;
esac

log "Generation finished. Outputs at: ${OUT_BASE}"
