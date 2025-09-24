#!/usr/bin/env bash
# NeuroForge Core — Protobuf/ gRPC code generator
# Industrial-grade, deterministic, multi-language generator.
# Supports: Python, Go, TypeScript (ts-proto or grpc-web), Java, grpc-web stubs.
# Works with: protoc, buf; local or Dockerized.
#
# Usage examples:
#   scripts/gen_proto.sh --lang python,go,ts --proto-dir proto --out-dir gen
#   scripts/gen_proto.sh --lang all --clean
#   scripts/gen_proto.sh --buf                 # uses buf generate (requires buf.{yaml,gen.yaml})
#   scripts/gen_proto.sh --docker --buf        # uses buf in Docker
#   scripts/gen_proto.sh --lang ts --ts-mode ts-proto
#   scripts/gen_proto.sh --lang grpc-web --grpc-web-mode grpcweb --grpc-web-import ts
#
# Exit codes: 0 ok; 2 usage; 3 missing tool; 4 no protos; 5 generation error.

set -Eeuo pipefail

# -------------- Defaults (override via env) -------------------
NF_PROTO_DIR="${NF_PROTO_DIR:-proto}"
NF_OUT_DIR="${NF_OUT_DIR:-gen}"
NF_LANGS="${NF_LANGS:-python}"
NF_USE_BUF="${NF_USE_BUF:-0}"       # 1 => use buf generate
NF_USE_DOCKER="${NF_USE_DOCKER:-0}" # 1 => wrap in docker where applicable
NF_CLEAN="${NF_CLEAN:-0}"

# TypeScript modes: ts-proto | protoc-gen-ts | auto
NF_TS_MODE="${NF_TS_MODE:-auto}"

# grpc-web config
NF_GRPC_WEB_MODE="${NF_GRPC_WEB_MODE:-grpcweb}"   # grpcweb | grpcwebtext
NF_GRPC_WEB_IMPORT="${NF_GRPC_WEB_IMPORT:-ts}"    # ts | commonjs

# Optional include roots (space-separated)
NF_EXTRA_INCLUDE="${NF_EXTRA_INCLUDE:-third_party googleapis}"

# Docker images (change if your org pins them)
DOCKER_BUF_IMAGE="${DOCKER_BUF_IMAGE:-ghcr.io/bufbuild/buf:latest}"

# -------------- Utilities -------------------
bold()   { printf '\033[1m%s\033[0m' "$*"; }
green()  { printf '\033[32m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
red()    { printf '\033[31m%s\033[0m' "$*"; }

log() { echo "$(bold [gen-proto]) $*"; }
warn(){ echo "$(bold [gen-proto]) $(yellow WARN:) $*" >&2; }
die() { echo "$(bold [gen-proto]) $(red ERROR:) $*" >&2; exit "${2:-1}"; }

usage() {
  cat <<EOF
$(bold "NeuroForge Protobuf generator")

$(bold USAGE)
  $(basename "$0") [options]

$(bold OPTIONS)
  --proto-dir DIR         Proto sources root (default: ${NF_PROTO_DIR})
  --out-dir DIR           Output root (default: ${NF_OUT_DIR})
  --lang LIST             Comma-separated: python,go,ts,java,grpc-web,all (default: ${NF_LANGS})
  --clean                 Clean output directories before generation
  --buf                   Use 'buf generate' (requires buf.yaml and buf.gen.yaml)
  --docker                Run buf in Docker (when --buf) (image: ${DOCKER_BUF_IMAGE})
  --ts-mode MODE          ts generation: ts-proto | protoc-gen-ts | auto (default: ${NF_TS_MODE})
  --grpc-web-mode MODE    grpc-web service mode: grpcweb | grpcwebtext (default: ${NF_GRPC_WEB_MODE})
  --grpc-web-import T     grpc-web import style: ts | commonjs (default: ${NF_GRPC_WEB_IMPORT})
  --extra-include LIST    Space-separated extra include roots (default: "${NF_EXTRA_INCLUDE}")
  -h|--help               Show this help

$(bold ENV VARS)
  NF_PROTO_DIR, NF_OUT_DIR, NF_LANGS, NF_USE_BUF, NF_USE_DOCKER, NF_CLEAN,
  NF_TS_MODE, NF_GRPC_WEB_MODE, NF_GRPC_WEB_IMPORT, NF_EXTRA_INCLUDE,
  DOCKER_BUF_IMAGE

$(bold EXAMPLES)
  $(basename "$0") --lang all --clean
  $(basename "$0") --buf
  $(basename "$0") --lang ts --ts-mode ts-proto
EOF
  exit 2
}

# -------------- Parse args -------------------
PROTO_DIR="${NF_PROTO_DIR}"
OUT_DIR="${NF_OUT_DIR}"
LANGS="${NF_LANGS}"
USE_BUF="${NF_USE_BUF}"
USE_DOCKER="${NF_USE_DOCKER}"
CLEAN="${NF_CLEAN}"
TS_MODE="${NF_TS_MODE}"
GRPC_WEB_MODE="${NF_GRPC_WEB_MODE}"
GRPC_WEB_IMPORT="${NF_GRPC_WEB_IMPORT}"
EXTRA_INCLUDE="${NF_EXTRA_INCLUDE}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proto-dir) PROTO_DIR="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --lang) LANGS="${2:-}"; shift 2;;
    --clean) CLEAN=1; shift;;
    --buf) USE_BUF=1; shift;;
    --docker) USE_DOCKER=1; shift;;
    --ts-mode) TS_MODE="${2:-}"; shift 2;;
    --grpc-web-mode) GRPC_WEB_MODE="${2:-}"; shift 2;;
    --grpc-web-import) GRPC_WEB_IMPORT="${2:-}"; shift 2;;
    --extra-include) EXTRA_INCLUDE="${2:-}"; shift 2;;
    -h|--help) usage;;
    *) die "Unknown argument: $1" 2;;
  esac
done

# -------------- Sanity checks -------------------
command_exists() { command -v "$1" >/dev/null 2>&1; }

# realpath fallback
abspath() {
  if command_exists realpath; then realpath "$1"; else
    python3 - <<PY "$1"
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
  fi
}

PROTO_DIR="$(abspath "${PROTO_DIR}")"
OUT_DIR="$(abspath "${OUT_DIR}")"
mkdir -p "${OUT_DIR}"

[[ -d "${PROTO_DIR}" ]] || die "Proto dir not found: ${PROTO_DIR}" 3

IFS=',' read -r -a LANG_ARR <<< "${LANGS}"
if [[ "${LANGS}" == "all" ]]; then
  LANG_ARR=(python go ts java grpc-web)
fi

# collect -I includes
INCLUDES=(-I "${PROTO_DIR}")
for d in ${EXTRA_INCLUDE}; do
  [[ -d "${d}" ]] && INCLUDES+=(-I "$(abspath "$d")")
done

# -------------- Discover .proto files -------------------
readarray -t PROTOS < <(find "${PROTO_DIR}" -type f -name "*.proto" ! -path "*/.venv/*" ! -path "*/node_modules/*" | sort)
[[ ${#PROTOS[@]} -gt 0 ]] || die "No .proto files in ${PROTO_DIR}" 4

# -------------- Cleaning (optional) -------------------
clean_out() {
  local sub="$1"
  local dir="${OUT_DIR}/${sub}"
  if [[ "${CLEAN}" -eq 1 ]]; then
    rm -rf "${dir}"
  fi
  mkdir -p "${dir}"
  # Help linguist treat as generated
  if [[ ! -f "${dir}/.gitattributes" ]]; then
    echo "* linguist-generated=true" > "${dir}/.gitattributes" || true
  fi
}

# -------------- Protoc/Buf wrappers -------------------
need_tool() { command_exists "$1" || die "Required tool not found: $1" 3; }

run_protoc() {
  need_tool protoc
  protoc "${INCLUDES[@]}" "$@"
}

run_buf() {
  if [[ "${USE_DOCKER}" -eq 1 ]]; then
    need_tool docker
    docker run --rm -u "$(id -u):$(id -g)" -v "${PWD}:/work" -w /work "${DOCKER_BUF_IMAGE}" generate
  else
    need_tool buf
    buf generate
  fi
}

# -------------- Language generators -------------------
gen_python() {
  clean_out python
  local out="${OUT_DIR}/python"
  # Prefer grpc_tools.protoc to avoid external grpc plugin binary
  need_tool python3
  local PYMOD="grpc_tools.protoc"
  # Optional mypy plugin
  local MYOPTS=()
  if command_exists protoc-gen-mypy; then
    MYOPTS+=(--mypy_out="${out}")
  fi
  log "Python: generating to ${out}"
  python3 -m "${PYMOD}" "${INCLUDES[@]}" \
    --python_out="${out}" \
    --grpc_python_out="${out}" \
    "${MYOPTS[@]}" \
    "${PROTOS[@]}" || die "Python generation failed" 5
}

gen_go() {
  clean_out go
  local out="${OUT_DIR}/go"
  need_tool protoc
  command_exists protoc-gen-go || die "Missing plugin protoc-gen-go" 3
  command_exists protoc-gen-go-grpc || die "Missing plugin protoc-gen-go-grpc" 3
  log "Go: generating to ${out}"
  run_protoc \
    --go_out="${out}" --go_opt=paths=source_relative \
    --go-grpc_out="${out}" --go-grpc_opt=paths=source_relative \
    "${PROTOS[@]}" || die "Go generation failed" 5
}

gen_ts_tsproto() {
  clean_out ts
  local out="${OUT_DIR}/ts"
  command_exists protoc-gen-ts_proto || die "Missing plugin protoc-gen-ts_proto (ts-proto)" 3
  log "TypeScript (ts-proto): generating to ${out}"
  run_protoc \
    --ts_proto_out="${out}" \
    --ts_proto_opt=esModuleInterop=true,outputServices=grpc-js,env=node,outputJsonMethods=false,outputClientImpl=false,forceLong=string \
    "${PROTOS[@]}" || die "TS (ts-proto) generation failed" 5
}

gen_ts_pgts() {
  clean_out ts
  local out="${OUT_DIR}/ts"
  command_exists protoc-gen-ts || die "Missing plugin protoc-gen-ts (ts-protoc-gen)" 3
  log "TypeScript (protoc-gen-ts): generating to ${out}"
  run_protoc \
    --js_out="import_style=commonjs,binary:${out}" \
    --ts_out="service=grpc-node,mode=grpc-js:${out}" \
    "${PROTOS[@]}" || die "TS (protoc-gen-ts) generation failed" 5
}

gen_java() {
  clean_out java
  local out="${OUT_DIR}/java"
  command_exists protoc-gen-grpc-java || die "Missing plugin protoc-gen-grpc-java" 3
  log "Java: generating to ${out}"
  run_protoc \
    --java_out="${out}" \
    --grpc-java_out="${out}" \
    "${PROTOS[@]}" || die "Java generation failed" 5
}

gen_grpc_web() {
  clean_out grpc-web
  local out="${OUT_DIR}/grpc-web"
  command_exists protoc-gen-grpc-web || die "Missing plugin protoc-gen-grpc-web" 3

  local js_out=""
  case "${GRPC_WEB_IMPORT}" in
    ts) js_out="import_style=typescript,mode=grpcwebtext";;
    commonjs) js_out="import_style=commonjs,binary";;
    *) die "Invalid --grpc-web-import: ${GRPC_WEB_IMPORT} (ts|commonjs)";;
  esac

  local mode="${GRPC_WEB_MODE}"
  [[ "${mode}" =~ ^(grpcweb|grpcwebtext)$ ]] || die "Invalid --grpc-web-mode: ${mode}"

  log "grpc-web: generating to ${out} (mode=${mode}, import=${GRPC_WEB_IMPORT})"
  if [[ "${GRPC_WEB_IMPORT}" == "ts" ]]; then
    # TypeScript declaration files + grpc-web client
    run_protoc \
      --js_out="${js_out}:${out}" \
      --grpc-web_out="import_style=typescript,mode=${mode}:${out}" \
      "${PROTOS[@]}" || die "grpc-web TS generation failed" 5
  else
    run_protoc \
      --js_out="${js_out}:${out}" \
      --grpc-web_out="import_style=commonjs,mode=${mode}:${out}" \
      "${PROTOS[@]}" || die "grpc-web JS generation failed" 5
  fi
}

# -------------- Main flow -------------------
main() {
  log "Proto root: ${PROTO_DIR}"
  log "Out root:   ${OUT_DIR}"
  log "Includes:   ${INCLUDES[*]}"
  log "Langs:      ${LANG_ARR[*]}"
  if [[ "${USE_BUF}" -eq 1 ]]; then
    [[ -f "buf.yaml" || -f "buf.yml" ]] || die "buf mode: buf.yaml not found at repo root" 3
    log "Mode: buf generate"
    run_buf
    log "$(green DONE)"
    exit 0
  fi

  # protoc-based generation per language
  for lang in "${LANG_ARR[@]}"; do
    case "${lang}" in
      python)    gen_python ;;
      go)        gen_go ;;
      ts)
        case "${TS_MODE}" in
          ts-proto)        gen_ts_tsproto ;;
          protoc-gen-ts)   gen_ts_pgts ;;
          auto)
            if command_exists protoc-gen-ts_proto; then gen_ts_tsproto
            elif command_exists protoc-gen-ts; then gen_ts_pgts
            else die "No TS plugin found (install ts-proto or ts-protoc-gen)" 3
            fi ;;
          *) die "Invalid --ts-mode: ${TS_MODE}" ;;
        esac ;;
      java)      gen_java ;;
      grpc-web)  gen_grpc_web ;;
      *) die "Unknown language: ${lang}" ;;
    esac
  done

  log "$(green DONE)"
}

trap 'code=$?; [[ $code -ne 0 ]] && echo "$(bold [gen-proto]) $(red FAILED) exit=$code" >&2' EXIT
main "$@"
