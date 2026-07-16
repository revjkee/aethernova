#!/usr/bin/env bash
# ledger-core/scripts/gen_proto.sh
# Industrial-grade generator for Protobuf/gRPC artifacts.
# - Python: grpcio + mypy-protobuf stubs
# - TypeScript: ts-proto
# - Prefers buf (if buf.yaml present), otherwise falls back to protoc
# - Optional Dockerized toolchain for hermetic builds
#
# Usage:
#   scripts/gen_proto.sh [--lang python|ts|all] [--in DIR] [--out DIR]
#                        [--docker] [--clean] [--protos "a.proto b.proto"]
#                        [--no-format]
#
# Examples:
#   scripts/gen_proto.sh --lang all
#   scripts/gen_proto.sh --lang python --docker
#   scripts/gen_proto.sh --protos "proto/ledger/v1/*.proto"
#
set -euo pipefail

########################################
# Defaults
########################################
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
SRC_DIR="${ROOT_DIR}/proto"
OUT_BASE="${ROOT_DIR}/generated"
OUT_PY="${OUT_BASE}/python"
OUT_TS="${OUT_BASE}/ts"
LANG="all"
USE_DOCKER="false"
DO_CLEAN="false"
PROTO_GLOBS=""
NO_FORMAT="false"

########################################
# Helpers
########################################
log()  { printf "[gen-proto] %s\n" "$*"; }
err()  { printf "[gen-proto][ERROR] %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

require_cmd() {
  local c="$1"
  command -v "$c" >/dev/null 2>&1 || die "Command not found: $c"
}

semver_ge() {
  # returns 0 if $1 >= $2
  # expects dotted X.Y[.Z]
  awk -v v1="$1" -v v2="$2" 'BEGIN{
    n1=split(v1,a,"."); n2=split(v2,b,".");
    for (i=1;i<=3;i++){ if(a[i]=="")a[i]=0; if(b[i]=="")b[i]=0;
      if (a[i]<b[i]) { exit 1 } else if (a[i]>b[i]) { exit 0 } }
    exit 0
  }'
}

# Resolve a list of .proto files
collect_protos() {
  local pattern="${1:-}"
  if [[ -n "$pattern" ]]; then
    # shellcheck disable=SC2206
    PROTO_FILES=($pattern)
  else
    mapfile -t PROTO_FILES < <(find "$SRC_DIR" -type f -name "*.proto" | sort)
  fi
  [[ ${#PROTO_FILES[@]} -gt 0 ]] || die "No .proto files found under ${SRC_DIR}"
}

########################################
# Parse args
########################################
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lang)        LANG="${2:-}"; shift 2 ;;
    --in)          SRC_DIR="${2:-}"; shift 2 ;;
    --out)         OUT_BASE="${2:-}"; OUT_PY="${OUT_BASE}/python"; OUT_TS="${OUT_BASE}/ts"; shift 2 ;;
    --docker)      USE_DOCKER="true"; shift ;;
    --clean)       DO_CLEAN="true"; shift ;;
    --protos)      PROTO_GLOBS="${2:-}"; shift 2 ;;
    --no-format)   NO_FORMAT="true"; shift ;;
    -h|--help)
      cat <<EOF
Usage: $0 [options]
  --lang <python|ts|all>     Languages to generate (default: all)
  --in <DIR>                 Proto sources root (default: proto/)
  --out <DIR>                Output base dir (default: generated/)
  --docker                   Use dockerized toolchain (bufbuild/protoc, node)
  --clean                    Remove outputs before generation
  --protos "<globs>"         Explicit proto files/globs (default: scan under --in)
  --no-format                Skip post-formatting (ruff/black/prettier)
EOF
      exit 0
      ;;
    *)
      die "Unknown arg: $1"
      ;;
  esac
done

########################################
# Validations
########################################
[[ -d "$ROOT_DIR" ]] || die "ROOT_DIR not found"
[[ -d "$SRC_DIR" ]] || die "Proto source dir not found: ${SRC_DIR}"

case "$LANG" in
  python|ts|all) ;;
  *) die "--lang must be python|ts|all" ;;
esac

if [[ "$DO_CLEAN" == "true" ]]; then
  log "Cleaning ${OUT_BASE}"
  rm -rf "${OUT_BASE}"
fi

mkdir -p "${OUT_PY}" "${OUT_TS}"

# Make generated dirs Python packages if needed
init_py_pkg() {
  local path="$1"
  [[ -d "$path" ]] || return 0
  find "$path" -type d -not -path '*/\.*' -exec bash -c 'f="$1/__init__.py"; [[ -f "$f" ]] || : > "$f"' _ {} \;
}

########################################
# Modes: BUF vs raw protoc
########################################
HAS_BUF="false"
if [[ -f "${ROOT_DIR}/buf.yaml" || -f "${ROOT_DIR}/buf.yml" ]]; then
  if [[ "$USE_DOCKER" == "true" ]]; then
    HAS_BUF="true"
  else
    if command -v buf >/dev/null 2>&1; then
      HAS_BUF="true"
    fi
  fi
fi

########################################
# Docker helpers
########################################
docker_run() {
  # $1 image
  # remaining args: command
  local img="$1"; shift
  require_cmd docker
  docker run --rm \
    -v "${ROOT_DIR}:${ROOT_DIR}" \
    -w "${ROOT_DIR}" \
    -u "$(id -u):$(id -g)" \
    "$img" "$@"
}

########################################
# Generators
########################################

gen_with_buf() {
  log "Using buf generate"
  # Expect buf.gen.yaml present with proper plugins; fall back to on-the-fly config if missing.
  if [[ -f "${ROOT_DIR}/buf.gen.yaml" || -f "${ROOT_DIR}/buf.gen.yml" ]]; then
    if [[ "$USE_DOCKER" == "true" ]]; then
      docker_run ghcr.io/bufbuild/buf:1.43.0 generate
    else
      require_cmd buf
      buf --version
      buf generate
    fi
  else
    # Minimal inline generation: python + ts-proto via ephemeral config
    local tmpcfg
    tmpcfg="$(mktemp)"
    cat > "$tmpcfg" <<'YAML'
version: v1
plugins:
  - plugin: python
    out: generated/python
  - plugin: grpc_python
    out: generated/python
  - plugin: mypy
    out: generated/python
  - plugin: buf.build/community/stephenh-ts-proto
    out: generated/ts
    opt:
      - outputServices=grpc-js
      - useExactTypes=false
      - esModuleInterop=true
      - useOptionals=messages
      - env=node
YAML
    if [[ "$USE_DOCKER" == "true" ]]; then
      docker_run ghcr.io/bufbuild/buf:1.43.0 generate --template "$tmpcfg"
    else
      require_cmd buf
      buf generate --template "$tmpcfg"
    fi
    rm -f "$tmpcfg"
  fi
}

gen_python_protoc() {
  log "Generating Python via protoc"
  # Prefer python -m grpc_tools.protoc for bundled grpc plugin
  local PY_GRPC="false"
  if python - <<'PY' >/dev/null 2>&1; then
import importlib, sys
sys.exit(0 if importlib.util.find_spec("grpc_tools.protoc") else 1)
PY
  then
    PY_GRPC="true"
  fi

  local has_mypy="false"
  if command -v protoc-gen-mypy >/dev/null 2>&1; then
    has_mypy="true"
  fi

  collect_protos "${PROTO_GLOBS}"

  if [[ "$PY_GRPC" == "true" ]]; then
    # shellcheck disable=SC2068
    python -m grpc_tools.protoc \
      -I "${SRC_DIR}" \
      --python_out="${OUT_PY}" \
      --grpc_python_out="${OUT_PY}" \
      ${PROTO_FILES[@]}
  else
    require_cmd protoc
    # Version check
    local pv outv
    pv="$(protoc --version | awk '{print $2}')"
    semver_ge "$pv" "3.21.0" || die "protoc >= 3.21.0 required (found $pv)"
    # grpc plugin
    if ! command -v grpc_python_plugin >/dev/null 2>&1 && ! command -v protoc-gen-grpc_python >/dev/null 2>&1; then
      die "grpc python plugin not found; install grpcio-tools or expose protoc-gen-grpc_python"
    fi
    # shellcheck disable=SC2068
    protoc \
      -I "${SRC_DIR}" \
      --python_out="${OUT_PY}" \
      --grpc_python_out="${OUT_PY}" \
      ${PROTO_FILES[@]}
  fi

  if [[ "$has_mypy" == "true" ]]; then
    # shellcheck disable=SC2068
    protoc \
      -I "${SRC_DIR}" \
      --mypy_out="${OUT_PY}" \
      ${PROTO_FILES[@]} || die "mypy-protobuf generation failed"
  else
    log "protoc-gen-mypy not found; skipping type stubs"
  fi

  init_py_pkg "${OUT_PY}"
}

gen_ts_protoc() {
  log "Generating TypeScript via ts-proto"
  collect_protos "${PROTO_GLOBS}"

  local ts_plugin=""
  if [[ "$USE_DOCKER" == "true" ]]; then
    # Use buf docker path if desired; otherwise rely on local node toolchain below
    log "Docker mode for TS: using node:lts with ts-proto installed ad-hoc"
    require_cmd docker
    docker_run node:20-bullseye bash -lc "
      set -euo pipefail
      npm -g i ts-proto@^1.172.0 && \
      mkdir -p ${OUT_TS} && \
      protoc --version >/dev/null 2>&1 || (apt-get update && apt-get install -y protobuf-compiler) && \
      protoc -I ${SRC_DIR} \
        --ts_proto_out=${OUT_TS} \
        --plugin=\$(npm root -g)/ts-proto/protoc-gen-ts_proto \
        --ts_proto_opt=outputServices=grpc-js,useExactTypes=false,esModuleInterop=true,useOptionals=messages,env=node \
        $(printf '%q ' "${PROTO_FILES[@]}")
    "
  else
    # Local toolchain: expect protoc + ts-proto plugin from node_modules or global
    require_cmd protoc
    local pv
    pv="$(protoc --version | awk '{print $2}')"
    semver_ge "$pv" "3.21.0" || die "protoc >= 3.21.0 required (found $pv)"

    if [[ -x "${ROOT_DIR}/node_modules/.bin/protoc-gen-ts_proto" ]]; then
      ts_plugin="${ROOT_DIR}/node_modules/.bin/protoc-gen-ts_proto"
    elif command -v protoc-gen-ts_proto >/dev/null 2>&1; then
      ts_plugin="$(command -v protoc-gen-ts_proto)"
    else
      die "ts-proto plugin not found. Install: npm i -D ts-proto"
    fi

    mkdir -p "${OUT_TS}"
    # shellcheck disable=SC2068
    protoc -I "${SRC_DIR}" \
      --ts_proto_out="${OUT_TS}" \
      --plugin="${ts_plugin}" \
      --ts_proto_opt="outputServices=grpc-js,useExactTypes=false,esModuleInterop=true,useOptionals=messages,env=node" \
      ${PROTO_FILES[@]}
  fi
}

format_outputs() {
  if [[ "$NO_FORMAT" == "true" ]]; then
    log "Skipping formatting"
    return 0
  fi
  # Python formatting (best-effort)
  if [[ -d "${OUT_PY}" ]]; then
    if command -v ruff >/dev/null 2>&1; then
      ruff check --select I --fix "${OUT_PY}" || true
      ruff format "${OUT_PY}" || true
    fi
    if command -v black >/dev/null 2>&1; then
      black -q "${OUT_PY}" || true
    fi
    if command -v isort >/dev/null 2>&1; then
      isort -q "${OUT_PY}" || true
    fi
  fi
  # TS formatting (best-effort)
  if [[ -d "${OUT_TS}" ]]; then
    if [[ -x "${ROOT_DIR}/node_modules/.bin/prettier" ]]; then
      "${ROOT_DIR}/node_modules/.bin/prettier" --loglevel warn -w "${OUT_TS}"/**/*.ts || true
    elif command -v prettier >/dev/null 2>&1; then
      prettier --loglevel warn -w "${OUT_TS}"/**/*.ts || true
    else
      log "Prettier not found; skip TS formatting"
    fi
  fi
}

########################################
# Main
########################################
log "ROOT=${ROOT_DIR}"
log "SRC=${SRC_DIR}"
log "OUT=${OUT_BASE} (py=${OUT_PY}, ts=${OUT_TS})"
log "LANG=${LANG} docker=${USE_DOCKER} clean=${DO_CLEAN}"

if [[ "$HAS_BUF" == "true" && "$LANG" == "all" && -z "$PROTO_GLOBS" ]]; then
  # Buf path (fastest + reproducible). If specific protos requested, use protoc path.
  gen_with_buf
else
  # Fine-grained path
  case "$LANG" in
    python)
      gen_python_protoc
      ;;
    ts)
      gen_ts_protoc
      ;;
    all)
      gen_python_protoc
      gen_ts_protoc
      ;;
  esac
fi

format_outputs

# Git hygiene: ensure generated dirs are ignored (best-effort)
for d in "${OUT_PY}" "${OUT_TS}"; do
  if [[ -d "$d" && ! -f "$d/.gitignore" ]]; then
    printf "*\n!.gitignore\n" > "$d/.gitignore" || true
  fi
done

log "Done."
