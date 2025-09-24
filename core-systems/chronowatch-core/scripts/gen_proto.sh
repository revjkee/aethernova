#!/usr/bin/env bash
# chronowatch-core/scripts/gen_proto.sh
# Industrial-grade protobuf/gRPC code generator with buf/protoc, Docker fallback,
# multi-language targets (Go/Python/TypeScript/Java), optional docs, parallelism,
# strict mode, and rich diagnostics.
#
# Usage:
#   scripts/gen_proto.sh [options]
#
# Common examples:
#   scripts/gen_proto.sh --langs all --clean
#   scripts/gen_proto.sh --langs go,python --in proto --out-base generated
#   scripts/gen_proto.sh --buf --docker --langs all
#
# Exit codes:
#   0 - success, nonzero - failure with diagnostic message.

set -Eeuo pipefail

#-------------------------------#
# Colors (no special chars)
#-------------------------------#
if [[ -t 1 ]]; then
  BOLD="$(printf '\033[1m')"
  RED="$(printf '\033[31m')"
  GREEN="$(printf '\033[32m')"
  YELLOW="$(printf '\033[33m')"
  BLUE="$(printf '\033[34m')"
  RESET="$(printf '\033[0m')"
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET="";
fi

#-------------------------------#
# Error trap
#-------------------------------#
on_error() {
  echo "${RED}ERROR${RESET}: Script failed at line ${BASH_LINENO[0]} (cmd: ${BASH_COMMAND})"
  exit 1
}
trap on_error ERR

#-------------------------------#
# Utilities
#-------------------------------#
realpath_portable() {
  # Works on macOS without coreutils
  python3 - "$1" <<'PY'
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

num_cpus() {
  if command_exists nproc; then nproc; elif command_exists sysctl; then sysctl -n hw.ncpu; else echo 4; fi
}

join_by() { local IFS="$1"; shift; echo "$*"; }

#-------------------------------#
# Defaults
#-------------------------------#
ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
PROTO_DIR_DEFAULT="$ROOT_DIR/proto"
OUT_BASE_DEFAULT="$ROOT_DIR/generated"

PROTO_DIR="${PROTO_DIR:-$PROTO_DIR_DEFAULT}"
OUT_BASE="${OUT_BASE:-$OUT_BASE_DEFAULT}"

OUT_GO="${OUT_GO:-$OUT_BASE/go}"
OUT_PY="${OUT_PY:-$OUT_BASE/python}"
OUT_TS="${OUT_TS:-$OUT_BASE/ts}"
OUT_JAVA="${OUT_JAVA:-$OUT_BASE/java}"
OUT_DOCS="${OUT_DOCS:-$OUT_BASE/docs}"

LANGS="all"              # all|go|python|ts|java comma-separated
WITH_GRPC="1"            # 1|0
USE_BUF="auto"           # auto|1|0
USE_DOCKER="auto"        # auto|1|0
CLEAN="0"                # 1|0
VERBOSE="0"              # 1|0
DOCS="0"                 # 1|0
PARALLEL="$(num_cpus)"

# Paths to include (allow extra via env)
EXTRA_PROTO_PATHS="${EXTRA_PROTO_PATHS:-}"
DEFAULT_INCLUDE_PATHS=("$PROTO_DIR")
for p in third_party vendor external; do
  [[ -d "$ROOT_DIR/$p" ]] && DEFAULT_INCLUDE_PATHS+=("$ROOT_DIR/$p")
done
IFS=' ' read -r -a EXTRA_ARR <<< "$EXTRA_PROTO_PATHS"
INCLUDE_PATHS=("${DEFAULT_INCLUDE_PATHS[@]}" "${EXTRA_ARR[@]}")

#-------------------------------#
# Help
#-------------------------------#
usage() {
  cat <<EOF
${BOLD}ChronoWatch-Core Proto Generator${RESET}

Options:
  --langs <list>        Comma-separated targets: all|go|python|ts|java (default: all)
  --in <dir>            Proto source dir (default: $PROTO_DIR)
  --out-base <dir>      Base output dir (default: $OUT_BASE)
  --with-grpc           Generate gRPC services where applicable (default)
  --no-grpc             Do not generate gRPC services
  --buf                 Force use of buf if available
  --no-buf              Force skip buf; use protoc directly
  --docker              Allow Docker fallback for buf/protoc images
  --no-docker           Forbid Docker fallback
  --clean               Clean output dirs before generation
  --docs                Generate Markdown API docs if protoc-gen-doc available
  --parallel <N>        Parallel jobs for per-file protoc (default: $PARALLEL)
  --verbose             Verbose logs
  -h|--help             Show this help

Environment overrides:
  PROTO_DIR, OUT_BASE, OUT_GO, OUT_PY, OUT_TS, OUT_JAVA, OUT_DOCS
  EXTRA_PROTO_PATHS="path1 path2" (additional -I include paths)

Notes:
  * Prefers buf if both buf and buf.gen.yaml present (or --buf set).
  * For TS generation prefers ts-proto (protoc-gen-ts_proto) if installed.
  * For Python uses python -m grpc_tools.protoc; optional mypy stubs if protoc-gen-mypy found.
  * For Java requires protoc-gen-grpc-java if gRPC is enabled.
  * If a target's plugins are missing, that target is skipped with a warning.
EOF
}

#-------------------------------#
# Parse args
#-------------------------------#
while [[ $# -gt 0 ]]; do
  case "$1" in
    --langs) LANGS="$2"; shift 2;;
    --in) PROTO_DIR="$2"; shift 2;;
    --out-base) OUT_BASE="$2"; shift 2;;
    --with-grpc) WITH_GRPC="1"; shift;;
    --no-grpc) WITH_GRPC="0"; shift;;
    --buf) USE_BUF="1"; shift;;
    --no-buf) USE_BUF="0"; shift;;
    --docker) USE_DOCKER="1"; shift;;
    --no-docker) USE_DOCKER="0"; shift;;
    --clean) CLEAN="1"; shift;;
    --docs) DOCS="1"; shift;;
    --parallel) PARALLEL="$2"; shift 2;;
    --verbose) VERBOSE="1"; shift;;
    -h|--help) usage; exit 0;;
    *) echo "${YELLOW}WARN${RESET}: Unknown option: $1"; usage; exit 2;;
  esac
done

# Resolve absolute paths
PROTO_DIR="$(realpath_portable "$PROTO_DIR")"
OUT_BASE="$(realpath_portable "$OUT_BASE")"
OUT_GO="$(realpath_portable "$OUT_GO")"
OUT_PY="$(realpath_portable "$OUT_PY")"
OUT_TS="$(realpath_portable "$OUT_TS")"
OUT_JAVA="$(realpath_portable "$OUT_JAVA")"
OUT_DOCS="$(realpath_portable "$OUT_DOCS")"

#-------------------------------#
# Banner
#-------------------------------#
echo "${BOLD}==> ChronoWatch-Core: Protobuf/gRPC Generation${RESET}"
echo "ROOT_DIR       : $ROOT_DIR"
echo "PROTO_DIR      : $PROTO_DIR"
echo "OUT_BASE       : $OUT_BASE"
echo "LANGS          : $LANGS"
echo "WITH_GRPC      : $WITH_GRPC"
echo "USE_BUF        : $USE_BUF"
echo "USE_DOCKER     : $USE_DOCKER"
echo "CLEAN          : $CLEAN"
echo "DOCS           : $DOCS"
echo "PARALLEL       : $PARALLEL"
if [[ "$VERBOSE" == "1" ]]; then
  echo "INCLUDE_PATHS  : $(join_by ' ' "${INCLUDE_PATHS[@]}")"
fi

#-------------------------------#
# Preflight checks
#-------------------------------#
[[ -d "$PROTO_DIR" ]] || { echo "${RED}ERROR${RESET}: PROTO_DIR not found: $PROTO_DIR"; exit 1; }

mapfile -t PROTO_FILES < <(find "$PROTO_DIR" -type f -name '*.proto' | sort)
[[ ${#PROTO_FILES[@]} -gt 0 ]] || { echo "${RED}ERROR${RESET}: No .proto files in $PROTO_DIR"; exit 1; }

# Detect buf preference
BUF_PRESENT="0"
if command_exists buf; then
  [[ -f "$ROOT_DIR/buf.gen.yaml" || -f "$ROOT_DIR/buf.gen.yml" || -f "$ROOT_DIR/buf.work.yaml" ]] && BUF_PRESENT="1"
fi

should_use_buf() {
  case "$USE_BUF" in
    1) [[ "$BUF_PRESENT" == "1" ]];;
    0) return 1;;
    auto) [[ "$BUF_PRESENT" == "1" ]];;
    *) return 1;;
  esac
}

# Docker availability
DOCKER_OK="0"
if [[ "$USE_DOCKER" != "0" ]] && command_exists docker; then
  DOCKER_OK="1"
fi

# Create outputs (maybe cleaned)
prepare_out_dir() {
  local d="$1"
  if [[ "$CLEAN" == "1" && -d "$d" ]]; then
    rm -rf "$d"
  fi
  mkdir -p "$d"
}

#-------------------------------#
# Clean and create output dirs
#-------------------------------#
prepare_out_dir "$OUT_BASE"
prepare_out_dir "$OUT_GO"
prepare_out_dir "$OUT_PY"
prepare_out_dir "$OUT_TS"
prepare_out_dir "$OUT_JAVA"
prepare_out_dir "$OUT_DOCS"

#-------------------------------#
# Generators: buf
#-------------------------------#
buf_generate() {
  echo "${BLUE}==> Using buf to generate${RESET}"

  local run="buf"
  if ! command_exists buf; then
    if [[ "$DOCKER_OK" == "1" ]]; then
      run="docker run --rm -u $(id -u):$(id -g) -v \"$ROOT_DIR:/workspace\" -w /workspace ghcr.io/bufbuild/buf:latest"
      echo "${YELLOW}WARN${RESET}: 'buf' not found, using Docker image."
    else
      echo "${RED}ERROR${RESET}: 'buf' not found and Docker unavailable."
      return 1
    fi
  fi

  # buf.gen.yaml is expected to define plugins and outputs.
  # We do not autogenerate a template here to avoid unexpected network fetches.
  if [[ ! -f "$ROOT_DIR/buf.gen.yaml" && ! -f "$ROOT_DIR/buf.gen.yml" ]]; then
    echo "${RED}ERROR${RESET}: buf.gen.yaml not found in repo root."
    return 1
  fi

  # Optional lint/format
  if [[ "$VERBOSE" == "1" ]]; then
    eval $run lint || echo "${YELLOW}WARN${RESET}: buf lint failed"
    eval $run format -w || true
  fi

  # Generate
  eval $run generate
}

#-------------------------------#
# Generators: protoc (per language)
#-------------------------------#
proto_include_flags() {
  local flags=()
  for inc in "${INCLUDE_PATHS[@]}"; do
    flags+=("-I" "$inc")
  done
  printf "%s\n" "${flags[@]}"
}

protoc_or_docker() {
  # $@ is protoc args
  if command_exists protoc; then
    if [[ "$VERBOSE" == "1" ]]; then echo "protoc $*"; fi
    protoc "$@"
  elif [[ "$DOCKER_OK" == "1" ]]; then
    # Use official protoc container; mount includes and workdir
    local args=("$@")
    local docker_cmd=(docker run --rm -u "$(id -u)":"$(id -g)")
    docker_cmd+=(-v "$ROOT_DIR:/workspace" -w /workspace)
    # Mount include paths
    for inc in "${INCLUDE_PATHS[@]}"; do
      docker_cmd+=(-v "$inc:$inc:ro")
    done
    docker_cmd+=(ghcr.io/protocolbuffers/protoc:latest)
    if [[ "$VERBOSE" == "1" ]]; then echo "${docker_cmd[*]} ${args[*]}"; fi
    "${docker_cmd[@]}" "${args[@]}"
  else
    echo "${RED}ERROR${RESET}: 'protoc' not found and Docker unavailable."
    return 1
  fi
}

gen_go() {
  echo "${BLUE}==> Generating Go${RESET}"
  if ! command_exists protoc-gen-go; then
    echo "${YELLOW}WARN${RESET}: protoc-gen-go not found, skipping Go."
    return 0
  fi
  local inc
  mapfile -t inc < <(proto_include_flags)

  local base_args=("${inc[@]}")
  base_args+=("--go_out=$OUT_GO")
  base_args+=("--go_opt=paths=source_relative")
  if [[ "$WITH_GRPC" == "1" ]]; then
    if ! command_exists protoc-gen-go-grpc; then
      echo "${YELLOW}WARN${RESET}: protoc-gen-go-grpc not found, skipping gRPC services for Go."
    else
      base_args+=("--go-grpc_out=$OUT_GO" "--go-grpc_opt=paths=source_relative,require_unimplemented_servers=false")
    fi
  fi

  # Parallel per-file invocation for better isolation
  printf "%s\n" "${PROTO_FILES[@]}" | xargs -I{} -P "$PARALLEL" bash -c '
    set -Eeuo pipefail
    protoc "$@" "{}"
  ' _ "${base_args[@]}"
}

gen_python() {
  echo "${BLUE}==> Generating Python${RESET}"
  if ! python3 -c "import grpc_tools.protoc" >/dev/null 2>&1; then
    echo "${YELLOW}WARN${RESET}: python grpc_tools not found, skipping Python."
    return 0
  fi

  local inc
  mapfile -t inc < <(proto_include_flags)
  local base_args=("${inc[@]}" "--python_out=$OUT_PY")
  if [[ "$WITH_GRPC" == "1" ]]; then
    base_args+=("--grpc_python_out=$OUT_PY")
  fi

  # mypy stubs if available
  local has_mypy="0"
  if command_exists protoc-gen-mypy; then
    has_mypy="1"
    base_args+=("--mypy_out=$OUT_PY")
  fi

  # Parallel per-file
  printf "%s\n" "${PROTO_FILES[@]}" | xargs -I{} -P "$PARALLEL" bash -c '
    set -Eeuo pipefail
    python3 -m grpc_tools.protoc "$@" "{}"
  ' _ "${base_args[@]}"

  if [[ "$has_mypy" == "1" ]]; then
    echo "${GREEN}INFO${RESET}: Generated mypy type stubs for Python."
  fi

  # Fix imports for pkg layout (optional but common)
  find "$OUT_PY" -type f -name "*_pb2*.py" -exec sed -i.bak "s/^import \(.*_pb2\)/from . import \1/" {} \; -exec rm -f {}.bak \;
}

gen_ts() {
  echo "${BLUE}==> Generating TypeScript${RESET}"
  # Prefer ts-proto (https://github.com/stephenh/ts-proto)
  local TS_PLUGIN=""
  if command_exists protoc-gen-ts_proto; then
    TS_PLUGIN="ts_proto"
  elif command_exists protoc-gen-ts; then
    TS_PLUGIN="ts"
  else
    echo "${YELLOW}WARN${RESET}: Neither protoc-gen-ts_proto nor protoc-gen-ts found, skipping TS."
    return 0
  fi

  local inc
  mapfile -t inc < <(proto_include_flags)

  mkdir -p "$OUT_TS"

  if [[ "$TS_PLUGIN" == "ts_proto" ]]; then
    # ts-proto options tuned for grpc-js and Node
    local opts="outputServices=grpc-js,env=node,esModuleInterop=true,useExactTypes=false,useOptionals=messages"
    printf "%s\n" "${PROTO_FILES[@]}" | xargs -I{} -P "$PARALLEL" bash -c '
      set -Eeuo pipefail
      protoc "$@" --ts_proto_out='"$OUT_TS"' --ts_proto_opt='"$opts"' "{}"
    ' _ "${inc[@]}"
  else
    # Legacy plugin (implies JS+TS typings for grpc-js)
    printf "%s\n" "${PROTO_FILES[@]}" | xargs -I{} -P "$PARALLEL" bash -c '
      set -Eeuo pipefail
      protoc "$@" --js_out=import_style=commonjs,binary:'"$OUT_TS"' '"$([[ "$WITH_GRPC" == "1" ]] && echo "--grpc_out=grpc_js:$OUT_TS")"' --ts_out=grpc_js:'"$OUT_TS"' "{}"
    ' _ "${inc[@]}"
  fi
}

gen_java() {
  echo "${BLUE}==> Generating Java${RESET}"
  if ! command_exists javac; then
    echo "${YELLOW}WARN${RESET}: JDK not found, skipping Java."
    return 0
  fi
  local inc
  mapfile -t inc < <(proto_include_flags)

  local base_args=("${inc[@]}" "--java_out=$OUT_JAVA")
  if [[ "$WITH_GRPC" == "1" ]]; then
    if command_exists protoc-gen-grpc-java; then
      base_args+=("--grpc-java_out=$OUT_JAVA")
    else
      echo "${YELLOW}WARN${RESET}: protoc-gen-grpc-java not found, skipping gRPC services for Java."
    fi
  fi

  printf "%s\n" "${PROTO_FILES[@]}" | xargs -I{} -P "$PARALLEL" bash -c '
    set -Eeuo pipefail
    protoc "$@" "{}"
  ' _ "${base_args[@]}"
}

gen_docs() {
  [[ "$DOCS" == "1" ]] || return 0
  echo "${BLUE}==> Generating Markdown API docs${RESET}"
  if ! command_exists protoc-gen-doc; then
    echo "${YELLOW}WARN${RESET}: protoc-gen-doc not found, skipping docs."
    return 0
  fi
  local inc
  mapfile -t inc < <(proto_include_flags)
  mkdir -p "$OUT_DOCS"
  # One consolidated doc
  protoc "${inc[@]}" --doc_out="$OUT_DOCS" --doc_opt=markdown,API.md "${PROTO_FILES[@]}"
}

#-------------------------------#
# Dispatch
#-------------------------------#
start_ts=$(date +%s)

LANGS_LOWER=",$(echo "$LANGS" | tr '[:upper:]' '[:lower:]'),"

if should_use_buf; then
  buf_generate
else
  echo "${BLUE}==> Using protoc directly${RESET}"
  # Go
  if [[ "$LANGS_LOWER" == *",all,"* || "$LANGS_LOWER" == *",go,"* ]]; then gen_go; fi
  # Python
  if [[ "$LANGS_LOWER" == *",all,"* || "$LANGS_LOWER" == *",python,"* ]]; then gen_python; fi
  # TypeScript
  if [[ "$LANGS_LOWER" == *",all,"* || "$LANGS_LOWER" == *",ts,"* ]]; then gen_ts; fi
  # Java
  if [[ "$LANGS_LOWER" == *",all,"* || "$LANGS_LOWER" == *",java,"* ]]; then gen_java; fi
  # Docs
  gen_docs
fi

end_ts=$(date +%s)
dur=$(( end_ts - start_ts ))

#-------------------------------#
# Summary
#-------------------------------#
echo "${GREEN}==> Done in ${dur}s${RESET}"
echo "Outputs:"
[[ -d "$OUT_GO" && -n "$(ls -A "$OUT_GO" 2>/dev/null || true)" ]] && echo "  Go   : $OUT_GO"
[[ -d "$OUT_PY" && -n "$(ls -A "$OUT_PY" 2>/dev/null || true)" ]] && echo "  Py   : $OUT_PY"
[[ -d "$OUT_TS" && -n "$(ls -A "$OUT_TS" 2>/dev/null || true)" ]] && echo "  TS   : $OUT_TS"
[[ -d "$OUT_JAVA" && -n "$(ls -A "$OUT_JAVA" 2>/dev/null || true)" ]] && echo "  Java : $OUT_JAVA"
[[ -d "$OUT_DOCS" && -n "$(ls -A "$OUT_DOCS" 2>/dev/null || true)" ]] && echo "  Docs : $OUT_DOCS"

# Advisory on unverified environment
echo "Note: Environment, plugin availability, and repository buf config are not verified by this script. I cannot verify this."
