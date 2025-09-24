#!/usr/bin/env bash
# datafabric-core — protobuf/gRPC codegen
# Features:
#  - buf generate (if buf.yaml present), else protoc / grpc_tools fallback
#  - Python gRPC stubs + mypy-protobuf (if installed)
#  - Deterministic outputs under src/datafabric_core/proto
#  - Docker fallback (--docker) with ghcr.io/bufbuild/buf / namely/protoc
#  - Strict shell, clear logs, exit on errors
#  - Optional clean mode, formatting (ruff/black)
#
# Usage:
#   scripts/gen_proto.sh [--clean] [--docker|--no-docker] [--buf|--no-buf]
#                        [--src proto] [--out src/datafabric_core/proto]
# Env:
#   PYTHON_BIN=python3      # override python binary
#   PROTO_INCLUDE=          # extra -I include(s), colon-separated
#   FORMAT=1                # set 0 to skip formatting
#   PARALLEL=auto           # auto|1|N for xargs -P (buf handles parallelism)
set -euo pipefail

# ----------------------------- Defaults ---------------------------------------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR_DEFAULT="proto"
OUT_DIR_DEFAULT="src/datafabric_core/proto"
USE_DOCKER="auto"
USE_BUF="auto"
DO_CLEAN=0
PYTHON_BIN="${PYTHON_BIN:-python3}"
FORMAT="${FORMAT:-1}"
PARALLEL="${PARALLEL:-auto}"
PROTO_INCLUDE="${PROTO_INCLUDE:-}"

# ----------------------------- Logging ----------------------------------------
log()  { printf "[gen-proto] %s\n" "$*" >&2; }
die()  { printf "[gen-proto][ERROR] %s\n" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------- Parse args -------------------------------------
SRC_DIR="$SRC_DIR_DEFAULT"
OUT_DIR="$OUT_DIR_DEFAULT"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean) DO_CLEAN=1; shift ;;
    --docker) USE_DOCKER="1"; shift ;;
    --no-docker) USE_DOCKER="0"; shift ;;
    --buf) USE_BUF="1"; shift ;;
    --no-buf) USE_BUF="0"; shift ;;
    --src) SRC_DIR="${2:?}"; shift 2 ;;
    --out) OUT_DIR="${2:?}"; shift 2 ;;
    -h|--help)
      sed -n '1,80p' "$0"; exit 0 ;;
    *)
      die "Unknown argument: $1" ;;
  esac
done

cd "$ROOT_DIR"

# ----------------------------- Sanity checks ----------------------------------
[[ -d "$SRC_DIR" ]] || die "Proto source dir not found: $SRC_DIR"
mkdir -p "$OUT_DIR"

mkpkg() {
  # Ensure __init__.py chain exists for a module path
  local p="$1"
  while [[ "$p" != "." && "$p" != "/" && "$p" != "" ]]; do
    [[ -d "$p" ]] || mkdir -p "$p"
    [[ -f "$p/__init__.py" ]] || touch "$p/__init__.py"
    p="$(dirname "$p")"
    [[ "$p" == "." ]] && break
  done
}

# ----------------------------- Clean ------------------------------------------
if [[ "$DO_CLEAN" -eq 1 ]]; then
  log "Cleaning output directory: $OUT_DIR"
  find "$OUT_DIR" -type f \( -name "*.py" -o -name "*.pyi" \) -delete 2>/dev/null || true
fi

# ----------------------------- Includes ---------------------------------------
INCLUDES=(-I "$SRC_DIR")
IFS=':' read -r -a EXTRA_INC <<< "$PROTO_INCLUDE"
for inc in "${EXTRA_INC[@]:-}"; do
  [[ -n "${inc:-}" ]] && INCLUDES+=(-I "$inc")
done

# ----------------------------- Detect tools -----------------------------------
BUF_CFG=""
if [[ "$USE_BUF" != "0" ]]; then
  if [[ -f "buf.yaml" || -f "buf.yml" ]]; then
    BUF_CFG="$(ls buf.yam[l] 2>/dev/null | head -n1 || true)"
  fi
fi

USE_BUF_FINAL=0
if [[ -n "$BUF_CFG" ]]; then
  if [[ "$USE_DOCKER" == "1" ]]; then
    have docker || die "Docker required for --docker"
    USE_BUF_FINAL=2  # via docker
  elif [[ "$USE_DOCKER" == "0" ]]; then
    have buf || die "buf not found and --no-docker set"
    USE_BUF_FINAL=1  # native
  else
    if have buf; then USE_BUF_FINAL=1; elif have docker; then USE_BUF_FINAL=2; else die "Need buf or docker"; fi
  fi
fi

# ----------------------------- Helper: list protos ----------------------------
mapfile -t PROTOS < <(find "$SRC_DIR" -type f -name '*.proto' | sort)
[[ "${#PROTOS[@]}" -gt 0 ]] || die "No .proto files found under $SRC_DIR"

# ----------------------------- BUF path ---------------------------------------
if [[ "$USE_BUF_FINAL" -gt 0 ]]; then
  log "Using buf (${BUF_CFG}), mode: $([[ "$USE_BUF_FINAL" -eq 1 ]] && echo native || echo docker)"
  # Prepare buf.gen.yaml (local) if not present; generate Python grpc + mypy
  GEN_FILE="buf.gen.yaml"
  if [[ ! -f "$GEN_FILE" ]]; then
    log "No buf.gen.yaml found, creating a local generator template for Python"
    cat > "$GEN_FILE" <<'YAML'
version: v1
plugins:
  - name: python
    out: src/datafabric_core/proto
    opt: paths=source_relative
  - name: pygrpc
    out: src/datafabric_core/proto
    opt: paths=source_relative
  - name: mypy
    out: src/datafabric_core/proto
    opt: paths=source_relative
  - name: mypy_grpc
    out: src/datafabric_core/proto
    opt: paths=source_relative
YAML
  fi

  if [[ "$USE_BUF_FINAL" -eq 1 ]]; then
    buf generate --path "$SRC_DIR" || die "buf generate failed"
  else
    docker run --rm \
      -v "$PWD":"$PWD" -w "$PWD" \
      ghcr.io/bufbuild/buf:1.48.0 \
      generate --path "$SRC_DIR" || die "buf (docker) generate failed"
  fi

  mkpkg "$OUT_DIR"
else
  # --------------------------- PROTOC fallback --------------------------------
  log "Using protoc/grpc_tools fallback for Python codegen"

  # Try python grpc_tools first for cross-platform resilience
  if "$PYTHON_BIN" -m grpc_tools.protoc --version >/dev/null 2>&1; then
    log "grpc_tools.protoc detected"
    # mypy-protobuf optional
    HAVE_MYPY=0
    if have protoc-gen-mypy || "$PYTHON_BIN" -c "import mypy_protobuf" >/dev/null 2>&1; then
      HAVE_MYPY=1
    fi

    # Generate per-file to keep paths deterministic (source_relative)
    # Determine parallelism
    if [[ "$PARALLEL" == "auto" ]]; then
      if have nproc; then PAR= "$(nproc)"; else PAR="4"; fi
    else
      PAR="$PARALLEL"
    fi
    PAR="${PAR:-4}"

    # shellcheck disable=SC2016
    printf "%s\0" "${PROTOS[@]}" | xargs -0 -n1 -P "$PAR" -I{} bash -lc \
      '"'"$PYTHON_BIN"'" -m grpc_tools.protoc '"${INCLUDES[*]}"' \
        --python_out='"$OUT_DIR"' \
        --grpc_python_out='"$OUT_DIR"' \
        --pyi_out='"$OUT_DIR"' \
        '"$([[ "$HAVE_MYPY" -eq 1 ]] && echo "--mypy_out=$OUT_DIR --mypy_grpc_out=$OUT_DIR" || true)"' \
        --experimental_allow_proto3_optional \
        --descriptor_set_out=/dev/null {}'

  elif have protoc; then
    log "System protoc detected (no grpc_tools). Ensuring plugins exist..."
    have protoc-gen-python || die "Missing protoc-gen-python"
    have protoc-gen-grpc-python || die "Missing protoc-gen-grpc-python (pygrpc)"

    protoc "${INCLUDES[@]}" \
      --python_out="$OUT_DIR" \
      --grpc-python_out="$OUT_DIR" \
      --experimental_allow_proto3_optional \
      "${PROTOS[@]}"

    if have protoc-gen-mypy; then
      log "Generating mypy stubs"
      protoc "${INCLUDES[@]}" \
        --mypy_out="$OUT_DIR" \
        --mypy_grpc_out="$OUT_DIR" \
        "${PROTOS[@]}"
    else
      log "mypy-protobuf not found — skipping .pyi from plugin (PEP 561 stubs still emitted via --pyi_out when using grpc_tools)"
    fi
  else
    # ------------------------- Docker protoc fallback --------------------------
    if [[ "$USE_DOCKER" == "0" ]]; then
      die "Neither grpc_tools.protoc nor protoc found, and --no-docker selected"
    fi
    have docker || die "Docker not found"
    log "Falling back to Docker protoc (namely/protoc-all)"
    docker run --rm -v "$PWD":"$PWD" -w "$PWD" namely/protoc-all:1.57_2 \
      -d "$SRC_DIR" -o "$OUT_DIR" -l python || die "Docker protoc generation failed"
  fi

  mkpkg "$OUT_DIR"
fi

# ----------------------------- Post-process -----------------------------------
# Normalize package structure for Python imports
# Ensure __init__ for every generated package tree
while IFS= read -r -d '' d; do
  mkpkg "$d"
done < <(find "$OUT_DIR" -type d -print0)

# Simple import fix for grpc tools (relative imports when not source_relative)
# We already used source_relative. If any absolute imports slipped in, you can add sed fixes here.

# ----------------------------- Format (optional) ------------------------------
if [[ "$FORMAT" == "1" ]]; then
  if have ruff; then
    ruff check --fix "$OUT_DIR" || true
    ruff format "$OUT_DIR" || true
  fi
  if have black; then
    black "$OUT_DIR" || true
  fi
fi

# ----------------------------- Summary ----------------------------------------
COUNT_PY=$(find "$OUT_DIR" -type f -name '*.py' | wc -l | tr -d ' ')
COUNT_PYI=$(find "$OUT_DIR" -type f -name '*.pyi' | wc -l | tr -d ' ')
log "Done. Generated files: ${COUNT_PY} .py, ${COUNT_PYI} .pyi under ${OUT_DIR}"
