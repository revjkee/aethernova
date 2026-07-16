#!/usr/bin/env bash
# Industrial-grade Protobuf/gRPC codegen for omnimind-core
# Supports: python, ts (ts-proto/ts-protoc-gen), go, java
# Features: autodetect tools, incremental build (hash), venv awareness, docker fallback, formatting

set -euo pipefail

# --------------------------- Config (override by env) ---------------------------
PROJECT_NAME="${PROJECT_NAME:-omnimind-core}"
# Where to search proto files (space-separated, in priority order)
PROTO_SRC_DIRS_DEFAULT=("proto" "api/proto" "apis/proto" "core-systems" "onchain" "engine" "gateway")
PROTO_SRC_DIRS=(${PROTO_SRC_DIRS_OVERRIDE:-${PROTO_SRC_DIRS_DEFAULT[@]}})

# Output roots per language
OUT_ROOT="${OUT_ROOT:-generated}"  # base folder for all langs
OUT_PY="${OUT_PY:-$OUT_ROOT/python}"
OUT_TS="${OUT_TS:-$OUT_ROOT/ts}"
OUT_GO="${OUT_GO:-$OUT_ROOT/go}"
OUT_JAVA="${OUT_JAVA:-$OUT_ROOT/java}"

# Python specifics
PY_BIN="${PY_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"
USE_VENV="${USE_VENV:-1}"  # 1 = attempt to use .venv if present

# Docker fallback image (bundles protoc & common plugins)
DOCKER_IMAGE="${DOCKER_IMAGE:-namely/protoc-all:1.57_4}"

# Minimum protoc version (semantic check)
PROTOC_MIN_MAJOR=3
PROTOC_MIN_MINOR=21

# --------------------------- CLI parsing ---------------------------
LANGS="all"
DO_CLEAN=0
USE_DOCKER=0
INPLACE=0
PROTOC_BIN=""
TS_PLUGIN=""     # ts-proto|ts-protoc-gen|auto
QUIET=0

usage() {
  cat <<EOF
$0 — Protobuf/gRPC generator for $PROJECT_NAME

Usage:
  $0 [--lang=python|ts|go|java|all] [--clean] [--docker] [--protoc=/path/to/protoc]
     [--inplace] [--ts-plugin=auto|ts-proto|ts-protoc-gen] [--quiet]

Options:
  --lang=...           Language to generate (default: all)
  --clean              Remove generated outputs before build
  --docker             Use Docker fallback (${DOCKER_IMAGE})
  --protoc=PATH        Use specific protoc binary
  --inplace            Put outputs next to sources when reasonable (Python only)
  --ts-plugin=...      Force TS plugin: auto (default), ts-proto or ts-protoc-gen
  --quiet              Less verbose logs
Env:
  PROTO_SRC_DIRS_OVERRIDE="dir1 dir2"   Override proto search roots
  OUT_ROOT, OUT_PY, OUT_TS, OUT_GO, OUT_JAVA
  PY_BIN, VENV_DIR, USE_VENV
EOF
}

for arg in "$@"; do
  case "$arg" in
    --lang=*) LANGS="${arg#*=}";;
    --clean) DO_CLEAN=1;;
    --docker) USE_DOCKER=1;;
    --inplace) INPLACE=1;;
    --protoc=*) PROTOC_BIN="${arg#*=}";;
    --ts-plugin=*) TS_PLUGIN="${arg#*=}";;
    --quiet) QUIET=1;;
    -h|--help) usage; exit 0;;
    *) echo "[ERROR] Unknown arg: $arg"; usage; exit 2;;
  esac
done

# --------------------------- Helpers ---------------------------
log() { if [[ $QUIET -eq 0 ]]; then echo -e "$@"; fi; }
err() { echo -e "$@" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || { err "[ERROR] Missing tool: $1"; exit 127; }; }
mkdirp() { mkdir -p "$1"; }

# repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# venv
if [[ $USE_VENV -eq 1 && -d "$VENV_DIR" && -x "$VENV_DIR/bin/activate" ]]; then
  # shellcheck disable=SC1090
  source "$VENV_DIR/bin/activate"
  log "[INFO] Activated venv: $VENV_DIR"
fi

# protoc detection
if [[ -n "$PROTOC_BIN" ]]; then
  PROTOC="$PROTOC_BIN"
else
  if command -v protoc >/dev/null 2>&1; then
    PROTOC="$(command -v protoc)"
  else
    PROTOC=""
  fi
fi

# version check
check_protoc_version() {
  [[ -z "$PROTOC" ]] && return 1
  local ver maj min
  ver="$("$PROTOC" --version 2>/dev/null | awk '{print $2}')"
  maj="$(echo "$ver" | cut -d. -f1)"
  min="$(echo "$ver" | cut -d. -f2)"
  if [[ -z "$maj" || -z "$min" ]]; then
    err "[WARN] Unable to parse protoc version: $ver"
    return 0
  fi
  if (( maj < PROTOC_MIN_MAJOR )) || (( maj == PROTOC_MIN_MAJOR && min < PROTOC_MIN_MINOR )); then
    err "[WARN] protoc $ver < required ${PROTOC_MIN_MAJOR}.${PROTOC_MIN_MINOR}. Will attempt Docker fallback if enabled."
    return 1
  fi
  return 0
}

# hashing for incremental builds
HASH_FILE=".protohash"
hasher() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256
  else
    python3 - <<'PY'
import sys,hashlib
data=sys.stdin.buffer.read()
print(hashlib.sha256(data).hexdigest())
PY
  fi
}

collect_proto_files() {
  local -a paths=()
  for root in "${PROTO_SRC_DIRS[@]}"; do
    [[ -d "$root" ]] || continue
    # only *.proto files, ignore build directories
    while IFS= read -r -d '' f; do
      case "$f" in
        */node_modules/*|*/build/*|*/dist/*|*/generated/*) ;;
        *) paths+=("$f");;
      esac
    done < <(find "$root" -type f -name '*.proto' -print0)
  done
  printf "%s\n" "${paths[@]}"
}

calc_tree_hash() {
  collect_proto_files | sort | xargs cat | hasher | awk '{print $1}'
}

dirty=1
if [[ -f "$HASH_FILE" ]]; then
  old_hash="$(cat "$HASH_FILE" 2>/dev/null || true)"
  new_hash="$(calc_tree_hash || true)"
  if [[ -n "$new_hash" && "$new_hash" == "$old_hash" ]]; then
    dirty=0
  fi
else
  new_hash="$(calc_tree_hash || true)"
fi

# --------------------------- Cleaning ---------------------------
if [[ $DO_CLEAN -eq 1 ]]; then
  log "[CLEAN] Removing $OUT_ROOT and hash"
  rm -rf "$OUT_ROOT" "$HASH_FILE"
fi

# --------------------------- Language selectors ---------------------------
want_lang() {
  local l="$1"
  [[ "$LANGS" == "all" || "$LANGS" == "$l" ]]
}

# --------------------------- TS plugin resolution ---------------------------
pick_ts_plugin() {
  case "$TS_PLUGIN" in
    ts-proto|ts-protoc-gen) echo "$TS_PLUGIN"; return 0;;
    auto|"")
      if command -v protoc-gen-ts_proto >/dev/null 2>&1; then
        echo "ts-proto"; return 0
      elif command -v protoc-gen-ts >/dev/null 2>&1; then
        echo "ts-protoc-gen"; return 0
      fi
      # try npx without network (use local devDeps)
      if npx --yes --no-install -c "command -v protoc-gen-ts_proto" >/dev/null 2>&1; then
        echo "ts-proto"; return 0
      elif npx --yes --no-install -c "command -v protoc-gen-ts" >/dev/null 2>&1; then
        echo "ts-protoc-gen"; return 0
      fi
      err "[WARN] No TS plugin found; TS generation will be skipped."
      echo "none"; return 0
      ;;
    *) err "[ERROR] Unknown --ts-plugin value: $TS_PLUGIN"; exit 2;;
  esac
}

# --------------------------- Formatters ---------------------------
format_python() {
  if command -v ruff >/dev/null 2>&1; then ruff format "$OUT_PY" || true; fi
  if command -v black >/dev/null 2>&1; then black "$OUT_PY" || true; fi
}

format_ts() {
  if command -v eslint >/dev/null 2>&1; then eslint --fix "$OUT_TS" || true; fi
  if command -v prettier >/dev/null 2>&1; then prettier -w "$OUT_TS" || true; fi
}

format_go() {
  if command -v gofmt >/dev/null 2>&1; then gofmt -w "$OUT_GO" || true; fi
  if command -v golines >/dev/null 2>&1; then golines -w "$OUT_GO" || true; fi
}

format_java() {
  if command -v google-java-format >/dev/null 2>&1; then find "$OUT_JAVA" -name '*.java' -print0 | xargs -0 -r google-java-format -i || true; fi
}

# --------------------------- Generators ---------------------------
gen_with_protoc_python() {
  need "$PROTOC"
  mkdirp "$OUT_PY"
  local -a incs=()
  for d in "${PROTO_SRC_DIRS[@]}"; do [[ -d "$d" ]] && incs+=("-I" "$d"); done
  local -a files=()
  while IFS= read -r f; do files+=("$f"); done < <(collect_proto_files)

  # choose python plugins: grpc_tools or native plugin
  if "$PY_BIN" -c "import grpc_tools.protoc" >/dev/null 2>&1; then
    log "[PY] Using grpc_tools.protoc"
    "$PY_BIN" -m grpc_tools.protoc \
      "${incs[@]}" \
      --python_out="$OUT_PY" \
      --grpc_python_out="$OUT_PY" \
      "${files[@]}"
  else
    # fallback to protoc + grpc_python_plugin
    if ! command -v protoc-gen-python >/dev/null 2>&1; then
      err "[ERROR] Neither grpc_tools nor protoc-gen-python available."
      exit 1
    fi
    log "[PY] Using protoc python plugins"
    "$PROTOC" "${incs[@]}" \
      --python_out="$OUT_PY" \
      --grpc_python_out="$OUT_PY" \
      "${files[@]}"
  fi

  # Optional typing stubs (mypy-protobuf)
  if command -v protoc-gen-mypy >/dev/null 2>&1; then
    log "[PY] Generating mypy stubs"
    "$PROTOC" "${incs[@]}" --mypy_out="$OUT_PY" "${files[@]}" || true
  fi

  # __init__.py touch to make packages importable
  find "$OUT_PY" -type d -print0 | xargs -0 -I{} bash -c 'f="{}/__init__.py"; [[ -f "$f" ]] || echo "# generated" > "$f"'
  format_python
}

gen_with_protoc_ts() {
  need "$PROTOC"
  local ts_plugin
  ts_plugin="$(pick_ts_plugin)"
  [[ "$ts_plugin" == "none" ]] && { err "[TS] Skip: no TS plugin"; return 0; }

  mkdirp "$OUT_TS"
  local -a incs=()
  for d in "${PROTO_SRC_DIRS[@]}"; do [[ -d "$d" ]] && incs+=("-I" "$d"); done
  local -a files=()
  while IFS= read -r f; do files+=("$f"); done < <(collect_proto_files)

  case "$ts_plugin" in
    ts-proto)
      # protoc-gen-ts_proto (https://github.com/stephenh/ts-proto)
      if ! command -v protoc-gen-ts_proto >/dev/null 2>&1; then
        # Attempt local npx without network
        if npx --yes --no-install -c "command -v protoc-gen-ts_proto" >/dev/null 2>&1; then
          export PATH="$(npx --yes --no-install -c 'dirname $(command -v protoc-gen-ts_proto)'):$PATH"
        else
          err "[ERROR] protoc-gen-ts_proto not found."
          exit 1
        fi
      fi
      log "[TS] Using ts-proto"
      "$PROTOC" "${incs[@]}" \
        --ts_proto_out="$OUT_TS" \
        --ts_proto_opt=env=both,outputServices=grpc-js,esModuleInterop=true \
        "${files[@]}"
      ;;
    ts-protoc-gen)
      # protoc-gen-ts (https://github.com/improbable-eng/ts-protoc-gen)
      if ! command -v protoc-gen-ts >/dev/null 2>&1; then
        if npx --yes --no-install -c "command -v protoc-gen-ts" >/dev/null 2>&1; then
          export PATH="$(npx --yes --no-install -c 'dirname $(command -v protoc-gen-ts)'):$PATH"
        else
          err "[ERROR] protoc-gen-ts not found."
          exit 1
        fi
      fi
      log "[TS] Using ts-protoc-gen"
      "$PROTOC" "${incs[@]}" \
        --js_out=import_style=commonjs,binary:"$OUT_TS" \
        --grpc-web_out=import_style=typescript,mode=grpcwebtext:"$OUT_TS" \
        --ts_out="$OUT_TS" \
        "${files[@]}"
      ;;
    *) err "[ERROR] Unknown TS plugin value: $ts_plugin"; exit 2;;
  esac

  format_ts
}

gen_with_protoc_go() {
  need "$PROTOC"
  if ! command -v protoc-gen-go >/dev/null 2>&1 || ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
    err "[ERROR] Missing protoc-gen-go and/or protoc-gen-go-grpc. Try: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
    exit 1
  fi
  mkdirp "$OUT_GO"
  local -a incs=()
  for d in "${PROTO_SRC_DIRS[@]}"; do [[ -d "$d" ]] && incs+=("-I" "$d"); done
  local -a files=()
  while IFS= read -r f; do files+=("$f"); done < <(collect_proto_files)

  log "[GO] Generating protobuf and gRPC"
  "$PROTOC" "${incs[@]}" \
    --go_out="$OUT_GO" --go_opt=paths=source_relative \
    --go-grpc_out="$OUT_GO" --go-grpc_opt=paths=source_relative \
    "${files[@]}"

  format_go
}

gen_with_protoc_java() {
  need "$PROTOC"
  mkdirp "$OUT_JAVA"
  local -a incs=()
  for d in "${PROTO_SRC_DIRS[@]}"; do [[ -d "$d" ]] && incs+=("-I" "$d"); done
  local -a files=()
  while IFS= read -r f; do files+=("$f"); done < <(collect_proto_files)

  local GRPC_JAVA_PLUGIN=""
  if command -v protoc-gen-grpc-java >/dev/null 2>&1; then
    GRPC_JAVA_PLUGIN="--grpc-java_out=$OUT_JAVA"
  else
    err "[WARN] protoc-gen-grpc-java not found. Will generate only messages."
  fi

  log "[JAVA] Generating protobuf $( [[ -n "$GRPC_JAVA_PLUGIN" ]] && echo '+ gRPC' || true )"
  "$PROTOC" "${incs[@]}" \
    --java_out="$OUT_JAVA" \
    ${GRPC_JAVA_PLUGIN:+$GRPC_JAVA_PLUGIN} \
    "${files[@]}"

  format_java
}

# --------------------------- Docker fallback ---------------------------
docker_codegen() {
  need docker
  local langs="$1"
  local -a src_mounts=()
  for d in "${PROTO_SRC_DIRS[@]}"; do [[ -d "$d" ]] && src_mounts+=("-v" "$(pwd)/$d:/defs/$d"); done
  [[ ${#src_mounts[@]} -eq 0 ]] && { err "[ERROR] No proto sources found for Docker run"; exit 1; }

  local out_abs="$(pwd)/$OUT_ROOT"
  mkdirp "$out_abs"

  # namely/protoc-all requires --lang and --out
  # Map langs to plugin set
  local docker_langs=()
  case "$langs" in
    all) docker_langs=("python" "go" "java" "web");;
    *) docker_langs=($langs);;
  esac

  for L in "${docker_langs[@]}"; do
    local LOUT="$out_abs/$L"
    mkdirp "$LOUT"
    log "[DOCKER] Generating $L -> $LOUT"
    docker run --rm -u "$(id -u):$(id -g)" \
      -v "$out_abs:/out" "${src_mounts[@]}" \
      "$DOCKER_IMAGE" \
      -d /defs -o "/out/$L" -l "$L" || { err "[ERROR] Docker codegen failed for $L"; exit 1; }
  done
}

# --------------------------- Inplace mode (Python) ---------------------------
relocate_python_inplace() {
  # Moves generated python files next to their proto namespaces (best-effort)
  # This is optional and only for teams preferring in-repo generated sources.
  [[ $INPLACE -eq 1 ]] || return 0
  [[ -d "$OUT_PY" ]] || return 0
  log "[PY] Relocating python outputs inplace"
  # Heuristic: preserve package structure by module path comment from grpc_tools (if present)
  find "$OUT_PY" -type f -name '*.py' -print0 | while IFS= read -r -d '' f; do
    # fallback: keep in generated if no target mapping known
    :
  done
  log "[PY] Inplace relocation skipped (no deterministic mapping). Outputs remain in $OUT_PY."
}

# --------------------------- Main flow ---------------------------
main() {
  # collect sources once
  mapfile -t PROTOS < <(collect_proto_files)
  if [[ ${#PROTOS[@]} -eq 0 ]]; then
    err "[ERROR] No .proto files found in: ${PROTO_SRC_DIRS[*]}"
    exit 1
  fi
  log "[INFO] Found ${#PROTOS[@]} proto files"

  if [[ $DO_CLEAN -eq 0 && $dirty -eq 0 ]]; then
    log "[SKIP] No proto changes detected (hash unchanged)."
    exit 0
  fi

  # Try native protoc first unless forced docker
  if [[ $USE_DOCKER -eq 0 ]]; then
    if [[ -z "$PROTOC" ]] || ! check_protoc_version; then
      err "[WARN] protoc not found or version too old."
      if [[ $USE_DOCKER -eq 0 ]]; then
        err "[INFO] Falling back to Docker for generation."
        USE_DOCKER=1
      fi
    fi
  fi

  if [[ $USE_DOCKER -eq 1 ]]; then
    docker_codegen "$LANGS"
  else
    mkdirp "$OUT_ROOT"
    if want_lang python; then gen_with_protoc_python; relocate_python_inplace; fi
    if want_lang ts; then gen_with_protoc_ts; fi
    if want_lang go; then gen_with_protoc_go; fi
    if want_lang java; then gen_with_protoc_java; fi
  fi

  # update hash
  calc_tree_hash > "$HASH_FILE" || true
  log "[DONE] Codegen complete. Outputs under: $OUT_ROOT"
}

main "$@"
