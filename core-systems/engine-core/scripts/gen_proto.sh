#!/usr/bin/env bash

set -euo pipefail

# ---------------------------------------
# Protobuf / gRPC Code Generator for Python
# Location: engine-core/scripts/gen_proto.sh
# Industrial-grade version
# ---------------------------------------

# === CONFIGURATION ===
SRC_DIR="./proto"
OUT_DIR="./src/engine_core/proto"
LOG_FILE="./scripts/gen_proto.log"
SUPPORTED_EXTENSIONS=("proto")
PROTOC_GEN="grpc_tools.protoc"

# === FUNCTIONS ===

function log() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

function ensure_dependencies() {
    if ! command -v python &>/dev/null; then
        log "Python not found. Aborting."
        exit 1
    fi
    if ! python -m grpc_tools.protoc --version &>/dev/null; then
        log "Missing grpcio-tools. Installing..."
        pip install grpcio grpcio-tools mypy-protobuf
    fi
}

function clean_output() {
    log "Cleaning output directory: $OUT_DIR"
    rm -rf "$OUT_DIR"
    mkdir -p "$OUT_DIR"
}

function generate_proto() {
    log "Generating protobuf files from $SRC_DIR"

    python -m grpc_tools.protoc \
        -I="$SRC_DIR" \
        --python_out="$OUT_DIR" \
        --grpc_python_out="$OUT_DIR" \
        --mypy_out="$OUT_DIR" \
        $(find "$SRC_DIR" -name "*.proto")

    log "Generation complete."
}

function fix_imports() {
    log "Fixing imports in generated files"
    find "$OUT_DIR" -type f -name "*.py" -exec \
        sed -i 's/^import \(.*_pb2\)/from . import \1/' {} \;
}

function validate_output() {
    log "Validating generated output"
    if [ -z "$(ls -A "$OUT_DIR")" ]; then
        log "Error: No files generated. Check .proto sources."
        exit 2
    fi
}

# === MAIN EXECUTION ===
log "Starting Protobuf generation..."
ensure_dependencies
clean_output
generate_proto
fix_imports
validate_output
log "Protobuf generation completed successfully."
