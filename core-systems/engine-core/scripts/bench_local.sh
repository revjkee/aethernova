#!/usr/bin/env bash

# ==============================================================================
# Industrial-grade Local Benchmarking Script
# Location: engine-core/scripts/bench_local.sh
# Purpose : Performance benchmark for API, worker or CLI operations
# ==============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT_APP="src/engine_core/app.py"
ENTRYPOINT_CLI="src/engine_core/tools/benchmark_entry.py"
LOG_DIR="$PROJECT_ROOT/.benchmarks"
ENV_FILE="$PROJECT_ROOT/.env"
MODE="${1:-api}"
BENCH_ITERATIONS="${2:-10}"
PORT="${PORT:-8000}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$LOG_DIR/bench_${MODE}_${TIMESTAMP}.log"
CSV_OUTPUT="$LOG_DIR/bench_${MODE}_${TIMESTAMP}.csv"

mkdir -p "$LOG_DIR"

function load_env() {
    if [[ -f "$ENV_FILE" ]]; then
        set -o allexport
        source "$ENV_FILE"
        set +o allexport
    fi
}

function check_dependencies() {
    command -v poetry >/dev/null || { echo "Poetry not installed"; exit 1; }
    command -v hyperfine >/dev/null || { echo "Install hyperfine: https://github.com/sharkdp/hyperfine"; exit 1; }
    command -v py-spy >/dev/null || { echo "Install py-spy: pip install py-spy"; exit 1; }
}

function benchmark_api() {
    echo "Running FastAPI server in background..."
    poetry run uvicorn "$ENTRYPOINT_APP":app --host 127.0.0.1 --port "$PORT" --reload &
    SERVER_PID=$!
    sleep 2

    echo "Benchmarking API with wrk..."
    wrk -t4 -c100 -d30s "http://127.0.0.1:$PORT" > "$LOG_FILE"

    echo "Profiling CPU (py-spy)..."
    py-spy top --pid $SERVER_PID --duration 15 --rate 50 --output "$LOG_DIR/pyspy_${TIMESTAMP}.txt"

    kill $SERVER_PID
}

function benchmark_cli() {
    echo "Benchmarking CLI tool..."
    hyperfine --warmup 3 --runs "$BENCH_ITERATIONS" \
        "poetry run python $ENTRYPOINT_CLI" \
        --export-csv "$CSV_OUTPUT" \
        --style=full \
        --show-output | tee "$LOG_FILE"
}

function benchmark_worker() {
    echo "Benchmarking worker script..."
    hyperfine --warmup 3 --runs "$BENCH_ITERATIONS" \
        "poetry run python src/engine_core/worker.py" \
        --export-csv "$CSV_OUTPUT" \
        --style=full \
        --show-output | tee "$LOG_FILE"
}

function main() {
    load_env
    check_dependencies

    case "$MODE" in
        api)
            benchmark_api
            ;;
        cli)
            benchmark_cli
            ;;
        worker)
            benchmark_worker
            ;;
        *)
            echo "Usage: $0 [api|cli|worker] [iterations]"
            exit 1
            ;;
    esac

    echo "Benchmark completed. Logs: $LOG_FILE"
}

main
