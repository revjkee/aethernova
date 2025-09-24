#!/usr/bin/env bash

# ======================================================================
# Industrial-grade script to run engine-core locally in isolated mode
# Location: engine-core/scripts/run_local.sh
# ======================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ENTRY="src/engine_core/app.py"
WORKER_ENTRY="src/engine_core/worker.py"
ENV_FILE="$PROJECT_ROOT/.env"
LOG_FILE="$PROJECT_ROOT/.logs/run_local_$(date +%Y%m%d_%H%M%S).log"

# Load .env variables
function load_env() {
    if [[ -f "$ENV_FILE" ]]; then
        echo "Loading environment variables from .env"
        set -o allexport
        source "$ENV_FILE"
        set +o allexport
    else
        echo "Warning: .env file not found at $ENV_FILE"
    fi
}

# Check dependencies
function check_dependencies() {
    echo "Checking dependencies..."
    command -v python >/dev/null || { echo "Python not found"; exit 1; }
    command -v poetry >/dev/null || { echo "Poetry not found"; exit 1; }

    echo "Installing Python dependencies..."
    poetry install --no-root --no-interaction >>"$LOG_FILE" 2>&1
}

# Run FastAPI app
function run_app() {
    echo "Starting FastAPI app..."
    poetry run uvicorn "$APP_ENTRY":app \
        --host 0.0.0.0 \
        --port "${PORT:-8000}" \
        --reload >>"$LOG_FILE" 2>&1
}

# Run worker
function run_worker() {
    echo "Starting background worker..."
    poetry run python "$WORKER_ENTRY" >>"$LOG_FILE" 2>&1
}

# Main runner
function main() {
    load_env
    check_dependencies

    case "${1:-app}" in
        app)
            run_app
            ;;
        worker)
            run_worker
            ;;
        both)
            echo "Running app and worker in parallel..."
            run_app &
            run_worker &
            wait
            ;;
        *)
            echo "Usage: $0 [app|worker|both]"
            exit 1
            ;;
    esac
}

main "$@"
