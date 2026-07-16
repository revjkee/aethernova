#!/usr/bin/env bash
# chronowatch-core: industrial deployment helper
# Modes: docker-compose OR kubernetes (helm)
# Usage examples:
#   ./scripts/deploy.sh --mode compose --env dev
#   ./scripts/deploy.sh --mode k8s --env staging --image-repo ghcr.io/org/chronowatch-core --push
#   ./scripts/deploy.sh --mode k8s --env prod --namespace chronowatch-prod --wait-sec 180

set -Eeuo pipefail

#######################################
# Global defaults
#######################################
APP_NAME="${APP_NAME:-chronowatch-core}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="${CHART_DIR:-${ROOT_DIR}/helm}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-${ROOT_DIR}/docker/Dockerfile}"

MODE="compose"          # compose|k8s
ENVIRONMENT="dev"       # dev|staging|prod
NAMESPACE=""            # auto: ${APP_NAME}-${ENVIRONMENT} for k8s
IMAGE_REPO="${IMAGE_REPO:-${APP_NAME}}"  # e.g. ghcr.io/org/chronowatch-core
IMAGE_TAG=""            # auto: from VERSION or git
PUSH_IMAGE="false"      # --push to enable
NO_CACHE="false"        # --no-cache to disable layer cache
WAIT_SEC=120            # wait for readiness/rollout
DRY_RUN="false"         # don't execute mutating commands
HELM_VALUES=""          # optional values file
HEALTH_URL="${HEALTH_URL:-http://localhost:8080/readyz}" # for compose wait
EXTRA_HELM_SET=()       # advanced: extra --set key=value pairs

#######################################
# Logging helpers
#######################################
log()   { printf "[%s] %s\n" "INFO" "$*"; }
warn()  { printf "[%s] %s\n" "WARN" "$*" >&2; }
error() { printf "[%s] %s\n" "ERROR" "$*" >&2; }
die()   { error "$*"; exit 1; }

on_err() {
  local code=$?
  error "Deployment failed with exit code ${code}"
  exit "${code}"
}
trap on_err ERR

#######################################
# Requirements
#######################################
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

#######################################
# Argument parsing
#######################################
print_help() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --mode [compose|k8s]           Deployment mode (default: compose)
  --env [dev|staging|prod]       Environment name (default: dev)
  --namespace NAME               K8s namespace (default: \${APP_NAME}-\${ENV})
  --image-repo REPO              Container registry/repo (default: ${IMAGE_REPO})
  --tag TAG                      Image tag (default: VERSION file or git short sha)
  --push                         Push image to registry after build
  --no-cache                     Build image with --no-cache
  --wait-sec N                   Wait seconds for health/rollout (default: ${WAIT_SEC})
  --helm-values FILE             Additional Helm values.yaml
  --set KEY=VALUE                Extra Helm --set (repeatable)
  --health-url URL               Compose readiness URL (default: ${HEALTH_URL})
  --dry-run                      Print actions without executing mutating steps
  -h, --help                     Show this help

Environment variables (optional):
  APP_NAME, CHART_DIR, DOCKERFILE_PATH, IMAGE_REPO, HEALTH_URL
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --env) ENVIRONMENT="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --image-repo) IMAGE_REPO="$2"; shift 2 ;;
    --tag) IMAGE_TAG="$2"; shift 2 ;;
    --push) PUSH_IMAGE="true"; shift 1 ;;
    --no-cache) NO_CACHE="true"; shift 1 ;;
    --wait-sec) WAIT_SEC="$2"; shift 2 ;;
    --helm-values) HELM_VALUES="$2"; shift 2 ;;
    --set) EXTRA_HELM_SET+=("$2"); shift 2 ;;
    --health-url) HEALTH_URL="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift 1 ;;
    -h|--help) print_help; exit 0 ;;
    *) die "Unknown argument: $1 (see --help)";;
  esac
done

#######################################
# Derived values
#######################################
if [[ -z "${IMAGE_TAG}" ]]; then
  if [[ -f "${ROOT_DIR}/VERSION" ]]; then
    IMAGE_TAG="$(tr -d ' \t\r\n' < "${ROOT_DIR}/VERSION")"
  elif git -C "${ROOT_DIR}" rev-parse --short HEAD >/dev/null 2>&1; then
    IMAGE_TAG="$(git -C "${ROOT_DIR}" rev-parse --short HEAD)"
  else
    IMAGE_TAG="$(date +%Y%m%d%H%M%S)"
  fi
fi
IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

if [[ -z "${NAMESPACE}" ]]; then
  NAMESPACE="${APP_NAME}-${ENVIRONMENT}"
fi

ENV_FILE_BASE="${ROOT_DIR}/.env"
ENV_FILE_ENV="${ROOT_DIR}/.env.${ENVIRONMENT}"
TMP_ENV_FILE="$(mktemp -t ${APP_NAME}.env.XXXXXX)"

#######################################
# Env merging (.env + .env.<env>)
#######################################
merge_env_files() {
  : > "${TMP_ENV_FILE}"
  if [[ -f "${ENV_FILE_BASE}" ]]; then
    log "Merging ${ENV_FILE_BASE}"
    cat "${ENV_FILE_BASE}" >> "${TMP_ENV_FILE}"
  else
    warn "Base env file not found: ${ENV_FILE_BASE} (continuing)"
  fi
  if [[ -f "${ENV_FILE_ENV}" ]]; then
    log "Merging ${ENV_FILE_ENV}"
    cat "${ENV_FILE_ENV}" >> "${TMP_ENV_FILE}"
  else
    warn "Environment env file not found: ${ENV_FILE_ENV} (continuing)"
  fi
  # Ensure required defaults for chronowatch-core if absent
  grep -q '^DATABASE_URL=' "${TMP_ENV_FILE}" 2>/dev/null || echo "DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/chronowatch" >> "${TMP_ENV_FILE}"
  grep -q '^REDIS_URL=' "${TMP_ENV_FILE}" 2>/dev/null || echo "REDIS_URL=redis://redis:6379/0" >> "${TMP_ENV_FILE}"
  grep -q '^LOG_LEVEL=' "${TMP_ENV_FILE}" 2>/dev/null || echo "LOG_LEVEL=INFO" >> "${TMP_ENV_FILE}"
  grep -q '^RBAC_ADMIN_TOKEN=' "${TMP_ENV_FILE}" 2>/dev/null || echo "RBAC_ADMIN_TOKEN=change-me" >> "${TMP_ENV_FILE}"
  grep -q '^SCHED_TICK_MS=' "${TMP_ENV_FILE}" 2>/dev/null || echo "SCHED_TICK_MS=500" >> "${TMP_ENV_FILE}"
  grep -q '^LEADER_TTL_SEC=' "${TMP_ENV_FILE}" 2>/dev/null || echo "LEADER_TTL_SEC=10" >> "${TMP_ENV_FILE}"
}

#######################################
# Docker build & optional push
#######################################
docker_build() {
  require_cmd docker
  local args=(build -f "${DOCKERFILE_PATH}" -t "${IMAGE}" "${ROOT_DIR}")
  if [[ "${NO_CACHE}" == "true" ]]; then
    args=(--no-cache "${args[@]}")
  fi
  log "Building image ${IMAGE}"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "docker ${args[*]}"; return 0
  fi
  docker "${args[@]}"
}

docker_push() {
  [[ "${PUSH_IMAGE}" != "true" ]] && return 0
  require_cmd docker
  log "Pushing image ${IMAGE}"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "docker push ${IMAGE}"; return 0
  fi
  docker push "${IMAGE}"
}

#######################################
# Compose deploy
#######################################
compose_up() {
  require_cmd docker
  require_cmd curl
  if ! docker compose version >/dev/null 2>&1; then
    die "docker compose plugin not found (install Docker Compose v2)"
  fi
  log "Starting via docker-compose"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "docker compose --env-file ${TMP_ENV_FILE} -f ${ROOT_DIR}/docker-compose.yml up -d"
  else
    docker compose --env-file "${TMP_ENV_FILE}" -f "${ROOT_DIR}/docker-compose.yml" up -d
  fi
  wait_http "${HEALTH_URL}" "${WAIT_SEC}"
}

#######################################
# HTTP readiness wait (compose)
#######################################
wait_http() {
  local url="$1" ; local timeout="$2"
  require_cmd curl
  log "Waiting for readiness at ${url} (timeout ${timeout}s)"
  local start=$(date +%s)
  until curl -fsS "${url}" >/dev/null 2>&1; do
    sleep 2
    local now=$(date +%s)
    if (( now - start > timeout )); then
      die "Readiness URL did not become healthy: ${url}"
    fi
  done
  log "Service is ready at ${url}"
}

#######################################
# Kubernetes helpers
#######################################
k8s_prepare() {
  require_cmd kubectl
  require_cmd helm
  [[ -d "${CHART_DIR}" ]] || die "Helm chart directory not found: ${CHART_DIR}"
  if [[ ! -d "${CHART_DIR}/templates" ]]; then
    die "Helm chart templates not found: ${CHART_DIR}/templates (cannot deploy to k8s)"
  fi
}

k8s_namespace() {
  log "Ensuring namespace ${NAMESPACE}"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "kubectl create namespace ${NAMESPACE} || true"
  else
    kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}"
  fi
}

k8s_secret_from_env() {
  local secret_name="${APP_NAME}-env"
  log "Applying secret ${secret_name} from merged env"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "kubectl -n ${NAMESPACE} create secret generic ${secret_name} --from-env-file=${TMP_ENV_FILE} --dry-run=client -o yaml | kubectl apply -f -"
  else
    kubectl -n "${NAMESPACE}" create secret generic "${secret_name}" \
      --from-env-file="${TMP_ENV_FILE}" \
      --dry-run=client -o yaml | kubectl apply -f -
  fi
}

helm_upgrade_install() {
  local set_args=(
    "--set" "image.repository=${IMAGE_REPO}"
    "--set" "image.tag=${IMAGE_TAG}"
    "--set" "env.LOG_LEVEL=$(grep -E '^LOG_LEVEL=' "${TMP_ENV_FILE}" | cut -d= -f2-)"
    "--set" "env.SCHED_TICK_MS=$(grep -E '^SCHED_TICK_MS=' "${TMP_ENV_FILE}" | cut -d= -f2-)"
    "--set" "env.LEADER_TTL_SEC=$(grep -E '^LEADER_TTL_SEC=' "${TMP_ENV_FILE}" | cut -d= -f2-)"
    "--set" "env.RBAC_ADMIN_TOKEN=$(grep -E '^RBAC_ADMIN_TOKEN=' "${TMP_ENV_FILE}" | cut -d= -f2-)"
    "--namespace" "${NAMESPACE}"
  )
  for kv in "${EXTRA_HELM_SET[@]}"; do
    set_args+=("--set" "$kv")
  done

  local values_args=()
  if [[ -n "${HELM_VALUES}" ]]; then
    [[ -f "${HELM_VALUES}" ]] || die "Helm values file not found: ${HELM_VALUES}"
    values_args=( -f "${HELM_VALUES}" )
  fi

  log "Helm upgrade --install ${APP_NAME} (repo=${IMAGE_REPO}, tag=${IMAGE_TAG})"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "helm upgrade --install ${APP_NAME} ${CHART_DIR} ${values_args[*]} ${set_args[*]} --dry-run"
    helm upgrade --install "${APP_NAME}" "${CHART_DIR}" "${values_args[@]}" "${set_args[@]}" --dry-run >/dev/null
  else
    helm upgrade --install "${APP_NAME}" "${CHART_DIR}" "${values_args[@]}" "${set_args[@]}"
  fi
}

k8s_wait_rollout() {
  log "Waiting for rollout (timeout ${WAIT_SEC}s)"
  local deploy
  # Try to detect deployment name by label selector app.kubernetes.io/name=${APP_NAME}
  deploy="$(kubectl -n "${NAMESPACE}" get deploy -l app.kubernetes.io/name="${APP_NAME}" -o name 2>/dev/null | head -n1 || true)"
  if [[ -z "${deploy}" ]]; then
    # fallback: single deployment in namespace with app label
    deploy="$(kubectl -n "${NAMESPACE}" get deploy -o name 2>/dev/null | head -n1 || true)"
  fi
  [[ -n "${deploy}" ]] || die "Could not determine deployment to wait for"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "kubectl -n ${NAMESPACE} rollout status ${deploy} --timeout=${WAIT_SEC}s"
  else
    kubectl -n "${NAMESPACE}" rollout status "${deploy}" --timeout="${WAIT_SEC}s"
  fi
  log "Rollout complete: ${deploy}"
}

#######################################
# Optional: migrations (safe no-op)
# Скрипт НЕ гарантирует наличие Alembic в образе.
# Выполнит миграции только если обнаружит alembic.ini и каталог alembic.
#######################################
maybe_run_migrations() {
  local have_alembic_ini="false"
  local have_alembic_dir="false"
  [[ -f "${ROOT_DIR}/alembic.ini" ]] && have_alembic_ini="true"
  [[ -d "${ROOT_DIR}/alembic" ]] && have_alembic_dir="true"

  if [[ "${have_alembic_ini}" == "true" && "${have_alembic_dir}" == "true" ]]; then
    warn "Attempting migrations is disabled by default to avoid inconsistent drivers."
    warn "Reason: provided alembic.ini may contain async URL (asyncpg), which is incompatible with sync Alembic engine."
    warn "Skip migrations or fix alembic.ini/engine before enabling this step."
    # To enable (at your own risk), uncomment the block below and ensure correct driver in alembic.ini:
    # require_cmd python3
    # require_cmd pip
    # log "Running Alembic migrations on host Python (isolated env)..."
    # python3 - <<'PY'
    # from alembic.config import Config
    # from alembic import command
    # cfg = Config("alembic.ini")
    # command.upgrade(cfg, "head")
    # PY
  else
    log "Migrations skipped (alembic files not found)"
  fi
}

#######################################
# Main flow
#######################################
main() {
  log "Deployment started for ${APP_NAME}"
  log "Mode=${MODE} Env=${ENVIRONMENT} Image=${IMAGE} Push=${PUSH_IMAGE} DryRun=${DRY_RUN}"

  merge_env_files
  docker_build
  docker_push

  case "${MODE}" in
    compose)
      compose_up
      ;;
    k8s)
      k8s_prepare
      k8s_namespace
      k8s_secret_from_env
      helm_upgrade_install
      k8s_wait_rollout
      ;;
    *)
      die "Unsupported mode: ${MODE}"
      ;;
  esac

  # Optional migrations (safe no-op with warning)
  maybe_run_migrations

  log "Deployment finished successfully"
  log "Summary:"
  log "  Mode:        ${MODE}"
  log "  Environment: ${ENVIRONMENT}"
  log "  Image:       ${IMAGE}"
  if [[ "${MODE}" == "k8s" ]]; then
    log "  Namespace:   ${NAMESPACE}"
  else
    log "  Health URL:  ${HEALTH_URL}"
  fi
}

main "$@"
