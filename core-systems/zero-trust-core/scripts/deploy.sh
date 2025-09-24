# path: zero-trust-core/scripts/deploy.sh
#!/usr/bin/env bash
# Industrial Zero-Trust deploy script for zero-trust-core
# - Safe Bash: strict mode, traps, no secrets in logs
# - Deterministic Docker build with BuildKit, minimal context
# - Optional cosign signing, SBOM, attestations
# - Helm deploy with canary / blue-green strategies
# - Rollout verification and safe rollback
# - Dry-run support and JSON audit logs

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# --------------- Globals / Defaults ---------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

AUDIT_JSON="${AUDIT_JSON:-0}"
DRY_RUN=0
PUSH=1
SIGN=0
SBOM=0

IMAGE_NAME="zerotrust/zero-trust-core"
IMAGE_TAG="$(date -u +%Y%m%d.%H%M%S)"
REGISTRY=""
PLATFORM="${PLATFORM:-linux/amd64}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"

KUBE_CONTEXT=""
NAMESPACE="zerotrust"
HELM_RELEASE="zero-trust-core"
HELM_CHART="${HELM_CHART:-./deploy/helm/zero-trust-core}"
HELM_VALUES=()
HELM_SET=()

STRATEGY="standard" # standard|canary|bluegreen
CANARY_WEIGHT="10"
TIMEOUT="300s"
ROLLBACK_ON_FAIL=1

SOPS_FILE=""
BUILD_SECRET_FILE=""
BUILD_CONTEXT="."

# --------------- Utilities ---------------
log() {
  local level="$1"; shift
  local msg="$*"
  if [[ "${AUDIT_JSON}" == "1" ]]; then
    # Minimal JSON without secrets
    printf '{"ts":"%s","level":"%s","msg":%q}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${level}" "${msg}"
  else
    printf "[%s] %s %s\n" "$(date -u +%H:%M:%S)" "${level^^}" "${msg}"
  fi
}

die() {
  log error "$*"
  exit 1
}

run() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    log info "(dry-run) $*"
    return 0
  fi
  log info "exec: $*"
  "$@"
}

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    log error "failed with exit code ${rc}"
  fi
  exit $rc
}
trap cleanup EXIT

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Build and deploy zero-trust-core with Zero-Trust safeguards.

Options:
  --registry REG              Container registry (e.g. ghcr.io/org) [required]
  --image NAME                Image name (default: ${IMAGE_NAME})
  --tag TAG                   Image tag (default: ${IMAGE_TAG})
  --platform P                Target platform (default: ${PLATFORM})
  --dockerfile PATH           Dockerfile path (default: ${DOCKERFILE})
  --context PATH              Build context (default: ${BUILD_CONTEXT})
  --no-push                   Do not push image

  --sign                      Cosign sign image (requires COSIGN_*)
  --sbom                      Generate and attach SBOM (syft/cyclonedx)

  --kube-context CTX          kubectl/helm context
  --namespace NS              Kubernetes namespace (default: ${NAMESPACE})
  --release NAME              Helm release (default: ${HELM_RELEASE})
  --chart PATH|NAME           Helm chart path or repo ref (default: ${HELM_CHART})
  --values FILE               Helm values.yaml (repeatable)
  --set k=v                   Helm --set (repeatable)
  --strategy TYPE             standard|canary|bluegreen (default: ${STRATEGY})
  --canary-weight N           Traffic weight for canary 0-100 (default: ${CANARY_WEIGHT})
  --timeout DUR               Rollout timeout (default: ${TIMEOUT})
  --no-rollback               Do not rollback on failure

  --sops FILE                 Decrypt secrets with sops before deploy
  --build-secret FILE         Pass build secret to Docker (buildkit secret)
  --dry-run                   Plan only, no changes
  --audit-json                JSON audit logs

Examples:
  $0 --registry ghcr.io/acme --values deploy/values.prod.yaml --sign --sbom --strategy canary --canary-weight 20
EOF
}

# --------------- Argparse ---------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --registry) REGISTRY="$2"; shift 2;;
    --image) IMAGE_NAME="$2"; shift 2;;
    --tag) IMAGE_TAG="$2"; shift 2;;
    --platform) PLATFORM="$2"; shift 2;;
    --dockerfile) DOCKERFILE="$2"; shift 2;;
    --context) BUILD_CONTEXT="$2"; shift 2;;
    --no-push) PUSH=0; shift;;
    --sign) SIGN=1; shift;;
    --sbom) SBOM=1; shift;;
    --kube-context) KUBE_CONTEXT="$2"; shift 2;;
    --namespace) NAMESPACE="$2"; shift 2;;
    --release) HELM_RELEASE="$2"; shift 2;;
    --chart) HELM_CHART="$2"; shift 2;;
    --values) HELM_VALUES+=("$2"); shift 2;;
    --set) HELM_SET+=("$2"); shift 2;;
    --strategy) STRATEGY="$2"; shift 2;;
    --canary-weight) CANARY_WEIGHT="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    --no-rollback) ROLLBACK_ON_FAIL=0; shift;;
    --sops) SOPS_FILE="$2"; shift 2;;
    --build-secret) BUILD_SECRET_FILE="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    --audit-json) AUDIT_JSON=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done

[[ -z "${REGISTRY}" ]] && die "--registry is required"

# --------------- Preflight checks ---------------
preflight() {
  have docker || die "docker is required"
  have helm || die "helm is required"
  have kubectl || die "kubectl is required"
  export DOCKER_BUILDKIT=1
  export COMPOSE_DOCKER_CLI_BUILD=1

  if [[ "${SIGN}" == "1" ]]; then
    have cosign || die "cosign is required for --sign"
    : "${COSIGN_EXPERIMENTAL:=1}"
  fi
  if [[ "${SBOM}" == "1" ]]; then
    if ! have syft && ! have cyclonedx; then
      die "syft or cyclonedx is required for --sbom"
    fi
  fi
  if [[ -n "${SOPS_FILE}" ]]; then
    have sops || die "sops is required for --sops"
    [[ -r "${SOPS_FILE}" ]] || die "sops file not readable: ${SOPS_FILE}"
  fi

  # Validate strategy
  case "${STRATEGY}" in
    standard|canary|bluegreen) ;;
    *) die "invalid --strategy: ${STRATEGY}" ;;
  esac

  # kube context
  if [[ -n "${KUBE_CONTEXT}" ]]; then
    run kubectl config use-context "${KUBE_CONTEXT}" >/dev/null
  fi
  run kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || run kubectl create ns "${NAMESPACE}"
}

# --------------- Secrets handling ---------------
decrypt_sops() {
  [[ -z "${SOPS_FILE}" ]] && return 0
  local out="${REPO_ROOT}/.secrets.dec.yaml"
  log info "decrypting secrets with sops -> ${out}"
  if [[ "${DRY_RUN}" == "1" ]]; then
    log info "(dry-run) sops -d ${SOPS_FILE} > ${out}"
  else
    sops -d "${SOPS_FILE}" > "${out}"
    chmod 600 "${out}"
    HELM_VALUES+=("${out}")
  fi
}

# --------------- Build & Push ---------------
build_and_push() {
  local ref="${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
  local build_args=(
    --file "${DOCKERFILE}"
    --platform "${PLATFORM}"
    --progress=plain
    --no-cache
    --pull
    "${BUILD_CONTEXT}"
  )

  # Build secrets via buildkit
  if [[ -n "${BUILD_SECRET_FILE}" ]]; then
    [[ -r "${BUILD_SECRET_FILE}" ]] || die "build secret file not readable: ${BUILD_SECRET_FILE}"
    build_args=(--secret "id=build_secret,src=${BUILD_SECRET_FILE}" "${build_args[@]}")
  fi

  log info "docker build -> ${ref}"
  run docker build -t "${ref}" "${build_args[@]}"

  if [[ "${PUSH}" == "1" ]]; then
    log info "docker push -> ${ref}"
    run docker push "${ref}"
  fi

  # SBOM
  if [[ "${SBOM}" == "1" ]]; then
    local sbom_path="${REPO_ROOT}/sbom-${IMAGE_TAG}.json"
    if have syft; then
      log info "syft sbom -> ${sbom_path}"
      run syft "registry:${ref}" -o cyclonedx-json > "${sbom_path}"
    elif have cyclonedx; then
      log info "cyclonedx sbom -> ${sbom_path}"
      run cyclonedx docker:generate --image "${ref}" --output "${sbom_path}" --format json
    fi
    chmod 600 "${sbom_path}"
  fi

  # Cosign
  if [[ "${SIGN}" == "1" && "${PUSH}" == "1" ]]; then
    log info "cosign sign -> ${ref}"
    run cosign sign --yes "${ref}"
    log info "cosign verify -> ${ref}"
    run cosign verify "${ref}" >/dev/null
  fi

  export IMAGE_REF="${ref}"
}

# --------------- Helm Deploy ---------------
helm_args_common() {
  local args=(--namespace "${NAMESPACE}")
  for v in "${HELM_VALUES[@]}"; do
    args+=(-f "${v}")
  done
  for s in "${HELM_SET[@]}"; do
    args+=(--set "${s}")
  done
  args+=(--set "image.repository=${REGISTRY}/${IMAGE_NAME%:*}")
  args+=(--set "image.tag=${IMAGE_TAG}")
  printf '%s\n' "${args[@]}"
}

deploy_standard() {
  local args=()
  mapfile -t args < <(helm_args_common)
  log info "helm upgrade --install (standard)"
  run helm upgrade --install "${HELM_RELEASE}" "${HELM_CHART}" \
    --create-namespace --atomic --timeout "${TIMEOUT}" "${args[@]}"
}

deploy_canary() {
  local args=()
  mapfile -t args < <(helm_args_common)
  args+=(--set "deploymentStrategy=canary" --set "canary.weight=${CANARY_WEIGHT}")
  log info "helm upgrade --install (canary weight=${CANARY_WEIGHT})"
  run helm upgrade --install "${HELM_RELEASE}" "${HELM_CHART}" \
    --create-namespace --timeout "${TIMEOUT}" "${args[@]}"

  # Verify primary stays healthy
  verify_rollout
}

deploy_bluegreen() {
  local args=()
  mapfile -t args < <(helm_args_common)
  args+=(--set "deploymentStrategy=bluegreen")
  log info "helm upgrade --install (blue-green)"
  run helm upgrade --install "${HELM_RELEASE}" "${HELM_CHART}" \
    --create-namespace --timeout "${TIMEOUT}" "${args[@]}"

  verify_rollout
}

verify_rollout() {
  log info "verifying rollout for ${HELM_RELEASE} in ns=${NAMESPACE}"
  local kind="deployment"
  # Attempt to detect workload name label app.kubernetes.io/name
  local deploy
  deploy="$(kubectl -n "${NAMESPACE}" get deploy -l app.kubernetes.io/instance="${HELM_RELEASE}" -o jsonpath='{.items[0].metadata.name}' || true)"
  if [[ -z "${deploy}" ]]; then
    log info "no deploy found by label, using release name"
    deploy="${HELM_RELEASE}"
  fi
  if [[ "${DRY_RUN}" == "1" ]]; then
    log info "(dry-run) kubectl -n ${NAMESPACE} rollout status deploy/${deploy} --timeout=${TIMEOUT}"
  else
    if ! kubectl -n "${NAMESPACE}" rollout status "deploy/${deploy}" --timeout="${TIMEOUT}"; then
      log error "rollout failed for deploy/${deploy}"
      if [[ "${ROLLBACK_ON_FAIL}" == "1" ]]; then
        log info "rolling back helm release ${HELM_RELEASE}"
        helm rollback "${HELM_RELEASE}" 0 --namespace "${NAMESPACE}" || true
      fi
      exit 1
    fi
  fi
}

# --------------- Main ---------------
main() {
  preflight
  decrypt_sops
  build_and_push

  case "${STRATEGY}" in
    standard)  deploy_standard ;;
    canary)    deploy_canary ;;
    bluegreen) deploy_bluegreen ;;
  esac

  verify_rollout
  log info "deploy succeeded: ${IMAGE_REF} -> ${HELM_RELEASE}/${NAMESPACE}"
}

main "$@"
