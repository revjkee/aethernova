#!/usr/bin/env bash
# veilmind-core — Industrial Deployment Script
# Safe Bash, observable, idempotent, CI/CD-friendly.

set -Eeuo pipefail

# ----------------------------- Defaults -----------------------------
APP_NAME="${APP_NAME:-veilmind-core}"
ENVIRONMENT="${ENVIRONMENT:-staging}"            # staging|prod|dev
REGISTRY="${REGISTRY:-}"                         # e.g. ghcr.io/org
IMAGE_NAME="${IMAGE_NAME:-$APP_NAME}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"
DOCKER_CONTEXT="${DOCKER_CONTEXT:-.}"
BUILD_ARGS="${BUILD_ARGS:-}"                      # e.g. "HTTP_PROXY=...;FOO=bar"
PLATFORM="${PLATFORM:-linux/amd64}"
PUSH_IMAGE="${PUSH_IMAGE:-true}"                 # true|false

# Kubernetes/Helm
KUBE_CONTEXT="${KUBE_CONTEXT:-}"                 # e.g. prod-cluster
KUBE_NAMESPACE="${KUBE_NAMESPACE:-$APP_NAME}"
HELM_RELEASE="${HELM_RELEASE:-$APP_NAME}"
HELM_CHART_PATH="${HELM_CHART_PATH:-./deploy/helm/veilmind-core}"
HELM_VALUES="${HELM_VALUES:-}"                   # comma-separated list of values files
KUSTOMIZE_DIR="${KUSTOMIZE_DIR:-}"               # alternative to helm
KUBE_MANIFEST="${KUBE_MANIFEST:-}"               # direct manifest path if needed

# Versioning
VERSION="${VERSION:-}"                           # explicit version (optional)
GIT_REF="${GIT_REF:-HEAD}"
TAG_LATEST="${TAG_LATEST:-true}"                 # also tag :latest

# Health / rollout
HEALTH_URL="${HEALTH_URL:-}"                     # e.g. http://svc/health
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"          # seconds
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180}"        # seconds
ROLLOUT_KIND="${ROLLOUT_KIND:-deployment}"       # deployment|statefulset
ROLLOUT_NAME="${ROLLOUT_NAME:-$APP_NAME}"        # k8s object name

# SBOM/Sign (optional)
ENABLE_SBOM="${ENABLE_SBOM:-false}"              # syft
ENABLE_SIGN="${ENABLE_SIGN:-false}"              # cosign

# Behavior
DRY_RUN="${DRY_RUN:-false}"
YES="${YES:-false}"                              # auto-confirm
LOG_LEVEL="${LOG_LEVEL:-INFO}"                   # DEBUG|INFO|WARN|ERROR
RETRIES="${RETRIES:-3}"
RETRY_DELAY="${RETRY_DELAY:-2}"

# ----------------------------- Logging ------------------------------
log_ts() { date +"%Y-%m-%dT%H:%M:%S%z"; }
lvl_num() {
  case "${1:-INFO}" in
    DEBUG) echo 10 ;;
    INFO)  echo 20 ;;
    WARN)  echo 30 ;;
    ERROR) echo 40 ;;
    *)     echo 20 ;;
  esac
}
LOG_LEVEL_NUM="$(lvl_num "$LOG_LEVEL")"

log() {
  local level="${1:-INFO}"; shift
  local msg="$*"
  local ln; ln="$(lvl_num "$level")"
  if (( ln >= LOG_LEVEL_NUM )); then
    printf '{"ts":"%s","lvl":"%s","msg":%s}\n' "$(log_ts)" "$level" "$(printf '%s' "$msg" | jq -Rs . 2>/dev/null || python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))' <<<"$msg")" >&2
  fi
}

die() { log ERROR "$*"; exit 1; }

confirm() {
  if [[ "$YES" == "true" ]]; then return 0; fi
  read -r -p "Продолжить? (yes/NO): " ans
  [[ "${ans:-}" == "yes" ]]
}

run() {
  local cmd="$*"
  if [[ "$DRY_RUN" == "true" ]]; then
    log INFO "DRY_RUN: $cmd"
  else
    log DEBUG "RUN: $cmd"
    eval "$cmd"
  fi
}

retry() {
  local n=0
  until "$@"; do
    n=$((n+1))
    if (( n > RETRIES )); then return 1; fi
    log WARN "Команда неуспешна, попытка $n/$RETRIES: $*"
    sleep "$RETRY_DELAY"
  done
}

# ----------------------------- Helpers ------------------------------
require_bin() {
  local b; for b in "$@"; do command -v "$b" >/dev/null 2>&1 || die "Не найден бинарь: $b"; done
}

git_version() {
  local v
  if [[ -n "$VERSION" ]]; then
    echo "$VERSION"
    return
  fi
  # prefer annotated tag; fallback to short sha with dirty mark
  if v="$(git describe --tags --abbrev=7 --dirty --always "$GIT_REF" 2>/dev/null)"; then
    echo "$v"
  else
    v="$(git rev-parse --short=7 "$GIT_REF" 2>/dev/null || echo "0.0.0")"
    echo "$v"
  fi
}

docker_tag() {
  local ver="$1"
  if [[ -n "$REGISTRY" ]]; then
    echo "$REGISTRY/$IMAGE_NAME:$ver"
  else
    echo "$IMAGE_NAME:$ver"
  fi
}

parse_build_args() {
  local IFS=';'
  for pair in $BUILD_ARGS; do
    [[ -z "$pair" ]] && continue
    echo -n "--build-arg $pair "
  done
}

kubectl_ns() {
  local extra=()
  [[ -n "$KUBE_CONTEXT" ]] && extra+=(--context "$KUBE_CONTEXT")
  [[ -n "$KUBE_NAMESPACE" ]] && extra+=(--namespace "$KUBE_NAMESPACE")
  kubectl "${extra[@]}" "$@"
}

helm_ns() {
  local extra=()
  [[ -n "$KUBE_CONTEXT" ]] && extra+=(--kube-context "$KUBE_CONTEXT")
  [[ -n "$KUBE_NAMESPACE" ]] && extra+=(--namespace "$KUBE_NAMESPACE")
  helm "${extra[@]}" "$@"
}

# ----------------------------- Phases -------------------------------
phase_prepare() {
  log INFO "Фаза: подготовка окружения"
  require_bin git jq
  [[ "$DRY_RUN" == "true" ]] || require_bin docker
  if [[ -n "$KUSTOMIZE_DIR" || -n "$KUBE_MANIFEST" || -d "$HELM_CHART_PATH" ]]; then
    require_bin kubectl
  fi
  if [[ -d "$HELM_CHART_PATH" ]]; then
    require_bin helm
  fi
  if [[ "$ENABLE_SBOM" == "true" ]]; then require_bin syft || die "syft не найден для SBOM"; fi
  if [[ "$ENABLE_SIGN" == "true" ]]; then require_bin cosign || die "cosign не найден для подписи"; fi
  if [[ -n "$KUBE_NAMESPACE" ]]; then
    run "kubectl_ns get ns \"$KUBE_NAMESPACE\" >/dev/null 2>&1 || kubectl_ns create ns \"$KUBE_NAMESPACE\""
  fi
}

phase_build() {
  log INFO "Фаза: сборка Docker-образа"
  local ver; ver="$(git_version)"
  local tag; tag="$(docker_tag "$ver")"
  local latest; latest="$(docker_tag "latest")"

  local args; args="$(parse_build_args)"
  local build_cmd="docker build --platform $PLATFORM -f \"$DOCKERFILE\" $args -t \"$tag\" \"$DOCKER_CONTEXT\""
  retry bash -lc "$build_cmd" || die "Сборка Docker-образа провалилась"

  if [[ "$TAG_LATEST" == "true" ]]; then
    run "docker tag \"$tag\" \"$latest\""
  fi

  if [[ "$ENABLE_SBOM" == "true" ]]; then
    run "syft \"$tag\" -o spdx-json > sbom-$APP_NAME-$ver.spdx.json"
    log INFO "SBOM создан: sbom-$APP_NAME-$ver.spdx.json"
  fi

  if [[ "$ENABLE_SIGN" == "true" ]]; then
    # Требует подготовленного keyless/keypair контекста cosign
    run "cosign sign --yes \"$tag\""
    [[ "$TAG_LATEST" == "true" ]] && run "cosign sign --yes \"$latest\""
  fi
}

phase_push() {
  [[ "$PUSH_IMAGE" == "true" ]] || { log INFO "Пропуск push (PUSH_IMAGE=false)"; return; }
  log INFO "Фаза: публикация образа"
  local ver; ver="$(git_version)"
  local tag; tag="$(docker_tag "$ver")"
  local latest; latest="$(docker_tag "latest")"

  retry docker push "$tag" || die "Публикация образа $tag провалилась"
  if [[ "$TAG_LATEST" == "true" ]]; then
    retry docker push "$latest" || die "Публикация latest провалилась"
  fi
}

phase_deploy_helm() {
  log INFO "Фаза: деплой через Helm"
  local ver; ver="$(git_version)"
  local img; img="$(docker_tag "$ver")"

  local vals=()
  IFS=',' read -r -a tmp_vals <<< "${HELM_VALUES:-}"
  for vf in "${tmp_vals[@]}"; do
    [[ -n "${vf:-}" ]] && vals+=( -f "$vf" )
  done

  local install_cmd=(
    helm_ns upgrade --install "$HELM_RELEASE" "$HELM_CHART_PATH"
    --set image.repository="$(dirname "$img" | sed 's#^$#'"$REGISTRY/$IMAGE_NAME"'#')" \
    --set image.tag="$(basename "$img" | awk -F: '{print $2}')" \
    --set env="$ENVIRONMENT"
  )
  if ((${#vals[@]})); then install_cmd+=("${vals[@]}"); fi
  [[ "$DRY_RUN" == "true" ]] && install_cmd+=( --dry-run )

  retry "${install_cmd[@]}" || die "Helm upgrade/install провалился"

  log INFO "Ожидание rollout: $ROLLOUT_KIND/$ROLLOUT_NAME"
  retry kubectl_ns rollout status "$ROLLOUT_KIND/$ROLLOUT_NAME" --timeout="${ROLLOUT_TIMEOUT}s" \
    || die "Rollout не завершился за ${ROLLOUT_TIMEOUT}s"
}

phase_deploy_kustomize_or_manifests() {
  if [[ -n "$KUSTOMIZE_DIR" ]]; then
    log INFO "Фаза: деплой через kustomize ($KUSTOMIZE_DIR)"
    local cmd=( kubectl_ns apply -k "$KUSTOMIZE_DIR" )
    [[ "$DRY_RUN" == "true" ]] && cmd+=( --dry-run=client )
    retry "${cmd[@]}" || die "kubectl apply -k провалился"
  elif [[ -n "$KUBE_MANIFEST" ]]; then
    log INFO "Фаза: деплой манифестов ($KUBE_MANIFEST)"
    local cmd=( kubectl_ns apply -f "$KUBE_MANIFEST" )
    [[ "$DRY_RUN" == "true" ]] && cmd+=( --dry-run=client )
    retry "${cmd[@]}" || die "kubectl apply -f провалился"
  else
    return 0
  fi

  log INFO "Ожидание rollout: $ROLLOUT_KIND/$ROLLOUT_NAME"
  retry kubectl_ns rollout status "$ROLLOUT_KIND/$ROLLOUT_NAME" --timeout="${ROLLOUT_TIMEOUT}s" \
    || die "Rollout не завершился за ${ROLLOUT_TIMEOUT}s"
}

phase_migrate() {
  # Опционально: выполнить миграции БД через Kubernetes Job/helm hook
  [[ -z "${MIGRATE_JOB_NAME:-}" ]] && { log INFO "Миграции отключены"; return; }
  log INFO "Фаза: миграции ($MIGRATE_JOB_NAME)"
  # Перезапуск job
  run "kubectl_ns delete job \"$MIGRATE_JOB_NAME\" --ignore-not-found"
  retry kubectl_ns create -f "${MIGRATE_JOB_MANIFEST:?MIGRATE_JOB_MANIFEST не задан}" || die "Создание job миграции провалилось"
  retry kubectl_ns wait --for=condition=complete "job/$MIGRATE_JOB_NAME" --timeout=300s || die "Миграции не завершились"
}

phase_healthcheck() {
  [[ -n "$HEALTH_URL" ]] || { log INFO "Health-check URL не задан"; return; }
  log INFO "Фаза: health-check ($HEALTH_URL)"
  require_bin curl
  local start ts
  start="$(date +%s)"
  while true; do
    if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
      log INFO "Health-check OK"
      break
    fi
    ts="$(date +%s)"
    if (( ts - start > HEALTH_TIMEOUT )); then
      die "Health-check не прошёл за ${HEALTH_TIMEOUT}s"
    fi
    sleep 2
  done
}

phase_status() {
  log INFO "Статус релиза"
  if [[ -d "$HELM_CHART_PATH" ]]; then
    helm_ns status "$HELM_RELEASE" || true
  fi
  kubectl_ns get pods -o wide || true
}

phase_rollback() {
  log WARN "Откат релиза"
  if [[ -d "$HELM_CHART_PATH" ]]; then
    helm_ns rollback "$HELM_RELEASE" 1 || die "Helm rollback не удался"
  else
    kubectl_ns rollout undo "$ROLLOUT_KIND/$ROLLOUT_NAME" || die "kubectl rollout undo не удался"
  fi
}

# ----------------------------- CLI -------------------------------
usage() {
  cat <<EOF
Использование: $(basename "$0") <команда> [опции]
Команды:
  prepare      — проверка окружения, создание namespace
  build        — сборка Docker-образа (и SBOM/подпись при включении)
  push         — публикация образа в реестр
  deploy       — деплой (Helm при наличии чартов, иначе kustomize/manifest)
  migrate      — запуск миграций (если MIGRATE_JOB_* заданы)
  health       — health-check приложения
  status       — краткий статус релиза/подов
  all          — полный цикл: prepare -> build -> push -> deploy -> migrate -> health
  rollback     — откат релиза (helm rollback или kubectl rollout undo)

Переменные окружения управляют поведением (см. верх файла). Флаги:
  DRY_RUN=true   — только показать команды без выполнения
  YES=true       — не спрашивать подтверждение

Примеры:
  ENVIRONMENT=prod REGISTRY=ghcr.io/org ./scripts/deploy.sh all
  DRY_RUN=true ./scripts/deploy.sh deploy
EOF
}

main() {
  local cmd="${1:-}"; shift || true
  case "${cmd:-}" in
    prepare)  phase_prepare ;;
    build)    phase_prepare; phase_build ;;
    push)     phase_push ;;
    deploy)   phase_prepare; confirm || die "Отменено"; phase_deploy_helm; phase_deploy_kustomize_or_manifests ;;
    migrate)  phase_migrate ;;
    health)   phase_healthcheck ;;
    status)   phase_status ;;
    rollback) confirm || die "Отменено"; phase_rollback ;;
    all)
      phase_prepare
      confirm || die "Отменено"
      phase_build
      phase_push
      phase_deploy_helm
      phase_deploy_kustomize_or_manifests
      phase_migrate
      phase_healthcheck
      phase_status
      ;;
    *) usage; exit 2 ;;
  esac
}

# Load .env if present (non-fatal)
if [[ -f ".env" ]]; then
  # shellcheck source=/dev/null
  . ".env"
fi

main "$@"
