#!/usr/bin/env bash
# omnimind-core: промышленный деплой
# Поддерживает: buildx multi-arch, SBOM, Trivy, Cosign, Helm, K8s rollout/rollback.

set -Eeuo pipefail

###############################################################################
# Константы и окружение
###############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION_FILE="${REPO_ROOT}/VERSION"
CHANGELOG_FILE="${REPO_ROOT}/CHANGELOG.md"

# OCI метаданные
OCI_TITLE="omnimind-core"
OCI_URL="${OCI_URL:-https://example.com/omnimind-core}"
OCI_VENDOR="${OCI_VENDOR:-Aethernova}"
OCI_LICENSE="${OCI_LICENSE:-Apache-2.0}"

# Пути чартов/значений
HELM_CHART_DIR="${HELM_CHART_DIR:-${REPO_ROOT}/charts/omnimind-core}"
VALUES_DIR_DEFAULT="${REPO_ROOT}/deploy/envs"

# Настройки сканирования/подписи
TRIVY_SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH}"
TRIVY_IGNORE_UNFIXED="${TRIVY_IGNORE_UNFIXED:-true}"
COSIGN_EXPERIMENTAL="${COSIGN_EXPERIMENTAL:-1}"

# Выходные артефакты
DIST_DIR="${REPO_ROOT}/dist"
mkdir -p "${DIST_DIR}"

###############################################################################
# Логирование и утилиты
###############################################################################
log()  { printf "[INFO] %s\n" "$*"; }
warn() { printf "[WARN] %s\n" "$*" >&2; }
err()  { printf "[ERROR] %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Требуется команда: $1"; }

semver_valid() {
  [[ "$1" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([-+][0-9A-Za-z\.-]+)?$ ]]
}

git_sha() {
  git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo "nogit"
}

git_branch() {
  git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown"
}

timestamp_rfc3339() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

cleanup() {
  if [[ -n "${BUILDX_BUILDER:-}" ]]; then
    docker buildx rm -f "${BUILDX_BUILDER}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

###############################################################################
# Использование
###############################################################################
usage() {
  cat <<EOF
Использование: $(basename "$0") [опции] [действия]

Действия (через запятую или по одному):
  build         Сборка Docker-образа
  scan          Сканирование уязвимостей (trivy)
  sbom          Генерация SBOM (syft)
  sign          Подпись образа (cosign)
  push          Публикация образа в реестр
  deploy        Helm upgrade/install в Kubernetes
  all           Последовательно: build, scan, sbom, sign, push, deploy

Опции:
  -e, --env ENV                 Окружение: dev|staging|prod (обязательно для deploy)
  -r, --registry REGISTRY       Регистри: например ghcr.io/org
  -i, --image IMAGE             Имя образа без реестра (например omnimind-core)
  -t, --tag TAG                 Явный тег образа (по умолчанию: из VERSION + git sha)
  -n, --namespace NAMESPACE     K8s namespace (по умолчанию: omnimind)
  -c, --context KUBE_CONTEXT    kubectl context (опционально)
      --platforms LIST          Платформы для buildx (по умолчанию: linux/amd64,linux/arm64)
      --no-cache                Сборка без кэша
      --push-in-build           Пушить во время buildx (multi-arch обязательно)
      --values FILE             Файл values.yaml для Helm (по умолчанию: deploy/envs/\$ENV.yaml)
      --release NAME            Имя релиза Helm (по умолчанию: omnimind-core)
      --set KEY=VAL             Доп. параметры Helm (можно повторять)
      --dry-run                 Сухой прогон Helm
  -h, --help                    Эта справка

Примеры:
  $(basename "$0") -r ghcr.io/acme -i omnimind-core all
  $(basename "$0") -r ghcr.io/acme -i omnimind-core -e staging deploy
EOF
}

###############################################################################
# Парсинг аргументов
###############################################################################
ACTIONS=()
ENVIRONMENT=""
REGISTRY=""
IMAGE=""
TAG=""
NAMESPACE="omnimind"
KUBE_CONTEXT=""
PLATFORMS="linux/amd64,linux/arm64"
NO_CACHE="false"
PUSH_IN_BUILD="false"
VALUES_FILE=""
HELM_RELEASE="omnimind-core"
HELM_SET_ARGS=()
HELM_DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    build|scan|sbom|sign|push|deploy|all)
      IFS=',' read -r -a parts <<< "$1"
      ACTIONS+=("${parts[@]}")
      shift
      ;;
    -e|--env) ENVIRONMENT="$2"; shift 2 ;;
    -r|--registry) REGISTRY="$2"; shift 2 ;;
    -i|--image) IMAGE="$2"; shift 2 ;;
    -t|--tag) TAG="$2"; shift 2 ;;
    -n|--namespace) NAMESPACE="$2"; shift 2 ;;
    -c|--context) KUBE_CONTEXT="$2"; shift 2 ;;
    --platforms) PLATFORMS="$2"; shift 2 ;;
    --no-cache) NO_CACHE="true"; shift ;;
    --push-in-build) PUSH_IN_BUILD="true"; shift ;;
    --values) VALUES_FILE="$2"; shift 2 ;;
    --release) HELM_RELEASE="$2"; shift 2 ;;
    --set) HELM_SET_ARGS+=("--set" "$2"); shift 2 ;;
    --dry-run) HELM_DRY_RUN="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Неизвестный аргумент: $1"; usage; exit 1 ;;
  esac
done

if [[ ${#ACTIONS[@]} -eq 0 ]]; then
  usage; exit 1
fi

###############################################################################
# Проверки и вычисления
###############################################################################
need_cmd docker
need_cmd git

# Версия
[[ -f "${VERSION_FILE}" ]] || die "Нет файла VERSION по пути: ${VERSION_FILE}"
VERSION="$(<"${VERSION_FILE}")"
semver_valid "${VERSION}" || die "VERSION=${VERSION} не соответствует SemVer"

GIT_SHA="$(git_sha)"
GIT_BRANCH="$(git_branch)"
BUILD_DATE="$(timestamp_rfc3339)"

if [[ -z "${REGISTRY}" ]]; then
  die "Укажите --registry"
fi
if [[ -z "${IMAGE}" ]]; then
  IMAGE="omnimind-core"
  warn "Не указано --image, использую по умолчанию: ${IMAGE}"
fi

if [[ -z "${TAG}" ]]; then
  # Пример тега: 0.1.0+abc1234
  TAG="${VERSION}-${GIT_SHA}"
fi

IMAGE_REF="${REGISTRY}/${IMAGE}:${TAG}"
IMAGE_REF_LATEST="${REGISTRY}/${IMAGE}:latest"

# Helm values по окружению
if [[ -z "${VALUES_FILE}" && -n "${ENVIRONMENT}" ]]; then
  ENV_CANDIDATE="${VALUES_DIR_DEFAULT}/${ENVIRONMENT}.yaml"
  [[ -f "${ENV_CANDIDATE}" ]] && VALUES_FILE="${ENV_CANDIDATE}"
fi

###############################################################################
# Функции операций
###############################################################################
ensure_buildx() {
  need_cmd docker
  docker buildx version >/dev/null 2>&1 || die "Требуется Docker Buildx"
  BUILDX_BUILDER="omnimind-core-$(openssl rand -hex 4 2>/dev/null || echo $$)"
  docker buildx create --use --name "${BUILDX_BUILDER}" >/dev/null
}

do_build() {
  log "Сборка образа ${IMAGE_REF}"
  ensure_buildx

  local push_flag=()
  local load_flag=("--load")
  if [[ "${PUSH_IN_BUILD}" == "true" ]]; then
    push_flag=("--push")
    load_flag=()
  fi

  local cache_flag=()
  if [[ "${NO_CACHE}" == "true" ]]; then
    cache_flag+=("--no-cache")
  fi

  docker buildx build \
    --platform "${PLATFORMS}" \
    "${push_flag[@]}" \
    "${load_flag[@]}" \
    "${cache_flag[@]}" \
    -f "${REPO_ROOT}/Dockerfile" \
    -t "${IMAGE_REF}" \
    -t "${IMAGE_REF_LATEST}" \
    --label "org.opencontainers.image.title=${OCI_TITLE}" \
    --label "org.opencontainers.image.description=omnimind-core service" \
    --label "org.opencontainers.image.source=${OCI_URL}" \
    --label "org.opencontainers.image.version=${VERSION}" \
    --label "org.opencontainers.image.revision=${GIT_SHA}" \
    --label "org.opencontainers.image.vendor=${OCI_VENDOR}" \
    --label "org.opencontainers.image.licenses=${OCI_LICENSE}" \
    --label "org.opencontainers.image.created=${BUILD_DATE}" \
    --build-arg "VERSION=${VERSION}" \
    --build-arg "GIT_SHA=${GIT_SHA}" \
    --build-arg "BUILD_DATE=${BUILD_DATE}" \
    "${REPO_ROOT}"
}

do_push() {
  log "Публикация образа ${IMAGE_REF}"
  need_cmd docker
  docker push "${IMAGE_REF}"
  docker push "${IMAGE_REF_LATEST}" || true
}

do_sbom() {
  need_cmd syft
  local sbom="${DIST_DIR}/sbom-${IMAGE//\//_}-${TAG}.spdx.json"
  log "Генерация SBOM ${sbom}"
  syft packages "registry:${IMAGE_REF}" -o spdx-json > "${sbom}"
  log "SBOM сохранен в ${sbom}"
}

do_scan() {
  need_cmd trivy
  log "Сканирование ${IMAGE_REF}"
  local ignore_unfixed_flag=""
  [[ "${TRIVY_IGNORE_UNFIXED}" == "true" ]] && ignore_unfixed_flag="--ignore-unfixed"
  trivy image --severity "${TRIVY_SEVERITY}" ${ignore_unfixed_flag} --exit-code 1 "${IMAGE_REF}"
  log "Сканирование завершено успешно"
}

do_sign() {
  need_cmd cosign
  log "Подпись образа ${IMAGE_REF}"
  if [[ -n "${COSIGN_KEY:-}" ]]; then
    COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" cosign sign --key "${COSIGN_KEY}" "${IMAGE_REF}"
  else
    # Keyless (OIDC). Требует аутентификацию в реестре и провайдере.
    cosign sign "${IMAGE_REF}"
  fi
  log "Подпись завершена"
}

do_deploy() {
  need_cmd helm
  need_cmd kubectl

  [[ -n "${ENVIRONMENT}" ]] || die "Для deploy укажите --env"
  [[ -d "${HELM_CHART_DIR}" ]] || die "Не найден Helm chart: ${HELM_CHART_DIR}"

  local namespace="${NAMESPACE}"
  local release="${HELM_RELEASE}"
  local values_args=()
  [[ -n "${VALUES_FILE}" ]] && values_args+=("-f" "${VALUES_FILE}")

  local context_args=()
  [[ -n "${KUBE_CONTEXT}" ]] && context_args+=(--kube-context "${KUBE_CONTEXT}")

  local dryrun_args=()
  [[ "${HELM_DRY_RUN}" == "true" ]] && dryrun_args+=(--dry-run)

  log "Helm upgrade --install ${release} в namespace=${namespace}, env=${ENVIRONMENT}"
  helm upgrade --install "${release}" "${HELM_CHART_DIR}" \
    -n "${namespace}" --create-namespace \
    "${values_args[@]}" \
    "${HELM_SET_ARGS[@]}" \
    --set "image.repository=${REGISTRY}/${IMAGE}" \
    --set "image.tag=${TAG}" \
    --set "env.name=${ENVIRONMENT}" \
    "${context_args[@]}" \
    "${dryrun_args[@]}"

  if [[ "${HELM_DRY_RUN}" == "true" ]]; then
    log "Dry-run завершён"
    return
  fi

  # Ожидание успешного раската (Deployment и StatefulSet по имени релиза или селектору)
  log "Ожидание раската ресурсов"
  # Попытка статус-деплоя по шаблонному имени
  set +e
  kubectl "${context_args[@]}" -n "${namespace}" rollout status deploy/"${release}" --timeout=180s
  DEPLOY_STATUS=$?
  set -e

  if [[ ${DEPLOY_STATUS} -ne 0 ]]; then
    warn "Rollout deploy/${release} не подтвердился. Пробую StatefulSet."
    set +e
    kubectl "${context_args[@]}" -n "${namespace}" rollout status sts/"${release}" --timeout=180s
    STS_STATUS=$?
    set -e
    if [[ ${STS_STATUS} -ne 0 ]]; then
      warn "Не удалось подтвердить раскатку. Вывод последних событий:"
      kubectl "${context_args[@]}" -n "${namespace}" get events --sort-by=.metadata.creationTimestamp | tail -n 50 || true
      die "Раскатка неуспешна"
    fi
  fi

  log "Деплой завершен успешно"
}

###############################################################################
# Выполнение
###############################################################################
# Проверки инструментов, зависящие от действий
for act in "${ACTIONS[@]}"; do
  case "$act" in
    build|push) need_cmd docker ;;
    scan) need_cmd trivy ;;
    sbom) need_cmd syft ;;
    sign) need_cmd cosign ;;
    deploy) need_cmd helm; need_cmd kubectl ;;
  esac
done

# Если задано "all", заменяем перечнем
for i in "${!ACTIONS[@]}"; do
  if [[ "${ACTIONS[$i]}" == "all" ]]; then
    ACTIONS=(build scan sbom sign push deploy)
    break
  fi
done

# Выполнение по порядку
for act in "${ACTIONS[@]}"; do
  case "$act" in
    build)  do_build ;;
    scan)   do_scan ;;
    sbom)   do_sbom ;;
    sign)   do_sign ;;
    push)   do_push ;;
    deploy) do_deploy ;;
    *) die "Неизвестное действие: ${act}" ;;
  esac
done

log "Готово: ${ACTIONS[*]} для ${IMAGE_REF}"
