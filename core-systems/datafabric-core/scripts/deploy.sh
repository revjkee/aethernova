#!/usr/bin/env bash
# DataFabric Core — Deployment script
# Shell: bash 5+, POSIX‑совместимо где возможно. Совместимо с shellcheck.
# Режимы:
#   - docker‑image build/push
#   - k8s blue‑green rollout с readiness‑проверкой и откатом
#   - миграции БД (опционально)
#
# Требования: bash, git, docker|podman, kubectl, envsubst, jq, awk, sed, coreutils
# Опционально: sentry-cli (для релизных меток)

set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------
# Константы и значения по умолчанию
# -----------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Конфигурация по умолчанию (переопределяется окружением или .env)
: "${APP_NAME:=datafabric-core}"
: "${REGISTRY:=registry.example.com}"
: "${IMAGE_REPO:=${REGISTRY}/${APP_NAME}}"
: "${K8S_NAMESPACE:=default}"
: "${K8S_DEPLOYMENT:=datafabric-core}"
: "${K8S_CONTAINER:=app}"
: "${K8S_SERVICE:=datafabric-core}"
: "${K8S_INGRESS_HOST:=datafabric.local}"
: "${HEALTH_PATH:=/health}"
: "${HEALTH_TIMEOUT:=60}"            # сек на проверку health
: "${TIMEOUT_ROLLOUT:=180}"          # сек на rollout
: "${KUBE_CONTEXT:=}"                # если пусто — используется текущий контекст
: "${REGION:=eu-central-1}"          # для тегов/маркировок
: "${DOCKERFILE:=Dockerfile}"
: "${PLATFORM:=linux/amd64}"
: "${BUILD_ARGS:=}"                  # доп. build args: "FOO=bar BAR=baz"
: "${DRY_RUN:=false}"
: "${RUN_DB_MIGRATIONS:=false}"
: "${DB_MIGRATE_CMD:=poetry run alembic upgrade head}"
: "${SENTRY_RELEASE:=false}"
: "${SENTRY_PROJECT:=datafabric-core}"
: "${SENTRY_ORG:=your-org}"
: "${ROLLBACK_ON_FAILURE:=true}"
: "${TAG_SUFFIX:=}"                  # например "-staging"
: "${ENV_FILE:=.env.deploy}"         # файл с переменными окружения

# -----------------------------
# Вывод/логирование
# -----------------------------
log()      { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()      { log "ERROR: $*"; exit 1; }
run()      { log "+ $*"; if [[ "${DRY_RUN}" == "true" ]]; then return 0; fi; "$@"; }
require()  { command -v "$1" >/dev/null 2>&1 || die "Не найден бинарь: $1"; }
section()  { printf '\n==== %s ====\n' "$*" >&2; }

# -----------------------------
# Загрузка .env (если есть)
# -----------------------------
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC2046
  export $(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "${ENV_FILE}" | xargs) || true
  section "Загружены переменные из ${ENV_FILE}"
fi

# -----------------------------
# Проверка зависимостей
# -----------------------------
check_deps() {
  section "Проверка зависимостей"
  require git
  require jq
  require awk
  require sed
  require envsubst
  if command -v docker >/dev/null 2>&1; then
    export OCI_BIN=docker
  elif command -v podman >/dev/null 2>&1; then
    export OCI_BIN=podman
  else
    die "Нужен docker или podman"
  fi
  require kubectl
  log "OCI_BIN=${OCI_BIN}"
  log "kubectl version: $(kubectl version --client --short 2>/dev/null || echo unknown)"
}

# -----------------------------
# Определение версии/тегов
# -----------------------------
compute_version() {
  local git_rev git_tag dirty ts
  git_rev="$(git rev-parse --short=12 HEAD)"
  git_tag="$(git describe --tags --abbrev=0 2>/dev/null || true)"
  dirty=""
  git diff --quiet || dirty="-dirty"
  ts="$(date -u +'%Y%m%d%H%M%S')"
  if [[ -n "${git_tag}" ]]; then
    VERSION="${git_tag#v}${dirty}"
  else
    VERSION="0.0.0+git.${ts}.${git_rev}${dirty}"
  fi
  IMAGE_TAG="${VERSION}${TAG_SUFFIX}"
  IMAGE_URI="${IMAGE_REPO}:${IMAGE_TAG}"
  export VERSION IMAGE_TAG IMAGE_URI
  log "VERSION=${VERSION}"
  log "IMAGE_URI=${IMAGE_URI}"
}

# -----------------------------
# Сборка и публикация контейнера
# -----------------------------
build_image() {
  section "Сборка образа ${IMAGE_URI}"
  local args=(buildx build --platform "${PLATFORM}" -f "${DOCKERFILE}" -t "${IMAGE_URI}" .)
  if [[ -n "${BUILD_ARGS}" ]]; then
    # Преобразуем "FOO=1 BAR=2" -> --build-arg FOO=1 --build-arg BAR=2
    for kv in ${BUILD_ARGS}; do
      args=( "${args[@]}" --build-arg "${kv}" )
    done
  fi
  run "${OCI_BIN}" "${args[@]}"
}

push_image() {
  section "Публикация образа ${IMAGE_URI}"
  run "${OCI_BIN}" push "${IMAGE_URI}"
}

# -----------------------------
# Kubernetes: blue-green rollout
# -----------------------------
k8s_set_image() {
  section "Установка образа в deployment ${K8S_DEPLOYMENT}"
  local kc=(kubectl)
  [[ -n "${KUBE_CONTEXT}" ]] && kc+=(--context "${KUBE_CONTEXT}")
  kc+=(--namespace "${K8S_NAMESPACE}")

  run "${kc[@]}" set image "deployment/${K8S_DEPLOYMENT}" "${K8S_CONTAINER}=${IMAGE_URI}"
}

k8s_wait_rollout() {
  section "Ожидание rollout (timeout=${TIMEOUT_ROLLOUT}s)"
  local kc=(kubectl)
  [[ -n "${KUBE_CONTEXT}" ]] && kc+=(--context "${KUBE_CONTEXT}")
  kc+=(--namespace "${K8S_NAMESPACE}")

  if [[ "${DRY_RUN}" == "true" ]]; then
    log "DRY_RUN: пропуск ожидания rollout"
    return 0
  fi

  if ! "${kc[@]}" rollout status "deployment/${K8S_DEPLOYMENT}" --timeout="${TIMEOUT_ROLLOUT}s"; then
    die "Rollout не завершился успешно"
  fi
}

k8s_healthcheck() {
  section "Проверка здоровья через Service/Ingress"
  local kc=(kubectl)
  [[ -n "${KUBE_CONTEXT}" ]] && kc+=(--context "${KUBE_CONTEXT}")
  kc+=(--namespace "${K8S_NAMESPACE}")

  local svc_ip
  # Пытаемся через ingress host, иначе ClusterIP через прокси kubectl
  if curl -fsS "https://${K8S_INGRESS_HOST}${HEALTH_PATH}" --max-time 5 >/dev/null 2>&1 \
     || curl -fsS "http://${K8S_INGRESS_HOST}${HEALTH_PATH}" --max-time 5 >/dev/null 2>&1; then
    log "HEALTH OK через ${K8S_INGRESS_HOST}${HEALTH_PATH}"
    return 0
  fi

  svc_ip="$("${kc[@]}" get svc "${K8S_SERVICE}" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
  if [[ -n "${svc_ip}" ]]; then
    # через kubectl proxy (локально)
    run "${kc[@]}" proxy --port=8001 >/dev/null 2>&1 &
    local proxy_pid=$!
    trap 'kill -9 ${proxy_pid} >/dev/null 2>&1 || true' EXIT
    local url="http://127.0.0.1:8001/api/v1/namespaces/${K8S_NAMESPACE}/services/http:${K8S_SERVICE}:80/proxy${HEALTH_PATH}"
    local end=$((SECONDS + HEALTH_TIMEOUT))
    until curl -fsS "${url}" >/dev/null 2>&1; do
      [[ ${SECONDS} -ge ${end} ]] && die "HEALTH FAIL: ${url}"
      sleep 2
    done
    log "HEALTH OK через kubectl proxy"
    kill -9 "${proxy_pid}" >/dev/null 2>&1 || true
    trap - EXIT
  else
    log "WARN: не удалось определить способ проверки здоровья; пропуск"
  fi
}

k8s_rollback() {
  section "Откат deployment ${K8S_DEPLOYMENT}"
  local kc=(kubectl)
  [[ -n "${KUBE_CONTEXT}" ]] && kc+=(--context "${KUBE_CONTEXT}")
  kc+=(--namespace "${K8S_NAMESPACE}")

  run "${kc[@]}" rollout undo "deployment/${K8S_DEPLOYMENT}"
  run "${kc[@]}" rollout status "deployment/${K8S_DEPLOYMENT}" --timeout="${TIMEOUT_ROLLOUT}s" || true
}

# -----------------------------
# Миграции БД (опционально)
# -----------------------------
db_migrate() {
  if [[ "${RUN_DB_MIGRATIONS}" == "true" ]]; then
    section "Выполнение миграций БД"
    run bash -c "${DB_MIGRATE_CMD}"
  else
    log "Миграции БД отключены (RUN_DB_MIGRATIONS=false)"
  fi
}

# -----------------------------
# Sentry релиз (опционально)
# -----------------------------
sentry_release() {
  if [[ "${SENTRY_RELEASE}" != "true" ]]; then
    log "Sentry релиз отключён"
    return 0
  fi
  require sentry-cli
  local release="${APP_NAME}@${VERSION}"
  section "Sentry release ${release}"
  run sentry-cli --org "${SENTRY_ORG}" --project "${SENTRY_PROJECT}" releases new "${release}"
  run sentry-cli --org "${SENTRY_ORG}" --project "${SENTRY_PROJECT}" releases set-commits --auto "${release}"
  run sentry-cli --org "${SENTRY_ORG}" --project "${SENTRY_PROJECT}" releases finalize "${release}"
}

# -----------------------------
# Usage
# -----------------------------
usage() {
  cat <<EOF
Usage: $(basename "$0") [command]

Commands:
  build           Сборка контейнерного образа
  push            Публикация образа в реестр
  deploy          Полный деплой: build -> push -> (db migrate) -> k8s set-image -> rollout -> health
  set-image       Только обновить образ в Kubernetes
  rollback        Откат последнего деплоя (kubectl rollout undo)
  version         Печать вычисленной версии/тегов
  help            Справка

Env overrides (пример):
  REGISTRY=registry.example.com K8S_NAMESPACE=prod RUN_DB_MIGRATIONS=true ./scripts/deploy.sh deploy

Dry-run:
  DRY_RUN=true ./scripts/deploy.sh deploy

Окружение берётся из переменных и файла ${ENV_FILE} (если существует).
EOF
}

# -----------------------------
# Основной пайплайн
# -----------------------------
main() {
  local cmd="${1:-help}"

  check_deps
  compute_version

  case "${cmd}" in
    build)
      build_image
      ;;
    push)
      push_image
      ;;
    set-image)
      k8s_set_image
      ;;
    rollback)
      k8s_rollback
      ;;
    version)
      echo "${VERSION}"
      ;;
    deploy)
      build_image
      push_image
      db_migrate
      if [[ "${DRY_RUN}" == "true" ]]; then
        log "DRY_RUN: пропуск обновления в Kubernetes"
        exit 0
      fi
      if [[ -n "${KUBE_CONTEXT}" ]]; then
        log "Kube context: ${KUBE_CONTEXT}"
      fi
      k8s_set_image
      if ! k8s_wait_rollout; then
        if [[ "${ROLLBACK_ON_FAILURE}" == "true" ]]; then
          k8s_rollback
        fi
        die "Rollout завершился ошибкой"
      fi
      k8s_healthcheck
      sentry_release
      section "DEPLOY SUCCESS: ${IMAGE_URI}"
      ;;
    help|-h|--help)
      usage
      ;;
    *)
      usage; exit 1;;
  esac
}

main "$@"
