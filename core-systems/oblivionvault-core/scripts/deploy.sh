#!/usr/bin/env bash
# oblivionvault-core/scripts/deploy.sh
# Унифицированный деплой Helm/Kubernetes и Docker Compose с безопасными дефолтами.

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------- Конфигурация по умолчанию -----------------------------
APP_NAME="${APP_NAME:-oblivionvault-core}"
DEFAULT_STRATEGY="helm"          # helm|compose
DEPLOY_ENV="${DEPLOY_ENV:-dev}"  # dev|stage|prod (влияет на .env.<ENV>, values-<ENV>.yaml и namespace)
REGISTRY="${REGISTRY:-}"         # например: ghcr.io/org, registry.example.com
IMAGE_REPO="${IMAGE_REPO:-${REGISTRY:+${REGISTRY}/}${APP_NAME}}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"
BUILD_CONTEXT="${BUILD_CONTEXT:-.}"
PLATFORM="${PLATFORM:-linux/amd64}"   # можно linux/amd64,linux/arm64
LOG_LEVEL="${LOG_LEVEL:-info}"

# Helm
HELM_RELEASE="${HELM_RELEASE:-${APP_NAME}}"
HELM_NAMESPACE="${HELM_NAMESPACE:-${APP_NAME}}"
HELM_CHART_DIR="${HELM_CHART_DIR:-ops/helm/${APP_NAME}}"
HELM_TIMEOUT="${HELM_TIMEOUT:-10m0s}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"  # можно оставить пустым

# Compose
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-${APP_NAME}-${DEPLOY_ENV}}"

# Миграции и проверка
RUN_MIGRATIONS="${RUN_MIGRATIONS:-false}"  # true|false
MIGRATE_CMD="${MIGRATE_CMD:-python -m app.migrate}" # команда для миграций внутри образа
HEALTHCHECK_URL="${HEALTHCHECK_URL:-}"     # например https://svc.example/health/ready
HEALTHCHECK_TIMEOUT="${HEALTHCHECK_TIMEOUT:-120}"  # секунд
HEALTHCHECK_RETRY_DELAY="${HEALTHCHECK_RETRY_DELAY:-5}"

# Прочее
DRY_RUN="${DRY_RUN:-false}"
PUBLISH="${PUBLISH:-true}"   # собирать/пушить образ: true|false
USE_HELM_DIFF="${USE_HELM_DIFF:-true}"  # если плагин есть — показать diff

# ----------------------------- Логирование и ошибки -----------------------------
_color() { local c="$1"; shift || true; printf "\033[%sm%s\033[0m\n" "$c" "$*"; }
_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { local lvl="$1"; shift; local msg="$*"; 
  case "$lvl" in
    debug) [[ "${LOG_LEVEL}" == "debug" ]] && _color "90" "[$(_ts)] [DEBUG] ${msg}" || true ;;
    info)  _color "36" "[$(_ts)] [INFO ] ${msg}" ;;
    warn)  _color "33" "[$(_ts)] [WARN ] ${msg}" ;;
    error) _color "31" "[$(_ts)] [ERROR] ${msg}" ;;
  esac
}

die() { log error "$*"; exit 1; }

_cleanup() {
  local ec=$?
  if [[ $ec -ne 0 ]]; then log error "Завершение с кодом $ec"; fi
  exit $ec
}
trap _cleanup EXIT
trap 'die "Прервано пользователем"' INT TERM

# ----------------------------- Помощь -----------------------------
usage() {
  cat <<'USAGE'
deploy.sh — безопасный деплой Helm/Kubernetes или Docker Compose

Использование:
  scripts/deploy.sh [-s helm|compose] [-e ENV] [-v VERSION] [--no-publish]
                    [--namespace NS] [--release NAME]
                    [--values FILE ...] [--set key=val ...]
                    [--migrate] [--health URL] [--timeout SEC]
                    [--dry-run] [--context KUBE_CTX]

Опции:
  -s, --strategy STR        Стратегия деплоя: helm|compose (по умолчанию helm)
  -e, --env ENV             Окружение: dev|stage|prod (по умолчанию dev)
  -v, --version VER         Версия/тег образа. Если не задано — git SHA/тег
      --no-publish          Не собирать/пушить образ (только деплой)
      --namespace NS        Kubernetes namespace (по умолчанию имя приложения)
      --release NAME        Helm release (по умолчанию имя приложения)
      --values FILE         Доп. values.yaml (можно повторять)
      --set K=V             helm --set (можно повторять)
      --migrate             Выполнить миграции после деплоя
      --health URL          Health URL для проверки готовности
      --timeout SEC         Таймаут health-check (сек)
      --dry-run             Только показать, что будет сделано
      --context CTX         kube-context (kubectl/helm)

Переменные окружения (основные):
  REGISTRY, IMAGE_REPO, PLATFORM, DOCKERFILE, BUILD_CONTEXT,
  HELM_CHART_DIR, HELM_TIMEOUT, COMPOSE_FILE, COMPOSE_PROJECT,
  MIGRATE_CMD, HEALTHCHECK_URL, HEALTHCHECK_TIMEOUT

Примеры:
  REGISTRY=ghcr.io/org scripts/deploy.sh -e stage -v 1.4.2
  scripts/deploy.sh -s helm --values ops/helm/oblivionvault-core/values-prod.yaml
  scripts/deploy.sh -s compose --no-publish
USAGE
}

# ----------------------------- Парсинг аргументов -----------------------------
STRATEGY="$DEFAULT_STRATEGY"
VERSION="${VERSION:-}"
VALUES_FILES=()
HELM_SET_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -s|--strategy) STRATEGY="$2"; shift 2 ;;
    -e|--env) DEPLOY_ENV="$2"; shift 2 ;;
    -v|--version) VERSION="$2"; shift 2 ;;
    --no-publish) PUBLISH="false"; shift ;;
    --namespace) HELM_NAMESPACE="$2"; shift 2 ;;
    --release) HELM_RELEASE="$2"; shift 2 ;;
    --values) VALUES_FILES+=("$2"); shift 2 ;;
    --set) HELM_SET_ARGS+=("$2"); shift 2 ;;
    --migrate) RUN_MIGRATIONS="true"; shift ;;
    --health) HEALTHCHECK_URL="$2"; shift 2 ;;
    --timeout) HEALTHCHECK_TIMEOUT="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    --context) KUBE_CONTEXT="$2"; shift 2 ;;
    *) die "Неизвестный аргумент: $1 (см. -h)" ;;
  esac
done

# ----------------------------- Проверка инструментов -----------------------------
need() { command -v "$1" >/dev/null 2>&1 || die "Требуется '$1'"; }
need jq
need sed
if [[ "$STRATEGY" == "helm" ]]; then
  need helm
  need kubectl
fi
if [[ "$PUBLISH" == "true" ]]; then
  need docker
fi

# ----------------------------- Загрузка .env -----------------------------
load_env_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  log info "Загрузка переменных из ${f}"
  # Поддержка простого .env (KEY=VALUE, без пробелов вокруг '='; строки с # игнорируются)
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      local k="${BASH_REMATCH[1]}"
      local v="${BASH_REMATCH[2]}"
      # Удалим обрамляющие кавычки, если есть
      v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
      export "${k}=${v}"
    fi
  done < "$f"
}

load_env_file ".env"
load_env_file ".env.${DEPLOY_ENV}"

# Повторная инициализация переменных после .env.*
IMAGE_REPO="${IMAGE_REPO:-${REGISTRY:+${REGISTRY}/}${APP_NAME}}"
HELM_NAMESPACE="${HELM_NAMESPACE:-${APP_NAME}}"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-${APP_NAME}-${DEPLOY_ENV}}"

# ----------------------------- Определение версии -----------------------------
guess_version() {
  if [[ -n "${VERSION}" ]]; then echo "${VERSION}"; return; fi
  if [[ -n "${GITHUB_SHA:-}" ]]; then echo "${GITHUB_SHA:0:12}"; return; fi
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    local tag
    tag="$(git describe --tags --abbrev=0 2>/dev/null || true)"
    if [[ -n "$tag" ]]; then echo "$tag"; return; fi
    local sha
    sha="$(git rev-parse --short=12 HEAD)"
    echo "$sha"; return
  fi
  echo "latest"
}
VERSION="$(guess_version)"
IMAGE_TAG="${VERSION}"
FULL_IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

log info "Стратегия: ${STRATEGY}, ENV: ${DEPLOY_ENV}, Версия: ${VERSION}"
log info "Образ: ${FULL_IMAGE}"

# ----------------------------- Сборка и публикация образа -----------------------------
build_and_push() {
  if [[ "$PUBLISH" != "true" ]]; then
    log info "Публикация образа отключена (--no-publish)"
    return
  fi
  log info "Сборка Docker образа (${FULL_IMAGE})"
  DOCKER_BUILDKIT=1 docker build \
    --platform "${PLATFORM}" \
    -f "${DOCKERFILE}" \
    -t "${FULL_IMAGE}" \
    --label "org.opencontainers.image.title=${APP_NAME}" \
    --label "org.opencontainers.image.version=${IMAGE_TAG}" \
    --label "org.opencontainers.image.revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
    "${BUILD_CONTEXT}"

  if [[ "$DRY_RUN" == "true" ]]; then
    log warn "DRY-RUN: пропуск docker push"
  else
    log info "Публикация образа в реестр"
    docker push "${FULL_IMAGE}"
  fi
}

# ----------------------------- Helm деплой -----------------------------
helm_deploy() {
  [[ -d "${HELM_CHART_DIR}" ]] || die "Не найден chart: ${HELM_CHART_DIR}"

  local kctx_args=()
  [[ -n "${KUBE_CONTEXT}" ]] && kctx_args+=(--kube-context "${KUBE_CONTEXT}")

  # Соберём список values-файлов: базовый + по окружению, если есть.
  local values_args=()
  local base_values="${HELM_CHART_DIR}/values.yaml"
  local env_values="${HELM_CHART_DIR}/values-${DEPLOY_ENV}.yaml"
  [[ -f "$base_values" ]] && values_args+=( -f "$base_values" )
  [[ -f "$env_values" ]] && values_args+=( -f "$env_values" )
  # Пользовательские файлы
  if [[ ${#VALUES_FILES[@]} -gt 0 ]]; then
    for vf in "${VALUES_FILES[@]}"; do
      values_args+=( -f "$vf" )
    done
  fi

  # --set аргументы
  local set_args=()
  for kv in "${HELM_SET_ARGS[@]}"; do
    set_args+=( --set "$kv" )
  done
  # Обязательные set: образ
  set_args+=( --set "image.repository=${IMAGE_REPO}" --set "image.tag=${IMAGE_TAG}" )
  set_args+=( --set "env=${DEPLOY_ENV}" )

  # Создадим namespace (идемпотентно)
  if [[ "$DRY_RUN" != "true" ]]; then
    kubectl "${kctx_args[@]}" get ns "${HELM_NAMESPACE}" >/dev/null 2>&1 || \
      kubectl "${kctx_args[@]}" create ns "${HELM_NAMESPACE}"
  fi

  # helm diff, если доступен и разрешен
  if [[ "$USE_HELM_DIFF" == "true" ]] && helm plugin list 2>/dev/null | grep -qi diff; then
    log info "Diff перед деплоем:"
    helm diff upgrade "${HELM_RELEASE}" "${HELM_CHART_DIR}" \
      "${values_args[@]}" "${set_args[@]}" \
      --namespace "${HELM_NAMESPACE}" "${kctx_args[@]}" || true
  fi

  local helm_cmd=(helm upgrade --install "${HELM_RELEASE}" "${HELM_CHART_DIR}"
                  --namespace "${HELM_NAMESPACE}"
                  --atomic --wait --timeout "${HELM_TIMEOUT}"
                  "${values_args[@]}" "${set_args[@]}" "${kctx_args[@]}")

  if [[ "$DRY_RUN" == "true" ]]; then
    log warn "DRY-RUN: helm команда:"
    printf '  %q ' "${helm_cmd[@]}"; echo
  else
    log info "Выполняется Helm деплой..."
    "${helm_cmd[@]}"
  fi
}

# ----------------------------- Compose деплой -----------------------------
compose_deploy() {
  [[ -f "${COMPOSE_FILE}" ]] || die "Не найден docker-compose файл: ${COMPOSE_FILE}"
  local compose=(docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}")
  # Передаём образ и env проекту через переменные окружения
  export IMAGE_REPO IMAGE_TAG FULL_IMAGE DEPLOY_ENV

  if [[ "$DRY_RUN" == "true" ]]; then
    log warn "DRY-RUN: docker compose pull/up пропущен"
    "${compose[@]}" config
  else
    log info "Compose: подтягиваем образ(ы)..."
    "${compose[@]}" pull || true
    log info "Compose: поднимаем сервисы..."
    "${compose[@]}" up -d --remove-orphans
  fi
}

# ----------------------------- Миграции -----------------------------
run_migrations() {
  [[ "$RUN_MIGRATIONS" == "true" ]] || return 0
  if [[ "$STRATEGY" == "helm" ]]; then
    local kctx_args=()
    [[ -n "${KUBE_CONTEXT}" ]] && kctx_args+=(--context "${KUBE_CONTEXT}")
    # Запустим одноразовый под с текущим образом
    local pod="mig-${APP_NAME}-$(date +%s)"
    log info "Запуск миграций в поде ${pod}"
    if [[ "$DRY_RUN" == "true" ]]; then
      log warn "DRY-RUN: пропуск миграций"
      return 0
    fi
    kubectl "${kctx_args[@]}" -n "${HELM_NAMESPACE}" run "${pod}" \
      --image="${FULL_IMAGE}" --restart=Never --command -- ${MIGRATE_CMD}
    # Ждём завершения
    kubectl "${kctx_args[@]}" -n "${HELM_NAMESPACE}" wait --for=condition=Succeeded pod/"${pod}" --timeout=300s || {
      log error "Миграции завершились неуспешно. Логи:"
      kubectl "${kctx_args[@]}" -n "${HELM_NAMESPACE}" logs "pod/${pod}" || true
      kubectl "${kctx_args[@]}" -n "${HELM_NAMESPACE}" delete pod "${pod}" --ignore-not-found
      return 1
    }
    kubectl "${kctx_args[@]}" -n "${HELM_NAMESPACE}" logs "pod/${pod}" || true
    kubectl "${kctx_args[@]}" -n "${HELM_NAMESPACE}" delete pod "${pod}" --ignore-not-found
  else
    # Локально: запустим временный контейнер из образа
    if [[ "$DRY_RUN" == "true" ]]; then
      log warn "DRY-RUN: пропуск миграций (compose)"
      return 0
    fi
    log info "Запуск миграций локально в контейнере..."
    docker run --rm --entrypoint "" "${FULL_IMAGE}" bash -lc "${MIGRATE_CMD}"
  fi
}

# ----------------------------- Health-check и rollback -----------------------------
healthcheck() {
  [[ -n "${HEALTHCHECK_URL}" ]] || { log info "HEALTHCHECK_URL не задан, пропускаем проверку"; return 0; }
  [[ "$DRY_RUN" == "true" ]] && { log warn "DRY-RUN: пропуск health-check"; return 0; }

  local deadline=$(( $(date +%s) + HEALTHCHECK_TIMEOUT ))
  while true; do
    if curl -fsS -m 5 "${HEALTHCHECK_URL}" >/dev/null; then
      log info "Health-check пройден: ${HEALTHCHECK_URL}"
      return 0
    fi
    if [[ $(date +%s) -ge $deadline ]]; then
      log error "Health-check не пройден за ${HEALTHCHECK_TIMEOUT}с"
      return 1
    fi
    log warn "Сервис ещё не готов, повтор через ${HEALTHCHECK_RETRY_DELAY}с..."
    sleep "${HEALTHCHECK_RETRY_DELAY}"
  done
}

rollback() {
  if [[ "$STRATEGY" == "helm" && "$DRY_RUN" != "true" ]]; then
    log warn "Откат Helm релиза до предыдущей ревизии..."
    local kctx_args=()
    [[ -n "${KUBE_CONTEXT}" ]] && kctx_args+=(--kube-context "${KUBE_CONTEXT}")
    # Определим предыдущую ревизию
    local prev
    prev="$(helm history "${HELM_RELEASE}" --namespace "${HELM_NAMESPACE}" -o json "${kctx_args[@]}" | jq 'map(select(.status=="superseded" or .status=="deployed")) | .[-1].revision // empty')"
    if [[ -n "${prev}" && "${prev}" != "null" ]]; then
      helm rollback "${HELM_RELEASE}" "${prev}" --namespace "${HELM_NAMESPACE}" "${kctx_args[@]}"
    else
      log warn "Предыдущая ревизия не найдена, откат невозможен"
    fi
  else
    log warn "Откат поддержан только для стратегии helm"
  fi
}

# ----------------------------- Основной поток -----------------------------
main() {
  case "$STRATEGY" in
    helm|compose) ;;
    *) die "Недопустимая стратегия: ${STRATEGY}. Используйте helm|compose" ;;
  esac

  build_and_push

  if [[ "$STRATEGY" == "helm" ]]; then
    helm_deploy
  else
    compose_deploy
  fi

  if ! run_migrations; then
    log error "Миграции завершились ошибкой"
    rollback || true
    exit 1
  fi

  if ! healthcheck; then
    rollback || true
    exit 1
  fi

  log info "Деплой завершён успешно: ${APP_NAME} @ ${VERSION}"
}

main "$@"
