#!/usr/bin/env bash
# aethernova-chain-core/scripts/devnet_up.sh
#
# Назначение: поднять локальный Kubernetes devnet окружения Aethernova на базе kind.
# Возможности:
#  - Создание kind-кластера (c optional локальным Docker registry)
#  - Установка ingress-nginx и kube-prometheus-stack (опционально)
#  - Применение вашего Kustomize каталога (если указан)
#  - Ожидание готовности ключевых ресурсов и вывод сводки
#
# Проверяемые источники:
#  - Bash set/pipefail/trap: GNU Bash Reference Manual, "The Set Builtin", "Signals" (https://www.gnu.org/software/bash/manual/)
#  - kind: создание кластера / локальный registry (https://kind.sigs.k8s.io/docs/user/quick-start/, https://kind.sigs.k8s.io/docs/user/local-registry/)
#  - kubectl kustomize/apply -k: оф. Kubernetes docs (https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/)
#  - kubectl wait: оф. справочник kubectl (https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands/#wait)
#  - Helm install/repo: Helm docs (https://helm.sh/docs/helm/helm_install/, https://helm.sh/docs/helm/helm_repo_add/)
#  - ingress-nginx deploy via Helm: оф. чарты (https://kubernetes.github.io/ingress-nginx/deploy/)
#  - kube-prometheus-stack: оф. репозиторий чарта (https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)

set -Eeuo pipefail
# shellcheck disable=SC2034
IFS=$'\n\t'

################################################################################
# ЛОГГЕРЫ И УТИЛИТЫ
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

log()  { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

cleanup() {
  # Удаление временных файлов
  [[ -n "${TMP_CLUSTER_CFG:-}" && -f "${TMP_CLUSTER_CFG}" ]] && rm -f "${TMP_CLUSTER_CFG}"
}
trap cleanup EXIT

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Требуется команда '$1' в PATH."; }

semver_ge() { # сравнение версий a >= b
  # Используем sort -V для сравнения семантических версий (coreutils).
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]
}

################################################################################
# ПАРАМЕТРЫ ПО УМОЛЧАНИЮ (переопределяются флагами/ENV)
################################################################################

: "${DEVNET_PROVIDER:=kind}"                     # kind (поддержка minikube/k3d — в будущем)
: "${DEVNET_CLUSTER_NAME:=aethernova-devnet}"
: "${DEVNET_NODES:=1}"                           # число worker-нод (master/control-plane всегда 1)
: "${DEVNET_ENABLE_REGISTRY:=true}"              # локальный docker registry :5001
: "${DEVNET_REGISTRY_NAME:=kind-registry}"
: "${DEVNET_REGISTRY_PORT:=5001}"
: "${DEVNET_INSTALL_INGRESS:=true}"              # ingress-nginx
: "${DEVNET_INSTALL_MONITORING:=false}"          # kube-prometheus-stack
: "${DEVNET_KUSTOMIZE_PATH:=}"                   # относительный путь к каталогу с kustomization.yaml
: "${DEVNET_HELM_TIMEOUT:=10m}"                  # таймаут helm операций
: "${DEVNET_WAIT:=true}"                         # ждать готовности DaemonSet/Deployments

################################################################################
# ПАРСИНГ АРГУМЕНТОВ
################################################################################
usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --provider <kind>               Провайдер (сейчас поддерживается: kind). Default: ${DEVNET_PROVIDER}
  --cluster-name <name>           Имя кластера. Default: ${DEVNET_CLUSTER_NAME}
  --nodes <N>                     Кол-во worker-нод kind (control-plane добавляется автоматически). Default: ${DEVNET_NODES}
  --enable-registry <true|false>  Локальный Docker registry :${DEVNET_REGISTRY_PORT}. Default: ${DEVNET_ENABLE_REGISTRY}
  --registry-port <port>          Порт локального registry. Default: ${DEVNET_REGISTRY_PORT}
  --install-ingress <true|false>  Установка ingress-nginx. Default: ${DEVNET_INSTALL_INGRESS}
  --install-monitoring <true|false> Установка kube-prometheus-stack. Default: ${DEVNET_INSTALL_MONITORING}
  --kustomize-path <path>         Применить kustomize каталог (относительно repo root).
  --helm-timeout <dur>            Таймаут Helm операций (напр., 10m). Default: ${DEVNET_HELM_TIMEOUT}
  --wait <true|false>             Ждать готовности основных компонентов. Default: ${DEVNET_WAIT}
  -h|--help                       Показать помощь.

ENV overrides:
  DEVNET_PROVIDER, DEVNET_CLUSTER_NAME, DEVNET_NODES, DEVNET_ENABLE_REGISTRY,
  DEVNET_REGISTRY_NAME, DEVNET_REGISTRY_PORT, DEVNET_INSTALL_INGRESS,
  DEVNET_INSTALL_MONITORING, DEVNET_KUSTOMIZE_PATH, DEVNET_HELM_TIMEOUT, DEVNET_WAIT

Примечание:
  - Безопасный режим Bash: set -Eeuo pipefail (GNU Bash Manual: The Set Builtin).
  - kind local registry — официальная методика (kind docs: local-registry).
  - kubectl -k (kustomize) — официальная задача Kubernetes.
  - kubectl wait — официальный сабкоманд kubectl.
  - Helm install/repo — официальные команды Helm.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider)                DEVNET_PROVIDER="${2:?}"; shift 2;;
    --cluster-name)            DEVNET_CLUSTER_NAME="${2:?}"; shift 2;;
    --nodes)                   DEVNET_NODES="${2:?}"; shift 2;;
    --enable-registry)         DEVNET_ENABLE_REGISTRY="${2:?}"; shift 2;;
    --registry-port)           DEVNET_REGISTRY_PORT="${2:?}"; shift 2;;
    --install-ingress)         DEVNET_INSTALL_INGRESS="${2:?}"; shift 2;;
    --install-monitoring)      DEVNET_INSTALL_MONITORING="${2:?}"; shift 2;;
    --kustomize-path)          DEVNET_KUSTOMIZE_PATH="${2:?}"; shift 2;;
    --helm-timeout)            DEVNET_HELM_TIMEOUT="${2:?}"; shift 2;;
    --wait)                    DEVNET_WAIT="${2:?}"; shift 2;;
    -h|--help)                 usage; exit 0;;
    *)                         die "Неизвестный аргумент: $1 (см. --help)";;
  esac
done

################################################################################
# ПРОВЕРКИ И ЗАВИСИМОСТИ
################################################################################

need_cmd docker
need_cmd kind
need_cmd kubectl
need_cmd helm

if [[ -n "${DEVNET_KUSTOMIZE_PATH}" ]]; then
  # kubectl kustomize встроен в kubectl >= 1.14
  need_cmd kubectl
fi

# Проверим доступность Docker daemon
docker info >/dev/null 2>&1 || die "Docker недоступен. Проверьте, что Docker daemon запущен."

################################################################################
# ФУНКЦИИ ДЛЯ KIND + LOCAL REGISTRY (ОФ. ДОК: kind local-registry)
################################################################################

ensure_local_registry() {
  local name="${DEVNET_REGISTRY_NAME}"
  local port="${DEVNET_REGISTRY_PORT}"

  if [[ "${DEVNET_ENABLE_REGISTRY}" != "true" ]]; then
    log "Локальный registry отключен (DEVNET_ENABLE_REGISTRY=false). Пропускаем."
    return 0
  fi

  if [[ "$(docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null || true)" != "true" ]]; then
    log "Создаю локальный Docker registry ${name}:${port}..."
    docker run -d --restart=always -p "127.0.0.1:${port}:5000" --name "${name}" registry:2 >/dev/null
  else
    log "Локальный Docker registry уже запущен: ${name}"
  fi

  # Создадим/обновим сети
  if ! docker network inspect kind >/dev/null 2>&1; then
    log "Docker network 'kind' ещё не создана — будет создана автоматически kind-ом."
  fi

  # Подключим контейнер registry к сети kind (может быть уже подключен)
  docker network connect "kind" "${name}" 2>/dev/null || true
}

kind_cluster_cfg() {
  # Сгенерировать временный конфиг kind с интеграцией локального registry и настройкой нод
  TMP_CLUSTER_CFG="$(mktemp -t kindcfg.XXXXXX.yaml)"
  {
    cat <<EOF
# kind cluster config (официальный формат: https://kind.sigs.k8s.io/docs/user/configuration/)
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${DEVNET_CLUSTER_NAME}
containerdConfigPatches:
$(if [[ "${DEVNET_ENABLE_REGISTRY}" == "true" ]]; then cat <<'EOR'
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:5001"]
    endpoint = ["http://kind-registry:5000"]
EOR
fi)
nodes:
  - role: control-plane
$(for i in $(seq 1 "${DEVNET_NODES}"); do
cat <<'EON'
  - role: worker
EON
done)
EOF
  } >"${TMP_CLUSTER_CFG}"
  log "Сконфигурирован kind cluster config: ${TMP_CLUSTER_CFG}"
}

create_kind_cluster() {
  if kind get clusters | grep -qx "${DEVNET_CLUSTER_NAME}"; then
    log "Кластер kind '${DEVNET_CLUSTER_NAME}' уже существует — пропускаю создание."
  else
    log "Создаю kind кластер '${DEVNET_CLUSTER_NAME}'..."
    kind create cluster --name "${DEVNET_CLUSTER_NAME}" --config "${TMP_CLUSTER_CFG}"
  fi

  # Настроим ConfigMap с локацией registry внутри кластера (официальная методика kind docs: local-registry)
  if [[ "${DEVNET_ENABLE_REGISTRY}" == "true" ]]; then
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${DEVNET_REGISTRY_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
  fi
}

################################################################################
# HELM: РЕПОЗИТОРИИ И УСТАНОВКИ
################################################################################

helm_repo_ensure() {
  # ingress-nginx
  if [[ "${DEVNET_INSTALL_INGRESS}" == "true" ]]; then
    helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
  fi
  # kube-prometheus-stack
  if [[ "${DEVNET_INSTALL_MONITORING}" == "true" ]]; then
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
  fi
  helm repo update >/dev/null
}

install_ingress_nginx() {
  [[ "${DEVNET_INSTALL_INGRESS}" == "true" ]] || { log "ingress-nginx отключен."; return 0; }

  log "Устанавливаю ingress-nginx..."
  kubectl create namespace ingress-nginx >/dev/null 2>&1 || true
  helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
    --namespace ingress-nginx \
    --wait --timeout "${DEVNET_HELM_TIMEOUT}" \
    --set controller.publishService.enabled=true >/dev/null

  if [[ "${DEVNET_WAIT}" == "true" ]]; then
    # Ожидание готовности контроллера
    kubectl -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout="${DEVNET_HELM_TIMEOUT}" >/dev/null
  fi
}

install_monitoring() {
  [[ "${DEVNET_INSTALL_MONITORING}" == "true" ]] || { log "kube-prometheus-stack отключен."; return 0; }

  log "Устанавливаю kube-prometheus-stack..."
  kubectl create namespace monitoring >/dev/null 2>&1 || true
  helm upgrade --install kps prometheus-community/kube-prometheus-stack \
    --namespace monitoring \
    --wait --timeout "${DEVNET_HELM_TIMEOUT}" >/dev/null

  if [[ "${DEVNET_WAIT}" == "true" ]]; then
    kubectl -n monitoring rollout status deploy/kps-grafana --timeout="${DEVNET_HELM_TIMEOUT}" >/dev/null || true
    kubectl -n monitoring rollout status statefulset/kps-prometheus --timeout="${DEVNET_HELM_TIMEOUT}" >/dev/null || true
    kubectl -n monitoring rollout status statefulset/alertmanager-kps-alertmanager --timeout="${DEVNET_HELM_TIMEOUT}" >/dev/null || true
  fi
}

################################################################################
# ПРИМЕНЕНИЕ ВАШЕГО KUSTOMIZE
################################################################################

apply_kustomize() {
  [[ -z "${DEVNET_KUSTOMIZE_PATH}" ]] && { log "Kustomize путь не задан — пропускаю apply."; return 0; }

  local kpath="${REPO_ROOT}/${DEVNET_KUSTOMIZE_PATH}"
  [[ -d "${kpath}" ]] || die "Kustomize каталог не найден: ${kpath}"
  [[ -f "${kpath}/kustomization.yaml" || -f "${kpath}/kustomization.yml" ]] || die "В каталоге ${kpath} нет kustomization.{yaml,yml}"

  log "Применяю kustomize из: ${kpath}"
  kubectl apply -k "${kpath}" >/dev/null

  if [[ "${DEVNET_WAIT}" == "true" ]]; then
    # Универсальное ожидание доступности развёрнутых Deployment в выбранных NS.
    # Пользователь может настроить список NS через окружение, иначе пытаемся угадать.
    local namespaces=()
    # Попробуем извлечь ns из kustomize (эвристика)
    namespaces=($(kubectl kustomize "${kpath}" | awk '/namespace:/{print $2}' | sort -u || true))
    if [[ ${#namespaces[@]} -eq 0 ]]; then
      namespaces=("default")
    fi
    for ns in "${namespaces[@]}"; do
      # Ждать, пока все deployments в ns перейдут в available
      mapfile -t deps < <(kubectl -n "${ns}" get deploy -o name 2>/dev/null || true)
      for d in "${deps[@]}"; do
        kubectl -n "${ns}" rollout status "${d}" --timeout="${DEVNET_HELM_TIMEOUT}" >/dev/null || true
      done
    done
  fi
}

################################################################################
# ОСНОВНОЙ ПОТОК
################################################################################

main() {
  log "Провайдер: ${DEVNET_PROVIDER}, кластер: ${DEVNET_CLUSTER_NAME}, worker-нод: ${DEVNET_NODES}"
  ensure_local_registry
  kind_cluster_cfg
  create_kind_cluster
  helm_repo_ensure
  install_ingress_nginx
  install_monitoring
  apply_kustomize

  # Сводка
  log "DevNet кластер '${DEVNET_CLUSTER_NAME}' готов."
  log "kubectl context: $(kubectl config current-context)"
  if [[ "${DEVNET_ENABLE_REGISTRY}" == "true" ]]; then
    log "Локальный Docker registry: localhost:${DEVNET_REGISTRY_PORT} (kind internal: kind-registry:5000)"
  fi
  if [[ "${DEVNET_INSTALL_INGRESS}" == "true" ]]; then
    log "ingress-nginx установлен (ns: ingress-nginx). Как получить адрес:"
    log "  kubectl -n ingress-nginx get svc ingress-nginx-controller"
  fi
  if [[ "${DEVNET_INSTALL_MONITORING}" == "true" ]]; then
    log "kube-prometheus-stack установлен (ns: monitoring). Примеры порт-форварда:"
    log "  kubectl -n monitoring port-forward svc/kps-grafana 3000:80"
    log "  kubectl -n monitoring port-forward svc/kps-kube-prometheus-prometheus 9090:9090"
  fi
  if [[ -n "${DEVNET_KUSTOMIZE_PATH}" ]]; then
    log "Применён ваш Kustomize: ${DEVNET_KUSTOMIZE_PATH}"
  fi
  log "Готово."
}

main "$@"
