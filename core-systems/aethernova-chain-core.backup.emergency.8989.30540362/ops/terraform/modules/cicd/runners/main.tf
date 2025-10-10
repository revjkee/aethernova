terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.23.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13.0"
    }
  }
}

# Провайдеры используют стандартный kubeconfig или in-cluster конфиг.
provider "kubernetes" {}
provider "helm" {}

############################
# ВХОДНЫЕ ПЕРЕМЕННЫЕ
############################

# === ARC (GitHub Actions Runner Controller) ===
variable "arc_controller_chart_version" {
  type        = string
  description = "Версия чарта gha-runner-scale-set-controller (OCI). Пример: 0.12.1"
}

variable "arc_scale_set_chart_version" {
  type        = string
  description = "Версия чарта gha-runner-scale-set (OCI). Пример: 0.12.1"
}

variable "arc_controller_release_name" {
  type        = string
  default     = "arc-controller"
  description = "Имя релиза Helm для контроллера ARC"
}

variable "arc_scale_set_release_name" {
  type        = string
  default     = "arc-runner-set"
  description = "Имя релиза Helm для runner scale set"
}

variable "github_config_url" {
  type        = string
  description = "URL уровня назначения раннеров: https://github.com/<org> или https://github.com/<org>/<repo> или https://github.com/enterprises/<enterprise>"
}

variable "github_app_id" {
  type        = string
  sensitive   = true
  description = "GitHub App ID (строка, по докам ID должен быть строкой)"
}

variable "github_app_installation_id" {
  type        = string
  sensitive   = true
  description = "GitHub App Installation ID (строка)"
}

variable "github_app_private_key_pem" {
  type        = string
  sensitive   = true
  description = "Приватный ключ GitHub App в PEM"
}

variable "arc_min_runners" {
  type        = number
  default     = 0
  description = "Минимум idling раннеров в scale set"
}

variable "arc_max_runners" {
  type        = number
  default     = 5
  description = "Максимум раннеров в scale set"
}

variable "arc_runner_group" {
  type        = string
  default     = "default"
  description = "Runner group, в который попадет scale set (опционально)"
}

# === GitLab Runner ===
variable "gitlab_runner_chart_version" {
  type        = string
  description = "Версия чарта gitlab/gitlab-runner (из https://charts.gitlab.io)"
}

variable "gitlab_runner_release_name" {
  type        = string
  default     = "gitlab-runner"
  description = "Имя релиза Helm для GitLab Runner"
}

variable "gitlab_url" {
  type        = string
  description = "Полный URL GitLab сервера. Например: https://gitlab.example.com"
}

variable "gitlab_runner_token" {
  type        = string
  sensitive   = true
  description = "Runner authentication token из UI GitLab (новый workflow, поле runnerToken)"
}

############################
# NAMESPACES
############################

resource "kubernetes_namespace" "arc_system" {
  metadata { name = "arc-system" }
}

resource "kubernetes_namespace" "arc_runners" {
  metadata { name = "arc-runners" }
}

resource "kubernetes_namespace" "gitlab_runners" {
  metadata { name = "gitlab-runners" }
}

############################
# ARC: СЕКРЕТ GITHUB APP
############################
# По официальным значениям секрет для GitHub App должен содержать ключи:
# github_app_id, github_app_installation_id, github_app_private_key
resource "kubernetes_secret" "arc_github_app" {
  metadata {
    name      = "arc-github-app"
    namespace = kubernetes_namespace.arc_runners.metadata[0].name
  }
  type = "Opaque"
  data = {
    github_app_id              = var.github_app_id
    github_app_installation_id = var.github_app_installation_id
    github_app_private_key     = var.github_app_private_key_pem
  }
}

############################
# ARC: CONTROLLER (OCI chart)
############################
resource "helm_release" "arc_controller" {
  name       = var.arc_controller_release_name
  namespace  = kubernetes_namespace.arc_system.metadata[0].name
  create_namespace = false

  # Официальный Helm-чат контроллера ARC распространяется как OCI
  # Формат использования OCI для helm_release: chart = "oci://…", version задается отдельно.
  chart   = "oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller"
  version = var.arc_controller_chart_version

  # Значения можно расширить при необходимости (метрики, tolerations и т.п.).
  # values = [ yamlencode({ metrics = { controllerManagerAddr=":8080", listenerAddr=":8080", listenerEndpoint="/metrics" } }) ]
  depends_on = [kubernetes_namespace.arc_system]
}

############################
# ARC: RUNNER SCALE SET (OCI chart)
############################
locals {
  arc_values = {
    githubConfigUrl   = var.github_config_url
    githubConfigSecret = kubernetes_secret.arc_github_app.metadata[0].name
    runnerGroup       = var.arc_runner_group
    # По докам minRunners не может превышать maxRunners.
    maxRunners        = var.arc_max_runners
    minRunners        = var.arc_min_runners
    # runnerScaleSetName по умолчанию берется из имени релиза; можно переопределить:
    # runnerScaleSetName = var.arc_scale_set_release_name
  }
}

resource "helm_release" "arc_scale_set" {
  name       = var.arc_scale_set_release_name
  namespace  = kubernetes_namespace.arc_runners.metadata[0].name
  create_namespace = false

  chart   = "oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set"
  version = var.arc_scale_set_chart_version

  values = [ yamlencode(local.arc_values) ]

  depends_on = [
    helm_release.arc_controller,
    kubernetes_secret.arc_github_app
  ]
}

############################
# GITLAB RUNNER (официальный chart)
############################
# Обязательные значения по докам: gitlabUrl, rbac.create, runnerToken.
# runnerToken передаем как set_sensitive.
resource "helm_release" "gitlab_runner" {
  name       = var.gitlab_runner_release_name
  namespace  = kubernetes_namespace.gitlab_runners.metadata[0].name
  create_namespace = false

  repository = "https://charts.gitlab.io"
  chart      = "gitlab-runner"
  version    = var.gitlab_runner_chart_version

  set {
    name  = "gitlabUrl"
    value = var.gitlab_url
  }

  set {
    name  = "rbac.create"
    value = "true"
  }

  set_sensitive {
    name  = "runnerToken"
    value = var.gitlab_runner_token
  }

  depends_on = [kubernetes_namespace.gitlab_runners]
}
