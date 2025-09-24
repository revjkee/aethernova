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

  # Хранение состояния в кластере: Secret + Lease (state locking).
  # Согласно документации backend "kubernetes" поддерживает secret_suffix, namespace и kubeconfig-доступ.
  # Рекомендуется частичная конфигурация (часть параметров задавать через -backend-config/переменные окружения).
  # См. HashiCorp Docs.
  backend "kubernetes" {
    namespace     = "terraform-state"
    secret_suffix = "prod"
    # config_path/config_context рекомендуем задавать как partial backend-config при init.
  }
}

# -------- Провайдеры (kubeconfig) --------
variable "kubeconfig_path" {
  type        = string
  default     = "~/.kube/config"
  description = "Путь к kubeconfig для prod-кластера"
}

variable "kube_context" {
  type        = string
  default     = null
  description = "Имя контекста kubeconfig (если не задан, берётся контекст по умолчанию)"
}

provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kube_context
}

provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = var.kube_context
  }
}

# -------- Параметры CICD раннеров (GitHub ARC + GitLab Runner) --------
variable "arc_controller_chart_version" {
  type        = string
  description = "Версия чарта gha-runner-scale-set-controller (OCI), например 0.12.x"
}
variable "arc_scale_set_chart_version" {
  type        = string
  description = "Версия чарта gha-runner-scale-set (OCI), например 0.12.x"
}
variable "github_config_url" {
  type        = string
  description = "https://github.com/<org> или https://github.com/<org>/<repo> или https://github.com/enterprises/<enterprise>"
}
variable "github_app_id" {
  type      = string
  sensitive = true
}
variable "github_app_installation_id" {
  type      = string
  sensitive = true
}
variable "github_app_private_key_pem" {
  type      = string
  sensitive = true
}
variable "arc_min_runners" {
  type    = number
  default = 0
}
variable "arc_max_runners" {
  type    = number
  default = 10
}
variable "arc_runner_group" {
  type    = string
  default = "default"
}

variable "gitlab_runner_chart_version" {
  type        = string
  description = "Версия чарта gitlab/gitlab-runner из charts.gitlab.io"
}
variable "gitlab_url" {
  type        = string
  description = "URL GitLab (например, https://gitlab.example.com)"
}
variable "gitlab_runner_token" {
  type      = string
  sensitive = true
}

# -------- Параметры приложения bridge-relayer --------
variable "bridge_namespace" {
  type    = string
  default = "bridge-relayer"
}
variable "bridge_chart_version" {
  type        = string
  description = "Версия чарта bjw-s/app-template"
}
variable "bridge_image_repository" {
  type = string
}
variable "bridge_image_tag" {
  type = string
}
variable "bridge_container_port" {
  type    = number
  default = 8080
}
variable "bridge_replicas" {
  type    = number
  default = 2
}
variable "bridge_env" {
  type    = map(string)
  default = {}
}
variable "bridge_secret_name" {
  type    = string
  default = "bridge-relayer-secrets"
}
variable "bridge_secret_data" {
  type      = map(string)
  sensitive = true
}

# -------- Модуль: CI/CD Runners (GitHub ARC + GitLab Runner) --------
module "cicd_runners" {
  source = "../../modules/cicd/runners"

  # GitHub ARC
  arc_controller_chart_version = var.arc_controller_chart_version
  arc_scale_set_chart_version  = var.arc_scale_set_chart_version
  github_config_url            = var.github_config_url
  github_app_id                = var.github_app_id
  github_app_installation_id   = var.github_app_installation_id
  github_app_private_key_pem   = var.github_app_private_key_pem
  arc_min_runners              = var.arc_min_runners
  arc_max_runners              = var.arc_max_runners
  arc_runner_group             = var.arc_runner_group

  # GitLab Runner
  gitlab_runner_chart_version = var.gitlab_runner_chart_version
  gitlab_url                  = var.gitlab_url
  gitlab_runner_token         = var.gitlab_runner_token

  # Явно передаём провайдеры модулю
  providers = {
    kubernetes = kubernetes
    helm       = helm
  }
}

# -------- Модуль: k8s-apps/bridge-relayer --------
module "bridge_relayer" {
  source = "../../modules/k8s-apps/bridge-relayer"

  namespace            = var.bridge_namespace
  chart_repository     = "https://bjw-s-labs.github.io/helm-charts"
  chart_name           = "app-template"
  chart_version        = var.bridge_chart_version

  image_repository     = var.bridge_image_repository
  image_tag            = var.bridge_image_tag
  container_port       = var.bridge_container_port
  replicas             = var.bridge_replicas

  relayer_env          = var.bridge_env
  relayer_secret_name  = var.bridge_secret_name
  relayer_secret_data  = var.bridge_secret_data

  providers = {
    kubernetes = kubernetes
    helm       = helm
  }

  depends_on = [module.cicd_runners]
}
