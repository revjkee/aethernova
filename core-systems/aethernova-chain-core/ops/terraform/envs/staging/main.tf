terraform {
  required_version = ">= 1.6.0"

  # Корневые требования к провайдерам (фиксируем источник и ветки версий)
  # Синтаксис required_providers — официальная документация Terraform.
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.38"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.0"
    }
    kubectl = {
      source  = "cynkra/kubectl"
      version = "~> 1.15"
    }
  }

  # Промышленная практика — держать backend-конфигурацию частично пустой
  # и передавать чувствительные/динамические параметры через `terraform init -backend-config=...`.
  # При необходимости добавьте блок backend в этом же файле (partial config).
  # Пример: terraform { backend "s3" {} } / backend "kubernetes" {}
}

# Провайдер Kubernetes: работа через kubeconfig (config_path/config_context)
# Эти поля описаны в документации Kubernetes-провайдера HashiCorp.
provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kube_context
}

# Провайдер Helm: подключение к кластеру через вложенный блок `kubernetes`
# с теми же параметрами kubeconfig; пример в README провайдера Helm.
provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = var.kube_context
  }
}

# Провайдер kubectl (cynkra): чтение kubeconfig; поддерживается режим load_config_file
# и поля для выбора контекста. Используем kubeconfig для staging-кластера.
provider "kubectl" {
  load_config_file = true
  config_path      = var.kubeconfig_path
  config_context   = var.kube_context
}

# Общие локали окружения (при необходимости используйте в модулях/ресурсах)
locals {
  environment = "staging"
}

# Подключение модулей проекта (локальные пути относительно env каталога).
# Локальные источники модулей — официальная документация Terraform по modules.
module "argocd" {
  source = "../modules/cicd/argocd"
}

module "explorer" {
  source = "../modules/k8s-apps/explorer"
}

# Входные параметры для провайдеров (kubeconfig)
variable "kubeconfig_path" {
  description = "Путь к kubeconfig файлу для доступа к кластеру"
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "Имя контекста в kubeconfig; если null — используется контекст по умолчанию"
  type        = string
  default     = null
}
