#############################################
# Aethernova — Terraform env: dev
# Назначение: базовая инициализация K8s-провайдеров и окружения,
# системные namespace'ы и условное включение ключевых модулей.
#############################################

terraform {
  required_version = ">= 1.6.0"

  # Требования к провайдерам (фиксируем источник и версии).
  # См. Terraform "required_providers". 
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.22.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.11.0"
    }
  }

  # Примечание: конфигурация backend (например, s3/remote) задаётся на уровне корня repo/орг-инфры.
  # См. Terraform backend reference.
  # backend "s3" { /* настраивается вне env/dev */ }
}

#############################################
# Входные переменные окружения dev
#############################################

variable "kubeconfig" {
  description = "Путь к kubeconfig для подключения к dev-кластеру."
  type        = string
  default     = null
  validation {
    condition     = var.kubeconfig == null || length(var.kubeconfig) > 0
    error_message = "kubeconfig должен быть непустой строкой или null."
  }
}

variable "kube_context" {
  description = "Kube context для dev-кластера (если не задан, берётся текущий)."
  type        = string
  default     = null
}

variable "enable_argocd" {
  description = "Разворачивать стек Argo CD в namespace 'cicd'."
  type        = bool
  default     = true
}

variable "enable_explorer" {
  description = "Разворачивать приложение 'explorer' в namespace 'aethernova-dev'."
  type        = bool
  default     = true
}

#############################################
# Провайдеры: Kubernetes и Helm
#############################################

# Kubernetes provider: управление ресурсами кластера.
# Документация провайдера Kubernetes.
provider "kubernetes" {
  config_path    = var.kubeconfig
  config_context = var.kube_context
}

# Helm provider: установка чартов через встроенный kube-блок.
# Документация провайдера Helm и nested kubernetes{}.
provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig
    config_context = var.kube_context
  }
}

#############################################
# Локальные значения и метки
#############################################
locals {
  env_name   = "dev"
  app_part   = "aethernova-chain-core"
  common_lbl = {
    "app.kubernetes.io/part-of" = local.app_part
    "app.kubernetes.io/managed-by" = "terraform"
    "topology.kubernetes.io/env" = local.env_name
  }
}

#############################################
# Системные пространства имён (Namespace)
# Ресурс kubernetes_namespace — официальный ресурс провайдера.
#############################################

resource "kubernetes_namespace" "dev" {
  metadata {
    name   = "aethernova-dev"
    labels = local.common_lbl
  }
}

resource "kubernetes_namespace" "cicd" {
  metadata {
    name = "cicd"
    labels = merge(local.common_lbl, {
      "policy.aethernova.io/tier" = "platform"
    })
  }
}

resource "kubernetes_namespace" "policies" {
  metadata {
    name = "policies"
    labels = merge(local.common_lbl, {
      "policy.aethernova.io/tier" = "security"
    })
  }
}

#############################################
# Модули окружения
# Используем meta-аргумент count для условного включения модулей.
# Подтверждено Terraform docs: count/for_each применимы к module-блокам.
#############################################

# CI/CD — Argo CD (через Helm).
module "cicd_argocd" {
  source = "../../modules/cicd/argocd"
  count  = var.enable_argocd ? 1 : 0

  # Пример параметров модуля (ожидается в модуле):
  # namespace выбора — из созданного ресурса.
  # Остальные значения — из самого модуля (Helm values/настройки).
  providers = {
    helm       = helm
    kubernetes = kubernetes
  }

  # Если модуль поддерживает параметр namespace — передаём его:
  # (безопасно: имя известно на этапе планирования)
  namespace = kubernetes_namespace.cicd.metadata[0].name
}

# Приложение: explorer (k8s-apps/explorer)
module "k8s_apps_explorer" {
  source = "../../modules/k8s-apps/explorer"
  count  = var.enable_explorer ? 1 : 0

  providers = {
    helm       = helm
    kubernetes = kubernetes
  }

  namespace    = kubernetes_namespace.dev.metadata[0].name
  service_name = "explorer"
  ingress_name = "explorer"
  # lookup_* по умолчанию = true внутри модуля (см. его variables)
}

#############################################
# Полезные проверки (опционально)
# Можно добавить check{} для мягкой валидации конфигурации (не блокирует операции).
# См. Terraform configuration-level validation (check blocks).
#############################################

# check "namespaces_created" {
#   assert {
#     condition     = length([kubernetes_namespace.dev.metadata[0].name, kubernetes_namespace.cicd.metadata[0].name, kubernetes_namespace.policies.metadata[0].name]) == 3
#     error_message = "Не удалось вычислить имена namespace'ов."
#   }
# }
