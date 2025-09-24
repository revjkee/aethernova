#############################################
# Path: ops/terraform/modules/bootstrap/providers/main.tf
# Purpose: Unified, production-grade provider definitions for AWS, GCP, Azure, Kubernetes, Helm
# Notes:
# - Не храните секреты в VCS. Передавайте через ENV или TF_VAR_*.
# - Все блоки провайдеров параметризованы и безопасны по умолчанию.
#############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.10.0"
    }
  }
}

########################################################
# Common inputs
########################################################

variable "tags" {
  description = "Глобальные теги/labels для поддерживаемых провайдеров."
  type        = map(string)
  default     = {}
}

variable "enable_aws" {
  description = "Включить конфигурацию провайдера AWS."
  type        = bool
  default     = true
}

variable "enable_gcp" {
  description = "Включить конфигурацию провайдера Google Cloud."
  type        = bool
  default     = false
}

variable "enable_azure" {
  description = "Включить конфигурацию провайдера Azure."
  type        = bool
  default     = false
}

variable "enable_kubernetes" {
  description = "Включить конфигурацию провайдера Kubernetes."
  type        = bool
  default     = false
}

variable "enable_helm" {
  description = "Включить конфигурацию провайдера Helm."
  type        = bool
  default     = false
}

locals {
  common_tags = merge(
    {
      ManagedBy = "Terraform"
      Component = "bootstrap/providers"
    },
    var.tags
  )
}

########################################################
# AWS provider (primary + optional replica)
########################################################

variable "aws_region" {
  description = "Основной регион AWS."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI/SDK профиль. Если пусто — используются переменные окружения/IMDS."
  type        = string
  default     = ""
}

variable "aws_replica_region" {
  description = "Дополнительный регион AWS (опционально)."
  type        = string
  default     = ""
}

variable "aws_default_tags" {
  description = "Дополнительные теги по умолчанию для AWS."
  type        = map(string)
  default     = {}
}

provider "aws" {
  alias   = "primary"
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null

  default_tags {
    tags = merge(local.common_tags, var.aws_default_tags)
  }

  # features {} # не требуется у aws
  # Используются стандартные механизмы аутентификации: env/SSO/IMDS/AssumeRole
  # Секреты не хранятся в коде.
  # Провайдер инициализируется, даже если не используется модулями (без обращения к API).
  # Активация через var.enable_aws.
  # Применяйте провайдера как: provider = aws.primary
  # или через alias "primary".
  # Чтобы полностью исключить провайдера из плана, не ссылайтесь на него в ресурсах.
  # var.enable_aws регулирует лишь намерение, не создает/удаляет сам провайдер.
  # Это ожидаемое поведение Terraform.
  # Не делаем зависимостей на переменные учётных данных.
  # Ошибок инициализации не будет, пока провайдер не используется.
  # Если используется — креды берутся из окружения/профиля.
  # Не могу подтвердить иное.
  # Примечание: комментарии даны для прозрачности поведения.
}

provider "aws" {
  alias   = "replica"
  region  = var.aws_replica_region != "" ? var.aws_replica_region : var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null

  default_tags {
    tags = merge(local.common_tags, var.aws_default_tags, { RegionRole = "replica" })
  }
}

########################################################
# Google Cloud provider (primary + optional replica)
########################################################

variable "gcp_project" {
  description = "ID проекта GCP."
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "Регион GCP."
  type        = string
  default     = "us-central1"
}

variable "gcp_replica_region" {
  description = "Дополнительный регион GCP (опционально)."
  type        = string
  default     = ""
}

variable "gcp_credentials_json" {
  description = "Полный JSON сервисного аккаунта (опционально, иначе используется ADC: env/gcloud)."
  type        = string
  default     = ""
  sensitive   = true
}

provider "google" {
  alias       = "primary"
  project     = var.gcp_project != "" ? var.gcp_project : null
  region      = var.gcp_region
  credentials = var.gcp_credentials_json != "" ? var.gcp_credentials_json : null
  user_project_override = false
  request_timeout       = "60s"
}

provider "google" {
  alias       = "replica"
  project     = var.gcp_project != "" ? var.gcp_project : null
  region      = var.gcp_replica_region != "" ? var.gcp_replica_region : var.gcp_region
  credentials = var.gcp_credentials_json != "" ? var.gcp_credentials_json : null
  user_project_override = false
  request_timeout       = "60s"
}

########################################################
# Azure provider (single)
########################################################

variable "azure_subscription_id" {
  description = "Subscription ID Azure."
  type        = string
  default     = ""
}

variable "azure_tenant_id" {
  description = "Tenant ID Azure."
  type        = string
  default     = ""
}

variable "azure_client_id" {
  description = "Client ID (приложение AAD). Пусто — используем Azure CLI/Managed Identity."
  type        = string
  default     = ""
}

variable "azure_client_secret" {
  description = "Client Secret (если используется приложенческий логин)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "azure_use_cli_auth" {
  description = "Использовать интерактивную авторизацию через Azure CLI."
  type        = bool
  default     = true
}

provider "azurerm" {
  features {}

  subscription_id = var.azure_subscription_id != "" ? var.azure_subscription_id : null
  tenant_id       = var.azure_tenant_id       != "" ? var.azure_tenant_id       : null

  client_id       = (var.azure_client_id != "" && !var.azure_use_cli_auth) ? var.azure_client_id : null
  client_secret   = (var.azure_client_secret != "" && !var.azure_use_cli_auth) ? var.azure_client_secret : null

  # Если включен use_cli_auth=true, провайдер попытается использовать az cli / managed identity.
  # Секреты в коде не требуются.
}

########################################################
# Kubernetes provider (primary + optional alias)
########################################################

# Способ 1: kubeconfig путь
variable "kubeconfig_path" {
  description = "Путь к kubeconfig. Если указан, используется он."
  type        = string
  default     = ""
}

# Способ 2: явные поля подключения
variable "kube_host" {
  description = "Kubernetes API server URL (если не используется kubeconfig)."
  type        = string
  default     = ""
}

variable "kube_ca_cert" {
  description = "CA сертификат кластера (PEM)."
  type        = string
  default     = ""
}

variable "kube_token" {
  description = "Bearer token для доступа к кластеру."
  type        = string
  default     = ""
  sensitive   = true
}

# Дополнительный контекст/кластер
variable "kube_alt_context" {
  description = "Имя альтернативного контекста в kubeconfig для второго провайдера."
  type        = string
  default     = ""
}

# primary
provider "kubernetes" {
  alias = "primary"

  dynamic "config_path" {
    for_each = var.kubeconfig_path != "" ? [1] : []
    content  = var.kubeconfig_path
  }

  dynamic "host" {
    for_each = (var.kubeconfig_path == "" && var.kube_host != "") ? [1] : []
    content  = var.kube_host
  }

  dynamic "cluster_ca_certificate" {
    for_each = (var.kubeconfig_path == "" && var.kube_ca_cert != "") ? [1] : []
    content  = var.kube_ca_cert
  }

  dynamic "token" {
    for_each = (var.kubeconfig_path == "" && var.kube_token != "") ? [1] : []
    content  = var.kube_token
  }
}

# secondary (через kubeconfig + context)
provider "kubernetes" {
  alias = "secondary"

  dynamic "config_path" {
    for_each = var.kubeconfig_path != "" ? [1] : []
    content  = var.kubeconfig_path
  }

  # Для вторичного провайдера используем context_name через variables в ресурсах helm/kubernetes,
  # так как провайдер kubernetes не имеет явного аргумента context_name.
  # Рекомендуется использовать отдельный kubeconfig при необходимости.
}

########################################################
# Helm provider (связан с Kubernetes provider)
########################################################

variable "helm_kube_context" {
  description = "Имя kubecontext для Helm (если используется kubeconfig)."
  type        = string
  default     = ""
}

variable "helm_namespace" {
  description = "Namespace по умолчанию для релизов Helm."
  type        = string
  default     = "default"
}

provider "helm" {
  alias = "primary"

  kubernetes {
    # Вариант 1: kubeconfig + context
    dynamic "config_path" {
      for_each = var.kubeconfig_path != "" ? [1] : []
      content  = var.kubeconfig_path
    }

    dynamic "config_context" {
      for_each = (var.kubeconfig_path != "" && var.helm_kube_context != "") ? [1] : []
      content  = var.helm_kube_context
    }

    # Вариант 2: явные поля (если нет kubeconfig)
    dynamic "host" {
      for_each = (var.kubeconfig_path == "" && var.kube_host != "") ? [1] : []
      content  = var.kube_host
    }

    dynamic "cluster_ca_certificate" {
      for_each = (var.kubeconfig_path == "" && var.kube_ca_cert != "") ? [1] : []
      content  = var.kube_ca_cert
    }

    dynamic "token" {
      for_each = (var.kubeconfig_path == "" && var.kube_token != "") ? [1] : []
      content  = var.kube_token
    }
  }

  experiments {
    manifest = true
  }

  registry {
    # При необходимости: аутентификация к OCI-репозиториям чартов через env/credentials helper.
  }
}

########################################################
# Convenience data sources
########################################################

data "aws_caller_identity" "current" {
  count = var.enable_aws ? 1 : 0
  provider = aws.primary
}

data "aws_region" "current" {
  count    = var.enable_aws ? 1 : 0
  provider = aws.primary
}

########################################################
# Minimal outputs (безопасные)
########################################################

output "providers_enabled" {
  description = "Активированные провайдеры-флаги."
  value = {
    aws        = var.enable_aws
    gcp        = var.enable_gcp
    azure      = var.enable_azure
    kubernetes = var.enable_kubernetes
    helm       = var.enable_helm
  }
}

output "aws_primary_region" {
  description = "Основной регион AWS (если включен)."
  value       = var.enable_aws ? var.aws_region : null
}

output "gcp_primary_region" {
  description = "Основной регион GCP (если включен)."
  value       = var.enable_gcp ? var.gcp_region : null
}
