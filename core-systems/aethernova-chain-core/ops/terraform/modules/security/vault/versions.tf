/**
 * Aethernova — Security/Vault
 * File: ops/terraform/modules/security/vault/versions.tf
 *
 * Назначение:
 *  - Фиксация поддерживаемой версии Terraform.
 *  - Жёсткая фиксация версий провайдеров, используемых подмодулем Vault.
 *  - Опциональная интеграция с Terraform Cloud/Enterprise через workspaces по тегам.
 *
 * Примечание:
 *  - Конкретные версии провайдеров подбираются по вашей матрице совместимости CI.
 *  - Рекомендуется поддерживать .terraform.lock.hcl под VCS.
 */

terraform {
  # Поддерживаемая версия Terraform
  required_version = ">= 1.6.0, < 2.0.0"

  # Жёсткая фиксация провайдеров для воспроизводимости сборок
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }

  # Опциональная интеграция с Terraform Cloud/Enterprise (удобно для линковки воркспейсов по тегам)
  cloud {
    hostname     = var.tf_cloud_hostname      # например, "app.terraform.io" или хост TFE
    organization = var.tf_cloud_organization  # ваша организация в TFC/TFE

    workspaces {
      tags = ["aethernova", "security", "vault"]
    }
  }

  # Метаданные для провайдера AWS (идентификация модуля в telemetry/инструментах)
  provider_meta "aws" {
    module_name = "aethernova/security-vault"
  }
}

# Опциональные переменные для блока cloud {}
# Значения задаются во внешнем окружении; при отсутствии — блок cloud можно удалить.
variable "tf_cloud_hostname" {
  description = "Хост Terraform Cloud/Enterprise. Пример: app.terraform.io"
  type        = string
  default     = "app.terraform.io"
}

variable "tf_cloud_organization" {
  description = "Имя организации в Terraform Cloud/Enterprise"
  type        = string
  default     = "aethernova"
}
