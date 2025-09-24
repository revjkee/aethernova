terraform {
  # Жесткое окно совместимости Terraform для модулей прод-уровня
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # AWS: S3/DynamoDB для state/lock (используется в инфраструктуре на AWS)
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }

    # Azure: Storage Account/Container для state (используется в инфраструктуре на Azure)
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.100.0, < 4.0.0"
    }

    # GCP: GCS Bucket для state (используется в инфраструктуре на GCP)
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0, < 6.0.0"
    }

    # Доп. канал для фич предварительного канала в GCP (опционально)
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0.0, < 6.0.0"
    }

    # Вспомогательные провайдеры для генерации суффиксов/идентификаторов и тайминга
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0, < 4.0.0"
    }

    time = {
      source  = "hashicorp/time"
      version = ">= 0.11.0, < 1.0.0"
    }
  }
}

# Примечание:
# - Конкретные provider {} блоки и их конфигурация (region, features и т.п.) выносите в providers.tf,
#   а окруженческие привязки — в *.tfvars/переменные. Данный файл фиксирует только совместимость версий.
