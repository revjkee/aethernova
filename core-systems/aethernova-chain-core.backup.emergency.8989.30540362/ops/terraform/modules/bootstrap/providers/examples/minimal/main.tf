#############################################
# aethernova-chain-core / ops / terraform
# modules/bootstrap/providers/examples/minimal/main.tf
#############################################

terraform {
  # Фиксируем совместимость Terraform (LTS-окно)
  required_version = ">= 1.6.0, < 2.0.0" # ref: Terraform block reference
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.90.0, < 5.0.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0, < 7.0.0"
    }
  }
}

#############################################
# Переключатель облака
#############################################
variable "cloud" {
  description = "Целевое облако: aws | azure | gcp"
  type        = string
  default     = "aws"

  validation {
    condition     = contains(["aws", "azure", "gcp"], var.cloud)
    error_message = "Допустимые значения: aws, azure, gcp."
  }
}

locals {
  use_aws   = var.cloud == "aws"
  use_azure = var.cloud == "azure"
  use_gcp   = var.cloud == "gcp"
}

#############################################
# Провайдеры: минимальные конфигурации
# - Пустая конфигурация допустима (HashiCorp Docs: provider configuration without arguments).
# - Для AzureRM обязателен блок features {} (Terraform Registry: azurerm features-block).
#############################################

provider "aws" {
  # region может быть задан через env (AWS_REGION) или TF_VAR_*
  # Оставлено пустым намеренно для примера "минимального" провайдера.
}

provider "azurerm" {
  features {} # обязательно для azurerm
}

provider "google" {
  # project/region/zone могут приходить из окружения GOOGLE_PROJECT/GOOGLE_CLOUD_PROJECT и т.п.
}

#############################################
# Диагностика подключения (по выбранному облаку)
# Data-источники поддерживают count/for_each (HashiCorp Docs: data sources multiple instances).
#############################################

# AWS: идентичность текущего вызывающего субъекта
data "aws_caller_identity" "current" {
  count = local.use_aws ? 1 : 0
}

# Azure: конфигурация клиента
data "azurerm_client_config" "current" {
  count = local.use_azure ? 1 : 0
}

# GCP: конфигурация клиента
data "google_client_config" "current" {
  count = local.use_gcp ? 1 : 0
}

#############################################
# Вывод диагностической информации по выбранному облаку
#############################################

output "diagnostics" {
  description = "Базовая диагностическая информация об учётных данных провайдера."
  value = {
    cloud = var.cloud

    aws = local.use_aws ? {
      account_id = data.aws_caller_identity.current[0].account_id
      arn        = data.aws_caller_identity.current[0].arn
      user_id    = data.aws_caller_identity.current[0].user_id
    } : null

    azure = local.use_azure ? {
      subscription_id = data.azurerm_client_config.current[0].subscription_id
      tenant_id       = data.azurerm_client_config.current[0].tenant_id
      object_id       = data.azurerm_client_config.current[0].object_id
    } : null

    gcp = local.use_gcp ? {
      project = data.google_client_config.current[0].project
      region  = data.google_client_config.current[0].region
      zone    = data.google_client_config.current[0].zone
    } : null
  }
  sensitive = true # содержит потенциально чувствительные идентификаторы
}

#############################################
# Подсказки по запуску (комментарии, не выполняются):
# terraform init
# terraform plan -var="cloud=aws|azure|gcp"
#############################################
