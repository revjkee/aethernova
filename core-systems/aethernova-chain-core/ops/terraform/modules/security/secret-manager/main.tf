// SPDX-License-Identifier: Apache-2.0
// Module: aethernova-chain-core/ops/terraform/modules/security/secret-manager
// File:   main.tf
// Purpose:
//   Cross-cloud secret management (AWS Secrets Manager / GCP Secret Manager / Azure Key Vault).
//   - Providers are configured at ROOT. This module declares resources conditionally.
//   - Supports: initial secret value, KMS/CMEK, replication, AWS rotation (via external Lambda), labels/tags.
//   - Azure: can create a new Key Vault or use an existing one by id.
//
// Notes:
//   - Configure providers (aws/google/azurerm) in the ROOT module; do not set credentials here.
//   - All variables are defined here for convenience; you may move them to variables.tf if preferred.

//-----------------------------
// Terraform + (optional) provider constraints
//-----------------------------
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.37.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.117.0"
    }
  }
}

//-----------------------------
// Variables (toggle each cloud, secret name/value, metadata)
//-----------------------------
variable "enable_aws" {
  description = "Включить создание секрета в AWS Secrets Manager."
  type        = bool
  default     = false
}

variable "enable_gcp" {
  description = "Включить создание секрета в GCP Secret Manager."
  type        = bool
  default     = false
}

variable "enable_azure" {
  description = "Включить создание секрета в Azure Key Vault."
  type        = bool
  default     = false
}

variable "name" {
  description = "Логическое имя секрета (будет использовано как base-name во всех облаках)."
  type        = string
}

variable "initial_secret_value" {
  description = "Начальное значение секрета. Если null — версия не создаётся автоматически."
  type        = string
  default     = null
  sensitive   = true
}

variable "labels" {
  description = "Произвольные метки/теги (будут маппиться на теги/ярлыки облаков)."
  type        = map(string)
  default     = {}
}

variable "kms" {
  description = <<-EOT
    Параметры шифрования:
      - aws.kms_key_id: KMS key id/arn для AWS Secrets Manager (optional).
      - gcp.kms_key_name: KMS key resource name для CMEK в GCP (optional).
      - azure.key_vault_sku: SKU Key Vault (standard/premium), если создаём его.
  EOT
  type = object({
    aws  = object({ kms_key_id     = optional(string) })
    gcp  = object({ kms_key_name   = optional(string) })
    azure= object({ key_vault_sku  = optional(string, "standard") })
  })
  default = {
    aws = { kms_key_id = null }
    gcp = { kms_key_name = null }
    azure = { key_vault_sku = "standard" }
  }
}

variable "aws" {
  description = <<-EOT
    Настройки AWS секрета:
      - description: описание секрета.
      - force_overwrite_replica_secret: перезапись при репликациях.
      - replica_regions: список регионов-реплик (например ["eu-west-1","us-east-1"]).
      - rotation_lambda_arn: ARN Lambda для ротации (optional).
      - rotation_interval_days: период ротации (days), если включена.
  EOT
  type = object({
    description                    = optional(string, "")
    force_overwrite_replica_secret = optional(bool, true)
    replica_regions                = optional(list(string), [])
    rotation_lambda_arn            = optional(string)
    rotation_interval_days         = optional(number, 30)
    tags                           = optional(map(string), {})
  })
  default = {}
}

variable "gcp" {
  description = <<-EOT
    Настройки GCP секрета:
      - project: проект GCP (если не задан в провайдере).
      - replica_locations: список локаций для user-managed репликации (если пуст — automatic).
      - labels: ярлыки для секрета.
  EOT
  type = object({
    project           = optional(string)
    replica_locations = optional(list(string), [])
    labels            = optional(map(string), {})
  })
  default = {}
}

variable "azure" {
  description = <<-EOT
    Настройки Azure:
      - create_vault: создавать ли Key Vault (true) или использовать существующий (false).
      - key_vault_id: id существующего Key Vault (если create_vault=false).
      - tenant_id, location, resource_group_name: обязательны при create_vault=true.
      - purge_protection_enabled, soft_delete_retention_days: политики хранения.
      - sku_name: см. kms.azure.key_vault_sku (standard/premium).
      - content_type: contentType секрета.
      - not_before, expiration_date: атрибуты секретa (RFC3339 timestamp).
      - secret_tags: теги для секрета.
  EOT
  type = object({
    create_vault           = optional(bool, false)
    key_vault_id           = optional(string)
    tenant_id              = optional(string)
    location               = optional(string)
    resource_group_name    = optional(string)
    purge_protection_enabled = optional(bool, true)
    soft_delete_retention_days = optional(number, 90)
    sku_name               = optional(string)
    content_type           = optional(string)
    not_before             = optional(string)
    expiration_date        = optional(string)
    secret_tags            = optional(map(string), {})
    vault_tags             = optional(map(string), {})
  })
  default = {}
}

//-----------------------------
// Locals
//-----------------------------
locals {
  merged_labels = merge(var.labels, {})

  aws_tags = merge(local.merged_labels, try(var.aws.tags, {}))

  azure_sku = coalesce(try(var.azure.sku_name, null), try(var.kms.azure.key_vault_sku, null), "standard")

  gcp_labels = merge(local.merged_labels, try(var.gcp.labels, {}))
}

//-----------------------------
// AWS Secrets Manager
//-----------------------------
resource "aws_secretsmanager_secret" "this" {
  count       = var.enable_aws ? 1 : 0
  name        = var.name
  description = try(var.aws.description, "")

  kms_key_id  = try(var.kms.aws.kms_key_id, null)

  force_overwrite_replica_secret = try(var.aws.force_overwrite_replica_secret, true)

  dynamic "replica" {
    for_each = try(var.aws.replica_regions, [])
    content {
      region     = replica.value
      kms_key_id = try(var.kms.aws.kms_key_id, null)
    }
  }

  tags = local.aws_tags
}

resource "aws_secretsmanager_secret_version" "initial" {
  count         = var.enable_aws && !isnull(var.initial_secret_value) ? 1 : 0
  secret_id     = aws_secretsmanager_secret.this[0].id
  secret_string = var.initial_secret_value
}

resource "aws_secretsmanager_secret_rotation" "this" {
  count                = var.enable_aws && try(var.aws.rotation_lambda_arn, null) != null ? 1 : 0
  secret_id            = aws_secretsmanager_secret.this[0].id
  rotation_lambda_arn  = var.aws.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = try(var.aws.rotation_interval_days, 30)
  }

  depends_on = [aws_secretsmanager_secret_version.initial]
}

//-----------------------------
// GCP Secret Manager
//-----------------------------
resource "google_secret_manager_secret" "this" {
  count  = var.enable_gcp ? 1 : 0
  secret_id = var.name
  project   = try(var.gcp.project, null)

  replication {
    dynamic "user_managed" {
      for_each = length(try(var.gcp.replica_locations, [])) > 0 ? [1] : []
      content {
        dynamic "replicas" {
          for_each = toset(var.gcp.replica_locations)
          content {
            location = replicas.value
            dynamic "customer_managed_encryption" {
              for_each = try(var.kms.gcp.kms_key_name, null) != null ? [1] : []
              content {
                kms_key_name = var.kms.gcp.kms_key_name
              }
            }
          }
        }
      }
    }
    dynamic "automatic" {
      for_each = length(try(var.gcp.replica_locations, [])) == 0 ? [1] : []
      content {
        dynamic "customer_managed_encryption" {
          for_each = try(var.kms.gcp.kms_key_name, null) != null ? [1] : []
          content {
            kms_key_name = var.kms.gcp.kms_key_name
          }
        }
      }
    }
  }

  labels = local.gcp_labels
}

resource "google_secret_manager_secret_version" "initial" {
  count       = var.enable_gcp && !isnull(var.initial_secret_value) ? 1 : 0
  secret      = google_secret_manager_secret.this[0].id
  secret_data = var.initial_secret_value
}

//-----------------------------
// Azure Key Vault (optionally create) + Secret
//-----------------------------
provider "azurerm" {
  features {}
}

resource "azurerm_key_vault" "this" {
  count                        = var.enable_azure && try(var.azure.create_vault, false) ? 1 : 0
  name                         = "${replace(var.name, "/[^a-zA-Z0-9-]/", "")}-kv"
  location                     = var.azure.location
  resource_group_name          = var.azure.resource_group_name
  tenant_id                    = var.azure.tenant_id
  sku_name                     = lower(local.azure_sku) == "premium" ? "premium" : "standard"
  soft_delete_retention_days   = try(var.azure.soft_delete_retention_days, 90)
  purge_protection_enabled     = try(var.azure.purge_protection_enabled, true)

  // Доступы и сети должны настраиваться снаружи (RBAC/Access Policies/Firewall).
  // Оставляем минимально необходимую конфигурацию.
  tags = try(var.azure.vault_tags, {})
}

locals {
  key_vault_id_effective = var.enable_azure ? (
    try(var.azure.create_vault, false)
      ? azurerm_key_vault.this[0].id
      : try(var.azure.key_vault_id, null)
  ) : null
}

resource "azurerm_key_vault_secret" "this" {
  count        = var.enable_azure ? 1 : 0
  name         = var.name
  value        = coalesce(var.initial_secret_value, "")
  key_vault_id = local.key_vault_id_effective

  content_type = try(var.azure.content_type, null)
  not_before   = try(var.azure.not_before, null)
  expiration_date = try(var.azure.expiration_date, null)

  tags = try(var.azure.secret_tags, {})

  lifecycle {
    ignore_changes = [
      // чтобы не принудительно пересоздавать секрет при внешней ротации/обновлении
      value
    ]
  }
}

//-----------------------------
// Outputs (minimal essentials)
//-----------------------------
output "aws_secret_arn" {
  description = "ARN секрета в AWS Secrets Manager."
  value       = try(aws_secretsmanager_secret.this[0].arn, null)
  sensitive   = false
}

output "aws_secret_version_id" {
  description = "ID версии AWS секрета (если создана)."
  value       = try(aws_secretsmanager_secret_version.initial[0].version_id, null)
  sensitive   = false
}

output "gcp_secret_id" {
  description = "ID секрета в GCP Secret Manager."
  value       = try(google_secret_manager_secret.this[0].id, null)
  sensitive   = false
}

output "gcp_secret_version_name" {
  description = "Имя версии GCP секрета (если создана)."
  value       = try(google_secret_manager_secret_version.initial[0].name, null)
  sensitive   = false
}

output "azure_key_vault_id" {
  description = "ID Key Vault (созданного модулем или переданного извне)."
  value       = local.key_vault_id_effective
  sensitive   = false
}

output "azure_secret_id" {
  description = "ID секрета в Azure Key Vault."
  value       = try(azurerm_key_vault_secret.this[0].id, null)
  sensitive   = false
}
