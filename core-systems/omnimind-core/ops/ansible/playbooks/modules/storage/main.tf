terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.114"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }
}

###############################################################################
# Входные переменные
###############################################################################

variable "provider" {
  description = "Целевой облачный провайдер: aws | gcp | azure"
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.provider)
    error_message = "provider должен быть одним из: aws, gcp, azure."
  }
}

variable "name" {
  description = "Логическое имя хранилища (без пробелов); используется в тегах и именах ресурсов."
  type        = string
}

variable "environment" {
  description = "Окружение: dev, staging, prod и т.п."
  type        = string
  default     = "dev"
}

variable "region" {
  description = "Регион/локация (AWS region, GCP location, Azure location)."
  type        = string
}

variable "tags" {
  description = "Теги/метки для ресурсов."
  type        = map(string)
  default     = {}
}

variable "versioning_enabled" {
  description = "Включить версионирование объектов."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Удалять бакет/контейнер с содержимым при destroy."
  type        = bool
  default     = false
}

variable "kms_key_id" {
  description = "Идентификатор KMS-ключа для шифрования на стороне сервера (ARN/ID/ResourceID). Если пусто — провайдерское шифрование по умолчанию."
  type        = string
  default     = ""
}

variable "public_access" {
  description = "Разрешить публичный чтение объектов (по умолчанию запрещено)."
  type        = bool
  default     = false
}

variable "logging_bucket" {
  description = "Имя бакета/контейнера для доступа логирования (целевой) — если пусто, логирование отключено."
  type        = string
  default     = ""
}

variable "lifecycle_current_transition_days" {
  description = "Через сколько дней переводить текущие объекты в более холодный класс (если поддерживается)."
  type        = number
  default     = 30
}

variable "lifecycle_current_delete_days" {
  description = "Удаление текущих объектов через X дней (0 — не удалять автоматически)."
  type        = number
  default     = 0
}

variable "lifecycle_noncurrent_delete_days" {
  description = "Удаление некоррентных версий через X дней (0 — не удалять автоматически)."
  type        = number
  default     = 90
}

# Azure-специфика
variable "azure_resource_group_name" {
  description = "Имя существующей Resource Group для Azure (обязательно при provider='azure')."
  type        = string
  default     = ""
}

variable "azure_storage_account_tier" {
  description = "Performance Tier для Azure Storage (Standard|Premium)."
  type        = string
  default     = "Standard"
}

variable "azure_replication_type" {
  description = "Тип репликации Azure (LRS|ZRS|GRS|RAGRS)."
  type        = string
  default     = "LRS"
}

# GCP-специфика
variable "gcp_location_type" {
  description = "Тип локации GCS (region|multi-region|dual-region)."
  type        = string
  default     = "region"
}

###############################################################################
# Локальные значения
###############################################################################

locals {
  common_tags = merge(
    {
      "app"         = var.name
      "env"         = var.environment
      "managed-by"  = "terraform"
      "component"   = "storage"
      "owner"       = "omnimind-core"
    },
    var.tags
  )

  # Нормализация имени для разных провайдеров
  normalized_name = lower(replace(var.name, "/[^a-zA-Z0-9-]/", "-"))

  # Включено ли логирование
  logging_enabled = length(var.logging_bucket) > 0
}

###############################################################################
# AWS S3
###############################################################################

# Случайный суффикс для уникальности (опционально для демонстрации, закомментировано)
# resource "random_id" "aws_suffix" {
#   byte_length = 2
#   keepers = {
#     name = local.normalized_name
#   }
# }

resource "aws_s3_bucket" "this" {
  count         = var.provider == "aws" ? 1 : 0
  bucket        = local.normalized_name
  force_destroy = var.force_destroy

  # object_lock только если нужно (можно расширить переменной)
  # object_lock_enabled = false

  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "this" {
  count  = var.provider == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count  = var.provider == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = length(var.kms_key_id) > 0 ? "aws:kms" : "AES256"
      kms_master_key_id = length(var.kms_key_id) > 0 ? var.kms_key_id : null
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  count  = var.provider == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = !var.public_access
  restrict_public_buckets = !var.public_access
}

resource "aws_s3_bucket_ownership_controls" "this" {
  count  = var.provider == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_logging" "this" {
  count  = var.provider == "aws" && local.logging_enabled ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  target_bucket = var.logging_bucket
  target_prefix = "logs/${local.normalized_name}/"
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = var.provider == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  rule {
    id     = "current-transition"
    status = var.lifecycle_current_transition_days > 0 ? "Enabled" : "Disabled"

    transition {
      days          = var.lifecycle_current_transition_days
      storage_class = "STANDARD_IA"
    }
  }

  rule {
    id     = "noncurrent-delete"
    status = var.lifecycle_noncurrent_delete_days > 0 ? "Enabled" : "Disabled"

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_noncurrent_delete_days
    }
  }

  rule {
    id     = "current-delete"
    status = var.lifecycle_current_delete_days > 0 ? "Enabled" : "Disabled"

    expiration {
      days = var.lifecycle_current_delete_days
    }
  }
}

# Политика Deny Insecure Transport + опциональная публичность чтения
data "aws_iam_policy_document" "s3_policy" {
  count = var.provider == "aws" ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [
      aws_s3_bucket.this[0].arn,
      "${aws_s3_bucket.this[0].arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  dynamic "statement" {
    for_each = var.public_access ? [1] : []
    content {
      sid       = "AllowPublicRead"
      effect    = "Allow"
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      actions = [
        "s3:GetObject"
      ]
      resources = ["${aws_s3_bucket.this[0].arn}/*"]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  count  = var.provider == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  policy = data.aws_iam_policy_document.s3_policy[0].json
}

###############################################################################
# GCP GCS
###############################################################################

resource "google_storage_bucket" "this" {
  count                        = var.provider == "gcp" ? 1 : 0
  name                         = local.normalized_name
  location                     = var.region
  force_destroy                = var.force_destroy
  uniform_bucket_level_access  = true
  public_access_prevention     = var.public_access ? "inherited" : "enforced"
  storage_class                = var.lifecycle_current_transition_days > 0 ? "STANDARD" : "STANDARD"

  versioning {
    enabled = var.versioning_enabled
  }

  dynamic "encryption" {
    for_each = length(var.kms_key_id) > 0 ? [1] : []
    content {
      default_kms_key_name = var.kms_key_id
    }
  }

  dynamic "logging" {
    for_each = local.logging_enabled ? [1] : []
    content {
      log_bucket        = var.logging_bucket
      log_object_prefix = "logs/${local.normalized_name}"
    }
  }

  lifecycle_rule {
    condition {
      age = var.lifecycle_current_delete_days > 0 ? var.lifecycle_current_delete_days : null
    }
    action {
      type = var.lifecycle_current_delete_days > 0 ? "Delete" : "Delete"
    }
  }

  lifecycle_rule {
    condition {
      num_newer_versions = var.lifecycle_noncurrent_delete_days > 0 ? 1 : null
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  labels = local.common_tags
}

###############################################################################
# Azure Blob
###############################################################################

provider "azurerm" {
  features {}
}

resource "azurerm_storage_account" "this" {
  count                    = var.provider == "azure" ? 1 : 0
  name                     = substr(replace(local.normalized_name, "/[^a-z0-9]/", ""), 0, 24)
  resource_group_name      = var.azure_resource_group_name
  location                 = var.region
  account_tier             = var.azure_storage_account_tier
  account_replication_type = var.azure_replication_type
  account_kind             = "StorageV2"
  enable_https_traffic_only = true
  min_tls_version          = "TLS1_2"
  allow_blob_public_access = var.public_access

  blob_properties {
    versioning_enabled       = var.versioning_enabled
    change_feed_enabled      = true
    last_access_time_enabled = true

    delete_retention_policy {
      days = var.lifecycle_current_delete_days > 0 ? var.lifecycle_current_delete_days : 7
    }

    container_delete_retention_policy {
      days = 7
    }
  }

  tags = local.common_tags
}

resource "azurerm_storage_container" "this" {
  count                 = var.provider == "azure" ? 1 : 0
  name                  = "${local.normalized_name}-data"
  storage_account_name  = azurerm_storage_account.this[0].name
  container_access_type = var.public_access ? "blob" : "private"
  metadata              = local.common_tags
}

# Политика управления жизненным циклом для Azure (Cool/Archive/Delete)
resource "azurerm_storage_management_policy" "this" {
  count               = var.provider == "azure" ? 1 : 0
  storage_account_id  = azurerm_storage_account.this[0].id

  rule {
    name    = "lifecycle"
    enabled = true
    filters {
      blob_types = ["blockBlob"]
      prefix_match = [azurerm_storage_container.this[0].name]
    }
    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = var.lifecycle_current_transition_days
        delete_after_days_since_modification_greater_than          = var.lifecycle_current_delete_days > 0 ? var.lifecycle_current_delete_days : null
      }
      version {
        delete_after_days_since_creation_greater_than = var.lifecycle_noncurrent_delete_days
      }
    }
  }
}

###############################################################################
# Outputs
###############################################################################

output "provider" {
  description = "Выбранный провайдер."
  value       = var.provider
}

output "name" {
  description = "Логическое имя хранилища."
  value       = var.name
}

output "bucket_id" {
  description = "Идентификатор бакета/контейнера."
  value = (
    var.provider == "aws"   ? aws_s3_bucket.this[0].id :
    var.provider == "gcp"   ? google_storage_bucket.this[0].name :
    var.provider == "azure" ? azurerm_storage_container.this[0].name :
    null
  )
}

output "resource_arn_or_url" {
  description = "ARN/URL ресурса (в зависимости от провайдера)."
  value = (
    var.provider == "aws"   ? aws_s3_bucket.this[0].arn :
    var.provider == "gcp"   ? "gs://${google_storage_bucket.this[0].name}" :
    var.provider == "azure" ? "https://${azurerm_storage_account.this[0].name}.blob.core.windows.net/${azurerm_storage_container.this[0].name}" :
    null
  )
}

output "versioning_enabled" {
  description = "Статус версионирования."
  value       = var.versioning_enabled
}

output "logging_enabled" {
  description = "Включено ли логирование доступа."
  value       = local.logging_enabled
}

output "kms_key_used" {
  description = "Используемый KMS-ключ (если задан)."
  value       = var.kms_key_id
  sensitive   = false
}
