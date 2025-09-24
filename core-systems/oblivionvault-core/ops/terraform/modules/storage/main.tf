# File: oblivionvault-core/ops/terraform/modules/storage/main.tf
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.100.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }
}

# -----------------------------
# Inputs
# -----------------------------
variable "cloud" {
  description = "Целевое облако: aws | gcp | azure."
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.cloud)
    error_message = "cloud должен быть одним из: aws, gcp, azure."
  }
}

variable "name" {
  description = "Базовое имя системы (используется в именах ресурсов). Только латиница, цифры и дефисы."
  type        = string
}

variable "environment" {
  description = "Окружение: prod|staging|dev и т.п."
  type        = string
  default     = "prod"
}

variable "labels" {
  description = "Общие метки/теги (map). Будут применены ко всем поддерживающим провайдерам."
  type        = map(string)
  default     = {}
}

variable "force_destroy" {
  description = "Разрешить уничтожение ресурса даже при наличии объектов/блобов (use with care)."
  type        = bool
  default     = false
}

variable "versioning_enabled" {
  description = "Включить версионирование объектов."
  type        = bool
  default     = true
}

# ---------- AWS specific ----------
variable "aws_bucket_name" {
  description = "Явное имя S3‑бакета. Если пусто, будет сгенерировано безопасное уникальное имя."
  type        = string
  default     = ""
}

variable "aws_kms_key_id" {
  description = "ID существующего KMS‑ключа для S3 SSE‑KMS. Если пусто и aws_create_kms_key=true — будет создан CMK."
  type        = string
  default     = ""
}

variable "aws_create_kms_key" {
  description = "Создать управляемый CMK для шифрования S3."
  type        = bool
  default     = true
}

variable "aws_kms_key_alias" {
  description = "Alias для создаваемого KMS‑ключа."
  type        = string
  default     = "alias/oblivionvault-storage"
}

variable "aws_log_bucket" {
  description = "Имя бакета для server access logging. Если пусто — логирование отключено."
  type        = string
  default     = ""
}

variable "aws_lifecycle_rules" {
  description = <<EOT
Список lifecycle‑правил для S3. Пример элемента:
{
  id      = "std-intelligent-ice"
  enabled = true
  prefix  = null
  transitions = [
    { days = 30, storage_class = "INTELLIGENT_TIERING" },
    { days = 90, storage_class = "GLACIER" }
  ]
  expiration_days = 365
  noncurrent_version_expiration_days = 365
}
EOT
  type = list(object({
    id                                = string
    enabled                           = bool
    prefix                            = string
    transitions                       = list(object({ days = number, storage_class = string }))
    expiration_days                   = optional(number)
    noncurrent_version_expiration_days = optional(number)
  }))
  default = []
}

variable "aws_replication" {
  description = <<EOT
Опциональная репликация S3. Пример:
{
  enabled               = false
  destination_bucket_arn= "arn:aws:s3:::target-bucket"
  destination_kms_key_arn = null
  storage_class         = "STANDARD"
}
EOT
  type = object({
    enabled                 = bool
    destination_bucket_arn  = optional(string)
    destination_kms_key_arn = optional(string)
    storage_class           = optional(string)
  })
  default = {
    enabled = false
  }
}

# ---------- GCP specific ----------
variable "gcp_bucket_location" {
  description = "Локация GCS (например, EU, US, europe-west4)."
  type        = string
  default     = "EU"
}

variable "gcp_storage_class" {
  description = "Класс хранения GCS (STANDARD, NEARLINE, COLDLINE, ARCHIVE)."
  type        = string
  default     = "STANDARD"
}

variable "gcp_kms_key_name" {
  description = "Полный путь к KMS‑ключу (projects/.../locations/.../keyRings/.../cryptoKeys/...). Если пусто — используется Google‑managed."
  type        = string
  default     = ""
}

variable "gcp_uniform_access" {
  description = "Uniform bucket-level access (UBLA)."
  type        = bool
  default     = true
}

variable "gcp_logging_bucket" {
  description = "Бакет для логов доступа. Если пуст — логирование отключено."
  type        = string
  default     = ""
}

variable "gcp_retention_period_seconds" {
  description = "Политика удержания (секунды). 0 — отключено."
  type        = number
  default     = 0
}

# ---------- Azure specific ----------
variable "azure_create_resource_group" {
  description = "Создавать ли Resource Group."
  type        = bool
  default     = false
}

variable "azure_resource_group_name" {
  description = "Имя Resource Group (если не создаем — должна существовать)."
  type        = string
  default     = ""
}

variable "azure_location" {
  description = "Локация Azure (например, westeurope, northeurope)."
  type        = string
  default     = "westeurope"
}

variable "azure_account_tier" {
  description = "Tier аккаунта (Standard|Premium)."
  type        = string
  default     = "Standard"
}

variable "azure_replication_type" {
  description = "Тип репликации (LRS|GRS|RAGRS|ZRS|GZRS|RAGZRS)."
  type        = string
  default     = "LRS"
}

variable "azure_allow_blob_public_access" {
  description = "Глобально разрешить public доступ к blob. По умолчанию запрещено."
  type        = bool
  default     = false
}

variable "azure_cm_key_id" {
  description = "ID ключа Key Vault для CMK шифрования. Если пусто — используется Microsoft‑managed."
  type        = string
  default     = ""
}

variable "azure_infrastructure_encryption_enabled" {
  description = "Дополнительное шифрование инфраструктуры (двухслойное)."
  type        = bool
  default     = true
}

variable "azure_containers" {
  description = <<EOT
Список контейнеров для создания:
[
  { name = "data",  access_type = "private" },
  { name = "logs",  access_type = "private" }
]
EOT
  type = list(object({
    name        = string
    access_type = string # private|blob|container
  }))
  default = []
}

# -----------------------------
# Locals
# -----------------------------
locals {
  # Санитизация имени для бакетов/аккаунтов
  base_name = lower(regexreplace(var.name, "[^a-z0-9-]", "-"))

  common_tags = merge(
    {
      "app"         = local.base_name
      "environment" = var.environment
      "managed-by"  = "terraform"
      "module"      = "oblivionvault-core/storage"
    },
    var.labels
  )
}

# -----------------------------
# Random suffix for uniqueness
# -----------------------------
resource "random_id" "suffix" {
  byte_length = 2
  keepers = {
    base_name   = local.base_name
    environment = var.environment
    cloud       = var.cloud
  }
}

# =============================
# AWS S3
# =============================
# Optional CMK
resource "aws_kms_key" "this" {
  count                   = var.cloud == "aws" && var.aws_create_kms_key && var.aws_kms_key_id == "" ? 1 : 0
  description             = "OblivionVault storage CMK"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false
  tags                    = local.common_tags
}

resource "aws_kms_alias" "this" {
  count         = var.cloud == "aws" && var.aws_create_kms_key && var.aws_kms_key_id == "" ? 1 : 0
  name          = var.aws_kms_key_alias
  target_key_id = aws_kms_key.this[0].key_id
}

locals {
  aws_kms_id_effective = var.aws_kms_key_id != "" ? var.aws_kms_key_id : (
    length(aws_kms_key.this) > 0 ? aws_kms_key.this[0].key_id : null
  )

  aws_bucket_name_effective = var.aws_bucket_name != "" ? var.aws_bucket_name : format(
    "%s-%s-%s-%s",
    local.base_name, var.environment, "s3", random_id.suffix.hex
  )
}

resource "aws_s3_bucket" "this" {
  count  = var.cloud == "aws" ? 1 : 0
  bucket = local.aws_bucket_name_effective
  force_destroy = var.force_destroy
  tags   = local.common_tags
}

resource "aws_s3_bucket_ownership_controls" "this" {
  count  = var.cloud == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  count = var.cloud == "aws" ? 1 : 0

  bucket                  = aws_s3_bucket.this[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  count  = var.cloud == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count  = var.cloud == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.aws_kms_id_effective != null ? "aws:kms" : "AES256"
      kms_master_key_id = local.aws_kms_id_effective
    }
    bucket_key_enabled = true
  }
}

# Access logging (optional)
resource "aws_s3_bucket_logging" "this" {
  count  = var.cloud == "aws" && var.aws_log_bucket != "" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  target_bucket = var.aws_log_bucket
  target_prefix = "logs/${local.aws_bucket_name_effective}/"
}

# Lifecycle rules (optional, flexible)
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = var.cloud == "aws" && length(var.aws_lifecycle_rules) > 0 ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  dynamic "rule" {
    for_each = var.aws_lifecycle_rules
    content {
      id     = rule.value.id
      status = rule.value.enabled ? "Enabled" : "Disabled"

      dynamic "filter" {
        for_each = rule.value.prefix != null ? [1] : []
        content {
          prefix = rule.value.prefix
        }
      }

      dynamic "transition" {
        for_each = rule.value.transitions
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      dynamic "expiration" {
        for_each = try([rule.value.expiration_days], [])
        content {
          days = expiration.value
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = try([rule.value.noncurrent_version_expiration_days], [])
        content {
          noncurrent_days = noncurrent_version_expiration.value
        }
      }
    }
  }
}

# TLS-only & encryption-enforcement policy
data "aws_iam_policy_document" "s3_secure" {
  count = var.cloud == "aws" ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    principals { type = "*", identifiers = ["*"] }
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

  statement {
    sid       = "DenyIncorrectEncryptionHeader"
    effect    = "Deny"
    principals { type = "*", identifiers = ["*"] }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this[0].arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = local.aws_kms_id_effective != null ? ["aws:kms"] : ["AES256", "aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "secure" {
  count  = var.cloud == "aws" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  policy = data.aws_iam_policy_document.s3_secure[0].json
}

# Optional replication
data "aws_iam_policy_document" "s3_replication_assume" {
  count = var.cloud == "aws" && try(var.aws_replication.enabled, false) ? 1 : 0
  statement {
    effect = "Allow"
    principals { type = "Service", identifiers = ["s3.amazonaws.com"] }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "s3_replication" {
  count              = var.cloud == "aws" && try(var.aws_replication.enabled, false) ? 1 : 0
  name               = "${local.base_name}-${var.environment}-s3-repl-${random_id.suffix.hex}"
  assume_role_policy = data.aws_iam_policy_document.s3_replication_assume[0].json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "s3_replication_policy" {
  count = var.cloud == "aws" && try(var.aws_replication.enabled, false) ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket"
    ]
    resources = [aws_s3_bucket.this[0].arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObjectVersion",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging"
    ]
    resources = ["${aws_s3_bucket.this[0].arn}/*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner"
    ]
    resources = ["${var.aws_replication.destination_bucket_arn}/*"]
  }

  dynamic "statement" {
    for_each = try(var.aws_replication.destination_kms_key_arn, null) != null ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      resources = [var.aws_replication.destination_kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "s3_replication" {
  count  = var.cloud == "aws" && try(var.aws_replication.enabled, false) ? 1 : 0
  name   = "s3-replication-policy"
  role   = aws_iam_role.s3_replication[0].id
  policy = data.aws_iam_policy_document.s3_replication_policy[0].json
}

resource "aws_s3_bucket_replication_configuration" "this" {
  count  = var.cloud == "aws" && try(var.aws_replication.enabled, false) ? 1 : 0
  depends_on = [
    aws_s3_bucket_versioning.this
  ]
  bucket = aws_s3_bucket.this[0].id
  role   = aws_iam_role.s3_replication[0].arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = var.aws_replication.destination_bucket_arn
      storage_class = coalesce(try(var.aws_replication.storage_class, null), "STANDARD")
      dynamic "encryption_configuration" {
        for_each = try(var.aws_replication.destination_kms_key_arn, null) != null ? [1] : []
        content {
          replica_kms_key_id = var.aws_replication.destination_kms_key_arn
        }
      }
    }
  }
}

# Outputs for AWS
output "aws_bucket_name" {
  value       = var.cloud == "aws" ? aws_s3_bucket.this[0].bucket : null
  description = "Имя S3 бакета (AWS)."
}

output "aws_bucket_arn" {
  value       = var.cloud == "aws" ? aws_s3_bucket.this[0].arn : null
  description = "ARN S3 бакета (AWS)."
}

# =============================
# GCP GCS
# =============================
resource "google_storage_bucket" "this" {
  count  = var.cloud == "gcp" ? 1 : 0
  name   = format("%s-%s-gcs-%s", local.base_name, var.environment, random_id.suffix.hex)

  location              = var.gcp_bucket_location
  storage_class         = var.gcp_storage_class
  force_destroy         = var.force_destroy
  uniform_bucket_level_access = var.gcp_uniform_access

  labels = {
    for k, v in local.common_tags : k => v
  }

  versioning {
    enabled = var.versioning_enabled
  }

  encryption {
    default_kms_key_name = var.gcp_kms_key_name != "" ? var.gcp_kms_key_name : null
  }

  # Public access prevention enforced for security
  public_access_prevention = "enforced"

  dynamic "logging" {
    for_each = var.gcp_logging_bucket != "" ? [1] : []
    content {
      log_bucket        = var.gcp_logging_bucket
      log_object_prefix = "logs/${local.base_name}-${var.environment}"
    }
  }

  dynamic "retention_policy" {
    for_each = var.gcp_retention_period_seconds > 0 ? [1] : []
    content {
      retention_period = var.gcp_retention_period_seconds
      is_locked        = false
    }
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 5
    }
    action {
      type = "Delete"
    }
  }
}

output "gcp_bucket_name" {
  value       = var.cloud == "gcp" ? google_storage_bucket.this[0].name : null
  description = "Имя GCS бакета (GCP)."
}

# =============================
# Azure Storage
# =============================
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "this" {
  count    = var.cloud == "azure" && var.azure_create_resource_group ? 1 : 0
  name     = var.azure_resource_group_name != "" ? var.azure_resource_group_name : "${local.base_name}-${var.environment}-rg"
  location = var.azure_location
  tags     = local.common_tags
}

locals {
  azure_rg_name = var.cloud == "azure" ? (
    var.azure_create_resource_group
    ? azurerm_resource_group.this[0].name
    : var.azure_resource_group_name
  ) : null
}

resource "azurerm_storage_account" "this" {
  count                    = var.cloud == "azure" ? 1 : 0
  name                     = replace(substr("${local.base_name}${random_id.suffix.hex}", 0, 24), "-", "")
  resource_group_name      = local.azure_rg_name
  location                 = var.azure_location
  account_tier             = var.azure_account_tier
  account_replication_type = var.azure_replication_type
  account_kind             = "StorageV2"

  min_tls_version                 = "TLS1_2"
  allow_blob_public_access        = var.azure_allow_blob_public_access
  infrastructure_encryption_enabled = var.azure_infrastructure_encryption_enabled

  dynamic "customer_managed_key" {
    for_each = var.azure_cm_key_id != "" ? [1] : []
    content {
      key_vault_key_id = var.azure_cm_key_id
    }
  }

  enable_https_traffic_only = true

  tags = local.common_tags
}

resource "azurerm_storage_container" "this" {
  for_each              = var.cloud == "azure" ? { for c in var.azure_containers : c.name => c } : {}
  name                  = each.value.name
  storage_account_name  = azurerm_storage_account.this[0].name
  container_access_type = each.value.access_type
}

output "azure_storage_account_name" {
  value       = var.cloud == "azure" ? azurerm_storage_account.this[0].name : null
  description = "Имя Azure Storage Account."
}

output "azure_containers" {
  value       = var.cloud == "azure" ? keys(azurerm_storage_container.this) : null
  description = "Список созданных контейнеров в Azure."
}
