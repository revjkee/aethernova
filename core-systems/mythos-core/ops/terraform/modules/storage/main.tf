#############################################
# mythos-core/ops/terraform/modules/storage/main.tf
# Industrial-grade storage module (AWS)
#############################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.30"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

#############################################
# Inputs
#############################################

variable "project" {
  description = "Имя проекта (в тегах и именах ресурсов)."
  type        = string
}

variable "environment" {
  description = "Окружение (prod|staging|dev|...)."
  type        = string
  default     = "prod"
}

variable "name" {
  description = "Базовое имя хранилища (будет использовано в именах бакетов)."
  type        = string
}

variable "enable_random_suffix" {
  description = "Добавлять случайный суффикс к имени бакетов для глобальной уникальности."
  type        = bool
  default     = true
}

variable "bucket_force_destroy" {
  description = "Разрешить уничтожение бакета с версиями/объектами (использовать осторожно)."
  type        = bool
  default     = false
}

variable "versioning_enabled" {
  description = "Включить версионирование основного бакета."
  type        = bool
  default     = true
}

variable "block_public_access" {
  description = "Заблокировать любой публичный доступ к бакетам."
  type        = bool
  default     = true
}

variable "logging_enabled" {
  description = "Включить access-логи S3 в отдельный лог-бакет."
  type        = bool
  default     = true
}

variable "log_bucket_retention_days" {
  description = "Срок хранения логов в днях."
  type        = number
  default     = 365
}

variable "kms_key_arn" {
  description = "Готовый KMS Key ARN для шифрования основного бакета. Если null и create_kms_key=true — будет создан новый KMS ключ."
  type        = string
  default     = null
}

variable "create_kms_key" {
  description = "Создавать KMS ключ для основного бакета, если kms_key_arn не задан."
  type        = bool
  default     = true
}

variable "lifecycle_rules" {
  description = <<EOT
Массив lifecycle-правил для aws_s3_bucket_lifecycle_configuration (autoscaling/v5 схема):
Пример элемента:
{
  id                                 = "expire-noncurrent"
  enabled                            = true
  prefix                             = null
  abort_incomplete_multipart_upload_days = 7
  transition_current = [
    { days = 30, storage_class = "STANDARD_IA" },
    { days = 60, storage_class = "GLACIER" }
  ]
  transition_noncurrent = [
    { newer_noncurrent_versions = 0, noncurrent_days = 30, storage_class = "STANDARD_IA" }
  ]
  expire_current_days                = null    # например 365
  expire_noncurrent_days             = 180
  noncurrent_versions_to_retain      = null
}
EOT
  type = list(object({
    id                                      = string
    enabled                                 = bool
    prefix                                  = optional(string)
    abort_incomplete_multipart_upload_days  = optional(number)
    transition_current = optional(list(object({
      days          = number
      storage_class = string
    })))
    transition_noncurrent = optional(list(object({
      noncurrent_days            = number
      newer_noncurrent_versions  = optional(number)
      storage_class              = string
    })))
    expire_current_days           = optional(number)
    expire_noncurrent_days        = optional(number)
    noncurrent_versions_to_retain = optional(number)
  }))
  default = [
    {
      id                                     = "default-lc"
      enabled                                = true
      abort_incomplete_multipart_upload_days = 7
      transition_current = [
        { days = 30, storage_class = "STANDARD_IA" }
      ]
      transition_noncurrent = [
        { noncurrent_days = 30, storage_class = "STANDARD_IA" }
      ]
      expire_current_days    = null
      expire_noncurrent_days = 365
    }
  ]
}

# Репликация (опционально). Для кросс-региона используйте alias провайдера "aws.replica" в корне.
variable "replication_enabled" {
  description = "Включить репликацию версий объектов."
  type        = bool
  default     = false
}

variable "manage_replication_destination" {
  description = "Создавать бакет назначения (true) или использовать существующий (false)."
  type        = bool
  default     = true
}

variable "replication_destination_bucket_name" {
  description = "Имя бакета назначения для репликации (если manage_replication_destination=false)."
  type        = string
  default     = null
}

variable "replication_prefix" {
  description = "Префикс в бакете назначения для реплицируемых объектов."
  type        = string
  default     = ""
}

variable "replication_kms_key_arn" {
  description = "KMS ключ ARN для бакета-назначения. Если не указан и создается dest-bucket — будет создан новый KMS ключ."
  type        = string
  default     = null
}

variable "use_replica_provider" {
  description = "Использовать провайдер aws.replica для ресурсов назначения (кросс-регион/аккаунт)."
  type        = bool
  default     = false
}

# Terraform backend infra (опционально)
variable "enable_tfstate_backend" {
  description = "Создать S3 + DynamoDB для Terraform remote state/lock."
  type        = bool
  default     = false
}

variable "tfstate_bucket_name" {
  description = "Имя бакета для Terraform state (если null — будет сгенерировано)."
  type        = string
  default     = null
}

variable "tfstate_dynamodb_table_name" {
  description = "Имя DynamoDB таблицы для блокировок (если null — будет сгенерировано)."
  type        = string
  default     = null
}

variable "tfstate_force_destroy" {
  description = "Разрешить уничтожение tfstate-бакета с версиями/объектами."
  type        = bool
  default     = false
}

variable "tfstate_versioning" {
  description = "Включить версионирование tfstate-бакета."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Дополнительные теги."
  type        = map(string)
  default     = {}
}

#############################################
# Locals
#############################################

locals {
  norm_name  = lower(replace(var.name, "/[^a-zA-Z0-9-]/", "-"))
  base_name  = "${local.norm_name}-${var.environment}"
}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  lower   = true
  numeric = true
  special = false
  keepers = {
    name = local.base_name
  }
}

locals {
  suffix           = var.enable_random_suffix ? "-${random_string.suffix.result}" : ""
  bucket_name      = "${local.base_name}${local.suffix}"
  log_bucket_name  = "${local.base_name}-logs${local.suffix}"

  tags = merge({
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    Module      = "mythos-core/storage"
  }, var.tags)
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

#############################################
# KMS (primary)
#############################################

resource "aws_kms_key" "primary" {
  count                   = var.kms_key_arn == null && var.create_kms_key ? 1 : 0
  description             = "KMS key for ${local.bucket_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_alias" "primary" {
  count         = length(aws_kms_key["primary"]) > 0 ? 1 : 0
  name          = "alias/${local.bucket_name}"
  target_key_id = aws_kms_key.primary[0].key_id
}

locals {
  primary_kms_arn = var.kms_key_arn != null ? var.kms_key_arn : (
    length(aws_kms_key.primary) > 0 ? aws_kms_key.primary[0].arn : null
  )
}

#############################################
# S3: Logs bucket (optional)
#############################################

resource "aws_s3_bucket" "logs" {
  count         = var.logging_enabled ? 1 : 0
  bucket        = local.log_bucket_name
  force_destroy = var.bucket_force_destroy
  tags          = merge(local.tags, { Purpose = "access-logs" })
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = var.logging_enabled ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = var.block_public_access
  block_public_policy     = var.block_public_access
  ignore_public_acls      = var.block_public_access
  restrict_public_buckets = var.block_public_access
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.logging_enabled ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.logging_enabled ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = var.logging_enabled ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    expiration {
      days = var.log_bucket_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Разрешения на доставку access-логов сервисом S3
resource "aws_s3_bucket_policy" "logs_delivery" {
  count  = var.logging_enabled ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerLogsDelivery"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${aws_s3_bucket.logs[0].id}/s3_access/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount"   = data.aws_caller_identity.current.account_id
            "s3:x-amz-acl"        = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

#############################################
# S3: Primary bucket
#############################################

resource "aws_s3_bucket" "primary" {
  bucket        = local.bucket_name
  force_destroy = var.bucket_force_destroy
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "primary" {
  bucket                  = aws_s3_bucket.primary.id
  block_public_acls       = var.block_public_access
  block_public_policy     = var.block_public_access
  ignore_public_acls      = var.block_public_access
  restrict_public_buckets = var.block_public_access
}

resource "aws_s3_bucket_ownership_controls" "primary" {
  bucket = aws_s3_bucket.primary.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  bucket = aws_s3_bucket.primary.id

  dynamic "rule" {
    for_each = [1]
    content {
      apply_server_side_encryption_by_default {
        sse_algorithm     = local.primary_kms_arn != null ? "aws:kms" : "AES256"
        kms_master_key_id = local.primary_kms_arn
      }
      bucket_key_enabled = true
    }
  }
}

# Логи включаются, если logging_enabled=true
resource "aws_s3_bucket_logging" "primary" {
  count         = var.logging_enabled ? 1 : 0
  bucket        = aws_s3_bucket.primary.id
  target_bucket = aws_s3_bucket.logs[0].id
  target_prefix = "s3_access/"
  depends_on    = [aws_s3_bucket_policy.logs_delivery]
}

# Lifecycle (гибкая схема)
resource "aws_s3_bucket_lifecycle_configuration" "primary" {
  bucket = aws_s3_bucket.primary.id

  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = rule.value.id
      status = rule.value.enabled ? "Enabled" : "Disabled"

      dynamic "filter" {
        for_each = rule.value.prefix != null ? [rule.value.prefix] : []
        content {
          prefix = filter.value
        }
      }

      dynamic "transition" {
        for_each = coalesce(rule.value.transition_current, [])
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      dynamic "noncurrent_version_transition" {
        for_each = coalesce(rule.value.transition_noncurrent, [])
        content {
          newer_noncurrent_versions = try(noncurrent_version_transition.value.newer_noncurrent_versions, null)
          noncurrent_days           = noncurrent_version_transition.value.noncurrent_days
          storage_class             = noncurrent_version_transition.value.storage_class
        }
      }

      dynamic "expiration" {
        for_each = rule.value.expire_current_days != null ? [rule.value.expire_current_days] : []
        content { days = expiration.value }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = rule.value.expire_noncurrent_days != null ? [rule.value.expire_noncurrent_days] : []
        content {
          noncurrent_days           = noncurrent_version_expiration.value
          newer_noncurrent_versions = try(rule.value.noncurrent_versions_to_retain, null)
        }
      }

      dynamic "abort_incomplete_multipart_upload" {
        for_each = rule.value.abort_incomplete_multipart_upload_days != null ? [rule.value.abort_incomplete_multipart_upload_days] : []
        content { days_after_initiation = abort_incomplete_multipart_upload.value }
      }
    }
  }
}

#############################################
# Replication (optional)
#############################################

# KMS для назначения (если создаем dest-bucket и ключ не задан)
resource "aws_kms_key" "replica" {
  count                   = var.replication_enabled && var.manage_replication_destination && var.replication_kms_key_arn == null ? 1 : 0
  description             = "KMS key for replica bucket ${local.bucket_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = local.tags
  provider                = var.use_replica_provider ? aws.replica : aws
}

locals {
  replica_kms_arn = var.replication_kms_key_arn != null ? var.replication_kms_key_arn : (
    length(aws_kms_key.replica) > 0 ? aws_kms_key.replica[0].arn : null
  )
  replica_bucket_name = var.manage_replication_destination
    ? "${local.base_name}-replica${local.suffix}"
    : var.replication_destination_bucket_name
}

resource "aws_s3_bucket" "replica" {
  count         = var.replication_enabled && var.manage_replication_destination ? 1 : 0
  bucket        = local.replica_bucket_name
  force_destroy = var.bucket_force_destroy
  tags          = merge(local.tags, { Purpose = "replica" })
  provider      = var.use_replica_provider ? aws.replica : aws
}

resource "aws_s3_bucket_public_access_block" "replica" {
  count                   = var.replication_enabled && var.manage_replication_destination ? 1 : 0
  bucket                  = aws_s3_bucket.replica[0].id
  block_public_acls       = var.block_public_access
  block_public_policy     = var.block_public_access
  ignore_public_acls      = var.block_public_access
  restrict_public_buckets = var.block_public_access
  provider                = var.use_replica_provider ? aws.replica : aws
}

resource "aws_s3_bucket_ownership_controls" "replica" {
  count    = var.replication_enabled && var.manage_replication_destination ? 1 : 0
  bucket   = aws_s3_bucket.replica[0].id
  provider = var.use_replica_provider ? aws.replica : aws
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "replica" {
  count    = var.replication_enabled && var.manage_replication_destination ? 1 : 0
  bucket   = aws_s3_bucket.replica[0].id
  provider = var.use_replica_provider ? aws.replica : aws
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica" {
  count    = var.replication_enabled && var.manage_replication_destination ? 1 : 0
  bucket   = aws_s3_bucket.replica[0].id
  provider = var.use_replica_provider ? aws.replica : aws

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.replica_kms_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = local.replica_kms_arn
    }
    bucket_key_enabled = true
  }
}

# IAM роль и политика для репликации
data "aws_iam_policy_document" "replication" {
  statement {
    sid     = "AllowS3Replication"
    effect  = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket"
    ]
    resources = [aws_s3_bucket.primary.arn]
  }

  statement {
    sid     = "AllowObjectRead"
    effect  = "Allow"
    actions = [
      "s3:GetObjectVersion",
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionTagging",
      "s3:GetObjectRetention",
      "s3:GetObjectLegalHold"
    ]
    resources = ["${aws_s3_bucket.primary.arn}/*"]
  }

  statement {
    sid     = "AllowObjectWriteReplica"
    effect  = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner"
    ]
    resources = [
      var.manage_replication_destination
        ? "${aws_s3_bucket.replica[0].arn}/*"
        : "arn:aws:s3:::${local.replica_bucket_name}/*"
    ]
  }

  dynamic "statement" {
    for_each = local.primary_kms_arn != null ? [1] : []
    content {
      sid     = "AllowDecryptOnSourceKMS"
      effect  = "Allow"
      actions = ["kms:Decrypt", "kms:DescribeKey"]
      resources = [local.primary_kms_arn]
    }
  }

  dynamic "statement" {
    for_each = local.replica_kms_arn != null ? [1] : []
    content {
      sid     = "AllowEncryptOnDestinationKMS"
      effect  = "Allow"
      actions = ["kms:Encrypt", "kms:ReEncrypt*", "kms:DescribeKey", "kms:GenerateDataKey*"]
      resources = [local.replica_kms_arn]
    }
  }
}

resource "aws_iam_role" "replication" {
  count              = var.replication_enabled ? 1 : 0
  name               = "s3-replication-${local.bucket_name}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "s3.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "replication" {
  count  = var.replication_enabled ? 1 : 0
  name   = "s3-replication-policy-${local.bucket_name}"
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication.json
}

resource "aws_s3_bucket_replication_configuration" "primary" {
  count  = var.replication_enabled ? 1 : 0
  bucket = aws_s3_bucket.primary.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id     = "all-objects"
    status = "Enabled"

    filter {
      prefix = ""
    }

    destination {
      bucket        = var.manage_replication_destination ? aws_s3_bucket.replica[0].arn : "arn:aws:s3:::${local.replica_bucket_name}"
      storage_class = "STANDARD"
      dynamic "encryption_configuration" {
        for_each = local.replica_kms_arn != null ? [1] : []
        content {
          replica_kms_key_id = local.replica_kms_arn
        }
      }
      dynamic "access_control_translation" {
        for_each = [1]
        content {
          owner = "Destination"
        }
      }
      account = null
      # optional prefix
      dynamic "metrics" {
        for_each = []
        content {}
      }
    }

    delete_marker_replication { status = "Enabled" }
  }

  depends_on = [
    aws_s3_bucket_versioning.primary,
    aws_s3_bucket_versioning.replica
  ]
}

#############################################
# Terraform State backend (optional)
#############################################

locals {
  tfstate_bucket_name = coalesce(var.tfstate_bucket_name, "${local.base_name}-tfstate${local.suffix}")
  tfstate_table_name  = coalesce(var.tfstate_dynamodb_table_name, "${local.base_name}-tf-locks")
}

resource "aws_s3_bucket" "tfstate" {
  count         = var.enable_tfstate_backend ? 1 : 0
  bucket        = local.tfstate_bucket_name
  force_destroy = var.tfstate_force_destroy
  tags          = merge(local.tags, { Purpose = "terraform-state" })
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  count                   = var.enable_tfstate_backend ? 1 : 0
  bucket                  = aws_s3_bucket.tfstate[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "tfstate" {
  count  = var.enable_tfstate_backend ? 1 : 0
  bucket = aws_s3_bucket.tfstate[0].id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  count  = var.enable_tfstate_backend ? 1 : 0
  bucket = aws_s3_bucket.tfstate[0].id
  versioning_configuration {
    status = var.tfstate_versioning ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  count  = var.enable_tfstate_backend ? 1 : 0
  bucket = aws_s3_bucket.tfstate[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_dynamodb_table" "tf_locks" {
  count          = var.enable_tfstate_backend ? 1 : 0
  name           = local.tfstate_table_name
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"
  point_in_time_recovery {
    enabled = true
  }

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = merge(local.tags, { Purpose = "terraform-locks" })
}

#############################################
# Outputs
#############################################

output "bucket_name" {
  description = "Имя основного S3 бакета."
  value       = aws_s3_bucket.primary.bucket
}

output "bucket_arn" {
  description = "ARN основного S3 бакета."
  value       = aws_s3_bucket.primary.arn
}

output "primary_kms_key_arn" {
  description = "KMS ключ ARN для основного бакета (если используется)."
  value       = local.primary_kms_arn
}

output "log_bucket_name" {
  description = "Имя лог-бакета (если включен)."
  value       = var.logging_enabled ? aws_s3_bucket.logs[0].bucket : null
}

output "replica_bucket_name" {
  description = "Имя бакета назначения репликации (если включено)."
  value       = var.replication_enabled ? local.replica_bucket_name : null
}

output "tfstate_bucket_name" {
  description = "Имя бакета Terraform state (если создается)."
  value       = var.enable_tfstate_backend ? aws_s3_bucket.tfstate[0].bucket : null
}

output "tfstate_lock_table_name" {
  description = "Имя DynamoDB таблицы блокировок Terraform (если создается)."
  value       = var.enable_tfstate_backend ? aws_dynamodb_table.tf_locks[0].name : null
}

#############################################
# Notes:
# - Для кросс-региональной репликации в корневом модуле задайте:
#
#   provider "aws" { region = "eu-west-1" }
#   provider "aws" { alias = "replica" region = "eu-central-1" }
#
#   module "storage" {
#     source              = "./ops/terraform/modules/storage"
#     providers = {
#       aws         = aws
#       aws.replica = aws.replica
#     }
#     use_replica_provider              = true
#     replication_enabled               = true
#   }
#
#############################################
