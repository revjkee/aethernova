#############################################
# ledger-core :: storage module (AWS S3+KMS)
# File: ops/terraform/modules/storage/main.tf
#############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

############################################################
# VARIABLES
############################################################

variable "name" {
  description = "Базовое имя бакета (будет нормализовано и дополнено окружением/уникальностью)."
  type        = string
}

variable "environment" {
  description = "Окружение: dev|staging|prod и т.п."
  type        = string
}

variable "tags" {
  description = "Общие теги."
  type        = map(string)
  default     = {}
}

variable "force_destroy" {
  description = "Удалять бакет с содержимым (опасно; используйте только в dev)."
  type        = bool
  default     = false
}

variable "enable_versioning" {
  description = "Включить версионирование бакета."
  type        = bool
  default     = true
}

variable "enable_object_lock" {
  description = "Включить Object Lock (требует создания бакета с lock). Невозможно включить на уже существующем."
  type        = bool
  default     = false
}

variable "kms_create_key" {
  description = "Создать управляемый KMS-ключ для шифрования."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Использовать существующий KMS-ключ (если kms_create_key=false)."
  type        = string
  default     = null
}

variable "kms_key_deletion_window_days" {
  description = "Окно удаления KMS ключа."
  type        = number
  default     = 30
}

variable "logging_enabled" {
  description = "Включить логирование доступа S3."
  type        = bool
  default     = true
}

variable "logging_create_bucket" {
  description = "Создать отдельный бакет для логов, если logging_enabled=true."
  type        = bool
  default     = true
}

variable "logging_bucket_name" {
  description = "Имя существующего бакета для логов, если logging_create_bucket=false."
  type        = string
  default     = null
}

variable "logging_prefix" {
  description = "Префикс ключей логов."
  type        = string
  default     = "s3-access/"
}

variable "block_public_access" {
  description = "Полная блокировка публичного доступа."
  type        = bool
  default     = true
}

variable "lifecycle_rules" {
  description = <<EOT
Список lifecycle-правил. Пример:
[
  {
    id      = "noncurrent-90-expire"
    enabled = true
    noncurrent_version_expiration = { newer_noncurrent_versions = 3, noncurrent_days = 90 }
  },
  {
    id      = "current-365-expire"
    enabled = true
    expiration = { days = 365 }
    transitions = [
      { days = 30, storage_class = "STANDARD_IA" },
      { days = 90, storage_class = "GLACIER" }
    ]
  }
]
EOT
  type    = any
  default = []
}

variable "replication_enabled" {
  description = "Включить CRR (кросс-региональную репликацию)."
  type        = bool
  default     = false
}

variable "replication_destination_bucket_arn" {
  description = "ARN целевого бакета для репликации."
  type        = string
  default     = null
}

variable "replication_destination_kms_key_arn" {
  description = "KMS ключ назначения."
  type        = string
  default     = null
}

variable "replication_create_role" {
  description = "Создать IAM роль для репликации (если не указана внешняя роль)."
  type        = bool
  default     = true
}

variable "app_iam_enable" {
  description = "Создать IAM роль/политику для приложения c доступом к префиксам."
  type        = bool
  default     = true
}

variable "app_role_name" {
  description = "Имя IAM роли приложения (если создаём)."
  type        = string
  default     = null
}

variable "app_allowed_actions" {
  description = "Ограниченный список действий для роли приложения."
  type        = list(string)
  default     = [
    "s3:PutObject",
    "s3:GetObject",
    "s3:DeleteObject",
    "s3:AbortMultipartUpload",
    "s3:ListBucketMultipartUploads",
    "s3:ListBucket",
    "s3:GetBucketLocation"
  ]
}

variable "app_prefixes" {
  description = "Список префиксов в бакете, к которым приложению разрешён доступ."
  type        = list(string)
  default     = ["data/", "tmp/"]
}

############################################################
# LOCALS
############################################################

locals {
  common_tags = merge({
    "Project"     = "ledger-core"
    "Environment" = var.environment
    "Module"      = "storage"
  }, var.tags)

  bucket_name_base = lower(replace(var.name, "/[^a-zA-Z0-9-]/", "-"))
  bucket_name      = "${local.bucket_name_base}-${var.environment}-${random_id.suffix.hex}"

  logs_bucket_name = var.logging_create_bucket ? "${local.bucket_name}-logs" : var.logging_bucket_name

  # Выбор KMS ключа
  effective_kms_key_arn = var.kms_create_key ? aws_kms_key.this[0].arn : var.kms_key_arn
}

############################################################
# RANDOM SUFFIX (уникальность имени бакета)
############################################################

resource "random_id" "suffix" {
  byte_length = 4
}

############################################################
# KMS (optional)
############################################################

resource "aws_kms_key" "this" {
  count                   = var.kms_create_key ? 1 : 0
  description             = "KMS key for S3 bucket ${local.bucket_name}"
  deletion_window_in_days = var.kms_key_deletion_window_days
  enable_key_rotation     = true

  tags = local.common_tags
}

resource "aws_kms_alias" "this" {
  count         = var.kms_create_key ? 1 : 0
  name          = "alias/${local.bucket_name}"
  target_key_id = aws_kms_key.this[0].key_id
}

############################################################
# LOGGING BUCKET (optional create)
############################################################

resource "aws_s3_bucket" "logs" {
  count  = var.logging_enabled && var.logging_create_bucket ? 1 : 0
  bucket = local.logs_bucket_name
  force_destroy = var.force_destroy

  tags = merge(local.common_tags, { "Purpose" = "access-logs" })
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.logging_enabled && var.logging_create_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "logs" {
  count  = var.logging_enabled && var.logging_create_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  acl    = "log-delivery-write"
  depends_on = [aws_s3_bucket_ownership_controls.logs]
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = var.logging_enabled && var.logging_create_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

############################################################
# MAIN BUCKET
############################################################

resource "aws_s3_bucket" "this" {
  bucket        = local.bucket_name
  force_destroy = var.force_destroy

  object_lock_enabled = var.enable_object_lock

  tags = local.common_tags
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = var.block_public_access
  block_public_policy     = var.block_public_access
  ignore_public_acls      = var.block_public_access
  restrict_public_buckets = var.block_public_access
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.effective_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "this" {
  count         = var.logging_enabled ? 1 : 0
  bucket        = aws_s3_bucket.this.id
  target_bucket = var.logging_create_bucket ? aws_s3_bucket.logs[0].id : var.logging_bucket_name
  target_prefix = var.logging_prefix
}

# Lifecycle rules (динамически)
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = try(rule.value.id, "rule-${rule.key}")
      status = try(rule.value.enabled, true) ? "Enabled" : "Disabled"

      dynamic "expiration" {
        for_each = try([rule.value.expiration], [])
        content {
          days = try(expiration.value.days, null)
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = try([rule.value.noncurrent_version_expiration], [])
        content {
          noncurrent_days           = try(noncurrent_version_expiration.value.noncurrent_days, null)
          newer_noncurrent_versions = try(noncurrent_version_expiration.value.newer_noncurrent_versions, null)
        }
      }

      dynamic "transition" {
        for_each = try(rule.value.transitions, [])
        content {
          days          = try(transition.value.days, null)
          storage_class = transition.value.storage_class
        }
      }

      filter {
        prefix = try(rule.value.prefix, null)
      }
    }
  }
}

############################################################
# BUCKET POLICY — Security guardrails
############################################################

data "aws_iam_policy_document" "bucket_policy" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyUnEncryptedObjectUploads"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.this.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid     = "DenyWrongKMSKey"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.this.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [local.effective_kms_key_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

############################################################
# REPLICATION (optional)
############################################################

# Роль для репликации (если создаём)
data "aws_iam_policy_document" "replication_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "replication" {
  count              = var.replication_enabled && var.replication_create_role ? 1 : 0
  name               = "${local.bucket_name}-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "replication_policy" {
  count = var.replication_enabled && var.replication_create_role ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket"
    ]
    resources = [aws_s3_bucket.this.arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObjectVersion",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectLegalHold",
      "s3:GetObjectVersionTagging",
      "s3:GetObjectRetention"
    ]
    resources = ["${aws_s3_bucket.this.arn}/*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner"
    ]
    resources = ["${var.replication_destination_bucket_arn}/*"]
  }

  dynamic "statement" {
    for_each = var.replication_destination_kms_key_arn == null ? [] : [1]
    content {
      effect = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      resources = [var.replication_destination_kms_key_arn]
    }
  }

  dynamic "statement" {
    for_each = var.kms_create_key || var.kms_key_arn != null ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey"
      ]
      resources = [local.effective_kms_key_arn]
    }
  }
}

resource "aws_iam_policy" "replication" {
  count  = var.replication_enabled && var.replication_create_role ? 1 : 0
  name   = "${local.bucket_name}-replication"
  policy = data.aws_iam_policy_document.replication_policy[0].json
}

resource "aws_iam_role_policy_attachment" "replication" {
  count      = var.replication_enabled && var.replication_create_role ? 1 : 0
  role       = aws_iam_role.replication[0].name
  policy_arn = aws_iam_policy.replication[0].arn
}

resource "aws_s3_bucket_replication_configuration" "this" {
  count  = var.replication_enabled ? 1 : 0
  bucket = aws_s3_bucket.this.id
  role   = var.replication_create_role ? aws_iam_role.replication[0].arn : null

  rule {
    id     = "crr-all"
    status = "Enabled"

    filter {}
    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket        = var.replication_destination_bucket_arn
      storage_class = "STANDARD"

      dynamic "encryption_configuration" {
        for_each = var.replication_destination_kms_key_arn == null ? [] : [1]
        content {
          replica_kms_key_id = var.replication_destination_kms_key_arn
        }
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

############################################################
# APP IAM (optional) — least privilege for prefixes
############################################################

resource "aws_iam_role" "app" {
  count = var.app_iam_enable ? 1 : 0
  name  = coalesce(var.app_role_name, "${local.bucket_name}-app")

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { AWS = "*" }, # Подставьте конкретные аккаунты/роли в root модуле!
      Action   = "sts:AssumeRole",
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "set-in-root-module"
        }
      }
    }]
  })

  tags = local.common_tags
}

data "aws_iam_policy_document" "app" {
  count = var.app_iam_enable ? 1 : 0

  statement {
    sid    = "BucketLevel"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation"
    ]
    resources = [aws_s3_bucket.this.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = var.app_prefixes
    }
  }

  statement {
    sid     = "ObjectLevel"
    effect  = "Allow"
    actions = var.app_allowed_actions
    resources = [
      for p in var.app_prefixes : "${aws_s3_bucket.this.arn}/${p}*"
    ]
  }

  # Позволим использовать KMS-ключ
  dynamic "statement" {
    for_each = var.app_iam_enable ? [1] : []
    content {
      sid     = "KMSUsage"
      effect  = "Allow"
      actions = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
      resources = [local.effective_kms_key_arn]
    }
  }
}

resource "aws_iam_policy" "app" {
  count  = var.app_iam_enable ? 1 : 0
  name   = "${local.bucket_name}-app"
  policy = data.aws_iam_policy_document.app[0].json
}

resource "aws_iam_role_policy_attachment" "app" {
  count      = var.app_iam_enable ? 1 : 0
  role       = aws_iam_role.app[0].name
  policy_arn = aws_iam_policy.app[0].arn
}

############################################################
# OUTPUTS
############################################################

output "bucket_name" {
  value       = aws_s3_bucket.this.bucket
  description = "Имя бакета."
}

output "bucket_arn" {
  value       = aws_s3_bucket.this.arn
  description = "ARN бакета."
}

output "kms_key_arn" {
  value       = local.effective_kms_key_arn
  description = "Используемый KMS ключ (созданный или переданный)."
}

output "logs_bucket_name" {
  value       = var.logging_enabled ? (var.logging_create_bucket ? aws_s3_bucket.logs[0].bucket : var.logging_bucket_name) : null
  description = "Имя бакета логов (если включено)."
}

output "app_role_arn" {
  value       = var.app_iam_enable ? aws_iam_role.app[0].arn : null
  description = "ARN IAM роли приложения (если создана)."
}

output "replication_role_arn" {
  value       = var.replication_enabled && var.replication_create_role ? aws_iam_role.replication[0].arn : null
  description = "ARN роли репликации (если создана)."
}
