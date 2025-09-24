#############################################
# policy-core/ops/terraform/modules/storage/main.tf
# Prod-grade S3 bucket module (single-file variant)
#############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
  }
}

#####################
# INPUT VARIABLES
#####################

variable "bucket_name" {
  description = "Имя S3 бакета (уникально по глобусу)."
  type        = string

  validation {
    condition     = length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63
    error_message = "bucket_name должен быть длиной 3..63."
  }

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name должен соответствовать ^[a-z0-9][a-z0-9.-]+[a-z0-9]$."
  }
}

variable "tags" {
  description = "Общие теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "enable_versioning" {
  description = "Включить версионирование бакета."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Позволить удалять бакет с объектами (опасно в проде)."
  type        = bool
  default     = false
}

variable "enable_sse" {
  description = "Включить шифрование объектов на стороне сервера."
  type        = bool
  default     = true
}

variable "use_kms" {
  description = "Использовать KMS для SSE (aws:kms). Если false — AES256."
  type        = bool
  default     = true
}

variable "create_kms_key" {
  description = "Создать KMS ключ для бакета (если false — используем kms_key_id)."
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "Идентификатор существующего KMS ключа (ARN/ID). Используется если create_kms_key=false."
  type        = string
  default     = ""
}

variable "enable_logging" {
  description = "Включить server access logging (требует совместимости с ACL на целевом бакете)."
  type        = bool
  default     = false
}

variable "logging_target_bucket" {
  description = "Имя существующего бакета для логов. Обязательно при enable_logging=true."
  type        = string
  default     = ""
}

variable "logging_target_prefix" {
  description = "Префикс путей для логов."
  type        = string
  default     = "s3-access/"
}

variable "lifecycle_rules" {
  description = <<EOT
Список lifecycle-правил. Пример:
[
  {
    id                                     = "std"
    enabled                                = true
    abort_incomplete_multipart_upload_days = 7
    noncurrent_newer_versions              = 3
    noncurrent_transition = [
      { storage_class = "STANDARD_IA", days = 30 },
      { storage_class = "GLACIER_IR",  days = 60 }
    ]
    expiration_days = 365
  }
]
EOT
  type = list(object({
    id                                     = string
    enabled                                = bool
    abort_incomplete_multipart_upload_days = optional(number)
    noncurrent_newer_versions              = optional(number)
    noncurrent_transition                  = optional(list(object({
      storage_class = string
      days          = number
    })))
    expiration_days = optional(number)
  }))
  default = []
}

variable "cors_rules" {
  description = <<EOT
Опциональные CORS-правила. Пример:
[
  {
    allowed_methods = ["GET"]
    allowed_origins = ["https://example.com"]
    allowed_headers = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 300
  }
]
EOT
  type = list(object({
    allowed_methods = list(string)
    allowed_origins = list(string)
    allowed_headers = optional(list(string))
    expose_headers  = optional(list(string))
    max_age_seconds = optional(number)
  }))
  default = []
}

variable "enable_replication" {
  description = "Включить межбакетную репликацию (CRR/SRR). Требует versioning."
  type        = bool
  default     = false
}

variable "destination_bucket_arn" {
  description = "ARN целевого бакета для репликации. Обязательно при enable_replication=true."
  type        = string
  default     = ""
}

variable "destination_account_id" {
  description = "ID аккаунта назначения (опционально, для явных условий KMS/репликации)."
  type        = string
  default     = ""
}

variable "replication_kms_key_arn" {
  description = "KMS ключ назначения для шифрования реплицируемых объектов (если требуется)."
  type        = string
  default     = ""
}

variable "require_tls" {
  description = "Запретить доступ к бакету по незащищенному протоколу (aws:SecureTransport)."
  type        = bool
  default     = true
}

variable "require_sse_bucket_encryption" {
  description = "Запретить загрузки без шифрования на стороне сервера."
  type        = bool
  default     = true
}

variable "additional_bucket_policy_json" {
  description = "Дополнительные JSON-политики для объединения (строка JSON)."
  type        = string
  default     = ""
}

#####################
# LOCALS
#####################

locals {
  # Объединяем теги
  tags = merge(
    {
      "Project"     = "policy-core"
      "Terraform"   = "true"
      "Component"   = "storage"
      "ManagedBy"   = "terraform"
    },
    var.tags
  )

  # Для совместимости с access logging: включаем ObjectWriter (ACL используется сервисом логирования).
  object_ownership = var.enable_logging ? "ObjectWriter" : "BucketOwnerEnforced"

  use_kms_effective = var.enable_sse && var.use_kms

  kms_key_arn_effective = var.create_kms_key ? (
    try(aws_kms_key.this[0].arn, "")
  ) : var.kms_key_id
}

#####################
# DATA SOURCES
#####################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

#####################
# KMS (опционально)
#####################

resource "aws_kms_key" "this" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "KMS key for S3 bucket ${var.bucket_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = null
  tags                    = local.tags
}

#####################
# S3 BUCKET
#####################

resource "aws_s3_bucket" "this" {
  bucket              = var.bucket_name
  force_destroy       = var.force_destroy
  object_lock_enabled = false # Можно параметризовать при необходимости.

  tags = local.tags

  lifecycle {
    prevent_destroy = false
  }
}

# Object ownership (BucketOwnerEnforced по умолчанию; ObjectWriter при логировании)
resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = local.object_ownership
  }
}

# Полный Block Public Access
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Версионирование
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

# Шифрование на стороне сервера
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count  = var.enable_sse ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.use_kms_effective ? "aws:kms" : "AES256"
      kms_master_key_id = local.use_kms_effective ? local.kms_key_arn_effective : null
    }
    bucket_key_enabled = local.use_kms_effective
  }
}

# Логирование доступа (опционально)
resource "aws_s3_bucket_logging" "this" {
  count  = var.enable_logging ? 1 : 0
  bucket = aws_s3_bucket.this.id

  target_bucket = var.logging_target_bucket
  target_prefix = trimsuffix(var.logging_target_prefix, "/") != "" ? "${trimsuffix(var.logging_target_prefix, "/")}/" : ""
}

# CORS (опционально)
resource "aws_s3_bucket_cors_configuration" "this" {
  count  = length(var.cors_rules) > 0 ? 1 : 0
  bucket = aws_s3_bucket.this.id

  dynamic "cors_rule" {
    for_each = var.cors_rules
    content {
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      allowed_headers = lookup(cors_rule.value, "allowed_headers", null)
      expose_headers  = lookup(cors_rule.value, "expose_headers", null)
      max_age_seconds = lookup(cors_rule.value, "max_age_seconds", null)
    }
  }
}

# Lifecycle правила (опционально)
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = length(var.lifecycle_rules) > 0 ? 1 : 0
  bucket = aws_s3_bucket.this.id

  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = rule.value.id
      status = rule.value.enabled ? "Enabled" : "Disabled"

      dynamic "abort_incomplete_multipart_upload" {
        for_each = rule.value.abort_incomplete_multipart_upload_days != null ? [1] : []
        content {
          days_after_initiation = rule.value.abort_incomplete_multipart_upload_days
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = rule.value.noncurrent_newer_versions != null || rule.value.expiration_days != null ? [1] : []
        content {
          newer_noncurrent_versions = rule.value.noncurrent_newer_versions
          noncurrent_days           = null
        }
      }

      dynamic "noncurrent_version_transition" {
        for_each = coalesce(rule.value.noncurrent_transition, [])
        content {
          storage_class   = noncurrent_version_transition.value.storage_class
          noncurrent_days = noncurrent_version_transition.value.days
        }
      }

      dynamic "expiration" {
        for_each = rule.value.expiration_days != null ? [1] : []
        content {
          days = rule.value.expiration_days
        }
      }
    }
  }
}

#####################
# BUCKET POLICY (TLS/SSE + user-extended)
#####################

data "aws_iam_policy_document" "base" {
  statement {
    sid     = "DenyNonTLSTraffic"
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

  dynamic "statement" {
    for_each = var.require_sse_bucket_encryption ? [1] : []
    content {
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
        values   = local.use_kms_effective ? ["aws:kms"] : ["AES256"]
      }
    }
  }
}

data "aws_iam_policy_document" "merged" {
  source_json = jsonencode(data.aws_iam_policy_document.base.json)

  dynamic "statement" {
    for_each = try(length(var.additional_bucket_policy_json) > 0, false) ? jsondecode(var.additional_bucket_policy_json).Statement : []
    content {
      sid     = try(statement.value.Sid, null)
      effect  = statement.value.Effect
      actions = statement.value.Action
      resources = statement.value.Resource
      dynamic "principals" {
        for_each = try([1], [])
        content {
          type        = try(statement.value.Principal.Type, "*")
          identifiers = try(statement.value.Principal.Identifiers, ["*"])
        }
      }
      dynamic "condition" {
        for_each = try(statement.value.Condition, null) != null ? [statement.value.Condition] : []
        content {
          test     = keys(condition.value)[0]
          variable = keys(values(condition.value)[0])[0]
          values   = values(values(condition.value)[0])[0]
        }
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = var.require_tls ? data.aws_iam_policy_document.merged.json : (
    try(length(var.additional_bucket_policy_json) > 0, false) ? var.additional_bucket_policy_json : data.aws_iam_policy_document.base.json
  )
}

#####################
# REPLICATION (опционально)
#####################

# IAM роль для репликации
resource "aws_iam_role" "replication" {
  count              = var.enable_replication ? 1 : 0
  name               = "s3-replication-${var.bucket_name}"
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

# Политика репликации (минимально необходимая)
data "aws_iam_policy_document" "replication" {
  count = var.enable_replication ? 1 : 0

  statement {
    sid    = "AllowReplicationRead"
    effect = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket"
    ]
    resources = [aws_s3_bucket.this.arn]
  }

  statement {
    sid    = "AllowReplicationGet"
    effect = "Allow"
    actions = [
      "s3:GetObjectVersion",
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging"
    ]
    resources = ["${aws_s3_bucket.this.arn}/*"]
  }

  statement {
    sid    = "AllowReplicationWrite"
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner",
      "s3:PutBucketVersioning",
      "s3:PutBucketReplication"
    ]
    resources = [var.destination_bucket_arn, "${var.destination_bucket_arn}/*"]
  }

  dynamic "statement" {
    for_each = length(var.replication_kms_key_arn) > 0 ? [1] : []
    content {
      sid    = "AllowKMSForReplication"
      effect = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      resources = [var.replication_kms_key_arn, local.kms_key_arn_effective]
    }
  }
}

resource "aws_iam_role_policy" "replication" {
  count  = var.enable_replication ? 1 : 0
  name   = "s3-replication-policy-${var.bucket_name}"
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication[0].json
}

# Конфигурация репликации
resource "aws_s3_bucket_replication_configuration" "this" {
  count = var.enable_replication ? 1 : 0

  depends_on = [
    aws_s3_bucket_versioning.this,
    aws_iam_role_policy.replication
  ]

  role   = aws_iam_role.replication[0].arn
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "replicate-all"
    status = "Enabled"

    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket        = var.destination_bucket_arn
      storage_class = "STANDARD"

      dynamic "encryption_configuration" {
        for_each = length(var.replication_kms_key_arn) > 0 ? [1] : []
        content {
          replica_kms_key_id = var.replication_kms_key_arn
        }
      }

      dynamic "access_control_translation" {
        for_each = var.destination_account_id != "" ? [1] : []
        content {
          owner = "Destination"
        }
      }

      account = var.destination_account_id != "" ? var.destination_account_id : null
    }

    filter {
      prefix = "" # реплицируем всё
    }
  }
}

#####################
# OUTPUTS
#####################

output "bucket_id" {
  description = "ID бакета."
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "ARN бакета."
  value       = aws_s3_bucket.this.arn
}

output "bucket_domain_name" {
  description = "DNS имя бакета."
  value       = aws_s3_bucket.this.bucket_domain_name
}

output "bucket_regional_domain_name" {
  description = "Региональное DNS имя бакета."
  value       = aws_s3_bucket.this.bucket_regional_domain_name
}

output "kms_key_arn" {
  description = "ARN KMS ключа, если использовался."
  value       = local.use_kms_effective ? local.kms_key_arn_effective : null
}

output "replication_role_arn" {
  description = "ARN IAM-роли для репликации, если включена."
  value       = var.enable_replication ? aws_iam_role.replication[0].arn : null
}
