#############################################
# Module: ops/terraform/modules/bootstrap/remote-state/main.tf
# Purpose: Industrial-grade AWS S3 + DynamoDB bootstrap for Terraform remote state
# Terraform >= 1.6, AWS Provider >= 5.x
#
# Key references (официальная документация, проверяемые источники):
# - Terraform S3 backend: https://developer.hashicorp.com/terraform/language/settings/backends/s3
# - AWS S3 bucket (v5): https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket
# - AWS DynamoDB table: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table
# - S3 Bucket Policy examples: https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html
# - S3 Block Public Access: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
# - S3 Default Encryption (SSE-KMS): https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
# - DynamoDB for state locking (Terraform): https://developer.hashicorp.com/terraform/language/settings/backends/s3#dynamodb_table
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

#############################################
# Provider
#############################################

provider "aws" {
  region = var.aws_region
}

#############################################
# Inputs
#############################################

variable "name_prefix" {
  description = "Префикс для ресурсов (напр. org-env). Используется в именах S3/DynamoDB/KMS."
  type        = string
}

variable "aws_region" {
  description = "Регион AWS для ресурсов remote state (совместим с backend конфигурацией)."
  type        = string
}

variable "s3_bucket_name" {
  description = "Полное имя S3 бакета для remote state (если пусто, сгенерируется из name_prefix). Должно быть глобально уникальным."
  type        = string
  default     = ""
}

variable "enable_kms" {
  description = "Включить отдельный AWS KMS ключ для шифрования S3 (SSE-KMS). Если false — используется AES256 (SSE-S3)."
  type        = bool
  default     = true
}

variable "kms_deletion_window_in_days" {
  description = "Окно удаления KMS-ключа в днях (7–30)."
  type        = number
  default     = 30
}

variable "enable_bucket_object_ownership_bucket_owner_enforced" {
  description = "Включить BucketOwnerEnforced (рекомендуется для modern ACL-free)."
  type        = bool
  default     = true
}

variable "dynamodb_table_name" {
  description = "Имя DynamoDB-таблицы для блокировок Terraform (если пусто, сгенерируется)."
  type        = string
  default     = ""
}

variable "enable_access_logs" {
  description = "Включить логирование доступа S3 в отдельный лог-бакет."
  type        = bool
  default     = true
}

variable "access_logs_bucket_name" {
  description = "Имя S3 бакета для логов. Если пусто и enable_access_logs=true — создается автоматически."
  type        = string
  default     = ""
}

variable "versioning_enabled" {
  description = "Включить версионирование S3 бакета (крайне рекомендуется для remote state)."
  type        = bool
  default     = true
}

variable "lifecycle_noncurrent_versions_expiration_days" {
  description = "Срок хранения неактуальных версий (Noncurrent) в днях. 0 — выключено."
  type        = number
  default     = 365
}

variable "lifecycle_abort_mpu_days" {
  description = "Отмена незавершенных multipart uploads через N дней."
  type        = number
  default     = 7
}

variable "force_destroy" {
  description = "Разрешить удаление бакета с объектами (осторожно в проде)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Общие теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

#############################################
# Locals
#############################################

locals {
  normalized_prefix = lower(replace(var.name_prefix, "/[^a-zA-Z0-9-]/", "-"))

  bucket_name = var.s3_bucket_name != "" ? var.s3_bucket_name : "${local.normalized_prefix}-tf-state"
  logs_bucket = var.enable_access_logs ? (var.access_logs_bucket_name != "" ? var.access_logs_bucket_name : "${local.normalized_prefix}-tf-logs") : null

  ddb_table = var.dynamodb_table_name != "" ? var.dynamodb_table_name : "${local.normalized_prefix}-tf-locks"

  common_tags = merge(
    {
      "ManagedBy"   = "Terraform"
      "Component"   = "remote-state"
      "Environment" = local.normalized_prefix
    },
    var.tags
  )
}

#############################################
# (Optional) Access Logs Bucket
# Best practice: хранить логи отдельно от основного state-бакета
# Docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_logging
#############################################

resource "aws_s3_bucket" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = local.logs_bucket

  force_destroy = var.force_destroy
  tags          = merge(local.common_tags, { "Name" = local.logs_bucket, "Purpose" = "s3-access-logs" })
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

#############################################
# KMS (optional) для шифрования S3 (SSE-KMS)
# Docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key
#############################################

resource "aws_kms_key" "s3" {
  count                   = var.enable_kms ? 1 : 0
  description             = "KMS key for Terraform remote state bucket ${local.bucket_name}"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = true

  tags = merge(local.common_tags, { "Name" = "${local.normalized_prefix}-tf-kms" })
}

resource "aws_kms_alias" "s3" {
  count         = var.enable_kms ? 1 : 0
  name          = "alias/${local.normalized_prefix}-tf-kms"
  target_key_id = aws_kms_key.s3[0].key_id
}

#############################################
# S3 Bucket for remote state
#############################################

resource "aws_s3_bucket" "state" {
  bucket        = local.bucket_name
  force_destroy = var.force_destroy

  tags = merge(local.common_tags, { "Name" = local.bucket_name, "Purpose" = "terraform-remote-state" })
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  # Public Access Block — best practice
  # Docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  # BucketOwnerEnforced — modern, без ACL (рекомендуется)
  # Docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls
  rule {
    object_ownership = var.enable_bucket_object_ownership_bucket_owner_enforced ? "BucketOwnerEnforced" : "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      # SSE-KMS или SSE-S3 (AES256)
      sse_algorithm     = var.enable_kms ? "aws:kms" : "AES256"
      kms_master_key_id = var.enable_kms ? aws_kms_key.s3[0].arn : null
    }
    bucket_key_enabled = var.enable_kms
  }
}

resource "aws_s3_bucket_logging" "state" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.state.id

  # Логи в отдельный бакет
  target_bucket = aws_s3_bucket.logs[0].id
  target_prefix = "s3/${local.bucket_name}/"
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  # Abort incomplete MPUs — экономия
  rule {
    id     = "abort-incomplete-mpu"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = var.lifecycle_abort_mpu_days
    }
  }

  # Управление неактуальными версиями (Noncurrent)
  dynamic "rule" {
    for_each = var.lifecycle_noncurrent_versions_expiration_days > 0 ? [1] : []
    content {
      id     = "noncurrent-versions-expiration"
      status = "Enabled"

      noncurrent_version_expiration {
        noncurrent_days = var.lifecycle_noncurrent_versions_expiration_days
      }
    }
  }
}

#############################################
# Strict Bucket Policy (TLS-only, deny unencrypted, enforce SSE)
# Docs:
# - TLS-only: https://docs.aws.amazon.com/AmazonS3/latest/userguide/secure-transport.html
# - Deny SSE off: https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html
#############################################

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*"
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
    resources = ["${aws_s3_bucket.state.arn}/*"]

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }

  # Если используется KMS — требуем aws:kms
  dynamic "statement" {
    for_each = var.enable_kms ? [1] : []
    content {
      sid     = "RequireKmsEncryption"
      effect  = "Deny"
      actions = ["s3:PutObject"]
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      resources = ["${aws_s3_bucket.state.arn}/*"]

      condition {
        test     = "StringNotEquals"
        variable = "s3:x-amz-server-side-encryption"
        values   = ["aws:kms"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_bucket.json
}

#############################################
# DynamoDB Table for Terraform state locking
# Docs:
# - Terraform S3 backend lock table: https://developer.hashicorp.com/terraform/language/settings/backends/s3#dynamodb_table
# - DynamoDB resource: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table
#############################################

resource "aws_dynamodb_table" "lock" {
  name         = local.ddb_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = merge(local.common_tags, { "Name" = local.ddb_table, "Purpose" = "terraform-state-lock" })
}

#############################################
# Useful Data
#############################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

#############################################
# Outputs
#############################################

output "aws_region" {
  description = "Регион AWS для backend."
  value       = var.aws_region
}

output "state_bucket_name" {
  description = "Имя S3 бакета для remote state."
  value       = aws_s3_bucket.state.bucket
}

output "state_bucket_arn" {
  description = "ARN S3 бакета для remote state."
  value       = aws_s3_bucket.state.arn
}

output "logs_bucket_name" {
  description = "Имя S3 бакета для логов (если включено)."
  value       = var.enable_access_logs ? aws_s3_bucket.logs[0].bucket : null
}

output "dynamodb_table_name" {
  description = "Имя DynamoDB-таблицы для блокировок."
  value       = aws_dynamodb_table.lock.name
}

output "kms_key_arn" {
  description = "ARN KMS-ключа для шифрования (если включено)."
  value       = var.enable_kms ? aws_kms_key.s3[0].arn : null
}

output "backend_config_example" {
  description = "Готовый шаблон backend s3 для корневого модуля (скопируйте в terraform { backend \"s3\" { ... } })."
  value = tomap({
    bucket         = aws_s3_bucket.state.bucket
    key            = "global/terraform.tfstate"
    region         = var.aws_region
    dynamodb_table = aws_dynamodb_table.lock.name
    encrypt        = true
    kms_key_id     = var.enable_kms ? aws_kms_key.s3[0].arn : ""
  })
}
