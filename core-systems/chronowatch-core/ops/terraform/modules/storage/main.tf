###############################################
# chronowatch-core/ops/terraform/modules/storage/main.tf
# Промышленный модуль S3-хранилища c KMS, версиями, логами и репликацией
###############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
  }
}

########################
# Входные переменные
########################

variable "project" {
  description = "Код проекта (для тегов и имени по умолчанию)"
  type        = string
}

variable "environment" {
  description = "Среда (prod|staging|dev|sandbox)"
  type        = string
}

variable "bucket_name" {
  description = "Имя бакета (глобально уникальное). Если null — будет вычислено детерминированно."
  type        = string
  default     = null
}

variable "force_destroy" {
  description = "Разрешить удаление бакета с объектами"
  type        = bool
  default     = false
}

variable "enable_versioning" {
  description = "Включить версионирование"
  type        = bool
  default     = true
}

variable "enable_object_lock" {
  description = "Включить Object Lock (только при создании бакета). Требует отдельного ресурса конфигурации."
  type        = bool
  default     = false
}

variable "object_lock_mode" {
  description = "Режим Object Lock по умолчанию (COMPLIANCE|GOVERNANCE)"
  type        = string
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.object_lock_mode)
    error_message = "object_lock_mode должен быть COMPLIANCE или GOVERNANCE."
  }
}

variable "object_lock_retention_days" {
  description = "Срок удержания по умолчанию для Object Lock (в днях)"
  type        = number
  default     = 0
}

variable "kms_alias" {
  description = "Псевдоним для KMS-ключа. Если null, будет сгенерирован."
  type        = string
  default     = null
}

variable "kms_deletion_window_in_days" {
  description = "Окно удаления KMS-ключа"
  type        = number
  default     = 30
}

variable "require_tls" {
  description = "Запретить не-TLS доступ"
  type        = bool
  default     = true
}

variable "require_kms_encryption" {
  description = "Запретить PutObject без SSE-KMS"
  type        = bool
  default     = true
}

variable "create_access_logs_bucket" {
  description = "Создавать отдельный бакет для журналов доступа"
  type        = bool
  default     = true
}

variable "access_logs_bucket_name" {
  description = "Имя бакета для логов. Если null и create_access_logs_bucket=true — будет вычислено."
  type        = string
  default     = null
}

variable "lifecycle_transition_days_standard_ia" {
  description = "Переход в STANDARD_IA через N дней"
  type        = number
  default     = 30
}

variable "lifecycle_transition_days_glacier_ir" {
  description = "Переход в GLACIER_IR через N дней"
  type        = number
  default     = 90
}

variable "noncurrent_version_expiration_days" {
  description = "Удаление старых версий через N дней"
  type        = number
  default     = 365
}

variable "abort_incomplete_multipart_days" {
  description = "Отмена незавершенных multipart загрузок через N дней"
  type        = number
  default     = 7
}

variable "replication_enabled" {
  description = "Включить репликацию версий в другой бакет/регион"
  type        = bool
  default     = false
}

variable "replication_destination_bucket_arn" {
  description = "ARN целевого бакета для репликации (должен существовать)"
  type        = string
  default     = null
}

variable "replication_destination_kms_key_arn" {
  description = "KMS-ключ для шифрования на стороне назначения"
  type        = string
  default     = null
}

variable "replication_priority" {
  description = "Приоритет правила репликации"
  type        = number
  default     = 10
}

variable "replication_filter_prefix" {
  description = "Префикс для репликации (если null — все объекты)"
  type        = string
  default     = null
}

variable "block_public_acls"    { type = bool, default = true }
variable "block_public_policy"  { type = bool, default = true }
variable "ignore_public_acls"   { type = bool, default = true }
variable "restrict_public_buckets" { type = bool, default = true }

variable "tags" {
  description = "Дополнительные теги"
  type        = map(string)
  default     = {}
}

########################
# Данные аккаунта/региона
########################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

########################
# Локальные переменные
########################

locals {
  common_tags = merge(
    {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "Terraform"
      Module      = "chronowatch-core/storage"
    },
    var.tags
  )

  bucket_base = lower(replace("${var.project}-${var.environment}-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}", "/[^a-z0-9-.]/", "-"))

  bucket_name_final = coalesce(var.bucket_name, local.bucket_base)

  logs_bucket_name_final = coalesce(var.access_logs_bucket_name, "${local.bucket_name_final}-logs")

  kms_alias_final = coalesce(var.kms_alias, "alias/${var.project}-${var.environment}-s3-kms")
}

########################
# KMS ключ для шифрования объектов
########################

data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid     = "EnableRootAccount"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  # Разрешаем сервису S3 использовать ключ (через права вызывающих ролей аккаунта)
  statement {
    sid    = "AllowS3UseOfTheKey"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "s3" {
  description             = "KMS key for S3 SSE for ${local.bucket_name_final}"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_key_policy.json
  tags                    = local.common_tags
}

resource "aws_kms_alias" "s3" {
  name          = local.kms_alias_final
  target_key_id = aws_kms_key.s3.key_id
}

########################
# Бакет для логов доступа (опционально)
########################

resource "aws_s3_bucket" "logs" {
  count         = var.create_access_logs_bucket ? 1 : 0
  bucket        = local.logs_bucket_name_final
  force_destroy = var.force_destroy
  tags          = merge(local.common_tags, { Purpose = "access-logs" })
}

# Ownership controls нужны, чтобы корректно применить ACL для log delivery
resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.create_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# ACL для приема логов (логирующий сервис пишет от своего имени)
resource "aws_s3_bucket_acl" "logs" {
  count  = var.create_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  acl    = "log-delivery-write"
  depends_on = [aws_s3_bucket_ownership_controls.logs]
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = var.create_access_logs_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

########################
# Основной S3 бакет
########################

resource "aws_s3_bucket" "this" {
  bucket        = local.bucket_name_final
  force_destroy = var.force_destroy
  # Включать object_lock_enabled можно только при создании
  object_lock_enabled = var.enable_object_lock
  tags                = local.common_tags
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = var.block_public_acls
  block_public_policy     = var.block_public_policy
  ignore_public_acls      = var.ignore_public_acls
  restrict_public_buckets = var.restrict_public_buckets
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# Логирование доступа в отдельный бакет (если создан)
resource "aws_s3_bucket_logging" "this" {
  count         = var.create_access_logs_bucket ? 1 : 0
  bucket        = aws_s3_bucket.this.id
  target_bucket = aws_s3_bucket.logs[0].id
  target_prefix = "s3-access/${local.bucket_name_final}/"
}

# Жизненные циклы: переходы и чистка
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "storage-tiering"
    status = "Enabled"

    transition {
      days          = var.lifecycle_transition_days_standard_ia
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.lifecycle_transition_days_glacier_ir
      storage_class = "GLACIER_IR"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_expiration_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = var.abort_incomplete_multipart_days
    }
  }
}

# Object Lock конфигурация (если включен на бакете)
resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.enable_object_lock ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode  = var.object_lock_mode
      days  = var.object_lock_retention_days
    }
  }
  depends_on = [aws_s3_bucket.this]
}

########################
# Политика бакета: TLS only и обязательное SSE-KMS
########################

data "aws_iam_policy_document" "bucket_policy" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals { type = "AWS"; identifiers = ["*"] }
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
    for_each = var.require_kms_encryption ? [1] : []
    content {
      sid     = "DenyUnEncryptedObjectUploads"
      effect  = "Deny"
      actions = ["s3:PutObject"]
      principals { type = "AWS"; identifiers = ["*"] }
      resources = ["${aws_s3_bucket.this.arn}/*"]

      # 1) Запрет, если заголовок SSE отсутствует
      condition {
        test     = "Null"
        variable = "s3:x-amz-server-side-encryption"
        values   = ["true"]
      }

      # 2) Запрет, если указан не aws:kms
      condition {
        test     = "StringNotEquals"
        variable = "s3:x-amz-server-side-encryption"
        values   = ["aws:kms"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

########################
# Репликация (опционально)
########################

data "aws_iam_policy_document" "replication_trust" {
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
  count              = var.replication_enabled ? 1 : 0
  name               = "${local.bucket_name_final}-replication-role"
  assume_role_policy = data.aws_iam_policy_document.replication_trust.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "replication_policy" {
  count = var.replication_enabled ? 1 : 0

  # Доступ к исходному бакету
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
      "s3:GetObjectVersionTagging"
    ]
    resources = ["${aws_s3_bucket.this.arn}/*"]
  }

  # Запись в целевой бакет
  statement {
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner"
    ]
    resources = ["${var.replication_destination_bucket_arn}/*"]
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.bucket_name_final}-replication-role"]
    }
  }

  # Доступ к KMS ключам (исходный -> decrypt, целевой -> encrypt)
  statement {
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.s3.arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = [var.replication_destination_kms_key_arn]
  }
}

resource "aws_iam_policy" "replication" {
  count  = var.replication_enabled ? 1 : 0
  name   = "${local.bucket_name_final}-replication-policy"
  policy = data.aws_iam_policy_document.replication_policy[0].json
  tags   = local.common_tags
}

resource "aws_iam_role_policy_attachment" "replication" {
  count      = var.replication_enabled ? 1 : 0
  role       = aws_iam_role.replication[0].name
  policy_arn = aws_iam_policy.replication[0].arn
}

resource "aws_s3_bucket_replication_configuration" "this" {
  count  = var.replication_enabled ? 1 : 0
  bucket = aws_s3_bucket.this.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id       = "replicate-all"
    status   = "Enabled"
    priority = var.replication_priority

    dynamic "filter" {
      for_each = var.replication_filter_prefix == null ? [] : [var.replication_filter_prefix]
      content {
        prefix = filter.value
      }
    }

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = var.replication_destination_bucket_arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = var.replication_destination_kms_key_arn
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.this,
    aws_iam_role_policy_attachment.replication
  ]
}

########################
# Выходные значения
########################

output "bucket_name" {
  description = "Имя основного бакета"
  value       = aws_s3_bucket.this.bucket
}

output "bucket_arn" {
  description = "ARN основного бакета"
  value       = aws_s3_bucket.this.arn
}

output "kms_key_arn" {
  description = "ARN KMS-ключа для SSE-KMS"
  value       = aws_kms_key.s3.arn
}

output "access_logs_bucket_name" {
  description = "Имя бакета для логов доступа (если создан)"
  value       = var.create_access_logs_bucket ? aws_s3_bucket.logs[0].bucket : null
}

output "replication_role_arn" {
  description = "ARN роли репликации (если включена)"
  value       = var.replication_enabled ? aws_iam_role.replication[0].arn : null
}
