terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

# ==============
# DATA & LOCALS
# ==============
data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

resource "random_id" "suffix" {
  byte_length = 4
  keepers = {
    env  = var.environment
    pref = var.name_prefix
  }
}

locals {
  base_name   = lower(replace("${var.name_prefix}-${var.environment}", "/[^a-z0-9-]/", "-"))
  bucket_name = lower(
    var.bucket_name != null
    ? var.bucket_name
    : (var.force_unique ? "${local.base_name}-${random_id.suffix.hex}" : local.base_name)
  )

  log_bucket_name = lower(
    var.create_log_bucket
    ? (var.log_bucket_name != null ? var.log_bucket_name : "${local.bucket_name}-logs")
    : coalesce(var.log_bucket_name, "")
  )

  common_tags = merge({
    "Environment"              = var.environment
    "ManagedBy"                = "Terraform"
    "Module"                   = "physical-integration-core/storage"
    "Owner"                    = var.owner
    "app.kubernetes.io/part-of" = "physical-integration-core"
  }, var.tags)
}

# =====================
# OPTIONAL KMS KEY
# =====================
# Создаём KMS-ключ при необходимости. Если не требуется — используем var.kms_key_arn или AES256.
resource "aws_kms_key" "this" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "KMS key for S3 bucket ${local.bucket_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Enable IAM User Permissions"
        Effect   = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.this.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid      = "Allow S3 Use of the Key"
        Effect   = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.this.account_id
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

locals {
  kms_key_arn_effective = var.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn
  sse_algorithm         = local.kms_key_arn_effective != null ? "aws:kms" : "AES256"
}

# =====================
# LOGGING BUCKET (OPT)
# =====================
resource "aws_s3_bucket" "logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = local.log_bucket_name

  force_destroy = var.log_bucket_force_destroy

  tags = merge(local.common_tags, { "Purpose" = "access-logs" })
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = var.create_log_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = var.create_log_bucket && var.log_expiration_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    expiration {
      days = var.log_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.log_expiration_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ===============
# MAIN S3 BUCKET
# ===============
resource "aws_s3_bucket" "this" {
  bucket        = local.bucket_name
  force_destroy = var.force_destroy

  # Object Lock must be enabled at creation if requested
  object_lock_enabled = var.enable_object_lock

  tags = local.common_tags
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = var.block_public_access
  block_public_policy     = var.block_public_access
  ignore_public_acls      = var.block_public_access
  restrict_public_buckets = var.block_public_access
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.sse_algorithm
      kms_master_key_id = local.sse_algorithm == "aws:kms" ? local.kms_key_arn_effective : null
    }
    bucket_key_enabled = local.sse_algorithm == "aws:kms" ? true : null
  }
}

resource "aws_s3_bucket_logging" "this" {
  count         = var.enable_access_logging && local.log_bucket_name != "" ? 1 : 0
  bucket        = aws_s3_bucket.this.id
  target_bucket = var.create_log_bucket ? aws_s3_bucket.logs[0].id : var.log_bucket_name
  target_prefix = "s3-access/"
}

# ===============
# LIFECYCLE RULES
# ===============
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "abort-incomplete"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = var.abort_incomplete_multipart_upload_days
    }
  }

  dynamic "rule" {
    for_each = var.lifecycle_current_object_days_to_expire != null ? [1] : []
    content {
      id     = "expire-current"
      status = "Enabled"
      expiration {
        days = var.lifecycle_current_object_days_to_expire
      }
    }
  }

  rule {
    id     = "transition-current"
    status = var.lifecycle_transition_current_enabled ? "Enabled" : "Disabled"

    transition {
      days          = var.current_to_ia_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.current_to_glacier_days
      storage_class = "GLACIER"
    }
  }

  rule {
    id     = "noncurrent-management"
    status = var.lifecycle_noncurrent_enabled ? "Enabled" : "Disabled"

    noncurrent_version_transition {
      noncurrent_days = var.noncurrent_to_ia_days
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = var.noncurrent_to_glacier_days
      storage_class   = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_expiration_days
    }
  }
}

# ===============
# OBJECT LOCK (OPT)
# ===============
resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.enable_object_lock ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode  = var.object_lock_mode
      days  = var.object_lock_days
    }
  }

  depends_on = [aws_s3_bucket.this]
}

# ======================
# SECURE BUCKET POLICIES
# ======================
data "aws_iam_policy_document" "secure_transport" {
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

  dynamic "statement" {
    for_each = var.deny_unencrypted_uploads ? [1] : []
    content {
      sid     = "DenyUnencryptedObjectUploads"
      effect  = "Deny"
      actions = ["s3:PutObject"]
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      resources = ["${aws_s3_bucket.this.arn}/*"]

      dynamic "condition" {
        for_each = local.sse_algorithm == "aws:kms" ? [1] : []
        content {
          test     = "StringNotEquals"
          variable = "s3:x-amz-server-side-encryption"
          values   = ["aws:kms"]
        }
      }

      dynamic "condition" {
        for_each = local.sse_algorithm != "aws:kms" ? [1] : []
        content {
          test     = "Null"
          variable = "s3:x-amz-server-side-encryption"
          values   = ["true"]
        }
      }
    }
  }

  dynamic "statement" {
    for_each = var.block_public_access ? [1] : []
    content {
      sid     = "DenyPublicAclsAndPolicies"
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
        test     = "StringEquals"
        variable = "s3:ResourceAccount"
        values   = [data.aws_caller_identity.this.account_id]
      }
      condition {
        test     = "Bool"
        variable = "aws:PrincipalIsAWSService"
        values   = ["false"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.secure_transport.json
}

# =================
# REPLICATION (OPT)
# =================
resource "aws_iam_role" "replication" {
  count = var.replication.enabled ? 1 : 0
  name  = "${local.bucket_name}-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "s3.amazonaws.com" }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "replication" {
  count = var.replication.enabled ? 1 : 0
  role  = aws_iam_role.replication[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowReplicationOnSource"
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.this.arn
      },
      {
        Sid    = "AllowObjectReplication"
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersion",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Resource = "${aws_s3_bucket.this.arn}/*"
      },
      {
        Sid    = "AllowWriteToDestination"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:ObjectOwnerOverrideToBucketOwner"
        ]
        Resource = [
          var.replication.destination_bucket_arn,
          "${var.replication.destination_bucket_arn}/*"
        ]
      },
      {
        Sid    = "AllowUseDestinationKms"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = coalesce(var.replication.destination_kms_key_arn, local.kms_key_arn_effective, "*")
      }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "this" {
  count  = var.replication.enabled ? 1 : 0
  bucket = aws_s3_bucket.this.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = var.replication.destination_bucket_arn
      storage_class = var.replication.storage_class
      dynamic "encryption_configuration" {
        for_each = var.replication.destination_kms_key_arn != null ? [1] : []
        content {
          replica_kms_key_id = var.replication.destination_kms_key_arn
        }
      }
      account = var.replication.destination_account_id
    }

    delete_marker_replication {
      status = var.replication.replicate_delete_markers ? "Enabled" : "Disabled"
    }

    filter {} # replicate all objects
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

# =========
# VARIABLES
# =========
variable "environment" {
  description = "Имя окружения (prod, staging, dev, etc.)"
  type        = string
  default     = "prod"
}

variable "name_prefix" {
  description = "Префикс имени бакета, например 'pic'"
  type        = string
  default     = "pic"
}

variable "bucket_name" {
  description = "Явно заданное имя бакета (если null — сгенерируется)."
  type        = string
  default     = null
}

variable "force_unique" {
  description = "Добавлять ли суффикс для уникальности имени."
  type        = bool
  default     = true
}

variable "owner" {
  description = "Ответственный владелец."
  type        = string
  default     = "platform-team"
}

variable "tags" {
  description = "Дополнительные теги."
  type        = map(string)
  default     = {}
}

variable "force_destroy" {
  description = "Удалять ли бакет с объектами без ручной очистки."
  type        = bool
  default     = false
}

variable "versioning_enabled" {
  description = "Включить версионирование."
  type        = bool
  default     = true
}

variable "create_kms_key" {
  description = "Создавать ли новый KMS-ключ для шифрования."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Готовый KMS Key ARN (если create_kms_key=false)."
  type        = string
  default     = null
}

variable "block_public_access" {
  description = "Полностью блокировать публичный доступ."
  type        = bool
  default     = true
}

variable "deny_unencrypted_uploads" {
  description = "Запретить незашифрованные загрузки (bucket policy)."
  type        = bool
  default     = true
}

variable "enable_access_logging" {
  description = "Включить логирование доступа."
  type        = bool
  default     = true
}

variable "create_log_bucket" {
  description = "Создать лог‑бакет автоматически."
  type        = bool
  default     = true
}

variable "log_bucket_name" {
  description = "Имя уже существующего лог‑бакета (если create_log_bucket=false)."
  type        = string
  default     = null
}

variable "log_bucket_force_destroy" {
  description = "Разрешить принудительное удаление лог‑бакета."
  type        = bool
  default     = false
}

variable "log_expiration_days" {
  description = "Срок хранения логов в днях."
  type        = number
  default     = 365
}

variable "abort_incomplete_multipart_upload_days" {
  description = "Через сколько дней прерывать незавершённые multipart‑загрузки."
  type        = number
  default     = 7
}

variable "lifecycle_current_object_days_to_expire" {
  description = "Удаление текущих версий через N дней (null — отключено)."
  type        = number
  default     = null
}

variable "lifecycle_transition_current_enabled" {
  description = "Включить переход текущих объектов в холодные классы."
  type        = bool
  default     = true
}

variable "current_to_ia_days" {
  description = "Переход текущих объектов в STANDARD_IA через N дней."
  type        = number
  default     = 30
}

variable "current_to_glacier_days" {
  description = "Переход текущих объектов в GLACIER через N дней."
  type        = number
  default     = 90
}

variable "lifecycle_noncurrent_enabled" {
  description = "Управление неактуальными (noncurrent) версиями."
  type        = bool
  default     = true
}

variable "noncurrent_to_ia_days" {
  description = "Переход неактуальных версий в STANDARD_IA через N дней."
  type        = number
  default     = 30
}

variable "noncurrent_to_glacier_days" {
  description = "Переход неактуальных версий в GLACIER через N дней."
  type        = number
  default     = 90
}

variable "noncurrent_expiration_days" {
  description = "Удаление неактуальных версий через N дней."
  type        = number
  default     = 365
}

variable "enable_object_lock" {
  description = "Включить S3 Object Lock (только при создании бакета!)."
  type        = bool
  default     = false
}

variable "object_lock_mode" {
  description = "Режим блокировки (COMPLIANCE или GOVERNANCE)."
  type        = string
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "object_lock_days" {
  description = "Дни удержания по умолчанию для Object Lock."
  type        = number
  default     = 30
}

variable "replication" {
  description = "Параметры репликации."
  type = object({
    enabled                     = bool
    destination_bucket_arn      = optional(string)
    destination_kms_key_arn     = optional(string)
    destination_account_id      = optional(string)
    storage_class               = optional(string, "STANDARD_IA")
    replicate_delete_markers    = optional(bool, true)
  })
  default = {
    enabled = false
  }
}

# =======
# OUTPUTS
# =======
output "bucket_name" {
  value       = aws_s3_bucket.this.bucket
  description = "Имя основного S3‑бакета."
}

output "bucket_arn" {
  value       = aws_s3_bucket.this.arn
  description = "ARN основного S3‑бакета."
}

output "bucket_domain_name" {
  value       = aws_s3_bucket.this.bucket_domain_name
  description = "Домашнее имя (endpoint) бакета."
}

output "kms_key_arn" {
  value       = local.kms_key_arn_effective
  description = "Используемый KMS‑ключ (если применимо)."
}

output "log_bucket_name" {
  value       = local.log_bucket_name
  description = "Имя бакета для логов (если включено)."
}
