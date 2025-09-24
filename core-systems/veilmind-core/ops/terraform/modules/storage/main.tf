terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

########################################
# Inputs
########################################
variable "name" {
  description = "Имя S3 бакета (уникально в глобальном пространстве)."
  type        = string
}

variable "tags" {
  description = "Дополнительные теги."
  type        = map(string)
  default     = {}
}

variable "force_destroy" {
  description = "Разрешать удаление бакета с объектами (только для не-prod)."
  type        = bool
  default     = false
}

variable "enable_versioning" {
  description = "Включить версионирование бакета."
  type        = bool
  default     = true
}

variable "enable_object_lock" {
  description = "Включить Object Lock (WORM). Требует создания нового бакета, не меняется post-factum."
  type        = bool
  default     = false
}

variable "object_lock_default_mode" {
  description = "Режим Object Lock: COMPLIANCE или GOVERNANCE."
  type        = string
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.object_lock_default_mode)
    error_message = "object_lock_default_mode должен быть COMPLIANCE или GOVERNANCE."
  }
}

variable "object_lock_default_days" {
  description = "Срок удержания (дни) по умолчанию для Object Lock."
  type        = number
  default     = 30
}

variable "create_kms_key" {
  description = "Создавать выделенный KMS CMK для шифрования. Если false, используется aws/s3."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Существующий KMS‑ключ для SSE (если create_kms_key=false)."
  type        = string
  default     = ""
}

variable "logging" {
  description = "Настройки логирования доступа в отдельный бакет (S3 Server Access Logs)."
  type = object({
    enabled             = bool
    create_logs_bucket  = bool
    logs_bucket_name    = optional(string)
    prefix              = optional(string, "s3-access/")
  })
  default = {
    enabled            = true
    create_logs_bucket = true
    logs_bucket_name   = null
    prefix             = "s3-access/"
  }
}

variable "lifecycle_rules" {
  description = "Массив правил lifecycle."
  type = list(object({
    id                                     = string
    enabled                                = bool
    abort_incomplete_multipart_upload_days = optional(number, 7)
    noncurrent_version_expiration_days     = optional(number)
    noncurrent_version_transitions = optional(list(object({
      days          = number
      storage_class = string # e.g. STANDARD_IA, GLACIER, GLACIER_IR, DEEP_ARCHIVE
    })), [])
    transitions = optional(list(object({
      days          = number
      storage_class = string
    })), [])
    expiration_days = optional(number)
    prefix          = optional(string)
    tags            = optional(map(string))
  }))
  default = [
    {
      id                                     = "default-tiering"
      enabled                                = true
      abort_incomplete_multipart_upload_days = 7
      transitions = [
        { days = 30, storage_class = "STANDARD_IA" },
        { days = 60, storage_class = "GLACIER_IR" }
      ]
      noncurrent_version_transitions = [
        { days = 30, storage_class = "GLACIER_IR" }
      ]
      noncurrent_version_expiration_days = 365
      expiration_days                    = null
    }
  ]
}

variable "replication" {
  description = "Репликация версий в другой бакет/регион. Требует включенного versioning."
  type = object({
    enabled                  = bool
    destination_bucket_arn   = optional(string)
    destination_storage_class = optional(string, "STANDARD")
    destination_kms_key_arn  = optional(string, null)
    filter_prefix            = optional(string, "")
    delete_marker_replication = optional(bool, true)
    replica_kms_encryption   = optional(bool, true)
  })
  default = {
    enabled                   = false
    destination_bucket_arn    = null
    destination_storage_class = "STANDARD"
    destination_kms_key_arn   = null
    filter_prefix             = ""
    delete_marker_replication = true
    replica_kms_encryption    = true
  }
}

variable "create_app_iam" {
  description = "Создавать IAM роли/политики для приложения (RW/RO)."
  type        = bool
  default     = true
}

variable "app_role_name_prefix" {
  description = "Префикс для IAM ролей приложения."
  type        = string
  default     = "veilmind-core"
}

variable "principals_app" {
  description = "Список ARNs сущностей (roles/users) которым можно присоединить политики RW/RO вместо AssumeRole."
  type        = list(string)
  default     = []
}

########################################
# Locals
########################################
locals {
  common_tags = merge(
    {
      "Project"                = "VeilMind"
      "Component"              = "Storage"
      "ManagedBy"              = "Terraform"
      "SecurityTier"           = "Restricted"
      "DataClassification"     = "Confidential"
    },
    var.tags
  )

  use_cmk   = var.create_kms_key || (var.kms_key_arn != "")
  kms_arn   = var.create_kms_key ? aws_kms_key.this[0].arn : (var.kms_key_arn != "" ? var.kms_key_arn : null)
  bucket_id = var.name
}

########################################
# KMS (optional dedicated CMK)
########################################
resource "aws_kms_key" "this" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "CMK for S3 bucket ${var.name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EnableRoot"
        Effect   = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowS3UseOfTheKey"
        Effect = "Allow"
        Principal = {
          Service = "s3.${data.aws_partition.current.dns_suffix}"
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "this" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/s3/${var.name}"
  target_key_id = aws_kms_key.this[0].key_id
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

########################################
# Access logs bucket (optional)
########################################
resource "aws_s3_bucket" "logs" {
  count = var.logging.enabled && var.logging.create_logs_bucket ? 1 : 0
  bucket = coalesce(var.logging.logs_bucket_name, "${var.name}-logs")
  tags   = merge(local.common_tags, { "Name" = "${var.name}-logs" })
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count = var.logging.enabled && var.logging.create_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.logging.enabled && var.logging.create_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.logging.enabled && var.logging.create_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.use_cmk ? "aws:kms" : "AES256"
      kms_master_key_id = local.use_cmk ? local.kms_arn : null
    }
    bucket_key_enabled = true
  }
}

########################################
# Primary bucket (hardened)
########################################
resource "aws_s3_bucket" "this" {
  bucket              = local.bucket_id
  force_destroy       = var.force_destroy
  object_lock_enabled = var.enable_object_lock
  tags                = merge(local.common_tags, { "Name" = var.name })
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
  depends_on = [aws_s3_bucket_ownership_controls.this]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.use_cmk ? "aws:kms" : "AES256"
      kms_master_key_id = local.use_cmk ? local.kms_arn : null
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "this" {
  count  = var.logging.enabled ? 1 : 0
  bucket = aws_s3_bucket.this.id
  target_bucket = var.logging.create_logs_bucket
    ? aws_s3_bucket.logs[0].id
    : var.logging.logs_bucket_name
  target_prefix = var.logging.prefix
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = rule.value.id
      status = rule.value.enabled ? "Enabled" : "Disabled"

      abort_incomplete_multipart_upload {
        days_after_initiation = coalesce(rule.value.abort_incomplete_multipart_upload_days, 7)
      }

      dynamic "noncurrent_version_expiration" {
        for_each = rule.value.noncurrent_version_expiration_days == null ? [] : [1]
        content {
          noncurrent_days = rule.value.noncurrent_version_expiration_days
        }
      }

      dynamic "noncurrent_version_transition" {
        for_each = coalesce(rule.value.noncurrent_version_transitions, [])
        content {
          noncurrent_days = noncurrent_version_transition.value.days
          storage_class   = noncurrent_version_transition.value.storage_class
        }
      }

      dynamic "transition" {
        for_each = coalesce(rule.value.transitions, [])
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      dynamic "expiration" {
        for_each = rule.value.expiration_days == null ? [] : [1]
        content {
          days = rule.value.expiration_days
        }
      }

      filter {
        dynamic "and" {
          for_each = (lookup(rule.value, "prefix", null) != null || lookup(rule.value, "tags", null) != null) ? [1] : []
          content {
            prefix = lookup(rule.value, "prefix", null)
            tags   = lookup(rule.value, "tags", null)
          }
        }
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

# Object Lock default retention (optional)
resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.enable_object_lock ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode = var.object_lock_default_mode
      days = var.object_lock_default_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

# Enforce TLS and SSE-KMS via Bucket Policy
data "aws_iam_policy_document" "bucket_policy" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals { type = "*"; identifiers = ["*"] }
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
    sid     = "DenyIncorrectEncryptionHeader"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals { type = "*"; identifiers = ["*"] }
    resources = ["${aws_s3_bucket.this.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = [local.use_cmk ? "aws:kms" : "AES256"]
    }
  }

  statement {
    sid     = "DenyUnEncryptedObjectUploads"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals { type = "*"; identifiers = ["*"] }
    resources = ["${aws_s3_bucket.this.arn}/*"]
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }

  dynamic "statement" {
    for_each = local.use_cmk ? [1] : []
    content {
      sid     = "DenyWrongKMSKey"
      effect  = "Deny"
      actions = ["s3:PutObject"]
      principals { type = "*"; identifiers = ["*"] }
      resources = ["${aws_s3_bucket.this.arn}/*"]
      condition {
        test     = "StringNotEquals"
        variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
        values   = [local.kms_arn]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

########################################
# Replication (optional)
########################################
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
  count              = var.replication.enabled ? 1 : 0
  name               = "${var.name}-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_trust.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "replication_policy" {
  count = var.replication.enabled ? 1 : 0

  statement {
    sid     = "SourceBucketRead"
    effect  = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
      "s3:GetBucketVersioning"
    ]
    resources = [aws_s3_bucket.this.arn]
  }

  statement {
    sid     = "SourceObjectsRead"
    effect  = "Allow"
    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
      "s3:GetObjectVersion"
    ]
    resources = ["${aws_s3_bucket.this.arn}/*"]
  }

  statement {
    sid     = "DestinationWrite"
    effect  = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner"
    ]
    resources = ["${var.replication.destination_bucket_arn}/*"]
  }

  dynamic "statement" {
    for_each = (var.replication.replica_kms_encryption && var.replication.destination_kms_key_arn != null) ? [1] : []
    content {
      sid     = "KMSPermissions"
      effect  = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      resources = [
        local.kms_arn != null ? local.kms_arn : "*",
        var.replication.destination_kms_key_arn
      ]
    }
  }
}

resource "aws_iam_role_policy" "replication" {
  count  = var.replication.enabled ? 1 : 0
  name   = "${var.name}-replication"
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication_policy[0].json
}

resource "aws_s3_bucket_replication_configuration" "this" {
  count  = var.replication.enabled ? 1 : 0
  bucket = aws_s3_bucket.this.id
  role   = aws_iam_role.replication[0].arn

  rules {
    id       = "replicate-all"
    status   = "Enabled"
    priority = 0

    delete_marker_replication {
      status = var.replication.delete_marker_replication ? "Enabled" : "Disabled"
    }

    filter {
      prefix = coalesce(var.replication.filter_prefix, "")
    }

    destination {
      bucket        = var.replication.destination_bucket_arn
      storage_class = var.replication.destination_storage_class

      dynamic "encryption_configuration" {
        for_each = (var.replication.replica_kms_encryption && var.replication.destination_kms_key_arn != null) ? [1] : []
        content {
          replica_kms_key_id = var.replication.destination_kms_key_arn
        }
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

########################################
# App IAM (optional)
########################################
# Политики доступа для приложения: RW и RO
data "aws_iam_policy_document" "app_rw" {
  statement {
    sid     = "S3RW"
    effect  = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:GetObjectVersion",
      "s3:PutObjectTagging",
      "s3:GetObjectTagging"
    ]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
  }

  dynamic "statement" {
    for_each = local.use_cmk ? [1] : []
    content {
      sid     = "KMSUsage"
      effect  = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:DescribeKey",
        "kms:ReEncrypt*"
      ]
      resources = [local.kms_arn]
    }
  }

  # Требуем TLS
  statement {
    sid     = "RequireTLS"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    principals { type = "*"; identifiers = ["*"] }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

data "aws_iam_policy_document" "app_ro" {
  statement {
    sid     = "S3RO"
    effect  = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging"
    ]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
  }

  dynamic "statement" {
    for_each = local.use_cmk ? [1] : []
    content {
      sid     = "KMSDecrypt"
      effect  = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey"
      ]
      resources = [local.kms_arn]
    }
  }

  statement {
    sid     = "RequireTLS"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    principals { type = "*"; identifiers = ["*"] }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "app_rw" {
  count       = var.create_app_iam ? 1 : 0
  name        = "${var.app_role_name_prefix}-${var.name}-s3-rw"
  description = "RW access to ${var.name} with KMS usage"
  policy      = data.aws_iam_policy_document.app_rw.json
  tags        = local.common_tags
}

resource "aws_iam_policy" "app_ro" {
  count       = var.create_app_iam ? 1 : 0
  name        = "${var.app_role_name_prefix}-${var.name}-s3-ro"
  description = "RO access to ${var.name} with KMS decrypt"
  policy      = data.aws_iam_policy_document.app_ro.json
  tags        = local.common_tags
}

# При необходимости выдаем политики заранее существующим принципалам
resource "aws_iam_policy_attachment" "attach_rw" {
  for_each = var.create_app_iam && length(var.principals_app) > 0 ? toset(var.principals_app) : []
  name       = "attach-rw-${replace(each.value, ":", "_")}"
  policy_arn = aws_iam_policy.app_rw[0].arn
  users      = [each.value]
  roles      = []
  groups     = []
}

resource "aws_iam_policy_attachment" "attach_ro" {
  for_each = var.create_app_iam && length(var.principals_app) > 0 ? toset(var.principals_app) : []
  name       = "attach-ro-${replace(each.value, ":", "_")}"
  policy_arn = aws_iam_policy.app_ro[0].arn
  users      = [each.value]
  roles      = []
  groups     = []
}

########################################
# Outputs
########################################
output "bucket_name" {
  description = "Имя S3 бакета."
  value       = aws_s3_bucket.this.bucket
}

output "bucket_arn" {
  description = "ARN S3 бакета."
  value       = aws_s3_bucket.this.arn
}

output "kms_key_arn" {
  description = "ARN KMS ключа, если используется."
  value       = local.kms_arn
}

output "app_policy_rw_arn" {
  description = "ARN политики RW для приложения (если создана)."
  value       = var.create_app_iam ? aws_iam_policy.app_rw[0].arn : null
}

output "app_policy_ro_arn" {
  description = "ARN политики RO для приложения (если создана)."
  value       = var.create_app_iam ? aws_iam_policy.app_ro[0].arn : null
}
