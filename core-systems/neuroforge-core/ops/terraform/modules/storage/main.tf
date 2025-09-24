# file: neuroforge-core/ops/terraform/modules/storage/main.tf
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
# Variables
########################################

variable "name" {
  description = "Логическое имя бакета (используется в теге и, при create_bucket = true, в имени ресурса)."
  type        = string
}

variable "create_bucket" {
  description = "Создавать S3 бакет (true) или работать только с политиками/настройками существующего?"
  type        = bool
  default     = true
}

variable "bucket_name" {
  description = "Полное имя бакета (при create_bucket = false обязательно). При create_bucket = true можно задать для детерминированного имени."
  type        = string
  default     = ""
}

variable "force_destroy" {
  description = "Разрешить удаление бакета с объектами (опасно в продакшне)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Общие теги."
  type        = map(string)
  default     = {}
}

variable "enable_versioning" {
  type        = bool
  default     = true
  description = "Включить версионирование."
}

variable "object_lock_enabled" {
  type        = bool
  default     = false
  description = "Включить Object Lock (требует создание нового бакета и особые ограничения)."
}

variable "ownership_mode" {
  type        = string
  default     = "BucketOwnerEnforced" # рекомендовано: убирает ACL
  description = "Режим владения объектами: BucketOwnerEnforced | BucketOwnerPreferred | ObjectWriter."
}

variable "block_public_access" {
  type        = bool
  default     = true
  description = "Глобальная блокировка публичного доступа."
}

# KMS
variable "create_kms_key" {
  type        = bool
  default     = true
  description = "Создать управляемый KMS-ключ для шифрования."
}

variable "kms_key_id" {
  type        = string
  default     = ""
  description = "ID/ARN существующего KMS ключа (если create_kms_key = false)."
}

variable "kms_key_alias" {
  type        = string
  default     = ""
  description = "Alias для создаваемого KMS ключа (например, alias/neuroforge/storage)."
}

variable "kms_deletion_window_days" {
  type        = number
  default     = 30
  description = "Окно удаления KMS-ключа."
}

variable "kms_admin_arns" {
  type        = list(string)
  default     = []
  description = "Список ARN админов KMS (дополнительно к текущему аккаунту)."
}

# Logging
variable "enable_access_logging" {
  type        = bool
  default     = true
  description = "Логирование доступа S3 в отдельный бакет."
}

variable "create_log_bucket" {
  type        = bool
  default     = true
}

variable "log_bucket_name" {
  type        = string
  default     = ""
}

variable "log_bucket_force_destroy" {
  type        = bool
  default     = false
}

# Lifecycle
variable "enable_lifecycle" {
  type        = bool
  default     = true
}

variable "lifecycle_rules" {
  description = <<EOT
Кастомные правила lifecycle. Каждый объект:
{
  id                         = "string"
  enabled                    = true
  prefix                     = "logs/"
  tags                       = { class = "cold" }
  abort_incomplete_mpu_days  = 7
  expiration_days            = 365
  noncurrent_expiration_days = 90
  transitions = [
    { days = 30, storage_class = "STANDARD_IA" },
    { days = 60, storage_class = "GLACIER_IR" }
  ]
  noncurrent_transitions = [
    { days = 30, storage_class = "STANDARD_IA" }
  ]
}
EOT
  type    = list(any)
  default = []
}

# CORS
variable "cors_rules" {
  description = "Массив CORS правил в формате aws_s3_bucket_cors_configuration."
  type        = list(object({
    allowed_headers = optional(list(string), [])
    allowed_methods = list(string)
    allowed_origins = list(string)
    expose_headers  = optional(list(string), [])
    max_age_seconds = optional(number, 0)
  }))
  default = []
}

# Политики доступа
variable "allowed_read_principal_arns" {
  description = "Список ARN, которым разрешен readonly (s3:GetObject, ListBucket)."
  type        = list(string)
  default     = []
}

variable "allowed_write_principal_arns" {
  description = "Список ARN, которым разрешен write (Put/Delete)."
  type        = list(string)
  default     = []
}

variable "additional_bucket_policy_json" {
  description = "Дополнительные statements JSON для политики бакета (встраиваются как есть)."
  type        = string
  default     = ""
}

# Notifications
variable "notifications" {
  description = <<EOT
Конфигурация нотификаций:
{
  sns = [
    { topic_arn = "...", events = ["s3:ObjectCreated:*"], filter_prefix = "in/", filter_suffix = ".json" }
  ],
  sqs = [
    { queue_arn = "...", events = ["s3:ObjectRemoved:*"] }
  ],
  lambda = [
    { function_arn = "...", events = ["s3:ObjectCreated:Put"], filter_prefix = "img/" }
  ]
}
EOT
  type = object({
    sns    = optional(list(object({ topic_arn = string, events = list(string), filter_prefix = optional(string), filter_suffix = optional(string) })), [])
    sqs    = optional(list(object({ queue_arn = string, events = list(string), filter_prefix = optional(string), filter_suffix = optional(string) })), [])
    lambda = optional(list(object({ function_arn = string, events = list(string), filter_prefix = optional(string), filter_suffix = optional(string) })), [])
  })
  default = {}
}

# Replication
variable "replication" {
  description = <<EOT
CRR репликация:
{
  enabled                  = false
  destination_bucket_arn   = "arn:aws:s3:::dest-bucket"
  destination_kms_key_arn  = null
  prefix                   = ""
  priority                 = 0
  storage_class            = "STANDARD"
  account_id               = null # если кросс-аккаунт, укажите ID
  iam_role_name            = ""   # если пусто, создадим роль автоматически
}
EOT
  type = object({
    enabled                 = bool
    destination_bucket_arn  = optional(string)
    destination_kms_key_arn = optional(string)
    prefix                  = optional(string)
    priority                = optional(number)
    storage_class           = optional(string)
    account_id              = optional(string)
    iam_role_name           = optional(string)
  })
  default = {
    enabled = false
  }
}

########################################
# Data & locals
########################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  bucket_name_effective = var.create_bucket ? (
    length(var.bucket_name) > 0 ? var.bucket_name : lower(replace("${var.name}-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}", "/[^a-z0-9-]/", "-"))
  ) : var.bucket_name

  log_bucket_name_effective = var.enable_access_logging ? (
    var.create_log_bucket ? (
      length(var.log_bucket_name) > 0 ? var.log_bucket_name : "${local.bucket_name_effective}-logs"
    ) : var.log_bucket_name
  ) : ""

  tags_base = merge(
    {
      "Project"   = var.name
      "ManagedBy" = "Terraform"
    },
    var.tags
  )

  use_kms  = var.create_kms_key || length(var.kms_key_id) > 0
  kms_arn  = var.create_kms_key ? aws_kms_key.this[0].arn : (length(var.kms_key_id) > 0 ? var.kms_key_id : null)

  # Условное создание бакета логов
  create_logs = var.enable_access_logging && var.create_log_bucket

  # Список statements из additional_bucket_policy_json
  additional_policy_json = try(jsondecode(var.additional_bucket_policy_json), null)
}

########################################
# KMS (optional)
########################################

resource "aws_kms_key" "this" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "KMS key for S3 bucket ${local.bucket_name_effective}"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "EnableRoot"
        Effect   = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      }
    ],
    length(var.kms_admin_arns) > 0 ? [
      {
        Sid      = "AllowAdmins"
        Effect   = "Allow"
        Principal = { AWS = var.kms_admin_arns }
        Action   = "kms:*"
        Resource = "*"
      }
    ] : [])
  })
  tags = local.tags_base
}

resource "aws_kms_alias" "this" {
  count         = var.create_kms_key && length(var.kms_key_alias) > 0 ? 1 : 0
  name          = var.kms_key_alias
  target_key_id = aws_kms_key.this[0].id
}

########################################
# Log bucket (optional)
########################################

resource "aws_s3_bucket" "logs" {
  count  = local.create_logs ? 1 : 0
  bucket = local.log_bucket_name_effective
  force_destroy = var.log_bucket_force_destroy

  tags = merge(local.tags_base, { "Purpose" = "access-logs" })
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = local.create_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count  = local.create_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

########################################
# Main bucket
########################################

resource "aws_s3_bucket" "this" {
  count  = var.create_bucket ? 1 : 0
  bucket = local.bucket_name_effective

  force_destroy = var.force_destroy
  object_lock_enabled = var.object_lock_enabled

  tags = local.tags_base
}

# Для существующего бакета можно подключиться через data source (необязательно).
data "aws_s3_bucket" "existing" {
  count  = var.create_bucket ? 0 : 1
  bucket = local.bucket_name_effective
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id
  rule {
    object_ownership = var.ownership_mode
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id

  block_public_acls       = var.block_public_access
  block_public_policy     = var.block_public_access
  ignore_public_acls      = var.block_public_access
  restrict_public_buckets = var.block_public_access
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id
  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count  = local.use_kms ? 1 : 0
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = local.kms_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "this" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id

  target_bucket = local.create_logs ? aws_s3_bucket.logs[0].id : local.log_bucket_name_effective
  target_prefix = "s3-access/"
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = var.enable_lifecycle ? 1 : 0
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id

  dynamic "rule" {
    for_each = length(var.lifecycle_rules) > 0 ? var.lifecycle_rules : [
      {
        id                        = "default-ia-glacier"
        enabled                   = true
        abort_incomplete_mpu_days = 7
        expiration_days           = 365
        noncurrent_expiration_days = 180
        transitions = [
          { days = 30, storage_class = "STANDARD_IA" },
          { days = 90, storage_class = "GLACIER_IR" }
        ]
        noncurrent_transitions = [
          { days = 30, storage_class = "STANDARD_IA" }
        ]
      }
    ]
    content {
      id     = try(rule.value.id, "rule-${rule.key}")
      status = try(rule.value.enabled, true) ? "Enabled" : "Disabled"

      filter {
        prefix = try(rule.value.prefix, null)
        dynamic "tag" {
          for_each = try(rule.value.tags, null) == null ? {} : rule.value.tags
          content {
            key   = tag.key
            value = tag.value
          }
        }
      }

      # Abort incomplete multipart uploads
      dynamic "abort_incomplete_multipart_upload" {
        for_each = try(rule.value.abort_incomplete_mpu_days, null) == null ? [] : [rule.value.abort_incomplete_mpu_days]
        content { days_after_initiation = abort_incomplete_multipart_upload.value }
      }

      # Current object transitions
      dynamic "transition" {
        for_each = try(rule.value.transitions, [])
        content {
          days          = try(transition.value.days, null)
          storage_class = transition.value.storage_class
        }
      }

      # Noncurrent transitions/expiration
      dynamic "noncurrent_version_transition" {
        for_each = try(rule.value.noncurrent_transitions, [])
        content {
          noncurrent_days = try(noncurrent_version_transition.value.days, 30)
          storage_class   = noncurrent_version_transition.value.storage_class
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = try(rule.value.noncurrent_expiration_days, null) == null ? [] : [rule.value.noncurrent_expiration_days]
        content { noncurrent_days = noncurrent_version_expiration.value }
      }

      dynamic "expiration" {
        for_each = try(rule.value.expiration_days, null) == null ? [] : [rule.value.expiration_days]
        content { days = expiration.value }
      }
    }
  }
}

resource "aws_s3_bucket_cors_configuration" "this" {
  count  = length(var.cors_rules) > 0 ? 1 : 0
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id

  dynamic "cors_rule" {
    for_each = var.cors_rules
    content {
      allowed_headers = try(cors_rule.value.allowed_headers, null)
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      expose_headers  = try(cors_rule.value.expose_headers, null)
      max_age_seconds = try(cors_rule.value.max_age_seconds, null)
    }
  }
}

########################################
# Bucket Policy (TLS+KMS enforcement, R/W access, extra statements)
########################################

data "aws_iam_policy_document" "base" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals { type = "*"; identifiers = ["*"] }
    resources = [
      "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}",
      "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Требуем kms шифрование для загрузок (если use_kms)
  dynamic "statement" {
    for_each = local.use_kms ? [1] : []
    content {
      sid     = "DenyUnEncryptedObjectUploads"
      effect  = "Deny"
      actions = ["s3:PutObject"]
      principals { type = "*"; identifiers = ["*"] }
      resources = ["arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}/*"]
      condition {
        test     = "StringNotEquals"
        variable = "s3:x-amz-server-side-encryption"
        values   = ["aws:kms"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.use_kms ? [1] : []
    content {
      sid     = "DenyIncorrectEncryptionHeader"
      effect  = "Deny"
      actions = ["s3:PutObject"]
      principals { type = "*"; identifiers = ["*"] }
      resources = ["arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}/*"]
      condition {
        test     = "StringNotEquals"
        variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
        values   = [local.kms_arn]
      }
    }
  }

  # Readonly principals
  dynamic "statement" {
    for_each = length(var.allowed_read_principal_arns) > 0 ? [1] : []
    content {
      sid    = "AllowReadOnly"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = var.allowed_read_principal_arns
      }
      actions = ["s3:GetObject", "s3:ListBucket"]
      resources = [
        "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}",
        "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}/*"
      ]
    }
  }

  # Write principals
  dynamic "statement" {
    for_each = length(var.allowed_write_principal_arns) > 0 ? [1] : []
    content {
      sid    = "AllowWrite"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = var.allowed_write_principal_arns
      }
      actions = ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"]
      resources = ["arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}/*"]
      condition {
        test     = "StringEquals"
        variable = "s3:x-amz-server-side-encryption"
        values   = local.use_kms ? ["aws:kms"] : ["AES256", "aws:kms"]
      }
    }
  }
}

# Merge with additional JSON if provided
data "aws_iam_policy_document" "merged" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]

  dynamic "override_json" {
    for_each = local.additional_policy_json == null ? [] : [1]
    content {
      statement = local.additional_policy_json.Statement
      version   = try(local.additional_policy_json.Version, null)
      id        = try(local.additional_policy_json.Id, null)
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id
  policy = data.aws_iam_policy_document.merged.json
}

########################################
# Notifications (SNS/SQS/Lambda)
########################################

resource "aws_s3_bucket_notification" "this" {
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id

  dynamic "topic" {
    for_each = try(var.notifications.sns, [])
    content {
      topic_arn = topic.value.topic_arn
      events    = topic.value.events
      filter_prefix = try(topic.value.filter_prefix, null)
      filter_suffix = try(topic.value.filter_suffix, null)
    }
  }

  dynamic "queue" {
    for_each = try(var.notifications.sqs, [])
    content {
      queue_arn = queue.value.queue_arn
      events    = queue.value.events
      filter_prefix = try(queue.value.filter_prefix, null)
      filter_suffix = try(queue.value.filter_suffix, null)
    }
  }

  dynamic "lambda_function" {
    for_each = try(var.notifications.lambda, [])
    content {
      lambda_function_arn = lambda_function.value.function_arn
      events              = lambda_function.value.events
      filter_prefix       = try(lambda_function.value.filter_prefix, null)
      filter_suffix       = try(lambda_function.value.filter_suffix, null)
    }
  }

  depends_on = [aws_s3_bucket_public_access_block.this]
}

########################################
# Replication (CRR)
########################################

# IAM role for replication (optional auto-create)
data "aws_iam_policy_document" "replication_assume" {
  statement {
    effect = "Allow"
    principals { type = "Service"; identifiers = ["s3.amazonaws.com"] }
    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "replication_policy" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket"
    ]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}"]
  }
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObjectVersion",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging"
    ]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}/*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner"
    ]
    resources = [try(var.replication.destination_bucket_arn, "")]
  }
  dynamic "statement" {
    for_each = try(var.replication.destination_kms_key_arn, null) == null ? [] : [1]
    content {
      effect = "Allow"
      actions = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
      resources = [var.replication.destination_kms_key_arn]
    }
  }
}

resource "aws_iam_role" "replication" {
  count              = try(var.replication.enabled, false) && (try(var.replication.iam_role_name, "") == "") ? 1 : 0
  name               = "s3-replication-${local.bucket_name_effective}"
  assume_role_policy = data.aws_iam_policy_document.replication_assume.json
  tags               = local.tags_base
}

resource "aws_iam_role_policy" "replication" {
  count  = try(var.replication.enabled, false) && (try(var.replication.iam_role_name, "") == "") ? 1 : 0
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication_policy.json
}

resource "aws_s3_bucket_replication_configuration" "this" {
  count  = try(var.replication.enabled, false) ? 1 : 0
  bucket = var.create_bucket ? aws_s3_bucket.this[0].id : data.aws_s3_bucket.existing[0].id
  role   = try(var.replication.iam_role_name, "") != "" ? var.replication.iam_role_name : aws_iam_role.replication[0].arn

  rule {
    id       = "crr-default"
    priority = try(var.replication.priority, 0)
    status   = "Enabled"

    filter {
      prefix = try(var.replication.prefix, "")
    }

    delete_marker_replication { status = "Disabled" }

    destination {
      bucket        = var.replication.destination_bucket_arn
      storage_class = try(var.replication.storage_class, "STANDARD")
      dynamic "encryption_configuration" {
        for_each = try(var.replication.destination_kms_key_arn, null) == null ? [] : [1]
        content {
          replica_kms_key_id = var.replication.destination_kms_key_arn
        }
      }
      dynamic "access_control_translation" {
        for_each = try(var.replication.account_id, null) == null ? [] : [1]
        content {
          owner = "Destination"
        }
      }
      account = try(var.replication.account_id, null)
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

########################################
# Outputs
########################################

output "bucket_name" {
  value       = local.bucket_name_effective
  description = "Имя бакета."
}

output "bucket_arn" {
  value       = var.create_bucket ? aws_s3_bucket.this[0].arn : "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name_effective}"
  description = "ARN бакета."
}

output "kms_key_arn" {
  value       = local.kms_arn
  description = "ARN KMS ключа для шифрования (если включено)."
}

output "log_bucket_name" {
  value       = local.create_logs ? aws_s3_bucket.logs[0].bucket : (length(local.log_bucket_name_effective) > 0 ? local.log_bucket_name_effective : null)
  description = "Имя бакета для логов доступа (если включено)."
}
