/*******************************************************
* datafabric-core / ops/terraform/modules/storage/main.tf
* Модуль: приватный S3 бакет с KMS, логами, CORS, lifecycle и CRR.
* Требуется: AWS provider >= 5.0, Terraform >= 1.4
*******************************************************/

terraform {
  required_version = ">= 1.4"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

#####################################
# ВХОДНЫЕ ПАРАМЕТРЫ
#####################################

variable "name" {
  description = "Базовое имя бакета (будет уникализировано через префикс/суффикс)."
  type        = string
}

variable "region" {
  description = "Регион AWS для ресурсов S3/KMS/IAM."
  type        = string
}

variable "force_destroy" {
  description = "Удалять бакет со всеми объектами при destroy (ОСТОРОЖНО)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Общие теги для всех создаваемых ресурсов."
  type        = map(string)
  default     = {}
}

variable "enable_versioning" {
  description = "Включить версии объектов."
  type        = bool
  default     = true
}

variable "enable_object_lock" {
  description = "Создать бакет с Object Lock. ВНИМАНИЕ: включается только при создании бакета и необратимо."
  type        = bool
  default     = false
}

variable "object_lock_mode" {
  description = "Режим Object Lock по умолчанию (GOVERNANCE/COMPLIANCE)."
  type        = string
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode должен быть GOVERNANCE или COMPLIANCE."
  }
}

variable "object_lock_days" {
  description = "Срок удержания по умолчанию (в днях) для Object Lock."
  type        = number
  default     = 0
}

variable "sse_algorithm" {
  description = "Алгоритм шифрования по умолчанию (AES256 или aws:kms)."
  type        = string
  default     = "AES256"
  validation {
    condition     = contains(["AES256", "aws:kms"], var.sse_algorithm)
    error_message = "sse_algorithm должен быть AES256 или aws:kms."
  }
}

variable "kms_key_arn" {
  description = "ARN существующего KMS ключа для шифрования. Если пусто и выбрано aws:kms — будет создан CMK."
  type        = string
  default     = ""
}

variable "create_kms_key" {
  description = "Создавать управляемый CMK для бакета, если kms_key_arn не задан."
  type        = bool
  default     = true
}

variable "enable_access_logging" {
  description = "Включить серверные логи доступа S3 (создастся отдельный лог‑бакет)."
  type        = bool
  default     = true
}

variable "log_bucket_name" {
  description = "Имя лог‑бакета (если пусто — создадим автоматически)."
  type        = string
  default     = ""
}

variable "cors_rules" {
  description = "Список CORS‑правил для бакета."
  type = list(object({
    allowed_headers = list(string)
    allowed_methods = list(string)
    allowed_origins = list(string)
    expose_headers  = optional(list(string), [])
    max_age_seconds = optional(number, 3600)
  }))
  default = []
}

variable "lifecycle_rules" {
  description = "Пользовательские lifecycle‑правила (дополняют дефолтные)."
  type = list(object({
    id      = string
    enabled = bool
    filter  = optional(any, null) # см. aws_s3_bucket_lifecycle_configuration.rules.filter
    transitions = optional(list(object({
      days          = optional(number)
      storage_class = string
    })), [])
    expiration = optional(object({
      days                         = optional(number)
      expired_object_delete_marker = optional(bool)
    }), null)
    noncurrent_version_expiration = optional(object({
      noncurrent_days = number
    }), null)
    noncurrent_version_transitions = optional(list(object({
      noncurrent_days = number
      storage_class   = string
    })), [])
  }))
  default = []
}

variable "default_lifecycle_enabled" {
  description = "Включить типовой lifecycle: переход через 30/90 дней и Glacier Deep Archive через 180 дней; удаление старых версий через 365 дней."
  type        = bool
  default     = true
}

variable "block_public_access" {
  description = "Жёстко блокировать публичный доступ (рекомендуется)."
  type        = bool
  default     = true
}

variable "allow_insecure_transport" {
  description = "Разрешить запросы без TLS (по умолчанию НЕТ, bucket policy запретит)."
  type        = bool
  default     = false
}

variable "replication" {
  description = "Конфигурация CRR (репликация в другой регион/бакет)."
  type = object({
    enabled                = bool
    destination_bucket_arn = optional(string)
    destination_kms_key_arn= optional(string)
    destination_storage_class = optional(string, "STANDARD")
    prefix                 = optional(string, "")
    account_id             = optional(string) # для policy условий
    create_role            = optional(bool, true)
  })
  default = {
    enabled = false
  }
}

#####################################
# ЛОКАЛЫ И ПРОВАЙДЕР
#####################################

provider "aws" {
  region = var.region
}

locals {
  bucket_name     = var.name
  use_kms         = var.sse_algorithm == "aws:kms"
  create_kms_cmk  = local.use_kms && var.kms_key_arn == "" && var.create_kms_key
  logs_bucket     = var.enable_access_logging ? (var.log_bucket_name != "" ? var.log_bucket_name : "${local.bucket_name}-logs") : null
  tags_common     = merge(var.tags, { "managed-by" = "terraform", "module" = "datafabric-core/storage" })
}

#####################################
# KMS ключ (опционально)
#####################################

resource "aws_kms_key" "this" {
  count                   = local.create_kms_cmk ? 1 : 0
  description             = "KMS CMK для S3 бакета ${local.bucket_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags_common
}

resource "aws_kms_alias" "this" {
  count         = local.create_kms_cmk ? 1 : 0
  name          = "alias/s3/${local.bucket_name}"
  target_key_id = aws_kms_key.this[0].key_id
}

#####################################
# ЛОГ-БАКЕТ (если включен access logging)
#####################################

resource "aws_s3_bucket" "logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = local.logs_bucket
  force_destroy = var.force_destroy

  tags = merge(local.tags_common, { "purpose" = "s3-access-logs" })
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced" # отключает ACL
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = var.enable_access_logging ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

#####################################
# ОСНОВНОЙ БАКЕТ
#####################################

resource "aws_s3_bucket" "this" {
  bucket        = local.bucket_name
  force_destroy = var.force_destroy

  # Включение Object Lock ТОЛЬКО на создании
  object_lock_enabled = var.enable_object_lock
  tags                = local.tags_common
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced" # запрет ACL, предотвращает проблемы с ownership
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status     = var.enable_versioning ? "Enabled" : "Suspended"
    mfa_delete = "Disabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.enable_object_lock ? 1 : 0
  bucket = aws_s3_bucket.this.id
  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.sse_algorithm
      kms_master_key_id = local.use_kms ? (var.kms_key_arn != "" ? var.kms_key_arn : aws_kms_key.this[0].arn) : null
    }
    bucket_key_enabled = local.use_kms # S3 Bucket Keys, снижает стоимость KMS
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = var.block_public_access
  block_public_policy     = var.block_public_access
  ignore_public_acls      = var.block_public_access
  restrict_public_buckets = var.block_public_access
}

resource "aws_s3_bucket_logging" "this" {
  count         = var.enable_access_logging ? 1 : 0
  bucket        = aws_s3_bucket.this.id
  target_bucket = aws_s3_bucket.logs[0].id
  target_prefix = "s3-access/"
}

resource "aws_s3_bucket_cors_configuration" "this" {
  count  = length(var.cors_rules) > 0 ? 1 : 0
  bucket = aws_s3_bucket.this.id

  dynamic "cors_rule" {
    for_each = var.cors_rules
    content {
      allowed_headers = cors_rule.value.allowed_headers
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      expose_headers  = lookup(cors_rule.value, "expose_headers", [])
      max_age_seconds = lookup(cors_rule.value, "max_age_seconds", 3600)
    }
  }
}

# Типовой Lifecycle (переводы по классам хранения + удаление старых версий)
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  dynamic "rule" {
    for_each = var.default_lifecycle_enabled ? [1] : []
    content {
      id     = "default-lifecycle"
      status = "Enabled"
      # все объекты
      filter {}
      transition {
        days          = 30
        storage_class = "STANDARD_IA"
      }
      transition {
        days          = 90
        storage_class = "GLACIER_IR"
      }
      transition {
        days          = 180
        storage_class = "DEEP_ARCHIVE"
      }
      noncurrent_version_transition {
        noncurrent_days = 30
        storage_class   = "STANDARD_IA"
      }
      noncurrent_version_expiration {
        noncurrent_days = 365
      }
      expiration {
        expired_object_delete_marker = true
      }
    }
  }

  # Пользовательские правила
  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = rule.value.id
      status = rule.value.enabled ? "Enabled" : "Disabled"

      dynamic "filter" {
        for_each = rule.value.filter == null ? [] : [rule.value.filter]
        content {
          # свободная форма фильтра: prefix/tags/and
          # пример: { prefix = "logs/" } или { and = { prefix="logs/"; tags=[{key="k", value="v"}] } }
          prefix = try(filter.value.prefix, null)
          dynamic "and" {
            for_each = can(filter.value.and) ? [filter.value.and] : []
            content {
              prefix = try(and.value.prefix, null)
              dynamic "tags" {
                for_each = try(and.value.tags, [])
                content {
                  key   = tags.value.key
                  value = tags.value.value
                }
              }
            }
          }
          dynamic "tag" {
            for_each = can(filter.value.tags) ? filter.value.tags : []
            content {
              key   = tag.value.key
              value = tag.value.value
            }
          }
        }
      }

      dynamic "transition" {
        for_each = rule.value.transitions
        content {
          days          = try(transition.value.days, null)
          storage_class = transition.value.storage_class
        }
      }

      dynamic "noncurrent_version_transition" {
        for_each = rule.value.noncurrent_version_transitions
        content {
          noncurrent_days = noncurrent_version_transition.value.noncurrent_days
          storage_class   = noncurrent_version_transition.value.storage_class
        }
      }

      dynamic "expiration" {
        for_each = rule.value.expiration == null ? [] : [rule.value.expiration]
        content {
          days                         = try(expiration.value.days, null)
          expired_object_delete_marker = try(expiration.value.expired_object_delete_marker, null)
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = rule.value.noncurrent_version_expiration == null ? [] : [rule.value.noncurrent_version_expiration]
        content {
          noncurrent_days = noncurrent_version_expiration.value.noncurrent_days
        }
      }
    }
  }
}

#####################################
# REPLICATION (CRR, опционально)
#####################################

# IAM роль и политика для репликации
resource "aws_iam_role" "replication" {
  count              = var.replication.enabled && try(var.replication.create_role, true) ? 1 : 0
  name               = "${local.bucket_name}-s3-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_trust.json
  tags               = local.tags_common
}

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

data "aws_iam_policy_document" "replication_policy" {
  count = var.replication.enabled && try(var.replication.create_role, true) ? 1 : 0

  statement {
    sid     = "KMSDecryptSource"
    effect  = "Allow"
    actions = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [
      local.use_kms ? (var.kms_key_arn != "" ? var.kms_key_arn : aws_kms_key.this[0].arn) : "*"
    ]
  }

  statement {
    sid     = "KMSencryptDestination"
    effect  = "Allow"
    actions = ["kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [
      try(var.replication.destination_kms_key_arn, "*")
    ]
  }

  statement {
    sid     = "S3ReplicationActions"
    effect  = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
      "s3:GetBucketVersioning",
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner",
      "s3:GetObjectVersionTagging",
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersion"
    ]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*",
      try(var.replication.destination_bucket_arn, null),
      "${try(var.replication.destination_bucket_arn, "")}/*"
    ]
  }
}

resource "aws_iam_policy" "replication" {
  count  = var.replication.enabled && try(var.replication.create_role, true) ? 1 : 0
  name   = "${local.bucket_name}-s3-replication"
  policy = data.aws_iam_policy_document.replication_policy[0].json
}

resource "aws_iam_role_policy_attachment" "replication" {
  count      = var.replication.enabled && try(var.replication.create_role, true) ? 1 : 0
  role       = aws_iam_role.replication[0].name
  policy_arn = aws_iam_policy.replication[0].arn
}

# Конфигурация репликации в бакете‑источнике
resource "aws_s3_bucket_replication_configuration" "this" {
  count  = var.replication.enabled ? 1 : 0
  bucket = aws_s3_bucket.this.id
  role   = try(aws_iam_role.replication[0].arn, "") != "" ? aws_iam_role.replication[0].arn : null

  rule {
    id       = "crr"
    status   = "Enabled"
    priority = 1
    filter {
      prefix = try(var.replication.prefix, "")
    }
    destination {
      bucket        = var.replication.destination_bucket_arn
      storage_class = try(var.replication.destination_storage_class, "STANDARD")
      dynamic "encryption_configuration" {
        for_each = try(var.replication.destination_kms_key_arn, "") != "" ? [1] : []
        content {
          replica_kms_key_id = var.replication.destination_kms_key_arn
        }
      }
      account = try(var.replication.account_id, null)
    }
    delete_marker_replication {
      status = "Enabled"
    }
    existing_object_replication {
      status = "Disabled"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.this
  ]
}

#####################################
# BUCKET POLICY (запрет не‑TLS + приватность)
#####################################

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
      values   = [var.allow_insecure_transport ? "false" : "false"]
    }
  }

  # Дополнительно можно добавлять условия/разрешения через внешние политики на IAM‑уровне.
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

#####################################
# ВЫХОДНЫЕ ДАННЫЕ
#####################################

output "bucket_id" {
  description = "Имя S3 бакета."
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "ARN S3 бакета."
  value       = aws_s3_bucket.this.arn
}

output "kms_key_arn" {
  description = "ARN KMS ключа, если используется."
  value       = local.use_kms ? (var.kms_key_arn != "" ? var.kms_key_arn : (local.create_kms_cmk ? aws_kms_key.this[0].arn : null)) : null
}

output "logs_bucket_id" {
  description = "Имя лог‑бакета (если включены логи)."
  value       = var.enable_access_logging ? aws_s3_bucket.logs[0].id : null
}

output "replication_role_arn" {
  description = "ARN IAM‑роли для репликации (если создана)."
  value       = var.replication.enabled && try(var.replication.create_role, true) ? aws_iam_role.replication[0].arn : null
}
