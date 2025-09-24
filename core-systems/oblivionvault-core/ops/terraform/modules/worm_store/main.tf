terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

########################################
# INPUTS
########################################

variable "name" {
  description = "Базовое имя ресурса (логическое). Будет использовано в имени S3 bucket."
  type        = string
}

variable "environment" {
  description = "Окружение: prod|staging|dev|... Входит в имя bucket и теги."
  type        = string
}

variable "tags" {
  description = "Дополнительные теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "region" {
  description = "Регион AWS для подсказки в тегах/политиках (провайдер задаётся снаружи)."
  type        = string
  default     = null
}

# Шифрование
variable "kms_key_arn" {
  description = "Если указан, используется существующий KMS‑ключ. Если пусто и create_kms_key=true — будет создан новый ключ."
  type        = string
  default     = ""
}

variable "create_kms_key" {
  description = "Создавать ли собственный KMS‑ключ для S3 SSE‑KMS."
  type        = bool
  default     = true
}

variable "kms_key_deletion_window_in_days" {
  description = "Окно удаления KMS‑ключа."
  type        = number
  default     = 30
}

variable "kms_key_rotation" {
  description = "Включить ли автоматическую ротацию KMS‑ключа."
  type        = bool
  default     = true
}

variable "kms_alias_suffix" {
  description = "Суффикс для alias KMS‑ключа (alias/oblivionvault-<name>-<env>-<suffix>)."
  type        = string
  default     = "s3-worm"
}

# Object Lock / WORM
variable "object_lock_mode" {
  description = "Режим WORM: GOVERNANCE или COMPLIANCE."
  type        = string
  default     = "GOVERNANCE"
  validation {
    condition     = can(index(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode))
    error_message = "object_lock_mode должен быть GOVERNANCE или COMPLIANCE."
  }
}

variable "retention_days" {
  description = "Срок удержания по умолчанию в днях (альтернатива retention_years)."
  type        = number
  default     = null
}

variable "retention_years" {
  description = "Срок удержания по умолчанию в годах (альтернатива retention_days)."
  type        = number
  default     = null
}

variable "require_encryption" {
  description = "Жёстко требовать SSE‑KMS при PUT (bucket policy)."
  type        = bool
  default     = true
}

variable "block_public_access" {
  description = "Полностью блокировать публичный доступ для bucket."
  type        = bool
  default     = true
}

# Логирование доступа
variable "logging_enabled" {
  description = "Включить логирование доступа в отдельный лог‑bucket."
  type        = bool
  default     = true
}

variable "log_bucket_name" {
  description = "Имя существующего bucket для логов. Если пусто и logging_enabled=true, то будет создан новый."
  type        = string
  default     = ""
}

variable "create_log_bucket" {
  description = "Создавать ли лог‑bucket, если log_bucket_name пуст."
  type        = bool
  default     = true
}

# Lifecycle
variable "lifecycle_glacier_transition_days" {
  description = "Через сколько дней переводить объекты в GLACIER_IR."
  type        = number
  default     = 30
}

variable "lifecycle_deep_archive_transition_days" {
  description = "Через сколько дней переводить объекты в DEEP_ARCHIVE."
  type        = number
  default     = 180
}

variable "lifecycle_noncurrent_deep_archive_days" {
  description = "Для неактуальных версий — через сколько дней переводить в DEEP_ARCHIVE."
  type        = number
  default     = 30
}

variable "abort_multipart_days" {
  description = "Через сколько дней абортировать незавершённые multipart‑загрузки."
  type        = number
  default     = 7
}

variable "force_destroy" {
  description = "Разрешить ли удаление bucket вместе с объектами (обычно false для WORM)."
  type        = bool
  default     = false
}

########################################
# LOCALS & DATA
########################################

data "aws_caller_identity" "this" {}

data "aws_partition" "this" {}

locals {
  base_name          = lower(replace("${var.name}-${var.environment}", "/[^a-zA-Z0-9-]/", "-"))
  # S3 bucket name: только строчные, цифры и дефис. Добавляем суффикс для уникальности.
  bucket_name_prefix = substr(local.base_name, 0, 48)
  common_tags = merge({
    "Project"     = "oblivionvault-core"
    "Environment" = var.environment
    "Module"      = "worm_store"
    "ManagedBy"   = "Terraform"
  }, var.tags)
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  bucket_name    = lower("${local.bucket_name_prefix}-${random_id.suffix.hex}")
  logs_bucket    = var.log_bucket_name != "" ? var.log_bucket_name : lower("${local.bucket_name_prefix}-logs-${random_id.suffix.hex}")
  use_logs_local = var.logging_enabled && var.log_bucket_name == "" && var.create_log_bucket
  # Выбор KMS
  use_kms_created = var.kms_key_arn == "" && var.create_kms_key
}

########################################
# KMS (optional)
########################################

resource "aws_kms_key" "s3" {
  count                   = local.use_kms_created ? 1 : 0
  description             = "KMS key for S3 WORM bucket ${local.bucket_name}"
  deletion_window_in_days = var.kms_key_deletion_window_in_days
  enable_key_rotation     = var.kms_key_rotation

  # Политика по умолчанию: владелец аккаунта имеет полный доступ.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Enable IAM User Permissions"
        Effect   = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.this.partition}:iam::${data.aws_caller_identity.this.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "s3" {
  count         = local.use_kms_created ? 1 : 0
  name          = "alias/oblivionvault-${var.environment}-${var.kms_alias_suffix}-${random_id.suffix.hex}"
  target_key_id = aws_kms_key.s3[0].key_id
}

locals {
  kms_key_arn_effective = var.kms_key_arn != "" ? var.kms_key_arn : (local.use_kms_created ? aws_kms_key.s3[0].arn : null)
}

########################################
# LOGGING BUCKET (optional create)
########################################

resource "aws_s3_bucket" "logs" {
  count         = local.use_logs_local ? 1 : 0
  bucket        = local.logs_bucket
  force_destroy = false
  tags          = merge(local.common_tags, { "Name" = local.logs_bucket })
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = local.use_logs_local ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count  = local.use_logs_local ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = local.use_logs_local ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.kms_key_arn_effective != null ? "aws:kms" : "AES256"
      kms_key_id        = local.kms_key_arn_effective
    }
    bucket_key_enabled = true
  }
}

# Политика для server access logging (S3 Log Delivery group)
data "aws_iam_policy_document" "logs_bucket_policy" {
  count = local.use_logs_local ?
