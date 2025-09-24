terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

############################################
# Data
############################################
data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

############################################
# Variables (самодостаточные для модуля)
############################################

variable "name" {
  description = "Базовое имя стека (kebab-case). Используется в нейминге ресурсов."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name))
    error_message = "name должен соответствовать ^[a-z0-9-]+$."
  }
}

variable "environment" {
  description = "Окружение: dev|stage|prod и т.п."
  type        = string
  default     = "dev"
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.environment))
    error_message = "environment должен соответствовать ^[a-z0-9-]+$."
  }
}

variable "tags" {
  description = "Доп. теги, добавляемые ко всем ресурсам."
  type        = map(string)
  default     = {}
}

variable "randomize_names" {
  description = "Добавлять случайный суффикс к именам бакетов/очередей для уникальности."
  type        = bool
  default     = true
}

variable "create_kms_key" {
  description = "Создавать управляемый KMS-ключ (true) или использовать существующий (false)."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "ARN существующего KMS-ключа, если create_kms_key=false."
  type        = string
  default     = ""
}

variable "kms_key_alias" {
  description = "Алиас для создаваемого KMS-ключа."
  type        = string
  default     = "video-ingest-kms"
  validation {
    condition     = var.kms_key_alias != "" && can(regex("^[a-z0-9-_/]+$", var.kms_key_alias))
    error_message = "kms_key_alias должен быть непустым и состоять из a-z0-9-_/."
  }
}

variable "s3_bucket_name" {
  description = "Явное имя бакета (если пусто — будет сгенерировано)."
  type        = string
  default     = ""
}

variable "s3_force_destroy" {
  description = "Разрешить удаление бакета с объектами (использовать осторожно в prod)."
  type        = bool
  default     = false
}

variable "s3_log_delivery" {
  description = "Включить отдельный бакет для логов доступа (server access logs)."
  type        = bool
  default     = true
}

variable "s3_noncurrent_retention_days" {
  description = "Через сколько дней удалять неактуальные версии объектов."
  type        = number
  default     = 90
  validation {
    condition     = var.s3_noncurrent_retention_days >= 7
    error_message = "s3_noncurrent_retention_days должен быть >= 7."
  }
}

variable "kinesis_retention_hours" {
  description = "Ретенция данных Kinesis Video Streams в часах."
  type        = number
  default     = 24
  validation {
    condition     = var.kinesis_retention_hours >= 0 && var.kinesis_retention_hours <= 8760
    error_message = "kinesis_retention_hours должен быть в диапазоне 0..8760."
  }
}

variable "kinesis_media_type" {
  description = "Media type для потока (например, video/h264)."
  type        = string
  default     = "video/h264"
}

variable "producer_principals" {
  description = "Список ARN субъектов, которым разрешено AssumeRole продьюсер-ролей (IAM Role/Role OIDC/Users)."
  type        = list(string)
  default     = []
}

variable "consumer_principals" {
  description = "Список ARN субъектов, которым разрешено AssumeRole консьюмер-ролей."
  type        = list(string)
  default     = []
}

variable "s3_notification_prefix" {
  description = "Префикс в бакете, с которого слать уведомления в SQS ('' = весь бакет)."
  type        = string
  default     = ""
}

variable "s3_notification_suffix" {
  description = "Суффикс объектов для уведомлений (например, .mp4)."
  type        = string
  default     = ""
}

############################################
# Locals
############################################
locals {
  base_name = "${var.name}-${var.environment}"

  random_suffix = var.randomize_names ? random_string.suffix[0].result : ""

  name_suffix = var.randomize_names && local.random_suffix != "" ? "-${local.random_suffix}" : ""

  bucket_name = var.s3_bucket_name != "" ? var.s3_bucket_name : "${replace(local.base_name, "/[^a-z0-9-]/", "")}-ingest${local.name_suffix}"

  queue_name       = "${local.base_name}-ingest-q${local.name_suffix}"
  dlq_name         = "${local.base_name}-ingest-dlq${local.name_suffix}"
  kinesis_name     = "${local.base_name}-stream${local.name_suffix}"
  logs_bucket_name = "${local.base_name}-s3-logs${local.name_suffix}"

  common_tags = merge(
    {
      "Project"     = var.name
      "Environment" = var.environment
      "ManagedBy"   = "Terraform"
      "Module"      = "physical-integration-core/video_ingest"
    },
    var.tags
  )
}

resource "random_string" "suffix" {
  count   = var.randomize_names ? 1 : 0
  length  = 6
  upper   = false
  lower   = true
  number  = true
  special = false
}

############################################
# KMS Key (optional managed)
############################################

data "aws_iam_policy_document" "kms" {
  statement {
    sid     = "AllowRootAccountAdministration"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.this.account_id}:root"]
    }
    resources = ["*"]
  }

  # Разрешаем сервисам в аккаунте использовать ключ
  dynamic "statement" {
    for_each = toset([
      "s3.${data.aws_region.this.name}.amazonaws.com",
      "sqs.${data.aws_region.this.name}.amazonaws.com",
      "kinesisvideo.${data.aws_region.this.name}.amazonaws.com",
    ])
    content {
      sid    = "AllowServiceUse-${replace(statement.value, "/[.:]/", "-")}"
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
        identifiers = [replace(statement.value, "/\\..*/", "")] # не используется; оставлено для совместимости
      }
      principals {
        type        = "Service"
        identifiers = [statement.value]
      }
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "kms:CallerAccount"
        values   = [data.aws_caller_identity.this.account_id]
      }
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = [statement.value]
      }
    }
  }
}

resource "aws_kms_key" "this" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "KMS key for video ingest (S3, SQS, KinesisVideo)"
  enable_key_rotation     = true
  multi_region            = false
  policy                  = data.aws_iam_policy_document.kms.json
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

resource "aws_kms_alias" "this" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/${var.kms_key_alias}"
  target_key_id = aws_kms_key.this[0].key_id
}

locals {
  kms_key_arn = var.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn
}

############################################
# S3 buckets (ingest + logs)
############################################

resource "aws_s3_bucket" "logs" {
  count  = var.s3_log_delivery ? 1 : 0
  bucket = local.logs_bucket_name
  force_destroy = var.s3_force_destroy
  tags   = merge(local.common_tags, { "Name" = local.logs_bucket_name })
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count  = var.s3_log_delivery ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.s3_log_delivery ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.s3_log_delivery ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = local.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket" "ingest" {
  bucket        = local.bucket_name
  force_destroy = var.s3_force_destroy
  tags          = merge(local.common_tags, { "Name" = local.bucket_name })
}

resource "aws_s3_bucket_public_access_block" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = local.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  rule {
    id     = "noncurrent-cleanup"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_noncurrent_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_logging" "ingest" {
  count  = var.s3_log_delivery ? 1 : 0
  bucket = aws_s3_bucket.ingest.id
  target_bucket = aws_s3_bucket.logs[0].id
  target_prefix = "s3-access/"
  depends_on = [aws_s3_bucket_server_side_encryption_configuration.logs]
}

# Политика: запрещаем незащищённый транспорт и старые TLS
data "aws_iam_policy_document" "s3_ingest_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.ingest.arn,
      "${aws_s3_bucket.ingest.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyTLS12AndLower"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.ingest.arn,
      "${aws_s3_bucket.ingest.arn}/*"
    ]
    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

resource "aws_s3_bucket_policy" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  policy = data.aws_iam_policy_document.s3_ingest_bucket.json
}

############################################
# SQS (events + DLQ) с шифрованием KMS
############################################

resource "aws_sqs_queue" "dlq" {
  name                      = local.dlq_name
  kms_master_key_id         = local.kms_key_arn
  message_retention_seconds = 1209600 # 14 days
  tags                      = local.common_tags
}

resource "aws_sqs_queue" "events" {
  name                       = local.queue_name
  kms_master_key_id          = local.kms_key_arn
  visibility_timeout_seconds = 60
  message_retention_seconds  = 345600 # 4 days
  redrive_policy             = jsonencode({ deadLetterTargetArn = aws_sqs_queue.dlq.arn, maxReceiveCount = 5 })
  receive_wait_time_seconds  = 10
  tags                       = local.common_tags
}

# Разрешаем S3 слать уведомления в очередь
data "aws_iam_policy_document" "sqs_from_s3" {
  statement {
    sid    = "AllowS3ToSendMessages"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.events.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.ingest.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.events.id
  policy    = data.aws_iam_policy_document.sqs_from_s3.json
}

# S3 → SQS notifications
resource "aws_s3_bucket_notification" "ingest" {
  bucket = aws_s3_bucket.ingest.id

  queue {
    queue_arn     = aws_sqs_queue.events.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = var.s3_notification_prefix
    filter_suffix = var.s3_notification_suffix
  }

  depends_on = [aws_sqs_queue_policy.events]
}

############################################
# Kinesis Video Stream
############################################

resource "aws_kinesis_video_stream" "this" {
  name                    = local.kinesis_name
  data_retention_in_hours = var.kinesis_retention_hours
  media_type              = var.kinesis_media_type
  kms_key_id              = local.kms_key_arn
  tags                    = local.common_tags
}

############################################
# IAM: роли продьюсера и консьюмера
############################################

# Trust policies
data "aws_iam_policy_document" "assume_producer" {
  dynamic "statement" {
    for_each = length(var.producer_principals) > 0 ? [1] : []
    content {
      sid     = "AllowAssumeFromConfiguredPrincipals"
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = var.producer_principals
      }
    }
  }
  # Если список пуст, роль можно присвоить напрямую без Assume (например, EC2 Instance Profile).
}

data "aws_iam_policy_document" "assume_consumer" {
  dynamic "statement" {
    for_each = length(var.consumer_principals) > 0 ? [1] : []
    content {
      sid     = "AllowAssumeFromConfiguredPrincipals"
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = var.consumer_principals
      }
    }
  }
}

# Policies
data "aws_iam_policy_document" "producer_inline" {
  statement {
    sid     = "KinesisVideoPutMedia"
    effect  = "Allow"
    actions = [
      "kinesisvideo:PutMedia",
      "kinesisvideo:DescribeStream",
      "kinesisvideo:GetDataEndpoint"
    ]
    resources = [aws_kinesis_video_stream.this.arn]
  }

  statement {
    sid     = "S3WriteIngestPrefix"
    effect  = "Allow"
    actions = [
      "s3:PutObject",
      "s3:AbortMultipartUpload",
      "s3:ListBucketMultipartUploads",
      "s3:ListBucket",
      "s3:ListMultipartUploadParts"
    ]
    resources = [
      aws_s3_bucket.ingest.arn,
      "${aws_s3_bucket.ingest.arn}/*"
    ]
  }

  statement {
    sid     = "KMSUsage"
    effect  = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = [local.kms_key_arn]
  }
}

data "aws_iam_policy_document" "consumer_inline" {
  statement {
    sid     = "KinesisVideoGetMedia"
    effect  = "Allow"
    actions = [
      "kinesisvideo:GetMedia",
      "kinesisvideo:GetDataEndpoint",
      "kinesisvideo:DescribeStream"
    ]
    resources = [aws_kinesis_video_stream.this.arn]
  }

  statement {
    sid     = "SQSConsume"
    effect  = "Allow"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility"
    ]
    resources = [aws_sqs_queue.events.arn]
  }

  statement {
    sid     = "KMSUsage"
    effect  = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = [local.kms_key_arn]
  }
}

resource "aws_iam_role" "producer" {
  name               = "${local.base_name}-producer${local.name_suffix}"
  assume_role_policy = length(var.producer_principals) > 0 ? data.aws_iam_policy_document.assume_producer.json : jsonencode({
    Version = "2012-10-17"
    Statement = []
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "producer" {
  name   = "${local.base_name}-producer-policy"
  role   = aws_iam_role.producer.id
  policy = data.aws_iam_policy_document.producer_inline.json
}

resource "aws_iam_role" "consumer" {
  name               = "${local.base_name}-consumer${local.name_suffix}"
  assume_role_policy = length(var.consumer_principals) > 0 ? data.aws_iam_policy_document.assume_consumer.json : jsonencode({
    Version = "2012-10-17"
    Statement = []
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "consumer" {
  name   = "${local.base_name}-consumer-policy"
  role   = aws_iam_role.consumer.id
  policy = data.aws_iam_policy_document.consumer_inline.json
}

############################################
# Outputs
############################################

output "s3_bucket_name" {
  description = "Имя ingest S3 бакета."
  value       = aws_s3_bucket.ingest.id
}

output "s3_logs_bucket_name" {
  description = "Имя S3 бакета логов (если включено)."
  value       = try(aws_s3_bucket.logs[0].id, null)
}

output "sqs_queue_url" {
  description = "URL основной очереди событий."
  value       = aws_sqs_queue.events.id
}

output "sqs_queue_arn" {
  description = "ARN основной очереди событий."
  value       = aws_sqs_queue.events.arn
}

output "sqs_dlq_arn" {
  description = "ARN DLQ."
  value       = aws_sqs_queue.dlq.arn
}

output "kinesis_video_stream_arn" {
  description = "ARN потока Kinesis Video."
  value       = aws_kinesis_video_stream.this.arn
}

output "kms_key_arn" {
  description = "Используемый KMS-ключ."
  value       = local.kms_key_arn
}

output "producer_role_arn" {
  description = "ARN роли продьюсера."
  value       = aws_iam_role.producer.arn
}

output "consumer_role_arn" {
  description = "ARN роли консьюмера."
  value       = aws_iam_role.consumer.arn
}
