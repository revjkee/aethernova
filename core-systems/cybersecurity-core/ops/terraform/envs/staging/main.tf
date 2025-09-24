terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  # Настройте backend через `terraform init -backend-config=...`
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.1"
    }
  }
}

################################################################################
# Provider & Globals
################################################################################

variable "aws_region" {
  description = "AWS регион для среды staging."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d$", var.aws_region))
    error_message = "aws_region должен быть в формате, например: eu-north-1."
  }
}

variable "org" {
  description = "Организация (краткое имя, латиницей)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]{2,32}$", var.org))
    error_message = "org может содержать только [a-z0-9-], длина 2..32."
  }
}

variable "project" {
  description = "Название проекта (краткое имя, латиницей)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]{2,32}$", var.project))
    error_message = "project может содержать только [a-z0-9-], длина 2..32."
  }
}

variable "tags" {
  description = "Дополнительные тэги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "enable_kms" {
  description = "Включить создание KMS CMK для шифрования журналов."
  type        = bool
  default     = true
}

variable "enable_logs_bucket" {
  description = "Включить защищённый S3 bucket для журналов."
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Включить CloudTrail с шифрованием и доставкой в S3 и CloudWatch."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Включить GuardDuty detector."
  type        = bool
  default     = true
}

variable "enable_securityhub" {
  description = "Включить Security Hub и подписку на стандарты."
  type        = bool
  default     = true
}

variable "cloudtrail_s3_data_events" {
  description = "Логировать события доступа к S3 объектам (data events)."
  type        = bool
  default     = false
}

variable "log_object_retention_days" {
  description = "Срок хранения S3 логов (дней) до перехода/удаления."
  type        = number
  default     = 365
}

# Имя бакета опционально — генерируется, если не задано.
variable "logs_bucket_name_override" {
  description = "Необязательно. Явное имя S3 bucket для логов; должно быть глобально уникальным."
  type        = string
  default     = null
}

locals {
  environment = "staging"

  name_prefix = lower(join("-", compact([
    var.org,
    var.project,
    local.environment
  ])))

  default_tags = merge(
    {
      "owner"            = var.org
      "project"          = var.project
      "environment"      = local.environment
      "managed-by"       = "terraform"
      "security-domain"  = "cybersecurity-core"
      "compliance"       = "baseline"
    },
    var.tags
  )
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.default_tags
  }
}

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

################################################################################
# KMS — Customer Managed Key для логов (опционально)
################################################################################

resource "aws_kms_key" "logs" {
  count                   = var.enable_kms ? 1 : 0
  description             = "${local.name_prefix}-logs-kms"
  enable_key_rotation     = true
  multi_region            = false
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Доступ владельцу аккаунта
      {
        Sid      = "EnableRootPermissions"
        Effect   = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.this.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      # Разрешить CloudTrail использовать ключ для шифрования
      {
        Sid    = "AllowCloudTrailEncrypt"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.this.account_id
          }
        }
      },
      # Разрешить CloudWatch Logs использовать ключ при необходимости
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "logs" {
  count         = var.enable_kms ? 1 : 0
  name          = "alias/${local.name_prefix}-logs"
  target_key_id = aws_kms_key.logs[0].key_id
}

################################################################################
# S3 bucket для логов (опционально)
################################################################################

resource "random_id" "suffix" {
  byte_length = 2
}

locals {
  logs_bucket_name = coalesce(
    var.logs_bucket_name_override,
    "${local.name_prefix}-logs-${random_id.suffix.hex}"
  )
}

resource "aws_s3_bucket" "logs" {
  count  = var.enable_logs_bucket ? 1 : 0
  bucket = local.logs_bucket_name

  # Включено версионирование, без публичного доступа
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = var.enable_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.enable_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = var.enable_logs_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.enable_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.enable_kms ? "aws:kms" : "AES256"
      kms_master_key_id = var.enable_kms ? aws_kms_key.logs[0].arn : null
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = var.enable_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    id     = "retain-and-optimize"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = var.log_object_retention_days
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.log_object_retention_days
    }
  }
}

# Политика для доставки CloudTrail логов в S3
resource "aws_s3_bucket_policy" "logs_allow_cloudtrail" {
  count  = var.enable_logs_bucket && var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AWSCloudTrailAclCheck"
        Effect   = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.logs[0].arn
      },
      {
        Sid      = "AWSCloudTrailWrite"
        Effect   = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs[0].arn}/AWSLogs/${data.aws_caller_identity.this.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

################################################################################
# CloudWatch Log Group для CloudTrail
################################################################################

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudtrail ? 1 : 0
  name              = "/aws/cloudtrail/${local.name_prefix}"
  retention_in_days = 365
  kms_key_id        = var.enable_kms ? aws_kms_key.logs[0].arn : null

  tags = local.default_tags
}

################################################################################
# CloudTrail (мульти-регион, с валидацией файлов и KMS)
################################################################################

resource "aws_cloudtrail" "this" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.logs[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = var.enable_kms ? aws_kms_key.logs[0].arn : null
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_cw[0].arn

  # Management events
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  dynamic "event_selector" {
    for_each = var.cloudtrail_s3_data_events ? [1] : []
    content {
      read_write_type           = "All"
      include_management_events = false
      data_resource {
        type   = "AWS::S3::Object"
        values = ["arn:aws:s3:::"]
      }
    }
  }

  depends_on = [
    aws_s3_bucket_policy.logs_allow_cloudtrail
  ]

  tags = local.default_tags
}

# Роль для доставки логов CloudTrail в CloudWatch Logs
resource "aws_iam_role" "cloudtrail_to_cw" {
  count              = var.enable_cloudtrail ? 1 : 0
  name               = "${local.name_prefix}-cloudtrail-to-cw"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json

  tags = local.default_tags
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_to_cw" {
  count = var.enable_cloudtrail ? 1 : 0
  name  = "${local.name_prefix}-cloudtrail-to-cw"
  role  = aws_iam_role.cloudtrail_to_cw[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ],
        Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
      },
      {
        Effect   = "Allow",
        Action   = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = var.enable_kms ? aws_kms_key.logs[0].arn : "*"
      }
    ]
  })
}

################################################################################
# GuardDuty (включение детектора)
################################################################################

resource "aws_guardduty_detector" "this" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes = true
      }
    }
  }

  tags = local.default_tags
}

################################################################################
# Security Hub + стандарты (AWS Foundational, CIS)
################################################################################

resource "aws_securityhub_account" "this" {
  count = var.enable_securityhub ? 1 : 0
  tags  = local.default_tags
}

# AWS Foundational Security Best Practices v1.0.0
resource "aws_securityhub_standards_subscription" "foundational" {
  count        = var.enable_securityhub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.this]
}

# CIS AWS Foundations Benchmark v1.4.0
resource "aws_securityhub_standards_subscription" "cis" {
  count        = var.enable_securityhub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_account.this]
}

################################################################################
# Outputs
################################################################################

output "account_id" {
  description = "ID AWS аккаунта."
  value       = data.aws_caller_identity.this.account_id
}

output "region" {
  description = "Регион AWS."
  value       = var.aws_region
}

output "logs_bucket_name" {
  description = "Имя S3 бакета для логов."
  value       = var.enable_logs_bucket ? aws_s3_bucket.logs[0].bucket : null
}

output "kms_key_arn" {
  description = "ARN KMS для шифрования логов."
  value       = var.enable_kms ? aws_kms_key.logs[0].arn : null
}

output "cloudtrail_arn" {
  description = "ARN CloudTrail."
  value       = var.enable_cloudtrail ? aws_cloudtrail.this[0].arn : null
}

output "guardduty_detector_id" {
  description = "ID GuardDuty детектора."
  value       = var.enable_guardduty ? aws_guardduty_detector.this[0].id : null
}
