############################
# Security-Core Staging Module (AWS + EKS)
# - KMS key (optional) for SSE-KMS
# - S3 logs bucket (TLS-only, SSE-KMS enforced)
# - CloudWatch Log Group (KMS)
# - IRSA role & policy (least-privilege)
# - Kubernetes namespace & ServiceAccount (IRSA)
#
# Notes:
# - Providers are expected to be configured in the root module:
#     provider "aws" { ... }
#     provider "kubernetes" { ... }
# - No backend here (module file).
############################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.29"
    }
  }
}

################
# Input Vars   #
################

variable "region" {
  description = "AWS регион."
  type        = string
}

variable "cluster_name" {
  description = "Имя EKS кластера."
  type        = string
}

variable "k8s_namespace" {
  description = "Namespace в Kubernetes для security-core."
  type        = string
  default     = "security-core"
}

variable "service_account_name" {
  description = "Имя ServiceAccount для IRSA."
  type        = string
  default     = "security-core"
}

variable "environment" {
  description = "Окружение (staging)."
  type        = string
  default     = "staging"
}

variable "app_name" {
  description = "Имя приложения."
  type        = string
  default     = "security-core"
}

variable "tags" {
  description = "Общие теги."
  type        = map(string)
  default = {
    Project     = "NeuroCity"
    System      = "core-systems"
    Component   = "security-core"
    Environment = "staging"
    ManagedBy   = "Terraform"
  }
}

# Feature flags
variable "create_kms_key" {
  description = "Создавать KMS-ключ для SSE-KMS."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Существующий KMS-ключ (если create_kms_key=false)."
  type        = string
  default     = ""
}

variable "create_s3_logs_bucket" {
  description = "Создавать S3 бакет для логов."
  type        = bool
  default     = true
}

variable "create_cw_log_group" {
  description = "Создавать CloudWatch Log Group."
  type        = bool
  default     = true
}

variable "logs_retention_days" {
  description = "Срок хранения логов в CloudWatch."
  type        = number
  default     = 30
}

variable "create_irsa" {
  description = "Создавать IAM роль и политику для IRSA."
  type        = bool
  default     = true
}

variable "extra_irsa_policy_json" {
  description = "Дополнительная JSON-политика (будет добавлена к минимальной)."
  type        = string
  default     = ""
}

variable "create_namespace" {
  description = "Создавать namespace и ServiceAccount в Kubernetes."
  type        = bool
  default     = true
}

#########################
# Data & Local Values   #
#########################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# EKS cluster and OIDC
data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = var.cluster_name
}

# Resolve OIDC provider from cluster identity
data "aws_iam_openid_connect_provider" "eks" {
  url = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

locals {
  partition      = data.aws_partition.current.partition
  account_id     = data.aws_caller_identity.current.account_id
  oidc_url       = data.aws_iam_openid_connect_provider.eks.url
  oidc_hostpath  = replace(local.oidc_url, "https://", "")
  sa_sub         = "system:serviceaccount:${var.k8s_namespace}:${var.service_account_name}"

  # Names
  bucket_logs_name = lower("nc-${var.app_name}-${var.environment}-logs-${local.account_id}-${var.region}")
  cw_log_group     = "/neurocity/${var.app_name}/${var.environment}"
  kms_alias_name   = "alias/${var.app_name}-${var.environment}-sse"

  # ARNs
  bucket_arn  = "arn:${local.partition}:s3:::${local.bucket_logs_name}"
  objects_arn = "${local.bucket_arn}/*"
}

############################
# KMS (optional create)    #
############################

data "aws_iam_policy_document" "kms_key_policy" {
  count = var.create_kms_key ? 1 : 0

  statement {
    sid     = "AllowRootAccountAdmin"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
    resources = ["*"]
  }

  # Доступ для IRSA роли (создаётся ниже) через S3-сервис
  # Привязка к роли задана позже с использованием aws_iam_role.irsa.arn через depends_on.
  # Здесь для корректности добавим placeholder, будет обновлён после создания роли.
}

resource "aws_kms_key" "sse" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "SSE-KMS for ${var.app_name}-${var.environment} logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = element([data.aws_iam_policy_document.kms_key_policy[0].json], 0)
  tags                    = var.tags
}

resource "aws_kms_alias" "sse_alias" {
  count        = var.create_kms_key ? 1 : 0
  name         = local.kms_alias_name
  target_key_id = aws_kms_key.sse[0].key_id
}

locals {
  effective_kms_key_arn = var.create_kms_key ? aws_kms_key.sse[0].arn : var.kms_key_arn
}

############################
# S3 Logs (optional)       #
############################

resource "aws_s3_bucket" "logs" {
  count         = var.create_s3_logs_bucket ? 1 : 0
  bucket        = local.bucket_logs_name
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = var.create_s3_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.create_s3_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.effective_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = var.create_s3_logs_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = var.create_s3_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    id     = "retain-and-transition"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
    expiration { days = 365 }
  }
}

# Bucket policy: enforce TLS + SSE-KMS, app role will be injected later
data "aws_iam_policy_document" "bucket_policy_base" {
  count = var.create_s3_logs_bucket ? 1 : 0

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals { type = "*"; identifiers = ["*"] }
    resources = [local.bucket_arn, local.objects_arn]
    condition { test = "Bool"; variable = "aws:SecureTransport"; values = ["false"] }
  }

  statement {
    sid     = "DenyUnEncryptedUploads"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals { type = "*"; identifiers = ["*"] }
    resources = [local.objects_arn]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

############################
# CloudWatch Logs (opt.)   #
############################

resource "aws_cloudwatch_log_group" "app" {
  count             = var.create_cw_log_group ? 1 : 0
  name              = local.cw_log_group
  retention_in_days = var.logs_retention_days
  kms_key_id        = local.effective_kms_key_arn
  tags              = var.tags
}

############################
# IRSA (optional)          #
############################

# Least-privilege policy for app to S3/KMS/CW
data "aws_iam_policy_document" "app" {
  count = var.create_irsa ? 1 : 0

  dynamic "statement" {
    for_each = var.create_s3_logs_bucket ? [1] : []
    content {
      sid    = "S3Access"
      effect = "Allow"
      actions = [
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload"
      ]
      resources = [local.bucket_arn, local.objects_arn]
    }
  }

  statement {
    sid    = "KMSForS3"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = [local.effective_kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }

  dynamic "statement" {
    for_each = var.create_cw_log_group ? [1] : []
    content {
      sid    = "CloudWatchLogs"
      effect = "Allow"
      actions = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ]
      resources = ["${aws_cloudwatch_log_group.app[0].arn}:*"]
    }
  }
}

resource "aws_iam_policy" "app" {
  count       = var.create_irsa ? 1 : 0
  name        = "${var.app_name}-${var.environment}-policy"
  description = "Least-privilege policy for ${var.app_name} (${var.environment})"
  policy      = data.aws_iam_policy_document.app[0].json
  tags        = var.tags
}

# Optional extra policy attachment (JSON string merged as inline policy)
resource "aws_iam_policy" "app_extra" {
  count       = var.create_irsa && length(trim(var.extra_irsa_policy_json)) > 0 ? 1 : 0
  name        = "${var.app_name}-${var.environment}-policy-extra"
  description = "Extra policy for ${var.app_name} (${var.environment})"
  policy      = var.extra_irsa_policy_json
  tags        = var.tags
}

data "aws_iam_policy_document" "assume_irsa" {
  count = var.create_irsa ? 1 : 0
  statement {
    sid     = "IRSAFederation"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.eks.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_hostpath}:sub"
      values   = [local.sa_sub]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_hostpath}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "irsa" {
  count              = var.create_irsa ? 1 : 0
  name               = "${var.app_name}-${var.environment}-irsa"
  assume_role_policy = data.aws_iam_policy_document.assume_irsa[0].json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "app" {
  count      = var.create_irsa ? 1 : 0
  role       = aws_iam_role.irsa[0].name
  policy_arn = aws_iam_policy.app[0].arn
}

resource "aws_iam_role_policy_attachment" "app_extra" {
  count      = var.create_irsa && length(trim(var.extra_irsa_policy_json)) > 0 ? 1 : 0
  role       = aws_iam_role.irsa[0].name
  policy_arn = aws_iam_policy.app_extra[0].arn
}

# Now finalize bucket policy with app role (if both created)
data "aws_iam_policy_document" "bucket_policy_full" {
  count = var.create_s3_logs_bucket ? 1 : 0

  source_json = data.aws_iam_policy_document.bucket_policy_base[0].json

  dynamic "statement" {
    for_each = var.create_irsa ? [1] : []
    content {
      sid    = "AllowAppRoleBucket"
      effect = "Allow"
      actions = [
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ]
      principals {
        type        = "AWS"
        identifiers = [aws_iam_role.irsa[0].arn]
      }
      resources = [local.bucket_arn]
    }
  }

  dynamic "statement" {
    for_each = var.create_irsa ? [1] : []
    content {
      sid    = "AllowAppRoleObjects"
      effect = "Allow"
      actions = [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload"
      ]
      principals {
        type        = "AWS"
        identifiers = [aws_iam_role.irsa[0].arn]
      }
      resources = [local.objects_arn]
      condition {
        test     = "StringEquals"
        variable = "s3:x-amz-server-side-encryption"
        values   = ["aws:kms"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  count  = var.create_s3_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  policy = data.aws_iam_policy_document.bucket_policy_full[0].json

  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.logs,
    aws_s3_bucket_public_access_block.logs
  ]
}

############################
# Kubernetes NS & SA       #
############################

resource "kubernetes_namespace" "ns" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name = var.k8s_namespace
    labels = {
      "app.kubernetes.io/name"        = var.app_name
      "app.kubernetes.io/environment" = var.environment
      "app.kubernetes.io/part-of"     = "core-systems"
      "app.kubernetes.io/component"   = "security-core"
    }
  }
}

resource "kubernetes_service_account" "sa" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name      = var.service_account_name
    namespace = var.k8s_namespace
    annotations = var.create_irsa ? {
      "eks.amazonaws.com/role-arn" = aws_iam_role.irsa[0].arn
    } : {}
    labels = {
      "app.kubernetes.io/name"        = var.app_name
      "app.kubernetes.io/environment" = var.environment
    }
  }
}

################
# Outputs      #
################

output "kms_key_arn" {
  description = "Используемый KMS ключ (созданный или внешний)."
  value       = local.effective_kms_key_arn
}

output "s3_logs_bucket" {
  description = "Имя S3 бакета для логов (если создан)."
  value       = var.create_s3_logs_bucket ? aws_s3_bucket.logs[0].bucket : null
}

output "cw_log_group_name" {
  description = "Имя CloudWatch Log Group (если создан)."
  value       = var.create_cw_log_group ? aws_cloudwatch_log_group.app[0].name : null
}

output "irsa_role_arn" {
  description = "ARN IAM роли для IRSA (если создана)."
  value       = var.create_irsa ? aws_iam_role.irsa[0].arn : null
}

output "namespace" {
  description = "Namespace Kubernetes (если создан)."
  value       = var.create_namespace ? var.k8s_namespace : null
}

output "service_account" {
  description = "ServiceAccount Kubernetes (если создан)."
  value       = var.create_namespace ? var.service_account_name : null
}
