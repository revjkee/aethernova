terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.55.0"
    }
  }

  # Настройте backend в terraform.tfbackend или через CLI:
  # terraform init -backend-config="bucket=YOUR_TFSTATE_BUCKET" -backend-config="key=policy-core/staging.tfstate" -backend-config="region=eu-north-1" -backend-config="dynamodb_table=YOUR_LOCK_TABLE" -backend-config="encrypt=true"
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

# ----------------------------- Конвенции имен -------------------------------
locals {
  env                     = "staging"
  name_prefix             = "${var.org}-${var.system}-policy-core-${local.env}"
  tags_common = merge(var.tags, {
    "Environment"         = local.env
    "System"              = var.system
    "Org"                 = var.org
    "ManagedBy"           = "Terraform"
    "ZeroTrust"           = "true"
    "Component"           = "policy-core"
  })
}

# -------------------------- KMS для шифрования ------------------------------
resource "aws_kms_key" "policy_core" {
  description             = "KMS CMK for ${local.name_prefix} (S3 objects, parameters, future needs)"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Админ-доступ для аккаунта (root)
      {
        Sid      = "EnableRootPermissions"
        Effect   = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = ["kms:*"]
        Resource = "*"
      }
    ]
  })

  tags = local.tags_common
}

resource "aws_kms_alias" "policy_core" {
  name          = "alias/${var.kms_alias != "" ? var.kms_alias : local.name_prefix}"
  target_key_id = aws_kms_key.policy_core.key_id
}

data "aws_caller_identity" "current" {}

# ------------------------------ S3 под бандлы -------------------------------
resource "aws_s3_bucket" "bundles" {
  bucket = var.s3_bucket_name != "" ? var.s3_bucket_name : "${local.name_prefix}-bundles"
  tags   = local.tags_common

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "bundles" {
  bucket = aws_s3_bucket.bundles.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bundles" {
  bucket = aws_s3_bucket.bundles.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.policy_core.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "bundles" {
  bucket                  = aws_s3_bucket.bundles.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Политика бакета: запрещаем не-TLS, требуем SSE-KMS, ограничиваем список команд
data "aws_iam_policy_document" "bundles_bucket_policy" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals { type = "*" identifiers = ["*"] }
    resources = [
      aws_s3_bucket.bundles.arn,
      "${aws_s3_bucket.bundles.arn}/*"
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
    principals { type = "*" identifiers = ["*"] }
    resources = ["${aws_s3_bucket.bundles.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid     = "DenyWrongKmsKey"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals { type = "*" identifiers = ["*"] }
    resources = ["${aws_s3_bucket.bundles.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.policy_core.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "bundles" {
  bucket = aws_s3_bucket.bundles.id
  policy = data.aws_iam_policy_document.bundles_bucket_policy.json
}

# ------------------------------- CloudWatch Logs ----------------------------
resource "aws_cloudwatch_log_group" "policy_core" {
  name              = "/${var.system}/${local.env}/policy-core"
  retention_in_days = var.logs_retention_days
  kms_key_id        = aws_kms_key.policy_core.arn
  tags              = local.tags_common
}

# ------------------------------ EKS OIDC (IRSA) -----------------------------
# Ожидается существующий EKS-кластер; находим OIDC provider и строим trust policy
data "aws_eks_cluster" "this" {
  name = var.eks_cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = var.eks_cluster_name
}

data "aws_iam_openid_connect_provider" "eks" {
  arn = var.eks_oidc_provider_arn
}

# Под каким ServiceAccount работает policy-core
locals {
  sa_namespace = var.k8s_namespace
  sa_name      = var.k8s_service_account
  oidc_thumb   = split("/", data.aws_iam_openid_connect_provider.eks.arn)[length(split("/", data.aws_iam_openid_connect_provider.eks.arn)) - 1]
  oidc_url     = data.aws_iam_openid_connect_provider.eks.url
}

data "aws_iam_policy_document" "irsa_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.eks.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(local.oidc_url, "https://", "")}:sub"
      values   = ["system:serviceaccount:${local.sa_namespace}:${local.sa_name}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(local.oidc_url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "policy_core" {
  name               = "${local.name_prefix}-irsa"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume_role.json
  tags               = local.tags_common
}

# ------------------------------- IAM Policy ---------------------------------
# Минимальные права: чтение объектов в S3-бакете бандлов, KMS:Decrypt, опционально SSM:GetParameter для ключей верификации
data "aws_iam_policy_document" "policy_core" {
  statement {
    sid    = "S3ReadBundles"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.bundles.arn,
      "${aws_s3_bucket.bundles.arn}/*"
    ]
  }

  statement {
    sid    = "KMSDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.policy_core.arn]
  }

  # Опционально: хранить публичные ключи/конфиг в SSM Parameter Store (SecureString/String)
  dynamic "statement" {
    for_each = var.enable_ssm_access ? [1] : []
    content {
      sid    = "SSMReadKeys"
      effect = "Allow"
      actions = [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParameterHistory"
      ]
      resources = [
        for p in var.ssm_parameter_arns : p
      ]
    }
  }

  # Разрешаем запись логов в CloudWatch, если sidecar/агент отправляет напрямую
  statement {
    sid    = "LogsWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = [
      "${aws_cloudwatch_log_group.policy_core.arn}:*"
    ]
  }
}

resource "aws_iam_policy" "policy_core" {
  name   = "${local.name_prefix}-policy"
  policy = data.aws_iam_policy_document.policy_core.json
  tags   = local.tags_common
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.policy_core.name
  policy_arn = aws_iam_policy.policy_core.arn
}

# ------------------------------- Выходные данные ----------------------------
output "s3_bundles_bucket" {
  value       = aws_s3_bucket.bundles.bucket
  description = "S3 bucket name for policy bundles"
}

output "kms_key_arn" {
  value       = aws_kms_key.policy_core.arn
  description = "KMS CMK ARN used for encryption/decryption"
}

output "iam_role_arn" {
  value       = aws_iam_role.policy_core.arn
  description = "IRSA role ARN to bind with Kubernetes ServiceAccount"
}

output "log_group_name" {
  value       = aws_cloudwatch_log_group.policy_core.name
  description = "CloudWatch Log Group for policy-core"
}

# -------------------------------- Переменные --------------------------------
variable "aws_region" {
  description = "AWS region (e.g., eu-north-1)"
  type        = string
  default     = "eu-north-1"
}

variable "org" {
  description = "Организация/tenant (кратко)"
  type        = string
}

variable "system" {
  description = "Система/проект (например, neurocity)"
  type        = string
}

variable "tags" {
  description = "Дополнительные теги"
  type        = map(string)
  default     = {}
}

variable "s3_bucket_name" {
  description = "Имя S3-бакета для бандлов (по умолчанию генерируется)"
  type        = string
  default     = ""
}

variable "kms_alias" {
  description = "Псевдоним для KMS ключа (по умолчанию генерируется)"
  type        = string
  default     = ""
}

variable "logs_retention_days" {
  description = "Хранение логов в днях"
  type        = number
  default     = 30
}

variable "eks_cluster_name" {
  description = "Имя существующего EKS кластера"
  type        = string
}

variable "eks_oidc_provider_arn" {
  description = "ARN OIDC провайдера EKS (IRSA)"
  type        = string
}

variable "k8s_namespace" {
  description = "Namespace Kubernetes, где работает policy-core"
  type        = string
  default     = "policy-core"
}

variable "k8s_service_account" {
  description = "ServiceAccount Kubernetes, к которому привязываем IRSA роль"
  type        = string
  default     = "policy-core"
}

variable "enable_ssm_access" {
  description = "Разрешить чтение параметров из SSM Parameter Store (публичные ключи/конфиг)"
  type        = bool
  default     = false
}

variable "ssm_parameter_arns" {
  description = "Список ARNs параметров SSM, к которым разрешено чтение (активно при enable_ssm_access=true)"
  type        = list(string)
  default     = []
}

# --------------------------------- Примечания --------------------------------
# 1) Привязка IRSA: укажите аннотацию в ServiceAccount Helm chart'а:
#    eks.amazonaws.com/role-arn: <вывод iam_role_arn>
# 2) Деплой: Terraform создаёт бакет, ключ, роль и политики; Helm монтирует роль в Pod.
# 3) Безопасность: бакет публично недоступен; запрещён не-TLS; принудительная SSE-KMS; KMS rotation=true.
# 4) Согласованность: лог-группа шифрована KMS; теги применены ко всем ресурсам.
