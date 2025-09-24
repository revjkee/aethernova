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
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }

  # В продакшне bucket/table должны существовать заранее (bootstrap).
  backend "s3" {
    bucket         = var.tf_state_bucket
    key            = "core-systems/security-core/dev/terraform.tfstate"
    region         = var.region
    dynamodb_table = var.tf_state_lock_table
    encrypt        = true
  }
}

############################
# Переменные dev‑окружения #
############################

variable "region" {
  description = "AWS регион"
  type        = string
  default     = "eu-north-1" # Стокгольм (для latency ближе к Europe/Stockholm)
}

variable "tf_state_bucket" {
  description = "S3 bucket для Terraform state (предсоздан)"
  type        = string
  default     = "neurocity-tf-state"
}

variable "tf_state_lock_table" {
  description = "DynamoDB таблица для блокировок Terraform state (предсоздана)"
  type        = string
  default     = "neurocity-tf-locks"
}

variable "cluster_name" {
  description = "Имя dev EKS‑кластера"
  type        = string
  default     = "eks-dev"
}

variable "k8s_namespace" {
  description = "Kubernetes namespace для security-core (dev)"
  type        = string
  default     = "security-core"
}

variable "sa_name" {
  description = "Имя ServiceAccount для IRSA"
  type        = string
  default     = "security-core"
}

variable "logs_retention_days" {
  description = "Срок хранения логов в CloudWatch, дней"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Общие теги"
  type        = map(string)
  default = {
    Project     = "NeuroCity"
    System      = "core-systems"
    Component   = "security-core"
    Environment = "dev"
    ManagedBy   = "Terraform"
  }
}

################
# Провайдеры   #
################

provider "aws" {
  region = var.region
  default_tags {
    tags = var.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# Подключение к существующему EKS‑кластеру (dev)
data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = var.cluster_name
}

# Провайдер Kubernetes поверх EKS
provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

# OIDC провайдер EKS для IRSA
data "aws_iam_openid_connect_provider" "eks" {
  url = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

locals {
  app_name             = "security-core"
  env                  = "dev"
  account_id           = data.aws_caller_identity.current.account_id
  partition            = data.aws_partition.current.partition
  oidc_url             = data.aws_iam_openid_connect_provider.eks.url
  oidc_hostpath        = replace(local.oidc_url, "https://", "")
  bucket_logs_name     = lower("nc-${local.app_name}-${local.env}-logs-${local.account_id}-${var.region}")
  bucket_logs_arn      = "arn:${local.partition}:s3:::${local.bucket_logs_name}"
  bucket_logs_objects  = "${local.bucket_logs_arn}/*"
  cw_log_group_name    = "/neurocity/${local.app_name}/${local.env}"
  sa_sub               = "system:serviceaccount:${var.k8s_namespace}:${var.sa_name}"
  # Полезный префикс для KMS alias
  kms_alias_name       = "alias/${local.app_name}-${local.env}-sse"
}

############################
# KMS: ключ для SSE‑KMS    #
############################

data "aws_iam_policy_document" "kms_key_policy" {
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

  # Разрешить приложению (через IAM роль IRSA) шифровать/дешифровать, только через S3‑сервис
  statement {
    sid    = "AllowAppViaS3Only"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.irsa.arn]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "sse" {
  description             = "SSE-KMS for ${local.app_name}-${local.env} logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms_key_policy.json
  tags                    = var.tags
}

resource "aws_kms_alias" "sse_alias" {
  name          = local.kms_alias_name
  target_key_id = aws_kms_key.sse.key_id
}

##########################################
# S3: бакет логов с принудительным шифром #
##########################################

resource "aws_s3_bucket" "logs" {
  bucket        = local.bucket_logs_name
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.sse.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
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
    expiration {
      days = 365
    }
  }
}

# Политика бакета: требуем TLS и SSE‑KMS, разрешаем доступ только роли приложения
data "aws_iam_policy_document" "bucket_policy" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [local.bucket_logs_arn, local.bucket_logs_objects]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyUnEncryptedUploads"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [local.bucket_logs_objects]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid    = "AllowAppRoleAccess"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation"
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.irsa.arn]
    }
    resources = [local.bucket_logs_arn]
  }

  statement {
    sid    = "AllowAppRoleObjectRW"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:AbortMultipartUpload"
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.irsa.arn]
    }
    resources = [local.bucket_logs_objects]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

############################
# CloudWatch Log Group     #
############################

resource "aws_cloudwatch_log_group" "app" {
  name              = local.cw_log_group_name
  retention_in_days = var.logs_retention_days
  kms_key_id        = aws_kms_key.sse.arn
  tags              = var.tags
}

#########################################
# IAM: роль для IRSA и политика доступа #
#########################################

# Политика доступа приложения к S3/KMS/CloudWatch
data "aws_iam_policy_document" "app" {
  statement {
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
    resources = [local.bucket_logs_arn, local.bucket_logs_objects]
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
    resources = [aws_kms_key.sse.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = ["${aws_cloudwatch_log_group.app.arn}:*"]
  }
}

resource "aws_iam_policy" "app" {
  name        = "${local.app_name}-${local.env}-policy"
  description = "Least-privilege policy for ${local.app_name} (${local.env})"
  policy      = data.aws_iam_policy_document.app.json
  tags        = var.tags
}

# IAM роль для IRSA (доверие к OIDC, ограничение по subject serviceaccount)
data "aws_iam_policy_document" "assume_irsa" {
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
  name               = "${local.app_name}-${local.env}-irsa"
  assume_role_policy = data.aws_iam_policy_document.assume_irsa.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "app" {
  role       = aws_iam_role.irsa.name
  policy_arn = aws_iam_policy.app.arn
}

############################
# Kubernetes: namespace/SA #
############################

resource "kubernetes_namespace" "security_core" {
  metadata {
    name = var.k8s_namespace
    labels = {
      "app.kubernetes.io/name"        = local.app_name
      "app.kubernetes.io/environment" = local.env
      "app.kubernetes.io/part-of"     = "core-systems"
      "app.kubernetes.io/component"   = "security-core"
    }
  }
}

# Внимание: если Pod задаёт automountServiceAccountToken=false,
# для IRSA потребуется projected token volume в манифесте Pod/Deployment.
resource "kubernetes_service_account" "security_core" {
  metadata {
    name      = var.sa_name
    namespace = kubernetes_namespace.security_core.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.irsa.arn
    }
    labels = {
      "app.kubernetes.io/name"        = local.app_name
      "app.kubernetes.io/environment" = local.env
    }
  }
  # automount_service_account_token по умолчанию true
}

########################
# Таймштамп (idempot.) #
########################

resource "time_static" "generated_at" {}

############
# Outputs  #
############

output "region" {
  value       = var.region
  description = "Регион AWS"
}

output "s3_logs_bucket" {
  value       = aws_s3_bucket.logs.bucket
  description = "S3 бакет для логов приложения"
}

output "kms_key_arn" {
  value       = aws_kms_key.sse.arn
  description = "KMS ключ для SSE‑KMS"
}

output "irsa_role_arn" {
  value       = aws_iam_role.irsa.arn
  description = "IAM роль для IRSA"
}

output "k8s_namespace" {
  value       = kubernetes_namespace.security_core.metadata[0].name
  description = "Namespace приложения в EKS"
}

output "service_account_name" {
  value       = kubernetes_service_account.security_core.metadata[0].name
  description = "ServiceAccount с аннотацией IRSA"
}
