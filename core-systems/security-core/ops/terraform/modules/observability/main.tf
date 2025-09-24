terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.27"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13"
    }
  }
}

# ------------------------------- ВХОДНЫЕ ДАННЫЕ -------------------------------

variable "name_prefix" {
  description = "Префикс для имен ресурсов (например, org-prod)."
  type        = string
}

variable "tags" {
  description = "Общие тэги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "namespace" {
  description = "Kubernetes namespace для observability объектов."
  type        = string
  default     = "observability"
}

# AWS регион (не обязателен, можно взять текущий)
variable "region" {
  description = "AWS регион (если не указан — data.aws_region.current)."
  type        = string
  default     = null
}

# --- KMS ---
variable "create_kms_key" {
  description = "Создавать собственный KMS ключ для S3."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Существующий KMS ключ (если create_kms_key=false)."
  type        = string
  default     = null
}

# --- S3 Loki / Tempo ---
variable "create_buckets" {
  description = "Создавать S3 бакеты для Loki/Tempo."
  type        = bool
  default     = true
}

variable "loki_s3_bucket_name" {
  description = "Имя S3 бакета для Loki (если пусто — сформируется автоматически)."
  type        = string
  default     = null
}

variable "tempo_s3_bucket_name" {
  description = "Имя S3 бакета для Tempo (если пусто — сформируется автоматически)."
  type        = string
  default     = null
}

variable "logs_retention_days" {
  description = "Ретенция для логов (Loki) в днях."
  type        = number
  default     = 30
}

variable "traces_retention_days" {
  description = "Ретенция для трейсов (Tempo) в днях."
  type        = number
  default     = 14
}

variable "force_destroy" {
  description = "Разрешить удаление S3 с объектами (только при осознанной необходимости)."
  type        = bool
  default     = false
}

# --- IRSA (IAM Roles for Service Accounts) ---
variable "enable_irsa" {
  description = "Включить создание IRSA-ролей для Loki/Tempo/OTEL."
  type        = bool
  default     = true
}

variable "eks_cluster_name" {
  description = "Имя EKS кластера (для меток/аудита)."
  type        = string
  default     = ""
}

variable "oidc_provider_arn" {
  description = "ARN OIDC-провайдера кластера (eks)."
  type        = string
  default     = ""
}

variable "oidc_provider_url" {
  description = "Issuer URL OIDC провайдера (например, https://oidc.eks.<region>.amazonaws.com/id/<ID>)."
  type        = string
  default     = ""
}

variable "sa_name_loki" {
  description = "Имя ServiceAccount для Loki."
  type        = string
  default     = "loki"
}

variable "sa_name_tempo" {
  description = "Имя ServiceAccount для Tempo."
  type        = string
  default     = "tempo"
}

variable "sa_name_otel" {
  description = "Имя ServiceAccount для OpenTelemetry Collector."
  type        = string
  default     = "otel-collector"
}

# --- Helm релизы (по умолчанию выключены) ---
variable "enable_kube_prometheus_stack" {
  description = "Установить kube-prometheus-stack через Helm."
  type        = bool
  default     = false
}

variable "enable_loki" {
  description = "Установить Loki через Helm."
  type        = bool
  default     = false
}

variable "enable_tempo" {
  description = "Установить Tempo через Helm."
  type        = bool
  default     = false
}

variable "enable_otel_collector" {
  description = "Установить OpenTelemetry Collector через Helm."
  type        = bool
  default     = false
}

# Пользовательские values для Helm (YAML-строки)
variable "kps_values_yaml" {
  description = "Доп. values.yaml для kube-prometheus-stack."
  type        = string
  default     = ""
}

variable "loki_values_yaml" {
  description = "Доп. values.yaml для Loki."
  type        = string
  default     = ""
}

variable "tempo_values_yaml" {
  description = "Доп. values.yaml для Tempo."
  type        = string
  default     = ""
}

variable "otel_values_yaml" {
  description = "Доп. values.yaml для OpenTelemetry Collector."
  type        = string
  default     = ""
}

# ------------------------------- ЛОКАЛЫ ---------------------------------------

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  region             = coalesce(var.region, data.aws_region.current.name)
  name_norm          = replace(var.name_prefix, "/[^a-zA-Z0-9-]/", "-")
  common_tags = merge({
    "Project"     = "security-core"
    "Component"   = "observability"
    "ManagedBy"   = "terraform"
    "Environment" = "shared"
  }, var.tags)

  # OIDC issuer без https://
  oidc_issuer_hostpath = trim(replace(var.oidc_provider_url, "https://", ""), "/")

  # Автоназвания бакетов
  loki_bucket_auto  = lower("${local.name_norm}-loki-${local.region}-${data.aws_caller_identity.current.account_id}")
  tempo_bucket_auto = lower("${local.name_norm}-tempo-${local.region}-${data.aws_caller_identity.current.account_id}")
}

# ------------------------------- KMS КЛЮЧ -------------------------------------

resource "aws_kms_key" "this" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "KMS key for ${var.name_prefix} observability (Loki/Tempo)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

resource "aws_kms_alias" "this" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/${local.name_norm}-observability"
  target_key_id = aws_kms_key.this[0].key_id
}

locals {
  kms_arn_effective = var.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn
}

# ------------------------------- S3 БАКЕТЫ ------------------------------------

# Общая политика S3: только TLS, только шифрование, KMS по умолчанию
data "aws_iam_policy_document" "s3_secure_base" {
  statement {
    sid     = "DenyInsecureTransport"
    actions = ["s3:*"]
    effect  = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyIncorrectEncryptionHeader"
    actions = ["s3:PutObject"]
    effect  = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid     = "DenyUnEncryptedObjectUploads"
    actions = ["s3:PutObject"]
    effect  = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["*"]
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }
}

# Loki bucket
resource "aws_s3_bucket" "loki" {
  count  = var.create_buckets && var.enable_loki ? 1 : 0
  bucket = coalesce(var.loki_s3_bucket_name, local.loki_bucket_auto)
  force_destroy = var.force_destroy
  tags  = merge(local.common_tags, { "Name" = "loki" })
}

resource "aws_s3_bucket_versioning" "loki" {
  count  = length(aws_s3_bucket.loki) > 0 ? 1 : 0
  bucket = aws_s3_bucket.loki[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "loki" {
  count  = length(aws_s3_bucket.loki) > 0 ? 1 : 0
  bucket = aws_s3_bucket.loki[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_arn_effective
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "loki" {
  count  = length(aws_s3_bucket.loki) > 0 ? 1 : 0
  bucket = aws_s3_bucket.loki[0].id
  rule {
    id     = "retention"
    status = "Enabled"
    expiration {
      days = var.logs_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.logs_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "loki" {
  count  = length(aws_s3_bucket.loki) > 0 ? 1 : 0
  bucket = aws_s3_bucket.loki[0].id
  policy = data.aws_iam_policy_document.s3_secure_loki[count.index].json
}

data "aws_iam_policy_document" "s3_secure_loki" {
  count = length(aws_s3_bucket.loki) > 0 ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.s3_secure_base.json]

  statement {
    sid     = "DenyWrongKmsKey"
    actions = ["s3:PutObject"]
    effect  = "Deny"
    principals { type = "*", identifiers = ["*"] }
    resources = ["${aws_s3_bucket.loki[0].arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [local.kms_arn_effective]
    }
  }
}

# Tempo bucket
resource "aws_s3_bucket" "tempo" {
  count  = var.create_buckets && var.enable_tempo ? 1 : 0
  bucket = coalesce(var.tempo_s3_bucket_name, local.tempo_bucket_auto)
  force_destroy = var.force_destroy
  tags  = merge(local.common_tags, { "Name" = "tempo" })
}

resource "aws_s3_bucket_versioning" "tempo" {
  count  = length(aws_s3_bucket.tempo) > 0 ? 1 : 0
  bucket = aws_s3_bucket.tempo[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tempo" {
  count  = length(aws_s3_bucket.tempo) > 0 ? 1 : 0
  bucket = aws_s3_bucket.tempo[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_arn_effective
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "tempo" {
  count  = length(aws_s3_bucket.tempo) > 0 ? 1 : 0
  bucket = aws_s3_bucket.tempo[0].id
  rule {
    id     = "retention"
    status = "Enabled"
    expiration {
      days = var.traces_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.traces_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "tempo" {
  count  = length(aws_s3_bucket.tempo) > 0 ? 1 : 0
  bucket = aws_s3_bucket.tempo[0].id
  policy = data.aws_iam_policy_document.s3_secure_tempo[count.index].json
}

data "aws_iam_policy_document" "s3_secure_tempo" {
  count = length(aws_s3_bucket.tempo) > 0 ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.s3_secure_base.json]

  statement {
    sid     = "DenyWrongKmsKey"
    actions = ["s3:PutObject"]
    effect  = "Deny"
    principals { type = "*", identifiers = ["*"] }
    resources = ["${aws_s3_bucket.tempo[0].arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [local.kms_arn_effective]
    }
  }
}

# ------------------------------- IRSA РОЛИ ------------------------------------

# Прекращаем создание ролей, если IRSA отключен или не указан OIDC
locals {
  irsa_enabled = var.enable_irsa && var.oidc_provider_arn != "" && var.oidc_provider_url != ""
}

# Общий trust policy для сервис-аккаунтов
data "aws_iam_policy_document" "irsa_trust" {
  count = local.irsa_enabled ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer_hostpath}:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Имя SA конкретизируем в каждой роли через подмену
  }
}

# Права S3 для Loki
data "aws_iam_policy_document" "loki_s3" {
  count = local.irsa_enabled && var.enable_loki ? 1 : 0

  statement {
    sid     = "BucketLevel"
    actions = ["s3:GetBucketLocation", "s3:ListBucket"]
    effect  = "Allow"
    resources = [
      aws_s3_bucket.loki[0].arn
    ]
  }

  statement {
    sid     = "ObjectLevel"
    actions = [
      "s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload",
      "s3:DeleteObject", "s3:ListBucketMultipartUploads"
    ]
    effect    = "Allow"
    resources = ["${aws_s3_bucket.loki[0].arn}/*"]
  }

  statement {
    sid     = "KmsEncryptDecrypt"
    actions = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    effect  = "Allow"
    resources = [local.kms_arn_effective]
  }
}

resource "aws_iam_policy" "loki_s3" {
  count       = length(data.aws_iam_policy_document.loki_s3) > 0 ? 1 : 0
  name        = "${local.name_norm}-loki-s3"
  description = "Loki S3 access (least privilege)"
  policy      = data.aws_iam_policy_document.loki_s3[0].json
  tags        = local.common_tags
}

resource "aws_iam_role" "loki" {
  count              = local.irsa_enabled && var.enable_loki ? 1 : 0
  name               = "${local.name_norm}-irsa-loki"
  assume_role_policy = replace(data.aws_iam_policy_document.irsa_trust[0].json, "\"sts.amazonaws.com\"", "\"sts.amazonaws.com\"")
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "loki_attach" {
  count      = length(aws_iam_role.loki) > 0 ? 1 : 0
  role       = aws_iam_role.loki[0].name
  policy_arn = aws_iam_policy.loki_s3[0].arn
}

# Tempo
data "aws_iam_policy_document" "tempo_s3" {
  count = local.irsa_enabled && var.enable_tempo ? 1 : 0

  statement {
    sid     = "BucketLevel"
    actions = ["s3:GetBucketLocation", "s3:ListBucket"]
    effect  = "Allow"
    resources = [
      aws_s3_bucket.tempo[0].arn
    ]
  }

  statement {
    sid     = "ObjectLevel"
    actions = [
      "s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload",
      "s3:DeleteObject", "s3:ListBucketMultipartUploads"
    ]
    effect    = "Allow"
    resources = ["${aws_s3_bucket.tempo[0].arn}/*"]
  }

  statement {
    sid     = "KmsEncryptDecrypt"
    actions = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    effect  = "Allow"
    resources = [local.kms_arn_effective]
  }
}

resource "aws_iam_policy" "tempo_s3" {
  count       = length(data.aws_iam_policy_document.tempo_s3) > 0 ? 1 : 0
  name        = "${local.name_norm}-tempo-s3"
  description = "Tempo S3 access (least privilege)"
  policy      = data.aws_iam_policy_document.tempo_s3[0].json
  tags        = local.common_tags
}

resource "aws_iam_role" "tempo" {
  count              = local.irsa_enabled && var.enable_tempo ? 1 : 0
  name               = "${local.name_norm}-irsa-tempo"
  assume_role_policy = replace(data.aws_iam_policy_document.irsa_trust[0].json, "\"sts.amazonaws.com\"", "\"sts.amazonaws.com\"")
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "tempo_attach" {
  count      = length(aws_iam_role.tempo) > 0 ? 1 : 0
  role       = aws_iam_role.tempo[0].name
  policy_arn = aws_iam_policy.tempo_s3[0].arn
}

# OTEL (часто пишет в OTLP/HTTP, S3 доступ не обязателен) — роль-каркас для mTLS/secret manager и т.п.
resource "aws_iam_role" "otel" {
  count              = local.irsa_enabled && var.enable_otel_collector ? 1 : 0
  name               = "${local.name_norm}-irsa-otel"
  assume_role_policy = replace(data.aws_iam_policy_document.irsa_trust[0].json, "\"sts.amazonaws.com\"", "\"sts.amazonaws.com\"")
  tags               = local.common_tags
}

# ----------------------------- K8S NAMESPACE ----------------------------------

resource "kubernetes_namespace" "this" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of" = "core-systems"
      "app.kubernetes.io/name"    = "observability"
      "managed-by"                = "terraform"
    }
  }
}

# ----------------------------- HELM РЕЛИЗЫ (опц.) -----------------------------

# kube-prometheus-stack
resource "helm_release" "kps" {
  count            = var.enable_kube_prometheus_stack ? 1 : 0
  name             = "kube-prometheus-stack"
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  namespace        = var.namespace
  create_namespace = false
  cleanup_on_fail  = true
  timeout          = 900

  values = compact([
    var.kps_values_yaml
  ])

  depends_on = [kubernetes_namespace.this]
}

# Loki (chart по умолчанию не настраиваем; значения передаются через loki_values_yaml)
resource "helm_release" "loki" {
  count            = var.enable_loki ? 1 : 0
  name             = "loki"
  repository       = "https://grafana.github.io/helm-charts"
  chart            = "loki"
  namespace        = var.namespace
  create_namespace = false
  cleanup_on_fail  = true
  timeout          = 900

  values = compact([
    var.loki_values_yaml
  ])

  # Пример аннотации IRSA в values (для справки):
  # loki:
  #   serviceAccount:
  #     create: true
  #     name: ${var.sa_name_loki}
  #     annotations:
  #       eks.amazonaws.com/role-arn: ${aws_iam_role.loki[0].arn}

  depends_on = [kubernetes_namespace.this]
}

# Tempo
resource "helm_release" "tempo" {
  count            = var.enable_tempo ? 1 : 0
  name             = "tempo"
  repository       = "https://grafana.github.io/helm-charts"
  chart            = "tempo"
  namespace        = var.namespace
  create_namespace = false
  cleanup_on_fail  = true
  timeout          = 900

  values = compact([
    var.tempo_values_yaml
  ])

  depends_on = [kubernetes_namespace.this]
}

# OpenTelemetry Collector
resource "helm_release" "otel" {
  count            = var.enable_otel_collector ? 1 : 0
  name             = "opentelemetry-collector"
  repository       = "https://open-telemetry.github.io/opentelemetry-helm-charts"
  chart            = "opentelemetry-collector"
  namespace        = var.namespace
  create_namespace = false
  cleanup_on_fail  = true
  timeout          = 900

  values = compact([
    var.otel_values_yaml
  ])

  depends_on = [kubernetes_namespace.this]
}

# ------------------------------- ВЫХОДЫ ---------------------------------------

output "kms_key_arn" {
  description = "Используемый KMS ключ (созданный или внешний)."
  value       = local.kms_arn_effective
}

output "loki_bucket" {
  description = "Имя S3 бакета для Loki (если создавался)."
  value       = try(aws_s3_bucket.loki[0].bucket, null)
}

output "tempo_bucket" {
  description = "Имя S3 бакета для Tempo (если создавался)."
  value       = try(aws_s3_bucket.tempo[0].bucket, null)
}

output "irsa_role_arn_loki" {
  description = "IRSA роль для Loki (если создана)."
  value       = try(aws_iam_role.loki[0].arn, null)
}

output "irsa_role_arn_tempo" {
  description = "IRSA роль для Tempo (если создана)."
  value       = try(aws_iam_role.tempo[0].arn, null)
}

output "irsa_role_arn_otel" {
  description = "IRSA роль для OTEL Collector (если создана)."
  value       = try(aws_iam_role.otel[0].arn, null)
}

output "namespace" {
  description = "Namespace для компонентов наблюдаемости."
  value       = kubernetes_namespace.this.metadata[0].name
}
