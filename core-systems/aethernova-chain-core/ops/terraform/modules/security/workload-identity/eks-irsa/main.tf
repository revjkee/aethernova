############################################################
# File: aethernova-chain-core/ops/terraform/modules/security/workload-identity/eks-irsa/main.tf
# Purpose: AWS IRSA (EKS OIDC provider + IAM role for K8s SA)
# Terraform: >= 1.4, AWS provider >= 5.x, TLS provider >= 4.x
############################################################

terraform {
  required_version = ">= 1.4.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
  }
}

############################################################
# Inputs
############################################################
variable "cluster_name" {
  description = "EKS cluster name (используется для получения OIDC issuer, если oidc_issuer_url не передан)"
  type        = string
  default     = null
}

variable "oidc_issuer_url" {
  description = "Полный OIDC issuer URL (например, https://oidc.eks.eu-north-1.amazonaws.com/id/XXXX). Если задан, data aws_eks_cluster не используется."
  type        = string
  default     = ""
}

variable "manage_oidc_provider" {
  description = "Создавать ли IAM OIDC provider (true) или использовать существующий ARN (false)"
  type        = bool
  default     = true
}

variable "existing_oidc_provider_arn" {
  description = "ARN существующего IAM OIDC provider (если manage_oidc_provider=false)"
  type        = string
  default     = ""
}

variable "role_name" {
  description = "Имя IAM-роли для IRSA"
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace, для которого выдаются права"
  type        = string
}

variable "service_account_names" {
  description = "Список имен ServiceAccount. Если пуст и namespace_wildcard=false, будет ошибка валидации."
  type        = list(string)
  default     = []
}

variable "namespace_wildcard" {
  description = "Если true — разрешить все SA в namespace через StringLike с маской system:serviceaccount:<ns>:*"
  type        = bool
  default     = false
}

variable "audience" {
  description = "Значение aud в JWT; для IRSA должно быть sts.amazonaws.com"
  type        = string
  default     = "sts.amazonaws.com"
}

variable "managed_policy_arns" {
  description = "Список ARNs управляемых IAM-политик для присоединения к роли"
  type        = list(string)
  default     = []
}

variable "inline_policies_json" {
  description = "Карта inline-политик {name => json}"
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Общие теги"
  type        = map(string)
  default     = {}
}

############################################################
# Validations
############################################################
locals {
  use_cluster_data = var.oidc_issuer_url == "" ? true : false
}

# Требуем либо manage_oidc_provider=true, либо задан existing_oidc_provider_arn
# и требуем либо список SA, либо wildcard
locals {
  _oidc_ok = var.manage_oidc_provider || (trim(var.existing_oidc_provider_arn) != "")
  _sa_ok   = var.namespace_wildcard || (length(var.service_account_names) > 0)
}

# Нулевой ресурс только для валидации precondition (Terraform 1.2+ поддерживает precondition)
resource "null_resource" "validations" {
  lifecycle {
    precondition {
      condition     = local._oidc_ok
      error_message = "Either set manage_oidc_provider=true or provide existing_oidc_provider_arn."
    }
    precondition {
      condition     = local._sa_ok
      error_message = "Provide service_account_names or set namespace_wildcard=true."
    }
  }
}

############################################################
# Discover OIDC issuer from EKS (если URL не задан)
############################################################
data "aws_eks_cluster" "this" {
  count = local.use_cluster_data ? 1 : 0
  name  = var.cluster_name
}

locals {
  oidc_issuer_url = local.use_cluster_data ? data.aws_eks_cluster.this[0].identity[0].oidc[0].issuer : var.oidc_issuer_url
  # В trust policy ключи условий должны быть без https://
  oidc_provider_hostpath = replace(local.oidc_issuer_url, "https://", "")
}

############################################################
# IAM OIDC Provider (создаём при необходимости)
# Получаем thumbprint корневого/замыкающего сертификата OIDC (TLS data source)
############################################################
data "tls_certificate" "oidc" {
  count = var.manage_oidc_provider ? 1 : 0
  url   = local.oidc_issuer_url
}

# Берем sha1_fingerprint последнего в цепочке (как правило, корневой CA);
# fall-back на первый элемент, если длина неизвестна.
locals {
  oidc_thumbprint = var.manage_oidc_provider ? try(
    data.tls_certificate.oidc[0].certificates[length(data.tls_certificate.oidc[0].certificates) - 1].sha1_fingerprint,
    data.tls_certificate.oidc[0].certificates[0].sha1_fingerprint
  ) : ""
}

resource "aws_iam_openid_connect_provider" "this" {
  count            = var.manage_oidc_provider ? 1 : 0
  url              = local.oidc_issuer_url
  client_id_list   = [var.audience] # sts.amazonaws.com
  thumbprint_list  = [local.oidc_thumbprint]
  tags             = merge(var.tags, { Name = "${var.role_name}-oidc" })
}

locals {
  oidc_provider_arn_effective = var.manage_oidc_provider ? aws_iam_openid_connect_provider.this[0].arn : var.existing_oidc_provider_arn
}

############################################################
# Trust policy для IRSA (AssumeRoleWithWebIdentity)
############################################################
# StringEquals: <issuer host>:aud = sts.amazonaws.com
# StringEquals: <issuer host>:sub = system:serviceaccount:<ns>:<sa> (список значений допустим)
# StringLike:   <issuer host>:sub = system:serviceaccount:<ns>:* (если wildcard=true)
locals {
  condition_equals = merge(
    { "${local.oidc_provider_hostpath}:aud" = var.audience },
    var.namespace_wildcard ? {} : {
      "${local.oidc_provider_hostpath}:sub" = [
        for n in var.service_account_names : "system:serviceaccount:${var.namespace}:${n}"
      ]
    }
  )

  condition_like = var.namespace_wildcard ? {
    "${local.oidc_provider_hostpath}:sub" = "system:serviceaccount:${var.namespace}:*"
  } : {}

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRoleWithWebIdentity"
        Principal = {
          Federated = local.oidc_provider_arn_effective
        }
        Condition = merge(
          { StringEquals = local.condition_equals },
          var.namespace_wildcard ? { StringLike = local.condition_like } : {}
        )
      }
    ]
  })
}

############################################################
# IAM Role (IRSA) + policy attachments
############################################################
resource "aws_iam_role" "irsa" {
  name               = var.role_name
  assume_role_policy = local.assume_role_policy
  description        = "IRSA role for K8s SA(s) in ${var.namespace}"
  tags               = merge(var.tags, { managed_by = "terraform", module = "security/workload-identity/eks-irsa" })

  lifecycle {
    precondition {
      condition     = length(local.oidc_provider_arn_effective) > 0
      error_message = "OIDC provider ARN is empty. Set manage_oidc_provider=true or provide existing_oidc_provider_arn."
    }
  }
}

# Присоединяем управляемые политики (AWS Managed/Customer Managed)
resource "aws_iam_role_policy_attachment" "managed" {
  for_each   = toset(var.managed_policy_arns)
  role       = aws_iam_role.irsa.name
  policy_arn = each.value
}

# Inline-политики (map name=>json)
resource "aws_iam_role_policy" "inline" {
  for_each = var.inline_policies_json
  name     = each.key
  role     = aws_iam_role.irsa.id
  policy   = each.value
}

############################################################
# Outputs с аннотацией для Kubernetes ServiceAccount
############################################################
output "irsa_role_arn" {
  description = "ARN созданной IAM-роли для IRSA"
  value       = aws_iam_role.irsa.arn
}

output "oidc_provider_arn" {
  description = "ARN IAM OIDC provider (созданного или существующего)"
  value       = local.oidc_provider_arn_effective
}

output "kubernetes_sa_annotation" {
  description = "Аннотация для ServiceAccount"
  value       = "eks.amazonaws.com/role-arn=${aws_iam_role.irsa.arn}"
}

output "trust_policy_preview" {
  description = "Сгенерированная trust policy (для отладки)"
  value       = local.assume_role_policy
  sensitive   = false
}
