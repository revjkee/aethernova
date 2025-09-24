terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
  }
}

########################################
# VARIABLES
########################################

variable "project_tags" {
  description = "Глобальные теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "cluster_name" {
  description = "Имя EKS-кластера."
  type        = string
}

variable "cluster_version" {
  description = "Версия Kubernetes (например, 1.29)."
  type        = string
}

variable "vpc_id" {
  description = "VPC, в которой разворачивается кластер."
  type        = string
}

variable "private_subnet_ids" {
  description = "Список приватных подсетей для control plane ENI и (опционально) частного эндпойнта."
  type        = list(string)
}

variable "cluster_log_types" {
  description = "Типы логов control-plane для отправки в CloudWatch Logs."
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  # См. поддерживаемые типы логов в AWS Docs.
}

variable "enable_private_endpoint" {
  description = "Включить приватный доступ к Kubernetes API (внутри VPC)."
  type        = bool
  default     = true
}

variable "enable_public_endpoint" {
  description = "Включить публичный доступ к Kubernetes API."
  type        = bool
  default     = false
}

variable "public_access_cidrs" {
  description = "Список CIDR, которым разрешён доступ к публичному эндпойнту (если он включён)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "kms_key_arn" {
  description = "ARN пользовательского KMS ключа для шифрования секретов в EKS (encryption_config)."
  type        = string
  default     = null
}

variable "addons" {
  description = <<EOT
Карта managed add-ons:
  ключ   — имя аддона (например, "vpc-cni","coredns","kube-proxy")
  value  — объект с версией/параметрами
Пример:
{
  vpc-cni   = { version = "v1.18.1-eksbuild.1" }
  coredns   = { version = "v1.11.1-eksbuild.3" }
  kube-proxy = { version = "v1.29.0-eksbuild.2" }
}
EOT
  type = map(object({
    version          = optional(string, null)
    resolve_conflicts = optional(string, "OVERWRITE") # NONE | OVERWRITE | PRESERVE
    service_account_role_arn = optional(string, null)  # для некоторых аддонов
  }))
  default = {
    vpc-cni    = {}
    coredns    = {}
    kube-proxy = {}
  }
}

########################################
# DATA (для региональных/аккаунтных фактов)
########################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

########################################
# SECURITY GROUP ДЛЯ CONTROL PLANE
########################################

resource "aws_security_group" "eks_cluster" {
  name        = "${var.cluster_name}-cluster-sg"
  description = "Security Group для EKS control plane"
  vpc_id      = var.vpc_id

  # Входной трафик к API (443) разрешается AWS с управляющих IP адресов
  # Для публичного эндпойнта фильтрация производится EKS по PublicAccessCidrs.
  # Для приватного — SG и маршрутизация внутри VPC.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.project_tags, {
    "Name" = "${var.cluster_name}-cluster-sg"
  })
}

########################################
# IAM ROLE ДЛЯ EKS КЛАСТЕРА
########################################

resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "eks.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.project_tags
}

# Обязательные политики для control plane согласно AWS
# AmazonEKSClusterPolicy, AmazonEKSVPCResourceController
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_vpc_rc_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

########################################
# EKS CLUSTER (CONTROL PLANE)
########################################

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.cluster_version
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = var.enable_private_endpoint
    endpoint_public_access  = var.enable_public_endpoint
    public_access_cidrs     = var.public_access_cidrs
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }

  enabled_cluster_log_types = var.cluster_log_types

  dynamic "encryption_config" {
    for_each = var.kms_key_arn == null ? [] : [var.kms_key_arn]
    content {
      resources = ["secrets"]
      provider {
        key_arn = encryption_config.value
      }
    }
  }

  # Явно дожидаемся прикрепления IAM-политик
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_rc_policy
  ]

  tags = var.project_tags
}

########################################
# IRSA: OIDC PROVIDER НА ОСНОВЕ КОНФИГУРАЦИИ КЛАСТЕРА
########################################

# Создаём OIDC-провайдера из поля identity.oidc.issuer кластера без data-источников,
# чтобы не попадать в циклы зависимостей на "пустой" план.
resource "aws_iam_openid_connect_provider" "this" {
  url = replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")

  client_id_list = ["sts.amazonaws.com"]

  # thumbprint_list: актуальные значения AWS публикует в документации;
  # большинство регионов используют корневой сертификат Starfield (1 долгоживущий отпечаток).
  # При необходимости обновите список согласно региону.
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da0afd10df6"]

  tags = var.project_tags
}

########################################
# MANAGED ADD-ONS (vpc-cni, coredns, kube-proxy, ...)
########################################

resource "aws_eks_addon" "this" {
  for_each = var.addons

  cluster_name             = aws_eks_cluster.this.name
  addon_name               = each.key
  addon_version            = try(each.value.version, null)
  resolve_conflicts        = try(each.value.resolve_conflicts, "OVERWRITE")
  service_account_role_arn = try(each.value.service_account_role_arn, null)

  tags = merge(var.project_tags, { "eks-addon" = each.key })
}

########################################
# OUTPUTS ДЛЯ СВЯЗАННЫХ МОДУЛЕЙ (k8s provider и т.д.)
########################################

output "cluster_name" {
  value       = aws_eks_cluster.this.name
  description = "Имя EKS-кластера."
}

output "cluster_endpoint" {
  value       = aws_eks_cluster.this.endpoint
  description = "Эндпойнт Kubernetes API."
}

output "cluster_certificate_authority_data" {
  value       = aws_eks_cluster.this.certificate_authority[0].data
  description = "CA data (base64) кластера."
}

output "cluster_oidc_issuer" {
  value       = aws_eks_cluster.this.identity[0].oidc[0].issuer
  description = "OIDC issuer кластера (для IRSA)."
}

output "cluster_security_group_id" {
  value       = aws_security_group.eks_cluster.id
  description = "Security Group, связанный с control plane."
}

output "oidc_provider_arn" {
  value       = aws_iam_openid_connect_provider.this.arn
  description = "ARN созданного IAM OIDC провайдера (IRSA)."
}
