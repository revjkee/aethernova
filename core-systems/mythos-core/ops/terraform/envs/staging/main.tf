terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # ВАЖНО: заполните реальные значения бакета/таблицы локов
  backend "s3" {
    bucket         = "org-terraform-state"
    key            = "mythos-core/staging/terraform.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "org-terraform-locks"
    encrypt        = true
  }
}

# ---------------------------
# Параметры окружения
# ---------------------------

variable "region" {
  description = "AWS регион"
  type        = string
  default     = "eu-west-1"
}

variable "vpc_cidr" {
  description = "CIDR блок VPC"
  type        = string
  default     = "10.42.0.0/16"
}

variable "domain_zone_name" {
  description = "Имя публичной Hosted Zone в Route53 (для external-dns). Оставьте пустым для отключения."
  type        = string
  default     = ""
}

locals {
  env        = "staging"
  app        = "mythos-core"
  name       = "${local.app}-${local.env}"
  # Префикс тегов для унификации
  tags = {
    "Project"                = "mythos-core"
    "Environment"            = local.env
    "Managed-By"             = "terraform"
    "Owner"                  = "platform"
    "Application"            = local.app
    "kubernetes.io/cluster/${local.name}" = "owned"
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------
# S3 для Flow Logs и артефактов
# ---------------------------

resource "aws_s3_bucket" "vpc_flow_logs" {
  bucket = "${local.name}-flow-logs"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "vpc_flow_logs" {
  bucket = aws_s3_bucket.vpc_flow_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vpc_flow_logs" {
  bucket = aws_s3_bucket.vpc_flow_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${local.name}-artifacts"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ---------------------------
# VPC: приватные/публичные подсети, NAT, Flow Logs
# ---------------------------

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.name}-vpc"
  cidr = var.vpc_cidr

  azs              = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets  = [for i in range(3) : cidrsubnet(var.vpc_cidr, 4, i)]       # /20
  public_subnets   = [for i in range(3) : cidrsubnet(var.vpc_cidr, 4, i + 8)]   # /20
  enable_nat_gateway = true
  single_nat_gateway = true

  enable_dns_hostnames = true
  enable_dns_support   = true

  # Тэги подсетей для балансировщиков
  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  # Flow logs в S3
  enable_flow_log           = true
  flow_log_destination_type = "s3"
  flow_log_destination_arn  = aws_s3_bucket.vpc_flow_logs.arn
  flow_log_file_format      = "parquet"
  flow_log_max_aggregation_interval = 60

  manage_default_security_group = true
  default_security_group_name   = "${local.name}-default-sg"

  # Эндпоинты для приватного доступа к ECR/S3/CloudWatch
  enable_s3_endpoint               = true
  enable_ecr_api_endpoint          = true
  enable_ecr_dkr_endpoint          = true
  enable_cloudwatch_logs_endpoint  = true
  enable_ssm_endpoint              = true
  enable_ssmmessages_endpoint      = true
  enable_ec2messages_endpoint      = true

  tags = local.tags
}

# ---------------------------
# KMS для шифрования секретов EKS
# ---------------------------

resource "aws_kms_key" "eks" {
  description             = "KMS key for ${local.name} EKS secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Enable IAM User Permissions"
        Effect   = "Allow"
        Principal = { AWS = data.aws_caller_identity.this.account_id }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
  tags = local.tags
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

# ---------------------------
# ECR для образов приложения
# ---------------------------

module "ecr" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 1.0"

  repository_name                 = local.name
  repository_force_delete         = false
  repository_image_tag_mutability = "MUTABLE"
  repository_encryption_type      = "AES256"

  lifecycle_policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 50 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 50 }
      action       = { type = "expire" }
    }]
  })

  tags = local.tags
}

# ---------------------------
# EKS кластер: IRSA, логи, аддоны, node groups
# ---------------------------

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "${local.name}-eks"
  cluster_version = "1.29"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access = true

  enable_irsa = true
  kms_key_arn = aws_kms_key.eks.arn

  create_cloudwatch_log_group           = true
  cloudwatch_log_group_retention_in_days = 30
  cluster_enabled_log_types             = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  cluster_addons = {
    coredns   = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni    = { most_recent = true }
  }

  eks_managed_node_groups = {
    ondemand = {
      name           = "ondemand"
      instance_types = ["m6i.large"]
      desired_size   = 2
      min_size       = 1
      max_size       = 4
      disk_size      = 50
      capacity_type  = "ON_DEMAND"
      subnets        = module.vpc.private_subnets
      labels         = { "workload" = "general" }
      tags           = local.tags
    }
    spot = {
      name           = "spot"
      instance_types = ["m6i.large", "m5.large", "c6i.large"]
      desired_size   = 0
      min_size       = 0
      max_size       = 6
      disk_size      = 50
      capacity_type  = "SPOT"
      subnets        = module.vpc.private_subnets
      labels         = { "workload" = "batch" }
      taints         = [{ key = "batch", value = "true", effect = "NO_SCHEDULE" }]
      tags           = local.tags
    }
  }

  tags = local.tags
}

# ---------------------------
# Провайдеры Kubernetes/Helm на данных кластера
# ---------------------------

data "aws_eks_cluster" "this" {
  name = module.eks.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

# ---------------------------
# IRSA роли для аддонов (external-dns, cluster-autoscaler)
# ---------------------------

module "irsa_external_dns" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name_prefix = "${local.name}-external-dns-"
  attach_external_dns_policy = true
  external_dns_hosted_zone_arns = var.domain_zone_name != "" ? [
    "arn:aws:route53:::hostedzone/*"
  ] : []

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }

  tags = local.tags
}

module "irsa_cluster_autoscaler" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name_prefix = "${local.name}-autoscaler-"
  attach_cluster_autoscaler_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }

  tags = local.tags
}

# ---------------------------
# Helm-релизы базовых аддонов
# ---------------------------

# metrics-server
resource "helm_release" "metrics_server" {
  name       = "metrics-server"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  version    = "3.12.2"

  values = [yamlencode({
    args = ["--kubelet-preferred-address-types=InternalIP", "--kubelet-insecure-tls"]
  })]
}

# ingress-nginx
resource "helm_release" "ingress_nginx" {
  name       = "ingress-nginx"
  namespace  = "ingress-nginx"
  create_namespace = true
  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
  version    = "4.11.3"

  values = [yamlencode({
    controller = {
      replicaCount = 2
      service = { annotations = { "service.beta.kubernetes.io/aws-load-balancer-type" = "nlb" } }
    }
  })]
}

# external-dns (включается только если задана hosted zone)
resource "helm_release" "external_dns" {
  count      = var.domain_zone_name != "" ? 1 : 0
  name       = "external-dns"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/external-dns/"
  chart      = "external-dns"
  version    = "1.15.0"

  values = [yamlencode({
    serviceAccount = {
      name = "external-dns"
      annotations = { "eks.amazonaws.com/role-arn" = module.irsa_external_dns.iam_role_arn }
    }
    provider = "aws"
    policy   = "upsert-only"
    txtOwnerId = local.name
    domainFilters = var.domain_zone_name != "" ? [var.domain_zone_name] : []
  })]
}

# cluster-autoscaler
resource "helm_release" "cluster_autoscaler" {
  name       = "cluster-autoscaler"
  namespace  = "kube-system"
  repository = "https://kubernetes.github.io/autoscaler"
  chart      = "cluster-autoscaler"
  version    = "9.45.0"

  values = [yamlencode({
    autoDiscovery = { clusterName = module.eks.cluster_name }
    awsRegion     = var.region
    rbac = {
      serviceAccount = {
        name        = "cluster-autoscaler"
        annotations = { "eks.amazonaws.com/role-arn" = module.irsa_cluster_autoscaler.iam_role_arn }
      }
    }
    extraArgs = {
      balance-similar-node-groups = "true"
      skip-nodes-with-local-storage = "false"
    }
  })]
}

# ---------------------------
# Выходные значения
# ---------------------------

output "region" {
  value       = var.region
  description = "Регион AWS"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "ID созданной VPC"
}

output "private_subnets" {
  value       = module.vpc.private_subnets
  description = "Приватные подсети"
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "Имя EKS кластера"
}

output "eks_cluster_endpoint" {
  value       = data.aws_eks_cluster.this.endpoint
  description = "Эндпоинт API сервера EKS"
}

output "ecr_repository_url" {
  value       = module.ecr.repository_url
  description = "URL ECR репозитория для образов приложения"
}

output "artifacts_bucket" {
  value       = aws_s3_bucket.artifacts.bucket
  description = "S3 бакет для артефактов"
}
