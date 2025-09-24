terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.29"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Настроить через: terraform init \
  #  -backend-config="bucket=..." -backend-config="key=envs/prod/terraform.tfstate" \
  #  -backend-config="region=..." -backend-config="dynamodb_table=..." -backend-config="encrypt=true"
  backend "s3" {}
}

############################
# Входные параметры
############################
variable "aws_region" {
  description = "AWS region for prod"
  type        = string
  default     = "eu-central-1"
}

variable "name_prefix" {
  description = "Prefix for all prod resources"
  type        = string
  default     = "zero-trust-core"
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.60.0.0/16"
}

variable "az_count" {
  description = "Number of AZs"
  type        = number
  default     = 3
}

variable "eks_version" {
  description = "EKS control plane version"
  type        = string
  default     = "1.29"
}

variable "node_instance_types" {
  description = "Node group instance types"
  type        = list(string)
  default     = ["m6i.large"]
}

variable "desired_size" {
  type        = number
  default     = 3
}

variable "min_size" {
  type        = number
  default     = 3
}

variable "max_size" {
  type        = number
  default     = 6
}

# Разрешенные источники к API EKS (ограничьте по офисным/бастионным CIDR)
variable "eks_api_whitelist_cidrs" {
  description = "Allowed CIDR to access EKS public API endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"] # PROD: сузьте!
}

############################
# Провайдер AWS и общие теги
############################
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.name_prefix
      Environment = "prod"
      Owner       = "platform"
      ManagedBy   = "terraform"
      ZeroTrust   = "true"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  env         = "prod"
  name        = "${var.name_prefix}-${locals.env}"
  azs         = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  log_bucket  = "${var.name_prefix}-${locals.env}-logs"
}

data "aws_availability_zones" "available" {
  state = "available"
}

############################
# Логовый бакет (S3) под Flow Logs/ALB/NLB/прочий аудит
############################
resource "aws_s3_bucket" "logs" {
  bucket        = local.log_bucket
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
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
    id     = "expire-logs"
    status = "Enabled"
    expiration { days = 365 }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

############################
# VPC (terraform-aws-modules/vpc/aws)
############################
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name}-vpc"
  cidr = var.vpc_cidr

  azs             = local.azs
  public_subnets  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  private_subnets = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 8)]

  enable_nat_gateway     = true
  single_nat_gateway     = true
  enable_dns_hostnames   = true
  enable_dns_support     = true
  manage_default_security_group = true

  flow_log_destination_type = "s3"
  flow_log_destination_arn  = aws_s3_bucket.logs.arn
  flow_log_max_aggregation_interval = 60

  tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
  }

  public_subnet_tags = {
    "kubernetes.io/role/elb"                = "1"
    "kubernetes.io/cluster/${local.name}"   = "shared"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"       = "1"
    "kubernetes.io/cluster/${local.name}"   = "shared"
  }
}

############################
# KMS для шифрования секретов EKS (envelope)
############################
resource "aws_kms_key" "eks_secrets" {
  description             = "${local.name} EKS secrets encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "eks_secrets" {
  name          = "alias/${local.name}/eks-secrets"
  target_key_id = aws_kms_key.eks_secrets.key_id
}

############################
# EKS (terraform-aws-modules/eks/aws)
############################
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.11"

  cluster_name                   = local.name
  cluster_version                = var.eks_version
  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  cluster_encryption_config = {
    resources = ["secrets"]
    provider_key_arn = aws_kms_key.eks_secrets.arn
  }

  # Логи control-plane
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  cloudwatch_log_group_retention_in_days = 30

  # API whitelist (ограничьте в проде)
  cluster_endpoint_public_access_cidrs = var.eks_api_whitelist_cidrs

  eks_managed_node_groups = {
    default = {
      ami_type       = "AL2_x86_64" # или BOTTLEROCKET_x86_64
      instance_types = var.node_instance_types
      desired_size   = var.desired_size
      min_size       = var.min_size
      max_size       = var.max_size

      subnet_ids = module.vpc.private_subnets

      labels = {
        "workload" = "general"
      }

      taints = []
      capacity_type = "ON_DEMAND"

      update_config = {
        max_unavailable_percentage = 33
      }

      # Диски и безопасность
      disk_size = 50
      additional_tags = {
        "ZeroTrust" = "true"
      }
    }
  }

  tags = {
    "ZeroTrust" = "true"
  }
}

data "aws_eks_cluster" "this" {
  name = module.eks.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

############################
# Провайдеры Kubernetes и Helm (через EKS)
############################
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

############################
# IRSA: роли для сервис‑аккаунтов (ALB Controller, ExternalDNS, cert-manager)
############################
module "iam_irsa_alb" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                              = "${local.name}-alb-controller"
  attach_load_balancer_controller_policy = true
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

module "iam_irsa_external_dns" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name = "${local.name}-externaldns"
  role_policy_arns = {
    route53 = aws_iam_policy.external_dns.arn
  }

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["zero-trust-core:external-dns"]
    }
  }
}

resource "aws_iam_policy" "external_dns" {
  name        = "${local.name}-externaldns"
  description = "Allow ExternalDNS to manage Route53 records"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["route53:ChangeResourceRecordSets"],
        Resource = ["arn:${data.aws_partition.current.partition}:route53:::hostedzone/*"]
      },
      {
        Effect = "Allow",
        Action = [
          "route53:ListHostedZones",
          "route53:ListResourceRecordSets",
          "route53:ListTagsForResource"
        ],
        Resource = ["*"]
      }
    ]
  })
}

module "iam_irsa_cert_manager" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name = "${local.name}-certmanager"
  role_policy_arns = {
    route53 = aws_iam_policy.cert_manager.arn
  }

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["cert-manager:cert-manager"]
    }
  }
}

resource "aws_iam_policy" "cert_manager" {
  name        = "${local.name}-certmanager"
  description = "Allow cert-manager to solve DNS01 in Route53"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "route53:ChangeResourceRecordSets"
        ],
        Resource = ["arn:${data.aws_partition.current.partition}:route53:::hostedzone/*"]
      },
      {
        Effect = "Allow",
        Action = [
          "route53:ListHostedZonesByName",
          "route53:ListHostedZones",
          "route53:GetChange",
          "route53:ListResourceRecordSets"
        ],
        Resource = ["*"]
      }
    ]
  })
}

############################
# (Опционально) Установка контроллеров через Helm
############################
resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = "1.7.2"

  depends_on = [module.eks]

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }

  set {
    name  = "serviceAccount.create"
    value = "false"
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "region"
    value = var.aws_region
  }
  set {
    name  = "vpcId"
    value = module.vpc.vpc_id
  }

  # IRSA
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.iam_irsa_alb.iam_role_arn
  }
}

resource "helm_release" "external_dns" {
  name       = "external-dns"
  namespace  = "zero-trust-core"
  repository = "https://kubernetes-sigs.github.io/external-dns/"
  chart      = "external-dns"
  version    = "1.15.0"

  create_namespace = true

  depends_on = [module.eks]

  set {
    name  = "provider"
    value = "aws"
  }
  set {
    name  = "policy"
    value = "sync"
  }
  set {
    name  = "txtOwnerId"
    value = module.eks.cluster_name
  }
  set {
    name  = "serviceAccount.create"
    value = "false"
  }
  set {
    name  = "serviceAccount.name"
    value = "external-dns"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.iam_irsa_external_dns.iam_role_arn
  }
}

############################
# Выходные данные
############################
output "cluster_name" {
  value       = module.eks.cluster_name
  description = "EKS cluster name"
}

output "region" {
  value       = var.aws_region
  description = "AWS region"
}

output "oidc_provider_arn" {
  value       = module.eks.oidc_provider_arn
  description = "OIDC provider ARN for IRSA"
}

output "kms_key_arn" {
  value       = aws_kms_key.eks_secrets.arn
  description = "KMS key for EKS secret encryption"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID"
}

output "private_subnets" {
  value       = module.vpc.private_subnets
  description = "Private subnets for worker nodes"
}
