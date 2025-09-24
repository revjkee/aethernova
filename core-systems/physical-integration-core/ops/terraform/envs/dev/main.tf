###############################################################
# physical-integration-core : Terraform DEV environment (AWS)
# Промышленный каркас: VPC, EKS, IRSA, аддоны, KMS, S3 артефакты
# Требования: Terraform >= 1.6, AWS CLI/creds, доступ в 3 AZ
###############################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.55"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
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

  # Рекомендуемый backend (замени на свой S3/Dynamo):
  backend "s3" {
    bucket         = "CHANGE_ME-tfstate"
    key            = "physical-integration-core/dev/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "CHANGE_ME-tf-locks"
    encrypt        = true
  }
}

############################
# Параметры и локальные значения
############################
locals {
  project        = "physical-integration-core"
  env            = "dev"
  name_prefix    = "${local.project}-${local.env}"
  region         = var.region
  eks_version    = var.eks_version
  azs            = var.azs
  vpc_cidr       = var.vpc_cidr
  k8s_tags       = { "kubernetes.io/cluster/${local.name_prefix}" = "shared" }
  common_tags = merge({
    "Project"                = local.project
    "Environment"            = local.env
    "ManagedBy"              = "Terraform"
    "Owner"                  = var.owner
    "CostCenter"             = var.cost_center
    "Compliance"             = "Restricted"
    "Service"                = "platform"
    "Tier"                   = "core"
  }, var.extra_tags)
}

provider "aws" {
  region = local.region
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

############################
# KMS для шифрования (EKS secrets, S3 и прочее)
############################
resource "aws_kms_key" "platform" {
  description             = "${local.name_prefix} platform key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_kms_alias" "platform_alias" {
  name          = "alias/${local.name_prefix}-kms"
  target_key_id = aws_kms_key.platform.key_id
}

############################
# S3 артефакт‑бакет (версионирование + KMS)
############################
resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.name_prefix}-artifacts"
  tags   = local.common_tags
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.platform.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

############################
# VPC (3 AZ, приватные worker‑ы, один NAT для DEV)
############################
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name_prefix}-vpc"
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for i, az in local.azs : cidrsubnet(local.vpc_cidr, 4, i)]
  public_subnets  = [for i, az in local.azs : cidrsubnet(local.vpc_cidr, 8, i + 48)]

  enable_nat_gateway     = true
  single_nat_gateway     = true
  one_nat_gateway_per_az = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = merge(local.k8s_tags, {
    "kubernetes.io/role/elb" = "1"
  })
  private_subnet_tags = merge(local.k8s_tags, {
    "kubernetes.io/role/internal-elb" = "1"
  })

  tags = local.common_tags
}

############################
# EKS (IRSA включён, 1 системный и 1 spot‑пул)
############################
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.17"

  cluster_name    = local.name_prefix
  cluster_version = local.eks_version

  cluster_endpoint_public_access = true
  enable_irsa                    = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = aws_kms_key.platform.arn
  }

  eks_managed_node_groups = {
    system = {
      min_size       = 2
      max_size       = 4
      desired_size   = 2
      instance_types = ["t3.large"]
      capacity_type  = "ON_DEMAND"
      labels = {
        "nodegroup" = "system"
        "workload"  = "platform"
      }
      tags = local.common_tags
    }

    spot = {
      min_size       = 0
      max_size       = 6
      desired_size   = 2
      instance_types = ["m6i.large", "t3a.large", "m5.large"]
      capacity_type  = "SPOT"
      labels = {
        "nodegroup" = "spot"
        "workload"  = "general"
      }
      taints = []
      tags   = local.common_tags
    }
  }

  cluster_addons = {
    coredns = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni = {
      most_recent              = true
      before_compute           = true
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = null
      configuration_values     = jsonencode({ enableNetworkPolicy = "true" })
    }
    aws-ebs-csi-driver = {
      most_recent              = true
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = null # заменим на IRSA ниже через Helm, если нужно
    }
  }

  tags = local.common_tags
}

############################
# Провайдеры Kubernetes/Helm на базе EKS
############################
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = module.eks.cluster_token
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = module.eks.cluster_token
  }
}

############################
# IRSA роли для системных аддонов (ALB, Autoscaler, ExternalDNS)
############################
module "iam_irsa_alb" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                              = "${local.name_prefix}-alb"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.common_tags
}

module "iam_irsa_autoscaler" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                         = "${local.name_prefix}-cluster-autoscaler"
  attach_cluster_autoscaler_policy  = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }

  tags = local.common_tags
}

module "iam_irsa_externaldns" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                  = "${local.name_prefix}-external-dns"
  attach_external_dns_policy = true
  external_dns_hosted_zone_arns = var.external_dns_hosted_zone_arns

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }

  tags = local.common_tags
}

############################
# Helm: AWS Load Balancer Controller
############################
resource "helm_release" "alb_controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = var.alb_chart_version

  depends_on = [module.iam_irsa_alb]

  values = [yamlencode({
    clusterName = module.eks.cluster_name
    serviceAccount = {
      create = true
      name   = "aws-load-balancer-controller"
      annotations = {
        "eks.amazonaws.com/role-arn" = module.iam_irsa_alb.iam_role_arn
      }
    }
    region = local.region
    vpcId  = module.vpc.vpc_id
  })]
}

############################
# Helm: Cluster Autoscaler
############################
resource "helm_release" "cluster_autoscaler" {
  name       = "cluster-autoscaler"
  namespace  = "kube-system"
  repository = "https://kubernetes.github.io/autoscaler"
  chart      = "cluster-autoscaler"
  version    = var.autoscaler_chart_version

  depends_on = [module.iam_irsa_autoscaler]

  values = [yamlencode({
    autoDiscovery = { clusterName = module.eks.cluster_name }
    awsRegion     = local.region
    rbac = { serviceAccount = { create = true, name = "cluster-autoscaler" } }
    extraArgs = {
      "balance-similar-node-groups" = "true"
      "skip-nodes-with-local-storage" = "false"
      "skip-nodes-with-system-pods" = "false"
      "scale-down-unneeded-time" = "5m"
    }
    serviceAccount = {
      annotations = { "eks.amazonaws.com/role-arn" = module.iam_irsa_autoscaler.iam_role_arn }
    }
  })]
}

############################
# Helm: ExternalDNS (опционально, если нужны публичные DNS записи)
############################
resource "helm_release" "external_dns" {
  count      = length(var.external_dns_hosted_zone_arns) > 0 ? 1 : 0
  name       = "external-dns"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/external-dns/"
  chart      = "external-dns"
  version    = var.externaldns_chart_version

  depends_on = [module.iam_irsa_externaldns]

  values = [yamlencode({
    provider = "aws"
    policy   = "upsert-only"
    registry = "txt"
    txtOwnerId = local.name_prefix
    sources = ["service", "ingress"]
    serviceAccount = {
      create = true
      name   = "external-dns"
      annotations = { "eks.amazonaws.com/role-arn" = module.iam_irsa_externaldns.iam_role_arn }
    }
    domainFilters = var.external_dns_domains
  })]
}

############################
# Helm: Metrics Server (метрики для HPA)
############################
resource "helm_release" "metrics_server" {
  name       = "metrics-server"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  version    = var.metrics_server_chart_version

  values = [yamlencode({
    args = [
      "--kubelet-insecure-tls",         # dev‑среда; для prod выключить
      "--kubelet-preferred-address-types=InternalIP,Hostname,InternalDNS,ExternalDNS,ExternalIP"
    ]
  })]
}

############################
# Выходные значения
############################
output "region" {
  value = local.region
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnets" {
  value = module.vpc.private_subnets
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "artifact_bucket" {
  value = aws_s3_bucket.artifacts.id
}

output "kms_key_arn" {
  value = aws_kms_key.platform.arn
}

############################
# Переменные с безопасными дефолтами
############################
variable "region" {
  description = "AWS регион для DEV"
  type        = string
  default     = "eu-central-1"
}

variable "azs" {
  description = "Список AZ (3 шт.)"
  type        = list(string)
  default     = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
}

variable "vpc_cidr" {
  description = "CIDR VPC"
  type        = string
  default     = "10.40.0.0/16"
}

variable "eks_version" {
  description = "Версия EKS/Kubernetes"
  type        = string
  default     = "1.30"
}

variable "owner" {
  description = "Владелец окружения"
  type        = string
  default     = "platform-ops"
}

variable "cost_center" {
  description = "Код затрат"
  type        = string
  default     = "NC-CORE"
}

variable "extra_tags" {
  description = "Дополнительные теги"
  type        = map(string)
  default     = {}
}

variable "alb_chart_version" {
  description = "Версия чарта aws-load-balancer-controller"
  type        = string
  default     = "1.7.2"
}

variable "autoscaler_chart_version" {
  description = "Версия чарта cluster-autoscaler"
  type        = string
  default     = "9.45.0"
}

variable "externaldns_chart_version" {
  description = "Версия чарта external-dns"
  type        = string
  default     = "1.15.0"
}

variable "metrics_server_chart_version" {
  description = "Версия чарта metrics-server"
  type        = string
  default     = "3.12.1"
}

variable "external_dns_hosted_zone_arns" {
  description = "Список ARN hosted zone для ExternalDNS (опционально)"
  type        = list(string)
  default     = []
}

variable "external_dns_domains" {
  description = "Домены, которые может изменять ExternalDNS"
  type        = list(string)
  default     = []
}
