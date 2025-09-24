# path: zero-trust-core/ops/terraform/envs/staging/main.tf
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.55"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # В реальной среде укажите свой бакет/таблицу для блокировок
  backend "s3" {
    bucket         = "CHANGE-ME-ztc-tfstate"
    key            = "zero-trust-core/staging/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "CHANGE-ME-ztc-tf-locks"
    encrypt        = true
  }
}

# ---------------------------
# Параметры/локальные значения
# ---------------------------
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}

variable "project" {
  description = "Project slug"
  type        = string
  default     = "zero-trust-core"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "staging"
}

variable "eks_version" {
  description = "EKS Kubernetes version"
  type        = string
  default     = "1.30"
}

variable "allowed_api_cidrs" {
  description = "CIDR-блоки, которым разрешён доступ к публичной EKS API (стейджинг)."
  type        = list(string)
  # Ограниченная маска по умолчанию — замените на свои офисные/VPN CIDR'ы
  default     = ["203.0.113.0/24"]
}

variable "node_desired_size" {
  type    = number
  default = 3
}
variable "node_max_size" {
  type    = number
  default = 6
}
variable "node_min_size" {
  type    = number
  default = 3
}

locals {
  name_prefix = "${var.project}-${var.environment}"
  common_tags = {
    "Project"                 = var.project
    "Environment"             = var.environment
    "App"                     = "zero-trust-core"
    "ZeroTrust"               = "true"
    "Owner"                   = "platform"
    "terraform-managed"       = "true"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

# ---------------------------
# Логи и S3 бакет для логов
# ---------------------------
resource "aws_s3_bucket" "logs" {
  bucket        = "${local.name_prefix}-logs-${data.aws_caller_identity.this.account_id}"
  force_destroy = false
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

# ---------------------------
# VPC (3 AZ, приватные+публичные, NAT, Flow Logs -> S3)
# ---------------------------
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name_prefix}-vpc"
  cidr = "10.60.0.0/16"

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = ["10.60.1.0/24", "10.60.2.0/24", "10.60.3.0/24"]
  public_subnets  = ["10.60.101.0/24", "10.60.102.0/24", "10.60.103.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = false
  enable_dns_hostnames   = true
  enable_dns_support     = true
  map_public_ip_on_launch = false

  flow_log_destination_type = "s3"
  flow_log_max_aggregation_interval = 60
  enable_flow_log = true
  flow_log_s3_bucket_arn = aws_s3_bucket.logs.arn
  flow_log_s3_key_prefix = "vpc-flow-logs/"

  tags = local.common_tags
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------
# ECR (immutable + scan on push)
# ---------------------------
resource "aws_ecr_repository" "ztc" {
  name                 = "${local.name_prefix}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = local.common_tags
}

# ---------------------------
# EKS кластер (private + restricted public)
# ---------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.16"

  cluster_name    = "${local.name_prefix}-eks"
  cluster_version = var.eks_version

  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true
  cluster_endpoint_public_access_cidrs = var.allowed_api_cidrs

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  # Логи control plane в CloudWatch
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Addons (версии могут быть auto/latest)
  cluster_addons = {
    coredns = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni = {
      most_recent = true
      configuration_values = jsonencode({
        env = {
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_PREFIX_TARGET       = "1"
        }
      })
    }
    eks-pod-identity-agent = { most_recent = true }
  }

  # Managed Node Groups
  eks_managed_node_groups = {
    default = {
      name               = "${local.name_prefix}-mng"
      instance_types     = ["t3.large"]
      min_size           = var.node_min_size
      max_size           = var.node_max_size
      desired_size       = var.node_desired_size
      capacity_type      = "ON_DEMAND"
      subnet_ids         = module.vpc.private_subnets
      iam_role_additional_policies = {
        cwlogs = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
        ebs    = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
      }
      labels = {
        "workload" = "general"
        "env"      = var.environment
      }
      taints = []
    }
  }

  tags = local.common_tags
}

# ---------------------------
# Kubernetes/Helm провайдеры
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
# IRSA роли для системных операторов
# ---------------------------
module "irsa_alb_controller" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name_prefix = "${local.name_prefix}-alb-ctlr-"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.common_tags
}

module "irsa_external_dns" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name_prefix = "${local.name_prefix}-extdns-"
  attach_external_dns_policy = true

  oidc_providers = {
    main = {
      provider_arn = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }

  tags = local.common_tags
}

module "irsa_cluster_autoscaler" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name_prefix = "${local.name_prefix}-ca-"
  attach_cluster_autoscaler_policy = true

  oidc_providers = {
    main = {
      provider_arn = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }

  tags = local.common_tags
}

# ---------------------------
# Helm-релизы базовой платформы
# ---------------------------

# AWS Load Balancer Controller (ALB/NLB Ingress)
resource "helm_release" "alb_controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = "1.7.2"

  values = [
    yamlencode({
      clusterName = module.eks.cluster_name
      region      = var.aws_region
      vpcId       = module.vpc.vpc_id
      serviceAccount = {
        create = true
        name   = "aws-load-balancer-controller"
        annotations = {
          "eks.amazonaws.com/role-arn" = module.irsa_alb_controller.iam_role_arn
        }
      }
      tolerations = [{
        key = "node-role.kubernetes.io/control-plane"
        operator = "Exists"
        effect = "NoSchedule"
      }]
    })
  ]

  depends_on = [module.eks]
}

# Metrics Server
resource "helm_release" "metrics_server" {
  name       = "metrics-server"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  version    = "3.12.1"

  values = [
    yamlencode({
      args = ["--kubelet-insecure-tls"]
    })
  ]

  depends_on = [module.eks]
}

# Cluster Autoscaler
resource "helm_release" "cluster_autoscaler" {
  name       = "cluster-autoscaler"
  namespace  = "kube-system"
  repository = "https://kubernetes.github.io/autoscaler"
  chart      = "cluster-autoscaler"
  version    = "9.43.0"

  values = [
    yamlencode({
      autoDiscovery = {
        clusterName = module.eks.cluster_name
      }
      awsRegion = var.aws_region
      rbac = {
        serviceAccount = {
          create = true
          name   = "cluster-autoscaler"
          annotations = {
            "eks.amazonaws.com/role-arn" = module.irsa_cluster_autoscaler.iam_role_arn
          }
        }
      }
      extraArgs = {
        "balance-similar-node-groups" = "true"
        "skip-nodes-with-system-pods" = "false"
        "expander"                    = "least-waste"
      }
    })
  ]

  depends_on = [module.eks, helm_release.metrics_server]
}

# ExternalDNS (опционально: задайте hosted zone)
variable "external_dns_domain_filter" {
  description = "Домены для ExternalDNS (опционально)"
  type        = string
  default     = ""
}

resource "helm_release" "external_dns" {
  count      = length(var.external_dns_domain_filter) > 0 ? 1 : 0
  name       = "external-dns"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/external-dns/"
  chart      = "external-dns"
  version    = "1.15.0"

  values = [
    yamlencode({
      provider = "aws"
      policy   = "upsert-only"
      txtOwnerId = "${local.name_prefix}-extdns"
      domainFilters = [var.external_dns_domain_filter]
      sources = ["service", "ingress"]
      serviceAccount = {
        create = true
        name   = "external-dns"
        annotations = {
          "eks.amazonaws.com/role-arn" = module.irsa_external_dns.iam_role_arn
        }
      }
    })
  ]

  depends_on = [module.eks]
}

# ---------------------------
# Выводы
# ---------------------------
output "region" {
  value = var.aws_region
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
output "eks_oidc_provider_arn" {
  value = module.eks.oidc_provider_arn
}
output "ecr_repository_url" {
  value = aws_ecr_repository.ztc.repository_url
}
