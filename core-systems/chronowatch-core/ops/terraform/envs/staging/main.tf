terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60" # LTS-ветка на момент подготовки
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
  }

  backend "s3" {
    # ЗАПОЛНИТЕ ПОД СВОЮ АККАУНТ/ОРГАНИЗАЦИЮ
    bucket         = "<your-tfstate-bucket>"
    key            = "chronowatch-core/staging/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "<your-tfstate-lock-table>"
    encrypt        = true
  }
}

###############################################################################
# БАЗОВЫЕ НАСТРОЙКИ И ТЕГИ
###############################################################################

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = local.project
      Environment = local.env
      Owner       = var.owner
      ManagedBy   = "terraform"
      Repository  = "chronowatch-core"
      Compliance  = "baseline"
    }
  }
}

locals {
  project = "chronowatch-core"
  env     = "staging"

  # Сетевые параметры (/16 -> 4 х /20)
  vpc_cidr             = "10.42.0.0/16"
  private_subnets_cidr = ["10.42.0.0/20", "10.42.16.0/20", "10.42.32.0/20"]
  public_subnets_cidr  = ["10.42.128.0/20", "10.42.144.0/20", "10.42.160.0/20"]

  eks_version = var.eks_version
  cluster_name = "${local.project}-${local.env}"
}

data "aws_caller_identity" "this" {}
data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

###############################################################################
# СЕТЬ — VPC С ПРИВАТНЫМИ/ПУБЛИЧНЫМИ ПОДСЕТЯМИ И NAT
###############################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.project}-${local.env}"
  cidr = local.vpc_cidr

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = local.private_subnets_cidr
  public_subnets  = local.public_subnets_cidr

  enable_nat_gateway     = true
  single_nat_gateway     = true
  enable_dns_hostnames   = true
  enable_dns_support     = true
  map_public_ip_on_launch = false

  # Flow Logs (лёгкие дефолты; при необходимости включите и укажите IAM role/S3)
  enable_flow_log           = false
  flow_log_max_aggregation_interval = 60

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = {
    Tier = "network"
  }
}

###############################################################################
# EKS — ПРОДАКШН-ДЕФОЛТЫ С IRSA И ADDONS
###############################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.24"

  cluster_name    = local.cluster_name
  cluster_version = local.eks_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = false

  # Базовые addon’ы
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
      # Для стабильности сетевого плагина можно закрепить спец. значения
      configuration_values = jsonencode({
        env = {
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_ENI_TARGET          = "1"
          WARM_IP_TARGET           = "5"
        }
      })
    }
  }

  # Управление auth map — вручную из GitOps/IR
  manage_aws_auth_configmap = false

  eks_managed_node_groups = {
    default = {
      instance_types = ["t3.large"]
      desired_size   = 2
      min_size       = 2
      max_size       = 5

      capacity_type = "ON_DEMAND"

      labels = {
        "workload" = "general"
        "env"      = local.env
      }

      taints = []
      update_config = {
        max_unavailable_percentage = 25
      }

      iam_role_additional_policies = {
        # Доступ к CloudWatch Logs при необходимости
        cwlogs = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
      }
    }
  }

  tags = {
    Tier = "compute"
  }
}

###############################################################################
# ECR — РЕПОЗИТОРИЙ ДЛЯ ОБРАЗОВ ПРОЕКТА
###############################################################################

module "ecr" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 1.7"

  repository_name                 = local.project
  repository_image_scan_on_push   = true
  repository_encryption_type      = "AES256"

  repository_force_delete         = true # в staging удобно для CI cleanup

  lifecycle_policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 30 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 30
      }
      action = { type = "expire" }
    }]
  })

  tags = {
    Tier = "registry"
  }
}

###############################################################################
# ПРОВАЙДЕРЫ KUBERNETES/HELM ДЛЯ ДАЛЬНЕЙШЕГО DEPLOY
###############################################################################

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

###############################################################################
# (ОПЦ.) ПОДГОТОВКА IRSA ДЛЯ AWS LOAD BALANCER CONTROLLER
###############################################################################

module "irsa_lb_controller" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                          = "${local.cluster_name}-alb-controller"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    eks = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = {
    Tier = "iam"
  }
}

# Пример Helm-релиза ALB Controller (установите после создания кластера)
resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = "1.8.1" # зафиксированная версия чарта

  depends_on = [module.eks, module.irsa_lb_controller]

  values = [yamlencode({
    clusterName = module.eks.cluster_name
    serviceAccount = {
      create = true
      name   = "aws-load-balancer-controller"
      annotations = {
        "eks.amazonaws.com/role-arn" = module.irsa_lb_controller.iam_role_arn
      }
    }
    region = var.aws_region
    vpcId  = module.vpc.vpc_id
  })]
}

###############################################################################
# ВЫВОДЫ
###############################################################################

output "region" {
  value       = var.aws_region
  description = "AWS region for staging."
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID."
}

output "private_subnets" {
  value       = module.vpc.private_subnets
  description = "Private subnet IDs."
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "EKS cluster name."
}

output "eks_cluster_endpoint" {
  value       = data.aws_eks_cluster.this.endpoint
  description = "EKS API endpoint."
}

output "ecr_repository_url" {
  value       = module.ecr.repository_url
  description = "ECR repository URL for chronowatch-core images."
}
