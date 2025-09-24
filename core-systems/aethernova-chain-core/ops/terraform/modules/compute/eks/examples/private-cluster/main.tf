terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.9.0"
    }
  }
}

################################################################################
# Provider & Data
################################################################################

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name_prefix = "aethernova-eks-private"
  # Базовый /16, разрежём на подсети ниже
  vpc_cidr    = "10.80.0.0/16"
  azs         = slice(data.aws_availability_zones.available.names, 0, 3)

  # 3 приватные подсети /20
  private_subnets = [
    cidrsubnet(local.vpc_cidr, 4, 0),
    cidrsubnet(local.vpc_cidr, 4, 1),
    cidrsubnet(local.vpc_cidr, 4, 2)
  ]
}

################################################################################
# VPC (без IGW/NAT), только приватные подсети и приватный DNS
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.0"

  name = "${local.name_prefix}-vpc"
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = local.private_subnets

  # Кластер private-only: без IGW/NAT
  create_igw        = false
  enable_nat_gateway = false

  enable_dns_support   = true
  enable_dns_hostnames = true

  # Ускоряет кластеры и контроллеры за счёт стандартной метки
  tags = {
    Project     = "Aethernova"
    Environment = "prod"
    ManagedBy   = "Terraform"
  }
}

################################################################################
# Security Group для Interface VPC Endpoints (443 из VPC)
################################################################################

resource "aws_security_group" "vpce" {
  name        = "${local.name_prefix}-vpce-sg"
  description = "Security group for Interface VPC Endpoints"
  vpc_id      = module.vpc.vpc_id

  egress {
    description = "Egress anywhere (for return traffic)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  tags = {
    Name        = "${local.name_prefix}-vpce-sg"
    ManagedBy   = "Terraform"
  }
}

################################################################################
# VPC Endpoints для приватной работы кластера (Interface + S3 Gateway)
# - Обязательные для EKS private-only (см. таблицу в EKS docs)
################################################################################

# Gateway endpoint для S3 (ECR слои в S3; маршрут в приватные RT)
# Политика минимального доступа к региональному ECR bucket для слоёв
data "aws_iam_policy_document" "s3_vpce_policy" {
  statement {
    sid     = "AllowECRLayerReads"
    actions = ["s3:GetObject"]
    resources = [
      "arn:aws:s3:::prod-${var.region}-starport-layer-bucket/*"
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = module.vpc.private_route_table_ids
  policy          = data.aws_iam_policy_document.s3_vpce_policy.json

  tags = {
    Name = "${local.name_prefix}-s3"
  }
}

# Набор Interface endpoints по рекомендации EKS Private Clusters
# ec2, ecr.api, ecr.dkr, logs, sts, elasticloadbalancing, eks, eks-auth
locals {
  interface_services = toset([
    "ec2",
    "ecr.api",
    "ecr.dkr",
    "logs",
    "sts",
    "elasticloadbalancing",
    "eks",
    "eks-auth"
  ])
}

resource "aws_vpc_endpoint" "interface" {
  for_each          = local.interface_services
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type = "Interface"

  subnet_ids          = module.vpc.private_subnets
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.vpce.id]

  tags = {
    Name = "${local.name_prefix}-vpce-${each.key}"
  }
}

################################################################################
# Amazon EKS (cluster + managed node group) — приватный endpoint only
################################################################################

# Версия Kubernetes (актуальные на момент публикации: 1.33/1.32/1.31)
variable "kubernetes_version" {
  type        = string
  description = "EKS Kubernetes version"
  default     = "1.33"
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.1"

  name               = "${local.name_prefix}"
  kubernetes_version = var.kubernetes_version

  # Полностью приватный API-сервер (см. EKS docs)
  endpoint_public_access  = false
  endpoint_private_access = true

  # Доступ администратора для создателя в момент развёртывания
  enable_cluster_creator_admin_permissions = true

  # Подсети для узлов и для control plane ENI — приватные
  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  # Базовые аддоны EKS (подтянуты как управляемые EKS Add-ons)
  addons = {
    vpc-cni = {
      before_compute = true
    }
    coredns    = {}
    kube-proxy = {}
    eks-pod-identity-agent = {
      before_compute = true
    }
  }

  # Managed Node Group (частный пул)
  eks_managed_node_groups = {
    default = {
      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = ["m5.large"]

      min_size     = 2
      desired_size = 2
      max_size     = 6

      subnet_ids = module.vpc.private_subnets
    }
  }

  tags = {
    Project     = "Aethernova"
    Environment = "prod"
    ManagedBy   = "Terraform"
  }
}

################################################################################
# Удобные выходы
################################################################################

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint (private)"
  value       = module.eks.cluster_endpoint
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnets" {
  value = module.vpc.private_subnets
}
