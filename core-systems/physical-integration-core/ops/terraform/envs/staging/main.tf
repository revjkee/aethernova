###############################################################################
# Terraform — staging | physical-integration-core
# Сеть (VPC), EKS (c KMS-шифрованием), node-groups, аддоны, провайдеры K8s/Helm
###############################################################################

terraform {
  required_version = "~> 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.52"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
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

  # Шаблон backend; замените значениями вашей инфраструктуры или используйте -backend-config
  backend "s3" {
    bucket         = "CHANGEME-neurocity-tfstate"
    key            = "physical-integration-core/staging/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "CHANGEME-neurocity-tf-lock"
    encrypt        = true
    # kms_key_id   = "arn:aws:kms:eu-north-1:111111111111:key/CHANGEME"
  }
}

########################
# Параметры и локальные
########################

variable "aws_region" {
  description = "AWS регион для staging"
  type        = string
  default     = "eu-north-1"
}

variable "vpc_cidr" {
  description = "CIDR для VPC staging"
  type        = string
  default     = "10.40.0.0/16"
}

variable "eks_version" {
  description = "Версия EKS"
  type        = string
  default     = "1.29"
}

locals {
  name   = "physical-integration-core"
  env    = "staging"
  prefix = "pic-stg"

  tags = {
    Project      = local.name
    Environment  = local.env
    ManagedBy    = "terraform"
    System       = "neurocity"
    Component    = "physical-integration-core"
    CostCenter   = "eng"
    Compliance   = "baseline"
  }

  # План подсетей: 2 AZ, 2 private + 2 public
  private_subnets = [for i in range(0, 2) : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i in range(2, 4) : cidrsubnet(var.vpc_cidr, 4, i)]
}

################
# Провайдер AWS
################

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

#############################
# Ключи KMS (EKS/Secrets, EBS)
#############################

resource "aws_kms_key" "eks_secrets" {
  description             = "KMS key for EKS secrets encryption (${local.prefix})"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  multi_region            = false

  tags = merge(local.tags, {
    Name = "${local.prefix}-eks-secrets-kms"
  })
}

resource "aws_kms_alias" "eks_secrets" {
  name          = "alias/${local.prefix}-eks-secrets"
  target_key_id = aws_kms_key.eks_secrets.key_id
}

resource "aws_kms_key" "ebs" {
  description             = "KMS key for EBS encryption (${local.prefix})"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.tags, {
    Name = "${local.prefix}-ebs-kms"
  })
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${local.prefix}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

########
#  VPC
########

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.prefix}-vpc"
  cidr = var.vpc_cidr

  azs             = slice(data.aws_availability_zones.available.names, 0, 2)
  private_subnets = local.private_subnets
  public_subnets  = local.public_subnets

  enable_dns_hostnames = true
  enable_dns_support   = true

  # Экономный staging: один NAT
  single_nat_gateway     = true
  enable_nat_gateway     = true
  enable_vpn_gateway     = false
  map_public_ip_on_launch = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = local.tags
}

############
#   EKS
############

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name    = "${local.prefix}-eks"
  cluster_version = var.eks_version

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  cluster_encryption_config = {
    resources = ["secrets"]
    provider_key_arn = aws_kms_key.eks_secrets.arn
  }

  create_cloudwatch_log_group = true
  cloudwatch_log_group_retention_in_days = 30
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Управляемые аддоны (версию можно зафиксировать при необходимости)
  cluster_addons = {
    coredns   = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni   = { most_recent = true }
    aws-ebs-csi-driver = {
      most_recent = true
      # При желании можно задать service_account_role_arn для строгого доступа
    }
  }

  # Node Groups
  eks_managed_node_groups = {
    default = {
      name               = "${local.prefix}-ng-default"
      desired_size       = 2
      max_size           = 4
      min_size           = 2
      instance_types     = ["m6a.large"]
      capacity_type      = "ON_DEMAND"
      ami_type           = "AL2_x86_64"
      disk_size          = 50
      force_update_version = true
      ebs_optimized        = true
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 50
            volume_type           = "gp3"
            encrypted             = true
            kms_key_id            = aws_kms_key.ebs.arn
            delete_on_termination = true
          }
        }
      }
      tags = merge(local.tags, { Name = "${local.prefix}-ng-default" })
    }

    physical = {
      name               = "${local.prefix}-ng-physical"
      desired_size       = 2
      max_size           = 4
      min_size           = 2
      instance_types     = ["c7a.large"]
      capacity_type      = "ON_DEMAND"
      ami_type           = "AL2_x86_64"
      disk_size          = 80
      labels             = { "workload" = "physical", "app.kubernetes.io/part-of" = "physical-integration-core" }
      taints             = [{ key = "workload", value = "physical", effect = "NO_SCHEDULE" }]
      force_update_version = true
      ebs_optimized        = true
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 80
            volume_type           = "gp3"
            encrypted             = true
            kms_key_id            = aws_kms_key.ebs.arn
            delete_on_termination = true
          }
        }
      }
      tags = merge(local.tags, { Name = "${local.prefix}-ng-physical" })
    }
  }

  tags = local.tags
}

########################################
# Kubernetes/Helm провайдеры (через EKS)
########################################

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

#########################
# Namespaces для работы
#########################

resource "kubernetes_namespace" "pic" {
  metadata {
    name = "physical-integration-core"
    labels = {
      "app.kubernetes.io/part-of" = "physical-integration-core"
      "environment"               = local.env
    }
  }
}

resource "kubernetes_namespace" "observability" {
  metadata {
    name = "observability"
    labels = {
      "system"      = "monitoring"
      "environment" = local.env
    }
  }
}

#########################
# Выходные значения
#########################

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

output "eks_cluster_endpoint" {
  value = data.aws_eks_cluster.this.endpoint
}

output "eks_cluster_oidc_issuer" {
  value = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

output "kms_key_eks_secrets_arn" {
  value = aws_kms_key.eks_secrets.arn
}

output "kms_key_ebs_arn" {
  value = aws_kms_key.ebs.arn
}
