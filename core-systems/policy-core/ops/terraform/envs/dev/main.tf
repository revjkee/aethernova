#############################################
# policy-core/ops/terraform/envs/dev/main.tf
#############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
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

  # Для DEV используем локальный стейт.
  # Для stage/prod перенесите backend в S3/DynamoDB.
  backend "local" {
    path = "terraform.tfstate"
  }
}

############################
# Параметры окружения DEV
############################

variable "aws_region" {
  description = "Регион AWS для окружения dev"
  type        = string
  default     = "eu-north-1" # Стокгольм
}

variable "aws_profile" {
  description = "AWS CLI/SDK профиль (опционально)"
  type        = string
  default     = null
}

variable "cluster_version" {
  description = "Версия Kubernetes для EKS"
  type        = string
  default     = "1.29"
}

locals {
  project     = "policy-core"
  environment = "dev"
  name        = "${local.project}-${local.environment}"

  tags = {
    Project     = local.project
    Environment = local.environment
    ManagedBy   = "Terraform"
    Module      = "envs/dev"
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

############################
# Случайный суффикс для уникальности имен
############################

resource "random_id" "suffix" {
  byte_length = 2
}

############################
# KMS: ключ для шифрования артефактов/репозиториев
############################

resource "aws_kms_key" "main" {
  description             = "${local.name} KMS key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name}-primary"
  target_key_id = aws_kms_key.main.key_id
}

############################
# S3: бакет артефактов dev
############################

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${local.name}-artifacts-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-noncurrent"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

############################
# ECR: репозиторий образов policy-core
############################

resource "aws_ecr_repository" "policy" {
  name                 = local.project
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.main.arn
  }
}

resource "aws_ecr_lifecycle_policy" "policy" {
  repository = aws_ecr_repository.policy.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 50 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 50
        }
        action = { type = "expire" }
      }
    ]
  })
}

############################
# CloudWatch Logs: базовая группа логов
############################

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${local.project}/${local.environment}/app"
  retention_in_days = 14
  kms_key_id        = aws_kms_key.main.arn
}

############################
# VPC через официальный модуль
############################

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = local.name
  cidr = "10.80.0.0/16"

  azs             = slice(data.aws_availability_zones.available.names, 0, 2)
  public_subnets  = ["10.80.0.0/20", "10.80.16.0/20"]
  private_subnets = ["10.80.32.0/20", "10.80.48.0/20"]

  enable_dns_hostnames = true
  enable_dns_support   = true

  enable_nat_gateway   = true
  single_nat_gateway   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = local.tags
}

############################
# EKS через официальный модуль
############################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = local.name
  cluster_version = var.cluster_version

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  enable_irsa              = true
  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = false

  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = aws_kms_key.main.arn
  }

  cluster_addons = {
    coredns   = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni   = { most_recent = true }
  }

  eks_managed_node_group_defaults = {
    disk_size      = 20
    ami_type       = "AL2_x86_64"
    instance_types = ["t3.medium"]
    capacity_type  = "ON_DEMAND"
  }

  eks_managed_node_groups = {
    default = {
      min_size     = 1
      desired_size = 2
      max_size     = 3
      labels = {
        "workload" = "general"
        "env"      = local.environment
      }
      taints = []
    }
  }

  tags = local.tags
}

############################
# Выводы
############################

output "region" {
  value       = var.aws_region
  description = "Регион AWS"
}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "ID аккаунта AWS"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "ID созданной VPC"
}

output "private_subnets" {
  value       = module.vpc.private_subnets
  description = "Приватные подсети"
}

output "public_subnets" {
  value       = module.vpc.public_subnets
  description = "Публичные подсети"
}

output "kms_key_arn" {
  value       = aws_kms_key.main.arn
  description = "ARN KMS ключа"
}

output "artifacts_bucket" {
  value       = aws_s3_bucket.artifacts.bucket
  description = "Имя S3 бакета артефактов"
}

output "ecr_repository_url" {
  value       = aws_ecr_repository.policy.repository_url
  description = "URL ECR репозитория"
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "Имя EKS кластера"
}

output "eks_cluster_endpoint" {
  value       = module.eks.cluster_endpoint
  description = "Endpoint Kubernetes API"
}

output "eks_oidc_provider_arn" {
  value       = module.eks.oidc_provider_arn
  description = "ARN OIDC провайдера для IRSA"
}
