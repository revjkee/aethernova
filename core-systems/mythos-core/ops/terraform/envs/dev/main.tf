#############################################
# mythos-core / ops/terraform/envs/dev/main.tf
# DEV окружение. Предположительно AWS (EKS). I cannot verify this.
#############################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.54"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.28"
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

  # Рекомендуется вынести значения backend в -backend-config=... при init.
  backend "s3" {
    bucket         = "mythos-tfstate-dev"   # заменить на существующий бакет
    key            = "terraform/dev/terraform.tfstate"
    region         = "eu-central-1"         # регион стейта
    dynamodb_table = "mythos-tf-locks"      # таблица блокировок
    encrypt        = true
  }
}

#########################
# ПЕРЕМЕННЫЕ С ДЕФОЛТАМИ
#########################

variable "project" {
  type        = string
  description = "Имя проекта (тэги/префиксы)"
  default     = "mythos-core"
}

variable "environment" {
  type        = string
  description = "Окружение"
  default     = "dev"
}

variable "region" {
  type        = string
  description = "AWS регион развертывания"
  default     = "eu-central-1"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR блока VPC"
  default     = "10.42.0.0/16"
}

variable "eks_version" {
  type        = string
  description = "Версия EKS"
  default     = "1.29" # I cannot verify this
}

variable "public_api_cidrs" {
  type        = list(string)
  description = "Список CIDR, которым разрешен доступ к публичной API EKS"
  default     = ["0.0.0.0/0"] # для DEV; ограничьте в PROD
}

variable "node_instance_types" {
  type        = list(string)
  description = "Типы инстансов для managed node groups"
  default     = ["t3.large", "t3a.large"]
}

variable "node_desired_size" {
  type        = number
  description = "Желаемое число узлов"
  default     = 2
}

variable "node_min_size" {
  type        = number
  default     = 1
}

variable "node_max_size" {
  type        = number
  default     = 5
}

#########################
# ЛОКАЛЫ И ТЭГИ
#########################

locals {
  name        = "${var.project}-${var.environment}"
  common_tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

#########################
# ПРОВАЙДЕРЫ И DATA
#########################

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

data "aws_availability_zones" "available" {
  state = "available"
}

#########################
# KMS ДЛЯ ШИФРОВАНИЯ
#########################

resource "aws_kms_key" "main" {
  description             = "KMS key for ${local.name} data at rest"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name}-kms"
  target_key_id = aws_kms_key.main.key_id
}

#########################
# VPC (terraform-aws-modules/vpc/aws)
#########################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name}-vpc"
  cidr = var.vpc_cidr

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  public_subnets  = [cidrsubnet(var.vpc_cidr, 4, 0), cidrsubnet(var.vpc_cidr, 4, 1), cidrsubnet(var.vpc_cidr, 4, 2)]
  private_subnets = [cidrsubnet(var.vpc_cidr, 4, 10), cidrsubnet(var.vpc_cidr, 4, 11), cidrsubnet(var.vpc_cidr, 4, 12)]

  enable_nat_gateway     = true
  single_nat_gateway     = true
  enable_dns_hostnames   = true
  enable_dns_support     = true
  map_public_ip_on_launch = false

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = local.common_tags
}

#########################
# ECR РЕПОЗИТОРИИ
#########################

resource "aws_ecr_repository" "repos" {
  for_each = toset([
    "training-worker",
    "serve-local",
    "llm-chat-demo"
  ])

  name                 = "${local.name}/${each.key}"
  image_tag_mutability = "MUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.main.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.common_tags
}

#########################
# S3 БАКЕТЫ ДЛЯ ДАННЫХ
#########################

resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.name}-artifacts"
  tags   = local.common_tags
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.main.arn
      }
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
    id     = "expire-multipart-uploads"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  rule {
    id     = "noncurrent-versions"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Бакет для "очередей"/джобов (если используется файловая очередь)
resource "aws_s3_bucket" "jobs" {
  bucket = "${local.name}-jobs"
  tags   = local.common_tags
}

resource "aws_s3_bucket_versioning" "jobs" {
  bucket = aws_s3_bucket.jobs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "jobs" {
  bucket = aws_s3_bucket.jobs.id
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.main.arn
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "jobs" {
  bucket                  = aws_s3_bucket.jobs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#########################
# CLOUDWATCH LOG GROUPS
#########################

resource "aws_cloudwatch_log_group" "app" {
  for_each          = toset(["training-worker", "serve-local", "llm-chat-demo"])
  name              = "/mythos/${var.environment}/${each.key}"
  retention_in_days = 14
  kms_key_id        = aws_kms_key.main.arn
  tags              = local.common_tags
}

#########################
# EKS КЛАСТЕР (terraform-aws-modules/eks/aws)
#########################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name                   = "${local.name}-eks"
  cluster_version                = var.eks_version
  cluster_endpoint_public_access = true
  cluster_endpoint_public_access_cidrs = var.public_api_cidrs

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Логи EKS API
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Шифрование секретов KMS
  kms_key_administrators = [data.aws_caller_identity.this.arn]
  create_kms_key         = false
  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = aws_kms_key.main.arn
  }

  # Managed Node Groups
  eks_managed_node_group_defaults = {
    ami_type       = "AL2_x86_64"
    disk_size      = 40
    instance_types = var.node_instance_types
    iam_role_additional_policies = {
      cw = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
    }
    labels = {
      "workload" = "general"
      "env"      = var.environment
    }
    tags = local.common_tags
  }

  eks_managed_node_groups = {
    general = {
      min_size     = var.node_min_size
      max_size     = var.node_max_size
      desired_size = var.node_desired_size
    }
  }

  # Аддоны EKS (версию можно опустить для latest совместимой)
  cluster_addons = {
    coredns = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni = { most_recent = true }
    aws-ebs-csi-driver = { most_recent = true }
  }

  tags = local.common_tags
}

#########################
# ДАННЫЕ ДЛЯ ПРОВАЙДЕРОВ K8S/HELM
#########################

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
# МИНИМАЛЬНАЯ СЕТЬ ДЛЯ ИНГРЕССА (опционально)
#########################

# Аннотации для ALB Ingress Controller/LoadBalancer можно добавлять в чартах.
# Здесь — security group для входящего трафика (DEV, 80/443 открыт). В PROD ограничить.
resource "aws_security_group" "ingress_lb" {
  name        = "${local.name}-ingress-lb"
  description = "Ingress LB SG"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

#########################
# ВЫВОДЫ
#########################

output "region" {
  value = var.region
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnets" {
  value = module.vpc.private_subnets
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "kubeconfig" {
  description = "Команда для генерации kubeconfig через awscli"
  value       = "aws eks update-kubeconfig --name ${module.eks.cluster_name} --region ${var.region}"
}

output "ecr_repositories" {
  value = { for k, r in aws_ecr_repository.repos : k => r.repository_url }
}

output "s3_artifacts_bucket" {
  value = aws_s3_bucket.artifacts.bucket
}

output "s3_jobs_bucket" {
  value = aws_s3_bucket.jobs.bucket
}

output "log_groups" {
  value = [for k, lg in aws_cloudwatch_log_group.app : lg.name]
}
