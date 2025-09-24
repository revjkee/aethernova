// neuroforge-core/ops/terraform/envs/dev/main.tf
// Промышленная конфигурация DEV окружения на AWS.
// Внимание: заполните плейсхолдеры в backend "s3" (bucket, dynamodb_table, kms_key_id) и переменные.

// -----------------------------
// Версии Terraform и провайдеров
// -----------------------------
terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60" // фиксируем мажор для предсказуемости
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "s3" {
    // ПЛЕЙСХОЛДЕРЫ: замените на значения вашей организации
    bucket         = "tfstate-neuroforge-core"   // имя S3 бакета для стейта
    key            = "envs/dev/terraform.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "tfstate-locks"             // таблица блокировок
    encrypt        = true
    kms_key_id     = "arn:aws:kms:eu-west-1:111122223333:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  }
}

// -----------------------------
// Провайдер и базовые данные
// -----------------------------
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project      = "neuroforge-core"
      Environment  = local.env
      Owner        = var.owner
      ManagedBy    = "terraform"
      CostCenter   = var.cost_center
      Confidential = "false"
    }
  }
}

data "aws_caller_identity" "this" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

// -----------------------------
// Локали и переменные
// -----------------------------
locals {
  env         = "dev"
  name_prefix = "${local.env}-neuroforge-core"
  azs         = slice(data.aws_availability_zones.available.names, 0, 3)

  // Общие теги для модулей, не попадающие в default_tags
  module_tags = {
    TerraformModule = "true"
  }
}

// -----------------------------
// Вводные переменные
// -----------------------------
variable "region" {
  description = "AWS регион для DEV"
  type        = string
  default     = "eu-west-1"
}

variable "owner" {
  description = "Ответственный владелец"
  type        = string
  default     = "platform@your-org"
}

variable "cost_center" {
  description = "Код центра затрат"
  type        = string
  default     = "DEV-PLATFORM"
}

variable "vpc_cidr" {
  description = "CIDR для VPC"
  type        = string
  default     = "10.10.0.0/16"
}

variable "kubernetes_version" {
  description = "Версия EKS кластера"
  type        = string
  default     = "1.29"
}

variable "eks_instance_types" {
  description = "Типы инстансов воркеров"
  type        = list(string)
  default     = ["t3.medium"]
}

variable "eks_desired_size" {
  description = "Желаемое число узлов"
  type        = number
  default     = 2
}

variable "eks_min_size" {
  description = "Минимум узлов"
  type        = number
  default     = 1
}

variable "eks_max_size" {
  description = "Максимум узлов"
  type        = number
  default     = 3
}

variable "enable_cluster_log_types" {
  description = "Типы логов EKS для CloudWatch"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "ecr_mutability" {
  description = "Политика мутабельности образов ECR"
  type        = string
  default     = "IMMUTABLE" // для DEV допускается IMMUTABLE, меняйте осознанно
}

variable "artifacts_bucket_name" {
  description = "Имя S3-бакета артефактов приложения (оставьте пустым для автогенерации)"
  type        = string
  default     = ""
}

// -----------------------------
// Модуль VPC (официальный)
// -----------------------------
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = local.name_prefix
  cidr = var.vpc_cidr
  azs  = local.azs

  public_subnets  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  private_subnets = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 8)]

  enable_nat_gateway     = true
  single_nat_gateway     = true
  one_nat_gateway_per_az = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = merge(local.module_tags, {
    "kubernetes.io/role/elb" = "1"
  })

  private_subnet_tags = merge(local.module_tags, {
    "kubernetes.io/role/internal-elb" = "1"
  })

  tags = local.module_tags
}

// -----------------------------
// Модуль EKS (официальный)
// -----------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.11"

  cluster_name                   = local.name_prefix
  cluster_version                = var.kubernetes_version
  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  cluster_enabled_log_types = var.enable_cluster_log_types

  eks_managed_node_groups = {
    default = {
      instance_types = var.eks_instance_types
      min_size       = var.eks_min_size
      max_size       = var.eks_max_size
      desired_size   = var.eks_desired_size

      ami_type       = "AL2_x86_64"
      capacity_type  = "ON_DEMAND"

      labels = {
        "workload" = "general"
        "env"      = local.env
      }

      taints = []

      update_config = {
        max_unavailable_percentage = 33
      }

      tags = local.module_tags
    }
  }

  tags = local.module_tags
}

// -----------------------------
// Репозиторий ECR для образов
// -----------------------------
resource "aws_ecr_repository" "app" {
  name                 = "${local.name_prefix}-app"
  image_tag_mutability = var.ecr_mutability

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    // Для DEV допустимо AWS-managed key, для PROD лучше указать customer-managed KMS
    // kms_key = "arn:aws:kms:..." // при необходимости
  }

  tags = local.module_tags
}

// Политика удержания только последних 30 образов с тегами
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy     = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 30 tagged images"
        selection    = {
          tagStatus     = "tagged"
          tagPrefixList = [""]
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Expire untagged older than 14 days"
        selection    = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 14
        }
        action = { type = "expire" }
      }
    ]
  })
}

// -----------------------------
// S3 бакет артефактов (без публичного доступа)
// -----------------------------
resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  artifacts_bucket_final = length(var.artifacts_bucket_name) > 0 ? var.artifacts_bucket_name : "${local.name_prefix}-artifacts-${random_id.suffix.hex}"
}

resource "aws_s3_bucket" "artifacts" {
  bucket = local.artifacts_bucket_final
  tags   = local.module_tags
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
      sse_algorithm = "aws:kms"
      // kms_master_key_id = "arn:aws:kms:..." // при необходимости
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

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
  rule {
    id     = "cleanup-mpu-aborts"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

// -----------------------------
// Полезные outputs
// -----------------------------
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
  description = "Приватные подсети для EKS"
}

output "public_subnets" {
  value       = module.vpc.public_subnets
  description = "Публичные подсети для балансировщиков"
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "Имя кластера EKS"
}

output "eks_cluster_endpoint" {
  value       = module.eks.cluster_endpoint
  description = "Публичный endpoint API сервера EKS"
}

output "eks_cluster_version" {
  value       = module.eks.cluster_version
  description = "Версия Kubernetes кластера"
}

output "ecr_repository_url" {
  value       = aws_ecr_repository.app.repository_url
  description = "URL ECR репозитория"
}

output "artifacts_bucket" {
  value       = aws_s3_bucket.artifacts.bucket
  description = "S3 бакет для артефактов"
}
