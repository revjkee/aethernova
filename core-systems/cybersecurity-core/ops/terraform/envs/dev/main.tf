############################################
# cybersecurity-core / ops / terraform / envs / dev / main.tf
# Промышленный dev-стек: Backend, Providers, VPC, KMS, ECR, EKS, SecOps, Observability
############################################

terraform {
  required_version = ">= 1.6.6, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.57" # 5.x с исправлениями провайдера
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.29.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.5.0"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 3.2.0"
    }
  }

  # Backend: S3 (шифрование KMS) + DynamoDB lock
  backend "s3" {
    bucket         = "CHANGE-ME-cybersecurity-core-tfstate"      # создать заранее
    key            = "envs/dev/terraform.tfstate"
    region         = "eu-north-1"                                 # Стокгольм
    dynamodb_table = "CHANGE-ME-cybersecurity-core-tflock"        # создать заранее
    encrypt        = true
    kms_key_id     = "arn:aws:kms:eu-north-1:123456789012:key/CHANGE-ME" # KMS ключ для state
  }
}

########################
# Переменные окружения dev
########################

variable "aws_region" {
  description = "AWS регион для dev"
  type        = string
  default     = "eu-north-1"
}

variable "owner" {
  description = "Владелец (email/группа)"
  type        = string
  default     = "CHANGE-ME-owner@example.com"
}

variable "cost_center" {
  description = "Код кост-центра"
  type        = string
  default     = "SEC-000"
}

variable "vpc_cidr" {
  description = "CIDR блока VPC"
  type        = string
  default     = "10.70.0.0/16"
}

variable "az_count" {
  description = "Количество AZ для приватных/публичных подсетей"
  type        = number
  default     = 3
}

variable "eks_version" {
  description = "Версия Kubernetes/EKS"
  type        = string
  default     = "1.30"
}

variable "admin_role_arns" {
  description = "Список IAM Role ARNs с правами cluster-admin (system:masters)"
  type        = list(string)
  default     = []
}

########################
# Локали и теги
########################

locals {
  env         = "dev"
  project     = "cybersecurity-core"
  region      = var.aws_region
  name_prefix = "${local.project}-${local.env}"

  default_tags = {
    Project        = local.project
    Environment    = local.env
    Owner          = var.owner
    CostCenter     = var.cost_center
    ManagedBy      = "terraform"
    Compliance     = "iso27001;soc2"
    DataClass      = "confidential"
  }
}

########################
# Провайдеры и данные
########################

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = local.default_tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

########################
# Сеть (VPC) — terraform-aws-modules/vpc/aws
########################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.name_prefix}-vpc"
  cidr = var.vpc_cidr

  azs             = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  private_subnets = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, 240 + i)]

  enable_dns_hostnames = true
  enable_dns_support   = true

  enable_nat_gateway   = true
  single_nat_gateway   = true
  one_nat_gateway_per_az = false

  map_public_ip_on_launch = false

  enable_flow_log = true
  flow_log_destination_type = "cloud-watch-logs"

  tags = local.default_tags
}

########################
# KMS — модуль для ключа шифрования приложений/логов
########################

module "kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 1.0"

  description             = "KMS key for ${local.name_prefix}"
  key_alias               = "alias/${local.name_prefix}-app"
  enable_default_service_roles = true
  deletion_window_in_days = 7
  key_rotation            = true

  tags = local.default_tags
}

########################
# ECR — реестр контейнеров
########################

module "ecr" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 1.19"

  repository_name                 = "${local.name_prefix}"
  repository_force_delete         = true
  repository_image_tag_mutability = "MUTABLE"
  create_lifecycle_policy         = true

  repository_lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 30 images"
        selection = {
          tagStatus     = "any"
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = { type = "expire" }
      }
    ]
  })

  tags = local.default_tags
}

########################
# EKS — кластер Kubernetes (IRSA, аудит-логи)
########################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "${local.name_prefix}-eks"
  cluster_version = var.eks_
