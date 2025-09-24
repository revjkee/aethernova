terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }

  # Удалённое хранилище состояния + блокировка (заполните плейсхолдеры)
  backend "s3" {
    bucket         = "REPLACE_ME-tfstate"          # например: datafabric-core-tfstate
    key            = "envs/dev/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "REPLACE_ME-tflock"           # например: datafabric-core-tflock
    encrypt        = true
  }
}

############################
# Вводные переменные окружения dev
############################
variable "aws_region" {
  description = "Регион AWS для dev окружения."
  type        = string
  default     = "eu-central-1"
}

variable "project" {
  description = "Идентификатор проекта."
  type        = string
  default     = "datafabric-core"
}

variable "env" {
  description = "Имя окружения."
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR-блок VPC."
  type        = string
  default     = "10.10.0.0/16"
}

# Экономичный dev: один NAT на все AZ
variable "nat_gateway_strategy" {
  description = "Стратегия NAT: none | single | per-az."
  type        = string
  default     = "single"
}

############################
# Провайдер и базовые данные
############################
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      "Project"                   = var.project
      "Environment"               = var.env
      "app.kubernetes.io/name"    = var.project
      "app.kubernetes.io/part-of" = var.project
      "managed-by"                = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
# Фильтруем AZ только с поддержкой рынка (без 'local-zone')
data "aws_availability_zones" "available" {
  state = "available"
  # При необходимости можно исключить локальные зоны/аутпосты:
  # filter { name = "opt-in-status"; values = ["opt-in-not-required", "opted-in"] }
}

############################
# Локальные значения dev
############################
locals {
  # Имя окружения в тегах/ресурсах
  name = "${var.project}-${var.env}"

  # Берём первые 2 AZ для dev
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  # Единая карта тегов для модулей
  common_tags = {
    "Name"                     = local.name
    "Environment"              = var.env
    "Owner"                    = "platform-team"
    "CostCenter"               = "dev"
    "application"              = var.project
    "terraform.module.root"    = "envs/dev"
  }
}

############################
# Модуль сети (internal)
# Использует ваш модуль: ../../modules/network
############################
module "network" {
  source = "../../modules/network"

  name       = local.name
  cidr_block = var.vpc_cidr
  azs        = local.azs

  enable_ipv6              = true
  public_subnet_newbits    = 4
  private_subnet_newbits   = 4
  nat_gateway_strategy     = var.nat_gateway_strategy

  enable_flow_logs         = true
  flow_logs_retention_days = 14

  enable_gateway_endpoints = true
  interface_endpoints      = [
    "ecr.api",
    "ecr.dkr",
    "logs",
    "sts"
  ]

  tags = local.common_tags
}

############################
# Пример: S3 bucket для артефактов dev (опционально)
############################
resource "aws_s3_bucket" "artifacts" {
  bucket        = "${local.name}-artifacts"
  force_destroy = true

  tags = merge(local.common_tags, {
    "Component" = "artifacts"
  })
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
      sse_algorithm = "AES256"
    }
  }
}

############################
# Выходные значения (для быстрого доступа)
############################
output "vpc_id" {
  description = "ID созданной VPC dev."
  value       = module.network.vpc_id
}

output "public_subnet_ids" {
  description = "Публичные подсети dev."
  value       = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  description = "Приватные подсети dev."
  value       = module.network.private_subnet_ids
}

output "region" {
  description = "Регион AWS для dev."
  value       = data.aws_region.current.name
}

output "account_id" {
  description = "AWS Account ID."
  value       = data.aws_caller_identity.current.account_id
}
