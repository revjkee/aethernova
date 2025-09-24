#############################################
# physical-integration-core
# ops/terraform/envs/prod/main.tf
#############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }

  backend "s3" {
    bucket         = "aethernova-tfstate-prod"     # Укажите существующий бакет
    key            = "physical-integration-core/prod/terraform.tfstate"
    region         = "eu-north-1"                  # Прод‑регион
    dynamodb_table = "aethernova-tf-locks"         # Таблица для локов
    encrypt        = true
    kms_key_id     = null                          # Укажите KMS при необходимости
  }
}

#############################################
# Provider and defaults
#############################################

provider "aws" {
  region = "eu-north-1"

  default_tags {
    tags = {
      Project                           = "physical-integration-core"
      Environment                       = "prod"
      Owner                             = "platform-ops"
      "app.kubernetes.io/part-of"       = "physical-integration-core"
      "app.kubernetes.io/managed-by"    = "terraform"
      "app.kubernetes.io/environment"   = "prod"
    }
  }
}

data "aws_region" "this" {}
data "aws_caller_identity" "this" {}

# 3 доступные AZ для региона
data "aws_availability_zones" "available" {
  state = "available"
}

#############################################
# Locals: адресное пространство и параметры
#############################################

locals {
  # Базовый /16 для VPC; далее подмаски считаются cidrsubnet’ом
  vpc_cidr  = "10.64.0.0/16"

  # Количество AZ и их имена
  az_count  = 3
  az_names  = slice(data.aws_availability_zones.available.names, 0, local.az_count)

  # Пулы подсетей (детерминированы и не пересекаются)
  # /20 для public: netnums 0..2
  public_subnets_ipv4 = [for i in range(local.az_count) : cidrsubnet(local.vpc_cidr, 4, i)]
  # /20 для private: netnums 8..10
  private_subnets_ipv4 = [for i in range(local.az_count) : cidrsubnet(local.vpc_cidr, 4, i + 8)]
  # /21 для database: netnums 24..26 (меньше, изолированы)
  database_subnets_ipv4 = [for i in range(local.az_count) : cidrsubnet(local.vpc_cidr, 5, i + 24)]

  # Имя/теги
  name_prefix = "pic-prod"
  project     = "physical-integration-core"
  owner       = "platform-ops"

  # Interface endpoints (дополняйте по необходимости)
  interface_endpoints = [
    "ec2",
    "ecr.api",
    "ecr.dkr",
    "logs",
    "sts",
    "kms",
    "secretsmanager",
    "ssm",
    "ssm-messages",
    "ec2messages",
    "monitoring"
  ]

  # Кастомный формат логов VPC Flow Logs
  flow_logs_format = "${version} ${vpc-id} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${tcp-flags} ${type} ${subtype} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id}"
}

#############################################
# Network module (IPv6, NAT per-AZ, Flow Logs)
#############################################

module "network" {
  source = "../../modules/network"

  name_prefix  = local.name_prefix
  environment  = "prod"
  project      = local.project
  owner        = local.owner

  # Адресация/зоны
  vpc_cidr     = local.vpc_cidr
  enable_ipv6  = true
  az_count     = local.az_count
  az_names     = local.az_names

  public_subnets_ipv4   = local.public_subnets_ipv4
  private_subnets_ipv4  = local.private_subnets_ipv4
  database_subnets_ipv4 = local.database_subnets_ipv4

  # Базовые флаги VPC
  instance_tenancy          = "default"
  create_internet_gateway   = true

  # NAT‑паттерн для продакшена
  nat_strategy = "per-az" # "per-az" | "single" | "none"

  # NACL и дефолтный egress‑SG для ворклоадов
  create_private_nacl     = true
  create_default_egress_sg= true

  # Flow Logs в CloudWatch
  flow_logs_strategy             = "cloudwatch"  # "cloudwatch" | "s3" | "none"
  flow_logs_cw_retention_days    = 90
  flow_logs_kms_key_id           = null
  flow_logs_log_format           = local.flow_logs_format
  flow_logs_aggregation_interval = 60

  # VPC Endpoints
  enable_s3_gateway_endpoint       = true
  enable_dynamodb_gateway_endpoint = true
  interface_endpoints              = local.interface_endpoints

  # Дополнительные теги
  tags = {
    "CostCenter" = "core-networking"
    "OwnerTeam"  = "platform"
  }
}

#############################################
# (Необязательно) Пример экспорта часто нужных значений
# Вы можете вынести в отдельный outputs.tf
#############################################

output "vpc_id" {
  value       = module.network.aws_vpc_id
  description = "ID созданного VPC"
}

output "public_subnet_ids" {
  value       = module.network.public_subnet_ids
  description = "Public subnet IDs (per AZ)"
}

output "private_subnet_ids" {
  value       = module.network.private_subnet_ids
  description = "Private subnet IDs (per AZ)"
}

output "database_subnet_ids" {
  value       = module.network.database_subnet_ids
  description = "Database subnet IDs (per AZ)"
}
