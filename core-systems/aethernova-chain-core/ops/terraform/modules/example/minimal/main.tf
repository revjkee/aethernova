/**
 * Aethernova — Remote State Bootstrap (AWS S3 + DynamoDB)
 * File: ops/terraform/modules/bootstrap/remote-state/examples/minimal/main.tf
 *
 * Назначение:
 * Пример промышленного вызова модуля bootstrap/remote-state.
 * Модуль создаёт S3-бакет для хранения terraform.tfstate и таблицу DynamoDB для блокировок.
 * После применения этого примера вы сможете сконфигурировать backend в рабочих каталогах.
 */

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60" # зафиксируйте при необходимости
    }
  }
}

# -------- Provider --------
provider "aws" {
  region = var.aws_region
}

# -------- Data --------
data "aws_caller_identity" "this" {}
data "aws_region" "current" {}

# -------- Locals --------
locals {
  # Базовая схема тегов для идентификации ресурсов
  default_tags = {
    Project        = "aethernova-chain-core"
    Module         = "bootstrap/remote-state"
    Environment    = var.environment
    ManagedBy      = "Terraform"
    Owner          = var.owner
    CostCenter     = var.cost_center
    TerraformState = "true"
  }

  # Имя бакета и таблицы можно задать явно, либо оставить вычисление по шаблону
  state_bucket_name = coalesce(
    var.state_bucket_name,
    format("%s-terraform-state-%s-%s", replace(local.default_tags.Project, "/[^a-z0-9-]/", ""), var.environment, data.aws_region.current.name)
  )

  lock_table_name = coalesce(
    var.lock_table_name,
    format("%s-terraform-locks-%s", replace(local.default_tags.Project, "/[^a-z0-9-]/", ""), var.environment)
  )
}

# -------- Module Call --------
module "remote_state" {
  # Путь до корня модуля из каталога examples/minimal
  source = "../.."

  providers = {
    aws = aws
  }

  # Обязательные параметры
  environment = var.environment

  # Необязательные (промышленная конфигурация по умолчанию)
  state_bucket_name   = local.state_bucket_name
  lock_table_name     = local.lock_table_name
  force_destroy       = false
  enable_versioning   = true
  enable_encryption   = true
  sse_algorithm       = "aws:kms"       # или "AES256"
  kms_key_arn         = var.kms_key_arn # если null — будет использоваться AWS-managed ключ
  block_public_access = true
  bucket_ownership    = "BucketOwnerEnforced" # строгая модель владения объектами

  # Lifecycle политики для оптимизации хранения
  lifecycle_rules = [
    {
      id                                     = "transition-current-to-standard-ia"
      enabled                                = true
      noncurrent_version_transition_days     = null
      noncurrent_version_glacier_transition  = null
      noncurrent_version_expiration_days     = null
      transition_days                        = 30
      transition_storage_class               = "STANDARD_IA"
      expiration_days                        = 365
      abort_incomplete_multipart_upload_days = 7
      tags                                   = null
    }
  ]

  # Политика блокировок DDB (R/W Capacity auto/on-demand – внутри модуля)
  dynamodb_billing_mode = "PAY_PER_REQUEST"

  # Теги
  tags = merge(local.default_tags, var.extra_tags)
}

# -------- Outputs (из примера для удобства) --------
output "state_bucket_name" {
  description = "Имя S3 бакета для Terraform State"
  value       = module.remote_state.state_bucket_name
}

output "lock_table_name" {
  description = "Имя DynamoDB таблицы для блокировок Terraform"
  value       = module.remote_state.lock_table_name
}

output "region" {
  description = "Регион AWS, где развёрнуты ресурсы удалённого состояния"
  value       = data.aws_region.current.name
}

# -------- Variables (пример делает файл самодостаточным) --------
variable "aws_region" {
  description = "Регион AWS для размещения ресурсов удалённого состояния"
  type        = string
  default     = "eu-central-1"
}

variable "environment" {
  description = "Среда: dev|staging|prod и т.п."
  type        = string
  default     = "dev"
}

variable "owner" {
  description = "Ответственный владелец ресурсов"
  type        = string
  default     = "platform-ops"
}

variable "cost_center" {
  description = "Код затратного центра"
  type        = string
  default     = "CC-0000"
}

variable "kms_key_arn" {
  description = "Опциональный KMS ключ для шифрования бакета. Если null — будет использован AWS-управляемый ключ."
  type        = string
  default     = null
}

variable "state_bucket_name" {
  description = "Необязательное явное имя S3 бакета для state. Если не задано — формируется автоматически."
  type        = string
  default     = null
}

variable "lock_table_name" {
  description = "Необязательное явное имя DynamoDB таблицы для блокировок. Если не задано — формируется автоматически."
  type        = string
  default     = null
}

variable "extra_tags" {
  description = "Дополнительные теги для ресурсов"
  type        = map(string)
  default     = {}
}
