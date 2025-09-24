// neuroforge-core/ops/terraform/modules/registry/main.tf
// Промышленный модуль AWS ECR (приватный реестр) с безопасными настройками.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

# --------------------------
# Входные переменные
# --------------------------
variable "name" {
  description = "Имя ECR-репозитория (kebab_case). Будет частью URL."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]+(?:[._/-][a-z0-9]+)*$", var.name))
    error_message = "name должен соответствовать паттерну ^[a-z0-9]+(?:[._/-][a-z0-9]+)*$."
  }
}

variable "tags" {
  description = "Общие теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "immutable_tags" {
  description = "Запрет перезаписи тегов образов (рекомендуется true)."
  type        = bool
  default     = true
}

variable "scan_on_push" {
  description = "Включить сканирование уязвимостей при публикации."
  type        = bool
  default     = true
}

variable "encryption_type" {
  description = "Тип шифрования образов: AES256 или KMS."
  type        = string
  default     = "KMS"
  validation {
    condition     = contains(["AES256", "KMS"], var.encryption_type)
    error_message = "encryption_type должен быть 'AES256' или 'KMS'."
  }
}

variable "create_kms_key" {
  description = "Создавать собственный KMS-ключ для ECR."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Если create_kms_key=false, ARN существующего KMS ключа для шифрования ECR."
  type        = string
  default     = ""
}

variable "lifecycle_keep_last" {
  description = "Сколько последних тегированных образов хранить (правило 1)."
  type        = number
  default     = 50
}

variable "lifecycle_untagged_expire_days" {
  description = "Удалять нетегированные манифесты старше X дней (правило 2). 0 — отключить."
  type        = number
  default     = 14
}

variable "allow_push_principals" {
  description = "Список ARNs субъектов (IAM Role/User), которым разрешён push/pull."
  type        = list(string)
  default     = []
}

variable "allow_pull_principals" {
  description = "Список ARNs субъектов, которым разрешён только pull."
  type        = list(string)
  default     = []
}

variable "replicate_to" {
  description = <<EOT
Список регионов-получателей для кросс-региональной репликации ECR.
Пример: ["eu-west-1", "eu-central-1"]. Пусто — репликация отключена.
EOT
  type    = list(string)
  default = []
}

variable "replication_registry_ids" {
  description = "Необязательные целевые AWS account IDs для репликации (по умолчанию текущий)."
  type        = list(string)
  default     = []
}

variable "enable_registry_scanning" {
  description = "Глобальная конфигурация сканирования реестра на уровне аккаунта."
  type        = bool
  default     = true
}

variable "registry_scan_rules" {
  description = "Правила глобального сканирования на уровне реестра (severity)."
  type = list(object({
    scan_frequency = optional(string, "SCAN_ON_PUSH") # CONTINUOUS_SCAN or SCAN_ON_PUSH
    rules = optional(list(object({
      # Например: applied_rules = ["CRITICAL","HIGH"]
      maximum_severity = string
      repository_filters = optional(list(object({
        filter       = string
        filter_type  = string   # WILDCARD
      })), [])
    })), [])
  }))
  default = []
}

variable "enable_pull_through_cache" {
  description = "Включить Pull Through Cache правила (кеширование удалённых реестров)."
  type        = bool
  default     = false
}

variable "pull_through_cache_rules" {
  description = <<EOT
Список правил pull-through cache.
Пример:
[
  { ecr_repository_prefix = "dockerhub", upstream_registry_url = "registry.hub.docker.com" },
  { ecr_repository_prefix = "ghcr",     upstream_registry_url = "ghcr.io" }
]
EOT
  type = list(object({
    ecr_repository_prefix = string
    upstream_registry_url = string
  }))
  default = []
}

# --------------------------
# Локальные значения и данные
# --------------------------
data "aws_caller_identity" "this" {}
data "aws_partition" "this" {}
data "aws_region" "this" {}

locals {
  effective_kms_arn = var.encryption_type == "KMS" ? (
    var.create_kms_key ? aws_kms_key.ecr[0].arn : var.kms_key_arn
  ) : null

  common_tags = merge({
    "project"   = "neuroforge-core"
    "module"    = "registry"
    "managedBy" = "terraform"
  }, var.tags)

  # Собираем список principals по правам
  push_principals = toset(var.allow_push_principals)
  pull_principals = toset(var.allow_pull_principals)

  # Нужна ли policy
  have_policy = length(local.push_principals) > 0 || length(local.pull_principals) > 0
}

# --------------------------
# KMS (опционально)
# --------------------------
resource "aws_kms_key" "ecr" {
  count                   = var.encryption_type == "KMS" && var.create_kms_key ? 1 : 0
  description             = "KMS key for ECR repository ${var.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = null
  tags                    = local.common_tags
}

resource "aws_kms_alias" "ecr" {
  count         = length(aws_kms_key.ecr) == 1 ? 1 : 0
  name          = "alias/ecr/${var.name}"
  target_key_id = aws_kms_key.ecr[0].key_id
}

# --------------------------
# ECR Repository
# --------------------------
resource "aws_ecr_repository" "this" {
  name                 = var.name
  image_tag_mutability = var.immutable_tags ? "IMMUTABLE" : "MUTABLE"

  image_scanning_configuration {
    scan_on_push = var.scan_on_push
  }

  encryption_configuration {
    encryption_type = var.encryption_type
    kms_key        = var.encryption_type == "KMS" ? local.effective_kms_arn : null
  }

  force_delete = false
  tags         = local.common_tags
}

# Политика жизненного цикла
resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name

  policy = jsonencode({
    rules = compact([
      {
        rulePriority = 1
        description  = "Keep last ${var.lifecycle_keep_last} tagged images (any tag)"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["*"]
          countType     = "imageCountMoreThan"
          countNumber   = var.lifecycle_keep_last
        }
        action = { type = "expire" }
      },
      var.lifecycle_untagged_expire_days > 0 ? {
        rulePriority = 2
        description  = "Expire untagged images older than ${var.lifecycle_untagged_expire_days} days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countNumber = var.lifecycle_untagged_expire_days
          countUnit   = "days"
        }
        action = { type = "expire" }
      } : null
    ])
  })
}

# Политика доступа на репозиторий
data "aws_iam_policy_document" "repo" {
  count = local.have_policy ? 1 : 0

  statement {
    sid     = "AllowPushPrincipals"
    effect  = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:InitiateLayerUpload",
      "ecr:ListImages",
      "ecr:PutImage",
      "ecr:UploadLayerPart"
    ]
    principals {
      type        = "AWS"
      identifiers = length(local.push_principals) > 0 ? tolist(local.push_principals) : ["arn:${data.aws_partition.this.partition}:iam::${data.aws_caller_identity.this.account_id}:root"]
    }
    resources = [aws_ecr_repository.this.arn]
  }

  statement {
    sid     = "AllowPullPrincipals"
    effect  = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:DescribeImages",
      "ecr:ListImages"
    ]
    principals {
      type        = "AWS"
      identifiers = length(local.pull_principals) > 0 ? tolist(local.pull_principals) : []
    }
    resources = [aws_ecr_repository.this.arn]
    condition {
      test     = "Bool"
      variable = "aws:PrincipalArn"
      values   = length(local.pull_principals) > 0 ? tolist(local.pull_principals) : ["false"] # заглушка, чтобы блок не давал доступ, если список пуст
    }
  }
}

resource "aws_ecr_repository_policy" "this" {
  count      = local.have_policy ? 1 : 0
  repository = aws_ecr_repository.this.name
  policy     = data.aws_iam_policy_document.repo[0].json
}

# --------------------------
# Глобальная конфигурация реестра (аккаунт)
# --------------------------
resource "aws_ecr_registry_scanning_configuration" "this" {
  count = var.enable_registry_scanning ? 1 : 0

  scan_type = length(var.registry_scan_rules) > 0 ? "ENHANCED" : "BASIC"

  dynamic "rule" {
    for_each = var.registry_scan_rules
    content {
      scan_frequency = try(rule.value.scan_frequency, "SCAN_ON_PUSH")
      dynamic "repository_filter" {
        for_each = try(rule.value.rules[0].repository_filters, [])
        content {
          filter      = repository_filter.value.filter
          filter_type = repository_filter.value.filter_type
        }
      }
    }
  }
}

# --------------------------
# Кросс-региональная репликация (опционально)
# --------------------------
resource "aws_ecr_replication_configuration" "this" {
  count = length(var.replicate_to) > 0 ? 1 : 0

  replication_configuration {
    dynamic "rule" {
      for_each = [for r in var.replicate_to : {
        region        = r
        registry_ids  = length(var.replication_registry_ids) > 0 ? var.replication_registry_ids : [data.aws_caller_identity.this.account_id]
      }]
      content {
        destination {
          region      = rule.value.region
          registry_id = rule.value.registry_ids[0]
        }
        repository_filter {
          filter      = aws_ecr_repository.this.name
          filter_type = "PREFIX_MATCH"
        }
      }
    }
  }
}

# --------------------------
# Pull Through Cache (опционально)
# --------------------------
resource "aws_ecr_pull_through_cache_rule" "rules" {
  for_each = var.enable_pull_through_cache ? {
    for r in var.pull_through_cache_rules : r.ecr_repository_prefix => r
  } : {}

  ecr_repository_prefix = each.value.ecr_repository_prefix
  upstream_registry_url = each.value.upstream_registry_url
  # Теги на уровне ресурса pull-through не поддерживаются
}

# --------------------------
# Выходные значения
# --------------------------
output "repository_name" {
  description = "Имя репозитория ECR."
  value       = aws_ecr_repository.this.name
}

output "repository_arn" {
  description = "ARN репозитория ECR."
  value       = aws_ecr_repository.this.arn
}

output "repository_url" {
  description = "Полный URL репозитория (для docker push/pull)."
  value       = aws_ecr_repository.this.repository_url
}

output "kms_key_arn" {
  description = "ARN KMS-ключа, используемого для шифрования (если применимо)."
  value       = local.effective_kms_arn
}

output "replication_enabled" {
  description = "Флаг — включена ли кросс-региональная репликация."
  value       = length(var.replicate_to) > 0
}
