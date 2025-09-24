###############################################################################
# modules/registry/ecr/variables.tf
#
# PURPOSE: Industrial-grade variables for AWS ECR module.
#
# VERIFIED SOURCES (Terraform Registry):
# - aws_ecr_repository:
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository
# - aws_ecr_lifecycle_policy:
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_lifecycle_policy
# - aws_ecr_repository_policy:
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy
# - aws_ecr_replication_configuration (account-level):
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_replication_configuration
# - aws_ecr_registry_scanning_configuration (account-level):
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_registry_scanning_configuration
# - aws_ecr_pull_through_cache_rule:
#   https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/ecr_pull_through_cache_rule
#
# Доп. практики по KMS/CMEK и сканированию:
# - Рекомендация использовать CMK для ECR (tfsec):
#   https://aquasecurity.github.io/tfsec/latest/checks/aws/ecr/repository-customer-key/    # ENH
# - ENHANCED scanning, пример правил:
#   https://security.snyk.io/rules/cloud/SNYK-CC-00762
#
# Примечание: значения и блоки, зависящие от версий провайдера, не «зашиты» в код;
# при изменениях схемы провайдера используйте соответствующие ресурсы, подтверждённые ссылками выше.
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

############################
# Общие теги/метки модуля  #
############################

variable "tags" {
  description = "Глобальные теги для всех создаваемых ресурсов (ECR repo, account-level)."
  type        = map(string)
  default     = {}
}

#########################################
# Репозитории ECR (repo-level settings) #
# См. aws_ecr_repository. :contentReference[oaicite:2]{index=2}
#########################################

variable "repositories" {
  description = <<-EOT
  Карта репозиториев для создания. Ключ карты — имя репозитория (DNS-совместимое).
  Значение — параметры репозитория: неизменяемость тэгов, сканирование, шифрование,
  force_delete, теги, а также встроенные/внешние политики и lifecycle-политики.

  ВНИМАНИЕ:
  - image_tag_mutability: допустимые значения провайдера — "MUTABLE" или "IMMUTABLE".
    (Не могу подтвердить это: наличие и стабильность расширенных режимов с исключениями
     в вашей версии провайдера. Если они доступны — подключайте их в реализующем коде.)
  - encryption.encryption_type: "AES256" или "KMS"; при "KMS" задайте kms_key_arn.
  - lifecycle_policy.json и repository_policy.json должны содержать валидный JSON.
  EOT

  type = map(object({
    image_tag_mutability = optional(string, "IMMUTABLE") # MUTABLE | IMMUTABLE
    scan_on_push         = optional(bool, true)           # image_scanning_configuration.scan_on_push
    force_delete         = optional(bool, false)

    encryption = optional(object({
      encryption_type = optional(string, "KMS")           # AES256 | KMS
      kms_key_arn     = optional(string)
    }), {})

    # Доп. теги на уровне репозитория; мерджатся с var.tags
    repo_tags = optional(map(string), {})

    # Политика жизненного цикла (JSON) — см. aws_ecr_lifecycle_policy. :contentReference[oaicite:3]{index=3}
    lifecycle_policy = optional(object({
      json = string
    }))

    # Политика репозитория (JSON) — см. aws_ecr_repository_policy. :contentReference[oaicite:4]{index=4}
    repository_policy = optional(object({
      json = string
    }))
  }))
  default = {}

  validation {
    condition = alltrue([
      for name, cfg in var.repositories :
      can(regex("^[a-z0-9._/-]+$", name))
    ])
    error_message = "Имена репозиториев должны содержать только [a-z0-9._/-]."
  }

  validation {
    condition = alltrue([
      for name, cfg in var.repositories :
      contains(["MUTABLE", "IMMUTABLE"], upper(cfg.image_tag_mutability))
    ])
    error_message = "image_tag_mutability должен быть MUTABLE или IMMUTABLE."
  }

  validation {
    condition = alltrue([
      for name, cfg in var.repositories :
      (try(upper(cfg.encryption.encryption_type), "KMS") == "KMS" ? true :
       try(upper(cfg.encryption.encryption_type), "AES256") == "AES256")
    ])
    error_message = "encryption.encryption_type должен быть AES256 или KMS."
  }
}

#######################################################
# Account-level: Registry scanning configuration (ECR)#
# См. aws_ecr_registry_scanning_configuration. :contentReference[oaicite:5]{index=5}
#######################################################

variable "enable_registry_scanning_configuration" {
  description = "Создавать/управлять account-level ECR Registry Scanning Configuration."
  type        = bool
  default     = true
}

variable "registry_scan_type" {
  description = <<-EOT
  Тип сканирования реестра: BASIC или ENHANCED.
  Пример best practice — ENHANCED. См. рекомендации Snyk. :contentReference[oaicite:6]{index=6}
  EOT
  type    = string
  default = "ENHANCED"
  validation {
    condition     = contains(["BASIC", "ENHANCED"], upper(var.registry_scan_type))
    error_message = "registry_scan_type должен быть BASIC или ENHANCED."
  }
}

variable "registry_scan_rules" {
  description = <<-EOT
  Список правил сканирования на уровне реестра. Каждое правило задаёт частоту и фильтр.
  Поля совместимы с aws_ecr_registry_scanning_configuration.rule:
  - scan_frequency: допустимые значения по провайдеру (например, CONTINUOUS_SCAN, SCAN_ON_PUSH, DAILY).
    (Не могу подтвердить это: полный перечень значений в вашей версии провайдера; ориентируйтесь на доки ресурса.)
  - repository_filter: { filter, filter_type } — тип, как правило, WILDCARD.
  См. Terraform Registry для точной схемы. :contentReference[oaicite:7]{index=7}
  EOT
  type = list(object({
    scan_frequency = string
    repository_filter = object({
      filter      = string
      filter_type = string # обычно WILDCARD
    })
  }))
  default = []
}

##################################################
# Account-level: Replication Configuration (ECR) #
# См. aws_ecr_replication_configuration. :contentReference[oaicite:8]{index=8}
##################################################

variable "enable_replication" {
  description = "Создавать account-level ECR Replication Configuration."
  type        = bool
  default     = false
}

variable "replication_rules" {
  description = <<-EOT
  Список правил репликации. Схема совместима с replication_configuration.rule:
  - destinations: список получателей { region, registry_id (опц.) }
  - repository_filters: список фильтров { filter, filter_type } — тип обычно PREFIX_MATCH.
  См. Terraform Registry. :contentReference[oaicite:9]{index=9}
  EOT
  type = list(object({
    destinations = list(object({
      region      = string
      registry_id = optional(string)
    }))
    repository_filters = optional(list(object({
      filter      = string
      filter_type = string # обычно PREFIX_MATCH
    })), [])
  }))
  default = []
}

######################################
# Pull-through cache rules (optional)#
# См. aws_ecr_pull_through_cache_rule. :contentReference[oaicite:10]{index=10}
######################################

variable "enable_pull_through_cache" {
  description = "Создавать Pull-through cache rules для внешних реестров."
  type        = bool
  default     = false
}

variable "pull_through_cache_rules" {
  description = <<-EOT
  Список правил pull-through cache:
  - ecr_repository_prefix: префикс в ECR для кэшируемых образов
  - upstream_registry_url: URL источника (например, public.ecr.aws, registry-1.docker.io)
  - credential_arn (опц.): ARN секретов для аутентификации к upstream (если требуется провайдером/реестром).
    (Не могу подтвердить это: поддержку конкретных upstream/credentialArn в вашей версии провайдера — следуйте релиз-нотам ресурса.)
  См. Terraform Registry. :contentReference[oaicite:11]{index=11}
  EOT
  type = list(object({
    ecr_repository_prefix = string
    upstream_registry_url = string
    credential_arn        = optional(string)
  }))
  default = []
}

##############################################
# Дополнительные опции для поведения модуля  #
##############################################

variable "create_repository_policies" {
  description = "При true — прикреплять политики из repositories[*].repository_policy.json."
  type        = bool
  default     = true
}

variable "create_lifecycle_policies" {
  description = "При true — прикреплять lifecycle-политики из repositories[*].lifecycle_policy.json."
  type        = bool
  default     = true
}

#####################################
# Валидации и «охранные» предикаты  #
#####################################

variable "fail_if_kms_missing_for_kms_type" {
  description = "Если true — валидировать, что при encryption_type=KMS указан kms_key_arn."
  type        = bool
  default     = true
}

locals {
  # Пример предиката для использования в main.tf через precondition:
  # ensure_kms_for_kms_type = alltrue([
  #   for name, cfg in var.repositories :
  #   upper(try(cfg.encryption.encryption_type, "KMS")) != "KMS" || try(cfg.encryption.kms_key_arn, null) != null
  # ])
}
