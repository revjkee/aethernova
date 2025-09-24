#############################################
# variables.tf — remote-state (industrial)
# Terraform >= 1.3
#############################################

############################
# Core selection
############################
variable "backend_provider" {
  description = "Провайдер для хранилища удалённого состояния: aws | gcp | azure | terraform_cloud."
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure", "terraform_cloud"], var.backend_provider)
    error_message = "backend_provider должен быть одним из: aws, gcp, azure, terraform_cloud."
  }
}

variable "project_id" {
  description = "Идентификатор проекта/аккаунта/подписки (AWS Account ID / GCP Project ID / Azure Subscription name or ID)."
  type        = string
}

variable "environment" {
  description = "Имя окружения (например: dev, stage, prod)."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.environment))
    error_message = "environment может содержать только [a-z0-9-]."
  }
}

variable "name_prefix" {
  description = "Префикс для создаваемых сущностей (например: org-team)."
  type        = string
  default     = ""
  validation {
    condition     = var.name_prefix == "" || can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix может содержать только [a-z0-9-]."
  }
}

############################
# State object naming
############################
variable "state_key_prefix" {
  description = "Префикс ключей состояния (папка/префикс в бакете/контейнере)."
  type        = string
  default     = "terraform/state"
}

variable "state_file_name" {
  description = "Имя файла состояния (без префикса)."
  type        = string
  default     = "global.tfstate"
  validation {
    condition     = can(regex("^[a-zA-Z0-9._-]+$", var.state_file_name))
    error_message = "state_file_name может содержать только буквы, цифры, . _ -"
  }
}

############################
# Common metadata
############################
variable "tags" {
  description = "Теги (AWS) в формате map(string)."
  type        = map(string)
  default     = {}
}

variable "labels" {
  description = "Метки (GCP/Azure) в формате map(string)."
  type        = map(string)
  default     = {}
}

############################
# Compliance and security
############################
variable "compliance" {
  description = <<-EOT
  Единые флаги комплаенса/безопасности:
  - enforce_versioning: включить версионирование (если поддерживается)
  - enforce_encryption: требовать шифрование по умолчанию
  - block_public_access: запрет публичного доступа (S3 Block Public Access / GCS Public Access Prevention)
  - immutable_lifecycle: включить правила WORM (если поддерживается провайдером)
  EOT
  type = object({
    enforce_versioning  : bool
    enforce_encryption  : bool
    block_public_access : bool
    immutable_lifecycle : bool
  })
  default = {
    enforce_versioning  = true
    enforce_encryption  = true
    block_public_access = true
    immutable_lifecycle = false
  }
}

############################
# Lifecycle rules (generic)
############################
variable "lifecycle_rules" {
  description = <<-EOT
  Унифицированные правила жизненного цикла объектов.
  Для AWS: будут транслироваться в LifecycleRule.
  Для GCP: в Bucket Lifecycle Rule.
  Для Azure: в Blob Lifecycle Management (где применимо).
  EOT
  type = list(object({
    id                 = optional(string)
    enabled            = bool
    prefix             = optional(string)
    tags               = optional(map(string))
    transitions        = optional(list(object({
      days          = number
      storage_class = string # e.g., STANDARD_IA/GLACIER (AWS), NEARLINE/COLDLINE/ARCHIVE (GCP), Cool/Archive (Azure)
    })))
    expiration_days    = optional(number)
    noncurrent_expiration_days = optional(number)
  }))
  default = []
}

############################
# Replication (generic)
############################
variable "replication" {
  description = <<-EOT
  Опциональная репликация бакета/контейнера.
  Общие поля, маппятся на механизмы провайдеров (S3 CRR, GCS Bucket Replication, Azure RA-GRS/политики).
  EOT
  type = object({
    enabled              : bool
    destination_location : optional(string)  # целевой регион/loсation
    destination_bucket   : optional(string)  # имя целевого бакета/контейнера
    kms_key              : optional(string)  # ключ для шифрования реплик
    storage_class        : optional(string)
  })
  default = {
    enabled = false
  }
}

############################
# Encryption (generic)
############################
variable "encryption" {
  description = <<-EOT
  Параметры шифрования по умолчанию.
  - algorithm: AES256 | aws:kms | google-managed | customer-managed | microsoft-managed
  - kms_key  : ARN/Resource ID ключа (если customer-managed/KMS)
  EOT
  type = object({
    algorithm : string
    kms_key   : optional(string)
  })
  default = {
    algorithm = "AES256"
  }
  validation {
    condition = contains(
      ["AES256", "aws:kms", "google-managed", "customer-managed", "microsoft-managed"],
      var.encryption.algorithm
    )
    error_message = "encryption.algorithm должен быть одним из: AES256, aws:kms, google-managed, customer-managed, microsoft-managed."
  }
}

############################
# AWS-specific
############################
variable "aws_region" {
  description = "Регион AWS (например: eu-north-1)."
  type        = string
  default     = "eu-north-1"
}

variable "aws_create_bucket" {
  description = "Создавать ли S3 бакет для состояния (true) или использовать существующий (false)."
  type        = bool
  default     = true
}

variable "aws_bucket_name" {
  description = "Имя S3 бакета для состояния (если пусто и create=true — будет выведено из шаблона)."
  type        = string
  default     = ""
  validation {
    condition     = var.aws_bucket_name == "" || can(regex("^[a-z0-9.-]{3,63}$", var.aws_bucket_name))
    error_message = "aws_bucket_name должен соответствовать правилам S3: [a-z0-9.-], длина 3..63."
  }
}

variable "aws_bucket_force_destroy" {
  description = "Разрешать ли force-destroy для S3 (удаление с объектами)."
  type        = bool
  default     = false
}

variable "aws_lock_table_create" {
  description = "Создавать ли DynamoDB таблицу для блокировок."
  type        = bool
  default     = true
}

variable "aws_lock_table_name" {
  description = "Имя DynamoDB таблицы для блокировок (если пусто и create=true — будет выведено из шаблона)."
  type        = string
  default     = ""
  validation {
    condition     = var.aws_lock_table_name == "" || can(regex("^[a-zA-Z0-9._-]{3,255}$", var.aws_lock_table_name))
    error_message = "aws_lock_table_name может содержать буквы, цифры, . _ - ; длина 3..255."
  }
}

variable "aws_lock_table_billing_mode" {
  description = "Режим биллинга DynamoDB: PROVISIONED или PAY_PER_REQUEST."
  type        = string
  default     = "PAY_PER_REQUEST"
  validation {
    condition     = contains(["PROVISIONED", "PAY_PER_REQUEST"], var.aws_lock_table_billing_mode)
    error_message = "aws_lock_table_billing_mode должен быть PROVISIONED или PAY_PER_REQUEST."
  }
}

variable "aws_bucket_block_public_access" {
  description = "Включить S3 Block Public Access для бакета."
  type        = bool
  default     = true
}

variable "aws_bucket_policy_json" {
  description = "Дополнительная JSON-политика для S3 бакета (строка JSON). Пусто — не применять."
  type        = string
  default     = ""
}

############################
# GCP-specific
############################
variable "gcp_location" {
  description = "Локация GCS бакета (например: EU или europe-north1)."
  type        = string
  default     = "EU"
}

variable "gcp_create_bucket" {
  description = "Создавать ли GCS бакет для состояния."
  type        = bool
  default     = true
}

variable "gcp_bucket_name" {
  description = "Имя GCS бакета (если пусто и create=true — будет выведено из шаблона)."
  type        = string
  default     = ""
  validation {
    condition     = var.gcp_bucket_name == "" || can(regex("^[a-z0-9._-]{3,222}$", var.gcp_bucket_name))
    error_message = "gcp_bucket_name должен соответствовать правилам GCS: [a-z0-9._-], длина 3..222."
  }
}

variable "gcp_public_access_prevention" {
  description = "Режим Public Access Prevention: 'enforced' для запрета публичного доступа, 'unspecified' для отключения."
  type        = string
  default     = "enforced"
  validation {
    condition     = contains(["enforced", "unspecified"], var.gcp_public_access_prevention)
    error_message = "gcp_public_access_prevention должен быть 'enforced' или 'unspecified'."
  }
}

variable "gcp_bucket_uniform_access" {
  description = "Uniform bucket-level access (UBLA) — единый уровень управления доступом."
  type        = bool
  default     = true
}

############################
# Azure-specific
############################
variable "azure_location" {
  description = "Регион Azure (например: northeurope, swedencentral при доступности)."
  type        = string
  default     = "northeurope"
}

variable "azure_resource_group_create" {
  description = "Создавать ли Resource Group."
  type        = bool
  default     = true
}

variable "azure_resource_group_name" {
  description = "Имя Resource Group (если пусто и create=true — будет выведено из шаблона)."
  type        = string
  default     = ""
  validation {
    condition     = var.azure_resource_group_name == "" || can(regex("^[a-zA-Z0-9._()-]{1,90}$", var.azure_resource_group_name))
    error_message = "azure_resource_group_name допускает: буквы, цифры, . _ ( ) - ; длина 1..90."
  }
}

variable "azure_storage_account_create" {
  description = "Создавать ли Storage Account."
  type        = bool
  default     = true
}

variable "azure_storage_account_name" {
  description = "Имя Storage Account (3..24, только строчные и цифры)."
  type        = string
  default     = ""
  validation {
    condition     = var.azure_storage_account_name == "" || can(regex("^[a-z0-9]{3,24}$", var.azure_storage_account_name))
    error_message = "azure_storage_account_name: 3..24 символов, только [a-z0-9]."
  }
}

variable "azure_container_create" {
  description = "Создавать ли контейнер blob для состояния."
  type        = bool
  default     = true
}

variable "azure_container_name" {
  description = "Имя контейнера blob (3..63, строчные/цифры/дефисы)."
  type        = string
  default     = ""
  validation {
    condition     = var.azure_container_name == "" || can(regex("^[a-z0-9-]{3,63}$", var.azure_container_name))
    error_message = "azure_container_name: 3..63, [a-z0-9-]."
  }
}

variable "azure_account_tier" {
  description = "Tier Storage Account: Standard или Premium."
  type        = string
  default     = "Standard"
  validation {
    condition     = contains(["Standard", "Premium"], var.azure_account_tier)
    error_message = "azure_account_tier должен быть Standard или Premium."
  }
}

variable "azure_replication_type" {
  description = "Тип репликации Storage Account (например: LRS, GRS, RA-GRS, ZRS, GZRS, RA-GZRS)."
  type        = string
  default     = "LRS"
  validation {
    condition = contains(
      ["LRS", "GRS", "RAGRS", "ZRS", "GZRS", "RAGZRS", "RA-GRS", "RA-GZRS"], 
      upper(replace(var.azure_replication_type, "-", ""))
    )
    error_message = "azure_replication_type должен быть одним из: LRS, ZRS, GRS, RA-GRS, GZRS, RA-GZRS."
  }
}

############################
# Terraform Cloud/Enterprise
############################
variable "tfc_organization" {
  description = "Организация Terraform Cloud/Enterprise."
  type        = string
  default     = ""
}

variable "tfc_workspace" {
  description = "Workspace Terraform Cloud/Enterprise."
  type        = string
  default     = ""
}

############################
# Naming templates
############################
variable "naming" {
  description = <<-EOT
  Шаблоны имён для создаваемых ресурсов:
    - aws_bucket_tpl: S3 бакет
    - aws_dynamodb_tpl: DynamoDB таблица
    - gcp_bucket_tpl: GCS бакет
    - azure_rg_tpl: Azure Resource Group
    - azure_sa_tpl: Azure Storage Account
    - azure_container_tpl: Azure Blob Container
  Подстановки: {name_prefix}, {environment}, {project_id}
  EOT
  type = object({
    aws_bucket_tpl       : string
    aws_dynamodb_tpl     : string
    gcp_bucket_tpl       : string
    azure_rg_tpl         : string
    azure_sa_tpl         : string
    azure_container_tpl  : string
  })
  default = {
    aws_bucket_tpl       = "{name_prefix}-{project_id}-{environment}-tfstate"
    aws_dynamodb_tpl     = "{name_prefix}-{project_id}-{environment}-tf-locks"
    gcp_bucket_tpl       = "{name_prefix}-{project_id}-{environment}-tfstate"
    azure_rg_tpl         = "{name_prefix}-{project_id}-{environment}-tf-rg"
    azure_sa_tpl         = "{name_prefix}{project_id}{environment}tfsa"
    azure_container_tpl  = "tfstate"
  }
}

############################
# Advanced controls
############################
variable "deny_unencrypted_state" {
  description = "Запретить применение без включённого шифрования (fail-fast)."
  type        = bool
  default     = true
}

variable "deny_without_versioning" {
  description = "Запретить применение без включённого версионирования (fail-fast)."
  type        = bool
  default     = true
}

variable "extra_bucket_headers" {
  description = "Дополнительные заголовки/метаданные на уровне бакета (провайдер-специфично)."
  type        = map(string)
  default     = {}
}

variable "state_locking_enabled" {
  description = "Требовать механизм блокировок состояния (DynamoDB для AWS и аналоги, если доступны)."
  type        = bool
  default     = true
}

############################
# Validation helpers (meta)
############################
variable "enable_strict_validations" {
  description = "Включить дополнительные строгие валидации на уровне модуля (рекомендуется)."
  type        = bool
  default     = true
}
