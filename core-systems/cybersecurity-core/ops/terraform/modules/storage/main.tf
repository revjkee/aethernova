terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.100.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }
}

############################################
# ВХОДНЫЕ ДАННЫЕ
############################################

variable "platform" {
  description = "Целевая платформа хранения: aws | gcp | azure"
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.platform)
    error_message = "platform must be one of: aws, gcp, azure."
  }
}

variable "name" {
  description = "Базовое имя хранилища (используется для генерации имени ресурса, если специфичное имя не задано)."
  type        = string
}

variable "tags" {
  description = "Общие теги/метки для ресурсов."
  type        = map(string)
  default     = {}
}

variable "versioning_enabled" {
  description = "Включить версионирование объектов."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Разрешить удаление корзины/бакета со всеми объектами (использовать с осторожностью)."
  type        = bool
  default     = false
}

variable "lifecycle_noncurrent_days" {
  description = "Через сколько дней удалять неактуальные версии объектов."
  type        = number
  default     = 90
}

variable "lifecycle_expiration_days" {
  description = "Через сколько дней удалять объекты (актуальные версии). 0 или null — не удалять."
  type        = number
  default     = null
}

variable "logging_enabled" {
  description = "Включить логирование доступа к бакету/аккаунту (если поддерживается)."
  type        = bool
  default     = true
}

# ---------- AWS ----------
variable "aws_bucket_name" {
  description = "Явное имя S3 бакета. Если пусто — будет сгенерировано."
  type        = string
  default     = ""
}

variable "aws_region" {
  description = "Регион AWS (используется опционально для политик/репликации)."
  type        = string
  default     = null
}

variable "aws_logging_bucket" {
  description = "Имя бакета для логов S3 (должен существовать). Если пусто, логирование отключится."
  type        = string
  default     = ""
}

variable "aws_logging_prefix" {
  description = "Префикс ключей для логов S3."
  type        = string
  default     = "logs/"
}

variable "aws_kms_key_arn" {
  description = "ARN существующего KMS ключа для SSE-KMS. Если пусто и create_kms_key=true — будет создан новый ключ."
  type        = string
  default     = ""
}

variable "aws_create_kms_key" {
  description = "Создавать KMS ключ для S3, если не указан существующий."
  type        = bool
  default     = false
}

variable "aws_block_public_access" {
  description = "Жёсткая блокировка публичного доступа к S3."
  type        = bool
  default     = true
}

variable "aws_replication_enabled" {
  description = "Включить репликацию S3 (CRR/SRR). Требуется IAM роль и целевой бакет."
  type        = bool
  default     = false
}

variable "aws_replication_role_arn" {
  description = "ARN роли IAM для репликации S3."
  type        = string
  default     = ""
}

variable "aws_replication_destination_bucket_arn" {
  description = "ARN целевого бакета для репликации."
  type        = string
  default     = ""
}

# ---------- GCP ----------
variable "gcp_bucket_name" {
  description = "Имя GCS бакета. Если пусто — будет сгенерировано."
  type        = string
  default     = ""
}

variable "gcp_location" {
  description = "Локация GCS (например, EU, US, europe-west1)."
  type        = string
  default     = null
}

variable "gcp_project" {
  description = "ID проекта GCP (если провайдер не настроен глобально)."
  type        = string
  default     = null
}

variable "gcp_log_bucket" {
  description = "Имя логового бакета для GCS (должен существовать). Пусто — логирование отключено."
  type        = string
  default     = ""
}

variable "gcp_log_prefix" {
  description = "Префикс логов GCS."
  type        = string
  default     = "logs/"
}

variable "gcp_kms_key_name" {
  description = "Полное имя KMS ключа (projects/.../locations/.../keyRings/.../cryptoKeys/...). Если пусто — провайдерские ключи."
  type        = string
  default     = ""
}

variable "gcp_retention_policy_days" {
  description = "Политика удержания объектов (в днях). null — без политики удержания."
  type        = number
  default     = null
}

# ---------- Azure ----------
variable "azure_storage_account_name" {
  description = "Имя Storage Account. Если пусто — будет сгенерировано из name (a-z0-9, до 24 символов)."
  type        = string
  default     = ""
}

variable "azure_container_name" {
  description = "Имя контейнера Blob. Если пусто — будет сгенерировано."
  type        = string
  default     = ""
}

variable "azure_resource_group_name" {
  description = "Имя Resource Group для Storage Account."
  type        = string
  default     = null
}

variable "azure_location" {
  description = "Локация Azure (например, westeurope, northeurope)."
  type        = string
  default     = null
}

variable "azure_account_tier" {
  description = "Tier аккаунта хранения: Standard | Premium."
  type        = string
  default     = "Standard"
}

variable "azure_replication_type" {
  description = "Тип репликации: LRS | GRS | RAGRS | ZRS | GZRS | RAGZRS."
  type        = string
  default     = "GRS"
}

variable "azure_log_analytics_workspace_id" {
  description = "ID Log Analytics Workspace для диагностических логов. Пусто — диагностика не настраивается."
  type        = string
  default     = ""
}

variable "azure_cmk_key_vault_id" {
  description = "ID Key Vault для CMK (опционально)."
  type        = string
  default     = ""
}

variable "azure_cmk_key_name" {
  description = "Имя ключа в Key Vault (опционально)."
  type        = string
  default     = ""
}

variable "azure_cmk_key_version" {
  description = "Версия ключа в Key Vault (опционально)."
  type        = string
  default     = ""
}

############################################
# ЛОКАЛЫ И СЛУЖЕБНОЕ
############################################

locals {
  # Общий нормализатор базового имени (буквы/цифры/дефис, нижний регистр)
  base_slug = lower(replace(var.name, "/[^a-zA-Z0-9-]/", "-"))

  # Имя для S3/GCS (допускаем дефисы; ограничим до 63 символов на всякий случай)
  object_bucket_name = substr(
    coalesce(trimspace(var.aws_bucket_name), trimspace(var.gcp_bucket_name), local.base_slug),
    0,
    63
  )

  # Имя для Azure Storage Account: только [a-z0-9], до 24 символов
  azure_sa_name = substr(
    length(trimspace(var.azure_storage_account_name)) > 0
      ? lower(replace(var.azure_storage_account_name, "/[^a-z0-9]/", ""))
      : lower(replace(var.name, "/[^a-z0-9]/", "")),
    0,
    24
  )

  # Имя контейнера в Azure: буквы/цифры/дефис, нижний регистр
  azure_container = length(trimspace(var.azure_container_name)) > 0
    ? lower(replace(var.azure_container_name, "/[^a-z0-9-]/", "-"))
    : lower(replace(var.name, "/[^a-z0-9-]/", "-"))

  common_tags = merge(
    {
      "project"   = var.name
      "component" = "storage"
      "managed-by" = "terraform"
    },
    var.tags
  )

  is_aws   = var.platform == "aws"
  is_gcp   = var.platform == "gcp"
  is_azure = var.platform == "azure"
}

# Иногда полезен случайный суффикс (для глобально уникальных имён).
# Отключён по умолчанию, но вы можете использовать при необходимости.
resource "random_id" "suffix" {
  count       = 0
  byte_length = 2
}

############################################
# AWS S3
############################################

# Опционально: создать KMS ключ, если не передан существующий
resource "aws_kms_key" "s3" {
  count                   = local.is_aws && var.aws_create_kms_key && var.aws_kms_key_arn == "" ? 1 : 0
  description             = "KMS key for S3 bucket ${local.object_bucket_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = var.tags
}

locals {
  aws_kms_arn_effective = local.is_aws ? (
    var.aws_kms_key_arn != "" ? var.aws_kms_key_arn :
    (length(aws_kms_key.s3) > 0 ? aws_kms_key.s3[0].arn : null)
  ) : null
}

resource "aws_s3_bucket" "this" {
  count  = local.is_aws ? 1 : 0
  bucket = local.object_bucket_name
  force_destroy = var.force_destroy

  tags = local.common_tags

  lifecycle {
    precondition {
      condition     = length(local.object_bucket_name) >= 3 && length(local.object_bucket_name) <= 63
      error_message = "S3 bucket name must be between 3 and 63 characters."
    }
  }
}

# Блокировка публичного доступа
resource "aws_s3_bucket_public_access_block" "this" {
  count  = local.is_aws && var.aws_block_public_access ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Владелец — владелец бакета
resource "aws_s3_bucket_ownership_controls" "this" {
  count  = local.is_aws ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Версионирование
resource "aws_s3_bucket_versioning" "this" {
  count  = local.is_aws ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

# Шифрование SSE-KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count  = local.is_aws ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.aws_kms_arn_effective != null ? "aws:kms" : "AES256"
      kms_master_key_id = local.aws_kms_arn_effective
    }
    bucket_key_enabled = true
  }
}

# Логирование
resource "aws_s3_bucket_logging" "this" {
  count  = local.is_aws && var.logging_enabled && var.aws_logging_bucket != "" ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  target_bucket = var.aws_logging_bucket
  target_prefix = var.aws_logging_prefix

  lifecycle {
    precondition {
      condition     = var.aws_logging_bucket != local.object_bucket_name
      error_message = "Logging bucket must be different from the source bucket."
    }
  }
}

# Lifecycle (неактуальные версии и опциональное удаление)
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = local.is_aws ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  rule {
    id     = "expire-noncurrent-versions"
    status = var.versioning_enabled ? "Enabled" : "Disabled"

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_noncurrent_days
    }
  }

  dynamic "rule" {
    for_each = var.lifecycle_expiration_days != null && var.lifecycle_expiration_days > 0 ? [1] : []
    content {
      id     = "expire-current-versions"
      status = "Enabled"

      expiration {
        days = var.lifecycle_expiration_days
      }
    }
  }
}

# Репликация (если требуется; роль и целевой бакет должны быть подготовлены заранее)
resource "aws_s3_bucket_replication_configuration" "this" {
  count  = local.is_aws && var.aws_replication_enabled ? 1 : 0
  role   = var.aws_replication_role_arn
  bucket = aws_s3_bucket.this[0].id

  rule {
    id     = "replication-all"
    status = "Enabled"

    filter {}
    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = var.aws_replication_destination_bucket_arn
      metrics {
        status = "Enabled"
      }
      replication_time {
        status  = "Enabled"
        minutes = 15
      }
      storage_class = "STANDARD"
      encryption_configuration {
        replica_kms_key_id = local.aws_kms_arn_effective
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]

  lifecycle {
    precondition {
      condition     = var.aws_replication_role_arn != "" && var.aws_replication_destination_bucket_arn != ""
      error_message = "Replication requires aws_replication_role_arn and aws_replication_destination_bucket_arn."
    }
  }
}

############################################
# GCP GCS
############################################

resource "google_storage_bucket" "this" {
  count         = local.is_gcp ? 1 : 0
  name          = local.object_bucket_name
  location      = coalesce(var.gcp_location, "EU")
  project       = var.gcp_project
  force_destroy = var.force_destroy

  # UBLA — единая модель прав на уровне бакета
  uniform_bucket_level_access = true

  versioning {
    enabled = var.versioning_enabled
  }

  dynamic "encryption" {
    for_each = var.gcp_kms_key_name != "" ? [1] : []
    content {
      default_kms_key_name = var.gcp_kms_key_name
    }
  }

  dynamic "logging" {
    for_each = var.logging_enabled && var.gcp_log_bucket != "" ? [1] : []
    content {
      log_bucket        = var.gcp_log_bucket
      log_object_prefix = var.gcp_log_prefix
    }
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = var.lifecycle_noncurrent_days
      # Для простоты применяем к старым объектам; для версий можно расширить с help of custom rules.
    }
  }

  dynamic "retention_policy" {
    for_each = var.gcp_retention_policy_days != null && var.gcp_retention_policy_days > 0 ? [1] : []
    content {
      retention_period = var.gcp_retention_policy_days * 24 * 60 * 60
      # is_locked — не задаём на уровне модуля, т.к. блокирует удаление и изменение.
    }
  }

  labels = local.common_tags

  lifecycle {
    precondition {
      condition     = length(local.object_bucket_name) >= 3 && length(local.object_bucket_name) <= 63
      error_message = "GCS bucket name must be between 3 and 63 characters."
    }
  }
}

############################################
# AZURE BLOB (Storage Account + Container)
############################################

provider "azurerm" {
  features {}
}

resource "azurerm_storage_account" "this" {
  count                    = local.is_azure ? 1 : 0
  name                     = local.azure_sa_name
  resource_group_name      = var.azure_resource_group_name
  location                 = var.azure_location
  account_tier             = var.azure_account_tier
  account_replication_type = var.azure_replication_type
  min_tls_version          = "TLS1_2"
  allow_blob_public_access = false

  blob_properties {
    versioning_enabled = var.versioning_enabled
    delete_retention_policy {
      days = var.lifecycle_expiration_days != null && var.lifecycle_expiration_days > 0 ? var.lifecycle_expiration_days : 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags

  lifecycle {
    precondition {
      condition     = length(local.azure_sa_name) >= 3 && length(local.azure_sa_name) <= 24
      error_message = "Azure Storage Account name must be 3..24 characters (a-z0-9)."
    }
  }
}

# Необязательное шифрование CMK (Key Vault)
resource "azurerm_storage_account_customer_managed_key" "cmk" {
  count               = local.is_azure && var.azure_cmk_key_vault_id != "" && var.azure_cmk_key_name != "" ? 1 : 0
  storage_account_id  = azurerm_storage_account.this[0].id
  key_vault_id        = var.azure_cmk_key_vault_id
  key_name            = var.azure_cmk_key_name
  key_version         = var.azure_cmk_key_version
  user_assigned_identity_id = null
}

resource "azurerm_storage_container" "this" {
  count                 = local.is_azure ? 1 : 0
  name                  = local.azure_container
  storage_account_name  = azurerm_storage_account.this[0].name
  container_access_type = "private"

  depends_on = [azurerm_storage_account.this]
}

# Диагностические логи в Log Analytics (если указан workspace)
resource "azurerm_monitor_diagnostic_setting" "this" {
  count                      = local.is_azure && var.logging_enabled && var.azure_log_analytics_workspace_id != "" ? 1 : 0
  name                       = "diag-storage"
  target_resource_id         = azurerm_storage_account.this[0].id
  log_analytics_workspace_id = var.azure_log_analytics_workspace_id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

############################################
# ВЫХОДНЫЕ ДАННЫЕ
###############
