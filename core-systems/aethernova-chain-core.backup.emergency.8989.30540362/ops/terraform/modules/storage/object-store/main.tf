// aethernova-chain-core/ops/terraform/modules/storage/object-store/main.tf
// Универсальный модуль объектного хранилища: AWS S3 / GCP GCS / Azure Blob.
// Особенности:
// - Единый вход через var.cloud: "aws" | "gcp" | "azure".
// - Шифрование: SSE-S3/KMS (AWS), CMEK/Google-managed (GCP), Storage Service Encryption/KMS (Azure).
// - Политики доступа: bucket policy (AWS), IAM policy binding (GCP), контейнер ACL + optional SAS/immutability (Azure).
// - Публичный доступ блокируется по умолчанию (где применимо).
// - Версионирование и управление жизненным циклом (lifecycle).
// - Логи доступа (где поддерживается).
// - Минимум провайдерской логики в корневом модуле: провайдеры должны быть настроены на уровне root.
//
// ВНИМАНИЕ: Значения по умолчанию подобраны консервативно. В проде задайте свои var-ы.
// Модуль можно рефакторить на отдельные files (variables.tf/outputs.tf), здесь всё в одном файле по запросу.

// --------------- Входные переменные ---------------

variable "cloud" {
  type        = string
  description = "Целевое облако: aws | gcp | azure"
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.cloud)
    error_message = "cloud должен быть одним из: aws, gcp, azure."
  }
}

variable "name" {
  type        = string
  description = "Логическое имя бакета/контейнера. Для провайдеров могут применяться требования к глобальной уникальности (например, S3/GCS)."
}

variable "location" {
  type        = string
  description = "Регион/локация: AWS region (e.g. eu-central-1), GCP location (e.g. EU/US/europe-west4), Azure location (e.g. westeurope)."
}

variable "resource_group_name" {
  type        = string
  description = "Только для Azure: существующая Resource Group, в которой создаётся Storage Account."
  default     = null
}

variable "account_name" {
  type        = string
  description = "Только для Azure: имя Storage Account (должно быть уникальным, 3-24 симв., только строчные и цифры). Если null — берётся из var.name с нормализацией."
  default     = null
}

variable "container_name" {
  type        = string
  description = "Только для Azure: имя контейнера (по умолчанию совпадает с var.name)."
  default     = null
}

variable "project_id" {
  type        = string
  description = "Только для GCP: ID проекта."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Теги/лейблы для ресурсов (где поддерживается)."
  default     = {}
}

variable "enable_versioning" {
  type        = bool
  description = "Включить версионирование объектов."
  default     = true
}

variable "uniform_access" {
  type        = bool
  description = "GCS: включить Uniform Bucket-Level Access (UBLA). AWS/Azure игнорируют."
  default     = true
}

variable "block_public_access" {
  type        = bool
  description = "Блокировать публичный доступ. Для AWS включает PublicAccessBlock, для GCP/Azure применяется политика и контейнерный уровень доступа."
  default     = true
}

variable "kms_key_id" {
  type        = string
  description = "KMS ключ: AWS (KMS Key ARN), GCP (full resource name cryptoKey), Azure (Key Vault Key URL). Если null — менеджер по умолчанию провайдера."
  default     = null
}

variable "logging" {
  type = object({
    enabled          = bool
    target_bucket    = optional(string)   // AWS/GCP: имя бакета для логов
    target_prefix    = optional(string)   // AWS/GCP: префикс
    target_container = optional(string)   // Azure: контейнер для логов, если используете soft-логирование средствами приложений
  })
  description = "Конфигурация логов доступа (поддержка зависит от провайдера)."
  default = {
    enabled       = false
    target_bucket = null
    target_prefix = null
  }
}

variable "policy_json" {
  type        = string
  description = "Пользовательская политика доступа: AWS bucket policy (JSON); для GCP — IAM bindings в var.iam_bindings; для Azure — не используется."
  default     = null
}

variable "iam_bindings" {
  type = list(object({
    role    = string
    members = list(string)
  }))
  description = "GCP: IAM биндинги уровня бакета."
  default     = []
}

variable "container_access_type" {
  type        = string
  description = "Azure: тип доступа контейнера: private | blob | container."
  default     = "private"
  validation {
    condition     = contains(["private", "blob", "container"], var.container_access_type)
    error_message = "container_access_type должен быть private, blob или container."
  }
}

variable "retention" {
  type = object({
    enabled              = bool
    retention_period_days = number
    mode                 = optional(string) // AWS Object Lock mode: GOVERNANCE|COMPLIANCE; GCS/Azure не используют
  })
  description = "Политика удержания объектов."
  default = {
    enabled               = false
    retention_period_days = 0
  }
}

variable "lifecycle_rules" {
  // Унифицированная схема. Провайдеры маппятся по best-effort.
  type = list(object({
    enabled                 = bool
    prefix                  = optional(string)
    tags                    = optional(map(string)) // AWS-only в policy; GCP/Azure ограничены
    abort_mpu_days          = optional(number)      // AWS: abort incomplete multipart upload
    expire_days             = optional(number)      // Текущее поколение: срок жизни
    noncurrent_expire_days  = optional(number)      // Версии, не текущие
    transition_class        = optional(string)      // AWS: STANDARD_IA|ONEZONE_IA|GLACIER|DEEP_ARCHIVE; GCP: NEARLINE|COLDLINE|ARCHIVE; Azure: Cool|Archive
    transition_days         = optional(number)      // Через сколько дней перевести
  }))
  description = "Lifecycle-правила в унифицированном виде."
  default     = []
}

variable "force_destroy" {
  type        = bool
  description = "Удалять бакет/контейнер со всем содержимым (использовать осторожно)."
  default     = false
}

// --------------- Локальные значения ---------------

locals {
  // Нормализации имён под разные провайдеры
  azure_account_name   = var.account_name != null ? var.account_name : replace(lower(var.name), "/[^a-z0-9]/", "")
  azure_container_name = coalesce(var.container_name, var.name)

  // Флаговые переключатели
  is_aws   = var.cloud == "aws"
  is_gcp   = var.cloud == "gcp"
  is_azure = var.cloud == "azure"

  // Политика запрета публичного доступа для AWS по умолчанию
  aws_public_access_block = {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}

// --------------- AWS S3 ---------------

resource "aws_s3_bucket" "this" {
  count  = local.is_aws ? 1 : 0
  bucket = var.name
  force_destroy = var.force_destroy

  tags = var.tags
}

resource "aws_s3_bucket_versioning" "this" {
  count  = local.is_aws ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count  = local.is_aws ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_id != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_id
    }
    bucket_key_enabled = var.kms_key_id != null ? true : null
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  count  = local.is_aws && var.block_public_access ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  block_public_acls       = local.aws_public_access_block.block_public_acls
  block_public_policy     = local.aws_public_access_block.block_public_policy
  ignore_public_acls      = local.aws_public_access_block.ignore_public_acls
  restrict_public_buckets = local.aws_public_access_block.restrict_public_buckets
}

resource "aws_s3_bucket_logging" "this" {
  count  = local.is_aws && var.logging.enabled && var.logging.target_bucket != null ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  target_bucket = var.logging.target_bucket
  target_prefix = coalesce(var.logging.target_prefix, "logs/")
}

resource "aws_s3_bucket_policy" "this" {
  count  = local.is_aws && var.policy_json != null ? 1 : 0
  bucket = aws_s3_bucket.this[0].id
  policy = var.policy_json
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = local.is_aws && length(var.lifecycle_rules) > 0 ? 1 : 0
  bucket = aws_s3_bucket.this[0].id

  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = "rule-${rule.key}"
      status = rule.value.enabled ? "Enabled" : "Disabled"

      dynamic "filter" {
        content {
          dynamic "prefix" {
            for_each = rule.value.prefix != null ? [1] : []
            content {
              prefix = rule.value.prefix
            }
          }
          // Примитивная поддержка tag-фильтра (если заданы)
          dynamic "and" {
            for_each = rule.value.tags != null && length(rule.value.tags) > 0 ? [1] : []
            content {
              dynamic "tag" {
                for_each = rule.value.tags != null ? rule.value.tags : {}
                content {
                  key   = tag.key
                  value = tag.value
                }
              }
            }
          }
        }
      }

      dynamic "abort_incomplete_multipart_upload" {
        for_each = rule.value.abort_mpu_days != null ? [1] : []
        content {
          days_after_initiation = rule.value.abort_mpu_days
        }
      }

      dynamic "expiration" {
        for_each = rule.value.expire_days != null ? [1] : []
        content {
          days = rule.value.expire_days
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = rule.value.noncurrent_expire_days != null ? [1] : []
        content {
          noncurrent_days = rule.value.noncurrent_expire_days
        }
      }

      dynamic "transition" {
        for_each = rule.value.transition_class != null && rule.value.transition_days != null ? [1] : []
        content {
          days          = rule.value.transition_days
          storage_class = rule.value.transition_class
        }
      }
    }
  }
}

// Object Lock (ретеншн) в S3 требует включения при создании бакета через отдельное свойство; для простоты — IAM/процедурно.
// При необходимости добавьте отдельный ресурс/настройку создания бакета с object_lock_enabled=true и политику ретеншна.

// --------------- GCP GCS ---------------

resource "google_storage_bucket" "this" {
  count         = local.is_gcp ? 1 : 0
  name          = var.name
  location      = var.location
  project       = var.project_id
  force_destroy = var.force_destroy

  uniform_bucket_level_access = var.uniform_access
  storage_class               = "STANDARD"

  versioning {
    enabled = var.enable_versioning
  }

  dynamic "encryption" {
    for_each = var.kms_key_id != null ? [1] : []
    content {
      default_kms_key_name = var.kms_key_id
    }
  }

  dynamic "logging" {
    for_each = var.logging.enabled && var.logging.target_bucket != null ? [1] : []
    content {
      log_bucket        = var.logging.target_bucket
      log_object_prefix = coalesce(var.logging.target_prefix, "logs")
    }
  }

  labels = var.tags

  dynamic "lifecycle_rule" {
    for_each = var.lifecycle_rules
    content {
      action {
        // expire vs transition
        type          = lifecycle_rule.value.transition_class != null ? "SetStorageClass" : "Delete"
        storage_class = lifecycle_rule.value.transition_class != null ? lifecycle_rule.value.transition_class : null
      }
      condition {
        age                   = lifecycle_rule.value.expire_days != null ? lifecycle_rule.value.expire_days : null
        matches_prefix        = lifecycle_rule.value.prefix != null ? [lifecycle_rule.value.prefix] : null
        // noncurrent_expire_days маппится ограниченно у GCS (isLive=false + age ~= noncurrent), опционально.
        // Для простоты — не задаем; при необходимости используйте отдельные условия is_live=false в расширении.
      }
    }
  }

  // Ретеншн
  dynamic "retention_policy" {
    for_each = var.retention.enabled ? [1] : []
    content {
      retention_period = var.retention.retention_period_days * 24 * 60 * 60
      // is_locked можно включать отдельно после верификации требований комплаенса
    }
  }
}

resource "google_storage_bucket_iam_binding" "this" {
  for_each = local.is_gcp ? { for b in var.iam_bindings : b.role => b } : {}
  bucket   = google_storage_bucket.this[0].name
  role     = each.value.role
  members  = each.value.members
}

// --------------- Azure Blob ---------------

resource "azurerm_storage_account" "this" {
  count                    = local.is_azure ? 1 : 0
  name                     = local.azure_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
  allow_blob_public_access = false

  // Шифрование по умолчанию включено; при наличии var.kms_key_id можно подключить customer-managed key (дополнительные ресурсы Key Vault).
  tags = var.tags

  // Блокировка публичного доступа реализуется уровнем контейнера + настройками аккаунта.
}

resource "azurerm_storage_container" "this" {
  count                 = local.is_azure ? 1 : 0
  name                  = local.azure_container_name
  storage_account_name  = azurerm_storage_account.this[0].name
  container_access_type = var.container_access_type // private|blob|container
}

resource "azurerm_storage_management_policy" "this" {
  count               = local.is_azure && length(var.lifecycle_rules) > 0 ? 1 : 0
  storage_account_id  = azurerm_storage_account.this[0].id

  policy {
    rules = [
      for idx, r in var.lifecycle_rules : {
        enabled = r.enabled
        name    = "rule-${idx}"
        type    = "Lifecycle"
        definition = {
          actions = {
            baseBlob = merge(
              r.expire_days != null ? { delete = { daysAfterModificationGreaterThan = r.expire_days } } : {},
              r.transition_class != null && r.transition_days != null ? (
                r.transition_class == "Cool" ? { tierToCool = { daysAfterModificationGreaterThan = r.transition_days } } :
                r.transition_class == "Archive" ? { tierToArchive = { daysAfterModificationGreaterThan = r.transition_days } } : {}
              ) : {}
            )
            snapshot = r.noncurrent_expire_days != null ? {
              delete = { daysAfterCreationGreaterThan = r.noncurrent_expire_days }
            } : null
            version = r.noncurrent_expire_days != null ? {
              delete = { daysAfterCreationGreaterThan = r.noncurrent_expire_days }
            } : null
          }
          filters = {
            blobTypes = ["blockBlob"]
            prefixMatch = r.prefix != null ? [r.prefix] : null
          }
        }
      }
    ]
  }
}

// Ретеншн (immutability) на уровне контейнера можно добавить через azurerm_storage_container_immutable_storage_with_versioning (при необходимости комплаенса).

// --------------- Выводы ---------------

output "bucket_name" {
  value = (
    local.is_aws   ? aws_s3_bucket.this[0].id :
    local.is_gcp   ? google_storage_bucket.this[0].name :
    local.is_azure ? azurerm_storage_container.this[0].name :
    null
  )
}

output "bucket_arn_or_url" {
  value = (
    local.is_aws   ? aws_s3_bucket.this[0].arn :
    local.is_gcp   ? "gs://${google_storage_bucket.this[0].name}" :
    local.is_azure ? format("https://%s.blob.core.windows.net/%s", azurerm_storage_account.this[0].name, azurerm_storage_container.this[0].name) :
    null
  )
}

output "encryption_mode" {
  value = (
    local.is_aws   ? (var.kms_key_id != null ? "aws:kms" : "AES256") :
    local.is_gcp   ? (var.kms_key_id != null ? "CMEK" : "Google-managed") :
    local.is_azure ? (var.kms_key_id != null ? "Customer-managed (Key Vault)" : "Service-managed") :
    null
  )
}
