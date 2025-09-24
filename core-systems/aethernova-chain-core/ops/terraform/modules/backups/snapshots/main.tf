##############################################
# aethernova-chain-core/ops/terraform/modules/backups/snapshots/main.tf
# ПОЛИТИКИ СНАПШОТОВ ДИСКОВ / БЭКАПОВ VM и РЕСУРСОВ
# Поддержка: AWS, GCP, Azure (выбор через var.cloud)
##############################################

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
      version = ">= 3.116.0"
    }
  }
}

# Конфигурация провайдеров задается на уровне root-модуля.
# Данный модуль не настраивает provider{} (многооблачный код).

########################
# ПЕРЕМЕННЫЕ (common)
########################
variable "cloud" {
  description = "Целевое облако: aws | gcp | azure"
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.cloud)
    error_message = "var.cloud должен быть одним из: aws | gcp | azure"
  }
}

variable "tags" {
  description = "Теги/метки по умолчанию для поддерживаемых ресурсов"
  type        = map(string)
  default     = {}
}

locals {
  is_aws   = var.cloud == "aws"
  is_gcp   = var.cloud == "gcp"
  is_azure = var.cloud == "azure"
}

########################
# AWS BACKUP (EBS/RDS/EFS/DynamoDB/S3 и др.)
########################

# Общие переменные AWS
variable "aws_vault_name" {
  description = "Имя AWS Backup vault"
  type        = string
  default     = "aethernova-backup-vault"
}

variable "aws_kms_key_arn" {
  description = "KMS ключ для шифрования бэкапов в vault (опционально)"
  type        = string
  default     = null
}

variable "aws_vault_lock" {
  description = "Настройки Vault Lock (иммутабельность)*"
  type = object({
    enable              = bool
    min_retention_days  = number
    max_retention_days  = number
    changeable_for_days = optional(number) # Грейс-период (Compliance mode)
  })
  default = {
    enable             = false
    min_retention_days = 7
    max_retention_days = 3650
  }
}

variable "aws_backup_plan_name" {
  description = "Имя плана AWS Backup"
  type        = string
  default     = "aethernova-backup-plan"
}

# Правила плана бэкапов
variable "aws_backup_rules" {
  description = <<EOT
Список правил AWS Backup. Пример:
[
  {
    name                       = "daily-core"
    schedule_cron              = "cron(0 1 * * ? *)"         # каждый день 01:00 UTC
    start_window_minutes       = 60
    completion_window_minutes  = 360
    enable_continuous_backup   = false
    lifecycle = {
      cold_storage_after = 30
      delete_after       = 365
    }
    recovery_point_tags = { "scope" = "daily" }

    copy_actions = [
      {
        destination_vault_arn = "arn:aws:backup:eu-central-1:111111111111:backup-vault:dr-vault"
        lifecycle = {
          cold_storage_after = 30
          delete_after       = 730
        }
      }
    ]
  }
]
EOT
  type = list(object({
    name                      = string
    schedule_cron             = string
    start_window_minutes      = number
    completion_window_minutes = number
    enable_continuous_backup  = optional(bool)
    lifecycle = optional(object({
      cold_storage_after = optional(number)
      delete_after       = optional(number)
    }))
    recovery_point_tags = optional(map(string))
    copy_actions = optional(list(object({
      destination_vault_arn = string
      lifecycle = optional(object({
        cold_storage_after = optional(number)
        delete_after       = optional(number)
      }))
    })))
  }))
  default = []
}

# Отбор ресурсов в план: по тегам и/или по списку ARN
variable "aws_selection_tags" {
  description = "Tag-based отбор ресурсов в план"
  type = list(object({
    type  = string # 'STRINGEQUALS'|'STRINGLIKE'
    key   = string
    value = string
  }))
  default = []
}

variable "aws_selection_resources" {
  description = "Список ARN ресурсов для отбора (если нужен прямой список)"
  type        = list(string)
  default     = []
}

# Роль для AWS Backup (если не передается извне)
variable "aws_create_backup_role" {
  description = "Создавать IAM роль для AWS Backup (если aws_backup_role_arn не задан)"
  type        = bool
  default     = true
}

variable "aws_backup_role_name" {
  description = "Имя IAM роли AWS Backup (если создаем)"
  type        = string
  default     = "AWSBackupServiceRole"
}

variable "aws_backup_role_arn" {
  description = "Готовый ARN IAM роли для aws_backup_selection (опционально)"
  type        = string
  default     = null
}

# Vault
resource "aws_backup_vault" "this" {
  count       = local.is_aws ? 1 : 0
  name        = var.aws_vault_name
  kms_key_arn = var.aws_kms_key_arn
  tags        = var.tags
}

# Vault Lock (опционально)
resource "aws_backup_vault_lock_configuration" "this" {
  count              = local.is_aws && var.aws_vault_lock.enable ? 1 : 0
  backup_vault_name  = aws_backup_vault.this[0].name
  min_retention_days = var.aws_vault_lock.min_retention_days
  max_retention_days = var.aws_vault_lock.max_retention_days
  changeable_for_days = try(var.aws_vault_lock.changeable_for_days, null)
}

# IAM роль (если требуется)
data "aws_iam_policy_document" "backup_assume_role" {
  count = local.is_aws && var.aws_create_backup_role && var.aws_backup_role_arn == null ? 1 : 0
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "backup" {
  count              = local.is_aws && var.aws_create_backup_role && var.aws_backup_role_arn == null ? 1 : 0
  name               = var.aws_backup_role_name
  assume_role_policy = data.aws_iam_policy_document.backup_assume_role[0].json
  tags               = var.tags
}

# Присоединяем управляемые политики AWS для Backup/Restore
resource "aws_iam_role_policy_attachment" "backup_attach" {
  for_each = local.is_aws && var.aws_create_backup_role && var.aws_backup_role_arn == null ? toset([
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
  ]) : toset([])
  role       = aws_iam_role.backup[0].name
  policy_arn = each.value
}

# План AWS Backup с динамическими правилами
resource "aws_backup_plan" "this" {
  count = local.is_aws ? 1 : 0
  name  = var.aws_backup_plan_name
  tags  = var.tags

  dynamic "rule" {
    for_each = var.aws_backup_rules
    content {
      rule_name                   = rule.value.name
      target_vault_name           = aws_backup_vault.this[0].name
      schedule                    = rule.value.schedule_cron
      start_window                = rule.value.start_window_minutes
      completion_window           = rule.value.completion_window_minutes
      enable_continuous_backup    = try(rule.value.enable_continuous_backup, null)
      recovery_point_tags         = try(rule.value.recovery_point_tags, null)

      dynamic "lifecycle" {
        for_each = try([rule.value.lifecycle], [])
        content {
          cold_storage_after = try(lifecycle.value.cold_storage_after, null)
          delete_after       = try(lifecycle.value.delete_after, null)
        }
      }

      dynamic "copy_action" {
        for_each = try(rule.value.copy_actions, [])
        content {
          destination_vault_arn = copy_action.value.destination_vault_arn
          dynamic "lifecycle" {
            for_each = try([copy_action.value.lifecycle], [])
            content {
              cold_storage_after = try(lifecycle.value.cold_storage_after, null)
              delete_after       = try(lifecycle.value.delete_after, null)
            }
          }
        }
      }
    }
  }
}

# Отбор ресурсов в план (по тегам)
locals {
  aws_selection_role_arn = coalesce(
    var.aws_backup_role_arn,
    try(aws_iam_role.backup[0].arn, null)
  )
}

resource "aws_backup_selection" "by_tags" {
  count        = local.is_aws && length(var.aws_selection_tags) > 0 ? 1 : 0
  name         = "${var.aws_backup_plan_name}-by-tags"
  plan_id      = aws_backup_plan.this[0].id
  iam_role_arn = local.aws_selection_role_arn

  dynamic "selection_tag" {
    for_each = var.aws_selection_tags
    content {
      type  = selection_tag.value.type
      key   = selection_tag.value.key
      value = selection_tag.value.value
    }
  }
}

# Отбор ресурсов в план (по списку ARN)
resource "aws_backup_selection" "by_arns" {
  count        = local.is_aws && length(var.aws_selection_resources) > 0 ? 1 : 0
  name         = "${var.aws_backup_plan_name}-by-arns"
  plan_id      = aws_backup_plan.this[0].id
  iam_role_arn = local.aws_selection_role_arn
  resources    = var.aws_selection_resources
}

########################
# GCP: Compute Engine Snapshot Schedule Policy + прикрепление к дискам
########################

# Переменные GCP
variable "gcp_project" {
  description = "ID проекта GCP (для привязки policy к дискам)"
  type        = string
  default     = null
}

variable "gcp_region" {
  description = "Регион для Resource Policy (например, europe-west1)"
  type        = string
  default     = null
}

variable "gcp_policy_name" {
  description = "Имя Resource Policy (snapshot schedule)"
  type        = string
  default     = "aethernova-snapshot-schedule"
}

# Расписание снапшотов
variable "gcp_schedule" {
  description = <<EOT
Настройка расписания:
{
  type       = "daily" | "hourly" | "weekly",
  start_time = "22:00",                 # UTC, начало на 'час:00'
  days_in_cycle  = optional(number),    # для daily; для PD: обычно 1
  hours_in_cycle = optional(number),    # для hourly (например 4)
  weekly = optional(list(string))       # для weekly: ["monday","thursday"]
}
EOT
  type = object({
    type           = string
    start_time     = string
    days_in_cycle  = optional(number)
    hours_in_cycle = optional(number)
    weekly         = optional(list(string))
  })
  default = {
    type       = "daily"
    start_time = "22:00"
    days_in_cycle = 1
  }
}

# Политика хранения и свойства снапшотов
variable "gcp_retention" {
  description = <<EOT
Политика хранения/удаления:
{
  max_retention_days   = number,                    # >=1
  on_source_disk_delete= "KEEP_AUTO_SNAPSHOTS" | "APPLY_RETENTION_POLICY"
}
EOT
  type = object({
    max_retention_days    = number
    on_source_disk_delete = string
  })
  default = {
    max_retention_days    = 30
    on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
  }
}

variable "gcp_snapshot_properties" {
  description = <<EOT
Свойства создаваемых снапшотов:
{
  storage_locations = optional(list(string)), # например ["EU"]
  labels            = optional(map(string)),
  guest_flush       = optional(bool)          # для Windows/Guest agents
}
EOT
  type = object({
    storage_locations = optional(list(string))
    labels            = optional(map(string))
    guest_flush       = optional(bool)
  })
  default = {}
}

# Список дисков для прикрепления политики: [{disk="name", zone="europe-west1-b"}]
variable "gcp_disks" {
  description = "Диски для прикрепления snapshot schedule policy"
  type = list(object({
    disk = string
    zone = string
  }))
  default = []
}

# Политика snapshot schedule
resource "google_compute_resource_policy" "snapshot" {
  count  = local.is_gcp ? 1 : 0
  name   = var.gcp_policy_name
  region = var.gcp_region
  project = var.gcp_project

  snapshot_schedule_policy {

    schedule {
      dynamic "hourly_schedule" {
        for_each = var.gcp_schedule.type == "hourly" ? [1] : []
        content {
          start_time     = var.gcp_schedule.start_time
          hours_in_cycle = coalesce(var.gcp_schedule.hours_in_cycle, 4)
        }
      }

      dynamic "daily_schedule" {
        for_each = var.gcp_schedule.type == "daily" ? [1] : []
        content {
          start_time    = var.gcp_schedule.start_time
          days_in_cycle = coalesce(var.gcp_schedule.days_in_cycle, 1)
        }
      }

      dynamic "weekly_schedule" {
        for_each = var.gcp_schedule.type == "weekly" ? [1] : []
        content {
          dynamic "day_of_weeks" {
            for_each = toset(coalesce(var.gcp_schedule.weekly, []))
            content {
              day        = day_of_weeks.value
              start_time = var.gcp_schedule.start_time
            }
          }
        }
      }
    }

    retention_policy {
      max_retention_days    = var.gcp_retention.max_retention_days
      on_source_disk_delete = var.gcp_retention.on_source_disk_delete
    }

    dynamic "snapshot_properties" {
      for_each = [var.gcp_snapshot_properties]
      content {
        storage_locations = try(snapshot_properties.value.storage_locations, null)
        labels            = try(snapshot_properties.value.labels, null)
        guest_flush       = try(snapshot_properties.value.guest_flush, null)
      }
    }
  }
  labels = var.tags
}

# Прикрепление политики ко всем указанным дискам
resource "google_compute_disk_resource_policy_attachment" "attach" {
  for_each = local.is_gcp ? {
    for d in var.gcp_disks : "${d.zone}/${d.disk}" => d
  } : {}

  name    = google_compute_resource_policy.snapshot[0].name
  disk    = each.value.disk
  zone    = each.value.zone
  project = var.gcp_project
}

########################
# AZURE: Recovery Services Vault + VM Backup Policy
########################

# Переменные Azure
variable "az_resource_group_name" {
  description = "Имя resource group для Recovery Services Vault"
  type        = string
  default     = null
}

variable "az_location" {
  description = "Регион Azure (например, westeurope)"
  type        = string
  default     = null
}

variable "az_vault_name" {
  description = "Имя Recovery Services Vault"
  type        = string
  default     = "aethernova-rsv"
}

variable "az_vault_sku" {
  description = "SKU хранилища резервных копий (Standard)"
  type        = string
  default     = "Standard"
}

variable "az_storage_mode_type" {
  description = "Тип избыточности хранилища: LocallyRedundant | GeoRedundant"
  type        = string
  default     = "GeoRedundant"
}

variable "az_soft_delete_enabled" {
  description = "Включить soft-delete в vault"
  type        = bool
  default     = true
}

variable "az_cross_region_restore_enabled" {
  description = "Включить Cross-Region Restore (CRR) в vault"
  type        = bool
  default     = false
}

# Параметры политики бэкапа VM (V1 Daily/Weekly — максимально совместимо)
variable "az_vm_policy_name" {
  description = "Имя политики VM Backup"
  type        = string
  default     = "aethernova-vm-backup-policy"
}

variable "az_backup_frequency" {
  description = "Частота: Daily или Weekly (для Enhanced Hourly см. policy_type=V2)"
  type        = string
  default     = "Daily"
}

variable "az_backup_time_utc" {
  description = "Время запуска (UTC, формат HH:MM)"
  type        = string
  default     = "23:00"
}

variable "az_backup_weekdays" {
  description = "Дни недели для Weekly (если backup_frequency=Weekly)"
  type        = list(string)
  default     = ["Sunday"]
}

variable "az_retention_daily_count" {
  description = "Количество ежедневных точек восстановления"
  type        = number
  default     = 14
}

variable "az_retention_weekly" {
  description = "Еженедельная ретенция: {count=число, weekdays=[...]}"
  type = object({
    count    = number
    weekdays = list(string)
  })
  default = {
    count    = 8
    weekdays = ["Sunday"]
  }
}

variable "az_policy_type" {
  description = "Тип политики Azure Backup: V1 (стандарт) или V2 (Enhanced)"
  type        = string
  default     = "V1"
}

# Recovery Services Vault
resource "azurerm_recovery_services_vault" "this" {
  count                         = local.is_azure ? 1 : 0
  name                          = var.az_vault_name
  location                      = var.az_location
  resource_group_name           = var.az_resource_group_name
  sku                           = var.az_vault_sku
  storage_mode_type             = var.az_storage_mode_type
  soft_delete_enabled           = var.az_soft_delete_enabled
  cross_region_restore_enabled  = var.az_cross_region_restore_enabled
  tags                          = var.tags
}

# Политика бэкапа VM
resource "azurerm_backup_policy_vm" "this" {
  count               = local.is_azure ? 1 : 0
  name                = var.az_vm_policy_name
  resource_group_name = var.az_resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.this[0].name
  policy_type         = var.az_policy_type # V1 (Daily/Weekly); V2 — Enhanced (hourly)

  backup {
    frequency = var.az_backup_frequency # "Daily" или "Weekly"
    time      = var.az_backup_time_utc  # "HH:MM" UTC
    weekdays  = var.az_backup_weekdays  # используется, если Weekly
  }

  # Минимально необходимая ретенция; при Weekly — добавляем weekly-блок
  retention_daily {
    count = var.az_retention_daily_count
  }

  dynamic "retention_weekly" {
    for_each = var.az_backup_frequency == "Weekly" ? [1] : []
    content {
      count    = var.az_retention_weekly.count
      weekdays = var.az_retention_weekly.weekdays
    }
  }

  # При необходимости можно расширить monthly/yearly и enhanced options (V2).
  # См. провайдер и Microsoft Learn.
  depends_on = [azurerm_recovery_services_vault.this]
}
