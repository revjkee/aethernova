terraform {
  required_version = ">= 1.6.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60.0, < 6.0.0"
    }
  }
}

###########################################################
# Core naming and tags
###########################################################

variable "name" {
  description = "Базовое имя для ресурсов бэкапа (backup vault/plan/selection)."
  type        = string

  validation {
    condition     = length(trim(var.name)) > 0
    error_message = "name не может быть пустым."
  }
}

variable "tags" {
  description = "Глобальные тэги."
  type        = map(string)
  default     = {}
}

###########################################################
# Backup Vault
###########################################################

variable "create_vault" {
  description = "Создавать Backup Vault в модуле."
  type        = bool
  default     = true
}

variable "vault_name" {
  description = "Имя Backup Vault (если create_vault=false — ожидается существующий)."
  type        = string
  default     = null
}

variable "vault_kms_key_arn" {
  description = "KMS Key ARN для шифрования Backup Vault."
  type        = string
  default     = null
}

# AWS Backup Vault Lock (immutability)
variable "vault_lock_config" {
  description = <<-EOT
Настройки Vault Lock (неизменяемость бэкапов):
  - min_retention_days (минимальный срок хранения)
  - max_retention_days (максимальный срок хранения)
  - changeable_for_days (окно 'cooling off' для изменения политики; 0 — без окна)
EOT
  type = object({
    min_retention_days  = optional(number)
    max_retention_days  = optional(number)
    changeable_for_days = optional(number, 0)
  })
  default = {}

  validation {
    condition = (
      var.vault_lock_config.min_retention_days == null ||
      var.vault_lock_config.max_retention_days == null ||
      var.vault_lock_config.max_retention_days >= var.vault_lock_config.min_retention_days
    )
    error_message = "max_retention_days должен быть >= min_retention_days."
  }
}

###########################################################
# Backup Plan (rules, lifecycle, copy)
###########################################################

variable "create_plan" {
  description = "Создавать Backup Plan."
  type        = bool
  default     = true
}

variable "plan_name" {
  description = "Имя Backup Plan. По умолчанию <name>-plan."
  type        = string
  default     = null
}

variable "plan_rules" {
  description = <<-EOT
Список правил плана бэкапа.
Поля:
  - name: имя правила
  - schedule_cron: cron выражение в UTC (формат AWS: cron(…))
  - start_window: секунды окна старта (опц.)
  - completion_window: секунды окна завершения (опц.)
  - enable_continuous_backup: true/false (опц.)
  - lifecycle: { cold_storage_after, delete_after } (дни; опц.)
  - copy_actions: список действий копирования:
      - destination_vault_arn
      - lifecycle: { cold_storage_after, delete_after } (опц.)
  - recovery_point_tags: map(string) — тэги на точки восстановления (опц.)
EOT
  type = list(object({
    name                     = string
    schedule_cron            = string
    start_window             = optional(number)
    completion_window        = optional(number)
    enable_continuous_backup = optional(bool, false)
    lifecycle = optional(object({
      cold_storage_after = optional(number)
      delete_after       = optional(number)
    }), null)
    copy_actions = optional(list(object({
      destination_vault_arn = string
      lifecycle = optional(object({
        cold_storage_after = optional(number)
        delete_after       = optional(number)
      }), null)
    })), [])
    recovery_point_tags = optional(map(string), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.plan_rules : can(regex("^cron\\((.+)\\)$", r.schedule_cron))
    ])
    error_message = "Каждый schedule_cron должен соответствовать формату AWS Backup: cron(…)"
  }

  validation {
    condition = alltrue([
      for r in var.plan_rules :
      (
        r.lifecycle == null
        || r.lifecycle.delete_after == null
        || r.lifecycle.cold_storage_after == null
        || r.lifecycle.delete_after > r.lifecycle.cold_storage_after
      )
    ])
    error_message = "В lifecycle.delete_after должно быть больше, чем lifecycle.cold_storage_after."
  }
}

###########################################################
# Backup Selection (what to protect)
###########################################################

variable "create_selection" {
  description = "Создавать Backup Selection (привязка ресурсов к плану)."
  type        = bool
  default     = true
}

variable "selection_name" {
  description = "Имя Backup Selection. По умолчанию <name>-selection."
  type        = string
  default     = null
}

variable "selection_iam_role_arn" {
  description = "IAM роль, которую AWS Backup использует для доступа к ресурсам."
  type        = string
  default     = null
}

variable "selection_resources" {
  description = "Список ARNs ресурсов для включения (EBS, RDS, EFS, DynamoDB и др.)."
  type        = list(string)
  default     = []
}

variable "selection_tags" {
  description = <<-EOT
Правила выбора по тэгам:
  - type: 'STRINGEQUALS' (требуется AWS)
  - key: ключ тэга
  - value: значение тэга
EOT
  type = list(object({
    type  = string
    key   = string
    value = string
  }))
  default = []

  validation {
    condition     = alltrue([for t in var.selection_tags : t.type == "STRINGEQUALS"])
    error_message = "selection_tags[].type должен быть 'STRINGEQUALS' по требованиям AWS Backup."
  }
}

variable "not_resources" {
  description = "Список ARNs ресурсов для исключения из выбора."
  type        = list(string)
  default     = []
}

###########################################################
# Advanced backup settings (per resource type)
###########################################################

variable "advanced_backup_settings" {
  description = <<-EOT
Доп. настройки бэкапа для сервисов:
map(object({
  resource_type = string  # например 'EC2', 'FSX', 'EFS' и т.п.
  options       = map(string)
}))
Пример: [{"resource_type":"EC2","options":{"WindowsVSS":"enabled"}}]
EOT
  type = list(object({
    resource_type = string
    options       = map(string)
  }))
  default = []
}

###########################################################
# Notifications / Events (optional integration)
###########################################################

variable "eventbridge_rules_enabled" {
  description = "Создавать правила EventBridge для событий Backup (успех/ошибка и т.п.)."
  type        = bool
  default     = false
}

variable "notification_targets" {
  description = <<-EOT
Цели уведомлений (если eventbridge_rules_enabled=true):
  - sns_topic_arn: ARN SNS топика (опц.)
  - event_pattern  : JSON паттерн (string) для EventBridge (опц.)
EOT
  type = object({
    sns_topic_arn = optional(string)
    event_pattern = optional(string)
  })
  default = {}
}

###########################################################
# Cross-account / cross-region (guarded via copy_actions)
###########################################################

variable "allow_cross_account_copy" {
  description = "Разрешить копирование Recovery Points в другой аккаунт (через copy_actions)."
  type        = bool
  default     = false
}

###########################################################
# Guards and defaults
###########################################################

variable "require_lock_when_kms" {
  description = "Требовать включённый Vault Lock при использовании пользовательского KMS (доп. жесткость)."
  type        = bool
  default     = false
}

variable "default_cron_tz_utc_hint" {
  description = "Подсказка: все cron в AWS Backup исполняются в UTC. Переменная только документирует это поведение."
  type        = string
  default     = "UTC"
}

variable "plan_enabled" {
  description = "Глобальное включение/выключение Backup Plan (создание ресурсов не отменяет)."
  type        = bool
  default     = true
}
