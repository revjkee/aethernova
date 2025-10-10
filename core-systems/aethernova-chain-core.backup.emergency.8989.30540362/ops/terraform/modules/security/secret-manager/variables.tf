// path: aethernova-chain-core/ops/terraform/modules/security/secret-manager/variables.tf
// SPDX-License-Identifier: Apache-2.0

############################
# Core identity & metadata #
############################

variable "name" {
  type        = string
  description = "Полное имя секрета в AWS Secrets Manager. Взаимоисключимо с name_prefix."
  default     = null
  nullable    = true
}

variable "name_prefix" {
  type        = string
  description = "Префикс для генерации уникального имени секрета. Взаимоисключимо с name."
  default     = null
  nullable    = true
}

variable "description" {
  type        = string
  description = "Описание секрета."
  default     = ""
}

variable "tags" {
  type        = map(string)
  description = "Теги для секрета."
  default     = {}
}

#################################
# Encryption & deletion windows #
#################################

variable "kms_key_id" {
  type        = string
  description = "KMS Key ID/ARN для шифрования секрета. Если null — используется ключ по умолчанию Secrets Manager."
  default     = null
  nullable    = true
}

variable "recovery_window_in_days" {
  type        = number
  description = "Окно восстановления при удалении секрета (7–30 дней)."
  default     = 30
  validation {
    condition     = var.recovery_window_in_days == 0 || (var.recovery_window_in_days >= 7 && var.recovery_window_in_days <= 30)
    error_message = "recovery_window_in_days должен быть 0 (немедленное удаление управляется отдельно) или в диапазоне 7..30."
  }
}

variable "force_overwrite_replica_secret" {
  type        = bool
  description = "Перезаписывать существующие реплики секрета при изменениях в первичном регионе."
  default     = false
}

############################
# Multi-Region replication #
############################

variable "replica_regions" {
  description = <<EOT
Список регионов-реплик. Для каждого региона можно указать отдельный KMS ключ.
Пример: [{ region = "eu-west-1" }, { region = "eu-north-1", kms_key_id = "arn:aws:kms:..." }]
EOT
  type = list(object({
    region     = string
    kms_key_id = optional(string)
  }))
  default = []
}

##########################
# Resource policy (JSON) #
##########################

variable "resource_policy_json" {
  type        = string
  description = "JSON-документ политики ресурса Secrets Manager (строка JSON). Если null — политика не применяется."
  default     = null
  nullable    = true
}

#####################################
# Initial secret value (managed via #
# aws_secretsmanager_secret_version)#
#####################################

variable "initial_secret_string" {
  type        = string
  description = "Начальное значение секрета как строка. Будет создана версия секрета. Взаимоисключимо с initial_secret_binary."
  default     = null
  nullable    = true
  sensitive   = true
}

variable "initial_secret_binary" {
  type        = string
  description = "Начальное значение секрета как base64-строка (binary). Взаимоисключимо с initial_secret_string."
  default     = null
  nullable    = true
  sensitive   = true
}

variable "version_stages" {
  type        = list(string)
  description = "Метки стадии версии для начального значения секрета."
  default     = ["AWSCURRENT"]
}

########################
# Rotation management  #
########################

variable "enable_rotation" {
  type        = bool
  description = "Включить автоматическую ротацию секрета."
  default     = false
}

variable "rotation_lambda_arn" {
  type        = string
  description = "ARN Lambda-функции ротации. Обязателен, если enable_rotation = true."
  default     = null
  nullable    = true
}

variable "rotation_rules" {
  description = <<EOT
Параметры расписания ротации. Укажите либо automatically_after_days (целое число),
либо schedule_expression (формат rate(...) или cron(...)).
EOT
  type = object({
    automatically_after_days = optional(number)
    schedule_expression      = optional(string)
  })
  default = {
    automatically_after_days = null
    schedule_expression      = null
  }
}

#############################
# Cross-field validations   #
#############################

# Ровно один из name/name_prefix
variable "enforce_name_choice" {
  type        = bool
  description = "Вспомогательная настройка для включения валидации name/name_prefix (не изменяйте)."
  default     = true
  validation {
    condition     = (var.name == null) != (var.name_prefix == null)
    error_message = "Необходимо указать ровно один из параметров: name ИЛИ name_prefix."
  }
}

# Взаимоисключение initial_secret_string / initial_secret_binary
variable "enforce_initial_value_choice" {
  type        = bool
  description = "Вспомогательная настройка для валидации исходного значения секрета (не изменяйте)."
  default     = true
  validation {
    condition     = !((var.initial_secret_string != null) && (var.initial_secret_binary != null))
    error_message = "Нельзя одновременно задавать initial_secret_string и initial_secret_binary."
  }
}

# Ротация: если enable_rotation=true — требуется rotation_lambda_arn и одно из правил
variable "enforce_rotation_requirements" {
  type        = bool
  description = "Вспомогательная настройка для валидации параметров ротации (не изменяйте)."
  default     = true
  validation {
    condition = (
      var.enable_rotation == false
      || (
        var.rotation_lambda_arn != null
        && (
          (try(var.rotation_rules.automatically_after_days, null) != null)
          || (try(var.rotation_rules.schedule_expression, null) != null)
        )
      )
    )
    error_message = "При enable_rotation=true необходимо задать rotation_lambda_arn и одно из rotation_rules: automatically_after_days или schedule_expression."
  }
}
