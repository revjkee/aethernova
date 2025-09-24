// path: aethernova-chain-core/ops/terraform/modules/security/policy-audit/variables.tf
// SPDX-License-Identifier: Apache-2.0

#######################################
# Global tags and common configuration #
#######################################

variable "tags" {
  description = "Глобальные теги, применяемые к создаваемым ресурсам аудита политик (Access Analyzer, Config и др.)."
  type        = map(string)
  default     = {}
}

#############################################
# IAM Access Analyzer - analyzers definition #
#############################################
# Поддерживаются типы анализаторов:
# ACCOUNT | ORGANIZATION | ACCOUNT_INTERNAL_ACCESS | ORGANIZATION_INTERNAL_ACCESS
# ACCOUNT_UNUSED_ACCESS | ORGANIZATION_UNUSED_ACCESS

variable "analyzers" {
  description = <<EOT
Список анализаторов IAM Access Analyzer. Каждый элемент задаёт один анализатор.
Поля:
- name                : (string) Имя анализатора (обязательно).
- type                : (string) Тип зоны доверия/анализа. Допустимые значения:
                        "ACCOUNT", "ORGANIZATION",
                        "ACCOUNT_INTERNAL_ACCESS", "ORGANIZATION_INTERNAL_ACCESS",
                        "ACCOUNT_UNUSED_ACCESS", "ORGANIZATION_UNUSED_ACCESS".
- delegated_account_id: (string|null) ID делегированного администратора (только при type, начинающемся с ORGANIZATION*).
- unused_access       : (object|null) Параметры для анализатора неиспользуемого доступа:
    - tracking_period_days : (number) 1..365 — окно анализа неиспользуемого доступа.
    - exclude_account_ids  : (list(string)) Список Account ID для исключения (только для ORGANIZATION_UNUSED_ACCESS).
    - exclude_principal_tags: (map(string)) Теги (key=value) для исключения пользователей/ролей (ACCOUNT/ORGANIZATION *_UNUSED_ACCESS).
- kms_key_arn         : (string|null) KMS-ключ для шифрования (если поддерживается конкретным ресурсом/логами вокруг него).
- tags                : (map(string)) Дополнительные теги (сливаются с var.tags).
EOT
  type = list(object({
    name                 = string
    type                 = string
    delegated_account_id = optional(string)
    unused_access = optional(object({
      tracking_period_days   = number
      exclude_account_ids    = optional(list(string), [])
      exclude_principal_tags = optional(map(string), {})
    }))
    kms_key_arn = optional(string)
    tags        = optional(map(string), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for a in var.analyzers : contains([
        "ACCOUNT",
        "ORGANIZATION",
        "ACCOUNT_INTERNAL_ACCESS",
        "ORGANIZATION_INTERNAL_ACCESS",
        "ACCOUNT_UNUSED_ACCESS",
        "ORGANIZATION_UNUSED_ACCESS"
      ], a.type)
    ])
    error_message = "analyzers[*].type должен быть одним из: ACCOUNT, ORGANIZATION, ACCOUNT_INTERNAL_ACCESS, ORGANIZATION_INTERNAL_ACCESS, ACCOUNT_UNUSED_ACCESS, ORGANIZATION_UNUSED_ACCESS."
  }

  validation {
    condition = alltrue([
      for a in var.analyzers : (
        a.type != "ORGANIZATION"
        && a.type != "ORGANIZATION_INTERNAL_ACCESS"
        && a.type != "ORGANIZATION_UNUSED_ACCESS"
      ) || try(a.delegated_account_id != null && length(a.delegated_account_id) > 0, false)
    ])
    error_message = "Для ORGANIZATION* анализаторов необходимо указать delegated_account_id (делегированный администратор Organizations)."
  }

  validation {
    condition = alltrue([
      for a in var.analyzers : (
        !startswith(a.type, "ACCOUNT_UNUSED_ACCESS") && !startswith(a.type, "ORGANIZATION_UNUSED_ACCESS")
      ) || (
        try(a.unused_access.tracking_period_days >= 1 && a.unused_access.tracking_period_days <= 365, false)
      )
    ])
    error_message = "Для *_UNUSED_ACCESS анализаторов необходимо задать unused_access.tracking_period_days в диапазоне 1..365."
  }
}

#######################################################
# IAM Access Analyzer - archive rules (suppressions)  #
#######################################################
variable "archive_rules" {
  description = <<EOT
Архив-правила для IAM Access Analyzer (применяются к НОВЫМ совпадающим находкам).
Каждый элемент:
- analyzer_name : (string) Имя анализатора, к которому относится правило.
- rule_name     : (string) Имя правила архивации.
- filter        : (map(list(string))) Критерии фильтра: ключи — разрешённые Access Analyzer filter keys
                  (например: "resource", "resourceType", "findingType", "isPublic", "principal", "condition").
                  Значения — списки допустимых значений (до 20 на критерий согласно лимитам сервиса).
EOT
  type = list(object({
    analyzer_name = string
    rule_name     = string
    filter        = map(list(string))
  }))
  default = []

  validation {
    condition = alltrue([for r in var.archive_rules : length(r.rule_name) > 0 && length(r.analyzer_name) > 0])
    error_message = "archive_rules[*] требуют непустые analyzer_name и rule_name."
  }
}

##########################################
# AWS Config - managed rules for policies #
##########################################
variable "enable_aws_config" {
  description = "Включить развёртывание AWS Config managed rules, относящихся к проверке IAM/политик/тегов."
  type        = bool
  default     = false
}

variable "config_delivery_channel_name" {
  description = "Имя delivery channel для AWS Config (если создаётся в пределах модуля или используется существующий)."
  type        = string
  default     = null
  nullable    = true
}

variable "config_s3_bucket" {
  description = "S3 bucket для доставки конфигураций/отчётов AWS Config (если управление этим аспектом входит в модуль)."
  type        = string
  default     = null
  nullable    = true
}

variable "config_rules" {
  description = <<EOT
Список AWS Config managed rules, которые следует включить (идентификаторы managed правил).
Примеры для аудита политик/безопасности:
- IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS
- IAM_USER_NO_POLICIES
- IAM_USER_MFA_ENABLED
- S3_BUCKET_PUBLIC_READ_PROHIBITED
- S3_BUCKET_PUBLIC_WRITE_PROHIBITED
EOT
  type    = list(string)
  default = []

  validation {
    condition     = alltrue([for r in var.config_rules : length(trim(r)) > 0])
    error_message = "config_rules не должны содержать пустых значений."
  }
}

#########################################
# Optional notifications / integration  #
#########################################

variable "notify_findings_to_sns" {
  description = "Публиковать ли события (через внеполосные механизмы) в SNS topic ARNs (интеграции на стороне пользователя)."
  type        = list(string)
  default     = []
}

#########################################
# Cross-field integrity / guard toggles #
#########################################

variable "enforce_org_analyzers_have_delegation" {
  description = "Перекрёстная валидация: для ORGANIZATION* анализаторов требуется delegated_account_id."
  type        = bool
  default     = true
  validation {
    condition = alltrue([
      for a in var.analyzers : (
        !startswith(a.type, "ORGANIZATION")
      ) || try(a.delegated_account_id != null && length(a.delegated_account_id) > 0, false)
    ])
    error_message = "ORGANIZATION* анализатор без delegated_account_id: укажите delegated_account_id."
  }
}

variable "enforce_archive_rules_names_unique" {
  description = "Проверять уникальность имён archive_rules в рамках одного анализатора."
  type        = bool
  default     = true
  validation {
    condition = (
      length(var.archive_rules) == 0
      || length(distinct([for r in var.archive_rules : "${r.analyzer_name}::${r.rule_name}"])) == length(var.archive_rules)
    )
    error_message = "Пары analyzer_name::rule_name в archive_rules должны быть уникальны."
  }
}

################################
# Advanced / future extensions #
################################

variable "policy_validation_strict" {
  description = "Строгий режим при валидации политик (используется ресурсами вне этого файла — генераторы/проверки policy JSON)."
  type        = bool
  default     = true
}

variable "reserved" {
  description = "Зарезервировано для будущих расширений (объект свободной формы)."
  type        = map(any)
  default     = {}
}
