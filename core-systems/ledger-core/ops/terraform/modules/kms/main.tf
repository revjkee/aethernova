terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

########################################
# Locals
########################################
locals {
  tags_base = {
    "Managed-By"        = "Terraform"
    "Module"            = "ledger-core/kms"
    "Environment"       = var.environment
    "Owner"             = var.owner
    "CostCenter"        = var.cost_center
    "SecurityTier"      = var.security_tier
    "DataClassification"= var.data_classification
  }

  tags = merge(local.tags_base, var.tags)

  # Определяем, можно ли включать rotation (только для SYMMETRIC_DEFAULT)
  rotation_allowed = var.key_spec == "SYMMETRIC_DEFAULT"

  # Детальная карта действий по ролям
  kms_actions_admin = [
    "kms:*"
  ]

  kms_actions_usage_read = [
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:Verify",
    "kms:GetPublicKey"
  ]

  kms_actions_usage_write = [
    "kms:Encrypt",
    "kms:ReEncrypt*",
    "kms:GenerateDataKey",
    "kms:GenerateDataKeyWithoutPlaintext",
    "kms:Sign"
  ]

  # Формируем statements для usage principals
  usage_principals_read  = [for p in var.usage_principals : p if contains(p.actions, "read")]
  usage_principals_write = [for p in var.usage_principals : p if contains(p.actions, "write")]

  # Контекст условий для usage (опционально)
  usage_conditions = var.usage_conditions # map(string=>any), уже валидирован в variables
}

########################################
# Data sources
########################################
data "aws_caller_identity" "this" {}

data "aws_partition" "this" {}

########################################
# Policy documents
########################################

# Базовая безопасная политика: предотвращает lockout, всегда включает root аккаунта и админов
data "aws_iam_policy_document" "base" {
  statement {
    sid = "EnableRootPermissions"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.this.partition}:iam::${data.aws_caller_identity.this.account_id}:root"]
    }
    actions   = local.kms_actions_admin
    resources = ["*"]
  }

  # Администраторы ключа (IAM роли/пользователи/ARN-ы)
  dynamic "statement" {
    for_each = length(var.admin_principals) > 0 ? [1] : []
    content {
      sid = "AllowKeyAdminsFullAccess"
      principals {
        type        = "AWS"
        identifiers = var.admin_principals
      }
      actions   = local.kms_actions_admin
      resources = ["*"]
    }
  }
}

# Usage: read-only
data "aws_iam_policy_document" "usage_read" {
  dynamic "statement" {
    for_each = length(local.usage_principals_read) > 0 ? local.usage_principals_read : []
    content {
      sid = "AllowUsageRead${replace(statement.value.principal, ":", "")}"
      principals {
        type        = "AWS"
        identifiers = [statement.value.principal]
      }
      actions   = local.kms_actions_usage_read
      resources = ["*"]

      dynamic "condition" {
        for_each = lookup(statement.value, "conditions", null) != null ? statement.value.conditions : (length(local.usage_conditions) > 0 ? [local.usage_conditions] : [])
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

# Usage: write
data "aws_iam_policy_document" "usage_write" {
  dynamic "statement" {
    for_each = length(local.usage_principals_write) > 0 ? local.usage_principals_write : []
    content {
      sid = "AllowUsageWrite${replace(statement.value.principal, ":", "")}"
      principals {
        type        = "AWS"
        identifiers = [statement.value.principal]
      }
      actions   = local.kms_actions_usage_write
      resources = ["*"]

      dynamic "condition" {
        for_each = lookup(statement.value, "conditions", null) != null ? statement.value.conditions : (length(local.usage_conditions) > 0 ? [local.usage_conditions] : [])
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

# Дополнительные пользовательские statements (raw JSON/YAML через variables)
data "aws_iam_policy_document" "extra" {
  dynamic "statement" {
    for_each = var.extra_policy_statements
    content {
      sid = lookup(statement.value, "sid", null)

      dynamic "principals" {
        for_each = lookup(statement.value, "principals", [])
        content {
          type        = principals.value.type
          identifiers = principals.value.identifiers
        }
      }

      actions   = statement.value.actions
      resources = statement.value.resources

      dynamic "condition" {
        for_each = lookup(statement.value, "conditions", [])
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

# Итоговая политика (merge всех документов)
data "aws_iam_policy_document" "final" {
  source_policy_documents = compact([
    data.aws_iam_policy_document.base.json,
    length(local.usage_principals_read)  > 0 ? data.aws_iam_policy_document.usage_read.json  : null,
    length(local.usage_principals_write) > 0 ? data.aws_iam_policy_document.usage_write.json : null,
    length(var.extra_policy_statements)  > 0 ? data.aws_iam_policy_document.extra.json        : null
  ])
}

########################################
# KMS Key
########################################
resource "aws_kms_key" "this" {
  description              = var.description
  key_usage                = var.key_usage
  customer_master_key_spec = var.key_spec
  multi_region             = var.multi_region
  deletion_window_in_days  = var.deletion_window_in_days
  is_enabled               = var.enabled
  enable_key_rotation      = local.rotation_allowed ? var.enable_key_rotation : false
  policy                   = data.aws_iam_policy_document.final.json
  bypass_policy_lockout_safety_check = var.bypass_policy_lockout_safety_check

  tags = local.tags

  lifecycle {
    prevent_destroy = var.prevent_destroy
    ignore_changes  = [tags]
  }
}

########################################
# Aliases
########################################
resource "aws_kms_alias" "aliases" {
  for_each      = toset(var.aliases)
  name          = "alias/${each.value}"
  target_key_id = aws_kms_key.this.key_id
}

########################################
# Grants
########################################
resource "aws_kms_grant" "grants" {
  for_each = { for g in var.grants : g.name => g }

  name              = each.value.name
  key_id            = aws_kms_key.this.key_id
  grantee_principal = each.value.grantee_principal

  # Операции на грант
  operations = each.value.operations

  # Необязательный retiring principal
  retiring_principal = try(each.value.retiring_principal, null)

  # Ограничения гранта (encryption context equality / subset)
  dynamic "constraints" {
    for_each = try(each.value.constraints, null) == null ? [] : [each.value.constraints]
    content {
      dynamic "encryption_context_equals" {
        for_each = try(constraints.value.encryption_context_equals, {})
        content {
          context = {
            for k, v in constraints.value.encryption_context_equals : k => v
          }
        }
      }
      dynamic "encryption_context_subset" {
        for_each = try(constraints.value.encryption_context_subset, {})
        content {
          context = {
            for k, v in constraints.value.encryption_context_subset : k => v
          }
        }
      }
    }
  }

  # Чтобы Terraform корректно пересоздавал гранты при замене ключа
  depends_on = [aws_kms_key.this]
}

########################################
# Outputs
########################################
output "key_id" {
  value       = aws_kms_key.this.key_id
  description = "ID KMS ключа"
}

output "key_arn" {
  value       = aws_kms_key.this.arn
  description = "ARN KMS ключа"
}

output "alias_arns" {
  value       = { for k, a in aws_kms_alias.aliases : k => a.arn }
  description = "ARN-ы алиасов"
}

output "policy" {
  value       = data.aws_iam_policy_document.final.json
  description = "Итоговая политика ключа"
  sensitive   = true
}

########################################
# Variables (в модуле для самодостаточности)
########################################

variable "environment" {
  type        = string
  description = "Идентификатор окружения (prod/stage/dev и т.д.)"
}

variable "owner" {
  type        = string
  description = "Ответственный владелец"
}

variable "cost_center" {
  type        = string
  description = "Код центра затрат"
}

variable "security_tier" {
  type        = string
  description = "Уровень безопасности (например, High/Medium/Low)"
  default     = "High"
}

variable "data_classification" {
  type        = string
  description = "Классификация данных (например, Confidential/Internal/Public)"
  default     = "Confidential"
}

variable "tags" {
  type        = map(string)
  description = "Дополнительные теги"
  default     = {}
}

variable "description" {
  type        = string
  description = "Описание KMS ключа"
  default     = "Ledger Core managed KMS key"
}

variable "key_usage" {
  type        = string
  description = "Назначение ключа: ENCRYPT_DECRYPT | SIGN_VERIFY"
  default     = "ENCRYPT_DECRYPT"
  validation {
    condition     = contains(["ENCRYPT_DECRYPT", "SIGN_VERIFY"], var.key_usage)
    error_message = "key_usage must be ENCRYPT_DECRYPT or SIGN_VERIFY."
  }
}

variable "key_spec" {
  type        = string
  description = <<EOT
Спецификация ключа:
- SYMMETRIC_DEFAULT
- RSA_2048 | RSA_3072 | RSA_4096
- ECC_NIST_P256 | ECC_NIST_P384 | ECC_NIST_P521 | ECC_SECG_P256K1
- HMAC_224 | HMAC_256 | HMAC_384 | HMAC_512
- SM2
EOT
  default     = "SYMMETRIC_DEFAULT"
}

variable "multi_region" {
  type        = bool
  description = "Включить много-регионность ключа (создаёт первичный multi-Region ключ)"
  default     = false
}

variable "deletion_window_in_days" {
  type        = number
  description = "Окно отложенного удаления ключа (7..30)"
  default     = 30
  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days must be between 7 and 30."
  }
}

variable "enabled" {
  type        = bool
  description = "Включён ли ключ"
  default     = true
}

variable "enable_key_rotation" {
  type        = bool
  description = "Включить автоматическую ротацию (только SYMMETRIC_DEFAULT)"
  default     = true
}

variable "prevent_destroy" {
  type        = bool
  description = "Защитить ключ от уничтожения на уровне Terraform (lifecycle.prevent_destroy)"
  default     = true
}

variable "bypass_policy_lockout_safety_check" {
  type        = bool
  description = "Разрешить попытку обновления политики без safety check (не рекомендуется)"
  default     = false
}

variable "aliases" {
  type        = list(string)
  description = "Список алиасов без префикса (будет применён alias/)"
  default     = []
}

variable "admin_principals" {
  type        = list(string)
  description = "ARN-ы IAM субъектов с полным админ-доступом к ключу"
  default     = []
}

# Структура usage_principals:
# [
#   {
#     principal  = "arn:aws:iam::<account-id>:role/app"
#     actions    = ["read","write"] # любое сочетание
#     conditions = [
#       { test = "StringEquals", variable = "kms:EncryptionContext:App", values = ["ledger-core"] }
#     ]
#   }
# ]
variable "usage_principals" {
  type = list(object({
    principal  = string
    actions    = list(string) # "read" | "write"
    conditions = optional(list(object({
      test     = string
      variable = string
      values   = list(string)
    })), [])
  }))
  description = "Пользователи ключа (минимально необходимые права с опциональными условиями)"
  default     = []
}

# Гранты:
# [
#   {
#     name               = "grant-to-service-x"
#     grantee_principal  = "arn:aws:iam::<account-id>:role/service"
#     operations         = ["Encrypt","Decrypt","GenerateDataKey"]
#     retiring_principal = "arn:aws:iam::<account-id>:role/admin" # optional
#     constraints = {
#       encryption_context_equals = { "App" = "ledger-core" }
#       encryption_context_subset = { "Env" = "prod" }
#     }
#   }
# ]
variable "grants" {
  type = list(object({
    name               = string
    grantee_principal  = string
    operations         = list(string)
    retiring_principal = optional(string)
    constraints = optional(object({
      encryption_context_equals = optional(map(string))
      encryption_context_subset = optional(map(string))
    }))
  }))
  description = "Набор KMS грантов для сервисов/подсистем"
  default     = []
}

# Дополнительные statements в политику ключа:
# [
#   {
#     sid        = "CustomStatement"
#     principals = [{ type = "AWS", identifiers = ["arn:aws:iam::<id>:role/x"] }]
#     actions    = ["kms:Decrypt"]
#     resources  = ["*"]
#     conditions = [
#       { test = "StringEquals", variable = "kms:EncryptionContext:Team", values = ["core"] }
#     ]
#   }
# ]
variable "extra_policy_statements" {
  type = list(object({
    sid        = optional(string)
    principals = optional(list(object({
      type        = string
      identifiers = list(string)
    })), [])
    actions    = list(string)
    resources  = list(string)
    conditions = optional(list(object({
      test     = string
      variable = string
      values   = list(string)
    })), [])
  }))
  description = "Дополнительные утверждения, встраиваемые в ключевую политику"
  default     = []
}

# Глобальные usage-conditions по умолчанию (если не заданы в конкретном principal)
# Пример: { test = "StringEquals", variable = "kms:EncryptionContext:Environment", values = ["prod"] }
variable "usage_conditions" {
  type = list(object({
    test     = string
    variable = string
    values   = list(string)
  }))
  description = "Условия по умолчанию для usage principals"
  default     = []
}
