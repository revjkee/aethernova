terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
  }
}

############################################
# Data sources
############################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

############################################
# Variables (все в одном файле для автономности модуля)
############################################

variable "name" {
  description = "Логическое имя ключа (используется в тегах и alias по умолчанию)."
  type        = string
}

variable "description" {
  description = "Описание назначения KMS Key."
  type        = string
  default     = "Customer Managed KMS Key for cybersecurity-core"
}

variable "alias" {
  description = "Алиас ключа без префикса alias/. Если не задан, берется var.name."
  type        = string
  default     = ""
}

variable "key_usage" {
  description = "Назначение ключа: ENCRYPT_DECRYPT или SIGN_VERIFY."
  type        = string
  default     = "ENCRYPT_DECRYPT"
  validation {
    condition     = contains(["ENCRYPT_DECRYPT", "SIGN_VERIFY"], var.key_usage)
    error_message = "key_usage должен быть ENCRYPT_DECRYPT или SIGN_VERIFY."
  }
}

variable "key_spec" {
  description = "Тип ключа: SYMMETRIC_DEFAULT, RSA_2048/3072/4096, ECC_NIST_P256/384/521, ECC_SECG_P256K1, HMAC_224/256/384/512, SM2."
  type        = string
  default     = "SYMMETRIC_DEFAULT"
}

variable "multi_region" {
  description = "Создавать ключ как Multi-Region Primary."
  type        = bool
  default     = true
}

variable "enable_key_rotation" {
  description = "Включать ротацию ключа (только для SYMMETRIC_DEFAULT)."
  type        = bool
  default     = true
}

variable "deletion_window_in_days" {
  description = "Окно удаления ключа (7–30 дней). Не применяется, если включен prevent_destroy."
  type        = number
  default     = 30
  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days должен быть в диапазоне 7–30."
  }
}

variable "admin_arns" {
  description = "ARN'ы IAM ролей/пользователей с полномочиями администратора ключа (kms:*)."
  type        = list(string)
  default     = []
}

variable "user_arns" {
  description = "ARN'ы субъектов, которым разрешены операции шифрования/расшифровки."
  type        = list(string)
  default     = []
}

variable "readonly_arns" {
  description = "ARN'ы субъектов с правом Describe/List без криптоопераций."
  type        = list(string)
  default     = []
}

variable "allowed_service_principals" {
  description = "Сервис-принципалы AWS, которым должны быть даны узкие права (например, logs.region.amazonaws.com)."
  type        = list(string)
  default     = []
}

variable "policy_additional_statements" {
  description = "Дополнительные сырые JSON-стейтменты (список объектов) для включения в политику ключа."
  type        = list(any)
  default     = []
}

variable "tags" {
  description = "Общие теги AWS."
  type        = map(string)
  default     = {}
}

variable "prevent_destroy" {
  description = "Защитить ключ от уничтожения (рекомендуется true для прод)."
  type        = bool
  default     = true
}

variable "create_replica" {
  description = "Создавать мульти-региональную реплику ключа."
  type        = bool
  default     = false
}

variable "replica_region" {
  description = "Регион для реплики (требует провайдер-алиас aws.replica в родительском модуле)."
  type        = string
  default     = null
}

variable "replica_alias" {
  description = "Алиас для реплики без префикса alias/. По умолчанию — alias исходного ключа."
  type        = string
  default     = ""
}

variable "grants" {
  description = <<EOT
Список грантов для выдачи конкретным grantee principals.
Пример элемента:
{
  name               = "logs-access"
  grantee_principal  = "arn:aws:iam::123456789012:role/app"
  operations         = ["Encrypt", "Decrypt", "GenerateDataKey*"]
  retiring_principal = null
  constraints = {
    encryption_context_equals   = {}
    encryption_context_subset   = {}
  }
}
EOT
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
  default = []
}

############################################
# Locals
############################################

locals {
  alias_effective         = coalesce(var.alias != "" ? var.alias : var.name)
  replica_alias_effective = coalesce(var.replica_alias != "" ? var.replica_alias : local.alias_effective)

  # Ротация поддерживается только для симметричных ключей (SYMMETRIC_DEFAULT)
  rotation_enabled = var.enable_key_rotation && var.key_spec == "SYMMETRIC_DEFAULT" && var.key_usage == "ENCRYPT_DECRYPT"

  base_tags = merge(
    {
      "Project"     = "neurocity"
      "Component"   = "cybersecurity-core"
      "ManagedBy"   = "terraform"
      "Environment" = "prod"
    },
    var.tags
  )
}

############################################
# Key Policy
############################################

data "aws_iam_policy_document" "kms_policy" {
  statement {
    sid     = "AllowRootAccount"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.admin_arns) > 0 ? [1] : []
    content {
      sid     = "AllowKeyAdmins"
      effect  = "Allow"
      actions = ["kms:*"]
      principals {
        type        = "AWS"
        identifiers = var.admin_arns
      }
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "kms:CallerAccount"
        values   = [data.aws_caller_identity.current.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.user_arns) > 0 ? [1] : []
    content {
      sid    = "AllowKeyUsersEncryptDecrypt"
      effect = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:DescribeKey"
      ]
      principals {
        type        = "AWS"
        identifiers = var.user_arns
      }
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "kms:CallerAccount"
        values   = [data.aws_caller_identity.current.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.readonly_arns) > 0 ? [1] : []
    content {
      sid     = "AllowReadOnlyDescribe"
      effect  = "Allow"
      actions = ["kms:DescribeKey", "kms:ListAliases", "kms:ListGrants", "kms:ListKeyPolicies"]
      principals {
        type        = "AWS"
        identifiers = var.readonly_arns
      }
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.allowed_service_principals
    content {
      sid     = "AllowServicePrincipal-${replace(statement.value, ".", "-")}"
      effect  = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      principals {
        type        = "Service"
        identifiers = [statement.value]
      }
      resources = ["*"]
      # При необходимости можно добавить условия ViaService/EncryptionContext
    }
  }

  dynamic "statement" {
    for_each = var.policy_additional_statements
    content {
      sid     = lookup(statement.value, "Sid", null)
      effect  = lookup(statement.value, "Effect", "Allow")
      actions = lookup(statement.value, "Action", [])
      resources = try(
        lookup(statement.value, "Resource", ["*"]),
        ["*"]
      )

      dynamic "principals" {
        for_each = lookup(statement.value, "Principal", null) != null ? [lookup(statement.value, "Principal", {})] : []
        content {
          type        = keys(principals.value)[0]
          identifiers = principals.value[keys(principals.value)[0]]
        }
      }

      dynamic "condition" {
        for_each = lookup(statement.value, "Condition", null) != null ? [lookup(statement.value, "Condition", {})] : []
        content {
          test     = keys(condition.value)[0] != null ? keys(condition.value)[0] : null
          variable = keys(values(condition.value)[0])[0]
          values   = values(values(condition.value)[0])[0]
        }
      }
    }
  }
}

############################################
# Primary KMS Key and Alias
############################################

resource "aws_kms_key" "this" {
  description             = var.description
  key_usage               = var.key_usage
  key_spec                = var.key_spec
  multi_region            = var.multi_region
  policy                  = data.aws_iam_policy_document.kms_policy.json
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = local.rotation_enabled
  tags                    = local.base_tags

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}

resource "aws_kms_alias" "this" {
  name          = "alias/${local.alias_effective}"
  target_key_id = aws_kms_key.this.key_id
}

############################################
# Optional: Multi-Region Replica
# Требуется в корневой конфигурации:
# provider "aws" { alias = "replica" region = var.replica_region }
############################################

resource "aws_kms_replica_key" "replica" {
  count           = var.create_replica && try(var.replica_region != null && var.replica_region != data.aws_region.current.name, true) ? 1 : 0
  provider        = aws.replica
  description     = "${var.description} (replica)"
  primary_key_arn = aws_kms_key.this.arn
  policy          = data.aws_iam_policy_document.kms_policy.json
  tags            = local.base_tags

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}

resource "aws_kms_alias" "replica" {
  count         = length(aws_kms_replica_key.replica) > 0 ? 1 : 0
  provider      = aws.replica
  name          = "alias/${local.replica_alias_effective}"
  target_key_id = aws_kms_replica_key.replica[0].key_id
}

############################################
# Optional: Grants
############################################

resource "aws_kms_grant" "this" {
  for_each          = { for g in var.grants : g.name => g }
  name              = each.value.name
  key_id            = aws_kms_key.this.key_id
  grantee_principal = each.value.grantee_principal
  operations        = each.value.operations

  dynamic "constraints" {
    for_each = try([each.value.constraints], [])
    content {
      encryption_context_equals = try(constraints.value.encryption_context_equals, null)
      encryption_context_subset = try(constraints.value.encryption_context_subset, null)
    }
  }

  retiring_principal = try(each.value.retiring_principal, null)
}

############################################
# Outputs
############################################

output "key_id" {
  description = "ID первичного KMS ключа."
  value       = aws_kms_key.this.key_id
}

output "key_arn" {
  description = "ARN первичного KMS ключа."
  value       = aws_kms_key.this.arn
}

output "alias_name" {
  description = "Имя алиаса первичного ключа."
  value       = aws_kms_alias.this.name
}

output "replica_key_id" {
  description = "ID ключа-реплики (если создана)."
  value       = length(aws_kms_replica_key.replica) > 0 ? aws_kms_replica_key.replica[0].key_id : null
}

output "replica_key_arn" {
  description = "ARN ключа-реплики (если создана)."
  value       = length(aws_kms_replica_key.replica) > 0 ? aws_kms_replica_key.replica[0].arn : null
}
