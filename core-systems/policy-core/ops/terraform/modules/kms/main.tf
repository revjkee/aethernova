// policy-core/ops/terraform/modules/kms/main.tf
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.43"
    }
  }
}

########################
# Data & locals
########################
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id             = data.aws_caller_identity.current.account_id
  root_arn               = "arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"
  rotation_supported     = var.key_spec == "SYMMETRIC_DEFAULT" && var.origin == "AWS_KMS"
  multi_region_supported = var.origin == "AWS_KMS"

  use_actions = var.key_usage == "ENCRYPT_DECRYPT" ? [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncrypt*",
    "kms:GenerateDataKey*",
    "kms:DescribeKey"
  ] : [
    "kms:DescribeKey",
    "kms:GetPublicKey",
    "kms:Sign",
    "kms:Verify"
  ]

  base_tags = merge({
    "Name"        = var.alias_name
    "app"         = "policy-core"
    "module"      = "kms"
    "managed-by"  = "terraform"
    "environment" = var.environment
  }, var.tags)
}

########################
# Key policy (default)
########################
data "aws_iam_policy_document" "default" {
  statement {
    sid     = "EnableRootAccountAdmin"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.admin_arns) > 0 ? [1] : []
    content {
      sid     = "GrantAdministratorsFullControl"
      actions = ["kms:*"]
      principals {
        type        = "AWS"
        identifiers = var.admin_arns
      }
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = length(var.usage_arns) > 0 ? [1] : []
    content {
      sid     = "AllowUseOfKey"
      actions = local.use_actions
      principals {
        type        = "AWS"
        identifiers = var.usage_arns
      }
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.additional_policy_statements
    content {
      sid     = lookup(statement.value, "sid", null)
      actions = statement.value.actions
      principals {
        type        = "AWS"
        identifiers = statement.value.principals
      }
      resources = coalesce(statement.value.resources, ["*"])
      dynamic "condition" {
        for_each = lookup(statement.value, "conditions", {})
        content {
          test     = condition.key
          variable = keys(condition.value)[0]
          values   = values(condition.value)[0]
        }
      }
    }
  }
}

########################
# KMS Key + Alias
########################
resource "aws_kms_key" "this" {
  description             = var.description != null ? var.description : "policy-core primary KMS key"
  policy                  = coalesce(var.key_policy_json, data.aws_iam_policy_document.default.json)
  key_usage               = var.key_usage
  key_spec                = var.key_spec
  origin                  = var.origin
  multi_region            = var.multi_region && local.multi_region_supported
  is_enabled              = var.is_enabled
  enable_key_rotation     = var.enable_rotation && local.rotation_supported
  deletion_window_in_days = var.deletion_window_in_days
  tags                    = local.base_tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.alias_name}"
  target_key_id = aws_kms_key.this.key_id
}

########################
# Optional replica key (multi-region)
# Требуется провайдер-алиас aws.replica, переданный из корневого модуля.
########################
resource "aws_kms_replica_key" "replica" {
  count             = var.enable_replica && local.multi_region_supported ? 1 : 0
  provider          = aws.replica
  primary_key_arn   = aws_kms_key.this.arn
  description       = coalesce(var.replica_description, "${var.alias_name} (replica)")
  policy            = coalesce(var.key_policy_json, data.aws_iam_policy_document.default.json)
  bypass_policy_lockout_safety_check = false
  tags              = local.base_tags
}

########################
# KMS Grants (fine-grained)
########################
resource "aws_kms_grant" "this" {
  for_each = { for idx, g in var.grants : coalesce(g.name, "grant-${idx}") => g }

  name               = each.key
  key_id             = aws_kms_key.this.key_id
  grantee_principal  = each.value.grantee_principal
  operations         = each.value.operations
  retiring_principal = try(each.value.retiring_principal, null)
  grant_creation_tokens = try(each.value.grant_tokens, null)

  dynamic "constraints" {
    for_each = try(each.value.constraints != null, false) ? [each.value.constraints] : []
    content {
      encryption_context_equals = try(constraints.value.encryption_context_equals, null)
      encryption_context_subset = try(constraints.value.encryption_context_subset, null)
    }
  }
}

########################
# Variables (self-contained module)
########################
variable "alias_name" {
  type        = string
  default     = "policy-core"
  description = "KMS alias (без префикса alias/)."
}

variable "description" {
  type        = string
  default     = null
  description = "Описание ключа."
}

variable "environment" {
  type        = string
  default     = "prod"
  description = "Метка окружения."
}

variable "key_spec" {
  type        = string
  default     = "SYMMETRIC_DEFAULT"
  description = "Спецификация ключа: SYMMETRIC_DEFAULT | RSA_2048 | RSA_3072 | RSA_4096 | ECC_NIST_P256 | ECC_NIST_P384 | ECC_NIST_P521 | ECC_SECG_P256K1."
  validation {
    condition     = contains(["SYMMETRIC_DEFAULT","RSA_2048","RSA_3072","RSA_4096","ECC_NIST_P256","ECC_NIST_P384","ECC_NIST_P521","ECC_SECG_P256K1"], var.key_spec)
    error_message = "Недопустимый key_spec."
  }
}

variable "key_usage" {
  type        = string
  default     = "ENCRYPT_DECRYPT"
  description = "Назначение ключа: ENCRYPT_DECRYPT (симметричный) или SIGN_VERIFY (асимметричный)."
  validation {
    condition     = contains(["ENCRYPT_DECRYPT","SIGN_VERIFY"], var.key_usage)
    error_message = "Недопустимый key_usage."
  }
}

variable "origin" {
  type        = string
  default     = "AWS_KMS"
  description = "Источник ключевого материала: AWS_KMS или EXTERNAL."
  validation {
    condition     = contains(["AWS_KMS","EXTERNAL"], var.origin)
    error_message = "Недопустимый origin."
  }
}

variable "multi_region" {
  type        = bool
  default     = true
  description = "Создавать Multi-Region ключ (только для origin=AWS_KMS)."
}

variable "is_enabled" {
  type        = bool
  default     = true
  description = "Включить ключ."
}

variable "enable_rotation" {
  type        = bool
  default     = true
  description = "Включить ежегодную ротацию (только SYMMETRIC_DEFAULT)."
}

variable "deletion_window_in_days" {
  type        = number
  default     = 30
  description = "Окно удаления ключа (7–30)."
  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days должен быть в диапазоне 7–30."
  }
}

variable "admin_arns" {
  type        = list(string)
  default     = []
  description = "Администраторы ключа (полный доступ kms:*)."
}

variable "usage_arns" {
  type        = list(string)
  default     = []
  description = "Субъекты, которым разрешено использование ключа (Encrypt/Decrypt или Sign/Verify)."
}

variable "additional_policy_statements" {
  description = "Дополнительные statements для политики ключа."
  type = list(object({
    sid        = optional(string)
    actions    = list(string)
    principals = list(string)
    resources  = optional(list(string))
    conditions = optional(map(map(list(string))))
  }))
  default = []
}

variable "key_policy_json" {
  type        = string
  default     = null
  description = "Готовая JSON-политика (переопределяет default)."
}

variable "enable_replica" {
  type        = bool
  default     = false
  description = "Создавать реплику ключа в другом регионе (требует провайдера aws.replica)."
}

variable "replica_description" {
  type        = string
  default     = null
  description = "Описание для реплики."
}

variable "grants" {
  description = "Гранты KMS (тонкая делегация прав)."
  type = list(object({
    name               = optional(string)
    grantee_principal  = string
    operations         = list(string)
    retiring_principal = optional(string)
    grant_tokens       = optional(list(string))
    constraints = optional(object({
      encryption_context_equals = optional(map(string))
      encryption_context_subset = optional(map(string))
    }))
  }))
  default = []
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Дополнительные теги."
}

########################
# Outputs
########################
output "key_id" {
  value       = aws_kms_key.this.key_id
  description = "ID KMS ключа."
}

output "key_arn" {
  value       = aws_kms_key.this.arn
  description = "ARN основного KMS ключа."
}

output "alias_name" {
  value       = aws_kms_alias.this.name
  description = "Имя alias."
}

output "alias_arn" {
  value       = aws_kms_alias.this.arn
  description = "ARN alias."
}

output "replica_key_arn" {
  value       = try(aws_kms_replica_key.replica[0].arn, null)
  description = "ARN реплики ключа (если создана)."
}
