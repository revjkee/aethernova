terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

############################
# Data & Locals
############################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  # Нормализованные теги
  tags = merge(
    {
      "ManagedBy" = "Terraform"
      "Module"    = "oblivionvault-core/kms"
      "Owner"     = coalesce(var.owner, "unknown")
      "Env"       = var.environment
      "Name"      = var.name
    },
    var.tags
  )

  # Сервисы, которым можно разрешить использование ключа через kms:ViaService
  # Ключ: доменное имя сервиса; Значение: true/false (включить/исключить)
  service_via = merge({
    "s3.${data.aws_region.current.name}.amazonaws.com"              = true
    "ec2.${data.aws_region.current.name}.amazonaws.com"             = true   # EBS
    "rds.${data.aws_region.current.name}.amazonaws.com"             = true
    "logs.${data.aws_region.current.name}.amazonaws.com"            = true   # CloudWatch Logs
    "secretsmanager.${data.aws_region.current.name}.amazonaws.com"  = true
    "lambda.${data.aws_region.current.name}.amazonaws.com"          = true
    "dynamodb.${data.aws_region.current.name}.amazonaws.com"        = false
    "eks.${data.aws_region.current.name}.amazonaws.com"             = false
    "glue.${data.aws_region.current.name}.amazonaws.com"            = false
  }, var.service_via)

  # Собираем массив ViaService из включенных сервисов
  via_services = [for k, v in local.service_via : k if v]

  # Policy override или генерируемая политика по принципу наименьших привилегий
  base_policy = {
    Version   = "2012-10-17"
    Statement = concat(
      [
        # 0) Гарантированный FullAccess для владельца аккаунта (root) — операционная страховка
        {
          Sid      = "AllowRootAccountFullAccess"
          Effect   = "Allow"
          Principal = {
            AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
          }
          Action   = "kms:*"
          Resource = "*"
        },

        # 1) Администрирование ключа (но без data‑операций) — var.admins
        {
          Sid      = "AllowKeyAdministrators"
          Effect   = length(var.admins) > 0 ? "Allow" : "Deny"
          Principal = {
            AWS = var.admins
          }
          Action = [
            "kms:Create*",
            "kms:Describe*",
            "kms:Enable*",
            "kms:List*",
            "kms:Put*",
            "kms:Update*",
            "kms:Revoke*",
            "kms:Disable*",
            "kms:Get*",
            "kms:Delete*",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion"
          ]
          Resource = "*"
        },

        # 2) Право шифрования (encrypt only) — var.write_principals
        {
          Sid      = "AllowEncryptAndGenerateDataKey"
          Effect   = length(var.write_principals) > 0 ? "Allow" : "Deny"
          Principal = {
            AWS = var.write_principals
          }
          Action = [
            "kms:Encrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:DescribeKey"
          ]
          Resource = "*"
          Condition = length(local.via_services) > 0 ? {
            "StringEquals" = {
              "kms:ViaService" = local.via_services
            }
          } : null
        },

        # 3) Право расшифровки (decrypt) — var.read_principals
        {
          Sid      = "AllowDecrypt"
          Effect   = length(var.read_principals) > 0 ? "Allow" : "Deny"
          Principal = {
            AWS = var.read_principals
          }
          Action = [
            "kms:Decrypt",
            "kms:DescribeKey"
          ]
          Resource = "*"
          Condition = length(local.via_services) > 0 ? {
            "StringEquals" = {
              "kms:ViaService" = local.via_services
            }
          } : null
        }
      ],

      # 4) Дополнительные произвольные statements пользователя (при необходимости)
      var.additional_statements
    )
  }

  rendered_policy = var.policy_json != null && trim(var.policy_json) != "" ?
    var.policy_json :
    jsonencode(local.base_policy)
}

############################
# KMS Key
############################

resource "aws_kms_key" "this" {
  description                        = var.description
  enable_key_rotation                = var.enable_key_rotation
  is_enabled                         = var.is_enabled
  deletion_window_in_days            = var.deletion_window_in_days
  multi_region                       = var.multi_region
  customer_master_key_spec           = var.key_spec
  key_usage                          = var.key_usage
  bypass_policy_lockout_safety_check = var.bypass_policy_lockout_safety_check

  # Политика ключа (policy)
  policy = local.rendered_policy

  tags = local.tags
}

############################
# Aliases (множественные)
############################

resource "aws_kms_alias" "aliases" {
  for_each      = toset(var.aliases)
  name          = "alias/${each.value}"
  target_key_id = aws_kms_key.this.key_id
}

############################
# Гранты (опционально)
############################
# Гранты полезны, когда нужно дать сервису или роли доступ к подмножеству операций
# без изменения key policy (например, временно или под конкретный реципиент).

resource "aws_kms_grant" "grants" {
  for_each          = { for g in var.grants : g.name => g }
  name              = each.value.name
  key_id            = aws_kms_key.this.key_id
  grantee_principal = each.value.grantee_principal
  operations        = each.value.operations

  constraints {
    encryption_context_equals = lookup(each.value.constraints, "encryption_context_equals", null)
    encryption_context_subset = lookup(each.value.constraints, "encryption_context_subset", null)
  }

  retiring_principal = lookup(each.value, "retiring_principal", null)
}

############################
# Outputs
############################

output "key_id" {
  description = "KMS Key ID"
  value       = aws_kms_key.this.key_id
}

output "key_arn" {
  description = "KMS Key ARN"
  value       = aws_kms_key.this.arn
}

output "alias_arns" {
  description = "ARNs of created aliases"
  value       = [for a in aws_kms_alias.aliases : a.arn]
}

output "policy_effective_json" {
  description = "Effective key policy JSON (rendered)"
  value       = local.rendered_policy
}

############################
# Variables
############################

variable "name" {
  description = "Логическое имя ключа (используется в тегах и алиасах)."
  type        = string
}

variable "description" {
  description = "Описание KMS‑ключа."
  type        = string
  default     = "OblivionVault KMS key"
}

variable "environment" {
  description = "Окружение (prod|stage|dev|...); попадёт в теги."
  type        = string
  default     = "prod"
}

variable "owner" {
  description = "Владелец (для тега Owner)."
  type        = string
  default     = null
}

variable "tags" {
  description = "Дополнительные теги."
  type        = map(string)
  default     = {}
}

variable "deletion_window_in_days" {
  description = "Окно ожидания удаления ключа (7..30)."
  type        = number
  default     = 30
  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days должен быть в диапазоне 7..30."
  }
}

variable "enable_key_rotation" {
  description = "Включить годовую ротацию ключа."
  type        = bool
  default     = true
}

variable "is_enabled" {
  description = "Включить ключ (true) или создать в выключенном состоянии (false)."
  type        = bool
  default     = true
}

variable "multi_region" {
  description = "Создать много региональный ключ (Multi-Region Primary)."
  type        = bool
  default     = false
}

variable "key_spec" {
  description = "Тип ключа: SYMMETRIC_DEFAULT | RSA_2048 | RSA_3072 | RSA_4096 | ECC_NIST_P256 | ECC_NIST_P384 | ECC_NIST_P521 | ECC_SECG_P256K1 | HMAC_224 | HMAC_256 | HMAC_384 | HMAC_512."
  type        = string
  default     = "SYMMETRIC_DEFAULT"
}

variable "key_usage" {
  description = "Назначение ключа: ENCRYPT_DECRYPT | SIGN_VERIFY | GENERATE_VERIFY_MAC."
  type        = string
  default     = "ENCRYPT_DECRYPT"
}

variable "bypass_policy_lockout_safety_check" {
  description = "Разрешить создание политики, которая может лишить доступа (использовать с осторожностью)."
  type        = bool
  default     = false
}

variable "aliases" {
  description = "Список алиасов без префикса alias/ (например, [\"oblivionvault\", \"oblivionvault-${var.environment}\"])."
  type        = list(string)
  default     = []
}

variable "admins" {
  description = "Список ARNs IAM‑пользователей/ролей с административным доступом к ключу (без data‑операций)."
  type        = list(string)
  default     = []
}

variable "write_principals" {
  description = "Список ARNs, которым разрешено Encrypt/ReEncrypt/GenerateDataKey."
  type        = list(string)
  default     = []
}

variable "read_principals" {
  description = "Список ARNs, которым разрешено Decrypt."
  type        = list(string)
  default     = []
}

variable "service_via" {
  description = "Карта сервисов для условия kms:ViaService (включение true/false). Ключ — FQDN сервиса."
  type        = map(bool)
  default     = {}
}

variable "additional_statements" {
  description = "Дополнительные JSON‑стейтменты политики (массив любых валидных Statement)."
  type        = list(any)
  default     = []
}

variable "policy_json" {
  description = "Полный override политики в виде JSON‑строки. Если задан, замещает генерируемую."
  type        = string
  default     = null
}

variable "grants" {
  description = <<-EOT
    Список грантов.
    Пример:
    [
      {
        name               = "grant-app1"
        grantee_principal  = "arn:aws:iam::111122223333:role/app1"
        operations         = ["Encrypt","Decrypt","GenerateDataKey"]
        constraints = {
          encryption_context_equals = { "app" = "app1" }
        }
        retiring_principal = "arn:aws:iam::111122223333:role/security-admins"
      }
    ]
  EOT
  type = list(object({
    name               = string
    grantee_principal  = string
    operations         = list(string)
    constraints = optional(object({
      encryption_context_equals = optional(map(string))
      encryption_context_subset = optional(map(string))
    }), {})
    retiring_principal = optional(string)
  }))
  default = []
}
