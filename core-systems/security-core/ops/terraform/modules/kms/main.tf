terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
}

############################
# Variables (with guards)  #
############################

variable "description" {
  type        = string
  default     = "security-core primary KMS key"
  description = "Человекочитаемое описание ключа."
}

variable "alias" {
  type        = string
  default     = "alias/security-core"
  description = "Имя alias. Можно передать без префикса alias/, он будет добавлен автоматически."
  validation {
    condition     = length(replace(var.alias, "alias/", "")) > 0
    error_message = "Alias не может быть пустым."
  }
}

variable "enable_key_rotation" {
  type        = bool
  default     = true
  description = "Включить автоматическую ротацию (только для SYMMETRIC_DEFAULT)."
}

variable "key_usage" {
  type        = string
  default     = "ENCRYPT_DECRYPT"
  description = "Назначение ключа."
  validation {
    condition     = contains(["ENCRYPT_DECRYPT", "SIGN_VERIFY"], var.key_usage)
    error_message = "key_usage должен быть ENCRYPT_DECRYPT или SIGN_VERIFY."
  }
}

variable "key_spec" {
  type        = string
  default     = "SYMMETRIC_DEFAULT"
  description = "Спецификация ключа."
  validation {
    condition = contains([
      "SYMMETRIC_DEFAULT",
      "RSA_2048", "RSA_3072", "RSA_4096",
      "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521",
      "ECC_SECG_P256K1", "HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512"
    ], var.key_spec)
    error_message = "Недопустимое значение key_spec."
  }
}

variable "origin" {
  type        = string
  default     = "AWS_KMS"
  description = "Источник ключевого материала: AWS_KMS | EXTERNAL | AWS_CLOUDHSM."
  validation {
    condition     = contains(["AWS_KMS", "EXTERNAL", "AWS_CLOUDHSM"], var.origin)
    error_message = "origin должен быть AWS_KMS, EXTERNAL или AWS_CLOUDHSM."
  }
}

variable "multi_region" {
  type        = bool
  default     = false
  description = "Создать Multi-Region ключ (MRK). Для AWS поддерживается преимущественно на SYMMETRIC_DEFAULT."
  validation {
    condition     = var.multi_region == false || var.key_spec == "SYMMETRIC_DEFAULT"
    error_message = "Multi-Region ключи поддерживаются только для SYMMETRIC_DEFAULT."
  }
}

variable "deletion_window_in_days" {
  type        = number
  default     = 30
  description = "Окно удаления (7–30 дней)."
  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days должен быть от 7 до 30."
  }
}

variable "is_enabled" {
  type        = bool
  default     = true
  description = "Включить ключ."
}

variable "policy_admin_arns" {
  type        = list(string)
  default     = []
  description = "Список ARN администраторов ключа (полный доступ kms:*)."
}

variable "policy_user_arns" {
  type        = list(string)
  default     = []
  description = "Список ARN пользователей ключа (encrypt/decrypt/generate/describe)."
}

variable "policy_service_principals" {
  type        = list(string)
  default     = []
  description = "Список сервисных принципалов (например, logs.amazonaws.com), которым разрешены базовые операции."
}

variable "allow_account_root_admin" {
  type        = bool
  default     = false
  description = "Добавить в политику стандартный блок Enable IAM User Permissions (root). Используйте осознанно."
}

variable "bypass_policy_lockout_safety_check" {
  type        = bool
  default     = false
  description = "Отключить защиту от lock-out при создании политики (не рекомендуется)."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Дополнительные теги."
}

# Опциональная реплика MRK (передайте провайдер alias aws.replica в родительском модуле)
variable "create_replica" {
  type        = bool
  default     = false
  description = "Создать мульти‑региональную реплику ключа (aws_kms_replica_key). Требует провайдера aws.replica."
}

variable "replica_alias_suffix" {
  type        = string
  default     = ""
  description = "Необязательный суффикс для alias в реплике, например '-eu'. Если пусто — используется тот же alias."
}

# Гранты на ключ (тонкая выдача прав на операции)
variable "grants" {
  type = list(object({
    name               = optional(string)
    grantee_principal  = string
    operations         = list(string) # например ["Encrypt","Decrypt","GenerateDataKey","DescribeKey"]
    constraints = optional(object({
      encryption_context_equals = optional(map(string))
      encryption_context_subset = optional(map(string))
    }))
    retiring_principal = optional(string)
  }))
  default     = []
  description = "Список грантов (kms grant) на ключ."
}

############################
# Data sources & locals    #
############################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  normalized_alias = startswith(var.alias, "alias/") ? var.alias : "alias/${var.alias}"

  default_tags = {
    Name        = "security-core-kms"
    Component   = "security-core"
    PartOf      = "core-systems"
    ManagedBy   = "terraform"
    Environment = coalesce(try(var.tags.Environment, null), "prod")
  }

  tags = merge(local.default_tags, var.tags)

  enable_rotation = var.enable_key_rotation && var.key_spec == "SYMMETRIC_DEFAULT"

  # Безопасность: требуем хотя бы одного админа или осознанно разрешённый root‑админ
  policy_admins_valid = length(var.policy_admin_arns) > 0 || var.allow_account_root_admin
}

############################
# IAM policy document      #
############################

# Блок Enable IAM User Permissions (по желанию)
data "aws_iam_policy_document" "enable_iam_user_permissions" {
  count = var.allow_account_root_admin ? 1 : 0

  statement {
    sid    = "EnableIamUserPermissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }
}

# Администраторы ключа (полный доступ)
data "aws_iam_policy_document" "admins" {
  count = length(var.policy_admin_arns) > 0 ? 1 : 0

  statement {
    sid    = "KeyAdmins"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = var.policy_admin_arns
    }

    actions = [
      "kms:*"
    ]

    resources = ["*"]
  }
}

# Пользователи ключа (минимально необходимые действия)
data "aws_iam_policy_document" "users" {
  count = length(var.policy_user_arns) > 0 ? 1 : 0

  statement {
    sid    = "KeyUsers"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = var.policy_user_arns
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]
  }
}

# Сервисные принципалы (например, logs.amazonaws.com) — только необходимые действия
data "aws_iam_policy_document" "services" {
  count = length(var.policy_service_principals) > 0 ? 1 : 0

  statement {
    sid    = "ServicePrincipals"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = var.policy_service_principals
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]
  }
}

# Компоновка итоговой политики
data "aws_iam_policy_document" "key_policy" {
  # Требование: не допустить пустую политику, которая приведёт к lock‑out
  dynamic "statement" {
    for_each = var.allow_account_root_admin ? [1] : []
    content {
      for_each = []
    }
  }

  source_policy_documents = compact([
    length(data.aws_iam_policy_document.admins) > 0 ? data.aws_iam_policy_document.admins[0].json : null,
    length(data.aws_iam_policy_document.users) > 0 ? data.aws_iam_policy_document.users[0].json : null,
    length(data.aws_iam_policy_document.services) > 0 ? data.aws_iam_policy_document.services[0].json : null,
    length(data.aws_iam_policy_document.enable_iam_user_permissions) > 0 ? data.aws_iam_policy_document.enable_iam_user_permissions[0].json : null
  ])
}

############################
# KMS Key & Alias          #
############################

resource "aws_kms_key" "this" {
  description                        = var.description
  key_usage                          = var.key_usage
  customer_master_key_spec           = var.key_spec
  deletion_window_in_days            = var.deletion_window_in_days
  enable_key_rotation                = local.enable_rotation
  is_enabled                         = var.is_enabled
  multi_region                       = var.multi_region
  origin                             = var.origin
  bypass_policy_lockout_safety_check = var.bypass_policy_lockout_safety_check

  # Защита от пустой политики
  policy = local.policy_admins_valid ? data.aws_iam_policy_document.key_policy.json : jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Sid       = "EmergencyRootAccess"
      Effect    = "Allow"
      Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })

  tags = local.tags
}

resource "aws_kms_alias" "this" {
  name          = local.normalized_alias
  target_key_id = aws_kms_key.this.key_id
}

############################
# Optional: MRK replica    #
############################

# В корневом модуле необходимо передать провайдер:
# providers = { aws = aws.primary, aws.replica = aws.replica }
resource "aws_kms_replica_key" "this" {
  count                             = var.create_replica ? 1 : 0
  provider                          = aws.replica
  description                       = "${var.description} (replica)"
  primary_key_arn                   = aws_kms_key.this.arn
  bypass_policy_lockout_safety_check = var.bypass_policy_lockout_safety_check
  deletion_window_in_days           = var.deletion_window_in_days
  enabled                           = var.is_enabled
  policy                            = aws_kms_key.this.policy
  tags                              = local.tags
}

resource "aws_kms_alias" "replica" {
  count         = var.create_replica ? 1 : 0
  provider      = aws.replica
  name          = var.replica_alias_suffix == "" ? local.normalized_alias : replace(local.normalized_alias, "/$", "") + var.replica_alias_suffix
  target_key_id = aws_kms_replica_key.this[0].key_id
}

############################
# KMS Grants               #
############################

resource "aws_kms_grant" "this" {
  for_each = { for g in var.grants : coalesce(try(g.name, null), sha1(join(",", concat([g.grantee_principal], g.operations)))) => g }

  name              = try(each.value.name, null)
  key_id            = aws_kms_key.this.key_id
  grantee_principal = each.value.grantee_principal
  operations        = each.value.operations

  dynamic "constraints" {
    for_each = try(each.value.constraints, null) == null ? [] : [each.value.constraints]
    content {
      encryption_context_equals = try(constraints.value.encryption_context_equals, null)
      encryption_context_subset = try(constraints.value.encryption_context_subset, null)
    }
  }

  retiring_principal = try(each.value.retiring_principal, null)
}

############################
# Outputs                  #
############################

output "key_id" {
  value       = aws_kms_key.this.key_id
  description = "ID KMS ключа."
}

output "key_arn" {
  value       = aws_kms_key.this.arn
  description = "ARN KMS ключа."
}

output "alias_name" {
  value       = aws_kms_alias.this.name
  description = "Имя alias."
}

output "rotation_enabled" {
  value       = aws_kms_key.this.enable_key_rotation
  description = "Флаг включенной ротации."
}

output "replica_key_arn" {
  value       = try(aws_kms_replica_key.this[0].arn, null)
  description = "ARN реплики MRK (если создана)."
}

output "policy_json" {
  value       = aws_kms_key.this.policy
  description = "Итоговая политика ключа."
  sensitive   = false
}
