############################################################
# Path: ops/terraform/modules/security/kms-keys/outputs.tf
# Purpose: Production-grade outputs for AWS KMS keys module
#
# Verified references (официальные источники):
# - aws_kms_key exports: arn, key_id
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key  # arn, key_id
# - aws_kms_alias exports: arn, name
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias # arn, name
#
# Предпосылки:
# - Внутри модуля существуют ресурсы:
#     resource "aws_kms_key"   "this"  { for_each = var.keys ... }
#     resource "aws_kms_alias" "this"  { for_each = var.aliases ... }
#   где ключи for_each — это логические имена (например, "s3", "ebs", "rds").
# - Если ваши имена ресурсов отличаются, скорректируйте адреса в выражениях ниже.
############################################################

############################
# KMS Keys (maps by logical name)
############################

# Карта: <logical_key_name> -> KMS Key ARN
output "kms_key_arns" {
  description = "Map of logical key names to AWS KMS Key ARNs."
  value       = { for k, r in aws_kms_key.this : k => r.arn }
  # См. официальную документацию по атрибутам aws_kms_key (arn):
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key
}

# Карта: <logical_key_name> -> KMS Key ID (UUID)
output "kms_key_ids" {
  description = "Map of logical key names to AWS KMS Key IDs (UUID)."
  value       = { for k, r in aws_kms_key.this : k => r.key_id }
  # Атрибут key_id подтвержден документацией aws_kms_key:
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key
}

# Карта: <logical_key_name> -> минимальный профиль ключа (ARN + Key ID)
output "kms_keys_compact" {
  description = "Compact profile per KMS key: ARN and Key ID."
  value = {
    for k, r in aws_kms_key.this :
    k => {
      arn    = r.arn
      key_id = r.key_id
    }
  }
}

############################
# KMS Aliases (maps by alias resource key)
############################

# Карта: <alias_resource_key> -> Alias ARN
output "kms_alias_arns" {
  description = "Map of alias resource keys to AWS KMS Alias ARNs."
  value       = { for a, r in aws_kms_alias.this : a => r.arn }
  # Экспортируемый атрибут arn подтвержден документацией aws_kms_alias:
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias
}

# Карта: <alias_resource_key> -> Alias name (например, 'alias/my-key')
output "kms_alias_names" {
  description = "Map of alias resource keys to alias names (e.g., 'alias/my-key')."
  value       = { for a, r in aws_kms_alias.this : a => r.name }
  # Экспортируемый атрибут name подтвержден документацией aws_kms_alias:
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias
}

############################
# JSON для межмодульной интеграции
############################

# Единый JSON-объект, удобный для передачи в другие модули и системы.
output "kms_inventory_json" {
  description = "JSON inventory of keys and aliases for programmatic consumption."
  value = jsonencode({
    keys = {
      for k, r in aws_kms_key.this :
      k => {
        arn    = r.arn
        key_id = r.key_id
      }
    }
    aliases = {
      for a, r in aws_kms_alias.this :
      a => {
        arn  = r.arn
        name = r.name
      }
    }
  })
  sensitive = false
}

############################
# Удобные выборки (flattened)
############################

# Отсортированный список всех Key ARNs (для модулей, ожидающих list(string))
output "all_key_arns" {
  description = "Sorted list of all KMS Key ARNs."
  value       = sort([for r in aws_kms_key.this : r.arn])
}

# Отсортированный список всех Alias ARNs
output "all_alias_arns" {
  description = "Sorted list of all KMS Alias ARNs."
  value       = sort([for r in aws_kms_alias.this : r.arn])
}

# Отсортированный список всех Alias names (e.g., alias/s3, alias/ebs)
output "all_alias_names" {
  description = "Sorted list of all alias names."
  value       = sort([for r in aws_kms_alias.this : r.name])
}
