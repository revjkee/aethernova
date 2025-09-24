###############################################
# modules/security/secret-manager/outputs.tf  #
# Industrial-grade, multi-cloud safe outputs  #
# SOURCES:
# - AWS Secrets Manager:
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_version
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_rotation
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_policy
# - Azure Key Vault / Secrets:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret
# - Google Secret Manager:
#   https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/secret_manager_secret
#   https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/secret_manager_secret_version
###############################################

############################
# Универсальные выходы    #
############################

# Какой провайдер(ы) активен(ы) в модуле (ожидается, что переменные заданы в variables.tf)
output "clouds_enabled" {
  description = "Список активных облачных провайдеров, например [\"aws\"], [\"azure\"], [\"gcp\"], либо их комбинации."
  value = compact([
    try(var.enable_aws ? "aws" : "", ""),
    try(var.enable_azure ? "azure" : "", ""),
    try(var.enable_gcp ? "gcp" : "", "")
  ])
}

# Унифицированные имена секретов (если в модуле введён единый map секретов userspace_name => конфиг)
# Здесь предполагается, что секреты создавались с ключами var.secrets (map).
output "requested_secret_keys" {
  description = "Ключи (user-facing имена) секретов, которые модуль пытался создать/управлять."
  value       = try(keys(var.secrets), [])
}

############################################
# AWS Secrets Manager (карты по множеству) #
############################################

# Идентификаторы секретов AWS по ключу (если создавались с for_each)
output "aws_secret_ids" {
  description = "Map: <key> => AWS Secrets Manager secret id."
  value = try({
    for k, s in aws_secretsmanager_secret.this : k => s.id
  }, {})
}

# ARNs секретов AWS
output "aws_secret_arns" {
  description = "Map: <key> => AWS Secrets Manager secret ARN."
  value = try({
    for k, s in aws_secretsmanager_secret.this : k => s.arn
  }, {})
}

# Имена секретов AWS
output "aws_secret_names" {
  description = "Map: <key> => имя секрета в AWS Secrets Manager."
  value = try({
    for k, s in aws_secretsmanager_secret.this : k => s.name
  }, {})
}

# KMS ключи, если секреты шифруются пользовательским KMS
output "aws_secret_kms_keys" {
  description = "Map: <key> => kms_key_id, если задан при создании секрета."
  value = try({
    for k, s in aws_secretsmanager_secret.this : k => try(s.kms_key_id, null)
  }, {})
}

# Текущие версии секретов (если модуль публикует значения через aws_secretsmanager_secret_version.this)
output "aws_secret_version_ids" {
  description = "Map: <key> => текущий version_id секретной версии."
  value = try({
    for k, v in aws_secretsmanager_secret_version.this : k => try(v.version_id, null)
  }, {})
}

# Признак и параметры ротации (если используется aws_secretsmanager_secret_rotation.this)
output "aws_secret_rotation" {
  description = "Map: <key> => сведения о ротации (rotation_enabled, rotation_lambda_arn, rotation_rules)."
  value = try({
    for k, r in aws_secretsmanager_secret_rotation.this : k => {
      rotation_enabled   = true
      rotation_lambda_arn= try(r.rotation_lambda_arn, null)
      rotation_rules     = {
        automatically_after_days = try(r.rotation_rules[0].automatically_after_days, null)
        duration                  = try(r.rotation_rules[0].duration, null)
        schedule_expression       = try(r.rotation_rules[0].schedule_expression, null)
      }
    }
  }, {})
}

# Политики доступа к секретам (если применялся aws_secretsmanager_secret_policy.this)
output "aws_secret_policies" {
  description = "Map: <key> => применённая политика JSON (если задана)."
  value = try({
    for k, p in aws_secretsmanager_secret_policy.this : k => try(p.policy, null)
  }, {})
}

#######################################
# Azure Key Vault (хранилище и секреты)
#######################################

# Идентификатор Key Vault (если модуль создаёт KV)
output "azurerm_key_vault_id" {
  description = "ID созданного/подконтрольного Azure Key Vault (если создавался в модуле)."
  value       = try(azurerm_key_vault.this.id, null)
}

# Имя Key Vault
output "azurerm_key_vault_name" {
  description = "Имя Azure Key Vault (если создавался/использовался)."
  value       = try(azurerm_key_vault.this.name, null)
}

# URI Key Vault (vault_uri), необходим для SDK/CLI интеграций
output "azurerm_key_vault_uri" {
  description = "URI (vault_uri) Azure Key Vault."
  value       = try(azurerm_key_vault.this.vault_uri, null)
}

# Секреты Azure: id’ы по ключу (если с for_each)
output "azure_secret_ids" {
  description = "Map: <key> => ID секрета в Azure Key Vault."
  value = try({
    for k, s in azurerm_key_vault_secret.this : k => s.id
  }, {})
}

# Имена и версии секретов Azure
output "azure_secret_names" {
  description = "Map: <key> => имя секрета в Azure Key Vault."
  value = try({
    for k, s in azurerm_key_vault_secret.this : k => s.name
  }, {})
}

output "azure_secret_versions" {
  description = "Map: <key> => версия секрета в Azure Key Vault."
  value = try({
    for k, s in azurerm_key_vault_secret.this : k => try(s.version, null)
  }, {})
}

########################################
# Google Secret Manager (секреты/версии)
########################################

# Идентификаторы секретов GCP
output "gcp_secret_ids" {
  description = "Map: <key> => ID google_secret_manager_secret."
  value = try({
    for k, s in google_secret_manager_secret.this : k => s.id
  }, {})
}

# Имена ресурсов GCP (resource name)
output "gcp_secret_names" {
  description = "Map: <key> => имя ресурса секрета в Google Secret Manager."
  value = try({
    for k, s in google_secret_manager_secret.this : k => s.name
  }, {})
}

# KMS-ключи на уровне секрета GCP (если используется customer-managed encryption)
output "gcp_secret_kms_keys" {
  description = "Map: <key> => kms_key_name, если задан и поддерживается."
  value = try({
    for k, s in google_secret_manager_secret.this : k => try(s.kms_key_name, null)
  }, {})
}

# Текущие версии GCP (если модуль публикует значения через google_secret_manager_secret_version.this)
output "gcp_secret_version_ids" {
  description = "Map: <key> => ID версии секрета в Google Secret Manager."
  value = try({
    for k, v in google_secret_manager_secret_version.this : k => try(v.id, null)
  }, {})
}

########################################
# Унифицированные агрегаты по провайдерам
########################################

# Единая сводка по секретам: для автоматизации и внешних модулей
# Структура: <key> => { provider, id, name, arn/self_link, version, kms/keyvault info, uri }
output "secrets_summary" {
  description = "Единая сводка по всем секретам, созданным модулем, независимо от провайдера."
  value = merge(
    # AWS
    try({
      for k, s in aws_secretsmanager_secret.this : k => {
        provider = "aws"
        id       = try(s.id, null)
        name     = try(s.name, null)
        arn      = try(s.arn, null)
        version  = try(aws_secretsmanager_secret_version.this[k].version_id, null)
        kms_key  = try(s.kms_key_id, null)
        uri      = null
      }
    }, {}),
    # Azure
    try({
      for k, s in azurerm_key_vault_secret.this : k => {
        provider = "azure"
        id       = try(s.id, null)
        name     = try(s.name, null)
        arn      = null
        version  = try(s.version, null)
        kms_key  = try(azurerm_key_vault.this.id, null)
        uri      = try(azurerm_key_vault.this.vault_uri, null)
      }
    }, {}),
    # GCP
    try({
      for k, s in google_secret_manager_secret.this : k => {
        provider = "gcp"
        id       = try(s.id, null)
        name     = try(s.name, null)
        arn      = null
        version  = try(google_secret_manager_secret_version.this[k].id, null)
        kms_key  = try(s.kms_key_name, null)
        uri      = null
      }
    }, {})
  )
}

############################################
# Диагностика/отладка (не содержит секретов)
############################################

# Количество управляемых секретов по каждому провайдеру
output "counts_by_provider" {
  description = "Диагностический счётчик управляемых секретов по провайдерам."
  value = {
    aws   = try(length(aws_secretsmanager_secret.this), 0)
    azure = try(length(azurerm_key_vault_secret.this), 0)
    gcp   = try(length(google_secret_manager_secret.this), 0)
  }
}

# Состояние ротации по ключам AWS
output "aws_rotation_enabled_keys" {
  description = "Список ключей секретов AWS, для которых включена ротация."
  value = try([
    for k, _ in aws_secretsmanager_secret_rotation.this : k
  ], [])
}
