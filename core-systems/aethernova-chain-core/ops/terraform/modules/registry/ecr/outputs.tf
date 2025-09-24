############################################################
# aethernova-chain-core/ops/terraform/modules/registry/ecr/outputs.tf
#
# ВНИМАНИЕ:
# Предполагается, что в модуле существуют ресурсы:
#   - aws_ecr_repository.this
#   - aws_ecr_lifecycle_policy.this            (optional, count=0/1)
#   - aws_ecr_repository_policy.this           (optional, count=0/1)
#   - aws_ecr_replication_configuration.this   (optional, count=0/1)
#   - aws_ecr_registry_scanning_configuration.this (optional, count=0/1)
# Если имена у вас иные — переименуйте ссылки ниже.
############################################################

# Базовые атрибуты ECR-репозитория (ARN, имя, URL, ID реестра)
output "repository_arn" {
  description = "Полный ARN репозитория ECR."
  value       = aws_ecr_repository.this.arn
}

output "repository_name" {
  description = "Имя репозитория ECR."
  value       = aws_ecr_repository.this.name
}

output "repository_url" {
  description = "Полный URL репозитория вида <account>.dkr.ecr.<region>.amazonaws.com/<repo>."
  value       = aws_ecr_repository.this.repository_url
}

output "registry_id" {
  description = "ID реестра, в котором создан репозиторий."
  value       = aws_ecr_repository.this.registry_id
}

# Удобный endpoint реестра для docker login (часть до имени репозитория)
output "registry_endpoint" {
  description = "Endpoint приватного реестра (без имени репозитория), пригоден для docker login."
  value       = element(split("/", aws_ecr_repository.this.repository_url), 0)
}

# Параметры шифрования и сканирования на push (если включено на уровне репозитория)
output "encryption" {
  description = "Конфигурация шифрования образов в репозитории (тип и KMS ключ, если задан)."
  value = {
    encryption_type = try(aws_ecr_repository.this.encryption_configuration[0].encryption_type, "AES256")
    kms_key_arn     = try(aws_ecr_repository.this.encryption_configuration[0].kms_key, null)
  }
}

output "image_scanning_on_push" {
  description = "Признак включения сканирования образов при push на уровне репозитория."
  value       = try(aws_ecr_repository.this.image_scanning_configuration[0].scan_on_push, null)
}

# Lifecycle Policy (если задана в модуле)
output "lifecycle_policy" {
  description = "Идентификатор и репозиторий для применённой Lifecycle Policy (если задана)."
  value = try({
    id         = aws_ecr_lifecycle_policy.this[0].id
    repository = aws_ecr_lifecycle_policy.this[0].repository
  }, null)
}

# Repository Policy (как есть JSON; помечаем чувствительным)
output "repository_policy_json" {
  description = "JSON политики репозитория ECR (если задана). Содержит чувствительные детали прав доступа."
  value       = try(aws_ecr_repository_policy.this[0].policy, null)
  sensitive   = true
}

# Репликация между реестрами (если настроена)
output "replication" {
  description = "Сводная информация о конфигурации репликации (целевые регионы/реестры), если включена."
  value = try({
    registry_id  = aws_ecr_replication_configuration.this.registry_id
    destinations = [
      for r in aws_ecr_replication_configuration.this.replication_configuration[0].rule :
      {
        region      = try(r.destination[0].region, null)
        registry_id = try(r.destination[0].registry_id, null)
      }
    ]
  }, null)
}

# Сканирование на уровне реестра (Registry Scanning Configuration), если включено
output "registry_scanning" {
  description = "Конфигурация сканирования на уровне реестра: тип сканирования и число правил (если задано)."
  value = try({
    registry_id = aws_ecr_registry_scanning_configuration.this.registry_id
    scan_type   = aws_ecr_registry_scanning_configuration.this.scan_type
    rules_count = length(aws_ecr_registry_scanning_configuration.this.rule)
  }, null)
}

# Компактный агрегированный объект
output "ecr" {
  description = "Агрегированный объект со всеми ключевыми параметрами ECR-репозитория для межмодульной интеграции."
  value = {
    arn                = aws_ecr_repository.this.arn
    name               = aws_ecr_repository.this.name
    repository_url     = aws_ecr_repository.this.repository_url
    registry_endpoint  = element(split("/", aws_ecr_repository.this.repository_url), 0)
    registry_id        = aws_ecr_repository.this.registry_id
    encryption_type    = try(aws_ecr_repository.this.encryption_configuration[0].encryption_type, "AES256")
    kms_key_arn        = try(aws_ecr_repository.this.encryption_configuration[0].kms_key, null)
    scan_on_push       = try(aws_ecr_repository.this.image_scanning_configuration[0].scan_on_push, null)
    lifecycle_policy   = try(aws_ecr_lifecycle_policy.this[0].id, null)
    replication        = try({
      registry_id  = aws_ecr_replication_configuration.this.registry_id
      destinations = [
        for r in aws_ecr_replication_configuration.this.replication_configuration[0].rule :
        {
          region      = try(r.destination[0].region, null)
          registry_id = try(r.destination[0].registry_id, null)
        }
      ]
    }, null)
    registry_scanning  = try({
      scan_type   = aws_ecr_registry_scanning_configuration.this.scan_type
      rules_count = length(aws_ecr_registry_scanning_configuration.this.rule)
    }, null)
  }
}
