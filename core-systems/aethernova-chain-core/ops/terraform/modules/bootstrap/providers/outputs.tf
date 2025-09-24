###############################################################################
# Providers — Outputs (AWS)
#
# Ожидаемые data-источники внутри МОДУЛЯ:
#   data "aws_partition" "current" {}
#   data "aws_region" "current" {}
#   data "aws_caller_identity" "current" {}
#   data "aws_availability_zones" "available" { state = "available" }
#
# Ожидаемые переменные:
#   variable "region" { type = string }
#   variable "tags"   { type = map(string) }
#
# Назначение:
#   - Стандартизированные выходы о провайдере/окружении для использования другими модулями.
#   - Агрегированные структуры и JSON для автоматизации (CI/CD, шаблоны ARN/эндпоинтов).
###############################################################################

########################
# Partition / DNS suffix
########################
output "aws_partition_id" {
  description = "Идентификатор partition (aws / aws-us-gov / aws-cn)."
  value       = data.aws_partition.current.partition
}

output "aws_dns_suffix" {
  description = "Основной DNS-суффикс partition (например, amazonaws.com)."
  value       = data.aws_partition.current.dns_suffix
}

output "aws_dualstack_dns_suffix" {
  description = "Dualstack DNS-суффикс partition."
  value       = data.aws_partition.current.dualstack_dns_suffix
}

output "aws_iam_partition" {
  description = "IAM partition (например, aws)."
  value       = data.aws_partition.current.partition
}

output "partition_descriptor" {
  description = "Сводная информация о partition и DNS-суффиксах."
  value = {
    id                    = data.aws_partition.current.partition
    dns_suffix            = data.aws_partition.current.dns_suffix
    dualstack_dns_suffix  = data.aws_partition.current.dualstack_dns_suffix
  }
}

##########
# Регион
##########
output "region_name" {
  description = "Имя региона (например, eu-central-1)."
  value       = data.aws_region.current.name
}

output "region_description" {
  description = "Описание региона, если доступно (может быть пустым)."
  value       = try(data.aws_region.current.description, null)
}

output "region_descriptor" {
  description = "Сводная информация о регионе."
  value = {
    name        = data.aws_region.current.name
    description = try(data.aws_region.current.description, null)
    input       = var.region
  }
}

#############################
# Аккаунт / вызывающая сущность
#############################
output "account_id" {
  description = "AWS Account ID (12-значный)."
  value       = data.aws_caller_identity.current.account_id
}

output "caller_arn" {
  description = "ARN текущего вызывающего субъекта (User/Role)."
  value       = data.aws_caller_identity.current.arn
}

output "caller_user_id" {
  description = "User ID текущего вызывающего субъекта."
  value       = data.aws_caller_identity.current.user_id
}

output "identity_descriptor" {
  description = "Сводная информация об аккаунте и вызывающей сущности."
  value = {
    account_id   = data.aws_caller_identity.current.account_id
    caller_arn   = data.aws_caller_identity.current.arn
    caller_uid   = data.aws_caller_identity.current.user_id
    partition    = data.aws_partition.current.partition
    region       = data.aws_region.current.name
  }
}

#########################
# Доступные зоны (AZ)
#########################
output "availability_zones" {
  description = "Список доступных Availability Zones (только state=available)."
  value       = data.aws_availability_zones.available.names
}

output "availability_zone_ids" {
  description = "Список идентификаторов AZ (если поддерживается провайдером)."
  value       = try(data.aws_availability_zones.available.zone_ids, [])
}

output "az_count" {
  description = "Количество доступных AZ."
  value       = length(data.aws_availability_zones.available.names)
}

output "az_descriptor" {
  description = "Сводная информация по AZ."
  value = {
    count   = length(data.aws_availability_zones.available.names)
    names   = data.aws_availability_zones.available.names
    zone_ids= try(data.aws_availability_zones.available.zone_ids, [])
  }
}

#########################
# Теги модуля (сквозные)
#########################
output "tags_effective" {
  description = "Итоговые теги, которыми должен помечаться ресурсный слой."
  value       = var.tags
}

#########################
# Эндпоинты (шаблоны)
#########################
# Примечание: это вычисляемые шаблоны на основе partition/region.
# Особые кейсы (например, s3 без region в некоторых partition) следует,
# при необходимости, обрабатывать во внешней логике.
output "service_endpoints" {
  description = "Базовые шаблоны эндпоинтов ключевых сервисов в регионе."
  value = {
    s3         = "s3.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
    dynamodb   = "dynamodb.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
    sts        = "sts.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
    ecr_api    = "api.ecr.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
    ecr_dkr    = "${data.aws_region.current.name}.dkr.ecr.${data.aws_partition.current.dns_suffix}"
    ec2        = "ec2.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
    logs       = "logs.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
    events     = "events.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
    kms        = "kms.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
  }
}

############################
# Агрегированные структуры
############################
output "providers_descriptor" {
  description = "Сводное описание окружения провайдера для повторного использования."
  value = {
    partition = {
      id                   = data.aws_partition.current.partition
      dns_suffix           = data.aws_partition.current.dns_suffix
      dualstack_dns_suffix = data.aws_partition.current.dualstack_dns_suffix
    }
    region = {
      name        = data.aws_region.current.name
      description = try(data.aws_region.current.description, null)
      input       = var.region
    }
    identity = {
      account_id = data.aws_caller_identity.current.account_id
      caller_arn = data.aws_caller_identity.current.arn
      caller_uid = data.aws_caller_identity.current.user_id
    }
    az = {
      count   = length(data.aws_availability_zones.available.names)
      names   = data.aws_availability_zones.available.names
      zone_ids= try(data.aws_availability_zones.available.zone_ids, [])
    }
    tags      = var.tags
    endpoints = {
      s3       = "s3.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      dynamodb = "dynamodb.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      sts      = "sts.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      ecr_api  = "api.ecr.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      ecr_dkr  = "${data.aws_region.current.name}.dkr.ecr.${data.aws_partition.current.dns_suffix}"
      ec2      = "ec2.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      logs     = "logs.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      events   = "events.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      kms      = "kms.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
    }
  }
}

output "providers_descriptor_json" {
  description = "JSON-представление сводного описания окружения."
  value = jsonencode({
    partition = {
      id                   = data.aws_partition.current.partition
      dns_suffix           = data.aws_partition.current.dns_suffix
      dualstack_dns_suffix = data.aws_partition.current.dualstack_dns_suffix
    }
    region = {
      name        = data.aws_region.current.name
      description = try(data.aws_region.current.description, null)
      input       = var.region
    }
    identity = {
      account_id = data.aws_caller_identity.current.account_id
      caller_arn = data.aws_caller_identity.current.arn
      caller_uid = data.aws_caller_identity.current.user_id
    }
    az = {
      count    = length(data.aws_availability_zones.available.names)
      names    = data.aws_availability_zones.available.names
      zone_ids = try(data.aws_availability_zones.available.zone_ids, [])
    }
    tags = var.tags
    endpoints = {
      s3       = "s3.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      dynamodb = "dynamodb.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      sts      = "sts.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      ecr_api  = "api.ecr.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      ecr_dkr  = "${data.aws_region.current.name}.dkr.ecr.${data.aws_partition.current.dns_suffix}"
      ec2      = "ec2.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      logs     = "logs.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      events   = "events.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
      kms      = "kms.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
    }
  })
}

##############################################
# Подсказки (человекочитаемые) для README/CI
##############################################
output "cli_hints" {
  description = "Подсказки по использованию выходов модуля в CLI/CI."
  value = <<EOT
Примеры использования:
- Получить Account ID:          terraform output -raw account_id
- Получить имя региона:         terraform output -raw region_name
- Список AZ (JSON):             terraform output availability_zones
- Сводка провайдера (JSON):     terraform output -raw providers_descriptor_json

Рекомендуется передавать tags_effective всем ресурсным модулям для единообразной маркировки.
EOT
}
