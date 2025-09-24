#############################################
# chronowatch-core/ops/terraform/modules/redis_cache/main.tf
# Industrial-grade Redis (AWS ElastiCache) module
#############################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.1"
    }
  }
}

#########################
# Variables (module API)
#########################

variable "name_prefix" {
  description = "Префикс ресурса (будет использоваться в именах RG/SG/PG/Secrets)."
  type        = string
}

variable "vpc_id" {
  description = "ID VPC, где будет размещаться Redis."
  type        = string
}

variable "subnet_ids" {
  description = "Список приватных subnet'ов для Subnet Group."
  type        = list(string)
}

variable "existing_security_group_ids" {
  description = "Существующие SG для Redis. Если пусто — модуль создаст собственную SG."
  type        = list(string)
  default     = []
}

variable "allowed_cidr_blocks" {
  description = "CIDR источников, которым разрешён доступ к Redis (используется, если создаём SG)."
  type        = list(string)
  default     = []
}

variable "node_type" {
  description = "Класс инстанса (например, cache.t4g.small, cache.r6g.large)."
  type        = string
  default     = "cache.t4g.small"
}

variable "engine_version" {
  description = "Версия Redis в ElastiCache."
  type        = string
  default     = "7.1"
}

variable "port" {
  description = "Порт Redis."
  type        = number
  default     = 6379
}

variable "transit_encryption_enabled" {
  description = "Включить шифрование трафика (in-transit). Требует Redis AUTH токен."
  type        = bool
  default     = true
}

variable "at_rest_encryption_enabled" {
  description = "Включить шифрование на диске (at-rest)."
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "KMS Key ID для шифрования at-rest (если пусто — AWS managed key)."
  type        = string
  default     = null
}

variable "multi_az_enabled" {
  description = "Мульти-AZ для повышенной отказоустойчивости."
  type        = bool
  default     = true
}

variable "automatic_failover_enabled" {
  description = "Автоматический фейловер (требует как минимум 1 реплику)."
  type        = bool
  default     = true
}

variable "auto_minor_version_upgrade" {
  description = "Автоматические минорные обновления Redis."
  type        = bool
  default     = true
}

variable "maintenance_window" {
  description = "Окно обслуживания (например, mon:02:00-mon:03:00)."
  type        = string
  default     = "sun:02:00-sun:03:00"
}

variable "snapshot_window" {
  description = "Окно снапшота (например, 03:00-04:00)."
  type        = string
  default     = "03:00-04:00"
}

variable "snapshot_retention_limit" {
  description = "Сколько дней хранить снапшоты."
  type        = number
  default     = 7
}

variable "parameter_overrides" {
  description = "Карта параметров Redis (ключ=значение) для Parameter Group."
  type        = map(string)
  default     = {}
}

variable "cluster_mode_enabled" {
  description = "Включить Cluster Mode (шардирование)."
  type        = bool
  default     = false
}

variable "num_node_groups" {
  description = "Количество шардов (только при cluster_mode_enabled=true)."
  type        = number
  default     = 1
}

variable "replicas_per_node_group" {
  description = "Количество реплик на шард (cluster mode)."
  type        = number
  default     = 1
}

variable "num_cache_clusters" {
  description = "Количество узлов при cluster mode = off (primary + replicas-1)."
  type        = number
  default     = 2
}

variable "alarm_cpu_high_threshold" {
  description = "Порог CPUUtilization для аларма, %."
  type        = number
  default     = 80
}

variable "alarm_freeable_memory_low_mb" {
  description = "Порог FreeableMemory (MB) для аларма (ниже => тревога)."
  type        = number
  default     = 256
}

variable "alarm_actions" {
  description = "Список ARNs (SNS/SM) для действий при алармах."
  type        = list(string)
  default     = []
}

variable "ok_actions" {
  description = "Список ARNs для действий при OK состоянии."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Дополнительные теги."
  type        = map(string)
  default     = {}
}

#########################
# Locals
#########################

locals {
  name_safe = lower(replace(var.name_prefix, "/[^a-zA-Z0-9-]/", "-"))

  common_tags = merge(
    {
      "Project"     = "chronowatch-core"
      "Component"   = "redis-cache"
      "ManagedBy"   = "Terraform"
      "Environment" = "unknown"
    },
    var.tags
  )

  sg_create = length(var.existing_security_group_ids) == 0

  # Для CloudWatch (MB -> Bytes)
  freeable_memory_low_bytes = var.alarm_freeable_memory_low_mb * 1024 * 1024
}

#########################
# Networking (SG/Subnets)
#########################

resource "aws_elasticache_subnet_group" "this" {
  name       = "${local.name_safe}-redis-subnets"
  subnet_ids = var.subnet_ids
  tags       = local.common_tags
}

resource "aws_security_group" "this" {
  count       = local.sg_create ? 1 : 0
  name        = "${local.name_safe}-redis-sg"
  description = "Security group for ${var.name_prefix} ElastiCache Redis"
  vpc_id      = var.vpc_id

  tags = local.common_tags
}

resource "aws_vpc_security_group_egress_rule" "redis_all_egress" {
  count             = local.sg_create ? 1 : 0
  security_group_id = aws_security_group.this[0].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Allow all egress"
}

resource "aws_vpc_security_group_ingress_rule" "redis_ingress" {
  for_each          = local.sg_create ? toset(var.allowed_cidr_blocks) : []
  security_group_id = aws_security_group.this[0].id
  cidr_ipv4         = each.value
  from_port         = var.port
  to_port           = var.port
  ip_protocol       = "tcp"
  description       = "Allow Redis from CIDR ${each.value}"
}

#########################
# Parameter Group
#########################

resource "aws_elasticache_parameter_group" "this" {
  name        = "${local.name_safe}-redis-pg"
  family      = "redis${replace(var.engine_version, "/\\..*$/", "")}" # redis7, redis6 etc.
  description = "Parameter group for ${var.name_prefix}"

  # Пример безопасных дефолтов; можно переопределить через variable
  # appendonly=yes требует совместимости; ElastiCache использует свой механизм персистентности,
  # поэтому примеры ниже — нейтральные, вы можете расширить при необходимости.
  dynamic "parameter" {
    for_each = var.parameter_overrides
    content {
      name  = parameter.key
      value = parameter.value
    }
  }

  tags = local.common_tags
}

#########################
# Auth token in Secrets
#########################

resource "random_password" "auth_token" {
  length           = 32
  special          = true
  override_special = "!@#$%^&*()_-+="
}

resource "aws_secretsmanager_secret" "auth" {
  name       = "${local.name_safe}/redis/auth-token"
  kms_key_id = var.kms_key_id
  tags       = local.common_tags
}

resource "aws_secretsmanager_secret_version" "auth" {
  secret_id     = aws_secretsmanager_secret.auth.id
  secret_string = random_password.auth_token.result
}

#########################
# Replication Group
#########################

# Собираем список SG: либо свои, либо переданные
locals {
  sg_ids = local.sg_create ? [aws_security_group.this[0].id] : var.existing_security_group_ids
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id          = "${local.name_safe}-redis-rg"
  replication_group_description = "Redis replication group for ${var.name_prefix}"

  engine                     = "redis"
  engine_version             = var.engine_version
  node_type                  = var.node_type
  port                       = var.port
  parameter_group_name       = aws_elasticache_parameter_group.this.name
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  security_group_ids         = local.sg_ids
  at_rest_encryption_enabled = var.at_rest_encryption_enabled
  kms_key_id                 = var.kms_key_id
  transit_encryption_enabled = var.transit_encryption_enabled

  auth_token                 = var.transit_encryption_enabled ? random_password.auth_token.result : null

  auto_minor_version_upgrade = var.auto_minor_version_upgrade
  maintenance_window         = var.maintenance_window
  snapshot_window            = var.snapshot_window
  snapshot_retention_limit   = var.snapshot_retention_limit

  multi_az_enabled           = var.multi_az_enabled
  automatic_failover_enabled = var.automatic_failover_enabled

  # Cluster Mode vs Single RG
  # Если включено шардирование:
  dynamic "cluster_mode" {
    for_each = var.cluster_mode_enabled ? [1] : []
    content {
      num_node_groups         = var.num_node_groups
      replicas_per_node_group = var.replicas_per_node_group
    }
  }

  # Если кластер мод выключен, используем num_cache_clusters
  num_cache_clusters = var.cluster_mode_enabled ? null : var.num_cache_clusters

  # Выравниваем имя primary cluster
  preferred_cache_cluster_azs = null

  # Теги
  tags = local.common_tags

  # Защита от случайного удаления
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [
      engine_version, # обновления версий лучше проводить через отдельный план
    ]
  }
}

#########################
# CloudWatch Alarms
#########################

# CPUUtilization high
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${local.name_safe}-redis-cpu-high"
  alarm_description   = "High CPUUtilization on Redis replication group"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = 60
  statistic           = "Average"
  threshold           = var.alarm_cpu_high_threshold
  treat_missing_data  = "missing"
  alarm_actions       = var.alarm_actions
  ok_actions          = var.ok_actions

  dimensions = {
    CacheClusterId = aws_elasticache_replication_group.this.configuration_endpoint_address
  }

  depends_on = [aws_elasticache_replication_group.this]
  tags       = local.common_tags
}

# FreeableMemory low
resource "aws_cloudwatch_metric_alarm" "freeable_memory_low" {
  alarm_name          = "${local.name_safe}-redis-freeablemem-low"
  alarm_description   = "Low FreeableMemory on Redis replication group"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "FreeableMemory"
  namespace           = "AWS/ElastiCache"
  period              = 60
  statistic           = "Average"
  threshold           = local.freeable_memory_low_bytes
  treat_missing_data  = "missing"
  alarm_actions       = var.alarm_actions
  ok_actions          = var.ok_actions

  dimensions = {
    CacheClusterId = aws_elasticache_replication_group.this.configuration_endpoint_address
  }

  depends_on = [aws_elasticache_replication_group.this]
  tags       = local.common_tags
}

#########################
# Outputs
#########################

output "replication_group_id" {
  description = "ID репликационной группы Redis."
  value       = aws_elasticache_replication_group.this.id
}

output "primary_endpoint_address" {
  description = "Primary endpoint адрес."
  value       = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "reader_endpoint_address" {
  description = "Reader endpoint адрес."
  value       = aws_elasticache_replication_group.this.reader_endpoint_address
}

output "configuration_endpoint_address" {
  description = "Cluster configuration endpoint (для cluster mode)."
  value       = aws_elasticache_replication_group.this.configuration_endpoint_address
}

output "security_group_ids" {
  description = "Идентификаторы Security Group'ов, применённых к Redis."
  value       = local.sg_ids
}

output "parameter_group_name" {
  description = "Имя группы параметров Redis."
  value       = aws_elasticache_parameter_group.this.name
}

output "auth_secret_arn" {
  description = "ARN секрета в Secrets Manager с Redis AUTH токеном."
  value       = aws_secretsmanager_secret.auth.arn
  sensitive   = true
}
