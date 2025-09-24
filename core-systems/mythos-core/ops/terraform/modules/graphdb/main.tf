##############################################
# mythos-core/ops/terraform/modules/graphdb/main.tf
##############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.32"
    }
  }
}

##############################################
# Variables (самодостаточно в одном файле)
##############################################

variable "name" {
  description = "Базовое имя ресурсов (cluster identifier префикс)"
  type        = string
}

variable "vpc_id" {
  description = "ID VPC, где размещать Neptune"
  type        = string
}

variable "subnet_ids" {
  description = "Список приватных subnetов для Subnet Group"
  type        = list(string)
}

variable "allowed_cidr_blocks" {
  description = "CIDR, которым разрешено подключение к порту Neptune (обычно CIDR приложений в той же VPC)"
  type        = list(string)
  default     = []
}

variable "instance_class" {
  description = "Класс инстансов Neptune (например, db.r6g.large)"
  type        = string
}

variable "instance_count" {
  description = "Общее число экземпляров в кластере (>=1). 1 — writer; остальные — читатели"
  type        = number
  default     = 1
  validation {
    condition     = var.instance_count >= 1
    error_message = "instance_count должен быть >= 1."
  }
}

variable "engine_version" {
  description = "Версия Neptune (например, 1.2.0.0). Пусто — использовать дефолт AWS"
  type        = string
  default     = null
}

variable "port" {
  description = "Порт Neptune"
  type        = number
  default     = 8182
}

variable "storage_encrypted" {
  description = "Шифровать ли Storage (KMS)"
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "KMS Key ARN для шифрования. Если null и storage_encrypted=true — будет создан отдельный ключ"
  type        = string
  default     = null
}

variable "iam_auth_enabled" {
  description = "Включить IAM Database Authentication"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Срок хранения автоматических бэкапов, дней"
  type        = number
  default     = 7
}

variable "preferred_backup_window" {
  description = "Окно бэкапа в формате UTC, например 04:00-05:00"
  type        = string
  default     = "04:00-05:00"
}

variable "preferred_maintenance_window" {
  description = "Окно обслуживания, например sun:06:00-sun:07:00"
  type        = string
  default     = "sun:06:00-sun:07:00"
}

variable "apply_immediately" {
  description = "Применять изменения немедленно (влечёт рестарт)"
  type        = bool
  default     = false
}

variable "deletion_protection" {
  description = "Защита от удаления кластера"
  type        = bool
  default     = true
}

variable "skip_final_snapshot" {
  description = "Пропустить финальный snapshot при удалении (НЕ рекомендуется)"
  type        = bool
  default     = false
}

variable "final_snapshot_identifier" {
  description = "Имя финального snapshot при удалении (если skip_final_snapshot=false)"
  type        = string
  default     = null
}

variable "publicly_accessible" {
  description = "Разрешить ли публичный доступ к экземплярам (обычно false)"
  type        = bool
  default     = false
}

variable "parameter_overrides" {
  description = "Переопределения параметров кластера (map name=>value) для aws_neptune_parameter_group"
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Дополнительные тэги"
  type        = map(string)
  default     = {}
}

# Алармы
variable "alarms_enabled" {
  description = "Создавать CloudWatch alarms"
  type        = bool
  default     = true
}

variable "alarm_cpu_high_threshold" {
  description = "Порог CPUUtilization, %"
  type        = number
  default     = 80
}

variable "alarm_freeable_memory_low_mb" {
  description = "Порог FreeableMemory, МБ"
  type        = number
  default     = 512
}

variable "alarm_connections_high" {
  description = "Порог DBConnections"
  type        = number
  default     = 500
}

##############################################
# Locals
##############################################

locals {
  common_tags = merge(
    {
      "Project"                 = "mythos-core"
      "Component"               = "graphdb"
      "ManagedBy"               = "Terraform"
      "terraform-module"        = "mythos-core/graphdb"
    },
    var.tags
  )

  # Список индексов экземпляров: [0..instance_count-1]
  instance_indexes = toset([for i in range(var.instance_count) : i])

  engine_version = var.engine_version == null ? null : var.engine_version
}

##############################################
# KMS (опционально)
##############################################

resource "aws_kms_key" "this" {
  count                   = var.storage_encrypted && var.kms_key_arn == null ? 1 : 0
  description             = "KMS key for Neptune cluster ${var.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

resource "aws_kms_alias" "this" {
  count         = var.storage_encrypted && var.kms_key_arn == null ? 1 : 0
  name          = "alias/${var.name}-neptune"
  target_key_id = aws_kms_key.this[0].id
}

##############################################
# Networking: Subnet Group & Security Group
##############################################

resource "aws_neptune_subnet_group" "this" {
  name       = "${var.name}-neptune-subnets"
  subnet_ids = var.subnet_ids
  tags       = local.common_tags
}

resource "aws_security_group" "this" {
  name        = "${var.name}-neptune-sg"
  description = "Security group for Neptune ${var.name}"
  vpc_id      = var.vpc_id
  tags        = local.common_tags

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Разрешить вход только с заданных CIDR (или оставить без ingress — если доступ идёт через SG-to-SG)
resource "aws_security_group_rule" "ingress_cidr" {
  count             = length(var.allowed_cidr_blocks) > 0 ? 1 : 0
  type              = "ingress"
  security_group_id = aws_security_group.this.id
  from_port         = var.port
  to_port           = var.port
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidr_blocks
  description       = "Allow Neptune port from allowed CIDRs"
}

##############################################
# Parameter Group (cluster-level)
##############################################

resource "aws_neptune_parameter_group" "this" {
  name        = "${var.name}-neptune-params"
  family      = "neptune1"
  description = "Cluster parameter group for ${var.name}"
  tags        = local.common_tags

  dynamic "parameter" {
    for_each = var.parameter_overrides
    content {
      name  = parameter.key
      value = parameter.value
    }
  }
}

##############################################
# Cluster
##############################################

resource "aws_neptune_cluster" "this" {
  cluster_identifier                     = "${var.name}-neptune-cluster"
  engine                                 = "neptune"
  port                                   = var.port
  vpc_security_group_ids                 = [aws_security_group.this.id]
  neptune_subnet_group_name              = aws_neptune_subnet_group.this.name
  neptune_cluster_parameter_group_name   = aws_neptune_parameter_group.this.name

  iam_database_authentication_enabled    = var.iam_auth_enabled

  backup_retention_period                = var.backup_retention_days
  preferred_backup_window                = var.preferred_backup_window
  preferred_maintenance_window           = var.preferred_maintenance_window

  storage_encrypted                      = var.storage_encrypted
  kms_key_arn                            = var.storage_encrypted ? coalesce(var.kms_key_arn, try(aws_kms_key.this[0].arn, null)) : null

  apply_immediately                      = var.apply_immediately
  deletion_protection                    = var.deletion_protection

  # Версия движка (опционально)
  engine_version                         = local.engine_version

  skip_final_snapshot                    = var.skip_final_snapshot
  final_snapshot_identifier              = var.skip_final_snapshot ? null : coalesce(var.final_snapshot_identifier, "${var.name}-final-${formatdate("YYYYMMDDhhmmss", timestamp())}")

  tags = local.common_tags
}

##############################################
# Instances (writer + readers)
##############################################

resource "aws_neptune_cluster_instance" "this" {
  for_each                     = local.instance_indexes

  identifier                   = "${var.name}-neptune-${each.value}"
  cluster_identifier           = aws_neptune_cluster.this.id
  instance_class               = var.instance_class
  engine                       = "neptune"

  # Writer — индекс 0, остальные — читатели (кластер управляет endpoint’ами)
  apply_immediately            = var.apply_immediately
  auto_minor_version_upgrade   = true
  publicly_accessible          = var.publicly_accessible
  preferred_maintenance_window = var.preferred_maintenance_window

  # Версия движка на уровне инстанса (обычно не указывают; оставим null если не задана на кластере)
  engine_version               = local.engine_version

  tags = merge(local.common_tags, { "neptune-role" = each.value == 0 ? "writer" : "reader" })
}

##############################################
# CloudWatch Alarms (per instance)
##############################################

# CPU high
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  for_each            = var.alarms_enabled ? aws_neptune_cluster_instance.this : {}

  alarm_name          = "${var.name}-neptune-${each.key}-cpu-high"
  alarm_description   = "Neptune CPUUtilization high on instance ${each.value.id}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 3
  threshold           = var.alarm_cpu_high_threshold
  treat_missing_data  = "missing"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/Neptune"
  period              = 60
  statistic           = "Average"
  dimensions = {
    DBInstanceIdentifier = each.value.id
  }
  tags = local.common_tags
}

# FreeableMemory low
resource "aws_cloudwatch_metric_alarm" "freeable_memory_low" {
  for_each            = var.alarms_enabled ? aws_neptune_cluster_instance.this : {}

  alarm_name          = "${var.name}-neptune-${each.key}-mem-low"
  alarm_description   = "Neptune FreeableMemory low on instance ${each.value.id}"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = 3
  threshold           = var.alarm_freeable_memory_low_mb * 1024 * 1024
  treat_missing_data  = "missing"
  metric_name         = "FreeableMemory"
  namespace           = "AWS/Neptune"
  period              = 60
  statistic           = "Average"
  dimensions = {
    DBInstanceIdentifier = each.value.id
  }
  tags = local.common_tags
}

# DBConnections high
resource "aws_cloudwatch_metric_alarm" "connections_high" {
  for_each            = var.alarms_enabled ? aws_neptune_cluster_instance.this : {}

  alarm_name          = "${var.name}-neptune-${each.key}-conns-high"
  alarm_description   = "Neptune DBConnections high on instance ${each.value.id}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 3
  threshold           = var.alarm_connections_high
  treat_missing_data  = "missing"
  metric_name         = "DBConnections"
  namespace           = "AWS/Neptune"
  period              = 60
  statistic           = "Average"
  dimensions = {
    DBInstanceIdentifier = each.value.id
  }
  tags = local.common_tags
}

##############################################
# Outputs
##############################################

output "cluster_id" {
  description = "ID кластера Neptune"
  value       = aws_neptune_cluster.this.id
}

output "cluster_arn" {
  description = "ARN кластера Neptune"
  value       = aws_neptune_cluster.this.arn
}

output "endpoint" {
  description = "Writer endpoint кластера"
  value       = aws_neptune_cluster.this.endpoint
}

output "reader_endpoint" {
  description = "Reader endpoint кластера"
  value       = aws_neptune_cluster.this.reader_endpoint
}

output "port" {
  description = "Порт Neptune"
  value       = aws_neptune_cluster.this.port
}

output "security_group_id" {
  description = "ID Security Group"
  value       = aws_security_group.this.id
}

output "subnet_group_name" {
  description = "Имя Subnet Group"
  value       = aws_neptune_subnet_group.this.name
}

output "instance_ids" {
  description = "Список идентификаторов инстансов"
  value       = [for i in aws_neptune_cluster_instance.this : i.id]
}

output "kms_key_arn" {
  description = "KMS ключ, используемый для шифрования (если включено)"
  value       = var.storage_encrypted ? coalesce(var.kms_key_arn, try(aws_kms_key.this[0].arn, null)) : null
}
