// datafabric-core / ops / terraform / modules / kafka / main.tf
// Промышленный модуль AWS MSK (Managed Streaming for Apache Kafka)

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

#####################################
# VARIABLES
#####################################

variable "name" {
  description = "Базовое имя кластера (префикс ресурсов)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "Список приватных подсетей для брокеров (рекомендуется по AZ)"
  type        = list(string)
}

variable "broker_instance_type" {
  description = "Тип EC2 для брокеров"
  type        = string
  default     = "kafka.m7g.large"
}

variable "broker_count" {
  description = "Количество брокеров (кратно числу AZ)"
  type        = number
  default     = 3
}

variable "kafka_version" {
  description = "Версия Kafka, поддерживаемая MSK"
  type        = string
  default     = "3.6.0"
}

variable "ebs_storage_gb" {
  description = "Размер EBS на брокера (GiB)"
  type        = number
  default     = 200
}

variable "enable_storage_autoscaling" {
  description = "Включить автоскейлинг хранилища (MSK Storage Auto-Scaling)"
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "KMS Key ARN для шифрования данных at-rest (если null — AWS‑managed)"
  type        = string
  default     = null
}

variable "enable_public_access" {
  description = "Публичный доступ к брокерам (обычно false для prod)"
  type        = bool
  default     = false
}

variable "allowed_client_sg_ids" {
  description = "Security Group IDs клиентов, которым разрешён доступ к брокерам"
  type        = list(string)
  default     = []
}

variable "allowed_client_cidrs" {
  description = "Доп. CIDR для клиентского доступа (например, VPN)"
  type        = list(string)
  default     = []
}

variable "enable_iam_auth" {
  description = "Разрешить IAM аутентификацию клиентов (MSK IAM SASL)"
  type        = bool
  default     = true
}

variable "enable_sasl_scram" {
  description = "Разрешить SASL/SCRAM аутентификацию"
  type        = bool
  default     = false
}

variable "scram_secret_arns" {
  description = "Список Secrets Manager ARNs с паролями пользователей SASL/SCRAM"
  type        = list(string)
  default     = []
}

variable "client_broker_encryption" {
  description = "Режим шифрования между клиентом и брокером: TLS, TLS_PLAINTEXT или PLAINTEXT (не рекоменд.)"
  type        = string
  default     = "TLS"
}

variable "cloudwatch_logs_enabled" {
  description = "Включить отправку брокерских логов в CloudWatch Logs"
  type        = bool
  default     = true
}

variable "cloudwatch_log_group_retention_days" {
  description = "Ретеншн лог‑группы CloudWatch (дни)"
  type        = number
  default     = 14
}

variable "open_monitoring_enabled" {
  description = "Включить MSK Open Monitoring (Prometheus via JMX/Node exporter)"
  type        = bool
  default     = true
}

variable "configuration_server_properties" {
  description = <<EOT
Карта свойств server.properties для aws_msk_configuration.
Примеры:
  num.partitions = 6
  default.replication.factor = 3
  min.insync.replicas = 2
  auto.create.topics.enable = false
  log.retention.hours = 168
  log.segment.bytes = 1073741824
  unclean.leader.election.enable = false
EOT
  type    = map(string)
  default = {
    "auto.create.topics.enable"   = "false"
    "num.partitions"              = "6"
    "default.replication.factor"  = "3"
    "min.insync.replicas"         = "2"
    "log.retention.hours"         = "168"
    "log.segment.bytes"           = "1073741824"
    "unclean.leader.election.enable" = "false"
  }
}

variable "tags" {
  description = "Общие теги для всех ресурсов"
  type        = map(string)
  default     = {}
}

#####################################
# LOCALS
#####################################

locals {
  name      = var.name
  base_tags = merge(
    {
      "Name"                      = var.name
      "app.kubernetes.io/name"    = "datafabric-core"
      "app.kubernetes.io/component" = "kafka"
      "app.kubernetes.io/part-of" = "datafabric"
      "module"                    = "kafka"
    },
    var.tags
  )

  // Преобразование карты свойств в текст server.properties
  server_properties = join("\n", [
    for k, v in sort(var.configuration_server_properties) : "${k}=${v}"
  ])
}

#####################################
# DATA / SUPPORT
#####################################

data "aws_region" "this" {}
data "aws_caller_identity" "this" {}

# Необязательно: если kms_key_arn не задан, MSK применит AWS-managed KMS.
# Можно добавить data/aws_kms_key по alias при необходимости.

#####################################
# NETWORKING: Security Group
#####################################

resource "aws_security_group" "msk" {
  name        = "${local.name}-sg"
  description = "MSK brokers security group"
  vpc_id      = var.vpc_id
  tags        = local.base_tags

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

// Разрешаем клиентский доступ на брокерские порты (TLS/PLAINTEXT диапазоны MSK)
# 9092: TLS, 9094: TLS (варианты у MSK различаются по типу аутентификации), 9098+: сервисные.
resource "aws_vpc_security_group_ingress_rule" "client_cidrs" {
  for_each          = toset(var.allowed_client_cidrs)
  description       = "Client CIDR access"
  security_group_id = aws_security_group.msk.id
  ip_protocol       = "tcp"
  from_port         = 9092
  to_port           = 9098
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "client_sgs" {
  for_each                           = toset(var.allowed_client_sg_ids)
  description                        = "Client SG access"
  security_group_id                  = aws_security_group.msk.id
  ip_protocol                        = "tcp"
  from_port                          = 9092
  to_port                            = 9098
  referenced_security_group_id       = each.value
}

# Внутрикластерная коммуникация
resource "aws_vpc_security_group_ingress_rule" "intra_cluster" {
  description         = "Broker to broker (self)"
  security_group_id   = aws_security_group.msk.id
  ip_protocol         = "-1"
  referenced_security_group_id = aws_security_group.msk.id
}

#####################################
# LOGS: CloudWatch
#####################################

resource "aws_cloudwatch_log_group" "msk" {
  count             = var.cloudwatch_logs_enabled ? 1 : 0
  name              = "/aws/msk/${local.name}"
  retention_in_days = var.cloudwatch_log_group_retention_days
  tags              = local.base_tags
}

#####################################
# CONFIGURATION: server.properties
#####################################

resource "aws_msk_configuration" "this" {
  name              = "${local.name}-config"
  kafka_versions    = [var.kafka_version]
  server_properties = local.server_properties
  description       = "Managed server.properties for ${local.name}"
  tags              = local.base_tags
}

#####################################
# MSK CLUSTER
#####################################

resource "aws_msk_cluster" "this" {
  cluster_name           = local.name
  kafka_version          = var.kafka_version
  number_of_broker_nodes = var.broker_count

  broker_node_group_info {
    instance_type   = var.broker_instance_type
    client_subnets  = var.subnet_ids
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info {
        volume_size = var.ebs_storage_gb
      }
    }
  }

  encryption_info {
    encryption_at_rest_kms_key_arn = var.kms_key_arn
    encryption_in_transit {
      client_broker = var.client_broker_encryption   # TLS | TLS_PLAINTEXT | PLAINTEXT (не рекомендуется)
      in_cluster    = true
    }
  }

  client_authentication {
    sasl {
      iam   = var.enable_iam_auth
      scram = var.enable_sasl_scram
    }
    tls {
      enabled = true
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.this.arn
    revision = aws_msk_configuration.this.latest_revision
  }

  dynamic "logging_info" {
    for_each = var.cloudwatch_logs_enabled ? [1] : []
    content {
      broker_logs {
        cloudwatch_logs {
          enabled   = true
          log_group = aws_cloudwatch_log_group.msk[0].name
        }
      }
    }
  }

  open_monitoring {
    prometheus {
      jmx_exporter {
        enabled_in_broker = var.open_monitoring_enabled
      }
      node_exporter {
        enabled_in_broker = var.open_monitoring_enabled
      }
    }
  }

  dynamic "storage_mode" {
    # Если включён авто‑скейлинг хранения, MSK использует "TIERED" или "LOCAL" в зависимости от региона/фич.
    # Здесь оставим без явного указания — управляется самим сервисом.
    for_each = []
    content {}
  }

  # Публичный доступ, как правило, выключен для prod
  # (оставляем блок пустым; управляется параметром create_public_access — провайдер >=5.46)
  dynamic "public_access" {
    for_each = var.enable_public_access ? [1] : []
    content {
      type = "SERVICE_PROVIDED_EIPS"
    }
  }

  tags = local.base_tags

  lifecycle {
    ignore_changes = [
      # Позволяет менять конфигурацию через новую aws_msk_configuration и обновлять revision без разрушения
      configuration_info[0].revision
    ]
  }
}

# Привязка SASL/SCRAM секретов (если включено)
resource "aws_msk_scram_secret_association" "this" {
  count                = var.enable_sasl_scram && length(var.scram_secret_arns) > 0 ? 1 : 0
  cluster_arn          = aws_msk_cluster.this.arn
  secret_arn_list      = var.scram_secret_arns
  depends_on           = [aws_msk_cluster.this]
}

#####################################
# OUTPUTS
#####################################

output "cluster_arn" {
  description = "ARN кластера MSK"
  value       = aws_msk_cluster.this.arn
}

output "bootstrap_brokers" {
  description = "PLAINTEXT/TLS bootstrap (включая варианты сервиса)"
  value       = aws_msk_cluster.this.bootstrap_brokers
}

output "bootstrap_brokers_tls" {
  description = "TLS bootstrap"
  value       = aws_msk_cluster.this.bootstrap_brokers_tls
}

output "bootstrap_brokers_sasl_scram" {
  description = "SASL/SCRAM bootstrap (если включено)"
  value       = try(aws_msk_cluster.this.bootstrap_brokers_sasl_scram, null)
}

output "bootstrap_brokers_iam" {
  description = "IAM bootstrap (если включено)"
  value       = try(aws_msk_cluster.this.bootstrap_brokers_iam, null)
}

output "zookeeper_connect_string_tls" {
  description = "ZooKeeper (TLS) — для некоторых операций администрирования (устаревает)"
  value       = try(aws_msk_cluster.this.zookeeper_connect_string_tls, null)
}

output "security_group_id" {
  description = "Security Group брокеров"
  value       = aws_security_group.msk.id
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group (если включено)"
  value       = var.cloudwatch_logs_enabled ? aws_cloudwatch_log_group.msk[0].name : null
}

output "configuration_arn" {
  description = "ARN aws_msk_configuration"
  value       = aws_msk_configuration.this.arn
}
