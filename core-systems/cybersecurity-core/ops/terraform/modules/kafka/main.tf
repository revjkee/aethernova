terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

########################################
# Data sources
########################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

########################################
# Locals
########################################

locals {
  # Базовые теги + пользовательские
  base_tags = {
    Project      = coalesce(var.project, "cybersecurity-core")
    Module       = "kafka"
    Environment  = var.environment
    Owner        = var.owner
    Region       = data.aws_region.current.name
    ManagedBy    = "terraform"
  }

  tags = merge(local.base_tags, var.tags)

  # Имя лог-группы: берём из var или формируем из шаблона
  cw_log_group_name = var.enable_cw_logs ? (trim(var.cw_log_group_name) != "" ? var.cw_log_group_name : "/aws/msk/${var.name}") : null
}

########################################
# Optional KMS key (customer managed)
########################################

resource "aws_kms_key" "msk" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "KMS CMK for MSK cluster ${var.name}"
  enable_key_rotation     = true
  multi_region            = false
  deletion_window_in_days = 30
  tags                    = local.tags
}

resource "aws_kms_alias" "msk" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/msk/${var.name}"
  target_key_id = aws_kms_key.msk[0].key_id
}

# Итоговый KMS ARN к использованию кластером
locals {
  kms_key_arn_effective = var.encryption_at_rest == "CUSTOMER_MANAGED"
    ? (var.kms_key_arn != "" ? var.kms_key_arn : aws_kms_key.msk[0].arn)
    : null
}

########################################
# Optional CloudWatch Log Group
########################################

resource "aws_cloudwatch_log_group" "msk" {
  count              = var.enable_cw_logs && trim(var.cw_log_group_name) == "" ? 1 : 0
  name               = local.cw_log_group_name
  retention_in_days  = var.cw_logs_retention_days
  kms_key_id         = var.cw_logs_kms_key_arn != "" ? var.cw_logs_kms_key_arn : null
  skip_destroy       = var.cw_logs_skip_destroy
  tags               = local.tags
}

########################################
# MSK Configuration (broker properties)
########################################

resource "aws_msk_configuration" "this" {
  name           = "${var.name}-cfg"
  kafka_versions = [var.kafka_version]
  description    = "Hardened broker configuration for ${var.name}"
  server_properties = <<-PROPS
    # Безопасность и устойчивость
    auto.create.topics.enable=false
    delete.topic.enable=false
    unclean.leader.election.enable=false
    allow.everyone.if.no.acl.found=false

    # Репликация и ISR
    default.replication.factor=${var.default_replication_factor}
    min.insync.replicas=${var.min_insync_replicas}
    num.partitions=${var.default_num_partitions}
    offsets.topic.replication.factor=${var.offsets_topic_replication_factor}
    transaction.state.log.replication.factor=${var.txn_state_log_replication_factor}
    transaction.state.log.min.isr=${var.txn_state_log_min_isr}

    # Лимиты и надёжность
    message.max.bytes=${var.message_max_bytes}
    replica.fetch.max.bytes=${var.replica_fetch_max_bytes}
    socket.request.max.bytes=${var.socket_request_max_bytes}
    log.retention.hours=${var.log_retention_hours}
    log.segment.bytes=${var.log_segment_bytes}
    log.retention.check.interval.ms=${var.log_retention_check_interval_ms}

    # Acl/Авторизация (для SCRAM/IAM/TLS-ACL управляется на уровне клиента/MSK)
    super.users=${var.super_users}

    # Производительность и сжатие
    compression.type=${var.compression_type}

    # Прочее
    group.initial.rebalance.delay.ms=${var.group_initial_rebalance_delay_ms}
  PROPS

  tags = local.tags
}

########################################
# MSK Cluster (provisioned)
########################################

resource "aws_msk_cluster" "this" {
  cluster_name           = var.name
  kafka_version          = var.kafka_version
  number_of_broker_nodes = var.number_of_broker_nodes

  broker_node_group_info {
    instance_type  = var.broker_instance_type
    client_subnets = var.subnet_ids
    security_groups = var.security_group_ids

    storage_info {
      ebs_storage_info {
        volume_size = var.broker_ebs_volume_size
        provisioned_throughput {
          enabled           = var.ebs_throughput_mibps > 0
          volume_throughput = var.ebs_throughput_mibps
        }
      }
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.this.arn
    revision = aws_msk_configuration.this.latest_revision
  }

  encryption_info {
    # at-rest
    encryption_at_rest_kms_key_arn = local.kms_key_arn_effective
    # in-transit
    encryption_in_transit {
      client_broker = var.client_broker_encryption    # TLS | PLAINTEXT | TLS_PLAINTEXT
      in_cluster    = true
    }
  }

  client_authentication {
    tls {
      # Если используете клиентские сертификаты, укажите ARNs корневых CAs
      certificate_authority_arns = length(var.tls_ca_arns) > 0 ? var.tls_ca_arns : null
    }
    sasl {
      scram = var.enable_sasl_scram
      iam   = var.enable_sasl_iam
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = var.enable_cw_logs
        log_group = local.cw_log_group_name
      }
      s3 {
        enabled = var.enable_s3_logs
        bucket  = var.s3_logs_bucket
        prefix  = var.s3_logs_prefix
      }
      firehose {
        enabled         = var.enable_firehose_logs
        delivery_stream = var.firehose_delivery_stream
      }
    }
  }

  enhanced_monitoring = var.enhanced_monitoring  # DEFAULT | PER_BROKER | PER_TOPIC_PER_PARTITION

  open_monitoring {
    prometheus {
      jmx_exporter {
        enabled_in_broker = var.enable_jmx_exporter
      }
      node_exporter {
        enabled_in_broker = var.enable_node_exporter
      }
    }
  }

  # Консервативные обновления кластера
  broker_software_update = "DEFAULT"

  tags = local.tags

  depends_on = [
    aws_msk_configuration.this,
    aws_cloudwatch_log_group.msk
  ]
}

########################################
# SCRAM users association (optional)
########################################

resource "aws_msk_scram_secret_association" "this" {
  count                = var.enable_sasl_scram && length(var.scram_secret_arns) > 0 ? 1 : 0
  cluster_arn          = aws_msk_cluster.this.arn
  secret_arn_list      = var.scram_secret_arns
  depends_on           = [aws_msk_cluster.this]
}

########################################
# Outputs are expected in outputs.tf (в другом файле модуля)
########################################
