############################################
# oblivionvault-core/ops/terraform/modules/compute/main.tf
# ПРИМЫШЛЕННЫЙ МОДУЛЬ AWS COMPUTE (LT + ASG)
############################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
  }
}

#########################
# VARIABLES
#########################

variable "name_prefix" {
  description = "Префикс имени для всех ресурсов (напр. 'oblivionvault-core')"
  type        = string
}

variable "vpc_id" {
  description = "ID VPC"
  type        = string
}

variable "subnet_ids" {
  description = "Список приватных/публичных подсетей для ASG"
  type        = list(string)
}

variable "instance_type" {
  description = "Тип инстанса"
  type        = string
  default     = "t3.medium"
}

variable "ami_id" {
  description = "Явный AMI ID; если пусто — используем Amazon Linux 2023 через SSM"
  type        = string
  default     = ""
}

variable "use_public_ip" {
  description = "Ассоциировать публичный IP (true для публичных подсетей)"
  type        = bool
  default     = false
}

variable "key_name" {
  description = "Имя SSH key pair (опционально)"
  type        = string
  default     = null
}

variable "root_volume_size_gb" {
  description = "Размер корневого тома"
  type        = number
  default     = 30
}

variable "root_volume_type" {
  description = "Тип корневого тома (gp3, gp2, io2, io1)"
  type        = string
  default     = "gp3"
}

variable "root_volume_iops" {
  description = "IOPS для томов gp3/io1/io2 (опционально)"
  type        = number
  default     = null
}

variable "root_volume_throughput" {
  description = "Пропускная способность (MB/s) для gp3 (опционально)"
  type        = number
  default     = null
}

variable "kms_key_id" {
  description = "KMS Key ID/ARN для шифрования EBS (если null — используется ключ по умолчанию AWS)"
  type        = string
  default     = null
}

variable "min_size" {
  description = "Минимальный размер ASG"
  type        = number
  default     = 2
}

variable "max_size" {
  description = "Максимальный размер ASG"
  type        = number
  default     = 6
}

variable "desired_capacity" {
  description = "Желаемый размер ASG (если null — управляется autoscaling/policies)"
  type        = number
  default     = 2
}

variable "health_check_type" {
  description = "Тип health check (EC2 или ELB)"
  type        = string
  default     = "EC2"
}

variable "health_check_grace_period" {
  description = "Грейс-период для health check (сек)"
  type        = number
  default     = 180
}

variable "termination_policies" {
  description = "Политики терминации инстансов"
  type        = list(string)
  default     = ["OldestLaunchTemplate", "OldestInstance", "Default"]
}

variable "target_group_arns" {
  description = "Список ARNs ALB/NLB Target Groups для прикрепления к ASG (опционально)"
  type        = list(string)
  default     = []
}

variable "allow_ssh_cidrs" {
  description = "CIDR для SSH доступа (по умолчанию закрыто)"
  type        = list(string)
  default     = []
}

variable "allow_http_cidrs" {
  description = "CIDR для HTTP 80 (по умолчанию закрыто)"
  type        = list(string)
  default     = []
}

variable "allow_https_cidrs" {
  description = "CIDR для HTTPS 443 (по умолчанию закрыто)"
  type        = list(string)
  default     = []
}

variable "additional_ingress" {
  description = "Доп. ingress правила: список объектов { from_port, to_port, protocol, cidr_blocks }"
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
    description = optional(string)
  }))
  default = []
}

variable "enable_spot" {
  description = "Использовать Mixed Instances Policy (Spot)"
  type        = bool
  default     = false
}

variable "on_demand_percentage" {
  description = "Процент On-Demand в Mixed Instances (0..100)"
  type        = number
  default     = 100
}

variable "spot_max_price" {
  description = "Максимальная цена Spot (как строка, напр. '0.05'); null = по рынку"
  type        = string
  default     = null
}

variable "capacity_rebalance" {
  description = "Включить Capacity Rebalance для Spot"
  type        = bool
  default     = true
}

variable "enable_detailed_monitoring" {
  description = "Включить Detailed Monitoring для EC2"
  type        = bool
  default     = true
}

variable "enable_warm_pool" {
  description = "Включить Warm Pool"
  type        = bool
  default     = false
}

variable "warm_pool_min_size" {
  description = "Минимальный размер Warm Pool (если null — по умолчанию)"
  type        = number
  default     = null
}

variable "cpu_target_value" {
  description = "Целевое значение CPUUtilization для Target Tracking"
  type        = number
  default     = 50
}

variable "log_retention_days" {
  description = "Срок хранения логов CloudWatch"
  type        = number
  default     = 30
}

variable "create_iam_role" {
  description = "Создавать IAM роль и Instance Profile для SSM и CloudWatch Agent"
  type        = bool
  default     = true
}

variable "iam_role_name" {
  description = "Имя IAM роли (если не создаётся автоматически)"
  type        = string
  default     = null
}

variable "iam_additional_policies" {
  description = "Список ARNs доп. управляемых IAM политик для EC2 роли"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Общие теги для ресурсов"
  type        = map(string)
  default     = {}
}

variable "extra_user_data_commands" {
  description = "Доп. команды bash, которые будут выполнены в user_data"
  type        = list(string)
  default     = []
}

#########################
# DATA & LOCALS
#########################

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Amazon Linux 2023 AMI через SSM, если ami_id не задан
data "aws_ssm_parameter" "al2023" {
  name            = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
  with_decryption = false
}

locals {
  module_name         = "${var.name_prefix}-compute"
  common_tags         = merge({ "Name" = local.module_name }, var.tags)
  resolved_ami_id     = var.ami_id != "" ? var.ami_id : data.aws_ssm_parameter.al2023.value
  cw_log_group_name   = "/aws/ec2/${local.module_name}"
  sg_name             = "${local.module_name}-sg"
  role_name_effective = var.create_iam_role ? coalesce(var.iam_role_name, "${local.module_name}-role") : var.iam_role_name

  # CloudWatch Agent конфиг (минимальный набор: syslog/journal, метрики)
  cw_agent_config = jsonencode({
    metrics = {
      namespace  = "OVault/EC2"
      append_dimensions = {
        AutoScalingGroupName = "${local.module_name}"
        InstanceId           = "${"{{instance_id}}"}"
      }
      metrics_collected = {
        cpu     = { measurement = ["cpu_usage_idle", "cpu_usage_user", "cpu_usage_system"], resources = ["*"], totalcpu = true }
        disk    = { measurement = ["used_percent"], resources = ["*"] }
        mem     = { measurement = ["mem_used_percent"] }
        netstat = { measurement = ["tcp_established", "tcp_time_wait"] }
      }
    }
    logs = {
      logs_collected = {
        files = {
          collect_list = [
            { file_path = "/var/log/messages", log_group_name = local.cw_log_group_name, log_stream_name = "{instance_id}/messages" },
            { file_path = "/var/log/cloud-init.log", log_group_name = local.cw_log_group_name, log_stream_name = "{instance_id}/cloud-init" }
          ]
        }
        journal = { collect = true, log_group_name = local.cw_log_group_name, log_stream_name = "{instance_id}/journal" }
      }
    }
  })

  # User data (bash) — установка/запуск CloudWatch Agent, проверка SSM, доп. команды
  user_data = <<-EOT
    #!/bin/bash
    set -euo pipefail

    # Обновление пакетов
    dnf -y update || true

    # Установка CloudWatch Agent (для AL2023 пакет доступен в репозитории)
    dnf -y install amazon-cloudwatch-agent || true

    # Конфиг CloudWatch Agent
    cat >/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'CFG'
    ${local.cw_agent_config}
    CFG

    systemctl enable amazon-cloudwatch-agent || true
    systemctl restart amazon-cloudwatch-agent || true

    # Убедиться, что SSM Agent активен (обычно предустановлен)
    systemctl enable amazon-ssm-agent || true
    systemctl restart amazon-ssm-agent || true

    # Тюнинг системных параметров (пример)
    echo 'vm.swappiness=10' > /etc/sysctl.d/99-ovault.conf
    sysctl --system || true

    # Дополнительные команды пользователя
    ${join("\n", var.extra_user_data_commands)}
  EOT
}

#########################
# IAM ROLE & PROFILE
#########################

resource "aws_iam_role" "this" {
  count              = var.create_iam_role ? 1 : 0
  name               = local.role_name_effective
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.${data.aws_partition.current.dns_suffix}"]
    }
  }
}

# Managed policies: SSM core + CloudWatch Agent
resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.create_iam_role ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cwagent" {
  count      = var.create_iam_role ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "additional" {
  for_each = var.create_iam_role ? toset(var.iam_additional_policies) : []
  role     = aws_iam_role.this[0].name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "this" {
  count = var.create_iam_role ? 1 : 0
  name  = "${local.module_name}-instance-profile"
  role  = aws_iam_role.this[0].name
  tags  = local.common_tags
}

#########################
# SECURITY GROUP
#########################

resource "aws_security_group" "this" {
  name        = local.sg_name
  description = "Security Group for ${local.module_name}"
  vpc_id      = var.vpc_id
  tags        = local.common_tags
}

# SSH (22)
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each          = toset(var.allow_ssh_cidrs)
  security_group_id = aws_security_group.this.id
  cidr_ipv4         = each.value
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH"
}

# HTTP (80)
resource "aws_vpc_security_group_ingress_rule" "http" {
  for_each          = toset(var.allow_http_cidrs)
  security_group_id = aws_security_group.this.id
  cidr_ipv4         = each.value
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "HTTP"
}

# HTTPS (443)
resource "aws_vpc_security_group_ingress_rule" "https" {
  for_each          = toset(var.allow_https_cidrs)
  security_group_id = aws_security_group.this.id
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS"
}

# Дополнительные правила
resource "aws_vpc_security_group_ingress_rule" "additional" {
  for_each          = { for i, r in var.additional_ingress : i => r }
  security_group_id = aws_security_group.this.id
  cidr_ipv4         = length(each.value.cidr_blocks) > 0 ? null : "0.0.0.0/32"
  # Если передан список CIDR — создадим отдельные ingress ниже
  from_port   = each.value.from_port
  to_port     = each.value.to_port
  ip_protocol = each.value.protocol
  description = try(each.value.description, "additional-ingress")
  # Примечание: для множественных CIDR Terraform 5.x рекомендует отдельные правила на CIDR;
  # здесь вышеописанное правило служит заглушкой, реальные CIDR зададим через ресурс ниже.
  lifecycle {
    create_before_destroy = true
    ignore_changes        = [cidr_ipv4]
  }
}

resource "aws_vpc_security_group_ingress_rule" "additional_multi" {
  for_each = {
    for idx, r in flatten([
      for i, rule in var.additional_ingress : [
        for c in rule.cidr_blocks : {
          key         = "${i}-${c}-${rule.from_port}-${rule.to_port}-${rule.protocol}"
          cidr        = c
          from_port   = rule.from_port
          to_port     = rule.to_port
          protocol    = rule.protocol
          description = try(rule.description, "additional-ingress")
        }
      ]
    ]) : idx => r
  }
  security_group_id = aws_security_group.this.id
  cidr_ipv4         = each.value.cidr
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  ip_protocol       = each.value.protocol
  description       = each.value.description
}

# Egress: всё наружу по умолчанию
resource "aws_vpc_security_group_egress_rule" "all_egress" {
  security_group_id = aws_security_group.this.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "All egress"
}

#########################
# CLOUDWATCH LOG GROUP
#########################

resource "aws_cloudwatch_log_group" "this" {
  name              = local.cw_log_group_name
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

#########################
# LAUNCH TEMPLATE
#########################

resource "aws_launch_template" "this" {
  name_prefix   = "${local.module_name}-lt-"
  image_id      = local.resolved_ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  iam_instance_profile {
    name = var.create_iam_role ? aws_iam_instance_profile.this[0].name : var.iam_role_name
  }

  network_interfaces {
    security_groups             = [aws_security_group.this.id]
    associate_public_ip_address = var.use_public_ip
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = var.kms_key_id
      volume_size           = var.root_volume_size_gb
      volume_type           = var.root_volume_type
      iops                  = var.root_volume_iops
      throughput            = var.root_volume_throughput
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 строго
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  tag_specifications {
    resource_type = "instance"
    tags          = local.common_tags
  }

  tag_specifications {
    resource_type = "volume"
    tags          = local.common_tags
  }

  user_data = base64encode(local.user_data)

  tags = local.common_tags

  lifecycle {
    create_before_destroy = true
  }
}

#########################
# AUTO SCALING GROUP
#########################

resource "aws_autoscaling_group" "this" {
  name                      = "${local.module_name}-asg"
  vpc_zone_identifier       = var.subnet_ids
  min_size                  = var.min_size
  max_size                  = var.max_size
  desired_capacity          = var.desired_capacity
  health_check_type         = var.health_check_type
  health_check_grace_period = var.health_check_grace_period
  termination_policies      = var.termination_policies
  capacity_rebalance        = var.capacity_rebalance

  # Если enable_spot=false -> используем простую LT
  dynamic "launch_template" {
    for_each = var.enable_spot ? [] : [1]
    content {
      id      = aws_launch_template.this.id
      version = "$Latest"
    }
  }

  # Если enable_spot=true -> Mixed Instances Policy (Spot/On-Demand)
  dynamic "mixed_instances_policy" {
    for_each = var.enable_spot ? [1] : []
    content {
      launch_template {
        launch_template_specification {
          launch_template_id = aws_launch_template.this.id
          version            = "$Latest"
        }
        override {
          instance_type = var.instance_type
        }
      }
      instances_distribution {
        on_demand_percentage_above_base_capacity = var.on_demand_percentage
        spot_max_price                           = var.spot_max_price
      }
    }
  }

  # Поддержка нового стиля тегов для ASG
  tag {
    key                 = "Name"
    value               = local.module_name
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = { for k, v in var.tags : k => v if k != "Name" }
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  # Instance Refresh для безопасных обновлений
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 90
      instance_warmup        = 120
      checkpoint_delay       = 0
      auto_rollback          = true
    }
    triggers = ["launch_template"]
  }

  # Warm Pool (опционально)
  dynamic "warm_pool" {
    for_each = var.enable_warm_pool ? [1] : []
    content {
      min_size = var.warm_pool_min_size
      pool_state = "Stopped"
    }
  }

  depends_on = [aws_cloudwatch_log_group.this]
  tags       = local.common_tags

  lifecycle {
    create_before_destroy = true
  }
}

# Прикрепление к Target Groups (если заданы)
resource "aws_autoscaling_attachment" "tg" {
  for_each               = toset(var.target_group_arns)
  autoscaling_group_name = aws_autoscaling_group.this.name
  lb_target_group_arn    = each.value
}

#########################
# SCALING POLICIES
#########################

resource "aws_cloudwatch_metric_alarm" "high_cpu_scale_out" {
  alarm_name          = "${local.module_name}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = var.cpu_target_value + 10
  alarm_description   = "Scale out on high CPU"
  dimensions          = {}
  tags                = local.common_tags

  lifecycle { ignore_changes = [dimensions] } # управляет TargetTracking; оставлено как пример ручной политики
}

# Target tracking — рекомендуется вместо кастомных CloudWatch alarm policies
resource "aws_autoscaling_policy" "cpu_target_tracking" {
  name                   = "${local.module_name}-tt-cpu"
  autoscaling_group_name = aws_autoscaling_group.this.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = var.cpu_target_value
  }

  depends_on = [aws_autoscaling_group.this]
}

#########################
# OUTPUTS
#########################

output "asg_name" {
  description = "Имя Auto Scaling Group"
  value       = aws_autoscaling_group.this.name
}

output "launch_template_id" {
  description = "ID Launch Template"
  value       = aws_launch_template.this.id
}

output "security_group_id" {
  description = "ID Security Group"
  value       = aws_security_group.this.id
}

output "iam_role_name" {
  description = "Имя IAM роли, присвоенной инстансам"
  value       = local.role_name_effective
}

output "cloudwatch_log_group" {
  description = "Имя CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.this.name
}
