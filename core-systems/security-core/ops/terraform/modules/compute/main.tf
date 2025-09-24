terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

########################################
# Locals
########################################
locals {
  name_prefix = var.name

  # Выбор AMI: приоритет у явного ami_id, иначе — из SSM параметра
  effective_ami_id = coalesce(
    var.ami_id,
    try(data.aws_ssm_parameter.ami.value, null)
  )

  # Стандартные теги + пользовательские
  common_tags = merge({
    "Name"                         = "${var.name}"
    "app.kubernetes.io/name"       = "security-core"
    "app.kubernetes.io/component"  = "security"
    "app.kubernetes.io/part-of"    = "neurocity"
    "module"                       = "compute"
    "managed-by"                   = "terraform"
    "security.neurocity.io/hard"   = "true"
  }, var.tags)

  # Признак использования MixedInstancesPolicy
  use_mixed = var.use_spot || length(var.additional_instance_types) > 0

  # Порты egress (443 TLS, 123 NTP), DNS (53 tcp/udp к VPC CIDR)
  egress_tls_ports = [443]
  egress_ntp_ports = [123]
}

########################################
# Data sources
########################################
data "aws_caller_identity" "this" {}

data "aws_vpc" "this" {
  id = var.vpc_id
}

# AMI через SSM (например, Amazon Linux 2023) — по умолчанию
data "aws_ssm_parameter" "ami" {
  count = var.ami_id == null && var.ami_ssm_parameter != null ? 1 : 0
  name  = var.ami_ssm_parameter
}

########################################
# IAM: Instance Role + Profile
########################################
resource "aws_iam_role" "this" {
  name               = "${local.name_prefix}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# Минимально необходимые политики: SSM и CloudWatch Agent
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_role_policy_attachment" "cwagent" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Опциональный доступ только на чтение к параметрам/секретам (рекомендуется ограничить по префиксу)
data "aws_iam_policy_document" "read_params" {
  count = var.allow_read_parameters ? 1 : 0

  statement {
    sid     = "ReadParameterStore"
    effect  = "Allow"
    actions = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    resources = [
      "arn:aws:ssm:*:${data.aws_caller_identity.this.account_id}:parameter${var.parameters_prefix}*"
    ]
  }

  statement {
    sid     = "ReadSecretsManager"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [
      "arn:aws:secretsmanager:*:${data.aws_caller_identity.this.account_id}:secret:${trim(var.secrets_prefix, "/")}*"
    ]
  }
}

resource "aws_iam_policy" "read_params" {
  count       = var.allow_read_parameters ? 1 : 0
  name        = "${local.name_prefix}-read-params"
  description = "Read-only access to SSM Parameter Store and Secrets Manager (scoped prefixes)"
  policy      = data.aws_iam_policy_document.read_params[0].json
  tags        = local.common_tags
}

resource "aws_iam_role_policy_attachment" "read_params" {
  count      = var.allow_read_parameters ? 1 : 0
  role       = aws_iam_role.this.name
  policy_arn = aws_iam_policy.read_params[0].arn
}

resource "aws_iam_instance_profile" "this" {
  name = "${local.name_prefix}-instance-profile"
  role = aws_iam_role.this.name
  tags = local.common_tags
}

########################################
# Security Group (строгий по умолчанию)
########################################
resource "aws_security_group" "this" {
  name        = "${local.name_prefix}-sg"
  description = "Security group for ${var.name}"
  vpc_id      = var.vpc_id
  tags        = local.common_tags
}

# Разрешённые входящие подключения по указанным портам/сетям
resource "aws_security_group_rule" "ingress_allowed" {
  for_each = {
    for idx, rule in var.ingress_rules :
    idx => rule
  }

  type              = "ingress"
  security_group_id = aws_security_group.this.id
  from_port         = each.value.port
  to_port           = each.value.port
  protocol          = "tcp"
  cidr_blocks       = try(each.value.cidr_blocks, [])
  ipv6_cidr_blocks  = try(each.value.ipv6_cidr_blocks, [])
  description       = try(each.value.description, "ingress")
}

# Опционально SSH (по умолчанию выключен)
resource "aws_security_group_rule" "ingress_ssh" {
  count             = var.enable_ssh ? 1 : 0
  type              = "ingress"
  security_group_id = aws_security_group.this.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = var.ssh_cidrs
  description       = "ssh"
}

# Egress: только TLS (443) наружу
resource "aws_security_group_rule" "egress_tls" {
  for_each = toset(local.egress_tls_ports)
  type              = "egress"
  security_group_id = aws_security_group.this.id
  from_port         = each.value
  to_port           = each.value
  protocol          = "tcp"
  cidr_blocks       = var.egress_cidrs
  description       = "egress tls"
}

# Egress: NTP (123/udp) наружу
resource "aws_security_group_rule" "egress_ntp" {
  for_each = toset(local.egress_ntp_ports)
  type              = "egress"
  security_group_id = aws_security_group.this.id
  from_port         = each.value
  to_port           = each.value
  protocol          = "udp"
  cidr_blocks       = var.egress_cidrs
  description       = "egress ntp"
}

# Egress: DNS к резолверам VPC (53 tcp/udp к CIDR VPC)
resource "aws_security_group_rule" "egress_dns_tcp" {
  type              = "egress"
  security_group_id = aws_security_group.this.id
  from_port         = 53
  to_port           = 53
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  description       = "egress dns tcp to VPC"
}
resource "aws_security_group_rule" "egress_dns_udp" {
  type              = "egress"
  security_group_id = aws_security_group.this.id
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  cidr_blocks       = [var.vpc_cidr]
  description       = "egress dns udp to VPC"
}

########################################
# Launch Template (IMDSv2, KMS, monitoring)
########################################
resource "aws_launch_template" "this" {
  name_prefix   = "${local.name_prefix}-lt-"
  image_id      = local.effective_ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  update_default_version = true

  iam_instance_profile {
    name = aws_iam_instance_profile.this.name
  }

  network_interfaces {
    associate_public_ip_address = var.associate_public_ip
    security_groups             = [aws_security_group.this.id]
  }

  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 only
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  block_device_mappings {
    device_name = var.root_device_name
    ebs {
      volume_size           = var.root_volume_size
      volume_type           = var.root_volume_type
      encrypted             = true
      kms_key_id            = var.kms_key_id
      delete_on_termination = true
      iops                  = var.root_volume_iops
      throughput            = var.root_volume_throughput
    }
  }

  # Дополнительные диски (если заданы)
  dynamic "block_device_mappings" {
    for_each = var.extra_ebs
    content {
      device_name = block_device_mappings.value.device_name
      ebs {
        volume_size           = block_device_mappings.value.size
        volume_type           = coalesce(block_device_mappings.value.type, "gp3")
        iops                  = try(block_device_mappings.value.iops, null)
        throughput            = try(block_device_mappings.value.throughput, null)
        encrypted             = true
        kms_key_id            = var.kms_key_id
        delete_on_termination = true
      }
    }
  }

  # Юзер-дата: передаём только Base64 (секреты сюда не кладём)
  user_data = var.user_data_base64 != null ? var.user_data_base64 : (
    var.user_data != null ? base64encode(var.user_data) : null
  )

  tag_specifications {
    resource_type = "instance"
    tags          = local.common_tags
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.common_tags
  }

  tags = local.common_tags

  lifecycle {
    create_before_destroy = true
  }
}

########################################
# Auto Scaling Group (ASG / MixedInstancesPolicy)
########################################
resource "aws_autoscaling_group" "this" {
  name                      = "${local.name_prefix}-asg"
  vpc_zone_identifier       = var.subnet_ids
  min_size                  = var.min_size
  max_size                  = var.max_size
  desired_capacity          = var.desired_capacity
  capacity_rebalance        = true
  health_check_type         = var.target_group_arns != null && length(var.target_group_arns) > 0 ? "ELB" : "EC2"
  health_check_grace_period = var.health_check_grace_seconds

  termination_policies = [
    "OldestInstance",
    "OldestLaunchTemplate",
    "AllocationStrategy",
    "Default"
  ]

  enabled_metrics    = ["GroupDesiredCapacity", "GroupInServiceInstances", "GroupTotalInstances"]
  metrics_granularity = "1Minute"

  dynamic "launch_template" {
    for_each = local.use_mixed ? [] : [1]
    content {
      id      = aws_launch_template.this.id
      version = "$Latest"
    }
  }

  dynamic "mixed_instances_policy" {
    for_each = local.use_mixed ? [1] : []
    content {
      launch_template {
        launch_template_specification {
          launch_template_id = aws_launch_template.this.id
          version            = "$Latest"
        }
        dynamic "override" {
          for_each = concat([var.instance_type], var.additional_instance_types)
          content {
            instance_type = override.value
          }
        }
      }
      instances_distribution {
        on_demand_base_capacity                  = var.on_demand_base_capacity
        on_demand_percentage_above_base_capacity = var.on_demand_percentage_above_base
        spot_allocation_strategy                 = var.spot_allocation_strategy
        spot_instance_pools                      = var.spot_instance_pools
        spot_max_price                           = var.spot_max_price
      }
    }
  }

  target_group_arns = coalesce(var.target_group_arns, [])

  # Тег Name с распространением на инстансы
  tag {
    key                 = "Name"
    value               = local.common_tags["Name"]
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = { for k, v in local.common_tags : k => v if k != "Name" }
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes = [
      desired_capacity # позволяем внешним контроллерам менять desired
    ]
  }

  depends_on = [
    aws_iam_instance_profile.this
  ]
}

########################################
# Variables
########################################
variable "name" {
  description = "Имя/префикс ресурсов"
  type        = string
}

variable "vpc_id" {
  description = "ID VPC"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR VPC (для egress DNS правил)"
  type        = string
}

variable "subnet_ids" {
  description = "Список приватных подсетей для ASG"
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Нужно минимум две подсети для отказоустойчивости."
  }
}

variable "instance_type" {
  description = "Базовый тип инстанса"
  type        = string
  default     = "t3.medium"
}

variable "additional_instance_types" {
  description = "Дополнительные типы для MixedInstancesPolicy/Spot"
  type        = list(string)
  default     = []
}

variable "use_spot" {
  description = "Включить MixedInstancesPolicy/Spot"
  type        = bool
  default     = true
}

variable "on_demand_base_capacity" {
  description = "On-Demand база (шт.)"
  type        = number
  default     = 0
}

variable "on_demand_percentage_above_base" {
  description = "Доля On-Demand сверх базы (%)"
  type        = number
  default     = 20
}

variable "spot_allocation_strategy" {
  description = "Стратегия распределения Spot"
  type        = string
  default     = "capacity-optimized-prioritized"
}

variable "spot_instance_pools" {
  description = "Количество пулов Spot (для lowest-price)"
  type        = number
  default     = 2
}

variable "spot_max_price" {
  description = "Максимальная цена Spot (строка или null)"
  type        = string
  default     = null
}

variable "ami_id" {
  description = "ID AMI (если null — берём из SSM параметра)"
  type        = string
  default     = null
}

variable "ami_ssm_parameter" {
  description = "SSM параметр AMI (например, /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64)"
  type        = string
  default     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"
}

variable "key_name" {
  description = "Имя SSH ключа (опционально)"
  type        = string
  default     = null
}

variable "associate_public_ip" {
  description = "Ассоциировать публичный IP (обычно false для приватных подсетей)"
  type        = bool
  default     = false
}

variable "enable_detailed_monitoring" {
  description = "Включить детальный мониторинг EC2 (1‑минутный)"
  type        = bool
  default     = true
}

variable "root_device_name" {
  description = "Имя корневого устройства (обычно /dev/xvda)"
  type        = string
  default     = "/dev/xvda"
}

variable "root_volume_size" {
  description = "Размер корневого диска (GiB)"
  type        = number
  default     = 30
}

variable "root_volume_type" {
  description = "Тип корневого диска (gp3/gp2/io1/io2)"
  type        = string
  default     = "gp3"
}

variable "root_volume_iops" {
  description = "IOPS для gp3/io1/io2 (если применимо)"
  type        = number
  default     = 3000
}

variable "root_volume_throughput" {
  description = "Пропускная способность (MiB/s) для gp3"
  type        = number
  default     = 125
}

variable "extra_ebs" {
  description = "Дополнительные EBS диски"
  type = list(object({
    device_name = string
    size        = number
    type        = optional(string, "gp3")
    iops        = optional(number)
    throughput  = optional(number)
  }))
  default = []
}

variable "kms_key_id" {
  description = "KMS ключ для шифрования EBS (если null — аккаунт‑дефолт)"
  type        = string
  default     = null
}

variable "user_data" {
  description = "User data (cloud-init). Не помещайте сюда секреты."
  type        = string
  default     = null
  sensitive   = false
}

variable "user_data_base64" {
  description = "Готовый base64 user data (альтернатива user_data)"
  type        = string
  default     = null
  sensitive   = false
}

variable "ingress_rules" {
  description = "Список ingress правил: порт + CIDR/IPv6"
  type = list(object({
    port             = number
    cidr_blocks      = optional(list(string), [])
    ipv6_cidr_blocks = optional(list(string), [])
    description      = optional(string)
  }))
  default = [
    # Пример: HTTPS с LB подсетей/адресов (рекомендуется задавать в корне)
    # { port = 443, cidr_blocks = ["10.0.0.0/8"], description = "https from lb" }
  ]
}

variable "enable_ssh" {
  description = "Разрешить SSH (port 22) по ssh_cidrs"
  type        = bool
  default     = false
}

variable "ssh_cidrs" {
  description = "Сети с доступом по SSH"
  type        = list(string)
  default     = []
}

variable "egress_cidrs" {
  description = "Направления для egress TLS/NTP"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "min_size" {
  description = "Минимум инстансов"
  type        = number
  default     = 2
}

variable "max_size" {
  description = "Максимум инстансов"
  type        = number
  default     = 10
}

variable "desired_capacity" {
  description = "Желаемая мощность (может управляться внешним контроллером)"
  type        = number
  default     = 2
}

variable "health_check_grace_seconds" {
  description = "Grace‑период health check"
  type        = number
  default     = 120
}

variable "target_group_arns" {
  description = "Список Target Group ARNs для привязки (опционально)"
  type        = list(string)
  default     = null
}

variable "allow_read_parameters" {
  description = "Разрешить чтение параметров/секретов по префиксу"
  type        = bool
  default     = false
}

variable "parameters_prefix" {
  description = "Префикс SSM Parameter Store (например, /neurocity/security-core/)"
  type        = string
  default     = "/neurocity/security-core/"
}

variable "secrets_prefix" {
  description = "Префикс Secrets Manager (например, neurocity/security-core/)"
  type        = string
  default     = "neurocity/security-core/"
}

variable "tags" {
  description = "Дополнительные теги"
  type        = map(string)
  default     = {}
}

########################################
# Outputs
########################################
output "security_group_id" {
  description = "ID Security Group"
  value       = aws_security_group.this.id
}

output "launch_template_id" {
  description = "ID Launch Template"
  value       = aws_launch_template.this.id
}

output "autoscaling_group_name" {
  description = "Имя Auto Scaling Group"
  value       = aws_autoscaling_group.this.name
}

output "instance_profile_name" {
  description = "Имя Instance Profile"
  value       = aws_iam_instance_profile.this.name
}

output "iam_role_arn" {
  description = "ARN Instance Role"
  value       = aws_iam_role.this.arn
}
