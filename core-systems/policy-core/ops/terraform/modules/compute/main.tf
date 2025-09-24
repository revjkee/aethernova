terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws    = { source = "hashicorp/aws", version = ">= 5.50.0" }
    random = { source = "hashicorp/random", version = ">= 3.5.1" }
  }
}

############################
# Data & locals
############################

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

# Последний AMI Amazon Linux 2023 x86_64, если ami_id не задан
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"
}

locals {
  module_name   = coalesce(var.name, "policy-core-compute")
  common_tags = merge(
    {
      "Name"                       = local.module_name
      "app.kubernetes.io/name"     = "policy-core"
      "app.kubernetes.io/component"= "compute"
      "app.kubernetes.io/part-of"  = "neurocity"
      "environment"                = var.environment
      "owner"                      = var.owner
      "repo"                       = var.repo
    },
    var.tags
  )

  # Итоговый список типов инстансов для MixedInstancesPolicy (если включено)
  mixed_instance_types = length(var.mixed_instance_types) > 0 ? var.mixed_instance_types : [var.instance_type]
  ami_effective        = try(coalesce(var.ami_id, data.aws_ssm_parameter.al2023.value), data.aws_ssm_parameter.al2023.value)
}

resource "random_id" "suffix" {
  byte_length = 2
}

############################
# IAM (опционально)
############################

resource "aws_iam_role" "this" {
  count              = var.create_iam_role ? 1 : 0
  name               = "${local.module_name}-role-${random_id.suffix.hex}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["ec2.amazonaws.com"] }
  }
}

# Базовые права: SSM + чтение CloudWatch
resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.create_iam_role ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Опционально — CloudWatchAgentServerPolicy
resource "aws_iam_role_policy_attachment" "cw_agent" {
  count      = var.attach_cw_agent_policy && var.create_iam_role ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "this" {
  count = var.create_iam_role ? 1 : 0
  name  = "${local.module_name}-profile-${random_id.suffix.hex}"
  role  = aws_iam_role.this[0].name
  tags  = local.common_tags
}

############################
# Security Group
############################

resource "aws_security_group" "this" {
  name        = "${local.module_name}-sg"
  description = "SG for ${local.module_name}"
  vpc_id      = var.vpc_id
  tags        = local.common_tags

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
    description      = "Allow all egress"
  }
}

# Ingress от доверенных SG (обычно — ALB/NLB SG) к приложенческому порту
resource "aws_security_group_rule" "ingress_from_sg" {
  for_each                 = toset(var.ingress_from_sg_ids)
  type                     = "ingress"
  security_group_id        = aws_security_group.this.id
  from_port                = var.app_port
  to_port                  = var.app_port
  protocol                 = "tcp"
  source_security_group_id = each.value
  description              = "Allow app port from trusted SG"
}

# Опциональный SSH-доступ (ограниченный по CIDR)
resource "aws_security_group_rule" "ssh" {
  count             = length(var.allow_ssh_cidrs) > 0 ? 1 : 0
  type              = "ingress"
  security_group_id = aws_security_group.this.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = var.allow_ssh_cidrs
  description       = "Restricted SSH"
}

############################
# Launch Template
############################

resource "aws_launch_template" "this" {
  name_prefix   = "${local.module_name}-lt-"
  image_id      = local.ami_effective
  update_default_version = true

  instance_type = var.instance_type

  iam_instance_profile {
    name = var.create_iam_role ? aws_iam_instance_profile.this[0].name : var.instance_profile_name
  }

  vpc_security_group_ids = compact([aws_security_group.this.id] ++ var.additional_sg_ids)

  # IMDSv2 only
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  monitoring {
    enabled = true
  }

  ebs_optimized = true

  block_device_mappings {
    device_name = var.root_volume_device_name
    ebs {
      volume_size           = var.root_volume_size_gb
      volume_type           = var.root_volume_type
      encrypted             = true
      kms_key_id            = var.kms_key_arn
      delete_on_termination = true
      iops                  = var.root_volume_iops
      throughput            = var.root_volume_throughput
    }
  }

  # Дополнительные тома, если заданы
  dynamic "block_device_mappings" {
    for_each = var.extra_ebs_volumes
    content {
      device_name = block_device_mappings.value.device_name
      ebs {
        volume_size           = block_device_mappings.value.size_gb
        volume_type           = try(block_device_mappings.value.type, "gp3")
        encrypted             = true
        kms_key_id            = var.kms_key_arn
        delete_on_termination = true
        iops                  = try(block_device_mappings.value.iops, null)
        throughput            = try(block_device_mappings.value.throughput, null)
      }
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags          = local.common_tags
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.common_tags
  }
  tag_specifications {
    resource_type = "network-interface"
    tags          = local.common_tags
  }

  user_data = base64encode(var.user_data)

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

############################
# Auto Scaling Group
############################

resource "aws_autoscaling_group" "this" {
  name                      = "${local.module_name}-asg-${random_id.suffix.hex}"
  vpc_zone_identifier       = var.subnet_ids
  default_cooldown          = 60
  health_check_type         = "EC2"
  health_check_grace_period = 60
  min_size                  = var.min_size
  max_size                  = var.max_size
  desired_capacity          = var.desired_capacity
  termination_policies      = ["OldestInstance", "AllocationStrategy", "Default"]
  capacity_rebalance        = var.capacity_rebalance

  # Вариант 1: обычный ASG с LT
  launch_template {
    id      = aws_launch_template.this.id
    version = "$Latest"
  }

  # Вариант 2: Mixed Instances (Spot/OD). Включается, когда use_mixed_instances = true
  dynamic "mixed_instances_policy" {
    for_each = var.use_mixed_instances ? [1] : []
    content {
      launch_template {
        launch_template_specification {
          launch_template_id = aws_launch_template.this.id
          version            = "$Latest"
        }
        dynamic "override" {
          for_each = toset(local.mixed_instance_types)
          content {
            instance_type = override.key
          }
        }
      }
      instances_distribution {
        on_demand_percentage_above_base_capacity = var.on_demand_percentage
        spot_allocation_strategy                 = var.spot_allocation_strategy
        spot_max_price                           = var.spot_max_price
        spot_instance_pools                      = var.spot_instance_pools
      }
    }
  }

  dynamic "target_group_arns" {
    for_each = length(var.target_group_arns) > 0 ? [true] : []
    content  = var.target_group_arns
  }

  enabled_metrics = [
    "GroupMinSize", "GroupMaxSize", "GroupDesiredCapacity", "GroupInServiceInstances",
    "GroupTotalInstances", "GroupPendingInstances", "GroupTerminatingInstances",
  ]

  metrics_granularity = "1Minute"

  tag {
    key                 = "Name"
    value               = local.module_name
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 90
      instance_warmup        = 60
      skip_matching          = true
    }
    triggers = ["launch_template"]
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes = [
      desired_capacity # чтобы внешние скейлеры не дестабилизировали план
    ]
  }

  depends_on = [aws_launch_template.this]
}

############################
# Scaling policies & alarms
############################

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  count               = var.enable_cpu_policies ? 1 : 0
  alarm_name          = "${local.module_name}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 70
  alarm_description   = "Scale out when average CPU > 70% for 2 minutes"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.this.name
  }
  alarm_actions = [aws_autoscaling_policy.scale_out[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "cpu_low" {
  count               = var.enable_cpu_policies ? 1 : 0
  alarm_name          = "${local.module_name}-cpu-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  threshold           = 30
  alarm_description   = "Scale in when average CPU < 30% for 3 minutes"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.this.name
  }
  alarm_actions = [aws_autoscaling_policy.scale_in[0].arn]
}

resource "aws_autoscaling_policy" "scale_out" {
  count                  = var.enable_cpu_policies ? 1 : 0
  name                   = "${local.module_name}-scale-out"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.this.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = var.scale_out_step
  cooldown               = 60
}

resource "aws_autoscaling_policy" "scale_in" {
  count                  = var.enable_cpu_policies ? 1 : 0
  name                   = "${local.module_name}-scale-in"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.this.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = -1 * var.scale_in_step
  cooldown               = 120
}

############################
# Variables
############################

variable "name" {
  type        = string
  description = "Базовое имя ресурсов (Name tag, префиксы)."
  default     = null
}

variable "environment" {
  type        = string
  description = "Окружение (prod/staging/dev)."
  default     = "prod"
  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "environment должен быть 'prod', 'staging' или 'dev'."
  }
}

variable "owner" {
  type        = string
  description = "Ответственный владелец (e.g., platform-security)."
  default     = "platform-security"
}

variable "repo" {
  type        = string
  description = "Идентификатор репозитория/проекта."
  default     = "neurocity/policy-core"
}

variable "tags" {
  type        = map(string)
  description = "Дополнительные теги."
  default     = {}
}

variable "vpc_id" {
  type        = string
  description = "VPC ID, где создаются ресурсы."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Список subnet IDs для ASG."
  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "Необходимо указать как минимум одну подсеть."
  }
}

variable "instance_type" {
  type        = string
  description = "Тип инстанса EC2."
  default     = "t3.medium"
}

variable "mixed_instance_types" {
  type        = list(string)
  description = "Список типов инстансов для MixedInstancesPolicy (при use_mixed_instances=true)."
  default     = []
}

variable "use_mixed_instances" {
  type        = bool
  description = "Включить MixedInstancesPolicy (Spot/OD)."
  default     = false
}

variable "on_demand_percentage" {
  type        = number
  description = "Доля On-Demand при MixedInstancesPolicy."
  default     = 100
  validation {
    condition     = var.on_demand_percentage >= 0 && var.on_demand_percentage <= 100
    error_message = "on_demand_percentage должен быть от 0 до 100."
  }
}

variable "spot_allocation_strategy" {
  type        = string
  description = "Стратегия аллокации Spot."
  default     = "price-capacity-optimized"
}

variable "spot_max_price" {
  type        = string
  description = "Максимальная цена за Spot (пусто для on-demand price)."
  default     = null
}

variable "spot_instance_pools" {
  type        = number
  description = "Количество пулов Spot (для старых стратегий; может игнорироваться)."
  default     = 2
}

variable "capacity_rebalance" {
  type        = bool
  description = "Включить Capacity Rebalance для ASG."
  default     = true
}

variable "min_size" {
  type        = number
  description = "Минимальный размер ASG."
  default     = 2
}

variable "max_size" {
  type        = number
  description = "Максимальный размер ASG."
  default     = 6
}

variable "desired_capacity" {
  type        = number
  description = "Желаемый размер ASG."
  default     = 3
}

variable "app_port" {
  type        = number
  description = "Порт приложения на инстансах."
  default     = 8080
}

variable "ingress_from_sg_ids" {
  type        = list(string)
  description = "Список SG, которым разрешён доступ к app_port (обычно — SG балансировщика)."
  default     = []
}

variable "allow_ssh_cidrs" {
  type        = list(string)
  description = "Список CIDR для SSH 22/tcp. Оставьте пустым для отключения."
  default     = []
}

variable "additional_sg_ids" {
  type        = list(string)
  description = "Дополнительные SG для инстансов."
  default     = []
}

variable "target_group_arns" {
  type        = list(string)
  description = "Список Target Group ARNs для регистрации инстансов."
  default     = []
}

variable "ami_id" {
  type        = string
  description = "Явный AMI ID. Если не задан, берётся последний Amazon Linux 2023 из SSM."
  default     = null
}

variable "user_data" {
  type        = string
  description = "User data (cloud-init)."
  default     = <<-EOT
                #!/bin/bash
                set -euo pipefail
                # Пример минимальной инициализации
                dnf -y update || true
                dnf -y install amazon-cloudwatch-agent || true
                systemctl enable amazon-cloudwatch-agent || true
                EOT
}

variable "root_volume_device_name" {
  type        = string
  description = "Имя корневого устройства."
  default     = "/dev/xvda"
}

variable "root_volume_size_gb" {
  type        = number
  description = "Размер корневого тома (GiB)."
  default     = 20
}

variable "root_volume_type" {
  type        = string
  description = "Тип EBS для корневого тома."
  default     = "gp3"
}

variable "root_volume_iops" {
  type        = number
  description = "IOPS для gp3 (или null)."
  default     = 3000
}

variable "root_volume_throughput" {
  type        = number
  description = "Пропускная способность для gp3 (MiB/s)."
  default     = 125
}

variable "extra_ebs_volumes" {
  description = <<-DESC
    Дополнительные тома EBS: список объектов:
    [{ device_name = "/dev/xvdb", size_gb = 50, type = "gp3", iops = 3000, throughput = 125 }, ...]
  DESC
  type        = list(object({
    device_name = string
    size_gb     = number
    type        = optional(string)
    iops        = optional(number)
    throughput  = optional(number)
  }))
  default = []
}

variable "kms_key_arn" {
  type        = string
  description = "KMS Key ARN для шифрования EBS (если null — managed key)."
  default     = null
}

variable "create_iam_role" {
  type        = bool
  description = "Создавать ли IAM Role/Instance Profile внутри модуля."
  default     = true
}

variable "instance_profile_name" {
  type        = string
  description = "Имя существующего Instance Profile (если create_iam_role=false)."
  default     = null
}

variable "attach_cw_agent_policy" {
  type        = bool
  description = "Прикрепить AWS CloudWatchAgentServerPolicy к роли (если она создаётся)."
  default     = true
}

variable "enable_cpu_policies" {
  type        = bool
  description = "Включить CloudWatch-политики масштабирования по CPU."
  default     = true
}

variable "scale_out_step" {
  type        = number
  description = "Шаг масштабирования при росте CPU."
  default     = 1
}

variable "scale_in_step" {
  type        = number
  description = "Шаг масштабирования при падении CPU."
  default     = 1
}

############################
# Outputs
############################

output "asg_name" {
  value       = aws_autoscaling_group.this.name
  description = "Имя Auto Scaling Group."
}

output "launch_template_id" {
  value       = aws_launch_template.this.id
  description = "ID Launch Template."
}

output "security_group_id" {
  value       = aws_security_group.this.id
  description = "ID Security Group."
}

output "instance_profile_name" {
  value       = var.create_iam_role ? aws_iam_instance_profile.this[0].name : var.instance_profile_name
  description = "Имя Instance Profile, используемого инстансами."
}

output "iam_role_arn" {
  value       = var.create_iam_role ? aws_iam_role.this[0].arn : null
  description = "ARN IAM роли (если создавалась модулем)."
}

output "ami_used" {
  value       = local.ami_effective
  description = "AMI ID, использованный в Launch Template."
}

output "target_group_arns" {
  value       = var.target_group_arns
  description = "Список Target Group ARNs, прикреплённых к ASG."
}
