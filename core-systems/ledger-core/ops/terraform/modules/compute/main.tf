terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    template = {
      source  = "hashicorp/template"
      version = ">= 2.2.0"
    }
  }
}

# -----------------------------
# VARIABLES
# -----------------------------
variable "name" {
  description = "Базовое имя ресурсов (префикс)."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "subnet_ids" {
  description = "Список подсетей для ASG."
  type        = list(string)
}

variable "tags" {
  description = "Дополнительные теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "desired_capacity" {
  description = "Желаемое количество инстансов."
  type        = number
  default     = 2
}

variable "min_size" {
  description = "Минимальный размер ASG."
  type        = number
  default     = 2
}

variable "max_size" {
  description = "Максимальный размер ASG."
  type        = number
  default     = 6
}

variable "health_check_type" {
  description = "Тип health check (EC2 или ELB)."
  type        = string
  default     = "EC2"
  validation {
    condition     = contains(["EC2", "ELB"], var.health_check_type)
    error_message = "health_check_type must be EC2 or ELB."
  }
}

variable "health_check_grace_period" {
  description = "Grace период health check, сек."
  type        = number
  default     = 300
}

variable "termination_policies" {
  description = "Политики терминации ASG."
  type        = list(string)
  default     = ["OldestLaunchTemplate", "OldestInstance", "Default"]
}

variable "protect_from_scale_in" {
  description = "Защищать инстансы от scale‑in."
  type        = bool
  default     = false
}

variable "enable_public_ip" {
  description = "Выдавать публичный IP (для public subnet/нативного доступа)."
  type        = bool
  default     = false
}

variable "ami_id" {
  description = "Явный AMI ID (если пусто — берём последний Amazon Linux 2023)."
  type        = string
  default     = ""
}

variable "instance_types" {
  description = "Список допустимых типов инстансов (для MixedInstancesPolicy). Первый — приоритетный OD."
  type        = list(string)
  default     = ["m7g.large", "m6g.large", "t4g.large", "c7g.large"]
}

variable "use_mixed_instances" {
  description = "Включить MixedInstancesPolicy (Spot + OnDemand)."
  type        = bool
  default     = true
}

variable "on_demand_base_capacity" {
  description = "MIP: базовое количество OD инстансов."
  type        = number
  default     = 1
}

variable "on_demand_percentage_above_base_capacity" {
  description = "MIP: процент OD выше базовой ёмкости."
  type        = number
  default     = 50
}

variable "spot_max_price" {
  description = "Максимальная цена за Spot (пусто = по умолчанию провайдера)."
  type        = string
  default     = ""
}

variable "key_name" {
  description = "Имя SSH key pair (опционально)."
  type        = string
  default     = null
}

variable "security_group_ingress" {
  description = "Правила ingress: { from_port, to_port, protocol, cidr_blocks }."
  type = list(object({
    description = optional(string, "")
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  default = []
}

variable "security_group_egress_all" {
  description = "Разрешить весь исходящий трафик."
  type        = bool
  default     = true
}

variable "additional_security_group_ids" {
  description = "Дополнительные SG IDs для инстансов."
  type        = list(string)
  default     = []
}

variable "root_volume_size" {
  description = "Размер корневого EBS (ГБ)."
  type        = number
  default     = 30
}

variable "root_volume_type" {
  description = "Тип EBS тома."
  type        = string
  default     = "gp3"
}

variable "root_volume_iops" {
  description = "IOPS для gp3/io* (0 = по умолчанию)."
  type        = number
  default     = 3000
}

variable "root_volume_throughput" {
  description = "Пропускная способность gp3 (МБ/с)."
  type        = number
  default     = 125
}

variable "extra_ebs_volumes" {
  description = "Доп. тома EBS."
  type = list(object({
    device_name           = string
    size                  = number
    type                  = string
    iops                  = optional(number)
    throughput            = optional(number)
    encrypted             = optional(bool, true)
    delete_on_termination = optional(bool, true)
  }))
  default = []
}

variable "enable_ssm" {
  description = "Прикреплять SSM Core для доступа/управления."
  type        = bool
  default     = true
}

variable "enable_cw_agent" {
  description = "Устанавливать CloudWatch Agent для метрик/логов."
  type        = bool
  default     = true
}

variable "user_data" {
  description = "Доп. user_data (bash cloud‑init), будет выполнен после базовой части."
  type        = string
  default     = ""
}

variable "target_group_arns" {
  description = "Список Target Group ARNs для регистрации ASG (ALB/NLB)."
  type        = list(string)
  default     = []
}

variable "desired_warm_pool_size" {
  description = "Размер warm pool (0 — не использовать)."
  type        = number
  default     = 0
}

variable "block_device_kms_key_id" {
  description = "KMS Key ID для шифрования EBS (если пусто — default KMS)."
  type        = string
  default     = null
}

variable "enable_instance_metadata_tags" {
  description = "Экспорт тегов инстанса в метаданные (IMDSv2)."
  type        = bool
  default     = true
}

variable "alb_healthcheck_grace" {
  description = "Доп. грейс для ELB health check в секундах (0 — без изменений)."
  type        = number
  default     = 0
}

# -----------------------------
# DATA / LOCALS
# -----------------------------
data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

# Latest Amazon Linux 2023 AMI (если ami_id не задан)
data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-arm64"
}

locals {
  module_tags = merge(
    {
      "Name"                         = var.name
      "ManagedBy"                    = "terraform"
      "terraform.io/module"          = "ledger-core/compute"
      "Environment"                  = "prod"
      "Application"                  = "ledger-core"
      "CostCenter"                   = "ledger"
    },
    var.tags
  )

  resolved_ami = var.ami_id != "" ? var.ami_id : data.aws_ssm_parameter.al2023_ami.value

  lt_user_data = base64encode(join("\n", compact([
    "#!/bin/bash",
    "set -euo pipefail",
    "echo '==> Bootstrapping ledger-core compute'",
    # Включаем IMDSv2 строгость (система по умолчанию на AL2023)
    "sysctl -w net.ipv4.ip_forward=1 || true",
    var.enable_ssm ? "systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service || systemctl enable --now amazon-ssm-agent || true" : "",
    var.enable_cw_agent ? <<-EOF
      dnf install -y amazon-cloudwatch-agent || yum install -y amazon-cloudwatch-agent || true
      cat >/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'CWCFG'
      {
        "metrics": {
          "aggregation_dimensions": [["AutoScalingGroupName"]],
          "metrics_collected": {
            "mem": {"measurement": ["mem_used_percent"]},
            "disk": {"measurement": ["used_percent"], "resources": ["*"]}
          }
        },
        "logs": {
          "logs_collected": {
            "files": {
              "collect_list": [
                {"file_path": "/var/log/messages", "log_group_name": "/ledger-core/messages", "log_stream_name": "{instance_id}"},
                {"file_path": "/var/log/cloud-init.log", "log_group_name": "/ledger-core/cloud-init", "log_stream_name": "{instance_id}"}
              ]
            }
          }
        }
      }
CWCFG
      systemctl enable --now amazon-cloudwatch-agent || true
    EOF
    : ""),
    var.user_data != "" ? var.user_data : "",
    "echo '==> Bootstrap complete'"
  ])))

  # SG правила egress
  egress_rules = var.security_group_egress_all ? [{
    description = "all egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }] : []
}

# -----------------------------
# IAM: роль для EC2 (минимум SSM, опц. CloudWatchAgent)
# -----------------------------
data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.name}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  tags               = local.module_tags
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  count      = var.enable_ssm ? 1 : 0
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cw_agent" {
  count      = var.enable_cw_agent ? 1 : 0
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.name}-instance-profile"
  role = aws_iam_role.this.name
  tags = local.module_tags
}

# -----------------------------
# SECURITY GROUP
# -----------------------------
resource "aws_security_group" "this" {
  name        = "${var.name}-sg"
  description = "Security Group for ${var.name}"
  vpc_id      = var.vpc_id
  tags        = local.module_tags

  dynamic "ingress" {
    for_each = var.security_group_ingress
    content {
      description = lookup(ingress.value, "description", null)
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }

  dynamic "egress" {
    for_each = local.egress_rules
    content {
      description = egress.value.description
      from_port   = egress.value.from_port
      to_port     = egress.value.to_port
      protocol    = egress.value.protocol
      cidr_blocks = egress.value.cidr_blocks
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------
# LAUNCH TEMPLATE
# -----------------------------
resource "aws_launch_template" "this" {
  name_prefix   = "${var.name}-lt-"
  image_id      = local.resolved_ami
  instance_type = var.instance_types[0]
  key_name      = var.key_name

  update_default_version = true

  iam_instance_profile {
    name = aws_iam_instance_profile.this.name
  }

  vpc_security_group_ids = concat([aws_security_group.this.id], var.additional_security_group_ids)

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 strict
    http_put_response_hop_limit = 2
    instance_metadata_tags      = var.enable_instance_metadata_tags ? "enabled" : "disabled"
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.root_volume_size
      volume_type           = var.root_volume_type
      iops                  = var.root_volume_type == "gp3" ? var.root_volume_iops : null
      throughput            = var.root_volume_type == "gp3" ? var.root_volume_throughput : null
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = var.block_device_kms_key_id
    }
  }

  dynamic "block_device_mappings" {
    for_each = var.extra_ebs_volumes
    content {
      device_name = block_device_mappings.value.device_name
      ebs {
        volume_size           = block_device_mappings.value.size
        volume_type           = block_device_mappings.value.type
        iops                  = try(block_device_mappings.value.iops, null)
        throughput            = try(block_device_mappings.value.throughput, null)
        delete_on_termination = try(block_device_mappings.value.delete_on_termination, true)
        encrypted             = try(block_device_mappings.value.encrypted, true)
        kms_key_id            = var.block_device_kms_key_id
      }
    }
  }

  network_interfaces {
    associate_public_ip_address = var.enable_public_ip
    security_groups             = concat([aws_security_group.this.id], var.additional_security_group_ids)
    delete_on_termination       = true
  }

  user_data = local.lt_user_data

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.module_tags, { "Role" = "compute" })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = local.module_tags
  }

  tags = local.module_tags

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------
# AUTO SCALING GROUP
# -----------------------------
resource "aws_autoscaling_group" "this" {
  name                      = "${var.name}-asg"
  vpc_zone_identifier       = var.subnet_ids
  desired_capacity          = var.desired_capacity
  min_size                  = var.min_size
  max_size                  = var.max_size
  health_check_type         = var.health_check_type
  health_check_grace_period = var.health_check_grace_period
  termination_policies      = var.termination_policies
  target_group_arns         = var.target_group_arns
  protect_from_scale_in     = var.protect_from_scale_in

  # Для ELB healthcheck можно добавить доп. grace
  timeouts {
    delete = "20m"
  }

  launch_template {
    id      = aws_launch_template.this.id
    version = "$Latest"
  }

  dynamic "mixed_instances_policy" {
    for_each = var.use_mixed_instances ? [1] : []
    content {
      launch_template {
        launch_template_specification {
          launch_template_id = aws_launch_template.this.id
          version            = "$Latest"
        }
        dynamic "override" {
          for_each = var.instance_types
          content {
            instance_type = override.value
          }
        }
      }
      instances_distribution {
        on_demand_base_capacity                  = var.on_demand_base_capacity
        on_demand_percentage_above_base_capacity = var.on_demand_percentage_above_base_capacity
        spot_allocation_strategy                 = "lowest-price"
        spot_instance_pools                      = 4
        spot_max_price                           = var.spot_max_price != "" ? var.spot_max_price : null
      }
    }
  }

  dynamic "warm_pool" {
    for_each = var.desired_warm_pool_size > 0 ? [1] : []
    content {
      pool_state                  = "Stopped"
      min_size                    = var.desired_warm_pool_size
      max_group_prepared_capacity = var.desired_capacity
    }
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes = [
      desired_capacity # позволяет внешнему авто‑скейлеру менять ёмкость
    ]
  }

  tag {
    key                 = "Name"
    value               = "${var.name}-asg"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = local.module_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

# -----------------------------
# OPTIONAL: Тонкая настройка для ELB health check grace
# -----------------------------
resource "aws_autoscaling_group_tag" "elb_grace_hint" {
  count               = var.alb_healthcheck_grace > 0 ? 1 : 0
  autoscaling_group_name = aws_autoscaling_group.this.name
  tag {
    key                 = "elb.healthcheck.grace"
    value               = tostring(var.alb_healthcheck_grace)
    propagate_at_launch = true
  }
}

# -----------------------------
# OUTPUTS
# -----------------------------
output "asg_name" {
  description = "Имя AutoScaling Group."
  value       = aws_autoscaling_group.this.name
}

output "launch_template_id" {
  description = "ID Launch Template."
  value       = aws_launch_template.this.id
}

output "security_group_id" {
  description = "ID Security Group."
  value       = aws_security_group.this.id
}

output "instance_profile_name" {
  description = "Имя IAM Instance Profile."
  value       = aws_iam_instance_profile.this.name
}

output "iam_role_name" {
  description = "Имя роли EC2."
  value       = aws_iam_role.this.name
}

output "ami_id" {
  description = "Использованный AMI ID."
  value       = local.resolved_ami
}

output "target_group_arns" {
  description = "Target Groups, к которым прикреплена ASG."
  value       = var.target_group_arns
}

# -----------------------------
# EXAMPLE USAGE (для справки)
# -----------------------------
# module "compute" {
#   source  = "./ops/terraform/modules/compute"
#   name    = "ledger-core-compute"
#   vpc_id  = aws_vpc.main.id
#   subnet_ids = [aws_subnet.app_a.id, aws_subnet.app_b.id]
#
#   security_group_ingress = [
#     { description = "HTTP", from_port = 80,  to_port = 80,  protocol = "tcp", cidr_blocks = ["0.0.0.0/0"] },
#     { description = "HTTPS",from_port = 443, to_port = 443, protocol = "tcp", cidr_blocks = ["0.0.0.0/0"] }
#   ]
#
#   instance_types = ["m7g.large","t4g.large","c7g.large"]
#   desired_capacity = 3
#   target_group_arns = [aws_lb_target_group.api.arn]
#   tags = { Environment = "prod", Application = "ledger-core" }
# }
