# path: veilmind-core/ops/terraform/modules/compute/main.tf
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.35.0"
    }
  }
}

#############################
# ВХОДНЫЕ ПЕРЕМЕННЫЕ
#############################

variable "name" {
  description = "Базовое имя ресурсов (будет использовано в тегах/имени SG/ASG/LT)."
  type        = string
}

variable "vpc_id" {
  description = "ID VPC."
  type        = string
}

variable "subnet_ids" {
  description = "Список приватных/публичных подсетей для ASG."
  type        = list(string)
}

variable "instance_types" {
  description = "Список типов инстансов для Mixed Instances Policy (первый — приоритетный)."
  type        = list(string)
  default     = ["m6i.large", "m6a.large", "m5.large"]
}

variable "ami_id" {
  description = "Явный AMI ID. Если пусто, берётся из SSM параметра ami_ssm_parameter."
  type        = string
  default     = ""
}

variable "ami_ssm_parameter" {
  description = "SSM параметр с последним AMI (Amazon Linux 2023 x86_64 по умолчанию)."
  type        = string
  default     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

variable "iam_instance_profile_arn" {
  description = "Существующий IAM Instance Profile ARN. Если пусто — будет создан."
  type        = string
  default     = ""
}

variable "create_cw_agent_permissions" {
  description = "Добавлять CloudWatchAgentServerPolicy к IAM роли."
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "KMS key id/arn для EBS. Если пусто — используется account default EBS encryption."
  type        = string
  default     = ""
}

variable "associate_public_ip" {
  description = "Назначать публичный IP сетевому интерфейсу."
  type        = bool
  default     = false
}

variable "min_size" {
  type        = number
  default     = 2
  description = "Минимальный размер ASG."
}

variable "desired_capacity" {
  type        = number
  default     = 3
  description = "Желаемый размер ASG (может изменяться политиками)."
}

variable "max_size" {
  type        = number
  default     = 6
  description = "Максимальный размер ASG."
}

variable "enable_spot" {
  description = "Включить использование Spot в Mixed Instances."
  type        = bool
  default     = true
}

variable "on_demand_base_capacity" {
  description = "Базовая On‑Demand емкость перед использованием Spot."
  type        = number
  default     = 1
}

variable "on_demand_percentage_above_base" {
  description = "Доля On‑Demand сверх базовой (0..100)."
  type        = number
  default     = 50
}

variable "alb_target_group_arns" {
  description = "Список Target Group ARNs для присоединения ASG."
  type        = list(string)
  default     = []
}

variable "enable_detailed_monitoring" {
  type        = bool
  default     = true
  description = "EC2 Detailed Monitoring."
}

variable "scaling_cpu_target" {
  description = "Целевое значение CPU для target tracking."
  type        = number
  default     = 45
}

variable "health_check_grace_period" {
  description = "Grace period (сек) для health checks."
  type        = number
  default     = 300
}

variable "enable_instance_refresh" {
  description = "Включить Instance Refresh при изменении LT."
  type        = bool
  default     = true
}

variable "warm_pool_size" {
  description = "Размер warm pool (0 — отключено)."
  type        = number
  default     = 0
}

variable "max_instance_lifetime" {
  description = "Максимальный срок жизни инстанса (сек). 0 — нет ограничения."
  type        = number
  default     = 0
}

variable "termination_policies" {
  description = "Порядок завершения инстансов."
  type        = list(string)
  default     = ["OldestLaunchConfiguration", "OldestInstance", "ClosestToNextInstanceHour"]
}

variable "capacity_rebalance" {
  description = "Включить capacity rebalance для Spot."
  type        = bool
  default     = true
}

variable "security_group_additional_ids" {
  description = "Дополнительные SG для NIC."
  type        = list(string)
  default     = []
}

variable "ingress_rules" {
  description = <<EOT
Список правил ingress для создаваемого SG.
Элемент: { description, protocol, from_port, to_port, cidrs (list), security_groups (list) }
EOT
  type = list(object({
    description     = optional(string, "")
    protocol        = optional(string, "tcp")
    from_port       = number
    to_port         = number
    cidrs           = optional(list(string), [])
    security_groups = optional(list(string), [])
  }))
  default = []
}

variable "root_volume_size_gb" {
  description = "Размер корневого EBS (GiB)."
  type        = number
  default     = 30
}

variable "root_volume_type" {
  description = "Тип корневого EBS."
  type        = string
  default     = "gp3"
}

variable "ebs_iops" {
  description = "IOPS для gp3/io1 при необходимости."
  type        = number
  default     = 3000
}

variable "ebs_throughput" {
  description = "Throughput для gp3 (MiB/s)."
  type        = number
  default     = 125
}

variable "key_name" {
  description = "Имя SSH key pair (опционально)."
  type        = string
  default     = ""
}

variable "metadata_http_put_response_hop_limit" {
  type        = number
  default     = 2
  description = "IMDS hop limit."
}

variable "tags" {
  description = "Дополнительные теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "user_data" {
  description = "Переопределить cloud-init user_data (base64 будет применён автоматически)."
  type        = string
  default     = ""
}

#############################
# ЛОКАЛЫ / AMI / ТЕГИ
#############################

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

data "aws_ssm_parameter" "ami" {
  count = var.ami_id == "" ? 1 : 0
  name  = var.ami_ssm_parameter
}

locals {
  ami_id      = var.ami_id != "" ? var.ami_id : one(data.aws_ssm_parameter.ami[*].value)
  common_tags = merge(
    {
      "Name"        = var.name
      "Project"     = "veilmind-core"
      "ManagedBy"   = "Terraform"
      "Environment" = "prod"
    },
    var.tags
  )

  # Безопасный user-data по умолчанию (минимум — обновления, включение IMDSv2 check, cw‑agent по желанию)
  user_data_default = <<-EOF
    #cloud-config
    package_update: true
    package_upgrade: true
    write_files:
      - path: /etc/sysctl.d/99-veilmind.conf
        permissions: "0644"
        owner: root
        content: |
          net.ipv4.tcp_syncookies = 1
          net.ipv4.conf.all.accept_redirects = 0
          net.ipv4.conf.all.send_redirects = 0
          net.ipv4.conf.all.accept_source_route = 0
          net.ipv6.conf.all.accept_redirects = 0
          net.ipv6.conf.all.accept_source_route = 0
          kernel.kptr_restrict = 2
          kernel.dmesg_restrict = 1
    runcmd:
      - sysctl --system || true
      - systemctl restart systemd-journald || true
    EOF

  user_data_final = base64encode(coalesce(trimspace(var.user_data), trimspace(local.user_data_default)))
  health_check_type = length(var.alb_target_group_arns) > 0 ? "ELB" : "EC2"
}

#############################
# IAM ROLE / INSTANCE PROFILE
#############################

resource "aws_iam_role" "this" {
  count = var.iam_instance_profile_arn == "" ? 1 : 0
  name  = "${var.name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.iam_instance_profile_arn == "" ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cw_agent" {
  count      = var.iam_instance_profile_arn == "" && var.create_cw_agent_permissions ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "this" {
  count = var.iam_instance_profile_arn == "" ? 1 : 0
  name  = "${var.name}-profile"
  role  = aws_iam_role.this[0].name
  tags  = local.common_tags
}

#############################
# SECURITY GROUP
#############################

resource "aws_security_group" "this" {
  name        = "${var.name}-sg"
  description = "Security group for ${var.name}"
  vpc_id      = var.vpc_id
  tags        = local.common_tags

  egress {
    description = "Allow all egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# Динамические ingress правила
resource "aws_vpc_security_group_ingress_rule" "custom_cidr" {
  for_each          = { for i, r in var.ingress_rules : "cidr-${i}" => r if length(try(r.cidrs, [])) > 0 }
  security_group_id = aws_security_group.this.id
  cidr_ipv4         = length(each.value.cidrs) > 0 ? each.value.cidrs[0] : null
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  ip_protocol       = each.value.protocol
  description       = try(each.value.description, null)
  # Для списков >1 можно добавить ещё правила при необходимости через flatten, упрощено для читаемости
}

resource "aws_vpc_security_group_ingress_rule" "custom_sg" {
  for_each                       = { for i, r in var.ingress_rules : "sg-${i}" => r if length(try(r.security_groups, [])) > 0 }
  security_group_id              = aws_security_group.this.id
  referenced_security_group_id   = each.value.security_groups[0]
  from_port                      = each.value.from_port
  to_port                        = each.value.to_port
  ip_protocol                    = each.value.protocol
  description                    = try(each.value.description, null)
}

#############################
# LAUNCH TEMPLATE
#############################

resource "aws_launch_template" "this" {
  name_prefix   = "${var.name}-lt-"
  image_id      = local.ami_id
  instance_type = var.instance_types[0]

  ebs_optimized = true
  key_name      = var.key_name != "" ? var.key_name : null

  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  iam_instance_profile {
    arn  = var.iam_instance_profile_arn != "" ? var.iam_instance_profile_arn : null
    name = var.iam_instance_profile_arn == "" ? aws_iam_instance_profile.this[0].name : null
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = var.metadata_http_put_response_hop_limit
    instance_metadata_tags      = "disabled"
  }

  enclave_options {
    enabled = false
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.root_volume_size_gb
      volume_type           = var.root_volume_type
      iops                  = var.root_volume_type == "gp3" ? var.ebs_iops : null
      throughput            = var.root_volume_type == "gp3" ? var.ebs_throughput : null
      encrypted             = true
      kms_key_id            = var.kms_key_id != "" ? var.kms_key_id : null
      delete_on_termination = true
    }
  }

  network_interfaces {
    security_groups             = concat([aws_security_group.this.id], var.security_group_additional_ids)
    associate_public_ip_address = var.associate_public_ip
    delete_on_termination       = true
  }

  user_data = local.user_data_final

  tag_specifications {
    resource_type = "instance"
    tags          = local.common_tags
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      "Backup" = "true"
    })
  }

  tags = local.common_tags
}

#############################
# AUTO SCALING GROUP
#############################

resource "aws_autoscaling_group" "this" {
  name                      = "${var.name}-asg"
  vpc_zone_identifier       = var.subnet_ids
  min_size                  = var.min_size
  max_size                  = var.max_size
  desired_capacity          = var.desired_capacity
  health_check_type         = local.health_check_type
  health_check_grace_period = var.health_check_grace_period
  target_group_arns         = var.alb_target_group_arns
  capacity_rebalance        = var.capacity_rebalance
  force_delete              = false
  max_instance_lifetime     = var.max_instance_lifetime > 0 ? var.max_instance_lifetime : null

  metrics_granularity = "1Minute"
  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances",
    "GroupPendingInstances",
    "GroupStandbyInstances",
    "GroupTerminatingInstances",
    "GroupInServiceCapacity",
    "GroupPendingCapacity",
    "GroupStandbyCapacity",
    "GroupTerminatingCapacity",
    "WarmPoolDesiredCapacity",
    "WarmPoolWarmedCapacity",
    "WarmPoolPendingCapacity",
    "WarmPoolTerminatingCapacity"
  ]

  dynamic "mixed_instances_policy" {
    for_each = toset(["use"])
    content {
      launch_template {
        launch_template_specification {
          launch_template_id = aws_launch_template.this.id
          version            = "$Latest"
        }
        dynamic "override" {
          for_each = toset(var.instance_types)
          content {
            instance_type     = override.value
            weighted_capacity = "1"
          }
        }
      }
      instances_distribution {
        on_demand_allocation_strategy            = "lowest-price"
        on_demand_base_capacity                  = var.on_demand_base_capacity
        on_demand_percentage_above_base_capacity = var.enable_spot ? var.on_demand_percentage_above_base : 100
        spot_allocation_strategy                 = "price-capacity-optimized"
        spot_max_price                           = ""  # по рыночной цене
      }
    }
  }

  dynamic "warm_pool" {
    for_each = var.warm_pool_size > 0 ? toset(["pool"]) : []
    content {
      pool_state                  = "Stopped"
      min_size                    = var.warm_pool_size
      max_group_prepared_capacity = var.max_size
    }
  }

  dynamic "instance_refresh" {
    for_each = var.enable_instance_refresh ? toset(["ref"]) : []
    content {
      strategy = "Rolling"
      preferences {
        min_healthy_percentage = 90
        instance_warmup        = 300
        skip_matching          = true
        auto_rollback          = true
      }
      triggers = ["launch_template"]
    }
  }

  termination_policies = var.termination_policies

  tag {
    key                 = "Name"
    value               = var.name
    propagate_at_launch = true
  }

  lifecycle {
    ignore_changes = [desired_capacity]
  }

  depends_on = [aws_launch_template.this]
  tags       = local.common_tags
}

#############################
# SCALING POLICY (CPU TARGET)
#############################

resource "aws_autoscaling_policy" "cpu_tgt" {
  name                   = "${var.name}-cpu-target"
  autoscaling_group_name = aws_autoscaling_group.this.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value       = var.scaling_cpu_target
    disable_scale_in   = false
    scale_in_cooldown  = 120
    scale_out_cooldown = 60
  }
}

#############################
# ВЫХОДЫ
#############################

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
  description = "ID созданного Security Group."
}

output "instance_profile_arn" {
  value       = var.iam_instance_profile_arn != "" ? var.iam_instance_profile_arn : aws_iam_instance_profile.this[0].arn
  description = "ARN Instance Profile, которым пользуется LT."
}

output "ami_id" {
  value       = local.ami_id
  description = "Используемый AMI ID."
}
