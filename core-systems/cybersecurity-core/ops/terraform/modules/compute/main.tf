terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

############################################
# Data
############################################
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Опционально тянем AMI через SSM Parameter, если var.ami_id не задан
data "aws_ssm_parameter" "ami" {
  count = var.ami_id == null ? 1 : 0
  name  = var.ami_ssm_parameter_name
}

############################################
# Locals
############################################
locals {
  tags_base = {
    "app.kubernetes.io/name"       = coalesce(var.name, "cybersecurity-core")
    "app.kubernetes.io/part-of"    = "cybersecurity-core"
    "app.kubernetes.io/component"  = "compute"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  tags = merge(local.tags_base, var.tags)

  image_id = var.ami_id != null ? var.ami_id : (length(data.aws_ssm_parameter.ami) > 0 ? data.aws_ssm_parameter.ami[0].value : null)

  lt_name = "${var.name}-lt"
  asg_name = "${var.name}-asg"

  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupPendingInstances",
    "GroupStandbyInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]
}

############################################
# IAM: EC2 Role + Instance Profile
############################################
resource "aws_iam_role" "ec2" {
  name = "${var.name}-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

# Managed policies: SSM, CloudWatchAgent (опционально), ECR read-only
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cw_agent" {
  count      = var.enable_cloudwatch_agent ? 1 : 0
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "ecr_read" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# Доп. тонкие разрешения (опционально)
resource "aws_iam_role_policy" "extra_inline" {
  count = length(var.extra_inline_iam_statements) > 0 ? 1 : 0
  name  = "${var.name}-ec2-inline"
  role  = aws_iam_role.ec2.id
  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = var.extra_inline_iam_statements
  })
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.name}-instance-profile"
  role = aws_iam_role.ec2.name
  tags = local.tags
}

############################################
# Security Group (жёсткий по умолчанию)
############################################
resource "aws_security_group" "this" {
  name        = "${var.name}-sg"
  description = "Compute SG for ${var.name}"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-sg" })
}

# Ingress правила (декларативно через список объектов var.ingress_rules)
resource "aws_vpc_security_group_ingress_rule" "ingress_ipv4" {
  for_each          = { for r in var.ingress_rules : r.key => r if length(try(r.cidr_blocks, [])) > 0 }
  security_group_id = aws_security_group.this.id
  description       = try(each.value.description, null)
  cidr_ipv4         = one(each.value.cidr_blocks) # по одному правилу-ресурсу: указывайте по одному CIDR в r.cidr_blocks
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  ip_protocol       = each.value.protocol
}

resource "aws_vpc_security_group_ingress_rule" "ingress_ipv6" {
  for_each          = { for r in var.ingress_rules : r.key => r if length(try(r.ipv6_cidr_blocks, [])) > 0 }
  security_group_id = aws_security_group.this.id
  description       = try(each.value.description, null)
  cidr_ipv6         = one(each.value.ipv6_cidr_blocks)
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  ip_protocol       = each.value.protocol
}

resource "aws_vpc_security_group_ingress_rule" "ingress_sg" {
  for_each          = { for r in var.ingress_rules : r.key => r if length(try(r.security_group_ids, [])) > 0 }
  security_group_id = aws_security_group.this.id
  description       = try(each.value.description, null)
  referenced_security_group_id = one(each.value.security_group_ids)
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  ip_protocol       = each.value.protocol
}

# Egress правила: по умолчанию 443/80 на 0.0.0.0/0 и ::/0, можно ужесточать через vars
resource "aws_vpc_security_group_egress_rule" "egress_ipv4" {
  for_each          = toset(var.egress_cidrs)
  security_group_id = aws_security_group.this.id
  cidr_ipv4         = each.value
  ip_protocol       = "-1"
}

resource "aws_vpc_security_group_egress_rule" "egress_ipv6" {
  for_each          = toset(var.egress_ipv6_cidrs)
  security_group_id = aws_security_group.this.id
  cidr_ipv6         = each.value
  ip_protocol       = "-1"
}

resource "aws_vpc_security_group_egress_rule" "egress_prefix" {
  for_each                 = toset(var.egress_prefix_list_ids)
  security_group_id        = aws_security_group.this.id
  prefix_list_id           = each.value
  ip_protocol              = "-1"
}

############################################
# Launch Template (IMDSv2, KMS, hardening)
############################################
resource "aws_launch_template" "this" {
  name_prefix   = "${local.lt_name}-"
  image_id      = local.image_id
  instance_type = var.default_instance_type
  key_name      = var.key_name

  update_default_version = true

  # IMDSv2 only
  metadata_options {
    http_tokens              = "required"
    http_endpoint            = "enabled"
    http_put_response_hop_limit = 2
  }

  # Nitro Enclaves (опционально)
  enclave_options {
    enabled = var.enable_nitro_enclaves
  }

  # Instance Profile
  iam_instance_profile {
    name = aws_iam_instance_profile.this.name
  }

  # Network interfaces
  network_interfaces {
    associate_public_ip_address = var.associate_public_ip
    delete_on_termination       = true
    security_groups             = [aws_security_group.this.id]
  }

  # Root volume (EBS)
  block_device_mappings {
    device_name = var.root_block_device_name
    ebs {
      delete_on_termination = true
      volume_type           = var.root_volume_type
      volume_size           = var.root_volume_size
      encrypted             = true
      kms_key_id            = var.kms_key_id
      iops                  = var.root_volume_type == "io2" || var.root_volume_type == "io1" ? var.root_volume_iops : null
      throughput            = var.root_volume_type == "gp3" ? var.root_volume_throughput : null
    }
  }

  # Доп. диски
  dynamic "block_device_mappings" {
    for_each = var.additional_ebs_volumes
    content {
      device_name = block_device_mappings.value.device_name
      ebs {
        delete_on_termination = true
        volume_type           = try(block_device_mappings.value.volume_type, "gp3")
        volume_size           = block_device_mappings.value.volume_size
        encrypted             = true
        kms_key_id            = var.kms_key_id
        iops                  = try(block_device_mappings.value.iops, null)
        throughput            = try(block_device_mappings.value.throughput, null)
      }
    }
  }

  # User data (base64)
  user_data = var.user_data != null ? base64encode(var.user_data) : null

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.tags, {
      Name = "${var.name}-instance"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.tags, {
      Name = "${var.name}-volume"
    })
  }

  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  placement {
    group_name = var.placement_group_name
  }

  hibernation_options {
    configured = var.enable_hibernation
  }

  tags = merge(local.tags, { Name = local.lt_name })
}

############################################
# Auto Scaling Group (Mixed Instances)
############################################
resource "aws_autoscaling_group" "this" {
  name                      = local.asg_name
  vpc_zone_identifier       = var.subnet_ids
  min_size                  = var.min_size
  max_size                  = var.max_size
  desired_capacity          = var.desired_capacity
  health_check_type         = var.health_check_type
  health_check_grace_period = var.health_check_grace_period
  force_delete              = var.force_delete
  capacity_rebalance        = var.capacity_rebalance
  termination_policies      = var.termination_policies

  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.this.id
        version            = "$Latest"
      }

      # Перечень instance types по приоритету
      dynamic "override" {
        for_each = var.instance_types
        content {
          instance_type = override.value
          weighted_capacity = "1"
        }
      }
    }

    instances_distribution {
      on_demand_base_capacity                  = var.on_demand_base_capacity
      on_demand_percentage_above_base_capacity = var.on_demand_percentage_above_base_capacity
      spot_allocation_strategy                 = var.spot_allocation_strategy   # capacity-optimized-prioritized
      spot_instance_pools                      = var.spot_instance_pools
    }
  }

  # Привязка к Target Groups (ALB/NLB)
  target_group_arns = var.target_group_arns

  # Метрики группы
  metrics_granularity = "1Minute"
  enabled_metrics     = local.enabled_metrics

  # Теги, распространяемые на инстансы
  tag {
    key                 = "Name"
    value               = "${var.name}-asg"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = local.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes = [
      desired_capacity # позволяет внешним контроллерам управлять емкостью
    ]
  }

  depends_on = [aws_launch_template.this]
}

############################################
# Warm Pool (опционально)
############################################
resource "aws_autoscaling_warm_pool" "this" {
  count              = var.enable_warm_pool ? 1 : 0
  autoscaling_group_name = aws_autoscaling_group.this.name
  pool_state         = var.warm_pool_state   # Stopped | Running | Hibernated
  min_size           = var.warm_pool_min_size
}

############################################
# Target Tracking Policies (CPU / ALB RequestCountPerTarget)
############################################
resource "aws_autoscaling_policy" "cpu_tgt" {
  count                  = var.enable_target_tracking_cpu ? 1 : 0
  name                   = "${var.name}-cpu-target"
  autoscaling_group_name = aws_autoscaling_group.this.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value       = var.cpu_target_value
    disable_scale_in   = var.disable_scale_in
  }
}

resource "aws_autoscaling_policy" "alb_tgt" {
  count                  = var.enable_target_tracking_alb ? 1 : 0
  name                   = "${var.name}-alb-req-target"
  autoscaling_group_name = aws_autoscaling_group.this.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = var.alb_resource_label # формат: app/<alb-name>/<alb-id>/targetgroup/<tg-name>/<tg-id>
    }
    target_value     = var.alb_target_value
    disable_scale_in = var.disable_scale_in
  }
}

############################################
# Outputs
############################################
output "launch_template_id" {
  value       = aws_launch_template.this.id
  description = "Launch Template ID"
}

output "autoscaling_group_name" {
  value       = aws_autoscaling_group.this.name
  description = "ASG name"
}

output "security_group_id" {
  value       = aws_security_group.this.id
  description = "Security Group ID"
}

output "instance_profile_name" {
  value       = aws_iam_instance_profile.this.name
  description = "Instance profile name"
}
