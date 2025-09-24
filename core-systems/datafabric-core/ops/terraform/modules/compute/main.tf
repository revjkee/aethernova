// datafabric-core / ops / terraform / modules / compute / main.tf
// Промышленный модуль AWS Compute Pool (ASG + Launch Template + Mixed Instances)

// ---------------------------
// Terraform / Providers
// ---------------------------
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

// ---------------------------
// Variables
// ---------------------------
variable "name"                       { description = "Имя пула (префикс ресурсов)"; type = string }
variable "vpc_id"                     { description = "VPC ID"; type = string }
variable "subnet_ids"                 { description = "Список приватных подсетей"; type = list(string) }
variable "allowed_cidrs"              { description = "CIDR для базового SSH"; type = list(string); default = [] }
variable "additional_ingress" {
  description = "Доп. ingress для SG"
  type = list(object({
    description = optional(string, "")
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = optional(list(string), [])
    sg_ids      = optional(list(string), [])
  }))
  default = []
}

variable "instance_type"              { description = "Тип по умолчанию"; type = string; default = "t3.large" }
variable "instance_type_overrides"    { description = "Типы для MIP"; type = list(string); default = ["t3a.large","t3.xlarge","m6i.large"] }
variable "enable_spot"                { description = "Включить Spot (MIP)"; type = bool; default = true }
variable "on_demand_base_capacity"    { description = "Базовая OD ёмкость"; type = number; default = 0 }
variable "on_demand_percent_above_base" { description = "Доля OD выше базы, %"; type = number; default = 0 }

variable "desired_capacity"           { type = number; default = 2 }
variable "min_size"                   { type = number; default = 2 }
variable "max_size"                   { type = number; default = 8 }

variable "health_check_type"          { type = string; default = "EC2" } // EC2|ELB
variable "health_check_grace_seconds" { type = number; default = 120 }

variable "ami_id"                     { description = "Явный AMI (если пусто — поиск)"; type = string; default = "" }
variable "ami_owners"                 { type = list(string); default = ["amazon"] }
variable "ami_filters" {
  description = "Фильтры AMI при пустом ami_id"
  type = list(object({ name = string, values = list(string) }))
  // AL2023, HVM, EBS
  default = [
    { name = "name",                 values = ["al2023-ami-*-x86_64"] },
    { name = "virtualization-type",  values = ["hvm"] },
    { name = "root-device-type",     values = ["ebs"] }
  ]
}

variable "key_name"                   { type = string; default = null }
variable "assign_public_ip"           { type = bool; default = false } // приватные подсети — false
variable "root_volume_size_gb"        { type = number; default = 40 }
variable "root_volume_type"           { type = string; default = "gp3" }
variable "root_volume_iops"           { type = number; default = null }
variable "root_volume_throughput"     { type = number; default = null }
variable "ebs_kms_key_id"             { type = string; default = null }

variable "user_data"                  { description = "Сырой bash/cloud-init"; type = string; default = "" }
variable "instance_profile_name"      { description = "Готовый Instance Profile (если задан — IAM не создаём)"; type = string; default = "" }
variable "enable_ssm"                 { type = bool; default = true }
variable "iam_additional_policies"    { type = list(string); default = [] }

variable "target_group_arns"          { description = "ARNs TG для прикрепления"; type = list(string); default = [] }
variable "capacity_reservation_spec" {
  description = "Присоединение к Capacity Reservation (опц.)"
  type = object({
    capacity_reservation_preference = optional(string) // open|none
    capacity_reservation_target_arn = optional(string)
  })
  default = null
}

variable "warm_pool" {
  description = "Параметры Warm Pool (опц.)"
  type = object({
    enabled            = bool
    pool_state         = optional(string) // Stopped|Running
    min_size           = optional(number)
    max_group_prepared_capacity = optional(number)
    instance_reuse     = optional(bool)
  })
  default = null
}

variable "cpu_target_value"           { description = "TargetTracking CPU %"; type = number; default = 55 }
variable "enable_alb_req_per_target"  { description = "TargetTracking по RPS/таргет"; type = bool; default = true }
variable "alb_tg_arn_for_rps"         { description = "TG ARN для RPS-политики (если пусто — auto из target_group_arns[0])"; type = string; default = "" }

variable "scheduled_scaling" {
  description = "Плановые окна масштабирования (опц.)"
  type = list(object({
    name            = string
    min_size        = number
    max_size        = number
    desired_capacity= number
    start_time      = string   // RFC3339
    end_time        = optional(string)
    recurrence      = optional(string) // CRON
  }))
  default = []
}

variable "tags" {
  description = "Теги"
  type        = map(string)
  default     = {}
}

// ---------------------------
// Locals / Data
// ---------------------------
locals {
  name = var.name
  base_tags = merge(
    {
      "Name"                      = var.name
      "app.kubernetes.io/name"    = "datafabric-core"
      "app.kubernetes.io/part-of" = "datafabric"
      "module"                    = "compute"
    },
    var.tags
  )
}

data "aws_region" "this" {}
data "aws_caller_identity" "this" {}

data "aws_ami" "selected" {
  count       = var.ami_id == "" ? 1 : 0
  most_recent = true
  owners      = var.ami_owners
  dynamic "filter" {
    for_each = var.ami_filters
    content {
      name   = filter.value.name
      values = filter.value.values
    }
  }
}

// ---------------------------
// Security Group (+ingress)
// ---------------------------
resource "aws_security_group" "this" {
  name        = "${local.name}-sg"
  description = "Security Group for ${local.name}"
  vpc_id      = var.vpc_id
  tags        = local.base_tags

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  count             = length(var.allowed_cidrs) > 0 ? 1 : 0
  security_group_id = aws_security_group.this.id
  description       = "SSH"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = element(var.allowed_cidrs, 0)
}

resource "aws_vpc_security_group_ingress_rule" "extra" {
  for_each          = { for i, r in var.additional_ingress : i => r }
  security_group_id = aws_security_group.this.id
  description       = try(each.value.description, null)
  ip_protocol       = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_ipv4         = length(try(each.value.cidr_blocks, [])) > 0 ? each.value.cidr_blocks[0] : null
  referenced_security_group_id = length(try(each.value.sg_ids, [])) > 0 ? each.value.sg_ids[0] : null
}

// ---------------------------
// IAM (условно, если не передан готовый profile)
// ---------------------------
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["ec2.amazonaws.com"] }
  }
}

resource "aws_iam_role" "this" {
  count              = var.instance_profile_name == "" ? 1 : 0
  name               = "${local.name}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = local.base_tags
}

resource "aws_iam_instance_profile" "this" {
  count = var.instance_profile_name == "" ? 1 : 0
  name  = "${local.name}-instance-profile"
  role  = aws_iam_role.this[0].name
  tags  = local.base_tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.instance_profile_name == "" && var.enable_ssm ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_role_policy_attachment" "cwagent" {
  count      = var.instance_profile_name == "" && var.enable_ssm ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
resource "aws_iam_role_policy_attachment" "extra" {
  for_each   = var.instance_profile_name == "" ? toset(var.iam_additional_policies) : []
  role       = aws_iam_role.this[0].name
  policy_arn = each.value
}

// ---------------------------
// Launch Template
// ---------------------------
resource "aws_launch_template" "this" {
  name_prefix              = "${local.name}-lt-"
  update_default_version   = true

  image_id      = var.ami_id != "" ? var.ami_id : data.aws_ami.selected[0].id
  instance_type = var.instance_type
  key_name      = var.key_name

  iam_instance_profile {
    name = var.instance_profile_name != "" ? var.instance_profile_name : aws_iam_instance_profile.this[0].name
  }

  metadata_options {
    http_tokens               = "required"  // IMDSv2
    http_endpoint             = "enabled"
    http_put_response_hop_limit = 2
  }

  monitoring { enabled = true }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.root_volume_size_gb
      volume_type           = var.root_volume_type
      iops                  = var.root_volume_iops
      throughput            = var.root_volume_throughput
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_id
      delete_on_termination = true
    }
  }

  network_interfaces {
    device_index                = 0
    security_groups             = [aws_security_group.this.id]
    associate_public_ip_address = var.assign_public_ip
  }

  dynamic "capacity_reservation_specification" {
    for_each = var.capacity_reservation_spec == null ? [] : [var.capacity_reservation_spec]
    content {
      capacity_reservation_preference = try(capacity_reservation_specification.value.capacity_reservation_preference, null)
      capacity_reservation_target {
        capacity_reservation_id = try(regex("^arn:aws:ec2:", capacity_reservation_specification.value.capacity_reservation_target_arn) != "" ? null : "", null) == null ? null : null
        capacity_reservation_resource_group_arn = try(capacity_reservation_specification.value.capacity_reservation_target_arn, null)
      }
    }
  }

  instance_initiated_shutdown_behavior = "terminate"
  ebs_optimized                        = true

  user_data = length(var.user_data) > 0 ? base64encode(var.user_data) : null

  tag_specifications {
    resource_type = "instance"
    tags          = local.base_tags
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.base_tags
  }

  tags = local.base_tags
}

// ---------------------------
// Auto Scaling Group (+MIP)
// ---------------------------
resource "aws_autoscaling_group" "this" {
  name                = "${local.name}-asg"
  vpc_zone_identifier = var.subnet_ids

  max_size         = var.max_size
  min_size         = var.min_size
  desired_capacity = var.desired_capacity

  health_check_type         = var.health_check_type
  health_check_grace_period = var.health_check_grace_seconds
  capacity_rebalance        = true
  default_cooldown          = 60

  // Обычный режим (без spot)
  dynamic "launch_template" {
    for_each = var.enable_spot ? [] : [1]
    content {
      id      = aws_launch_template.this.id
      version = "$Latest"
    }
  }

  // Mixed Instances Policy
  dynamic "mixed_instances_policy" {
    for_each = var.enable_spot ? [1] : []
    content {
      launch_template {
        launch_template_specification {
          launch_template_id = aws_launch_template.this.id
          version            = "$Latest"
        }
        dynamic "override" {
          for_each = toset(var.instance_type_overrides)
          content {
            instance_type = override.value
          }
        }
      }
      instances_distribution {
        on_demand_allocation_strategy            = "prioritized"
        on_demand_base_capacity                  = var.on_demand_base_capacity
        on_demand_percentage_above_base_capacity = var.on_demand_percent_above_base
        spot_allocation_strategy                 = "capacity-optimized-prioritized"
        spot_instance_pools                      = 4
      }
    }
  }

  target_group_arns = var.target_group_arns

  // Instance Refresh (rolling обновления)
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 80
      instance_warmup        = 90
      skip_matching          = true
      auto_rollback          = true
    }
    triggers = ["launch_template", "tag"]
  }

  // Прокидываем теги на инстансы
  dynamic "tag" {
    for_each = local.base_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes = [desired_capacity]
  }

  depends_on = [aws_launch_template.this]
}

# Warm Pool (опционально)
resource "aws_autoscaling_warm_pool" "this" {
  count                         = var.warm_pool != null && var.warm_pool.enabled ? 1 : 0
  autoscaling_group_name        = aws_autoscaling_group.this.name
  pool_state                    = try(var.warm_pool.pool_state, "Stopped")
  min_size                      = try(var.warm_pool.min_size, 0)
  max_group_prepared_capacity   = try(var.warm_pool.max_group_prepared_capacity, null)
  instance_reuse_policy {
    reuse_on_scale_in = try(var.warm_pool.instance_reuse, true)
  }
}

// ---------------------------
// Target Tracking Policies
// ---------------------------
resource "aws_autoscaling_policy" "cpu" {
  name                   = "${local.name}-tt-cpu"
  policy_type            = "TargetTrackingScaling"
  autoscaling_group_name = aws_autoscaling_group.this.name
  target_tracking_configuration {
    predefined_metric_specification { predefined_metric_type = "ASGAverageCPUUtilization" }
    target_value = var.cpu_target_value
  }
}

locals {
  _tg_for_rps = var.alb_tg_arn_for_rps != "" ? var.alb_tg_arn_for_rps : (length(var.target_group_arns) > 0 ? var.target_group_arns[0] : "")
}

resource "aws_autoscaling_policy" "alb_rps" {
  count                  = var.enable_alb_req_per_target && local._tg_for_rps != "" ? 1 : 0
  name                   = "${local.name}-tt-rps"
  policy_type            = "TargetTrackingScaling"
  autoscaling_group_name = aws_autoscaling_group.this.name
  target_tracking_configuration {
    customized_metric_specification {
      metric_name = "RequestCountPerTarget"
      namespace   = "AWS/ApplicationELB"
      statistic   = "Average"
      unit        = "Count"
      dimensions = {
        TargetGroup  = element(split("targetgroup/", local._tg_for_rps), 1)
        LoadBalancer = "" // необязательно, метрика агрегируется по TG
      }
    }
    target_value = 120 // целевой RPS/таргет — при необходимости параметризуйте
  }
}

// ---------------------------
// Step Scaling + CloudWatch Alarms
// ---------------------------
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${local.name}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  dimensions = { AutoScalingGroupName = aws_autoscaling_group.this.name }
  alarm_actions = [aws_autoscaling_policy.step_out.arn]
  tags          = local.base_tags
}

resource "aws_cloudwatch_metric_alarm" "cpu_low" {
  alarm_name          = "${local.name}-cpu-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 20
  dimensions = { AutoScalingGroupName = aws_autoscaling_group.this.name }
  alarm_actions = [aws_autoscaling_policy.step_in.arn]
  tags          = local.base_tags
}

resource "aws_autoscaling_policy" "step_out" {
  name                   = "${local.name}-step-out"
  autoscaling_group_name = aws_autoscaling_group.this.name
  adjustment_type        = "PercentChangeInCapacity"
  policy_type            = "StepScaling"
  estimated_instance_warmup = 90
  step_adjustment {
    metric_interval_lower_bound = 0
    scaling_adjustment          = 50
  }
}

resource "aws_autoscaling_policy" "step_in" {
  name                   = "${local.name}-step-in"
  autoscaling_group_name = aws_autoscaling_group.this.name
  adjustment_type        = "PercentChangeInCapacity"
  policy_type            = "StepScaling"
  estimated_instance_warmup = 90
  step_adjustment {
    metric_interval_upper_bound = 0
    scaling_adjustment          = -25
  }
}

// ---------------------------
// Lifecycle Hooks (опц. уведомления/дренаж)
// ---------------------------
resource "aws_autoscaling_lifecycle_hook" "launching" {
  name                   = "${local.name}-hook-launching"
  autoscaling_group_name = aws_autoscaling_group.this.name
  default_result         = "CONTINUE"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"
}
resource "aws_autoscaling_lifecycle_hook" "terminating" {
  name                   = "${local.name}-hook-terminating"
  autoscaling_group_name = aws_autoscaling_group.this.name
  default_result         = "CONTINUE"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
}

// ---------------------------
// Scheduled Scaling (опц.)
// ---------------------------
resource "aws_autoscaling_schedule" "this" {
  for_each              = { for s in var.scheduled_scaling : s.name => s }
  scheduled_action_name = each.value.name
  autoscaling_group_name= aws_autoscaling_group.this.name
  min_size              = each.value.min_size
  max_size              = each.value.max_size
  desired_capacity      = each.value.desired_capacity
  start_time            = each.value.start_time
  end_time              = try(each.value.end_time, null)
  recurrence            = try(each.value.recurrence, null)
}

// ---------------------------
// Outputs
// ---------------------------
output "asg_name"            { value = aws_autoscaling_group.this.name }
output "launch_template_id"  { value = aws_launch_template.this.id }
output "security_group_id"   { value = aws_security_group.this.id }
output "instance_profile"    { value = var.instance_profile_name != "" ? var.instance_profile_name : aws_iam_instance_profile.this[0].name }
output "effective_ami_id"    { value = var.ami_id != "" ? var.ami_id : data.aws_ami.selected[0].id }
