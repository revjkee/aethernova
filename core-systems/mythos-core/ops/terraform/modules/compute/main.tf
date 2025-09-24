#############################################
# Mythos Core - compute module (AWS)
# Industrial-grade Auto Scaling EC2 module
#############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.30"
    }
  }
}

#############################################
# Inputs
#############################################

variable "name" {
  description = "Base name/prefix for all compute resources"
  type        = string
  validation {
    condition     = length(var.name) >= 3 && can(regex("^[a-z0-9-]+$", var.name))
    error_message = "name must be lowercase alphanumeric and dashes, >= 3 chars."
  }
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "List of private subnets for ASG"
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "Provide at least one subnet id."
  }
}

variable "associate_public_ip" {
  description = "Associate public IP addresses to instances (use only in public subnets)"
  type        = bool
  default     = false
}

variable "instance_types" {
  description = "Preferred instance types (first is primary when not using mixed instances)."
  type        = list(string)
  default     = ["t3.large"]
  validation {
    condition     = length(var.instance_types) > 0
    error_message = "Provide at least one instance type."
  }
}

variable "enable_mixed_instances" {
  description = "Enable MixedInstancesPolicy with Spot capacity."
  type        = bool
  default     = true
}

variable "on_demand_base_capacity" {
  description = "ASG on-demand base capacity for mixed policy"
  type        = number
  default     = 0
}

variable "on_demand_percentage_above_base_capacity" {
  description = "Percentage of on-demand above base (0..100) for mixed policy"
  type        = number
  default     = 50
  validation {
    condition     = var.on_demand_percentage_above_base_capacity >= 0 && var.on_demand_percentage_above_base_capacity <= 100
    error_message = "on_demand_percentage_above_base_capacity must be 0..100."
  }
}

variable "spot_allocation_strategy" {
  description = "Spot allocation strategy for mixed policy"
  type        = string
  default     = "capacity-optimized"
}

variable "ami_id" {
  description = "Explicit AMI ID. If empty, latest Amazon Linux 2023 x86_64 will be used."
  type        = string
  default     = ""
}

variable "ami_owners" {
  description = "Owners for AMI discovery (when ami_id not set)"
  type        = list(string)
  default     = ["137112412989"] # Amazon
}

variable "desired_capacity" {
  description = "ASG desired capacity"
  type        = number
  default     = 2
}

variable "min_size" {
  description = "ASG minimum size"
  type        = number
  default     = 2
}

variable "max_size" {
  description = "ASG maximum size"
  type        = number
  default     = 10
  validation {
    condition     = var.max_size >= var.min_size
    error_message = "max_size must be >= min_size."
  }
}

variable "health_check_type" {
  description = "EC2 or ELB"
  type        = string
  default     = "EC2"
  validation {
    condition     = contains(["EC2", "ELB"], var.health_check_type)
    error_message = "health_check_type must be EC2 or ELB."
  }
}

variable "health_check_grace_period" {
  description = "Seconds to ignore health checks after instance launch"
  type        = number
  default     = 120
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring on instances"
  type        = bool
  default     = true
}

variable "enable_capacity_rebalance" {
  description = "Enable capacity rebalance for spot"
  type        = bool
  default     = true
}

variable "user_data" {
  description = "Plain user_data (cloud-init). If both user_data and user_data_path null, a minimal SSM bootstrap will be used."
  type        = string
  default     = ""
}

variable "user_data_path" {
  description = "Path to a user_data template file (templatefile)."
  type        = string
  default     = ""
}

variable "user_data_vars" {
  description = "Variables for templatefile when user_data_path provided"
  type        = map(any)
  default     = {}
}

variable "root_block_device" {
  description = "Root EBS configuration"
  type = object({
    volume_size           = number
    volume_type           = string
    iops                  = optional(number)
    throughput            = optional(number)
    delete_on_termination = optional(bool, true)
    encrypted             = optional(bool, true)
    kms_key_id            = optional(string)
  })
  default = {
    volume_size = 30
    volume_type = "gp3"
  }
}

variable "extra_block_devices" {
  description = "Extra EBS block devices list"
  type = list(object({
    device_name           = string
    volume_size           = number
    volume_type           = string
    iops                  = optional(number)
    throughput            = optional(number)
    delete_on_termination = optional(bool, true)
    encrypted             = optional(bool, true)
    kms_key_id            = optional(string)
  }))
  default = []
}

variable "security_group_ingress" {
  description = "Additional ingress rules (cidr list per port)"
  type = list(object({
    description = optional(string)
    from_port   = number
    to_port     = number
    protocol    = string
    cidrs       = list(string)
  }))
  default = []
}

variable "ssh_cidrs" {
  description = "CIDRs allowed to SSH (port 22). Leave empty to disable SSH ingress."
  type        = list(string)
  default     = []
}

variable "egress_cidrs" {
  description = "Egress CIDRs"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enable_ssm" {
  description = "Attach SSM IAM policies to allow Session Manager"
  type        = bool
  default     = true
}

variable "iam_role_additional_policies" {
  description = "Additional policy ARNs to attach to instance role"
  type        = list(string)
  default     = []
}

variable "key_name" {
  description = "EC2 key pair name for SSH (optional)"
  type        = string
  default     = ""
}

variable "target_group_arns" {
  description = "List of ALB/NLB Target Group ARNs to attach ASG"
  type        = list(string)
  default     = []
}

variable "termination_policies" {
  description = "ASG termination policies"
  type        = list(string)
  default     = ["OldestInstance", "Default"]
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

#############################################
# Locals
#############################################

locals {
  common_tags = merge({
    "Name"                       = var.name
    "app.kubernetes.io/part-of"  = "mythos-core"
    "managed-by"                 = "terraform"
    "module"                     = "compute"
  }, var.tags)

  resolved_user_data = (
    length(trimspace(var.user_data)) > 0 ? var.user_data :
    length(trimspace(var.user_data_path)) > 0 ? templatefile(var.user_data_path, var.user_data_vars) :
<<-EOT
#cloud-config
package_update: true
package_upgrade: true
runcmd:
  - 'echo "Bootstrapped by Mythos compute module"'
EOT
  )
}

#############################################
# AMI (if not provided)
#############################################

data "aws_ami" "al2023" {
  count       = var.ami_id == "" ? 1 : 0
  owners      = var.ami_owners
  most_recent = true
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

#############################################
# Security Group
#############################################

resource "aws_security_group" "this" {
  name        = "${var.name}-sg"
  description = "SG for ${var.name}"
  vpc_id      = var.vpc_id
  tags        = local.common_tags
}

# Egress (allow to internet by default)
resource "aws_security_group_rule" "egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = var.egress_cidrs
  security_group_id = aws_security_group.this.id
  description       = "Egress"
}

# Optional SSH
resource "aws_security_group_rule" "ssh" {
  count             = length(var.ssh_cidrs) > 0 ? 1 : 0
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = var.ssh_cidrs
  security_group_id = aws_security_group.this.id
  description       = "SSH access"
}

# Custom ingress rules
resource "aws_security_group_rule" "custom_ingress" {
  for_each          = { for i, r in var.security_group_ingress : i => r }
  type              = "ingress"
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  protocol          = each.value.protocol
  cidr_blocks       = each.value.cidrs
  security_group_id = aws_security_group.this.id
  description       = coalesce(each.value.description, "custom ingress")
}

#############################################
# IAM Role + Instance Profile
#############################################

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.name}-profile"
  role = aws_iam_role.this.name
  tags = local.common_tags
}

# Core managed policies
resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.enable_ssm ? 1 : 0
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cw_agent" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Additional user-defined policies
resource "aws_iam_role_policy_attachment" "extra" {
  for_each  = toset(var.iam_role_additional_policies)
  role      = aws_iam_role.this.name
  policy_arn = each.key
}

#############################################
# Launch Template
#############################################

resource "aws_launch_template" "this" {
  name_prefix   = "${var.name}-lt-"
  description   = "Launch Template for ${var.name}"
  update_default_version = true

  iam_instance_profile {
    name = aws_iam_instance_profile.this.name
  }

  image_id = var.ami_id != "" ? var.ami_id : data.aws_ami.al2023[0].id

  # Primary instance type (used when not mixed)
  instance_type = var.enable_mixed_instances ? null : var.instance_types[0]

  # Networking
  network_interfaces {
    security_groups             = [aws_security_group.this.id]
    associate_public_ip_address = var.associate_public_ip
  }

  # Storage - root
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.root_block_device.volume_size
      volume_type           = var.root_block_device.volume_type
      delete_on_termination = lookup(var.root_block_device, "delete_on_termination", true)
      encrypted             = lookup(var.root_block_device, "encrypted", true)
      kms_key_id            = lookup(var.root_block_device, "kms_key_id", null)
      iops                  = lookup(var.root_block_device, "iops", null)
      throughput            = lookup(var.root_block_device, "throughput", null)
    }
  }

  # Extra EBS devices
  dynamic "block_device_mappings" {
    for_each = var.extra_block_devices
    content {
      device_name = block_device_mappings.value.device_name
      ebs {
        volume_size           = block_device_mappings.value.volume_size
        volume_type           = block_device_mappings.value.volume_type
        delete_on_termination = lookup(block_device_mappings.value, "delete_on_termination", true)
        encrypted             = lookup(block_device_mappings.value, "encrypted", true)
        kms_key_id            = lookup(block_device_mappings.value, "kms_key_id", null)
        iops                  = lookup(block_device_mappings.value, "iops", null)
        throughput            = lookup(block_device_mappings.value, "throughput", null)
      }
    }
  }

  # Metadata service hardened
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2
    http_put_response_hop_limit = 2
  }

  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  # SSH key (optional)
  key_name = var.key_name != "" ? var.key_name : null

  ebs_optimized = true

  user_data = base64encode(local.resolved_user_data)

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.common_tags, { "aws:autoscaling:groupName" = var.name })
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.common_tags
  }

  tags = local.common_tags
}

#############################################
# Auto Scaling Group
#############################################

resource "aws_autoscaling_group" "this" {
  name                = var.name
  vpc_zone_identifier = var.subnet_ids
  desired_capacity    = var.desired_capacity
  min_size            = var.min_size
  max_size            = var.max_size

  health_check_type         = var.health_check_type
  health_check_grace_period = var.health_check_grace_period

  termination_policies = var.termination_policies

  # Launch template or mixed instances
  launch_template {
    id      = aws_launch_template.this.id
    version = "$Latest"
  }

  dynamic "mixed_instances_policy" {
    for_each = var.enable_mixed_instances ? [1] : []
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
        spot_allocation_strategy                 = var.spot_allocation_strategy
      }
    }
  }

  target_group_arns = var.target_group_arns

  enabled_metrics = [
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupPendingInstances",
    "GroupStandbyInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances"
  ]

  metrics_granularity = "1Minute"

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 90
      instance_warmup        = 60
      auto_rollback          = true
    }
    triggers = ["launch_template"]
  }

  capacity_rebalance = var.enable_capacity_rebalance

  # Tag propagation to instances
  tag {
    key                 = "Name"
    value               = var.name
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

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_iam_instance_profile.this
  ]
  tags = local.common_tags
}

#############################################
# Target tracking scaling policy (CPU 50%) - optional enable by size gates
#############################################

resource "aws_autoscaling_policy" "cpu_tgt" {
  name                   = "${var.name}-cpu-tgt"
  autoscaling_group_name = aws_autoscaling_group.this.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value       = 50
    disable_scale_in   = false
  }
}

#############################################
# Outputs
#############################################

output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.this.name
}

output "launch_template_id" {
  description = "Launch Template ID"
  value       = aws_launch_template.this.id
}

output "security_group_id" {
  description = "Security Group ID"
  value       = aws_security_group.this.id
}

output "iam_role_name" {
  description = "Instance role name"
  value       = aws_iam_role.this.name
}

output "instance_profile_name" {
  description = "Instance profile name"
  value       = aws_iam_instance_profile.this.name
}
