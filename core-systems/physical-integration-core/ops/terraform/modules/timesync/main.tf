#############################################
# physical-integration-core/ops/terraform/modules/timesync/main.tf
# Industrial-grade Time Sync module (AWS)
# Modes:
#  - dhcp_only   : Associate VPCs with DHCP options pointing to Amazon Time Sync or custom NTP servers
#  - self_hosted : Deploy chrony NTP cluster behind NLB (UDP/123) with TCP health checks
#  - both        : Do both at once
#############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
  }
}

#############################################
# Variables
#############################################

variable "name" {
  description = "Base name prefix for all resources."
  type        = string
  default     = "timesync"
}

variable "mode" {
  description = "Deployment mode: dhcp_only | self_hosted | both"
  type        = string
  default     = "dhcp_only"
  validation {
    condition     = contains(["dhcp_only", "self_hosted", "both"], var.mode)
    error_message = "mode must be one of: dhcp_only, self_hosted, both."
  }
}

variable "tags" {
  description = "Common tags for all resources."
  type        = map(string)
  default     = {}
}

# ---------- DHCP options inputs ----------
variable "vpc_ids" {
  description = "List of VPC IDs to associate DHCP options with (for dhcp_only/both)."
  type        = list(string)
  default     = []
}

variable "dhcp_ntp_servers" {
  description = "NTP servers for DHCP options. Defaults to Amazon Time Sync (169.254.169.123)."
  type        = list(string)
  default     = ["169.254.169.123"]
  validation {
    condition     = length(var.dhcp_ntp_servers) > 0
    error_message = "At least one NTP server must be provided."
  }
}

variable "dhcp_domain_name" {
  description = "Optional DHCP domain-name option."
  type        = string
  default     = null
}

variable "dhcp_domain_name_servers" {
  description = "Optional DHCP domain-name-servers option."
  type        = list(string)
  default     = null
}

# ---------- Self-hosted NTP inputs ----------
variable "private_subnet_ids" {
  description = "Private subnet IDs for ASG (self_hosted/both). Spread across AZs."
  type        = list(string)
  default     = []
}

variable "allowed_cidrs" {
  description = "CIDR blocks allowed to query NTP over UDP/123."
  type        = list(string)
  default     = []
}

variable "instance_type" {
  description = "EC2 instance type for chrony nodes."
  type        = string
  default     = "t3.micro"
}

variable "ami_id" {
  description = "Optional AMI ID. If null, Amazon Linux 2023 latest will be used."
  type        = string
  default     = null
}

variable "asg_min_size" {
  description = "Minimum ASG size."
  type        = number
  default     = 2
}

variable "asg_max_size" {
  description = "Maximum ASG size."
  type        = number
  default     = 4
}

variable "asg_desired_capacity" {
  description = "Desired ASG capacity."
  type        = number
  default     = 2
}

variable "health_check_port" {
  description = "TCP port used by NLB health checks."
  type        = number
  default     = 32012
}

variable "ntp_upstream_servers" {
  description = "Upstream NTP servers for chrony. Amazon Time Sync recommended."
  type        = list(string)
  default     = ["169.254.169.123"]
}

variable "enable_ssm" {
  description = "Attach SSM IAM role/policy for management."
  type        = bool
  default     = true
}

variable "log_group_name" {
  description = "CloudWatch Log Group name for instance logs; if null, auto-generated."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days."
  type        = number
  default     = 30
}

variable "kms_key_arn_for_logs" {
  description = "Optional KMS CMK ARN for encrypting CloudWatch Log Group."
  type        = string
  default     = null
}

# Optional SSH access (disabled by default)
variable "ssh_cidrs" {
  description = "CIDRs allowed for SSH (22/tcp). Empty to disable SSH ingress."
  type        = list(string)
  default     = []
}

#############################################
# Locals
#############################################

locals {
  enabled_dhcp     = contains(["dhcp_only", "both"], var.mode)
  enabled_selfhost = contains(["self_hosted", "both"], var.mode)

  name_prefix = var.name

  # Basic tagging convention
  common_tags = merge(
    {
      "Name"        = local.name_prefix
      "Module"      = "physical-integration-core/timesync"
      "ManagedBy"   = "Terraform"
      "Environment" = coalesce(try(var.tags["Environment"], null), "prod")
    },
    var.tags
  )

  # Defaults for log group
  cw_log_group_name = coalesce(var.log_group_name, "/timesync/${local.name_prefix}")

  # Derived booleans for validation
  need_vpc_assoc    = local.enabled_dhcp && length(var.vpc_ids) == 0 ? true : false
  need_subnets_asg  = local.enabled_selfhost && length(var.private_subnet_ids) == 0 ? true : false
  need_allowed_cidr = local.enabled_selfhost && length(var.allowed_cidrs) == 0 ? true : false
}

#############################################
# Defensive validations (preconditions)
#############################################

# Ensure inputs make sense for selected mode(s)
resource "null_resource" "input_guards" {
  triggers = {
    mode                 = var.mode
    vpc_ids              = join(",", var.vpc_ids)
    private_subnet_ids   = join(",", var.private_subnet_ids)
    allowed_cidrs        = join(",", var.allowed_cidrs)
  }

  lifecycle {
    ignore_changes = [triggers]
  }

  provisioner "local-exec" {
    when    = create
    command = "echo Validating timesync inputs..."
  }

  # Soft validations through 'precondition' blocks (Terraform 1.5+)
  depends_on = []
}

# Dhcp mode requires VPC IDs
moved {
  from = null_resource.input_guards
  to   = null_resource.input_guards
}

# Terraform 1.5+ dynamic validations
resource "terraform_data" "validate_dhcp" {
  count = local.enabled_dhcp ? 1 : 0

  lifecycle {
    precondition {
      condition     = !local.need_vpc_assoc
      error_message = "mode requires at least one VPC ID in var.vpc_ids for DHCP association."
    }
  }
}

resource "terraform_data" "validate_selfhost_subnets" {
  count = local.enabled_selfhost ? 1 : 0

  lifecycle {
    precondition {
      condition     = !local.need_subnets_asg
      error_message = "self_hosted mode requires at least two private subnet IDs in var.private_subnet_ids."
    }
    precondition {
      condition     = length(var.private_subnet_ids) >= 2
      error_message = "Provide at least two subnets (multi-AZ) for HA."
    }
    precondition {
      condition     = !local.need_allowed_cidr
      error_message = "self_hosted mode requires at least one allowed CIDR in var.allowed_cidrs for UDP/123."
    }
  }
}

#############################################
# Data sources
#############################################

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Latest Amazon Linux 2023 AMI if not provided
data "aws_ami" "al2023" {
  count       = local.enabled_selfhost && var.ami_id == null ? 1 : 0
  most_recent = true
  owners      = ["137112412989"] # Amazon

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
}

#############################################
# CloudWatch Log Group (optional encryption)
#############################################

resource "aws_cloudwatch_log_group" "this" {
  count             = local.enabled_selfhost ? 1 : 0
  name              = local.cw_log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn_for_logs
  tags              = local.common_tags
}

#############################################
# DHCP Options for Amazon Time Sync (or custom)
#############################################

resource "aws_vpc_dhcp_options" "this" {
  count = local.enabled_dhcp ? 1 : 0

  # Only set those options that are provided
  dynamic "ntp_servers" {
    for_each = [1]
    content  = {}
  }

  # HCL for dhcp_options requires direct arguments, not blocks:
  # Using 'ntp_servers', 'domain_name', 'domain_name_servers'
  ntp_servers          = var.dhcp_ntp_servers
  domain_name          = var.dhcp_domain_name
  domain_name_servers  = var.dhcp_domain_name_servers

  tags = merge(local.common_tags, {
    "Component" = "dhcp-options"
  })
}

resource "aws_vpc_dhcp_options_association" "assoc" {
  for_each = local.enabled_dhcp ? toset(var.vpc_ids) : toset([])

  vpc_id          = each.value
  dhcp_options_id = aws_vpc_dhcp_options.this[0].id
}

#############################################
# Self-hosted NTP: Security Group
#############################################

resource "aws_security_group" "ntp" {
  count       = local.enabled_selfhost ? 1 : 0
  name        = "${local.name_prefix}-ntp-sg"
  description = "Security group for NTP nodes"
  vpc_id      = regex("^vpc-.*", length(var.vpc_ids) > 0 ? var.vpc_ids[0] : "vpc-000000") != "" ? (length(var.vpc_ids) > 0 ? var.vpc_ids[0] : null) : null

  dynamic "ingress" {
    for_each = var.allowed_cidrs
    content {
      description = "NTP client access"
      from_port   = 123
      to_port     = 123
      protocol    = "udp"
      cidr_blocks = [ingress.value]
    }
  }

  # Health check TCP ingress from NLB (within VPC)
  ingress {
    description = "NLB TCP health check"
    from_port   = var.health_check_port
    to_port     = var.health_check_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Optional SSH
  dynamic "ingress" {
    for_each = var.ssh_cidrs
    content {
      description = "Admin SSH"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    "Component" = "ntp-sg"
  })
}

#############################################
# IAM for instances (SSM + CloudWatch)
#############################################

data "aws_iam_policy_document" "assume" {
  count = local.enabled_selfhost && var.enable_ssm ? 1 : 0
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  count              = local.enabled_selfhost && var.enable_ssm ? 1 : 0
  name               = "${local.name_prefix}-ntp-role"
  assume_role_policy = data.aws_iam_policy_document.assume[0].json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count      = local.enabled_selfhost && var.enable_ssm ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:${data.aws_caller_identity.current.partition == "aws" ? "aws" : data.aws_caller_identity.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cw" {
  count      = local.enabled_selfhost && var.enable_ssm ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:${data.aws_caller_identity.current.partition == "aws" ? "aws" : data.aws_caller_identity.current.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "this" {
  count = local.enabled_selfhost && var.enable_ssm ? 1 : 0
  name  = "${local.name_prefix}-ntp-profile"
  role  = aws_iam_role.this[0].name
}

#############################################
# Launch Template with chrony & health socket
#############################################

locals {
  effective_ami = local.enabled_selfhost ? (var.ami_id != null ? var.ami_id : data.aws_ami.al2023[0].id) : null

  user_data = local.enabled_selfhost ? base64encode(<<-EOT
    #!/bin/bash
    set -euo pipefail

    # Harden instance basics
    sysctl -w net.ipv4.ip_forward=0
    sysctl -w net.ipv4.conf.all.send_redirects=0

    # Install chrony
    dnf -y install chrony

    # Configure chrony
    cat >/etc/chrony.conf <<'CFG'
driftfile /var/lib/chrony/drift
rtcsync
makestep 1.0 3
logdir /var/log/chrony

# Upstream servers
%{ for s in ntp_upstreams ~}
server ${s} prefer iburst
%{ endfor ~}

# Allow queries from anywhere; security via SG
allow 0.0.0.0/0

# NTP access control: deny modification
cmdport 0
CFG

    # systemd health socket/service for TCP check
    cat >/etc/systemd/system/ntp-health.socket <<'UNIT'
[Unit]
Description=NTP health TCP socket

[Socket]
ListenStream=%{health_port}
Accept=true
NoDelay=true

[Install]
WantedBy=sockets.target
UNIT

    cat >/etc/systemd/system/ntp-health@.service <<'UNIT'
[Unit]
Description=NTP health accept service

[Service]
Type=simple
ExecStart=/usr/bin/true
User=root
Group=root

[Install]
WantedBy=multi-user.target
UNIT

    # Enable services
    systemctl daemon-reload
    systemctl enable --now chronyd
    systemctl enable --now ntp-health.socket

    # CloudWatch Agent (optional): write a minimal config if present
    if [ -x /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then
      cat >/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'CW'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          { "file_path": "/var/log/chrony/measurements.log", "log_group_name": "%{log_group}", "log_stream_name": "{instance_id}-chrony-measurements" },
          { "file_path": "/var/log/messages", "log_group_name": "%{log_group}", "log_stream_name": "{instance_id}-messages" }
        ]
      }
    }
  }
}
CW
      /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a start || true
    fi

    # IMDSv2 recommended
    TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || true)
    curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/dynamic/instance-identity/document || true

    echo "User data completed."
  EOT
  ) : null
}

resource "aws_launch_template" "ntp" {
  count = local.enabled_selfhost ? 1 : 0

  name_prefix   = "${local.name_prefix}-lt-"
  image_id      = local.effective_ami
  instance_type = var.instance_type

  update_default_version = true

  # IMDSv2 required
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  user_data = replace(replace(local.user_data,
               "%{health_port}", tostring(var.health_check_port)),
               "%{log_group}", local.cw_log_group_name
             )

  iam_instance_profile {
    name = var.enable_ssm ? aws_iam_instance_profile.this[0].name : null
  }

  vpc_security_group_ids = [aws_security_group.ntp[0].id]

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.common_tags, { "Component" = "ntp-node" })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.common_tags, { "Component" = "ntp-node" })
  }

  lifecycle {
    create_before_destroy = true
  }
}

#############################################
# NLB + Target Group (UDP/123) with TCP health checks
#############################################

resource "aws_lb" "ntp" {
  count                      = local.enabled_selfhost ? 1 : 0
  name                       = "${local.name_prefix}-nlb"
  internal                   = true
  load_balancer_type         = "network"
  enable_deletion_protection = false
  subnets                    = var.private_subnet_ids

  tags = merge(local.common_tags, { "Component" = "ntp-nlb" })
}

resource "aws_lb_target_group" "ntp_udp" {
  count    = local.enabled_selfhost ? 1 : 0
  name     = "${local.name_prefix}-tg-udp"
  port     = 123
  protocol = "UDP"
  vpc_id   = element(var.vpc_ids, 0)

  health_check {
    protocol            = "TCP"
    port                = tostring(var.health_check_port)
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
  }

  tags = merge(local.common_tags, { "Component" = "ntp-tg" })
}

resource "aws_lb_listener" "udp_123" {
  count             = local.enabled_selfhost ? 1 : 0
  load_balancer_arn = aws_lb.ntp[0].arn
  port              = 123
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ntp_udp[0].arn
  }
}

#############################################
# Auto Scaling Group
#############################################

resource "aws_autoscaling_group" "ntp" {
  count = local.enabled_selfhost ? 1 : 0

  name                      = "${local.name_prefix}-asg"
  min_size                  = var.asg_min_size
  max_size                  = var.asg_max_size
  desired_capacity          = var.asg_desired_capacity
  health_check_type         = "EC2"
  health_check_grace_period = 60
  vpc_zone_identifier       = var.private_subnet_ids

  launch_template {
    id      = aws_launch_template.ntp[0].id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.ntp_udp[0].arn]

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-ntp"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "ntp-asg"
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
}

#############################################
# Outputs
#############################################

output "dhcp_options_id" {
  description = "ID of DHCP options (if created)."
  value       = local.enabled_dhcp ? aws_vpc_dhcp_options.this[0].id : null
}

output "ntp_endpoint" {
  description = "NTP endpoint: NLB DNS name if self-hosted, otherwise Amazon Time Sync (169.254.169.123)."
  value       = local.enabled_selfhost ? aws_lb.ntp[0].dns_name : "169.254.169.123"
}

output "asg_name" {
  description = "ASG name for NTP nodes (if created)."
  value       = local.enabled_selfhost ? aws_autoscaling_group.ntp[0].name : null
}

output "mode_effective" {
  description = "Effective deployment mode."
  value       = var.mode
}

#############################################
# Template helpers (for user_data interpolation)
#############################################

# Render user_data with upstream servers
locals {
  user_data_template = local.enabled_selfhost ? replace(local.user_data, "%{ for s in ntp_upstreams ~}\nserver ${s} prefer iburst\n%{ endfor ~}", join("\n", [
    for s in var.ntp_upstream_servers : "server ${s} prefer iburst"
  ])) : null
}

# Override launch template user_data with rendered content
resource "aws_launch_template" "ntp_ud" {
  count = 0 # reserved for future refactors
}
