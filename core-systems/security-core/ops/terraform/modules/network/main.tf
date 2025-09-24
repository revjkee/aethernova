############################################################
# core-systems/security-core/ops/terraform/modules/network/main.tf
# Industrial, Zero-Trust oriented AWS network module
############################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

########################################
# ========== VARIABLES ================
########################################

variable "name" {
  description = "Base name/prefix for all resources"
  type        = string
  validation {
    condition     = length(var.name) >= 3 && length(var.name) <= 32
    error_message = "name must be 3..32 characters."
  }
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "cidr_block" {
  description = "Primary IPv4 CIDR for VPC (e.g. 10.0.0.0/16)"
  type        = string
}

variable "enable_ipv6" {
  description = "Assign Amazon-provided IPv6 /56 to the VPC"
  type        = bool
  default     = true
}

variable "az_count" {
  description = "How many AZs to use (1..6)."
  type        = number
  default     = 3
  validation {
    condition     = var.az_count >= 1 && var.az_count <= 6
    error_message = "az_count must be between 1 and 6."
  }
}

variable "create_public_subnets" {
  description = "Create public subnets (ingress via IGW/NLB/ALB as needed)"
  type        = bool
  default     = true
}

variable "nat_strategy" {
  description = "NAT strategy: none|single|one_per_az"
  type        = string
  default     = "one_per_az"
  validation {
    condition     = contains(["none", "single", "one_per_az"], var.nat_strategy)
    error_message = "nat_strategy must be one of: none, single, one_per_az."
  }
}

variable "flow_logs_destination" {
  description = "VPC Flow Logs destination: cloudwatch|s3|none"
  type        = string
  default     = "cloudwatch"
  validation {
    condition     = contains(["cloudwatch", "s3", "none"], var.flow_logs_destination)
    error_message = "flow_logs_destination must be one of: cloudwatch, s3, none."
  }
}

variable "flow_logs_s3_bucket_arn" {
  description = "S3 bucket ARN for flow logs (required if destination=s3)"
  type        = string
  default     = ""
}

variable "interface_endpoints" {
  description = "List of AWS interface endpoint service names to enable in the VPC"
  type        = list(string)
  # Secure defaults for private compute:
  default = [
    "com.amazonaws.${data.aws_region.current.name}.ec2",
    "com.amazonaws.${data.aws_region.current.name}.ecr.api",
    "com.amazonaws.${data.aws_region.current.name}.ecr.dkr",
    "com.amazonaws.${data.aws_region.current.name}.ssm",
    "com.amazonaws.${data.aws_region.current.name}.ssmmessages",
    "com.amazonaws.${data.aws_region.current.name}.ec2messages",
    "com.amazonaws.${data.aws_region.current.name}.logs",
    "com.amazonaws.${data.aws_region.current.name}.secretsmanager",
    "com.amazonaws.${data.aws_region.current.name}.kms"
  ]
}

variable "gateway_endpoints" {
  description = "Gateway endpoints to create (supported: s3, dynamodb)"
  type        = list(string)
  default     = ["s3"]
  validation {
    condition     = alltrue([for g in var.gateway_endpoints : contains(["s3", "dynamodb"], g)])
    error_message = "Only s3 and dynamodb are supported gateway endpoints."
  }
}

variable "private_subnet_bits" {
  description = "New bits for private subnet cidrs (relative to VPC cidr)"
  type        = number
  default     = 4
}

variable "public_subnet_bits" {
  description = "New bits for public subnet cidrs (relative to VPC cidr)"
  type        = number
  default     = 6
}

variable "enable_dns_hostnames" {
  description = "Enable DNS hostnames on VPC"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Enable DNS support on VPC"
  type        = bool
  default     = true
}

########################################
# ========== DATA SOURCES =============
########################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

########################################
# ========== LOCALS ===================
########################################

locals {
  name    = var.name
  azs     = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  # Tag baseline with ownership and purpose
  tags = merge(
    {
      "Name"        = local.name
      "ManagedBy"   = "Terraform"
      "System"      = "core-systems"
      "Module"      = "security-core-network"
      "ZeroTrust"   = "true"
      "Environment" = lookup(var.tags, "Environment", "prod")
    },
    var.tags
  )
}

########################################
# ========== VPC & IPv6 ===============
########################################

resource "aws_vpc" "this" {
  cidr_block                       = var.cidr_block
  enable_dns_hostnames             = var.enable_dns_hostnames
  enable_dns_support               = var.enable_dns_support
  assign_generated_ipv6_cidr_block = var.enable_ipv6

  tags = merge(local.tags, { "Component" = "vpc" })
}

########################################
# ========== INTERNET GATEWAY =========
########################################

resource "aws_internet_gateway" "igw" {
  count  = var.create_public_subnets ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { "Component" = "igw" })
}

########################################
# ========== SUBNETS ==================
########################################

# Private subnets across AZs
resource "aws_subnet" "private" {
  for_each = { for idx, az in local.azs : idx => az }

  vpc_id            = aws_vpc.this.id
  availability_zone = each.value
  cidr_block        = cidrsubnet(var.cidr_block, var.private_subnet_bits, each.key)

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, each.key) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    "Component" = "subnet"
    "Tier"      = "private"
    "AZ"        = each.value
  })
}

# Public subnets across AZs (optional)
resource "aws_subnet" "public" {
  for_each = var.create_public_subnets ? { for idx, az in local.azs : idx => az } : {}

  vpc_id            = aws_vpc.this.id
  availability_zone = each.value
  cidr_block        = cidrsubnet(var.cidr_block, var.public_subnet_bits, 100 + each.key)

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, 100 + each.key) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  map_public_ip_on_launch = true

  tags = merge(local.tags, {
    "Component" = "subnet"
    "Tier"      = "public"
    "AZ"        = each.value
  })
}

########################################
# ========== ROUTE TABLES =============
########################################

resource "aws_route_table" "private" {
  for_each = aws_subnet.private

  vpc_id = aws_vpc.this.id
  tags = merge(local.tags, {
    "Component" = "route-table"
    "Tier"      = "private"
    "AZ"        = each.value.availability_zone
  })
}

resource "aws_route_table" "public" {
  for_each = aws_subnet.public

  vpc_id = aws_vpc.this.id
  tags = merge(local.tags, {
    "Component" = "route-table"
    "Tier"      = "public"
    "AZ"        = each.value.availability_zone
  })
}

# Public default route to IGW
resource "aws_route" "public_inet" {
  for_each = aws_route_table.public

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = one(aws_internet_gateway.igw[*].id)
}

resource "aws_route" "public_inet_v6" {
  for_each = var.enable_ipv6 ? aws_route_table.public : {}

  route_table_id              = each.value.id
  destination_ipv6_cidr_block = "::/0"
  gateway_id                  = one(aws_internet_gateway.igw[*].id)
}

# Associate subnets to route tables
resource "aws_route_table_association" "private_assoc" {
  for_each = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[tonumber(each.key)].id
}

resource "aws_route_table_association" "public_assoc" {
  for_each = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public[tonumber(each.key)].id
}

########################################
# ========== NAT GATEWAYS =============
########################################

# EIP for NAT(s)
resource "aws_eip" "nat" {
  count = var.nat_strategy == "none" ? 0 : (var.nat_strategy == "single" ? 1 : length(local.azs))
  domain = "vpc"
  tags   = merge(local.tags, { "Component" = "eip", "Purpose" = "nat" })
}

resource "aws_nat_gateway" "this" {
  count         = length(aws_eip.nat)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = element(values(aws_subnet.public)[*].id, var.nat_strategy == "single" ? 0 : count.index)
  tags          = merge(local.tags, { "Component" = "nat", "Index" = tostring(count.index) })

  depends_on = [aws_internet_gateway.igw]
}

# Private routes to NAT (IPv4 only; IPv6 goes direct via IGW/egress-only GW if used)
resource "aws_route" "private_ipv4_to_nat" {
  for_each = var.nat_strategy == "none" ? {} : aws_route_table.private

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.nat_strategy == "single" ? aws_nat_gateway.this[0].id : element(aws_nat_gateway.this[*].id, tonumber(each.key))
}

########################################
# ========== NACLs (Baseline) =========
########################################

# Default deny inbound, allow established; strict baseline
resource "aws_network_acl" "private_nacl" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { "Component" = "nacl", "Tier" = "private" })
}

resource "aws_network_acl_rule" "private_in_deny_all" {
  network_acl_id = aws_network_acl.private_nacl.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "private_out_allow_all" {
  network_acl_id = aws_network_acl.private_nacl.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_network_acl_association" "private_assoc" {
  for_each       = aws_subnet.private
  network_acl_id = aws_network_acl.private_nacl.id
  subnet_id      = each.value.id
}

# Public NACL: allow 80/443/1024-65535 inbound; allow all egress
resource "aws_network_acl" "public_nacl" {
  count = var.create_public_subnets ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { "Component" = "nacl", "Tier" = "public" })
}

resource "aws_network_acl_rule" "public_in_https" {
  count          = var.create_public_subnets ? 1 : 0
  network_acl_id = aws_network_acl.public_nacl[0].id
  rule_number    = 100
  egress         = false
  protocol       = "6"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "public_in_http" {
  count          = var.create_public_subnets ? 1 : 0
  network_acl_id = aws_network_acl.public_nacl[0].id
  rule_number    = 110
  egress         = false
  protocol       = "6"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 80
  to_port        = 80
}

resource "aws_network_acl_rule" "public_in_ephemeral" {
  count          = var.create_public_subnets ? 1 : 0
  network_acl_id = aws_network_acl.public_nacl[0].id
  rule_number    = 120
  egress         = false
  protocol       = "6"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "public_out_allow_all" {
  count          = var.create_public_subnets ? 1 : 0
  network_acl_id = aws_network_acl.public_nacl[0].id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_network_acl_association" "public_assoc" {
  for_each = aws_subnet.public
  network_acl_id = aws_network_acl.public_nacl[0].id
  subnet_id      = each.value.id
}

########################################
# ========== SECURITY GROUP ===========
########################################

# Baseline SG for interface endpoints / shared use (no inbound by default)
resource "aws_security_group" "baseline" {
  name        = "${local.name}-baseline-sg"
  description = "Baseline SG: deny all inbound, allow all egress"
  vpc_id      = aws_vpc.this.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = var.enable_ipv6 ? ["::/0"] : null
  }

  tags = merge(local.tags, { "Component" = "sg", "Purpose" = "baseline" })
}

########################################
# ========== VPC ENDPOINTS ============
########################################

# Gateway endpoints
resource "aws_vpc_endpoint" "gateway" {
  for_each = { for svc in var.gateway_endpoints : svc => svc }

  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.${each.value}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(values(aws_route_table.private)[*].id, values(aws_route_table.public)[*].id)

  tags = merge(local.tags, { "Component" = "vpce", "Type" = "gateway", "Service" = each.value })
}

# Interface endpoints
resource "aws_vpc_endpoint" "interface" {
  for_each = { for s in var.interface_endpoints : s => s }

  vpc_id              = aws_vpc.this.id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = values(aws_subnet.private)[*].id
  security_group_ids  = [aws_security_group.baseline.id]

  tags = merge(local.tags, { "Component" = "vpce", "Type" = "interface", "Service" = each.value })
}

########################################
# ========== FLOW LOGS ================
########################################

# CloudWatch destination (default)
resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = var.flow_logs_destination == "cloudwatch" ? 1 : 0
  name              = "/aws/vpc/${local.name}/flow-logs"
  retention_in_days = 90
  tags              = merge(local.tags, { "Component" = "logs", "Purpose" = "vpc-flow" })
}

resource "aws_iam_role" "flow_logs" {
  count = var.flow_logs_destination == "cloudwatch" ? 1 : 0
  name  = "${local.name}-vpc-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
  tags = merge(local.tags, { "Component" = "iam", "Purpose" = "vpc-flow" })
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.flow_logs_destination == "cloudwatch" ? 1 : 0
  name  = "${local.name}-vpc-flow-logs-policy"
  role  = aws_iam_role.flow_logs[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "to_cloudwatch" {
  count                = var.flow_logs_destination == "cloudwatch" ? 1 : 0
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.flow_logs[0].name
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.this.id
  iam_role_arn         = aws_iam_role.flow_logs[0].arn
  tags                 = merge(local.tags, { "Component" = "flowlog", "Destination" = "cloudwatch" })
}

# S3 destination
resource "aws_flow_log" "to_s3" {
  count                = var.flow_logs_destination == "s3" ? 1 : 0
  log_destination_type = "s3"
  log_destination      = var.flow_logs_s3_bucket_arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.this.id
  tags                 = merge(local.tags, { "Component" = "flowlog", "Destination" = "s3" })
}

########################################
# ========== OUTPUTS ==================
########################################

output "vpc_id" {
  value       = aws_vpc.this.id
  description = "ID of the VPC"
}

output "vpc_cidr_block" {
  value       = aws_vpc.this.cidr_block
  description = "IPv4 CIDR of the VPC"
}

output "vpc_ipv6_cidr_block" {
  value       = try(aws_vpc.this.ipv6_cidr_block, null)
  description = "Amazon-provided IPv6 CIDR of the VPC (if enabled)"
}

output "private_subnet_ids" {
  value       = values(aws_subnet.private)[*].id
  description = "Private subnet IDs"
}

output "public_subnet_ids" {
  value       = values(aws_subnet.public)[*].id
  description = "Public subnet IDs (if created)"
}

output "route_table_ids_private" {
  value       = values(aws_route_table.private)[*].id
  description = "Private route table IDs"
}

output "route_table_ids_public" {
  value       = values(aws_route_table.public)[*].id
  description = "Public route table IDs"
}

output "interface_endpoint_ids" {
  value       = { for k, v in aws_vpc_endpoint.interface : k => v.id }
  description = "Map of interface endpoint IDs by service name"
}

output "gateway_endpoint_ids" {
  value       = { for k, v in aws_vpc_endpoint.gateway : k => v.id }
  description = "Map of gateway endpoint IDs by service"
}

output "baseline_security_group_id" {
  value       = aws_security_group.baseline.id
  description = "Baseline security group ID"
}
