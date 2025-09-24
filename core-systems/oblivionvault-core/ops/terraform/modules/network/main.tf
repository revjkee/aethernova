#############################################
# oblivionvault-core / ops / terraform / modules / network / main.tf
# Industrial-grade VPC networking module for AWS
#############################################

terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

#############################################
# INPUT VARIABLES (self-contained for this single-file module)
#############################################

variable "name" {
  description = "Base name/prefix for all network resources (e.g., oblivionvault-core)."
  type        = string
  validation {
    condition     = length(trim(var.name)) > 0
    error_message = "name must be a non-empty string."
  }
}

variable "vpc_cidr" {
  description = "VPC IPv4 CIDR (e.g., 10.0.0.0/16)."
  type        = string
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid IPv4 CIDR."
  }
}

variable "enable_ipv6" {
  description = "Enable IPv6 for VPC and subnets."
  type        = bool
  default     = true
}

variable "az_count" {
  description = "How many AZs to use (1..6 typical)."
  type        = number
  default     = 3
  validation {
    condition     = var.az_count >= 1 && var.az_count <= 6
    error_message = "az_count must be between 1 and 6."
  }
}

variable "dns_hostnames" {
  description = "Enable DNS hostnames in the VPC."
  type        = bool
  default     = true
}

variable "dns_support" {
  description = "Enable DNS support in the VPC."
  type        = bool
  default     = true
}

variable "subnet_newbits" {
  description = "newbits for cidrsubnet() when carving subnets (e.g., 8 turns /16 into /24)."
  type        = number
  default     = 8
  validation {
    condition     = var.subnet_newbits >= 1 && var.subnet_newbits <= 12
    error_message = "subnet_newbits must be between 1 and 12."
  }
}

variable "nat_enabled" {
  description = "Create NAT gateway(s) for private subnets."
  type        = bool
  default     = true
}

variable "nat_per_az" {
  description = "If true, create one NAT GW per AZ; if false, create a single NAT GW."
  type        = bool
  default     = true
}

variable "single_nat_az_index" {
  description = "AZ index (0-based) to place the single NAT GW when nat_per_az=false."
  type        = number
  default     = 0
}

variable "enable_gateway_endpoints" {
  description = "Create S3 and DynamoDB gateway endpoints."
  type        = bool
  default     = true
}

variable "enable_interface_endpoints" {
  description = "Create common interface endpoints (SSM, EC2, ECR, Logs, Monitoring, STS)."
  type        = bool
  default     = true
}

variable "interface_endpoints" {
  description = "Override the default set of interface endpoints (service names without prefix)."
  type        = list(string)
  default     = [
    "ssm",
    "ssmmessages",
    "ec2",
    "ec2messages",
    "ecr.api",
    "ecr.dkr",
    "logs",
    "monitoring",
    "sts"
  ]
}

variable "allowed_endpoint_cidrs" {
  description = "CIDR blocks allowed to access interface endpoints SG (typically private VPC CIDR)."
  type        = list(string)
  default     = []
}

variable "flow_logs_enabled" {
  description = "Enable VPC Flow Logs."
  type        = bool
  default     = true
}

variable "flow_logs_destination" {
  description = "Where to send flow logs: cloudwatch or s3."
  type        = string
  default     = "cloudwatch"
  validation {
    condition     = contains(["cloudwatch", "s3"], lower(var.flow_logs_destination))
    error_message = "flow_logs_destination must be one of: cloudwatch, s3."
  }
}

variable "s3_flow_logs_bucket_arn" {
  description = "S3 bucket ARN for VPC Flow Logs if destination is s3."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch Log Group retention in days (if cloudwatch is used)."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Extra tags to apply to resources."
  type        = map(string)
  default     = {}
}

variable "create_network_acls" {
  description = "Create custom NACLs for public/private subnets."
  type        = bool
  default     = false
}

#############################################
# LOCALS
#############################################

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Deterministic subnet carving: even indexes -> public, odd -> private
  public_subnet_cidrs  = [for i in range(length(local.azs)) : cidrsubnet(var.vpc_cidr, var.subnet_newbits, i * 2)]
  private_subnet_cidrs = [for i in range(length(local.azs)) : cidrsubnet(var.vpc_cidr, var.subnet_newbits, i * 2 + 1)]

  name_prefix = replace(var.name, "/[^a-zA-Z0-9-_]/", "-")

  base_tags = merge(
    {
      "Project"   = var.name
      "Module"    = "network"
      "ManagedBy" = "Terraform"
    },
    var.tags
  )

  # Deduce endpoint SG allowed CIDRs
  endpoint_allowed_cidrs = length(var.allowed_endpoint_cidrs) > 0 ? var.allowed_endpoint_cidrs : [var.vpc_cidr]
}

#############################################
# VPC + (optional) IPv6
#############################################

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = var.dns_hostnames
  enable_dns_support   = var.dns_support

  assign_generated_ipv6_cidr_block = var.enable_ipv6

  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-vpc"
  })
}

# Assign IPv6 /56 by AWS if enabled
resource "aws_vpc_ipv6_cidr_block_association" "this" {
  count      = var.enable_ipv6 ? 1 : 0
  vpc_id     = aws_vpc.this.id
  ipv6_ipam_pool_id   = null
  ipv6_netmask_length = 56
}

#############################################
# Internet gateways
#############################################

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-igw"
  })
}

resource "aws_egress_only_internet_gateway" "eigw" {
  count  = var.enable_ipv6 ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-eigw"
  })
}

#############################################
# Subnets (public/private per AZ) + optional IPv6 /64
#############################################

resource "aws_subnet" "public" {
  for_each = {
    for idx, az in local.azs :
    idx => {
      az   = az
      cidr = local.public_subnet_cidrs[idx]
    }
  }

  vpc_id            = aws_vpc.this.id
  availability_zone = each.value.az
  cidr_block        = each.value.cidr
  map_public_ip_on_launch = true

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, each.key * 2) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-public-${each.value.az}"
    Tier = "public"
  })
}

resource "aws_subnet" "private" {
  for_each = {
    for idx, az in local.azs :
    idx => {
      az   = az
      cidr = local.private_subnet_cidrs[idx]
    }
  }

  vpc_id            = aws_vpc.this.id
  availability_zone = each.value.az
  cidr_block        = each.value.cidr
  map_public_ip_on_launch = false

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, each.key * 2 + 1) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-private-${each.value.az}"
    Tier = "private"
  })
}

#############################################
# NAT strategy
#############################################

# Allocate one EIP per AZ if nat_per_az, otherwise one EIP only
resource "aws_eip" "nat" {
  for_each = var.nat_enabled ? (
    var.nat_per_az ?
    aws_subnet.public : { for k, v in aws_subnet.public : k => v if k == var.single_nat_az_index }
  ) : {}

  domain = "vpc"
  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-nat-eip-${each.key}"
  })
}

resource "aws_nat_gateway" "this" {
  for_each = var.nat_enabled ? (
    var.nat_per_az ?
    aws_subnet.public : { for k, v in aws_subnet.public : k => v if k == var.single_nat_az_index }
  ) : {}

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id

  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-nat-${each.key}"
  })

  depends_on = [aws_internet_gateway.igw]
}

#############################################
# Route tables & associations
#############################################

# Public RTs (per AZ) — default route to IGW; IPv6 route to IGW
resource "aws_route_table" "public" {
  for_each = aws_subnet.public

  vpc_id = aws_vpc.this.id
  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-rt-public-${each.key}"
  })
}

resource "aws_route" "public_ipv4_default" {
  for_each               = aws_route_table.public
  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route" "public_ipv6_default" {
  for_each                      = var.enable_ipv6 ? aws_route_table.public : {}
  route_table_id                = each.value.id
  destination_ipv6_cidr_block   = "::/0"
  gateway_id                    = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_assoc" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public[each.key].id
}

# Private RTs (per AZ) — default route to NAT; IPv6 to egress-only IGW
resource "aws_route_table" "private" {
  for_each = aws_subnet.private

  vpc_id = aws_vpc.this.id
  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-rt-private-${each.key}"
  })
}

resource "aws_route" "private_ipv4_default" {
  for_each               = var.nat_enabled ? aws_route_table.private : {}
  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"

  nat_gateway_id = var.nat_per_az ? aws_nat_gateway.this[tonumber(each.key)].id
  : aws_nat_gateway.this[ var.single_nat_az_index ].id
}

resource "aws_route" "private_ipv6_default" {
  for_each                    = var.enable_ipv6 ? aws_route_table.private : {}
  route_table_id              = each.value.id
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = aws_egress_only_internet_gateway.eigw[0].id
}

resource "aws_route_table_association" "private_assoc" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

#############################################
# Network ACLs (optional)
#############################################

resource "aws_network_acl" "public" {
  count  = var.create_network_acls ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.base_tags, { Name = "${local.name_prefix}-nacl-public" })
}

resource "aws_network_acl_association" "public_assoc" {
  for_each = var.create_network_acls ? aws_subnet.public : {}
  network_acl_id = aws_network_acl.public[0].id
  subnet_id      = each.value.id
}

# Allow HTTP/HTTPS/SSH/ICMP out and established in (stateless rules)
resource "aws_network_acl_rule" "public_egress_all" {
  count          = var.create_network_acls ? 1 : 0
  network_acl_id = aws_network_acl.public[0].id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "public_ingress_ephemeral" {
  count          = var.create_network_acls ? 1 : 0
  network_acl_id = aws_network_acl.public[0].id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl" "private" {
  count  = var.create_network_acls ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.base_tags, { Name = "${local.name_prefix}-nacl-private" })
}

resource "aws_network_acl_association" "private_assoc" {
  for_each = var.create_network_acls ? aws_subnet.private : {}
  network_acl_id = aws_network_acl.private[0].id
  subnet_id      = each.value.id
}

resource "aws_network_acl_rule" "private_ingress_all_vpc" {
  count          = var.create_network_acls ? 1 : 0
  network_acl_id = aws_network_acl.private[0].id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
}

resource "aws_network_acl_rule" "private_egress_all" {
  count          = var.create_network_acls ? 1 : 0
  network_acl_id = aws_network_acl.private[0].id
  rule_number    = 110
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

#############################################
# VPC Endpoints
#############################################

# Gateway endpoints
resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_gateway_endpoints ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_availability_zones.available.zone_ids[0][0..-2] != "" ? substr(data.aws_availability_zones.available.names[0], 0, 9) : "aws"}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(values(aws_route_table.private)[*].id, values(aws_route_table.public)[*].id)

  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-vpce-s3"
  })
}

resource "aws_vpc_endpoint" "dynamodb" {
  count             = var.enable_gateway_endpoints ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${split("-", data.aws_availability_zones.available.names[0])[0]}-${split("-", data.aws_availability_zones.available.names[0])[1]}-${split("-", data.aws_availability_zones.available.names[0])[2]}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = values(aws_route_table.private)[*].id

  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-vpce-dynamodb"
  })
}

# Interface endpoints (in private subnets)
resource "aws_security_group" "endpoints" {
  count       = var.enable_interface_endpoints ? 1 : 0
  name        = "${local.name_prefix}-vpce-sg"
  description = "Interface VPC endpoints SG"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "Allow HTTPS from VPC CIDR(s)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = local.endpoint_allowed_cidrs
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-vpce-sg"
  })
}

locals {
  interface_services = var.enable_interface_endpoints ? (
    length(var.interface_endpoints) > 0 ? var.interface_endpoints : []
  ) : []
}

resource "aws_vpc_endpoint" "interface" {
  for_each = { for s in local.interface_services : s => s }

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${split("-", data.aws_availability_zones.available.names[0])[0]}-${split("-", data.aws_availability_zones.available.names[0])[1]}-${split("-", data.aws_availability_zones.available.names[0])[2]}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  security_group_ids  = var.enable_interface_endpoints ? [aws_security_group.endpoints[0].id] : []
  subnet_ids          = values(aws_subnet.private)[*].id

  tags = merge(local.base_tags, {
    Name = "${local.name_prefix}-vpce-${each.value}"
  })
}

#############################################
# Flow Logs
#############################################

# CloudWatch variant
resource "aws_cloudwatch_log_group" "flow" {
  count             = var.flow_logs_enabled && lower(var.flow_logs_destination) == "cloudwatch" ? 1 : 0
  name              = "/vpc/${local.name_prefix}/flow-logs"
  retention_in_days = var.log_retention_days
  tags              = merge(local.base_tags, { Name = "${local.name_prefix}-flow-logs" })
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "flow" {
  count = var.flow_logs_enabled && lower(var.flow_logs_destination) == "cloudwatch" ? 1 : 0
  name  = "${local.name_prefix}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.base_tags
}

resource "aws_iam_role_policy" "flow" {
  count = var.flow_logs_enabled && lower(var.flow_logs_destination) == "cloudwatch" ? 1 : 0
  name  = "${local.name_prefix}-vpc-flow-logs-policy"
  role  = aws_iam_role.flow[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"],
      Resource = "${aws_cloudwatch_log_group.flow[0].arn}:*"
    }]
  })
}

# S3 variant – requires bucket ARN
resource "aws_flow_log" "this" {
  count = var.flow_logs_enabled ? 1 : 0

  log_destination_type = lower(var.flow_logs_destination) == "s3" ? "s3" : "cloud-watch-logs"
  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"

  destination_arn = lower(var.flow_logs_destination) == "s3" ? var.s3_flow_logs_bucket_arn : aws_cloudwatch_log_group.flow[0].arn
  iam_role_arn    = lower(var.flow_logs_destination) == "s3" ? null : aws_iam_role.flow[0].arn

  tags = merge(local.base_tags, { Name = "${local.name_prefix}-vpc-flow-logs" })
}

#############################################
# OUTPUTS
#############################################

output "vpc_id" {
  value       = aws_vpc.this.id
  description = "VPC ID."
}

output "vpc_cidr_block" {
  value       = aws_vpc.this.cidr_block
  description = "VPC IPv4 CIDR."
}

output "vpc_ipv6_cidr_block" {
  value       = try(aws_vpc.this.ipv6_cidr_block, null)
  description = "VPC IPv6 CIDR (if enabled)."
}

output "azs" {
  value       = local.azs
  description = "Availability Zones used."
}

output "public_subnet_ids" {
  value       = [for k in sort(keys(aws_subnet.public)) : aws_subnet.public[k].id]
  description = "Public subnet IDs (ordered by AZ index)."
}

output "private_subnet_ids" {
  value       = [for k in sort(keys(aws_subnet.private)) : aws_subnet.private[k].id]
  description = "Private subnet IDs (ordered by AZ index)."
}

output "public_route_table_ids" {
  value       = [for k in sort(keys(aws_route_table.public)) : aws_route_table.public[k].id]
  description = "Public route table IDs."
}

output "private_route_table_ids" {
  value       = [for k in sort(keys(aws_route_table.private)) : aws_route_table.private[k].id]
  description = "Private route table IDs."
}

output "internet_gateway_id" {
  value       = aws_internet_gateway.igw.id
  description = "Internet Gateway ID."
}

output "egress_only_internet_gateway_id" {
  value       = try(aws_egress_only_internet_gateway.eigw[0].id, null)
  description = "Egress-only Internet Gateway ID (IPv6)."
}

output "nat_gateway_ids" {
  value       = [for k in sort(keys(aws_nat_gateway.this)) : aws_nat_gateway.this[k].id]
  description = "NAT Gateway IDs (empty if disabled)."
}

output "gateway_endpoints" {
  value = {
    s3       = try(aws_vpc_endpoint.s3[0].id, null)
    dynamodb = try(aws_vpc_endpoint.dynamodb[0].id, null)
  }
  description = "Gateway VPC Endpoint IDs."
}

output "interface_endpoints" {
  value       = { for k, v in aws_vpc_endpoint.interface : k => v.id }
  description = "Interface VPC Endpoint IDs keyed by service short name."
}

output "endpoint_security_group_id" {
  value       = try(aws_security_group.endpoints[0].id, null)
  description = "Security Group ID for interface endpoints."
}

#############################################
# VALIDATION & SAFETY CHECKS
#############################################

# Ensure S3 ARN provided if S3 destination chosen
locals {
  s3_dest_chosen = var.flow_logs_enabled && lower(var.flow_logs_destination) == "s3"
}

resource "null_resource" "validate_s3_arn" {
  count = local.s3_dest_chosen && trim(var.s3_flow_logs_bucket_arn) == "" ? 1 : 0
  triggers = {
    error = "s3_flow_logs_bucket_arn must be provided when flow_logs_destination='s3'."
  }
}
