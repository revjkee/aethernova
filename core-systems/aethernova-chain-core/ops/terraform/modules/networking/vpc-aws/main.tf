############################################################
# File: aethernova-chain-core/ops/terraform/modules/networking/vpc-aws/main.tf
# Purpose: Industrial-grade VPC with IPv4/IPv6, IGW, egress-only IGW,
#          public/private subnets across AZs, NAT (single or per-AZ),
#          route tables, gateway endpoints (S3/DynamoDB),
#          VPC Flow Logs to CloudWatch with IAM role.
############################################################

terraform {
  required_version = ">= 1.4.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

############################################################
# Variables (module-local for a self-contained single-file delivery)
############################################################
variable "region"                    { type = string }
variable "project"                   { type = string }
variable "environment"               { type = string }
variable "vpc_cidr"                  { type = string }
variable "az_count"                  { type = number  default = 2 }
variable "nat_strategy"              {
  type        = string
  default     = "single" # "single" | "per_az"
  validation {
    condition     = contains(["single", "per_az"], var.nat_strategy)
    error_message = "nat_strategy must be one of: single, per_az."
  }
}
variable "enable_ipv6"               { type = bool    default = true }
# newbits: for /16 VPC, 8 -> /24 subnets; adjust per your plan
variable "public_subnet_newbits"     { type = number  default = 8 }
variable "private_subnet_newbits"    { type = number  default = 8 }
variable "flow_logs_retention_days"  { type = number  default = 90 }
variable "tags"                      { type = map(string) default = {} }

############################################################
# Data: Availability Zones (stable ordering)
############################################################
data "aws_availability_zones" "this" {
  state = "available"
}

locals {
  azs                 = slice(data.aws_availability_zones.this.names, 0, var.az_count)
  name_prefix         = "${lower(var.project)}-${lower(var.environment)}"
  vpc_tags            = merge(var.tags, { Name = "${local.name_prefix}-vpc", project = var.project, env = var.environment, managed_by = "terraform", module = "networking/vpc-aws" })
  public_rt_name      = "${local.name_prefix}-rt-public"
  private_rt_name     = "${local.name_prefix}-rt-private"
  nat_keys            = var.nat_strategy == "per_az" ? local.azs : [local.azs[0]]
  nat_default_key     = local.nat_keys[0]
}

############################################################
# VPC
############################################################
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  # IPv6 block for VPC (if enabled)
  assign_generated_ipv6_cidr_block = var.enable_ipv6

  tags = local.vpc_tags
}

############################################################
# Internet Gateway (for public subnets)
############################################################
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${local.name_prefix}-igw" })
}

############################################################
# Subnets: public and private across AZs (IPv4 + optional IPv6)
############################################################
# Public subnets
resource "aws_subnet" "public" {
  for_each = toset(local.azs)

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = cidrsubnet(var.vpc_cidr, var.public_subnet_newbits, index(local.azs, each.key))
  map_public_ip_on_launch = true

  # IPv6 per-subnet /64 from VPC IPv6 /56 by default (8 new bits)
  ipv6_cidr_block                     = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, index(local.azs, each.key)) : null
  assign_ipv6_address_on_creation     = var.enable_ipv6

  tags = merge(var.tags, {
    Name      = "${local.name_prefix}-subnet-public-${each.key}"
    tier      = "public"
    az        = each.key
    managed_by= "terraform"
  })
}

# Private subnets
resource "aws_subnet" "private" {
  for_each = toset(local.azs)

  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = cidrsubnet(var.vpc_cidr, var.private_subnet_newbits, length(local.azs) + index(local.azs, each.key))

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, length(local.azs) + index(local.azs, each.key)) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(var.tags, {
    Name      = "${local.name_prefix}-subnet-private-${each.key}"
    tier      = "private"
    az        = each.key
    managed_by= "terraform"
  })
}

############################################################
# Public Route Table + routes + associations
############################################################
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = local.public_rt_name, tier = "public" })
}

resource "aws_route" "public_ipv4_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route" "public_ipv6_default" {
  count                  = var.enable_ipv6 ? 1 : 0
  route_table_id         = aws_route_table.public.id
  destination_ipv6_cidr_block = "::/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_assoc" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

############################################################
# NAT: single or per-AZ (best practice — per-AZ for HA)
############################################################
# EIPs for NAT
resource "aws_eip" "nat" {
  for_each = toset(local.nat_keys)
  domain   = "vpc"
  tags     = merge(var.tags, { Name = "${local.name_prefix}-eip-nat-${each.key}" })
}

# NAT Gateways in public subnets
resource "aws_nat_gateway" "this" {
  for_each      = aws_eip.nat
  allocation_id = each.value.id
  subnet_id     = aws_subnet.public[each.key].id
  tags          = merge(var.tags, { Name = "${local.name_prefix}-nat-${each.key}" })

  depends_on = [aws_internet_gateway.igw] # ensure IGW exists for public subnet egress
}

############################################################
# Private Route Tables + default routes to NAT + associations
############################################################
resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.this.id
  tags     = merge(var.tags, { Name = "${local.private_rt_name}-${each.key}", tier = "private", az = each.key })
}

# IPv4 default route to NAT
resource "aws_route" "private_ipv4_default" {
  for_each                  = aws_route_table.private
  route_table_id            = each.value.id
  destination_cidr_block    = "0.0.0.0/0"
  nat_gateway_id            = var.nat_strategy == "per_az" ? aws_nat_gateway.this[each.key].id : aws_nat_gateway.this[local.nat_default_key].id
}

# IPv6 default route to egress-only IGW (for private subnets)
resource "aws_egress_only_internet_gateway" "egress6" {
  count  = var.enable_ipv6 ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${local.name_prefix}-eigw" })
}

resource "aws_route" "private_ipv6_default" {
  for_each                      = var.enable_ipv6 ? aws_route_table.private : {}
  route_table_id                = each.value.id
  destination_ipv6_cidr_block   = "::/0"
  egress_only_internet_gateway_id = aws_egress_only_internet_gateway.egress6[0].id
}

resource "aws_route_table_association" "private_assoc" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

############################################################
# Gateway Endpoints: S3 & DynamoDB (no IGW/NAT required)
############################################################
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for rt in aws_route_table.private : rt.id]
  tags              = merge(var.tags, { Name = "${local.name_prefix}-vpce-s3", type = "gateway" })
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for rt in aws_route_table.private : rt.id]
  tags              = merge(var.tags, { Name = "${local.name_prefix}-vpce-dynamodb", type = "gateway" })
}

############################################################
# VPC Flow Logs -> CloudWatch Logs (requires IAM role)
############################################################
resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/vpc/${local.name_prefix}/flow-logs"
  retention_in_days = var.flow_logs_retention_days
  tags              = merge(var.tags, { Name = "${local.name_prefix}-cwl-flowlogs" })
}

data "aws_iam_policy_document" "flowlogs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flowlogs_role" {
  name               = "${local.name_prefix}-flowlogs-role"
  assume_role_policy = data.aws_iam_policy_document.flowlogs_assume.json
  tags               = merge(var.tags, { Name = "${local.name_prefix}-flowlogs-role" })
}

# Minimal permissions to put logs into CloudWatch
data "aws_iam_policy_document" "flowlogs_policy" {
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "flowlogs_role_policy" {
  name   = "${local.name_prefix}-flowlogs-policy"
  role   = aws_iam_role.flowlogs_role.id
  policy = data.aws_iam_policy_document.flowlogs_policy.json
}

resource "aws_flow_log" "vpc" {
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.vpc_flow.name
  iam_role_arn         = aws_iam_role.flowlogs_role.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.this.id
  tags                 = merge(var.tags, { Name = "${local.name_prefix}-flowlogs" })
}
