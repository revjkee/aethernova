#########################################
# Terraform / Provider
#########################################
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

provider "aws" {
  region = var.region
}

#########################################
# Variables
#########################################
variable "region" {
  description = "AWS region"
  type        = string
}

variable "name" {
  description = "Base name/prefix for all resources (e.g. ledger-core)"
  type        = string
}

variable "cidr_block" {
  description = "Primary IPv4 CIDR for VPC (e.g. 10.20.0.0/16)"
  type        = string
}

variable "azs" {
  description = "Availability Zones to use (e.g. [\"eu-west-1a\",\"eu-west-1b\"])"
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "Explicit CIDRs for public subnets (one per AZ). If empty, derived via cidrsubnets."
  type        = list(string)
  default     = []
}

variable "private_subnet_cidrs" {
  description = "Explicit CIDRs for private subnets (one per AZ). If empty, derived via cidrsubnets."
  type        = list(string)
  default     = []
}

variable "create_ipv6" {
  description = "Allocate /56 IPv6 block to VPC and /64 to subnets"
  type        = bool
  default     = false
}

variable "enable_dns_support" {
  description = "Enable VPC DNS support"
  type        = bool
  default     = true
}

variable "enable_dns_hostnames" {
  description = "Enable VPC DNS hostnames"
  type        = bool
  default     = true
}

variable "map_public_ip_on_launch" {
  description = "Map public IPs in public subnets"
  type        = bool
  default     = true
}

variable "enable_nat" {
  description = "Create NAT Gateway(s) for private subnets"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway across all AZs (cost-efficient). If false, per-AZ NAT."
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_logs_destination" {
  description = "Destination for Flow Logs: cloudwatch or s3"
  type        = string
  default     = "cloudwatch"
  validation {
    condition     = contains(["cloudwatch", "s3"], lower(var.flow_logs_destination))
    error_message = "flow_logs_destination must be one of: cloudwatch, s3"
  }
}

variable "flow_logs_s3_bucket_arn" {
  description = "S3 bucket ARN for Flow Logs (required if destination = s3)"
  type        = string
  default     = ""
}

variable "enable_interface_endpoints" {
  description = "Create commonly used Interface VPC Endpoints (PrivateLink)"
  type        = bool
  default     = false
}

variable "interface_endpoints" {
  description = <<EOT
Map of interface endpoints to create. Keys are service short names without 'com.amazonaws.<region>.'
Example:
{
  "ecr.api"   = {},
  "ecr.dkr"   = {},
  "logs"      = {},
  "sts"       = {}
}
EOT
  type    = map(object({ security_group_ingress_cidrs = optional(list(string)) }))
  default = {}
}

variable "enable_gateway_endpoints" {
  description = "Create Gateway VPC Endpoints (S3, DynamoDB)"
  type        = bool
  default     = true
}

variable "gateway_endpoints" {
  description = "List of gateway endpoints to create (supported: s3, dynamodb)"
  type        = list(string)
  default     = ["s3", "dynamodb"]
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}

#########################################
# Locals
#########################################
locals {
  base_tags = merge(
    {
      "Name"                       = var.name
      "app.kubernetes.io/name"     = var.name
      "app.kubernetes.io/part-of"  = "ledger-core"
      "terraform.module"           = "network"
    },
    var.tags
  )

  az_count = length(var.azs)

  # Если CIDR подсетей не заданы, рассчитываем их детерминированно.
  # Делим /16 на /20 (пример) — 16 подсетей; половина на public, половина на private по AZ.
  # Вы можете адаптировать разрядность при необходимости.
  derived_public = length(var.public_subnet_cidrs) == 0 ? [
    for i in range(local.az_count) : cidrsubnet(var.cidr_block, 4, i) # /20
  ] : var.public_subnet_cidrs

  derived_private = length(var.private_subnet_cidrs) == 0 ? [
    for i in range(local.az_count) : cidrsubnet(var.cidr_block, 4, i + 16) # смещение
  ] : var.private_subnet_cidrs

  # Проверка размеров
  check_sizes = length(local.derived_public) == local.az_count && length(local.derived_private) == local.az_count

  # Сопоставление AZ -> CIDR
  public_subnets_map  = { for idx, az in var.azs : az => local.derived_public[idx] }
  private_subnets_map = { for idx, az in var.azs : az => local.derived_private[idx] }

  # Имя сервиса для интерфейсных endpoints (регионозависимо)
  if_ep_map = {
    for k, v in var.interface_endpoints :
    k => format("com.amazonaws.%s.%s", var.region, k)
  }
}

#########################################
# VPC & IGW
#########################################
resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_support   = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames

  tags = merge(local.base_tags, { "Name" = "${var.name}-vpc" })
}

# IPv6 /56 + распределение /64 по подсетям
resource "aws_vpc_ipv6_cidr_block_association" "this" {
  count = var.create_ipv6 ? 1 : 0

  vpc_id            = aws_vpc[this].id
  ipv6_ipam_pool_id = null
  amazon_provided_ipv6_cidr_block = true
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.base_tags, { "Name" = "${var.name}-igw" })
}

#########################################
# Subnets
#########################################
resource "aws_subnet" "public" {
  for_each = local.public_subnets_map

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = each.value
  map_public_ip_on_launch = var.map_public_ip_on_launch

  ipv6_cidr_block                 = var.create_ipv6 ? cidrsubnet(aws_vpc_ipv6_cidr_block_association.this[0].ipv6_cidr_block, 8, index(keys(local.public_subnets_map), each.key)) : null
  assign_ipv6_address_on_creation = var.create_ipv6

  tags = merge(local.base_tags, {
    "Name" = "${var.name}-public-${substr(each.key, length(each.key)-1, 1)}"
    "tier" = "public"
  })
}

resource "aws_subnet" "private" {
  for_each = local.private_subnets_map

  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = each.value

  ipv6_cidr_block                 = var.create_ipv6 ? cidrsubnet(aws_vpc_ipv6_cidr_block_association.this[0].ipv6_cidr_block, 8, local.az_count + index(keys(local.private_subnets_map), each.key)) : null
  assign_ipv6_address_on_creation = var.create_ipv6

  tags = merge(local.base_tags, {
    "Name" = "${var.name}-private-${substr(each.key, length(each.key)-1, 1)}"
    "tier" = "private"
  })
}

#########################################
# Route Tables & Routes
#########################################
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.base_tags, { "Name" = "${var.name}-public-rt" })
}

resource "aws_route" "public_inet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route" "public_inet_v6" {
  count = var.create_ipv6 ? 1 : 0

  route_table_id              = aws_route_table.public.id
  destination_ipv6_cidr_block = "::/0"
  gateway_id                  = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_assoc" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# NAT (single или per-AZ)
resource "aws_eip" "nat" {
  count = var.enable_nat ? (var.single_nat_gateway ? 1 : local.az_count) : 0
  domain = "vpc"
  tags   = merge(local.base_tags, { "Name" = "${var.name}-nat-eip-${count.index}" })
}

resource "aws_nat_gateway" "this" {
  count = var.enable_nat ? (var.single_nat_gateway ? 1 : local.az_count) : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = element(values(aws_subnet.public)[*].id, var.single_nat_gateway ? 0 : count.index)
  tags          = merge(local.base_tags, { "Name" = "${var.name}-nat-${count.index}" })

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_route_table" "private" {
  for_each = aws_subnet.private

  vpc_id = aws_vpc.this.id
  tags   = merge(local.base_tags, { "Name" = "${var.name}-private-rt-${substr(each.key, length(each.key)-1, 1)}" })
}

resource "aws_route" "private_default" {
  for_each = aws_route_table.private

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.enable_nat ? (var.single_nat_gateway ? aws_nat_gateway.this[0].id : element(aws_nat_gateway.this[*].id, index(keys(aws_route_table.private), each.key))) : null
}

resource "aws_route" "private_default_v6" {
  for_each = var.create_ipv6 ? aws_route_table.private : {}

  route_table_id              = each.value.id
  destination_ipv6_cidr_block = "::/0"
  egress_only_internet_gateway_id = null # можно добавить aws_egress_only_internet_gateway при необходимости
}

resource "aws_route_table_association" "private_assoc" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

#########################################
# VPC Endpoints
#########################################
# Gateway endpoints (S3/DynamoDB)
resource "aws_vpc_endpoint" "gateway" {
  for_each = var.enable_gateway_endpoints ? toset(var.gateway_endpoints) : toset([])

  vpc_id       = aws_vpc.this.id
  service_name = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private[key].id for key in keys(aws_route_table.private)]

  tags = merge(local.base_tags, { "Name" = "${var.name}-vpce-${each.key}" })
}

# Security Group для интерфейсных endpoints
resource "aws_security_group" "endpoints" {
  count  = var.enable_interface_endpoints && length(var.interface_endpoints) > 0 ? 1 : 0
  name   = "${var.name}-endpoints-sg"
  vpc_id = aws_vpc.this.id

  description = "Security group for Interface VPC Endpoints"
  tags        = merge(local.base_tags, { "Name" = "${var.name}-endpoints-sg" })
}

# Разрешим трафик из приватных подсетей к интерфейсным ENI (443)
resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  count             = var.enable_interface_endpoints && length(var.interface_endpoints) > 0 ? 1 : 0
  security_group_id = aws_security_group.endpoints[0].id
  description       = "HTTPS from private subnets"
  cidr_ipv4         = aws_vpc.this.cidr_block
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "endpoints_all" {
  count             = var.enable_interface_endpoints && length(var.interface_endpoints) > 0 ? 1 : 0
  security_group_id = aws_security_group.endpoints[0].id
  description       = "All egress"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# Interface endpoints
resource "aws_vpc_endpoint" "interface" {
  for_each = var.enable_interface_endpoints ? local.if_ep_map : {}

  vpc_id              = aws_vpc.this.id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  security_group_ids  = length(aws_security_group.endpoints) > 0 ? [aws_security_group.endpoints[0].id] : null
  subnet_ids          = [for s in aws_subnet.private : s.id]

  tags = merge(local.base_tags, { "Name" = "${var.name}-vpce-${each.key}" })
}

#########################################
# Flow Logs
#########################################
# CloudWatch Logs
resource "aws_cloudwatch_log_group" "flow" {
  count             = var.enable_vpc_flow_logs && lower(var.flow_logs_destination) == "cloudwatch" ? 1 : 0
  name              = "/aws/vpc/flow/${var.name}"
  retention_in_days = 30
  tags              = merge(local.base_tags, { "Name" = "${var.name}-flow" })
}

# IAM role for VPC Flow Logs to CloudWatch
data "aws_iam_policy_document" "flow_assume" {
  count = var.enable_vpc_flow_logs && lower(var.flow_logs_destination) == "cloudwatch" ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow" {
  count              = var.enable_vpc_flow_logs && lower(var.flow_logs_destination) == "cloudwatch" ? 1 : 0
  name               = "${var.name}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_assume[0].json
  tags               = local.base_tags
}

data "aws_iam_policy_document" "flow_cwl" {
  count = var.enable_vpc_flow_logs && lower(var.flow_logs_destination) == "cloudwatch" ? 1 : 0

  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]
    resources = ["${aws_cloudwatch_log_group.flow[0].arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_cwl" {
  count  = var.enable_vpc_flow_logs && lower(var.flow_logs_destination) == "cloudwatch" ? 1 : 0
  name   = "${var.name}-vpc-flow-logs-cwl"
  role   = aws_iam_role.flow[0].id
  policy = data.aws_iam_policy_document.flow_cwl[0].json
}

# S3 destination requires bucket policy to allow delivery; предполагается, что бакет уже создан и политика настроена снаружи.
# Создаем сам Flow Log (общая часть)
resource "aws_flow_log" "this" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  vpc_id = aws_vpc.this.id
  traffic_type = "ALL"

  log_destination_type = lower(var.flow_logs_destination) == "s3" ? "s3" : "cloud-watch-logs"

  # CloudWatch
  log_group_name  = lower(var.flow_logs_destination) == "cloudwatch" ? aws_cloudwatch_log_group.flow[0].name : null
  iam_role_arn    = lower(var.flow_logs_destination) == "cloudwatch" ? aws_iam_role.flow[0].arn : null

  # S3
  log_destination = lower(var.flow_logs_destination) == "s3" ? var.flow_logs_s3_bucket_arn : null

  tags = merge(local.base_tags, { "Name" = "${var.name}-vpc-flow" })
}

#########################################
# Outputs
#########################################
output "vpc_id" {
  value       = aws_vpc.this.id
  description = "VPC ID"
}

output "vpc_cidr_block" {
  value       = aws_vpc.this.cidr_block
  description = "VPC IPv4 CIDR"
}

output "vpc_ipv6_cidr_block" {
  value       = var.create_ipv6 ? aws_vpc_ipv6_cidr_block_association.this[0].ipv6_cidr_block : null
  description = "VPC IPv6 /56 (if enabled)"
}

output "public_subnet_ids" {
  value       = [for s in aws_subnet.public : s.id]
  description = "Public subnet IDs"
}

output "private_subnet_ids" {
  value       = [for s in aws_subnet.private : s.id]
  description = "Private subnet IDs"
}

output "public_route_table_id" {
  value       = aws_route_table.public.id
  description = "Public route table ID"
}

output "private_route_table_ids" {
  value       = [for k, rt in aws_route_table.private : rt.id]
  description = "Private route table IDs"
}

output "nat_gateway_ids" {
  value       = var.enable_nat ? [for n in aws_nat_gateway.this : n.id] : []
  description = "NAT Gateway IDs"
}

output "gateway_endpoint_ids" {
  value       = [for k, e in aws_vpc_endpoint.gateway : e.id]
  description = "Gateway endpoint IDs"
}

output "interface_endpoint_ids" {
  value       = [for k, e in aws_vpc_endpoint.interface : e.id]
  description = "Interface endpoint IDs"
}
