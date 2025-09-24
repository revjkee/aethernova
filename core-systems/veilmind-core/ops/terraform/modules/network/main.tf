terraform {
  required_version = ">= 1.4.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

########################################
# Data & locals
########################################

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

locals {
  name = var.name

  # Сколько AZ использовать
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Теги по умолчанию
  tags = merge(
    {
      Project     = var.name
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.tags
  )

  # Разбиение адресного пространства на подсети.
  # Для исключения пересечений используем смещённый netnum по группам.
  public_subnet_cidrs = {
    for idx, az in local.azs :
    az => cidrsubnet(var.vpc_cidr, var.subnet_newbits.public, idx)
  }

  private_subnet_cidrs = {
    for idx, az in local.azs :
    az => cidrsubnet(var.vpc_cidr, var.subnet_newbits.private, idx + length(local.azs))
  }

  isolated_subnet_cidrs = {
    for idx, az in local.azs :
    az => cidrsubnet(var.vpc_cidr, var.subnet_newbits.isolated, idx + 2 * length(local.azs))
  }

  # NAT режимы
  nat_azs = var.enable_nat_gateway ? (
    var.single_nat_gateway ? [local.azs[0]] : local.azs
  ) : []

  # Для IPv6 подсетей
  ipv6_assign = var.enable_ipv6
}

########################################
# VPC & IGW / Egress-only IGW
########################################

resource "aws_vpc" "this" {
  cidr_block                           = var.vpc_cidr
  enable_dns_hostnames                 = true
  enable_dns_support                   = true
  assign_generated_ipv6_cidr_block     = var.enable_ipv6
  instance_tenancy                     = "default"

  tags = merge(local.tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-igw" })
}

# Для IPv6 приватного egress без NAT
resource "aws_egress_only_internet_gateway" "this" {
  count  = var.enable_ipv6 && var.enable_private_ipv6_egress ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-eigw" })
}

########################################
# Subnets
########################################

resource "aws_subnet" "public" {
  for_each = local.public_subnet_cidrs

  vpc_id                          = aws_vpc.this.id
  cidr_block                      = each.value
  availability_zone               = each.key
  map_public_ip_on_launch         = true
  assign_ipv6_address_on_creation = local.ipv6_assign

  ipv6_cidr_block = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, index(local.azs, each.key)) : null

  tags = merge(local.tags, {
    Name = "${local.name}-public-${replace(each.key, "/[a-z-]/", "")}"
    Tier = "public"
  })
}

resource "aws_subnet" "private" {
  for_each = local.private_subnet_cidrs

  vpc_id                          = aws_vpc.this.id
  cidr_block                      = each.value
  availability_zone               = each.key
  map_public_ip_on_launch         = false
  assign_ipv6_address_on_creation = local.ipv6_assign

  ipv6_cidr_block = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, index(local.azs, each.key) + length(local.azs)) : null

  tags = merge(local.tags, {
    Name = "${local.name}-private-${replace(each.key, "/[a-z-]/", "")}"
    Tier = "private"
  })
}

resource "aws_subnet" "isolated" {
  for_each = local.isolated_subnet_cidrs

  vpc_id                          = aws_vpc.this.id
  cidr_block                      = each.value
  availability_zone               = each.key
  map_public_ip_on_launch         = false
  assign_ipv6_address_on_creation = local.ipv6_assign

  ipv6_cidr_block = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, index(local.azs, each.key) + 2 * length(local.azs)) : null

  tags = merge(local.tags, {
    Name = "${local.name}-isolated-${replace(each.key, "/[a-z-]/", "")}"
    Tier = "isolated"
  })
}

########################################
# NAT Gateways (single or per-AZ)
########################################

resource "aws_eip" "nat" {
  for_each = toset(local.nat_azs)

  domain = "vpc"

  tags = merge(local.tags, { Name = "${local.name}-nat-eip-${replace(each.key, "/[a-z-]/", "")}" })
}

resource "aws_nat_gateway" "this" {
  for_each = aws_eip.nat

  allocation_id = each.value.id
  subnet_id     = aws_subnet.public[each.key].id

  tags = merge(local.tags, { Name = "${local.name}-nat-${replace(each.key, "/[a-z-]/", "")}" })

  depends_on = [aws_internet_gateway.this]
}

########################################
# Route tables & routes
########################################

# Public
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-rt-public" })
}

resource "aws_route" "public_ipv4_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route" "public_ipv6_default" {
  count                  = var.enable_ipv6 ? 1 : 0
  route_table_id         = aws_route_table.public.id
  destination_ipv6_cidr_block = "::/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# Private (per AZ)
resource "aws_route_table" "private" {
  for_each = toset(local.azs)
  vpc_id   = aws_vpc.this.id
  tags     = merge(local.tags, { Name = "${local.name}-rt-private-${replace(each.key, "/[a-z-]/", "")}" })
}

resource "aws_route" "private_ipv4_default" {
  for_each                 = var.enable_nat_gateway ? toset(local.azs) : []
  route_table_id           = aws_route_table.private[each.key].id
  destination_cidr_block   = "0.0.0.0/0"
  nat_gateway_id           = var.single_nat_gateway ? aws_nat_gateway.this[local.azs[0]].id : aws_nat_gateway.this[each.key].id
}

resource "aws_route" "private_ipv6_default" {
  for_each                        = (var.enable_ipv6 && var.enable_private_ipv6_egress) ? toset(local.azs) : []
  route_table_id                  = aws_route_table.private[each.key].id
  destination_ipv6_cidr_block     = "::/0"
  egress_only_gateway_id          = aws_egress_only_internet_gateway.this[0].id
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

# Isolated (no default routes)
resource "aws_route_table" "isolated" {
  for_each = toset(local.azs)
  vpc_id   = aws_vpc.this.id
  tags     = merge(local.tags, { Name = "${local.name}-rt-isolated-${replace(each.key, "/[a-z-]/", "")}" })
}

resource "aws_route_table_association" "isolated" {
  for_each       = aws_subnet.isolated
  subnet_id      = each.value.id
  route_table_id = aws_route_table.isolated[each.key].id
}

########################################
# VPC Flow Logs -> CloudWatch Logs (KMS)
########################################

resource "aws_kms_key" "flowlogs" {
  count                   = var.enable_vpc_flow_logs && var.flow_logs.kms_enable ? 1 : 0
  description             = "${local.name} VPC FlowLogs"
  enable_key_rotation     = true
  deletion_window_in_days = 10

  tags = merge(local.tags, { Name = "${local.name}-flowlogs-kms" })
}

resource "aws_cloudwatch_log_group" "flowlogs" {
  count             = var.enable_vpc_flow_logs ? 1 : 0
  name              = "/aws/vpc/${local.name}/flow-logs"
  retention_in_days = var.flow_logs.retention_days
  kms_key_id        = var.flow_logs.kms_enable ? aws_kms_key.flowlogs[0].arn : null

  tags = local.tags
}

resource "aws_iam_role" "flowlogs" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  name  = "${local.name}-flowlogs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy" "flowlogs" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  name  = "${local.name}-flowlogs-policy"
  role  = aws_iam_role.flowlogs[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
        Resource = "${aws_cloudwatch_log_group.flowlogs[0].arn}:*"
      }
    ]
  })
}

resource "aws_flow_log" "this" {
  count                 = var.enable_vpc_flow_logs ? 1 : 0
  log_destination_type  = "cloud-watch-logs"
  log_group_name        = aws_cloudwatch_log_group.flowlogs[0].name
  iam_role_arn          = aws_iam_role.flowlogs[0].arn
  traffic_type          = var.flow_logs.traffic_type
  vpc_id                = aws_vpc.this.id
  max_aggregation_interval = 60
  tags                  = merge(local.tags, { Name = "${local.name}-flowlog" })
}

########################################
# VPC Endpoints
########################################

# Security Group для Interface Endpoints (ENI)
resource "aws_security_group" "vpce" {
  name        = "${local.name}-vpce-sg"
  description = "Allow HTTPS from VPC to Interface Endpoints"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS from VPC CIDR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    ipv6_cidr_blocks = var.enable_ipv6 ? [aws_vpc.this.ipv6_cidr_block] : []
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = var.enable_ipv6 ? ["::/0"] : []
  }

  tags = merge(local.tags, { Name = "${local.name}-vpce-sg" })
}

# Gateway Endpoints для приватного доступа к S3 и DynamoDB
resource "aws_vpc_endpoint" "gateway" {
  for_each = var.enable_gateway_endpoints ? {
    for s in ["s3", "dynamodb"] : s => s
  } : {}

  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.this.name}.${each.key}"
  vpc_endpoint_type = "Gateway"

  route_table_ids = concat(
    [for rt in aws_route_table.private  : rt.value.id],
    [for rt in aws_route_table.isolated : rt.value.id]
  )

  tags = merge(local.tags, { Name = "${local.name}-gw-${each.key}" })
}

# Interface Endpoints
resource "aws_vpc_endpoint" "interface" {
  for_each = { for s in var.interface_endpoints : s => s }

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.this.name}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.private : s.value.id]
  private_dns_enabled = var.interface_private_dns
  security_group_ids  = [aws_security_group.vpce.id]

  tags = merge(local.tags, { Name = "${local.name}-if-${each.key}" })
}

########################################
# Variables
########################################

variable "name" {
  description = "Базовое имя ресурса (префикс Name)."
  type        = string
}

variable "environment" {
  description = "Окружение (dev/stage/prod/…)"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR блока VPC (например, 10.0.0.0/16)."
  type        = string
}

variable "az_count" {
  description = "Количество AZ для развёртывания подсетей."
  type        = number
  default     = 3
}

variable "enable_ipv6" {
  description = "Включить IPv6 CIDR для VPC и подсетей."
  type        = bool
  default     = true
}

variable "enable_private_ipv6_egress" {
  description = "Разрешить egress IPv6 из приватных подсетей через Egress-Only IGW."
  type        = bool
  default     = true
}

variable "subnet_newbits" {
  description = "Размерности подсетей (смещение битов для cidrsubnet) для public/private/isolated."
  type = object({
    public   = number
    private  = number
    isolated = number
  })
  default = {
    public   = 4  # /20 из /16
    private  = 4
    isolated = 6  # /22 из /16
  }
}

variable "enable_nat_gateway" {
  description = "Включить NAT Gateway для приватных подсетей (IPv4 egress)."
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Один NAT GW на VPC (true) или по одному на каждую AZ (false)."
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Включить VPC Flow Logs."
  type        = bool
  default     = true
}

variable "flow_logs" {
  description = "Параметры Flow Logs."
  type = object({
    retention_days = number
    kms_enable     = bool
    traffic_type   = string
  })
  default = {
    retention_days = 90
    kms_enable     = true
    traffic_type   = "ALL"
  }
}

variable "enable_gateway_endpoints" {
  description = "Создавать gateway endpoints (S3, DynamoDB) для приватных/изолированных таблиц маршрутизации."
  type        = bool
  default     = true
}

variable "interface_endpoints" {
  description = "Список interface‑endpoint сервисов (без префикса региона)."
  type        = list(string)
  default = [
    "sts",
    "ecr.api",
    "ecr.dkr",
    "ec2",
    "ec2messages",
    "ssm",
    "ssmmessages",
    "kms",
    "secretsmanager",
    "logs",
    "monitoring"
  ]
}

variable "interface_private_dns" {
  description = "Включить Private DNS для interface‑endpoint’ов."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Дополнительные теги на все ресурсы."
  type        = map(string)
  default     = {}
}

########################################
# Outputs
########################################

output "vpc_id" {
  value       = aws_vpc.this.id
  description = "ID созданной VPC."
}

output "vpc_cidr_block" {
  value       = aws_vpc.this.cidr_block
  description = "CIDR VPC."
}

output "vpc_ipv6_cidr_block" {
  value       = var.enable_ipv6 ? aws_vpc.this.ipv6_cidr_block : null
  description = "IPv6 CIDR VPC (если включён)."
}

output "public_subnet_ids" {
  value       = [for s in aws_subnet.public : s.value.id]
  description = "Список ID публичных подсетей."
}

output "private_subnet_ids" {
  value       = [for s in aws_subnet.private : s.value.id]
  description = "Список ID приватных подсетей."
}

output "isolated_subnet_ids" {
  value       = [for s in aws_subnet.isolated : s.value.id]
  description = "Список ID изолированных подсетей."
}

output "igw_id" {
  value       = aws_internet_gateway.this.id
  description = "ID Internet Gateway."
}

output "nat_gateway_ids" {
  value       = [for n in aws_nat_gateway.this : n.value.id]
  description = "ID NAT Gateway (один или по AZ)."
}

output "public_route_table_id" {
  value       = aws_route_table.public.id
  description = "ID публичной таблицы маршрутов."
}

output "private_route_table_ids" {
  value       = [for rt in aws_route_table.private : rt.value.id]
  description = "ID приватных таблиц маршрутов (по AZ)."
}

output "isolated_route_table_ids" {
  value       = [for rt in aws_route_table.isolated : rt.value.id]
  description = "ID изолированных таблиц маршрутов (по AZ)."
}

output "vpc_endpoint_ids" {
  value = merge(
    { for k, v in aws_vpc_endpoint.gateway   : k => v.id },
    { for k, v in aws_vpc_endpoint.interface : k => v.id }
  )
  description = "ID созданных VPC Endpoints (gateway + interface)."
}

output "flow_logs_log_group" {
  value       = try(aws_cloudwatch_log_group.flowlogs[0].name, null)
  description = "Имя Log Group для VPC Flow Logs (если включено)."
}
