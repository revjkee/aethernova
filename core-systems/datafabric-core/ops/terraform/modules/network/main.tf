terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

############################
# Variables
############################
variable "name" {
  description = "Базовое имя для ресурсов (используется в тегах и именах)."
  type        = string
}

variable "cidr_block" {
  description = "Основной IPv4 CIDR для VPC (например, 10.0.0.0/16)."
  type        = string
}

variable "azs" {
  description = "Список доступных AZ для развёртывания подсетей (напр. [\"eu-central-1a\", \"eu-central-1b\"])."
  type        = list(string)
}

variable "enable_ipv6" {
  description = "Включить IPv6 CIDR/маршрутизацию."
  type        = bool
  default     = true
}

variable "public_subnet_newbits" {
  description = "Сколько бит выделить под каждую публичную подсеть (cidrsubnet)."
  type        = number
  default     = 4
}

variable "private_subnet_newbits" {
  description = "Сколько бит выделить под каждую приватную подсеть (cidrsubnet)."
  type        = number
  default     = 4
}

variable "nat_gateway_strategy" {
  description = "Стратегия NAT: none | single | per-az."
  type        = string
  default     = "per-az"
  validation {
    condition     = contains(["none", "single", "per-az"], var.nat_gateway_strategy)
    error_message = "nat_gateway_strategy должен быть one of: none, single, per-az."
  }
}

variable "tags" {
  description = "Дополнительные теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "enable_flow_logs" {
  description = "Включить VPC Flow Logs в CloudWatch."
  type        = bool
  default     = true
}

variable "flow_logs_retention_days" {
  description = "Срок хранения CloudWatch логов."
  type        = number
  default     = 30
}

variable "enable_gateway_endpoints" {
  description = "Создавать gateway VPC endpoints для S3 и DynamoDB."
  type        = bool
  default     = true
}

variable "interface_endpoints" {
  description = "Список сервисов для interface VPC endpoints (например, [\"ecr.api\", \"ecr.dkr\", \"logs\"])."
  type        = list(string)
  default     = []
}

############################
# Locals / tags
############################
locals {
  common_tags = merge(
    {
      "Name"                       = var.name
      "app.kubernetes.io/name"     = var.name
      "app.kubernetes.io/part-of"  = var.name
      "terraform.module"           = "network"
      "terraform"                  = "true"
    },
    var.tags
  )

  # Индексы для публичных/приватных подсетей
  public_indexes  = toset([for i in range(length(var.azs)) : i])
  private_indexes = toset([for i in range(length(var.azs)) : i])

  # IPv6 разбивка на /64 из /56 блока VPC (AWS выдаёт /56 по умолчанию)
  ipv6_per_subnet_prefix = 64
}

############################
# VPC + IPv6
############################
resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  assign_generated_ipv6_cidr_block = var.enable_ipv6

  tags = merge(local.common_tags, { "Component" = "vpc" })
}

############################
# IGW / Egress-only IGW (IPv6)
############################
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Component" = "igw" })
}

resource "aws_egress_only_internet_gateway" "this" {
  count  = var.enable_ipv6 ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Component" = "eigw" })
}

############################
# Публичные подсети
############################
resource "aws_subnet" "public" {
  for_each = local.public_indexes

  vpc_id                  = aws_vpc.this.id
  availability_zone       = var.azs[each.key]
  cidr_block              = cidrsubnet(var.cidr_block, var.public_subnet_newbits, each.key)
  map_public_ip_on_launch = true

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, local.ipv6_per_subnet_prefix - 56, each.key) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.common_tags, {
    "Component"                    = "subnet-public"
    "kubernetes.io/role/elb"       = "1"
    "kubernetes.io/cluster/${var.name}" = "shared"
    "Name"                         = "${var.name}-public-${each.key}"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Component" = "rtb-public" })
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

resource "aws_route_table_association" "public_assoc" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

############################
# NAT Gateways (по стратегии)
############################
# EIP для NAT
resource "aws_eip" "nat" {
  for_each = var.nat_gateway_strategy == "per-az" ? local.private_indexes : (
    var.nat_gateway_strategy == "single" ? toset([0]) : toset([])
  )
  domain = "vpc"
  tags   = merge(local.common_tags, { "Component" = "eip-nat", "Index" = tostring(each.key) })
}

# NAT Gateway в публичных подсетях
resource "aws_nat_gateway" "this" {
  for_each = aws_eip.nat

  allocation_id = each.value.id
  subnet_id     = aws_subnet.public[tonumber(each.key)].id

  tags = merge(local.common_tags, { "Component" = "nat", "Index" = tostring(each.key) })

  depends_on = [aws_internet_gateway.this]
}

############################
# Приватные подсети и маршрутизация
############################
resource "aws_subnet" "private" {
  for_each = local.private_indexes

  vpc_id            = aws_vpc.this.id
  availability_zone = var.azs[each.key]
  cidr_block        = cidrsubnet(var.cidr_block, var.private_subnet_newbits, each.key + 100) # смещение для уникальности

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, local.ipv6_per_subnet_prefix - 56, each.key + 100) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.common_tags, {
    "Component"                          = "subnet-private"
    "kubernetes.io/role/internal-elb"    = "1"
    "kubernetes.io/cluster/${var.name}"  = "shared"
    "Name"                               = "${var.name}-private-${each.key}"
  })
}

# Отдельная RTB на AZ, чтобы гибко вести в свой NAT
resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.this.id
  tags     = merge(local.common_tags, { "Component" = "rtb-private", "Index" = tostring(each.key) })
}

# IPv4 default route через NAT (если выбран single, все private идут в NAT[0])
resource "aws_route" "private_ipv4_default" {
  for_each = aws_route_table.private

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"

  nat_gateway_id = (
    var.nat_gateway_strategy == "per-az" ? aws_nat_gateway.this[tonumber(each.key)].id :
    var.nat_gateway_strategy == "single"  ? aws_nat_gateway.this[0].id :
    null
  )

  lifecycle {
    precondition {
      condition     = (var.nat_gateway_strategy == "none") ? false : true
      error_message = "NAT выключен (nat_gateway_strategy=none), не создаём маршрут 0.0.0.0/0."
    }
  }
}

# IPv6 default route через egress-only IGW для приватных
resource "aws_route" "private_ipv6_default" {
  for_each = var.enable_ipv6 ? aws_route_table.private : {}
  route_table_id              = each.value.id
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = aws_egress_only_internet_gateway.this[0].id
}

resource "aws_route_table_association" "private_assoc" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

############################
# VPC Flow Logs → CloudWatch
############################
resource "aws_cloudwatch_log_group" "flow" {
  count             = var.enable_flow_logs ? 1 : 0
  name              = "/aws/vpc/${var.name}/flow-logs"
  retention_in_days = var.flow_logs_retention_days
  tags              = merge(local.common_tags, { "Component" = "flow-logs" })
}

resource "aws_iam_role" "flow" {
  count = var.enable_flow_logs ? 1 : 0
  name  = "${var.name}-vpc-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow" {
  count = var.enable_flow_logs ? 1 : 0
  name  = "${var.name}-vpc-flow-logs-policy"
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

resource "aws_flow_log" "this" {
  count                = var.enable_flow_logs ? 1 : 0
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.flow[0].name
  iam_role_arn         = aws_iam_role.flow[0].arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.this.id
  tags                 = merge(local.common_tags, { "Component" = "flow-log" })
}

############################
# VPC Endpoints
############################
# Gateway endpoints (S3/DynamoDB) — прикрепляем к приватным RTB
resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_gateway_endpoints ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for r in aws_route_table.private : r.id]
  tags              = merge(local.common_tags, { "Component" = "vpce-s3" })
}

resource "aws_vpc_endpoint" "dynamodb" {
  count             = var.enable_gateway_endpoints ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for r in aws_route_table.private : r.id]
  tags              = merge(local.common_tags, { "Component" = "vpce-dynamodb" })
}

# Interface endpoints (по списку)
resource "aws_security_group" "vpce" {
  count       = length(var.interface_endpoints) > 0 ? 1 : 0
  name        = "${var.name}-vpce"
  description = "Security group for Interface VPC Endpoints"
  vpc_id      = aws_vpc.this.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = var.enable_ipv6 ? ["::/0"] : []
  }

  ingress {
    description      = "From private subnets"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [for s in aws_subnet.private : s.cidr_block]
    ipv6_cidr_blocks = var.enable_ipv6 ? [for s in aws_subnet.private : s.ipv6_cidr_block] : []
  }

  tags = merge(local.common_tags, { "Component" = "sg-vpce" })
}

data "aws_region" "current" {}

resource "aws_vpc_endpoint" "interface" {
  for_each          = toset(var.interface_endpoints)
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.${each.key}"
  vpc_endpoint_type = "Interface"
  private_dns_enabled = true
  security_group_ids  = aws_security_group.vpce.*.id

  subnet_ids = [for s in aws_subnet.private : s.id]

  tags = merge(local.common_tags, { "Component" = "vpce-interface", "Service" = each.key })
}

############################
# Outputs (минимально необходимые)
############################
output "vpc_id" {
  value       = aws_vpc.this.id
  description = "ID созданной VPC."
}

output "public_subnet_ids" {
  value       = [for s in aws_subnet.public : s.id]
  description = "Список ID публичных подсетей."
}

output "private_subnet_ids" {
  value       = [for s in aws_subnet.private : s.id]
  description = "Список ID приватных подсетей."
}

output "public_route_table_id" {
  value       = aws_route_table.public.id
  description = "ID публичной таблицы маршрутизации."
}

output "private_route_table_ids" {
  value       = [for r in aws_route_table.private : r.id]
  description = "ID приватных таблиц маршрутизации (по AZ)."
}

output "nat_gateway_ids" {
  value       = [for n in aws_nat_gateway.this : n.id]
  description = "ID NAT шлюзов (может быть пустым при стратегии none)."
}

output "ipv6_cidr_block" {
  value       = var.enable_ipv6 ? aws_vpc.this.ipv6_cidr_block : null
  description = "Выданный AWS IPv6 CIDR для VPC (если включено)."
}
