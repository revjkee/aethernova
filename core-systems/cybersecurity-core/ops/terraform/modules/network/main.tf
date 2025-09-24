##############################################
# cybersecurity-core / ops / terraform
# modules / network / main.tf
# Industrial-grade AWS VPC networking module
##############################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60"
    }
  }
}

##############################################
# Variables (с безопасными дефолтами)
##############################################

variable "name" {
  description = "Базовое имя (префикс) ресурсов."
  type        = string
  default     = "cybersecurity-core"
}

variable "environment" {
  description = "Среда (dev/stage/prod)."
  type        = string
  default     = "dev"
}

variable "region" {
  description = "AWS регион (для локальных вычислений/логики; провайдер настраивается вне модуля)."
  type        = string
  default     = "eu-north-1"
}

variable "tags" {
  description = "Глобальные тэги для всех поддерживаемых ресурсов."
  type        = map(string)
  default     = {}
}

variable "vpc_cidr" {
  description = "CIDR блока VPC."
  type        = string
  default     = "10.60.0.0/16"
}

variable "enable_ipv6" {
  description = "Включить IPv6 CIDR и egress-only IGW."
  type        = bool
  default     = true
}

variable "azs" {
  description = "Список AZ; если пусто — берутся первые az_count AZ."
  type        = list(string)
  default     = []
}

variable "az_count" {
  description = "Количество AZ при автоподборе."
  type        = number
  default     = 3
}

variable "subnet_new_bits" {
  description = "Сколько бит добавить при разбиении VPC CIDR на подсети."
  type        = number
  default     = 8
}

variable "private_subnet_offset" {
  description = "Смещение индекса для генерации private CIDR."
  type        = number
  default     = 32
}

variable "intra_subnet_offset" {
  description = "Смещение индекса для генерации intra CIDR."
  type        = number
  default     = 64
}

variable "public_subnet_cidrs" {
  description = "Необязательный список CIDR для public подсетей (по AZ)."
  type        = list(string)
  default     = []
}

variable "private_subnet_cidrs" {
  description = "Необязательный список CIDR для private подсетей (по AZ)."
  type        = list(string)
  default     = []
}

variable "intra_subnet_cidrs" {
  description = "Необязательный список CIDR для intra/isolated подсетей (по AZ)."
  type        = list(string)
  default     = []
}

variable "enable_nat_gateways" {
  description = "Создавать NAT Gateways для private egress."
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Один NAT GW (в первой public подсети) вместо per-AZ."
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Включить VPC Flow Logs."
  type        = bool
  default     = true
}

variable "flow_logs_destination_type" {
  description = "Тип назначения flow logs: cloudwatch или s3."
  type        = string
  default     = "cloudwatch"
  validation {
    condition     = contains(["cloudwatch", "s3"], var.flow_logs_destination_type)
    error_message = "flow_logs_destination_type must be 'cloudwatch' or 's3'."
  }
}

variable "flow_logs_log_retention_days" {
  description = "Срок хранения логов в днях (CloudWatch Logs)."
  type        = number
  default     = 30
}

variable "enable_kms_for_logs" {
  description = "Создать KMS ключ и шифровать CloudWatch Log Group."
  type        = bool
  default     = true
}

variable "flow_logs_s3_bucket_arn" {
  description = "ARN существующего S3 bucket для Flow Logs (если выбран s3)."
  type        = string
  default     = ""
}

variable "enable_vpc_endpoints" {
  description = "Создать VPC Endpoints."
  type        = bool
  default     = true
}

variable "endpoint_services_interface" {
  description = "Сервисы для interface VPC endpoints (без s3/dynamodb)."
  type        = list(string)
  default = [
    "com.amazonaws.${var.region}.ecr.api",
    "com.amazonaws.${var.region}.ecr.dkr",
    "com.amazonaws.${var.region}.logs",
    "com.amazonaws.${var.region}.ec2",
    "com.amazonaws.${var.region}.sts",
    "com.amazonaws.${var.region}.ssm",
    "com.amazonaws.${var.region}.ssmmessages"
  ]
}

##############################################
# Locals
##############################################

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  std_tags = merge(
    {
      "Name"        = "${var.name}-${var.environment}"
      "Environment" = var.environment
      "Module"      = "cybersecurity-core/network"
      "ManagedBy"   = "Terraform"
    },
    var.tags
  )

  azs = length(var.azs) > 0 ? var.azs : slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # CIDR генерация при отсутствии списков
  public_cidrs = length(var.public_subnet_cidrs) > 0 ? var.public_subnet_cidrs : [
    for idx in range(length(local.azs)) : cidrsubnet(var.vpc_cidr, var.subnet_new_bits, idx)
  ]

  private_cidrs = length(var.private_subnet_cidrs) > 0 ? var.private_subnet_cidrs : [
    for idx in range(length(local.azs)) : cidrsubnet(var.vpc_cidr, var.subnet_new_bits, var.private_subnet_offset + idx)
  ]

  intra_cidrs = length(var.intra_subnet_cidrs) > 0 ? var.intra_subnet_cidrs : [
    for idx in range(length(local.azs)) : cidrsubnet(var.vpc_cidr, var.subnet_new_bits, var.intra_subnet_offset + idx)
  ]

  az_map = { for i, az in local.azs : az => i }

  # Карты AZ->CIDR
  public_map  = { for az, i in local.az_map : az => local.public_cidrs[i] }
  private_map = { for az, i in local.az_map : az => local.private_cidrs[i] }
  intra_map   = { for az, i in local.az_map : az => local.intra_cidrs[i] }

  # Имя для ресурсов
  vpc_name = "${var.name}-${var.environment}-vpc"
}

##############################################
# VPC + (опционально) IPv6
##############################################

resource "aws_vpc" "this" {
  cidr_block                       = var.vpc_cidr
  enable_dns_hostnames             = true
  enable_dns_support               = true
  assign_generated_ipv6_cidr_block = var.enable_ipv6

  tags = merge(local.std_tags, { "Name" = local.vpc_name })
}

resource "aws_egress_only_internet_gateway" "ipv6" {
  count  = var.enable_ipv6 ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.std_tags, { "Name" = "${local.vpc_name}-egress6" })
}

##############################################
# Internet Gateway
##############################################

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.std_tags, { "Name" = "${local.vpc_name}-igw" })
}

##############################################
# Subnets (public/private/intra)
##############################################

resource "aws_subnet" "public" {
  for_each = local.public_map

  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = true

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, lookup(local.az_map, each.key)) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.std_tags, {
    "Name" = "${var.name}-${var.environment}-public-${each.key}"
    "Tier" = "public"
  })
}

resource "aws_subnet" "private" {
  for_each = local.private_map

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  availability_zone = each.key

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, var.private_subnet_offset + lookup(local.az_map, each.key)) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.std_tags, {
    "Name" = "${var.name}-${var.environment}-private-${each.key}"
    "Tier" = "private"
  })
}

resource "aws_subnet" "intra" {
  for_each = local.intra_map

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  availability_zone = each.key

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, var.intra_subnet_offset + lookup(local.az_map, each.key)) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.std_tags, {
    "Name" = "${var.name}-${var.environment}-intra-${each.key}"
    "Tier" = "intra"
  })
}

##############################################
# NAT Gateways (single или per-AZ)
##############################################

# EIP под NAT GW
resource "aws_eip" "nat" {
  count      = var.enable_nat_gateways ? (var.single_nat_gateway ? 1 : length(local.azs)) : 0
  domain     = "vpc"
  depends_on = [aws_internet_gateway.igw]
  tags       = merge(local.std_tags, { "Name" = "${local.vpc_name}-nat-eip-${count.index}" })
}

# NAT GW в public подсетях
resource "aws_nat_gateway" "this" {
  count = var.enable_nat_gateways ? (var.single_nat_gateway ? 1 : length(local.azs)) : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = var.single_nat_gateway ? element(values(aws_subnet.public)[*].id, 0) : element(values(aws_subnet.public)[*].id, count.index)
  tags          = merge(local.std_tags, { "Name" = "${local.vpc_name}-nat-${count.index}" })

  depends_on = [aws_internet_gateway.igw]
}

##############################################
# Route Tables & Associations
##############################################

# Public RT -> IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.std_tags, { "Name" = "${local.vpc_name}-rt-public" })
}

resource "aws_route" "public_ipv4_inet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route" "public_ipv6_inet" {
  count = var.enable_ipv6 ? 1 : 0

  route_table_id              = aws_route_table.public.id
  destination_ipv6_cidr_block = "::/0"
  gateway_id                  = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# Private RTs -> NAT GW (single или per-AZ)
resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.this.id
  tags = merge(local.std_tags, {
    "Name" = "${local.vpc_name}-rt-private-${each.key}"
    "Tier" = "private"
  })
}

resource "aws_route" "private_ipv4_egress" {
  for_each = aws_route_table.private

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.enable_nat_gateways ? (
    var.single_nat_gateway
    ? aws_nat_gateway.this[0].id
    : aws_nat_gateway.this[lookup(local.az_map, each.key)].id
  ) : null
  depends_on = [aws_nat_gateway.this]
}

resource "aws_route" "private_ipv6_egress" {
  for_each = var.enable_ipv6 ? aws_route_table.private : {}

  route_table_id              = each.value.id
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = var.enable_ipv6 ? aws_egress_only_internet_gateway.ipv6[0].id : null
  depends_on                  = [aws_egress_only_internet_gateway.ipv6]
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

# Intra RT (без egress в интернет)
resource "aws_route_table" "intra" {
  for_each = aws_subnet.intra
  vpc_id   = aws_vpc.this.id
  tags = merge(local.std_tags, {
    "Name" = "${local.vpc_name}-rt-intra-${each.key}"
    "Tier" = "intra"
  })
}

resource "aws_route_table_association" "intra" {
  for_each       = aws_subnet.intra
  subnet_id      = each.value.id
  route_table_id = aws_route_table.intra[each.key].id
}

##############################################
# Default Security Group hardening (deny-all)
##############################################

resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  # Без правил — deny-all (и ingress, и egress)
  revoke_rules_on_delete = true

  tags = merge(local.std_tags, { "Name" = "${local.vpc_name}-default-sg-locked" })
}

##############################################
# Minimal NACLs (пример: public allow egress 80/443/ephemeral)
##############################################

resource "aws_network_acl" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.std_tags, { "Name" = "${local.vpc_name}-nacl-public" })
}

# Ingress: allow established/related (ephemeral)
resource "aws_network_acl_rule" "public_ingress_ephemeral" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# Egress: allow 80
resource "aws_network_acl_rule" "public_egress_http" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 110
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 80
  to_port        = 80
}

# Egress: allow 443
resource "aws_network_acl_rule" "public_egress_https" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 120
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# Ассоциации NACL с public подсетями
resource "aws_network_acl_association" "public_assoc" {
  for_each       = aws_subnet.public
  network_acl_id = aws_network_acl.public.id
  subnet_id      = each.value.id
}

##############################################
# VPC Endpoints (S3/DynamoDB gateway + interface)
##############################################

resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_vpc_endpoints ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private[one(keys(aws_route_table.private))].id] # placeholder to force eval

  # Все private RT
  dynamic "route_table_ids" {
    for_each = [true]
    content {
      # dummy (ignored)
    }
  }

  # Правильная передача всех private RT
  depends_on = [aws_route_table.private]
  tags       = merge(local.std_tags, { "Name" = "${local.vpc_name}-vpce-s3" })
}

# Хак для передачи всех RT (Terraform не поддерживает динамику на простом списке без костылей):
locals {
  private_rts = [for k, rt in aws_route_table.private : rt.id]
}

resource "aws_vpc_endpoint_route_table_association" "s3_rtas" {
  for_each        = { for idx, id in local.private_rts : idx => id }
  route_table_id  = each.value
  vpc_endpoint_id = aws_vpc_endpoint.s3[0].id
}

resource "aws_vpc_endpoint" "dynamodb" {
  count             = var.enable_vpc_endpoints ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  tags              = merge(local.std_tags, { "Name" = "${local.vpc_name}-vpce-dynamodb" })
}

resource "aws_vpc_endpoint_route_table_association" "dynamodb_rtas" {
  for_each        = var.enable_vpc_endpoints ? { for idx, id in local.private_rts : idx => id } : {}
  route_table_id  = each.value
  vpc_endpoint_id = aws_vpc_endpoint.dynamodb[0].id
}

# SG для interface endpoints (разрешаем 443 из VPC CIDR)
resource "aws_security_group" "endpoints" {
  count       = var.enable_vpc_endpoints ? 1 : 0
  name        = "${var.name}-${var.environment}-vpce-sg"
  description = "SG for Interface VPC Endpoints"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(local.std_tags, { "Name" = "${local.vpc_name}-vpce-sg" })
}

resource "aws_vpc_endpoint" "interfaces" {
  for_each = var.enable_vpc_endpoints ? toset(var.endpoint_services_interface) : toset([])

  vpc_id              = aws_vpc.this.id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.endpoints[0].id]
  subnet_ids          = [for s in aws_subnet.private : s.id]

  tags = merge(local.std_tags, { "Name" = "${local.vpc_name}-vpce-${replace(each.value, "com.amazonaws.${var.region}.", "")}" })
}

##############################################
# Flow Logs (CloudWatch Logs с KMS) или S3
##############################################

# KMS для CloudWatch Logs (опционально)
resource "aws_kms_key" "logs" {
  count                   = var.enable_flow_logs && var.flow_logs_destination_type == "cloudwatch" && var.enable_kms_for_logs ? 1 : 0
  description             = "KMS key for VPC Flow Logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = merge(local.std_tags, { "Name" = "${local.vpc_name}-kms-logs" })
}

resource "aws_cloudwatch_log_group" "flow" {
  count             = var.enable_flow_logs && var.flow_logs_destination_type == "cloudwatch" ? 1 : 0
  name              = "/vpc/${local.vpc_name}/flow-logs"
  retention_in_days = var.flow_logs_log_retenti_
