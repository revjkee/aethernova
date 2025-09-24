terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# ВХОДНЫЕ ПЕРЕМЕННЫЕ
# -----------------------------------------------------------------------------

variable "name" {
  description = "Имя VPC/сети (используется в тегах, логах, именах ресурсов)."
  type        = string
}

variable "region" {
  description = "AWS регион, например eu-north-1."
  type        = string
}

variable "cidr_block" {
  description = "CIDR VPC (IPv4), например 10.0.0.0/16."
  type        = string
}

variable "azs" {
  description = "Список AZ региона в порядке предпочтения (например [\"eu-north-1a\",\"eu-north-1b\",\"eu-north-1c\"])."
  type        = list(string)
}

variable "enable_ipv6" {
  description = "Включить IPv6 для VPC и подсетей."
  type        = bool
  default     = false
}

variable "enable_dns_hostnames" {
  description = "Включить DNS hostnames в VPC."
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Включить DNS support в VPC."
  type        = bool
  default     = true
}

variable "public_subnets" {
  description = "Необязательно: список IPv4 CIDR публичных подсетей (по числу AZ). Если null — рассчитываются автоматически."
  type        = list(string)
  default     = null
}

variable "private_subnets" {
  description = "Необязательно: список IPv4 CIDR приватных подсетей (по числу AZ). Если null — рассчитываются автоматически."
  type        = list(string)
  default     = null
}

variable "database_subnets" {
  description = "Необязательно: список IPv4 CIDR для подсетей под БД (по числу AZ). Если null и create_database_subnets=true — рассчитываются автоматически."
  type        = list(string)
  default     = null
}

variable "create_database_subnets" {
  description = "Создавать подсети для БД."
  type        = bool
  default     = false
}

variable "public_newbits" {
  description = "Разрядность для автогенерации публичных подсетей через cidrsubnet."
  type        = number
  default     = 4
}

variable "private_newbits" {
  description = "Разрядность для автогенерации приватных подсетей через cidrsubnet."
  type        = number
  default     = 4
}

variable "database_newbits" {
  description = "Разрядность для автогенерации БД-подсетей через cidrsubnet."
  type        = number
  default     = 4
}

variable "single_nat_gateway" {
  description = "true — один NAT на регион; false — NAT в каждой AZ."
  type        = bool
  default     = true
}

variable "enable_nat" {
  description = "Создавать NAT Gateway для приватного выхода в интернет (IPv4)."
  type        = bool
  default     = true
}

variable "enable_dhcp_options" {
  description = "Создавать и ассоциировать DHCP options."
  type        = bool
  default     = true
}

variable "dhcp_domain_name" {
  description = "Произвольное значение domain-name в DHCP options (если пусто — значение не задается)."
  type        = string
  default     = ""
}

variable "flow_logs_enabled" {
  description = "Включить VPC Flow Logs в CloudWatch."
  type        = bool
  default     = true
}

variable "flow_logs_retention_days" {
  description = "Retention лог-группы CloudWatch (дни)."
  type        = number
  default     = 30
}

variable "vpc_endpoints" {
  description = <<EOT
Карта включения VPC endpoints:
s3, dynamodb (gateway);
ssm, ec2messages, ssmmessages, ecrapi, ecrdkr, logs, cloudwatch, kms, sts, secretsmanager (interface).
EOT
  type = object({
    s3             = optional(bool, true)
    dynamodb       = optional(bool, true)
    ssm            = optional(bool, false)
    ec2messages    = optional(bool, false)
    ssmmessages    = optional(bool, false)
    ecrapi         = optional(bool, false)
    ecrdkr         = optional(bool, false)
    logs           = optional(bool, false)
    cloudwatch     = optional(bool, false)
    kms            = optional(bool, false)
    sts            = optional(bool, false)
    secretsmanager = optional(bool, false)
  })
  default = {}
}

variable "private_dns_for_interface_endpoints" {
  description = "Включать приватный DNS для interface endpoints."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Глобальные теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "vpc_tags" {
  description = "Дополнительные теги только для VPC."
  type        = map(string)
  default     = {}
}

variable "subnet_tags" {
  description = "Дополнительные теги только для подсетей."
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# ЛОКАЛЫ
# -----------------------------------------------------------------------------

locals {
  common_tags = merge(
    {
      "Name"                       = var.name
      "app.kubernetes.io/part-of"  = "chronowatch-core"
      "module"                     = "network"
    },
    var.tags
  )

  az_map = { for idx, az in var.azs : az => idx }

  # Автогенерация IPv4 CIDR для подсетей с безопасными смещениями (чтобы не пересекались)
  public_cidrs_auto  = [for i in range(length(var.azs)) : cidrsubnet(var.cidr_block, var.public_newbits, i)]
  private_cidrs_auto = [for i in range(length(var.azs)) : cidrsubnet(var.cidr_block, var.private_newbits, i + 100)]
  db_cidrs_auto      = [for i in range(length(var.azs)) : cidrsubnet(var.cidr_block, var.database_newbits, i + 200)]

  public_cidrs  = var.public_subnets  != null ? var.public_subnets  : local.public_cidrs_auto
  private_cidrs = var.private_subnets != null ? var.private_subnets : local.private_cidrs_auto
  db_cidrs      = var.database_subnets != null ? var.database_subnets : local.db_cidrs_auto

  create_db = var.create_database_subnets

  # Для gateway endpoints привязываем приватные RT
  private_rts_ids = [for k, rt in aws_route_table.private : rt.id]
}

# -----------------------------------------------------------------------------
# ПРОВАЙДЕР
# -----------------------------------------------------------------------------

provider "aws" {
  region = var.region
}

# -----------------------------------------------------------------------------
# РЕСУРСЫ VPC / IPv6 / DHCP
# -----------------------------------------------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support

  tags = merge(local.common_tags, var.vpc_tags, { "Name" = "${var.name}-vpc" })
}

# IPv6 CIDR (Amazon-provided). Создается только при enable_ipv6.
resource "aws_vpc_ipv6_cidr_block_association" "this" {
  count     = var.enable_ipv6 ? 1 : 0
  vpc_id    = aws_vpc.this.id
  network_border_group = var.region
}

# DHCP options (опционально)
resource "aws_vpc_dhcp_options" "this" {
  count = var.enable_dhcp_options ? 1 : 0

  # domain-name задаем только если указан.
  dynamic "domain_name" {
    for_each = length(var.dhcp_domain_name) > 0 ? [1] : []
    content  = var.dhcp_domain_name
  }

  domain_name_servers = ["AmazonProvidedDNS"]

  tags = merge(local.common_tags, { "Name" = "${var.name}-dhcp" })
}

resource "aws_vpc_dhcp_options_association" "this" {
  count          = var.enable_dhcp_options ? 1 : 0
  vpc_id         = aws_vpc.this.id
  dhcp_options_id = aws_vpc_dhcp_options.this[0].id
}

# Интернет-шлюз
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Name" = "${var.name}-igw" })
}

# Egress-only IGW (IPv6)
resource "aws_egress_only_internet_gateway" "this" {
  count  = var.enable_ipv6 ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Name" = "${var.name}-eigw" })
}

# -----------------------------------------------------------------------------
# ПОДСЕТИ (PUBLIC / PRIVATE / DB) ПО AZ
# -----------------------------------------------------------------------------

# Публичные
resource "aws_subnet" "public" {
  for_each = local.az_map

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = local.public_cidrs[each.value]
  map_public_ip_on_launch = true

  # IPv6 (если включено)
  assign_ipv6_address_on_creation = var.enable_ipv6
  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc_ipv6_cidr_block_association.this[0].ipv6_cidr_block, 8, each.value) : null

  tags = merge(local.common_tags, var.subnet_tags, {
    "Name" = "${var.name}-public-${each.value + 1}"
    "tier" = "public"
  })
}

# Приватные
resource "aws_subnet" "private" {
  for_each = local.az_map

  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = local.private_cidrs[each.value]

  assign_ipv6_address_on_creation = var.enable_ipv6
  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc_ipv6_cidr_block_association.this[0].ipv6_cidr_block, 8, each.value + 64) : null

  tags = merge(local.common_tags, var.subnet_tags, {
    "Name" = "${var.name}-private-${each.value + 1}"
    "tier" = "private"
  })
}

# Подсети под базы данных (опционально, без маршрута в интернет)
resource "aws_subnet" "database" {
  for_each = local.create_db ? local.az_map : {}

  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = local.db_cidrs[each.value]

  assign_ipv6_address_on_creation = var.enable_ipv6
  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc_ipv6_cidr_block_association.this[0].ipv6_cidr_block, 8, each.value + 128) : null

  tags = merge(local.common_tags, var.subnet_tags, {
    "Name" = "${var.name}-db-${each.value + 1}"
    "tier" = "database"
  })
}

# -----------------------------------------------------------------------------
# ROUTE TABLES / ROUTES / ASSOCIATIONS
# -----------------------------------------------------------------------------

# Публичные RT и ассоциации
resource "aws_route_table" "public" {
  for_each = aws_subnet.public

  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Name" = "${var.name}-rt-public-${each.value.availability_zone}" })
}

resource "aws_route" "public_ipv4_inet" {
  for_each               = aws_route_table.public
  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route" "public_ipv6_inet" {
  for_each = var.enable_ipv6 ? aws_route_table.public : {}

  route_table_id              = each.value.id
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = aws_egress_only_internet_gateway.this[0].id
}

resource "aws_route_table_association" "public_assoc" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public[each.key].id
}

# Приватные RT и ассоциации
resource "aws_route_table" "private" {
  for_each = aws_subnet.private

  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Name" = "${var.name}-rt-private-${each.value.availability_zone}" })
}

resource "aws_route_table_association" "private_assoc" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

# DB RT и ассоциации (без выхода в интернет)
resource "aws_route_table" "database" {
  for_each = aws_subnet.database

  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Name" = "${var.name}-rt-db-${each.value.availability_zone}" })
}

resource "aws_route_table_association" "database_assoc" {
  for_each       = aws_subnet.database
  subnet_id      = each.value.id
  route_table_id = aws_route_table.database[each.key].id
}

# -----------------------------------------------------------------------------
# NAT Gateways (IPv4)
# -----------------------------------------------------------------------------

# EIP для NAT
resource "aws_eip" "nat" {
  count      = var.enable_nat ? (var.single_nat_gateway ? 1 : length(var.azs)) : 0
  domain     = "vpc"
  depends_on = [aws_internet_gateway.this]

  tags = merge(local.common_tags, { "Name" = "${var.name}-nat-eip-${count.index + 1}" })
}

# Один NAT в первой публичной подсети
resource "aws_nat_gateway" "single" {
  count         = var.enable_nat && var.single_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = element([for k, s in aws_subnet.public : s.id], 0)

  tags = merge(local.common_tags, { "Name" = "${var.name}-nat-single" })
}

# NAT в каждой AZ
resource "aws_nat_gateway" "per_az" {
  for_each = var.enable_nat && !var.single_nat_gateway ? aws_subnet.public : {}

  allocation_id = aws_eip.nat[lookup(local.az_map, each.value.availability_zone)].id
  subnet_id     = each.value.id

  tags = merge(local.common_tags, { "Name" = "${var.name}-nat-${each.value.availability_zone}" })
}

# Маршруты приватных RT через NAT
resource "aws_route" "private_default_ipv4" {
  for_each               = aws_route_table.private
  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.enable_nat ? (var.single_nat_gateway ? aws_nat_gateway.single[0].id : aws_nat_gateway.per_az[each.key].id) : null
}

# Приватный IPv6 по EIGW (если включено)
resource "aws_route" "private_default_ipv6" {
  for_each = var.enable_ipv6 ? aws_route_table.private : {}

  route_table_id              = each.value.id
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = aws_egress_only_internet_gateway.this[0].id
}

# -----------------------------------------------------------------------------
# VPC ENDPOINTS
# -----------------------------------------------------------------------------

# Gateway endpoints: S3, DynamoDB
resource "aws_vpc_endpoint" "s3" {
  count             = try(var.vpc_endpoints.s3, true) ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.private_rts_ids

  tags = merge(local.common_tags, { "Name" = "${var.name}-vpce-s3" })
}

resource "aws_vpc_endpoint" "dynamodb" {
  count             = try(var.vpc_endpoints.dynamodb, true) ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.private_rts_ids

  tags = merge(local.common_tags, { "Name" = "${var.name}-vpce-dynamodb" })
}

# Interface endpoints: карта сервисов -> короткие имена
locals {
  interface_services = {
    ssm            = "ssm"
    ec2messages    = "ec2messages"
    ssmmessages    = "ssmmessages"
    ecrapi         = "ecr.api"
    ecrdkr         = "ecr.dkr"
    logs           = "logs"
    cloudwatch     = "monitoring"
    kms            = "kms"
    sts            = "sts"
    secretsmanager = "secretsmanager"
  }

  interface_enabled = {
    for k, v in local.interface_services :
    k => try(var.vpc_endpoints[k], false)
  }
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name}-endpoints-sg"
  description = "Security group for interface endpoints"
  vpc_id      = aws_vpc.this.id

  # Разрешаем исходящий трафик
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = var.enable_ipv6 ? ["::/0"] : []
  }

  # Входящие — по умолчанию закрыты (endpoint и так приватный)
  tags = merge(local.common_tags, { "Name" = "${var.name}-endpoints-sg" })
}

resource "aws_vpc_endpoint" "interface" {
  for_each          = { for k, enabled in local.interface_enabled : k => enabled if enabled }
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.${local.interface_services[each.key]}"
  vpc_endpoint_type = "Interface"
  private_dns_enabled = var.private_dns_for_interface_endpoints
  subnet_ids        = [for s in aws_subnet.private : s.id]
  security_group_ids = [aws_security_group.endpoints.id]

  tags = merge(local.common_tags, { "Name" = "${var.name}-vpce-${each.key}" })
}

# -----------------------------------------------------------------------------
# FLOW LOGS (CloudWatch)
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = var.flow_logs_enabled ? 1 : 0
  name              = "/aws/vpc/${var.name}/flow-logs"
  retention_in_days = var.flow_logs_retention_days
  tags              = merge(local.common_tags, { "Name" = "${var.name}-flow-logs" })
}

data "aws_iam_policy_document" "vpc_flow_assume" {
  count = var.flow_logs_enabled ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "vpc_flow" {
  count              = var.flow_logs_enabled ? 1 : 0
  name               = "${var.name}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.vpc_flow_assume[0].json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "vpc_flow_policy" {
  count = var.flow_logs_enabled ? 1 : 0
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]
    resources = [
      aws_cloudwatch_log_group.flow_logs[0].arn,
      "${aws_cloudwatch_log_group.flow_logs[0].arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "vpc_flow_attach" {
  count  = var.flow_logs_enabled ? 1 : 0
  name   = "${var.name}-vpc-flow-logs-policy"
  role   = aws_iam_role.vpc_flow[0].id
  policy = data.aws_iam_policy_document.vpc_flow_policy[0].json
}

resource "aws_flow_log" "this" {
  count                     = var.flow_logs_enabled ? 1 : 0
  log_destination_type      = "cloud-watch-logs"
  log_group_name            = aws_cloudwatch_log_group.flow_logs[0].name
  deliver_logs_permission_arn = aws_iam_role.vpc_flow[0].arn
  traffic_type              = "ALL"
  vpc_id                    = aws_vpc.this.id
  tags                      = merge(local.common_tags, { "Name" = "${var.name}-flow-log" })
}

# -----------------------------------------------------------------------------
# ВЫХОДЫ
# -----------------------------------------------------------------------------

output "vpc_id" {
  value       = aws_vpc.this.id
  description = "ID созданного VPC."
}

output "vpc_cidr_block" {
  value       = aws_vpc.this.cidr_block
  description = "CIDR блока VPC."
}

output "ipv6_associated" {
  value       = var.enable_ipv6
  description = "Признак включенного IPv6."
}

output "public_subnet_ids" {
  value       = [for s in aws_subnet.public : s.id]
  description = "Список ID публичных подсетей."
}

output "private_subnet_ids" {
  value       = [for s in aws_subnet.private : s.id]
  description = "Список ID приватных подсетей."
}

output "database_subnet_ids" {
  value       = [for s in aws_subnet.database : s.id]
  description = "Список ID подсетей для баз данных."
}

output "internet_gateway_id" {
  value       = aws_internet_gateway.this.id
  description = "ID интернет-шлюза."
}

output "egress_only_internet_gateway_id" {
  value       = var.enable_ipv6 ? aws_egress_only_internet_gateway.this[0].id : null
  description = "ID egress-only IGW (IPv6), если включено."
}

output "nat_gateway_ids" {
  value       = var.enable_nat ? (var.single_nat_gateway ? [aws_nat_gateway.single[0].id] : [for k, n in aws_nat_gateway.per_az : n.id]) : []
  description = "ID NAT шлюзов."
}

output "route_table_ids_public" {
  value       = [for k, rt in aws_route_table.public : rt.id]
  description = "Маршрутные таблицы для публичных подсетей."
}

output "route_table_ids_private" {
  value       = [for k, rt in aws_route_table.private : rt.id]
  description = "Маршрутные таблицы для приватных подсетей."
}

output "vpc_endpoint_ids" {
  value = merge(
    { s3 = try(aws_vpc_endpoint.s3[0].id, null) },
    { dynamodb = try(aws_vpc_endpoint.dynamodb[0].id, null) },
    { for k, v in aws_vpc_endpoint.interface : k => v.id }
  )
  description = "ID созданных VPC endpoints."
}

output "flow_logs_log_group" {
  value       = var.flow_logs_enabled ? aws_cloudwatch_log_group.flow_logs[0].name : null
  description = "Имя CloudWatch Log Group для Flow Logs."
}
