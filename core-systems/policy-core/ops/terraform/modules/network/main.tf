// policy-core/ops/terraform/modules/network/main.tf
// Промышленный модуль сети AWS для policy-core.
// Требует Terraform >= 1.4 и AWS provider >= 5.0.

// ------------------------------------------------------------
// Терраформ/провайдеры и базовые настройки
// ------------------------------------------------------------
terraform {
  required_version = ">= 1.4.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

// Провайдер обычно задаётся на уровне root-модуля.
// Здесь используем data-источники для региона/AZ.
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

// ------------------------------------------------------------
// Переменные
// ------------------------------------------------------------
variable "environment" {
  description = "Окружение (staging/prod и т. п.)"
  type        = string
}

variable "cidr_block" {
  description = "CIDR VPC (например, 10.0.0.0/16)"
  type        = string
}

variable "allocate_ipv6" {
  description = "Выдавать ли VPC IPv6 CIDR"
  type        = bool
  default     = false
}

variable "azs" {
  description = "Явный список AZ (если пусто — возьмём первые az_count из доступных)"
  type        = list(string)
  default     = []
}

variable "az_count" {
  description = "Сколько AZ использовать, если azs не задан"
  type        = number
  default     = 2
}

variable "public_subnet_newbits" {
  description = "Сколько дополнительных бит CIDR для публичных подсетей (на основе VPC CIDR)"
  type        = number
  default     = 8
}

variable "private_subnet_newbits" {
  description = "Сколько дополнительных бит CIDR для приватных подсетей (на основе VPC CIDR)"
  type        = number
  default     = 8
}

variable "enable_nat_gateway" {
  description = "Создавать ли NAT Gateway"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Один NAT на VPC (true) или по одному на AZ (false)"
  type        = bool
  default     = true
}

variable "create_flow_logs" {
  description = "Включить VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_logs_destination_type" {
  description = "Тип назначения flow logs: cloud-watch-logs или s3"
  type        = string
  default     = "cloud-watch-logs"
  validation {
    condition     = contains(["cloud-watch-logs", "s3"], var.flow_logs_destination_type)
    error_message = "flow_logs_destination_type должен быть cloud-watch-logs или s3."
  }
}

variable "s3_flow_logs_bucket_arn" {
  description = "ARN S3 bucket для flow logs (если выбран тип s3)"
  type        = string
  default     = null
}

variable "enable_vpc_endpoints" {
  description = "Включить ли набор VPC endpoints"
  type        = bool
  default     = true
}

variable "vpc_interface_endpoints" {
  description = "Включаемые interface endpoints"
  type = object({
    ecr_api          = optional(bool, true)
    ecr_dkr          = optional(bool, true)
    logs             = optional(bool, true)
    ec2              = optional(bool, true)
    ec2messages      = optional(bool, false)
    ssm              = optional(bool, true)
    ssmmessages      = optional(bool, true)
    kms              = optional(bool, false)
    secretsmanager   = optional(bool, true)
    sts              = optional(bool, true)
  })
  default = {}
}

variable "enable_s3_gateway_endpoint" {
  description = "Создавать ли gateway endpoint для S3"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Дополнительные теги"
  type        = map(string)
  default     = {}
}

// ------------------------------------------------------------
// Локальные значения
// ------------------------------------------------------------
locals {
  name_prefix = "policy-core"

  azs = length(var.azs) > 0
    ? var.azs
    : slice(data.aws_availability_zones.available.names, 0, var.az_count)

  n_azs = length(local.azs)

  // Генерация подсетей из единого VPC CIDR: публичные с индексами [0..),
  // приватные — со смещением 100 для независимости.
  public_subnets = {
    for idx, az in local.azs :
    az => cidrsubnet(var.cidr_block, var.public_subnet_newbits, idx)
  }

  private_subnets = {
    for idx, az in local.azs :
    az => cidrsubnet(var.cidr_block, var.private_subnet_newbits, idx + 100)
  }

  // NAT размещаем либо один в первой AZ, либо по всем AZ.
  nat_azs = var.enable_nat_gateway ? (var.single_nat_gateway ? [local.azs[0]] : local.azs) : []

  // Общие теги
  common_tags = merge({
    Project          = "policy-core"
    Environment      = var.environment
    ManagedBy        = "Terraform"
    Module           = "network"
    OwnerAccountId   = data.aws_caller_identity.current.account_id
    Region           = data.aws_region.current.name
  }, var.tags)
}

// ------------------------------------------------------------
// VPC и базовые сети
// ------------------------------------------------------------
resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true

  assign_generated_ipv6_cidr_block = var.allocate_ipv6

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc"
  })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-igw"
  })
}

// Публичные подсети (по AZ)
resource "aws_subnet" "public" {
  for_each                = local.public_subnets
  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = true

  ipv6_native             = false
  assign_ipv6_address_on_creation = var.allocate_ipv6

  tags = merge(local.common_tags, {
    Name                                     = "${local.name_prefix}-public-${each.key}"
    "kubernetes.io/role/elb"                 = "1"
    "kubernetes.io/cluster/${local.name_prefix}" = "shared"
    Tier                                     = "public"
  })
}

// Приватные подсети (по AZ)
resource "aws_subnet" "private" {
  for_each          = local.private_subnets
  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  availability_zone = each.key

  ipv6_native             = false
  assign_ipv6_address_on_creation = var.allocate_ipv6

  tags = merge(local.common_tags, {
    Name                                         = "${local.name_prefix}-private-${each.key}"
    "kubernetes.io/role/internal-elb"            = "1"
    "kubernetes.io/cluster/${local.name_prefix}" = "shared"
    Tier                                         = "private"
  })
}

// Публичная таблица маршрутов
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rt-public"
  })
}

resource "aws_route" "public_inet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public_assoc" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

// NAT: EIP и NAT GW (один или по каждому AZ с публичной подсетью)
resource "aws_eip" "nat" {
  for_each = toset(local.nat_azs)
  domain   = "vpc"
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eip-nat-${each.key}"
  })
}

resource "aws_nat_gateway" "this" {
  for_each      = aws_eip.nat
  allocation_id = each.value.id
  subnet_id     = aws_subnet.public[each.key].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-nat-${each.key}"
  })

  depends_on = [aws_internet_gateway.this]
}

// Приватные таблицы маршрутов (по AZ)
resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.this.id
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rt-private-${each.key}"
  })
}

// Маршруты по умолчанию из приватных подсетей через NAT (если включено)
resource "aws_route" "private_default" {
  for_each = var.enable_nat_gateway ? aws_route_table.private : {}

  route_table_id         = aws_route_table.private[each.key].id
  destination_cidr_block = "0.0.0.0/0"

  nat_gateway_id = var.single_nat_gateway
    ? aws_nat_gateway.this[local.nat_azs[0]].id
    : aws_nat_gateway.this[each.key].id
}

resource "aws_route_table_association" "private_assoc" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

// ------------------------------------------------------------
// VPC Flow Logs (CloudWatch Logs или S3)
// ------------------------------------------------------------
resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = var.create_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? 1 : 0
  name              = "/aws/vpc/${local.name_prefix}/flow-logs"
  retention_in_days = 14
  tags              = local.common_tags
}

data "aws_iam_policy_document" "flow_logs_assume" {
  count = var.create_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  count              = var.create_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? 1 : 0
  name               = "${local.name_prefix}-vpc-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume[0].json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "flow_logs_policy" {
  count = var.create_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? 1 : 0
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  count  = var.create_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? 1 : 0
  name   = "${local.name_prefix}-vpc-flow-logs-policy"
  role   = aws_iam_role.flow_logs[0].id
  policy = data.aws_iam_policy_document.flow_logs_policy[0].json
}

resource "aws_flow_log" "this" {
  count           = var.create_flow_logs ? 1 : 0
  vpc_id          = aws_vpc.this.id
  traffic_type    = "ALL"
  log_format      = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${action} ${log-status}"

  destination_options {
    file_format        = "plain-text"
    hive_compatible_partitions = false
    per_hour_partition = false
  }

  log_destination_type = var.flow_logs_destination_type

  dynamic "cloud_watch_logs" {
    for_each = var.flow_logs_destination_type == "cloud-watch-logs" ? [1] : []
    content {
      log_group_arn = aws_cloudwatch_log_group.flow_logs[0].arn
      role_arn      = aws_iam_role.flow_logs[0].arn
    }
  }

  dynamic "s3_bucket" {
    for_each = var.flow_logs_destination_type == "s3" && var.s3_flow_logs_bucket_arn != null ? [1] : []
    content {
      arn = var.s3_flow_logs_bucket_arn
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc-flow-logs"
  })
}

// ------------------------------------------------------------
// VPC Endpoints: S3 (gateway) и набор interface endpoints
// ------------------------------------------------------------

// Security Group для интерфейсных endpoint'ов
resource "aws_security_group" "vpce" {
  count       = var.enable_vpc_endpoints ? 1 : 0
  name        = "${local.name_prefix}-vpce-sg"
  description = "Security Group for VPC Interface Endpoints"
  vpc_id      = aws_vpc.this.id

  // Разрешаем входящие 443 с внутреннего адресного пространства VPC
  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.this.cidr_block]
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpce-sg"
  })
}

// S3 gateway endpoint — привязываем к приватным RT
resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_vpc_endpoints && var.enable_s3_gateway_endpoint ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for rt in aws_route_table.private : rt.id]
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpce-s3"
  })
}

// Карта сервисов для interface endpoints
locals {
  interface_services = {
    ecr_api        = "com.amazonaws.${data.aws_region.current.name}.ecr.api"
    ecr_dkr        = "com.amazonaws.${data.aws_region.current.name}.ecr.dkr"
    logs           = "com.amazonaws.${data.aws_region.current.name}.logs"
    ec2            = "com.amazonaws.${data.aws_region.current.name}.ec2"
    ec2messages    = "com.amazonaws.${data.aws_region.current.name}.ec2messages"
    ssm            = "com.amazonaws.${data.aws_region.current.name}.ssm"
    ssmmessages    = "com.amazonaws.${data.aws_region.current.name}.ssmmessages"
    kms            = "com.amazonaws.${data.aws_region.current.name}.kms"
    secretsmanager = "com.amazonaws.${data.aws_region.current.name}.secretsmanager"
    sts            = "com.amazonaws.${data.aws_region.current.name}.sts"
  }

  // Фильтруем по включённым флагам
  enabled_interface_services = {
    for k, v in local.interface_services :
    k => v
    if var.enable_vpc_endpoints && lookup(var.vpc_interface_endpoints, k, true)
  }
}

// Создаём interface endpoints в приватных подсетях
resource "aws_vpc_endpoint" "interface" {
  for_each          = local.enabled_interface_services
  vpc_id            = aws_vpc.this.id
  service_name      = each.value
  vpc_endpoint_type = "Interface"
  subnet_ids        = [for s in aws_subnet.private : s.id]
  security_group_ids = aws_security_group.vpce.*.id

  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpce-${each.key}"
  })
}

// ------------------------------------------------------------
// Выходные значения
// ------------------------------------------------------------
output "vpc_id" {
  value       = aws_vpc.this.id
  description = "ID созданной VPC"
}

output "vpc_cidr_block" {
  value       = aws_vpc.this.cidr_block
  description = "CIDR VPC"
}

output "vpc_ipv6_cidr_block" {
  value       = try(aws_vpc.this.ipv6_cidr_block, null)
  description = "IPv6 CIDR VPC (если выдавался)"
}

output "public_subnet_ids" {
  value       = [for s in aws_subnet.public : s.id]
  description = "IDs публичных подсетей"
}

output "private_subnet_ids" {
  value       = [for s in aws_subnet.private : s.id]
  description = "IDs приватных подсетей"
}

output "public_route_table_id" {
  value       = aws_route_table.public.id
  description = "ID публичной таблицы маршрутов"
}

output "private_route_table_ids" {
  value       = [for rt in aws_route_table.private : rt.id]
  description = "IDs приватных таблиц маршрутов"
}

output "internet_gateway_id" {
  value       = aws_internet_gateway.this.id
  description = "ID IGW"
}

output "nat_gateway_ids" {
  value       = [for nat in aws_nat_gateway.this : nat.id]
  description = "IDs NAT Gateway (может быть пустым)"
}

output "vpc_endpoint_ids" {
  value = merge(
    var.enable_s3_gateway_endpoint ? { s3 = try(aws_vpc_endpoint.s3[0].id, null) } : {},
    { for k, ep in aws_vpc_endpoint.interface : k => ep.id }
  )
  description = "IDs VPC endpoints (s3 и interface)"
}

output "tags" {
  value       = local.common_tags
  description = "Финальные теги, применённые к ресурсам"
}
