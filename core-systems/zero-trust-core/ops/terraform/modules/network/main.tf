terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
  }
}

########################################
# Variables
########################################

variable "name" {
  description = "Базовое имя (префикс) для ресурсов VPC"
  type        = string
}

variable "cidr_block" {
  description = "CIDR для VPC (IPv4)"
  type        = string
  validation {
    condition     = can(cidrhost(var.cidr_block, 0))
    error_message = "cidr_block должен быть корректной IPv4 CIDR."
  }
}

variable "enable_ipv6" {
  description = "Включить IPv6 для VPC и подсетей"
  type        = bool
  default     = true
}

variable "az_count" {
  description = "Количество AZ для распределения подсетей"
  type        = number
  default     = 3
  validation {
    condition     = var.az_count >= 2 && var.az_count <= 6
    error_message = "az_count должен быть в диапазоне [2..6] для высокой доступности."
  }
}

variable "region" {
  description = "Регион AWS"
  type        = string
}

variable "tags" {
  description = "Обязательные теги (будут дополнены служебными)"
  type        = map(string)
  default     = {}
}

variable "create_public_subnets" {
  description = "Создавать публичные подсети"
  type        = bool
  default     = true
}

variable "create_private_subnets" {
  description = "Создавать приватные подсети (через NAT к Интернету)"
  type        = bool
  default     = true
}

variable "create_isolated_subnets" {
  description = "Создавать изолированные подсети (без исходящего в Интернет)"
  type        = bool
  default     = false
}

variable "public_subnet_bits" {
  description = "Сколько бит выделить под подсети public (для cidrsubnet)"
  type        = number
  default     = 4
}

variable "private_subnet_bits" {
  description = "Сколько бит выделить под подсети private"
  type        = number
  default     = 4
}

variable "isolated_subnet_bits" {
  description = "Сколько бит выделить под подсети isolated"
  type        = number
  default     = 4
}

variable "single_nat_gateway" {
  description = "true: один NAT на зону; false: NAT в каждой AZ"
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Включить VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_logs_destination" {
  description = "Назначение Flow Logs: s3 | cloudwatch"
  type        = string
  default     = "s3"
  validation {
    condition     = contains(["s3", "cloudwatch"], var.flow_logs_destination)
    error_message = "flow_logs_destination должен быть s3 или cloudwatch."
  }
}

variable "flow_logs_s3_bucket_arn" {
  description = "ARN S3 бакета для Flow Logs (если destination=s3)"
  type        = string
  default     = null
}

variable "flow_logs_cw_log_group_name" {
  description = "Имя CloudWatch Log Group для Flow Logs (если destination=cloudwatch)"
  type        = string
  default     = null
}

variable "flow_logs_kms_key_arn" {
  description = "KMS ключ для шифрования логов (S3 или CloudWatch)"
  type        = string
  default     = null
}

variable "enable_endpoints_gw" {
  description = "Включить Gateway VPC Endpoints (S3, DynamoDB)"
  type        = bool
  default     = true
}

variable "enable_endpoints_interface" {
  description = "Включить Interface VPC Endpoints (e.g., STS, ECR, SSM и др.)"
  type        = bool
  default     = false
}

variable "interface_endpoints" {
  description = "Список имён сервисов для Interface Endpoints (без префикса com.amazonaws)"
  type        = list(string)
  default     = ["sts", "ecr.api", "ecr.dkr", "ssm", "ssmmessages", "ec2messages"]
}

variable "endpoint_subnet_tier" {
  description = "Tier подсетей для размещения Interface Endpoints: public|private|isolated"
  type        = string
  default     = "private"
  validation {
    condition     = contains(["public", "private", "isolated"], var.endpoint_subnet_tier)
    error_message = "endpoint_subnet_tier должен быть public, private или isolated."
  }
}

variable "private_subnet_nat_egress" {
  description = "Разрешить приватным подсетям исходящий трафик через NAT"
  type        = bool
  default     = true
}

variable "dhcp_domain_name" {
  description = "Пользовательское доменное имя для DHCP options (опционально)"
  type        = string
  default     = null
}

variable "dhcp_domain_name_servers" {
  description = "Список DNS серверов для DHCP options (например AmazonProvidedDNS)"
  type        = list(string)
  default     = ["AmazonProvidedDNS"]
}

########################################
# Provider Configuration
########################################

provider "aws" {
  region = var.region
}

########################################
# Locals
########################################

locals {
  name   = var.name
  tags   = merge(var.tags, { "Name" = var.name, "Module" = "ztc-network" })
  azs    = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Индексы подсетей по типам (чтобы cidrsubnet не пересекались)
  idx_public   = 0
  idx_private  = 50
  idx_isolated = 100

  # Выбор подсетей для Interface Endpoints
  endpoint_subnet_ids = var.enable_endpoints_interface ? (
    var.endpoint_subnet_tier == "public"   ? aws_subnet.public[*].id :
    var.endpoint_subnet_tier == "private"  ? aws_subnet.private[*].id :
    aws_subnet.isolated[*].id
  ) : []
}

data "aws_availability_zones" "available" {
  state = "available"
}

########################################
# VPC and IPv6
########################################

resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true

  assign_generated_ipv6_cidr_block = var.enable_ipv6

  tags = merge(local.tags, {
    "Resource" = "vpc"
  })
}

resource "aws_vpc_ipv6_cidr_block_association" "this" {
  count                     = var.enable_ipv6 ? 1 : 0
  vpc_id                    = aws_vpc.this.id
  ipv6_ipam_pool_id         = null
  ipv6_cidr_block_network_border_group = null
}

########################################
# Internet Gateway
########################################

resource "aws_internet_gateway" "this" {
  count  = var.create_public_subnets ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { "Resource" = "igw" })
}

########################################
# Subnets
########################################

resource "aws_subnet" "public" {
  count                   = var.create_public_subnets ? length(local.azs) : 0
  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(var.cidr_block, var.public_subnet_bits, local.idx_public + count.index)
  map_public_ip_on_launch = false

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, local.idx_public + count.index) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.tags, {
    "Resource" = "subnet"
    "Tier"     = "public"
    "AZ"       = local.azs[count.index]
  })
}

resource "aws_subnet" "private" {
  count                   = var.create_private_subnets ? length(local.azs) : 0
  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(var.cidr_block, var.private_subnet_bits, local.idx_private + count.index)
  map_public_ip_on_launch = false

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, local.idx_private + count.index) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.tags, {
    "Resource" = "subnet"
    "Tier"     = "private"
    "AZ"       = local.azs[count.index]
  })
}

resource "aws_subnet" "isolated" {
  count                   = var.create_isolated_subnets ? length(local.azs) : 0
  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(var.cidr_block, var.isolated_subnet_bits, local.idx_isolated + count.index)
  map_public_ip_on_launch = false

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, local.idx_isolated + count.index) : null
  assign_ipv6_address_on_creation = var.enable_ipv6

  tags = merge(local.tags, {
    "Resource" = "subnet"
    "Tier"     = "isolated"
    "AZ"       = local.azs[count.index]
  })
}

########################################
# NAT Gateways (Single or per-AZ)
########################################

resource "aws_eip" "nat" {
  count = var.create_private_subnets && var.private_subnet_nat_egress ? (var.single_nat_gateway ? 1 : length(local.azs)) : 0
  domain = "vpc"
  tags   = merge(local.tags, { "Resource" = "eip", "Purpose" = "nat" })
}

resource "aws_nat_gateway" "this" {
  count = var.create_private_subnets && var.private_subnet_nat_egress ? (var.single_nat_gateway ? 1 : length(local.azs)) : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = element(aws_subnet.public[*].id, var.single_nat_gateway ? 0 : count.index)

  connectivity_type = "public"
  tags              = merge(local.tags, { "Resource" = "nat" })

  depends_on = [aws_internet_gateway.this]
}

########################################
# Route Tables and Associations
########################################

# Public RT (0..N)
resource "aws_route_table" "public" {
  count  = var.create_public_subnets ? length(local.azs) : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { "Resource" = "rt", "Tier" = "public", "AZ" = local.azs[count.index] })
}

resource "aws_route" "public_inet4" {
  count                  = var.create_public_subnets ? length(local.azs) : 0
  route_table_id         = aws_route_table.public[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

resource "aws_route" "public_inet6" {
  count                         = var.create_public_subnets && var.enable_ipv6 ? length(local.azs) : 0
  route_table_id                = aws_route_table.public[count.index].id
  destination_ipv6_cidr_block   = "::/0"
  gateway_id                    = aws_internet_gateway.this[0].id
}

resource "aws_route_table_association" "public_assoc" {
  count          = var.create_public_subnets ? length(local.azs) : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[count.index].id
}

# Private RT (per-AZ)
resource "aws_route_table" "private" {
  count  = var.create_private_subnets ? length(local.azs) : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { "Resource" = "rt", "Tier" = "private", "AZ" = local.azs[count.index] })
}

resource "aws_route" "private_nat_egress" {
  count = var.create_private_subnets && var.private_subnet_nat_egress ? length(local.azs) : 0
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = element(
    aws_nat_gateway.this[*].id,
    var.single_nat_gateway ? 0 : count.index
  )
}

resource "aws_route_table_association" "private_assoc" {
  count          = var.create_private_subnets ? length(local.azs) : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Isolated RT (no internet)
resource "aws_route_table" "isolated" {
  count  = var.create_isolated_subnets ? length(local.azs) : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { "Resource" = "rt", "Tier" = "isolated", "AZ" = local.azs[count.index] })
}

resource "aws_route_table_association" "isolated_assoc" {
  count          = var.create_isolated_subnets ? length(local.azs) : 0
  subnet_id      = aws_subnet.isolated[count.index].id
  route_table_id = aws_route_table.isolated[count.index].id
}

########################################
# DHCP Options (optional)
########################################

resource "aws_vpc_dhcp_options" "this" {
  count                = var.dhcp_domain_name != null || length(var.dhcp_domain_name_servers) > 0 ? 1 : 0
  domain_name          = var.dhcp_domain_name
  domain_name_servers  = var.dhcp_domain_name_servers
  tags                 = merge(local.tags, { "Resource" = "dhcp" })
}

resource "aws_vpc_dhcp_options_association" "this" {
  count              = length(aws_vpc_dhcp_options.this) == 1 ? 1 : 0
  vpc_id             = aws_vpc.this.id
  dhcp_options_id    = aws_vpc_dhcp_options.this[0].id
}

########################################
# VPC Endpoints
########################################

# Gateway endpoints (S3, DynamoDB) в таблицы маршрутов приватного/изолированного тира
resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_endpoints_gw ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(aws_route_table.private[*].id, aws_route_table.isolated[*].id)
  tags              = merge(local.tags, { "Resource" = "vpce", "Service" = "s3" })
}

resource "aws_vpc_endpoint" "dynamodb" {
  count             = var.enable_endpoints_gw ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(aws_route_table.private[*].id, aws_route_table.isolated[*].id)
  tags              = merge(local.tags, { "Resource" = "vpce", "Service" = "dynamodb" })
}

# Interface endpoints (в выбранном tier подсетей)
resource "aws_security_group" "endpoints" {
  count       = var.enable_endpoints_interface ? 1 : 0
  name        = "${local.name}-vpce"
  description = "Interface VPC Endpoints SG"
  vpc_id      = aws_vpc.this.id
  revoke_rules_on_delete = true

  # Разрешаем трафик внутрь по 443 из VPC
  ingress {
    description = "TLS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.this.cidr_block]
    ipv6_cidr_blocks = var.enable_ipv6 ? [aws_vpc.this.ipv6_cidr_block] : []
  }

  # Исходящий — ограничен VPC
  egress {
    description = "Egress to VPC only"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.this.cidr_block]
    ipv6_cidr_blocks = var.enable_ipv6 ? [aws_vpc.this.ipv6_cidr_block] : []
  }

  tags = merge(local.tags, { "Resource" = "sg", "Purpose" = "vpc-endpoints" })
}

resource "aws_vpc_endpoint" "interface" {
  for_each          = var.enable_endpoints_interface ? toset(var.interface_endpoints) : []
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type = "Interface"
  subnet_ids        = local.endpoint_subnet_ids
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.endpoints[0].id]
  tags              = merge(local.tags, { "Resource" = "vpce", "Service" = each.key })
}

########################################
# Flow Logs (S3 or CloudWatch)
########################################

resource "aws_flow_log" "this" {
  count                         = var.enable_flow_logs ? 1 : 0
  vpc_id                        = aws_vpc.this.id
  traffic_type                  = "ALL"
  max_aggregation_interval      = 60
  log_format                    = "${join(" ", ["${var.enable_ipv6 ? "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}" : "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}"}])}"

  dynamic "destination_options" {
    for_each = var.flow_logs_destination == "s3" ? [1] : []
    content {
      file_format                = "parquet"
      per_hour_partition         = true
      hive_compatible_partitions = true
    }
  }

  # S3
  log_destination_type = var.flow_logs_destination == "s3" ? "s3" : "cloud-watch-logs"
  log_destination      = var.flow_logs_destination == "s3" ? var.flow_logs_s3_bucket_arn : null
  # CloudWatch
  log_group_name       = var.flow_logs_destination == "cloudwatch" ? var.flow_logs_cw_log_group_name : null
  iam_role_arn         = null

  tags = merge(local.tags, { "Resource" = "flow-logs" })
}

########################################
# Outputs
########################################

output "vpc_id" {
  value       = aws_vpc.this.id
  description = "ID созданного VPC"
}

output "vpc_cidr" {
  value       = aws_vpc.this.cidr_block
  description = "CIDR VPC"
}

output "vpc_ipv6_cidr" {
  value       = var.enable_ipv6 ? aws_vpc.this.ipv6_cidr_block : null
  description = "IPv6 CIDR VPC (если включен)"
}

output "public_subnet_ids" {
  value       = aws_subnet.public[*].id
  description = "IDs публичных подсетей"
}

output "private_subnet_ids" {
  value       = aws_subnet.private[*].id
  description = "IDs приватных подсетей"
}

output "isolated_subnet_ids" {
  value       = aws_subnet.isolated[*].id
  description = "IDs изолированных подсетей"
}

output "route_table_public_ids" {
  value       = aws_route_table.public[*].id
  description = "IDs таблиц маршрутов public"
}

output "route_table_private_ids" {
  value       = aws_route_table.private[*].id
  description = "IDs таблиц маршрутов private"
}

output "endpoint_sg_id" {
  value       = length(aws_security_group.endpoints) > 0 ? aws_security_group.endpoints[0].id : null
  description = "Security Group для Interface Endpoints"
}

output "interface_endpoints_ids" {
  value       = { for k, v in aws_vpc_endpoint.interface : k => v.id }
  description = "Идентификаторы Interface VPC Endpoints"
}

output "s3_gateway_endpoint_id" {
  value       = length(aws_vpc_endpoint.s3) > 0 ? aws_vpc_endpoint.s3[0].id : null
  description = "ID Gateway Endpoint S3"
}

output "dynamodb_gateway_endpoint_id" {
  value       = length(aws_vpc_endpoint.dynamodb) > 0 ? aws_vpc_endpoint.dynamodb[0].id : null
  description = "ID Gateway Endpoint DynamoDB"
}
