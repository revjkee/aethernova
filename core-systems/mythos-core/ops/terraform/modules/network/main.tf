terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

############################################
# Variables
############################################

variable "name" {
  description = "Имя/префикс для ресурсов (kebab-case)"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]{3,32}$", var.name))
    error_message = "var.name должен быть kebab-case (3..32 символа)."
  }
}

variable "tags" {
  description = "Общие теги для всех ресурсов"
  type        = map(string)
  default     = {}
}

variable "vpc_cidr" {
  description = "CIDR-блок VPC (например, 10.0.0.0/16)"
  type        = string
}

variable "enable_ipv6" {
  description = "Включить IPv6 для VPC и подсетей (/64 на подсеть)"
  type        = bool
  default     = true
}

variable "azs" {
  description = "Список имён AZ (например, [\"eu-central-1a\",\"eu-central-1b\"]). Если пусто — берутся первые az_count AZ региона."
  type        = list(string)
  default     = []
}

variable "az_count" {
  description = "Сколько AZ использовать, если var.azs не задан"
  type        = number
  default     = 3
}

variable "public_subnet_cidrs" {
  description = "Список CIDR для публичных подсетей (по числу AZ)"
  type        = list(string)
  default     = []
}

variable "private_subnet_cidrs" {
  description = "Список CIDR для приватных подсетей (по числу AZ)"
  type        = list(string)
  default     = []
}

variable "database_subnet_cidrs" {
  description = "Опционально: список CIDR для DB-подсетей (без выхода в интернет; по числу AZ)."
  type        = list(string)
  default     = []
}

variable "nat_gateway_strategy" {
  description = "Стратегия NAT: none | single | per_az"
  type        = string
  default     = "single"
  validation {
    condition     = contains(["none", "single", "per_az"], var.nat_gateway_strategy)
    error_message = "nat_gateway_strategy: допустимо none, single, per_az."
  }
}

variable "enable_s3_gateway_endpoint" {
  description = "Создавать Gateway VPC Endpoint для S3"
  type        = bool
  default     = true
}

variable "enable_dynamodb_gateway_endpoint" {
  description = "Создавать Gateway VPC Endpoint для DynamoDB"
  type        = bool
  default     = false
}

variable "interface_endpoints" {
  description = <<-EOT
  Сервисы для Interface VPC Endpoints (например, ["ecr.api","ecr.dkr","ssm","ssmmessages","ec2","kms","logs","monitoring","secretsmanager","sts"]).
  Разворачиваются в приватных подсетях.
  EOT
  type    = list(string)
  default = []
}

variable "harden_default_sg" {
  description = "Очистить правила default Security Group (вход/выход deny)"
  type        = bool
  default     = true
}

variable "flow_logs" {
  description = "Настройки VPC Flow Logs"
  type = object({
    enabled         = bool
    destination     = string   # cloudwatch | s3
    log_retention   = optional(number, 30) # дней
    s3_bucket_arn   = optional(string)     # если destination == s3
    traffic_type    = optional(string, "ALL") # ACCEPT | REJECT | ALL
  })
  default = {
    enabled       = true
    destination   = "cloudwatch"
    log_retention = 30
    traffic_type  = "ALL"
  }
  validation {
    condition     = !var.flow_logs.enabled || contains(["cloudwatch", "s3"], var.flow_logs.destination)
    error_message = "flow_logs.destination должен быть 'cloudwatch' или 's3'."
  }
}

variable "prevent_destroy" {
  description = "Защита от уничтожения ключевых ресурсов (VPC/подсети)"
  type        = bool
  default     = false
}

############################################
# Data & locals
############################################

data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs_final = length(var.azs) > 0 ? var.azs : slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Проверки согласованности
  want_len = length(local.azs_final)

  pub_ok = length(var.public_subnet_cidrs) == 0 || length(var.public_subnet_cidrs) == local.want_len
  prv_ok = length(var.private_subnet_cidrs) == 0 || length(var.private_subnet_cidrs) == local.want_len
  db_ok  = length(var.database_subnet_cidrs) == 0 || length(var.database_subnet_cidrs) == local.want_len

  common_tags = merge({
    "Name"                         = var.name
    "app.kubernetes.io/part-of"    = "mythos-core"
    "terraform.module"             = "network"
  }, var.tags)

  # Карты для for_each с детерминированными ключами "0","1",...
  public_plan = length(var.public_subnet_cidrs) > 0 ? {
    for idx, cidr in var.public_subnet_cidrs :
    tostring(idx) => { cidr = cidr, az = local.azs_final[idx] }
  } : {}

  private_plan = length(var.private_subnet_cidrs) > 0 ? {
    for idx, cidr in var.private_subnet_cidrs :
    tostring(idx) => { cidr = cidr, az = local.azs_final[idx] }
  } : {}

  database_plan = length(var.database_subnet_cidrs) > 0 ? {
    for idx, cidr in var.database_subnet_cidrs :
    tostring(idx) => { cidr = cidr, az = local.azs_final[idx] }
  } : {}

  use_nat_single = var.nat_gateway_strategy == "single"
  use_nat_per_az = var.nat_gateway_strategy == "per_az"
  use_nat_none   = var.nat_gateway_strategy == "none"
}

# Жёсткая валидация длин списков
resource "null_resource" "validate_lengths" {
  lifecycle { prevent_destroy = true }
  triggers = {
    pub_ok = tostring(local.pub_ok)
    prv_ok = tostring(local.prv_ok)
    db_ok  = tostring(local.db_ok)
  }
  provisioner "local-exec" {
    when    = create
    command = "test '${self.triggers.pub_ok}' = 'true' && test '${self.triggers.prv_ok}' = 'true' && test '${self.triggers.db_ok}' = 'true' || (echo 'Subnet CIDR lists must be empty or match AZ count (${local.want_len})' >&2 && exit 1)"
    interpreter = ["/bin/sh", "-c"]
  }
}

############################################
# VPC
############################################

resource "aws_vpc" "this" {
  cidr_block                           = var.vpc_cidr
  enable_dns_support                   = true
  enable_dns_hostnames                 = true
  assign_generated_ipv6_cidr_block     = var.enable_ipv6

  tags = merge(local.common_tags, {
    "Name" = "${var.name}-vpc"
  })

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}

# Жёсткая очистка правил default SG (опционально)
resource "aws_default_security_group" "harden" {
  count  = var.harden_default_sg ? 1 : 0
  vpc_id = aws_vpc.this.id
  # Без правил — implicit deny
  ingress = []
  egress  = []
  tags    = merge(local.common_tags, { "Name" = "${var.name}-default-sg-hardened" })
}

############################################
# Internet Gateway
############################################

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Name" = "${var.name}-igw" })
}

############################################
# Subnets
############################################

resource "aws_subnet" "public" {
  for_each                = local.public_plan
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value.az
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = true

  ipv6_cidr_block = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, tonumber(each.key)) : null

  tags = merge(local.common_tags, {
    "Name" = "${var.name}-public-${each.key}"
    "tier" = "public"
  })

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}

resource "aws_subnet" "private" {
  for_each          = local.private_plan
  vpc_id            = aws_vpc.this.id
  availability_zone = each.value.az
  cidr_block        = each.value.cidr
  ipv6_cidr_block   = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, tonumber(each.key) + 100) : null

  tags = merge(local.common_tags, {
    "Name" = "${var.name}-private-${each.key}"
    "tier" = "private"
  })

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}

resource "aws_subnet" "database" {
  for_each          = local.database_plan
  vpc_id            = aws_vpc.this.id
  availability_zone = each.value.az
  cidr_block        = each.value.cidr
  ipv6_cidr_block   = var.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, tonumber(each.key) + 200) : null

  tags = merge(local.common_tags, {
    "Name" = "${var.name}-db-${each.key}"
    "tier" = "database"
  })

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}

############################################
# Route tables
############################################

# Публичные: маршрут в интернет через IGW
resource "aws_route_table" "public" {
  count  = length(local.public_plan) > 0 ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { "Name" = "${var.name}-public-rt" })
}

resource "aws_route" "public_inet" {
  count                  = length(local.public_plan) > 0 ? 1 : 0
  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route" "public_inet_v6" {
  count                       = length(local.public_plan) > 0 && var.enable_ipv6 ? 1 : 0
  route_table_id              = aws_route_table.public[0].id
  destination_ipv6_cidr_block = "::/0"
  gateway_id                  = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_assoc" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public[0].id
}

# NAT: EIP + NAT GW (single или per_az)
resource "aws_eip" "nat" {
  count      = local.use_nat_per_az ? length(aws_subnet.public) : (local.use_nat_single ? 1 : 0)
  domain     = "vpc"
  depends_on = [aws_internet_gateway.igw]
  tags       = merge(local.common_tags, { "Name" = "${var.name}-nat-eip-${count.index}" })
}

resource "aws_nat_gateway" "this" {
  count         = local.use_nat_per_az ? length(aws_subnet.public) : (local.use_nat_single ? 1 : 0)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = local.use_nat_per_az ? values(aws_subnet.public)[count.index].id : aws_subnet.public["0"].id
  tags          = merge(local.common_tags, { "Name" = "${var.name}-nat-${count.index}" })
  depends_on    = [aws_internet_gateway.igw]
}

# Приватные: своя RT на каждую AZ (для отказоустойчивости)
resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.this.id
  tags     = merge(local.common_tags, { "Name" = "${var.name}-private-rt-${each.key}" })
}

# Маршруты приватных: на NAT (если включён) или только локальный
resource "aws_route" "private_nat" {
  for_each = local.use_nat_none ? {} : aws_route_table.private
  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"

  nat_gateway_id = local.use_nat_per_az ? aws_nat_gateway.this[tonumber(each.key)].id : aws_nat_gateway.this[0].id
}

resource "aws_route" "private_nat_v6" {
  for_each = (local.use_nat_none || !var.enable_ipv6) ? {} : aws_route_table.private
  route_table_id              = each.value.id
  destination_ipv6_cidr_block = "::/0"
  nat_gateway_id              = local.use_nat_per_az ? aws_nat_gateway.this[tonumber(each.key)].id : aws_nat_gateway.this[0].id
}

resource "aws_route_table_association" "private_assoc" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

# DB: отдельные таблицы без выхода в интернет (только локал/эндпойнты)
resource "aws_route_table" "database" {
  for_each = aws_subnet.database
  vpc_id   = aws_vpc.this.id
  tags     = merge(local.common_tags, { "Name" = "${var.name}-db-rt-${each.key}" })
}

resource "aws_route_table_association" "database_assoc" {
  for_each       = aws_subnet.database
  subnet_id      = each.value.id
  route_table_id = aws_route_table.database[each.key].id
}

############################################
# VPC Endpoints
############################################

# Gateway endpoints: S3, DynamoDB (привязываем к приватным/DB RT)
locals {
  private_rts = [for k, rt in aws_route_table.private : rt.id]
  db_rts      = [for k, rt in aws_route_table.database : rt.id]
  gw_endpoint_rts = concat(local.private_rts, local.db_rts)
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_s3_gateway_endpoint ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.gw_endpoint_rts
  tags              = merge(local.common_tags, { "Name" = "${var.name}-vpce-s3" })
}

resource "aws_vpc_endpoint" "dynamodb" {
  count             = var.enable_dynamodb_gateway_endpoint ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.gw_endpoint_rts
  tags              = merge(local.common_tags, { "Name" = "${var.name}-vpce-dynamodb" })
}

# SG для Interface endpoints (443 от VPC CIDR)
resource "aws_security_group" "vpce" {
  count       = length(var.interface_endpoints) > 0 ? 1 : 0
  name        = "${var.name}-vpce-sg"
  description = "Allow HTTPS from VPC to Interface VPC Endpoints"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.this.cidr_block]
    ipv6_cidr_blocks = var.enable_ipv6 ? [aws_vpc.this.ipv6_cidr_block] : []
    description = "HTTPS from VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = var.enable_ipv6 ? ["::/0"] : []
    description = "All egress"
  }

  tags = merge(local.common_tags, { "Name" = "${var.name}-vpce-sg" })
}

resource "aws_vpc_endpoint" "interface" {
  for_each          = { for s in var.interface_endpoints : s => s }
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.${each.key}"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [for k, s in aws_subnet.private : s.id]
  security_group_ids = length(aws_security_group.vpce) > 0 ? [aws_security_group.vpce[0].id] : null
  private_dns_enabled = true

  tags = merge(local.common_tags, { "Name" = "${var.name}-vpce-${each.key}" })
}

############################################
# Flow Logs
############################################

# CloudWatch Logs вариант: минимальные права для VPC Flow Logs
data "aws_iam_policy_document" "flowlogs_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "flowlogs_cw_policy" {
  statement {
    sid     = "AllowCWLogs"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "flowlogs" {
  count              = var.flow_logs.enabled && var.flow_logs.destination == "cloudwatch" ? 1 : 0
  name               = "${var.name}-flowlogs-role"
  assume_role_policy = data.aws_iam_policy_document.flowlogs_assume.json
  inline_policy {
    name   = "cwlogs"
    policy = data.aws_iam_policy_document.flowlogs_cw_policy.json
  }
  tags = merge(local.common_tags, { "Name" = "${var.name}-flowlogs-role" })
}

resource "aws_cloudwatch_log_group" "flowlogs" {
  count             = var.flow_logs.enabled && var.flow_logs.destination == "cloudwatch" ? 1 : 0
  name              = "/vpc/${var.name}/flowlogs"
  retention_in_days = try(var.flow_logs.log_retention, 30)
  tags              = merge(local.common_tags, { "Name" = "${var.name}-flowlogs" })
}

resource "aws_flow_log" "this" {
  count = var.flow_logs.enabled ? 1 : 0

  vpc_id = aws_vpc.this.id
  traffic_type = try(var.flow_logs.traffic_type, "ALL")

  log_destination_type = var.flow_logs.destination == "s3" ? "s3" : "cloud-watch-logs"

  log_group_name         = var.flow_logs.destination == "cloudwatch" ? aws_cloudwatch_log_group.flowlogs[0].name : null
  iam_role_arn           = var.flow_logs.destination == "cloudwatch" ? aws_iam_role.flowlogs[0].arn : null
  log_destination        = var.flow_logs.destination == "s3" ? var.flow_logs.s3_bucket_arn : null

  depends_on = [
    aws_cloudwatch_log_group.flowlogs,
    aws_iam_role.flowlogs
  ]

  tags = merge(local.common_tags, { "Name" = "${var.name}-flowlog" })
}

############################################
# Outputs
############################################

output "vpc_id" {
  value       = aws_vpc.this.id
  description = "ID созданной VPC"
}

output "vpc_cidr_block" {
  value       = aws_vpc.this.cidr_block
  description = "CIDR VPC"
}

output "vpc_ipv6_cidr_block" {
  value       = var.enable_ipv6 ? aws_vpc.this.ipv6_cidr_block : null
  description = "IPv6 CIDR VPC (/56), если включено"
}

output "public_subnet_ids" {
  value       = [for k, s in aws_subnet.public : s.id]
  description = "Список ID публичных подсетей"
}

output "private_subnet_ids" {
  value       = [for k, s in aws_subnet.private : s.id]
  description = "Список ID приватных подсетей"
}

output "database_subnet_ids" {
  value       = [for k, s in aws_subnet.database : s.id]
  description = "Список ID DB-подсетей"
}

output "nat_gateway_ids" {
  value       = [for i in aws_nat_gateway.this : i.id]
  description = "ID NAT-шлюзов (пусто при стратегии none)"
}

output "route_table_private_ids" {
  value       = [for k, rt in aws_route_table.private : rt.id]
  description = "RT приватных подсетей"
}

output "route_table_public_id" {
  value       = length(aws_route_table.public) > 0 ? aws_route_table.public[0].id : null
  description = "RT публичных подсетей"
}

output "vpc_endpoint_ids" {
  description = "VPC Endpoints (map)"
  value = {
    s3        = try(aws_vpc_endpoint.s3[0].id, null)
    dynamodb  = try(aws_vpc_endpoint.dynamodb[0].id, null)
    interface = { for k, e in aws_vpc_endpoint.interface : k => e.id }
  }
}
