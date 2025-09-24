#############################
# physical-integration-core
# ops/terraform/modules/network/main.tf
#############################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

#####################################
# Data sources and preconditions
#####################################

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

# Доступные AZ (supporting opt-in компактность через var.az_names)
data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "region-name"
    values = [data.aws_region.this.name]
  }
}

locals {
  name_prefix      = coalesce(var.name_prefix, "pic")
  vpc_name         = "${local.name_prefix}-vpc"
  enable_ipv6      = var.enable_ipv6
  az_names         = length(var.az_names) > 0 ? var.az_names : slice(data.aws_availability_zones.available.names, 0, var.az_count)
  az_count_effect  = length(local.az_names)

  # Проверка согласованности входных сетей
  public_subnets_ipv4  = length(var.public_subnets_ipv4)  == local.az_count_effect ? var.public_subnets_ipv4  : []
  private_subnets_ipv4 = length(var.private_subnets_ipv4) == local.az_count_effect ? var.private_subnets_ipv4 : []
  database_subnets_ipv4= length(var.database_subnets_ipv4)== local.az_count_effect ? var.database_subnets_ipv4: []

  # Теги
  common_tags = merge(
    {
      "Name"                             = local.vpc_name
      "Environment"                      = var.environment
      "Project"                          = var.project
      "Owner"                            = var.owner
      "app.kubernetes.io/part-of"        = "physical-integration-core"
      "app.kubernetes.io/managed-by"     = "terraform"
      "app.kubernetes.io/environment"    = var.environment
    },
    var.tags
  )

  # NAT strategy: "single" | "per-az" | "none"
  nat_strategy = var.nat_strategy

  # Flow logs strategy: "s3" | "cloudwatch" | "none"
  flow_logs_strategy = var.flow_logs_strategy

  # Поддержка S3 gateway endpoint’а всегда через route table private/database
  gw_endpoints_services = toset(compact([
    var.enable_s3_gateway_endpoint ? "s3" : null,
    var.enable_dynamodb_gateway_endpoint ? "dynamodb" : null
  ]))

  # Список интерфейс‑endpoint’ов, как "com.amazonaws.${region}.ecr.dkr", "ec2", "logs", "secretsmanager", "sts" и т.п.
  interface_endpoints = toset(var.interface_endpoints)
}

#####################################
# VPC with optional IPv6
#####################################

resource "aws_vpc" "this" {
  cidr_block                       = var.vpc_cidr
  enable_dns_hostnames             = true
  enable_dns_support               = true
  assign_generated_ipv6_cidr_block = local.enable_ipv6

  instance_tenancy = var.instance_tenancy

  tags = merge(local.common_tags, {
    "Name" = local.vpc_name
    "Tier" = "network"
  })
}

# IPv6 association (explicit output via aws_vpc later)
# Подсети IPv6 формируются только при включенном IPv6

#####################################
# Internet Gateway (for public subnets)
#####################################

resource "aws_internet_gateway" "this" {
  count = var.create_internet_gateway ? 1 : 0

  vpc_id = aws_vpc.this.id
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-igw"
  })
}

#####################################
# Subnets (public/private/database)
#####################################

# Public
resource "aws_subnet" "public" {
  for_each = { for idx, az in local.az_names : idx => {
    az   = az
    cidr = local.public_subnets_ipv4[idx]
  } }

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value.az
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = true

  ipv6_cidr_block                 = local.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, tonumber(each.key)) : null
  assign_ipv6_address_on_creation = local.enable_ipv6

  tags = merge(local.common_tags, {
    "Name"  = "${local.name_prefix}-public-${each.value.az}"
    "Scope" = "public"
  })
}

# Private (для приложений/worker)
resource "aws_subnet" "private" {
  for_each = { for idx, az in local.az_names : idx => {
    az   = az
    cidr = local.private_subnets_ipv4[idx]
  } }

  vpc_id            = aws_vpc.this.id
  availability_zone = each.value.az
  cidr_block        = each.value.cidr

  ipv6_cidr_block                 = local.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, tonumber(each.key) + 16) : null
  assign_ipv6_address_on_creation = local.enable_ipv6

  tags = merge(local.common_tags, {
    "Name"  = "${local.name_prefix}-private-${each.value.az}"
    "Scope" = "private"
  })
}

# Database (для RDS/TimescaleDB, без прямого выхода в интернет)
resource "aws_subnet" "database" {
  for_each = { for idx, az in local.az_names : idx => {
    az   = az
    cidr = local.database_subnets_ipv4[idx]
  } }

  vpc_id            = aws_vpc.this.id
  availability_zone = each.value.az
  cidr_block        = each.value.cidr

  ipv6_cidr_block                 = local.enable_ipv6 ? cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, tonumber(each.key) + 32) : null
  assign_ipv6_address_on_creation = local.enable_ipv6

  tags = merge(local.common_tags, {
    "Name"  = "${local.name_prefix}-db-${each.value.az}"
    "Scope" = "database"
  })
}

#####################################
# NAT Gateways (optional)
#####################################

# EIP для NAT (single/per-az)
resource "aws_eip" "nat" {
  count = local.nat_strategy == "per-az" ? local.az_count_effect : local.nat_strategy == "single" ? 1 : 0

  domain = "vpc"
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-nat-eip-${count.index}"
  })
}

# NAT GW в public подсетях
resource "aws_nat_gateway" "this" {
  count = local.nat_strategy == "per-az" ? local.az_count_effect : local.nat_strategy == "single" ? 1 : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = element(values(aws_subnet.public)[*].id, local.nat_strategy == "per-az" ? count.index : 0)

  connectivity_type = "public"
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-nat-${count.index}"
  })

  depends_on = [aws_internet_gateway.this]
}

#####################################
# Route Tables and Associations
#####################################

# Public RT: route via IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags = merge(local.common_tags, {
    "Name"  = "${local.name_prefix}-rt-public"
    "Scope" = "public"
  })
}

resource "aws_route" "public_ipv4_default" {
  count                  = var.create_internet_gateway ? 1 : 0
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

resource "aws_route" "public_ipv6_default" {
  count                         = var.create_internet_gateway && local.enable_ipv6 ? 1 : 0
  route_table_id                = aws_route_table.public.id
  destination_ipv6_cidr_block   = "::/0"
  gateway_id                    = aws_internet_gateway.this[0].id
}

# Ассоциации public
resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# Private RT: route via NAT (if enabled)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags = merge(local.common_tags, {
    "Name"  = "${local.name_prefix}-rt-private"
    "Scope" = "private"
  })
}

# Для private IPv4 default через NAT (single/per-az)
resource "aws_route" "private_ipv4_default" {
  count = local.nat_strategy == "none" ? 0 : local.nat_strategy == "single" ? 1 : local.az_count_effect

  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = local.nat_strategy == "single" ? aws_nat_gateway.this[0].id : aws_nat_gateway.this[count.index].id
}

# Ассоциации private
resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

# Database RT (без выхода в Интернет)
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.this.id
  tags = merge(local.common_tags, {
    "Name"  = "${local.name_prefix}-rt-db"
    "Scope" = "database"
  })
}

resource "aws_route_table_association" "database" {
  for_each       = aws_subnet.database
  subnet_id      = each.value.id
  route_table_id = aws_route_table.database.id
}

#####################################
# Network ACLs (optional strict defaults)
#####################################

resource "aws_network_acl" "default_private" {
  count  = var.create_private_nacl ? 1 : 0
  vpc_id = aws_vpc.this.id

  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-nacl-private"
  })
}

# Разрешаем внутри VPC и egress к Интернету (через NAT); блокируем всё остальное явно
resource "aws_network_acl_rule" "private_inbound_vpc" {
  count          = var.create_private_nacl ? 1 : 0
  network_acl_id = aws_network_acl.default_private[0].id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
}

resource "aws_network_acl_rule" "private_outbound_all" {
  count          = var.create_private_nacl ? 1 : 0
  network_acl_id = aws_network_acl.default_private[0].id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_network_acl_association" "private_assoc" {
  for_each       = var.create_private_nacl ? aws_subnet.private : {}
  subnet_id      = each.value.id
  network_acl_id = aws_network_acl.default_private[0].id
}

#####################################
# VPC Flow Logs (S3 or CloudWatch)
#####################################

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = local.flow_logs_strategy == "cloudwatch" ? 1 : 0
  name              = "/aws/vpc/flowlogs/${local.vpc_name}"
  retention_in_days = var.flow_logs_cw_retention_days
  kms_key_id        = var.flow_logs_kms_key_id
  tags              = local.common_tags
}

# IAM role/policy можно вынести в отдельный модуль; здесь используем default delivery
resource "aws_flow_log" "this" {
  count = local.flow_logs_strategy == "none" ? 0 : 1

  log_destination_type = local.flow_logs_strategy == "s3" ? "s3" : "cloud-watch-logs"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.this.id

  log_format           = var.flow_logs_log_format # поддерживает кастомный формат
  max_aggregation_interval = var.flow_logs_aggregation_interval

  # S3
  log_destination = local.flow_logs_strategy == "s3" ? var.flow_logs_s3_arn : null

  # CloudWatch
  deliver_logs_permission_arn = null
  iam_role_arn                = null
  log_group_name              = local.flow_logs_strategy == "cloudwatch" ? aws_cloudwatch_log_group.flow_logs[0].name : null

  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-vpc-flow-logs"
  })
}

#####################################
# VPC Endpoints (Gateway + Interface)
#####################################

# Gateway endpoints: S3 / DynamoDB
resource "aws_vpc_endpoint" "gateway" {
  for_each = local.gw_endpoints_services

  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.this.name}.${each.value}"
  vpc_endpoint_type = "Gateway"

  route_table_ids = compact([
    aws_route_table.private.id,
    aws_route_table.database.id
  ])

  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-ep-gw-${each.value}"
  })
}

# Security Group для Interface Endpoints
resource "aws_security_group" "endpoints" {
  count  = length(local.interface_endpoints) > 0 ? 1 : 0
  name   = "${local.name_prefix}-endpoints-sg"
  vpc_id = aws_vpc.this.id

  description = "Security group for VPC Interface Endpoints"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = local.enable_ipv6 ? ["::/0"] : null
  }

  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-endpoints-sg"
  })
}

# Interface endpoints (например: ec2, ecr.dkr, ecr.api, logs, kms, sts, secretsmanager, ssm, ssm-messages, ec2messages, monitoring)
resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.this.name}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  security_group_ids = length(aws_security_group.endpoints) > 0 ? [aws_security_group.endpoints[0].id] : []

  subnet_ids = values(aws_subnet.private)[*].id

  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-ep-if-${each.value}"
  })
}

#####################################
# Default SG (egress-only allow) — опционально
#####################################

resource "aws_security_group" "default_egress" {
  count       = var.create_default_egress_sg ? 1 : 0
  name        = "${local.name_prefix}-egress-only"
  description = "Default egress-only SG for workloads"
  vpc_id      = aws_vpc.this.id

  egress {
    description = "Allow all egress IPv4"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "egress" {
    for_each = local.enable_ipv6 ? [1] : []
    content {
      description      = "Allow all egress IPv6"
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      ipv6_cidr_blocks = ["::/0"]
    }
  }

  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-egress-only"
  })
}

#####################################
# Validations and safeguards
#####################################

resource "null_resource" "validations" {
  triggers = {
    vpc_cidr_valid   = can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", var.vpc_cidr)) ? "ok" : "fail"
    nat_strategy     = contains(["single", "per-az", "none"], var.nat_strategy) ? "ok" : "fail"
    flow_logs_mode   = contains(["s3", "cloudwatch", "none"], var.flow_logs_strategy) ? "ok" : "fail"
    az_consistency   = tostring(local.az_count_effect)
    public_len       = tostring(length(local.public_subnets_ipv4))
    private_len      = tostring(length(local.private_subnets_ipv4))
    database_len     = tostring(length(local.database_subnets_ipv4))
  }

  lifecycle {
    ignore_changes = all
  }

  provisioner "local-exec" {
    when    = create
    command = "echo 'Network module validated: AZ=${self.triggers.az_consistency}'"
  }
}

#####################################
# Helpful locals for outputs
#####################################

locals {
  public_subnet_ids   = values(aws_subnet.public)[*].id
  private_subnet_ids  = values(aws_subnet.private)[*].id
  database_subnet_ids = values(aws_subnet.database)[*].id

  private_route_table_id  = aws_route_table.private.id
  database_route_table_id = aws_route_table.database.id
  public_route_table_id   = aws_route_table.public.id

  nat_gateway_ids = aws_nat_gateway.this[*].id
  eip_nat_ids     = aws_eip.nat[*].id
}
