terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

###############################################################################
# VARIABLES (все в одном файле для самодостаточности модуля)
###############################################################################

variable "name" {
  description = "Имя/префикс ресурсов (Name-тег)."
  type        = string
}

variable "environment" {
  description = "Окружение (dev|stage|prod). Входит в теги."
  type        = string
  default     = "dev"
}

variable "vpc_cidr_block" {
  description = "CIDR VPC (например, 10.0.0.0/16)."
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr_block))
    error_message = "vpc_cidr_block должен быть валидным CIDR."
  }
}

variable "enable_dns_support" {
  description = "Включить DNS support для VPC."
  type        = bool
  default     = true
}

variable "enable_dns_hostnames" {
  description = "Включить DNS hostnames для VPC."
  type        = bool
  default     = true
}

variable "azs" {
  description = "Список AZ (e.g. [\"eu-central-1a\",\"eu-central-1b\"]). Если null — берутся первые az_count доступных."
  type        = list(string)
  default     = null
}

variable "az_count" {
  description = "Сколько AZ выбрать, если azs=null."
  type        = number
  default     = 3
  validation {
    condition     = var.az_count >= 1 && var.az_count <= 6
    error_message = "az_count должен быть в диапазоне 1..6."
  }
}

variable "subnet_newbits" {
  description = "Сколько битов добавлять при разбиении CIDR на подсети (по умолчанию /24 из /16 => 8)."
  type        = number
  default     = 8
  validation {
    condition     = var.subnet_newbits >= 4 && var.subnet_newbits <= 12
    error_message = "subnet_newbits должен быть в диапазоне 4..12."
  }
}

variable "public_subnet_cidrs" {
  description = "Необязательно: явные CIDR для публичных подсетей (длина = числу AZ). Иначе рассчитываются автоматически."
  type        = list(string)
  default     = null
}

variable "private_subnet_cidrs" {
  description = "Необязательно: явные CIDR для приватных подсетей (длина = числу AZ). Иначе рассчитываются автоматически."
  type        = list(string)
  default     = null
}

variable "enable_nat_gateway" {
  description = "Создавать NAT Gateway для приватных подсетей."
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "true — один NAT на первую AZ, false — NAT в каждой AZ."
  type        = bool
  default     = false
}

variable "enable_ipv6" {
  description = "Выделить IPv6-префикс (/56) и раздать /64 подсетям."
  type        = bool
  default     = false
}

variable "enable_egress_only_igw" {
  description = "Создать egress-only IGW для IPv6 (при enable_ipv6)."
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Включить VPC Flow Logs."
  type        = bool
  default     = false
}

variable "flow_logs_destination_type" {
  description = "Назначение Flow Logs: cloud-watch-logs | s3."
  type        = string
  default     = "cloud-watch-logs"
  validation {
    condition     = contains(["cloud-watch-logs", "s3"], var.flow_logs_destination_type)
    error_message = "flow_logs_destination_type должен быть cloud-watch-logs или s3."
  }
}

variable "flow_logs_log_group_name" {
  description = "Имя Log Group для Flow Logs (если null — создаётся /aws/vpc/flowlogs/<name>)."
  type        = string
  default     = null
}

variable "flow_logs_log_group_kms_key_arn" {
  description = "Необязательно: KMS Key ARN для шифрования Log Group."
  type        = string
  default     = null
}

variable "flow_logs_retention_days" {
  description = "Срок хранения логов, дни."
  type        = number
  default     = 30
}

variable "flow_logs_s3_bucket_arn" {
  description = "ARN S3 бакета для Flow Logs (только если destination_type = s3)."
  type        = string
  default     = null
}

variable "flow_logs_s3_hive_compatible_partitions" {
  description = "Hive-совместимая разбивка при выгрузке в S3."
  type        = bool
  default     = true
}

variable "flow_logs_iam_role_arn" {
  description = "Существующая роль IAM для Flow Logs. Если null и cloud-watch-logs — создаётся автоматически."
  type        = string
  default     = null
}

variable "enable_nacl" {
  description = "Создавать Network ACL для public/private подсетей с базовыми правилами."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Дополнительные теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

###############################################################################
# LOCALS & DATA
###############################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = var.azs != null ? var.azs : slice(data.aws_availability_zones.available.names, 0, var.az_count)

  default_tags = {
    Name        = var.name
    Project     = "neuroforge-core"
    Environment = var.environment
    Module      = "network"
  }

  tags = merge(local.default_tags, var.tags)

  # Авто-расчёт CIDR при отсутствии явных списков
  public_cidrs_auto  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr_block, var.subnet_newbits, i)]
  private_cidrs_auto = [for i, az in local.azs : cidrsubnet(var.vpc_cidr_block, var.subnet_newbits, i + 64)]

  public_cidrs  = var.public_subnet_cidrs  != null ? var.public_subnet_cidrs  : local.public_cidrs_auto
  private_cidrs = var.private_subnet_cidrs != null ? var.private_subnet_cidrs : local.private_cidrs_auto

  # Проверка длины списков
  public_ok  = length(local.public_cidrs)  == length(local.azs)
  private_ok = length(local.private_cidrs) == length(local.azs)

  # IPv6: /56 -> /64 (добавляем 8 бит)
  ipv6_newbits = 8
}

###############################################################################
# VALIDATIONS
###############################################################################

resource "null_resource" "validate_subnets" {
  lifecycle { ignore_changes = all }
  triggers = {
    public_ok  = tostring(local.public_ok)
    private_ok = tostring(local.private_ok)
  }
  provisioner "local-exec" {
    when    = create
    command = "test ${self.triggers.public_ok} = true && test ${self.triggers.private_ok} = true || (echo 'ERROR: длина public/private подсетей должна соответствовать числу AZ' && exit 1)"
    interpreter = ["/bin/sh", "-c"]
  }
}

###############################################################################
# VPC & INTERNET CONNECTIVITY
###############################################################################

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_support   = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames

  tags = local.tags
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}

# IPv6 ассоциация (опционально)
resource "aws_vpc_ipv6_cidr_block_association" "this" {
  count      = var.enable_ipv6 ? 1 : 0
  vpc_id     = aws_vpc.this.id
  ipv6_ipam_pool_id   = null
  ipv6_netmask_length = 56
}

resource "aws_egress_only_internet_gateway" "this" {
  count  = var.enable_ipv6 && var.enable_egress_only_igw ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}

###############################################################################
# SUBNETS
###############################################################################

# Публичные подсети (по AZ)
resource "aws_subnet" "public" {
  for_each = { for idx, az in local.azs : az => {
    idx  = idx
    cidr = local.public_cidrs[idx]
    az   = az
  } }

  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = true

  # IPv6 для подсети
  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(one(aws_vpc_ipv6_cidr_block_association.this[*].ipv6_cidr_block), local.ipv6_newbits, each.value.idx) : null
  assign_ipv6_address_on_creation = var.enable_ipv6 ? true : null

  tags = merge(local.tags, {
    "kubernetes.io/role/elb" = "1"
    "Tier"                   = "public"
  })
}

# Приватные подсети (по AZ)
resource "aws_subnet" "private" {
  for_each = { for idx, az in local.azs : az => {
    idx  = idx
    cidr = local.private_cidrs[idx]
    az   = az
  } }

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az

  ipv6_cidr_block                 = var.enable_ipv6 ? cidrsubnet(one(aws_vpc_ipv6_cidr_block_association.this[*].ipv6_cidr_block), local.ipv6_newbits, each.value.idx + 128) : null
  assign_ipv6_address_on_creation = var.enable_ipv6 ? true : null

  tags = merge(local.tags, {
    "kubernetes.io/role/internal-elb" = "1"
    "Tier"                            = "private"
  })
}

###############################################################################
# ROUTE TABLES
###############################################################################

# Публичная RT (общая)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { "Tier" = "public" })
}

# Маршрут 0.0.0.0/0 -> IGW
resource "aws_route" "public_ipv4_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

# IPv6 ::/0 -> egress-only IGW (если включено)
resource "aws_route" "public_ipv6_default" {
  count                         = var.enable_ipv6 && var.enable_egress_only_igw ? 1 : 0
  route_table_id                = aws_route_table.public.id
  destination_ipv6_cidr_block   = "::/0"
  egress_only_internet_gateway_id = one(aws_egress_only_internet_gateway.this[*].id)
}

# Ассоциации RT с публичными подсетями
resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# Приватные RT (по подсети)
resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.this.id
  tags     = merge(local.tags, { "Tier" = "private", "AZ" = each.value.availability_zone })
}

# NAT инфраструктура (опционально)
resource "aws_eip" "nat" {
  for_each = var.enable_nat_gateway ? (
    var.single_nat_gateway ? { "shared" = true } : { for k, s in aws_subnet.public : k => true }
  ) : {}

  domain = "vpc"
  tags   = local.tags
}

resource "aws_nat_gateway" "this" {
  for_each = var.enable_nat_gateway ? (
    var.single_nat_gateway ? { "shared" = { subnet_id = element(values(aws_subnet.public)[*].id, 0) } } :
    { for k, s in aws_subnet.public : k => { subnet_id = s.id } }
  ) : {}

  allocation_id = var.single_nat_gateway ? aws_eip.nat["shared"].id : aws_eip.nat[each.key].id
  subnet_id     = each.value.subnet_id

  tags = local.tags

  depends_on = [aws_internet_gateway.this]
}

# Маршруты из приватных RT -> NAT
resource "aws_route" "private_ipv4_default" {
  for_each = var.enable_nat_gateway ? aws_route_table.private : {}
  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = var.single_nat_gateway ? aws_nat_gateway.this["shared"].id : aws_nat_gateway.this[each.key].id
}

# Ассоциации RT с приватными подсетями
resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

###############################################################################
# NETWORK ACLs (опционально)
###############################################################################

# Публичный NACL
resource "aws_network_acl" "public" {
  count      = var.enable_nacl ? 1 : 0
  vpc_id     = aws_vpc.this.id
  subnet_ids = [for s in aws_subnet.public : s.id]
  tags       = merge(local.tags, { "Tier" = "public" })
}

resource "aws_network_acl_rule" "public_inbound_allow_http_https" {
  count          = var.enable_nacl ? 2 : 0
  network_acl_id = aws_network_acl.public[0].id
  rule_number    = 100 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = count.index == 0 ? 80 : 443
  to_port        = count.index == 0 ? 80 : 443
}

resource "aws_network_acl_rule" "public_inbound_ephemeral" {
  count          = var.enable_nacl ? 1 : 0
  network_acl_id = aws_network_acl.public[0].id
  rule_number    = 120
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "public_outbound_all" {
  count          = var.enable_nacl ? 1 : 0
  network_acl_id = aws_network_acl.public[0].id
  rule_number    = 130
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# Приватный NACL
resource "aws_network_acl" "private" {
  count      = var.enable_nacl ? 1 : 0
  vpc_id     = aws_vpc.this.id
  subnet_ids = [for s in aws_subnet.private : s.id]
  tags       = merge(local.tags, { "Tier" = "private" })
}

resource "aws_network_acl_rule" "private_inbound_all_from_vpc" {
  count          = var.enable_nacl ? 1 : 0
  network_acl_id = aws_network_acl.private[0].id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr_block
}

resource "aws_network_acl_rule" "private_outbound_all" {
  count          = var.enable_nacl ? 1 : 0
  network_acl_id = aws_network_acl.private[0].id
  rule_number    = 110
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

###############################################################################
# VPC FLOW LOGS (опционально)
###############################################################################

resource "aws_cloudwatch_log_group" "flow" {
  count             = var.enable_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" && var.flow_logs_log_group_name == null ? 1 : 0
  name              = var.flow_logs_log_group_name == null ? "/aws/vpc/flowlogs/${var.name}" : var.flow_logs_log_group_name
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = var.flow_logs_log_group_kms_key_arn
  tags              = local.tags
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow" {
  count              = var.enable_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" && var.flow_logs_iam_role_arn == null ? 1 : 0
  name               = "${var.name}-flowlogs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "flow_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
      "logs:PutRetentionPolicy"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "flow" {
  count  = var.enable_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" && var.flow_logs_iam_role_arn == null ? 1 : 0
  name   = "${var.name}-flowlogs-policy"
  role   = aws_iam_role.flow[0].id
  policy = data.aws_iam_policy_document.flow_permissions.json
}

resource "aws_flow_log" "this" {
  count                = var.enable_flow_logs ? 1 : 0
  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = var.flow_logs_destination_type

  dynamic "destination_options" {
    for_each = var.flow_logs_destination_type == "s3" ? [1] : []
    content {
      file_format                = "parquet"
      hive_compatible_partitions = var.flow_logs_s3_hive_compatible_partitions
      per_hour_partition         = true
    }
  }

  # CloudWatch Logs
  log_group_name = var.flow_logs_destination_type == "cloud-watch-logs" ? (
    var.flow_logs_log_group_name != null ? var.flow_logs_log_group_name : aws_cloudwatch_log_group.flow[0].name
  ) : null

  iam_role_arn = var.flow_logs_destination_type == "cloud-watch-logs" ? (
    var.flow_logs_iam_role_arn != null ? var.flow_logs_iam_role_arn : aws_iam_role.flow[0].arn
  ) : null

  # S3
  log_destination = var.flow_logs_destination_type == "s3" ? var.flow_logs_s3_bucket_arn : null

  tags = local.tags

  depends_on = [
    aws_cloudwatch_log_group.flow,
    aws_iam_role.flow,
    aws_iam_role_policy.flow
  ]
}

###############################################################################
# OUTPUTS
###############################################################################

output "vpc_id" {
  description = "ID созданной VPC."
  value       = aws_vpc.this.id
}

output "vp
