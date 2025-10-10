############################################################
# File: aethernova-chain-core/ops/terraform/modules/networking/firewall/main.tf
# Purpose: Industrial-grade Security Groups for P2P, RPC, gRPC, Metrics
# Cloud:   AWS (terraform aws provider >= 5.0)
# Notes:
#  - Separate SG per perimeter to keep least-privilege and blast-radius isolation.
#  - Uses atomic rule resources for deterministic diffs and lifecycle control.
#  - IPv4 and IPv6 source allow-lists + SG-based allow.
############################################################

terraform {
  required_version = ">= 1.4.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

############################
# Variables
############################
variable "vpc_id" {
  description = "Target VPC ID for security groups"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for SG names, e.g. 'aethernova-chain-prod'"
  type        = string
}

variable "tags" {
  description = "Common tags to attach to SGs"
  type        = map(string)
  default     = {}
}

# Global egress policy toggles
variable "egress_allow_all" {
  description = "If true, allow all egress (0.0.0.0/0 and ::/0); otherwise only what is explicitly configured"
  type        = bool
  default     = false
}

variable "egress_additional_cidrs_ipv4" {
  description = "Explicit egress IPv4 CIDRs to allow (when egress_allow_all=false)"
  type        = list(string)
  default     = []
}

variable "egress_additional_cidrs_ipv6" {
  description = "Explicit egress IPv6 CIDRs to allow (when egress_allow_all=false)"
  type        = list(string)
  default     = []
}

############################################################
# P2P perimeter
############################################################
variable "p2p_enabled" {
  type    = bool
  default = true
}

variable "p2p_ports_tcp" {
  description = "List of TCP ports or begin-end ranges for P2P. Examples: [30303] or ['30000-30100']"
  type        = list(string)
  default     = ["30303"]
}

variable "p2p_ports_udp" {
  description = "List of UDP ports or ranges for P2P discovery"
  type        = list(string)
  default     = ["30303"]
}

variable "p2p_allow_cidrs_ipv4" {
  description = "IPv4 CIDRs allowed for inbound P2P"
  type        = list(string)
  default     = []
}

variable "p2p_allow_cidrs_ipv6" {
  description = "IPv6 CIDRs allowed for inbound P2P"
  type        = list(string)
  default     = []
}

variable "p2p_allow_source_sg_ids" {
  description = "Source Security Group IDs allowed inbound to P2P (node-to-node intra-cluster)"
  type        = list(string)
  default     = []
}

############################################################
# RPC perimeter (HTTP/WS JSON-RPC, e.g., 80/443/8545/8546)
############################################################
variable "rpc_enabled" {
  type    = bool
  default = true
}

variable "rpc_ports_tcp" {
  description = "TCP ports for RPC exposure"
  type        = list(string)
  default     = ["80", "443", "8545", "8546"]
}

variable "rpc_allow_cidrs_ipv4" {
  type    = list(string)
  default = []
}

variable "rpc_allow_cidrs_ipv6" {
  type    = list(string)
  default = []
}

variable "rpc_allow_source_sg_ids" {
  type    = list(string)
  default = []
}

############################################################
# gRPC perimeter (e.g., 9090/9091 etc.)
############################################################
variable "grpc_enabled" {
  type    = bool
  default = true
}

variable "grpc_ports_tcp" {
  type    = list(string)
  default = ["9090"]
}

variable "grpc_allow_cidrs_ipv4" {
  type    = list(string)
  default = []
}

variable "grpc_allow_cidrs_ipv6" {
  type    = list(string)
  default = []
}

variable "grpc_allow_source_sg_ids" {
  type    = list(string)
  default = []
}

############################################################
# Metrics perimeter (Prometheus scraping, Node Exporter, etc.)
############################################################
variable "metrics_enabled" {
  type    = bool
  default = true
}

variable "metrics_ports_tcp" {
  description = "TCP ports for metrics exposure (e.g., 9090 Prometheus, 9100 Node Exporter)"
  type        = list(string)
  default     = ["9090", "9100"]
}

variable "metrics_allow_cidrs_ipv4" {
  type    = list(string)
  default = []
}

variable "metrics_allow_cidrs_ipv6" {
  type    = list(string)
  default = []
}

variable "metrics_allow_source_sg_ids" {
  type    = list(string)
  default = []
}

############################
# Locals
############################
locals {
  base_tags = merge(var.tags, {
    managed_by = "terraform"
    module     = "networking/firewall"
  })
}

############################
# Helper: SG constructor
############################
resource "aws_security_group" "p2p" {
  count       = var.p2p_enabled ? 1 : 0
  name        = "${var.name_prefix}-sg-p2p"
  description = "P2P perimeter"
  vpc_id      = var.vpc_id
  tags        = merge(local.base_tags, { Name = "${var.name_prefix}-sg-p2p", perimeter = "p2p" })
}

resource "aws_security_group" "rpc" {
  count       = var.rpc_enabled ? 1 : 0
  name        = "${var.name_prefix}-sg-rpc"
  description = "RPC perimeter"
  vpc_id      = var.vpc_id
  tags        = merge(local.base_tags, { Name = "${var.name_prefix}-sg-rpc", perimeter = "rpc" })
}

resource "aws_security_group" "grpc" {
  count       = var.grpc_enabled ? 1 : 0
  name        = "${var.name_prefix}-sg-grpc"
  description = "gRPC perimeter"
  vpc_id      = var.vpc_id
  tags        = merge(local.base_tags, { Name = "${var.name_prefix}-sg-grpc", perimeter = "grpc" })
}

resource "aws_security_group" "metrics" {
  count       = var.metrics_enabled ? 1 : 0
  name        = "${var.name_prefix}-sg-metrics"
  description = "Metrics perimeter"
  vpc_id      = var.vpc_id
  tags        = merge(local.base_tags, { Name = "${var.name_prefix}-sg-metrics", perimeter = "metrics" })
}

############################
# Ingress rules: P2P (TCP/UDP)
############################
# P2P TCP from CIDR IPv4
resource "aws_vpc_security_group_ingress_rule" "p2p_tcp_ipv4" {
  for_each = var.p2p_enabled ? {
    for port in var.p2p_ports_tcp : "p2p-tcp-ipv4-${port}" => port
  } : {}

  security_group_id = aws_security_group.p2p[0].id
  cidr_ipv4         = length(var.p2p_allow_cidrs_ipv4) > 0 ? null : "0.0.0.0/32"
  # If list provided, create separate rules for each CIDR
  # Use dynamic resource for each cidr:
  # We emulate via separate resource below to truly split per CIDR.
  description       = "P2P TCP IPv4 placeholder (split below)"
  from_port         = tonumber(regex("^\\d+$", each.value) ? each.value : split("-", each.value)[0])
  to_port           = tonumber(regex("^\\d+$", each.value) ? each.value : split("-", each.value)[1])
  ip_protocol       = "tcp"

  lifecycle { create_before_destroy = true }
}

# Split per IPv4 CIDR to avoid conditional ambiguity
resource "aws_vpc_security_group_ingress_rule" "p2p_tcp_ipv4_list" {
  for_each = var.p2p_enabled ? {
    for cidr in var.p2p_allow_cidrs_ipv4 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.p2p[0].id
  cidr_ipv4         = each.value
  description       = "P2P TCP IPv4"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"

  lifecycle { create_before_destroy = true }
}

# P2P TCP from IPv6 CIDR list
resource "aws_vpc_security_group_ingress_rule" "p2p_tcp_ipv6_list" {
  for_each = var.p2p_enabled ? {
    for cidr in var.p2p_allow_cidrs_ipv6 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.p2p[0].id
  cidr_ipv6         = each.value
  description       = "P2P TCP IPv6"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"

  lifecycle { create_before_destroy = true }
}

# P2P TCP from other SGs
resource "aws_vpc_security_group_ingress_rule" "p2p_tcp_sg" {
  for_each = var.p2p_enabled ? toset(var.p2p_allow_source_sg_ids) : []

  security_group_id = aws_security_group.p2p[0].id
  referenced_security_group_id = each.value
  description       = "P2P TCP from SG"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"

  lifecycle { create_before_destroy = true }
}

# P2P UDP (discovery) — IPv4 list
resource "aws_vpc_security_group_ingress_rule" "p2p_udp_ipv4_list" {
  for_each = var.p2p_enabled ? {
    for cidr in var.p2p_allow_cidrs_ipv4 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.p2p[0].id
  cidr_ipv4         = each.value
  description       = "P2P UDP IPv4 discovery"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "udp"

  lifecycle { create_before_destroy = true }
}

# P2P UDP — IPv6 list
resource "aws_vpc_security_group_ingress_rule" "p2p_udp_ipv6_list" {
  for_each = var.p2p_enabled ? {
    for cidr in var.p2p_allow_cidrs_ipv6 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.p2p[0].id
  cidr_ipv6         = each.value
  description       = "P2P UDP IPv6 discovery"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "udp"

  lifecycle { create_before_destroy = true }
}

# P2P UDP — from SGs
resource "aws_vpc_security_group_ingress_rule" "p2p_udp_sg" {
  for_each = var.p2p_enabled ? toset(var.p2p_allow_source_sg_ids) : []

  security_group_id            = aws_security_group.p2p[0].id
  referenced_security_group_id = each.value
  description                  = "P2P UDP from SG"
  from_port                    = 0
  to_port                      = 65535
  ip_protocol                  = "udp"

  lifecycle { create_before_destroy = true }
}

############################################################
# Ingress rules: RPC (TCP)
############################################################
resource "aws_vpc_security_group_ingress_rule" "rpc_tcp_ipv4" {
  for_each = var.rpc_enabled ? {
    for port in var.rpc_ports_tcp : "rpc-tcp-ipv4-${port}" => port
  } : {}

  security_group_id = aws_security_group.rpc[0].id
  description       = "RPC TCP IPv4"
  cidr_ipv4         = length(var.rpc_allow_cidrs_ipv4) > 0 ? null : "0.0.0.0/32"
  from_port         = tonumber(regex("^\\d+$", each.value) ? each.value : split("-", each.value)[0])
  to_port           = tonumber(regex("^\\d+$", each.value) ? each.value : split("-", each.value)[1])
  ip_protocol       = "tcp"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "rpc_tcp_ipv4_list" {
  for_each = var.rpc_enabled ? {
    for cidr in var.rpc_allow_cidrs_ipv4 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.rpc[0].id
  cidr_ipv4         = each.value
  description       = "RPC TCP IPv4 list"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "rpc_tcp_ipv6_list" {
  for_each = var.rpc_enabled ? {
    for cidr in var.rpc_allow_cidrs_ipv6 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.rpc[0].id
  cidr_ipv6         = each.value
  description       = "RPC TCP IPv6 list"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "rpc_tcp_sg" {
  for_each = var.rpc_enabled ? toset(var.rpc_allow_source_sg_ids) : []

  security_group_id            = aws_security_group.rpc[0].id
  referenced_security_group_id = each.value
  description                  = "RPC TCP from SG"
  from_port                    = 0
  to_port                      = 65535
  ip_protocol                  = "tcp"
  lifecycle                   { create_before_destroy = true }
}

############################################################
# Ingress rules: gRPC (TCP)
############################################################
resource "aws_vpc_security_group_ingress_rule" "grpc_tcp_ipv4" {
  for_each = var.grpc_enabled ? {
    for port in var.grpc_ports_tcp : "grpc-tcp-ipv4-${port}" => port
  } : {}

  security_group_id = aws_security_group.grpc[0].id
  cidr_ipv4         = length(var.grpc_allow_cidrs_ipv4) > 0 ? null : "0.0.0.0/32"
  description       = "gRPC TCP IPv4"
  from_port         = tonumber(regex("^\\d+$", each.value) ? each.value : split("-", each.value)[0])
  to_port           = tonumber(regex("^\\d+$", each.value) ? each.value : split("-", each.value)[1])
  ip_protocol       = "tcp"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "grpc_tcp_ipv4_list" {
  for_each = var.grpc_enabled ? {
    for cidr in var.grpc_allow_cidrs_ipv4 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.grpc[0].id
  cidr_ipv4         = each.value
  description       = "gRPC TCP IPv4 list"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "grpc_tcp_ipv6_list" {
  for_each = var.grpc_enabled ? {
    for cidr in var.grpc_allow_cidrs_ipv6 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.grpc[0].id
  cidr_ipv6         = each.value
  description       = "gRPC TCP IPv6 list"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "grpc_tcp_sg" {
  for_each = var.grpc_enabled ? toset(var.grpc_allow_source_sg_ids) : []

  security_group_id            = aws_security_group.grpc[0].id
  referenced_security_group_id = each.value
  description                  = "gRPC TCP from SG"
  from_port                    = 0
  to_port                      = 65535
  ip_protocol                  = "tcp"
  lifecycle                   { create_before_destroy = true }
}

############################################################
# Ingress rules: Metrics (TCP)
############################################################
resource "aws_vpc_security_group_ingress_rule" "metrics_tcp_ipv4" {
  for_each = var.metrics_enabled ? {
    for port in var.metrics_ports_tcp : "metrics-tcp-ipv4-${port}" => port
  } : {}

  security_group_id = aws_security_group.metrics[0].id
  cidr_ipv4         = length(var.metrics_allow_cidrs_ipv4) > 0 ? null : "0.0.0.0/32"
  description       = "Metrics TCP IPv4"
  from_port         = tonumber(regex("^\\d+$", each.value) ? each.value : split("-", each.value)[0])
  to_port           = tonumber(regex("^\\d+$", each.value) ? each.value : split("-", each.value)[1])
  ip_protocol       = "tcp"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "metrics_tcp_ipv4_list" {
  for_each = var.metrics_enabled ? {
    for cidr in var.metrics_allow_cidrs_ipv4 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.metrics[0].id
  cidr_ipv4         = each.value
  description       = "Metrics TCP IPv4 list"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "metrics_tcp_ipv6_list" {
  for_each = var.metrics_enabled ? {
    for cidr in var.metrics_allow_cidrs_ipv6 : cidr => cidr
  } : {}

  security_group_id = aws_security_group.metrics[0].id
  cidr_ipv6         = each.value
  description       = "Metrics TCP IPv6 list"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "metrics_tcp_sg" {
  for_each = var.metrics_enabled ? toset(var.metrics_allow_source_sg_ids) : []

  security_group_id            = aws_security_group.metrics[0].id
  referenced_security_group_id = each.value
  description                  = "Metrics TCP from SG"
  from_port                    = 0
  to_port                      = 65535
  ip_protocol                  = "tcp"
  lifecycle                   { create_before_destroy = true }
}

############################################################
# Egress policy (shared pattern)
############################################################
# Allow-all egress (IPv4+IPv6) if enabled
resource "aws_vpc_security_group_egress_rule" "egress_all_ipv4" {
  for_each = toset([
    for sg in concat(
      var.p2p_enabled ? [aws_security_group.p2p[0].id] : [],
      var.rpc_enabled ? [aws_security_group.rpc[0].id] : [],
      var.grpc_enabled ? [aws_security_group.grpc[0].id] : [],
      var.metrics_enabled ? [aws_security_group.metrics[0].id] : []
    ) : sg
  ])

  security_group_id = each.value
  ip_protocol       = "-1"
  cidr_ipv4         = var.egress_allow_all ? "0.0.0.0/0" : null
  description       = "Allow all IPv4 egress"
  lifecycle        { create_before_destroy = true }
}

resource "aws_vpc_security_group_egress_rule" "egress_all_ipv6" {
  for_each = toset([
    for sg in concat(
      var.p2p_enabled ? [aws_security_group.p2p[0].id] : [],
      var.rpc_enabled ? [aws_security_group.rpc[0].id] : [],
      var.grpc_enabled ? [aws_security_group.grpc[0].id] : [],
      var.metrics_enabled ? [aws_security_group.metrics[0].id] : []
    ) : sg
  ])

  security_group_id = each.value
  ip_protocol       = "-1"
  cidr_ipv6         = var.egress_allow_all ? "::/0" : null
  description       = "Allow all IPv6 egress"
  lifecycle        { create_before_destroy = true }
}

# Additional explicit egress IPv4 CIDRs
resource "aws_vpc_security_group_egress_rule" "egress_ipv4_list" {
  for_each = {
    for idx, pair in flatten([
      for sg_id in concat(
        var.p2p_enabled ? [aws_security_group.p2p[0].id] : [],
        var.rpc_enabled ? [aws_security_group.rpc[0].id] : [],
        var.grpc_enabled ? [aws_security_group.grpc[0].id] : [],
        var.metrics_enabled ? [aws_security_group.metrics[0].id] : []
      ) : [
        for cidr in var.egress_additional_cidrs_ipv4 : {
          sg_id = sg_id
          cidr  = cidr
        }
      ]
    ]) : "${pair.sg_id}-${pair.cidr}" => pair
  }

  security_group_id = each.value.sg_id
  ip_protocol       = "-1"
  cidr_ipv4         = var.egress_allow_all ? null : each.value.cidr
  description       = "Explicit IPv4 egress"
  lifecycle        { create_before_destroy = true }
}

# Additional explicit egress IPv6 CIDRs
resource "aws_vpc_security_group_egress_rule" "egress_ipv6_list" {
  for_each = {
    for idx, pair in flatten([
      for sg_id in concat(
        var.p2p_enabled ? [aws_security_group.p2p[0].id] : [],
        var.rpc_enabled ? [aws_security_group.rpc[0].id] : [],
        var.grpc_enabled ? [aws_security_group.grpc[0].id] : [],
        var.metrics_enabled ? [aws_security_group.metrics[0].id] : []
      ) : [
        for cidr in var.egress_additional_cidrs_ipv6 : {
          sg_id = sg_id
          cidr  = cidr
        }
      ]
    ]) : "${pair.sg_id}-${pair.cidr}" => pair
  }

  security_group_id = each.value.sg_id
  ip_protocol       = "-1"
  cidr_ipv6         = var.egress_allow_all ? null : each.value.cidr
  description       = "Explicit IPv6 egress"
  lifecycle        { create_before_destroy = true }
}

############################
# Outputs
############################
output "sg_ids" {
  description = "All security group IDs"
  value = {
    p2p     = var.p2p_enabled     ? aws_security_group.p2p[0].id     : null
    rpc     = var.rpc_enabled     ? aws_security_group.rpc[0].id     : null
    grpc    = var.grpc_enabled    ? aws_security_group.grpc[0].id    : null
    metrics = var.metrics_enabled ? aws_security_group.metrics[0].id : null
  }
}

output "sg_arns" {
  description = "All security group ARNs"
  value = {
    p2p     = var.p2p_enabled     ? aws_security_group.p2p[0].arn     : null
    rpc     = var.rpc_enabled     ? aws_security_group.rpc[0].arn     : null
    grpc    = var.grpc_enabled    ? aws_security_group.grpc[0].arn    : null
    metrics = var.metrics_enabled ? aws_security_group.metrics[0].arn : null
  }
}
