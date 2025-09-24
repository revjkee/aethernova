#############################################
# Aethernova / AVM Core — VPN module (AWS/GCP)
# Path: core-systems/avm_core/ops/terraform/vpn.tf
#############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
  }
}

############################
# Common variables
############################

variable "cloud" {
  description = "Target cloud for VPN resources: aws | gcp"
  type        = string
  validation {
    condition     = contains(["aws", "gcp"], var.cloud)
    error_message = "cloud must be one of: aws, gcp."
  }
}

variable "name" {
  description = "Logical name/prefix for resources"
  type        = string
}

variable "environment" {
  description = "Environment tag (e.g., prod, stage)"
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Common tags/labels"
  type        = map(string)
  default     = {}
}

locals {
  common_tags = merge(
    {
      "app.kubernetes.io/part-of" = "avm_core"
      "aethernova.io/environment" = var.environment
      "aethernova.io/component"   = "vpn"
    },
    var.tags
  )
}

############################
# AWS section (Site-to-Site VPN)
############################

# AWS-specific variables
variable "aws_region" {
  description = "AWS region (if using aws)"
  type        = string
  default     = null
}

variable "aws_vpc_id" {
  description = "AWS VPC ID for VGW attach (required if use_vgw=true)"
  type        = string
  default     = null
}

variable "aws_use_tgw" {
  description = "Attach VPN to Transit Gateway (true) or to VPC VGW (false)"
  type        = bool
  default     = false
}

variable "aws_tgw_id" {
  description = "Existing Transit Gateway ID (required if aws_use_tgw=true)"
  type        = string
  default     = null
}

variable "aws_amazon_side_asn" {
  description = "Amazon side ASN (for VGW)"
  type        = number
  default     = 64512
}

variable "aws_customer_gateway_ip" {
  description = "Customer/peer public IP (single IP) for AWS CGW"
  type        = string
  default     = null
}

variable "aws_customer_bgp_asn" {
  description = "Peer BGP ASN (for dynamic routing)"
  type        = number
  default     = 65010
}

variable "aws_static_routes_only" {
  description = "Use static routing (true) or BGP (false)"
  type        = bool
  default     = false
}

variable "aws_static_routes" {
  description = "List of static routes (required if static_routes_only=true)"
  type        = list(string)
  default     = []
}

variable "aws_tunnel1_preshared_key" {
  description = "Optional PSK for tunnel1; if null AWS generates one"
  type        = string
  default     = null
  sensitive   = true
}

variable "aws_tunnel2_preshared_key" {
  description = "Optional PSK for tunnel2; if null AWS generates one"
  type        = string
  default     = null
  sensitive   = true
}

variable "aws_inside_cidrs" {
  description = "Optional inside CIDRs (/30) for tunnel interfaces [t1, t2]"
  type        = list(string)
  default     = []
}

variable "aws_enable_flow_logs" {
  description = "Enable VPC Flow Logs for the VPC (if using VGW attach)"
  type        = bool
  default     = false
}

variable "aws_flow_logs_log_group_name" {
  description = "CloudWatch Log Group name for VPC flow logs"
  type        = string
  default     = null
}

# Optional provider configuration (module can inherit parent provider)
provider "aws" {
  alias   = "this"
  region  = var.aws_region != null ? var.aws_region : null
  dynamic "assume_role" {
    for_each = []
    content {}
  }
}

# Customer Gateway
resource "aws_customer_gateway" "this" {
  count        = var.cloud == "aws" ? 1 : 0
  bgp_asn      = var.aws_customer_bgp_asn
  ip_address   = var.aws_customer_gateway_ip
  type         = "ipsec.1"
  device_name  = "${var.name}-cgw"
  tags         = merge(local.common_tags, { Name = "${var.name}-cgw" })
  provider     = aws.this
}

# VGW (if not using TGW)
resource "aws_vpn_gateway" "this" {
  count          = var.cloud == "aws" && !var.aws_use_tgw ? 1 : 0
  amazon_side_asn = var.aws_amazon_side_asn
  tags           = merge(local.common_tags, { Name = "${var.name}-vgw" })
  provider       = aws.this
}

resource "aws_vpn_gateway_attachment" "this" {
  count    = var.cloud == "aws" && !var.aws_use_tgw ? 1 : 0
  vpc_id   = var.aws_vpc_id
  vpn_gateway_id = aws_vpn_gateway.this[0].id
  provider = aws.this
}

# Site-to-Site VPN connection
resource "aws_vpn_connection" "this" {
  count                = var.cloud == "aws" ? 1 : 0
  customer_gateway_id  = aws_customer_gateway.this[0].id
  vpn_gateway_id       = var.aws_use_tgw ? null : (aws_vpn_gateway.this[0].id)
  transit_gateway_id   = var.aws_use_tgw ? var.aws_tgw_id : null
  type                 = "ipsec.1"
  static_routes_only   = var.aws_static_routes_only
  enable_acceleration  = true
  local_ipv4_network_cidr  = null
  remote_ipv4_network_cidr = null

  dynamic "tunnel1_options" {
    for_each = [1]
    content {
      ike_versions             = ["ikev2"]
      dpd_timeout_seconds      = 30
      startup_action           = "add"
      phase1_dh_group_numbers  = [14, 16, 21]
      phase2_dh_group_numbers  = [14, 16, 21]
      phase1_encryption_algorithms = ["AES256"]
      phase2_encryption_algorithms = ["AES256"]
      phase1_integrity_algorithms  = ["SHA2-256"]
      phase2_integrity_algorithms  = ["SHA2-256"]
      rekey_margin_time_seconds    = 540
      rekey_fuzz_percentage        = 100
      pre_shared_key               = var.aws_tunnel1_preshared_key
      tunnel_inside_cidr           = length(var.aws_inside_cidrs) > 0 ? var.aws_inside_cidrs[0] : null
    }
  }

  dynamic "tunnel2_options" {
    for_each = [1]
    content {
      ike_versions             = ["ikev2"]
      dpd_timeout_seconds      = 30
      startup_action           = "add"
      phase1_dh_group_numbers  = [14, 16, 21]
      phase2_dh_group_numbers  = [14, 16, 21]
      phase1_encryption_algorithms = ["AES256"]
      phase2_encryption_algorithms = ["AES256"]
      phase1_integrity_algorithms  = ["SHA2-256"]
      phase2_integrity_algorithms  = ["SHA2-256"]
      rekey_margin_time_seconds    = 540
      rekey_fuzz_percentage        = 100
      pre_shared_key               = var.aws_tunnel2_preshared_key
      tunnel_inside_cidr           = length(var.aws_inside_cidrs) > 1 ? var.aws_inside_cidrs[1] : null
    }
  }

  tags     = merge(local.common_tags, { Name = "${var.name}-vpn" })
  provider = aws.this

  lifecycle {
    ignore_changes = [
      tunnel1_options[0].pre_shared_key,
      tunnel2_options[0].pre_shared_key
    ]
  }
}

# Static routes (if static routing is used)
resource "aws_vpn_connection_route" "static" {
  count                = var.cloud == "aws" && var.aws_static_routes_only ? length(var.aws_static_routes) : 0
  destination_cidr_block = var.aws_static_routes[count.index]
  vpn_connection_id      = aws_vpn_connection.this[0].id
  provider               = aws.this
}

# Optional VPC Flow Logs (if VGW attached to VPC)
resource "aws_cloudwatch_log_group" "flow_logs" {
  count      = var.cloud == "aws" && var.aws_enable_flow_logs && !var.aws_use_tgw ? 1 : 0
  name       = coalesce(var.aws_flow_logs_log_group_name, "/aws/vpc/${var.aws_vpc_id}/flow-logs")
  retention_in_days = 30
  tags       = merge(local.common_tags, { Name = "${var.name}-vpc-flow-logs" })
  provider   = aws.this
}

resource "aws_flow_log" "vpc" {
  count                 = var.cloud == "aws" && var.aws_enable_flow_logs && !var.aws_use_tgw ? 1 : 0
  log_destination_type  = "cloud-watch-logs"
  log_group_name        = aws_cloudwatch_log_group.flow_logs[0].name
  traffic_type          = "ALL"
  vpc_id                = var.aws_vpc_id
  max_aggregation_interval = 60
  tags                  = merge(local.common_tags, { Name = "${var.name}-flow-log" })
  provider              = aws.this
}

############################
# GCP section (HA VPN)
############################

# GCP-specific variables
variable "gcp_project" {
  description = "GCP project"
  type        = string
  default     = null
}

variable "gcp_region" {
  description = "GCP region for HA VPN"
  type        = string
  default     = null
}

variable "gcp_network" {
  description = "VPC network self_link or name"
  type        = string
  default     = null
}

variable "gcp_router_asn" {
  description = "Cloud Router ASN (GCP side)"
  type        = number
  default     = 64514
}

variable "gcp_peer_bgp_asn" {
  description = "Peer BGP ASN (external gateway)"
  type        = number
  default     = 65010
}

variable "gcp_peer_ip_addresses" {
  description = "List of peer public IPs (1 or 2) for external gateway"
  type        = list(string)
  default     = []
  validation {
    condition     = length(var.gcp_peer_ip_addresses) == 0 || length(var.gcp_peer_ip_addresses) == 1 || length(var.gcp_peer_ip_addresses) == 2
    error_message = "gcp_peer_ip_addresses must contain 0, 1 or 2 IPs."
  }
}

variable "gcp_shared_secret" {
  description = "Shared secret (PSK) for VPN tunnels"
  type        = string
  default     = null
  sensitive   = true
}

variable "gcp_bgp_session_ranges" {
  description = "List of /30 ranges for BGP session IPs (per tunnel). Example: [\"169.254.10.0/30\", \"169.254.11.0/30\"]"
  type        = list(string)
  default     = []
}

# Optional provider (module can inherit parent)
provider "google" {
  alias   = "this"
  project = var.gcp_project != null ? var.gcp_project : null
  region  = var.gcp_region  != null ? var.gcp_region  : null
}

# HA VPN Gateway
resource "google_compute_ha_vpn_gateway" "this" {
  count   = var.cloud == "gcp" ? 1 : 0
  name    = "${var.name}-ha-gw"
  region  = var.gcp_region
  network = var.gcp_network
  labels  = { "aethernova-io-environment" = var.environment }
  provider = google.this
}

# External peer gateway (on-prem/AWS side)
resource "google_compute_external_vpn_gateway" "peer" {
  count      = var.cloud == "gcp" && length(var.gcp_peer_ip_addresses) > 0 ? 1 : 0
  name       = "${var.name}-peer-gw"
  redundancy_type = length(var.gcp_peer_ip_addresses) == 2 ? "TWO_IPS_REDUNDANCY" : "SINGLE_IP_INTERNALLY_REDUNDANT"
  description = "External peer gateway"
  interface {
    id         = 0
    ip_address = var.gcp_peer_ip_addresses[0]
  }
  dynamic "interface" {
    for_each = length(var.gcp_peer_ip_addresses) == 2 ? [1] : []
    content {
      id         = 1
      ip_address = var.gcp_peer_ip_addresses[1]
    }
  }
  provider = google.this
}

# Cloud Router
resource "google_compute_router" "this" {
  count   = var.cloud == "gcp" ? 1 : 0
  name    = "${var.name}-cr"
  region  = var.gcp_region
  network = var.gcp_network
  bgp {
    asn = var.gcp_router_asn
  }
  provider = google.this
}

# Router interfaces per tunnel (expect /30 per tunnel)
resource "google_compute_router_interface" "ifaces" {
  count          = var.cloud == "gcp" ? length(var.gcp_bgp_session_ranges) : 0
  name           = "${var.name}-if-${count.index}"
  region         = var.gcp_region
  router         = google_compute_router.this[0].name
  ip_range       = var.gcp_bgp_session_ranges[count.index]
  vpn_tunnel     = google_compute_vpn_tunnel.tunnels[count.index].name
  provider       = google.this
}

# VPN tunnels (1 or 2)
resource "google_compute_vpn_tunnel" "tunnels" {
  count                   = var.cloud == "gcp" && length(var.gcp_bgp_session_ranges) > 0 ? length(var.gcp_bgp_session_ranges) : 0
  name                    = "${var.name}-tnl-${count.index}"
  region                  = var.gcp_region
  vpn_gateway             = google_compute_ha_vpn_gateway.this[0].id
  vpn_gateway_interface   = count.index
  shared_secret           = var.gcp_shared_secret
  router                  = google_compute_router.this[0].name

  # Peer can be external gateway (on-prem/AWS)
  peer_external_gateway            = length(var.gcp_peer_ip_addresses) > 0 ? google_compute_external_vpn_gateway.peer[0].id : null
  peer_external_gateway_interface  = length(var.gcp_peer_ip_addresses) == 2 ? count.index : 0

  ike_version             = 2
  labels = {
    "aethernova-io-environment" = var.environment
  }
  provider = google.this
}

# Router peers (BGP) per tunnel
resource "google_compute_router_peer" "peers" {
  count          = var.cloud == "gcp" ? length(var.gcp_bgp_session_ranges) : 0
  name           = "${var.name}-peer-${count.index}"
  region         = var.gcp_region
  router         = google_compute_router.this[0].name
  interface      = google_compute_router_interface.ifaces[count.index].name
  peer_asn       = var.gcp_peer_bgp_asn

  # GCP side/peer side IPs are derived from /30: .1 and .2
  ip_address     = cidrhost(var.gcp_bgp_session_ranges[count.index], 1)
  peer_ip_address= cidrhost(var.gcp_bgp_session_ranges[count.index], 2)

  advertise_mode = "DEFAULT"
  enable         = true
  provider       = google.this
}

############################
# Outputs
############################

# AWS outputs
output "aws_vpn_connection_id" {
  value       = var.cloud == "aws" ? aws_vpn_connection.this[0].id : null
  description = "AWS VPN connection ID"
}

output "aws_customer_gateway_id" {
  value       = var.cloud == "aws" ? aws_customer_gateway.this[0].id : null
  description = "AWS Customer Gateway ID"
}

output "aws_vpn_tunnel_details" {
  description = "Tunnel details for remote configuration (AWS side addresses may be used for monitoring)"
  value = var.cloud == "aws" ? {
    tunnel1 = {
      outside_ip        = aws_vpn_connection.this[0].tunnel1_address
      cgw_inside_cidr   = aws_vpn_connection.this[0].tunnel1_cgw_inside_address
      vgw_inside_cidr   = aws_vpn_connection.this[0].tunnel1_vgw_inside_address
      pre_shared_key    = aws_vpn_connection.this[0].tunnel1_preshared_key
    }
    tunnel2 = {
      outside_ip        = aws_vpn_connection.this[0].tunnel2_address
      cgw_inside_cidr   = aws_vpn_connection.this[0].tunnel2_cgw_inside_address
      vgw_inside_cidr   = aws_vpn_connection.this[0].tunnel2_vgw_inside_address
      pre_shared_key    = aws_vpn_connection.this[0].tunnel2_preshared_key
    }
  } : null
  sensitive = true
}

# GCP outputs
output "gcp_vpn_gateway_id" {
  value       = var.cloud == "gcp" ? google_compute_ha_vpn_gateway.this[0].id : null
  description = "GCP HA VPN Gateway ID"
}

output "gcp_router" {
  value       = var.cloud == "gcp" ? google_compute_router.this[0].name : null
  description = "GCP Cloud Router name"
}

output "gcp_tunnels" {
  value = var.cloud == "gcp" ? [
    for t in google_compute_vpn_tunnel.tunnels : {
      name      = t.name
      interface = t.vpn_gateway_interface
      router    = t.router
    }
  ] : []
  description = "List of GCP VPN tunnels"
}

output "gcp_bgp_session_ips" {
  description = "Per-tunnel BGP session IPs (GCP side and peer side) derived from /30 ranges"
  value = var.cloud == "gcp" ? [
    for idx in range(length(var.gcp_bgp_session_ranges)) : {
      range          = var.gcp_bgp_session_ranges[idx]
      gcp_ip         = cidrhost(var.gcp_bgp_session_ranges[idx], 1)
      peer_ip        = cidrhost(var.gcp_bgp_session_ranges[idx], 2)
    }
  ] : []
}

############################
# Validations / sanity checks
############################

locals {
  is_aws = var.cloud == "aws"
  is_gcp = var.cloud == "gcp"
}

# Guardrails (preconditions are evaluated when resources are planned)
resource "null_resource" "guards" {
  count = 0

  lifecycle {
    precondition {
      condition     = !(local.is_aws && !var.aws_use_tgw) || (var.aws_vpc_id != null && var.aws_vpc_id != "")
      error_message = "AWS VGW mode requires aws_vpc_id."
    }
    precondition {
      condition     = !local.is_aws || (var.aws_customer_gateway_ip != null && var.aws_customer_gateway_ip != "")
      error_message = "AWS mode requires aws_customer_gateway_ip."
    }
    precondition {
      condition     = !(local.is_aws && var.aws_static_routes_only) || length(var.aws_static_routes) > 0
      error_message = "When aws_static_routes_only=true, provide aws_static_routes."
    }
    precondition {
      condition     = !(local.is_aws && var.aws_use_tgw) || (var.aws_tgw_id != null && var.aws_tgw_id != "")
      error_message = "aws_use_tgw=true requires aws_tgw_id."
    }
    precondition {
      condition     = !local.is_gcp || (var.gcp_project != null && var.gcp_region != null && var.gcp_network != null)
      error_message = "GCP mode requires gcp_project, gcp_region and gcp_network."
    }
    precondition {
      condition     = !local.is_gcp || length(var.gcp_bgp_session_ranges) > 0
      error_message = "GCP mode requires gcp_bgp_session_ranges (/30 per tunnel)."
    }
    precondition {
      condition     = !local.is_gcp || (var.gcp_shared_secret != null && var.gcp_shared_secret != "")
      error_message = "GCP mode requires gcp_shared_secret."
    }
  }
}
