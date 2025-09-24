###############################################
# modules/networking/peering-and-endpoints/main.tf
# Industrial-grade, multi-cloud (AWS/Azure) module
#
# SOURCES:
# - AWS VPC Peering (Terraform): https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_peering_connection
# - AWS VPC Endpoints (Terraform): https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint
# - AWS PrivateLink overview:   https://docs.aws.amazon.com/vpc/latest/privatelink/endpoint-services-overview.html
# - Azure VNet Peering (Terraform): https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_peering
# - Azure Private Endpoint (Terraform): https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint
# - Azure Private Endpoint overview:  https://learn.microsoft.com/azure/private-link/private-endpoint-overview
###############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.90"
    }
  }
}

############################################
# Variables (declare in variables.tf ideally)
############################################
# cloud: "aws" | "azure"
variable "cloud" { type = string }

# Common tagging/naming
variable "name_prefix" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}

############################
# ---------- AWS ----------
############################

# Peering config (AWS)
variable "aws_enable_peering" {
  type    = bool
  default = false
}
variable "aws_requester_vpc_id" { type = string }
variable "aws_accepter_vpc_id"  { type = string }
variable "aws_peer_region" {
  type    = string
  default = null # same region if null
}
variable "aws_peer_account_id" {
  type    = string
  default = null # same account if null
}
variable "aws_auto_accept" {
  type    = bool
  default = false # cross-account typically requires explicit accept
}
variable "aws_allow_remote_vpc_dns_resolution" {
  type    = bool
  default = true # enables DNS resolution across peering (where supported)
}

# Route tables and CIDRs to propagate over peering
variable "aws_requester_route_table_ids" {
  type    = list(string)
  default = []
}
variable "aws_accepter_route_table_ids" {
  type    = list(string)
  default = []
}
variable "aws_requester_routes_to_peer" {
  description = "CIDR blocks reachable via peering from requester side"
  type        = list(string)
  default     = []
}
variable "aws_accepter_routes_to_peer" {
  description = "CIDR blocks reachable via peering from accepter side"
  type        = list(string)
  default     = []
}

# VPC Endpoints (AWS)
variable "aws_enable_endpoints" {
  type    = bool
  default = false
}

# Subnets and SG for Interface Endpoints
variable "aws_interface_subnet_ids" {
  description = "Subnets for Interface VPC Endpoints ENIs (usually private)"
  type        = list(string)
  default     = []
}
variable "aws_interface_endpoint_sg_id" {
  description = "Security group to attach to Interface Endpoints"
  type        = string
  default     = null
}

# Maps of endpoints: service_name => { private_dns = bool, policy = json or null }
# Examples of service names (verify availability per region in AWS docs):
#   "ecr.api", "ecr.dkr", "ssm", "secretsmanager", "kms", "rds", "rds-data"
# Ref: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint
variable "aws_interface_endpoints" {
  type = map(object({
    private_dns = optional(bool, true)
    policy      = optional(string, null) # IAM policy JSON for the endpoint
  }))
  default = {}
}

# Gateway endpoints (attach to specified RTs). Typical: "s3", "dynamodb"
variable "aws_gateway_endpoints" {
  type = map(object({
    route_table_ids = list(string)
    policy          = optional(string, null)
  }))
  default = {}
}

# Provider alias (optional) for cross-account ops
provider "aws" {
  alias = "peer"
  # Supply region/credentials for peer as needed from root module
}

########################################
# AWS VPC Peering — requester side
# Terraform docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_peering_connection
########################################
resource "aws_vpc_peering_connection" "this" {
  count = var.cloud == "aws" && var.aws_enable_peering ? 1 : 0

  vpc_id        = var.aws_requester_vpc_id
  peer_vpc_id   = var.aws_accepter_vpc_id
  peer_owner_id = var.aws_peer_account_id
  peer_region   = var.aws_peer_region
  auto_accept   = var.aws_auto_accept

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpc-peer"
  })
}

# If not auto-accepted (e.g., cross-account), accept from accepter side using provider.aws.peer
# Docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_peering_connection_accepter
resource "aws_vpc_peering_connection_accepter" "accept" {
  count = var.cloud == "aws" && var.aws_enable_peering && var.aws_auto_accept == false ? 1 : 0

  provider                  = aws.peer
  vpc_peering_connection_id = aws_vpc_peering_connection.this[0].id
  auto_accept               = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpc-peer-accepter"
  })
}

# Configure DNS resolution options on both sides
# Docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_peering_connection_options
resource "aws_vpc_peering_connection_options" "requester" {
  count = var.cloud == "aws" && var.aws_enable_peering ? 1 : 0

  vpc_peering_connection_id = aws_vpc_peering_connection.this[0].id

  requester {
    allow_remote_vpc_dns_resolution = var.aws_allow_remote_vpc_dns_resolution
  }
}

resource "aws_vpc_peering_connection_options" "accepter" {
  count = var.cloud == "aws" && var.aws_enable_peering ? 1 : 0

  vpc_peering_connection_id = aws_vpc_peering_connection.this[0].id

  accepter {
    allow_remote_vpc_dns_resolution = var.aws_allow_remote_vpc_dns_resolution
  }
}

# Propagate routes from requester side to peer
# Docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route
resource "aws_route" "requester_to_peer" {
  for_each = var.cloud == "aws" && var.aws_enable_peering ? {
    for rtid in var.aws_requester_route_table_ids : rtid => rtid
  } : {}

  route_table_id            = each.key
  destination_cidr_block    = null
  destination_ipv6_cidr_block = null

  # Create one route per CIDR via dynamic block (workaround using separate resources per cidr)
  # We materialize with a nested resource using for_each over cidrs:
}

resource "aws_route" "requester_to_peer_cidrs" {
  for_each = var.cloud == "aws" && var.aws_enable_peering ? {
    for pair in flatten([
      for rtid in var.aws_requester_route_table_ids : [
        for cidr in var.aws_requester_routes_to_peer : {
          key  = "${rtid}|${cidr}"
          rtid = rtid
          cidr = cidr
        }
      ]
    ]) : pair.key => pair
  } : {}

  route_table_id         = each.value.rtid
  destination_cidr_block = can(regex(":", each.value.cidr)) ? null : each.value.cidr
  destination_ipv6_cidr_block = can(regex(":", each.value.cidr)) ? each.value.cidr : null
  vpc_peering_connection_id   = aws_vpc_peering_connection.this[0].id
}

# Propagate routes from accepter side to peer (use provider.aws.peer if needed)
resource "aws_route" "accepter_to_peer_cidrs" {
  provider = aws.peer
  for_each = var.cloud == "aws" && var.aws_enable_peering ? {
    for pair in flatten([
      for rtid in var.aws_accepter_route_table_ids : [
        for cidr in var.aws_accepter_routes_to_peer : {
          key  = "${rtid}|${cidr}"
          rtid = rtid
          cidr = cidr
        }
      ]
    ]) : pair.key => pair
  } : {}

  route_table_id         = each.value.rtid
  destination_cidr_block = can(regex(":", each.value.cidr)) ? null : each.value.cidr
  destination_ipv6_cidr_block = can(regex(":", each.value.cidr)) ? each.value.cidr : null
  vpc_peering_connection_id   = aws_vpc_peering_connection.this[0].id
}

########################################
# AWS VPC Endpoints (Interface/Gateway)
# Terraform docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint
########################################

# Interface endpoints (ENI in subnets)
resource "aws_vpc_endpoint" "interface" {
  for_each = var.cloud == "aws" && var.aws_enable_endpoints ? var.aws_interface_endpoints : {}

  vpc_id            = var.aws_requester_vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.${each.key}" # verify available services per region
  vpc_endpoint_type = "Interface"
  private_dns_enabled = try(each.value.private_dns, true)
  subnet_ids        = var.aws_interface_subnet_ids

  security_group_ids = compact([var.aws_interface_endpoint_sg_id])

  # Optional policy JSON
  policy = try(each.value.policy, null)

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpce-if-${replace(each.key, "/[^a-z0-9.]/", "")}"
  })
}

data "aws_region" "current" {}

# Gateway endpoints (attach to route tables)
resource "aws_vpc_endpoint" "gateway" {
  for_each = var.cloud == "aws" && length(var.aws_gateway_endpoints) > 0 ? var.aws_gateway_endpoints : {}

  vpc_id            = var.aws_requester_vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.${each.key}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = each.value.route_table_ids
  policy            = try(each.value.policy, null)

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpce-gw-${replace(each.key, "/[^a-z0-9.]/", "")}"
  })
}

############################
# ---------- Azure --------
############################

# Peering config (Azure)
variable "az_enable_peering" {
  type    = bool
  default = false
}

# Peering requires both VNets (local and remote) and bidirectional peering for full connectivity
variable "az_local_vnet_id"  { type = string }
variable "az_remote_vnet_id" { type = string }

# Control flags according to MS docs (forwarded traffic, transitive use via gateway, etc.)
# Docs: https://learn.microsoft.com/azure/virtual-network/virtual-network-peering-overview
variable "az_allow_vnet_access" {
  type    = bool
  default = true
}
variable "az_allow_forwarded_traffic" {
  type    = bool
  default = true
}
variable "az_allow_gateway_transit" {
  type    = bool
  default = false
}
variable "az_use_remote_gateways" {
  type    = bool
  default = false
}

# Azure Private Endpoint common params
variable "az_enable_private_endpoints" {
  type    = bool
  default = false
}

# Map of endpoints:
# key => {
#   resource_id         = "<target PaaS resource id>"
#   subresource_names   = ["sqlServer","blob","redis","registry"]  # per service
#   subnet_id           = "<subnet for PE NIC>"
#   private_dns_zone_ids = ["<zone_id1>", ...]  # optional; will create zone group
# }
# Docs: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint
variable "az_private_endpoints" {
  type = map(object({
    resource_id          = string
    subresource_names    = list(string)
    subnet_id            = string
    private_dns_zone_ids = optional(list(string), [])
  }))
  default = {}
}

# AzureRM provider features block typically required at root
provider "azurerm" {
  features {}
}

# Bidirectional VNet peering
# Terraform: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_peering
resource "azurerm_virtual_network_peering" "local_to_remote" {
  count                        = var.cloud == "azure" && var.az_enable_peering ? 1 : 0
  name                         = "${var.name_prefix}-vnet-peer-l2r"
  resource_group_name          = data.azurerm_virtual_network.local.resource_group_name
  virtual_network_name         = data.azurerm_virtual_network.local.name
  remote_virtual_network_id    = var.az_remote_vnet_id
  allow_virtual_network_access = var.az_allow_vnet_access
  allow_forwarded_traffic      = var.az_allow_forwarded_traffic
  allow_gateway_transit        = var.az_allow_gateway_transit
  use_remote_gateways          = var.az_use_remote_gateways

  tags = var.tags
}

resource "azurerm_virtual_network_peering" "remote_to_local" {
  count                        = var.cloud == "azure" && var.az_enable_peering ? 1 : 0
  name                         = "${var.name_prefix}-vnet-peer-r2l"
  resource_group_name          = data.azurerm_virtual_network.remote.resource_group_name
  virtual_network_name         = data.azurerm_virtual_network.remote.name
  remote_virtual_network_id    = var.az_local_vnet_id
  allow_virtual_network_access = var.az_allow_vnet_access
  allow_forwarded_traffic      = var.az_allow_forwarded_traffic
  allow_gateway_transit        = var.az_allow_gateway_transit
  use_remote_gateways          = var.az_use_remote_gateways

  tags = var.tags
}

data "azurerm_virtual_network" "local" {
  count               = var.cloud == "azure" && var.az_enable_peering ? 1 : 0
  name                = split("/", var.az_local_vnet_id)[8]
  resource_group_name = split("/", var.az_local_vnet_id)[4]
}

data "azurerm_virtual_network" "remote" {
  count               = var.cloud == "azure" && var.az_enable_peering ? 1 : 0
  name                = split("/", var.az_remote_vnet_id)[8]
  resource_group_name = split("/", var.az_remote_vnet_id)[4]
}

# Azure Private Endpoints
# Terraform: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint
resource "azurerm_private_endpoint" "this" {
  for_each            = var.cloud == "azure" && var.az_enable_private_endpoints ? var.az_private_endpoints : {}
  name                = "${var.name_prefix}-pep-${replace(each.key, "/[^a-z0-9-]/", "")}"
  location            = data.azurerm_subnet.pep[each.key].location
  resource_group_name = data.azurerm_subnet.pep[each.key].resource_group_name
  subnet_id           = each.value.subnet_id

  private_service_connection {
    name                           = "${var.name_prefix}-psc-${replace(each.key, "/[^a-z0-9-]/", "")}"
    is_manual_connection           = false
    private_connection_resource_id = each.value.resource_id
    subresource_names              = each.value.subresource_names
  }

  tags = var.tags
}

# Optional DNS zone group bind
# Terraform: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone_group
resource "azurerm_private_dns_zone_group" "this" {
  for_each            = var.cloud == "azure" && var.az_enable_private_endpoints ? {
    for k, v in var.az_private_endpoints : k => v if length(try(v.private_dns_zone_ids, [])) > 0
  } : {}
  name                = "${var.name_prefix}-pdnszg-${replace(each.key, "/[^a-z0-9-]/", "")}"
  resource_group_name = data.azurerm_subnet.pep[each.key].resource_group_name
  private_endpoint_id = azurerm_private_endpoint.this[each.key].id

  dynamic "private_dns_zone_configs" {
    for_each = toset(each.value.private_dns_zone_ids)
    content {
      name                 = "zone-${replace(replace(private_dns_zone_configs.value, "/.*/", ""), "/[^a-z0-9-]/", "")}"
      private_dns_zone_id  = private_dns_zone_configs.value
    }
  }
}

data "azurerm_subnet" "pep" {
  for_each = var.cloud == "azure" && var.az_enable_private_endpoints ? var.az_private_endpoints : {}
  name                 = split("/", each.value.subnet_id)[10]
  virtual_network_name = split("/", each.value.subnet_id)[8]
  resource_group_name  = split("/", each.value.subnet_id)[4]
}

#########################
# Outputs (optional)
#########################
output "aws_vpc_peering_connection_id" {
  value       = try(aws_vpc_peering_connection.this[0].id, null)
  description = "AWS VPC peering connection id (if created)"
}

output "aws_interface_endpoint_ids" {
  value       = [for k, v in aws_vpc_endpoint.interface : v.id]
  description = "AWS Interface VPC Endpoint IDs"
}

output "aws_gateway_endpoint_ids" {
  value       = [for k, v in aws_vpc_endpoint.gateway : v.id]
  description = "AWS Gateway VPC Endpoint IDs"
}

output "az_private_endpoint_ids" {
  value       = [for k, v in azurerm_private_endpoint.this : v.id]
  description = "Azure Private Endpoint IDs"
}

output "az_vnet_peering_ids" {
  value       = compact([
    try(azurerm_virtual_network_peering.local_to_remote[0].id, null),
    try(azurerm_virtual_network_peering.remote_to_local[0].id, null)
  ])
  description = "Azure VNet Peering IDs"
}
