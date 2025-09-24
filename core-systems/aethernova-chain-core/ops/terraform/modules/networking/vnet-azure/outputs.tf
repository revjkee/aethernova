###############################################################################
# File: ops/terraform/modules/networking/vnet-azure/outputs.tf
# Purpose: Stable, null-safe outputs for Azure Virtual Network module.
# Notes:
#  - Designed to be resilient even when optional resources are disabled.
#  - Avoids hard failures by wrapping optionals with try() and defaulting to {} or [].
#  - Keep output names stable; they are part of the module's public contract.
###############################################################################

############################
# Core VNet attributes
############################
output "vnet_id" {
  description = "ID of the Virtual Network."
  value       = azurerm_virtual_network.this.id
}

output "vnet_name" {
  description = "Name of the Virtual Network."
  value       = azurerm_virtual_network.this.name
}

output "vnet_resource_group_name" {
  description = "Resource group where the VNet resides."
  value       = azurerm_virtual_network.this.resource_group_name
}

output "vnet_location" {
  description = "Azure region of the VNet."
  value       = azurerm_virtual_network.this.location
}

output "vnet_address_space" {
  description = "Address space (list of CIDR blocks) of the VNet."
  value       = azurerm_virtual_network.this.address_space
}

output "vnet_dns_servers" {
  description = "Custom DNS servers applied to the VNet (empty if not set)."
  value       = try(azurerm_virtual_network.this.dns_servers, [])
}

output "vnet_tags" {
  description = "Tags applied to the VNet."
  value       = try(azurerm_virtual_network.this.tags, {})
}

############################
# Subnets (maps and lists)
############################
# Flat list of subnet IDs (useful for for_each consumers).
output "subnet_ids" {
  description = "List of all subnet IDs."
  value       = [for s in azurerm_subnet.this : s.id]
}

# Map: subnet_name => subnet_id
output "subnet_id_map" {
  description = "Map of subnet name to subnet ID."
  value       = { for s in azurerm_subnet.this : s.name => s.id }
}

# Rich map of subnet_name => attributes
output "subnets" {
  description = "Detailed attributes per subnet (id, name, address_prefixes, route_table_id, nsg_id, delegations, service_endpoints, private_endpoint_network_policies)."
  value = {
    for s in azurerm_subnet.this : s.name => {
      id                               = s.id
      name                             = s.name
      address_prefixes                 = try(s.address_prefixes, s.address_prefix != null ? [s.address_prefix] : [])
      route_table_id                   = try(azurerm_subnet_route_table_association.this[s.name].route_table_id, null)
      network_security_group_id        = try(azurerm_subnet_network_security_group_association.this[s.name].network_security_group_id, null)
      delegations                      = try([for d in s.delegation : { name = d.name, service_delegation = d.service_delegation[0].name }], [])
      service_endpoints                = try(s.service_endpoints, [])
      service_endpoint_policy_ids      = try(s.service_endpoint_policy_ids, [])
      private_endpoint_network_policies = try(s.private_endpoint_network_policies, null)
      private_link_service_network_policies = try(s.private_link_service_network_policies, null)
    }
  }
}

############################
# Network Security Groups
############################
# NSG resources may be optional; use try() to default to {} / [].
output "nsg_ids" {
  description = "List of Network Security Group IDs (empty if NSG disabled)."
  value       = try([for k, n in azurerm_network_security_group.this : n.id], [])
}

output "nsg_id_map" {
  description = "Map of NSG name to NSG ID."
  value       = try({ for k, n in azurerm_network_security_group.this : n.name => n.id }, {})
}

output "nsg_rules" {
  description = "Map of NSG name to its security rules (flattened minimal view)."
  value = try({
    for k, n in azurerm_network_security_group.this :
    n.name => [
      for r in try(n.security_rule, []) : {
        name                       = r.name
        priority                   = r.priority
        direction                  = r.direction
        access                     = r.access
        protocol                   = r.protocol
        source_port_range          = try(r.source_port_range, null)
        destination_port_range     = try(r.destination_port_range, null)
        source_address_prefix      = try(r.source_address_prefix, null)
        destination_address_prefix = try(r.destination_address_prefix, null)
      }
    ]
  }, {})
}

############################
# Route Tables
############################
output "route_table_ids" {
  description = "List of Route Table IDs (empty if none created)."
  value       = try([for k, rt in azurerm_route_table.this : rt.id], [])
}

output "route_table_id_map" {
  description = "Map of Route Table name to ID."
  value       = try({ for k, rt in azurerm_route_table.this : rt.name => rt.id }, {})
}

output "route_table_routes" {
  description = "Map of Route Table name to its routes (name, address_prefix, next_hop_type, next_hop_ip)."
  value = try({
    for k, rt in azurerm_route_table.this :
    rt.name => [
      for r in try(rt.route, []) : {
        name           = r.name
        address_prefix = r.address_prefix
        next_hop_type  = r.next_hop_type
        next_hop_ip    = try(r.next_hop_in_ip_address, null)
      }
    ]
  }, {})
}

############################
# DDoS Protection (optional)
############################
output "ddos_protection_plan_id" {
  description = "ID of the DDoS Protection Plan attached to the VNet (null if not used)."
  value       = try(azurerm_ddos_protection_plan.this.id, null)
}

############################
# Peerings (optional)
############################
output "peerings" {
  description = "Map of peering name to attributes (id, remote_vnet_id, allow_* flags, use_remote_gateways)."
  value = try({
    for k, p in azurerm_virtual_network_peering.this :
    p.name => {
      id                    = p.id
      remote_virtual_network_id = p.remote_virtual_network_id
      allow_forwarded_traffic   = try(p.allow_forwarded_traffic, false)
      allow_gateway_transit     = try(p.allow_gateway_transit, false)
      allow_virtual_network_access = try(p.allow_virtual_network_access, true)
      use_remote_gateways       = try(p.use_remote_gateways, false)
      peering_state             = try(p.peering_state, null)
    }
  }, {})
}

############################
# Special subnets (well-known names, if present)
############################
output "bastion_subnet_id" {
  description = "ID of AzureBastionSubnet (null if not present)."
  value       = try(azurerm_subnet.this["AzureBastionSubnet"].id, null)
}

output "firewall_subnet_id" {
  description = "ID of AzureFirewallSubnet (null if not present)."
  value       = try(azurerm_subnet.this["AzureFirewallSubnet"].id, null)
}

############################
# Private DNS links (optional)
############################
output "private_dns_vnet_links" {
  description = "Map of Private DNS zone link name to ID (empty if not created)."
  value       = try({ for k, l in azurerm_private_dns_zone_virtual_network_link.this : l.name => l.id }, {})
}

############################
# Export for cross-module wiring
############################
output "export" {
  description = <<EOT
Stable export bundle for downstream modules:
- vnet: { id, name, rg, location, address_space, dns_servers, tags }
- subnets: { <name>: { id, address_prefixes, route_table_id, network_security_group_id, ... } }
- nsg_id_map, route_table_id_map, peerings, ddos_protection_plan_id
EOT
  value = {
    vnet = {
      id            = azurerm_virtual_network.this.id
      name          = azurerm_virtual_network.this.name
      resource_group= azurerm_virtual_network.this.resource_group_name
      location      = azurerm_virtual_network.this.location
      address_space = azurerm_virtual_network.this.address_space
      dns_servers   = try(azurerm_virtual_network.this.dns_servers, [])
      tags          = try(azurerm_virtual_network.this.tags, {})
    }
    subnets                   = {
      for s in azurerm_subnet.this : s.name => {
        id                                = s.id
        address_prefixes                  = try(s.address_prefixes, s.address_prefix != null ? [s.address_prefix] : [])
        route_table_id                    = try(azurerm_subnet_route_table_association.this[s.name].route_table_id, null)
        network_security_group_id         = try(azurerm_subnet_network_security_group_association.this[s.name].network_security_group_id, null)
        service_endpoints                 = try(s.service_endpoints, [])
        service_endpoint_policy_ids       = try(s.service_endpoint_policy_ids, [])
        private_endpoint_network_policies = try(s.private_endpoint_network_policies, null)
        private_link_service_network_policies = try(s.private_link_service_network_policies, null)
      }
    }
    nsg_id_map               = try({ for k, n in azurerm_network_security_group.this : n.name => n.id }, {})
    route_table_id_map       = try({ for k, rt in azurerm_route_table.this : rt.name => rt.id }, {})
    peerings                 = try({
      for k, p in azurerm_virtual_network_peering.this :
      p.name => {
        id                           = p.id
        remote_virtual_network_id    = p.remote_virtual_network_id
        allow_forwarded_traffic      = try(p.allow_forwarded_traffic, false)
        allow_gateway_transit        = try(p.allow_gateway_transit, false)
        allow_virtual_network_access = try(p.allow_virtual_network_access, true)
        use_remote_gateways          = try(p.use_remote_gateways, false)
        peering_state                = try(p.peering_state, null)
      }
    }, {})
    ddos_protection_plan_id  = try(azurerm_ddos_protection_plan.this.id, null)
    bastion_subnet_id        = try(azurerm_subnet.this["AzureBastionSubnet"].id, null)
    firewall_subnet_id       = try(azurerm_subnet.this["AzureFirewallSubnet"].id, null)
  }
}
