#############################################
# Path: ops/terraform/modules/networking/vnet-azure/main.tf
# Purpose: Industrial-grade Azure Virtual Network module
#
# Verified references (официальные источники):
# Provider overview:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs
# Virtual Network:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network
# Subnet:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet
# Network Security Group:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_group
# Network Security Rule:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule
# Subnet-NSG Association:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet_network_security_group_association
# Route Table:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/route_table
# Route:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/route
# Subnet-RouteTable Association:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet_route_table_association
# DDoS Protection Plan:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_ddos_protection_plan
#   (блок ddos_protection_plan в Virtual Network):
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network#ddos_protection_plan
#############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.112.0"
    }
  }
}

provider "azurerm" {
  features {}
}

#############################################
# Inputs
#############################################

variable "resource_group_name" {
  description = "Имя ресурсной группы."
  type        = string
}

variable "location" {
  description = "Регион Azure (например, westeurope)."
  type        = string
}

variable "vnet_name" {
  description = "Имя виртуальной сети."
  type        = string
}

variable "address_space" {
  description = "Список CIDR для VNet."
  type        = list(string)
}

variable "dns_servers" {
  description = "Необязательный список пользовательских DNS-серверов."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Общие теги."
  type        = map(string)
  default     = {}
}

# Опциональный DDoS Plan.
variable "enable_ddos_plan" {
  description = "Включить DDoS Protection Plan для VNet."
  type        = bool
  default     = false
}

variable "ddos_plan_name" {
  description = "Имя DDoS Protection Plan (создаётся в этом модуле при enable_ddos_plan=true)."
  type        = string
  default     = ""
}

# Описание подсетей:
# Каждая запись — объект с именем, CIDR, опциями: service_endpoints, delegations, private_link_policies, nsg_name, rt_name, disable_private_endpoint_network_policies, disable_private_service_network_policies
variable "subnets" {
  description = <<EOT
Список подсетей. Пример:
[
  {
    name = "app"
    address_prefixes = ["10.0.1.0/24"]

    service_endpoints = ["Microsoft.Storage","Microsoft.KeyVault"] # опционально
    delegations = [
      {
        name = "aks-delegation"
        service_delegation = {
          name = "Microsoft.ContainerService/managedClusters"
          actions = [
            "Microsoft.Network/virtualNetworks/subnets/join/action",
            "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action"
          ]
        }
      }
    ]

    nsg_name = "nsg-app"   # опционально; если задано, создаётся NSG и прикрепляется
    nsg_rules = [          # опционально; список правил для NSG
      {
        name                       = "Allow-HTTP-Inbound"
        priority                   = 100
        direction                  = "Inbound"
        access                     = "Allow"
        protocol                   = "Tcp"
        source_port_range          = "*"
        destination_port_range     = "80"
        source_address_prefix      = "*"
        destination_address_prefix = "*"
      }
    ]

    rt_name = "rt-app"     # опционально; если задано, создаётся Route Table и прикрепляется
    routes = [             # опционально; UDR маршруты
      {
        name                   = "default-inet"
        address_prefix         = "0.0.0.0/0"
        next_hop_type          = "Internet"
        next_hop_in_ip_address = null
      }
    ]

    disable_private_endpoint_network_policies = false
    disable_private_service_network_policies  = false
  }
]
EOT
  type = list(object({
    name            = string
    address_prefixes = list(string)

    service_endpoints = optional(list(string), [])
    delegations = optional(list(object({
      name = string
      service_delegation = object({
        name    = string
        actions = list(string)
      })
    })), [])

    nsg_name  = optional(string)
    nsg_rules = optional(list(object({
      name                       = string
      priority                   = number
      direction                  = string # Inbound/Outbound
      access                     = string # Allow/Deny
      protocol                   = string # Tcp/Udp/Icmp/Asterisk
      source_port_range          = optional(string)
      source_port_ranges         = optional(list(string))
      destination_port_range     = optional(string)
      destination_port_ranges    = optional(list(string))
      source_address_prefix      = optional(string)
      source_address_prefixes    = optional(list(string))
      destination_address_prefix = optional(string)
      destination_address_prefixes = optional(list(string))
      description                = optional(string)
    })), [])

    rt_name = optional(string)
    routes = optional(list(object({
      name                   = string
      address_prefix         = string
      next_hop_type          = string  # VnetLocal/VnetPeering/Internet/VirtualAppliance/VirtualNetworkGateway/None
      next_hop_in_ip_address = optional(string)
    })), [])

    disable_private_endpoint_network_policies = optional(bool, false)
    disable_private_service_network_policies  = optional(bool, false)
  }))
}

#############################################
# (Optional) DDoS Plan
# Docs: azurerm_network_ddos_protection_plan
#############################################

resource "azurerm_network_ddos_protection_plan" "this" {
  count               = var.enable_ddos_plan ? 1 : 0
  name                = var.ddos_plan_name != "" ? var.ddos_plan_name : "${var.vnet_name}-ddos"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

#############################################
# Virtual Network
# Docs: azurerm_virtual_network
#############################################

resource "azurerm_virtual_network" "this" {
  name                = var.vnet_name
  address_space       = var.address_space
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_servers         = length(var.dns_servers) > 0 ? var.dns_servers : null
  tags                = merge({ Component = "vnet" }, var.tags)

  dynamic "ddos_protection_plan" {
    for_each = var.enable_ddos_plan ? [1] : []
    content {
      id     = azurerm_network_ddos_protection_plan.this[0].id
      enable = true
    }
  }
}

#############################################
# NSGs per subnet (optional, created if nsg_name provided)
# Docs:
#   azurerm_network_security_group
#   azurerm_network_security_rule
#############################################

# Карта NSG по имени, чтобы переиспользовать для нескольких подсетей с одинаковым nsg_name (если такое будет).
locals {
  nsg_specs = {
    for s in var.subnets : s.nsg_name => {
      subnet_name = s.name
      rules       = coalesce(s.nsg_rules, [])
    }
    if try(s.nsg_name, null) != null
  }
}

resource "azurerm_network_security_group" "nsg" {
  for_each            = local.nsg_specs
  name                = each.key
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = merge({ Component = "nsg", Subnet = each.value.subnet_name }, var.tags)
}

# Правила NSG
resource "azurerm_network_security_rule" "nsg_rules" {
  for_each = {
    for nsg_name, spec in local.nsg_specs :
    for r in spec.rules :
    "${nsg_name}:${r.name}" => {
      nsg_name = nsg_name
      rule     = r
    }
  }

  name                        = each.value.rule.name
  priority                    = each.value.rule.priority
  direction                   = each.value.rule.direction
  access                      = each.value.rule.access
  protocol                    = each.value.rule.protocol
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.nsg[each.value.nsg_name].name

  # Допускаются *либо* одиночные строки, *либо* списки (см. доки по resource schema).
  source_port_range           = try(each.value.rule.source_port_range, null)
  destination_port_range      = try(each.value.rule.destination_port_range, null)
  source_port_ranges          = try(each.value.rule.source_port_ranges, null)
  destination_port_ranges     = try(each.value.rule.destination_port_ranges, null)

  source_address_prefix       = try(each.value.rule.source_address_prefix, null)
  destination_address_prefix  = try(each.value.rule.destination_address_prefix, null)
  source_address_prefixes     = try(each.value.rule.source_address_prefixes, null)
  destination_address_prefixes = try(each.value.rule.destination_address_prefixes, null)

  description                 = try(each.value.rule.description, null)
}

#############################################
# Route Tables per subnet (optional)
# Docs: azurerm_route_table, azurerm_route
#############################################

locals {
  rt_specs = {
    for s in var.subnets : s.rt_name => {
      subnet_name = s.name
      routes      = coalesce(s.routes, [])
    }
    if try(s.rt_name, null) != null
  }
}

resource "azurerm_route_table" "rt" {
  for_each            = local.rt_specs
  name                = each.key
  location            = var.location
  resource_group_name = var.resource_group_name
  disable_bgp_route_propagation = false
  tags                = merge({ Component = "route-table", Subnet = each.value.subnet_name }, var.tags)
}

resource "azurerm_route" "rt_routes" {
  for_each = {
    for rt_name, spec in local.rt_specs :
    for r in spec.routes :
    "${rt_name}:${r.name}" => {
      rt_name = rt_name
      route   = r
    }
  }

  name                   = each.value.route.name
  resource_group_name    = var.resource_group_name
  route_table_name       = azurerm_route_table.rt[each.value.rt_name].name
  address_prefix         = each.value.route.address_prefix
  next_hop_type          = each.value.route.next_hop_type
  next_hop_in_ip_address = try(each.value.route.next_hop_in_ip_address, null)
}

#############################################
# Subnets
# Docs: azurerm_subnet
#############################################

resource "azurerm_subnet" "subnet" {
  for_each = {
    for s in var.subnets : s.name => s
  }

  name                 = each.value.name
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = each.value.address_prefixes

  # Service endpoints
  service_endpoints    = try(each.value.service_endpoints, null)

  # Private Link policies
  private_endpoint_network_policies_enabled = !try(each.value.disable_private_endpoint_network_policies, false)
  private_link_service_network_policies_enabled = !try(each.value.disable_private_service_network_policies, false)

  # Delegations
  dynamic "delegation" {
    for_each = try(each.value.delegations, [])
    content {
      name = delegation.value.name
      service_delegation {
        name    = delegation.value.service_delegation.name
        actions = delegation.value.service_delegation.actions
      }
    }
  }
}

#############################################
# Associations (Subnet <-> NSG, Subnet <-> Route Table)
# Docs:
#   azurerm_subnet_network_security_group_association
#   azurerm_subnet_route_table_association
#############################################

resource "azurerm_subnet_network_security_group_association" "assoc" {
  for_each = {
    for s in var.subnets :
    s.name => s
    if try(s.nsg_name, null) != null
  }

  subnet_id                 = azurerm_subnet.subnet[each.value.name].id
  network_security_group_id = azurerm_network_security_group.nsg[each.value.nsg_name].id
}

resource "azurerm_subnet_route_table_association" "assoc" {
  for_each = {
    for s in var.subnets :
    s.name => s
    if try(s.rt_name, null) != null
  }

  subnet_id      = azurerm_subnet.subnet[each.value.name].id
  route_table_id = azurerm_route_table.rt[each.value.rt_name].id
}

#############################################
# Outputs
#############################################

output "vnet_id" {
  description = "ID созданной VNet."
  value       = azurerm_virtual_network.this.id
}

output "vnet_name" {
  description = "Имя VNet."
  value       = azurerm_virtual_network.this.name
}

output "subnet_ids" {
  description = "Карта: имя подсети -> ID."
  value       = { for k, v in azurerm_subnet.subnet : k => v.id }
}

output "nsg_ids" {
  description = "Карта: имя NSG -> ID (только созданные)."
  value       = try({ for k, v in azurerm_network_security_group.nsg : k => v.id }, {})
}

output "route_table_ids" {
  description = "Карта: имя RT -> ID (только созданные)."
  value       = try({ for k, v in azurerm_route_table.rt : k => v.id }, {})
}

output "ddos_plan_id" {
  description = "ID DDoS-плана (если включён)."
  value       = var.enable_ddos_plan ? azurerm_network_ddos_protection_plan.this[0].id : null
}
