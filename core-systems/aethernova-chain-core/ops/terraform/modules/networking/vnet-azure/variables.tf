#############################################
# variables.tf — networking/vnet-azure (industrial)
# Terraform >= 1.5  |  azurerm >= 3.x
#############################################

############################
# Core context
############################
variable "name_prefix" {
  description = "Префикс ресурсов (например, org-team). Используется для VNet и зависимых ресурсов."
  type        = string
  default     = ""
  validation {
    condition     = var.name_prefix == "" || can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix допускает только [a-z0-9-]."
  }
}

variable "environment" {
  description = "Окружение (dev/stage/prod/...); участвует в нейминге и метаданных."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.environment))
    error_message = "environment допускает только [a-z0-9-]."
  }
}

variable "location" {
  description = "Регион Azure (например, northeurope, westeurope, swedencentral при доступности)."
  type        = string
}

variable "resource_group_name" {
  description = "Имя существующей Resource Group для размещения сети и зависимых ресурсов."
  type        = string
}

############################
# VNet addressing
############################
variable "vnet_name" {
  description = "Имя создаваемой Virtual Network. Пусто — будет сгенерировано из шаблона нейминга."
  type        = string
  default     = ""
  validation {
    condition     = var.vnet_name == "" || can(regex("^[a-zA-Z0-9-._()]{2,64}$", var.vnet_name))
    error_message = "vnet_name: 2..64, буквы/цифры/.-_()."
  }
}

variable "address_space" {
  description = "Список IPv4 CIDR для VNet (например, [\"10.10.0.0/16\"])."
  type        = list(string)
  validation {
    condition     = length(var.address_space) > 0 && alltrue([for c in var.address_space : can(cidrnetmask(c))])
    error_message = "address_space должен содержать как минимум один корректный IPv4 CIDR."
  }
}

variable "address_space_ipv6" {
  description = "Опциональный список IPv6 префиксов для VNet (например, [\"fd00:10:10::/48\"])."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.address_space_ipv6 : can(cidrnetmask(c))])
    error_message = "address_space_ipv6 должен содержать корректные IPv6 CIDR (или быть пустым)."
  }
}

############################
# Subnets (industrial)
############################
variable "subnets" {
  description = <<-EOT
  Описание сабнетов VNet. Для каждого сабнета:
    - name: имя сабнета
    - address_prefixes: список CIDR (IPv4/IPv6)
    - nsg_name: имя NSG для привязки (или пусто)
    - route_table_name: имя Route Table для привязки (или пусто)
    - service_endpoints: список endpoint-ов (например, ["Microsoft.Storage","Microsoft.KeyVault"])
    - delegations: список делегаций (name, service e.g. "Microsoft.Web/serverFarms", actions[])
    - private_endpoint_network_policies: "Enabled"|"Disabled" (по умолч. Enabled)
    - private_link_service_network_policies: "Enabled"|"Disabled" (по умолч. Enabled)
    - nat_gateway_name: привязка NAT Gateway (или пусто)
    - enforce_private_link_endpoint_network_policies: bool; жёстко отключает политики для PE
    - dns_servers: список кастомных DNS серверов (опционально, для будущего расширения)
  EOT
  type = list(object({
    name                                      = string
    address_prefixes                           = list(string)
    nsg_name                                   = optional(string, "")
    route_table_name                           = optional(string, "")
    service_endpoints                          = optional(list(string), [])
    delegations                                = optional(list(object({
      name    = string
      service = string
      actions = optional(list(string), [])
    })), [])
    private_endpoint_network_policies          = optional(string, "Enabled")
    private_link_service_network_policies      = optional(string, "Enabled")
    nat_gateway_name                           = optional(string, "")
    enforce_private_link_endpoint_network_policies = optional(bool, false)
    dns_servers                                = optional(list(string), [])
  }))
  default = []
  validation {
    condition = alltrue([
      for s in var.subnets : (
        length(s.address_prefixes) > 0 &&
        alltrue([for c in s.address_prefixes : can(cidrnetmask(c))]) &&
        contains(["Enabled","Disabled"], s.private_endpoint_network_policies) &&
        contains(["Enabled","Disabled"], s.private_link_service_network_policies)
      )
    ])
    error_message = "Каждый subnet должен иметь корректные CIDR и валидные значения *network_policies (Enabled|Disabled)."
  }
}

############################
# Network Security Groups (NSG) & Rules
############################
variable "nsgs" {
  description = <<-EOT
  Определение NSG как карты объектов:
    key (map key) → имя NSG
    value:
      - location: регион (если пусто, использовать var.location)
      - rules: список правил:
          name, priority (100..4096), direction(Inbound|Outbound), access(Allow|Deny),
          protocol(Tcp|Udp|Icmp|Ah|Esp|*), source/destination (address_prefixes|application_security_group_ids),
          source_port_ranges, destination_port_ranges
  EOT
  type = map(object({
    location = optional(string, "")
    rules = list(object({
      name                       = string
      priority                   = number
      direction                  = string
      access                     = string
      protocol                   = string
      source_address_prefixes    = optional(list(string), [])
      destination_address_prefixes = optional(list(string), [])
      source_port_ranges         = optional(list(string), ["*"])
      destination_port_ranges    = optional(list(string), ["*"])
      source_application_security_group_ids      = optional(list(string), [])
      destination_application_security_group_ids = optional(list(string), [])
      description                = optional(string, "")
    }))
    tags = optional(map(string), {})
  }))
  default = {}
  validation {
    condition = alltrue([
      for k, v in var.nsgs : alltrue([
        for r in v.rules : (
          r.priority >= 100 && r.priority <= 4096 &&
          contains(["Inbound","Outbound"], r.direction) &&
          contains(["Allow","Deny"], r.access) &&
          contains(["Tcp","Udp","Icmp","Ah","Esp","*"], r.protocol)
        )
      )
    ])
    error_message = "Для NSG: priority 100..4096, direction ∈ {Inbound,Outbound}, access ∈ {Allow,Deny}, protocol ∈ {Tcp,Udp,Icmp,Ah,Esp,*}."
  }
}

############################
# Route Tables (UDR)
############################
variable "route_tables" {
  description = <<-EOT
  Карта route tables:
    key → имя таблицы
    value:
      - location: регион (если пусто → var.location)
      - routes: список маршрутов:
          name, address_prefix (CIDR), next_hop_type(VirtualAppliance|Internet|None|VirtualNetworkGateway|VnetLocal|VirtualNetwork|HyperNetGateway),
          next_hop_in_ip_address (для VirtualAppliance)
  EOT
  type = map(object({
    location = optional(string, "")
    disable_bgp_route_propagation = optional(bool, false)
    routes = list(object({
      name                   = string
      address_prefix         = string
      next_hop_type          = string
      next_hop_in_ip_address = optional(string)
    }))
    tags = optional(map(string), {})
  }))
  default = {}
  validation {
    condition = alltrue([
      for k, v in var.route_tables : alltrue([
        for r in v.routes : (
          can(cidrnetmask(r.address_prefix)) &&
          contains([
            "VirtualAppliance","Internet","None","VirtualNetworkGateway",
            "VnetLocal","VirtualNetwork","HyperNetGateway"
          ], r.next_hop_type)
        )
      )
    ])
    error_message = "UDR: address_prefix должен быть CIDR; next_hop_type — допустимое значение."
  }
}

############################
# NAT Gateway & Public IPs
############################
variable "nat_gateways" {
  description = <<-EOT
  Карта NAT Gateway:
    key → имя NAT
    value:
      - location (если пусто → var.location)
      - public_ip_names: имена создаваемых/используемых Public IP (из map public_ips)
      - idle_timeout_in_minutes: 4..120
  EOT
  type = map(object({
    location                 = optional(string, "")
    public_ip_names          = optional(list(string), [])
    idle_timeout_in_minutes  = optional(number, 4)
    sku                      = optional(string, "Standard")
    zones                    = optional(list(string), [])
    tags                     = optional(map(string), {})
  }))
  default = {}
  validation {
    condition     = alltrue([for _, n in var.nat_gateways : n.idle_timeout_in_minutes >= 4 && n.idle_timeout_in_minutes <= 120])
    error_message = "idle_timeout_in_minutes для NAT Gateway должен быть 4..120."
  }
}

variable "public_ips" {
  description = <<-EOT
  Карта Public IP:
    key → имя PIP
    value:
      - allocation_method: Static|Dynamic (для Standard обычно Static)
      - sku: Basic|Standard (рекомендуется Standard)
      - version: IPv4|IPv6
      - zones: список зон, если требуется
  EOT
  type = map(object({
    location          = optional(string, "")
    allocation_method = optional(string, "Static")
    sku               = optional(string, "Standard")
    version           = optional(string, "IPv4")
    dns_label         = optional(string, "")
    zones             = optional(list(string), [])
    tags              = optional(map(string), {})
  }))
  default = {}
  validation {
    condition = alltrue([
      for _, p in var.public_ips :
      contains(["Static","Dynamic"], p.allocation_method) &&
      contains(["Basic","Standard"], p.sku) &&
      contains(["IPv4","IPv6"], p.version)
    ])
    error_message = "Public IP: allocation_method ∈ {Static,Dynamic}, sku ∈ {Basic,Standard}, version ∈ {IPv4,IPv6}."
  }
}

############################
# Azure Firewall / Bastion (optional)
############################
variable "enable_firewall" {
  description = "Создавать Azure Firewall."
  type        = bool
  default     = false
}

variable "firewall_config" {
  description = <<-EOT
  Параметры Azure Firewall:
    - name
    - subnet_name (обычно 'AzureFirewallSubnet' / /26)
    - public_ip_name (ключ из public_ips)
    - sku_tier: Standard|Premium
    - dns_servers: список кастомных DNS
  EOT
  type = object({
    name           = optional(string)
    subnet_name    = optional(string, "AzureFirewallSubnet")
    public_ip_name = optional(string, "")
    sku_tier       = optional(string, "Standard")
    dns_servers    = optional(list(string), [])
    tags           = optional(map(string), {})
  })
  default = {}
  validation {
    condition     = var.enable_firewall ? contains(["Standard","Premium"], try(var.firewall_config.sku_tier, "Standard")) : true
    error_message = "Azure Firewall sku_tier должен быть Standard или Premium."
  }
}

variable "enable_bastion" {
  description = "Создавать Azure Bastion Host."
  type        = bool
  default     = false
}

variable "bastion_config" {
  description = <<-EOT
  Параметры Azure Bastion:
    - name
    - subnet_name (обычно 'AzureBastionSubnet' /27)
    - public_ip_name (ключ из public_ips)
    - scale_units (1..50)
  EOT
  type = object({
    name           = optional(string)
    subnet_name    = optional(string, "AzureBastionSubnet")
    public_ip_name = optional(string, "")
    scale_units    = optional(number, 2)
    tags           = optional(map(string), {})
  })
  default = {}
  validation {
    condition     = var.enable_bastion ? (try(var.bastion_config.scale_units, 2) >= 1 && try(var.bastion_config.scale_units, 2) <= 50) : true
    error_message = "Bastion scale_units должен быть 1..50."
  }
}

############################
# DDoS Protection
############################
variable "ddos_protection" {
  description = <<-EOT
  Поддержка DDoS Protection для VNet:
    - enabled: bool
    - plan_id: Resource ID существующего плана (если используется стандартный план)
  EOT
  type = object({
    enabled = bool
    plan_id = optional(string)
  })
  default = {
    enabled = false
  }
}

############################
# VNet Peerings
############################
variable "peerings" {
  description = <<-EOT
  Список пирингов:
    - name
    - remote_vnet_id: ID удалённой VNet
    - allow_forwarded_traffic, allow_gateway_transit, use_remote_gateways
    - allow_virtual_network_access
  EOT
  type = list(object({
    name                         = string
    remote_vnet_id               = string
    allow_forwarded_traffic      = optional(bool, false)
    allow_gateway_transit        = optional(bool, false)
    use_remote_gateways          = optional(bool, false)
    allow_virtual_network_access = optional(bool, true)
    triggers                     = optional(map(string), {}) # для форс-обновлений
  }))
  default = []
}

############################
# Diagnostics & Flow Logs
############################
variable "diagnostics" {
  description = <<-EOT
  Настройки диагностирования:
    - enabled: bool
    - destination_type: "log_analytics"|"storage"|"event_hub"
    - destination_id: Resource ID рабочего пространства/бакета/eh-namespace
    - log_categories: список категорий логов (NetworkSecurityGroupEvent/RuleCounter/VMProtectionAlerts и др.)
    - metric_categories: список метрик (All, или конкретные)
  EOT
  type = object({
    enabled          = bool
    destination_type = optional(string, "log_analytics")
    destination_id   = optional(string)
    log_categories   = optional(list(string), [])
    metric_categories= optional(list(string), [])
  })
  default = {
    enabled = false
  }
  validation {
    condition     = var.diagnostics.enabled ? contains(["log_analytics","storage","event_hub"], try(var.diagnostics.destination_type, "log_analytics")) : true
    error_message = "diagnostics.destination_type ∈ {log_analytics, storage, event_hub}."
  }
}

variable "nsg_flow_logs" {
  description = <<-EOT
  NSG Flow Logs (NPM/Azure Network Watcher):
    - enabled: bool
    - network_watcher_rg: Resource Group с Network Watcher
    - storage_id: Resource ID Storage Account для логов
    - retention_days: срок хранения (0..3650)
    - traffic_analytics: объект:
        enabled: bool
        workspace_id / workspace_region / workspace_resource_id
  EOT
  type = object({
    enabled             = bool
    network_watcher_rg  = optional(string)
    storage_id          = optional(string)
    retention_days      = optional(number, 90)
    traffic_analytics   = optional(object({
      enabled               = bool
      workspace_id          = optional(string)
      workspace_region      = optional(string)
      workspace_resource_id = optional(string)
    }), null)
  })
  default = {
    enabled = false
  }
  validation {
    condition     = var.nsg_flow_logs.enabled ? (try(var.nsg_flow_logs.retention_days, 90) >= 0 && try(var.nsg_flow_logs.retention_days, 90) <= 3650) : true
    error_message = "nsg_flow_logs.retention_days должен быть в диапазоне 0..3650."
  }
}

############################
# Policy / Locks
############################
variable "enable_resource_locks" {
  description = "Создавать CanNotDelete locks на критичных ресурсах (VNet, RT, NSG и т.п.)."
  type        = bool
  default     = false
}

variable "policy_compliance" {
  description = <<-EOT
  Флаги строгого соответствия политике:
    - deny_public_ip_on_subnet: запрещать публичные IP в сабнете
    - enforce_private_endpoint_policies: принудительно отключать network policies для PE
  EOT
  type = object({
    deny_public_ip_on_subnet        = optional(bool, false)
    enforce_private_endpoint_policies = optional(bool, true)
  })
  default = {}
}

############################
# DNS (optional)
############################
variable "custom_dns_servers" {
  description = "Список кастомных DNS серверов для VNet. Пусто — системные."
  type        = list(string)
  default     = []
}

variable "private_dns_links" {
  description = <<-EOT
  Привязки Private DNS zones к VNet:
    - zone_id: Resource ID private DNS зоны
    - registration_enabled: bool
  EOT
  type = list(object({
    zone_id              = string
    registration_enabled = optional(bool, false)
  }))
  default = []
}

############################
# Tags / Naming / Features
############################
variable "tags" {
  description = "Теги по умолчанию для всех поддерживаемых ресурсов."
  type        = map(string)
  default     = {}
}

variable "naming" {
  description = <<-EOT
  Шаблоны нейминга:
    - vnet_tpl
    - nsg_tpl
    - rt_tbl_tpl
    - nat_tpl
    - pip_tpl
    - firewall_tpl
    - bastion_tpl
  Подстановки: {name_prefix}, {environment}
  EOT
  type = object({
    vnet_tpl      : string
    nsg_tpl       : string
    rt_tbl_tpl    : string
    nat_tpl       : string
    pip_tpl       : string
    firewall_tpl  : string
    bastion_tpl   : string
  })
  default = {
    vnet_tpl     = "{name_prefix}-{environment}-vnet"
    nsg_tpl      = "{name_prefix}-{environment}-nsg-{key}"
    rt_tbl_tpl   = "{name_prefix}-{environment}-rt-{key}"
    nat_tpl      = "{name_prefix}-{environment}-nat-{key}"
    pip_tpl      = "{name_prefix}-{environment}-pip-{key}"
    firewall_tpl = "{name_prefix}-{environment}-afw"
    bastion_tpl  = "{name_prefix}-{environment}-bastion"
  }
}

variable "feature_flags" {
  description = <<-EOT
  Фич-флаги поведения модуля:
    - create_missing_bindings: создавать отсутствующие NSG/UDR/PIP/NAT из карт
    - strict_validations: включить дополнительные проверки согласованности
  EOT
  type = object({
    create_missing_bindings = optional(bool, true)
    strict_validations      = optional(bool, true)
  })
  default = {}
}

############################
# Defensive meta validations
############################
variable "min_subnet_prefix" {
  description = "Минимально допустимый размер префикса для IPv4 сабнета (например, /28 => 28)."
  type        = number
  default     = 28
  validation {
    condition     = var.min_subnet_prefix >= 16 && var.min_subnet_prefix <= 30
    error_message = "min_subnet_prefix должен быть 16..30."
  }
}

variable "allow_ipv6" {
  description = "Разрешить IPv6-адресацию для VNet/сабнетов."
  type        = bool
  default     = false
}

############################
# Internal consistency guard (computed in locals in main.tf usually)
############################
variable "reserved_subnet_names" {
  description = "Зарезервированные имена сабнетов (например, AzureFirewallSubnet, AzureBastionSubnet)."
  type        = list(string)
  default     = ["AzureFirewallSubnet", "AzureBastionSubnet"]
}
