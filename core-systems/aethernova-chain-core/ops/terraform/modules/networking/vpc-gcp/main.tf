terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      # Фиксация мин. версии провайдера (совместимо с 5.x/6.x/7.x ветками).
      version = ">= 5.0"
    }
  }
}

############################
# ВХОДНЫЕ ДАННЫЕ МОДУЛЯ
############################

variable "project_id" {
  description = "ID проекта GCP. Может также задаваться на провайдере."
  type        = string
}

variable "network_name" {
  description = "Имя создаваемой VPC сети."
  type        = string
}

variable "routing_mode" {
  description = "Режим динамической маршрутизации VPC: GLOBAL или REGIONAL."
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = contains(["GLOBAL", "REGIONAL"], var.routing_mode)
    error_message = "routing_mode должен быть GLOBAL или REGIONAL."
  }
}

variable "mtu" {
  description = "MTU для VPC. 0 — значение по умолчанию GCP (1460). Допустимо 1300..8896 согласно документации GCP."
  type        = number
  default     = 0
  validation {
    condition     = var.mtu == 0 || (var.mtu >= 1300 && var.mtu <= 8896)
    error_message = "mtu должен быть 0 или в диапазоне 1300..8896."
  }
}

variable "delete_default_routes_on_create" {
  description = "Удалять ли дефолтные маршруты при создании сети."
  type        = bool
  default     = false
}

# Описание подсетей. Используются optional-атрибуты (Terraform 1.3+).
variable "subnets" {
  description = <<EOT
Список подсетей. secondary_ip_ranges поддерживает alias IP/GKE.
flow_logs управляет VPC Flow Logs (рекомендуется включать).
EOT
  type = list(object({
    name                     = string
    region                   = string
    ip_cidr_range            = string
    private_ip_google_access = optional(bool, true)

    secondary_ip_ranges = optional(list(object({
      range_name    = string
      ip_cidr_range = string
    })), [])

    flow_logs = optional(object({
      enable                = optional(bool, true)
      aggregation_interval  = optional(string, "INTERVAL_5_SEC") # см. registry по subnetwork
      flow_sampling         = optional(number, 0.5)
      metadata              = optional(string, "INCLUDE_ALL_METADATA")
      metadata_fields       = optional(list(string), [])
      filter_expr           = optional(string, null)
    }), {})
  }))
  default = []
}

# Унифицированное описание firewall-правил.
variable "firewall_rules" {
  description = "Список firewall-правил уровня сети."
  type = list(object({
    name        = string
    description = optional(string, null)
    direction   = string                              # INGRESS или EGRESS
    priority    = optional(number, 1000)
    ranges      = optional(list(string), [])          # source_ranges для INGRESS, destination_ranges для EGRESS

    target_tags             = optional(list(string), [])
    target_service_accounts = optional(list(string), [])
    source_tags             = optional(list(string), [])
    source_service_accounts = optional(list(string), [])

    allow = optional(list(object({
      protocol = string
      ports    = optional(list(string), [])
    })), [])

    deny = optional(list(object({
      protocol = string
      ports    = optional(list(string), [])
    })), [])

    disabled = optional(bool, false)

    log_config = optional(object({
      metadata = optional(string, "INCLUDE_ALL_METADATA") # INCLUDE_ALL_METADATA | EXCLUDE_ALL_METADATA
    }), {})
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.firewall_rules : contains(["INGRESS", "EGRESS"], r.direction)])
    error_message = "Каждое firewall правило должно иметь direction INGRESS или EGRESS."
  }
}

# Кастомные маршруты (если нужно, включая явное воссоздание default route).
variable "routes" {
  description = "Список статических маршрутов."
  type = list(object({
    name        = string
    description = optional(string, null)
    dest_range  = string
    priority    = optional(number, 1000)
    tags        = optional(list(string), [])

    # Ровно один next-hop должен быть задан через тип/значение:
    next_hop = object({
      # gateway | ip | instance | ilb | vpn_tunnel
      type  = string
      value = string
    })
  }))
  default = []
}

# NAT: включение Cloud Router/NAT по всем затронутым регионам
variable "nat" {
  description = "Параметры Cloud NAT (при enabled=true создается по одному NAT на регион из subnets)."
  type = object({
    enabled               = bool
    name_prefix           = optional(string, "nat")
    router_name_prefix    = optional(string, "cr")
    nat_ip_allocate_option = optional(string, "AUTO_ONLY") # AUTO_ONLY | MANUAL_ONLY

    min_ports_per_vm                     = optional(number, 64)
    udp_idle_timeout_sec                 = optional(number, 30)
    tcp_established_idle_timeout_sec     = optional(number, 1200)
    tcp_transitory_idle_timeout_sec      = optional(number, 30)
    enable_endpoint_independent_mapping  = optional(bool, true)

    log_config = optional(object({
      enable = optional(bool, true)
      # ALL | ERRORS_ONLY | TRANSLATIONS_ONLY
      filter = optional(string, "ALL")
    }), {})
  })
  default = {
    enabled = false
  }
}

############################
# ЛОКАЛЬНЫЕ ПЕРЕМЕННЫЕ
############################

locals {
  # Множество регионов, где есть подсети
  regions = distinct([for s in var.subnets : s.region])

  subnets_map = {
    for s in var.subnets :
    "${s.region}/${s.name}" => s
  }

  firewall_map = {
    for r in var.firewall_rules :
    r.name => r
  }

  routes_map = {
    for rt in var.routes :
    rt.name => rt
  }
}

############################
# РЕСУРСЫ СЕТИ
############################

resource "google_compute_network" "vpc" {
  project                         = var.project_id
  name                            = var.network_name
  auto_create_subnetworks         = false
  routing_mode                    = var.routing_mode
  mtu                             = var.mtu
  delete_default_routes_on_create = var.delete_default_routes_on_create
}

# Подсети с secondary ranges, Private Google Access и VPC Flow Logs
resource "google_compute_subnetwork" "subnet" {
  for_each      = local.subnets_map
  project       = var.project_id
  name          = each.value.name
  region        = each.value.region
  ip_cidr_range = each.value.ip_cidr_range
  network       = google_compute_network.vpc.self_link

  private_ip_google_access = try(each.value.private_ip_google_access, true)

  dynamic "secondary_ip_range" {
    for_each = try(each.value.secondary_ip_ranges, [])
    content {
      range_name    = secondary_ip_range.value.range_name
      ip_cidr_range = secondary_ip_range.value.ip_cidr_range
    }
  }

  # VPC Flow Logs через log_config (современно и совместимо с провайдером 5/6/7)
  dynamic "log_config" {
    for_each = try(each.value.flow_logs.enable, true) ? [1] : []
    content {
      aggregation_interval = try(each.value.flow_logs.aggregation_interval, "INTERVAL_5_SEC")
      flow_sampling        = try(each.value.flow_logs.flow_sampling, 0.5)
      metadata             = try(each.value.flow_logs.metadata, "INCLUDE_ALL_METADATA")
      metadata_fields      = try(each.value.flow_logs.metadata_fields, [])
      filter_expr          = try(each.value.flow_logs.filter_expr, null)
    }
  }
}

############################
# FIREWALL ПРАВИЛА
############################

resource "google_compute_firewall" "rules" {
  for_each = local.firewall_map

  project     = var.project_id
  name        = each.value.name
  description = try(each.value.description, null)
  network     = google_compute_network.vpc.self_link
  direction   = each.value.direction
  priority    = try(each.value.priority, 1000)
  disabled    = try(each.value.disabled, false)

  target_tags             = length(try(each.value.target_tags, [])) > 0 ? each.value.target_tags : null
  target_service_accounts = length(try(each.value.target_service_accounts, [])) > 0 ? each.value.target_service_accounts : null

  # Источники/назначения в зависимости от направления
  source_ranges             = each.value.direction == "INGRESS"    ? (length(try(each.value.ranges, [])) > 0 ? each.value.ranges : null) : null
  destination_ranges        = each.value.direction == "EGRESS"     ? (length(try(each.value.ranges, [])) > 0 ? each.value.ranges : null) : null
  source_tags               = each.value.direction == "INGRESS"    ? (length(try(each.value.source_tags, [])) > 0 ? each.value.source_tags : null) : null
  source_service_accounts   = each.value.direction == "INGRESS"    ? (length(try(each.value.source_service_accounts, [])) > 0 ? each.value.source_service_accounts : null) : null

  dynamic "allow" {
    for_each = try(each.value.allow, [])
    content {
      protocol = allow.value.protocol
      ports    = length(try(allow.value.ports, [])) > 0 ? allow.value.ports : null
    }
  }

  dynamic "deny" {
    for_each = try(each.value.deny, [])
    content {
      protocol = deny.value.protocol
      ports    = length(try(deny.value.ports, [])) > 0 ? deny.value.ports : null
    }
  }

  dynamic "log_config" {
    for_each = [1] # включаем логирование правил firewall; поведение управляется metadata.
    content {
      metadata = try(each.value.log_config.metadata, "INCLUDE_ALL_METADATA")
    }
  }
}

############################
# СТАТИЧЕСКИЕ МАРШРУТЫ
############################

resource "google_compute_route" "routes" {
  for_each = local.routes_map

  project     = var.project_id
  name        = each.value.name
  description = try(each.value.description, null)
  network     = google_compute_network.vpc.self_link
  dest_range  = each.value.dest_range
  priority    = try(each.value.priority, 1000)
  tags        = length(try(each.value.tags, [])) > 0 ? each.value.tags : null

  # Ровно один из next_hop_* должен быть установлен
  next_hop_gateway     = try(each.value.next_hop.type, "") == "gateway"    ? each.value.next_hop.value : null
  next_hop_ip          = try(each.value.next_hop.type, "") == "ip"         ? each.value.next_hop.value : null
  next_hop_instance    = try(each.value.next_hop.type, "") == "instance"   ? each.value.next_hop.value : null
  next_hop_ilb         = try(each.value.next_hop.type, "") == "ilb"        ? each.value.next_hop.value : null
  next_hop_vpn_tunnel  = try(each.value.next_hop.type, "") == "vpn_tunnel" ? each.value.next_hop.value : null
}

############################
# CLOUT ROUTER + CLOUD NAT (ОПЦИОНАЛЬНО)
############################

resource "google_compute_router" "cr" {
  for_each = var.nat.enabled ? toset(local.regions) : toset([])

  project = var.project_id
  name    = "${try(var.nat.router_name_prefix, "cr")}-${each.value}"
  region  = each.value
  network = google_compute_network.vpc.self_link
}

resource "google_compute_router_nat" "nat" {
  for_each = var.nat.enabled ? toset(local.regions) : toset([])

  project = var.project_id
  name    = "${try(var.nat.name_prefix, "nat")}-${each.value}"
  region  = each.value
  router  = google_compute_router.cr[each.value].name

  nat_ip_allocate_option = try(var.nat.nat_ip_allocate_option, "AUTO_ONLY")
  # Применяем NAT ко всем подсетям региона и всем их IP-диапазонам
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  min_ports_per_vm                    = try(var.nat.min_ports_per_vm, 64)
  enable_endpoint_independent_mapping = try(var.nat.enable_endpoint_independent_mapping, true)

  udp_idle_timeout_sec             = try(var.nat.udp_idle_timeout_sec, 30)
  tcp_established_idle_timeout_sec = try(var.nat.tcp_established_idle_timeout_sec, 1200)
  tcp_transitory_idle_timeout_sec  = try(var.nat.tcp_transitory_idle_timeout_sec, 30)

  log_config {
    enable = try(var.nat.log_config.enable, true)
    filter = try(var.nat.log_config.filter, "ALL")
  }
}
