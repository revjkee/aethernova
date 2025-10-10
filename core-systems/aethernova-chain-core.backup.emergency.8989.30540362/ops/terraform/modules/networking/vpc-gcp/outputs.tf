##############################
# networking/vpc-gcp/outputs.tf
##############################

# NOTE:
# Ожидается, что в модуле определены ресурсы:
#   - google_compute_network.vpc
#   - google_compute_subnetwork.subnets   (for_each по карте подсетей)
# Если используются иные имена, скорректируйте ссылки в outputs.

################################
# VPC: агрегированный объект
################################
output "vpc_network" {
  description = "Сводная информация о VPC."
  value = {
    id                        = google_compute_network.vpc.id
    self_link                 = google_compute_network.vpc.self_link
    name                      = google_compute_network.vpc.name
    auto_create_subnetworks   = google_compute_network.vpc.auto_create_subnetworks
    mtu                       = google_compute_network.vpc.mtu
    routing_mode              = google_compute_network.vpc.routing_mode
  }

  sensitive = false
}

################################
# VPC: атомарные удобные выводы
################################
output "vpc_network_id" {
  description = "Идентификатор VPC (Compute Engine)."
  value       = google_compute_network.vpc.id
}

output "vpc_network_self_link" {
  description = "Полный self_link VPC."
  value       = google_compute_network.vpc.self_link
}

output "vpc_network_name" {
  description = "Имя VPC."
  value       = google_compute_network.vpc.name
}

output "vpc_routing_mode" {
  description = "Режим маршрутизации VPC."
  value       = google_compute_network.vpc.routing_mode
}

output "vpc_mtu" {
  description = "MTU для VPC (байты)."
  value       = google_compute_network.vpc.mtu
}

################################
# Subnets: подробная карта по имени
################################
# Карта: имя_подсети => объект свойств
output "subnets_by_name" {
  description = "Подробная информация по каждой подсети, индекс — имя подсети."
  value = {
    for name, s in google_compute_subnetwork.subnets :
    name => {
      id                         = s.id
      self_link                  = s.self_link
      name                       = s.name
      region                     = s.region
      network                    = s.network
      ip_cidr_range              = s.ip_cidr_range
      gateway_address            = try(s.gateway_address, null)
      private_ip_google_access   = try(s.private_ip_google_access, null)

      # VPC Flow Logs (если включены)
      flow_logs = try({
        enabled               = true
        aggregation_interval  = try(s.log_config[0].aggregation_interval, null)
        flow_sampling         = try(s.log_config[0].flow_sampling, null)
        metadata              = try(s.log_config[0].metadata, null)
        metadata_fields       = try(s.log_config[0].metadata_fields, null)
        filter_expr           = try(s.log_config[0].filter_expr, null)
      }, null)

      # IPv6/стек и целевое назначение подсети (если заданы)
      stack_type               = try(s.stack_type, null)
      ipv6_access_type         = try(s.ipv6_access_type, null)
      purpose                  = try(s.purpose, null)
      role                     = try(s.role, null)

      # Вторичные диапазоны как карта: имя_диапазона => CIDR
      secondary_ip_ranges = try({
        for r in s.secondary_ip_range : r.range_name => r.ip_cidr_range
      }, {})
    }
  }

  sensitive = false
}

################################
# Subnets: удобные представления
################################

# Список self_link всех подсетей
output "subnet_self_links" {
  description = "Список self_link для всех подсетей."
  value       = [for s in values(google_compute_subnetwork.subnets) : s.self_link]
}

# Карта: имя_подсети => CIDR
output "subnet_cidrs_by_name" {
  description = "Основные CIDR всех подсетей, индекс — имя подсети."
  value       = { for name, s in google_compute_subnetwork.subnets : name => s.ip_cidr_range }
}

# Карта: имя_подсети => адрес шлюза
output "subnet_gateway_by_name" {
  description = "Адрес шлюза подсети, индекс — имя подсети."
  value       = { for name, s in google_compute_subnetwork.subnets : name => try(s.gateway_address, null) }
}

# Карта: имя_подсети => карта вторичных диапазонов
output "subnet_secondary_ranges_by_name" {
  description = "Вторичные диапазоны, сгруппированные по подсетям: имя_подсети => { имя_диапазона => CIDR }."
  value = {
    for name, s in google_compute_subnetwork.subnets :
    name => try({ for r in s.secondary_ip_range : r.range_name => r.ip_cidr_range }, {})
  }
}

# Карта: имя_подсети => включен ли Private Google Access
output "subnet_private_google_access_by_name" {
  description = "Признак включения Private Google Access для каждой подсети."
  value       = { for name, s in google_compute_subnetwork.subnets : name => try(s.private_ip_google_access, null) }
}

# Карта: имя_подсети => режимы IPv6/стека (если применимо)
output "subnet_ip_stack_flags_by_name" {
  description = "Параметры IPv6/стека по подсетям."
  value = {
    for name, s in google_compute_subnetwork.subnets :
    name => {
      stack_type       = try(s.stack_type, null)
      ipv6_access_type = try(s.ipv6_access_type, null)
    }
  }
}
