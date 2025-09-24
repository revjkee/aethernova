/**
 * Module: compute/aks
 * File: outputs.tf
 * Purpose: Expose a stable, production-grade AKS output surface for downstream
 *          modules/pipelines (CI/CD, IAM, networking, policy).
 *
 * Notes:
 * - Assumes primary cluster resource: azurerm_kubernetes_cluster.this
 * - Assumes optional node pools: azurerm_kubernetes_cluster_node_pool.this (for_each)
 * - Uses try(...) to keep outputs resilient to optional features/provider drift
 */

################################
# Core cluster identification  #
################################

output "cluster" {
  description = "Основные атрибуты AKS-кластера."
  value = {
    id                     = azurerm_kubernetes_cluster.this.id
    name                   = azurerm_kubernetes_cluster.this.name
    resource_group_name    = azurerm_kubernetes_cluster.this.resource_group_name
    location               = azurerm_kubernetes_cluster.this.location
    kubernetes_version     = azurerm_kubernetes_cluster.this.kubernetes_version
    dns_prefix             = try(azurerm_kubernetes_cluster.this.dns_prefix, null)
    fqdn                   = try(azurerm_kubernetes_cluster.this.fqdn, null)
    private_fqdn           = try(azurerm_kubernetes_cluster.this.private_fqdn, null)
    node_resource_group    = try(azurerm_kubernetes_cluster.this.node_resource_group, null)
    private_cluster_enabled = try(azurerm_kubernetes_cluster.this.private_cluster_enabled, null)
    api_server_authorized_ip_ranges = try(azurerm_kubernetes_cluster.this.api_server_authorized_ip_ranges, null)
    oidc_issuer_url        = try(azurerm_kubernetes_cluster.this.oidc_issuer_url, null)
    tags                   = try(azurerm_kubernetes_cluster.this.tags, {})
  }
}

#########################
# Network profile block #
#########################

output "network_profile" {
  description = "Параметры сетевого профиля AKS."
  value = {
    network_plugin        = try(azurerm_kubernetes_cluster.this.network_profile[0].network_plugin, null)
    network_policy        = try(azurerm_kubernetes_cluster.this.network_profile[0].network_policy, null)
    service_cidr          = try(azurerm_kubernetes_cluster.this.network_profile[0].service_cidr, null)
    service_cidrs         = try(azurerm_kubernetes_cluster.this.network_profile[0].service_cidrs, null)
    dns_service_ip        = try(azurerm_kubernetes_cluster.this.network_profile[0].dns_service_ip, null)
    docker_bridge_cidr    = try(azurerm_kubernetes_cluster.this.network_profile[0].docker_bridge_cidr, null)
    pod_cidr              = try(azurerm_kubernetes_cluster.this.network_profile[0].pod_cidr, null)
    pod_cidrs             = try(azurerm_kubernetes_cluster.this.network_profile[0].pod_cidrs, null)
    load_balancer_sku     = try(azurerm_kubernetes_cluster.this.network_profile[0].load_balancer_sku, null)
    outbound_type         = try(azurerm_kubernetes_cluster.this.network_profile[0].outbound_type, null)
    effective_outbound_ips = try(azurerm_kubernetes_cluster.this.network_profile[0].load_balancer_profile[0].effective_outbound_ips, null)
    managed_outbound_ip_count = try(azurerm_kubernetes_cluster.this.network_profile[0].load_balancer_profile[0].managed_outbound_ip_count, null)
    idle_timeout_in_minutes   = try(azurerm_kubernetes_cluster.this.network_profile[0].load_balancer_profile[0].idle_timeout_in_minutes, null)
  }
}

#########################
# Identity information  #
#########################

output "identity" {
  description = "Идентичность кластера (System/User Assigned)."
  value = {
    type                       = try(azurerm_kubernetes_cluster.this.identity[0].type, null)
    principal_id               = try(azurerm_kubernetes_cluster.this.identity[0].principal_id, null)
    tenant_id                  = try(azurerm_kubernetes_cluster.this.identity[0].tenant_id, null)
    user_assigned_identity_ids = try(azurerm_kubernetes_cluster.this.identity[0].identity_ids, [])
  }
}

output "kubelet_identity" {
  description = "Идентичность kubelet (используется для ACR и др.)."
  value = {
    client_id                 = try(azurerm_kubernetes_cluster.this.kubelet_identity[0].client_id, null)
    object_id                 = try(azurerm_kubernetes_cluster.this.kubelet_identity[0].object_id, null)
    user_assigned_identity_id = try(azurerm_kubernetes_cluster.this.kubelet_identity[0].user_assigned_identity_id, null)
  }
}

#########################
# Kubeconfig (sensitive)#
#########################

output "kube_config_raw" {
  description = "Пользовательский kubeconfig (base64/PEM, содержит креды)."
  value       = try(azurerm_kubernetes_cluster.this.kube_config_raw, null)
  sensitive   = true
}

output "kube_admin_config_raw" {
  description = "Админский kubeconfig (если включен провайдером/настройками)."
  value       = try(azurerm_kubernetes_cluster.this.kube_admin_config_raw, null)
  sensitive   = true
}

#################################
# Default node pool information #
#################################

output "default_node_pool" {
  description = "Характеристики default node pool."
  value = {
    name                  = try(azurerm_kubernetes_cluster.this.default_node_pool[0].name, null)
    vm_size               = try(azurerm_kubernetes_cluster.this.default_node_pool[0].vm_size, null)
    node_count            = try(azurerm_kubernetes_cluster.this.default_node_pool[0].node_count, null)
    min_count             = try(azurerm_kubernetes_cluster.this.default_node_pool[0].min_count, null)
    max_count             = try(azurerm_kubernetes_cluster.this.default_node_pool[0].max_count, null)
    enable_auto_scaling   = try(azurerm_kubernetes_cluster.this.default_node_pool[0].enable_auto_scaling, null)
    max_pods              = try(azurerm_kubernetes_cluster.this.default_node_pool[0].max_pods, null)
    os_disk_size_gb       = try(azurerm_kubernetes_cluster.this.default_node_pool[0].os_disk_size_gb, null)
    vnet_subnet_id        = try(azurerm_kubernetes_cluster.this.default_node_pool[0].vnet_subnet_id, null)
    orchestrator_version  = try(azurerm_kubernetes_cluster.this.default_node_pool[0].orchestrator_version, null)
    availability_zones    = try(azurerm_kubernetes_cluster.this.default_node_pool[0].zones, null)
    node_labels           = try(azurerm_kubernetes_cluster.this.default_node_pool[0].node_labels, null)
    node_taints           = try(azurerm_kubernetes_cluster.this.default_node_pool[0].node_taints, null)
    tags                  = try(azurerm_kubernetes_cluster.this.default_node_pool[0].tags, null)
    kubelet_config        = try(azurerm_kubernetes_cluster.this.default_node_pool[0].kubelet_config[0], null)
    linux_os_config       = try(azurerm_kubernetes_cluster.this.default_node_pool[0].linux_os_config[0], null)
  }
}

#####################################
# Additional managed node pools map #
#####################################

output "node_pools" {
  description = "Карта дополнительных пулов узлов (если объявлены)."
  value = {
    for k, np in azurerm_kubernetes_cluster_node_pool.this :
    k => {
      id                   = np.id
      name                 = np.name
      mode                 = try(np.mode, null)
      vm_size              = try(np.vm_size, null)
      node_count           = try(np.node_count, null)
      min_count            = try(np.min_count, null)
      max_count            = try(np.max_count, null)
      enable_auto_scaling  = try(np.enable_auto_scaling, null)
      max_pods             = try(np.max_pods, null)
      os_disk_size_gb      = try(np.os_disk_size_gb, null)
      vnet_subnet_id       = try(np.vnet_subnet_id, null)
      orchestrator_version = try(np.orchestrator_version, null)
      availability_zones   = try(np.zones, null)
      node_labels          = try(np.node_labels, null)
      node_taints          = try(np.node_taints, null)
      tags                 = try(np.tags, null)
      kubelet_config       = try(np.kubelet_config[0], null)
      linux_os_config      = try(np.linux_os_config[0], null)
    }
  }
}

#########################
# Add-ons core signals  #
#########################

output "addons" {
  description = "Состояние основных аддонов (если включены в конфигурации кластера)."
  value = {
    azure_policy_enabled = try(azurerm_kubernetes_cluster.this.azure_policy_enabled, null)

    oms_agent = {
      enabled                     = try(azurerm_kubernetes_cluster.this.oms_agent[0].enabled, null)
      log_analytics_workspace_id  = try(azurerm_kubernetes_cluster.this.oms_agent[0].log_analytics_workspace_id, null)
    }

    open_service_mesh_enabled = try(azurerm_kubernetes_cluster.this.open_service_mesh_enabled, null)

    key_vault_secrets_provider = {
      enabled          = try(azurerm_kubernetes_cluster.this.key_vault_secrets_provider[0].secret_rotation_enabled, null)
      secret_rotation  = try(azurerm_kubernetes_cluster.this.key_vault_secrets_provider[0].secret_rotation_enabled, null)
      rotation_interval= try(azurerm_kubernetes_cluster.this.key_vault_secrets_provider[0].rotation_poll_interval, null)
      secret_identity  = {
        client_id = try(azurerm_kubernetes_cluster.this.key_vault_secrets_provider[0].secret_identity[0].client_id, null)
        object_id = try(azurerm_kubernetes_cluster.this.key_vault_secrets_provider[0].secret_identity[0].object_id, null)
      }
    }

    ingress_application_gateway = {
      gateway_id = try(azurerm_kubernetes_cluster.this.ingress_application_gateway[0].gateway_id, null)
      subnet_id  = try(azurerm_kubernetes_cluster.this.ingress_application_gateway[0].subnet_id, null)
    }
  }
}

#########################
# Diagnostics (optional)#
#########################

output "diagnostic_settings_ids" {
  description = "ID diagnostic settings, если модуль их создаёт рядом с кластером."
  value       = try([for ds in azurerm_monitor_diagnostic_setting.aks : ds.id], [])
}

#########################
# Convenience outputs   #
#########################

output "resource_ids" {
  description = "Полезные ID для привязок (RBAC/Policy/KeyVault/ACR)."
  value = {
    cluster_id             = azurerm_kubernetes_cluster.this.id
    principal_id           = try(azurerm_kubernetes_cluster.this.identity[0].principal_id, null)
    kubelet_object_id      = try(azurerm_kubernetes_cluster.this.kubelet_identity[0].object_id, null)
    kubelet_client_id      = try(azurerm_kubernetes_cluster.this.kubelet_identity[0].client_id, null)
    node_resource_group_id = try(format("/subscriptions/%s/resourceGroups/%s",
                                 data.azurerm_client_config.current.subscription_id,
                                 azurerm_kubernetes_cluster.this.node_resource_group), null)
  }
}

# Примечание:
# - data.azurerm_client_config.current должен существовать в модуле для корректной сборки node_resource_group_id.
#   Если его нет, удалите поле node_resource_group_id либо объявите соответствующий data-source в модуле.
