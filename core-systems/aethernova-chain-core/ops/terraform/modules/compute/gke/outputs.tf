// path: aethernova-chain-core/ops/terraform/modules/compute/gke/outputs.tf
// SPDX-License-Identifier: Apache-2.0

############################################
# Cluster identity & control-plane details #
############################################

output "cluster_name" {
  description = "Имя кластера GKE."
  value       = google_container_cluster.this.name
}

output "cluster_location" {
  description = "Локация кластера (region/zone)."
  value       = google_container_cluster.this.location
}

output "cluster_id" {
  description = "Полный идентификатор ресурса кластера (projects/.../locations/.../clusters/...)."
  value       = google_container_cluster.this.id
}

output "endpoint" {
  description = "API endpoint control-plane (без схемы https://)."
  value       = google_container_cluster.this.endpoint
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "Base64-encoded CA сертификат control-plane."
  # master_auth[0].cluster_ca_certificate — атрибут ресурса google_container_cluster
  value     = google_container_cluster.this.master_auth[0].cluster_ca_certificate
  sensitive = true
}

output "cluster_ca_certificate_pem" {
  description = "CA сертификат в PEM (base64decode)."
  value       = base64decode(google_container_cluster.this.master_auth[0].cluster_ca_certificate)
  sensitive   = true
}

##############################
# Usability: kubeconfig blob #
##############################

output "kubeconfig_yaml" {
  description = "Готовый kubeconfig для kubectl/kubelogin (использует GCP auth-provider)."
  value = yamlencode({
    apiVersion = "v1"
    clusters = [{
      name    = google_container_cluster.this.name
      cluster = {
        "certificate-authority-data" = google_container_cluster.this.master_auth[0].cluster_ca_certificate
        server                       = "https://${google_container_cluster.this.endpoint}"
      }
    }]
    contexts = [{
      name    = google_container_cluster.this.name
      context = {
        cluster = google_container_cluster.this.name
        user    = google_container_cluster.this.name
      }
    }]
    "current-context" = google_container_cluster.this.name
    users = [{
      name = google_container_cluster.this.name
      user = {
        # Провайдер аутентификации kubectl для GKE
        "auth-provider" = {
          name = "gcp"
        }
      }
    }]
  })
  sensitive = true
}

#########################
# Release / Workload ID #
#########################

output "release_channel" {
  description = "Канал выпуска GKE (RAPID/REGULAR/STABLE), если включён."
  value       = try(google_container_cluster.this.release_channel[0].channel, null)
}

output "workload_identity_pool" {
  description = "Пул Workload Identity (формат: PROJECT_ID.svc.id.goog), если включён."
  value       = try(google_container_cluster.this.workload_identity_config[0].workload_pool, null)
}

############################
# Network / IP allocations #
############################

output "network" {
  description = "Имя VPC сети, к которой подключён кластер."
  value       = google_container_cluster.this.network
}

output "subnetwork" {
  description = "Имя подсети для узлов кластера."
  value       = google_container_cluster.this.subnetwork
}

output "cluster_secondary_range_name" {
  description = "Имя secondary-диапазона подсети для Pod CIDR (если используется VPC-Native)."
  value       = try(google_container_cluster.this.ip_allocation_policy[0].cluster_secondary_range_name, null)
}

output "services_secondary_range_name" {
  description = "Имя secondary-диапазона подсети для Service CIDR (если используется VPC-Native)."
  value       = try(google_container_cluster.this.ip_allocation_policy[0].services_secondary_range_name, null)
}

output "cluster_ipv4_cidr" {
  description = "Pod CIDR (если возвращается провайдером)."
  value       = try(google_container_cluster.this.cluster_ipv4_cidr, null)
}

output "services_ipv4_cidr" {
  description = "Service CIDR (если возвращается провайдером)."
  value       = try(google_container_cluster.this.services_ipv4_cidr, null)
}

output "private_control_plane_cidr" {
  description = "Диапазон для private control-plane endpoint (для private_cluster_config), если задан."
  value       = try(google_container_cluster.this.private_cluster_config[0].master_ipv4_cidr_block, null)
}

###########################################
# Logging / Monitoring service selections #
###########################################

output "logging_service" {
  description = "Сервис логирования control-plane (например, logging.googleapis.com/kubernetes)."
  value       = try(google_container_cluster.this.logging_service, null)
}

output "monitoring_service" {
  description = "Сервис мониторинга control-plane (например, monitoring.googleapis.com/kubernetes)."
  value       = try(google_container_cluster.this.monitoring_service, null)
}

############################
# Resource labels (cluster)#
############################

output "resource_labels" {
  description = "Ресурсные метки (labels) кластера."
  value       = try(google_container_cluster.this.resource_labels, {})
}

#############################
# Node pools summarized map #
#############################

# Ожидается, что нод-пулы создаются как:
# resource "google_container_node_pool" "node_pools" { for_each = var.node_pools ... }
output "node_pools" {
  description = "Сводная информация по нод-пулам: версии, размеры, MIG URL’ы, теги и service account."
  value = {
    for k, np in google_container_node_pool.node_pools :
    k => {
      name                         = np.name
      version                      = try(np.version, null)
      node_count                   = try(np.node_count, null)
      min_count                    = try(np.autoscaling[0].min_node_count, null)
      max_count                    = try(np.autoscaling[0].max_node_count, null)
      instance_group_urls          = try(np.instance_group_urls, null)
      managed_instance_group_urls  = try(np.managed_instance_group_urls, null)
      service_account              = try(np.node_config[0].service_account, null)
      tags                         = try(np.node_config[0].tags, [])
      preemptible                  = try(np.node_config[0].preemptible, null)
      spot                         = try(np.node_config[0].spot, null)
      disk_type                    = try(np.node_config[0].disk_type, null)
      disk_size_gb                 = try(np.node_config[0].disk_size_gb, null)
      machine_type                 = try(np.node_config[0].machine_type, null)
    }
  }
}

########################################
# Convenience: minimal provider inputs #
########################################

output "kubectl_host" {
  description = "Полный URL API сервера для провайдера kubernetes.host."
  value       = "https://${google_container_cluster.this.endpoint}"
  sensitive   = true
}

output "kubectl_cluster_ca_cert_pem" {
  description = "Удобный PEM CA для провайдера kubernetes.cluster_ca_certificate."
  value       = base64decode(google_container_cluster.this.master_auth[0].cluster_ca_certificate)
  sensitive   = true
}
