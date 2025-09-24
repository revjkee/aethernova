/**
 * Aethernova — Compute/GKE
 * File: ops/terraform/modules/compute/gke/main.tf
 *
 * Назначение:
 *   Универсальный модуль GKE с поддержкой Autopilot и Standard.
 *   Включает Private Cluster, IP Alias, Workload Identity, Binary Authorization,
 *   CMEK, Shielded Nodes, MAN (Master Authorized Networks), Release Channels,
 *   и полноценную конфигурацию Node Pool'ов для Standard.
 *
 * Примечания:
 *   - Переменные, используемые в этом файле, определяются в variables.tf.
 *   - Выходные значения — в outputs.tf.
 *   - Версии провайдеров — в versions.tf (рекомендуется).
 */

#####################################################
# Locals
#####################################################
locals {
  cluster_labels = merge(
    {
      module  = "aethernova-compute-gke"
      env     = var.environment
      project = var.project_id
    },
    var.cluster_labels
  )

  is_autopilot = lower(var.cluster_mode) == "autopilot"

  # Имя VPC/подсети может быть задано строкой "self-link" или именем; модуль принимает строку как есть.
  network    = var.network
  subnetwork = var.subnetwork

  cluster_name = var.name
}

#####################################################
# (Опционально) Метаданные для провайдера
#####################################################
terraform {
  provider_meta "google" {
    module_name = "aethernova/compute-gke"
  }
  provider_meta "google-beta" {
    module_name = "aethernova/compute-gke"
  }
}

#####################################################
# Общие проверки согласованности (Terraform >=1.6)
#####################################################
check "ip_alias_ranges" {
  assert {
    condition = var.private_cluster.enabled ?
      (length(var.cluster_secondary_range_name) > 0 && length(var.services_secondary_range_name) > 0)
      : true
    error_message = "Для private_cluster.enabled=true необходимо указать cluster_secondary_range_name и services_secondary_range_name."
  }
}

check "autopilot_node_pools_forbidden" {
  assert {
    condition = local.is_autopilot ? (length(var.node_pools) == 0) : true
    error_message = "В режиме Autopilot нельзя задавать node_pools."
  }
}

#####################################################
# GKE Autopilot Cluster
#####################################################
resource "google_container_cluster" "autopilot" {
  count    = local.is_autopilot ? 1 : 0
  name     = local.cluster_name
  project  = var.project_id
  location = var.location

  network    = local.network
  subnetwork = local.subnetwork

  # VPC Native & IP aliasing
  ip_allocation_policy {
    cluster_secondary_range_name  = var.cluster_secondary_range_name
    services_secondary_range_name = var.services_secondary_range_name
  }

  # Release channel
  dynamic "release_channel" {
    for_each = var.release_channel != "" ? [1] : []
    content {
      channel = var.release_channel # RAPID|REGULAR|STABLE
    }
  }

  # Private Cluster
  dynamic "private_cluster_config" {
    for_each = var.private_cluster.enabled ? [1] : []
    content {
      enable_private_nodes    = true
      enable_private_endpoint = var.private_cluster.enable_private_endpoint
      master_ipv4_cidr_block  = var.private_cluster.master_cidr
    }
  }

  # Master Authorized Networks
  dynamic "master_authorized_networks_config" {
    for_each = length(var.master_authorized_networks) > 0 ? [1] : []
    content {
      enabled = true
      dynamic "cidr_blocks" {
        for_each = var.master_authorized_networks
        content {
          cidr_block   = cidr_blocks.value.cidr
          display_name = coalesce(cidr_blocks.value.name, "allowed")
        }
      }
    }
  }

  # Workload Identity
  dynamic "workload_identity_config" {
    for_each = var.workload_pool != "" ? [1] : []
    content {
      workload_pool = var.workload_pool # "<PROJECT_ID>.svc.id.goog"
    }
  }

  # Binary Authorization
  dynamic "binary_authorization" {
    for_each = var.binary_authorization.enabled ? [1] : []
    content {
      evaluation_mode = var.binary_authorization.evaluation_mode # PROJECT_SINGLETON_POLICY_ENFORCE|DISABLED
    }
  }

  # CMEK (Database Encryption)
  dynamic "database_encryption" {
    for_each = var.cmek_key_name != "" ? [1] : []
    content {
      state    = "ENCRYPTED"
      key_name = var.cmek_key_name
    }
  }

  # Shielded Nodes
  shielded_nodes {
    enabled = var.enable_shielded_nodes
  }

  # VPA (Autopilot управляет ресурсами; блок безопасен)
  vertical_pod_autoscaling {
    enabled = var.enable_vpa
  }

  # Логирование/Мониторинг на уровне кластера
  logging_service    = var.enable_cluster_logging    ? "logging.googleapis.com/kubernetes"    : "none"
  monitoring_service = var.enable_cluster_monitoring ? "monitoring.googleapis.com/kubernetes" : "none"

  resource_labels = local.cluster_labels

  # Обслуживание (Maintenance Policy)
  dynamic "maintenance_policy" {
    for_each = var.maintenance_policy.enabled ? [1] : []
    content {
      dynamic "recurring_window" {
        for_each = var.maintenance_policy.recurring != null ? [1] : []
        content {
          recurrence = var.maintenance_policy.recurring.recurrence # RRULE
          start_time = var.maintenance_policy.recurring.start_time # RFC3339
          end_time   = var.maintenance_policy.recurring.end_time   # RFC3339
        }
      }
      dynamic "maintenance_exclusion" {
        for_each = var.maintenance_policy.exclusions
        content {
          exclusion_name = maintenance_exclusion.value.name
          start_time     = maintenance_exclusion.value.start_time
          end_time       = maintenance_exclusion.value.end_time
          exclusion_options {
            scope = maintenance_exclusion.value.scope # NO_UPGRADES|NODE_POOL|IN_PLACE_UPDATE
          }
        }
      }
    }
  }

  # Autopilot режим
  autopilot {
    enabled = true
  }

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}

#####################################################
# GKE Standard Cluster (без default node pool)
#####################################################
resource "google_container_cluster" "standard" {
  count    = local.is_autopilot ? 0 : 1
  name     = local.cluster_name
  project  = var.project_id
  location = var.location

  network    = local.network
  subnetwork = local.subnetwork

  # Обязательный initial_node_count при remove_default_node_pool=true (требование API)
  remove_default_node_pool = true
  initial_node_count       = 1

  # VPC Native & IP aliasing
  ip_allocation_policy {
    cluster_secondary_range_name  = var.cluster_secondary_range_name
    services_secondary_range_name = var.services_secondary_range_name
  }

  # Release channel
  dynamic "release_channel" {
    for_each = var.release_channel != "" ? [1] : []
    content {
      channel = var.release_channel
    }
  }

  # Private Cluster
  dynamic "private_cluster_config" {
    for_each = var.private_cluster.enabled ? [1] : []
    content {
      enable_private_nodes    = true
      enable_private_endpoint = var.private_cluster.enable_private_endpoint
      master_ipv4_cidr_block  = var.private_cluster.master_cidr
    }
  }

  # Master Authorized Networks
  dynamic "master_authorized_networks_config" {
    for_each = length(var.master_authorized_networks) > 0 ? [1] : []
    content {
      enabled = true
      dynamic "cidr_blocks" {
        for_each = var.master_authorized_networks
        content {
          cidr_block   = cidr_blocks.value.cidr
          display_name = coalesce(cidr_blocks.value.name, "allowed")
        }
      }
    }
  }

  # Workload Identity
  dynamic "workload_identity_config" {
    for_each = var.workload_pool != "" ? [1] : []
    content {
      workload_pool = var.workload_pool
    }
  }

  # Binary Authorization
  dynamic "binary_authorization" {
    for_each = var.binary_authorization.enabled ? [1] : []
    content {
      evaluation_mode = var.binary_authorization.evaluation_mode
    }
  }

  # CMEK (Database Encryption)
  dynamic "database_encryption" {
    for_each = var.cmek_key_name != "" ? [1] : []
    content {
      state    = "ENCRYPTED"
      key_name = var.cmek_key_name
    }
  }

  # Shielded Nodes
  shielded_nodes {
    enabled = var.enable_shielded_nodes
  }

  # Network Policy (Calico)
  dynamic "network_policy" {
    for_each = var.network_policy.enabled ? [1] : []
    content {
      enabled  = true
      provider = var.network_policy.provider # "CALICO"
    }
  }

  # Datapath Provider (eBPF dataplane)
  dynamic "default_snat_status" {
    for_each = var.default_snat_disabled ? [1] : []
    content {
      disabled = true
    }
  }

  # Vertical Pod Autoscaling
  vertical_pod_autoscaling {
    enabled = var.enable_vpa
  }

  # Cluster Autoscaling (Node Auto-Provisioning)
  dynamic "cluster_autoscaling" {
    for_each = var.cluster_autoscaling.enable_node_autoprovisioning ? [1] : []
    content {
      enabled                       = true
      autoscaling_profile           = var.cluster_autoscaling.profile
      enable_node_autoprovisioning  = true

      dynamic "auto_provisioning_defaults" {
        for_each = [1]
        content {
          service_account = var.cluster_autoscaling.service_account
          oauth_scopes    = var.cluster_autoscaling.oauth_scopes
          disk_type       = var.cluster_autoscaling.disk_type
          disk_size       = var.cluster_autoscaling.disk_size_gb
          image_type      = var.cluster_autoscaling.image_type
          min_cpu_platform = var.cluster_autoscaling.min_cpu_platform
          boot_disk_kms_key = var.cluster_autoscaling.boot_disk_kms_key
          management {
            auto_upgrade = var.cluster_autoscaling.management.auto_upgrade
            auto_repair  = var.cluster_autoscaling.management.auto_repair
          }
          shielded_instance_config {
            enable_secure_boot          = var.cluster_autoscaling.shielded.enable_secure_boot
            enable_integrity_monitoring = var.cluster_autoscaling.shielded.enable_integrity_monitoring
          }
        }
      }
      dynamic "resource_limits" {
        for_each = var.cluster_autoscaling.resource_limits
        content {
          resource_type = resource_limits.value.type
          minimum       = resource_limits.value.min
          maximum       = resource_limits.value.max
        }
      }
    }
  }

  # Логирование/Мониторинг
  logging_service    = var.enable_cluster_logging    ? "logging.googleapis.com/kubernetes"    : "none"
  monitoring_service = var.enable_cluster_monitoring ? "monitoring.googleapis.com/kubernetes" : "none"

  # Доп. параметры
  datapath_provider          = var.datapath_provider          # "ADVANCED_DATAPATH" | "LEGACY_DATAPATH"
  default_max_pods_per_node  = var.default_max_pods_per_node

  resource_labels = local.cluster_labels

  # Обслуживание (Maintenance Policy)
  dynamic "maintenance_policy" {
    for_each = var.maintenance_policy.enabled ? [1] : []
    content {
      dynamic "recurring_window" {
        for_each = var.maintenance_policy.recurring != null ? [1] : []
        content {
          recurrence = var.maintenance_policy.recurring.recurrence
          start_time = var.maintenance_policy.recurring.start_time
          end_time   = var.maintenance_policy.recurring.end_time
        }
      }
      dynamic "maintenance_exclusion" {
        for_each = var.maintenance_policy.exclusions
        content {
          exclusion_name = maintenance_exclusion.value.name
          start_time     = maintenance_exclusion.value.start_time
          end_time       = maintenance_exclusion.value.end_time
          exclusion_options {
            scope = maintenance_exclusion.value.scope
          }
        }
      }
    }
  }

  lifecycle {
    prevent_destroy = var.prevent_destroy

    precondition {
      condition     = var.network_policy.enabled ? (var.network_policy.provider == "CALICO") : true
      error_message = "Поддерживается только CALICO в network_policy.provider."
    }
  }
}

#####################################################
# Node Pools (Standard only)
#####################################################
resource "google_container_node_pool" "pools" {
  for_each = local.is_autopilot ? {} : var.node_pools

  name     = each.key
  project  = var.project_id
  location = var.location
  cluster  = google_container_cluster.standard[0].name

  # Выбор: фиксированный размер или автоскейлинг
  dynamic "autoscaling" {
    for_each = try(each.value.autoscaling.enabled, false) ? [1] : []
    content {
      min_node_count = each.value.autoscaling.min
      max_node_count = each.value.autoscaling.max
      location_policy = try(each.value.autoscaling.location_policy, null)
    }
  }

  # Если автоскейлинг выключен — задаём node_count
  node_count = try(each.value.autoscaling.enabled, false) ? null : each.value.node_count

  management {
    auto_repair  = try(each.value.management.auto_repair, true)
    auto_upgrade = try(each.value.management.auto_upgrade, true)
  }

  upgrade_settings {
    max_surge       = try(each.value.upgrade.max_surge, 1)
    max_unavailable = try(each.value.upgrade.max_unavailable, 0)
    strategy        = try(each.value.upgrade.strategy, null)
  }

  node_config {
    machine_type    = each.value.machine_type
    image_type      = try(each.value.image_type, "COS_CONTAINERD")
    disk_type       = try(each.value.disk_type, "pd-standard")
    disk_size_gb    = try(each.value.disk_size_gb, 100)
    min_cpu_platform = try(each.value.min_cpu_platform, null)

    service_account = try(each.value.service_account, var.default_node_service_account)
    oauth_scopes    = try(each.value.oauth_scopes, ["https://www.googleapis.com/auth/cloud-platform"])

    tags   = try(each.value.tags, [])
    labels = try(each.value.labels, {})

    # Spot/Preemptible
    spot        = try(each.value.spot, false)
    preemptible = try(each.value.preemptible, false)

    # gVNIC/GCFS
    dynamic "gvnic" {
      for_each = try(each.value.gvnic_enabled, false) ? [1] : []
      content {
        enabled = true
      }
    }
    dynamic "gcfs_config" {
      for_each = try(each.value.gcfs_enabled, false) ? [1] : []
      content {
        enabled = true
      }
    }

    # Workload Metadata
    workload_metadata_config {
      mode = try(each.value.workload_metadata_mode, "GKE_METADATA") # GCE_METADATA|GKE_METADATA
    }

    # Shielded
    shielded_instance_config {
      enable_secure_boot          = try(each.value.shielded.enable_secure_boot, true)
      enable_integrity_monitoring = try(each.value.shielded.enable_integrity_monitoring, true)
    }

    # Sandbox (gVisor)
    dynamic "sandbox_config" {
      for_each = try(each.value.gvisor_enabled, false) ? [1] : []
      content {
        sandbox_type = "gvisor"
      }
    }

    # Linux sysctls (тонкая настройка)
    dynamic "linux_node_config" {
      for_each = length(try(each.value.linux_sysctls, {})) > 0 ? [1] : []
      content {
        sysctls = each.value.linux_sysctls
      }
    }

    # Taints
    dynamic "taint" {
      for_each = try(each.value.taints, [])
      content {
        key    = taint.value.key
        value  = taint.value.value
        effect = taint.value.effect # NO_SCHEDULE|PREFER_NO_SCHEDULE|NO_EXECUTE
      }
    }

    # Boot Disk CMEK
    boot_disk_kms_key = try(each.value.boot_disk_kms_key, null)
  }

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}
