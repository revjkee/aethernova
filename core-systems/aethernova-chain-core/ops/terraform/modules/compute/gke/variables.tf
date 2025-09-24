// SPDX-License-Identifier: Apache-2.0
// Module: aethernova-chain-core/ops/terraform/modules/compute/gke
// File:   variables.tf
// Purpose:
//   Production-grade variables for GKE clusters (Standard & Autopilot),
//   including private cluster, IP aliases, Workload Identity, logging/monitoring,
//   binary authorization, network policy, autoscaling, maintenance and node pools.

//-----------------------------
// Core identification & location
//-----------------------------

variable "project_id" {
  description = "GCP project ID для кластера GKE."
  type        = string
  nullable    = false
  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id не может быть пустым."
  }
}

variable "location" {
  description = "Регион или зона размещения кластера (например, europe-west1 для регионального или europe-west1-b для зонального)."
  type        = string
  nullable    = false
  validation {
    condition     = length(var.location) > 0
    error_message = "location не может быть пустым."
  }
}

variable "cluster_name" {
  description = "Имя кластера GKE."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[-a-z0-9]+$", var.cluster_name)) && length(var.cluster_name) >= 1
    error_message = "cluster_name должен состоять из строчных латинских букв, цифр и дефисов."
  }
}

//-----------------------------
// Networking (VPC Native / IP Aliases)
//-----------------------------

variable "network" {
  description = "Имя VPC сети (google_compute_network)."
  type        = string
  nullable    = false
}

variable "subnetwork" {
  description = "Имя подсети (google_compute_subnetwork), к которой будет привязан кластер."
  type        = string
  nullable    = false
}

variable "ip_allocation_policy" {
  description = <<-EOT
    IP Aliases / secondary ranges. Если используются существующие secondary ranges,
    укажите их имена. Если ranges создаются снаружи — передайте соответствующие значения.
  EOT
  type = object({
    cluster_secondary_range_name  = optional(string)
    services_secondary_range_name = optional(string)
  })
  default = {}
}

//-----------------------------
// Cluster mode & versions
//-----------------------------

variable "enable_autopilot" {
  description = "Включить Autopilot режим (true) или Standard (false)."
  type        = bool
  default     = false
}

variable "release_channel" {
  description = "Канал релизов GKE: RAPID, REGULAR, STABLE или UNSPECIFIED."
  type        = string
  default     = "REGULAR"
  validation {
    condition     = contains(["RAPID", "REGULAR", "STABLE", "UNSPECIFIED"], upper(var.release_channel))
    error_message = "release_channel должен быть одним из: RAPID, REGULAR, STABLE, UNSPECIFIED."
  }
}

variable "cluster_version" {
  description = "Желаемая версия GKE (например, 1.29.x). Если null — выбирается версией по каналу."
  type        = string
  default     = null
}

//-----------------------------
// Private cluster & control plane access
//-----------------------------

variable "private_cluster_config" {
  description = "Параметры приватного кластера и доступа к control plane."
  type = object({
    enable_private_nodes    = optional(bool, true)
    enable_private_endpoint = optional(bool, false)
    master_ipv4_cidr_block  = optional(string)    // например, 172.16.0.0/28
    master_global_access    = optional(bool, false)
  })
  default = {}
}

variable "master_authorized_networks" {
  description = "Список доверенных сетей для доступа к control plane."
  type = list(object({
    cidr_block   = string
    display_name = optional(string)
  }))
  default = []
}

//-----------------------------
// Security & identity
//-----------------------------

variable "workload_identity_enabled" {
  description = "Включить Workload Identity для связывания GSA↔KSA."
  type        = bool
  default     = true
}

variable "workload_pool_override" {
  description = "Явное имя Workload Pool (project.svc.id.goog). Если null — вычисляется в самом модуле."
  type        = string
  default     = null
}

variable "enable_shielded_nodes" {
  description = "Включить Shielded Nodes."
  type        = bool
  default     = true
}

variable "enable_binary_authorization" {
  description = "Включить Binary Authorization на уровне кластера."
  type        = bool
  default     = false
}

variable "database_encryption" {
  description = "Шифрование секретов в etcd (CMEK). Если enabled=true — укажите key_name."
  type = object({
    enabled  = optional(bool, false)
    key_name = optional(string) // формат ресурса KMS-ключа
  })
  default = {}
}

//-----------------------------
// Logging & Monitoring
//-----------------------------

variable "logging_config" {
  description = "Компоненты, для которых включается логирование на уровне кластера."
  type = object({
    components = optional(list(string), ["SYSTEM_COMPONENTS", "WORKLOADS"])
  })
  default = {}
  validation {
    condition = length(
      setsubtract(
        toset(try(var.logging_config.components, [])),
        toset(["SYSTEM_COMPONENTS","WORKLOADS","APISERVER","SCHEDULER","CONTROLLER_MANAGER","STORAGE"])
      )
    ) == 0
    error_message = "logging_config.components содержит недопустимые значения."
  }
}

variable "monitoring_config" {
  description = "Компоненты мониторинга GKE."
  type = object({
    components = optional(list(string), ["SYSTEM_COMPONENTS","WORKLOADS"])
    managed_prometheus = optional(bool, true)
  })
  default = {}
  validation {
    condition = length(
      setsubtract(
        toset(try(var.monitoring_config.components, [])),
        toset(["SYSTEM_COMPONENTS","WORKLOADS","APISERVER","SCHEDULER","CONTROLLER_MANAGER","STORAGE","HPA"])
      )
    ) == 0
    error_message = "monitoring_config.components содержит недопустимые значения."
  }
}

//-----------------------------
// Network policy, dataplane, DNS, SNAT
//-----------------------------

variable "enable_network_policy" {
  description = "Включить сетевую политику (Calico)."
  type        = bool
  default     = true
}

variable "dataplane_v2_enabled" {
  description = "Включить Dataplane V2 (eBPF) для сетевой политики и dataplane."
  type        = bool
  default     = false
}

variable "dns_cache_enabled" {
  description = "Включить DNS Cache addon."
  type        = bool
  default     = true
}

variable "default_snat_disabled" {
  description = "Отключить Default SNAT на узлах."
  type        = bool
  default     = false
}

//-----------------------------
// Cluster autoscaling & VPA
//-----------------------------

variable "cluster_autoscaling" {
  description = "Настройки кластерного автоскейлинга (для Standard)."
  type = object({
    enabled            = optional(bool, true)
    autoscaling_profile= optional(string, "BALANCED") // BALANCED | OPTIMIZE_UTILIZATION
    location_policy    = optional(string)              // BALANCED | ANY
    resource_limits    = optional(list(object({
      resource_type = string  // cpu|memory|nvidia.com/gpu и т.п.
      minimum       = number
      maximum       = number
    })), [])
  })
  default = {}
}

variable "vertical_pod_autoscaling" {
  description = "Включить Vertical Pod Autoscaler."
  type        = bool
  default     = true
}

//-----------------------------
// Maintenance & upgrades
//-----------------------------

variable "maintenance_policy" {
  description = <<-EOT
    Политика обслуживания control plane. Если используется окно,
    укажите recurrence (RRULE/RFC5545), start_time и end_time в RFC3339.
  EOT
  type = object({
    recurrence = optional(string)
    start_time = optional(string)
    end_time   = optional(string)
  })
  default = {}
}

variable "node_pool_upgrade_settings" {
  description = "Настройки blue-green/surge обновлений узлов."
  type = object({
    max_surge       = optional(number, 1)
    max_unavailable = optional(number, 0)
    strategy        = optional(string, "SURGE") // SURGE|BLUE_GREEN (выбор реализуется в модуле)
  })
  default = {}
}

//-----------------------------
// Resource usage export / cost allocation
//-----------------------------

variable "usage_metering" {
  description = "Экспорт метрик использования в BigQuery и биллинг-метрики сети."
  type = object({
    enabled                              = optional(bool, false)
    bigquery_dataset_id                  = optional(string)
    enable_network_egress_metering       = optional(bool, false)
    enable_resource_consumption_metering = optional(bool, true)
  })
  default = {}
}

//-----------------------------
// Labels, annotations, tags
//-----------------------------

variable "resource_labels" {
  description = "Ресурсные метки на уровне кластера GKE."
  type        = map(string)
  default     = {}
}

variable "cluster_annotations" {
  description = "Аннотации для кластера (если используются в модуле через google-beta)."
  type        = map(string)
  default     = {}
}

//-----------------------------
// Gateway API, Mesh, features
//-----------------------------

variable "gateway_api" {
  description = "Включение функций Gateway API (если конфигурируется в модуле)."
  type        = object({
    enabled = optional(bool, false)
    channel = optional(string) // например, STANDARD или EXPERIMENTAL — применяется в модуле
  })
  default = {}
}

//-----------------------------
// Default limits
//-----------------------------

variable "default_max_pods_per_node" {
  description = "Максимум Pod на узел по умолчанию (для Standard)."
  type        = number
  default     = 110
}

//-----------------------------
// Node pools (Standard mode only)
//-----------------------------

variable "node_pools" {
  description = <<-EOT
    Описание node pools (только для Standard; для Autopilot должно быть пусто).
    Для каждого пула можно указать тип машины, диски, метки, таинты, теги и т.д.
  EOT
  type = list(object({
    name               = string
    machine_type       = string
    min_count          = optional(number, 1)
    max_count          = optional(number, 3)
    initial_count      = optional(number, 1)
    autoscaling        = optional(bool, true)
    local_ssd_count    = optional(number, 0)
    disk_type          = optional(string, "pd-balanced") // pd-standard|pd-ssd|pd-balanced
    disk_size_gb       = optional(number, 100)
    image_type         = optional(string, "COS_CONTAINERD")
    spot               = optional(bool, false)     // spot VMs
    preemptible        = optional(bool, false)     // legacy preemptible
    confidential_nodes = optional(bool, false)
    sandbox_gvisor     = optional(bool, false)
    enable_gcfs        = optional(bool, false)
    max_pods_per_node  = optional(number)
    service_account    = optional(string)          // SA для узлов
    oauth_scopes       = optional(list(string), ["https://www.googleapis.com/auth/cloud-platform"])
    tags               = optional(list(string), [])
    labels             = optional(map(string), {})
    taints             = optional(list(object({
      key    = string
      value  = optional(string)
      effect = string // NO_SCHEDULE|PREFER_NO_SCHEDULE|NO_EXECUTE
    })), [])
    node_metadata      = optional(string, "GKE_METADATA") // GKE_METADATA|GCE_METADATA
    boot_disk_kms_key  = optional(string)
    shielded_instance_config = optional(object({
      enable_secure_boot          = optional(bool, true)
      enable_vtpm                 = optional(bool, true)
      enable_integrity_monitoring = optional(bool, true)
    }), {})
    upgrade_settings   = optional(object({
      max_surge       = optional(number)
      max_unavailable = optional(number)
    }), {})
    network_tags       = optional(list(string), [])
  }))
  default = []
  validation {
    condition     = var.enable_autopilot ? length(var.node_pools) == 0 : true
    error_message = "В режиме Autopilot список node_pools должен быть пустым."
  }
  validation {
    condition     = alltrue([for np in var.node_pools : contains(["COS_CONTAINERD","UBUNTU_CONTAINERD"], upper(try(np.image_type, "COS_CONTAINERD"))) ])
    error_message = "Допустимые image_type: COS_CONTAINERD, UBUNTU_CONTAINERD."
  }
}

//-----------------------------
// Addons (subset used commonly)
//-----------------------------

variable "addons" {
  description = "Стандартные аддоны GKE."
  type = object({
    http_load_balancing          = optional(bool, true)
    horizontal_pod_autoscaling   = optional(bool, true)
    gce_persistent_disk_csi_driver = optional(bool, true)
    dns_cache                    = optional(bool, true)
  })
  default = {}
}

//-----------------------------
// Intra-node visibility, mesh, etc.
//-----------------------------

variable "intranode_visibility_enabled" {
  description = "Включить Intra-node visibility."
  type        = bool
  default     = false
}

//-----------------------------
// Deletion protection & misc
//-----------------------------

variable "deletion_protection" {
  description = "Защита от удаления ресурса кластера."
  type        = bool
  default     = true
}

variable "enable_master_global_access" {
  description = "Разрешить доступ к control plane из глобальной сети (для приватного кластера)."
  type        = bool
  default     = false
}

variable "labels" {
  description = "Универсальные метки, которые могут применяться в модуле (сливаются с resource_labels)."
  type        = map(string)
  default     = {}
}
