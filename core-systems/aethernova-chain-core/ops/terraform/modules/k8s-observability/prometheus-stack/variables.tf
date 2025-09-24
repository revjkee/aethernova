############################################################
# File: aethernova-chain-core/ops/terraform/modules/k8s-observability/prometheus-stack/variables.tf
# Purpose: Inputs for kube-prometheus-stack Helm deployment (industrial-grade)
# Terraform: >= 1.4
############################################################

############################
# Helm release / chart
############################
variable "release_name" {
  description = "Helm release name for kube-prometheus-stack"
  type        = string
  default     = "prometheus-stack"
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.release_name))
    error_message = "release_name must be a valid Helm release/K8s name (DNS-1123)."
  }
}

variable "namespace" {
  description = "Kubernetes namespace to install the stack"
  type        = string
  default     = "monitoring"
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace must match DNS-1123 label."
  }
}

variable "create_namespace" {
  description = "Create namespace if it doesn't exist"
  type        = bool
  default     = true
}

variable "helm_repo" {
  description = "Helm repository URL for prometheus-community"
  type        = string
  default     = "https://prometheus-community.github.io/helm-charts"
}

variable "chart_name" {
  description = "Chart name"
  type        = string
  default     = "kube-prometheus-stack"
}

variable "chart_version" {
  description = "Chart version constraint (e.g., 77.5.0). Leave empty to take module default."
  type        = string
  default     = ""
}

variable "install_crds" {
  description = "Whether to let the chart manage CRDs (subject to Helm CRD semantics)."
  type        = bool
  default     = true
}

############################
# Global tags/labels
############################
variable "common_labels" {
  description = "Labels to add to all managed resources where supported"
  type        = map(string)
  default     = {}
}

variable "common_annotations" {
  description = "Annotations to add to all managed resources where supported"
  type        = map(string)
  default     = {}
}

############################
# Prometheus persistence & retention
############################
variable "prometheus_storage_enabled" {
  description = "Enable PVC for Prometheus TSDB"
  type        = bool
  default     = true
}

variable "prometheus_storage_size" {
  description = "PVC size for Prometheus (e.g., 100Gi)"
  type        = string
  default     = "100Gi"
}

variable "prometheus_storage_class" {
  description = "StorageClass name; empty means default"
  type        = string
  default     = ""
}

variable "prometheus_retention_time" {
  description = "Prometheus retention time (Prometheus duration: y,w,d,h,m,s,ms)."
  type        = string
  default     = "15d"
  validation {
    condition     = can(regex("^\\d+(ms|s|m|h|d|w|y)$", var.prometheus_retention_time))
    error_message = "Use Prometheus duration format, e.g., 6h, 15d, 4w, 1y."
  }
}

variable "prometheus_retention_size" {
  description = "Prometheus retention by size (e.g., 50GB, 512MB). Empty disables size-based retention."
  type        = string
  default     = ""
}

variable "prometheus_resources" {
  description = "Resources for Prometheus pods (requests/limits structure as values map)"
  type        = any
  default     = {}
}

############################
# Alertmanager persistence & retention
############################
variable "alertmanager_enabled" {
  description = "Enable Alertmanager"
  type        = bool
  default     = true
}

variable "alertmanager_storage_enabled" {
  description = "Enable PVC for Alertmanager"
  type        = bool
  default     = true
}

variable "alertmanager_storage_size" {
  description = "PVC size for Alertmanager"
  type        = string
  default     = "10Gi"
}

variable "alertmanager_storage_class" {
  description = "StorageClass for Alertmanager"
  type        = string
  default     = ""
}

variable "alertmanager_retention" {
  description = "Alertmanager retention (GoDuration: ms,s,m,h)"
  type        = string
  default     = "120h"
  validation {
    condition     = can(regex("^\\d+(ms|s|m|h)$", var.alertmanager_retention))
    error_message = "Use GoDuration format for Alertmanager (e.g., 120h, 30m)."
  }
}

variable "alertmanager_resources" {
  description = "Resources for Alertmanager pods"
  type        = any
  default     = {}
}

############################
# Grafana
############################
variable "grafana_enabled" {
  description = "Enable Grafana subchart"
  type        = bool
  default     = true
}

variable "grafana_admin_user" {
  description = "Grafana admin username (used if grafana_admin_password is set inline)"
  type        = string
  default     = "admin"
}

variable "grafana_admin_password" {
  description = "Grafana admin password (inline). Prefer secret if possible."
  type        = string
  default     = ""
  sensitive   = true
}

variable "grafana_admin_password_existing_secret" {
  description = "Existing K8s Secret name with key 'admin-password' for Grafana"
  type        = string
  default     = ""
}

variable "grafana_plugins" {
  description = "List of Grafana plugins to install (e.g., grafana-piechart-panel)"
  type        = list(string)
  default     = []
}

variable "grafana_persistence_enabled" {
  description = "Enable Grafana PVC"
  type        = bool
  default     = true
}

variable "grafana_persistence_size" {
  description = "Grafana PVC size"
  type        = string
  default     = "10Gi"
}

variable "grafana_storage_class" {
  description = "StorageClass for Grafana PVC"
  type        = string
  default     = ""
}

############################
# Ingress (per component)
############################
variable "prometheus_ingress" {
  description = "Ingress settings for Prometheus (enabled, className, hosts, tls_secret)"
  type = object({
    enabled     = bool
    class_name  = string
    hosts       = list(string)
    tls_secret  = string
    annotations = map(string)
  })
  default = {
    enabled     = false
    class_name  = ""
    hosts       = []
    tls_secret  = ""
    annotations = {}
  }
}

variable "alertmanager_ingress" {
  description = "Ingress settings for Alertmanager"
  type = object({
    enabled     = bool
    class_name  = string
    hosts       = list(string)
    tls_secret  = string
    annotations = map(string)
  })
  default = {
    enabled     = false
    class_name  = ""
    hosts       = []
    tls_secret  = ""
    annotations = {}
  }
}

variable "grafana_ingress" {
  description = "Ingress settings for Grafana"
  type = object({
    enabled     = bool
    class_name  = string
    hosts       = list(string)
    tls_secret  = string
    annotations = map(string)
  })
  default = {
    enabled     = false
    class_name  = ""
    hosts       = []
    tls_secret  = ""
    annotations = {}
  }
}

############################
# Remote write (Prometheus -> remote backends)
############################
variable "prometheus_remote_write" {
  description = <<EOT
List of remote_write endpoints (maps directly into PrometheusSpec.remoteWrite).
Each item supports at least:
  - url (string, required)
  - basic_auth_secret_name (string, optional; secret with 'username'/'password' keys)
  - bearer_token_secret_name (string, optional; secret with 'token' key)
  - write_relabel_configs (list(any), optional) — raw relabel configs
  - queue_config (map(any), optional) — tuning params (capacity, max_shards, etc.)
  - metadata_config (map(any), optional)
  - headers (map(string), optional)
EOT
  type = list(object({
    url                        = string
    basic_auth_secret_name     = optional(string, "")
    bearer_token_secret_name   = optional(string, "")
    write_relabel_configs      = optional(list(any), [])
    queue_config               = optional(map(any), {})
    metadata_config            = optional(map(any), {})
    headers                    = optional(map(string), {})
  }))
  default = []
  validation {
    condition     = alltrue([for rw in var.prometheus_remote_write : can(regex("^https?://", rw.url))])
    error_message = "Each remote_write.url must be an http(s) URL."
  }
}

############################
# Thanos sidecar (via PrometheusSpec.thanos)
############################
variable "thanos_enabled" {
  description = "Enable Thanos sidecar for Prometheus"
  type        = bool
  default     = false
}

variable "thanos_objstore_secret_name" {
  description = "K8s Secret name with Thanos object store config (key: objstore.yml)"
  type        = string
  default     = ""
}

variable "thanos_extra_args" {
  description = "Additional CLI args for Thanos sidecar (list of strings)"
  type        = list(string)
  default     = []
}

############################
# Scrape & selectors
############################
variable "enable_kube_state_metrics" {
  description = "Enable kube-state-metrics"
  type        = bool
  default     = true
}

variable "enable_node_exporter" {
  description = "Enable node-exporter"
  type        = bool
  default     = true
}

variable "additional_service_monitor_selectors" {
  description = "Extra label selectors to pick up ServiceMonitors (AND semantics)"
  type        = map(string)
  default     = {}
}

variable "additional_pod_monitor_selectors" {
  description = "Extra label selectors to pick up PodMonitors (AND semantics)"
  type        = map(string)
  default     = {}
}

############################
# Raw values passthrough (escape hatch)
############################
variable "extra_values" {
  description = "Arbitrary Helm values overrides merged into chart values"
  type        = any
  default     = {}
}

############################
# Validations (cross-field, best-effort)
############################
variable "enable_tls_strict" {
  description = "If true, require tls_secret to be set when any ingress is enabled (checked by calling module, not at plan-time)."
  type        = bool
  default     = true
}
