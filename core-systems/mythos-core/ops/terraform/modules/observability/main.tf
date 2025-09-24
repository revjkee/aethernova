###############################################
# mythos-core / ops / terraform / modules / observability / main.tf
# Industrial, cloud-agnostic Observability module for Kubernetes
###############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.29"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# This module expects configured providers "kubernetes" and "helm"
# in the root module (cluster credentials/context).

###############################################
# Variables
###############################################

variable "namespace" {
  description = "Kubernetes namespace for all observability components."
  type        = string
  default     = "observability"
}

variable "labels" {
  description = "Common labels applied to created resources."
  type        = map(string)
  default     = {}
}

# kube-prometheus-stack controls
variable "kps_enabled" {
  description = "Install prometheus-community/kube-prometheus-stack."
  type        = bool
  default     = true
}

variable "kps_chart_version" {
  description = "Explicit chart version for kube-prometheus-stack (null = latest)."
  type        = string
  default     = null
}

variable "prometheus_retention" {
  description = "Prometheus retention period (e.g., 15d)."
  type        = string
  default     = "15d"
}

variable "prometheus_storage_size" {
  description = "PVC size for Prometheus (e.g., 50Gi). Null to use emptyDir."
  type        = string
  default     = null
}

variable "prometheus_storage_class" {
  description = "StorageClass name for Prometheus PVC (null = default)."
  type        = string
  default     = null
}

variable "prometheus_external_labels" {
  description = "Additional external labels for Prometheus."
  type        = map(string)
  default     = {}
}

variable "prometheus_remote_write" {
  description = "List of remote_write configurations for Prometheus (directly rendered into chart values)."
  type        = list(any)
  default     = []
}

# Grafana controls
variable "grafana_enabled" {
  description = "Enable Grafana subchart in kube-prometheus-stack."
  type        = bool
  default     = true
}

variable "grafana_admin_password" {
  description = "Grafana admin password (sensitive). If null, a random password will be generated."
  type        = string
  default     = null
  sensitive   = true
}

variable "grafana_ingress_enabled" {
  description = "Enable Ingress for Grafana."
  type        = bool
  default     = false
}

variable "grafana_host" {
  description = "Hostname for Grafana Ingress (required if ingress enabled)."
  type        = string
  default     = null
}

variable "grafana_tls_secret" {
  description = "TLS secret name for Grafana Ingress (null to disable TLS)."
  type        = string
  default     = null
}

variable "ingress_class_name" {
  description = "IngressClass name for Grafana Ingress (e.g., nginx, traefik)."
  type        = string
  default     = null
}

variable "kps_values" {
  description = "Raw values overlay for kube-prometheus-stack (merged last)."
  type        = map(any)
  default     = {}
}

# Loki + Promtail (optional)
variable "loki_enabled" {
  description = "Install Grafana Loki."
  type        = bool
  default     = false
}

variable "loki_chart_version" {
  description = "Explicit chart version for grafana/loki (null = latest)."
  type        = string
  default     = null
}

variable "loki_storage_size" {
  description = "Persistent size for Loki (null = use in-memory)."
  type        = string
  default     = null
}

variable "loki_storage_class" {
  description = "StorageClass for Loki PVC."
  type        = string
  default     = null
}

variable "loki_values" {
  description = "Raw values overlay for Loki (merged last)."
  type        = map(any)
  default     = {}
}

variable "promtail_enabled" {
  description = "Install Grafana Promtail DaemonSet."
  type        = bool
  default     = false
}

variable "promtail_chart_version" {
  description = "Explicit chart version for grafana/promtail (null = latest)."
  type        = string
  default     = null
}

variable "promtail_values" {
  description = "Raw values overlay for Promtail (merged last)."
  type        = map(any)
  default     = {}
}

###############################################
# Locals
###############################################

locals {
  ns = var.namespace

  grafana_password = coalesce(var.grafana_admin_password, try(random_password.grafana[0].result, null))

  # kube-prometheus-stack default values (safe baseline).
  # NOTE: Keys mirror the chart's values structure; user-provided kps_values are merged last.
  kps_defaults = {
    fullnameOverride = "kube-prometheus-stack"
    prometheus = {
      prometheusSpec = merge(
        {
          retention     = var.prometheus_retention
          externalLabels = var.prometheus_external_labels
        },
        length(var.prometheus_remote_write) > 0 ? { remoteWrite = var.prometheus_remote_write } : {},
        var.prometheus_storage_size != null ? {
          storageSpec = {
            volumeClaimTemplate = {
              spec = {
                accessModes      = ["ReadWriteOnce"]
                storageClassName = var.prometheus_storage_class
                resources = {
                  requests = { storage = var.prometheus_storage_size }
                }
              }
            }
          }
        } : {}
      )
    }
    alertmanager = {
      enabled = true
    }
    grafana = merge(
      { enabled = var.grafana_enabled },
      var.grafana_enabled ? (
        {
          adminPassword = local.grafana_password
          defaultDashboardsEnabled = true
          service = { type = "ClusterIP" }
        }
        )
        : {}
    )
  }

  # Grafana ingress branch added if enabled
  kps_with_ingress = var.grafana_ingress_enabled && var.grafana_enabled ? merge(
    local.kps_defaults,
    {
      grafana = merge(
        local.kps_defaults.grafana,
        {
          ingress = merge(
            {
              enabled = true
              hosts   = var.grafana_host != null ? [var.grafana_host] : []
              ingressClassName = var.ingress_class_name
            },
            var.grafana_tls_secret != null && var.grafana_host != null ? {
              tls = [{
                secretName = var.grafana_tls_secret
                hosts      = [var.grafana_host]
              }]
            } : {}
          )
        }
      )
    }
  ) : local.kps_defaults

  kps_values_final = merge(local.kps_with_ingress, var.kps_values)

  # Loki minimal defaults
  loki_defaults = {
    fullnameOverride = "loki"
    persistence = var.loki_storage_size != null ? {
      enabled          = true
      size             = var.loki_storage_size
      storageClassName = var.loki_storage_class
    } : { enabled = false }
  }

  loki_values_final = merge(local.loki_defaults, var.loki_values)

  # Promtail defaults
  promtail_defaults = {
    fullnameOverride = "promtail"
    config = {
      clients = var.loki_enabled ? [
        { url = "http://loki-headless.${local.ns}.svc.cluster.local:3100/loki/api/v1/push" }
      ] : []
    }
  }

  promtail_values_final = merge(local.promtail_defaults, var.promtail_values)
}

###############################################
# Namespace & secrets
###############################################

resource "kubernetes_namespace" "this" {
  metadata {
    name   = local.ns
    labels = merge({ "app.kubernetes.io/part-of" = "mythos", "app.kubernetes.io/component" = "observability" }, var.labels)
  }
}

resource "random_password" "grafana" {
  count            = var.grafana_enabled && var.kps_enabled && var.grafana_admin_password == null ? 1 : 0
  length           = 20
  special          = true
  override_special = "_%@"
}

###############################################
# Helm releases
###############################################

# kube-prometheus-stack (Prometheus + Alertmanager + Grafana)
resource "helm_release" "kps" {
  count            = var.kps_enabled ? 1 : 0
  name             = "kube-prometheus-stack"
  namespace        = kubernetes_namespace.this.metadata[0].name
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  # version is optional; latest if null
  version          = var.kps_chart_version
  create_namespace = false
  timeout          = 600
  wait             = true
  atomic           = true

  values = [
    yamlencode(local.kps_values_final)
  ]

  # Basic labels
  metadata {
    labels = var.labels
  }

  depends_on = [kubernetes_namespace.this]
}

# Grafana password as output only when enabled
# NOTE: The password is stored in Terraform state (sensitive output). Manage state storage securely.

# Loki (optional)
resource "helm_release" "loki" {
  count            = var.loki_enabled ? 1 : 0
  name             = "loki"
  namespace        = kubernetes_namespace.this.metadata[0].name
  repository       = "https://grafana.github.io/helm-charts"
  chart            = "loki"
  version          = var.loki_chart_version
  create_namespace = false
  timeout          = 600
  wait             = true
  atomic           = true

  values = [
    yamlencode(local.loki_values_final)
  ]

  metadata {
    labels = var.labels
  }

  depends_on = [kubernetes_namespace.this]
}

# Promtail (optional)
resource "helm_release" "promtail" {
  count            = var.promtail_enabled ? 1 : 0
  name             = "promtail"
  namespace        = kubernetes_namespace.this.metadata[0].name
  repository       = "https://grafana.github.io/helm-charts"
  chart            = "promtail"
  version          = var.promtail_chart_version
  create_namespace = false
  timeout          = 600
  wait             = true
  atomic           = true

  values = [
    yamlencode(local.promtail_values_final)
  ]

  metadata {
    labels = var.labels
  }

  depends_on = [
    kubernetes_namespace.this,
    helm_release.loki
  ]
}

###############################################
# Outputs
###############################################

output "namespace" {
  description = "Namespace where observability stack is installed."
  value       = kubernetes_namespace.this.metadata[0].name
}

output "grafana_admin_password" {
  description = "Grafana admin password (if Grafana enabled)."
  value       = local.grafana_password
  sensitive   = true
}

output "grafana_ingress_host" {
  description = "Grafana ingress host (if enabled)."
  value       = var.grafana_ingress_enabled ? var.grafana_host : null
}

output "kube_prometheus_stack_release_name" {
  description = "Helm release name for kube-prometheus-stack (if enabled)."
  value       = var.kps_enabled ? helm_release.kps[0].name : null
}

output "loki_release_name" {
  description = "Helm release name for Loki (if enabled)."
  value       = var.loki_enabled ? helm_release.loki[0].name : null
}

output "promtail_release_name" {
  description = "Helm release name for Promtail (if enabled)."
  value       = var.promtail_enabled ? helm_release.promtail[0].name : null
}
