# File: aethernova-chain-core/ops/terraform/modules/k8s-apps/aethernova-node/main.tf

########################################
# Inputs (with sane production defaults)
########################################

variable "name" {
  description = "Helm release name (and app.kubernetes.io/instance label)."
  type        = string
  default     = "aethernova-node"
}

variable "namespace" {
  description = "Target namespace for the release."
  type        = string
  default     = "aethernova"
}

variable "create_namespace" {
  description = "Create namespace if it does not exist."
  type        = bool
  default     = true
}

variable "repository" {
  description = "Helm chart repository URL (e.g. https://charts.example.com)."
  type        = string
}

variable "chart" {
  description = "Helm chart name or path."
  type        = string
}

variable "chart_version" {
  description = "Helm chart version (immutable for reproducible deploys)."
  type        = string
}

variable "values_files" {
  description = "List of paths to values YAML files (merged in order)."
  type        = list(string)
  default     = []
}

variable "values_yaml" {
  description = "Extra values as Terraform map (merged after files)."
  type        = any
  default     = {}
}

variable "atomic" {
  description = "Install/upgrade atomically (rollback on failure)."
  type        = bool
  default     = true
}

variable "cleanup_on_fail" {
  description = "Cleanup resources created by a failed install/upgrade."
  type        = bool
  default     = true
}

variable "wait" {
  description = "Wait until all resources are in a ready state."
  type        = bool
  default     = true
}

variable "wait_for_jobs" {
  description = "Wait for all Jobs to complete before marking release successful."
  type        = bool
  default     = true
}

variable "timeout_seconds" {
  description = "Timeout for Helm operations in seconds."
  type        = number
  default     = 600
}

variable "max_history" {
  description = "How many release versions to retain (for rollback)."
  type        = number
  default     = 10
}

variable "pdb_enabled" {
  description = "Create PodDisruptionBudget for this workload."
  type        = bool
  default     = true
}

variable "pdb_min_available" {
  description = "minAvailable for PDB (string or number per K8s API)."
  type        = string
  default     = "1"
}

########################################
# Locals
########################################

locals {
  # Render list of YAML strings from files in declared order.
  values_from_files = [
    for p in var.values_files : file(p)
  ]

  # Encode map/object -> YAML and append last, so it overrides files.
  values_from_map = length(keys(try(var.values_yaml, {}))) > 0 ? [yamlencode(var.values_yaml)] : []

  merged_values = concat(local.values_from_files, local.values_from_map)

  # Common labels for selectors and discovery.
  common_labels = {
    "app.kubernetes.io/name"       = var.name
    "app.kubernetes.io/instance"   = var.name
    "app.kubernetes.io/part-of"    = "aethernova-chain-core"
    "app.kubernetes.io/component"  = "node"
    "app.kubernetes.io/managed-by" = "terraform-helm"
  }
}

########################################
# Optional Namespace
########################################

resource "kubernetes_namespace_v1" "this" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name   = var.namespace
    labels = local.common_labels
  }
}

########################################
# Helm Release
########################################

resource "helm_release" "this" {
  name       = var.name
  namespace  = var.namespace

  # If using a repository, set both repository and chart.
  repository = var.repository
  chart      = var.chart
  version    = var.chart_version

  # Production-safe flags
  atomic           = var.atomic
  cleanup_on_fail  = var.cleanup_on_fail
  wait             = var.wait
  wait_for_jobs    = var.wait_for_jobs
  timeout          = var.timeout_seconds
  max_history      = var.max_history
  dependency_update = true

  # Create namespace by Helm too (in addition to TF resource for idempotency/race-safety).
  create_namespace = var.create_namespace

  # Merge values: files first, then map overrides (see locals.merged_values).
  values = local.merged_values

  # Recommended annotations and labels for the release itself
  metadata {
    annotations = {
      "policies.aethernova.io/source" = "terraform"
    }
    labels = local.common_labels
  }

  # Lifecycle: keep TF as the single source of truth
  lifecycle {
    ignore_changes = [
      # Ignore drift if some operators adjust annotations in-cluster.
      metadata[0].annotations,
    ]
  }

  depends_on = [
    kubernetes_namespace_v1.this
  ]
}

########################################
# Pod Disruption Budget (optional)
########################################

resource "kubernetes_pod_disruption_budget_v1" "this" {
  count = var.pdb_enabled ? 1 : 0

  metadata {
    name      = "${var.name}-pdb"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    selector {
      match_labels = {
        "app.kubernetes.io/instance" = var.name
      }
    }
    # Choose either minAvailable or maxUnavailable; here we use minAvailable.
    min_available = var.pdb_min_available
  }

  depends_on = [
    helm_release.this
  ]
}

########################################
# Outputs
########################################

output "release_name" {
  description = "The Helm release name."
  value       = helm_release.this.name
}

output "release_namespace" {
  description = "The namespace where the release is installed."
  value       = helm_release.this.namespace
}

output "release_version" {
  description = "The chart version deployed."
  value       = helm_release.this.version
}
