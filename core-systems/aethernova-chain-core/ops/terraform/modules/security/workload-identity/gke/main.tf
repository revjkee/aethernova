###############################################################################
# File: ops/terraform/modules/security/workload-identity/gke/main.tf
# Purpose: Production-grade GKE Workload Identity (KSA <-> GSA binding).
# Scope:
#   - Optionally create a Google Service Account (GSA)
#   - Optionally create/annotate a Kubernetes Service Account (KSA)
#   - Bind roles/iam.workloadIdentityUser on the GSA to the WI principal that
#     represents the KSA: serviceAccount:WORKLOAD_POOL[namespace/ksa]
#   - Optionally grant extra IAM project roles to the GSA
# Notes:
#   - Providers "google" and "kubernetes" must be configured by the caller.
#   - The module can verify the cluster's workload pool and use it to compute
#     the WI member string; otherwise falls back to PROJECT_ID.svc.id.goog.
###############################################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.11"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

###############################################################################
# Inputs
###############################################################################

# GCP project where the GKE cluster lives (controls workload pool).
variable "project_id" {
  description = "Google Cloud project ID of the GKE cluster (defines WORKLOAD_POOL = PROJECT_ID.svc.id.goog)."
  type        = string
}

# Cluster lookup (optional but recommended for verification and to read workload pool)
variable "cluster_name" {
  description = "GKE cluster name for verification and workload pool resolution."
  type        = string
  default     = null
}

variable "location" {
  description = "GKE cluster location (zone or region) for data lookup."
  type        = string
  default     = null
}

variable "verify_cluster_workload_identity" {
  description = "If true, assert that Workload Identity is enabled and read workload pool from the cluster."
  type        = bool
  default     = true
}

# Google Service Account (GSA) controls
variable "gsa_create" {
  description = "Create the Google service account if true; otherwise expect it to exist."
  type        = bool
  default     = true
}

variable "gsa_project_id" {
  description = "Project ID where the GSA resides (defaults to project_id if null)."
  type        = string
  default     = null
}

variable "gsa_name" {
  description = "GSA account_id (left part before @) to create or use."
  type        = string
}

variable "gsa_display_name" {
  description = "Display name for the GSA when created."
  type        = string
  default     = "Workload Identity service account"
}

# Extra project IAM roles to grant to the GSA (e.g., roles/storage.objectViewer)
variable "gsa_project_roles" {
  description = "List of additional project-level roles to grant to the GSA."
  type        = list(string)
  default     = []
}

# Kubernetes Service Account (KSA) controls
variable "manage_ksa" {
  description = "If true, create/annotate the Kubernetes ServiceAccount."
  type        = bool
  default     = true
}

variable "namespace" {
  description = "Kubernetes namespace containing the KSA."
  type        = string
}

variable "ksa_name" {
  description = "Kubernetes ServiceAccount name."
  type        = string
}

variable "ksa_labels" {
  description = "Optional labels for the KSA."
  type        = map(string)
  default     = {}
}

variable "ksa_annotations_extra" {
  description = "Extra annotations merged into the KSA (in addition to the required GSA annotation)."
  type        = map(string)
  default     = {}
}

###############################################################################
# Data sources (cluster -> workload pool) and locals
###############################################################################

# Optionally verify that WI is enabled on the cluster and read the workload pool.
data "google_container_cluster" "cluster" {
  count    = var.verify_cluster_workload_identity && var.cluster_name != null && var.location != null ? 1 : 0
  name     = var.cluster_name
  location = var.location
  project  = var.project_id
}

locals {
  effective_gsa_project_id = coalesce(var.gsa_project_id, var.project_id)
  gsa_email                = "${var.gsa_name}@${local.effective_gsa_project_id}.iam.gserviceaccount.com"

  # Prefer reading workload pool from the cluster; otherwise default to PROJECT_ID.svc.id.goog
  workload_pool = var.verify_cluster_workload_identity && length(data.google_container_cluster.cluster) == 1 ?
    try(data.google_container_cluster.cluster[0].workload_identity_config[0].workload_pool, "${var.project_id}.svc.id.goog") :
    "${var.project_id}.svc.id.goog"

  # Member string required by roles/iam.workloadIdentityUser binding for KSA
  wi_member = "serviceAccount:${local.workload_pool}[${var.namespace}/${var.ksa_name}]"

  # Required KSA annotation linking to GSA
  ksa_required_annotation = {
    "iam.gke.io/gcp-service-account" = local.gsa_email
  }

  ksa_annotations = merge(local.ksa_required_annotation, var.ksa_annotations_extra)
}

###############################################################################
# Guardrails
###############################################################################

resource "null_resource" "guards" {
  triggers = {
    verify = var.verify_cluster_workload_identity ? "true" : "false"
  }

  lifecycle {
    precondition {
      condition     = !var.verify_cluster_workload_identity || (length(data.google_container_cluster.cluster) == 1 && try(data.google_container_cluster.cluster[0].workload_identity_config[0].workload_pool != "", false))
      error_message = "Workload Identity appears disabled or the cluster was not resolvable. Enable WI on the cluster or set verify_cluster_workload_identity=false."
    }
  }
}

###############################################################################
# Google Service Account (create optional)
###############################################################################

resource "google_service_account" "gsa" {
  count        = var.gsa_create ? 1 : 0
  project      = local.effective_gsa_project_id
  account_id   = var.gsa_name
  display_name = var.gsa_display_name
}

# Bind roles/iam.workloadIdentityUser on the GSA to the WI principal (KSA)
resource "google_service_account_iam_member" "wi_user" {
  service_account_id = local.gsa_email
  role               = "roles/iam.workloadIdentityUser"
  member             = local.wi_member

  depends_on = [null_resource.guards]
}

# Optional: grant additional project roles to the GSA
resource "google_project_iam_member" "gsa_extra_roles" {
  for_each = toset(var.gsa_project_roles)
  project  = local.effective_gsa_project_id
  role     = each.value
  member   = "serviceAccount:${local.gsa_email}"
}

###############################################################################
# Kubernetes Service Account (create/annotate optional)
###############################################################################

resource "kubernetes_service_account" "ksa" {
  count = var.manage_ksa ? 1 : 0

  metadata {
    name        = var.ksa_name
    namespace   = var.namespace
    labels      = var.ksa_labels
    annotations = local.ksa_annotations
  }
}

###############################################################################
# Outputs
###############################################################################

output "gsa_email" {
  description = "Email of the Google service account used by Workload Identity."
  value       = local.gsa_email
}

output "workload_pool" {
  description = "Resolved Workload Identity pool used to build the WI principal."
  value       = local.workload_pool
}

output "wi_member" {
  description = "IAM member string bound to roles/iam.workloadIdentityUser on the GSA."
  value       = local.wi_member
}

output "ksa_annotation" {
  description = "Required KSA annotation mapping to the GSA."
  value       = local.ksa_required_annotation
}

output "ksa_fqdn" {
  description = "FQDN of the Kubernetes ServiceAccount (namespace/name)."
  value       = "${var.namespace}/${var.ksa_name}"
}
