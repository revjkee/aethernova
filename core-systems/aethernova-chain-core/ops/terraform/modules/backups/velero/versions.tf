/**
 * Module: backups/velero
 * File: versions.tf
 * Purpose: Deterministic version pinning for Velero deployments across Kubernetes
 *          and major cloud object storages (AWS S3, GCP GCS, Azure Blob).
 *
 * Notes:
 * - Provider configuration (endpoints, creds, features) belongs in the root module.
 * - The module may conditionally use cloud providers depending on selected backend.
 * - Ranges allow security/bugfix updates within the same major line.
 */

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # Kubernetes API for namespaces, RBAC, CRDs readiness checks, etc.
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.23.0, < 3.0.0"
    }

    # Helm for deploying Velero chart and plugins
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.11.0, < 3.0.0"
    }

    # AWS (S3/object storage, IAM for backup credentials)
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }

    # Google Cloud (GCS/Memorystore of creds, project services)
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0, < 7.0.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 6.0.0, < 7.0.0"
    }

    # Azure (Blob storage for backup buckets, identities)
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.100.0, < 5.0.0"
    }

    # Utilities commonly used in production modules
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0, < 4.0.0"
    }

    null = {
      source  = "hashicorp/null"
      version = ">= 3.2.1, < 4.0.0"
    }

    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.5, < 5.0.0"
    }

    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.1, < 1.0.0"
    }
  }

  # Provenance hints for registries/CI logs
  provider_meta "hashicorp/kubernetes" { module_name = "aethernova/backups/velero" }
  provider_meta "hashicorp/helm"       { module_name = "aethernova/backups/velero" }
  provider_meta "hashicorp/aws"        { module_name = "aethernova/backups/velero" }
  provider_meta "hashicorp/google"     { module_name = "aethernova/backups/velero" }
  provider_meta "hashicorp/google-beta"{ module_name = "aethernova/backups/velero" }
  provider_meta "hashicorp/azurerm"    { module_name = "aethernova/backups/velero" }
}
