###############################################################################
# File: ops/terraform/modules/k8s-observability/otel-collector/versions.tf
# Purpose: Centralized Terraform & provider version constraints for the
#          OpenTelemetry Collector deployment module (via Helm/Kubernetes).
# Notes:
#  - Keep constraints conservative to allow patch/minor updates while avoiding
#    breaking major upgrades in CI/CD.
#  - Provider configuration (contexts, kubeconfig, helm repo creds) lives in
#    separate files (e.g., providers.tf) at the calling layer.
###############################################################################

terraform {
  # Terraform core version: 1.6 LTS-compatible, block major upgrades
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    ###########################################################################
    # Kubernetes API provider (manifests, CRDs status checks)
    ###########################################################################
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32"
    }

    ###########################################################################
    # Helm provider (install/upgrade OpenTelemetry Collector/Operator charts)
    ###########################################################################
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.14"
    }

    ###########################################################################
    # Utilities (idempotent randomness, timestamps, local rendering, no-op)
    ###########################################################################
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }

    ###########################################################################
    # Optional helpers (TLS material, HTTP fetch of remote YAML/templates)
    ###########################################################################
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
  }
}

###############################################################################
# Rationale:
# - Pin to stable major lines with pessimistic operator (~>) for predictable CI.
# - Only versions/sources here; no provider auth/config in this file.
###############################################################################
