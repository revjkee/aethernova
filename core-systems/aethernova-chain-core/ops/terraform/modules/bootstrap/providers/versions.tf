###############################################################################
# File: ops/terraform/modules/bootstrap/providers/versions.tf
# Purpose: Centralized version constraints for Terraform and core providers.
# Notes:
#   - Keep constraints conservative for stability in CI/CD.
#   - Provider source addresses are explicit to avoid implicit registry drift.
#   - Actual provider configuration (auth/regions/tags) should live in providers.tf.
###############################################################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # Cloud providers
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"   # AWS provider 5.x line
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 6.11"   # Google provider 6.x line
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.11"   # Google beta for features ahead of GA
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.9"    # AzureRM provider 4.x line
    }

    # Cluster & packaging
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32"   # Kubernetes provider 2.x line
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.14"   # Helm provider 2.x line
    }

    # Core utilities
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

###############################################################################
# Rationale:
# - Lock to major branches with pessimistic constraints (~>) to allow patch/minor
#   updates while preventing breaking major upgrades during CI/CD.
# - Centralizes provider set for bootstrap modules that may touch multiple clouds.
# - Keep this file minimal: only versions and sources. No provider configs here.
###############################################################################
