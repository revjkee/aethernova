#############################################
# File: ops/terraform/modules/registry/gar/versions.tf
# Purpose: Pin Terraform & providers for Google Artifact Registry (GAR)
# Notes:
# - Version constraints declared only in terraform.required_providers (per HashiCorp guidance)
# - Provider configs live elsewhere (providers.tf)
#############################################

terraform {
  # Pin Terraform 1.x (features like dependency lockfile and plugin behavior)
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    #############################
    # Google Cloud providers
    #############################
    google = {
      source  = "hashicorp/google"
      # Allow stable 5.x–6.x; cap before next major to avoid breaking changes
      version = ">= 5.0.0, < 7.0.0"
    }

    google-beta = {
      source  = "hashicorp/google-beta"
      # Beta provider kept in step with google provider major; cap before next major
      version = ">= 5.0.0, < 7.0.0"
    }

    #############################
    # Optional: integrate GAR with GKE/Helm charts (robot tokens, secrets)
    #############################
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.26.0, < 3.0.0"
    }

    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.0, < 3.0.0"
    }

    #############################
    # Utilities commonly used around registries
    #############################
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0, < 4.0.0"
    }

    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0, < 5.0.0"
    }

    time = {
      source  = "hashicorp/time"
      version = ">= 0.11.0, < 1.0.0"
    }

    local = {
      source  = "hashicorp/local"
      version = ">= 2.4.0, < 3.0.0"
    }
  }
}
