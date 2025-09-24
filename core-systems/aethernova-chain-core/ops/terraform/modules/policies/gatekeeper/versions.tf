############################################################
# File: aethernova-chain-core/ops/terraform/modules/policies/gatekeeper/versions.tf
# Purpose: Pin Terraform & providers for OPA Gatekeeper deployment (Helm)
# Notes:
#  - Constrain providers to current major trains to avoid breaking changes.
#  - Gatekeeper Helm chart requires Helm 3.
############################################################

terraform {
  # Pin Terraform to a tested minor series; allow patch updates only.
  # See HashiCorp docs on version constraints and recommended use of ~>.
  required_version = "~> 1.6"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      # Stay within 2.x to avoid 3.x breaking changes; baseline at 2.38.0+.
      version = ">= 2.38.0, < 3.0.0"
    }
    helm = {
      source  = "hashicorp/helm"
      # Stay within 3.x to align with Helm 3 and provider's v3 API behavior.
      version = ">= 3.0.2, < 4.0.0"
    }
  }
}
