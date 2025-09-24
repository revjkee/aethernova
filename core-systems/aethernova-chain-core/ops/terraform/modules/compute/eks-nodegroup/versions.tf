############################################################
# File: aethernova-chain-core/ops/terraform/modules/compute/eks-nodegroup/versions.tf
# Purpose: Pin Terraform and provider versions for stable EKS nodegroup deployments
# Notes:
#  - Use pessimistic/upper-bound constraints to avoid accidental major upgrades.
#  - Aligns with HashiCorp guidance on version constraints and provider locking.
############################################################

terraform {
  # Best practice: pin major+minor so patch updates are allowed, but no silent jumps
  # to the next minor/major. See HashiCorp docs on version constraints.
  # Example here: allow 1.6.x (1.6.*).
  required_version = "~> 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      # AWS Provider v6 is current major; block <7.0 to avoid breaking changes in future majors.
      # Pick a stable baseline within 6.x.
      version = ">= 6.5.0, < 7.0.0"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      # Keep within 2.x to avoid major breaking changes.
      # 2.37+ includes compatibility fixes with newer Terraform; stay <3.0.0.
      version = ">= 2.37.0, < 3.0.0"
    }

    helm = {
      source  = "hashicorp/helm"
      # Helm provider switched to Plugin Framework in 3.x (breaking); require 3.x but not 4.
      version = ">= 3.0.1, < 4.0.0"
    }

    tls = {
      source  = "hashicorp/tls"
      # Latest major is 4.x; pin within it.
      version = ">= 4.0.0, < 5.0.0"
    }

    random = {
      source  = "hashicorp/random"
      # Keep within 3.x.
      version = ">= 3.5.0, < 4.0.0"
    }

    time = {
      source  = "hashicorp/time"
      # Keep within 0.x train but pin to recent releases.
      version = ">= 0.13.0, < 1.0.0"
    }
  }
}
