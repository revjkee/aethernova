/**
 * Module: networking/peering-and-endpoints
 * File: versions.tf
 * Purpose: Pin Terraform/Core provider versions for deterministic, reproducible builds.
 * Scope: Module-level constraints only (no provider configurations here).
 */

terraform {
  # Require modern Terraform features (moved blocks, counts/for_each stability, etc.)
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      # Lock to a major line known to be compatible with VPC peering & endpoints resources
      version = ">= 6.0.0, < 7.0.0"
    }

    google-beta = {
      source  = "hashicorp/google-beta"
      # Keep beta in step with the same major line as stable when using preview features
      version = ">= 6.0.0, < 7.0.0"
    }

    # Utility providers frequently used for naming, guards, and orchestration
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
  }

  # Provider meta can help with provenance/tracing in CI logs and registries
  provider_meta "hashicorp/google" {
    module_name = "aethernova/networking/peering-and-endpoints"
  }

  provider_meta "hashicorp/google-beta" {
    module_name = "aethernova/networking/peering-and-endpoints"
  }
}
