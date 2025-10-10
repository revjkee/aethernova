/**
 * Module: storage/postgres
 * File: versions.tf
 * Purpose: Pin Terraform core and providers to stable, production-grade ranges
 *          for deterministic plans and applies when managing PostgreSQL.
 *
 * Scope:
 * - Only version constraints. No provider configurations here.
 * - Keep exact provider configuration (endpoints, credentials) in the root/caller.
 */

terraform {
  # Require modern Terraform features (moved blocks, preconditions, etc.)
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # PostgreSQL provider for roles, grants, schemas, databases, privileges
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = ">= 1.20.0, < 2.0.0"
    }

    # Utility providers commonly used by PostgreSQL modules
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
}

/*
Notes:
- This module intentionally avoids pinning to exact patch versions to allow
  security/bugfix updates within the same major line.
- Provider configuration (provider "postgresql" { ... }) must be done by the caller.
- If you also deploy Postgres inside Kubernetes or via Helm (operators), pin
  kubernetes/helm providers in the parent and pass connection details here.
*/
